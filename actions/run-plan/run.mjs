#!/usr/bin/env node
// Trusted checked-in bundle only; target plans are data and never become shell code.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { appendFile, lstat, open, realpath, unlink } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { superviseCli } from './supervise.mjs';

const REVISION = 'built-in-plan-run-v1', DIGEST = /^[a-f0-9]{64}$/;
const RUN_ID = /^r-[a-f0-9-]{36}$/, TASK_ID = /^t-[a-z0-9-]{1,40}$/;
const FORMATS = ['report.json', 'report.sarif', 'report.md', 'agent-report.json'];
const cancelled = new AbortController(), cancel = () => { cancelled.abort(); process.exitCode = 2; };
process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const gate = value => [0, 1, 2].includes(value);
const object = value => value && typeof value === 'object' && !Array.isArray(value);
function requireFact(value) { if (!value || cancelled.signal.aborted) throw Error('unverified_plan_action'); }
function relative(value) {
  requireFact(typeof value === 'string' && /^[A-Za-z0-9_./-]{1,200}$/.test(value)
    && !value.startsWith('/') && value.split('/').every(part => part && part !== '.' && part !== '..'));
  return value;
}
function integer(value, fallback, max) {
  const raw = value ?? String(fallback);
  requireFact(/^[1-9][0-9]{0,8}$/.test(raw) && Number(raw) <= max); return Number(raw);
}
/** Same consent/trigger/fork policy as scripts/action-run.mjs, before plan reads or engine setup. */
async function policy(env) {
  requireFact(env.WAKEIO_PLAN_ACTIVE_CONSENT === 'true' && env.GITHUB_EVENT_NAME !== 'pull_request_target');
  const event = env.GITHUB_EVENT_NAME ?? '';
  if (event.startsWith('pull_request') || event === 'workflow_run') {
    const payload = JSON.parse((await bytes(env.GITHUB_EVENT_PATH, 4 * 1024 * 1024)).toString('utf8'));
    const head = event === 'workflow_run' ? payload?.workflow_run?.head_repository?.full_name : payload?.pull_request?.head?.repo?.full_name;
    const base = event === 'workflow_run' ? payload?.workflow_run?.repository?.full_name : payload?.pull_request?.base?.repo?.full_name;
    requireFact(typeof head === 'string' && typeof base === 'string' && head === base);
  }
  const raw = env.WAKEIO_PLAN_ALLOWED_ORIGIN;
  requireFact(typeof raw === 'string' && raw.length <= 2048 && !/[\u0000-\u0020\u007f]/.test(raw));
  const url = new URL(raw);
  requireFact(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash);
  requireFact(['true', 'false'].includes(env.WAKEIO_PLAN_ALLOW_PRIVATE ?? 'false'));
  const failOn = env.WAKEIO_PLAN_FAIL_ON ?? 'high';
  requireFact(['critical', 'high', 'medium', 'low', 'info', 'none'].includes(failOn));
  const [major, minor] = process.versions.node.split('.').map(Number);
  requireFact(major === 22 && minor >= 13 || major === 23 && minor >= 4 || major >= 24);
  return { plan: relative(env.WAKEIO_PLAN), inputs: relative(env.WAKEIO_PLAN_INPUTS), out: relative(env.WAKEIO_PLAN_OUT ?? 'wakeio-run-plan-reports'),
    origin: url.origin, failOn, allowPrivate: env.WAKEIO_PLAN_ALLOW_PRIVATE === 'true',
    maxRequests: integer(env.WAKEIO_PLAN_MAX_REQUESTS, 64, 20_000), timeoutMs: integer(env.WAKEIO_PLAN_TIMEOUT_MS, 120_000, 600_000),
    rate: integer(env.WAKEIO_PLAN_RATE, 10, 150), concurrency: integer(env.WAKEIO_PLAN_CONCURRENCY, 2, 4) };
}
async function directory(path) { const stat = await lstat(path); requireFact(stat.isDirectory() && !stat.isSymbolicLink()); }
async function descendant(workspace, path, newLeaf = false, fileLeaf = false) {
  const parts = relative(path).split('/'); let current = workspace;
  for (const [index, part] of parts.entries()) {
    current = join(current, part);
    try {
      if (fileLeaf && index === parts.length - 1) { const stat = await lstat(current); requireFact(stat.isFile() && !stat.isSymbolicLink()); }
      else await directory(current);
      requireFact(!newLeaf || index !== parts.length - 1);
    }
    catch (error) { if (error.code !== 'ENOENT') throw error; requireFact(index === parts.length - 1); }
  }
  return current;
}
async function bytes(path, cap) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat(); requireFact(before.isFile() && before.size <= cap);
    const buffer = Buffer.alloc(before.size + 1); let used = 0;
    while (used < buffer.length) { const read = await handle.read(buffer, used, buffer.length - used, used); if (!read.bytesRead) break; used += read.bytesRead; }
    const after = await handle.stat();
    requireFact(used === before.size && before.size === after.size && before.ctimeMs === after.ctimeMs && before.mtimeMs === after.mtimeMs);
    return buffer.subarray(0, used);
  } finally { await handle.close(); }
}
async function verifyPublication(out, command, childExit) {
  requireFact(object(command) && command.version === 1 && RUN_ID.test(command.runId) && gate(command.exitCode) && command.exitCode === childExit
    && command.delivery === 'published' && command.outDir === out && DIGEST.test(command.manifestSha256) && Array.isArray(command.tasks)
    && command.tasks.length >= 1 && command.tasks.length <= 16 && command.status === (childExit === 2 ? 'partial' : 'completed'));
  await directory(out);
  const markerBytes = await bytes(join(out, 'run-receipt.json'), 65536), marker = JSON.parse(markerBytes.toString('utf8'));
  requireFact(marker.version === 1 && marker.profileRevision === REVISION && marker.runId === command.runId
    && marker.status === 'publication_only' && marker.exitCode === childExit && marker.manifestSha256 === command.manifestSha256
    && marker.requiresCallerAcknowledgement === true && marker.provesFinalProcessExit === false && DIGEST.test(marker.runReportSha256));
  const manifestBytes = await bytes(join(out, 'run-manifest.json'), 1024 * 1024), manifest = JSON.parse(manifestBytes.toString('utf8'));
  requireFact(digest(manifestBytes) === command.manifestSha256 && manifest.version === 1 && manifest.profileRevision === REVISION
    && manifest.runId === command.runId && DIGEST.test(manifest.planSha256) && DIGEST.test(manifest.scopeHash) && Array.isArray(manifest.artifacts));
  const required = new Set(['run-start.json', 'run-report.json', 'run-report.md', 'agent-run.json', 'run.db']);
  const taskIds = new Set();
  for (const task of command.tasks) {
    requireFact(object(task) && TASK_ID.test(task.taskId) && !taskIds.has(task.taskId) && gate(task.exitCode)
      && task.status === (task.exitCode === 2 ? 'partial' : 'completed') && task.reportPath === `tasks/${task.taskId}/report.json` && DIGEST.test(task.reportSha256));
    taskIds.add(task.taskId); for (const format of FORMATS) required.add(`tasks/${task.taskId}/${format}`);
  }
  requireFact(manifest.artifacts.length >= required.size && manifest.artifacts.length <= 16384);
  const members = new Map();
  for (const artifact of manifest.artifacts) {
    requireFact(object(artifact) && typeof artifact.path === 'string' && !members.has(artifact.path)
      && (required.has(artifact.path) || /^evidence\/f-[a-f0-9]{32}\.json$/.test(artifact.path))
      && Number.isSafeInteger(artifact.bytes) && artifact.bytes >= 0 && artifact.bytes <= 16 * 1024 * 1024 && DIGEST.test(artifact.sha256));
    const content = await bytes(await descendant(out, artifact.path, false, true), 16 * 1024 * 1024);
    requireFact(content.byteLength === artifact.bytes && digest(content) === artifact.sha256); members.set(artifact.path, content);
  }
  requireFact([...required].every(path => members.has(path)));
  const reportBytes = members.get('run-report.json'), report = JSON.parse(reportBytes.toString('utf8'));
  const start = JSON.parse(members.get('run-start.json').toString('utf8')), agent = JSON.parse(members.get('agent-run.json').toString('utf8'));
  requireFact(digest(reportBytes) === marker.runReportSha256 && report.version === 1 && report.profileRevision === REVISION
    && report.runId === command.runId && report.exitCode === childExit && report.status === command.status
    && report.planSha256 === manifest.planSha256 && report.scopeHash === manifest.scopeHash
    && isDeepStrictEqual(report.tasks, command.tasks) && isDeepStrictEqual(report.requests, command.requests)
    && start.runId === command.runId && start.declarationOnly === true && isDeepStrictEqual(start.expectedTasks, command.tasks.map(({ taskId, engine }) => ({ taskId, engine })))
    && agent.runId === command.runId && agent.exitCode === childExit && agent.reportArtifact?.digest === digest(reportBytes)
    && agent.diagnosticOnly === true && agent.replayAuthority === false);
  for (const task of command.tasks) {
    const path = `tasks/${task.taskId}/`, original = members.get(path + 'report.json');
    const taskAgent = JSON.parse(members.get(path + 'agent-report.json').toString('utf8'));
    requireFact(digest(original) === task.reportSha256 && taskAgent.reportArtifact?.digest === task.reportSha256
      && taskAgent.reportArtifact.name === 'report.json' && taskAgent.reportArtifact.algorithm === 'sha256' && taskAgent.scanGate?.exitCode === task.exitCode);
  }
  requireFact(childExit === (command.tasks.some(task => task.exitCode === 2) || report.stopReason !== 'complete' ? 2 : command.tasks.some(task => task.exitCode === 1) ? 1 : 0));
  return { manifestSha256: command.manifestSha256, runReportSha256: marker.runReportSha256, publicationReceiptSha256: digest(markerBytes) };
}
async function outputs(env, state) {
  if (!env.GITHUB_OUTPUT) return;
  const out = state.deliveryStatus === 'delivered' ? state.outDir : '';
  const values = { 'exit-code': state.exitCode, 'setup-status': state.setupStatus, 'scan-status': state.scanStatus, 'delivery-status': state.deliveryStatus,
    'report-dir': out, 'run-report': out && join(out, 'run-report.json'), 'run-agent': out && join(out, 'agent-run.json'),
    manifest: out && join(out, 'run-manifest.json'), 'publication-marker': out && join(out, 'run-receipt.json'), receipt: state.receipt ?? '', 'run-id': out ? state.runId : '' };
  const lines = Object.entries(values).map(([key, value]) => { if (/[\r\n]/.test(String(value))) throw Error('invalid_output'); return `${key}=${value}`; }).join('\n');
  await appendFile(env.GITHUB_OUTPUT, lines + '\n');
}
async function main() {
  const env = process.env;
  let state = { version: 1, exitCode: 2, setupStatus: 'refused', scanStatus: 'not-run', deliveryStatus: 'failed' };
  let receiptOwned = false;
  try {
    const options = await policy(env);
    state.setupStatus = 'failure';
    const workspace = await realpath(resolve(env.GITHUB_WORKSPACE || process.cwd())); await directory(workspace);
    const out = await descendant(workspace, options.out, true);
    const plan = await descendant(workspace, options.plan, false, true), inputs = await descendant(workspace, options.inputs, false, true);
    const actionPath = resolve(env.WAKEIO_ACTION_PATH || env.GITHUB_ACTION_PATH || dirname(fileURLToPath(import.meta.url)));
    const entry = resolve(actionPath, '../../dist-action/wakeio-security-ci.mjs'), bundleSha256 = digest(await bytes(entry, 32 * 1024 * 1024));
    const args = [entry, 'run-plan', '--plan', plan, '--inputs', inputs, '--active-consent', '--allowed-origin', options.origin, '--out', out,
      '--max-requests', String(options.maxRequests), '--timeout-ms', String(options.timeoutMs), '--rate-per-second', String(options.rate),
      '--concurrency', String(options.concurrency), '--fail-on', options.failOn];
    if (options.allowPrivate) args.push('--allow-private');
    for (const [flag, name] of [['--schemathesis-python', 'WAKEIO_PLAN_SCHEMATHESIS_PYTHON'], ['--nuclei', 'WAKEIO_PLAN_NUCLEI_PATH'], ['--nuclei-templates', 'WAKEIO_PLAN_NUCLEI_TEMPLATES'], ['--zap', 'WAKEIO_PLAN_ZAP_PATH']]) {
      const value = env[name]; if (value) { requireFact(value.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(value)); args.push(flag, value); }
    }
    requireFact(true); state.setupStatus = 'success';
    const child = await superviseCli(process.execPath, args, { cwd: workspace, env, timeoutMs: options.timeoutMs + 5000,
      maxOutputBytes: 4 * 1024 * 1024, signal: cancelled.signal });
    state.scanStatus = child.reason === 'cancelled' ? 'cancelled' : 'incomplete';
    requireFact(child.cleanupConfirmed && child.closeConfirmed && !child.reason && !child.signal && gate(child.exitCode));
    const lines = child.stdout.trim().split('\n'); requireFact(lines.length === 1 && Buffer.byteLength(lines[0]) <= 4 * 1024 * 1024);
    const command = JSON.parse(lines[0]), publication = await verifyPublication(out, command, child.exitCode);
    requireFact(digest(await bytes(entry, 32 * 1024 * 1024)) === bundleSha256);
    const receipt = join(out, 'run-action-receipt.json');
    state = { ...state, exitCode: child.exitCode, scanStatus: child.exitCode === 0 ? 'completed' : child.exitCode === 1 ? 'findings' : 'incomplete',
      deliveryStatus: 'delivered', outDir: out, runId: command.runId, receipt, ...publication, bundleSha256,
      childExitCode: child.exitCode, childCleanupConfirmed: true, acknowledgement: 'current_child_and_publication_verified', provesFinalActionExit: false };
    const handle = await open(receipt, 'wx', 0o600); receiptOwned = true;
    try { await handle.writeFile(JSON.stringify(state, null, 2) + '\n'); } finally { await handle.close(); }
    requireFact(true);
  } catch {
    if (receiptOwned && state.receipt) await unlink(state.receipt).catch(() => {});
    receiptOwned = false;
    state = { version: 1, exitCode: 2, setupStatus: state.setupStatus, scanStatus: cancelled.signal.aborted ? 'cancelled' : state.scanStatus,
      deliveryStatus: 'failed' };
    process.stderr.write('Run-plan Action refused or could not acknowledge a current result; exit 2.\n');
  }
  try {
    await outputs(env, state);
    if (env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY, `### Wakeio built-in plan run\n\nWrapper exit: ${state.exitCode}. Delivery: ${state.deliveryStatus}. Group completion covers the selected checks only. Publication and final Action outcome remain separate.\n`);
    if (cancelled.signal.aborted) throw Error('cancelled');
  } catch {
    if (receiptOwned && state.receipt) await unlink(state.receipt).catch(() => {});
    receiptOwned = false;
    state = { version: 1, exitCode: 2, setupStatus: state.setupStatus, scanStatus: cancelled.signal.aborted ? 'cancelled' : 'incomplete', deliveryStatus: 'failed' };
    await outputs(env, state).catch(() => {});
  }
  process.stdout.write(JSON.stringify({ version: 1, exitCode: state.exitCode, deliveryStatus: state.deliveryStatus }) + '\n');
  process.exitCode = state.exitCode;
}
try { await main(); } catch { process.stderr.write('Run-plan Action failed closed; exit 2.\n'); process.exitCode = 2; }
finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
