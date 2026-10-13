#!/usr/bin/env node
// Own synthetic fixtures only. No npm, target checkout script, or external URL.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { appendFile, lstat, mkdir, open, readdir, realpath, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { runBounded } from '../../scripts/ci-process.mjs';

const SCOPE = 'owned-synthetic-resource-patch-write';
const CANDIDATES = new Set(['fixed', 'ineffective', 'all-deny', 'normal-regression', 'status-only', 'wrong-object']);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const FORMATS = ['agent-report.json', 'report.json', 'report.md', 'report.sarif'];
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const gate = value => [0, 1, 2].includes(value);
function requireFact(condition) { if (!condition) throw Error('unverified_action_result'); }
function inputs(env) {
  requireFact(env.WAKEIO_WRITE_ACTIVE_CONSENT === 'true' && CANDIDATES.has(env.WAKEIO_WRITE_CANDIDATE));
  const timeout = env.WAKEIO_WRITE_TIMEOUT_MS ?? '30000', out = env.WAKEIO_WRITE_OUT ?? 'wakeio-api-write-reports';
  requireFact(/^[1-9][0-9]{0,4}$/.test(timeout) && Number(timeout) <= 30000);
  requireFact(/^[A-Za-z0-9_./-]{1,200}$/.test(out) && !out.startsWith('/')
    && out.split('/').every(part => part && part !== '.' && part !== '..'));
  return { candidate: env.WAKEIO_WRITE_CANDIDATE, timeout: Number(timeout), out };
}
async function directory(path, privateMode = false) {
  const stat = await lstat(path);
  requireFact(stat.isDirectory() && !stat.isSymbolicLink() && (!privateMode || (stat.mode & 0o777) === 0o700));
}
async function safeDescendant(workspace, relative, mustBeNew = false) {
  let path = workspace;
  const parts = relative.split('/');
  for (const [index, part] of parts.entries()) {
    requireFact(part && part !== '.' && part !== '..' && !part.includes('\\'));
    path = join(path, part);
    try { await directory(path); requireFact(!mustBeNew || index !== parts.length - 1); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return path;
}
async function bytes(path, cap, privateMode = false) {
  const stat = await lstat(path);
  requireFact(stat.isFile() && !stat.isSymbolicLink() && stat.size <= cap
    && (!privateMode || (stat.mode & 0o777) === 0o600));
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat();
    requireFact(before.isFile() && before.dev === stat.dev && before.ino === stat.ino && before.size <= cap);
    const buffer = Buffer.alloc(before.size + 1);
    let used = 0;
    while (used < buffer.length) {
      const read = await fd.read(buffer, used, buffer.length - used, used);
      if (!read.bytesRead) break;
      used += read.bytesRead;
    }
    const after = await fd.stat();
    requireFact(used === before.size && after.size === before.size
      && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs);
    return buffer.subarray(0, used);
  } finally { await fd.close(); }
}
async function verifyPublication(out, command) {
  requireFact(command.delivery === 'delivered' && command.commandStatus === 'completed');
  requireFact(UUID.test(command.runId) && UUID.test(command.deliveryAttemptId)
    && command.outputRelativePath === command.runId + '/' + command.deliveryAttemptId);
  await directory(out, true);
  const run = join(out, command.runId), published = join(run, command.deliveryAttemptId);
  await directory(run, true); await directory(published, true);
  const markerPath = join(published, 'api-write-delivery.json'), markerBytes = await bytes(markerPath, 65536, true);
  const marker = JSON.parse(markerBytes.toString('utf8'));
  requireFact(marker.version === 1 && marker.runId === command.runId && marker.deliveryAttemptId === command.deliveryAttemptId
    && marker.status === 'publication_only' && marker.requiresCallerAcknowledgement === true
    && marker.provesFinalProcessExit === false && marker.apiReexecuted === false && DIGEST.test(marker.artifactSha256)
    && DIGEST.test(marker.manifestSha256));
  requireFact(isDeepStrictEqual(Object.keys(marker).sort(), ['version', 'runId', 'deliveryAttemptId', 'status',
    'requiresCallerAcknowledgement', 'provesFinalProcessExit', 'artifactSha256', 'manifestSha256', 'reportDigests', 'apiReexecuted'].sort()));
  requireFact(object(marker.reportDigests) && DIGEST.test(marker.reportDigests.verification)
    && Object.keys(marker.reportDigests).every(name => ['before', 'after', 'verification'].includes(name) && DIGEST.test(marker.reportDigests[name])));
  const phases = Object.keys(marker.reportDigests).sort();
  const manifestPath = join(published, 'api-write-manifest.json'), manifestBytes = await bytes(manifestPath, 65536, true);
  requireFact(digest(manifestBytes) === marker.manifestSha256);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  requireFact(object(manifest) && manifest.version === 1 && manifest.scope === SCOPE
    && manifest.runId === command.runId && manifest.deliveryAttemptId === command.deliveryAttemptId
    && isDeepStrictEqual(Object.keys(manifest).sort(), ['version', 'scope', 'runId', 'deliveryAttemptId', 'artifacts'].sort()));
  const expected = ['before', 'after', 'verification'].filter(phase => phases.includes(phase))
    .flatMap(phase => ['report.json', 'agent-report.json', 'report.md', 'report.sarif'].map(format => phase + '/' + format));
  requireFact(Array.isArray(manifest.artifacts) && manifest.artifacts.length === expected.length);
  const members = new Map();
  for (const [index, artifact] of manifest.artifacts.entries()) {
    requireFact(object(artifact) && artifact.path === expected[index] && Number.isSafeInteger(artifact.bytes)
      && artifact.bytes >= 0 && artifact.bytes <= 16 * 1024 * 1024 && DIGEST.test(artifact.sha256)
      && isDeepStrictEqual(Object.keys(artifact).sort(), ['path', 'bytes', 'sha256'].sort()));
    members.set(artifact.path, artifact);
  }
  requireFact(isDeepStrictEqual((await readdir(published)).sort(), [...phases, 'api-write-delivery.json', 'api-write-manifest.json'].sort()));
  const reports = {};
  for (const name of phases) {
    const folder = join(published, name); await directory(folder, true);
    requireFact(isDeepStrictEqual((await readdir(folder)).sort(), FORMATS));
    const contents = {};
    for (const format of FORMATS) {
      contents[format] = await bytes(join(folder, format), 16 * 1024 * 1024, true);
      const member = members.get(name + '/' + format);
      requireFact(contents[format].byteLength === member.bytes && digest(contents[format]) === member.sha256);
    }
    const report = JSON.parse(contents['report.json'].toString('utf8'));
    const agent = JSON.parse(contents['agent-report.json'].toString('utf8'));
    requireFact(report.schemaVersion === '1.0.0' && report.mode === 'api' && agent.schemaVersion === '1.0.0' && agent.mode === 'api'
      && agent.reportArtifact?.name === 'report.json' && agent.reportArtifact.algorithm === 'sha256'
      && agent.reportArtifact.digest === digest(contents['report.json'])
      && marker.reportDigests[name] === digest(contents['report.json']) && gate(agent.scanGate?.exitCode));
    const check = report.checks?.find(item => item.id === 'api.owned-write-state-oracle');
    const projection = agent.checks?.find(item => item.checkId === 'api.owned-write-state-oracle');
    const evidence = check?.apiWriteStateEvidence;
    requireFact(evidence?.scope === SCOPE && evidence.lineage?.runId === command.runId
      && evidence.phase === (name === 'verification' ? 'comparison' : name === 'before' ? 'baseline' : 'candidate')
      && isDeepStrictEqual(evidence, projection?.apiWriteStateEvidence));
    reports[name] = { reportSha256: marker.reportDigests[name], agentReportSha256: digest(contents['agent-report.json']),
      markdownSha256: digest(contents['report.md']), sarifSha256: digest(contents['report.sarif']), exitCode: agent.scanGate.exitCode };
  }
  requireFact(reports.verification.exitCode === command.verificationExitCode
    && command.finalExitCode === command.verificationExitCode);
  return { published, markerPath, markerSha256: digest(markerBytes), manifestPath, manifestSha256: digest(manifestBytes), reports };
}
function outputValues(state, receiptPath) {
  const published = state.delivery === 'delivered' ? state.publication.published : '';
  return { 'exit-code': state.finalExitCode, 'before-exit-code': state.publication?.reports.before?.exitCode ?? 'unknown',
    'after-exit-code': state.publication?.reports.after?.exitCode ?? 'unknown', 'verification-exit-code': state.verificationExitCode,
    'delivery-status': state.delivery, 'command-status': state.commandStatus, 'report-dir': published,
    'before-report': published && state.publication.reports.before ? join(published, 'before/report.json') : '',
    'after-report': published && state.publication.reports.after ? join(published, 'after/report.json') : '',
    'verification-report': published ? join(published, 'verification/report.json') : '',
    'report-agent': published ? join(published, 'verification/agent-report.json') : '',
    'publication-marker': published ? state.publication.markerPath : '', receipt: receiptPath ?? '',
    'run-id': state.delivery === 'delivered' ? state.runId : '', 'delivery-attempt-id': state.delivery === 'delivered' ? state.deliveryAttemptId : '' };
}
async function emitOutputs(env, values) {
  if (!env.GITHUB_OUTPUT) return;
  const lines = Object.entries(values).map(([key, value]) => {
    requireFact(!/[\r\n]/.test(String(value))); return key + '=' + value;
  }).join('\n') + '\n';
  await appendFile(env.GITHUB_OUTPUT, lines);
}
async function main() {
  const env = process.env;
  let state = { version: 1, scope: SCOPE, delivery: 'unknown', commandStatus: 'refused',
    verificationExitCode: 2, finalExitCode: 2, apiReexecuted: false, provesFinalActionExit: false };
  let out, ownedOutput = false, receiptPath;
  try {
    const options = inputs(env);
    const rawWorkspace = resolve(env.GITHUB_WORKSPACE || process.cwd()); await directory(rawWorkspace);
    const workspace = await realpath(rawWorkspace);
    out = await safeDescendant(workspace, options.out, true); ownedOutput = true;
    const actionPath = resolve(env.WAKEIO_ACTION_PATH || env.GITHUB_ACTION_PATH || dirname(fileURLToPath(import.meta.url)));
    const entry = resolve(actionPath, '../../dist-action/wakeio-security-ci.mjs');
    const bundleSha256 = digest(await bytes(entry, 32 * 1024 * 1024));
    state.commandStatus = 'error';
    const child = await runBounded(process.execPath, [entry, 'api-write-state', '--candidate', options.candidate,
      '--active-consent', '--timeout-ms', String(options.timeout), '--out', out],
    { cwd: workspace, env, timeoutMs: 45000, maxOutputBytes: 1024 * 1024 });
    if (child.reason === 'cancelled') state.commandStatus = 'cancelled';
    requireFact(child.cleanupConfirmed && child.closeConfirmed && !child.reason && !child.signal && gate(child.exitCode));
    const lines = child.stdout.trim().split('\n'); requireFact(lines.length === 1 && lines[0].length <= 65536);
    const command = JSON.parse(lines[0]);
    requireFact(object(command) && command.version === 1 && command.scope === SCOPE && command.apiReexecuted === false
      && gate(command.finalExitCode) && gate(command.verificationExitCode) && command.finalExitCode === child.exitCode
      && ['completed', 'cancelled'].includes(command.commandStatus));
    requireFact(isDeepStrictEqual(Object.keys(command).sort(), ['version', 'scope', 'runId', 'deliveryAttemptId',
      'outputRelativePath', 'delivery', 'verificationExitCode', 'finalExitCode', 'apiReexecuted', 'commandStatus'].sort()));
    const publication = await verifyPublication(out, command);
    requireFact(digest(await bytes(entry, 32 * 1024 * 1024)) === bundleSha256);
    state = { ...state, ...command, publication, candidate: options.candidate, bundleSha256,
      childExitCode: child.exitCode, childCleanupConfirmed: true, acknowledgement: 'current_child_and_publication_verified' };
  } catch {
    state = { version: 1, scope: SCOPE, delivery: 'unknown', commandStatus: state.commandStatus,
      verificationExitCode: 2, finalExitCode: 2, apiReexecuted: false, provesFinalActionExit: false };
    process.stderr.write('Owned API write-state Action could not acknowledge a current result; exit 2.\n');
  }
  try {
    if (ownedOutput) {
      await safeDescendant(await realpath(resolve(env.GITHUB_WORKSPACE || process.cwd())), env.WAKEIO_WRITE_OUT ?? 'wakeio-api-write-reports');
      await mkdir(out, { recursive: true, mode: 0o700 }); await directory(out, true);
      receiptPath = join(out, 'api-write-action-receipt.json');
      await writeFile(receiptPath, JSON.stringify(state, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    }
    await emitOutputs(env, outputValues(state, receiptPath));
    if (env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY,
      '### Owned API write-state pilot\n\nFinal wrapper exit: ' + state.finalExitCode
      + '. Delivery: ' + state.delivery + '. Comparison gate: ' + state.verificationExitCode
      + '. Original phase gates are separate outputs. Fixed own loopback fixtures only; no external target or production fix verified.\n');
  } catch {
    if (receiptPath) await unlink(receiptPath).catch(() => {});
    state = { ...state, delivery: 'unknown', finalExitCode: 2, verificationExitCode: 2, publication: undefined };
    await emitOutputs(env, outputValues(state, undefined)).catch(() => {});
    process.stderr.write('Owned API write-state Action outputs were incomplete; exit 2.\n');
  }
  process.stdout.write(JSON.stringify({ version: 1, scope: SCOPE, finalExitCode: state.finalExitCode, delivery: state.delivery }) + '\n');
  process.exitCode = state.finalExitCode;
}
await main();
