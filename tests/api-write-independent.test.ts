import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import fsp from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolve, dirname, basename, sep } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { Server } from 'node:http';
import * as publicSdk from '../src/index.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { compareReports } from '../src/compare.js';

// Independent expected semantics were frozen before producer output:
// artifacts/api-write-2026-10-13/independent-oracle/oracle.json
// SHA256 2551e0734bb247a755f554dfd25eeb56a4d6fd8318029ad5d154d169166c7ea7.
// Namespace import remains baseline-loadable: only agreed public SDK/CLI paths,
// never a prospective detector/observer helper. Own child IO/HTTP interception
// supplies faults without giving the shipped SDK a target/callback/fault option.
const SCOPE = 'owned-synthetic-resource-patch-write', CHECK = 'api.owned-write-state-oracle';
const CANARY = 'owned-write-extra-private-marker-b715';
type Candidate = 'fixed' | 'ineffective' | 'all-deny' | 'normal-regression' | 'status-only' | 'wrong-object';
function api() {
  const value = publicSdk as Record<string, any>;
  assert.equal(typeof value.runOwnedApiWriteStatePilot, 'function', 'missing public owned write SDK');
  assert.equal(typeof value.deliverOwnedApiWriteStatePilot, 'function', 'missing public delivery SDK');
  return { run: value.runOwnedApiWriteStatePilot, deliver: value.deliverOwnedApiWriteStatePilot };
}
const sha = (text: string) => createHash('sha256').update(text).digest('hex');
async function folder(t: TestContext) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-write-independent-'));
  t.after(() => rm(top, { recursive: true, force: true })); return top;
}
async function processResult(args: string[], env: NodeJS.ProcessEnv, timeout = 12_000) {
  return await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(process.execPath, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(Error('owned child exceeded outer wall limit')); }, timeout);
    child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

// This preload executes only inside a root-run owned child. It is not a public
// callback, source predicate, replacement handler, or installed target module.
const preload = String.raw`
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import { Server, ServerResponse } from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { resolve, sep } from 'node:path';
const anchor = resolve(process.env.OWNED_WRITE_TOP);
const mode = process.env.OWNED_WRITE_FAULT || 'none';
const trace = { requests: [], markers: [], snapshots: [], stateModes: [], afterAbort: 0, faultFired: false, fdFailureReads: 0 };
const markers = new Set(), fdPaths = new Map(), active = new Map(), stores = [];
const realOpen = fsp.open.bind(fsp), realWrite = fs.writeSync.bind(fs), realTruncate = fs.ftruncateSync.bind(fs);
const realRead = fs.readFileSync.bind(fs), realWriteFile = fs.writeFileSync.bind(fs);
const realReadSync = fs.readSync.bind(fs), realStatSync = fs.fstatSync.bind(fs); let deniedFD;
function readFault(fd) { if (fd === deniedFD) { trace.fdFailureReads++; throw Object.assign(Error('owned observer read unavailable'), {code:'EBADF'}); } }
const under = path => typeof path === 'string' && resolve(path).startsWith(anchor + sep);
function state(path) {
  if (!under(path)) return;
  try {
    const bytes = realRead(path);
    if (bytes.length > 65536) return;
    const value = JSON.parse(bytes.toString());
    if (value?.version !== 1 || typeof value.runId !== 'string' || !Array.isArray(value.resources)
      || value.resources.length !== 2 || !value.resources.every(row => typeof row.id === 'string' && typeof row.title === 'string')) return;
    if (!stores.includes(path)) stores.push(path);
    for (const row of value.resources) for (const key of ['canary', 'title', 'contents'])
      if (typeof row[key] === 'string' && row[key].length >= 8) markers.add(row[key]);
    for (const [fd, record] of active) if (record.path === path && !trace.stateModes.some(item => item.fd === fd && item.path === path))
      trace.stateModes.push({ fd, path, mode: record.mode });
    return value;
  } catch {}
}
fsp.open = async (...args) => {
  const handle = await realOpen(...args), path = typeof args[0] === 'string' ? args[0] : undefined;
  if (under(path)) {
    const flags = args[1], access = typeof flags === 'number' ? flags & 3 : flags === 'r' ? 0 : 2;
    fdPaths.set(handle.fd, path); active.set(handle.fd, { path, mode: access }); state(path);
    const close = handle.close.bind(handle), fd = handle.fd;
    handle.close = async (...values) => { try { return await close(...values); } finally { active.delete(fd); if (deniedFD === fd) deniedFD = undefined; } };
    const write = handle.writeFile.bind(handle);
    handle.writeFile = async (...values) => { const result = await write(...values); state(path); return result; };
  }
  return handle;
};
fs.writeSync = (...args) => { const result = realWrite(...args); state(fdPaths.get(args[0])); return result; };
fs.ftruncateSync = (...args) => { const result = realTruncate(...args); state(fdPaths.get(args[0])); return result; };
fs.readSync = (...args) => { readFault(args[0]); return realReadSync(...args); };
fs.fstatSync = (...args) => { readFault(args[0]); return realStatSync(...args); };
syncBuiltinESMExports();
const servers = new WeakMap(), responses = new WeakMap(); let serverCount = 0, aborted = false;
globalThis.__ownedWriteAbort = () => { aborted = true; globalThis.__ownedWriteController?.abort(); };
const emit = Server.prototype.emit;
Server.prototype.emit = function(event, ...args) {
  if (event === 'request') {
    if (!servers.has(this)) servers.set(this, { phase: serverCount++, ordinal: 0, auth: [] });
    const server = servers.get(this), req = args[0], res = args[1];
    if (aborted) trace.afterAbort++;
    const authorization = req.headers.authorization;
    if (authorization && !server.auth.includes(authorization)) server.auth.push(authorization);
    if (authorization) markers.add(authorization);
    const item = { phase: server.phase, ordinal: server.ordinal++, method: req.method, path: req.url,
      actor: authorization ? server.auth.indexOf(authorization) : 2, bytes: 0 };
    trace.requests.push(item); responses.set(res, { item, before: state(stores.at(-1)) });
    let body = '';
    req.on('data', chunk => { item.bytes += chunk.length; if (item.bytes <= 4096) body += chunk.toString(); });
    req.on('end', () => { try { const parsed = JSON.parse(body); if (typeof parsed.title === 'string') { item.title = parsed.title; markers.add(parsed.title); } } catch {} });
    // Reach the lost-response fault even when a slow earlier read exceeds the old 700 ms pilot budget.
    if (mode === 'lost-peer-response' && item.phase === 0 && item.ordinal === 0) {
      setTimeout(() => Reflect.apply(emit, this, [event, ...args]), 800); return true;
    }
  }
  return Reflect.apply(emit, this, [event, ...args]);
};
const end = ServerResponse.prototype.end;
ServerResponse.prototype.end = function(...args) {
  const seen = responses.get(this);
  if (seen) {
    const { item, before } = seen, path = stores.at(-1), after = state(path);
    item.status = this.statusCode;
    if (item.method === 'PATCH' && after) {
      const id = item.path.split('/').at(-1), row = after.resources.find(row => row.id === id);
      item.persistedTitle = !!row && row.title === item.title;
      item.otherRowChanged = !!before && before.resources.some(old => old.id !== id && JSON.stringify(old) !== JSON.stringify(after.resources.find(row => row.id === old.id)));
      trace.snapshots.push({ phase: item.phase, ordinal: item.ordinal, persistedTitle: item.persistedTitle, otherRowChanged: item.otherRowChanged });
    }
    if (!trace.faultFired && mode === 'identity-before' && item.phase === 0 && item.ordinal === 0) {
      trace.faultFired = true; args[0] = JSON.stringify({ userId: 'owned-wrong-principal', orgId: 'owned-wrong-org' });
    }
    if (!trace.faultFired && mode === 'identity-after' && item.phase === 0 && item.ordinal === 16) {
      trace.faultFired = true; args[0] = JSON.stringify({ userId: 'owned-wrong-principal', orgId: 'owned-wrong-org' });
    }
    if (!trace.faultFired && mode === 'lost-peer-response' && item.phase === 1 && item.ordinal === 5) {
      trace.faultFired = true; this.destroy(); return this; // Actual handler write has happened; the peer loses the response.
    }
    if (!trace.faultFired && mode === 'abort-owner-response' && item.phase === 0 && item.ordinal === 3) {
      trace.faultFired = true; globalThis.__ownedWriteAbort();
    }
    if (!trace.faultFired && mode === 'malformed-store' && item.phase === 1 && item.ordinal === 3 && after) {
      trace.faultFired = true; realWriteFile(path, '{');
    }
    if (!trace.faultFired && mode === 'observer-fd' && item.phase === 1 && item.ordinal === 3 && after) {
      const observer = [...active].find(([fd, record]) => record.path === path && record.mode === 0);
      if (observer) { trace.faultFired = true; deniedFD = observer[0]; } // Keep handle ownership/cleanup intact; deny only its later reads/stat.
    }
  }
  return Reflect.apply(end, this, args);
};
process.on('exit', () => { trace.markers = [...markers]; realWriteFile(process.env.OWNED_WRITE_TRACE, JSON.stringify(trace)); });
`;
const runner = String.raw`
import fs from 'node:fs/promises';
const sdk = await import(process.env.OWNED_WRITE_ENTRY);
if (typeof sdk.runOwnedApiWriteStatePilot !== 'function') throw Error('missing_public_write_sdk');
const controller = new AbortController(); globalThis.__ownedWriteController = controller;
if (process.env.OWNED_WRITE_FAULT === 'pre-abort') globalThis.__ownedWriteAbort();
if (process.env.OWNED_WRITE_RUN_KIND === 'cli') {
  const {main} = await import(process.env.OWNED_WRITE_CLI);
  let stdout = '', stderr = ''; const oldOut = process.stdout.write, oldErr = process.stderr.write;
  process.stdout.write = data => { stdout += data.toString(); return true; };
  process.stderr.write = data => { stderr += data.toString(); return true; };
  let code;
  try { code = await main(['api-write-state','--candidate',process.env.OWNED_WRITE_CANDIDATE,'--active-consent','--timeout-ms','3000','--out',process.env.OWNED_WRITE_OUT]); }
  finally { process.stdout.write = oldOut; process.stderr.write = oldErr; }
  await fs.writeFile(process.env.OWNED_WRITE_RESULT, JSON.stringify({code,stdout,stderr}));
} else {
  const result = await sdk.runOwnedApiWriteStatePilot({candidate:process.env.OWNED_WRITE_CANDIDATE,activeConsent:true,
    timeoutMs:3000,signal:controller.signal});
  await fs.writeFile(process.env.OWNED_WRITE_RESULT, JSON.stringify(result));
}
`;
async function childPilot(t: TestContext, candidate: Candidate, fault = 'none', kind = 'sdk') {
  api();
  const top = await folder(t), temporary = join(top, 'private'); await mkdir(temporary);
  const tracePath = join(top, 'private-trace.json'), resultPath = join(top, 'result.json');
  const preloadPath = join(top, 'preload.mjs'), runnerPath = join(top, 'runner.mjs');
  await writeFile(preloadPath, preload); await writeFile(runnerPath, runner);
  const out = join(top, 'out');
  const process = await processResult(['--import', preloadPath, runnerPath], { ...globalThis.process.env,
    TMPDIR: temporary, OWNED_WRITE_TOP: top, OWNED_WRITE_FAULT: fault, OWNED_WRITE_CANDIDATE: candidate,
    OWNED_WRITE_RUN_KIND: kind, OWNED_WRITE_OUT: out, OWNED_WRITE_TRACE: tracePath, OWNED_WRITE_RESULT: resultPath,
    OWNED_WRITE_ENTRY: new URL('../src/index.js', import.meta.url).href, OWNED_WRITE_CLI: new URL('../src/cli.js', import.meta.url).href });
  assert.equal(process.code, 0, 'owned child did not finish SDK/CLI invocation: ' + process.stderr.slice(0, 1000));
  const result = JSON.parse(await readFile(resultPath, 'utf8')), trace = JSON.parse(await readFile(tracePath, 'utf8'));
  const publicText = JSON.stringify(result) + process.stdout + process.stderr;
  for (const marker of trace.markers) assert.equal(publicText.includes(marker), false, 'public result/log leaked a synthetic request/store marker');
  assert.equal(trace.afterAbort, 0, 'new HTTP arrival after acknowledged abort');
  return { result, trace, top, out };
}
function allFindings(result: any) {
  return [result.before?.report, result.after?.report, result.verification].filter(Boolean)
    .flatMap((report: any) => report.checks.flatMap((check: any) => check.findings));
}
function phase(phase: any, code: number) {
  assert.ok(phase); assert.equal(phase.scanGate.exitCode, code);
  assert.equal(evaluateGate(phase.report).exitCode, code); assert.equal(toAgentReport(phase.report).scanGate.exitCode, code);
  assert.equal(phase.evidence.scope, SCOPE); assert.equal(phase.evidence.version, 1);
  assert.equal(phase.evidence.counts.plannedRequests, 18);
  assert.ok(phase.evidence.counts.httpAttempts <= 18); assert.ok(phase.evidence.counts.patchAttempts <= 6);
}
function bounded(result: any, trace: any) {
  assert.equal(result.scope, SCOPE); assert.equal(result.version, 1);
  assert.ok(result.execution.httpAttempts <= 36); assert.ok(result.execution.patchAttempts <= 12);
  assert.equal(result.execution.httpAttempts, trace.requests.length);
  assert.equal(result.execution.patchAttempts, trace.requests.filter((r: any) => r.method === 'PATCH').length);
  for (const finding of allFindings(result)) assert.ok(['observation', 'candidate'].includes(finding.kind));
  for (const report of [result.before?.report, result.after?.report, result.verification].filter(Boolean)) {
    for (const finding of toAgentReport(report).findings) {
      assert.equal(finding.verification.vulnerabilityConfirmed, false); assert.equal(finding.verification.remediationVerified, false);
      assert.equal(finding.verification.state, 'not_run');
    }
  }
}

test('api write independent: real baseline/fixed store discrimination, normal writer and readonly observation survive a fresh seed', async t => {
  let firstRun = '';
  for (let iteration = 0; iteration < 2; iteration++) {
    const { result: r, trace } = await childPilot(t, 'fixed'); bounded(r, trace);
    phase(r.before, 1); phase(r.after, 0); assert.equal(r.verificationGate.exitCode, 0);
    assert.equal(r.before.evidence.effect, 'observed'); assert.equal(r.after.evidence.effect, 'not_observed');
    assert.equal(r.before.evidence.normal, 'passed'); assert.equal(r.after.evidence.normal, 'passed');
    assert.equal(r.execution.httpAttempts, 36); assert.equal(r.execution.patchAttempts, 12);
    assert.equal(trace.requests.filter((x: any) => x.phase === 0 && x.method === 'PATCH' && x.actor !== 2 && x.persistedTitle).length, 4);
    assert.equal(trace.requests.filter((x: any) => x.phase === 1 && x.method === 'PATCH' && x.persistedTitle).length, 2);
    assert.ok(trace.stateModes.some((x: any) => x.mode === 0), 'no independently held readonly state FD was observed');
    assert.equal(r.execution.cleanup, 'confirmed');
    assert.notEqual(r.before.evidence.lineage.handlerSha256, r.after.evidence.lineage.handlerSha256);
    assert.ok(r.before.report.checks.flatMap((c: any) => c.findings).some((f: any) => f.severity === 'high' && f.kind === 'observation'));
    if (firstRun) assert.notEqual(r.runId, firstRun); firstRun = r.runId;
  }
});

test('api write independent: 403-with-write and 200-noop differ while every unmet owner normal control remains partial', async t => {
  for (const [candidate, expected] of [['ineffective', 1], ['status-only', 0], ['all-deny', 2], ['normal-regression', 2], ['wrong-object', 2]] as const) {
    const { result: r, trace } = await childPilot(t, candidate); bounded(r, trace); phase(r.before, 1); phase(r.after, expected);
    assert.equal(r.verificationGate.exitCode, expected);
    const candidateWrites = trace.requests.filter((x: any) => x.phase === 1 && x.method === 'PATCH');
    if (candidate === 'ineffective') {
      assert.ok(candidateWrites.some((x: any) => x.status === 403 && x.persistedTitle));
      assert.equal(r.after.evidence.effect, 'observed');
    } else if (candidate === 'status-only') {
      assert.ok(candidateWrites.some((x: any) => x.actor === 2 && x.status === 200 && !x.persistedTitle));
      assert.equal(candidateWrites.filter((x: any) => x.persistedTitle).length, 2);
      assert.equal(r.after.evidence.normal, 'passed'); assert.equal(r.after.evidence.effect, 'not_observed');
    } else {
      assert.equal(r.after.report.checks.find((c: any) => c.id === CHECK).status, 'partial');
      assert.equal(evaluateGate(r.verification, 'none').exitCode, 2);
      if (candidate === 'wrong-object') assert.ok(candidateWrites.some((x: any) => x.otherRowChanged), 'actual wrong-row effect was not exercised');
      if (candidate !== 'all-deny') assert.ok(r.after.report.checks.flatMap((c: any) => c.findings).length > 0, 'concrete normal/state failure was erased');
    }
  }
});

test('api write independent: identity-before blocks all mutation and identity-after retains prior stored effect without certifying a fix', async t => {
  const before = await childPilot(t, 'fixed', 'identity-before'); bounded(before.result, before.trace);
  assert.equal(before.trace.faultFired, true); assert.equal(before.trace.requests.filter((x: any) => x.method === 'PATCH').length, 0);
  assert.equal(before.result.execution.patchAttempts, 0); assert.equal(before.result.verificationGate.exitCode, 2);
  assert.equal(before.result.after, null);
  const after = await childPilot(t, 'fixed', 'identity-after'); bounded(after.result, after.trace);
  assert.equal(after.trace.faultFired, true); phase(after.result.before, 2); assert.equal(after.result.verificationGate.exitCode, 2);
  assert.equal(after.result.before.evidence.effect, 'observed'); assert.equal(after.result.after, null);
  assert.ok(after.result.before.report.checks.flatMap((c: any) => c.findings).some((f: any) => f.severity === 'high'));
});

test('api write independent: state/FD failure and absent, forged or wrongly attached write evidence fail closed without leaking unknown metadata', async t => {
  for (const fault of ['malformed-store', 'observer-fd']) {
    const { result: r, trace } = await childPilot(t, 'fixed', fault); bounded(r, trace);
    assert.equal(trace.faultFired, true, 'owned private state fault was not exercised');
    if (fault === 'observer-fd') assert.ok(trace.fdFailureReads > 0, 'independent readonly FD failure did not reach an observer read/stat');
    phase(r.before, 1); phase(r.after, 2); assert.equal(r.verificationGate.exitCode, 2);
  }
  const { run } = api(), valid = await run({ candidate: 'fixed', activeConsent: true, timeoutMs: 3000 });
  const base = valid.verification.checks.find((c: any) => c.id === CHECK); assert.ok(base?.apiWriteStateEvidence);
  const mutate: Array<(c: any) => void> = [
    c => { delete c.apiWriteStateEvidence; },
    c => { c.id = 'fixture:unrelated-check'; },
    c => { c.apiWriteStateEvidence.extraBody = CANARY; },
    c => { c.apiWriteStateEvidence.ledger.extraBody = CANARY; },
    c => { c.apiWriteStateEvidence.ledger.steps[0].body = CANARY; },
    c => { c.apiWriteStateEvidence.lineage.unexpectedSha256 = 'd'.repeat(64); },
    c => { c.apiWriteStateEvidence.lineage.runId = CANARY; },
    c => { c.apiWriteStateEvidence.lineage.runtimeVersion = CANARY; },
    c => { c.apiWriteStateEvidence.counts.httpAttempts = 0; },
  ];
  for (const change of mutate) {
    const check = JSON.parse(JSON.stringify(base)); check.status = 'completed'; change(check);
    const report = createReport([check], 'api', '2026-10-13T00:00:00Z');
    assert.equal(evaluateGate(report).exitCode, 2, 'malformed/absent write proof became pass');
    assert.equal(toAgentReport(report).scanGate.exitCode, 2);
    const formats = [JSON.stringify(report), JSON.stringify(toAgentReport(report)), toMarkdown(report), JSON.stringify(toSarif(report))];
    for (const text of formats) assert.equal(text.includes(CANARY), false, 'unknown evidence metadata leaked into a public format');
    let comparison: ReturnType<typeof compareReports> | undefined;
    try { comparison = compareReports(valid.verification, report); }
    catch (error) {
      assert.ok(error instanceof Error, 'untyped comparison failure is not a documented refusal');
      assert.equal(error.message, 'Invalid scan report', 'arbitrary comparison errors cannot satisfy fail-closed evidence');
    }
    if (comparison) assert.equal(comparison.comparable, false);
  }
  const observed = valid.before.report.checks.find((c: any) => c.id === CHECK);
  assert.equal(observed.apiWriteStateEvidence.effect, 'observed');
  assert.equal(evaluateGate(createReport([observed], 'api', '2026-10-13T00:00:00Z'), 'none').exitCode, 0,
    'none still suppresses the threshold of a valid completed observation');
  for (const change of [
    (check: any) => { check.findings = []; },
    (check: any) => { check.findings.forEach((finding: any) => { finding.severity = 'low'; }); },
  ]) {
    const check = JSON.parse(JSON.stringify(observed)); change(check);
    const report = createReport([check], 'api', '2026-10-13T00:00:00Z');
    assert.equal(evaluateGate(report).exitCode, 2, 'observed effect without its blocking observation was laundered into pass');
    assert.equal(evaluateGate(report, 'none').exitCode, 2, 'none cannot conceal malformed observed-effect evidence');
    assert.equal(toAgentReport(report).scanGate.exitCode, 2);
    assert.match(toMarkdown(report), /Scan gate: incomplete; exit 2/);
    assert.equal(toSarif(report).runs[0].invocations[0].executionSuccessful, false);
  }
  const spurious = JSON.parse(JSON.stringify(base));
  assert.equal(spurious.apiWriteStateEvidence.effect, 'not_observed');
  spurious.findings = JSON.parse(JSON.stringify(observed.findings));
  const contradicted = createReport([spurious], 'api', '2026-10-13T00:00:00Z');
  assert.equal(evaluateGate(contradicted).exitCode, 2, 'completed not-observed evidence accepted a contradictory observed-effect finding');
  assert.equal(evaluateGate(contradicted, 'none').exitCode, 2); assert.equal(toAgentReport(contradicted).scanGate.exitCode, 2);
  assert.match(toMarkdown(contradicted), /Scan gate: incomplete; exit 2/);
  assert.equal(toSarif(contradicted).runs[0].invocations[0].executionSuccessful, false);
});

test('api write independent: no write retry after lost response, abort prohibits new requests, consent and budgets remain explicit', async t => {
  const { run } = api();
  for (const options of [{ candidate: 'fixed' }, { candidate: 'fixed', activeConsent: false },
    { candidate: 'fixed', activeConsent: true, timeoutMs: 30001 }, { candidate: 'fixed', activeConsent: true, url: 'http://127.0.0.1:1' }]) {
    await assert.rejects(() => run(options), 'invalid consent/target/budget must not execute');
  }
  const pre = await childPilot(t, 'fixed', 'pre-abort'); bounded(pre.result, pre.trace);
  assert.equal(pre.trace.requests.length, 0); assert.equal(pre.result.verificationGate.exitCode, 2);
  const active = await childPilot(t, 'fixed', 'abort-owner-response'); bounded(active.result, active.trace);
  assert.equal(active.trace.faultFired, true); assert.equal(active.trace.requests.filter((x: any) => x.method === 'PATCH').length, 1);
  assert.equal(active.result.verificationGate.exitCode, 2); assert.equal(active.result.after, null);
  const lost = await childPilot(t, 'ineffective', 'lost-peer-response'); bounded(lost.result, lost.trace);
  assert.equal(lost.trace.faultFired, true); assert.equal(lost.result.verificationGate.exitCode, 2);
  const peer = lost.trace.requests.filter((x: any) => x.phase === 1 && x.method === 'PATCH' && x.actor === 1);
  assert.equal(peer.length, 1, 'ambiguous peer PATCH was retried'); assert.equal(peer[0].persistedTitle, true);
  assert.equal(lost.result.after.evidence.effect, 'observed');
  assert.ok(lost.result.after.report.checks.flatMap((c: any) => c.findings).some((f: any) => f.severity === 'high'), 'actual peer effect was erased by lost response');
});

async function publicArtifacts(directory: string) {
  const names = ['report.json', 'agent-report.json', 'report.md', 'report.sarif'], outputs: Record<string, string> = {};
  for (const phase of ['before', 'after', 'verification']) for (const name of names) outputs[phase + '/' + name] = await readFile(join(directory, phase, name), 'utf8');
  return outputs;
}
function artifactCoherence(outputs: Record<string, string>, digests: any, gates: number[]) {
  for (const [index, name] of ['before', 'after', 'verification'].entries()) {
    const report = JSON.parse(outputs[name + '/report.json']), agent = JSON.parse(outputs[name + '/agent-report.json']);
    assert.equal(sha(outputs[name + '/report.json']), digests[name]); assert.equal(agent.reportArtifact.digest, digests[name]);
    assert.equal(agent.scanGate.exitCode, gates[index]); assert.equal(evaluateGate(report).exitCode, gates[index]);
    assert.ok(outputs[name + '/report.md'].includes('exit ' + gates[index]));
    assert.equal(JSON.parse(outputs[name + '/report.sarif']).runs[0].invocations[0].executionSuccessful, gates[index] !== 2);
  }
}
async function manifestCoherence(directory: string, outputs: Record<string, string>, runId: string, attemptId: string) {
  const text = await readFile(join(directory, 'api-write-manifest.json'), 'utf8'), manifest = JSON.parse(text);
  assert.deepEqual(Object.keys(manifest).sort(), ['version', 'scope', 'runId', 'deliveryAttemptId', 'artifacts'].sort());
  assert.equal(manifest.version, 1); assert.equal(manifest.scope, SCOPE); assert.equal(manifest.runId, runId); assert.equal(manifest.deliveryAttemptId, attemptId);
  const paths = ['before', 'after', 'verification'].flatMap(phase =>
    ['report.json', 'agent-report.json', 'report.md', 'report.sarif'].map(name => phase + '/' + name));
  assert.deepEqual(manifest.artifacts.map((entry: any) => entry.path), paths);
  for (const entry of manifest.artifacts) {
    assert.deepEqual(Object.keys(entry).sort(), ['path', 'bytes', 'sha256'].sort());
    assert.equal(entry.bytes, Buffer.byteLength(outputs[entry.path], 'utf8')); assert.equal(entry.sha256, sha(outputs[entry.path]));
  }
  const marker = JSON.parse(await readFile(join(directory, 'api-write-delivery.json'), 'utf8'));
  assert.equal(marker.manifestSha256, sha(text)); return marker;
}
test('api write independent: atomic redacted delivery/CLI gates retain original phases and cannot replay on storage retry or mutable result', async t => {
  const top = await folder(t), { run, deliver } = api();
  const emit = Server.prototype.emit; let arrivals = 0;
  t.mock.method(Server.prototype, 'emit', function (this: Server, event: string, ...args: unknown[]) {
    if (event === 'request') arrivals++;
    return Reflect.apply(emit, this, [event, ...args]);
  });
  const result = await run({ candidate: 'ineffective', activeConsent: true, timeoutMs: 3000 });
  const frozen = JSON.stringify(result), out = join(top, 'delivered'), requestCount = arrivals;
  // Either deep immutability or retained canonical authority must prevent caller
  // mutation from changing the delivery verdict and bytes.
  try { result.verificationGate.exitCode = 0; } catch {}
  try { result.verification.checks[0].notes.push(CANARY); } catch {}
  const receipt = await deliver(result, { outDir: out });
  assert.equal(receipt.status, 'delivered'); assert.equal(receipt.finalExitCode, 1); assert.equal(receipt.verificationExitCode, 1);
  assert.equal(receipt.apiReexecuted, false);
  const directory = join(out, receipt.outputRelativePath), outputs = await publicArtifacts(directory);
  artifactCoherence(outputs, receipt.reportDigests, [1, 1, 1]);
  for (const text of Object.values(outputs)) assert.equal(text.includes(CANARY), false);
  const marker = await manifestCoherence(directory, outputs, receipt.runId, receipt.deliveryAttemptId);
  assert.equal(marker.status, 'publication_only'); assert.equal(marker.requiresCallerAcknowledgement, true); assert.equal(marker.provesFinalProcessExit, false);
  assert.deepEqual(marker.reportDigests, receipt.reportDigests);
  assert.equal(receipt.artifactSha256, sha(JSON.stringify(JSON.parse(frozen), null, 2) + '\n'));
  const sentinel = join(out, 'sentinel'); await writeFile(sentinel, CANARY);
  const second = await deliver(result, { outDir: out });
  assert.equal(second.status, 'delivered'); assert.equal(second.finalExitCode, 1);
  assert.notEqual(second.deliveryAttemptId, receipt.deliveryAttemptId);
  assert.equal(second.artifactSha256, receipt.artifactSha256); assert.deepEqual(second.reportDigests, receipt.reportDigests);
  assert.equal(second.apiReexecuted, false); assert.equal(arrivals, requestCount);
  assert.deepEqual(await publicArtifacts(directory), outputs, 'new delivery replaced the earlier bundle');
  assert.equal(await readFile(sentinel, 'utf8'), CANARY);
  let calls = 0;
  const failed = await deliver(result, { storage: { async put(_key: string, bytes: Uint8Array) { calls++; bytes.fill(0); throw Error('owned storage failure'); } } });
  assert.equal(failed.finalExitCode, 2); assert.equal(failed.apiReexecuted, false);
  const retried = await deliver(result, { storage: { async put(_key: string, bytes: Uint8Array) { calls++; assert.equal(sha(Buffer.from(bytes).toString()), receipt.artifactSha256); } } });
  assert.equal(retried.finalExitCode, 1); assert.equal(retried.apiReexecuted, false); assert.equal(calls, 2);
  assert.equal(arrivals, requestCount, 'delivery/storage retry performed HTTP');
  // Private builtin UUID collision, only around delivery of an already completed
  // result. Existing OUT roots are allowed; occupied FINAL attempts are not.
  const originalUUID = crypto.randomUUID;
  crypto.randomUUID = (() => receipt.deliveryAttemptId) as typeof crypto.randomUUID;
  syncBuiltinESMExports();
  try {
    const rejected = await deliver(result, { outDir: out });
    assert.equal(rejected.finalExitCode, 2, 'occupied final attempt must not be replaced');
    assert.equal(rejected.apiReexecuted, false);
  } finally { crypto.randomUUID = originalUUID; syncBuiltinESMExports(); }
  assert.deepEqual(await publicArtifacts(directory), outputs, 'failed final collision deleted/replaced an earlier bundle');
  assert.equal(await readFile(sentinel, 'utf8'), CANARY); assert.equal(arrivals, requestCount);
  // Late local publication fault, not a new public SDK fault flag. Staged report
  // files can finish, but the unique final-directory rename must fail atomically.
  const rename = fsp.rename; let publicationFaults = 0;
  fsp.rename = (async (from, to) => {
    const target = String(to);
    if (dirname(target) === resolve(out, result.runId) && /^[a-f0-9-]{36}$/.test(basename(target))) {
      publicationFaults++; throw Object.assign(Error('owned publication fault'), { code: 'EIO' });
    }
    return await rename(from, to);
  }) as typeof fsp.rename;
  syncBuiltinESMExports();
  try {
    const failedPublish = await deliver(result, { outDir: out });
    assert.equal(publicationFaults, 1, 'late final-directory publication boundary was not exercised');
    assert.equal(failedPublish.status, 'unknown'); assert.equal(failedPublish.finalExitCode, 2); assert.equal(failedPublish.apiReexecuted, false);
    await assert.rejects(readFile(join(out, failedPublish.outputRelativePath, 'api-write-delivery.json')), 'failed publication left a final success marker');
  } finally { fsp.rename = rename; syncBuiltinESMExports(); }
  assert.deepEqual(await publicArtifacts(directory), outputs); assert.equal(arrivals, requestCount);
  for (const candidate of ['fixed', 'ineffective', 'all-deny'] as const) {
    const { result: cli, trace, out: cliOut } = await childPilot(t, candidate, 'none', 'cli');
    const lines = cli.stdout.trim().split('\n'), summary = JSON.parse(lines.at(-1)!);
    const expected = candidate === 'fixed' ? 0 : candidate === 'ineffective' ? 1 : 2;
    assert.equal(cli.code, expected); assert.equal(summary.finalExitCode, expected); assert.equal(summary.verificationExitCode, expected);
    assert.equal(summary.scope, SCOPE); assert.equal(summary.delivery, 'delivered'); assert.equal(summary.commandStatus, 'completed');
    const path = join(cliOut, summary.outputRelativePath), files = await publicArtifacts(path);
    const publication = await manifestCoherence(path, files, summary.runId, summary.deliveryAttemptId);
    artifactCoherence(files, publication.reportDigests, [1, expected, expected]);
    for (const text of Object.values(files)) for (const secret of trace.markers) assert.equal(text.includes(secret), false, 'CLI report leaked a synthetic state/request marker');
  }
  // Actual narrow Action wrapper, not a dist CLI call mislabeled as Action QA.
  // Root's fresh-archive harness separately validates installed distribution.
  const action = resolve(process.cwd(), 'actions/api-write-state');
  assert.match(await readFile(join(action, 'action.yml'), 'utf8'), /node "\$WAKEIO_ACTION_PATH\/run\.mjs"/);
  for (const [candidate, expected] of [['fixed', 0], ['ineffective', 1], ['all-deny', 2]] as const) {
    const workspace = await folder(t), ghOutput = join(workspace, 'github-output'); await writeFile(ghOutput, '');
    const actual = await processResult([join(action, 'run.mjs')], { ...process.env, GITHUB_WORKSPACE: workspace,
      WAKEIO_ACTION_PATH: action, GITHUB_OUTPUT: ghOutput, GITHUB_STEP_SUMMARY: join(workspace, 'summary'),
      WAKEIO_WRITE_CANDIDATE: candidate, WAKEIO_WRITE_ACTIVE_CONSENT: 'true', WAKEIO_WRITE_TIMEOUT_MS: '3000', WAKEIO_WRITE_OUT: 'reports' });
    assert.equal(actual.code, expected, 'actual Action wrapper lost the process gate');
    const values = Object.fromEntries((await readFile(ghOutput, 'utf8')).trim().split('\n').map(line => {
      const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)];
    }));
    assert.equal(values['exit-code'], String(expected)); assert.equal(values['before-exit-code'], '1');
    assert.equal(values['after-exit-code'], String(expected)); assert.equal(values['verification-exit-code'], String(expected));
    assert.equal(values['delivery-status'], 'delivered');
    const canonicalWorkspace = await fsp.realpath(workspace), canonicalReport = await fsp.realpath(values['report-dir']);
    assert.equal(values['report-dir'], canonicalReport, 'Action must return its canonical current report path');
    assert.ok(canonicalReport.startsWith(canonicalWorkspace + sep), 'Action report must remain inside the actual owned workspace');
    const files = await publicArtifacts(values['report-dir']), publication = await manifestCoherence(values['report-dir'], files, values['run-id'], values['delivery-attempt-id']);
    artifactCoherence(files, publication.reportDigests, [1, expected, expected]);
    const wrapperReceipt = JSON.parse(await readFile(values.receipt, 'utf8'));
    assert.equal(wrapperReceipt.finalExitCode, expected); assert.equal(wrapperReceipt.childExitCode, expected);
    assert.equal(wrapperReceipt.acknowledgement, 'current_child_and_publication_verified');
  }
  const refusalWorkspace = await folder(t), refusalOutput = join(refusalWorkspace, 'outputs'); await writeFile(refusalOutput, '');
  const refused = await processResult([join(action, 'run.mjs')], { ...process.env, GITHUB_WORKSPACE: refusalWorkspace,
    GITHUB_OUTPUT: refusalOutput, WAKEIO_ACTION_PATH: action, WAKEIO_WRITE_CANDIDATE: 'fixed', WAKEIO_WRITE_ACTIVE_CONSENT: 'false',
    WAKEIO_WRITE_TIMEOUT_MS: '3000', WAKEIO_WRITE_OUT: 'reports' });
  assert.equal(refused.code, 2); assert.match(await readFile(refusalOutput, 'utf8'), /exit-code=2/);
  await assert.rejects(readFile(join(refusalWorkspace, 'reports/api-write-action-receipt.json')), 'refused Action dispatched or published output');
});
