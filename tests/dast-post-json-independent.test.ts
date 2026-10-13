import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { parseDastPolicy, runDast } from '../src/dast.js';
import { replayDastFinding } from '../src/dast-replay.js';
import { main } from '../src/cli.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';
import { compareReports, parseScanReport } from '../src/compare.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';

// Root froze actual SQLite truth before product execution: two INTEGER rows;
// concat results [2,1,2,0,2], bound results [2,1,0,0,2]. Never use the detector's
// result or the fixture mode label as the database/wire oracle. Target fixture
// is author-owned; no consumer source is imported, built or executed.
const MODULE = new URL('../../tests/fixtures/native-dast-post-json-sqlite.mjs', import.meta.url).href;
const ENV = 'OWNED_POST_JSON_AUTH', MARKER = 'owned-post-json-private-marker-3b5e';
const PLAN = ['identity-before', 'baseline-before', 'benign-alternate', 'true', 'false', 'baseline-after',
  'baseline-before', 'benign-alternate', 'true', 'false', 'baseline-after', 'identity-after'];
const SEEDS = ['1', '2', '1 AND 1=1', '1 AND 1=2', '1', '1', '2', '1 AND 1=1', '1 AND 1=2', '1'];
type Target = any;
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value));
async function fixture(mode = 'vulnerable'): Promise<Target> { return (await import(MODULE)).startPostJsonSqlite({ mode }); }
function policy(target: Target): any {
  return { version: 4, kind: 'sql-boolean-differential', profile: 'numeric', method: 'POST',
    baseUrl: target.origin + '/', url: target.url, parameter: 'minId',
    body: { minId: '1', marker: MARKER, pageSize: 2, enabled: true, empty: null },
    alternate: { value: '2', expected: 1 },
    oracle: { jsonPointer: '/count', expectedBaseline: 2, expectedTrue: 2, expectedFalse: 0 },
    authorizationEnv: ENV, identity: { path: '/whoami', status: 200, jsonPointer: '/principal', equals: target.principal } };
}
async function run(target: Target, extra: Record<string, unknown> = {}): Promise<any> {
  const [check] = await runDast({ policy: policy(target), consent: true, allowPrivate: true, env: { [ENV]: target.authorization }, ...extra } as any);
  assert.ok(check); return check;
}
function report(check: any): any { return createReport([check], 'url', '2026-10-13T00:00:00Z', { fingerprint: 'a'.repeat(64), ruleset: 'owned-post-json-independent' }); }
function gate(check: any, expected: number) {
  const value = report(check); assert.equal(evaluateGate(value).exitCode, expected); assert.equal(toAgentReport(value).scanGate.exitCode, expected);
  if (expected === 2) { assert.equal(evaluateGate(value, 'none').exitCode, 2); assert.equal(toSarif(value).runs[0].invocations[0].executionSuccessful, false); }
}
function noSecrets(text: string, target: Target) {
  for (const secret of [MARKER, target.authorization, target.authorization.slice(7), target.principal, ENV,
    '1 AND 1=1', '1 AND 1=2', '"expectedBaseline":2', '"minId":"1"', 'SELECT count(*)', 'owned-first', 'owned-second']) {
    assert.equal(text.includes(secret), false, `public artifact leaked ${secret}`);
  }
}
function stableDatabase(target: Target) {
  assert.deepEqual(target.state(), [{ id: 1, label: 'owned-first' }, { id: 2, label: 'owned-second' }]);
  assert.equal(target.stats.stateUnchanged, true);
  for (const q of target.queryLog) assert.deepEqual(q.stateBefore, q.stateAfter);
}
async function captured(fn: () => Promise<number>) {
  const stdout = process.stdout.write, stderr = process.stderr.write; let out = '', err = '';
  process.stdout.write = ((chunk: any) => { out += String(chunk); return true; }) as any;
  process.stderr.write = ((chunk: any) => { err += String(chunk); return true; }) as any;
  try { return { code: await fn(), out, err }; } finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}

test('post JSON independent: real SQLite concat/bound discriminate 1/0 with alternate input and exact twelve-request wire plan', async () => {
  for (const [mode, expected, counts] of [['vulnerable', 1, [2, 1, 2, 0, 2, 2, 1, 2, 0, 2]], ['bound', 0, [2, 1, 0, 0, 2, 2, 1, 0, 0, 2]]] as const) {
    const target = await fixture(mode);
    try {
      assert.equal(parseDastPolicy(policy(target)).policy.version, 4);
      const check = await run(target); assert.equal(check.status, 'completed'); gate(check, expected);
      const e = check.dastExecution; assert.equal(e.version, 4); assert.equal(e.method, 'POST'); assert.equal(e.profile, 'numeric');
      assert.equal(e.authentication, 'authorization'); assert.equal(e.profileRevision, 'sql-boolean-json-auth-v4');
      assert.equal(e.plannedRequests, 12); assert.equal(e.counts.httpAttempts, 12); assert.deepEqual(e.steps.map((s: any) => s.phase), PLAN);
      assert.deepEqual(e.identityControls, { before: 'matched', after: 'matched' });
      assert.deepEqual(e.normalControls, { round1: 'matched', round2: 'matched' });
      assert.equal(e.probeOutcome, expected ? 'observed' : 'not_observed');
      const requests = target.requests, posts = requests.filter((r: any) => r.method === 'POST');
      assert.equal(requests.length, 12); assert.equal(posts.length, 10);
      assert.deepEqual(requests.map((r: any) => r.path), ['/whoami', ...Array(10).fill('/search'), '/whoami']);
      assert.deepEqual(posts.map((r: any) => r.body.minId), SEEDS); assert.deepEqual(target.queryLog.map((q: any) => q.count), counts);
      for (const r of requests) assert.equal(r.authorization, target.authorization);
      for (const p of posts) { assert.equal(p.bodyType, 'object'); assert.match(p.contentType, /^application\/json/);
        assert.equal(p.requestBytes, Buffer.byteLength(p.rawBody)); assert.ok(p.requestBytes <= 4096);
        assert.deepEqual({ ...p.body, minId: '1' }, policy(target).body); }
      if (expected) { assert.equal(check.findings.length, 1); assert.equal(check.findings[0].kind, 'candidate'); assert.equal(check.findings[0].confidence, 'medium'); }
      else assert.deepEqual(check.findings, []);
      stableDatabase(target); noSecrets(JSON.stringify(report(check)), target);
    } finally { await target.close(); }
    assert.equal(target.socketCount, 0);
  }
});

test('post JSON independent: ignored field, canned response, all-deny and validation rejection never certify normal/fixed success', async () => {
  for (const mode of ['field-ignored', 'constant', 'all-deny', 'validation-reject', 'echo', 'malformed']) {
    const target = await fixture(mode);
    try {
      const check = await run(target); gate(check, 2); assert.equal(check.status, 'partial'); assert.deepEqual(check.findings, []);
      assert.ok(target.stats.postRequests > 0 && target.stats.postRequests < 10); stableDatabase(target);
      if (mode === 'field-ignored' || mode === 'constant') {
        assert.deepEqual(target.requests.filter((r: any) => r.method === 'POST').map((r: any) => r.body.minId), ['1', '2']);
        assert.equal(check.dastExecution.normalControls.round1, 'mismatched'); assert.equal(check.dastExecution.stopReason, 'benign_control_mismatch');
      }
    } finally { await target.close(); }
  }
});

test('post JSON independent: strict policy/body/auth options refuse traffic before preparation', async () => {
  const target = await fixture(); let invoked = 0;
  try {
    const valid = policy(target), changed: any[] = [
      { ...valid, method: 'PUT' }, { ...valid, url: target.url + '?minId=1' }, { ...valid, url: 'http://owned.invalid/search' },
      { ...valid, profile: 'single-quoted' }, { ...valid, parameter: 'missing' }, { ...valid, body: { ...valid.body, minId: 1 } },
      { ...valid, body: { ...valid.body, minId: '01' } }, { ...valid, body: { ...valid.body, nested: {} } },
      { ...valid, body: { ...valid.body, marker: 'x'.repeat(1025) } },
      { ...valid, alternate: { value: '1', expected: 1 } }, { ...valid, alternate: { value: '2', expected: 2 } },
      { ...valid, alternate: { value: '2 AND 1=1', expected: 1 } }, { ...valid, oracle: { ...valid.oracle, expectedTrue: 1 } },
      { ...valid, authorizationEnv: undefined }, { ...valid, identity: undefined }, { ...valid, extra: 'unsupported' },
      { ...valid, body: { minId: '1', ...Object.fromEntries(Array.from({ length: 16 }, (_, i) => ['k' + i, '1'])) } },
      { ...valid, body: { minId: '1', a: 'x'.repeat(1024), b: 'x'.repeat(1024), c: 'x'.repeat(1024), d: 'x'.repeat(1024) } },
    ];
    for (const key of ['__proto__', 'constructor', 'prototype']) {
      const body = { ...valid.body }; Object.defineProperty(body, key, { value: '1', enumerable: true }); changed.push({ ...valid, body });
    }
    for (const bad of changed) { assert.throws(() => parseDastPolicy(bad)); gate(await run(target, { policy: bad }), 2); }
    const getterBody = Object.defineProperty({ ...valid.body }, 'minId', { enumerable: true, get() { invoked++; return '1'; } });
    assert.throws(() => parseDastPolicy({ ...valid, body: getterBody }));
    const proxyBody = new Proxy(valid.body, { ownKeys() { invoked++; throw Error('must not reflect'); }, get() { invoked++; throw Error('must not read'); } });
    assert.throws(() => parseDastPolicy({ ...valid, body: proxyBody }));
    const authGetter = Object.defineProperty({}, ENV, { enumerable: true, get() { invoked++; return target.authorization; } });
    const authProxy = new Proxy({ [ENV]: target.authorization }, { getOwnPropertyDescriptor() { invoked++; throw Error('must not reflect'); } });
    for (const env of [{}, Object.create({ [ENV]: target.authorization }), authGetter, authProxy, { [ENV]: '' }, { [ENV]: target.authorization + '\r\nInjected:1' }]) gate(await run(target, { env }), 2);
    for (const extra of [{ consent: false }, { maxRequests: 0 }, { maxRequests: 65 }, { timeoutMs: 0 }]) gate(await run(target, extra), 2);
    assert.equal(invoked, 0); assert.equal(target.requests.length, 0);
  } finally { await target.close(); }
});

test('post JSON independent: selected template, alternate, oracle and environment are snapshotted before awaits', async () => {
  const target = await fixture(), p = policy(target), env = { [ENV]: target.authorization };
  try {
    const pending = run(target, { policy: p, env }); await target.firstRequest;
    p.body.minId = '999'; p.body.marker = 'mutated-body'; p.alternate.value = '888'; p.oracle.expectedBaseline = 999; p.identity.equals = 'mutated-principal'; env[ENV] = 'Bearer mutated';
    const check = await pending; gate(check, 1);
    const posts = target.requests.filter((r: any) => r.method === 'POST'); assert.deepEqual(posts.map((r: any) => r.body.minId), SEEDS);
    assert.ok(posts.every((r: any) => r.body.marker === MARKER)); assert.ok(target.requests.every((r: any) => r.authorization === target.authorization));
    stableDatabase(target);
  } finally { await target.close(); }
});

test('post JSON independent: identity-before failure permits no POST; failed trailing identity retains scoped evidence without replay authority', async () => {
  for (const mode of ['identity-before', 'identity-after']) {
    const target = await fixture(mode);
    try {
      const check = await run(target); gate(check, 2);
      assert.equal(target.stats.postRequests, mode === 'identity-before' ? 0 : 10);
      assert.equal(check.findings.length, mode === 'identity-before' ? 0 : 1);
      if (mode === 'identity-after') { assert.equal(check.findings[0].confidence, 'low'); assert.equal(check.dastExecution.probeOutcome, 'observed');
        const before = target.requests.length, r = report(check);
        const replay = await replayDastFinding({ report: r, policy: policy(target), findingId: r.checks[0].findings[0].id, consent: true, allowPrivate: true, env: { [ENV]: target.authorization } } as any);
        assert.equal(replay.outcome, 'refused'); assert.equal(target.requests.length, before); }
      stableDatabase(target);
    } finally { await target.close(); }
  }
});

test('post JSON independent: actual accepted POST with dropped reply is not retried', async () => {
  const target = await fixture('drop-response');
  try {
    const check = await run(target, { timeoutMs: 1000 }); gate(check, 2);
    assert.equal(target.stats.identityRequests, 1); assert.equal(target.stats.postRequests, 1); assert.equal(target.queryLog.length, 1);
    assert.equal(target.queryLog[0].count, 2); assert.equal(check.dastExecution.counts.httpAttempts, 2);
    assert.ok(check.dastExecution.steps.slice(2).every((s: any) => s.outcome === 'not_attempted')); stableDatabase(target);
  } finally { await target.close(); }
});

test('post JSON independent: pre-abort, in-flight abort and deadline prohibit later probes', async () => {
  const before = await fixture('hang'), pre = new AbortController(); pre.abort();
  try { gate(await run(before, { signal: pre.signal }), 2); assert.equal(before.requests.length, 0); } finally { await before.close(); }
  const target = await fixture('hang'), controller = new AbortController();
  try {
    const pending = run(target, { signal: controller.signal, timeoutMs: 5000 }); await target.firstPost; controller.abort();
    const check = await pending; gate(check, 2); assert.equal(check.dastExecution.stopReason, 'cancelled');
    assert.equal(target.stats.postRequests, 1); assert.equal(target.requests.length, 2); stableDatabase(target);
  } finally { await target.close(); }
  const timed = await fixture('hang');
  try { const check = await run(timed, { timeoutMs: 300 }); gate(check, 2); assert.equal(check.dastExecution.stopReason, 'deadline');
    assert.equal(timed.stats.postRequests, 1); assert.equal(timed.requests.length, 2); } finally { await timed.close(); }
});

test('post JSON independent: wire request cap, response bytes and redirects remain fail-closed', async () => {
  for (const limit of [11, 12, 13]) {
    const target = await fixture();
    try { const check = await run(target, { maxRequests: limit }); gate(check, limit < 12 ? 2 : 1);
      assert.equal(target.requests.length, Math.min(limit, 12)); assert.equal(check.dastExecution.counts.httpAttempts, Math.min(limit, 12)); stableDatabase(target); }
    finally { await target.close(); }
  }
  for (const mode of ['redirect', 'large-over', 'large-run']) {
    const target = await fixture(mode);
    try { const check = await run(target); gate(check, 2);
      assert.equal(target.requests.filter((r: any) => r.path === '/redirected').length, 0); assert.ok(target.stats.postRequests > 0 && target.stats.postRequests < 10);
      if (mode === 'redirect' || mode === 'large-over') assert.equal(target.stats.postRequests, 1); stableDatabase(target); }
    finally { await target.close(); }
  }
});

test('post JSON independent: four artifacts and agent advice preserve redacted normal/body-origin evidence', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-post-artifacts-')), target = await fixture();
  try {
    const check = await run(target), original = report(check), before = JSON.stringify(original); await writeReports(original, top);
    const json = await readFile(join(top, 'report.json'), 'utf8'), agent = JSON.parse(await readFile(join(top, 'agent-report.json'), 'utf8'));
    assert.equal(agent.reportArtifact.digest, createHash('sha256').update(json).digest('hex')); assert.equal(agent.scanGate.exitCode, 1);
    assert.deepEqual(agent.checks[0].dastExecution.normalControls, { round1: 'matched', round2: 'matched' });
    assert.equal(agent.checks[0].dastExecution.method, 'POST'); assert.equal(agent.findings[0].verification.state, 'not_run');
    assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false); assert.equal(agent.findings[0].verification.remediationVerified, false);
    for (const name of ['report.json', 'agent-report.json', 'report.md', 'report.sarif']) {
      const text = await readFile(join(top, name), 'utf8'); noSecrets(text, target);
      const visible = name === 'report.md' ? text.replace(/\\-/g, '-') : text;
      assert.ok(visible.includes('sql-boolean-json-auth-v4'), `${name} must individually retain the selected profile revision`);
    }
    const advice = projectAdviceContext(agent, true).input as any; noSecrets(JSON.stringify(advice), target);
    assert.deepEqual(advice.checks[0].nativeDast.normalControls, { round1: 'matched', round2: 'matched' }); assert.equal(advice.checks[0].nativeDast.method, 'POST');
    assert.equal(advice.findings[0].replayAvailable, true);
    assert.equal(JSON.stringify(original), before); assert.deepEqual(parseScanReport(JSON.parse(json)), JSON.parse(json));
  } finally { await target.close(); await rm(top, { recursive: true, force: true }); }
});

test('post JSON independent: malformed or contradictory v4 ledger never launders observations into success', async () => {
  const target = await fixture();
  try {
    const check = await run(target), original = report(check);
    for (const mutate of [
      (c: any) => { c.findings = []; }, (c: any) => { c.dastExecution.method = 'GET'; },
      (c: any) => { c.dastExecution.profile = 'single-quoted'; }, (c: any) => { delete c.dastExecution.authentication; },
      (c: any) => { c.dastExecution.plannedRequests = 10; },
      (c: any) => { delete c.dastExecution.normalControls; }, (c: any) => { c.dastExecution.normalControls.round1 = 'mismatched'; },
      (c: any) => { c.dastExecution.steps[2].oracleMatch = 'baseline'; },
      (c: any) => { c.dastExecution.steps[2].phase = 'true'; }, (c: any) => { c.dastExecution.counts.httpAttempts = 11; },
      (c: any) => { c.dastExecution.steps[11].httpAttempts = 0; c.dastExecution.steps[11].httpStatus = null; },
      (c: any) => { const e = c.dastExecution; e.steps[1].httpAttempts = 2; for (const step of e.steps.slice(2)) step.attemptStart++;
        e.counts.httpAttempts = 13; e.maxRequests = 64; c.metrics.requestCount = 13; },
      (c: any) => { c.dastExecution.body = { raw: MARKER }; },
    ]) {
      const raw = copy(check); mutate(raw); const value = report(raw); assert.equal(evaluateGate(value, 'none').exitCode, 2);
      assert.equal(toAgentReport(value).scanGate.exitCode, 2); noSecrets(JSON.stringify(value), target); noSecrets(toMarkdown(value), target); noSecrets(JSON.stringify(toSarif(value)), target);
      let comparison: ReturnType<typeof compareReports> | undefined;
      try { comparison = compareReports(original, value); } catch (error) { assert.ok(error instanceof Error); assert.equal(error.message, 'Invalid scan report'); }
      if (comparison) assert.equal(comparison.comparable, false);
    }
  } finally { await target.close(); }
});

test('post JSON independent: same-origin replay requires body/alternate/identity identity and distinguishes bound fix', async () => {
  const target = await fixture();
  try {
    const original = report(await run(target)), originalBytes = JSON.stringify(original), p = policy(target), findingId = original.checks[0].findings[0].id;
    const stale = copy(original); stale.checks[0].dastExecution.normalControls.round1 = 'mismatched';
    const staleStart = target.requests.length;
    const staleReplay = await replayDastFinding({ report: stale, policy: p, findingId, consent: true, allowPrivate: true, env: { [ENV]: target.authorization } } as any);
    assert.equal(staleReplay.outcome, 'refused'); assert.equal(target.requests.length, staleStart);
    for (const mutate of [(x: any) => { x.body.pageSize = 3; }, (x: any) => { x.alternate.value = '3'; },
      (x: any) => { x.alternate.expected = 0; }, (x: any) => { x.identity.equals = 'other-owned-user'; }]) {
      const changed = copy(p); mutate(changed); const count = target.requests.length;
      const rejected = await replayDastFinding({ report: original, policy: changed, findingId, consent: true, allowPrivate: true, env: { [ENV]: target.authorization } } as any);
      assert.equal(rejected.outcome, 'refused'); assert.equal(target.requests.length, count);
    }
    const before = target.requests.length;
    const reproduced = await replayDastFinding({ report: original, policy: p, findingId, consent: true, allowPrivate: true, env: { [ENV]: target.authorization } } as any);
    assert.equal(reproduced.outcome, 'reproduced'); assert.equal(target.requests.length - before, 12);
    target.setMode('bound'); const fixedStart = target.requests.length;
    const fixed = await replayDastFinding({ report: original, policy: p, findingId, consent: true, allowPrivate: true, env: { [ENV]: target.authorization } } as any);
    assert.equal(fixed.outcome, 'not_reproduced'); assert.equal(target.requests.length - fixedStart, 12);
    assert.equal(JSON.stringify(original), originalBytes); stableDatabase(target);
  } finally { await target.close(); }
});

test('post JSON independent: public CLI preflight, process gate and report/replay paths use the selected JSON profile', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-post-cli-')), target = await fixture();
  const old = process.env[ENV]; process.env[ENV] = target.authorization;
  try {
    const file = join(top, 'policy.json'); await writeFile(file, JSON.stringify(policy(target)));
    const plan = await captured(() => main(['plan', '--dast-policy', file, '--allow-private'])); assert.equal(plan.code, 0); assert.equal(target.requests.length, 0); noSecrets(plan.out, target);
    const refusal = await captured(() => main(['scan', '--dast-policy', file, '--allow-private', '--tools', 'none', '--out', join(top, 'refusal')]));
    assert.equal(refusal.code, 2); assert.equal(target.requests.length, 0);
    const out = join(top, 'before'), args = ['scan', '--dast-policy', file, '--active-consent', '--allow-private', '--allowed-origin', target.origin, '--tools', 'none', '--out', out];
    assert.equal((await captured(() => main(args))).code, 1); assert.equal(target.requests.length, 12);
    const original = await readFile(join(out, 'report.json'), 'utf8'), agent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
    const finding = agent.findings[0]; assert.equal(agent.scanGate.exitCode, 1); assert.equal(agent.checks[0].dastExecution.version, 4);
    target.setMode('bound');
    const replay = await captured(() => main(['replay', '--report', join(out, 'report.json'), '--dast-policy', file, '--finding', finding.findingId,
      '--active-consent', '--allow-private', '--out', join(top, 'replayed')])); assert.equal(replay.code, 0); assert.equal(target.requests.length, 24);
    assert.equal(await readFile(join(out, 'report.json'), 'utf8'), original);
    for (const name of ['report.json', 'agent-report.json', 'report.md', 'report.sarif']) noSecrets(await readFile(join(out, name), 'utf8'), target);
  } finally { if (old === undefined) delete process.env[ENV]; else process.env[ENV] = old; await target.close(); await rm(top, { recursive: true, force: true }); }
});
