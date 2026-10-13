import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { runDast, parseDastPolicy } from '../src/dast.js';
import { replayDastFinding, dastReplayExitCode } from '../src/dast-replay.js';
import { createReport, exitCode, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';
import { sanitizeDastExecution } from '../src/dast-execution.js';
import type { CheckResult } from '../src/contracts.js';

const secret = 'Bearer owned-quoted-credential-582c';
const principal = 'owned-quoted-principal-582c';
const envName = 'OWNED_QUOTED_AUTH_582C';
const textSeed = 'owned-quoted-name-582c';
const identityPath = '/owned-identity-582c';
const identityPointer = '/principal582c';
const suffixes = ["' AND '1'='1", "' AND '1'='2"];

/** Actual SQLite evaluates the supplied value. Modes change binding or response controls, never regex SQL proof. */
async function fixture(seed = textSeed, authenticated = false, initialMode = 'concat') {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE items (name TEXT NOT NULL)');
  db.prepare('INSERT INTO items VALUES (?)').run(seed);
  let mode = initialMode, token = secret, identityCount = 0, sqlCount = 0;
  const requests: Array<{ path: string; value: string | null; retained: string | null; authorization: string | undefined }> = [];
  let firstResolve!: () => void;
  const firstRequest = new Promise<void>(resolve => { firstResolve = resolve; });
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    requests.push({ path: url.pathname, value: url.searchParams.get('name'), retained: url.searchParams.get('keep'), authorization: request.headers.authorization });
    if (requests.length === 1) firstResolve();
    const json = (status: number, value: unknown) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); };
    if (request.method !== 'GET') return json(405, {});
    if (authenticated && request.headers.authorization !== token) return json(401, {});
    if (url.pathname === identityPath) {
      identityCount++;
      if (mode === 'wrong-principal' || mode === 'expire-after' && identityCount > 1) return json(200, { principal582c: 'wrong-owned-principal' });
      return json(200, { principal582c: principal });
    }
    if (url.pathname !== '/items') return json(404, {});
    sqlCount++;
    if (mode === 'slow') { setTimeout(() => { if (!response.destroyed) json(200, { count: 1 }); }, 150); return; }
    if (mode === 'error') return json(500, { error: 'owned-query-error' });
    if (mode === 'redirect') { response.writeHead(302, { location: '/other' }); response.end(); return; }
    if (mode === 'malformed') { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{'); return; }
    if (mode === 'oversize') return json(200, { padding: 'x'.repeat(128 * 1024), count: 1 });
    try {
      const value = url.searchParams.get('name');
      const row = mode === 'bound' ? db.prepare('SELECT COUNT(*) AS count FROM items WHERE name = ?').get(value)
        : mode === 'ignored' ? db.prepare('SELECT COUNT(*) AS count FROM items').get()
          : db.prepare(`SELECT COUNT(*) AS count FROM items WHERE name = '${value}'`).get();
      return json(200, { count: mode === 'drift' && sqlCount === 4 ? 2 : row!.count });
    } catch { return json(500, { error: 'owned-query-error' }); }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  const url = new URL('/items', origin); url.searchParams.set('name', seed);
  return { origin, url: url.href, requests, firstRequest,
    setMode(value: string) { mode = value; identityCount = 0; sqlCount = 0; }, setToken(value: string) { token = value; },
    async close() { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); db.close(); } };
}
type Target = Awaited<ReturnType<typeof fixture>>;
function policy(target: Target, authenticated = false) {
  return { version: 3, kind: 'sql-boolean-differential', baseUrl: `${target.origin}/`, url: target.url,
    parameter: 'name', profile: 'single-quoted', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 },
    ...(authenticated ? { authorizationEnv: envName, identity: { path: identityPath, status: 200, jsonPointer: identityPointer, equals: principal } } : {}) };
}
async function scan(target: Target, authenticated = false, extra: Record<string, unknown> = {}) {
  const [check] = await runDast({ policy: policy(target, authenticated), consent: true, allowPrivate: true,
    ...(authenticated ? { env: { [envName]: secret } } : {}), ...extra } as unknown as Parameters<typeof runDast>[0]);
  assert.ok(check); publicEvidence(check); return check;
}
function report(check: CheckResult) { return createReport([check], 'url', new Date()); }
function ledger(check: CheckResult): any { assert.ok(check.dastExecution); return check.dastExecution; }
function publicEvidence(check: CheckResult) {
  const r = report(check);
  const outputs = [JSON.stringify(r), JSON.stringify(toAgentReport(r)), JSON.stringify(toSarif(r)), toMarkdown(r), JSON.stringify(projectAdviceContext(toAgentReport(r), true))];
  for (const value of outputs) for (const forbidden of [secret, secret.slice(7), createHash('sha256').update(secret).digest('hex'),
    textSeed, principal, envName, identityPath, identityPointer, ...suffixes, "SELECT COUNT(*) AS count FROM items WHERE name = '", 'owned-query-error']) {
    assert.equal(value.includes(forbidden), false, `public evidence leaked synthetic sentinel ${forbidden}`);
  }
}

test('independent existing numeric profile misses quoted numeric-looking data without claiming a clean service', { timeout: 30000 }, async () => {
  const target = await fixture('1');
  try {
    const numeric = { ...policy(target), version: 1, profile: 'numeric' };
    const [check] = await runDast({ policy: numeric, consent: true, allowPrivate: true } as unknown as Parameters<typeof runDast>[0]);
    assert.ok(check); assert.equal(check.status, 'completed'); assert.equal(ledger(check).outcome, 'not_observed');
    assert.equal(exitCode(report(check), 'high'), 0); assert.equal(target.requests.length, 8); publicEvidence(check);
  } finally { await target.close(); }
});

test('independent quoted SQLite vulnerable/fixed/ignored pairs use the exact repeated approved mutation', { timeout: 30000 }, async () => {
  for (const seed of ['1', textSeed]) for (const authenticated of [false, true]) for (const mode of ['concat', 'bound', 'ignored']) {
    const target = await fixture(seed, authenticated, mode);
    try {
      assert.equal(parseDastPolicy(policy(target, authenticated)).policy.version, 3);
      const check = await scan(target, authenticated); const e = ledger(check);
      assert.equal(check.status, 'completed', `${seed}/${authenticated}/${mode}`);
      assert.equal(e.version, 3); assert.equal(e.authentication, authenticated ? 'authorization' : 'none');
      assert.equal(e.profile, 'single-quoted'); assert.equal(e.plannedRequests, authenticated ? 10 : 8);
      assert.equal(e.counts.httpAttempts, authenticated ? 10 : 8);
      assert.equal(e.outcome, mode === 'concat' ? 'observed' : 'not_observed');
      assert.equal(exitCode(report(check), 'high'), mode === 'concat' ? 1 : 0);
      assert.deepEqual(target.requests.filter(row => row.path === '/items').map(row => row.value),
        [seed, seed + suffixes[0], seed + suffixes[1], seed, seed, seed + suffixes[0], seed + suffixes[1], seed]);
      assert.deepEqual(target.requests.map(row => row.path), authenticated ? [identityPath, ...Array(8).fill('/items'), identityPath] : Array(8).fill('/items'));
      assert.ok(target.requests.every(row => row.authorization === (authenticated ? secret : undefined)));
      if (authenticated) assert.deepEqual(e.identityControls, { before: 'matched', after: 'matched' });
      else { assert.equal(e.identityControls, undefined); assert.equal(e.probeOutcome, undefined); }
      assert.equal(check.findings.length, mode === 'concat' ? 1 : 0);
      if (mode === 'concat') {
        const finding = check.findings[0]!;
        assert.equal(finding.kind, 'candidate'); assert.equal(finding.ruleId, 'dast.sql-boolean-differential');
        assert.equal(finding.severity, 'high'); assert.equal(finding.confidence, 'medium');
        assert.equal(finding.location.url?.split('?')[0], `${target.origin}/items`);
      }
    } finally { await target.close(); }
  }
});

test('independent invalid quoted seeds and incomplete auth declaration refuse before traffic', { timeout: 30000 }, async () => {
  const target = await fixture();
  try {
    for (const seed of ['', ' ', 'x'.repeat(129), "O'Reilly", 'a\\b', 'a\nb', 'é', 'a\x7fb']) {
      const url = new URL(target.url); url.searchParams.set('name', seed);
      const check = await scan(target, false, { policy: { ...policy(target), url: url.href } });
      assert.equal(exitCode(report(check), 'none'), 2); assert.equal(target.requests.length, 0);
    }
    for (const candidate of [{ ...policy(target), authorizationEnv: envName }, { ...policy(target), identity: policy(target, true).identity },
      { ...policy(target), url: target.url + '&name=other' }, { ...policy(target), profile: 'auto' }]) {
      const check = await scan(target, false, { policy: candidate });
      assert.equal(exitCode(report(check), 'none'), 2); assert.equal(target.requests.length, 0);
    }
    for (const seed of ['x'.repeat(128), 'a b', 'a"b']) {
      const url = new URL(target.url); url.searchParams.set('name', seed);
      assert.equal(parseDastPolicy({ ...policy(target), url: url.href }).policy.version, 3);
    }
  } finally { await target.close(); }
});

test('independent quoted encoding preserves ordinary double quotes, percent, plus, spaces and other query values', { timeout: 30000 }, async () => {
  for (const seed of ['a"b', 'a%b', 'a+b', 'a b']) {
    const target = await fixture(seed);
    try {
      const url = new URL(target.url); url.searchParams.set('keep', 'owned+retained% value');
      let accesses = 0;
      const env = new Proxy({}, { getOwnPropertyDescriptor() { accesses++; throw Error('unauth must not inspect env'); }, get() { accesses++; throw Error('unauth must not inspect env'); } });
      const check = await scan({ ...target, url: url.href }, false, { env });
      assert.equal(check.status, 'completed'); assert.equal(ledger(check).outcome, 'observed');
      assert.equal(accesses, 0); assert.equal(target.requests.length, 8);
      assert.ok(target.requests.every(row => row.retained === 'owned+retained% value'));
      assert.deepEqual(target.requests.map(row => row.value), [seed, seed + suffixes[0], seed + suffixes[1], seed, seed, seed + suffixes[0], seed + suffixes[1], seed]);
    } finally { await target.close(); }
  }
});

test('independent v3 ledger rejects phase, count, revision and authentication graft or stripping', { timeout: 30000 }, async () => {
  for (const authenticated of [false, true]) {
    const target = await fixture(textSeed, authenticated);
    try {
      const check = await scan(target, authenticated); const original = ledger(check);
      const mutations: Array<(e: any) => void> = [
        e => { e.steps[1].phase = 'false'; }, e => { e.steps[1].ordinal = 9; },
        e => { e.counts.httpAttempts++; }, e => { e.plannedRequests = authenticated ? 8 : 10; },
        e => { e.profileRevision = 'sql-boolean-numeric-v1'; }, e => { e.authentication = authenticated ? 'none' : 'authorization'; },
        e => { if (authenticated) delete e.identityControls; else e.identityControls = { before: 'matched', after: 'matched' }; },
        e => { if (authenticated) delete e.probeOutcome; else e.probeOutcome = 'observed'; },
      ];
      for (const mutate of mutations) {
        const forged = structuredClone(original); mutate(forged);
        assert.equal(sanitizeDastExecution(forged), null);
        const r = report({ ...check, dastExecution: forged });
        assert.equal(exitCode(r, 'none'), 2); assert.equal(r.checks[0]!.findings.length, 0);
      }
    } finally { await target.close(); }
  }
});

test('independent quoted finding identity differs from numeric evidence at the same rule and URL', { timeout: 30000 }, async () => {
  const target = await fixture('1');
  try {
    const quoted = await scan(target); assert.equal(quoted.findings.length, 1);
    const numeric = structuredClone(quoted), numericLedger = ledger(numeric);
    numericLedger.version = 1; numericLedger.profile = 'numeric'; numericLedger.profileRevision = 'sql-boolean-numeric-v1'; delete numericLedger.authentication;
    assert.ok(sanitizeDastExecution(numericLedger));
    const quotedReport = report(quoted), numericReport = report(numeric);
    assert.equal(numericReport.checks[0]!.findings.length, 1);
    assert.notEqual(quotedReport.checks[0]!.findings[0]!.id, numericReport.checks[0]!.findings[0]!.id);
    assert.equal(quotedReport.checks[0]!.findings[0]!.ruleId, numericReport.checks[0]!.findings[0]!.ruleId);
    assert.deepEqual(quotedReport.checks[0]!.findings[0]!.location, numericReport.checks[0]!.findings[0]!.location);
  } finally { await target.close(); }
});

test('independent response controls and shared budgets never turn incomplete quoted scans clean', { timeout: 30000 }, async () => {
  for (const mode of ['drift', 'error', 'redirect', 'malformed', 'oversize']) {
    const target = await fixture(textSeed, false, mode);
    try {
      const check = await scan(target); assert.equal(check.status, 'partial', mode);
      assert.equal(exitCode(report(check), 'none'), 2); assert.equal(check.findings.length, 0);
    } finally { await target.close(); }
  }
  const target = await fixture();
  try {
    const check = await scan(target, false, { maxRequests: 7 });
    assert.equal(check.status, 'partial'); assert.equal(ledger(check).stopReason, 'request_budget');
    assert.equal(target.requests.length, 7); assert.equal(exitCode(report(check), 'none'), 2);
  } finally { await target.close(); }
});

test('independent quoted cancellation and timeout stop unfinished control sequences', { timeout: 30000 }, async () => {
  for (const cancel of [false, true]) {
    const target = await fixture(textSeed, false, 'slow');
    try {
      const controller = new AbortController();
      const pending = scan(target, false, { timeoutMs: cancel ? 2000 : 30, signal: controller.signal });
      if (cancel) {
        const first = await Promise.race([target.firstRequest.then(() => 'request'), pending.then(() => 'completed')]);
        assert.equal(first, 'request', 'quoted policy must be accepted and send its first request before cancellation');
        controller.abort();
      }
      const check = await pending;
      assert.equal(check.status, 'partial'); assert.equal(ledger(check).stopReason, cancel ? 'cancelled' : 'deadline');
      assert.equal(exitCode(report(check), 'none'), 2); assert.ok(target.requests.length <= 1);
    } finally { await target.close(); }
  }
});

test('independent quoted authenticated controls preserve partial evidence but never grant replay', { timeout: 30000 }, async () => {
  for (const mode of ['wrong-principal', 'expire-after', 'budget-nine']) {
    const target = await fixture(textSeed, true, mode);
    try {
      const check = await scan(target, true, mode === 'budget-nine' ? { maxRequests: 9 } : {});
      assert.equal(check.status, 'partial'); assert.equal(exitCode(report(check), 'none'), 2);
      assert.equal(ledger(check).probeOutcome, mode === 'wrong-principal' ? 'inconclusive' : 'observed');
      assert.equal(check.findings.length, mode === 'wrong-principal' ? 0 : 1);
      assert.equal(target.requests.length, mode === 'wrong-principal' ? 1 : mode === 'budget-nine' ? 9 : 10);
      if (mode !== 'wrong-principal') {
        assert.equal(check.findings[0]!.confidence, 'low'); const r = report(check);
        assert.equal(JSON.stringify(projectAdviceContext(toAgentReport(r), true)).includes('replay_native_finding_same_policy'), false);
        const before = target.requests.length;
        const result = await replayDastFinding({ report: r, policy: policy(target, true), findingId: r.checks[0]!.findings[0]!.id,
          consent: true, allowPrivate: true, env: { [envName]: secret } } as unknown as Parameters<typeof replayDastFinding>[0]);
        assert.equal(result.outcome, 'refused'); assert.equal(target.requests.length, before);
      }
    } finally { await target.close(); }
  }
});

test('independent quoted replay binds policy revision and fresh credentials while retaining original evidence', { timeout: 30000 }, async () => {
  for (const authenticated of [false, true]) {
    const target = await fixture(textSeed, authenticated);
    try {
      const check = await scan(target, authenticated); assert.equal(check.findings.length, 1);
      const original = report(check), bytes = JSON.stringify(original), findingId = original.checks[0]!.findings[0]!.id;
      const rotated = secret + '-rotated'; if (authenticated) target.setToken(rotated);
      const base = { report: original, policy: policy(target, authenticated), findingId, consent: true, allowPrivate: true,
        ...(authenticated ? { env: { [envName]: rotated } } : {}) };
      const replay = () => replayDastFinding(base as unknown as Parameters<typeof replayDastFinding>[0]);
      assert.equal((await replay()).outcome, 'reproduced');
      for (const mode of ['bound', 'error']) {
        target.setMode(mode); const result = await replay();
        assert.equal(result.outcome, mode === 'bound' ? 'not_reproduced' : 'inconclusive');
        assert.equal(dastReplayExitCode(result), mode === 'bound' ? 0 : 2);
      }
      const forged = structuredClone(original); (forged.checks[0]!.dastExecution as any).profileRevision = 'sql-boolean-numeric-v1';
      const before = target.requests.length;
      const refused = await replayDastFinding({ ...base, report: forged } as unknown as Parameters<typeof replayDastFinding>[0]);
      assert.equal(refused.outcome, 'refused'); assert.equal(target.requests.length, before);
      assert.equal(JSON.stringify(original), bytes);
    } finally { await target.close(); }
  }
});
