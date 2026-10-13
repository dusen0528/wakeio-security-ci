import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { parseDastPolicy, prepareDastPolicy, snapshotDastEnvironment, runDast, dastDefaultMaxRequests, dastProfileRevision,
  hasDastAuthentication, dastRequestPlan, type DastPolicyV1, type DastPolicyV2, type DastPolicyV3Unauth, type DastPolicyV3Auth } from '../src/dast.js';
import { sanitizeDastExecution, hasDastIdentityControls, isDastObservedEvidence, isDastReplayableExecution,
  type DastExecutionV3Unauth, type DastExecutionV3Auth } from '../src/dast-execution.js';

const numeric: DastPolicyV1 = { version: 1, kind: 'sql-boolean-differential', baseUrl: 'https://owned.example.test/',
  url: 'https://owned.example.test/items?id=1', parameter: 'id', profile: 'numeric',
  oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
const quoted = (): DastPolicyV3Unauth => ({ ...numeric, version: 3, profile: 'single-quoted' });
const authenticated = (): DastPolicyV3Auth => ({ ...quoted(), authorizationEnv: 'OWNED_QUOTED_AUTH',
  identity: { path: '/identity', status: 200, jsonPointer: '/principal', equals: 'owned-principal' } });

test('numeric v1/v2 normalization, hash envelope and profile defaults stay exact', () => {
  const canonical = '{"version":1,"kind":"sql-boolean-differential","baseUrl":"https://owned.example.test/","url":"https://owned.example.test/items?id=1","parameter":"id","profile":"numeric","oracle":{"jsonPointer":"/count","expectedBaseline":1,"expectedTrue":1,"expectedFalse":0}}';
  const first = parseDastPolicy(numeric);
  assert.equal(JSON.stringify(first.policy), canonical);
  assert.equal(first.policySha256, 'b05072fc6998789810b5733f999ff723566dcb10b02ca0fd23d18fe58ceb8d89');
  assert.equal(dastProfileRevision(first.policy), 'sql-boolean-numeric-v1'); assert.equal(dastDefaultMaxRequests(first.policy), 8);
  const auth: DastPolicyV2 = { ...numeric, version: 2, authorizationEnv: 'OWNED_QUOTED_AUTH', identity: authenticated().identity };
  const authCanonical = canonical.replace('"version":1', '"version":2').slice(0, -1)
    + ',"authorizationEnv":"OWNED_QUOTED_AUTH","identity":{"path":"/identity","status":200,"jsonPointer":"/principal","equals":"owned-principal"}}';
  const second = parseDastPolicy(auth);
  assert.equal(JSON.stringify(second.policy), authCanonical);
  assert.equal(second.policySha256, createHash('sha256').update('{"revision":"sql-boolean-numeric-auth-v2","policy":' + authCanonical + '}').digest('hex'));
  assert.equal(dastProfileRevision(second.policy), 'sql-boolean-numeric-auth-v2'); assert.equal(dastDefaultMaxRequests(second.policy), 10);
});

test('v3 explicitly binds quoted profile and strict optional authentication pair without reading unrelated env', () => {
  const plain = parseDastPolicy(quoted()), auth = parseDastPolicy(authenticated());
  assert.equal(dastProfileRevision(plain.policy), 'sql-boolean-single-quoted-v3'); assert.equal(dastDefaultMaxRequests(plain.policy), 8);
  assert.equal(dastProfileRevision(auth.policy), 'sql-boolean-single-quoted-auth-v3'); assert.equal(dastDefaultMaxRequests(auth.policy), 10);
  assert.notEqual(plain.policySha256, auth.policySha256); assert.notEqual(plain.policySha256, parseDastPolicy(numeric).policySha256);
  assert.equal(hasDastAuthentication(plain.policy), false); assert.equal(hasDastAuthentication(auth.policy), true);
  assert.equal(dastRequestPlan(plain.policy).length, 8);
  assert.deepEqual(dastRequestPlan(auth.policy).map(step => step.phase), ['identity-before', 'baseline-before', 'true', 'false', 'baseline-after', 'baseline-before', 'true', 'false', 'baseline-after', 'identity-after']);
  let reads = 0;
  const hostile = new Proxy({}, { get() { reads++; throw Error('must not read'); }, ownKeys() { reads++; throw Error('must not enumerate'); } });
  assert.equal(snapshotDastEnvironment(quoted(), hostile), undefined); assert.equal(reads, 0);
  const first = prepareDastPolicy(authenticated(), { env: { OWNED_QUOTED_AUTH: 'Bearer first' } });
  assert.deepEqual(first, prepareDastPolicy(authenticated(), { env: { OWNED_QUOTED_AUTH: 'Bearer rotated' } }));
  for (const input of [{ ...quoted(), authorizationEnv: 'OWNED_QUOTED_AUTH' }, { ...quoted(), identity: authenticated().identity },
    { ...quoted(), version: 1 }, { ...quoted(), version: 2 }, { ...numeric, version: 3 }, { ...quoted(), headers: { Authorization: 'private' } }]) assert.throws(() => parseDastPolicy(input));
});

test('decoded single-quoted seeds are bounded ASCII data, with no quoting or dialect escaping', () => {
  for (const seed of ['1', ' owned value ', 'double"quote', 'x'.repeat(128)]) {
    const value = parseDastPolicy({ ...quoted(), url: `https://owned.example.test/items?id=${encodeURIComponent(seed)}` });
    assert.equal(new URL(value.policy.url).searchParams.get('id'), seed);
  }
  for (const seed of ['', '  ', "private'quote", 'private\\escape', 'private\nline', 'private\0null', '\x7f', '한글', 'x'.repeat(129)]) {
    assert.throws(() => parseDastPolicy({ ...quoted(), url: `https://owned.example.test/items?id=${encodeURIComponent(seed)}` }), error => error instanceof Error && (!seed || !error.message.includes(seed)));
  }
  assert.throws(() => parseDastPolicy({ ...quoted(), url: 'https://owned.example.test/items?id=1&id=1' }));
});

// This owned fixture executes real in-memory SQLite only when a test explicitly starts it.
async function target(mode: 'vulnerable' | 'bound' | 'wrong-context' | 'expire-after' = 'vulnerable', auth = false) {
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(':memory:'); db.exec("CREATE TABLE items(label TEXT); INSERT INTO items VALUES ('1');");
  const requests: { path: string; value: string | null; authorization?: string }[] = [];
  let identities = 0;
  const server = createServer((request, response) => {
    const url = new URL(request.url!, 'http://owned.invalid');
    requests.push({ path: url.pathname, value: url.searchParams.get('id'), authorization: request.headers.authorization });
    const json = (status: number, value: unknown) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); };
    if (auth && request.headers.authorization !== 'Bearer owned-quoted-token') return json(401, { error: 'owned-auth' });
    if (url.pathname === '/identity') { identities++; return mode === 'expire-after' && identities > 1 ? json(401, { error: 'owned-expired' }) : json(200, { principal: 'owned-principal' }); }
    try {
      const value = url.searchParams.get('id');
      const row = mode === 'bound' ? db.prepare('SELECT COUNT(*) AS count FROM items WHERE label=?').get(value)
        : db.prepare(`SELECT COUNT(*) AS count FROM items WHERE label=${mode === 'wrong-context' ? value : `'${value}'`}`).get();
      return json(200, { count: row!.count });
    } catch { return json(500, { error: 'owned-query' }); }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  const policy = auth ? { ...authenticated(), baseUrl: `${origin}/`, url: `${origin}/items?id=1` } : { ...quoted(), baseUrl: `${origin}/`, url: `${origin}/items?id=1` };
  return { policy, requests, close: async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); db.close(); } };
}

test('quoted real SQLite positive and bound control produce eight or ten fixed probes without profile discovery', async () => {
  for (const auth of [false, true]) for (const mode of ['vulnerable', 'bound'] as const) {
    const owned = await target(mode, auth);
    try {
      const [check] = await runDast({ policy: owned.policy, consent: true, allowPrivate: true, env: { OWNED_QUOTED_AUTH: 'Bearer owned-quoted-token' } });
      assert.equal(check.status, 'completed'); assert.equal(check.findings.length, mode === 'vulnerable' ? 1 : 0);
      assert.equal(check.dastExecution?.outcome, mode === 'vulnerable' ? 'observed' : 'not_observed');
      assert.equal(check.dastExecution?.version, 3); assert.equal(check.dastExecution?.profile, 'single-quoted');
      assert.equal(check.metrics?.profileRevision, dastProfileRevision(owned.policy));
      assert.equal(check.dastExecution?.counts.httpAttempts, auth ? 10 : 8);
      const sql = owned.requests.filter(request => request.path === '/items');
      assert.deepEqual(sql.map(request => request.value), ['1', "1' AND '1'='1", "1' AND '1'='2", '1', '1', "1' AND '1'='1", "1' AND '1'='2", '1']);
      if (auth) assert.ok(owned.requests.every(request => request.authorization === 'Bearer owned-quoted-token'));
      const serialized = JSON.stringify(check);
      for (const privateValue of ["1' AND '1'", 'owned-quoted-token', 'owned-principal', 'OWNED_QUOTED_AUTH']) assert.equal(serialized.includes(privateValue), false);
      assert.deepEqual(sanitizeDastExecution(check.dastExecution), check.dastExecution);
    } finally { await owned.close(); }
  }
});

test('old numeric probes cannot observe the quoted-context positive, and wrong declared context stays incomplete', async () => {
  const owned = await target();
  try {
    const [old] = await runDast({ policy: { ...numeric, baseUrl: owned.policy.baseUrl, url: owned.policy.url }, consent: true, allowPrivate: true });
    assert.equal(old.status, 'completed'); assert.equal(old.findings.length, 0); assert.equal(old.dastExecution?.outcome, 'not_observed');
  } finally { await owned.close(); }
  const mismatch = await target('wrong-context');
  try {
    const [check] = await runDast({ policy: mismatch.policy, consent: true, allowPrivate: true });
    assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 0); assert.equal(check.dastExecution?.stopReason, 'response_invalid');
    assert.equal(mismatch.requests.length, 2);
  } finally { await mismatch.close(); }
});

function complete(auth: false): DastExecutionV3Unauth;
function complete(auth: true): DastExecutionV3Auth;
function complete(auth: boolean): DastExecutionV3Unauth | DastExecutionV3Auth {
  const policy = auth ? authenticated() : quoted();
  const common = { version: 3 as const, policySha256: 'a'.repeat(64), profile: 'single-quoted' as const,
    maxRequests: auth ? 10 : 8, timeoutMs: 30000, allowPrivate: true, status: 'complete' as const, outcome: 'observed' as const,
    counts: { evaluated: auth ? 10 : 8, inconclusive: 0, notAttempted: 0, httpAttempts: auth ? 10 : 8 }, stopReason: 'none' as const };
  const steps = dastRequestPlan(policy).map(step => ({ ...step, outcome: 'evaluated' as const, reason: 'evaluated' as const,
    attemptStart: step.ordinal, httpAttempts: 1, httpStatus: 200,
    oracleMatch: step.round === 0 ? 'unavailable' as const : step.phase === 'false' ? 'false' as const : 'baseline' as const }));
  return auth ? { ...common, authentication: 'authorization', profileRevision: 'sql-boolean-single-quoted-auth-v3', plannedRequests: 10, steps,
    identityControls: { before: 'matched', after: 'matched' }, probeOutcome: 'observed' }
    : { ...common, authentication: 'none', profileRevision: 'sql-boolean-single-quoted-v3', plannedRequests: 8,
      steps: steps.map(step => ({ ...step, round: step.round as 1 | 2, phase: step.phase as DastExecutionV3Unauth['steps'][number]['phase'] })) };
}

test('v3 strict ledger reconstructs authentication, phases and outcomes without legacy unknown-key normalization', () => {
  for (const input of [complete(false), complete(true)]) {
    assert.deepEqual(sanitizeDastExecution(input), input); assert.equal(isDastObservedEvidence(input), true); assert.equal(isDastReplayableExecution(input), true);
    assert.equal(hasDastIdentityControls(input), input.authentication === 'authorization');
    const mutations: Array<(value: any) => void> = [
      value => value.profile = 'numeric', value => value.profileRevision = 'sql-boolean-numeric-v1', value => value.authentication = 'inferred',
      value => value.extra = 'private-seed', value => value.counts.secret = 'private-seed', value => value.steps[0].url = 'private-seed',
      value => value.steps[1].ordinal = 7, value => value.steps[0].round = 1.5, value => value.steps[0].oracleMatch = 'other',
      value => value.counts.evaluated--, value => value.maxRequests = 7, value => { value.status = 'partial'; value.outcome = 'inconclusive'; value.stopReason = 'oracle_inconsistent'; },
    ];
    if (input.authentication === 'none') mutations.push(value => value.identityControls = { before: 'matched', after: 'matched' }, value => value.probeOutcome = 'observed');
    else mutations.push(value => delete value.identityControls, value => delete value.probeOutcome, value => value.identityControls.after = 'mismatched');
    for (const mutate of mutations) { const copy = structuredClone(input); mutate(copy); assert.equal(sanitizeDastExecution(copy), null); }
  }
});

test('quoted auth trailing identity and shared attempt budget preserve low probe evidence without replay authority', async () => {
  for (const [mode, budget] of [['expire-after', 10], ['vulnerable', 9]] as const) {
    const owned = await target(mode, true);
    try {
      const [check] = await runDast({ policy: owned.policy, consent: true, allowPrivate: true, maxRequests: budget, env: { OWNED_QUOTED_AUTH: 'Bearer owned-quoted-token' } });
      assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 1); assert.equal(check.findings[0].confidence, 'low');
      const execution = check.dastExecution; assert.ok(execution && hasDastIdentityControls(execution));
      assert.equal(execution.probeOutcome, 'observed'); assert.equal(execution.outcome, 'inconclusive');
      assert.equal(execution.identityControls.after, budget === 9 ? 'not_attempted' : 'inconclusive');
      assert.equal(isDastObservedEvidence(execution), true); assert.equal(isDastReplayableExecution(execution), false);
      assert.equal(owned.requests.length, budget);
    } finally { await owned.close(); }
  }
});

test('last quoted response evaluation cannot complete after deadline or caller cancellation', async t => {
  for (const cause of ['deadline', 'cancelled'] as const) {
    const owned = await target(), controller = new AbortController();
    let now = Date.now(), decoded = 0;
    const clock = t.mock.method(Date, 'now', () => now), originalDecode = TextDecoder.prototype.decode;
    const decoder = t.mock.method(TextDecoder.prototype, 'decode', function(this: TextDecoder, ...args: Parameters<TextDecoder['decode']>) {
      const text = originalDecode.apply(this, args);
      if (++decoded === 8) { if (cause === 'cancelled') controller.abort(); now += 30001; }
      return text;
    });
    try {
      const [check] = await runDast({ policy: owned.policy, consent: true, allowPrivate: true, signal: controller.signal });
      assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 0); assert.equal(check.dastExecution?.stopReason, cause);
      assert.equal(check.dastExecution?.counts.evaluated, 7); assert.equal(check.dastExecution?.counts.httpAttempts, 8);
    } finally { decoder.mock.restore(); clock.mock.restore(); await owned.close(); }
  }
});
