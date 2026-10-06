import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import dns from 'node:dns/promises';
import { syncBuiltinESMExports } from 'node:module';
import * as sdk from '../src/index.js';
import type { ApiExecutionLedger, ApiRunOptions, CheckResult } from '../src/index.js';

const ENV = { LEDGER_OWNER_AUTH: 'Bearer owner-private-sentinel', LEDGER_OTHER_AUTH: 'Bearer other-private-sentinel' };
const NOW = '2026-10-06T00:00:00.000Z';
function policy(baseUrl: string): any {
  return { version: 2, baseUrl, actors: [
    { id: 'OwnerPrivateLabel', authorizationEnv: 'LEDGER_OWNER_AUTH', identity: { path: '/private-identity', status: 200, jsonPointer: '/principal', equals: 'owner-principal-private' } },
    { id: 'OtherPrivateLabel', authorizationEnv: 'LEDGER_OTHER_AUTH', identity: { path: '/private-identity', status: 200, jsonPointer: '/principal', equals: 'other-principal-private' } },
    { id: 'anonymous' },
  ], cases: [{ id: 'CasePrivateLabel', path: '/private-resource', allow: { actor: 'OwnerPrivateLabel', status: 200,
    resource: { jsonPointer: '/id', equals: 'resource-private' }, protected: { jsonPointer: '/canary', equals: 'canary-private' } },
    deny: [{ actor: 'OtherPrivateLabel', statuses: [401, 403] }, { actor: 'anonymous', statuses: [401] }] }] };
}
const json = (response: ServerResponse, status: number, value: unknown) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); };
async function fixture(mode = 'safe', extra: Partial<ApiRunOptions> = {}) {
  const arrivals: string[] = [];
  const server = createServer((request, response) => {
    arrivals.push(request.url!);
    const owner = request.headers.authorization === ENV.LEDGER_OWNER_AUTH;
    const other = request.headers.authorization === ENV.LEDGER_OTHER_AUTH;
    if (mode === 'timeout') return; // Closed explicitly in finally, no background timer.
    if (request.url === '/private-identity') return json(response, 200, { principal: owner ? 'owner-principal-private' : 'other-principal-private' });
    if (mode === 'body-limit' && owner) { response.writeHead(200, { 'content-type': 'application/json' }); response.end('x'.repeat(2 * 1024 * 1024 + 1)); return; }
    if (owner) return json(response, mode === 'owner-failed' ? 503 : 200, { id: 'resource-private', canary: 'canary-private' });
    if (mode === 'exposure' && other) return json(response, 200, { id: 'resource-private', canary: 'canary-private' });
    return json(response, other && mode !== 'auth-lost' ? 403 : 401, { error: 'denied' });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const input = policy(`http://${['retries', 'attempt-budget'].includes(mode) ? 'localhost' : '127.0.0.1'}:${address.port}`);
  if (mode === 'attempt-budget') input.cases = Array.from({ length: 15 }, (_, index) => ({ ...input.cases[0], id: `case-${index}` }));
  const options: ApiRunOptions = { policy: input, env: ENV, allowPrivate: true, timeoutMs: 3000, ...extra };
  try { const preflight = sdk.preflightApiPolicy(options); const [check] = await sdk.runApiPolicy(options); return { check, preflight, arrivals, input }; }
  finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}
function ledger(check: CheckResult): ApiExecutionLedger { assert.ok(check.apiExecution); return check.apiExecution; }
function report(check: CheckResult) { return sdk.createReport([check], 'api', NOW, { fingerprint: 'a'.repeat(64), ruleset: sdk.RULESET_VERSION }); }
function rehash(value: any): void { value.planSha256 = createHash('sha256').update(JSON.stringify({ version: 1, policyVersion: value.policyVersion, plan: value.plan })).digest('hex'); }

test('execution ledger maps every preflight ordinal and actual HTTP attempt without extra requests', async () => {
  const { check, preflight, arrivals } = await fixture(); const value = ledger(check);
  assert.equal(check.status, 'completed'); assert.equal(value.status, 'complete');
  assert.deepEqual(value.plan, preflight.plan); assert.equal(value.planSha256, preflight.planSha256);
  assert.equal(arrivals.length, 8); assert.equal(check.metrics?.requestCount, 8);
  assert.deepEqual(value.counts, { planned: 8, evaluated: 8, inconclusive: 0, notAttempted: 0, httpAttempts: 8 });
  value.steps.forEach((step, ordinal) => { assert.equal(step.ordinal, ordinal); assert.equal(step.attemptStart, ordinal); assert.equal(step.httpAttempts, 1); assert.equal(step.outcome, 'evaluated'); });
  assert.deepEqual(sdk.sanitiseApiExecutionLedger(value), value);
});

test('owner control failure retains never-called deny and owner-after ordinals', async () => {
  const { check, arrivals } = await fixture('owner-failed'); const value = ledger(check);
  assert.equal(check.status, 'partial'); assert.equal(value.status, 'partial'); assert.equal(arrivals.length, 5);
  assert.deepEqual(value.steps.slice(3, 6).map(s => [s.ordinal, s.outcome, s.reason, s.httpAttempts, s.attemptStart]),
    [3, 4, 5].map(n => [n, 'not_attempted', 'prerequisite_failed', 0, 3]));
  assert.equal(value.steps[2].outcome, 'inconclusive'); assert.equal(value.steps[2].httpStatus, 503);
  assert.equal(value.steps[6].attemptStart, 3); assert.equal(value.counts.notAttempted, 3);
  assert.equal(sdk.evaluateGate(report(check), 'none').exitCode, 2);
});

test('authenticated 401 is inconclusive while anonymous denial remains evaluated', async () => {
  const { check } = await fixture('auth-lost'); const value = ledger(check);
  assert.equal(value.status, 'partial'); assert.equal(value.steps[3].outcome, 'inconclusive');
  assert.equal(value.steps[3].httpStatus, 401); assert.equal(value.steps[4].outcome, 'evaluated');
  assert.equal(value.counts.httpAttempts, 8); assert.equal(sdk.evaluateGate(report(check), 'none').exitCode, 2);
});

test('pre-cancellation keeps all planned rows but no HTTP attempts', async () => {
  const controller = new AbortController(); controller.abort();
  const { check, arrivals } = await fixture('safe', { signal: controller.signal }); const value = ledger(check);
  assert.equal(arrivals.length, 0); assert.equal(value.counts.httpAttempts, 0); assert.equal(value.counts.notAttempted, 8);
  assert.ok(value.steps.every(s => s.outcome === 'not_attempted' && s.httpStatus === null));
  assert.equal(value.steps[0].reason, 'cancelled'); assert.equal(check.status, 'partial');
});

test('deadline distinguishes an attempted inconclusive request from remaining unattempted steps', async () => {
  const { check, arrivals } = await fixture('timeout', { timeoutMs: 150 }); const value = ledger(check);
  assert.equal(arrivals.length, 1); assert.equal(value.steps[0].outcome, 'inconclusive');
  assert.equal(value.steps[0].reason, 'deadline'); assert.equal(value.steps[0].httpStatus, null);
  assert.equal(value.counts.httpAttempts, 1); assert.equal(value.counts.notAttempted, 7); assert.equal(value.status, 'partial');
});

test('body-limit stops later attempts and never fabricates a captured HTTP status', async () => {
  const { check, arrivals } = await fixture('body-limit'); const value = ledger(check);
  assert.equal(arrivals.length, 3); assert.equal(value.steps[2].outcome, 'inconclusive');
  assert.equal(value.steps[2].httpStatus, null); assert.equal(value.steps[2].reason, 'body_budget');
  assert.equal(value.counts.httpAttempts, 3); assert.equal(value.status, 'partial');
});

test('evaluated ledger preserves exposure finding and never promotes exploit or fix verification', async () => {
  const { check } = await fixture('exposure'); const value = ledger(check);
  assert.equal(value.status, 'complete'); assert.equal(value.steps[3].outcome, 'evaluated');
  const agent = sdk.toAgentReport(report(check)); assert.equal(agent.scanGate.exitCode, 1);
  assert.equal(agent.findings.length, 1); assert.equal(agent.findings[0].verification.state, 'not_run');
  assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
  assert.deepEqual(agent.checks[0].apiExecution, value);
});

test('redacted plan identity excludes all caller labels, target, assertion values and credentials', async () => {
  const { check, preflight, input } = await fixture(); const value = ledger(check);
  const rendered = JSON.stringify(value);
  for (const secret of ['OwnerPrivateLabel', 'OtherPrivateLabel', 'CasePrivateLabel', 'private-identity', 'private-resource',
    'LEDGER_OWNER_AUTH', 'LEDGER_OTHER_AUTH', 'owner-principal-private', 'other-principal-private',
    'resource-private', 'canary-private', ...Object.values(ENV), input.baseUrl]) assert.equal(rendered.includes(secret), false, secret);
  const changed = structuredClone(input); changed.baseUrl = 'https://other.example.test';
  changed.actors[0].identity.equals = 'a'; changed.actors[1].identity.equals = 'b'; changed.cases[0].allow.protected.equals = 'different';
  const second = sdk.preflightApiPolicy({ policy: changed, env: { LEDGER_OWNER_AUTH: 'Bearer next-owner', LEDGER_OTHER_AUTH: 'Bearer next-other' }, allowPrivate: true, timeoutMs: 3000 });
  assert.equal(second.planSha256, preflight.planSha256); // Deliberately not a target/policy/credential commitment.
  assert.notEqual(sdk.preflightApiPolicy({ policy: changed, env: ENV, allowPrivate: true, timeoutMs: 3001 }).planSha256, preflight.planSha256);
});

test('malformed or incompatible ledgers fail closed without preserving untrusted fields', async () => {
  const { check } = await fixture(); const valid = ledger(check);
  const changes: Array<(x: any) => void> = [
    x => x.version = 2, x => x.status = 'verified', x => x.planSha256 = '0'.repeat(64),
    x => x.steps.pop(), x => x.steps.push(x.steps[0]), x => x.steps[1].ordinal = 0,
    x => x.steps.reverse(), x => x.steps[1].attemptStart = 0, x => x.steps[0].httpAttempts = NaN,
    x => x.steps[0].httpAttempts = 65, x => x.steps[0].httpStatus = 600, x => x.steps[0].httpStatus = null,
    x => x.steps[0].outcome = 'not_attempted', x => x.steps[0].reason = 'untrusted-private-sentinel',
    x => x.counts.evaluated = 0, x => x.reasons = ['run_incomplete'], x => x.steps[0].headers = 'untrusted-private-sentinel',
    x => { delete x.steps[0]; }, x => x.plan.steps[0].method = 'POST',
    x => { x.plan.steps[1].actorIndex = 0; rehash(x); }, x => { x.plan.steps[5].actorIndex = 1; rehash(x); },
    x => { x.plan.steps[3].caseIndex = 1; rehash(x); }, x => { x.plan.maximumHttpAttempts = 65; rehash(x); },
    x => { x.plan.timeoutMs = 120001; rehash(x); }, x => x.plan.extra = 'untrusted-private-sentinel',
  ];
  for (const mutate of changes) {
    const input = structuredClone(valid); mutate(input); const result = sdk.sanitiseApiExecutionLedger(input);
    assert.equal(result.status, 'invalid', mutate.toString()); assert.deepEqual(result.reasons, ['invalid_ledger']);
    assert.equal(JSON.stringify(result).includes('untrusted-private-sentinel'), false);
    assert.deepEqual(sdk.sanitiseApiExecutionLedger(result), result);
  }
});

test('accessors, proxies, toJSON and non-data ledger objects never run', async () => {
  const { check } = await fixture(); const valid = ledger(check); let calls = 0;
  const getter = structuredClone(valid); Object.defineProperty(getter, 'version', { enumerable: true, get() { calls++; return 1; } });
  const proxy = new Proxy(valid, { get() { calls++; throw Error('getter'); }, ownKeys() { calls++; throw Error('keys'); } });
  const toJSON = { ...valid, toJSON() { calls++; return valid; } };
  for (const input of [getter, proxy, toJSON, Object.create(valid)]) assert.equal(sdk.sanitiseApiExecutionLedger(input).status, 'invalid');
  const outer = { ...check }; Object.defineProperty(outer, 'apiExecution', { enumerable: true, get() { calls++; return valid; } });
  assert.equal(sdk.createReport([outer], 'api', NOW).checks[0].apiExecution?.status, 'invalid'); assert.equal(calls, 0);
});

test('invalid ledger downgrades all public projections, retaining findings and artifact delivery', async () => {
  const { check } = await fixture('exposure');
  const invalid = { ...check, apiExecution: { version: 9, response: 'untrusted-private-sentinel' } as any };
  const safe = report(invalid); assert.equal(safe.checks[0].status, 'partial'); assert.equal(safe.checks[0].findings.length, 1);
  assert.equal(sdk.parseScanReport(safe).checks[0].status, 'partial');
  const agent = sdk.toAgentReport(safe); assert.equal(agent.scanGate.exitCode, 2); assert.equal(agent.checks[0].apiExecution?.status, 'invalid');
  for (const output of [JSON.stringify(safe), JSON.stringify(agent), JSON.stringify(sdk.toSarif(safe)), sdk.toMarkdown(safe)]) {
    assert.match(output, /invalid/); assert.equal(output.includes('untrusted-private-sentinel'), false);
  }
  const mismatch = report({ ...check, metrics: { ...check.metrics, requestCount: 1 } });
  assert.equal(mismatch.checks[0].apiExecution?.status, 'invalid');
});

test('comparison requires matching complete declared API plans and keeps partial absence unverified', async () => {
  const { check } = await fixture('exposure'); const before = report(check);
  const after = report({ ...check, findings: [] });
  assert.equal(sdk.compareReports(before, after).summary.not_observed, 1);
  const changed = structuredClone(after); changed.checks[0].apiExecution!.plan!.timeoutMs++;
  rehash(changed.checks[0].apiExecution);
  assert.equal(sdk.compareReports(before, changed).summary.unverified, 1);
  const legacy = structuredClone(after); delete legacy.checks[0].apiExecution;
  assert.equal(sdk.compareReports(before, legacy).comparable, false);
  const bothLegacy = structuredClone(before); delete bothLegacy.checks[0].apiExecution;
  assert.equal(sdk.compareReports(bothLegacy, legacy).summary.not_observed, 1);
  const broken = structuredClone(after); broken.checks[0].apiExecution!.steps.pop();
  assert.equal(sdk.compareReports(before, broken).summary.unverified, 1);
});

test('legacy reports without a ledger remain readable and are not retroactively attested', () => {
  const old: CheckResult = { id: 'api.authorization', status: 'completed', notes: [], findings: [] };
  const safe = sdk.parseScanReport(report(old)); assert.equal(safe.checks[0].status, 'completed');
  assert.equal(Object.hasOwn(safe.checks[0], 'apiExecution'), false);
  assert.equal(Object.hasOwn(sdk.toAgentReport(safe).checks[0], 'apiExecution'), false);
});


test('counted HTTP retries share the cap and never become extra logical plan steps', async () => {
  const original = dns.lookup;
  dns.lookup = (async () => [{ address: '127.0.0.2', family: 4 }, { address: '127.0.0.1', family: 4 }]) as unknown as typeof dns.lookup;
  syncBuiltinESMExports();
  try {
    const retried = await fixture('retries'); const first = ledger(retried.check);
    assert.equal(retried.arrivals.length, 8); assert.equal(first.steps.length, 8);
    assert.equal(first.counts.httpAttempts, 16); assert.ok(first.steps.every(step => step.httpAttempts === 2));
    assert.equal(first.status, 'complete');
    const bounded = await fixture('attempt-budget'); const second = ledger(bounded.check);
    assert.equal(second.plan?.logicalRequests, 64); assert.equal(second.counts.httpAttempts, 64);
    assert.equal(bounded.arrivals.length, 32); assert.equal(second.status, 'partial');
    assert.ok(second.steps.some(step => step.reason === 'request_budget' && step.outcome === 'not_attempted'));
    assert.equal(sdk.evaluateGate(report(bounded.check), 'none').exitCode, 2);
  } finally { dns.lookup = original; syncBuiltinESMExports(); }
});

test('offline verifier rejects hard HTTP and control-order contradictions even with recomputed hashes', async () => {
  const { check } = await fixture(); const valid = ledger(check);
  for (const index of [0, 2, 3]) for (const status of [101, 302, 401, 429, 500]) {
    const input = structuredClone(valid); input.steps[index].httpStatus = status;
    assert.equal(sdk.sanitiseApiExecutionLedger(input).status, 'invalid', `${index}:${status}`);
  }
  const actors = structuredClone(valid); actors.plan!.actorCount = 32; rehash(actors);
  assert.equal(sdk.sanitiseApiExecutionLedger(actors).status, 'invalid');
  const order = structuredClone(valid); order.steps[2].outcome = 'inconclusive'; order.steps[2].reason = 'assertion_inconclusive';
  order.status = 'partial'; order.counts.evaluated!--; order.counts.inconclusive!++; order.reasons = ['run_incomplete', 'incomplete_steps'];
  assert.equal(sdk.sanitiseApiExecutionLedger(order).status, 'invalid');
  for (const reason of ['body_budget', 'cancelled', 'deadline', 'request_budget', 'assertion_inconclusive'] as const) {
    const input = structuredClone(valid); input.status = 'partial'; input.steps[0].outcome = 'inconclusive';
    input.steps[0].reason = reason; input.steps[0].httpStatus = null;
    input.counts.evaluated!--; input.counts.inconclusive!++; input.reasons = ['run_incomplete', 'incomplete_steps'];
    assert.equal(sdk.sanitiseApiExecutionLedger(input).status, 'invalid', reason);
  }
  const identity = structuredClone(valid); identity.status = 'partial'; identity.steps[1].outcome = 'inconclusive';
  identity.steps[1].reason = 'assertion_inconclusive'; identity.steps[1].httpStatus = 401;
  identity.counts.evaluated!--; identity.counts.inconclusive!++; identity.reasons = ['run_incomplete', 'incomplete_steps'];
  assert.equal(sdk.sanitiseApiExecutionLedger(identity).status, 'invalid');
});

test('blocked private target preserves zero-attempt indexed coverage without any connection', async () => {
  const [check] = await sdk.runApiPolicy({ policy: policy('https://127.0.0.1:9'), env: ENV }); const value = ledger(check);
  assert.equal(value.status, 'partial'); assert.equal(value.counts.httpAttempts, 0); assert.equal(value.counts.notAttempted, 8);
  assert.equal(value.steps[0].reason, 'network_policy'); assert.equal(sdk.evaluateGate(report(check), 'none').exitCode, 2);
});
