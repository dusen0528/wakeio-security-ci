import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDastPolicy, dastDefaultMaxRequests, dastRequestPlan } from '../src/dast.js';
import { sanitizeDastExecution, type DastExecutionV4 } from '../src/dast-execution.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';

const input = () => ({ version: 4, kind: 'sql-boolean-differential', profile: 'numeric', method: 'POST',
  baseUrl: 'https://owned.invalid/', url: 'https://owned.invalid/search', parameter: 'id',
  body: { id: '1', label: 'private-synthetic-body-marker', active: true, spare: null }, alternate: { value: '2', expected: 1 },
  oracle: { jsonPointer: '/count', expectedBaseline: 2, expectedTrue: 2, expectedFalse: 0 },
  authorizationEnv: 'OWNED_POST_AUTH', identity: { path: '/whoami', status: 200, jsonPointer: '/principal', equals: 'private-synthetic-identity-marker' } });

test('POST JSON policy binds all fixed scalar inputs and plans twelve steps without execution', () => {
  const parsed = parseDastPolicy(input());
  assert.equal(parsed.policy.version, 4);
  assert.equal(dastDefaultMaxRequests(parsed.policy), 12);
  const plan = dastRequestPlan(parsed.policy);
  assert.deepEqual(plan.map(step => step.phase), ['identity-before', 'baseline-before', 'benign-alternate', 'true', 'false', 'baseline-after', 'baseline-before', 'benign-alternate', 'true', 'false', 'baseline-after', 'identity-after']);
  for (const mutation of [() => ({ ...input(), body: { ...input().body, label: 'different-body' } }), () => ({ ...input(), alternate: { value: '3', expected: 1 } }), () => ({ ...input(), alternate: { value: '2', expected: 3 } })]) assert.notEqual(parseDastPolicy(mutation()).policySha256, parsed.policySha256);
  const body = input(); const frozen = parseDastPolicy(body); body.body.id = '9';
  assert.equal(frozen.policy.version === 4 && frozen.policy.body.id, '1');
});

test('POST JSON parser refuses unsupported bodies, protocols and controls', () => {
  for (const change of [ { method: 'GET' }, { url: 'https://owned.invalid/search?id=1' }, { profile: 'single-quoted' },
    { body: { id: 1 } }, { body: { id: '1', nested: {} } }, { body: { id: '1', list: [] } },
    { alternate: { value: '1', expected: 1 } }, { alternate: { value: '2', expected: 2 } },
    { body: { id: '1', label: 'x'.repeat(1025) } }, { headers: { 'x-owned': 'fixed' } },
    { body: Object.assign(Object.create(null), { id: '1', constructor: 'fixed' }) },
    { body: Object.fromEntries([['id', '1'], ...Array.from({ length: 16 }, (_, i) => [`field_${i}`, false])]) },
    { body: { id: '1', a: 'x'.repeat(1024), b: 'x'.repeat(1024), c: 'x'.repeat(1024), d: 'x'.repeat(1024) } } ]) assert.throws(() => parseDastPolicy({ ...input(), ...change }));
  const missing = input() as Record<string, unknown>; delete missing.authorizationEnv; assert.throws(() => parseDastPolicy(missing));
  let accessed = false; const accessor = input(); Object.defineProperty(accessor, 'body', { enumerable: true, get() { accessed = true; return { id: '1' }; } });
  assert.throws(() => parseDastPolicy(accessor)); assert.equal(accessed, false);
});

function ledger(): DastExecutionV4 {
  const parsed = parseDastPolicy(input());
  return { version: 4, method: 'POST', authentication: 'authorization', profile: 'numeric', profileRevision: 'sql-boolean-json-auth-v4', policySha256: parsed.policySha256,
    maxRequests: 12, timeoutMs: 30000, allowPrivate: false, status: 'complete', outcome: 'observed', probeOutcome: 'observed', plannedRequests: 12,
    identityControls: { before: 'matched', after: 'matched' }, normalControls: { round1: 'matched', round2: 'matched' }, stopReason: 'none',
    counts: { evaluated: 12, inconclusive: 0, notAttempted: 0, httpAttempts: 12 },
    steps: dastRequestPlan(parsed.policy).map(step => ({ ...step, outcome: 'evaluated', reason: 'evaluated', attemptStart: step.ordinal, httpAttempts: 1, httpStatus: 200,
      oracleMatch: step.round === 0 ? 'unavailable' : step.phase === 'benign-alternate' ? 'alternate' : step.phase === 'false' ? 'false' : 'baseline' })) };
}

test('POST JSON ledger rejects retries, extra raw data and contradictory normal proof', () => {
  assert.deepEqual(sanitizeDastExecution(ledger()), ledger());
  for (const raw of [{ ...ledger(), body: input().body }, { ...ledger(), method: 'GET' }, { ...ledger(), normalControls: { round1: 'mismatched', round2: 'matched' } }]) assert.equal(sanitizeDastExecution(raw), null);
  const retry = ledger(); retry.steps[1].httpAttempts = 2; assert.equal(sanitizeDastExecution(retry), null);
  const ignored = ledger(); ignored.steps[2].oracleMatch = 'baseline'; assert.equal(sanitizeDastExecution(ignored), null);
});

test('POST JSON public projections retain enums while omitting private request and oracle data', () => {
  const report = createReport([{ id: 'url.sql-boolean', status: 'completed', findings: [], notes: [], metrics: { requestCount: 12 }, dastExecution: ledger() }], 'url', new Date());
  assert.equal(evaluateGate(report, 'none').exitCode, 2, 'an observed ledger without its finding must remain incomplete');
  const formats = [JSON.stringify(report), JSON.stringify(toAgentReport(report)), JSON.stringify(toSarif(report)), toMarkdown(report)];
  for (const format of formats) {
    assert.match(format, /sql-boolean-json-auth-v4/);
    assert.doesNotMatch(format, /private-synthetic-body-marker|private-synthetic-identity-marker|OWNED_POST_AUTH|expectedBaseline/);
  }
  assert.match(formats[1], /normalControls/);
  assert.match(formats[3], /normal field-effect controls/);
});
