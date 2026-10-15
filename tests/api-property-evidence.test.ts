import test from 'node:test';
import assert from 'node:assert/strict';
import type { ApiPropertyWriteEvidence, CheckResult } from '../src/contracts.js';
import { API_PROPERTY_CHECK, API_PROPERTY_RULE, apiPropertySteps, parseApiPropertyWriteEvidence, unknownApiPropertyWriteEvidence } from '../src/api-property-evidence.js';
import { createReport, exitCode, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { parseScanReport, compareReports } from '../src/compare.js';
import { projectAdviceContext, ADVICE_PROJECTION_POLICY_VERSION } from '../src/agent-advice-context.js';
const start = '2026-10-15T00:00:00.000Z';
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
function complete(effect: 'observed' | 'not_observed' = 'observed'): ApiPropertyWriteEvidence {
  const e = unknownApiPropertyWriteEvidence();
  e.execution = 'completed'; e.effect = effect; e.provisional = effect; e.policySha256 = 'a'.repeat(64);
  e.budget = { maxRequests: 23, timeoutMs: 30000, maxRequestBodyBytes: 4096, maxResponseBodyBytes: 65536, maxTotalResponseBytes: 1048576 };
  e.cleanup = 'confirmed'; e.stopReason = 'none'; e.reasons = []; e.ledger.status = 'complete';
  for (const key of Object.keys(e.controls) as Array<keyof typeof e.controls>) e.controls[key] = 'passed';
  for (const s of e.ledger.steps.slice(0, 22)) {
    s.attempted = true; s.outcome = 'evaluated'; s.httpStatus = s.ordinal === 4 || s.ordinal === 6 ? 412 : s.method === 'PATCH' ? 204 : 200;
  }
  e.counts = { plannedRequests: 22, httpAttempts: 22, patchAttempts: 8, capturedResponses: 22 }; return e;
}
function check(e: ApiPropertyWriteEvidence): CheckResult {
  return { id: API_PROPERTY_CHECK, status: e.execution === 'completed' ? 'completed' : 'partial', notes: [], propertyWriteEvidence: e,
    metrics: { httpAttempts: e.counts.httpAttempts, patchAttempts: e.counts.patchAttempts },
    findings: e.effect === 'observed' ? [{ ruleId: API_PROPERTY_RULE, title: 'Protected property effect observed', description: 'Privileged HTTP readback after fresh normal barrier.',
      severity: 'high', confidence: 'low', kind: 'candidate', remediation: 'Review property authorization and cleanup.', location: {} }] : [] };
}
function report(c: CheckResult) { return createReport([c], 'api', start, { fingerprint: 'b'.repeat(64), ruleset: 'property-test' }); }

test('complete HTTP readback retains candidate-only evidence in four formats and no automatic advice replay', () => {
  const e = complete(), r = report(check(e));
  assert.ok(parseApiPropertyWriteEvidence(e)); assert.equal(exitCode(r, 'high'), 1);
  assert.equal(parseScanReport(clone(r)).checks[0].propertyWriteEvidence?.effect, 'observed');
  const agent = toAgentReport(r);
  assert.equal(agent.checks[0].propertyWriteEvidence?.counts.httpAttempts, 22);
  assert.deepEqual(agent.findings[0].verification, { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
  const sarif = toSarif(r) as { runs: Array<{ properties: Record<string, unknown> }> };
  assert.ok(sarif.runs[0].properties.propertyWriteEvidence);
  assert.match(toMarkdown(r), /authenticated|API readback/); assert.match(toMarkdown(r), /Step 22: reconcile-read/);
  const advice = projectAdviceContext(agent, false);
  assert.equal(ADVICE_PROJECTION_POLICY_VERSION, 13);
  assert.equal(advice.input.checks[0].recheckRoute, 'review_check_diagnostics');
  assert.equal(advice.input.findings[0].recheckRoute, 'review_check_diagnostics');
  assert.equal(advice.input.findings[0].replayAvailable, false);
});

test('completed not-observed is scoped zero; 403 with effect is still a candidate and 200 without effect is zero', () => {
  const denied = complete(); denied.ledger.steps[14].httpStatus = 403;
  assert.ok(parseApiPropertyWriteEvidence(denied)); assert.equal(exitCode(report(check(denied)), 'high'), 1);
  const noEffect = complete('not_observed'); noEffect.ledger.steps[14].httpStatus = 200;
  assert.equal(exitCode(report(check(noEffect)), 'high'), 0);
  assert.equal(toAgentReport(report(check(noEffect))).findings.length, 0);
});

test('cleanup and trailing identity failures preserve already observed effect with partial gate two', () => {
  for (const stopAt of [18, 20, 21]) {
    const e = complete(); e.execution = 'partial'; e.ledger.status = 'partial'; e.stopReason = stopAt === 18 ? 'cleanup_failed' : 'identity_failed'; e.reasons = [e.stopReason];
    e.cleanup = stopAt === 18 ? 'unknown' : 'confirmed'; e.controls.identityAfter = 'failed';
    e.ledger.steps[stopAt].outcome = 'inconclusive'; e.ledger.steps[stopAt].reason = e.stopReason;
    for (let i = stopAt + 1; i < 22; i++) e.ledger.steps[i] = apiPropertySteps()[i];
    e.counts.httpAttempts = stopAt + 1; e.counts.capturedResponses = stopAt + 1;
    e.counts.patchAttempts = e.ledger.steps.filter(s => s.attempted && s.method === 'PATCH').length;
    assert.ok(parseApiPropertyWriteEvidence(e), `valid tail failure ${stopAt}`);
    const r = report(check(e)); assert.equal(exitCode(r, 'none'), 2);
    assert.equal(r.checks[0].propertyWriteEvidence?.effect, 'observed'); assert.equal(r.checks[0].findings.length, 1);
    assert.equal(parseScanReport(clone(r)).checks[0].status, 'partial');
  }
});

test('provisional match cannot become effect without all fresh barrier prerequisites', () => {
  for (const key of ['identityBefore', 'ownerResource', 'ownerPrecondition', 'verifierPrecondition', 'normal', 'positive', 'restore', 'freshness'] as const) {
    const e = complete(); e.controls[key] = 'unknown'; assert.equal(parseApiPropertyWriteEvidence(e), undefined, key);
  }
  for (const step of [4, 6, 9, 11, 13, 15, 16, 17]) {
    const e = complete(); e.ledger.steps[step].outcome = 'inconclusive'; e.ledger.steps[step].reason = 'response_invalid';
    assert.equal(parseApiPropertyWriteEvidence(e), undefined, String(step));
  }
});

test('fixed plan, status, budget, count and closed nested evidence mutations fail closed', () => {
  const mutations: Array<(e: any) => void> = [
    e => { e.ledger.steps[4].httpStatus = 204; }, e => { e.ledger.steps[14].httpStatus = 401; },
    e => { e.ledger.steps[0].actorIndex = 1; }, e => { e.ledger.steps.reverse(); }, e => { e.ledger.steps.pop(); },
    e => { e.budget.maxRequests = 21; }, e => { e.budget.timeoutMs = null; }, e => { e.budget.maxResponseBodyBytes = 65537; },
    e => { e.ledger.maximumHttpAttempts = 24; }, e => { e.counts.patchAttempts = 7; }, e => { e.counts.capturedResponses = 21; },
    e => { e.ledger.steps[22].attempted = true; }, e => { e.controls.freshness = 'passed-by-status'; },
    e => { e.extraBody = 'private-sentinel'; }, e => { e.ledger.steps[0].etag = 'private-sentinel'; },
    e => { e.controls.rawIdentity = 'private-sentinel'; }, e => { e.policySha256 = 'private-sentinel'; },
    e => { e.stopReason = 'none'; e.execution = 'partial'; e.ledger.status = 'partial'; },
  ];
  for (const mutate of mutations) {
    const e = complete(); mutate(e); assert.equal(parseApiPropertyWriteEvidence(e), undefined);
    const r = report(check(e)); assert.equal(exitCode(r, 'none'), 2);
    assert.equal(JSON.stringify(r).includes('private-sentinel'), false);
  }
});

test('evidence getters, proxies, cycles and source-bearing extras are never evaluated or retained', () => {
  let reads = 0;
  const accessor = complete(); Object.defineProperty(accessor, 'effect', { enumerable: true, get() { reads++; throw Error('private'); } });
  assert.equal(parseApiPropertyWriteEvidence(accessor), undefined); assert.equal(reads, 0);
  assert.equal(parseApiPropertyWriteEvidence(new Proxy(complete(), { ownKeys() { reads++; throw Error('private'); } })), undefined); assert.equal(reads, 0);
  const c: any = complete(); c.self = c; assert.equal(parseApiPropertyWriteEvidence(c), undefined);
  const raw: any = check(complete()); Object.defineProperty(raw, 'propertyWriteEvidence', { enumerable: true, get() { reads++; throw Error('private'); } });
  assert.equal(exitCode(report(raw), 'none'), 2); assert.equal(reads, 0);
});

test('missing, foreign, inconsistent findings and count metrics cannot produce a completed check', () => {
  const mutations: Array<(c: CheckResult) => void> = [
    c => { delete c.propertyWriteEvidence; }, c => { c.id = 'other-check'; }, c => { c.findings = []; },
    c => { c.findings.push(clone(c.findings[0])); }, c => { c.findings[0].kind = 'observation'; },
    c => { c.findings[0].confidence = 'high'; }, c => { c.metrics!.httpAttempts = 21; }, c => { delete c.metrics; },
  ];
  for (const mutate of mutations) { const c = check(complete()); mutate(c); assert.equal(exitCode(report(c), 'none'), 2); }
  const spurious = check(complete('not_observed')); spurious.findings = check(complete()).findings;
  assert.equal(exitCode(report(spurious), 'none'), 2);
  const privateMetrics = check(complete()); privateMetrics.metrics!.authorizationEnv = 'private-env-sentinel'; privateMetrics.metrics!.url = 'https://private-sentinel.example/secret';
  const r = report(privateMetrics); assert.equal(exitCode(r, 'high'), 1); assert.doesNotMatch(JSON.stringify(r), /private-env-sentinel|private-sentinel/);
});

test('one readonly reconcile after an ambiguous PATCH remains partial unknown, never cleanup or effect proof', () => {
  const e = unknownApiPropertyWriteEvidence('write_ambiguous'); e.budget = clone(complete().budget); e.policySha256 = 'a'.repeat(64); e.cleanup = 'unknown';
  for (const s of e.ledger.steps.slice(0, 5)) { s.attempted = true; s.httpStatus = s.ordinal === 4 ? null : 200; s.outcome = s.ordinal === 4 ? 'inconclusive' : 'evaluated'; s.reason = s.ordinal === 4 ? 'write_ambiguous' : 'none'; }
  Object.assign(e.ledger.steps[22], { attempted: true, outcome: 'inconclusive', httpStatus: 200, reason: 'write_ambiguous' });
  e.counts = { plannedRequests: 22, httpAttempts: 6, patchAttempts: 1, capturedResponses: 5 };
  assert.ok(parseApiPropertyWriteEvidence(e)); assert.equal(exitCode(report(check(e)), 'none'), 2);
  const forged = clone(e); forged.effect = 'observed'; assert.equal(parseApiPropertyWriteEvidence(forged), undefined);
  for (const cause of ['cancelled', 'deadline', 'body_limit'] as const) {
    const stopped = clone(e); stopped.stopReason = cause; stopped.reasons = [cause]; stopped.ledger.steps[4].reason = cause;
    assert.equal(parseApiPropertyWriteEvidence(stopped), undefined, `no reconcile after ${cause}`);
    stopped.ledger.steps[22] = apiPropertySteps()[22]; stopped.counts.httpAttempts--; stopped.counts.capturedResponses--;
    assert.ok(parseApiPropertyWriteEvidence(stopped), `retain legitimate ${cause} without extra HTTP`);
  }
  const cancelledRead = clone(e); cancelledRead.ledger.steps[22].reason = 'cancelled'; cancelledRead.ledger.steps[22].httpStatus = null;
  cancelledRead.counts.capturedResponses--;
  assert.ok(parseApiPropertyWriteEvidence(cancelledRead), 'cancellation during already dispatched reconciliation is valid partial');

  const retried = clone(e); Object.assign(retried.ledger.steps[6], { attempted: true, outcome: 'evaluated', httpStatus: 412 });
  assert.equal(parseApiPropertyWriteEvidence(retried), undefined);
});

test('comparison binds declared policy and does not turn missing or incomplete evidence into a fixed result', () => {
  const before = report(check(complete())), after = report(check(complete('not_observed')));
  const same = compareReports(before, after); assert.equal(same.comparable, true); assert.equal(same.summary.not_observed, 1);
  const changed = clone(after); changed.checks[0].propertyWriteEvidence!.policySha256 = 'c'.repeat(64);
  assert.equal(compareReports(before, changed).comparable, false);
  const budgetChanged = clone(after); budgetChanged.checks[0].propertyWriteEvidence!.budget.timeoutMs = 20000;
  assert.equal(compareReports(before, budgetChanged).comparable, false);
  const incomplete = report(check(unknownApiPropertyWriteEvidence('cancelled')));
  assert.equal(compareReports(before, incomplete).comparable, false);
  const malformed = clone(after); delete malformed.checks[0].propertyWriteEvidence;
  assert.throws(() => parseScanReport(malformed), /Invalid scan report/);
});

test('ambiguous cleanup permits one readonly reconcile while retaining established effect and candidate', () => {
  for (const effect of ['observed', 'not_observed'] as const) {
    const e = complete(effect); e.execution = 'partial'; e.ledger.status = 'partial'; e.cleanup = 'unknown';
    e.stopReason = 'transport_error'; e.reasons = ['transport_error']; e.controls.identityAfter = 'not_run';
    Object.assign(e.ledger.steps[18], { outcome: 'inconclusive', httpStatus: null, reason: 'transport_error' });
    for (let i = 19; i < 22; i++) e.ledger.steps[i] = apiPropertySteps()[i];
    Object.assign(e.ledger.steps[22], { attempted: true, outcome: 'inconclusive', httpStatus: 200, reason: 'write_ambiguous' });
    e.counts = { plannedRequests: 22, httpAttempts: 20, patchAttempts: 8, capturedResponses: 19 };
    assert.ok(parseApiPropertyWriteEvidence(e));
    const r = report(check(e)); assert.equal(exitCode(r, 'none'), 2);
    assert.equal(r.checks[0].propertyWriteEvidence?.effect, effect); assert.equal(r.checks[0].findings.length, effect === 'observed' ? 1 : 0);
    assert.equal(parseScanReport(clone(r)).checks[0].propertyWriteEvidence?.effect, effect);
  }
});
