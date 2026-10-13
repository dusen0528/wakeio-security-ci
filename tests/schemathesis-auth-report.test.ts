import test from 'node:test';
import assert from 'node:assert/strict';
import type { CheckResult, ScanScope } from '../src/contracts.js';
import { SCHEMATHESIS_AUTH_REVISION, sanitiseSchemathesisAuth, type SchemathesisAuthEvidence } from '../src/schemathesis-auth.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { compareReports, parseScanReport } from '../src/compare.js';
import { ADVICE_PROJECTION_POLICY_VERSION, projectAdviceContext } from '../src/agent-advice-context.js';

// Producer-side typed-ledger regression tests only. No engine, target or model
// execution; independent integration acceptance is owned by a different author.
const NOW = '2026-10-13T00:00:00.000Z';
const EXTRA = 'owned-auth-report-extra-not-for-publication';
const copy = <T>(value: T): T => structuredClone(value);
function evidence(server = false): SchemathesisAuthEvidence {
  return {
    version: 1, profileRevision: SCHEMATHESIS_AUTH_REVISION, status: 'completed', stopReason: 'complete',
    policySha256: 'a'.repeat(64), schemaSha256: 'b'.repeat(64), workerSha256: 'c'.repeat(64),
    limits: { maxRequests: 8, timeoutMs: 30000, maxBodyBytes: 1024, maxTotalBytes: 8192 }, seed: 1,
    operations: [{ operation: 'GET /owned-private-operation', generatedRequests: 1, deniedRequests: 0 }],
    controls: [
      { ordinal: 1, phase: 'identity-before', operationIndex: null, outcome: 'matched', httpStatus: 200, attempt: 1 },
      { ordinal: 2, phase: 'anonymous-normal', operationIndex: 0, outcome: 'matched', httpStatus: 401, attempt: 2 },
      { ordinal: 3, phase: 'normal-before', operationIndex: 0, outcome: 'matched', httpStatus: 200, attempt: 3 },
      { ordinal: 4, phase: 'normal-after', operationIndex: 0, outcome: 'matched', httpStatus: 200, attempt: 5 },
      { ordinal: 5, phase: 'identity-after', operationIndex: null, outcome: 'matched', httpStatus: 200, attempt: 6 },
    ],
    requests: { attempted: 6, generated: 1, completedGenerated: 1, responseBytes: 128 },
    records: [{ ordinal: 1, operationIndex: 0, attempt: 4, status: server ? 500 : 200,
      check: server ? 'response_contract' : 'passed', inputFingerprint: 'e'.repeat(64),
      failures: server ? [{ rule: 'not_a_server_error', kind: 'server_error' }] : [] }],
    engineVersion: '4.2.0', runtime: { python: '3.12.13', hypothesis: '6.168.3', jsonschema: '4.26.0', requests: '2.34.2' },
  };
}
function check(server = false): CheckResult {
  const e = evidence(server);
  return { id: 'api.schemathesis', status: 'completed', notes: [], schemathesisAuthRequired: true, schemathesisAuth: e,
    metrics: { requestCount: e.requests.attempted }, findings: server ? [{
      ruleId: 'api.schemathesis.server_error', title: 'Generated request caused a server error', description: 'A generated GET returned 500.',
      severity: 'medium', confidence: 'high', kind: 'observation', location: { url: 'https://owned.invalid/owned-private-operation' },
      remediation: 'Review the operation and repeat the bounded controls.',
    }] : [] };
}
function scope(e = evidence()): ScanScope {
  return { fingerprint: 'd'.repeat(64), ruleset: 'auth-fixture-v1', projectId: 'owned/auth-report',
    schemathesisAuthPolicy: { profileRevision: e.profileRevision, policySha256: e.policySha256, schemaSha256: e.schemaSha256 } };
}
function report(c = check(), s: ScanScope | undefined = scope(c.schemathesisAuth)) { return createReport([c], 'api', NOW, s); }
function allFormats(r = report()) {
  return [JSON.stringify(sanitiseReport(r)), JSON.stringify(toAgentReport(r)), toMarkdown(r), JSON.stringify(toSarif(r))];
}

test('authenticated typed diagnostics preserve canonical fields in all four report formats', () => {
  const c = check(true);
  (c as unknown as Record<string, unknown>).authorizationEnv = EXTRA;
  c.metrics!.rawBody = EXTRA;
  const r = report(c), agent = toAgentReport(r, 'medium');
  assert.equal(evaluateGate(r, 'medium').exitCode, 1);
  assert.deepEqual(sanitiseSchemathesisAuth(evidence(true)), evidence(true));
  assert.deepEqual(r.checks[0].schemathesisAuth, evidence(true));
  assert.deepEqual(agent.checks[0].schemathesisAuth, evidence(true));
  assert.equal(agent.checks[0].schemathesisAuthRequired, true);
  const sarif = toSarif(r) as any;
  assert.deepEqual(sarif.runs[0].invocations[0].properties.schemathesisAuths[0].schemathesisAuth, evidence(true));
  for (const bytes of allFormats(r)) {
    assert.ok(bytes.includes(SCHEMATHESIS_AUTH_REVISION));
    assert.equal(bytes.includes(EXTRA), false);
  }
  assert.match(toMarkdown(r), /identity-before/);
  assert.match(toMarkdown(r), /Operation index 0: generated=1, denied=0/);
  assert.deepEqual(parseScanReport(r), sanitiseReport(r));
});

test('missing, malformed or contradictory authenticated diagnostics stay incomplete even with fail-on none', () => {
  const cases = [
    (c: CheckResult) => { delete c.schemathesisAuth; },
    (c: CheckResult) => { (c as any).schemathesisAuthRequired = false; },
    (c: CheckResult) => { (c.schemathesisAuth!.controls[0] as any).outcome = 'invented'; },
    (c: CheckResult) => { c.metrics!.requestCount = 5; },
    (c: CheckResult) => { c.metrics!.generatedRequests = 0; },
    (c: CheckResult) => { (c.schemathesisAuth as any).rawCredential = EXTRA; },
    (c: CheckResult) => { c.id = 'other'; },
  ];
  for (const change of cases) {
    const c = check(); change(c); const r = report(c);
    assert.equal(evaluateGate(r, 'none').exitCode, 2);
    assert.equal(toAgentReport(r, 'none').scanGate.exitCode, 2);
    assert.equal(r.checks[0].schemathesisAuthRequired, true);
    assert.equal(allFormats(r).join('').includes(EXTRA), false);
  }
  const raw = report(); raw.checks[0].metrics!.requestCount = 5;
  assert.throws(() => parseScanReport(raw), /Invalid scan report/);
  const invalid = report(); (invalid.checks[0].schemathesisAuth!.controls[0] as any).outcome = 'invented';
  assert.throws(() => parseScanReport(invalid), /Invalid scan report/);
});

test('explicit authenticated scope cannot disappear through public createReport scope sanitation', () => {
  const legacy: CheckResult = { id: 'api.schemathesis', status: 'completed', findings: [], notes: [], metrics: { requestCount: 1 } };
  for (const s of [scope(), { ...scope(), schemathesisAuthPolicy: { ...scope().schemathesisAuthPolicy!, policySha256: null } } as any]) {
    for (const checks of [[legacy], [{ ...legacy, id: 'other' }]]) {
      const r = createReport(checks, 'api', NOW, s);
      assert.equal(evaluateGate(r, 'none').exitCode, 2);
      assert.ok(toAgentReport(r).checks.some(c => c.checkId === 'api.schemathesis' && c.schemathesisAuthRequired));
    }
  }
  assert.equal(evaluateGate(createReport([legacy], 'api', NOW), 'none').exitCode, 0, 'legacy anonymous report unchanged');
});

test('completed failure records and finding kind/severity must agree without inventing findings', () => {
  for (const change of [
    (c: CheckResult) => { c.findings = []; },
    (c: CheckResult) => { c.findings[0].severity = 'info'; },
    (c: CheckResult) => { c.findings[0].kind = 'candidate'; },
  ]) {
    const c = check(true); change(c); const r = report(c);
    assert.equal(evaluateGate(r, 'none').exitCode, 2);
    assert.equal(r.checks[0].findings.length, c.findings.length);
  }
  const spurious = check(); spurious.findings = check(true).findings;
  assert.equal(evaluateGate(report(spurious), 'none').exitCode, 2);
  const partial = check(true); partial.status = 'partial';
  partial.schemathesisAuth!.status = 'partial'; partial.schemathesisAuth!.stopReason = 'identity_mismatch';
  partial.schemathesisAuth!.controls[4].outcome = 'not_matched';
  assert.ok(sanitiseSchemathesisAuth(partial.schemathesisAuth));
  assert.equal(report(partial).checks[0].findings.length, 1);
  assert.equal(evaluateGate(report(partial), 'none').exitCode, 2);
});

test('authenticated comparison refuses credential-free or changed execution inputs independently of scope fingerprint', () => {
  const before = report(check(true));
  assert.equal(compareReports(before, copy(before)).comparable, true);
  const anonymous = copy(before); delete anonymous.checks[0].schemathesisAuth; delete anonymous.checks[0].schemathesisAuthRequired;
  delete anonymous.scope!.schemathesisAuthPolicy;
  assert.equal(compareReports(before, anonymous).comparable, false);
  for (const change of [
    (e: SchemathesisAuthEvidence) => { e.policySha256 = 'f'.repeat(64); },
    (e: SchemathesisAuthEvidence) => { e.schemaSha256 = 'f'.repeat(64); },
    (e: SchemathesisAuthEvidence) => { e.workerSha256 = 'f'.repeat(64); },
    (e: SchemathesisAuthEvidence) => { e.seed += 1; },
    (e: SchemathesisAuthEvidence) => { e.limits.timeoutMs += 1; },
    (e: SchemathesisAuthEvidence) => { e.operations[0].operation = 'GET /different-owned-operation'; },
    (e: SchemathesisAuthEvidence) => { e.runtime!.requests = '2.34.3'; },
  ]) {
    const after = copy(before); change(after.checks[0].schemathesisAuth!);
    const auth = after.checks[0].schemathesisAuth!;
    if (after.scope!.schemathesisAuthPolicy!.policySha256 !== auth.policySha256
      || after.scope!.schemathesisAuthPolicy!.schemaSha256 !== auth.schemaSha256) {
      assert.throws(() => compareReports(before, after), /Invalid scan report/, 'internally inconsistent completed evidence must be rejected');
    }
    // Compare coherent changed inputs, not a ledger that contradicts its own
    // scope binding. The unchanged fingerprint must not conceal this drift.
    after.scope!.schemathesisAuthPolicy = { profileRevision: auth.profileRevision,
      policySha256: auth.policySha256, schemaSha256: auth.schemaSha256 };
    const result = compareReports(before, after);
    assert.equal(result.comparable, false);
    assert.ok(result.entries.every(entry => entry.state === 'unverified'));
  }
});

test('advice policy 11 exposes bounded indices/enums/counts only and grants no replay route', () => {
  const agent = toAgentReport(report(check(true)), 'medium');
  const projected = projectAdviceContext(agent, true).input;
  assert.equal(ADVICE_PROJECTION_POLICY_VERSION, 11);
  assert.equal(projected.projectionVersion, 11);
  assert.equal(projected.checks[0].recheckRoute, 'review_check_diagnostics');
  assert.deepEqual(projected.checks[0].schemathesisAuth?.operations, [{ operationIndex: 0, generatedRequests: 1, deniedRequests: 0 }]);
  assert.equal(projected.findings[0].replayAvailable, false);
  assert.equal(projected.findings[0].recheckRoute, 'review_check_diagnostics');
  for (const forbidden of ['/owned-private-operation', 'owned.invalid', 'policySha256', 'schemaSha256', 'workerSha256', 'inputFingerprint', 'authorizationEnv', 'jsonPointer', 'equals']) {
    assert.equal(JSON.stringify(projected).includes(forbidden), false, forbidden);
  }
  const missing = check(); delete missing.schemathesisAuth;
  const incomplete = toAgentReport(report(missing), 'none');
  assert.equal(incomplete.scanGate.exitCode, 2);
  assert.equal(projectAdviceContext(incomplete, true).input.checks[0].schemathesisAuth, undefined);
});
