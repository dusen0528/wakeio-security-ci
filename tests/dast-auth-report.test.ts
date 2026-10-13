import test from 'node:test';
import assert from 'node:assert/strict';
import { createReport, exitCode, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { compareReports, parseScanReport } from '../src/compare.js';
import type { CheckResult, Finding } from '../src/contracts.js';
import type { DastExecutionV2, DastAuthExecutionStep } from '../src/dast-execution.js';

// Schema fixtures test report authority only, independently of runtime efficacy.
function ledger(partial = false): DastExecutionV2 {
  const phases = ['baseline-before', 'true', 'false', 'baseline-after'] as const;
  const steps: DastAuthExecutionStep[] = Array.from({ length: 10 }, (_, ordinal) => {
    const identity = ordinal === 0 || ordinal === 9;
    return { ordinal, round: identity ? 0 : ordinal < 5 ? 1 : 2,
      phase: identity ? ordinal === 0 ? 'identity-before' : 'identity-after' : phases[(ordinal - 1) % 4]!,
      outcome: partial && ordinal === 9 ? 'inconclusive' : 'evaluated',
      reason: partial && ordinal === 9 ? 'identity_mismatch' : 'evaluated',
      attemptStart: ordinal, httpAttempts: 1, httpStatus: 200,
      oracleMatch: identity ? 'unavailable' : phases[(ordinal - 1) % 4] === 'false' ? 'false' : 'baseline' };
  });
  return { version: 2, policySha256: 'a'.repeat(64), profile: 'numeric', profileRevision: 'sql-boolean-numeric-auth-v2',
    maxRequests: 10, timeoutMs: 30000, allowPrivate: true, status: partial ? 'partial' : 'complete',
    outcome: partial ? 'inconclusive' : 'observed', plannedRequests: 10, steps,
    counts: { evaluated: partial ? 9 : 10, inconclusive: partial ? 1 : 0, notAttempted: 0, httpAttempts: 10 },
    stopReason: partial ? 'identity_mismatch' : 'none', identityControls: { before: 'matched', after: partial ? 'mismatched' : 'matched' },
    probeOutcome: 'observed' };
}
const finding: Finding = { ruleId: 'dast.sql-boolean-differential', title: 'SQL boolean response differential observed',
  description: 'Bounded numeric differential observed.', kind: 'candidate', severity: 'high', confidence: 'medium',
  location: { url: 'http://127.0.0.1:8080/items' }, remediation: 'Bind the numeric parameter.' };
function check(partial = false): CheckResult {
  return { id: 'url.sql-boolean', status: partial ? 'partial' : 'completed', notes: [], findings: [finding],
    metrics: { requestCount: 10 }, dastExecution: ledger(partial) };
}
const report = (value: CheckResult) => createReport([value], 'url', new Date(), { fingerprint: 'b'.repeat(64), ruleset: 'auth-report-test' });

test('v2 partial observed evidence stays low, immutable and consistent in all local projections', () => {
  const input = check(true); const bytes = JSON.stringify(input);
  const safe = report(input);
  assert.equal(safe.checks[0]?.findings.length, 1); assert.equal(safe.checks[0]?.findings[0]?.confidence, 'low');
  assert.equal(exitCode(safe, 'none'), 2); assert.equal(JSON.stringify(input), bytes);
  assert.deepEqual(parseScanReport(safe), safe);
  assert.deepEqual(toAgentReport(safe).checks[0]?.dastExecution, input.dastExecution);
  assert.deepEqual(toSarif(safe).runs[0]?.results?.[0]?.properties?.dastExecution, input.dastExecution);
  assert.match(toMarkdown(safe), /SQL probe outcome: observed/);
  assert.match(toMarkdown(safe), /before=matched; after=mismatched/);
});

test('v2 observed ledger cannot become a completed empty clean report', () => {
  const input = { ...check(), findings: [] };
  const safe = report(input);
  assert.equal(safe.checks[0]?.status, 'partial'); assert.equal(exitCode(safe, 'none'), 2);
  assert.deepEqual(parseScanReport(safe), safe, 'canonical partial metadata remains readable');
  assert.throws(() => parseScanReport({ ...safe, checks: [input] }));
});

test('v2 fixed/no-finding SARIF retains the same identity and SQL ledger as JSON and agent', () => {
  const fixed = ledger(); fixed.outcome = 'not_observed'; fixed.probeOutcome = 'not_observed';
  fixed.steps = fixed.steps.map(step => step.phase === 'false' ? { ...step, oracleMatch: 'baseline' } : step);
  const safe = report({ ...check(), findings: [], dastExecution: fixed });
  assert.equal(exitCode(safe, 'high'), 0);
  const sarif = toSarif(safe);
  assert.equal(sarif.runs[0]?.results.length, 0);
  assert.deepEqual(sarif.runs[0]?.properties.dastExecution,
    [{ checkIndex: 0, checkId: 'url.sql-boolean', dastExecution: safe.checks[0]!.dastExecution }]);
  assert.deepEqual(toAgentReport(safe).checks[0]?.dastExecution, fixed);
});

test('external v2 wrapper accessors, proxies and forged completion fail closed without execution', () => {
  const input = check(true); const original = report(input); let invoked = 0;
  const accessor = Object.defineProperty({ ...input }, 'dastExecution', { enumerable: true, get() { invoked++; return ledger(); } });
  const proxy = new Proxy(ledger(), { get() { invoked++; throw new Error('must not execute'); }, ownKeys() { invoked++; throw new Error('must not reflect'); } });
  const versionAccessor = Object.defineProperty({ ...ledger() }, 'version', { enumerable: true, get() { invoked++; return 2; } });
  for (const value of [accessor, { ...input, dastExecution: proxy }, { ...input, dastExecution: versionAccessor },
    { ...input, status: 'completed', dastExecution: ledger(true) }, { ...input, metrics: { requestCount: 9 } }]) {
    assert.throws(() => parseScanReport({ ...original, checks: [value] }));
    assert.equal(exitCode(report(value as CheckResult), 'none'), 2);
  }
  assert.equal(invoked, 0);
});

test('partial identity evidence disappearing from a later report stays unverified', () => {
  const before = report(check(true));
  const fixed = ledger(); fixed.outcome = 'not_observed'; fixed.probeOutcome = 'not_observed';
  fixed.steps = fixed.steps.map(step => step.phase === 'false' ? { ...step, oracleMatch: 'baseline' } : step);
  const after = report({ ...check(), findings: [], dastExecution: fixed });
  const compared = compareReports(before, after);
  assert.equal(compared.comparable, false); assert.equal(compared.summary.not_observed, 0);
  assert.equal(compared.summary.unverified, 1);
});
