import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { CheckResult, FailOn, Finding, Severity } from '../src/contracts.js';
// Public APIs present before this identity contract; no implementation helpers.
import { createReport, sanitiseReport, toAgentReport } from '../src/report.js';
import { compareReports, comparisonExitCode, parseScanReport, writeComparison } from '../src/compare.js';

const START = '2026-10-14T00:00:00.000Z';
const SCOPE = { fingerprint: 'a'.repeat(64), ruleset: 'owned.identity.1', projectId: 'owned/finding-identity' };
const KEY_A = 'b'.repeat(64), KEY_B = 'c'.repeat(64);
const finding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: 'owned:identity', title: 'Owned candidate', description: 'Synthetic report metadata only.',
  severity: 'high', confidence: 'medium', kind: 'candidate', location: { path: 'app.ts', line: 1 },
  remediation: 'Review the local evidence and independently verify controls.', ...overrides,
});
const report = (findings: readonly Finding[], status: CheckResult['status'] = 'completed') => createReport([
  { id: 'fixture.identity', status, findings: [...findings], notes: [] },
], 'source', START, SCOPE);

test('finding identity: repeated IDs preserve row threshold truth and unique blocking-ID counts', () => {
  for (const rows of [[finding(), finding({ severity: 'low' })], [finding({ severity: 'low' }), finding()]]) {
    const input = report(rows), agent = toAgentReport(input, 'high');
    assert.equal(input.checks[0].findings[0].id, input.checks[0].findings[1].id, 'severity is outside the existing ID');
    assert.deepEqual(agent.findings.map(row => row.reachesFailOn), rows.map(row => row.severity === 'high'));
    assert.equal(agent.scanGate.exitCode, 1);
    assert.equal(agent.scanGate.blockingFindingIds.length, 1);
    assert.ok(agent.summary, 'producer supplies the first-read summary');
    assert.deepEqual(agent.summary.counts, { findings: 2, candidates: 2, blockingFindings: 1,
      blockingCandidates: 1, completedChecks: 1, incompleteChecks: 0, notApplicableChecks: 0 });
    assert.deepEqual(toAgentReport(sanitiseReport(input), 'high'), agent);
    for (const row of agent.findings) {
      assert.equal(row.verification.vulnerabilityConfirmed, false);
      assert.equal(row.verification.remediationVerified, false);
      assert.equal(row.remediation.state, 'not_verified');
    }
  }
});

test('finding identity: every threshold, none and invalid selectors retain per-row semantics', () => {
  const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const input = report(severities.map(severity => finding({ severity })));
  assert.equal(new Set(input.checks[0].findings.map(row => row.id)).size, 1);
  for (const [rank, threshold] of severities.entries()) {
    const agent = toAgentReport(input, threshold);
    assert.deepEqual(agent.findings.map(row => row.reachesFailOn), severities.map((_, index) => index >= rank), threshold);
    assert.equal(agent.scanGate.exitCode, 1);
    assert.equal(agent.scanGate.blockingFindingIds.length, 1);
    assert.ok(agent.summary, 'producer supplies the first-read summary');
    assert.equal(agent.summary.counts.blockingFindings, 1);
  }
  for (const threshold of ['none', 'invalid', '__proto__', 'constructor'] as const) {
    const agent = toAgentReport(input, threshold as FailOn);
    assert.deepEqual(agent.findings.map(row => row.reachesFailOn), severities.map(() => false), threshold);
    assert.equal(agent.scanGate.exitCode, threshold === 'none' ? 0 : 2);
    assert.equal(agent.scanGate.failOn, threshold === 'none' ? 'none' : 'invalid');
    assert.equal(agent.scanGate.blockingFindingIds.length, 0);
    assert.ok(agent.summary, 'producer supplies the first-read summary');
    assert.equal(agent.summary.counts.blockingFindings, 0);
  }
});

test('finding identity: partial completion takes precedence without changing row thresholds', () => {
  const input = report([finding(), finding({ severity: 'low' })], 'partial');
  const agent = toAgentReport(input, 'high');
  assert.equal(agent.scanGate.exitCode, 2);
  assert.equal(agent.scanGate.outcome, 'incomplete');
  assert.deepEqual(agent.findings.map(row => row.reachesFailOn), [true, false]);
  assert.equal(agent.scanGate.blockingFindingIds.length, 1);
  assert.ok(agent.scanGate.reasons.some(reason => reason.code === 'check_incomplete'));
  assert.ok(agent.scanGate.reasons.some(reason => reason.code === 'severity_threshold'));
  const disabled = toAgentReport(input, 'none');
  assert.equal(disabled.scanGate.exitCode, 2);
  assert.deepEqual(disabled.findings.map(row => row.reachesFailOn), [false, false]);
});

test('finding identity: identical legacy duplicates on either side are unverified, including none', () => {
  for (const [beforeCount, afterCount] of [[2, 1], [1, 2], [2, 2]] as const) {
    const comparison = compareReports(report(Array.from({ length: beforeCount }, () => finding())),
      report(Array.from({ length: afterCount }, () => finding())));
    assert.equal(comparison.comparable, false, `${beforeCount} -> ${afterCount}`);
    assert.equal(comparison.entries.length, beforeCount + afterCount, 'ambiguous rows must not be paired or lost');
    assert.ok(comparison.entries.every(row => row.state === 'unverified'));
    assert.deepEqual(comparison.summary, { new: 0, changed: 0, unchanged: 0, not_observed: 0,
      unverified: beforeCount + afterCount });
    assert.equal(comparisonExitCode(comparison, 'none'), 2);
    assert.equal(comparisonExitCode(comparison, 'high'), 2);
    assert.equal(comparisonExitCode(comparison, 'invalid' as FailOn), 2);
    assert.ok(comparison.reasons.some(reason => /ambiguous/i.test(reason)));
  }
});

test('finding identity: heterogeneous legacy duplicate permutations cannot choose a severity or confidence match', () => {
  for (const duplicate of [finding({ severity: 'low' }), finding({ confidence: 'low' })]) {
    for (const repeated of [[finding(), duplicate], [duplicate, finding()]]) {
      for (const [before, after] of [[repeated, [finding()]], [[finding()], repeated],
        [repeated, [...repeated].reverse()]] as const) {
        const comparison = compareReports(report(before), report(after));
        assert.equal(comparison.comparable, false);
        assert.equal(comparison.entries.length, before.length + after.length);
        assert.ok(comparison.entries.every(row => row.state === 'unverified'));
        assert.equal(comparisonExitCode(comparison, 'none'), 2);
        assert.equal(comparisonExitCode(comparison, 'high'), 2);
      }
    }
  }
});

test('finding identity: distinct unique semantic keys may share an ID and survive row permutations', () => {
  const high = finding({ comparisonKey: KEY_A }), low = finding({ comparisonKey: KEY_B, severity: 'low' });
  const before = report([high, low]), after = report([low, high]);
  assert.equal(before.checks[0].findings[0].id, before.checks[0].findings[1].id);
  const comparison = compareReports(before, after);
  assert.equal(comparison.comparable, true);
  assert.deepEqual(comparison.summary, { new: 0, changed: 0, unchanged: 2, not_observed: 0, unverified: 0 });
  assert.equal(comparisonExitCode(comparison, 'high'), 0);
  const changed = compareReports(before, report([low, { ...high, severity: 'critical' }]));
  assert.equal(changed.comparable, true);
  assert.deepEqual(changed.summary, { new: 0, changed: 1, unchanged: 1, not_observed: 0, unverified: 0 });
  assert.equal(changed.entries.find(row => row.finding.comparisonKey === KEY_A)?.state, 'changed');
  assert.equal(changed.entries.find(row => row.finding.comparisonKey === KEY_B)?.state, 'unchanged');
  assert.equal(comparisonExitCode(changed, 'critical'), 1);
  assert.deepEqual(toAgentReport(after, 'high').findings.map(row => row.reachesFailOn), [false, true]);
});

test('finding identity: a unique semantic kind change is changed without claiming independent proof', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-owned-kind-comparison-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  for (const [beforeKind, afterKind] of [['candidate', 'observation'], ['candidate', 'advisory'],
    ['observation', 'candidate']] as const) {
    const before = report([finding({ comparisonKey: KEY_A, kind: beforeKind })]);
    const after = report([finding({ comparisonKey: KEY_A, kind: afterKind })]);
    assert.notEqual(before.checks[0].findings[0].id, after.checks[0].findings[0].id, 'kind remains in existing ID');
    const comparison = compareReports(before, after);
    assert.equal(comparison.comparable, true);
    assert.deepEqual(comparison.summary, { new: 0, changed: 1, unchanged: 0, not_observed: 0, unverified: 0 });
    assert.equal(comparison.entries[0].finding.kind, afterKind);
    assert.equal((comparison.entries[0] as { previousKind?: Finding['kind'] }).previousKind, beforeKind);
    assert.equal(comparisonExitCode(comparison, 'high'), 1);
    assert.equal(comparisonExitCode(comparison, 'none'), 0);
    const agent = toAgentReport(after);
    assert.equal(agent.findings[0].verification.state, 'not_run');
    assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
    assert.equal(agent.findings[0].verification.remediationVerified, false);
    const out = join(top, `${beforeKind}-${afterKind}`);
    await writeComparison(comparison, out);
    const delivered = JSON.parse(await readFile(join(out, 'comparison.json'), 'utf8'));
    assert.equal(delivered.entries[0].previousKind, beforeKind);
    assert.equal(delivered.entries[0].finding.kind, afterKind);
    assert.equal(delivered.entries[0].state, 'changed');
    assert.ok((await readFile(join(out, 'comparison.md'), 'utf8')).includes(`; kind: ${beforeKind} → ${afterKind}`));
  }
});

test('finding identity: unique legacy controls retain stable, changed, moved and recomputed identities', () => {
  const before = report([finding()]);
  const stable = compareReports(before, report([finding()]));
  assert.equal(stable.comparable, true);
  assert.equal(stable.summary.unchanged, 1);
  assert.equal(comparisonExitCode(stable, 'invalid' as FailOn), 2);
  assert.equal(Object.hasOwn(stable.entries[0], 'previousKind'), false);
  for (const update of [{ severity: 'critical' as const }, { confidence: 'low' as const }]) {
    const changed = compareReports(before, report([finding(update)]));
    assert.equal(changed.comparable, true);
    assert.equal(changed.summary.changed, 1);
    assert.equal(Object.hasOwn(changed.entries[0], 'previousKind'), false);
  }
  for (const update of [{ location: { path: 'app.ts', line: 2 } }, { kind: 'observation' as const }]) {
    const moved = compareReports(before, report([finding(update)]));
    assert.equal(moved.comparable, true);
    assert.equal(moved.summary.new, 1);
    assert.equal(moved.summary.not_observed, 1);
  }
  const forged = structuredClone(before);
  forged.checks[0].findings[0].id = 'd'.repeat(64);
  assert.equal(parseScanReport(forged).checks[0].findings[0].id, before.checks[0].findings[0].id);
});
