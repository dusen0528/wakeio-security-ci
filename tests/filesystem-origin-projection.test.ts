import test from 'node:test';
import assert from 'node:assert/strict';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { compareReports } from '../src/compare.js';

// Own raw SDK data, not detector-produced source findings or runtime evidence.
// Strict external parse validation is separately covered. A renderer may discard
// invalid flow, but that loss must preserve incomplete gate/compare semantics.
test('filesystem origin projection: valid origin enum with erased malformed flow cannot become completed/pass SDK evidence', () => {
  const validFlow = { kind: 'static_flow', sourceKind: 'filesystem_filename', truncated: true, steps: [
    { role: 'source', location: { path: 'app.mts', line: 1, column: 1 } },
    { role: 'sink', location: { path: 'app.mts', line: 2, column: 1 } },
  ] };
  const finding = { ruleId: 'fixture:filesystem-origin', title: 'Own malformed origin fixture',
    description: 'Own structural input only.', remediation: 'Review source evidence.', kind: 'candidate',
    severity: 'low', confidence: 'medium', location: { path: 'app.mts', line: 2, column: 1 } };
  const make = (flow: unknown) => ({ id: 'fixture:filesystem-origin', status: 'completed', notes: [],
    findings: [{ ...finding, staticFlow: flow }] });
  const scope = { fingerprint: 'a'.repeat(64), ruleset: 'synthetic.filesystem-origin' };
  const before = createReport([make(validFlow) as any], 'source', '2026-10-13T00:00:00Z', scope);
  for (const flow of [
    { kind: 'static_flow', sourceKind: 'filesystem_filename', truncated: false, steps: [] },
    { kind: 'wrong_kind', sourceKind: 'filesystem_filename', truncated: false, steps: [] },
    { kind: 'static_flow', sourceKind: 'filesystem_filename', truncated: false,
      steps: [{ role: 'invented', location: { path: 'app.mts', line: 1, column: 1 } }] },
  ]) {
    const input = make(flow), unchanged = JSON.stringify(input);
    const report = createReport([input as any], 'source', '2026-10-13T00:00:00Z', scope);
    assert.equal(report.checks[0].status, 'partial', 'erasing valid origin with invalid flow must retain the coverage gap');
    assert.equal(evaluateGate(report, 'high').exitCode, 2, 'low malformed finding cannot launder coverage into threshold pass');
    const json = JSON.parse(JSON.stringify(report));
    assert.equal(json.checks[0].status, 'partial'); assert.equal(evaluateGate(json, 'high').exitCode, 2);
    const agent = JSON.parse(JSON.stringify(toAgentReport(report, 'high')));
    assert.equal(agent.scanGate.exitCode, 2); assert.equal(agent.scanGate.outcome, 'incomplete');
    assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
    assert.equal(agent.findings[0].verification.remediationVerified, false);
    assert.match(toMarkdown(report, 'high'), /Scan gate: incomplete; exit 2; fail-on high/);
    const sarif = JSON.parse(JSON.stringify(toSarif(report)));
    assert.equal(sarif.runs[0].invocations?.[0].executionSuccessful, false);
    assert.equal(sarif.runs[0].invocations?.[0].properties?.statuses?.['fixture:filesystem-origin'], 'partial');
    assert.equal(compareReports(before, report).comparable, false, 'lost origin evidence cannot establish a disappearance or fix');
    assert.equal(JSON.stringify(input), unchanged, 'public renderer mutated raw SDK input');
  }
});
