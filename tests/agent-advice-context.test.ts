import test from 'node:test';
import assert from 'node:assert/strict';
import { createReport, toAgentReport } from '../src/report.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';
import { createApiExecutionLedger, finishApiExecutionLedger, invalidApiExecutionLedger } from '../src/api-execution.js';
import type { AgentReport, ApiRequestPlan, CheckResult } from '../src/contracts.js';

const NOW = '2026-10-13T00:00:00.000Z';
const finding = { ruleId: 'fixture:authorization', title: 'Authorization candidate', description: 'private-description-sentinel',
  severity: 'high' as const, confidence: 'medium' as const, kind: 'candidate' as const,
  location: { path: 'private-location-sentinel.ts', line: 3 }, remediation: 'private-remediation-sentinel' };
const report = (checks: CheckResult[], mode: 'api' | 'source' = 'api') => toAgentReport(createReport(checks, mode, NOW));

function apiPlan(): ApiRequestPlan {
  return { actorCount: 2, caseCount: 1, logicalRequests: 5, maximumHttpAttempts: 64,
    timeoutMs: 1000, maximumResponseBytes: 2 * 1024 * 1024,
    maximumTotalResponseBytes: 10 * 1024 * 1024, allowPrivate: false,
    steps: [
      { ordinal: 0, method: 'GET', phase: 'identity-before', actorIndex: 0 },
      { ordinal: 1, method: 'GET', phase: 'owner-before', actorIndex: 0, caseIndex: 0 },
      { ordinal: 2, method: 'GET', phase: 'deny', actorIndex: 1, caseIndex: 0 },
      { ordinal: 3, method: 'GET', phase: 'owner-after', actorIndex: 0, caseIndex: 0 },
      { ordinal: 4, method: 'GET', phase: 'identity-after', actorIndex: 0 },
    ] };
}

test('API cards retain typed phases, controls and replay route without actor/case labels or secrets', () => {
  const agent = report([{ id: 'api.authorization', status: 'completed', findings: [finding], notes: [] }]);
  const ledger = createApiExecutionLedger(2, apiPlan());
  for (const [index, step] of ledger.steps.entries()) {
    step.outcome = 'evaluated'; step.reason = 'evaluated'; step.attemptStart = index;
    step.httpAttempts = 1; step.httpStatus = 200;
  }
  agent.checks[0].apiExecution = finishApiExecutionLedger(ledger, false);
  agent.findings[0].evidence.controlVerification = { state: 'controls_passed', method: 'api-differential-canary',
    controls: { identityBefore: 'passed', ownerBefore: 'passed', probe: 'canary_exposed',
      probeCompleted: true, ownerAfter: 'passed', identityAfter: 'passed' } };
  agent.findings[0].evidence.replay = { kind: 'api-policy-case', policySha256: 'a'.repeat(64),
    caseId: 'private-case-sentinel', actor: 'private-actor-sentinel' };
  agent.findings[0].evidence.apiExecution = { basis: 'api-execution-ledger', planSha256: 'b'.repeat(64),
    steps: [{ ordinal: 2, phase: 'deny', actor: 'private-actor-sentinel', outcome: 'evaluated', httpStatus: 200 }] };
  const { input, referenceRoutes } = projectAdviceContext(agent, true);
  assert.equal(input.checks[0].apiExecution?.status, 'complete');
  assert.deepEqual(input.checks[0].apiExecution?.steps.map(step => step.phase),
    ['identity-before', 'owner-before', 'deny', 'owner-after', 'identity-after']);
  assert.equal(input.findings[0].inRunControl?.state, 'controls_passed');
  assert.equal(input.findings[0].replayAvailable, true);
  assert.equal(referenceRoutes.get(input.findings[0].referenceId), 'replay_api_finding_same_policy');
  const serialized = JSON.stringify(input);
  for (const secret of ['private-description-sentinel', 'private-location-sentinel', 'private-remediation-sentinel',
    'private-case-sentinel', 'private-actor-sentinel', '"actor":', '"path":', '"url":']) {
    assert.equal(serialized.includes(secret), false, secret);
  }
  const partial = structuredClone(agent);
  partial.checks[0].status = 'partial';
  partial.checks[0].apiExecution = invalidApiExecutionLedger();
  partial.findings[0].evidence.controlVerification = { ...partial.findings[0].evidence.controlVerification!, state: 'inconclusive' };
  const projectedPartial = projectAdviceContext(partial, true).input;
  assert.equal(projectedPartial.checks[0].apiExecution?.status, 'invalid');
  assert.equal(projectedPartial.findings[0].replayAvailable, false);
  assert.equal(projectedPartial.findings[0].recheckRoute, 'review_check_diagnostics');
});

test('SAST card keeps static roles and budget/gap accounting but no source locations', () => {
  const agent = report([{ id: 'source.typescript', status: 'partial', findings: [finding], notes: [] }], 'source');
  agent.findings[0].evidence.staticFlow = { kind: 'static_flow', truncated: true,
    steps: [{ role: 'source', location: { path: 'private-flow-source.ts', line: 2, column: 1 } },
      { role: 'sink', location: { path: 'private-flow-sink.ts', line: 9, column: 3 } }] };
  agent.findings[0].evidence.traceStatus = 'static_truncated';
  agent.checks[0].analysisBudget = { revision: 'ast-work-v1', requestedProfile: 'extended', effectiveProfile: 'extended',
    limits: { indexWork: 1200000, flowWork: 800000, nodeVisits: 2000000, functions: 8000,
      summaryWork: 20000, moduleEdges: 8000, callDepth: 8, aliasSteps: 64, traceSteps: 24 } };
  agent.checks[0].analysisGaps = { accounting: 'exact', eventsObserved: 3, eventsDropped: 1, truncated: true,
    items: [{ reason: 'flow_work_limit', phase: 'flow', extent: 'check', observations: 2,
      nextReview: 'review_analysis_budget', location: { path: 'private-gap-source.ts', line: 4, column: 5 } }],
    reasonSummary: { accounting: 'exact', rows: [{ reason: 'flow_work_limit', eventsObserved: 3, eventsDropped: 1 }] } };
  const { input } = projectAdviceContext(agent, true);
  assert.deepEqual(input.findings[0].staticFlow?.roles, ['source', 'sink']);
  assert.equal(input.findings[0].staticFlow?.truncated, true);
  assert.equal(input.checks[0].analysisBudget?.effectiveProfile, 'extended');
  assert.equal(input.checks[0].analysisGaps?.eventsDropped, 1);
  assert.equal(input.checks[0].analysisGaps?.representative[0].nextReview, 'review_analysis_budget');
  for (const secret of ['private-flow-source.ts', 'private-flow-sink.ts', 'private-gap-source.ts',
    'private-location-sentinel.ts', 'private-description-sentinel']) {
    assert.equal(JSON.stringify(input).includes(secret), false, secret);
  }
});

test('priority and size caps retain linked checks and count every omitted row', () => {
  const checks: CheckResult[] = Array.from({ length: 30 }, (_, index) => ({
    id: `source.check-${index}`, status: 'completed', findings: [], notes: [] }));
  checks.push({ id: 'source.important', status: 'partial', findings: [finding], notes: [] });
  const agent = report(checks, 'source');
  const projected = projectAdviceContext(agent, true).input;
  assert.equal(projected.checks[0].checkIndex, 30);
  assert.equal(projected.findings[0].checkIndex, 30);
  assert.ok(projected.checks.some(check => check.checkIndex === projected.findings[0].checkIndex));
  assert.equal(projected.omittedChecks, agent.checks.length - projected.checks.length);
  assert.equal(projected.omittedFindings, agent.findings.length - projected.findings.length);
  assert.ok(Buffer.byteLength(JSON.stringify(projected)) <= 32 * 1024);

  // A 64-step API ledger on many checks must shrink the list, not discard the
  // highest-priority incomplete check or leave a selected finding orphaned.
  const large = structuredClone(agent) as AgentReport;
  const base = createApiExecutionLedger(2, apiPlan());
  base.steps = Array.from({ length: 64 }, (_, ordinal) => ({ ...base.steps[0], ordinal,
    reason: 'not_reached' as const, attemptStart: 0 }));
  base.plan!.steps = Array.from({ length: 64 }, (_, ordinal) => ({ ordinal, method: 'GET' as const,
    phase: 'deny' as const, actorIndex: 1, caseIndex: 0 }));
  for (const check of large.checks) { check.checkId = 'api.authorization'; check.apiExecution = structuredClone(base); }
  const capped = projectAdviceContext(large, true).input;
  assert.ok(capped.omittedChecks > 7);
  assert.equal(capped.checks[0].checkIndex, 30);
  assert.ok(capped.findings.every(row => capped.checks.some(check => check.checkIndex === row.checkIndex)));
  assert.equal(capped.omittedChecks, large.checks.length - capped.checks.length);
  assert.equal(capped.omittedFindings, large.findings.length - capped.findings.length);
  assert.ok(Buffer.byteLength(JSON.stringify(capped)) <= 32 * 1024);
});
