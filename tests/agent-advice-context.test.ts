import test from 'node:test';
import assert from 'node:assert/strict';
import { createReport, toAgentReport } from '../src/report.js';
import { ADVICE_PROJECTION_POLICY_VERSION, projectAdviceContext } from '../src/agent-advice-context.js';
import { createApiExecutionLedger, finishApiExecutionLedger, invalidApiExecutionLedger } from '../src/api-execution.js';
import { resolveCollectionBudget, collectionEvidence, COLLECTION_ISSUE_CODES } from '../src/source/collection-budget.js';
import type { AgentReport, ApiRequestPlan, CheckResult, StaticCandidateContext } from '../src/contracts.js';

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


test('collection cards keep validated bounds and aggregate reasons only, while legacy and malformed metadata remain unknown', () => {
  const agent = report([{ id: 'source.inventory', status: 'partial', findings: [], notes: ['private-note-sentinel'] }], 'source');
  const budget = resolveCollectionBudget({ maxFiles: 1002, maxBytes: 134217728 });
  const evidence = collectionEvidence([{ code: 'file_limit' }, { code: 'size_limit' }]);
  agent.checks[0].collectionBudget = budget; agent.checks[0].collectionEvidence = evidence;
  agent.checks[0].metrics = { root: '/private/root-sentinel' };
  const { input, referenceRoutes } = projectAdviceContext(agent, false);
  assert.equal(input.projectionVersion, ADVICE_PROJECTION_POLICY_VERSION);
  assert.deepEqual(input.checks[0].collectionBudget, budget);
  assert.deepEqual(input.checks[0].collectionEvidence, evidence);
  assert.equal(referenceRoutes.get('check:0'), 'review_static_flow_or_budget');
  for (const secret of ['private-note-sentinel', 'root-sentinel', '"path":', '"url":']) assert.equal(JSON.stringify(input).includes(secret), false);
  const legacy = structuredClone(agent); delete legacy.checks[0].collectionBudget; delete legacy.checks[0].collectionEvidence;
  const unknown = projectAdviceContext(legacy, false);
  assert.equal(unknown.input.checks[0].collectionBudget, undefined);
  assert.equal(unknown.input.checks[0].collectionEvidence, undefined);
  assert.equal(unknown.referenceRoutes.get('check:0'), 'review_check_diagnostics');
  const malformed = structuredClone(agent);
  Object.assign(malformed.checks[0].collectionBudget!, { privatePath: '/private/never-upload' });
  Object.assign(malformed.checks[0].collectionEvidence!.issues[0], { path: '/private/never-upload' });
  const rejected = projectAdviceContext(malformed, false);
  assert.equal(rejected.input.checks[0].collectionBudget, undefined);
  assert.equal(rejected.input.checks[0].collectionEvidence, undefined);
  assert.equal(JSON.stringify(rejected.input).includes('never-upload'), false);
  assert.equal(rejected.referenceRoutes.get('check:0'), 'review_check_diagnostics');
  agent.checks[0].checkId = 'source.other';
  assert.equal(projectAdviceContext(agent, false).input.checks[0].collectionBudget, undefined);
  assert.equal(projectAdviceContext(agent, false).input.checks[0].collectionEvidence, undefined);
});

test('collection evidence remains bounded by existing card and byte caps with accurate omission accounting', () => {
  const checks: CheckResult[] = Array.from({ length: 40 }, () => ({ id: 'source.inventory', status: 'partial', findings: [], notes: [] }));
  const agent = report(checks, 'source');
  for (const check of agent.checks) {
    check.collectionBudget = resolveCollectionBudget({ maxFiles: 10000, maxBytes: 134217728 });
    check.collectionEvidence = collectionEvidence(COLLECTION_ISSUE_CODES.map(code => ({ code })));
  }
  const { input, referenceRoutes } = projectAdviceContext(agent, false);
  assert.ok(input.checks.length <= 24);
  assert.equal(input.omittedChecks, 40 - input.checks.length);
  assert.equal(input.omittedFindings, 0);
  assert.ok(Buffer.byteLength(JSON.stringify(input)) <= 32 * 1024);
  for (const check of input.checks) {
    assert.deepEqual(check.collectionEvidence, agent.checks[check.checkIndex].collectionEvidence);
    assert.equal(referenceRoutes.get(check.referenceId), 'review_static_flow_or_budget');
  }
});

test('policy4 conditional context cards expose enum kinds and counts without any context positions or new action route', () => {
  const context: StaticCandidateContext = { revision: 'static-context-v1', authority: 'conditional', truncated: true,
    items: [
      { kind: 'unresolved_cjs_dispatch', location: { path: 'private-context-call.ts', line: 12345, column: 54321 }, target: { path: 'private-context-body.ts', line: 98765, column: 56789 } },
      { kind: 'constructor_continuation', location: { path: 'private-context-constructor.ts', line: 10101, column: 20202 } },
    ] };
  const agent = report([{ id: 'source.builtin-ast', status: 'partial', findings: [{ ...finding, staticContext: context }], notes: [] }], 'source');
  const { input, referenceRoutes } = projectAdviceContext(agent, false);
  assert.equal(input.projectionVersion, 4);
  assert.deepEqual(input.findings[0].staticContext, { authority: 'conditional', kinds: ['constructor_continuation', 'unresolved_cjs_dispatch'], itemCount: 2, truncated: true });
  assert.equal(input.findings[0].replayAvailable, false);
  assert.equal(referenceRoutes.get(input.findings[0].referenceId), 'review_static_flow_or_budget');
  const json = JSON.stringify(input);
  for (const secret of ['private-context-', '12345', '54321', '98765', '56789', '10101', '20202', '"location":', '"target":', '"path":', '"command":']) assert.equal(json.includes(secret), false, secret);
  let reads = 0;
  Object.defineProperty(agent.findings[0].evidence, 'staticContext', { enumerable: true, get: () => { reads++; throw new Error('must not execute'); } });
  assert.equal(projectAdviceContext(agent, false).input.findings[0].staticContext, undefined);
  assert.equal(reads, 0);
});

test('conditional context cards stay within the existing byte cap and preserve omission accounting', () => {
  const context: StaticCandidateContext = { revision: 'static-context-v1', authority: 'conditional', truncated: false,
    items: [{ kind: 'unqualified_mongo_origin', location: { path: 'private-origin.ts', line: 1, column: 1 } }] };
  const checks: CheckResult[] = Array.from({ length: 40 }, (_, index) => ({ id: `source.context-${index}`, status: 'partial', notes: [],
    findings: Array.from({ length: 2 }, () => ({ ...finding, staticContext: context })) }));
  const agent = report(checks, 'source');
  const { input } = projectAdviceContext(agent, false);
  assert.ok(Buffer.byteLength(JSON.stringify(input)) <= 32 * 1024);
  assert.equal(input.omittedChecks, agent.checks.length - input.checks.length);
  assert.equal(input.omittedFindings, agent.findings.length - input.findings.length);
  assert.ok(input.findings.every(row => input.checks.some(check => check.checkIndex === row.checkIndex)));
  assert.equal(JSON.stringify(input).includes('private-origin.ts'), false);
});
