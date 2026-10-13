import test from 'node:test';
import assert from 'node:assert/strict';
import type { CheckResult, Finding } from '../src/contracts.js';
import type { DastExecutionV1 } from '../src/dast-execution.js';
import { createReport, toAgentReport } from '../src/report.js';
import { projectAdviceContext, type AdviceSelection } from '../src/agent-advice-context.js';

// Owned metadata only: these tests never run a target, probe, provider or replay.
const NOW = '2026-10-14T00:00:00.000Z';
const phases = ['baseline-before', 'true', 'false', 'baseline-after'] as const;
function execution(outcome: 'observed' | 'not_observed' = 'observed'): DastExecutionV1 {
  return { version: 1, policySha256: 'a'.repeat(64), profile: 'numeric', profileRevision: 'sql-boolean-numeric-v1',
    maxRequests: 8, timeoutMs: 30000, allowPrivate: false, status: 'complete', outcome, plannedRequests: 8,
    steps: Array.from({ length: 8 }, (_, ordinal): DastExecutionV1['steps'][number] => ({
      ordinal, round: ordinal < 4 ? 1 : 2, phase: phases[ordinal % 4], outcome: 'evaluated',
      reason: 'evaluated', attemptStart: ordinal, httpAttempts: 1, httpStatus: 200,
      oracleMatch: outcome === 'observed' && ordinal % 4 === 2 ? 'false' : 'baseline',
    })), counts: { evaluated: 8, inconclusive: 0, notAttempted: 0, httpAttempts: 8 }, stopReason: 'none' };
}
function finding(index = 0): Finding {
  return { ruleId: 'dast.sql-boolean-differential', title: 'SQL boolean response differential observed',
    description: 'Owned metadata fixture; no request was executed.', severity: index === 0 ? 'high' : 'low',
    confidence: 'medium', kind: 'candidate', location: { url: `https://owned.invalid/items/${index}` },
    remediation: 'Review independently.' };
}
function native(findings: Finding[] = [finding()]): CheckResult {
  return { id: 'url.sql-boolean', status: 'completed', notes: [], metrics: { requestCount: 8 },
    dastExecution: execution(findings.length ? 'observed' : 'not_observed'), findings };
}
const agentReport = (checks: CheckResult[]) => toAgentReport(createReport(checks, 'url', NOW));
const selection = (agent: ReturnType<typeof agentReport>): AdviceSelection => ({
  checkIndex: 0, findingId: agent.findings[0].findingId,
});

test('selected advice replay: unique canonical native metadata retains the positive replay route', () => {
  const agent = agentReport([native()]), selected = selection(agent);
  assert.equal(agent.checks[0].status, 'completed');
  assert.equal(agent.checks[0].dastExecution?.status, 'complete');
  assert.equal(agent.findings[0].confidence, 'medium');
  const { input, referenceRoutes } = projectAdviceContext(agent, true, selected);
  assert.deepEqual(input.selection, selected);
  assert.equal(input.findings.length, 1);
  assert.equal(input.findings[0].replayAvailable, true);
  assert.equal(input.findings[0].recheckRoute, 'replay_native_finding_same_policy');
  assert.equal(referenceRoutes.get(input.findings[0].referenceId), 'replay_native_finding_same_policy');
  assert.equal(projectAdviceContext(agent, false, selected).input.findings[0].replayAvailable, false,
    'selection cannot bypass the independent bounded report prerequisite');
});

test('selected advice replay: additional native findings beyond the default row cap still deny replay', () => {
  // V1 metadata keeps the completed/medium positive prerequisites independent
  // of cardinality, so a partial check cannot accidentally explain this denial.
  const agent = agentReport([native(Array.from({ length: 26 }, (_, index) => finding(index)))]);
  assert.equal(agent.checks[0].status, 'completed');
  assert.equal(agent.findings[0].confidence, 'medium');
  assert.equal(new Set(agent.findings.map(row => row.findingId)).size, 26);
  const normal = projectAdviceContext(agent, true).input;
  assert.equal(normal.findings.length, 24);
  assert.equal(normal.omittedFindings, 2);
  const selected = selection(agent), { input, referenceRoutes } = projectAdviceContext(agent, true, selected);
  assert.deepEqual(input.selection, selected);
  assert.equal(input.checks.length, 1);
  assert.equal(input.checks[0].findingRows, 26);
  assert.equal(input.findings.length, 1);
  assert.equal(input.omittedFindings, 25);
  assert.deepEqual(input.counts, agent.summary!.counts);
  assert.equal(input.findings[0].replayAvailable, false);
  assert.equal(input.findings[0].recheckRoute, 'review_check_diagnostics');
  assert.equal(referenceRoutes.get(input.findings[0].referenceId), 'review_check_diagnostics');
});

test('selected advice replay: a duplicate native check outside the default check cap still denies replay', () => {
  const unrelated: CheckResult[] = Array.from({ length: 30 }, (_, index) => ({
    id: `url.owned-${index}`, status: 'completed', findings: [], notes: [],
  }));
  const unique = agentReport([native(), ...unrelated]);
  assert.equal(projectAdviceContext(unique, true, selection(unique)).input.findings[0].replayAvailable, true,
    'unrelated checks exceeding the cap alone do not deny the valid native route');
  const agent = agentReport([native(), ...unrelated, native([])]);
  assert.equal(agent.checks[31].status, 'completed');
  assert.equal(agent.checks[31].checkId, 'url.sql-boolean');
  const normal = projectAdviceContext(agent, true).input;
  assert.equal(normal.checks.length, 24);
  assert.equal(normal.checks.some(check => check.checkIndex === 31), false);
  const { input, referenceRoutes } = projectAdviceContext(agent, true, selection(agent));
  assert.equal(input.checks.length, 1);
  assert.equal(input.checks[0].findingRows, 1);
  assert.equal(input.findings.length, 1);
  assert.equal(input.omittedChecks, 31);
  assert.deepEqual(input.counts, agent.summary!.counts);
  assert.equal(input.findings[0].replayAvailable, false);
  assert.equal(input.findings[0].recheckRoute, 'review_check_diagnostics');
  assert.equal(referenceRoutes.get(input.findings[0].referenceId), 'review_check_diagnostics');
});
