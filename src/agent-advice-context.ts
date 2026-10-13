import { sanitiseCollectionBudget, sanitiseCollectionEvidence } from './source/collection-budget.js';
import type { AgentReport } from './contracts.js';
import { redactSecrets, safeHttpUrl } from './report-path.js';
import { sanitizeDastExecution, isDastReplayableExecution, hasDastIdentityControls } from './dast-execution.js';
import { sanitiseStaticContext } from './static-context.js';
import { types } from 'node:util';

export type RecheckRoute = 'repeat_native_same_policy' | 'replay_native_finding_same_policy' | 'replay_api_finding_same_policy'
  | 'review_static_flow_or_budget' | 'review_check_diagnostics' | 'review_scope';

export const ADVICE_PROJECTION_POLICY_VERSION = 6;

const MAX_CHECKS = 24;
const MAX_FINDINGS = 24;
const MAX_BYTES = 32 * 1024;
const NATIVE_CHECK = 'url.sql-boolean';
const NATIVE_RULE = 'dast.sql-boolean-differential';
const NATIVE_TITLE = 'SQL boolean response differential observed';
const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 } as const;
const boundedText = (value: string, size: number) => redactSecrets(value).slice(0, size);

function checkPriority(check: AgentReport['checks'][number], blocking: Set<string>): number {
  if (!['completed', 'not_applicable'].includes(check.status)) return 0;
  if (check.findingIds.some(id => blocking.has(id))) return 1;
  if (check.findingIds.length > 0) return 2;
  return 3;
}

/** Report-only prerequisites mirrored from replayDastFinding; policy matching is still checked at replay time. */
function nativeExecutionEligible(check: AgentReport['checks'][number], nativeCheckCount: number): boolean {
  const execution = sanitizeDastExecution(check.dastExecution);
  return nativeCheckCount === 1 && check.checkId === NATIVE_CHECK && check.status === 'completed'
    && !!execution && execution.status === 'complete'
    && check.metrics?.requestCount === execution.counts.httpAttempts
    && execution.counts.evaluated === execution.plannedRequests && execution.counts.httpAttempts >= execution.plannedRequests
    && (!hasDastIdentityControls(execution) || execution.identityControls.before === 'matched' && execution.identityControls.after === 'matched');
}

function checkRoute(check: AgentReport['checks'][number], mode: AgentReport['mode'], nativeCheckCount: number): RecheckRoute {
  if (check.checkId === 'source.inventory' && (sanitiseCollectionBudget(check.collectionBudget) || sanitiseCollectionEvidence(check.collectionEvidence))) return 'review_static_flow_or_budget';
  if (check.status !== 'completed') return check.analysisGaps || check.analysisBudget
    ? 'review_static_flow_or_budget' : 'review_check_diagnostics';
  if (nativeExecutionEligible(check, nativeCheckCount)) return 'repeat_native_same_policy';
  if (mode === 'source' || check.checkId.startsWith('source.')) return 'review_static_flow_or_budget';
  return 'review_check_diagnostics';
}

function checkCard(check: AgentReport['checks'][number], mode: AgentReport['mode'], nativeCheckCount: number) {
  const dast = check.checkId === 'url.sql-boolean' ? sanitizeDastExecution(check.dastExecution) : undefined;
  const api = check.checkId === 'api.authorization' ? check.apiExecution : undefined;
  const gaps = check.analysisGaps;
  const collectionBudget = check.checkId === 'source.inventory' ? sanitiseCollectionBudget(check.collectionBudget) : undefined;
  const collectionEvidence = check.checkId === 'source.inventory' ? sanitiseCollectionEvidence(check.collectionEvidence) : undefined;
  return {
    referenceId: `check:${check.checkIndex}`, checkIndex: check.checkIndex,
    checkId: boundedText(check.checkId, 100), status: check.status,
    ...(collectionBudget ? { collectionBudget } : {}),
    ...(collectionEvidence ? { collectionEvidence } : {}),
    findingRows: check.findingIds.length, recheckRoute: checkRoute(check, mode, nativeCheckCount),
    engine: dast ? 'native_sql_boolean' as const : api ? 'api_authorization' as const
      : mode === 'source' || check.checkId.startsWith('source.') ? 'source_check' as const : 'other' as const,
    ...(dast ? { nativeDast: {
      profileRevision: dast.profileRevision, status: dast.status, outcome: dast.outcome,
      ...(hasDastIdentityControls(dast) ? { identityControls: { before: dast.identityControls.before, after: dast.identityControls.after }, probeOutcome: dast.probeOutcome } : {}),
      plannedRequests: dast.plannedRequests, maxRequests: dast.maxRequests,
      timeoutMs: dast.timeoutMs, allowPrivate: dast.allowPrivate, policyBound: true,
      counts: dast.counts, stopReason: dast.stopReason,
      steps: dast.steps.map(step => ({ ordinal: step.ordinal, round: step.round, phase: step.phase,
        outcome: step.outcome, reason: step.reason, httpAttempts: step.httpAttempts,
        httpStatus: step.httpStatus, oracleMatch: step.oracleMatch })),
    } } : {}),
    ...(api ? { apiExecution: {
      status: api.status, policyVersion: api.policyVersion,
      counts: api.counts, reasons: api.reasons,
      ...(api.plan ? { plan: { actorCount: api.plan.actorCount, caseCount: api.plan.caseCount,
        logicalRequests: api.plan.logicalRequests, maximumHttpAttempts: api.plan.maximumHttpAttempts } } : {}),
      steps: api.steps.map((step, ordinal) => ({ ordinal, phase: api.plan?.steps[ordinal]?.phase ?? 'unknown',
        actorIndex: api.plan?.steps[ordinal]?.actorIndex ?? null,
        caseIndex: api.plan?.steps[ordinal]?.caseIndex ?? null,
        outcome: step.outcome, reason: step.reason, httpAttempts: step.httpAttempts,
        httpStatus: step.httpStatus })),
    } } : {}),
    ...(check.analysisBudget ? { analysisBudget: { revision: check.analysisBudget.revision,
      requestedProfile: check.analysisBudget.requestedProfile,
      effectiveProfile: check.analysisBudget.effectiveProfile, limits: check.analysisBudget.limits } } : {}),
    ...(gaps ? { analysisGaps: { accounting: gaps.accounting, eventsObserved: gaps.eventsObserved,
      eventsDropped: gaps.eventsDropped, truncated: gaps.truncated,
      reasonSummary: gaps.reasonSummary?.rows.slice(0, 8).map(row => ({ reason: row.reason,
        eventsObserved: row.eventsObserved, eventsDropped: row.eventsDropped })) ?? [],
      representative: gaps.items.slice(0, 8).map(item => ({ reason: item.reason, phase: item.phase,
        extent: item.extent, observations: item.observations, nextReview: item.nextReview })),
      omittedRepresentativeItems: Math.max(0, gaps.items.length - 8) } } : {}),
  };
}

function findingRoute(finding: AgentReport['findings'][number],
  check: AgentReport['checks'][number], mode: AgentReport['mode'], nativeCheckCount: number,
  findingRowsForCheck: number, nativeReplayReportEligible: boolean, conditionalContext: boolean): RecheckRoute {
  if (conditionalContext) return 'review_static_flow_or_budget';
  if (nativeReplayReportEligible && nativeExecutionEligible(check, nativeCheckCount)
      && check.dastExecution && isDastReplayableExecution(check.dastExecution)
      && check.findingIds.length === 1 && findingRowsForCheck === 1
      && check.findingIds[0] === finding.findingId
      && finding.ruleId === NATIVE_RULE && finding.title === NATIVE_TITLE
      && finding.evidence.kind === 'candidate' && finding.severity === 'high'
      && finding.confidence === 'medium' && typeof finding.location.url === 'string'
      && safeHttpUrl(finding.location.url) === finding.location.url) return 'replay_native_finding_same_policy';
  if (check.checkId === 'api.authorization' && check.apiExecution?.status === 'complete'
      && finding.evidence.replay?.kind === 'api-policy-case') return 'replay_api_finding_same_policy';
  if (finding.evidence.staticFlow || mode === 'source') return 'review_static_flow_or_budget';
  return 'review_check_diagnostics';
}

function findingCard(finding: AgentReport['findings'][number], check: AgentReport['checks'][number],
  mode: AgentReport['mode'], nativeCheckCount: number, findingRowsForCheck: number,
  nativeReplayReportEligible: boolean) {
  const flow = finding.evidence.staticFlow;
  const contextField = types.isProxy(finding.evidence) ? undefined : Object.getOwnPropertyDescriptor(finding.evidence, 'staticContext');
  const contextPresent = types.isProxy(finding.evidence) || !!contextField;
  const context = contextField && Object.hasOwn(contextField, 'value') ? sanitiseStaticContext(contextField.value) : undefined;
  const control = finding.evidence.controlVerification;
  const apiEvidence = finding.evidence.apiExecution;
  const route = findingRoute(finding, check, mode, nativeCheckCount, findingRowsForCheck,
    nativeReplayReportEligible, contextPresent);
  return { referenceId: `finding:${finding.checkIndex}:${finding.findingId}`,
    findingId: finding.findingId, checkIndex: finding.checkIndex,
    ruleId: boundedText(finding.ruleId, 120), title: boundedText(finding.title, 180),
    severity: finding.severity, confidence: finding.confidence,
    evidenceKind: finding.evidence.kind, traceStatus: finding.evidence.traceStatus,
    reachesFailOn: finding.reachesFailOn, verification: 'not_run' as const,
    recheckRoute: route,
    ...(flow ? { staticFlow: { roles: flow.steps.map(step => step.role),
      stepCount: flow.steps.length, truncated: flow.truncated } } : {}),
    ...(context ? { staticContext: { authority: context.authority,
      kinds: [...new Set(context.items.map(item => item.kind))], itemCount: context.items.length,
      truncated: context.truncated } } : {}),
    ...(control ? { inRunControl: { state: control.state, method: control.method,
      controls: control.controls } } : {}),
    ...(apiEvidence ? { apiEvidence: { basis: apiEvidence.basis,
      steps: apiEvidence.steps.map(step => ({ ordinal: step.ordinal, phase: step.phase,
        outcome: step.outcome, httpStatus: step.httpStatus })) } } : {}),
    replayAvailable: route === 'replay_api_finding_same_policy' || route === 'replay_native_finding_same_policy',
  };
}

/** Typed, data-only evidence projection. Report and source locations never enter this object. */
export function projectAdviceContext(agent: AgentReport, nativeReplayReportEligible: boolean) {
  const blocking = new Set(agent.scanGate.blockingFindingIds);
  const nativeCheckCount = agent.checks.filter(check => check.checkId === NATIVE_CHECK).length;
  const findingRowsByCheck = new Map<number, number>();
  for (const finding of agent.findings) findingRowsByCheck.set(finding.checkIndex,
    (findingRowsByCheck.get(finding.checkIndex) ?? 0) + 1);
  const checks = [...agent.checks].sort((a, b) => checkPriority(a, blocking) - checkPriority(b, blocking)
    || a.checkIndex - b.checkIndex).slice(0, MAX_CHECKS);
  const selectedCheckIndexes = new Set(checks.map(check => check.checkIndex));
  const checkByIndex = new Map(checks.map(check => [check.checkIndex, check]));
  const findings = agent.findings.map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => selectedCheckIndexes.has(finding.checkIndex))
    .sort((a, b) => Number(b.finding.reachesFailOn) - Number(a.finding.reachesFailOn)
      || severityRank[b.finding.severity] - severityRank[a.finding.severity] || a.index - b.index)
    .slice(0, MAX_FINDINGS);
  const selectedFindings = findings.map(({ finding }) => findingCard(finding, checkByIndex.get(finding.checkIndex)!,
    agent.mode, nativeCheckCount, findingRowsByCheck.get(finding.checkIndex) ?? 0,
    nativeReplayReportEligible));
  const selectedChecks = checks.map(check => checkCard(check, agent.mode, nativeCheckCount));
  const sourceMode = agent.mode === 'source' || agent.mode === 'both' || agent.mode === 'combined';
  const input = {
    projectionVersion: ADVICE_PROJECTION_POLICY_VERSION, schemaVersion: agent.schemaVersion, mode: agent.mode,
    scanGate: { outcome: agent.scanGate.outcome, exitCode: agent.scanGate.exitCode,
      failOn: agent.scanGate.failOn, reasons: agent.scanGate.reasons.map(reason => reason.code).slice(0, 8) },
    scope: { mode: agent.summary?.scope.mode ?? agent.mode, wholeProjectCoverage: 'not_established' as const,
      ...(sourceMode ? { sourceToolSelection: agent.summary?.scope.toolSelection ?? 'unknown' } : {}),
      ...(agent.summary?.scope.analysisProfile ? { analysisProfile: agent.summary.scope.analysisProfile,
        analysisBudgetRevision: agent.summary.scope.analysisBudgetRevision } : {}),
      nextRead: { kind: agent.summary?.nextRead.kind ?? 'review_scope_limitations',
        ...(agent.summary?.nextRead.checkIndex !== undefined ? { checkIndex: agent.summary.nextRead.checkIndex } : {}) } },
    counts: agent.summary?.counts,
    checks: selectedChecks, omittedChecks: 0,
    findings: selectedFindings, omittedFindings: 0,
  };
  const updateOmissions = () => {
    input.omittedChecks = agent.checks.length - input.checks.length;
    input.omittedFindings = agent.findings.length - input.findings.length;
  };
  updateOmissions();
  while (Buffer.byteLength(JSON.stringify(input)) > MAX_BYTES) {
    // Preserve the highest-priority check and its linked findings before trimming
    // lower-priority checks; a single oversized check then loses low-priority rows.
    if (input.checks.length > 1) input.checks.pop();
    else if (input.findings.length > 0) input.findings.pop();
    else if (input.checks.length > 0) input.checks.pop();
    else throw new Error('report_projection_too_large');
    // A finding must never outlive the check whose evidence and execution it references.
    const retained = new Set(input.checks.map(check => check.checkIndex));
    input.findings = input.findings.filter(finding => retained.has(finding.checkIndex));
    updateOmissions();
  }
  const referenceRoutes = new Map<string, RecheckRoute>([['scope', 'review_scope']]);
  for (const check of input.checks) referenceRoutes.set(check.referenceId, check.recheckRoute);
  for (const finding of input.findings) referenceRoutes.set(finding.referenceId, finding.recheckRoute);
  const clean = agent.scanGate.outcome === 'pass' && agent.summary?.counts.findings === 0
    && agent.summary?.counts.incompleteChecks === 0;
  return { input, referenceRoutes, clean };
}
