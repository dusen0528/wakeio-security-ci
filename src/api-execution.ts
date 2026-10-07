import { createHash } from 'node:crypto';
import type { ApiExecutionLedger, ApiExecutionStep, ApiRequestPlan, ApiRequestPlanStep } from './contracts.js';
import { snapshotJsonData } from './json-snapshot.js';

export function apiRequestPlanDigest(policyVersion: 1 | 2, plan: ApiRequestPlan): string {
  return createHash('sha256').update(JSON.stringify({ version: 1, policyVersion, plan })).digest('hex');
}
function counts(steps: ApiExecutionStep[]): ApiExecutionLedger['counts'] {
  return { planned: steps.length, evaluated: steps.filter(s => s.outcome === 'evaluated').length,
    inconclusive: steps.filter(s => s.outcome === 'inconclusive').length,
    notAttempted: steps.filter(s => s.outcome === 'not_attempted').length,
    httpAttempts: steps.reduce((sum, step) => sum + step.httpAttempts, 0) };
}
/** Internal producer; no response data, caller labels, environment names or credentials. */
export function createApiExecutionLedger(policyVersion: 1 | 2, plan: ApiRequestPlan): ApiExecutionLedger {
  const steps: ApiExecutionStep[] = plan.steps.map(step => ({ ordinal: step.ordinal, outcome: 'not_attempted',
    reason: 'not_reached', attemptStart: 0, httpAttempts: 0, httpStatus: null }));
  return { version: 1, basis: 'declared-api-execution', status: 'partial', policyVersion,
    planSha256: apiRequestPlanDigest(policyVersion, plan), plan, steps, counts: counts(steps), reasons: ['incomplete_steps'] };
}
export function finishApiExecutionLedger(value: ApiExecutionLedger, incomplete: boolean): ApiExecutionLedger {
  let offset = 0;
  for (const step of value.steps) { if (step.outcome === 'not_attempted') step.attemptStart = offset; offset += step.httpAttempts; }
  value.counts = counts(value.steps);
  value.reasons = [ ...(value.policyVersion === 1 ? ['legacy_policy' as const] : []),
    ...(incomplete ? ['run_incomplete' as const] : []),
    ...(value.steps.some(s => s.outcome !== 'evaluated') ? ['incomplete_steps' as const] : []) ];
  value.status = value.reasons.length ? 'partial' : 'complete';
  return sanitiseApiExecutionLedger(value);
}
export function invalidApiExecutionLedger(): ApiExecutionLedger {
  return { version: 1, basis: 'declared-api-execution', status: 'invalid', policyVersion: null, planSha256: null,
    plan: null, steps: [], counts: { planned: null, evaluated: null, inconclusive: null, notAttempted: null, httpAttempts: null }, reasons: ['invalid_ledger'] };
}
function fail(): never { throw Error('invalid_api_execution'); }
function object(value: any, keys: string[]): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail();
}
function integer(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}
/** Build fixed-key canonical data after the accessor/proxy-free bounded snapshot. */
function planData(value: any, version: 1 | 2): ApiRequestPlan {
  object(value, ['actorCount', 'caseCount', 'logicalRequests', 'maximumHttpAttempts', 'timeoutMs',
    'maximumResponseBytes', 'maximumTotalResponseBytes', 'allowPrivate', 'steps']);
  if (!integer(value.actorCount, 1, 32) || !integer(value.caseCount, 1, 20)
    || !integer(value.logicalRequests, 1, 64) || value.maximumHttpAttempts !== 64
    || !integer(value.timeoutMs, 1, 120_000) || value.maximumResponseBytes !== 2 * 1024 * 1024
    || value.maximumTotalResponseBytes !== 10 * 1024 * 1024 || typeof value.allowPrivate !== 'boolean'
    || !Array.isArray(value.steps) || value.steps.length !== value.logicalRequests) fail();
  const steps: ApiRequestPlanStep[] = value.steps.map((step: any, index: number) => {
    const identity = step?.phase === 'identity-before' || step?.phase === 'identity-after';
    object(step, ['ordinal', 'method', 'phase', 'actorIndex', ...(identity ? [] : ['caseIndex'])]);
    if (step.ordinal !== index || step.method !== 'GET' || !integer(step.actorIndex, 0, value.actorCount - 1)
      || !['identity-before', 'owner-before', 'deny', 'owner-after', 'identity-after'].includes(step.phase)
      || (!identity && !integer(step.caseIndex, 0, value.caseCount - 1))) fail();
    return { ordinal: index, method: 'GET', phase: step.phase, actorIndex: step.actorIndex,
      ...(identity ? {} : { caseIndex: step.caseIndex }) };
  });
  let index = 0;
  const identities: number[] = [];
  while (steps[index]?.phase === 'identity-before') {
    const actor = steps[index++].actorIndex;
    if (version === 1 || actor <= (identities.at(-1) ?? -1)) fail();
    identities.push(actor);
  }
  if (version === 2 && (identities.length < 1 || identities.length < value.actorCount - 1)) fail();
  for (let caseIndex = 0; caseIndex < value.caseCount; caseIndex++) {
    const before = steps[index++];
    if (before?.phase !== 'owner-before' || before.caseIndex !== caseIndex
      || (version === 2 && !identities.includes(before.actorIndex))) fail();
    const denyActors = new Set<number>();
    while (steps[index]?.phase === 'deny' && steps[index].caseIndex === caseIndex) {
      const actor = steps[index++].actorIndex;
      if (actor === before.actorIndex || denyActors.has(actor)) fail();
      denyActors.add(actor);
    }
    if (!denyActors.size) fail();
    const after = steps[index++];
    if (after?.phase !== 'owner-after' || after.caseIndex !== caseIndex || after.actorIndex !== before.actorIndex) fail();
  }
  for (const actor of identities) {
    const step = steps[index++];
    if (step?.phase !== 'identity-after' || step.actorIndex !== actor) fail();
  }
  if (index !== steps.length) fail();
  return { actorCount: value.actorCount, caseCount: value.caseCount, logicalRequests: value.logicalRequests,
    maximumHttpAttempts: value.maximumHttpAttempts, timeoutMs: value.timeoutMs, maximumResponseBytes: value.maximumResponseBytes,
    maximumTotalResponseBytes: value.maximumTotalResponseBytes, allowPrivate: value.allowPrivate, steps };
}
const REASONS = ['evaluated', 'assertion_inconclusive', 'transport_error', 'network_policy', 'request_budget',
  'body_budget', 'shared_request_budget', 'shared_body_budget', 'cancelled', 'deadline', 'prerequisite_failed', 'not_reached'];
/** Offline structural/accounting verifier. No network, truth, signature or exploit verification. */
export function sanitiseApiExecutionLedger(input: unknown): ApiExecutionLedger {
  try {
    const value = snapshotJsonData(input) as any;
    object(value, ['version', 'basis', 'status', 'policyVersion', 'planSha256', 'plan', 'steps', 'counts', 'reasons']);
    if (value.version !== 1 || value.basis !== 'declared-api-execution'
      || ![1, 2].includes(value.policyVersion) || !['complete', 'partial'].includes(value.status)) fail();
    const plan = planData(value.plan, value.policyVersion);
    const planSha256 = apiRequestPlanDigest(value.policyVersion, plan);
    if (value.planSha256 !== planSha256 || !Array.isArray(value.steps) || value.steps.length !== plan.steps.length) fail();
    let offset = 0;
    const steps: ApiExecutionStep[] = value.steps.map((step: any, index: number) => {
      object(step, ['ordinal', 'outcome', 'reason', 'attemptStart', 'httpAttempts', 'httpStatus']);
      if (step.ordinal !== index || !['evaluated', 'inconclusive', 'not_attempted'].includes(step.outcome)
        || !REASONS.includes(step.reason) || step.attemptStart !== offset
        || !integer(step.httpAttempts, 0, 64 - offset)
        || (step.httpStatus !== null && !integer(step.httpStatus, 100, 599))) fail();
      if (step.outcome === 'evaluated' ? step.reason !== 'evaluated' || step.httpAttempts < 1 || step.httpStatus === null
        : step.reason === 'evaluated') fail();
      if (step.outcome === 'not_attempted' ? step.httpAttempts !== 0 || step.httpStatus !== null : step.httpAttempts < 1) fail();
      if (['prerequisite_failed', 'not_reached'].includes(step.reason) && step.outcome !== 'not_attempted') fail();
      if (!['evaluated', 'assertion_inconclusive'].includes(step.reason) && step.httpStatus !== null) fail();
      if (step.reason === 'request_budget' && step.attemptStart + step.httpAttempts !== 64) fail();
      if (step.reason === 'assertion_inconclusive' && (step.outcome !== 'inconclusive' || step.httpStatus === null)) fail();
      const planned = plan.steps[index];
      if (step.outcome === 'evaluated') {
        if (planned.phase !== 'deny' && (step.httpStatus < 200 || step.httpStatus >= 300)) fail();
        if (planned.phase === 'deny' && (step.httpStatus < 200 || (step.httpStatus >= 300 && step.httpStatus < 400)
          || step.httpStatus === 429 || step.httpStatus >= 500
          || (step.httpStatus === 401 && plan.steps.some(p => p.phase === 'identity-before' && p.actorIndex === planned.actorIndex)))) fail();
      }
      if (step.reason === 'prerequisite_failed' && !['deny', 'owner-after'].includes(planned.phase)) fail();
      offset += step.httpAttempts;
      return { ordinal: index, outcome: step.outcome, reason: step.reason, attemptStart: step.attemptStart,
        httpAttempts: step.httpAttempts, httpStatus: step.httpStatus };
    });
    let stopped = false;
    for (const step of steps) {
      if (stopped && step.httpAttempts > 0) fail();
      if (['body_budget', 'shared_body_budget', 'shared_request_budget', 'cancelled', 'deadline', 'request_budget'].includes(step.reason)) stopped = true;
      const planned = plan.steps[step.ordinal];
      if (planned.phase === 'deny' && step.outcome === 'evaluated') {
        const identity = plan.steps.find(p => p.phase === 'identity-before' && p.actorIndex === planned.actorIndex);
        if (identity && steps[identity.ordinal].outcome !== 'evaluated') fail();
      }
    }
    for (const planned of plan.steps) {
      if (!['deny', 'owner-after'].includes(planned.phase)) continue;
      const before = plan.steps.find(p => p.phase === 'owner-before' && p.caseIndex === planned.caseIndex)!;
      if (steps[before.ordinal].outcome !== 'evaluated' && (steps[planned.ordinal].outcome !== 'not_attempted'
        || steps[planned.ordinal].reason !== 'prerequisite_failed')) fail();
      if (steps[before.ordinal].outcome === 'evaluated' && steps[planned.ordinal].reason === 'prerequisite_failed') fail();
    }
    const expectedCounts = counts(steps);
    object(value.counts, Object.keys(expectedCounts));
    if (Object.entries(expectedCounts).some(([key, count]) => value.counts[key] !== count)) fail();
    if (!Array.isArray(value.reasons) || value.reasons.length > 3 || new Set(value.reasons).size !== value.reasons.length
      || value.reasons.some((r: string) => !['legacy_policy', 'run_incomplete', 'incomplete_steps'].includes(r))) fail();
    if (value.reasons.includes('legacy_policy') !== (value.policyVersion === 1)
      || value.reasons.includes('incomplete_steps') !== steps.some(step => step.outcome !== 'evaluated')
      || value.status !== (value.reasons.length ? 'partial' : 'complete')) fail();
    return { version: 1, basis: 'declared-api-execution', status: value.status, policyVersion: value.policyVersion,
      planSha256, plan, steps, counts: expectedCounts,
      reasons: ['legacy_policy', 'run_incomplete', 'incomplete_steps'].filter(r => value.reasons.includes(r)) as ApiExecutionLedger['reasons'] };
  } catch { return invalidApiExecutionLedger(); }
}
