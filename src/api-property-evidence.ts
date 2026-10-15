import { snapshotJsonData } from './json-snapshot.js';
import type { ApiPropertyPhase, ApiPropertyReason, ApiPropertyWriteEvidence, ApiPropertyWriteStep, CheckResult } from './contracts.js';

export const API_PROPERTY_CHECK = 'api.property-write';
export const API_PROPERTY_RULE = 'api.property-write-unauthorized-effect';
export const API_PROPERTY_SCOPE = 'policy-resource-property-write' as const;
const PHASES: readonly ApiPropertyPhase[] = ['owner-identity-before', 'verifier-identity-before', 'owner-resource', 'baseline-read',
  'owner-precondition', 'owner-precondition-read', 'verifier-precondition', 'verifier-precondition-read', 'owner-normal', 'owner-normal-read',
  'verifier-positive', 'verifier-positive-read', 'verifier-restore', 'verifier-restore-read', 'owner-probe', 'probe-read',
  'owner-barrier', 'barrier-read', 'cleanup', 'cleanup-read', 'owner-identity-after', 'verifier-identity-after', 'reconcile-read'];
const PATCHES = new Set([4, 6, 8, 10, 12, 14, 16, 18]);
const OWNER = new Set([0, 2, 4, 8, 14, 16, 20]);
const CONTROL_STEPS = { identityBefore: [0, 1], ownerResource: [2], ownerPrecondition: [4, 5], verifierPrecondition: [6, 7],
  normal: [8, 9], positive: [10, 11], restore: [12, 13], freshness: [14, 15, 16, 17], identityAfter: [20, 21] } as const;
const REASONS: readonly ApiPropertyReason[] = ['none', 'invalid_evidence', 'invalid_policy', 'consent_missing', 'credential_unavailable',
  'identity_failed', 'resource_mismatch', 'run_marker_mismatch', 'baseline_mismatch', 'unsupported_validator', 'precondition_not_enforced',
  'positive_control_failed', 'normal_failed', 'restore_failed', 'freshness_failed', 'unexpected_mutation', 'response_invalid',
  'readback_unobservable', 'stale_or_conflicting_state', 'write_ambiguous', 'cleanup_failed', 'cleanup_unconfirmed', 'request_limit',
  'body_limit', 'transport_error', 'target_refused', 'deadline', 'cancelled'];
const exact = (v: object, names: readonly string[]) => Object.keys(v).every(k => names.includes(k));
const enumValue = (v: unknown, names: readonly string[]) => typeof v === 'string' && names.includes(v);
export function apiPropertySteps(): ApiPropertyWriteStep[] {
  return PHASES.map((phase, ordinal) => ({ ordinal, phase, method: PATCHES.has(ordinal) ? 'PATCH' : 'GET',
    actorIndex: OWNER.has(ordinal) ? 0 : 1, attempted: false, outcome: 'not_attempted', httpStatus: null, reason: 'none' }));
}
export function unknownApiPropertyWriteEvidence(reason: ApiPropertyReason = 'invalid_evidence'): ApiPropertyWriteEvidence {
  return { version: 1, scope: API_PROPERTY_SCOPE, basis: 'authenticated-http-readback', execution: 'partial', effect: 'unknown',
    provisional: 'unknown', controls: { identityBefore: 'not_run', ownerResource: 'not_run', ownerPrecondition: 'not_run',
      verifierPrecondition: 'not_run', normal: 'not_run', positive: 'not_run', restore: 'not_run', freshness: 'not_run', identityAfter: 'not_run' },
    cleanup: 'not_run', budget: { maxRequests: null, timeoutMs: null, maxRequestBodyBytes: 4096, maxResponseBodyBytes: 65536, maxTotalResponseBytes: 1048576 }, stopReason: reason, reasons: [reason], counts: { plannedRequests: 22, httpAttempts: 0, patchAttempts: 0, capturedResponses: 0 },
    ledger: { version: 1, status: 'partial', maximumHttpAttempts: 23, maximumPatchAttempts: 8, steps: apiPropertySteps() } };
}
/** Syntax/consistency only: a well-formed ledger does not authenticate remote state. */
export function parseApiPropertyWriteEvidence(input: unknown): ApiPropertyWriteEvidence | undefined {
  try {
    const e = snapshotJsonData(input) as ApiPropertyWriteEvidence;
    if (!e || !exact(e, ['version', 'scope', 'basis', 'execution', 'effect', 'provisional', 'controls', 'cleanup', 'policySha256', 'budget', 'stopReason', 'reasons', 'counts', 'ledger'])
      || e.version !== 1 || e.scope !== API_PROPERTY_SCOPE || e.basis !== 'authenticated-http-readback'
      || !enumValue(e.execution, ['completed', 'partial', 'error']) || !enumValue(e.effect, ['observed', 'not_observed', 'unknown'])
      || !enumValue(e.provisional, ['observed', 'not_observed', 'unknown']) || !enumValue(e.cleanup, ['confirmed', 'unknown', 'not_run', 'not_needed'])
      || !enumValue(e.stopReason, REASONS) || !Array.isArray(e.reasons) || e.reasons.length > REASONS.length
      || new Set(e.reasons).size !== e.reasons.length || e.reasons.some(r => r === 'none' || !enumValue(r, REASONS))
      || (e.policySha256 !== undefined && (typeof e.policySha256 !== 'string' || !/^[a-f0-9]{64}$/.test(e.policySha256)))) return undefined;
    const b = e.budget;
    if (!b || Object.keys(b).length !== 5 || !exact(b, ['maxRequests', 'timeoutMs', 'maxRequestBodyBytes', 'maxResponseBodyBytes', 'maxTotalResponseBytes'])
      || b.maxRequestBodyBytes !== 4096 || b.maxResponseBodyBytes !== 65536 || b.maxTotalResponseBytes !== 1048576
      || b.maxRequests !== null && (!Number.isSafeInteger(b.maxRequests) || b.maxRequests < 1 || b.maxRequests > 23)
      || b.timeoutMs !== null && (!Number.isSafeInteger(b.timeoutMs) || b.timeoutMs < 1 || b.timeoutMs > 120000)) return undefined;
    if (!e.controls || Object.keys(e.controls).length !== 9 || !exact(e.controls, Object.keys(CONTROL_STEPS))
      || Object.values(e.controls).some(v => !enumValue(v, ['passed', 'failed', 'unknown', 'not_run']))) return undefined;
    if (!e.counts || Object.keys(e.counts).length !== 4 || !exact(e.counts, ['plannedRequests', 'httpAttempts', 'patchAttempts', 'capturedResponses'])
      || e.counts.plannedRequests !== 22 || !Object.values(e.counts).every(v => Number.isSafeInteger(v) && v >= 0)) return undefined;
    const l = e.ledger;
    if (!l || Object.keys(l).length !== 5 || !exact(l, ['version', 'status', 'maximumHttpAttempts', 'maximumPatchAttempts', 'steps'])
      || l.version !== 1 || l.maximumHttpAttempts !== 23 || l.maximumPatchAttempts !== 8 || !enumValue(l.status, ['complete', 'partial'])
      || !Array.isArray(l.steps) || l.steps.length !== 23) return undefined;
    let attempts = 0, patches = 0, responses = 0, stopped = false;
    for (const [i, s] of l.steps.entries()) {
      const expected = apiPropertySteps()[i];
      if (!s || Object.keys(s).length !== 8 || !exact(s, ['ordinal', 'phase', 'method', 'actorIndex', 'attempted', 'outcome', 'httpStatus', 'reason'])
        || s.ordinal !== i || s.phase !== expected.phase || s.method !== expected.method || s.actorIndex !== expected.actorIndex
        || typeof s.attempted !== 'boolean' || !enumValue(s.outcome, ['evaluated', 'inconclusive', 'not_attempted']) || !enumValue(s.reason, REASONS)
        || s.httpStatus !== null && (!Number.isSafeInteger(s.httpStatus) || s.httpStatus < 100 || s.httpStatus > 599)) return undefined;
      if (!s.attempted) { if (s.outcome !== 'not_attempted' || s.httpStatus !== null || s.reason !== 'none') return undefined; if (i < 22) stopped = true; continue; }
      if (s.outcome === 'not_attempted' || i < 22 && stopped) return undefined;
      attempts++; if (s.method === 'PATCH') patches++; if (s.httpStatus !== null) responses++;
      if (s.outcome === 'evaluated') {
        const allowed = s.method === 'GET' ? [200] : i === 4 || i === 6 ? [412] : i === 14 ? [200, 204, 403] : [200, 204];
        if (s.reason !== 'none' || !allowed.includes(s.httpStatus!)) return undefined;
      } else { if (s.reason === 'none') return undefined; if (i < 22) stopped = true; }
    }
    if (attempts !== e.counts.httpAttempts || patches !== e.counts.patchAttempts || responses !== e.counts.capturedResponses || attempts > 23 || patches > 8
      || attempts > 0 && (b.maxRequests === null || b.timeoutMs === null) || b.maxRequests !== null && attempts > b.maxRequests) return undefined;
    const evaluated = (i: number) => l.steps[i].outcome === 'evaluated';
    for (const [name, indices] of Object.entries(CONTROL_STEPS)) {
      if (e.controls[name as keyof typeof CONTROL_STEPS] === 'passed' && !indices.every(evaluated)) return undefined;
    }
    // An effect requires fresh verifier readback after a successful owner-only nonce barrier.
    if (e.effect !== 'unknown' && (e.effect !== e.provisional || !l.steps.slice(0, 18).every(s => s.outcome === 'evaluated')
      || Object.entries(e.controls).some(([k, v]) => k !== 'identityAfter' && v !== 'passed'))) return undefined;
    if (e.provisional !== 'unknown' && !evaluated(15)) return undefined;
    if (e.cleanup === 'confirmed' && (!evaluated(18) || !evaluated(19))) return undefined;
    if (e.cleanup === 'not_needed' && patches !== 0) return undefined;
    const reconcile = l.steps[22];
    const lastAttempted = [...l.steps.slice(0, 22)].reverse().find(s => s.attempted);
    if (reconcile.attempted && (e.execution === 'completed' || !lastAttempted || lastAttempted.method !== 'PATCH'
      || lastAttempted.outcome !== 'inconclusive' || ['cancelled', 'deadline', 'body_limit'].includes(lastAttempted.reason))) return undefined;
    if (e.execution === 'completed') {
      if (l.status !== 'complete' || b.maxRequests === null || b.maxRequests < 22 || b.timeoutMs === null || !e.policySha256 || e.stopReason !== 'none' || e.reasons.length || e.effect === 'unknown'
        || e.cleanup !== 'confirmed' || Object.values(e.controls).some(v => v !== 'passed') || attempts !== 22 || responses !== 22 || patches !== 8
        || reconcile.attempted || !l.steps.slice(0, 22).every(s => s.outcome === 'evaluated')) return undefined;
    } else if (l.status !== 'partial' || e.stopReason === 'none' || e.reasons[0] !== e.stopReason) return undefined;
    return e;
  } catch { return undefined; }
}
export function sanitiseApiPropertyWriteEvidence(input: unknown): ApiPropertyWriteEvidence {
  return parseApiPropertyWriteEvidence(input) ?? unknownApiPropertyWriteEvidence();
}
/** Cross-check the candidate and closed numeric metrics; no replay authority is created. */
export function apiPropertyCheckConsistent(check: Pick<CheckResult, 'id' | 'findings' | 'metrics'>, evidence: ApiPropertyWriteEvidence): boolean {
  if (check.id !== API_PROPERTY_CHECK || check.metrics?.httpAttempts !== evidence.counts.httpAttempts || check.metrics?.patchAttempts !== evidence.counts.patchAttempts) return false;
  const expected = evidence.effect === 'observed' ? 1 : 0;
  return check.findings.length === expected && check.findings.every(f => f.ruleId === API_PROPERTY_RULE && f.kind === 'candidate' && f.severity === 'high' && f.confidence === 'low');
}
