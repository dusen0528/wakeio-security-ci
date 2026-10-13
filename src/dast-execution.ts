import { snapshotJsonData } from "./json-snapshot.js";

/** Redacted, fixed-plan evidence for the owned numeric SQL differential probe. */
export type DastPhase = "baseline-before" | "true" | "false" | "baseline-after";
export type DastStepReason = "evaluated" | "response_invalid" | "network_policy" | "transport_error"
  | "request_budget" | "body_budget" | "cancelled" | "deadline" | "not_reached";
export type DastOracleMatch = "baseline" | "false" | "other" | "unavailable";

export interface DastExecutionStep {
  ordinal: number;
  round: 1 | 2;
  phase: DastPhase;
  outcome: "evaluated" | "inconclusive" | "not_attempted";
  reason: DastStepReason;
  attemptStart: number;
  httpAttempts: number;
  httpStatus: number | null;
  oracleMatch: DastOracleMatch;
}

export interface DastExecutionV1 {
  version: 1;
  policySha256: string;
  profile: "numeric";
  profileRevision: "sql-boolean-numeric-v1";
  maxRequests: number;
  timeoutMs: number;
  allowPrivate: boolean;
  status: "complete" | "partial" | "invalid";
  outcome: "observed" | "not_observed" | "inconclusive";
  plannedRequests: 8;
  steps: DastExecutionStep[];
  counts: { evaluated: number; inconclusive: number; notAttempted: number; httpAttempts: number };
  stopReason: DastStepReason | "oracle_inconsistent" | "none";
}

const PHASES: DastPhase[] = ["baseline-before", "true", "false", "baseline-after"];
const REASONS: readonly DastStepReason[] = ["evaluated", "response_invalid", "network_policy", "transport_error", "request_budget", "body_budget", "cancelled", "deadline", "not_reached"];
const MATCHES: readonly DastOracleMatch[] = ["baseline", "false", "other", "unavailable"];
const SHA256 = /^[0-9a-f]{64}$/;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Validate a ledger as data. No response value or request URL belongs in it. */
function sanitizeV1(raw: unknown): DastExecutionV1 | null {
  try { raw = snapshotJsonData(raw); } catch { return null; }
  if (!record(raw) || raw.version !== 1 || typeof raw.policySha256 !== "string" || !SHA256.test(raw.policySha256)
    || raw.profile !== "numeric" || raw.profileRevision !== "sql-boolean-numeric-v1"
    || !Number.isSafeInteger(raw.maxRequests) || Number(raw.maxRequests) < 1 || Number(raw.maxRequests) > 64
    || !Number.isSafeInteger(raw.timeoutMs) || Number(raw.timeoutMs) < 1 || Number(raw.timeoutMs) > 120_000
    || typeof raw.allowPrivate !== "boolean" || !["complete", "partial", "invalid"].includes(String(raw.status))
    || !["observed", "not_observed", "inconclusive"].includes(String(raw.outcome)) || raw.plannedRequests !== 8
    || !Array.isArray(raw.steps) || raw.steps.length !== 8 || !record(raw.counts)
    || ![...REASONS, "oracle_inconsistent", "none"].includes(String(raw.stopReason))) return null;
  let evaluated = 0, inconclusive = 0, notAttempted = 0, httpAttempts = 0;
  let stopped = false;
  const steps: DastExecutionStep[] = [];
  for (let ordinal = 0; ordinal < 8; ordinal++) {
    const value = raw.steps[ordinal];
    if (!record(value) || value.ordinal !== ordinal || value.round !== Math.floor(ordinal / 4) + 1
      || value.phase !== PHASES[ordinal % 4] || !["evaluated", "inconclusive", "not_attempted"].includes(String(value.outcome))
      || !REASONS.includes(value.reason as DastStepReason)
      || !Number.isSafeInteger(value.attemptStart) || Number(value.attemptStart) !== httpAttempts
      || !Number.isSafeInteger(value.httpAttempts) || Number(value.httpAttempts) < 0 || Number(value.httpAttempts) > 32
      || (value.httpStatus !== null && (!Number.isSafeInteger(value.httpStatus) || Number(value.httpStatus) < 100 || Number(value.httpStatus) > 599))
      || !MATCHES.includes(value.oracleMatch as DastOracleMatch)) return null;
    if (stopped && value.outcome !== "not_attempted") return null;
    if (value.outcome === "evaluated") {
      if (value.reason !== "evaluated" || Number(value.httpAttempts) < 1 || Number(value.httpStatus) < 200
        || Number(value.httpStatus) > 299 || value.oracleMatch === "unavailable") return null;
      evaluated++;
    } else if (value.outcome === "inconclusive") {
      if (value.reason === "evaluated" || value.reason === "not_reached" || value.oracleMatch !== "unavailable") return null;
      inconclusive++;
      stopped = true;
    } else {
      if (value.reason !== "not_reached" || value.httpAttempts !== 0 || value.httpStatus !== null || value.oracleMatch !== "unavailable") return null;
      notAttempted++;
      stopped = true;
    }
    steps.push({ ordinal, round: value.round as 1 | 2, phase: value.phase as DastPhase,
      outcome: value.outcome as DastExecutionStep["outcome"], reason: value.reason as DastStepReason,
      attemptStart: Number(value.attemptStart), httpAttempts: Number(value.httpAttempts),
      httpStatus: value.httpStatus as number | null, oracleMatch: value.oracleMatch as DastOracleMatch });
    httpAttempts += Number(value.httpAttempts);
    if (httpAttempts > Number(raw.maxRequests)) return null;
  }
  if (raw.counts.evaluated !== evaluated || raw.counts.inconclusive !== inconclusive
    || raw.counts.notAttempted !== notAttempted || raw.counts.httpAttempts !== httpAttempts) return null;
  if (raw.status === "invalid") return null;
  if (raw.status === "complete" && (evaluated !== 8 || inconclusive !== 0 || notAttempted !== 0)) return null;
  if (raw.status !== "complete" && raw.outcome !== "inconclusive") return null;
  if (raw.status === "complete" && raw.outcome === "inconclusive") return null;
  if (raw.outcome === "observed" && steps.some((step) => step.oracleMatch !== (step.phase === "false" ? "false" : "baseline"))) return null;
  if (raw.outcome === "not_observed") {
    if (steps.some(step => (step.phase === "baseline-before" || step.phase === "baseline-after") && step.oracleMatch !== "baseline")) return null;
    const probes = steps.filter(step => step.phase === "true" || step.phase === "false");
    if (probes.some(step => step.oracleMatch !== "baseline" && step.oracleMatch !== "false")
      || probes.some(step => step.oracleMatch !== probes[0]!.oracleMatch)) return null;
  }
  if (raw.status === "complete" && raw.stopReason !== "none") return null;
  if (raw.status !== "complete" && raw.stopReason === "none") return null;
  const firstIncomplete = steps.find(step => step.outcome === "inconclusive");
  if (firstIncomplete && raw.stopReason !== firstIncomplete.reason) return null;
  if (!firstIncomplete && notAttempted > 0) return null;
  if (raw.status === "partial" && !firstIncomplete && (evaluated !== 8 || raw.stopReason !== "oracle_inconsistent")) return null;
  return { version: 1, policySha256: raw.policySha256, profile: "numeric", profileRevision: "sql-boolean-numeric-v1",
    maxRequests: Number(raw.maxRequests), timeoutMs: Number(raw.timeoutMs), allowPrivate: raw.allowPrivate,
    status: raw.status as DastExecution["status"],
    outcome: raw.outcome as DastExecution["outcome"], plannedRequests: 8, steps,
    counts: { evaluated, inconclusive, notAttempted, httpAttempts }, stopReason: raw.stopReason as DastExecutionV1["stopReason"] };
}


export type DastIdentityOutcome = "matched" | "mismatched" | "inconclusive" | "not_attempted";
export type DastAuthStepReason = DastStepReason | "identity_mismatch";
export type DastAuthPhase = DastPhase | "identity-before" | "identity-after";
export interface DastAuthExecutionStep extends Omit<DastExecutionStep, "round" | "phase" | "reason"> {
  round: 0 | 1 | 2;
  phase: DastAuthPhase;
  reason: DastAuthStepReason;
}
export interface DastExecutionV2 extends Omit<DastExecutionV1, "version" | "profileRevision" | "plannedRequests" | "steps" | "stopReason"> {
  version: 2;
  profileRevision: "sql-boolean-numeric-auth-v2";
  plannedRequests: 10;
  steps: DastAuthExecutionStep[];
  identityControls: { before: DastIdentityOutcome; after: DastIdentityOutcome };
  probeOutcome: DastExecutionV1["outcome"];
  stopReason: DastExecutionV1["stopReason"] | "identity_mismatch";
}
export interface DastExecutionV3Unauth extends Omit<DastExecutionV1, 'version' | 'profile' | 'profileRevision' | 'status'> {
  version: 3;
  profile: 'single-quoted';
  profileRevision: 'sql-boolean-single-quoted-v3';
  authentication: 'none';
  status: 'complete' | 'partial';
}
export interface DastExecutionV3Auth extends Omit<DastExecutionV2, 'version' | 'profile' | 'profileRevision'> {
  version: 3;
  profile: 'single-quoted';
  profileRevision: 'sql-boolean-single-quoted-auth-v3';
  authentication: 'authorization';
}
export type DastExecutionV3 = DastExecutionV3Unauth | DastExecutionV3Auth;
export type DastJsonStepReason = DastAuthStepReason | 'benign_control_mismatch';
export interface DastJsonExecutionStep extends Omit<DastAuthExecutionStep, 'phase' | 'reason' | 'oracleMatch'> {
  phase: DastAuthPhase | 'benign-alternate';
  reason: DastJsonStepReason;
  oracleMatch: DastOracleMatch | 'alternate';
}
export interface DastExecutionV4 extends Omit<DastExecutionV2, 'version' | 'profileRevision' | 'plannedRequests' | 'steps' | 'stopReason' | 'status'> {
  status: 'complete' | 'partial';
  version: 4;
  method: 'POST';
  authentication: 'authorization';
  profileRevision: 'sql-boolean-json-auth-v4';
  plannedRequests: 12;
  steps: DastJsonExecutionStep[];
  normalControls: { round1: DastIdentityOutcome; round2: DastIdentityOutcome };
  stopReason: DastExecutionV2['stopReason'] | 'benign_control_mismatch';
}
export type DastExecution = DastExecutionV1 | DastExecutionV2 | DastExecutionV3 | DastExecutionV4;
export function isLegacyDastExecution(execution: DastExecution): execution is DastExecutionV1 { return execution.version === 1; }
export function hasDastIdentityControls(execution: DastExecution): execution is DastExecutionV2 | DastExecutionV3Auth | DastExecutionV4 {
  return execution.version === 4 || execution.version === 2 || execution.version === 3 && execution.authentication === 'authorization';
}

/** Classifies only the eight SQL phases, independently of identity controls. */
export function dastProbeOutcome(steps: readonly DastExecutionStep[]): DastExecutionV1["outcome"] {
  if (steps.length !== 8 || steps.some(step => step.outcome !== "evaluated")) return "inconclusive";
  if (steps.some(step => (step.phase === "baseline-before" || step.phase === "baseline-after") && step.oracleMatch !== "baseline")) return "inconclusive";
  if (steps.every(step => step.oracleMatch === (step.phase === "false" ? "false" : "baseline"))) return "observed";
  const probes = steps.filter(step => step.phase === "true" || step.phase === "false");
  return probes.every(step => step.oracleMatch === probes[0]!.oracleMatch && ["baseline", "false"].includes(step.oracleMatch)) ? "not_observed" : "inconclusive";
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function sanitizeFixed(raw: Record<string, unknown>): DastExecutionV2 | DastExecutionV3 | null {
  const quoted = raw.version === 3;
  const authenticated = raw.version === 2 || quoted && raw.authentication === 'authorization';
  const plannedRequests = authenticated ? 10 : 8;
  const revision = quoted ? authenticated ? 'sql-boolean-single-quoted-auth-v3' : 'sql-boolean-single-quoted-v3' : 'sql-boolean-numeric-auth-v2';
  if ((!quoted && raw.version !== 2) || quoted && !['none', 'authorization'].includes(String(raw.authentication))
    || !exact(raw, ["version", "policySha256", "profile", "profileRevision", "maxRequests", "timeoutMs", "allowPrivate", "status", "outcome", "plannedRequests", "steps", "counts", "stopReason", ...(quoted ? ['authentication'] : []), ...(authenticated ? ["identityControls", "probeOutcome"] : [])])
    || typeof raw.policySha256 !== "string" || !SHA256.test(raw.policySha256) || raw.profile !== (quoted ? 'single-quoted' : "numeric") || raw.profileRevision !== revision
    || !Number.isSafeInteger(raw.maxRequests) || Number(raw.maxRequests) < 1 || Number(raw.maxRequests) > 64
    || !Number.isSafeInteger(raw.timeoutMs) || Number(raw.timeoutMs) < 1 || Number(raw.timeoutMs) > 120_000
    || typeof raw.allowPrivate !== "boolean" || !["complete", "partial"].includes(String(raw.status))
    || !["observed", "not_observed", "inconclusive"].includes(String(raw.outcome)) || raw.plannedRequests !== plannedRequests
    || !Array.isArray(raw.steps) || raw.steps.length !== plannedRequests || !record(raw.counts)
    || !exact(raw.counts, ["evaluated", "inconclusive", "notAttempted", "httpAttempts"])
    || authenticated && (!record(raw.identityControls) || !exact(raw.identityControls, ["before", "after"]))) return null;
  const steps: DastAuthExecutionStep[] = [];
  let evaluated = 0, inconclusive = 0, notAttempted = 0, httpAttempts = 0, stopped = false;
  for (let ordinal = 0; ordinal < plannedRequests; ordinal++) {
    const value = raw.steps[ordinal], identity = authenticated && (ordinal === 0 || ordinal === 9);
    const sqlIndex = ordinal - (authenticated ? 1 : 0);
    const phase: DastAuthPhase = identity ? ordinal === 0 ? "identity-before" : "identity-after" : PHASES[sqlIndex % 4]!;
    const round = identity ? 0 : Math.floor(sqlIndex / 4) + 1;
    if (!record(value) || !exact(value, ["ordinal", "round", "phase", "outcome", "reason", "attemptStart", "httpAttempts", "httpStatus", "oracleMatch"])
      || value.ordinal !== ordinal || value.round !== round || value.phase !== phase
      || !["evaluated", "inconclusive", "not_attempted"].includes(String(value.outcome))
      || ![...REASONS, ...(identity ? ["identity_mismatch"] : [])].includes(String(value.reason))
      || !Number.isSafeInteger(value.attemptStart) || value.attemptStart !== httpAttempts
      || !Number.isSafeInteger(value.httpAttempts) || Number(value.httpAttempts) < 0 || Number(value.httpAttempts) > 32
      || value.httpStatus !== null && (!Number.isSafeInteger(value.httpStatus) || Number(value.httpStatus) < 100 || Number(value.httpStatus) > 599)
      || !MATCHES.includes(value.oracleMatch as DastOracleMatch) || identity && value.oracleMatch !== "unavailable") return null;
    if (stopped && value.outcome !== "not_attempted") return null;
    if (value.outcome === "evaluated") {
      if (value.reason !== "evaluated" || Number(value.httpAttempts) < 1 || Number(value.httpStatus) < 200 || Number(value.httpStatus) > 299
        || !identity && value.oracleMatch === "unavailable") return null;
      evaluated++;
    } else if (value.outcome === "inconclusive") {
      if (["evaluated", "not_reached"].includes(String(value.reason)) || value.oracleMatch !== "unavailable"
        || value.reason === "identity_mismatch" && (Number(value.httpAttempts) < 1 || Number(value.httpStatus) < 200 || Number(value.httpStatus) > 299)) return null;
      inconclusive++; stopped = true;
    } else {
      if (!stopped || value.reason !== "not_reached" || value.httpAttempts !== 0 || value.httpStatus !== null || value.oracleMatch !== "unavailable") return null;
      notAttempted++;
    }
    steps.push({ ordinal, round: round as 0 | 1 | 2, phase, outcome: value.outcome as DastAuthExecutionStep["outcome"], reason: value.reason as DastAuthStepReason,
      attemptStart: httpAttempts, httpAttempts: Number(value.httpAttempts), httpStatus: value.httpStatus as number | null, oracleMatch: value.oracleMatch as DastOracleMatch });
    httpAttempts += Number(value.httpAttempts); if (httpAttempts > Number(raw.maxRequests)) return null;
  }
  const counts = { evaluated, inconclusive, notAttempted, httpAttempts };
  if (Object.entries(counts).some(([key, value]) => raw.counts && (raw.counts as Record<string, unknown>)[key] !== value)) return null;
  const identityOutcome = (step: DastAuthExecutionStep): DastIdentityOutcome => step.outcome === "evaluated" ? "matched"
    : (step.outcome === "not_attempted" || step.httpAttempts === 0) ? "not_attempted" : step.reason === "identity_mismatch" ? "mismatched" : "inconclusive";
  const identityControls = authenticated ? { before: identityOutcome(steps[0]!), after: identityOutcome(steps[9]!) } : undefined;
  if (authenticated && (!record(raw.identityControls) || raw.identityControls.before !== identityControls!.before || raw.identityControls.after !== identityControls!.after)) return null;
  const probeOutcome = dastProbeOutcome((authenticated ? steps.slice(1, 9) : steps) as DastExecutionStep[]);
  if (authenticated && raw.probeOutcome !== probeOutcome) return null;
  const outcome = !authenticated || identityControls!.before === "matched" && identityControls!.after === "matched" ? probeOutcome : "inconclusive";
  const status: 'partial' | 'complete' = outcome === "inconclusive" ? "partial" : "complete";
  const firstFailure = steps.find(step => step.outcome === "inconclusive");
  const stopReason = firstFailure?.reason ?? (status === "complete" ? "none" : "oracle_inconsistent");
  if (raw.outcome !== outcome || raw.status !== status || raw.stopReason !== stopReason) return null;
  if (!quoted) return { version: 2, policySha256: raw.policySha256, profile: "numeric", profileRevision: "sql-boolean-numeric-auth-v2",
    maxRequests: Number(raw.maxRequests), timeoutMs: Number(raw.timeoutMs), allowPrivate: raw.allowPrivate, status, outcome,
    plannedRequests: 10, steps, counts, identityControls: identityControls!, probeOutcome, stopReason };
  const common = { policySha256: raw.policySha256, maxRequests: Number(raw.maxRequests), timeoutMs: Number(raw.timeoutMs), allowPrivate: raw.allowPrivate,
    status, outcome, counts };
  return authenticated ? { version: 3, ...common, profile: 'single-quoted', profileRevision: 'sql-boolean-single-quoted-auth-v3', authentication: 'authorization',
    plannedRequests: 10, steps, identityControls: identityControls!, probeOutcome, stopReason }
    : { version: 3, ...common, profile: 'single-quoted', profileRevision: 'sql-boolean-single-quoted-v3', authentication: 'none',
      plannedRequests: 8, steps: steps as DastExecutionStep[], stopReason: stopReason as DastExecutionV3Unauth['stopReason'] };
}

/** Strict fixed-plan v2/v3 reconstruction and backward-compatible v1 normalization. */
export function sanitizeDastExecution(raw: unknown): DastExecution | null {
  try { raw = snapshotJsonData(raw); } catch { return null; }
  if (!record(raw)) return null;
  return raw.version === 4 ? sanitizeJsonPost(raw) : raw.version === 2 || raw.version === 3 ? sanitizeFixed(raw) : sanitizeV1(raw);
}
/** Use only after ledger sanitation. An observed SQL differential survives failed trailing identity. */
export function isDastObservedEvidence(execution: DastExecution): boolean {
  return hasDastIdentityControls(execution) ? execution.probeOutcome === "observed" : execution.status === "complete" && execution.outcome === "observed";
}
/** Original replay authority requires complete controls, not merely retained probe evidence. */
export function isDastReplayableExecution(execution: DastExecution): boolean {
  return execution.status === "complete" && execution.outcome === "observed"
    && (!hasDastIdentityControls(execution) || execution.probeOutcome === "observed" && execution.identityControls.before === "matched" && execution.identityControls.after === "matched");
}

export function dastJsonNormalControls(steps: readonly DastJsonExecutionStep[]): DastExecutionV4['normalControls'] {
  const round = (n: 1 | 2): DastIdentityOutcome => {
    const controls = steps.filter(step => step.round === n && ['baseline-before', 'benign-alternate', 'baseline-after'].includes(step.phase));
    if (controls.some(step => step.reason === 'benign_control_mismatch')) return 'mismatched';
    if (controls.length === 3 && controls.every(step => step.outcome === 'evaluated' && step.oracleMatch === (step.phase === 'benign-alternate' ? 'alternate' : 'baseline'))) return 'matched';
    return controls.some(step => step.outcome === 'inconclusive' && step.httpAttempts > 0) ? 'inconclusive' : 'not_attempted';
  };
  return { round1: round(1), round2: round(2) };
}

/** Normal field-effect controls are prerequisites; negative probe outcomes stay conservative. */
export function dastJsonProbeOutcome(steps: readonly DastJsonExecutionStep[]): DastExecutionV1['outcome'] {
  const sql = steps.filter(step => step.round !== 0), normal = dastJsonNormalControls(steps);
  if (sql.length !== 10 || sql.some(step => step.outcome !== 'evaluated') || normal.round1 !== 'matched' || normal.round2 !== 'matched') return 'inconclusive';
  const probes = sql.filter(step => step.phase === 'true' || step.phase === 'false');
  if (probes.length !== 4) return 'inconclusive';
  if (probes.every(step => step.oracleMatch === (step.phase === 'false' ? 'false' : 'baseline'))) return 'observed';
  return probes.every(step => step.oracleMatch === probes[0]!.oracleMatch && (step.oracleMatch === 'baseline' || step.oracleMatch === 'false')) ? 'not_observed' : 'inconclusive';
}

function sanitizeJsonPost(raw: Record<string, unknown>): DastExecutionV4 | null {
  if (!exact(raw, ['version', 'policySha256', 'profile', 'profileRevision', 'method', 'authentication', 'maxRequests', 'timeoutMs', 'allowPrivate', 'status', 'outcome', 'plannedRequests', 'steps', 'counts', 'stopReason', 'identityControls', 'normalControls', 'probeOutcome'])
    || raw.version !== 4 || raw.method !== 'POST' || raw.authentication !== 'authorization' || raw.profile !== 'numeric' || raw.profileRevision !== 'sql-boolean-json-auth-v4'
    || typeof raw.policySha256 !== 'string' || !SHA256.test(raw.policySha256) || !Number.isSafeInteger(raw.maxRequests) || Number(raw.maxRequests) < 1 || Number(raw.maxRequests) > 64
    || !Number.isSafeInteger(raw.timeoutMs) || Number(raw.timeoutMs) < 1 || Number(raw.timeoutMs) > 120_000 || typeof raw.allowPrivate !== 'boolean' || raw.plannedRequests !== 12
    || !Array.isArray(raw.steps) || raw.steps.length !== 12 || !record(raw.counts) || !exact(raw.counts, ['evaluated', 'inconclusive', 'notAttempted', 'httpAttempts'])
    || !record(raw.identityControls) || !exact(raw.identityControls, ['before', 'after']) || !record(raw.normalControls) || !exact(raw.normalControls, ['round1', 'round2'])) return null;
  const phases = ['baseline-before', 'benign-alternate', 'true', 'false', 'baseline-after'] as const;
  const steps: DastJsonExecutionStep[] = [];
  let evaluated = 0, inconclusive = 0, notAttempted = 0, httpAttempts = 0, stopped = false;
  for (let ordinal = 0; ordinal < 12; ordinal++) {
    const v = raw.steps[ordinal], identity = ordinal === 0 || ordinal === 11;
    const phase = identity ? ordinal === 0 ? 'identity-before' : 'identity-after' : phases[(ordinal - 1) % 5]!;
    const round = identity ? 0 : Math.floor((ordinal - 1) / 5) + 1;
    const normal = ['baseline-before', 'benign-alternate', 'baseline-after'].includes(phase);
    const reasons = [...REASONS, ...(identity ? ['identity_mismatch'] : normal ? ['benign_control_mismatch'] : [])];
    if (!record(v) || !exact(v, ['ordinal', 'round', 'phase', 'outcome', 'reason', 'attemptStart', 'httpAttempts', 'httpStatus', 'oracleMatch']) || v.ordinal !== ordinal || v.round !== round || v.phase !== phase
      || typeof v.outcome !== 'string' || !['evaluated', 'inconclusive', 'not_attempted'].includes(v.outcome) || typeof v.reason !== 'string' || !reasons.includes(v.reason)
      || !Number.isSafeInteger(v.attemptStart) || v.attemptStart !== httpAttempts || !Number.isSafeInteger(v.httpAttempts) || Number(v.httpAttempts) < 0 || Number(v.httpAttempts) > (identity ? 32 : 1)
      || v.httpStatus !== null && (!Number.isSafeInteger(v.httpStatus) || Number(v.httpStatus) < 100 || Number(v.httpStatus) > 599)
      || typeof v.oracleMatch !== 'string' || ![...MATCHES, 'alternate'].includes(v.oracleMatch) || identity && v.oracleMatch !== 'unavailable') return null;
    if (stopped && v.outcome !== 'not_attempted') return null;
    if (v.outcome === 'evaluated') {
      if (v.reason !== 'evaluated' || Number(v.httpAttempts) < 1 || Number(v.httpStatus) < 200 || Number(v.httpStatus) > 299
        || !identity && v.oracleMatch === 'unavailable' || normal && v.oracleMatch !== (phase === 'benign-alternate' ? 'alternate' : 'baseline')
        || !normal && !identity && v.oracleMatch === 'alternate') return null;
      evaluated++;
    } else if (v.outcome === 'inconclusive') {
      if (v.reason === 'evaluated' || v.reason === 'not_reached' || v.oracleMatch !== 'unavailable'
        || ['identity_mismatch', 'benign_control_mismatch'].includes(v.reason) && (Number(v.httpAttempts) < 1 || Number(v.httpStatus) < 200 || Number(v.httpStatus) > 299)) return null;
      inconclusive++; stopped = true;
    } else {
      if (!stopped || v.reason !== 'not_reached' || v.httpAttempts !== 0 || v.httpStatus !== null || v.oracleMatch !== 'unavailable') return null;
      notAttempted++;
    }
    steps.push({ ordinal, round: round as 0 | 1 | 2, phase, outcome: v.outcome as DastJsonExecutionStep['outcome'], reason: v.reason as DastJsonStepReason,
      attemptStart: httpAttempts, httpAttempts: Number(v.httpAttempts), httpStatus: v.httpStatus as number | null, oracleMatch: v.oracleMatch as DastJsonExecutionStep['oracleMatch'] });
    httpAttempts += Number(v.httpAttempts); if (httpAttempts > Number(raw.maxRequests)) return null;
  }
  const counts = { evaluated, inconclusive, notAttempted, httpAttempts };
  const identity = (step: DastJsonExecutionStep): DastIdentityOutcome => step.outcome === 'evaluated' ? 'matched' : step.outcome === 'not_attempted' || step.httpAttempts === 0 ? 'not_attempted' : step.reason === 'identity_mismatch' ? 'mismatched' : 'inconclusive';
  const identityControls = { before: identity(steps[0]!), after: identity(steps[11]!) };
  const normalControls = dastJsonNormalControls(steps), probeOutcome = dastJsonProbeOutcome(steps);
  const outcome = identityControls.before === 'matched' && identityControls.after === 'matched' ? probeOutcome : 'inconclusive';
  const status = outcome === 'inconclusive' ? 'partial' : 'complete';
  const stopReason = steps.find(step => step.outcome === 'inconclusive')?.reason ?? (status === 'complete' ? 'none' : 'oracle_inconsistent');
  const sameCounts = Object.entries(counts).every(([key, value]) => (raw.counts as Record<string, unknown>)[key] === value);
  if (!sameCounts || raw.identityControls.before !== identityControls.before || raw.identityControls.after !== identityControls.after
    || raw.normalControls.round1 !== normalControls.round1 || raw.normalControls.round2 !== normalControls.round2 || raw.probeOutcome !== probeOutcome
    || raw.outcome !== outcome || raw.status !== status || raw.stopReason !== stopReason) return null;
  return { version: 4, method: 'POST', authentication: 'authorization', policySha256: raw.policySha256, profile: 'numeric', profileRevision: 'sql-boolean-json-auth-v4',
    maxRequests: Number(raw.maxRequests), timeoutMs: Number(raw.timeoutMs), allowPrivate: raw.allowPrivate, plannedRequests: 12, steps, counts, identityControls, normalControls,
    probeOutcome, outcome, status, stopReason };
}
