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
export type DastExecution = DastExecutionV1 | DastExecutionV2;

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
function sanitizeV2(raw: Record<string, unknown>): DastExecutionV2 | null {
  if (!exact(raw, ["version", "policySha256", "profile", "profileRevision", "maxRequests", "timeoutMs", "allowPrivate", "status", "outcome", "plannedRequests", "steps", "counts", "stopReason", "identityControls", "probeOutcome"])
    || typeof raw.policySha256 !== "string" || !SHA256.test(raw.policySha256) || raw.profile !== "numeric" || raw.profileRevision !== "sql-boolean-numeric-auth-v2"
    || !Number.isSafeInteger(raw.maxRequests) || Number(raw.maxRequests) < 1 || Number(raw.maxRequests) > 64
    || !Number.isSafeInteger(raw.timeoutMs) || Number(raw.timeoutMs) < 1 || Number(raw.timeoutMs) > 120_000
    || typeof raw.allowPrivate !== "boolean" || !["complete", "partial"].includes(String(raw.status))
    || !["observed", "not_observed", "inconclusive"].includes(String(raw.outcome)) || raw.plannedRequests !== 10
    || !Array.isArray(raw.steps) || raw.steps.length !== 10 || !record(raw.counts)
    || !exact(raw.counts, ["evaluated", "inconclusive", "notAttempted", "httpAttempts"])
    || !record(raw.identityControls) || !exact(raw.identityControls, ["before", "after"])) return null;
  const steps: DastAuthExecutionStep[] = [];
  let evaluated = 0, inconclusive = 0, notAttempted = 0, httpAttempts = 0, stopped = false;
  for (let ordinal = 0; ordinal < 10; ordinal++) {
    const value = raw.steps[ordinal], identity = ordinal === 0 || ordinal === 9;
    const phase: DastAuthPhase = identity ? ordinal === 0 ? "identity-before" : "identity-after" : PHASES[(ordinal - 1) % 4]!;
    const round = identity ? 0 : Math.floor((ordinal - 1) / 4) + 1;
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
  const identityControls = { before: identityOutcome(steps[0]!), after: identityOutcome(steps[9]!) };
  if (raw.identityControls.before !== identityControls.before || raw.identityControls.after !== identityControls.after) return null;
  const probeOutcome = dastProbeOutcome(steps.slice(1, 9) as DastExecutionStep[]);
  if (raw.probeOutcome !== probeOutcome) return null;
  const outcome = identityControls.before === "matched" && identityControls.after === "matched" ? probeOutcome : "inconclusive";
  const status = outcome === "inconclusive" ? "partial" : "complete";
  const firstFailure = steps.find(step => step.outcome === "inconclusive");
  const stopReason = firstFailure?.reason ?? (status === "complete" ? "none" : "oracle_inconsistent");
  if (raw.outcome !== outcome || raw.status !== status || raw.stopReason !== stopReason) return null;
  return { version: 2, policySha256: raw.policySha256, profile: "numeric", profileRevision: "sql-boolean-numeric-auth-v2",
    maxRequests: Number(raw.maxRequests), timeoutMs: Number(raw.timeoutMs), allowPrivate: raw.allowPrivate, status, outcome,
    plannedRequests: 10, steps, counts, identityControls, probeOutcome, stopReason };
}

/** Strict v2 envelope and backward-compatible v1 normalization. No secret metadata is retained. */
export function sanitizeDastExecution(raw: unknown): DastExecution | null {
  try { raw = snapshotJsonData(raw); } catch { return null; }
  if (!record(raw)) return null;
  return raw.version === 2 ? sanitizeV2(raw) : sanitizeV1(raw);
}
/** Use only after ledger sanitation. An observed SQL differential survives failed trailing identity. */
export function isDastObservedEvidence(execution: DastExecution): boolean {
  return execution.version === 2 ? execution.probeOutcome === "observed" : execution.status === "complete" && execution.outcome === "observed";
}
/** Original replay authority requires complete controls, not merely retained probe evidence. */
export function isDastReplayableExecution(execution: DastExecution): boolean {
  return execution.status === "complete" && execution.outcome === "observed"
    && (execution.version === 1 || execution.probeOutcome === "observed" && execution.identityControls.before === "matched" && execution.identityControls.after === "matched");
}
