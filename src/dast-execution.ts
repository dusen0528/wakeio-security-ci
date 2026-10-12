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

export interface DastExecution {
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
export function sanitizeDastExecution(raw: unknown): DastExecution | null {
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
    counts: { evaluated, inconclusive, notAttempted, httpAttempts }, stopReason: raw.stopReason as DastExecution["stopReason"] };
}
