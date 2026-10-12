import { createHash } from "node:crypto";
import { types } from "node:util";
import { createApiRunControl } from "./api.js";
import type { CheckResult, Finding } from "./contracts.js";
import { snapshotJsonData } from "./json-snapshot.js";
import { sanitizeDastExecution, type DastExecution, type DastExecutionStep, type DastStepReason, type DastPhase, type DastOracleMatch } from "./dast-execution.js";
import { fetchResource, normalizeUrl, safeUrl, type UrlNetworkContext, UrlNetworkError } from "./url-network.js";

/** A bounded, opt-in numeric SQL boolean differential probe, based on an explicit JSON oracle. */
export const DAST_CHECK_ID = "url.sql-boolean";
export const DAST_PROFILE_REVISION = "sql-boolean-numeric-v1";
export const DAST_DEFAULT_MAX_REQUESTS = 8;
export const DAST_MAX_REQUESTS = 64;
export const DAST_DEFAULT_TIMEOUT_MS = 30_000;
export const DAST_MAX_TIMEOUT_MS = 120_000;
const SINGLE_BODY_BYTES = 128 * 1024;
const TOTAL_BODY_BYTES = 512 * 1024;
const NOTE = "Numeric SQL differential preview: one consented GET URL and one existing query parameter, eight fixed requests, exact configured JSON oracle. A candidate is not proof of exploitability or complete SQL injection coverage.";
const PARAMETER = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const NUMERIC = /^(?:0|[1-9][0-9]{0,8})$/;

export type DastScalar = string | number | boolean | null;
export interface DastPolicy {
  version: 1;
  kind: "sql-boolean-differential";
  baseUrl: string;
  url: string;
  parameter: string;
  profile: "numeric";
  oracle: { jsonPointer: string; expectedBaseline: DastScalar; expectedTrue: DastScalar; expectedFalse: DastScalar };
}
export interface ParsedDastPolicy { policy: DastPolicy; policySha256: string }
export interface DastOptions {
  policy: DastPolicy;
  consent: boolean;
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxRequests?: number;
  signal?: AbortSignal;
}

function fail(message: string): never { throw new TypeError(`invalid_dast_policy: ${message}`); }
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function keys(value: Record<string, unknown>, expected: string[], label: string): void {
  if (Object.keys(value).sort().join("\0") !== expected.sort().join("\0")) fail(`${label} keys`);
}
function scalar(value: unknown, label: string): DastScalar {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  fail(`${label} must be a JSON scalar`);
}
function sameScalar(a: DastScalar, b: DastScalar): boolean { return typeof a === typeof b && a === b; }
function pointer(value: unknown): string {
  if (typeof value !== "string" || value.length > 512 || (value && !value.startsWith("/"))
    || /[\u0000-\u001f\u007f]/.test(value) || /~(?![01])/.test(value)) fail("oracle.jsonPointer must be RFC 6901");
  return value;
}
function atPointer(value: unknown, jsonPointer: string): unknown {
  let current = value;
  if (jsonPointer === "") return current;
  for (const escaped of jsonPointer.slice(1).split("/")) {
    const part = escaped.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9]\d*)$/.test(part)) return undefined;
      const index = Number(part);
      if (!Number.isSafeInteger(index) || index >= current.length) return undefined;
      current = current[index];
    } else if (record(current) && Object.prototype.hasOwnProperty.call(current, part)) current = current[part];
    else return undefined;
  }
  return current;
}

/** Strictly rebuild and hash the policy before any await or target traffic. */
export function parseDastPolicy(raw: unknown): ParsedDastPolicy {
  const input = snapshotJsonData(raw, () => fail("bounded JSON data required"), () => fail("policy too large"));
  if (!record(input)) fail("object required");
  keys(input, ["version", "kind", "baseUrl", "url", "parameter", "profile", "oracle"], "policy");
  if (input.version !== 1 || input.kind !== "sql-boolean-differential" || input.profile !== "numeric") fail("unsupported version, kind or profile");
  if (typeof input.baseUrl !== "string" || typeof input.url !== "string") fail("URL strings required");
  const base = normalizeUrl(input.baseUrl), target = normalizeUrl(input.url);
  const baseParsed = new URL(base.href), targetParsed = new URL(target.href);
  if (baseParsed.pathname !== "/" || baseParsed.search || target.origin !== base.origin || !targetParsed.search) fail("one same-origin URL with an existing query is required");
  if (typeof input.parameter !== "string" || !PARAMETER.test(input.parameter)) fail("invalid parameter name");
  const matches = targetParsed.searchParams.getAll(input.parameter);
  if (matches.length !== 1 || !NUMERIC.test(matches[0]!)) fail("parameter must appear once with a bounded decimal value");
  if (!record(input.oracle)) fail("oracle object required");
  keys(input.oracle, ["jsonPointer", "expectedBaseline", "expectedTrue", "expectedFalse"], "oracle");
  const oracle = { jsonPointer: pointer(input.oracle.jsonPointer), expectedBaseline: scalar(input.oracle.expectedBaseline, "baseline"),
    expectedTrue: scalar(input.oracle.expectedTrue, "true"), expectedFalse: scalar(input.oracle.expectedFalse, "false") };
  if (!sameScalar(oracle.expectedBaseline, oracle.expectedTrue) || sameScalar(oracle.expectedBaseline, oracle.expectedFalse))
    fail("true oracle must equal baseline; false oracle must differ");
  const policy: DastPolicy = { version: 1, kind: "sql-boolean-differential", baseUrl: base.href, url: target.href,
    parameter: input.parameter, profile: "numeric", oracle };
  const policySha256 = createHash("sha256").update(JSON.stringify({ revision: DAST_PROFILE_REVISION, policy })).digest("hex");
  return { policy, policySha256 };
}

function optionsSnapshot(raw: DastOptions): DastOptions {
  if (!raw || typeof raw !== "object" || types.isProxy(raw) || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) throw new TypeError("invalid_dast_options");
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  const allowed = new Set(["policy", "consent", "allowPrivate", "timeoutMs", "maxRequests", "signal"]);
  for (const [key, descriptor] of Object.entries(descriptors)) if (!allowed.has(key) || !("value" in descriptor)) throw new TypeError("invalid_dast_options");
  const read = (key: keyof DastOptions): unknown => descriptors[key]?.value;
  return { policy: read("policy") as DastPolicy, consent: read("consent") as boolean,
    allowPrivate: read("allowPrivate") as boolean | undefined, timeoutMs: read("timeoutMs") as number | undefined,
    maxRequests: read("maxRequests") as number | undefined, signal: read("signal") as AbortSignal | undefined };
}

function result(status: CheckResult["status"], reason: string, metrics: Record<string, number | string | boolean> = {}): CheckResult[] {
  return [{ id: DAST_CHECK_ID, status, findings: [], notes: [NOTE, reason], metrics: { requestCount: 0, ...metrics } }];
}
function stopReason(error: unknown, abortCause: "deadline" | "cancelled" | undefined, deadlineAt: number): DastStepReason {
  if (abortCause) return abortCause;
  if (Date.now() >= deadlineAt) return "deadline";
  const code = error instanceof UrlNetworkError ? error.code : "transport_error";
  if (code === "request_limit") return "request_budget";
  if (/body|decompress|encoding/.test(code)) return "body_budget";
  if (/blocked|private|metadata|redirect|scheme|port|address|tls|dns_rebinding|host/.test(code)) return "network_policy";
  return "transport_error";
}
function phaseUrl(policy: DastPolicy, phase: DastPhase): string {
  const url = new URL(policy.url);
  const original = url.searchParams.get(policy.parameter)!;
  if (phase === "true") url.searchParams.set(policy.parameter, `${original} AND 1=1`);
  if (phase === "false") url.searchParams.set(policy.parameter, `${original} AND 1=2`);
  return url.toString();
}
function matches(value: DastScalar, policy: DastPolicy): DastOracleMatch {
  if (sameScalar(value, policy.oracle.expectedBaseline)) return "baseline";
  if (sameScalar(value, policy.oracle.expectedFalse)) return "false";
  return "other";
}
function isScalar(value: unknown): value is DastScalar {
  return value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number" && Number.isFinite(value);
}
function jsonType(headers: Record<string, string | string[]>): boolean {
  const value = Object.entries(headers).find(([name]) => name.toLowerCase() === "content-type")?.[1];
  const first = Array.isArray(value) ? value[0] : value;
  return typeof first === "string" && /^application\/(?:json|[a-z0-9.+-]+\+json)(?:\s*;|\s*$)/i.test(first);
}
function ledger(policySha256: string, steps: DastExecutionStep[], status: DastExecution["status"], outcome: DastExecution["outcome"], stop: DastExecution["stopReason"],
  maxRequests: number, timeoutMs: number, allowPrivate: boolean): DastExecution {
  return { version: 1, policySha256, profile: "numeric", profileRevision: DAST_PROFILE_REVISION,
    maxRequests, timeoutMs, allowPrivate, status, outcome, plannedRequests: 8, steps,
    counts: { evaluated: steps.filter(s => s.outcome === "evaluated").length,
      inconclusive: steps.filter(s => s.outcome === "inconclusive").length,
      notAttempted: steps.filter(s => s.outcome === "not_attempted").length,
      httpAttempts: steps.reduce((sum, s) => sum + s.httpAttempts, 0) }, stopReason: stop };
}

export async function runDast(rawOptions: DastOptions): Promise<CheckResult[]> {
  let options: DastOptions;
  try { options = optionsSnapshot(rawOptions); } catch { return result("error", "DAST options were rejected before requests.", { errorCode: "invalid_options" }); }
  if (options.consent !== true) return result("error", "Active DAST requires explicit consent; no requests were made.", { errorCode: "consent_required" });
  let parsed: ParsedDastPolicy;
  try { parsed = parseDastPolicy(options.policy); } catch { return result("error", "DAST policy was rejected before requests.", { errorCode: "invalid_policy" }); }
  const maxRequests = options.maxRequests ?? DAST_DEFAULT_MAX_REQUESTS;
  const timeoutMs = options.timeoutMs ?? DAST_DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > DAST_MAX_REQUESTS
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DAST_MAX_TIMEOUT_MS
    || (options.signal !== undefined && (types.isProxy(options.signal) || !(options.signal instanceof AbortSignal))))
    return result("error", "DAST budget or cancellation signal is invalid; no requests were made.", { errorCode: "invalid_budget" });
  const control = createApiRunControl(timeoutMs, options.signal, DAST_MAX_TIMEOUT_MS);
  // The shared signal merges caller cancellation and the timer. Capture the cause
  // at its first abort: wall-clock checks in a later catch can mislabel either.
  let abortCause: "deadline" | "cancelled" | undefined;
  const captureAbortCause = () => { abortCause ??= options.signal?.aborted ? "cancelled" : "deadline"; };
  if (control.signal.aborted) captureAbortCause();
  else control.signal.addEventListener("abort", captureAbortCause, { once: true });
  const budget = { count: 0, max: maxRequests };
  const context: UrlNetworkContext = { allowPrivate: options.allowPrivate === true, signal: control.signal, budget,
    deadlineAt: control.deadlineAt, rejectRedirects: true, acceptJson: true };
  const phases: DastPhase[] = ["baseline-before", "true", "false", "baseline-after"];
  const steps: DastExecutionStep[] = [];
  const values: DastScalar[] = [];
  let totalBytes = 0;
  let firstFailure: DastStepReason | undefined;
  try {
    for (let ordinal = 0; ordinal < 8; ordinal++) {
      const phase = phases[ordinal % 4]!;
      const round = (Math.floor(ordinal / 4) + 1) as 1 | 2;
      const attemptStart = budget.count;
      if (firstFailure) {
        steps.push({ ordinal, round, phase, outcome: "not_attempted", reason: "not_reached", attemptStart,
          httpAttempts: 0, httpStatus: null, oracleMatch: "unavailable" });
        continue;
      }
      let httpStatus: number | null = null;
      try {
        if (totalBytes >= TOTAL_BODY_BYTES) throw new UrlNetworkError("body_limit", "cumulative response body budget exhausted");
        const target = normalizeUrl(phaseUrl(parsed.policy, phase));
        const response = await fetchResource(target, context, new URL(parsed.policy.baseUrl).origin,
          Math.min(SINGLE_BODY_BYTES, TOTAL_BODY_BYTES - totalBytes),
          Math.min(SINGLE_BODY_BYTES, TOTAL_BODY_BYTES - totalBytes));
        httpStatus = response.status;
        totalBytes += response.body.byteLength;
        if (totalBytes > TOTAL_BODY_BYTES || response.status < 200 || response.status > 299 || !jsonType(response.headers)) throw new Error("response_invalid");
        let json: unknown;
        try { json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.body)); }
        catch { throw new Error("response_invalid"); }
        const value = atPointer(json, parsed.policy.oracle.jsonPointer);
        if (!isScalar(value)) throw new Error("response_invalid");
        values.push(value);
        steps.push({ ordinal, round, phase, outcome: "evaluated", reason: "evaluated", attemptStart,
          httpAttempts: budget.count - attemptStart, httpStatus, oracleMatch: matches(value, parsed.policy) });
      } catch (error) {
        firstFailure = error instanceof Error && error.message === "response_invalid" ? "response_invalid"
          : stopReason(error, abortCause, control.deadlineAt);
        steps.push({ ordinal, round, phase, outcome: "inconclusive", reason: firstFailure, attemptStart,
          httpAttempts: budget.count - attemptStart, httpStatus, oracleMatch: "unavailable" });
      }
    }
    let outcome: DastExecution["outcome"] = "inconclusive";
    let status: DastExecution["status"] = "partial";
    let stop: DastExecution["stopReason"] = firstFailure ?? "oracle_inconsistent";
    if (!firstFailure) {
      const [b1, t1, f1, b2, b3, t2, f2, b4] = values;
      const baselineStable = [b1, b2, b3, b4].every(value => sameScalar(value!, parsed.policy.oracle.expectedBaseline));
      const trueStable = sameScalar(t1!, t2!);
      const falseStable = sameScalar(f1!, f2!);
      if (baselineStable && trueStable && falseStable) {
        if (sameScalar(t1!, parsed.policy.oracle.expectedTrue) && sameScalar(f1!, parsed.policy.oracle.expectedFalse)) {
          outcome = "observed";
        } else if (sameScalar(t1!, f1!) && (sameScalar(t1!, parsed.policy.oracle.expectedBaseline)
          || sameScalar(t1!, parsed.policy.oracle.expectedFalse))) {
          outcome = "not_observed";
        }
      }
      if (outcome !== "inconclusive") { status = "complete"; stop = "none"; }
    }
    const execution = ledger(parsed.policySha256, steps, status, outcome, stop, maxRequests, timeoutMs, options.allowPrivate === true);
    if (!sanitizeDastExecution(execution)) return result("error", "DAST execution ledger failed its internal validation.", { errorCode: "invalid_execution", requestCount: budget.count });
    const finding: Finding[] = outcome === "observed" ? [{ ruleId: "dast.sql-boolean-differential", title: "SQL boolean response differential observed",
      description: `The configured JSON oracle changed consistently for numeric true/false conditions on parameter ${parsed.policy.parameter}. This is a candidate; SQL execution and exploitability have not been independently proven.`,
      severity: "high", confidence: "medium", kind: "candidate", location: { url: safeUrl(parsed.policy.url) },
      remediation: "Review how the query parameter reaches database execution. Use parameter binding, then rerun the same normal and differential controls." }] : [];
    const check: CheckResult = { id: DAST_CHECK_ID, status: status === "complete" ? "completed" : "partial", findings: finding,
      notes: [NOTE, `Target ${safeUrl(parsed.policy.url)}; parameter ${parsed.policy.parameter}; ${budget.count} HTTP attempt(s) across ${steps.filter(s => s.outcome === "evaluated").length}/8 evaluated phase(s).`,
        outcome === "observed" ? "The expected boolean differential repeated in both rounds; browser, database internals and exploitability were not independently verified."
          : outcome === "not_observed" ? "Both boolean probes had the same stable oracle; the configured differential was not observed."
          : `Incomplete: ${stop}. Absent findings are not a clean SQL result.`],
      metrics: { requestCount: budget.count, plannedRequests: 8, maxRequests, responseBytes: totalBytes,
        profileRevision: DAST_PROFILE_REVISION, policySha256: parsed.policySha256, outcome, stopReason: stop },
      dastExecution: execution };
    return [check];
  } finally { control.signal.removeEventListener("abort", captureAbortCause); control.dispose(); }
}
