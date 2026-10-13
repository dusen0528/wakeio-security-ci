import { createHash } from "node:crypto";
import { types } from "node:util";
import { createApiRunControl } from "./api.js";
import type { CheckResult, Finding } from "./contracts.js";
import { snapshotJsonData } from "./json-snapshot.js";
import { sanitizeDastExecution, type DastExecution, type DastExecutionV1, type DastExecutionV2, type DastExecutionV3Unauth, type DastExecutionV3Auth, type DastExecutionV4, type DastJsonExecutionStep, type DastJsonStepReason, dastJsonProbeOutcome, dastJsonNormalControls, type DastAuthExecutionStep, type DastAuthPhase, type DastAuthStepReason, dastProbeOutcome, type DastExecutionStep, type DastStepReason, type DastPhase, type DastOracleMatch } from "./dast-execution.js";
import { postJsonResource, fetchResource, normalizeUrl, safeUrl, type UrlNetworkContext, UrlNetworkError } from "./url-network.js";

/** A bounded, opt-in numeric SQL boolean differential probe, based on an explicit JSON oracle. */
export const DAST_CHECK_ID = "url.sql-boolean";
export const DAST_PROFILE_REVISION = "sql-boolean-numeric-v1";
export const DAST_DEFAULT_MAX_REQUESTS = 8;
export const DAST_AUTH_PROFILE_REVISION = "sql-boolean-numeric-auth-v2";
export const DAST_AUTH_DEFAULT_MAX_REQUESTS = 10;
export const DAST_QUOTED_PROFILE_REVISION = "sql-boolean-single-quoted-v3";
export const DAST_QUOTED_AUTH_PROFILE_REVISION = "sql-boolean-single-quoted-auth-v3";
export const DAST_JSON_AUTH_PROFILE_REVISION = 'sql-boolean-json-auth-v4';
export const DAST_JSON_AUTH_DEFAULT_MAX_REQUESTS = 12;
export const DAST_JSON_REQUEST_BODY_BYTES = 4096;
export const DAST_MAX_REQUESTS = 64;
export const DAST_DEFAULT_TIMEOUT_MS = 30_000;
export const DAST_MAX_TIMEOUT_MS = 120_000;
const SINGLE_BODY_BYTES = 128 * 1024;
const TOTAL_BODY_BYTES = 512 * 1024;
const NOTE = "Numeric SQL differential preview: one consented GET URL and one existing query parameter, eight fixed requests, exact configured JSON oracle. A candidate is not proof of exploitability or complete SQL injection coverage.";
const PARAMETER = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const NUMERIC = /^(?:0|[1-9][0-9]{0,8})$/;

export type DastScalar = string | number | boolean | null;
export interface DastPolicyV1 {
  version: 1;
  kind: "sql-boolean-differential";
  baseUrl: string;
  url: string;
  parameter: string;
  profile: "numeric";
  oracle: { jsonPointer: string; expectedBaseline: DastScalar; expectedTrue: DastScalar; expectedFalse: DastScalar };
}
export interface DastPolicyV2 extends Omit<DastPolicyV1, "version"> {
  version: 2;
  authorizationEnv: string;
  identity: { path: string; status: number; jsonPointer: string; equals: string };
}
export interface DastPolicyV3Unauth extends Omit<DastPolicyV1, "version" | "profile"> {
  version: 3;
  profile: "single-quoted";
  authorizationEnv?: never;
  identity?: never;
}
export interface DastPolicyV3Auth extends Omit<DastPolicyV3Unauth, "authorizationEnv" | "identity"> {
  authorizationEnv: DastPolicyV2['authorizationEnv'];
  identity: DastPolicyV2['identity'];
}
export interface DastPolicyV4 extends Omit<DastPolicyV2, 'version'> {
  version: 4;
  method: 'POST';
  body: Record<string, DastScalar>;
  alternate: { value: string; expected: DastScalar };
}
export type DastPolicyV3 = DastPolicyV3Unauth | DastPolicyV3Auth;
export type DastPolicy = DastPolicyV1 | DastPolicyV2 | DastPolicyV3 | DastPolicyV4;
/** Capability query for a policy already accepted by parseDastPolicy. */
export function hasDastAuthentication(policy: DastPolicy): policy is DastPolicyV2 | DastPolicyV3Auth | DastPolicyV4 {
  return policy.version === 4 || policy.version === 2 || policy.version === 3 && Object.hasOwn(policy, 'authorizationEnv');
}
export function dastProfileRevision(policy: DastPolicy): typeof DAST_PROFILE_REVISION | typeof DAST_AUTH_PROFILE_REVISION | typeof DAST_QUOTED_PROFILE_REVISION | typeof DAST_QUOTED_AUTH_PROFILE_REVISION | typeof DAST_JSON_AUTH_PROFILE_REVISION {
  return policy.version === 4 ? DAST_JSON_AUTH_PROFILE_REVISION : policy.version === 3 ? hasDastAuthentication(policy) ? DAST_QUOTED_AUTH_PROFILE_REVISION : DAST_QUOTED_PROFILE_REVISION
    : policy.version === 2 ? DAST_AUTH_PROFILE_REVISION : DAST_PROFILE_REVISION;
}
export function dastDefaultMaxRequests(policy: DastPolicy): 8 | 10 | 12 { return policy.version === 4 ? 12 : hasDastAuthentication(policy) ? 10 : 8; }
export function dastRequestPlan(policy: DastPolicyV1 | DastPolicyV2 | DastPolicyV3): { ordinal: number; round: 0 | 1 | 2; phase: DastAuthPhase }[];
export function dastRequestPlan(policy: DastPolicyV4): { ordinal: number; round: 0 | 1 | 2; phase: DastAuthPhase | 'benign-alternate' }[];
export function dastRequestPlan(policy: DastPolicy): { ordinal: number; round: 0 | 1 | 2; phase: DastAuthPhase | 'benign-alternate' }[];
export function dastRequestPlan(policy: DastPolicy): { ordinal: number; round: 0 | 1 | 2; phase: DastAuthPhase | 'benign-alternate' }[] {
  if (policy.version === 4) return Array.from({ length: 12 }, (_, ordinal) => {
    const identity = ordinal === 0 || ordinal === 11, index = ordinal - 1;
    return { ordinal, round: identity ? 0 : index < 5 ? 1 : 2, phase: identity ? ordinal === 0 ? 'identity-before' : 'identity-after' : ['baseline-before', 'benign-alternate', 'true', 'false', 'baseline-after'][index % 5]! } as { ordinal: number; round: 0 | 1 | 2; phase: DastAuthPhase | 'benign-alternate' };
  });
  const authenticated = hasDastAuthentication(policy);
  const phases: DastPhase[] = ['baseline-before', 'true', 'false', 'baseline-after'];
  return Array.from({ length: authenticated ? 10 : 8 }, (_, ordinal): { ordinal: number; round: 0 | 1 | 2; phase: DastAuthPhase } => {
    const identity = authenticated && (ordinal === 0 || ordinal === 9), index = ordinal - (authenticated ? 1 : 0);
    return { ordinal, round: identity ? 0 : index < 4 ? 1 : 2,
      phase: identity ? ordinal === 0 ? 'identity-before' : 'identity-after' : phases[index % 4]! };
  });
}
export interface ParsedDastPolicy { policy: DastPolicy; policySha256: string }
export interface DastOptions {
  policy: DastPolicy;
  consent: boolean;
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxRequests?: number;
  signal?: AbortSignal;
  env?: NodeJS.ProcessEnv;
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
  const authenticated = input.version === 4 || input.version === 2 || input.version === 3 && (Object.hasOwn(input, 'authorizationEnv') || Object.hasOwn(input, 'identity'));
  keys(input, ["version", "kind", "baseUrl", "url", "parameter", "profile", "oracle", ...(input.version === 4 ? ["method", "body", "alternate"] : []), ...(authenticated ? ["authorizationEnv", "identity"] : [])], "policy");
  if (input.version !== 1 && input.version !== 2 && input.version !== 3 && input.version !== 4
    || input.kind !== "sql-boolean-differential" || input.profile !== (input.version === 3 ? "single-quoted" : "numeric")) fail("unsupported version, kind or profile");
  if (typeof input.baseUrl !== "string" || typeof input.url !== "string") fail("URL strings required");
  const base = normalizeUrl(input.baseUrl), target = normalizeUrl(input.url);
  const baseParsed = new URL(base.href), targetParsed = new URL(target.href);
  if (baseParsed.pathname !== "/" || baseParsed.search || target.origin !== base.origin || (input.version === 4 ? !!targetParsed.search : !targetParsed.search)) fail(input.version === 4 ? "one same-origin POST URL without query is required" : "one same-origin URL with an existing query is required");
  if (typeof input.parameter !== "string" || !PARAMETER.test(input.parameter)) fail("invalid parameter name");
  const matches = targetParsed.searchParams.getAll(input.parameter);
  if (input.version === 4) {
    if (input.method !== "POST" || !record(input.body) || Object.keys(input.body).length < 1 || Object.keys(input.body).length > 16) fail("bounded scalar body required");
    for (const [key, value] of Object.entries(input.body)) {
      if (!PARAMETER.test(key) || ["__proto__", "constructor", "prototype"].includes(key)) fail("invalid body field");
      scalar(value, "body value");
      if (typeof value === "string" && value.length > 1024) fail("body value too large");
    }
    if (!Object.hasOwn(input.body, input.parameter) || typeof input.body[input.parameter] !== "string" || !NUMERIC.test(input.body[input.parameter] as string)) fail("numeric string body field required");
    if (!record(input.alternate)) fail("alternate control required");
    keys(input.alternate, ["value", "expected"], "alternate");
    if (typeof input.alternate.value !== "string" || !NUMERIC.test(input.alternate.value) || input.alternate.value === input.body[input.parameter]) fail("distinct numeric alternate required");
  } else if (input.version === 3) {
    if (matches.length !== 1 || !/^[\x20-\x7e]{1,128}$/.test(matches[0]!) || !matches[0]!.trim() || /['\\]/.test(matches[0]!)) fail("parameter must appear once with a bounded single-quoted seed");
  } else if (matches.length !== 1 || !NUMERIC.test(matches[0]!)) fail("parameter must appear once with a bounded decimal value");
  if (!record(input.oracle)) fail("oracle object required");
  keys(input.oracle, ["jsonPointer", "expectedBaseline", "expectedTrue", "expectedFalse"], "oracle");
  const oracle = { jsonPointer: pointer(input.oracle.jsonPointer), expectedBaseline: scalar(input.oracle.expectedBaseline, "baseline"),
    expectedTrue: scalar(input.oracle.expectedTrue, "true"), expectedFalse: scalar(input.oracle.expectedFalse, "false") };
  if (!sameScalar(oracle.expectedBaseline, oracle.expectedTrue) || sameScalar(oracle.expectedBaseline, oracle.expectedFalse))
    fail("true oracle must equal baseline; false oracle must differ");
  let policy: DastPolicy = { version: 1, kind: "sql-boolean-differential", baseUrl: base.href, url: target.href,
    parameter: input.parameter, profile: "numeric", oracle };
  if (input.version === 3) policy = { ...policy, version: 3, profile: "single-quoted" };
  if (input.version === 4) {
    const body = Object.fromEntries(Object.entries(input.body as Record<string, DastScalar>));
    const alternateInput = input.alternate as Record<string, unknown>;
    const alternate = { value: alternateInput.value as string, expected: scalar(alternateInput.expected, "alternate expected") };
    if (sameScalar(alternate.expected, oracle.expectedBaseline)) fail("alternate oracle must differ from baseline");
    for (const value of [body[input.parameter] as string, alternate.value, `${body[input.parameter]} AND 1=1`, `${body[input.parameter]} AND 1=2`]) {
      if (Buffer.byteLength(JSON.stringify({ ...body, [input.parameter]: value }), "utf8") > DAST_JSON_REQUEST_BODY_BYTES) fail("body byte limit");
    }
    policy = { ...policy, version: 4, profile: 'numeric', method: 'POST', body, alternate, authorizationEnv: '', identity: { path: '/', status: 200, jsonPointer: '', equals: '' } };
  }
  if (authenticated) {
    if (typeof input.authorizationEnv !== "string" || !/^[A-Z][A-Z0-9_]{0,127}$/.test(input.authorizationEnv)) fail("invalid authorization binding");
    if (!record(input.identity)) fail("identity object required");
    keys(input.identity, ["path", "status", "jsonPointer", "equals"], "identity");
    const identity = input.identity;
    if (typeof identity.path !== "string" || !identity.path.startsWith("/") || identity.path.startsWith("//") || identity.path.length > 2048
      || /[?#\\\u0000-\u001f\u007f]/.test(identity.path)) fail("invalid identity path");
    const identityUrl = normalizeUrl(new URL(identity.path, base.href).href);
    if (identityUrl.origin !== base.origin) fail("identity origin mismatch");
    if (!Number.isSafeInteger(identity.status) || Number(identity.status) < 200 || Number(identity.status) > 299) fail("invalid identity status");
    if (typeof identity.equals !== "string" || identity.equals.trim().length === 0 || identity.equals.length > 512 || /[\u0000-\u001f\u007f]/.test(identity.equals)) fail("invalid identity assertion");
    const authFields = { authorizationEnv: input.authorizationEnv,
      identity: { path: identity.path, status: Number(identity.status), jsonPointer: pointer(identity.jsonPointer), equals: identity.equals } };
    policy = policy.version === 3 || policy.version === 4 ? { ...policy, ...authFields } : { ...policy, version: 2, ...authFields };
  }
  const policySha256 = createHash("sha256").update(JSON.stringify({ revision: dastProfileRevision(policy), policy })).digest("hex");
  return { policy, policySha256 };
}

function optionsSnapshot(raw: DastOptions): DastOptions {
  if (!raw || typeof raw !== "object" || types.isProxy(raw) || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) throw new TypeError("invalid_dast_options");
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  const allowed = new Set(["policy", "consent", "allowPrivate", "timeoutMs", "maxRequests", "signal", "env"]);
  for (const [key, descriptor] of Object.entries(descriptors)) if (!allowed.has(key) || !("value" in descriptor)) throw new TypeError("invalid_dast_options");
  const read = (key: keyof DastOptions): unknown => descriptors[key]?.value;
  return { policy: read("policy") as DastPolicy, consent: read("consent") as boolean,
    allowPrivate: read("allowPrivate") as boolean | undefined, timeoutMs: read("timeoutMs") as number | undefined,
    maxRequests: read("maxRequests") as number | undefined, signal: read("signal") as AbortSignal | undefined, env: read("env") as NodeJS.ProcessEnv | undefined };
}

function result(status: CheckResult["status"], reason: string, metrics: Record<string, number | string | boolean> = {}): CheckResult[] {
  return [{ id: DAST_CHECK_ID, status, findings: [], notes: ['SQL differential preparation: no profile execution is established. A candidate is not proof of exploitability or complete SQL injection coverage.', reason], metrics: { requestCount: 0, ...metrics } }];
}
function profileNote(policy: DastPolicy): string {
  if (policy.version === 4) return 'Authenticated numeric JSON SQL differential preview: ten fixed POST controls across two rounds, with GET identity before/after. JSON POST may have side effects; this is a response candidate, not SQL execution or exploitability proof.';
  return policy.profile === 'numeric' ? NOTE : 'Single-quoted SQL differential preview: one consented GET URL and one existing query parameter, eight fixed SQL phases, exact configured JSON oracle. A candidate is not proof of exploitability or general SQL dialect support.';
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
  if (phase === "true") url.searchParams.set(policy.parameter, policy.profile === 'single-quoted' ? `${original}' AND '1'='1` : `${original} AND 1=1`);
  if (phase === "false") url.searchParams.set(policy.parameter, policy.profile === 'single-quoted' ? `${original}' AND '1'='2` : `${original} AND 1=2`);
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
function ledger(policySha256: string, steps: DastExecutionStep[], status: DastExecutionV1["status"], outcome: DastExecutionV1["outcome"], stop: DastExecutionV1["stopReason"],
  maxRequests: number, timeoutMs: number, allowPrivate: boolean): DastExecutionV1 {
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
  const maxRequests = options.maxRequests ?? dastDefaultMaxRequests(parsed.policy);
  const timeoutMs = options.timeoutMs ?? DAST_DEFAULT_TIMEOUT_MS;
  if (options.allowPrivate !== undefined && typeof options.allowPrivate !== "boolean" || !Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > DAST_MAX_REQUESTS
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DAST_MAX_TIMEOUT_MS
    || (options.signal !== undefined && (types.isProxy(options.signal) || !(options.signal instanceof AbortSignal))))
    return result("error", "DAST budget or cancellation signal is invalid; no requests were made.", { errorCode: "invalid_budget" });
  if (hasDastAuthentication(parsed.policy)) return runAuthenticatedDast(parsed.policy, parsed.policySha256, options, maxRequests, timeoutMs);
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
        if (control.signal.aborted || Date.now() >= control.deadlineAt) throw new Error('run_stopped');
        const value = atPointer(json, parsed.policy.oracle.jsonPointer);
        if (!isScalar(value)) throw new Error("response_invalid");
        values.push(value);
        steps.push({ ordinal, round, phase, outcome: "evaluated", reason: "evaluated", attemptStart,
          httpAttempts: budget.count - attemptStart, httpStatus, oracleMatch: matches(value, parsed.policy) });
      } catch (error) {
        firstFailure = abortCause ?? (Date.now() >= control.deadlineAt ? 'deadline' : error instanceof Error && error.message === "response_invalid" ? "response_invalid"
          : stopReason(error, abortCause, control.deadlineAt));
        steps.push({ ordinal, round, phase, outcome: "inconclusive", reason: firstFailure, attemptStart,
          httpAttempts: budget.count - attemptStart, httpStatus, oracleMatch: "unavailable" });
      }
    }
    let outcome: DastExecution["outcome"] = "inconclusive";
    let status: DastExecution["status"] = "partial";
    let stop: DastExecutionV1["stopReason"] = firstFailure ?? "oracle_inconsistent";
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
    const numericExecution = ledger(parsed.policySha256, steps, status, outcome, stop, maxRequests, timeoutMs, options.allowPrivate === true);
    const execution: DastExecutionV1 | DastExecutionV3Unauth = parsed.policy.version === 3
      ? { ...numericExecution, version: 3, profile: 'single-quoted', profileRevision: DAST_QUOTED_PROFILE_REVISION, authentication: 'none', status }
      : numericExecution;
    if (!sanitizeDastExecution(execution)) return result("error", "DAST execution ledger failed its internal validation.", { errorCode: "invalid_execution", requestCount: budget.count });
    const finding: Finding[] = outcome === "observed" ? [{ ruleId: "dast.sql-boolean-differential", title: "SQL boolean response differential observed",
      description: `The configured JSON oracle changed consistently for ${parsed.policy.profile} true/false conditions on parameter ${parsed.policy.parameter}. This is a candidate; SQL execution and exploitability have not been independently proven.`,
      severity: "high", confidence: "medium", kind: "candidate", location: { url: safeUrl(parsed.policy.url) },
      remediation: "Review how the query parameter reaches database execution. Use parameter binding, then rerun the same normal and differential controls." }] : [];
    const check: CheckResult = { id: DAST_CHECK_ID, status: status === "complete" ? "completed" : "partial", findings: finding,
      notes: [profileNote(parsed.policy), `Target ${safeUrl(parsed.policy.url)}; parameter ${parsed.policy.parameter}; ${budget.count} HTTP attempt(s) across ${steps.filter(s => s.outcome === "evaluated").length}/8 evaluated phase(s).`,
        outcome === "observed" ? "The expected boolean differential repeated in both rounds; browser, database internals and exploitability were not independently verified."
          : outcome === "not_observed" ? "Both boolean probes had the same stable oracle; the configured differential was not observed."
          : `Incomplete: ${stop}. Absent findings are not a clean SQL result.`],
      metrics: { requestCount: budget.count, plannedRequests: 8, maxRequests, responseBytes: totalBytes,
        profileRevision: dastProfileRevision(parsed.policy), policySha256: parsed.policySha256, outcome, stopReason: stop },
      dastExecution: execution };
    return [check];
  } finally { control.signal.removeEventListener("abort", captureAbortCause); control.dispose(); }
}

export type DastPreparationCode = 'invalid_options' | 'invalid_policy' | 'invalid_credentials' | 'insecure_authenticated_transport';
export class DastPreparationError extends TypeError {
  constructor(readonly code: DastPreparationCode) { super(`DAST preparation failed: ${code}. No requests were made.`); }
}
export interface DastPreparationOptions { allowPrivate?: boolean; env?: NodeJS.ProcessEnv }

/** Select one own-data credential; never enumerate or copy unrelated environment values. */
export function snapshotDastEnvironment(rawPolicy: DastPolicy, env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv | undefined {
  let policy: DastPolicy;
  try { policy = parseDastPolicy(rawPolicy).policy; } catch { throw new DastPreparationError('invalid_policy'); }
  if (!hasDastAuthentication(policy)) return undefined;
  if (!env || typeof env !== 'object' || types.isProxy(env) || Array.isArray(env)) throw new DastPreparationError('invalid_credentials');
  const descriptor = Object.getOwnPropertyDescriptor(env, policy.authorizationEnv);
  const value: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
  if (typeof value !== 'string' || !value.trim() || value.length > 8192 || /[^\x20-\x7e\x80-\xff]/.test(value)) throw new DastPreparationError('invalid_credentials');
  return Object.freeze({ [policy.authorizationEnv]: value });
}

/** Snapshot authorization before awaits. Neither its value nor a value hash is public evidence. */
function authorizationSnapshot(policy: DastPolicyV2 | DastPolicyV3Auth | DastPolicyV4, options: DastPreparationOptions): string {
  const selected = snapshotDastEnvironment(policy, options.env);
  const target = new URL(policy.baseUrl);
  if (target.protocol !== 'https:' && !(options.allowPrivate === true && ['127.0.0.1', '[::1]'].includes(target.hostname))) throw new DastPreparationError('insecure_authenticated_transport');
  return selected![policy.authorizationEnv]!;
}

/** Offline validation only. Re-resolve credentials at execution; this return never carries credentials. */
export function prepareDastPolicy(raw: unknown, rawOptions: DastPreparationOptions = {}): ParsedDastPolicy {
  if (!rawOptions || typeof rawOptions !== 'object' || types.isProxy(rawOptions)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(rawOptions)) || Object.getOwnPropertySymbols(rawOptions).length) throw new DastPreparationError('invalid_options');
  const descriptors = Object.getOwnPropertyDescriptors(rawOptions);
  if (Object.entries(descriptors).some(([key, value]) => !['allowPrivate', 'env'].includes(key) || !value.enumerable || !('value' in value))) throw new DastPreparationError('invalid_options');
  const options: DastPreparationOptions = { allowPrivate: descriptors.allowPrivate?.value, env: descriptors.env?.value };
  if (options.allowPrivate !== undefined && typeof options.allowPrivate !== 'boolean') throw new DastPreparationError('invalid_options');
  let parsed: ParsedDastPolicy;
  try { parsed = parseDastPolicy(raw); } catch { throw new DastPreparationError('invalid_policy'); }
  if (hasDastAuthentication(parsed.policy)) authorizationSnapshot(parsed.policy, options);
  return parsed;
}

/** V2 has one request/body/deadline budget across identity-before, eight probes and identity-after. */
async function runAuthenticatedDast(policy: DastPolicyV2 | DastPolicyV3Auth | DastPolicyV4, policySha256: string, options: DastOptions,
  maxRequests: number, timeoutMs: number): Promise<CheckResult[]> {
  let authorization: string;
  try { authorization = authorizationSnapshot(policy, options); }
  catch (error) { return result('error', 'Authenticated DAST preparation failed before requests.', { errorCode: error instanceof DastPreparationError ? error.code : 'invalid_credentials' }); }
  const control = createApiRunControl(timeoutMs, options.signal, DAST_MAX_TIMEOUT_MS);
  let abortCause: 'deadline' | 'cancelled' | undefined;
  const captureAbortCause = () => { abortCause ??= options.signal?.aborted ? 'cancelled' : 'deadline'; };
  if (control.signal.aborted) captureAbortCause(); else control.signal.addEventListener('abort', captureAbortCause, { once: true });
  const budget = { count: 0, max: maxRequests };
  const context: UrlNetworkContext = { allowPrivate: options.allowPrivate === true, signal: control.signal, budget,
    deadlineAt: control.deadlineAt, rejectRedirects: true, acceptJson: true, authorization };
  const plan = dastRequestPlan(policy);
  const steps: Array<DastAuthExecutionStep | DastJsonExecutionStep> = [];
  const identityControls: DastExecutionV2['identityControls'] = { before: 'not_attempted', after: 'not_attempted' };
  let firstFailure: DastJsonStepReason | undefined, totalBytes = 0;
  try {
    for (const { ordinal, phase, round } of plan) {
      const identity = phase === 'identity-before' || phase === 'identity-after';
      const attemptStart = budget.count;
      const common = { ordinal, round: round as 0 | 1 | 2, phase, attemptStart };
      if (firstFailure) { steps.push({ ...common, outcome: 'not_attempted', reason: 'not_reached', httpAttempts: 0, httpStatus: null, oracleMatch: 'unavailable' }); continue; }
      let httpStatus: number | null = null;
      try {
        if (totalBytes >= TOTAL_BODY_BYTES) throw new UrlNetworkError('body_limit', 'cumulative response body budget exhausted');
        const target = normalizeUrl(identity ? new URL(policy.identity.path, policy.baseUrl).href : policy.version === 4 ? policy.url : phaseUrl(policy, phase as DastPhase));
        const cap = Math.min(SINGLE_BODY_BYTES, TOTAL_BODY_BYTES - totalBytes);
        const response = policy.version === 4 && !identity
          ? await postJsonResource(target, context, new URL(policy.baseUrl).origin, jsonPhaseBody(policy, phase), cap, cap)
          : await fetchResource(target, context, new URL(policy.baseUrl).origin, cap, cap);
        httpStatus = response.status; totalBytes += response.body.byteLength;
        if (response.status < 200 || response.status > 299 || identity && response.status !== policy.identity.status || !jsonType(response.headers)) throw new Error('response_invalid');
        let json: unknown;
        try { json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(response.body)); } catch { throw new Error('response_invalid'); }
        if (control.signal.aborted || Date.now() >= control.deadlineAt) throw new Error('run_stopped');
        const value = atPointer(json, identity ? policy.identity.jsonPointer : policy.oracle.jsonPointer);
        if (identity) {
          if (typeof value !== 'string' || value !== policy.identity.equals) throw new Error('identity_mismatch');
          identityControls[ordinal === 0 ? 'before' : 'after'] = 'matched';
        } else {
          if (!isScalar(value)) throw new Error('response_invalid');
          if (policy.version === 4 && ['baseline-before', 'benign-alternate', 'baseline-after'].includes(phase)
            && !sameScalar(value, phase === 'benign-alternate' ? policy.alternate.expected : policy.oracle.expectedBaseline)) throw new Error('benign_control_mismatch');
        }
        steps.push({ ...common, outcome: 'evaluated', reason: 'evaluated', httpAttempts: budget.count - attemptStart, httpStatus,
          oracleMatch: identity ? 'unavailable' : phase === 'benign-alternate' ? 'alternate' : matches(value as DastScalar, policy) });
      } catch (error) {
        firstFailure = abortCause ?? (Date.now() >= control.deadlineAt ? 'deadline' : error instanceof Error && error.message === 'identity_mismatch' ? 'identity_mismatch'
          : policy.version === 4 && error instanceof Error && error.message === 'benign_control_mismatch' ? 'benign_control_mismatch'
          : error instanceof Error && error.message === 'response_invalid' ? 'response_invalid' : stopReason(error, abortCause, control.deadlineAt));
        if (identity) identityControls[ordinal === 0 ? 'before' : 'after'] = budget.count === attemptStart ? 'not_attempted' : firstFailure === 'identity_mismatch' ? 'mismatched' : 'inconclusive';
        steps.push({ ...common, outcome: 'inconclusive', reason: firstFailure, httpAttempts: budget.count - attemptStart, httpStatus, oracleMatch: 'unavailable' });
      }
    }
    const probeOutcome = policy.version === 4 ? dastJsonProbeOutcome(steps as DastJsonExecutionStep[]) : dastProbeOutcome(steps.slice(1, 9) as DastExecutionStep[]);
    const outcome = identityControls.before === 'matched' && identityControls.after === 'matched' ? probeOutcome : 'inconclusive';
    const status = outcome === 'inconclusive' ? 'partial' : 'complete';
    const stop = firstFailure ?? (status === 'complete' ? 'none' : 'oracle_inconsistent');
    const numericExecution: DastExecutionV2 = { version: 2, policySha256, profile: 'numeric', profileRevision: DAST_AUTH_PROFILE_REVISION,
      maxRequests, timeoutMs, allowPrivate: options.allowPrivate === true, plannedRequests: 10, steps: steps as DastAuthExecutionStep[], status, outcome, probeOutcome, identityControls,
      counts: { evaluated: steps.filter(step => step.outcome === 'evaluated').length, inconclusive: steps.filter(step => step.outcome === 'inconclusive').length,
        notAttempted: steps.filter(step => step.outcome === 'not_attempted').length, httpAttempts: budget.count }, stopReason: stop as DastExecutionV2['stopReason'] };
    const execution: DastExecutionV2 | DastExecutionV3Auth | DastExecutionV4 = policy.version === 4
      ? { ...numericExecution, version: 4, method: 'POST', authentication: 'authorization', profileRevision: DAST_JSON_AUTH_PROFILE_REVISION, plannedRequests: 12, steps: steps as DastJsonExecutionStep[], normalControls: dastJsonNormalControls(steps as DastJsonExecutionStep[]), status, stopReason: stop }
      : policy.version === 3
      ? { ...numericExecution, version: 3, profile: 'single-quoted', profileRevision: DAST_QUOTED_AUTH_PROFILE_REVISION, authentication: 'authorization' }
      : numericExecution;
    if (!sanitizeDastExecution(execution)) return result('error', 'DAST execution ledger failed its internal validation.', { errorCode: 'invalid_execution', requestCount: budget.count });
    const findings: Finding[] = probeOutcome === 'observed' ? [{ ruleId: 'dast.sql-boolean-differential', title: 'SQL boolean response differential observed',
      description: policy.version === 4 ? 'The configured JSON oracle changed consistently for numeric true/false conditions in the selected JSON field after the benign controls matched. This is a candidate; SQL execution and exploitability have not been independently proven.' : `The configured JSON oracle changed consistently for ${policy.profile} true/false conditions on parameter ${policy.parameter}. This is a candidate; SQL execution and exploitability have not been independently proven.`,
      severity: 'high', confidence: status === 'complete' ? 'medium' : 'low', kind: 'candidate', location: { url: safeUrl(policy.url) },
      remediation: policy.version === 4 ? 'Review how the selected JSON field reaches database execution. Use parameter binding, then rerun the same identity, benign and differential controls.' : 'Review how the query parameter reaches database execution. Use parameter binding, then rerun the same normal and differential controls.' }] : [];
    return [{ id: DAST_CHECK_ID, status: status === 'complete' ? 'completed' : 'partial', findings,
      notes: [profileNote(policy), `Authenticated ${policy.profile} profile: identity is checked before and after ${plan.length - 2} SQL phases; matching controls do not prove uninterrupted session identity.`,
        status === 'complete' ? 'All identity and SQL controls completed for this policy.' : `Incomplete: ${stop}. Any retained differential is unverified and cannot authorize replay.`],
      metrics: { requestCount: budget.count, plannedRequests: plan.length, maxRequests, responseBytes: totalBytes,
        profileRevision: dastProfileRevision(policy), policySha256, outcome, probeOutcome, stopReason: stop }, dastExecution: execution }];
  } finally { control.signal.removeEventListener('abort', captureAbortCause); control.dispose(); }
}

function jsonPhaseBody(policy: DastPolicyV4, phase: DastAuthPhase | 'benign-alternate'): string {
  const seed = policy.body[policy.parameter] as string;
  const value = phase === 'benign-alternate' ? policy.alternate.value : phase === 'true' ? `${seed} AND 1=1` : phase === 'false' ? `${seed} AND 1=2` : seed;
  return JSON.stringify({ ...policy.body, [policy.parameter]: value });
}
