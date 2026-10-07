import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { API_DEFAULT_TIMEOUT_MS, API_MAX_REQUESTS, API_MAX_SINGLE_BODY_BYTES, API_MAX_TIMEOUT_MS,
  API_MAX_TOTAL_BODY_BYTES, createApiRunControl } from "./api.js";
import type { CheckResult, Finding } from "./contracts.js";
import { resolveDastOrigin, startEgressGate, type EgressGate } from "./dast-egress.js";
import { selectOpenApiLiveOperations, OpenApiPolicyError } from "./openapi.js";
import { superviseWorker } from "./schemathesis.js";
import { safeUrl, UrlNetworkError } from "./url-network.js";

/**
 * Opt-in Schemathesis generation against an explicitly consented origin.
 * Read-only GET operations only; every request crosses the egress gate.
 */
export const LIVE_CHECK_ID = "api.schemathesis";
const LIVE_OUTPUT_CAP = 256 * 1024;
const DIGEST = /^[a-f0-9]{64}$/;
const VERSION = /^\d{1,4}\.\d{1,4}\.\d{1,4}(?:[a-z]+\d{0,4})?$/;
const KEYWORDS = new Set(["type", "required", "enum", "const", "format", "pattern", "minimum", "maximum",
  "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems", "uniqueItems",
  "additionalProperties", "properties", "items", "oneOf", "anyOf", "allOf", "not", "other"]);
const SCOPE_NOTE = "Schemathesis live mode generates bounded GET inputs for the explicitly selected OpenAPI operations against one consented origin; it does not send writes, credentials, or follow redirects, and it does not establish whole-API coverage.";

export interface SchemathesisLiveOptions {
  document: unknown;
  baseUrl: string;
  operations: Array<{ method: "GET"; path: string }>;
  /** Must be true; the caller records explicit user consent for active testing. */
  consent: boolean;
  allowPrivate?: boolean;
  python?: string;
  timeoutMs?: number;
  maxRequests?: number;
  maxBodyBytes?: number;
  maxTotalBytes?: number;
  seed?: number;
  signal?: AbortSignal;
}

type LiveFailure = { rule: "not_a_server_error" | "response_schema_conformance"; kind: "server_error" | "malformed_json" | "schema_violation" | "unclassified"; keyword?: string };
interface LiveRecord { operation: string; ordinal: number; status: number; check: "passed" | "response_contract"; inputFingerprint: string; failures: LiveFailure[] }
interface LiveResult {
  status: "completed" | "partial";
  reason: "complete" | "request_limit" | "body_limit" | "timeout" | "transport_error";
  requestCount: number; bytesInspected: number; transportErrors: number;
  operations: Array<{ operation: string; requests: number }>;
  workerSha256: string; engineVersion: "4.2.0";
  runtime: Record<"python" | "hypothesis" | "jsonschema" | "requests", string>;
  records: LiveRecord[];
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function invalid(): never { throw new Error("invalid_worker_output"); }
function bounded(value: number | undefined, fallback: number, cap: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > cap) throw new RangeError("invalid budget");
  return result;
}

/** Strict projection: fixed enums, labels from the validated allowlist, counts and digests only. */
export function projectLiveResult(raw: string, labels: ReadonlySet<string>, maxRequests: number): LiveResult {
  if (typeof raw !== "string" || Buffer.byteLength(raw) > LIVE_OUTPUT_CAP) return invalid();
  const r: unknown = JSON.parse(raw);
  if (!record(r) || r.version !== 2) return invalid();
  const reasons = ["complete", "request_limit", "body_limit", "timeout", "transport_error"];
  if (typeof r.reason !== "string" || !reasons.includes(r.reason) || r.status !== (r.reason === "complete" ? "completed" : "partial")) return invalid();
  for (const key of ["requestCount", "bytesInspected", "transportErrors"] as const) {
    if (!Number.isSafeInteger(r[key]) || Number(r[key]) < 0) return invalid();
  }
  if (Number(r.requestCount) > maxRequests || (r.status === "completed" && Number(r.requestCount) < 1)) return invalid();
  if (r.engineVersion !== "4.2.0" || typeof r.workerSha256 !== "string" || !DIGEST.test(r.workerSha256) || !record(r.runtime)) return invalid();
  const runtime = {} as LiveResult["runtime"];
  for (const key of ["python", "hypothesis", "jsonschema", "requests"] as const) {
    const value = r.runtime[key];
    if (typeof value !== "string" || !VERSION.test(value)) return invalid();
    runtime[key] = value;
  }
  if (!Array.isArray(r.operations) || r.operations.length > labels.size) return invalid();
  const operations = r.operations.map((value: unknown) => {
    if (!record(value) || typeof value.operation !== "string" || !labels.has(value.operation) || !Number.isSafeInteger(value.requests) || Number(value.requests) < 0) return invalid();
    return { operation: value.operation, requests: Number(value.requests) };
  });
  if (operations.reduce((sum, item) => sum + item.requests, 0) !== Number(r.requestCount)) return invalid();
  if (!Array.isArray(r.records) || r.records.length > Number(r.requestCount)) return invalid();
  if (r.status === "completed" && r.records.length !== r.requestCount) return invalid();
  const records = r.records.map((value: unknown, index: number): LiveRecord => {
    if (!record(value) || typeof value.operation !== "string" || !labels.has(value.operation) || value.ordinal !== index + 1 ||
        !Number.isSafeInteger(value.status) || Number(value.status) < 100 || Number(value.status) > 599 ||
        (value.check !== "passed" && value.check !== "response_contract") ||
        typeof value.inputFingerprint !== "string" || !DIGEST.test(value.inputFingerprint) ||
        !Array.isArray(value.failures) || value.failures.length > 4 || (value.check === "passed") !== (value.failures.length === 0)) return invalid();
    const failures = value.failures.map((failure: unknown): LiveFailure => {
      if (!record(failure)) return invalid();
      if (failure.rule === "not_a_server_error" && failure.kind === "server_error") return { rule: failure.rule, kind: failure.kind };
      if (failure.rule === "response_schema_conformance" && (failure.kind === "malformed_json" || failure.kind === "unclassified")) return { rule: failure.rule, kind: failure.kind };
      if (failure.rule === "response_schema_conformance" && failure.kind === "schema_violation" && typeof failure.keyword === "string" && KEYWORDS.has(failure.keyword)) {
        return { rule: failure.rule, kind: failure.kind, keyword: failure.keyword };
      }
      return invalid();
    });
    if (failures.some((failure) => failure.rule === "not_a_server_error") !== (Number(value.status) >= 500)) return invalid();
    return { operation: value.operation, ordinal: index + 1, status: Number(value.status), check: value.check, inputFingerprint: value.inputFingerprint, failures };
  });
  return { status: r.status as LiveResult["status"], reason: r.reason as LiveResult["reason"], requestCount: Number(r.requestCount),
    bytesInspected: Number(r.bytesInspected), transportErrors: Number(r.transportErrors), operations,
    workerSha256: r.workerSha256, engineVersion: "4.2.0", runtime, records };
}

function findingsFor(result: LiveResult, origin: string): Finding[] {
  const groups = new Map<string, { operation: string; failure: LiveFailure; count: number }>();
  for (const item of result.records) {
    for (const failure of item.failures) {
      const key = `${item.operation}\u0000${failure.rule}\u0000${failure.kind}\u0000${failure.keyword ?? ""}`;
      const group = groups.get(key) ?? { operation: item.operation, failure, count: 0 };
      group.count += 1;
      groups.set(key, group);
    }
  }
  return [...groups.values()].map(({ operation, failure, count }) => {
    const path = operation.slice("GET ".length);
    const server = failure.rule === "not_a_server_error";
    const detail = failure.kind === "schema_violation" ? ` (schema keyword: ${failure.keyword})` : failure.kind === "malformed_json" ? " (malformed JSON)" : "";
    return {
      ruleId: server ? "api.schemathesis.server_error" : "api.schemathesis.response_schema",
      title: server ? "Generated request caused a server error" : "Response did not conform to the OpenAPI schema",
      description: `${operation}: ${count} generated request(s) failed ${failure.rule}${detail}. Response bodies and generated values are not retained; only input fingerprints are recorded.`,
      severity: server ? "medium" : "low",
      confidence: "high",
      kind: "observation",
      location: { url: `${origin}${path.replace(/^\//, "")}` },
      remediation: server
        ? "Handle invalid or unexpected inputs without a 5xx response, then rerun the same operation selection and seed."
        : "Align the response with the documented schema (or correct the schema), then rerun the same operation selection and seed.",
      references: ["https://schemathesis.readthedocs.io/en/stable/"],
    } satisfies Finding;
  });
}

function errorCheck(code: string, message: string, extra: Record<string, number | string | boolean> = {}): CheckResult[] {
  return [{ id: LIVE_CHECK_ID, status: "error", findings: [], notes: [SCOPE_NOTE, message], metrics: { requestCount: 0, errorCode: code, ...extra } }];
}

export async function runSchemathesisLive(options: SchemathesisLiveOptions): Promise<CheckResult[]> {
  if (!record(options) || options.consent !== true) return errorCheck("consent_required", "Active API testing requires explicit consent; no requests were made.");
  let maxRequests: number, timeoutMs: number, maxBodyBytes: number, maxTotalBytes: number, seed: number;
  try {
    maxRequests = bounded(options.maxRequests, 32, API_MAX_REQUESTS);
    timeoutMs = bounded(options.timeoutMs, API_DEFAULT_TIMEOUT_MS * 2, API_MAX_TIMEOUT_MS);
    maxBodyBytes = bounded(options.maxBodyBytes, API_MAX_SINGLE_BODY_BYTES, API_MAX_SINGLE_BODY_BYTES);
    maxTotalBytes = bounded(options.maxTotalBytes, API_MAX_TOTAL_BODY_BYTES, API_MAX_TOTAL_BODY_BYTES);
    seed = bounded(options.seed, 1, 2147483647);
  } catch {
    return errorCheck("invalid_budget", "Schemathesis live budgets are invalid; no requests were made.");
  }
  let selection;
  try {
    selection = selectOpenApiLiveOperations(options.document, options.operations);
  } catch (error) {
    return errorCheck(error instanceof OpenApiPolicyError ? error.code : "invalid_openapi", "The OpenAPI document or operation allowlist was rejected before any request.");
  }
  const schemaBytes = Buffer.from(JSON.stringify(selection.document));
  const schemaSha256 = createHash("sha256").update(schemaBytes).digest("hex");
  const script = fileURLToPath(new URL("../../workers/schemathesis/worker.py", import.meta.url));
  const expectedWorkerSha256 = createHash("sha256").update(await readFile(script)).digest("hex");
  const control = createApiRunControl(timeoutMs, options.signal);
  const engine = new AbortController();
  const stopEngine = () => engine.abort();
  control.signal.addEventListener("abort", stopEngine, { once: true });
  let gate: EgressGate | undefined;
  let target: string | undefined;
  try {
    let resolved;
    try {
      resolved = await resolveDastOrigin(options.baseUrl, options.allowPrivate === true, control.signal);
    } catch (error) {
      const code = error instanceof UrlNetworkError ? error.code : "dast_origin_required";
      return errorCheck(code, "The API origin was rejected by the URL-network policy (origin only; metadata/private rules apply); no requests were made.");
    }
    target = safeUrl(resolved.origin);
    if (control.signal.aborted) {
      return [{ id: LIVE_CHECK_ID, status: "partial", findings: [], notes: [SCOPE_NOTE, "Cancelled before any request was sent."], metrics: { requestCount: 0, stopReason: options.signal?.aborted ? "cancelled" : "timeout" } }];
    }
    gate = await startEgressGate({ origin: resolved.origin, address: resolved.address, methods: new Set(["GET", "HEAD"]),
      maxRequests, maxSingleBodyBytes: maxBodyBytes, maxTotalBytes, signal: control.signal, deadlineAt: control.deadlineAt });
    gate.onStop(stopEngine);
    const labels = new Set(selection.operations.map((item) => `GET ${item.path}`));
    const job = { version: 2, mode: "live", proxy: gate.proxyUrl, baseUrl: resolved.origin.href, schema: selection.document,
      operations: selection.operations, maxRequests, timeoutMs, maxBodyBytes, maxTotalBytes, seed };
    let result: LiveResult | undefined;
    let failure: string | undefined;
    try {
      const output = await superviseWorker(options.python ?? "python3", ["-I", script], JSON.stringify(job), engine.signal, LIVE_OUTPUT_CAP);
      if (output.exitCode !== 0) failure = "worker_failed";
      else {
        result = projectLiveResult(output.stdout, labels, maxRequests);
        if (result.workerSha256 !== expectedWorkerSha256) { result = undefined; failure = "worker_digest_mismatch"; }
      }
    } catch {
      failure = "worker_unavailable";
    }
    const counters = { ...gate.counters };
    const stop = gate.stopReason();
    const interrupted = control.signal.aborted;
    const metrics: Record<string, number | string | boolean> = {
      requestCount: result?.requestCount ?? counters.forwarded,
      gateForwarded: counters.forwarded, gateTunnels: counters.tunnels,
      skippedByBudget: counters.blockedBudget, blockedOrigin: counters.blockedOrigin, blockedMethod: counters.blockedMethod,
      upstreamErrors: counters.upstreamErrors, rejectedEncoding: counters.rejectedEncoding, responseBytes: counters.responseBytes,
      maxRequests, operationsSelected: selection.operations.length, seed, schemaSha256, workerSha256: expectedWorkerSha256,
      engine: "schemathesis", engineVersion: "4.2.0",
    };
    if (!result) {
      if (!interrupted && !stop && (failure === "worker_unavailable" || failure === "worker_failed")) {
        return [{ id: LIVE_CHECK_ID, status: "error", findings: [], notes: [SCOPE_NOTE, "The Schemathesis engine was unavailable or failed; Python 3.12 with workers/schemathesis/requirements.lock.txt is required."], metrics: { ...metrics, errorCode: failure } }];
      }
      return [{ id: LIVE_CHECK_ID, status: "partial", findings: [], notes: [SCOPE_NOTE, `Execution stopped before a trustworthy engine result (${stop ?? (options.signal?.aborted ? "cancelled" : interrupted ? "timeout" : failure)}). Counts are gate observations only.`], metrics: { ...metrics, stopReason: stop ?? (options.signal?.aborted ? "cancelled" : interrupted ? "timeout" : failure ?? "unknown") } }];
    }
    for (const operation of result.operations) metrics[`requests:${operation.operation}`] = operation.requests;
    metrics.operationsExercised = result.operations.filter((item) => item.requests > 0).length;
    metrics.transportErrors = result.transportErrors;
    metrics.bytesInspected = result.bytesInspected;
    metrics.python = result.runtime.python; metrics.hypothesis = result.runtime.hypothesis;
    const incomplete = result.status !== "completed" || stop !== undefined || counters.upstreamErrors > 0 || counters.rejectedEncoding > 0 ||
      counters.blockedOrigin > 0 || counters.blockedMethod > 0 || interrupted;
    const reason = stop ?? (result.reason !== "complete" ? result.reason : counters.upstreamErrors > 0 ? "upstream_error"
      : counters.rejectedEncoding > 0 ? "rejected_encoding" : counters.blockedOrigin + counters.blockedMethod > 0 ? "egress_refused" : interrupted ? "timeout" : "complete");
    metrics.stopReason = reason;
    const notes = [SCOPE_NOTE,
      `Target ${target}; ${result.requestCount} generated request(s) across ${metrics.operationsExercised}/${selection.operations.length} selected operation(s); ${counters.blockedBudget} refused by the request budget.`,
      "Reproduce with the same schema digest, operation selection and seed; Hypothesis generation may still vary across engine versions."];
    if (incomplete) notes.push(`Incomplete: ${reason}. Treat absent findings as unverified.`);
    return [{ id: LIVE_CHECK_ID, status: incomplete ? "partial" : "completed", findings: findingsFor(result, target), notes, metrics }];
  } finally {
    control.signal.removeEventListener("abort", stopEngine);
    control.dispose();
    await gate?.close();
  }
}
