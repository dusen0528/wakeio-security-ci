import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { link, mkdir, open, readFile, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { API_DEFAULT_TIMEOUT_MS, API_MAX_REQUESTS, API_MAX_SINGLE_BODY_BYTES,
  API_MAX_TOTAL_BODY_BYTES, API_MAX_TIMEOUT_MS, createApiRunControl } from "./api.js";

const OUTPUT_CAP = 65536;
const UUID = /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const VERSION = /^\d{1,4}\.\d{1,4}\.\d{1,4}(?:[a-z]\d{1,4})?$/;
export interface FixtureJob {
  version: 1; environment: "staging";
  fixture: "broken" | "fixed" | "oversized" | "slow";
  operations: ["readItems"]; maxRequests: number; timeoutMs: number;
  maxBodyBytes: number; maxTotalBytes: number; seed: number;
  /** Safe synthetic inputs; null selects Hypothesis generation. No arbitrary HTTP replay. */
  replayQuantities: number[] | null;
}
export interface FixtureFailure {
  rule: "response_schema_conformance" | "not_a_server_error";
  kind: "type_mismatch" | "schema_violation" | "server_error";
  instancePointer: "/count" | "/";
  expected: "integer" | "schema_conformant" | "status_below_500";
  actualType?: "string";
}
export interface FixtureRecord {
  operation: "readItems"; method: "GET"; path: "/items";
  ordinal: number; status: number; check: "passed" | "response_contract";
  input: { quantity: number; token: "[REDACTED]"; fingerprint: string };
  failures: FixtureFailure[];
}
export interface RedactedWorkerResult {
  version: 1;
  status: "completed" | "partial" | "error";
  reason: "complete" | "request_limit" | "body_limit" | "timeout" | "cancelled" | "worker_error";
  requestCount?: number; bytesInspected?: number;
  schemaSha256?: string; workerSha256?: string; dependencyLockSha256?: string;
  engineVersion?: "4.2.0";
  runtime?: { python: string; hypothesis: string; jsonschema: string; werkzeug: string };
  records?: FixtureRecord[];
}
export interface FixtureArtifact extends RedactedWorkerResult {
  runId: string; scope: "synthetic-wsgi-only"; redacted: true;
  replay: { job: FixtureJob; workerProtocol: 1; nodeVersion: string; note: string };
}
export interface CodeWorker {
  /** Must terminate and await its execution on abort, including owned descendants. */
  execute(job: FixtureJob, signal: AbortSignal): Promise<{ exitCode: number; stdout: string }>;
}
/** Coordinator-selected protocol-v1 implementation. Digests do not attest worker honesty or installed dependencies. */
export interface FixtureWorkerManifest {
  schemaSha256: string; workerSha256: string; dependencyLockSha256: string;
}
/** Implementations accept only redacted bytes. Same key+bytes retries are idempotent; conflicting bytes must fail. */
export interface SharedArtifactStorage {
  put(id: string, redactedJson: Uint8Array): Promise<string>;
}
/** Trusted local directory, POSIX filesystem: publish complete bytes atomically, without overwriting. */
export function localArtifactStorage(directory: string): SharedArtifactStorage {
  return { async put(id, redactedJson) {
    if (!UUID.test(id)) throw new Error("invalid_artifact_id");
    const bytes = Buffer.from(redactedJson);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const path = resolve(directory, `${id}.json`);
    const temporary = resolve(directory, `.${id}.${randomUUID()}.tmp`);
    const handle = await open(temporary, "wx", 0o600);
    try {
      try { await handle.writeFile(bytes); await handle.sync(); }
      finally { await handle.close(); }
      try { await link(temporary, path); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (!(await readFile(path)).equals(bytes)) throw new Error("artifact_conflict");
      }
      // Return only after the publication has been synced. On failure the caller
      // may retry identical bytes with the same key; never overwrite another result.
      const dir = await open(directory, "r");
      try { await dir.sync(); } finally { await dir.close(); }
      return path;
    } finally { await unlink(temporary); }
  } };
}
/** Trusted executable/arguments, never supplied by the job. POSIX process groups, no shell or inherited credentials. */
export function localCodeWorker(executable: string, args: readonly string[]): CodeWorker {
  return { execute(job, signal) { return superviseWorker(executable, args, JSON.stringify(job), signal); } };
}
/** Run a trusted worker in its own POSIX process group with a capped stdout and no stderr retention. */
export function superviseWorker(executable: string, args: readonly string[], input: string, signal: AbortSignal,
  outputCap = OUTPUT_CAP): Promise<{ exitCode: number; stdout: string }> {
    return new Promise((done, reject) => {
      if (signal.aborted) { reject(new Error("cancelled")); return; }
      if (process.platform === "win32") { reject(new Error("process_groups_unavailable")); return; }
      const child = spawn(executable, [...args], {
        detached: true, shell: false, env: { PATH: process.env.PATH ?? "" },
        stdio: ["pipe", "pipe", "pipe"],
      });
      const chunks: Buffer[] = [];
      let size = 0, overflow = false, unavailable = false;
      // Kill the isolated process group, including descendants holding output
      // pipes open. Await 'close', not merely aborting the Node await.
      const terminate = () => {
        if (child.pid === undefined) return;
        try { process.kill(-child.pid, "SIGKILL"); }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ESRCH") child.kill("SIGKILL");
        }
      };
      signal.addEventListener("abort", terminate, { once: true });
      if (signal.aborted) terminate();
      child.stdout.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > outputCap) { overflow = true; terminate(); }
        else chunks.push(chunk);
      });
      child.stderr.on("data", () => { /* raw diagnostics never retained */ });
      child.stdin.on("error", () => { /* exit/close handles EPIPE */ });
      child.once("error", () => { unavailable = true; terminate(); });
      // A normally exiting worker must not leave background descendants alive.
      child.once("exit", terminate);
      child.once("close", (code) => {
        signal.removeEventListener("abort", terminate);
        if (unavailable) { reject(new Error("worker_unavailable")); return; }
        done({ exitCode: overflow ? -1 : code ?? -1,
          stdout: overflow ? "" : Buffer.concat(chunks).toString("utf8") });
      });
      child.stdin.end(input);
    });
}
export function pythonFixtureWorker(python = "python3"): CodeWorker {
  const script = fileURLToPath(new URL("../../workers/schemathesis/worker.py", import.meta.url));
  return localCodeWorker(python, ["-I", script]);
}
export interface SchemathesisOptions {
  fixture: FixtureJob["fixture"]; environment: "staging"; operations: ["readItems"];
  storage: SharedArtifactStorage; worker: CodeWorker; signal?: AbortSignal;
  timeoutMs?: number; maxRequests?: number; maxBodyBytes?: number; maxTotalBytes?: number; seed?: number;
  replayQuantities?: number[];
  /** Omitted: hash the trusted bundled files before execution. Custom deployments must pin their expected bytes here. */
  expectedManifest?: FixtureWorkerManifest;
  /** Reusing an ID still executes the worker again; storage only deduplicates identical resulting bytes. */
  runId?: string;
}
function bounded(value: number, cap: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > cap) throw new RangeError("invalid budget");
  return value;
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function invalid(): never { throw new Error("invalid_worker_output"); }
function manifest(value: unknown): Readonly<FixtureWorkerManifest> {
  if (!record(value)) throw new Error("invalid_expected_manifest");
  const result = {} as FixtureWorkerManifest;
  for (const key of ["schemaSha256", "workerSha256", "dependencyLockSha256"] as const) {
    if (typeof value[key] !== "string" || !DIGEST.test(value[key])) throw new Error("invalid_expected_manifest");
    result[key] = value[key];
  }
  // Copy before invoking any worker; neither the job nor a caller-owned object
  // may change the coordinator's expected implementation during execution.
  return Object.freeze(result);
}
async function bundledManifest(): Promise<Readonly<FixtureWorkerManifest>> {
  const files = [["schemaSha256", "openapi.json"], ["workerSha256", "worker.py"],
    ["dependencyLockSha256", "requirements.lock.txt"]] as const;
  const entries = await Promise.all(files.map(async ([key, file]) => {
    const bytes = await readFile(new URL(`../../workers/schemathesis/${file}`, import.meta.url));
    return [key, createHash("sha256").update(bytes).digest("hex")] as const;
  }));
  return manifest(Object.fromEntries(entries));
}
function projectFailure(v: unknown): FixtureFailure {
  if (!record(v)) return invalid();
  if (v.rule === "response_schema_conformance" && v.kind === "type_mismatch" &&
      v.instancePointer === "/count" && v.expected === "integer" && v.actualType === "string") {
    return { rule: v.rule, kind: v.kind, instancePointer: v.instancePointer, expected: v.expected, actualType: v.actualType };
  }
  if (v.rule === "response_schema_conformance" && v.kind === "schema_violation" &&
      v.instancePointer === "/" && v.expected === "schema_conformant") {
    return { rule: v.rule, kind: v.kind, instancePointer: v.instancePointer, expected: v.expected };
  }
  if (v.rule === "not_a_server_error" && v.kind === "server_error" &&
      v.instancePointer === "/" && v.expected === "status_below_500") {
    return { rule: v.rule, kind: v.kind, instancePointer: v.instancePointer, expected: v.expected };
  }
  return invalid();
}
/** Project enums, static fixture paths, bounded synthetic integers and versions; never engine messages or raw values. */
function project(raw: string, job: FixtureJob, expected: Readonly<FixtureWorkerManifest>): RedactedWorkerResult {
  if (typeof raw !== "string" || Buffer.byteLength(raw) > OUTPUT_CAP) return invalid();
  const r: unknown = JSON.parse(raw);
  if (!record(r) || r.version !== 1) return invalid();
  if (r.status === "error") {
    if (r.reason !== "worker_error") return invalid();
    return { version: 1, status: "error", reason: "worker_error" };
  }
  const reasons = ["complete", "request_limit", "body_limit", "timeout"];
  if (typeof r.reason !== "string" || !reasons.includes(r.reason) || r.status !== (r.reason === "complete" ? "completed" : "partial") ||
      !Number.isSafeInteger(r.requestCount) || Number(r.requestCount) < 0 || Number(r.requestCount) > job.maxRequests ||
      (r.status === "completed" && Number(r.requestCount) < 1) ||
      !Number.isSafeInteger(r.bytesInspected) || Number(r.bytesInspected) < 0 || Number(r.bytesInspected) > job.maxTotalBytes ||
      typeof r.schemaSha256 !== "string" || !DIGEST.test(r.schemaSha256) || r.engineVersion !== "4.2.0" ||
      typeof r.workerSha256 !== "string" || !DIGEST.test(r.workerSha256) ||
      typeof r.dependencyLockSha256 !== "string" || !DIGEST.test(r.dependencyLockSha256) ||
      !Array.isArray(r.records) || r.records.length > Number(r.requestCount) ||
      (r.status === "completed" && r.records.length !== r.requestCount) ||
      (r.status === "completed" && job.replayQuantities !== null && r.requestCount !== job.replayQuantities.length) ||
      r.schemaSha256 !== expected.schemaSha256 || r.workerSha256 !== expected.workerSha256 ||
      r.dependencyLockSha256 !== expected.dependencyLockSha256) return invalid();
  if (!record(r.runtime)) return invalid();
  const runtime = {} as NonNullable<RedactedWorkerResult["runtime"]>;
  for (const key of ["python", "hypothesis", "jsonschema", "werkzeug"] as const) {
    const value = r.runtime[key];
    if (typeof value !== "string" || !VERSION.test(value)) return invalid();
    runtime[key] = value;
  }
  const records = r.records.map((v: unknown, index: number): FixtureRecord => {
    if (!record(v) || v.operation !== "readItems" || v.method !== "GET" || v.path !== "/items" ||
        v.ordinal !== index + 1 || !Number.isSafeInteger(v.status) || Number(v.status) < 100 || Number(v.status) > 599 ||
        (typeof v.check !== "string" || (v.check !== "passed" && v.check !== "response_contract")) || !record(v.input) ||
        !Number.isSafeInteger(v.input.quantity) || Number(v.input.quantity) < 1 || Number(v.input.quantity) > 20 ||
        v.input.token !== "[REDACTED]" || typeof v.input.fingerprint !== "string" || !DIGEST.test(v.input.fingerprint) ||
        !Array.isArray(v.failures) || v.failures.length > 2 ||
        (v.check === "passed") !== (v.failures.length === 0)) return invalid();
    const failures = v.failures.map(projectFailure);
    // Protocol v1 always selects not_a_server_error and response_schema_conformance.
    // An HTTP 5xx must therefore carry its selected check's failure, exactly once.
    if (new Set(failures.map(f => f.rule)).size !== failures.length ||
        failures.some(f => f.rule === "not_a_server_error") !== (Number(v.status) >= 500)) return invalid();
    const fingerprint = createHash("sha256").update(JSON.stringify({ quantity: Number(v.input.quantity) })).digest("hex");
    if (v.input.fingerprint !== fingerprint) return invalid();
    if (job.replayQuantities && v.input.quantity !== job.replayQuantities[index]) return invalid();
    return { operation: "readItems", method: "GET", path: "/items", ordinal: index + 1,
      status: Number(v.status), check: v.check,
      input: { quantity: Number(v.input.quantity), token: "[REDACTED]", fingerprint: v.input.fingerprint }, failures };
  });
  return { version: 1, status: r.status as "completed" | "partial", reason: r.reason as RedactedWorkerResult["reason"],
    requestCount: Number(r.requestCount), bytesInspected: Number(r.bytesInspected), schemaSha256: r.schemaSha256,
    workerSha256: r.workerSha256, dependencyLockSha256: r.dependencyLockSha256,
    engineVersion: "4.2.0", runtime, records };
}
export async function runSchemathesisFixture(options: SchemathesisOptions) {
  if (!record(options) || options.environment !== "staging" || JSON.stringify(options.operations) !== '["readItems"]' ||
      !["broken", "fixed", "oversized", "slow"].includes(options.fixture)) throw new Error("invalid_fixture_scope");
  const job: FixtureJob = { version: 1, environment: "staging", fixture: options.fixture,
    operations: ["readItems"], timeoutMs: bounded(options.timeoutMs ?? API_DEFAULT_TIMEOUT_MS, API_MAX_TIMEOUT_MS),
    maxRequests: bounded(options.maxRequests ?? 10, API_MAX_REQUESTS),
    maxBodyBytes: bounded(options.maxBodyBytes ?? API_MAX_SINGLE_BODY_BYTES, API_MAX_SINGLE_BODY_BYTES),
    maxTotalBytes: bounded(options.maxTotalBytes ?? API_MAX_TOTAL_BODY_BYTES, API_MAX_TOTAL_BODY_BYTES),
    seed: bounded(options.seed ?? 1, 2147483647), replayQuantities: null };
  if (options.replayQuantities !== undefined) {
    if (!Array.isArray(options.replayQuantities) || options.replayQuantities.length !== job.maxRequests) throw new Error("invalid_replay");
    job.replayQuantities = options.replayQuantities.map(q => bounded(q, 20));
  }
  const id = options.runId ?? randomUUID();
  if (typeof id !== "string" || !UUID.test(id)) throw new Error("invalid_artifact_id");
  const configuredManifest = options.expectedManifest === undefined ? undefined : manifest(options.expectedManifest);
  const control = createApiRunControl(job.timeoutMs, options.signal);
  let result: RedactedWorkerResult;
  try {
    if (control.signal.aborted) throw new Error("cancelled");
    const expected = configuredManifest ?? await bundledManifest();
    if (control.signal.aborted || Date.now() >= control.deadlineAt) throw new Error("cancelled");
    // Pass a copy so a remote/custom implementation cannot alter the artifact's scope.
    const output = await options.worker.execute(structuredClone(job), control.signal);
    if (control.signal.aborted || Date.now() >= control.deadlineAt) throw new Error("cancelled");
    if (output.exitCode !== 0) throw new Error("worker_failed");
    result = project(output.stdout, job, expected);
  } catch {
    const interrupted = control.signal.aborted || Date.now() >= control.deadlineAt;
    result = { version: 1, status: interrupted ? "partial" : "error",
      reason: interrupted ? (options.signal?.aborted ? "cancelled" : "timeout") : "worker_error" };
  } finally { control.dispose(); }
  const artifact: FixtureArtifact = { ...result, runId: id, scope: "synthetic-wsgi-only", redacted: true,
    replay: { job, workerProtocol: 1, nodeVersion: process.versions.node,
      note: "Replay safe quantity inputs with the bundled fixture; token is injected locally. No raw HTTP replay." } };
  const bytes = Buffer.from(JSON.stringify(artifact, null, 2) + "\n");
  // A storage failure rejects the entire delivery, including for completed scans.
  const artifactRef = await options.storage.put(id, bytes);
  return { artifact, artifactRef, sha256: createHash("sha256").update(bytes).digest("hex") };
}
