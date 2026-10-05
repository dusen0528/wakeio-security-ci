import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createApiRunControl } from "../src/api.js";
import { localArtifactStorage, localCodeWorker, pythonFixtureWorker, runSchemathesisFixture,
  type CodeWorker, type FixtureJob, type FixtureWorkerManifest, type SchemathesisOptions } from "../src/schemathesis.js";

function options(worker: CodeWorker): SchemathesisOptions {
  return { fixture: "fixed", environment: "staging", operations: ["readItems"],
    worker, storage: { async put(_id, bytes) {
      assert.ok(!Buffer.from(bytes).toString().includes("synthetic-secret-canary"));
      return "memory:artifact";
    } } };
}
const bundled: FixtureWorkerManifest = {
  schemaSha256: createHash("sha256").update(await readFile(new URL("../../workers/schemathesis/openapi.json", import.meta.url))).digest("hex"),
  workerSha256: createHash("sha256").update(await readFile(new URL("../../workers/schemathesis/worker.py", import.meta.url))).digest("hex"),
  dependencyLockSha256: createHash("sha256").update(await readFile(new URL("../../workers/schemathesis/requirements.lock.txt", import.meta.url))).digest("hex"),
};
const valid = { version: 1, status: "completed", reason: "complete", requestCount: 1,
  bytesInspected: 10, ...bundled, engineVersion: "4.2.0",
  runtime: { python: "3.12.13", hypothesis: "6.168.3", jsonschema: "4.26.0", werkzeug: "3.1.3" },
  records: [{ operation: "readItems", method: "GET", path: "/items", ordinal: 1, status: 200, check: "passed",
    input: { quantity: 1, token: "[REDACTED]", fingerprint: createHash("sha256").update('{"quantity":1}').digest("hex") }, failures: [] }] };
function mock(value: unknown): CodeWorker {
  return { async execute() { return { exitCode: 0, stdout: JSON.stringify(value) }; } };
}
function fixtureRecord(ordinal: number, quantity: number) {
  return { ...valid.records[0], ordinal,
    input: { quantity, token: "[REDACTED]", fingerprint: createHash("sha256")
      .update(`{"quantity":${quantity}}`).digest("hex") } };
}
function differentDigest(digest: string) {
  return (digest[0] === "0" ? "1" : "0") + digest.slice(1);
}
test("reason must be a string enum, with a coherent completed or partial status", async () => {
  for (const reason of [["timeout"], [], {}, null, 1, true, "cancelled", "unknown"]) {
    const result = await runSchemathesisFixture(options(mock({ ...valid, status: "partial", reason })));
    assert.equal(result.artifact.status, "error");
    assert.equal(result.artifact.reason, "worker_error");
  }
  for (const value of [{ ...valid, reason: "timeout" }, { ...valid, status: "partial" }]) {
    assert.equal((await runSchemathesisFixture(options(mock(value)))).artifact.status, "error");
  }
  assert.equal((await runSchemathesisFixture(options(mock({ ...valid, status: "partial", reason: "timeout" })))).artifact.reason, "timeout");
});
test("selected server-error check rejects 5xx passed or missing/duplicate failures", async () => {
  const server = { rule: "not_a_server_error", kind: "server_error", expected: "status_below_500", instancePointer: "/" };
  const schema = { rule: "response_schema_conformance", kind: "schema_violation", expected: "schema_conformant", instancePointer: "/" };
  for (const row of [
    { ...valid.records[0], status: 500 },
    { ...valid.records[0], status: 599, check: "response_contract", failures: [schema] },
    { ...valid.records[0], status: 499, check: "response_contract", failures: [server] },
    { ...valid.records[0], status: 500, check: "response_contract", failures: [server, server] },
    { ...valid.records[0], check: "response_contract", failures: [schema, schema] },
  ]) {
    assert.equal((await runSchemathesisFixture(options(mock({ ...valid, records: [row] })))).artifact.status, "error");
  }
  for (const failures of [[server], [server, schema]]) {
    const result = await runSchemathesisFixture(options(mock({ ...valid,
      records: [{ ...valid.records[0], status: 500, check: "response_contract", failures }] })));
    assert.equal(result.artifact.status, "completed");
    assert.equal(result.artifact.records?.[0].check, "response_contract");
  }
  assert.equal((await runSchemathesisFixture(options(mock({ ...valid,
    records: [{ ...valid.records[0], status: 499 }] })))).artifact.status, "completed");
});
test("completed explicit replay requires every planned ordinal and input, unlike generation", async () => {
  const generated = await runSchemathesisFixture({ ...options(mock(valid)), maxRequests: 3 });
  assert.equal(generated.artifact.status, "completed");
  assert.equal(generated.artifact.requestCount, 1);
  const o = { ...options(mock(valid)), maxRequests: 3, replayQuantities: [1, 2, 3] };
  assert.equal((await runSchemathesisFixture(o)).artifact.status, "error");
  const records = [fixtureRecord(1, 1), fixtureRecord(2, 2), fixtureRecord(3, 3)];
  for (const invalidRecords of [records.slice(0, 2), [records[0], records[0], records[2]],
    [records[0], records[2], records[1]], [records[0], fixtureRecord(2, 3), records[2]]]) {
    assert.equal((await runSchemathesisFixture({ ...o,
      worker: mock({ ...valid, requestCount: 3, records: invalidRecords }) })).artifact.status, "error");
  }
  const complete = await runSchemathesisFixture({ ...o, worker: mock({ ...valid, requestCount: 3, records }) });
  assert.equal(complete.artifact.status, "completed");
  assert.deepEqual(complete.artifact.records?.map(r => [r.ordinal, r.input.quantity]), [[1, 1], [2, 2], [3, 3]]);
  const repeated = await runSchemathesisFixture({ ...o, replayQuantities: [2, 2, 20],
    worker: mock({ ...valid, requestCount: 3, records: [fixtureRecord(1, 2), fixtureRecord(2, 2), fixtureRecord(3, 20)] }) });
  assert.equal(repeated.artifact.status, "completed");
});
test("partial explicit replay preserves only a verified prefix, including unrecorded attempted calls", async () => {
  const output = { ...valid, status: "partial", reason: "body_limit", requestCount: 3,
    records: [fixtureRecord(1, 1), fixtureRecord(2, 2)] };
  const o = { ...options(mock(output)), maxRequests: 3, replayQuantities: [1, 2, 3] };
  const partial = await runSchemathesisFixture(o);
  assert.equal(partial.artifact.status, "partial");
  assert.equal(partial.artifact.requestCount, 3);
  assert.equal(partial.artifact.records?.length, 2);
  const prefixOne = await runSchemathesisFixture({ ...o, worker: mock({ ...output,
    reason: "timeout", requestCount: 1, records: [fixtureRecord(1, 1)] }) });
  assert.equal(prefixOne.artifact.status, "partial");
  assert.equal(prefixOne.artifact.records?.length, 1);
  for (const records of [[fixtureRecord(1, 2)], [fixtureRecord(1, 1), fixtureRecord(2, 3)],
    [fixtureRecord(2, 1)], [fixtureRecord(1, 1), fixtureRecord(1, 2)]]) {
    assert.equal((await runSchemathesisFixture({ ...o, worker: mock({ ...output, records }) })).artifact.status, "error");
  }
  assert.equal((await runSchemathesisFixture({ ...o, worker: mock({ ...output, requestCount: 1, records: [] }) })).artifact.status, "partial");
});
test("coordinator checks bundled digests and recomputes canonical safe-input fingerprints", async () => {
  for (const key of ["schemaSha256", "workerSha256", "dependencyLockSha256"] as const) {
    for (const status of ["completed", "partial"]) {
      const output = { ...valid, status, reason: status === "completed" ? "complete" : "timeout",
        [key]: differentDigest(bundled[key]) };
      assert.equal((await runSchemathesisFixture(options(mock(output)))).artifact.status, "error");
    }
  }
  for (const input of [{ ...valid.records[0].input, fingerprint: differentDigest(valid.records[0].input.fingerprint) },
    { ...valid.records[0].input, quantity: 2 }]) {
    assert.equal((await runSchemathesisFixture(options(mock({ ...valid,
      records: [{ ...valid.records[0], input }] })))).artifact.status, "error");
  }
  assert.equal((await runSchemathesisFixture(options(mock(valid)))).artifact.status, "completed");
});
test("custom manifests are explicit, validated before execution and copied immutably", async () => {
  const expected = { schemaSha256: differentDigest(bundled.schemaSha256),
    workerSha256: differentDigest(bundled.workerSha256), dependencyLockSha256: differentDigest(bundled.dependencyLockSha256) };
  const output = { ...valid, ...expected };
  assert.equal((await runSchemathesisFixture(options(mock(output)))).artifact.status, "error");
  assert.equal((await runSchemathesisFixture({ ...options(mock(output)), expectedManifest: expected })).artifact.status, "completed");
  assert.equal((await runSchemathesisFixture({ ...options(mock(valid)), expectedManifest: expected })).artifact.status, "error");
  let calls = 0;
  for (const value of [null, {}, { ...expected, workerSha256: [expected.workerSha256] },
    { ...expected, schemaSha256: "wrong" }, { ...expected, dependencyLockSha256: undefined }]) {
    await assert.rejects(runSchemathesisFixture({ ...options({ async execute() { calls++; throw Error(); } }),
      expectedManifest: value } as SchemathesisOptions), /invalid_expected_manifest/);
  }
  assert.equal(calls, 0);
  const mutable = { ...bundled };
  const result = await runSchemathesisFixture({ ...options({ async execute() {
    mutable.workerSha256 = expected.workerSha256;
    return { exitCode: 0, stdout: JSON.stringify({ ...valid, workerSha256: mutable.workerSha256 }) };
  } }), expectedManifest: mutable });
  assert.equal(result.artifact.status, "error");
});
test("adapter projects metadata and never persists raw logs/extra fields", async () => {
  const r = await runSchemathesisFixture(options(mock({ ...valid,
    raw: "synthetic-secret-canary", records: [{ ...valid.records[0], body: "synthetic-secret-canary" }] })));
  assert.equal(r.artifact.status, "completed");
  assert.equal(r.sha256.length, 64);
});
test("adapter rejects malformed output, impossible counters, and injected operations", async () => {
  for (const r of [{}, { ...valid, requestCount: 65 }, { ...valid, bytesInspected: -1 },
    { ...valid, records: [] }, { ...valid, records: [{ ...valid.records[0], operation: "writeAdmin" }] }]) {
    const result = await runSchemathesisFixture(options(mock(r)));
    assert.equal(result.artifact.status, "error");
    assert.equal(result.artifact.reason, "worker_error");
  }
  for (const worker of [
    { async execute() { return { exitCode: 1, stdout: "synthetic-secret-canary" }; } },
    { async execute(): Promise<never> { throw Error("synthetic-secret-canary"); } },
  ]) {
    const result = await runSchemathesisFixture(options(worker));
    assert.equal(result.artifact.status, "error");
    assert.equal(result.artifact.reason, "worker_error");
  }
});
test("invalid scopes and budgets never invoke worker", async () => {
  let calls = 0;
  const o = options({ async execute() { calls++; throw Error(); } });
  for (const bad of [{ environment: "production" }, { operations: ["writeAdmin"] },
    { fixture: "https://example.com" }, { timeoutMs: NaN }, { maxRequests: 65 }, { seed: 0 }]) {
    await assert.rejects(runSchemathesisFixture({ ...o, ...bad } as SchemathesisOptions));
  }
  assert.equal(calls, 0);
});
test("pre-cancel skips worker; shared API control propagates cancellation", async () => {
  const c = new AbortController(); c.abort();
  let calls = 0;
  const r = await runSchemathesisFixture({ ...options({ async execute() { calls++; throw Error(); } }), signal: c.signal });
  assert.equal(calls, 0); assert.equal(r.artifact.reason, "cancelled");
  const upstream = new AbortController();
  const control = createApiRunControl(30000, upstream.signal);
  upstream.abort(); assert.equal(control.signal.aborted, true); control.dispose();
});
test("storage failure is surfaced, never reported as completed delivery", async () => {
  await assert.rejects(runSchemathesisFixture({ ...options(mock(valid)), storage: { async put() { throw Error("store unavailable"); } } }));
});
test("local artifact store refuses traversal keys", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-store-"));
  try {
    await assert.rejects(localArtifactStorage(directory).put("../escape", Buffer.from("{}")));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

const python = process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(process.cwd(), ".venv-schemathesis/bin/python");
test("real Schemathesis fixture: broken/fixed, limits, redaction, reproducibility and storage", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-st-"));
  try {
    const o = { ...options(pythonFixtureWorker(python)), storage: localArtifactStorage(directory), maxRequests: 3 };
    const broken = await runSchemathesisFixture({ ...o, fixture: "broken" });
    assert.equal(broken.artifact.status, "completed");
    assert.ok((broken.artifact.records as Array<{ check: string }>).some(v => v.check === "response_contract"));
    const fixed = await runSchemathesisFixture(o);
    assert.equal(fixed.artifact.status, "completed");
    assert.ok((fixed.artifact.records as Array<{ check: string }>).every(v => v.check === "passed"));
    assert.equal(fixed.artifact.requestCount, 3);
    const bounded = await runSchemathesisFixture({ ...o, maxRequests: 1 });
    assert.equal(bounded.artifact.requestCount, 1);
    const replay = await runSchemathesisFixture(o);
    assert.deepEqual(replay.artifact.records, fixed.artifact.records);
    assert.equal(replay.artifact.schemaSha256, fixed.artifact.schemaSha256);
    assert.equal(replay.artifact.dependencyLockSha256, fixed.artifact.dependencyLockSha256);
    assert.deepEqual(replay.artifact.runtime, fixed.artifact.runtime);
    assert.equal(replay.artifact.engineVersion, "4.2.0");
    assert.equal(replay.artifact.runtime!.hypothesis, "6.168.3");
    assert.equal(replay.artifact.runtime!.jsonschema, "4.26.0");
    assert.equal(replay.artifact.runtime!.werkzeug, "3.1.3");
    assert.deepEqual(broken.artifact.records?.[0].failures, [{ rule: "response_schema_conformance",
      kind: "type_mismatch", instancePointer: "/count", expected: "integer", actualType: "string" }]);
    assert.match(broken.artifact.runtime!.python, /^3\.\d+\.\d+$/);
    const quantities = broken.artifact.records!.map(r => r.input.quantity);
    const exactReplay = await runSchemathesisFixture({ ...o, fixture: "broken", seed: 987,
      maxRequests: quantities.length, replayQuantities: quantities });
    assert.deepEqual(exactReplay.artifact.records?.map(r => r.input.fingerprint),
      broken.artifact.records?.map(r => r.input.fingerprint));
    const concurrent = await Promise.all([runSchemathesisFixture(o), runSchemathesisFixture(o)]);
    assert.notEqual(concurrent[0].artifactRef, concurrent[1].artifactRef);
    const raw = await readFile(broken.artifactRef, "utf8");
    assert.ok(!raw.includes("synthetic-secret-canary"));
    assert.ok(!raw.includes("curl") && !raw.includes("Authorization"));
    assert.equal((await stat(broken.artifactRef)).mode & 0o777, 0o600);
    const oversized = await runSchemathesisFixture({ ...o, fixture: "oversized", maxBodyBytes: 10 });
    assert.equal(oversized.artifact.status, "partial");
    assert.equal(oversized.artifact.reason, "body_limit");
    assert.equal(oversized.artifact.requestCount, 1);
    const total = await runSchemathesisFixture({ ...o, maxTotalBytes: 1 });
    assert.equal(total.artifact.reason, "body_limit");
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test("real worker deadline and running cancellation interrupt slow fixture", async () => {
  const o = options(pythonFixtureWorker(python));
  const start = Date.now();
  const timed = await runSchemathesisFixture({ ...o, fixture: "slow", timeoutMs: 2000 });
  assert.equal(timed.artifact.reason, "timeout");
  assert.ok(Date.now() - start < 4500);
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), 2000);
  try {
    const r = await runSchemathesisFixture({ ...o, fixture: "slow", signal: c.signal });
    assert.equal(r.artifact.reason, "cancelled");
  } finally { clearTimeout(timer); }
});

test("metadata rejects raw inputs, incoherent failure checks and malformed runtime metadata", async () => {
  for (const value of [
    { ...valid, runtime: { ...valid.runtime, python: "synthetic-secret-canary" } },
    { ...valid, records: [{ ...valid.records[0], input: { quantity: 21, token: "[REDACTED]" } }] },
    { ...valid, records: [{ ...valid.records[0], input: { quantity: 1, token: "synthetic-secret-canary" } }] },
    { ...valid, records: [{ ...valid.records[0], path: "/admin" }] },
    { ...valid, records: [{ ...valid.records[0], check: "response_contract" }] },
    { ...valid, records: [{ ...valid.records[0], check: ["passed"] }] },
    { ...valid, records: [{ ...valid.records[0], check: "response_contract", failures: [{
      rule: "not_a_server_error", kind: "server_error", expected: "status_below_500", instancePointer: "/" }] }] },
    { ...valid, records: [{ ...valid.records[0], check: "response_contract", failures: [{
      rule: "response_schema_conformance", kind: "synthetic-secret-canary" }] }] },
  ]) {
    assert.equal((await runSchemathesisFixture(options(mock(value)))).artifact.status, "error");
  }
  const injected = await runSchemathesisFixture(options(mock({ ...valid,
    runtime: { ...valid.runtime, raw: "synthetic-secret-canary" }, records: [{ ...valid.records[0],
      input: { ...valid.records[0].input, secret: "synthetic-secret-canary" }, raw: "synthetic-secret-canary" }] })));
  assert.equal(injected.artifact.status, "completed");
});
test("invalid explicit replays and delivery keys fail before executing", async () => {
  let calls = 0;
  const o = options({ async execute() { calls++; throw Error(); } });
  for (const bad of [{ runId: "../escape" }, { replayQuantities: [0] }, { maxRequests: 1, replayQuantities: [21] },
    { maxRequests: 1, replayQuantities: [1, 2] }, { maxRequests: 1, replayQuantities: ["1"] }]) {
    await assert.rejects(runSchemathesisFixture({ ...o, ...bad } as SchemathesisOptions));
  }
  assert.equal(calls, 0);
});
test("worker cannot mutate the replay scope or store credentials through the job", async () => {
  const r = await runSchemathesisFixture(options({ async execute(job) {
    job.operations[0] = "writeAdmin" as "readItems";
    (job as unknown as Record<string, unknown>).secret = "synthetic-secret-canary";
    return { exitCode: 0, stdout: JSON.stringify(valid) };
  } }));
  assert.deepEqual(r.artifact.replay.job.operations, ["readItems"]);
});
test("atomic local storage: retries and concurrent same-key puts publish one complete artifact", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-atomic-"));
  try {
    const store = localArtifactStorage(directory), id = randomUUID();
    const bytes = Buffer.from(JSON.stringify({ records: "x".repeat(65536) }));
    const paths = await Promise.all(Array.from({ length: 8 }, () => store.put(id, bytes)));
    assert.equal(new Set(paths).size, 1);
    assert.deepEqual(await readFile(paths[0]), bytes);
    await assert.rejects(store.put(id, Buffer.from("{}")), /artifact_conflict/);
    assert.deepEqual(await readdir(directory), [`${id}.json`]);
    assert.equal((await stat(paths[0])).mode & 0o777, 0o600);
    const next = await store.put(randomUUID(), bytes);
    assert.notEqual(next, paths[0]);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test("atomic publication failure cleans temporary files and preserves existing destination", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-write-fail-"));
  try {
    const id = randomUUID();
    await mkdir(join(directory, `${id}.json`));
    await assert.rejects(localArtifactStorage(directory).put(id, Buffer.from("{}")));
    assert.deepEqual(await readdir(directory), [`${id}.json`]);
    assert.equal((await stat(join(directory, `${id}.json`))).isDirectory(), true);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test("same-run-ID executions deduplicate identical delivery; changed results conflict and failed store permits retry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-retry-"));
  try {
    const store = localArtifactStorage(directory), runId = randomUUID();
    let executions = 0;
    const worker: CodeWorker = { async execute() {
      executions++;
      return { exitCode: 0, stdout: JSON.stringify(valid) };
    } };
    const o = { ...options(worker), storage: store, runId };
    const results = await Promise.all([runSchemathesisFixture(o), runSchemathesisFixture(o)]);
    assert.equal(executions, 2, "same run ID does not turn API calls into delivery-only retries");
    assert.equal(results[0].artifactRef, results[1].artifactRef);
    assert.equal(results[0].sha256, results[1].sha256);
    assert.equal(createHash("sha256").update(await readFile(results[0].artifactRef)).digest("hex"), results[0].sha256);
    await store.put(runId, await readFile(results[0].artifactRef));
    assert.equal(executions, 2, "resending retained bytes through storage does not execute a worker");
    await assert.rejects(runSchemathesisFixture({ ...o, worker: mock({ ...valid, bytesInspected: 11 }) }), /artifact_conflict/);
    const retryId = randomUUID(); let failed = false;
    const flaky = { async put(id: string, bytes: Uint8Array) {
      if (!failed) { failed = true; throw Error("storage unavailable"); }
      return store.put(id, bytes);
    } };
    await assert.rejects(runSchemathesisFixture({ ...o, runId: retryId, storage: flaky }));
    assert.equal((await runSchemathesisFixture({ ...o, runId: retryId, storage: flaky })).artifact.status, "completed");
    assert.equal((await readdir(directory)).length, 2);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

const supervisorScript = fileURLToPath(new URL("../../tests/fixtures/schemathesis-process.py", import.meta.url));
const job: FixtureJob = { version: 1, environment: "staging", fixture: "fixed", operations: ["readItems"],
  maxRequests: 1, maxBodyBytes: 1024, maxTotalBytes: 1024, timeoutMs: 30000, seed: 1, replayQuantities: null };
async function waitForPids(path: string) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try { return JSON.parse(await readFile(path, "utf8")) as { parent: number; child: number }; }
    catch { await delay(20); }
  }
  throw Error("process fixture did not start");
}
async function assertTerminated(pids: { parent: number; child: number }) {
  for (const pid of Object.values(pids)) {
    let alive = true;
    for (let i = 0; i < 100; i++) {
      try { process.kill(pid, 0); } catch { alive = false; break; }
      await delay(20);
    }
    if (alive && process.platform === "linux") {
      // A container PID 1 may defer orphan reaping. A zombie cannot run or keep pipes open.
      const result = await promisify(execFile)("ps", ["-p", String(pid), "-o", "stat="]);
      alive = !result.stdout.trim().startsWith("Z");
    }
    assert.equal(alive, false, `process ${pid} must be terminated`);
  }
}
test("supervisor abort, timeout, output overflow and normal exit terminate owned process groups", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-pgroup-"));
  try {
    for (const mode of ["cancel", "timeout", "overflow", "exit"]) {
      const pidPath = join(directory, `${mode}.json`);
      const control = createApiRunControl(mode === "timeout" ? 1500 : 10000);
      const caller = new AbortController();
      const promise = localCodeWorker(python!, ["-I", supervisorScript, mode, pidPath])
        .execute(job, mode === "cancel" ? caller.signal : control.signal);
      try {
        const pids = await waitForPids(pidPath);
        if (mode === "cancel") caller.abort();
        const result = await promise;
        if (mode === "exit") assert.equal(result.exitCode, 0);
        else assert.equal(result.exitCode, -1);
        if (mode === "overflow") assert.equal(result.stdout, "");
        await assertTerminated(pids);
      } finally { caller.abort(); control.dispose(); }
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test("supervisor handles missing executable and strips inherited credentials", async () => {
  const c = new AbortController();
  await assert.rejects(localCodeWorker("/no/such/python", []).execute(job, c.signal), /worker_unavailable/);
  const previous = process.env.WAKEIO_TEST_SECRET;
  process.env.WAKEIO_TEST_SECRET = "synthetic-secret-canary";
  try {
    const result = await localCodeWorker(python!, ["-I", supervisorScript, "echo", "unused"]).execute(job, c.signal);
    assert.equal(JSON.parse(result.stdout).secretInherited, false);
  } finally {
    if (previous === undefined) delete process.env.WAKEIO_TEST_SECRET;
    else process.env.WAKEIO_TEST_SECRET = previous;
  }
});
test("Python rejects unsafe raw jobs and directly emits only redacted metadata", async () => {
  const worker = pythonFixtureWorker(python), signal = new AbortController().signal;
  for (const bad of [{ operations: ["writeAdmin"] }, { environment: "production" },
    { url: "https://example.com" }, { maxRequests: 65 }, { maxRequests: true }, { version: true },
    { replayQuantities: [21] }]) {
    const output = await worker.execute({ ...job, ...bad } as FixtureJob, signal);
    assert.deepEqual(JSON.parse(output.stdout), { version: 1, status: "error", reason: "worker_error" });
  }
  const output = await worker.execute(job, signal);
  assert.equal(JSON.parse(output.stdout).status, "completed");
  assert.ok(!output.stdout.includes("synthetic-secret-canary"));
  const tooLarge = await worker.execute({ ...job, padding: "x".repeat(16385) } as FixtureJob, signal);
  assert.equal(JSON.parse(tooLarge.stdout).status, "error");
});
