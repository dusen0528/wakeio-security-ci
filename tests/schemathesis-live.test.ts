import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseCliArgs, CliUsageError } from "../src/cli.js";
import { projectLiveResult, runSchemathesisLive, type SchemathesisLiveOptions } from "../src/schemathesis-live.js";

const root = process.cwd();
const python = process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(root, ".venv-schemathesis/bin/python");
const document = JSON.parse(await readFile(join(root, "tests/fixtures/openapi-live.json"), "utf8"));
const operations: SchemathesisLiveOptions["operations"] = [{ method: "GET", path: "/items/{id}" }, { method: "GET", path: "/search" }];

async function fixture(variant: "risk" | "normal"): Promise<{ origin: string; requests: () => Promise<Array<{ method: string; path: string; encoding: string | null }>>; stop: () => Promise<void> }> {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-live-"));
  const log = join(directory, "requests.jsonl");
  const child: ChildProcess = spawn(process.execPath, [join(root, "tests/fixtures/openapi-live-target.mjs"), variant],
    { env: { PATH: process.env.PATH ?? "", WAKEIO_FIXTURE_LOG: log }, stdio: ["ignore", "pipe", "ignore"] });
  const port = await new Promise<string>((resolve) => child.stdout!.once("data", (chunk) => resolve(String(chunk).trim())));
  return {
    origin: `http://127.0.0.1:${port}/`,
    requests: async () => (await readFile(log, "utf8").catch(() => "")).split("\n").filter(Boolean).map((line) => JSON.parse(line)),
    stop: async () => { child.kill(); await new Promise((resolve) => child.once("close", resolve)); await rm(directory, { recursive: true, force: true }); },
  };
}

function live(origin: string, extra: Partial<SchemathesisLiveOptions> = {}): Promise<import("../src/contracts.js").CheckResult[]> {
  return runSchemathesisLive({ document, baseUrl: origin, operations, consent: true, allowPrivate: true, python, maxRequests: 32, seed: 7, ...extra });
}

test("schemathesis live: risk/normal pair through the egress gate", async () => {
  for (const variant of ["risk", "normal"] as const) {
    const target = await fixture(variant);
    try {
      const [check] = await live(target.origin);
      const seen = await target.requests();
      assert.equal(check!.status, "completed", `${variant}: ${check!.notes.join(" | ")}`);
      assert.equal(check!.metrics?.requestCount, 32);
      assert.equal(check!.metrics?.gateForwarded, 32);
      assert.equal(check!.metrics?.skippedByBudget, 0);
      assert.equal(check!.metrics?.["requests:GET /items/{id}"], 16);
      assert.equal(check!.metrics?.["requests:GET /search"], 16);
      assert.equal(seen.length, 32, "every request crossed the gate exactly once");
      assert.ok(seen.every((item) => item.method === "GET" && item.encoding === "identity"));
      assert.ok(seen.every((item) => item.path === "/search" || /^\/items\/\d+$/.test(item.path)));
      const rules = check!.findings.map((finding) => `${finding.ruleId}:${finding.location.url}`).sort();
      if (variant === "risk") {
        assert.deepEqual(rules, [`api.schemathesis.response_schema:${target.origin}items/{id}`, `api.schemathesis.server_error:${target.origin}search`]);
      } else {
        assert.deepEqual(rules, []);
      }
      const serialized = JSON.stringify(check);
      assert.ok(!serialized.includes("wakeio:") && !serialized.includes(root) && !serialized.includes("unhandled"), "no proxy credential, absolute path or response body");
    } finally { await target.stop(); }
  }
});

test("schemathesis live: budget split, seed reproducibility and coverage counts", async () => {
  const target = await fixture("risk");
  try {
    const [first] = await live(target.origin, { maxRequests: 6, seed: 11 });
    const [second] = await live(target.origin, { maxRequests: 6, seed: 11 });
    assert.equal(first!.status, "completed");
    assert.equal(first!.metrics?.requestCount, 6);
    assert.equal(first!.metrics?.["requests:GET /items/{id}"], 3);
    assert.equal(first!.metrics?.["requests:GET /search"], 3);
    assert.deepEqual(first!.findings.map((item) => item.description), second!.findings.map((item) => item.description));
    assert.equal((await target.requests()).length, 12);
  } finally { await target.stop(); }
});

test("schemathesis live: rejected inputs make no requests", async () => {
  const target = await fixture("normal");
  try {
    const cases: Array<[Partial<SchemathesisLiveOptions>, string]> = [
      [{ consent: false }, "consent_required"],
      [{ operations: [{ method: "GET", path: "/admin/reset" }] }, "unsupported_openapi"],
      [{ operations: [{ method: "GET", path: "/missing" }] }, "invalid_openapi_policy"],
      [{ document: { ...document, paths: { "/x": { get: { responses: { "200": { $ref: "https://example.invalid/r.json" } } } } } }, operations: [{ method: "GET", path: "/x" }] }, "unsupported_openapi"],
      [{ baseUrl: "http://169.254.169.254/" }, "blocked_address"],
      [{ allowPrivate: false }, "blocked_address"],
      [{ baseUrl: `${target.origin}api/` }, "dast_origin_required"],
      [{ maxRequests: 65 }, "invalid_budget"],
    ];
    for (const [overrides, code] of cases) {
      const [check] = await live(target.origin, overrides);
      assert.equal(check!.status, "error", code);
      assert.equal(check!.metrics?.errorCode, code);
    }
    const controller = new AbortController();
    controller.abort();
    const [cancelled] = await live(target.origin, { signal: controller.signal });
    assert.notEqual(cancelled!.status, "completed");
    assert.equal((await target.requests()).length, 0);
  } finally { await target.stop(); }
});

test("schemathesis live: a target that fails mid-run is partial, never clean", async () => {
  let count = 0;
  const server = createServer((req, res) => {
    count += 1;
    if (count > 3) { req.socket.destroy(); return; }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: 1, name: "ok", results: [] }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  try {
    const [check] = await live(`http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}/`, { maxRequests: 20 });
    assert.equal(check!.status, "partial");
    assert.match(String(check!.metrics?.stopReason), /transport_error|upstream_error/);
    assert.ok(Number(check!.metrics?.upstreamErrors) >= 1);
  } finally { server.close(); }
});

test("schemathesis live projection rejects unknown shapes, labels and failure kinds", () => {
  const labels = new Set(["GET /a"]);
  const digest = "a".repeat(64);
  const base = { version: 2, status: "completed", reason: "complete", requestCount: 1, bytesInspected: 2, transportErrors: 0,
    operations: [{ operation: "GET /a", requests: 1 }], workerSha256: digest, engineVersion: "4.2.0",
    runtime: { python: "3.12.3", hypothesis: "6.168.3", jsonschema: "4.26.0", requests: "2.34.2" },
    records: [{ operation: "GET /a", ordinal: 1, status: 200, check: "response_contract", inputFingerprint: digest,
      failures: [{ rule: "response_schema_conformance", kind: "schema_violation", keyword: "type" }] }] };
  assert.equal(projectLiveResult(JSON.stringify(base), labels, 4).records[0]!.failures[0]!.keyword, "type");
  const bad = (patch: (value: typeof base) => unknown) => assert.throws(() => projectLiveResult(JSON.stringify(patch(structuredClone(base))), labels, 4));
  bad((value) => ({ ...value, records: [{ ...value.records[0], operation: "GET /other" }] }));
  bad((value) => ({ ...value, records: [{ ...value.records[0], failures: [{ rule: "response_schema_conformance", kind: "schema_violation", keyword: "secret-value" }] }] }));
  bad((value) => ({ ...value, records: [{ ...value.records[0], status: 500 }] }));
  bad((value) => ({ ...value, requestCount: 5 }));
  bad((value) => ({ ...value, extraMessage: undefined, records: [{ ...value.records[0], check: "passed" }] }));
});

test("active DAST CLI requires explicit consent before any request", () => {
  const openapi = ["scan", "--openapi", "spec.json", "--api-base", "https://api.example.test/", "--operation", "/items/{id}"];
  assert.throws(() => parseCliArgs(openapi), (error: Error) => error instanceof CliUsageError && /--active-consent/.test(error.message));
  assert.throws(() => parseCliArgs(["scan", "--url", "https://example.test/", "--engine", "nuclei", "--nuclei-templates", "t"]), /--active-consent/);
  assert.throws(() => parseCliArgs(["scan", "--url", "https://example.test/", "--active-consent"]), /requires --openapi or --engine/);
  assert.throws(() => parseCliArgs(["scan", "--openapi", "spec.json", "--active-consent"]), /--api-base and at least one --operation/);
  assert.throws(() => parseCliArgs(["scan", "--url", "https://example.test/", "--engine", "nuclei", "--active-consent"]), /--nuclei-templates/);
  assert.throws(() => parseCliArgs(["scan", "--source", ".", "--seed", "3"]), /require --openapi/);
  assert.throws(() => parseCliArgs([...openapi, "--active-consent", "--api-max-requests", "65"]), /between 1 and 64/);
  const parsed = parseCliArgs([...openapi, "--active-consent"]);
  assert.ok(!("help" in parsed));
  if (!("help" in parsed)) {
    assert.equal(parsed.activeConsent, true);
    assert.deepEqual(parsed.operations, ["/items/{id}"]);
  }
  const nuclei = parseCliArgs(["scan", "--url", "https://example.test/", "--engine", "nuclei", "--nuclei-templates", "t", "--active-consent"]);
  if (!("help" in nuclei)) assert.deepEqual(nuclei.nucleiScopes, ["misconfiguration"]);
});
