import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyTemplate, parseNucleiOutput, runNuclei, selectNucleiTemplates, type NucleiOptions } from "../src/nuclei.js";

const root = process.cwd();
const SIGNED = "\n# digest: 4a0a00473045022100aaf216ebf8c81edf0fccca9a99f59a60686b67c7ccb1a1cff8ac40197d65981e33:922c64590222798bb761d5b6d8e72950\n";
const template = (body: string, signed = true) => `id: t\ninfo:\n  name: t\n  severity: info\n${body}${signed ? SIGNED : "\n"}`;

test("nuclei static template selection excludes unsafe, non-GET, unsigned and non-HTTP templates", () => {
  assert.equal(classifyTemplate(template("http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n")), "selected");
  assert.equal(classifyTemplate(template("http:\n  - method: HEAD\n    path:\n      - \"{{BaseURL}}\"\n")), "selected");
  assert.equal(classifyTemplate(template("http:\n  - method: GET\n", false)), "unsigned");
  assert.equal(classifyTemplate(template("http:\n  - raw:\n      - |\n        GET / HTTP/1.1\n")), "rawOrUnsafe");
  assert.equal(classifyTemplate(template("http:\n  - method: GET\n    unsafe: true\n")), "rawOrUnsafe");
  assert.equal(classifyTemplate(template("http:\n  - method: GET\n  - method: post\n")), "method");
  assert.equal(classifyTemplate(template("javascript:\n  - code: x\n")), "protocol");
  assert.equal(classifyTemplate(template("http:\n  - method: GET\nflow: http(1)\n")), "protocol");
  assert.equal(classifyTemplate(template("self-contained: true\nhttp:\n  - method: GET\n")), "selfContained");
});

test("nuclei output projection keeps only origin-bound metadata and parses progress", () => {
  const origin = "http://127.0.0.1:8080";
  const lines = [
    JSON.stringify({ "template-id": "git-config", info: { name: "Git\u0007 Config", severity: "medium", reference: ["https://example.test/r", "javascript:alert(1)"] },
      "matched-at": `${origin}/.git/config?token=s3cr3t`, "extracted-results": ["s3cr3t-extracted"], request: "GET /", response: "raw-body" }),
    JSON.stringify({ "template-id": "git-config", info: { severity: "medium" }, "matched-at": `${origin}/.git/config?token=s3cr3t` }),
    JSON.stringify({ "template-id": "x", info: { severity: "high" }, "matched-at": "http://127.0.0.1:4040/jobs/" }),
    JSON.stringify({ "template-id": "../evil", info: { severity: "high" }, "matched-at": `${origin}/` }),
    "{not json",
  ];
  const stats = JSON.stringify({ duration: "0:00:03", errors: "2", matched: "1", percent: "10", requests: "12", templates: "5", total: "120" });
  const parsed = parseNucleiOutput(lines.join("\n"), stats, origin);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.droppedOutOfOrigin, 1);
  assert.equal(parsed.malformed, 2);
  assert.deepEqual(parsed.stats, { percent: 10, requests: 12, total: 120, errors: 2, templates: 5, matched: 1 });
  const finding = parsed.findings[0]!;
  assert.equal(finding.ruleId, "nuclei.git-config");
  assert.equal(finding.severity, "medium");
  assert.equal(finding.title, "Git  Config");
  assert.equal(finding.location.url, `${origin}/.git/config?[REDACTED]`);
  assert.deepEqual(finding.references, ["https://example.test/r"]);
  const serialized = JSON.stringify(parsed);
  for (const secret of ["s3cr3t", "raw-body", "GET /"]) assert.ok(!serialized.includes(secret), secret);
});

async function fakeEngine(directory: string, behaviour: { version?: string; percent?: number; errors?: number; exitCode?: number }): Promise<string> {
  const path = join(directory, `fake-nuclei-${Math.random().toString(16).slice(2)}`);
  await writeFile(path, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args.includes("-version")) { process.stderr.write("[INF] Nuclei Engine Version: v${behaviour.version ?? "3.11.1"}\\n"); process.exit(0); }
const target = args[args.indexOf("-u") + 1];
process.stdout.write(JSON.stringify({ "template-id": "fake-template", info: { name: "Fake", severity: "low" }, "matched-at": target }) + "\\n");
process.stderr.write(JSON.stringify({ percent: "${behaviour.percent ?? 100}", requests: "3", total: "30", errors: "${behaviour.errors ?? 0}", templates: "1", matched: "1" }) + "\\n");
process.exit(${behaviour.exitCode ?? 0});
`);
  await chmod(path, 0o755);
  return path;
}

async function templatesDir(directory: string): Promise<string> {
  const templates = join(directory, "templates");
  await mkdir(join(templates, "http", "misconfiguration"), { recursive: true });
  await mkdir(join(templates, "http", "exposures"), { recursive: true });
  await writeFile(join(templates, "http", "misconfiguration", "ok.yaml"), template("http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n"));
  await writeFile(join(templates, "http", "misconfiguration", "raw.yaml"), template("http:\n  - raw:\n      - |\n        GET / HTTP/1.1\n"));
  await writeFile(join(templates, "templates-checksum.txt"), "http/misconfiguration/ok.yaml:abc\n");
  await writeFile(join(templates, ".templates-config.json"), JSON.stringify({ "nuclei-templates-version": "v10.5.0" }));
  return templates;
}

async function localServer(): Promise<{ server: Server; origin: string }> {
  const server = createServer((_req, res) => { res.writeHead(200); res.end("ok"); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return { server, origin: `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}/` };
}

test("nuclei adapter never reports completion from exit 0 alone and reports engine/input errors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-nuclei-test-"));
  const { server, origin } = await localServer();
  try {
    const templates = await templatesDir(directory);
    const selection = await selectNucleiTemplates(templates, ["misconfiguration"]);
    assert.equal(selection.selected.length, 1);
    assert.equal(selection.excluded.rawOrUnsafe, 1);
    const base: NucleiOptions = { url: origin, templatesDir: templates, scopes: ["misconfiguration"], consent: true, allowPrivate: true, timeoutMs: 20_000 };
    const run = async (behaviour: Parameters<typeof fakeEngine>[1], extra: Partial<NucleiOptions> = {}) =>
      (await runNuclei({ ...base, executable: await fakeEngine(directory, behaviour), ...extra }))[0]!;

    const complete = await run({});
    assert.equal(complete.status, "completed", complete.notes.join(" | "));
    assert.equal(complete.findings[0]?.ruleId, "nuclei.fake-template");
    assert.equal(complete.metrics?.templatesVersion, "v10.5.0");
    assert.equal(complete.metrics?.templatesSelected, 1);
    assert.equal(complete.metrics?.templatesExcludedRawOrUnsafe, 1);

    const tenPercent = await run({ percent: 10 });
    assert.equal(tenPercent.status, "partial");
    assert.equal(tenPercent.metrics?.stopReason, "engine_incomplete");
    assert.equal((await run({ errors: 3 })).metrics?.stopReason, "engine_errors");
    assert.equal((await run({ exitCode: 1 })).metrics?.stopReason, "engine_exit");

    const cases: Array<[Promise<import("../src/contracts.js").CheckResult[]>, string]> = [
      [runNuclei({ ...base, executable: join(directory, "missing-nuclei") }), "engine_missing"],
      [runNuclei({ ...base, executable: await fakeEngine(directory, { version: "3.10.0" }) }), "unsupported_engine_version"],
      [runNuclei({ ...base, executable: await fakeEngine(directory, {}), templatesDir: join(directory, "nope") }), "templates_missing"],
      [runNuclei({ ...base, executable: await fakeEngine(directory, {}), scopes: ["exposures"] }), "no_templates"],
      [runNuclei({ ...base, executable: await fakeEngine(directory, {}), consent: false }), "consent_required"],
      [runNuclei({ ...base, executable: await fakeEngine(directory, {}), allowPrivate: false }), "blocked_address"],
      [runNuclei({ ...base, executable: await fakeEngine(directory, {}), url: "http://169.254.169.254/" }), "blocked_address"],
      [runNuclei({ ...base, executable: await fakeEngine(directory, {}), rateLimit: 151 }), "invalid_budget"],
    ];
    for (const [promise, code] of cases) {
      const [check] = await promise;
      assert.equal(check!.status, "error", code);
      assert.equal(check!.metrics?.errorCode, code);
    }
  } finally {
    server.close();
    await rm(directory, { recursive: true, force: true });
  }
});

const realEngine = process.env.WAKEIO_NUCLEI;
const realTemplates = process.env.WAKEIO_NUCLEI_TEMPLATES;
const requireReal = process.env.WAKEIO_REQUIRE_NUCLEI === "1";
const realSkip = realEngine && realTemplates ? false
  : requireReal ? false : "set WAKEIO_NUCLEI and WAKEIO_NUCLEI_TEMPLATES (npm run test:nuclei requires them)";

async function nucleiFixture(variant: "risk" | "normal"): Promise<{ origin: string; received: () => Promise<number>; stop: () => Promise<void> }> {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-nuclei-fixture-"));
  const log = join(directory, "requests.jsonl");
  const child: ChildProcess = spawn(process.execPath, [join(root, "tests/fixtures/nuclei-target.mjs"), variant],
    { env: { PATH: process.env.PATH ?? "", WAKEIO_FIXTURE_LOG: log }, stdio: ["ignore", "pipe", "ignore"] });
  const port = await new Promise<string>((resolve) => child.stdout!.once("data", (chunk) => resolve(String(chunk).trim())));
  return {
    origin: `http://127.0.0.1:${port}/`,
    received: async () => (await readFile(log, "utf8").catch(() => "")).split("\n").filter(Boolean).length,
    stop: async () => { child.kill(); await new Promise((resolve) => child.once("close", resolve)); await rm(directory, { recursive: true, force: true }); },
  };
}

test("real nuclei: risk/normal pair, wire coverage and egress refusal counts", { skip: realSkip }, async () => {
  assert.ok(realEngine && realTemplates, "WAKEIO_NUCLEI and WAKEIO_NUCLEI_TEMPLATES are required");
  const results: Record<string, { ids: string[]; requests: number }> = {};
  for (const variant of ["risk", "normal"] as const) {
    const target = await nucleiFixture(variant);
    try {
      const [check] = await runNuclei({ url: target.origin, executable: realEngine, templatesDir: realTemplates, scopes: ["misconfiguration", "exposures"],
        consent: true, allowPrivate: true, rateLimit: 150, timeoutMs: 300_000 });
      assert.equal(check!.status, "completed", check!.notes.join(" | "));
      assert.equal(check!.metrics?.enginePercent, 100);
      assert.equal(check!.metrics?.engineErrors, 0);
      assert.equal(await target.received(), check!.metrics?.requestCount, "every request reached the fixture through the gate");
      assert.ok(Number(check!.metrics?.blockedOrigin) >= 1, "templates probing other ports are refused, not sent");
      assert.equal(check!.metrics?.blockedMethod, 0);
      results[variant] = { ids: check!.findings.map((finding) => finding.ruleId).sort(), requests: Number(check!.metrics?.requestCount) };
    } finally { await target.stop(); }
  }
  assert.ok(results.risk!.ids.includes("nuclei.git-config"));
  assert.ok(results.risk!.ids.includes("nuclei.http-missing-security-headers.content-security-policy"));
  assert.equal(new Set(results.risk!.ids).size, results.risk!.ids.length, "each matcher is a distinct rule identity");
  assert.deepEqual(results.normal!.ids, []);
  assert.equal(results.risk!.requests, results.normal!.requests, "same template plan against both fixtures");
});

test("real nuclei: request budget and a failing target are partial even though nuclei exits 0", { skip: realSkip }, async () => {
  assert.ok(realEngine && realTemplates);
  const target = await nucleiFixture("normal");
  try {
    const [limited] = await runNuclei({ url: target.origin, executable: realEngine, templatesDir: realTemplates, scopes: ["misconfiguration"],
      consent: true, allowPrivate: true, rateLimit: 150, maxRequests: 40, timeoutMs: 120_000 });
    assert.equal(limited!.status, "partial");
    assert.equal(limited!.metrics?.stopReason, "request_limit");
    assert.equal(limited!.metrics?.requestCount, 40);
    assert.ok(Number(limited!.metrics?.skippedByBudget) > 0, "budget refusals are reported separately from executed requests");
    // In-flight requests may still be landing when the gate closes; the bound is what matters.
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const received = await target.received();
    assert.ok(received >= 1 && received <= 40, `target received ${received} requests for a budget of 40`);
  } finally { await target.stop(); }
  let count = 0;
  const server = createServer((req, res) => {
    count += 1;
    if (count > 50) { req.socket.destroy(); return; }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  try {
    const [failing] = await runNuclei({ url: `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}/`, executable: realEngine,
      templatesDir: realTemplates, scopes: ["misconfiguration"], consent: true, allowPrivate: true, rateLimit: 150, timeoutMs: 120_000 });
    assert.equal(failing!.status, "partial", failing!.notes.join(" | "));
    assert.ok(Number(failing!.metrics?.upstreamErrors) > 0);
  } finally { server.close(); }
});

test("doctor --dast reports active engine readiness without running engines", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const exec = promisify(execFile);
  const directory = await mkdtemp(join(tmpdir(), "wakeio-doctor-dast-"));
  try {
    const templates = await templatesDir(directory);
    const engine = await fakeEngine(directory, {});
    const cli = join(root, "build/src/cli.js");
    const ready = await exec(process.execPath, [cli, "doctor", "--source", directory, "--tools", "none", "--json", "--dast", "--nuclei", engine, "--nuclei-templates", templates]);
    const dast = JSON.parse(ready.stdout).activeDast;
    assert.equal(dast.nuclei.availability, "available");
    assert.equal(dast.nucleiTemplates.availability, "available");
    assert.deepEqual(dast.nucleiTemplates.scopes, ["misconfiguration", "exposures"]);
    await assert.rejects(exec(process.execPath, [cli, "doctor", "--source", directory, "--tools", "none", "--strict", "--dast", "--nuclei", join(directory, "missing"), "--nuclei-templates", templates]),
      (error: { code?: number }) => error.code === 2);
    await assert.rejects(exec(process.execPath, [cli, "doctor", "--tools", "none", "--nuclei", engine]), (error: { code?: number }) => error.code === 2);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
