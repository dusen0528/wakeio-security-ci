import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer, type Server } from "node:http";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ScanReport } from "../src/contracts.js";
import { main } from "../src/cli.js";

const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const marker = "synthetic_cancelled_secret_721084";
const reportFiles = ["report.json", "report.sarif", "report.md", "agent-report.json"];

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function launch(args: string[], env: NodeJS.ProcessEnv = process.env) {
  const child = spawn(process.execPath, [cli, "scan", ...args, "--timeout-ms", "60000", "--fail-on", "none"], { env });
  const done = new Promise<{ code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("cancelled CLI did not terminate within 10 seconds")); }, 10_000);
    child.stdout.on("data", (value: Buffer) => { stdout += value.toString(); });
    child.stderr.on("data", (value: Buffer) => { stderr += value.toString(); });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
  return { child, done };
}

async function cancelledReport(run: ReturnType<typeof launch>, out: string): Promise<ScanReport> {
  const result = await run.done;
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stdout, /INCOMPLETE:/);
  assert.doesNotMatch(result.stdout, /COMPLETED:/);
  assert.equal((result.stdout + result.stderr).includes(marker), false);
  for (const name of reportFiles) {
    const text = await readFile(join(out, name), "utf8");
    assert.ok(text.length > 0);
    assert.equal(text.includes(marker), false);
    if (name !== "report.md") assert.doesNotThrow(() => JSON.parse(text));
  }
  const report = JSON.parse(await readFile(join(out, "report.json"), "utf8")) as ScanReport;
  assert.equal(report.checks.find((check) => check.id === "scan.cancelled")?.status, "partial");
  return report;
}

function policy(baseUrl: string) {
  return {
    version: 2, baseUrl,
    actors: [
      { id: "owner", authorizationEnv: "WAKEIO_CANCELLATION_AUTH", identity: { path: "/whoami", status: 200, jsonPointer: "/userId", equals: "owner-user" } },
      { id: "anonymous" },
    ],
    cases: ["first", "stalled"].map((id) => ({
      id, path: `/${id}`,
      allow: { actor: "owner", status: 200, resource: { jsonPointer: "/id", equals: id }, protected: { jsonPointer: "/canary", equals: "synthetic-protected-canary" } },
      deny: [{ actor: "anonymous", statuses: [401] }],
    })),
  };
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  test(`spawned URL CLI handles ${signal}, keeps root findings and writes all reports`, { skip: process.platform === "win32" }, async () => {
    const root = await mkdtemp(join(tmpdir(), "wakeio-url-cancel-"));
    const out = join(root, "reports");
    let child: ChildProcessWithoutNullStreams | undefined;
    const requested: string[] = [];
    const server = createServer((request, response) => {
      requested.push(request.url ?? "");
      if (request.url === "/stalled.js") { assert.ok(child?.kill(signal)); return; }
      response.setHeader("content-type", "text/html");
      response.end(`<script>const apiKey = '${marker}';</script><script src='/stalled.js'></script><script src='/later.js'></script>`);
    });
    const base = await listen(server);
    try {
      const run = launch(["--url", base, "--page", "/later-page", "--allow-private", "--out", out]);
      child = run.child;
      const report = await cancelledReport(run, out);
      const urlCheck = report.checks.find((check) => check.id === "url.scan");
      assert.equal(urlCheck?.status, "partial");
      assert.ok(urlCheck?.findings.some((finding) => finding.ruleId === "url.secret-assignment"));
      assert.ok(urlCheck?.notes.some((note) => /was cancelled/.test(note)));
      assert.deepEqual(requested, ["/", "/stalled.js"]);
    } finally { child?.kill("SIGKILL"); await close(server); await rm(root, { recursive: true, force: true }); }
  });

  test(`spawned source CLI handles ${signal} without native preview and retains built-in findings`, { skip: process.platform === "win32" }, async () => {
    const root = await mkdtemp(join(tmpdir(), "wakeio-source-cancel-"));
    const source = join(root, "source");
    const out = join(root, "reports");
    const scanner = join(root, "synthetic-gitleaks");
    let child: ChildProcessWithoutNullStreams | undefined;
    try {
      await mkdir(source);
      await writeFile(join(source, "app.ts"), "export function run(input: string) { return eval(input); }\n");
      // This synthetic scanner only tells the owned CLI process to cancel;
      // it neither scans nor contacts any external service.
      await writeFile(scanner, `#!${process.execPath}\nprocess.kill(process.ppid, ${JSON.stringify(signal)}); setInterval(() => {}, 1000);\n`);
      await chmod(scanner, 0o700);
      const run = launch(["--source", source, "--tools", "gitleaks", "--gitleaks", scanner, "--out", out]);
      child = run.child;
      const report = await cancelledReport(run, out);
      assert.ok(report.checks.find((check) => check.id === "source.builtin-ast")?.findings.length);
      assert.equal(report.checks.find((check) => check.id === "source.cancelled")?.status, "partial");
    } finally { child?.kill("SIGKILL"); await rm(root, { recursive: true, force: true }); }
  });

  test(`spawned API CLI handles ${signal}, retains earlier observations and writes all reports`, { skip: process.platform === "win32" }, async () => {
    const root = await mkdtemp(join(tmpdir(), "wakeio-api-cancel-"));
    const out = join(root, "reports");
    let child: ChildProcessWithoutNullStreams | undefined;
    const requested: string[] = [];
    const server = createServer((request, response) => {
      requested.push(request.url ?? "");
      if (request.url === "/stalled") { assert.ok(child?.kill(signal)); return; }
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(request.url === "/whoami" ? { userId: "owner-user" } : { id: "first", canary: "synthetic-protected-canary" }));
    });
    const base = await listen(server);
    try {
      const policyFile = join(root, "policy.json");
      await writeFile(policyFile, JSON.stringify(policy(base)));
      const run = launch(["--api-policy", policyFile, "--allow-private", "--out", out], { ...process.env, WAKEIO_CANCELLATION_AUTH: "Bearer synthetic-owned-fixture" });
      child = run.child;
      const report = await cancelledReport(run, out);
      const apiCheck = report.checks.find((check) => check.id === "api.authorization");
      assert.equal(apiCheck?.status, "partial");
      assert.ok(apiCheck?.findings.length);
      assert.ok(apiCheck?.notes.some((note) => /was cancelled/.test(note)));
      assert.equal(JSON.stringify(report).includes("Bearer synthetic-owned-fixture"), false);
      assert.equal(requested.at(-1), "/stalled");
    } finally { child?.kill("SIGKILL"); await close(server); await rm(root, { recursive: true, force: true }); }
  });
}

test("combined CLI cancellation retains completed source and root findings and never starts the API stage", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-combined-cancel-"));
  const source = join(root, "source");
  const out = join(root, "reports");
  let child: ChildProcessWithoutNullStreams | undefined;
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    if (request.url === "/stalled.js") { assert.ok(child?.kill("SIGTERM")); return; }
    response.setHeader("content-type", "text/html");
    response.end(`<script>const apiKey = '${marker}';</script><script src='/stalled.js'></script>`);
  });
  const base = await listen(server);
  try {
    await mkdir(source);
    await writeFile(join(source, "app.ts"), "export function run(input: string) { return eval(input); }\n");
    const policyFile = join(root, "policy.json");
    await writeFile(policyFile, JSON.stringify(policy(base)));
    const run = launch(["--source", source, "--tools", "none", "--url", base, "--api-policy", policyFile, "--allow-private", "--out", out], { ...process.env, WAKEIO_CANCELLATION_AUTH: "Bearer synthetic-owned-fixture" });
    child = run.child;
    const report = await cancelledReport(run, out);
    assert.equal(report.mode, "combined");
    assert.ok(report.checks.find((check) => check.id === "source.builtin-ast")?.findings.length);
    assert.ok(report.checks.find((check) => check.id === "url.scan")?.findings.some((finding) => finding.ruleId === "url.secret-assignment"));
    assert.equal(report.checks.some((check) => check.id.startsWith("api.")), false);
    assert.deepEqual(requested, ["/", "/stalled.js"]);
  } finally { child?.kill("SIGKILL"); await close(server); await rm(root, { recursive: true, force: true }); }
});

test("CLI releases universal scan signal handlers after success and collection error", async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-cli-handlers-"));
  const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
  const server = createServer((_request, response) => { response.setHeader("content-type", "text/html"); response.end("<p>okay</p>"); });
  const base = await listen(server);
  try {
    assert.equal(await main(["scan", "--url", base, "--allow-private", "--fail-on", "none", "--out", join(root, "success")]), 0);
    assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], before);
    assert.equal(await main(["scan", "--url", base, "--out", join(root, "failed")]), 2);
    assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], before);
  } finally { await close(server); await rm(root, { recursive: true, force: true }); }
});
