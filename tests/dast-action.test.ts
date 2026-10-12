import test from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = process.cwd();
const python = process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(root, ".venv-schemathesis/bin/python");

async function launch(entry: string, env: NodeJS.ProcessEnv, cwd: string) {
  try {
    const result = await exec(process.execPath, [entry], { env, cwd, maxBuffer: 8 * 1024 * 1024 });
    return { code: 0, stdout: String(result.stdout), stderr: String(result.stderr) };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    if (typeof failure.code !== "number") throw error;
    return { code: failure.code, stdout: String(failure.stdout ?? ""), stderr: String(failure.stderr ?? "") };
  }
}

/** Lay out the Action exactly as a consumer checkout sees it, then run the bundled CLI from it. */
async function actionLayout(top: string): Promise<string> {
  const action = join(top, "action");
  await mkdir(join(action, "scripts"), { recursive: true });
  await mkdir(join(action, "dist-action"));
  await mkdir(join(action, "workers", "schemathesis"), { recursive: true });
  await mkdir(join(action, "dast"));
  for (const name of ["action-run.mjs", "install-tools.mjs"]) await copyFile(resolve(root, "scripts", name), join(action, "scripts", name));
  await copyFile(resolve(root, "dist-action/wakeio-security-ci.mjs"), join(action, "dist-action/wakeio-security-ci.mjs"));
  for (const name of ["worker.py", "requirements.lock.txt"]) await copyFile(resolve(root, "workers/schemathesis", name), join(action, "workers/schemathesis", name));
  await copyFile(resolve(root, "dast/action.yml"), join(action, "dast/action.yml"));
  return action;
}

async function fixture(script: string, variant: string): Promise<{ origin: string; requests: () => Promise<number>; stop: () => Promise<void> }> {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-dast-action-fixture-"));
  const log = join(directory, "requests.jsonl");
  const child: ChildProcess = spawn(process.execPath, [join(root, "tests/fixtures", script), variant],
    { env: { PATH: process.env.PATH ?? "", WAKEIO_FIXTURE_LOG: log }, stdio: ["ignore", "pipe", "ignore"] });
  const port = await new Promise<string>((done) => child.stdout!.once("data", (chunk) => done(String(chunk).trim())));
  return {
    origin: `http://127.0.0.1:${port}`,
    requests: async () => (await readFile(log, "utf8").catch(() => "")).split("\n").filter(Boolean).length,
    stop: async () => { child.kill(); await new Promise((done) => child.once("close", done)); await rm(directory, { recursive: true, force: true }); },
  };
}

function outputs(text: string): Record<string, string> {
  return Object.fromEntries(text.split("\n").filter(Boolean).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
}

async function workspaceFor(top: string, event?: unknown) {
  const workspace = join(top, "workspace");
  await mkdir(workspace, { recursive: true });
  await copyFile(join(root, "tests/fixtures/openapi-live.json"), join(workspace, "openapi.json"));
  const output = join(top, "output"), summary = join(top, "summary"), eventPath = join(top, "event.json");
  await writeFile(output, ""); await writeFile(summary, "");
  if (event !== undefined) await writeFile(eventPath, JSON.stringify(event));
  return { workspace, output, summary, eventPath };
}

const sameRepoPr = { pull_request: { head: { repo: { full_name: "acme/app" } }, base: { repo: { full_name: "acme/app" } } } };

test("DAST Action refuses missing consent, unlisted origins and untrusted triggers before any request", async () => {
  const top = await mkdtemp(join(tmpdir(), "wakeio-dast-action-"));
  const target = await fixture("openapi-live-target.mjs", "normal");
  try {
    const action = await actionLayout(top);
    const paths = await workspaceFor(top, sameRepoPr);
    const forkEvent = join(top, "fork.json");
    await writeFile(forkEvent, JSON.stringify({ pull_request: { head: { repo: { full_name: "evil/app" } }, base: { repo: { full_name: "acme/app" } } } }));
    const base: NodeJS.ProcessEnv = {
      PATH: process.env.PATH, WAKEIO_MODE: "dast", WAKEIO_ACTION_PATH: action, GITHUB_WORKSPACE: paths.workspace,
      GITHUB_OUTPUT: paths.output, GITHUB_STEP_SUMMARY: paths.summary, GITHUB_REPOSITORY: "acme/app", GITHUB_EVENT_NAME: "push",
      WAKEIO_ACTIVE_CONSENT: "true", WAKEIO_ALLOWED_ORIGINS: target.origin, WAKEIO_OPENAPI: "openapi.json",
      WAKEIO_API_BASE: `${target.origin}/`, WAKEIO_OPERATIONS: "/items/{id}", WAKEIO_ALLOW_PRIVATE: "true",
      WAKEIO_SCHEMATHESIS_PYTHON: python, WAKEIO_OUT: "reports",
    };
    const refusals: Array<[string, NodeJS.ProcessEnv]> = [
      ["consent missing", { WAKEIO_ACTIVE_CONSENT: "" }],
      ["consent not exactly true", { WAKEIO_ACTIVE_CONSENT: "yes" }],
      ["allowed-origins missing", { WAKEIO_ALLOWED_ORIGINS: "" }],
      ["allowed-origins with a path", { WAKEIO_ALLOWED_ORIGINS: `${target.origin}/api` }],
      ["api-base not allowlisted", { WAKEIO_ALLOWED_ORIGINS: "https://staging.example.test" }],
      ["api-base with a path", { WAKEIO_API_BASE: `${target.origin}/api` }],
      ["pull_request_target", { GITHUB_EVENT_NAME: "pull_request_target", GITHUB_EVENT_PATH: paths.eventPath }],
      ["fork pull request", { GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: forkEvent }],
      ["unreadable pull request event", { GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: join(top, "missing.json") }],
      ["unknown engine", { WAKEIO_ENGINES: "zap" }],
      ["nuclei without pinned templates", { WAKEIO_ENGINES: "nuclei", WAKEIO_URL: `${target.origin}/`, WAKEIO_NUCLEI_TEMPLATES: "t" }],
      ["nothing selected", { WAKEIO_OPENAPI: "" }],
    ];
    for (const [name, overrides] of refusals) {
      await writeFile(paths.output, ""); await writeFile(paths.summary, "");
      const result = await launch(join(action, "scripts/action-run.mjs"), { ...base, ...overrides }, paths.workspace);
      assert.equal(result.code, 2, name);
      assert.match(result.stderr, /DAST refused/, name);
      const values = outputs(await readFile(paths.output, "utf8"));
      assert.equal(values["setup-status"], "refused", name);
      assert.equal(values["exit-code"], "2", name);
      const status = JSON.parse(await readFile(join(paths.workspace, "reports/action-status.json"), "utf8"));
      assert.equal(status.setupStatus, "refused", name);
      assert.match(await readFile(paths.summary, "utf8"), /active DAST/, name);
    }
    assert.equal(await target.requests(), 0, "no refusal reached the target");
  } finally {
    await target.stop();
    await rm(top, { recursive: true, force: true });
  }
});

test("DAST Action runs Schemathesis from the bundled layout for a same-repository pull request", async () => {
  const top = await mkdtemp(join(tmpdir(), "wakeio-dast-action-"));
  const target = await fixture("openapi-live-target.mjs", "risk");
  try {
    const action = await actionLayout(top);
    const paths = await workspaceFor(top, sameRepoPr);
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH, WAKEIO_MODE: "dast", WAKEIO_ACTION_PATH: action, GITHUB_WORKSPACE: paths.workspace,
      GITHUB_OUTPUT: paths.output, GITHUB_STEP_SUMMARY: paths.summary, GITHUB_REPOSITORY: "acme/app",
      GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: paths.eventPath,
      WAKEIO_ACTIVE_CONSENT: "true", WAKEIO_ALLOWED_ORIGINS: `https://staging.example.test\n${target.origin}`,
      WAKEIO_OPENAPI: "openapi.json", WAKEIO_API_BASE: `${target.origin}/`, WAKEIO_OPERATIONS: "/items/{id}\n/search",
      WAKEIO_API_MAX_REQUESTS: "32", WAKEIO_SEED: "7", WAKEIO_ALLOW_PRIVATE: "true", WAKEIO_SCHEMATHESIS_PYTHON: python,
      WAKEIO_FAIL_ON: "low", WAKEIO_OUT: "reports",
    };
    const result = await launch(join(action, "scripts/action-run.mjs"), env, paths.workspace);
    assert.equal(result.code, 1, result.stderr);
    const values = outputs(await readFile(paths.output, "utf8"));
    assert.equal(values["setup-status"], "success");
    assert.equal(values["scan-status"], "findings");
    assert.equal(values["finding-count"], "2");
    assert.equal(values["incomplete-count"], "0");
    const report = JSON.parse(await readFile(join(paths.workspace, "reports/report.json"), "utf8"));
    const check = report.checks.find((item: { id: string }) => item.id === "api.schemathesis");
    assert.equal(check.status, "completed");
    assert.equal(check.metrics.requestCount, 32);
    assert.equal(await target.requests(), 32);
    const summary = await readFile(paths.summary, "utf8");
    assert.match(summary, /schemathesis http:\/\/127\.0\.0\.1:\d+\//);
    for (const name of await readdir(join(paths.workspace, "reports"))) {
      const text = await readFile(join(paths.workspace, "reports", name), "utf8");
      assert.ok(!text.includes("wakeio:") && !text.includes(top), `${name} keeps no proxy credential or absolute temp path`);
    }
  } finally {
    await target.stop();
    await rm(top, { recursive: true, force: true });
  }
});

test("DAST Action stops on a template digest mismatch before downloading Nuclei or sending requests", async () => {
  const top = await mkdtemp(join(tmpdir(), "wakeio-dast-action-"));
  const target = await fixture("nuclei-target.mjs", "risk");
  try {
    const action = await actionLayout(top);
    const paths = await workspaceFor(top);
    const templates = join(paths.workspace, "templates");
    await mkdir(templates);
    await writeFile(join(templates, "templates-checksum.txt"), "x.yaml:abc\n");
    const cache = join(top, "cache");
    await mkdir(cache);
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH, WAKEIO_MODE: "dast", WAKEIO_ACTION_PATH: action, GITHUB_WORKSPACE: paths.workspace,
      GITHUB_OUTPUT: paths.output, GITHUB_STEP_SUMMARY: paths.summary, GITHUB_EVENT_NAME: "push",
      WAKEIO_ACTIVE_CONSENT: "true", WAKEIO_ALLOWED_ORIGINS: target.origin, WAKEIO_ENGINES: "nuclei", WAKEIO_URL: `${target.origin}/`,
      WAKEIO_NUCLEI_TEMPLATES: "templates", WAKEIO_NUCLEI_TEMPLATES_SHA256: "0".repeat(64), WAKEIO_TOOL_CACHE: cache,
      WAKEIO_ALLOW_PRIVATE: "true", WAKEIO_OUT: "reports",
    };
    const result = await launch(join(action, "scripts/action-run.mjs"), env, paths.workspace);
    assert.equal(result.code, 2);
    assert.equal(outputs(await readFile(paths.output, "utf8"))["setup-status"], "failure");
    assert.deepEqual(await readdir(cache), [], "no engine archive was fetched");
    assert.equal(await target.requests(), 0);
  } finally {
    await target.stop();
    await rm(top, { recursive: true, force: true });
  }
});

const realEngine = process.env.WAKEIO_NUCLEI;
const realTemplates = process.env.WAKEIO_NUCLEI_TEMPLATES;
const requireReal = process.env.WAKEIO_REQUIRE_NUCLEI === "1";
test("DAST Action runs pinned Nuclei through the bundled layout", {
  skip: (realEngine && realTemplates) || requireReal ? false : "set WAKEIO_NUCLEI and WAKEIO_NUCLEI_TEMPLATES (npm run test:schemathesis provisions them)",
}, async () => {
  assert.ok(realEngine && realTemplates, "WAKEIO_NUCLEI and WAKEIO_NUCLEI_TEMPLATES are required");
  const top = await mkdtemp(join(tmpdir(), "wakeio-dast-action-"));
  const target = await fixture("nuclei-target.mjs", "risk");
  try {
    const action = await actionLayout(top);
    const paths = await workspaceFor(top);
    const digest = createHash("sha256").update(await readFile(join(realTemplates, "templates-checksum.txt"))).digest("hex");
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH, WAKEIO_MODE: "dast", WAKEIO_ACTION_PATH: action, GITHUB_WORKSPACE: paths.workspace,
      GITHUB_OUTPUT: paths.output, GITHUB_STEP_SUMMARY: paths.summary, GITHUB_EVENT_NAME: "workflow_dispatch",
      WAKEIO_ACTIVE_CONSENT: "true", WAKEIO_ALLOWED_ORIGINS: target.origin, WAKEIO_ENGINES: "nuclei", WAKEIO_URL: `${target.origin}/`,
      WAKEIO_NUCLEI_PATH: realEngine, WAKEIO_NUCLEI_TEMPLATES: realTemplates, WAKEIO_NUCLEI_TEMPLATES_SHA256: digest,
      WAKEIO_NUCLEI_RATE_LIMIT: "150", WAKEIO_ALLOW_PRIVATE: "true", WAKEIO_FAIL_ON: "info", WAKEIO_OUT: "reports",
      WAKEIO_NUCLEI_TIMEOUT_MS: "300000",
    };
    const result = await launch(join(action, "scripts/action-run.mjs"), env, paths.workspace);
    const report = JSON.parse(await readFile(join(paths.workspace, "reports/report.json"), "utf8"));
    assert.equal(result.code, 1, JSON.stringify(report.checks.map((item: { id: string; status: string; metrics?: unknown }) => [item.id, item.status, item.metrics])));
    const check = report.checks.find((item: { id: string }) => item.id === "url.nuclei");
    assert.equal(check.status, "completed");
    assert.ok(check.findings.length >= 10);
    assert.equal(report.checks.find((item: { id: string }) => item.id === "url.scan").status, "completed", "the Nuclei budget does not leak into the passive URL check");
    assert.ok(await target.requests() >= check.metrics.requestCount, "every gate-forwarded request reached the target; the passive URL scan adds its own bounded GETs");
    assert.equal(outputs(await readFile(paths.output, "utf8"))["setup-status"], "success");
  } finally {
    await target.stop();
    await rm(top, { recursive: true, force: true });
  }
});

test("DAST Action preflight skips engine setup for every refusal and records nothing itself", async () => {
  const top = await mkdtemp(join(tmpdir(), "wakeio-dast-preflight-"));
  try {
    const action = await actionLayout(top);
    const paths = await workspaceFor(top, sameRepoPr);
    const forkEvent = join(top, "fork.json");
    await writeFile(forkEvent, JSON.stringify({ pull_request: { head: { repo: { full_name: "evil/app" } }, base: { repo: { full_name: "acme/app" } } } }));
    const origin = "https://staging.example.test";
    const base: NodeJS.ProcessEnv = {
      PATH: process.env.PATH, WAKEIO_MODE: "dast-preflight", WAKEIO_ACTION_PATH: action, GITHUB_WORKSPACE: paths.workspace,
      GITHUB_OUTPUT: paths.output, GITHUB_STEP_SUMMARY: paths.summary, GITHUB_EVENT_NAME: "push",
      WAKEIO_ACTIVE_CONSENT: "true", WAKEIO_ALLOWED_ORIGINS: origin, WAKEIO_OPENAPI: "openapi.json",
      WAKEIO_API_BASE: `${origin}/`, WAKEIO_OPERATIONS: "/items/{id}", WAKEIO_OUT: "reports",
    };
    const cases: Array<[string, NodeJS.ProcessEnv, string]> = [
      ["allowed openapi", {}, "true"],
      ["allowed nuclei only", { WAKEIO_OPENAPI: "", WAKEIO_ENGINES: "nuclei", WAKEIO_URL: `${origin}/`, WAKEIO_NUCLEI_TEMPLATES: "t", WAKEIO_NUCLEI_TEMPLATES_SHA256: "a".repeat(64) }, "false"],
      ["consent missing", { WAKEIO_ACTIVE_CONSENT: "" }, "false"],
      ["api-base not allowlisted", { WAKEIO_ALLOWED_ORIGINS: "https://other.example.test" }, "false"],
      ["pull_request_target", { GITHUB_EVENT_NAME: "pull_request_target", GITHUB_EVENT_PATH: paths.eventPath }, "false"],
      ["fork pull request", { GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: forkEvent }, "false"],
      ["unreadable pull request event", { GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: join(top, "missing.json") }, "false"],
    ];
    for (const [name, overrides, expected] of cases) {
      await writeFile(paths.output, ""); await writeFile(paths.summary, "");
      const result = await launch(join(action, "scripts/action-run.mjs"), { ...base, ...overrides }, paths.workspace);
      assert.equal(result.code, 0, name);
      assert.deepEqual(outputs(await readFile(paths.output, "utf8")), { "prepare-schemathesis": expected }, name);
      assert.equal(await readFile(paths.summary, "utf8"), "", name);
    }
    assert.deepEqual(await readdir(paths.workspace), ["openapi.json"], "preflight writes no report or status artifact");

    const workflow = await readFile(resolve(root, "dast/action.yml"), "utf8");
    const steps = workflow.slice(workflow.indexOf("\n  steps:"));
    assert.ok(steps.indexOf("id: dast-preflight") < steps.indexOf("actions/setup-python@"), "policy preflight runs before Python setup");
    assert.equal((steps.match(/steps\.dast-preflight\.outputs\.prepare-schemathesis == 'true'/g) ?? []).length, 2, "both Python setup steps follow the preflight");
    assert.doesNotMatch(steps, /inputs\.active-consent == 'true'/, "setup no longer runs on consent alone");
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});
