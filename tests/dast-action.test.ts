import test from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
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
    const httpsNuclei = await launch(join(action, "scripts/action-run.mjs"), { ...base,
      WAKEIO_OPENAPI: "", WAKEIO_ENGINES: "nuclei", WAKEIO_URL: `${origin}/`,
      WAKEIO_NUCLEI_TEMPLATES: "t", WAKEIO_NUCLEI_TEMPLATES_SHA256: "a".repeat(64),
    }, paths.workspace);
    assert.match(httpsNuclei.stderr, /preflight refused/);
    assert.equal(outputs(await readFile(paths.output, "utf8"))["prepare-schemathesis"], "false");
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


// Synthetic transport oracle; real SQL differential correctness is covered by dast-native.test.ts.
test("DAST Action runs native policy from its bundle and refuses invalid policy before engine preparation", async () => {
  let hits = 0;
  const target = createServer((req, res) => {
    hits++;
    const value = new URL(req.url!, 'http://fixture.invalid').searchParams.get('id') ?? '';
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ count: value.includes('1=2') ? 0 : 1 }));
  });
  await new Promise<void>(done => target.listen(0, '127.0.0.1', done));
  const address = target.address(); assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  const top = await mkdtemp(join(tmpdir(), 'wakeio-native-action-'));
  try {
    const action = await actionLayout(top);
    const paths = await workspaceFor(top);
    const policyPath = join(paths.workspace, 'dast.json');
    const policy = { version: 1, kind: 'sql-boolean-differential', baseUrl: `${origin}/`, url: `${origin}/items?id=1`,
      parameter: 'id', profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
    await writeFile(policyPath, JSON.stringify(policy));
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, WAKEIO_MODE: 'dast', WAKEIO_ACTION_PATH: action,
      GITHUB_WORKSPACE: paths.workspace, GITHUB_OUTPUT: paths.output, GITHUB_STEP_SUMMARY: paths.summary, GITHUB_EVENT_NAME: 'push',
      WAKEIO_ACTIVE_CONSENT: 'true', WAKEIO_ALLOWED_ORIGINS: origin, WAKEIO_DAST_POLICY: 'dast.json', WAKEIO_ALLOW_PRIVATE: 'true',
      WAKEIO_OUT: 'reports' };
    const preflight = await launch(join(action, 'scripts/action-run.mjs'), { ...env, WAKEIO_MODE: 'dast-preflight' }, paths.workspace);
    assert.equal(preflight.code, 0, preflight.stderr);
    assert.equal(outputs(await readFile(paths.output, 'utf8'))['prepare-schemathesis'], 'false');
    assert.equal(hits, 0);
    for (const override of [{ WAKEIO_ALLOWED_ORIGINS: 'https://outside.example' }, { WAKEIO_ACTIVE_CONSENT: '' }]) {
      const refused = await launch(join(action, 'scripts/action-run.mjs'), { ...env, ...override }, paths.workspace);
      assert.equal(refused.code, 2); assert.match(refused.stderr, /DAST refused/); assert.equal(hits, 0);
    }
    await writeFile(policyPath, JSON.stringify({ ...policy, parameter: 'unknown' }));
    const invalid = await launch(join(action, 'scripts/action-run.mjs'), { ...env, WAKEIO_OPENAPI: 'openapi.json',
      WAKEIO_API_BASE: `${origin}/`, WAKEIO_OPERATIONS: '/search', WAKEIO_SCHEMATHESIS_PYTHON: '/must-not-start' }, paths.workspace);
    assert.equal(invalid.code, 2); assert.match(invalid.stderr, /DAST refused/); assert.equal(hits, 0);
    await writeFile(policyPath, JSON.stringify(policy));
    const complete = await launch(join(action, 'scripts/action-run.mjs'), env, paths.workspace);
    assert.equal(complete.code, 1, complete.stderr); assert.equal(hits, 8);
    const report = JSON.parse(await readFile(join(paths.workspace, 'reports/report.json'), 'utf8'));
    assert.equal(report.checks[0].dastExecution.outcome, 'observed');
    const values = outputs(await readFile(paths.output, 'utf8'));
    assert.ok(values['report-agent']?.endsWith('agent-report.json'));
    assert.match(await readFile(paths.summary, 'utf8'), /native http:\/\/127\.0\.0\.1/);
    const partial = await launch(join(action, 'scripts/action-run.mjs'), { ...env, WAKEIO_DAST_MAX_REQUESTS: '7',
      WAKEIO_FAIL_ON: 'none', WAKEIO_OUT: 'partial' }, paths.workspace);
    assert.equal(partial.code, 2, partial.stderr); assert.match(partial.stderr, /DAST refused/); assert.equal(hits, 8);
  } finally { await new Promise<void>(done => target.close(() => done())); await rm(top, { recursive: true, force: true }); }
});

async function syntheticAction(top: string, scan: string, installer = 'process.stdout.write("{}");') {
  const action = join(top, "action");
  await mkdir(join(action, "scripts"), { recursive: true });
  await mkdir(join(action, "dist-action"));
  await copyFile(join(root, "scripts/action-run.mjs"), join(action, "scripts/action-run.mjs"));
  await writeFile(join(action, "dist-action/wakeio-security-ci.mjs"), scan);
  await writeFile(join(action, "scripts/install-tools.mjs"), installer);
  return action;
}

for (const mode of ["dast", "dast-preflight"] as const) {
  test(`${mode} Action cancellation during native policy preflight prevents scan launch`, { timeout: 12000 }, async () => {
    const top = await mkdtemp(join(tmpdir(), "wakeio-native-plan-cancel-"));
    let running: ReturnType<typeof controlledAction> | undefined;
    let plannerPid: number | undefined;
    try {
      const action = await syntheticAction(top, `
import { writeFileSync } from 'node:fs';
if (process.argv[2] !== 'plan') {
  writeFileSync('unexpected-scan', 'started');
  process.exit(0);
}
process.on('SIGTERM', () => {
  writeFileSync('received-signal', 'SIGTERM');
  process.stdout.write(JSON.stringify({ kind: 'native-dast-plan', status: 'ready', origin: 'http://owned.example.test' }));
  process.exit(0);
});
writeFileSync('ready', String(process.pid));
setInterval(() => {}, 1000);
`, `import { writeFileSync } from 'node:fs'; writeFileSync('unexpected-setup', 'started');`);
      const paths = await workspaceFor(top);
      if (mode === "dast") await seedSuccess(paths);
      const env = { ...syntheticEnv(action, paths, "dast"), WAKEIO_MODE: mode,
        WAKEIO_OPENAPI: "", WAKEIO_DAST_POLICY: "native.json" };
      running = controlledAction(action, env, paths.workspace);
      plannerPid = Number(await waitForFile(join(paths.workspace, "ready")));
      assert.ok(running.child.kill("SIGTERM"));
      const result = await running.finished;
      assert.equal(result.code, 2, result.stderr);
      assert.equal(result.signal, null);
      assert.equal(await readFile(join(paths.workspace, "received-signal"), "utf8"), "SIGTERM");
      for (const file of ["unexpected-scan", "unexpected-setup"]) {
        await assert.rejects(readFile(join(paths.workspace, file)), { code: "ENOENT" });
      }
      const values = outputs(await readFile(paths.output, "utf8"));
      const statusFile = join(paths.workspace, "reports/action-status.json");
      if (mode === "dast") {
        const status = JSON.parse(await readFile(statusFile, "utf8"));
        assert.equal(status.exitCode, 2);
        assert.equal(status.setupStatus, "failure");
        assert.equal(status.scanStatus, "not-run");
        assert.equal(status.cancellationSignal, "SIGTERM");
        assert.equal(values["exit-code"], "2");
        assert.equal(values["report-agent"], "");
      } else {
        assert.equal(values["prepare-schemathesis"], "false");
        await assert.rejects(readFile(statusFile), { code: "ENOENT" });
      }
    } finally {
      running?.child.kill("SIGKILL");
      if (plannerPid) { try { process.kill(plannerPid, "SIGKILL"); } catch { /* already reaped */ } }
      await running?.finished.catch(() => undefined);
      await rm(top, { recursive: true, force: true });
    }
  });
}

const delay = (ms: number) => new Promise<void>((done) => setTimeout(done, ms));

async function waitForFile(path: string) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text) return text;
    await delay(10);
  }
  throw new Error(`synthetic child did not become ready: ${path}`);
}

function controlledAction(action: string, env: NodeJS.ProcessEnv, cwd: string) {
  const child = spawn(process.execPath, [join(action, "scripts/action-run.mjs")], { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr!.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  child.stdout!.resume();
  const finished = new Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }>((done, reject) => {
    const timeout = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Action cancellation exceeded its shutdown bound")); }, 8000);
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", (code, signal) => { clearTimeout(timeout); done({ code, signal, stderr }); });
  });
  return { child, finished };
}

async function seedSuccess(paths: Awaited<ReturnType<typeof workspaceFor>>) {
  const directory = join(paths.workspace, "reports");
  await mkdir(directory);
  const report = JSON.stringify({ checks: [{ id: "old.success", status: "completed", findings: [{}] }] });
  await writeFile(join(directory, "report.json"), report);
  await writeFile(join(directory, "agent-report.json"), JSON.stringify({ schemaVersion: "1.0.0", reportArtifact: {
    name: "report.json", algorithm: "sha256", digest: createHash("sha256").update(report).digest("hex"),
  } }));
  await writeFile(join(directory, "action-status.json"), JSON.stringify({ setupStatus: "success", scanStatus: "success", exitCode: 0 }));
  await writeFile(paths.output, `exit-code=0\nsetup-status=success\nscan-status=success\nreport-agent=${directory}/agent-report.json\n`);
}

function syntheticEnv(action: string, paths: Awaited<ReturnType<typeof workspaceFor>>, mode: "dast" | "source"): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH, WAKEIO_ACTION_PATH: action, GITHUB_WORKSPACE: paths.workspace,
    GITHUB_OUTPUT: paths.output, GITHUB_STEP_SUMMARY: paths.summary, WAKEIO_OUT: "reports",
    ...(mode === "source" ? { WAKEIO_SOURCE: ".", WAKEIO_TOOLS: "none" } : {
      WAKEIO_MODE: "dast", GITHUB_EVENT_NAME: "push", WAKEIO_ACTIVE_CONSENT: "true",
      WAKEIO_ALLOWED_ORIGINS: "http://owned.example.test", WAKEIO_OPENAPI: "openapi.json",
      WAKEIO_API_BASE: "http://owned.example.test", WAKEIO_OPERATIONS: "/items",
    }),
  };
}

// These scripts never scan or contact the synthetic origin. They exercise the
// wrapper's process lifecycle independently of a real engine or Python setup.
const cooperativeScan = `
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
let stopping = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  if (stopping) return;
  stopping = true;
  writeFileSync('forwarded-signal', signal);
  setTimeout(() => {
    const report = JSON.stringify({ checks: [
      { id: 'completed.stage', status: 'completed', findings: [{}] },
      { id: 'scan.cancelled', status: 'partial', findings: [] },
    ] });
    writeFileSync('reports/report.json', report);
    writeFileSync('reports/agent-report.json', JSON.stringify({ schemaVersion: '1.0.0', reportArtifact: {
      name: 'report.json', algorithm: 'sha256', digest: createHash('sha256').update(report).digest('hex'),
    } }));
    process.exit(0);
  }, 100);
});
writeFileSync('ready', String(process.pid));
setInterval(() => {}, 1000);
`;

for (const mode of ["dast", "source"] as const) {
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    test(`${mode} Action cancellation forwards ${signal} and retains fresh partial evidence even when the child exits zero`, { timeout: 12000 }, async () => {
      const top = await mkdtemp(join(tmpdir(), "wakeio-action-cancel-"));
      let running: ReturnType<typeof controlledAction> | undefined;
      try {
        const action = await syntheticAction(top, cooperativeScan);
        const paths = await workspaceFor(top);
        await seedSuccess(paths);
        running = controlledAction(action, syntheticEnv(action, paths, mode), paths.workspace);
        await waitForFile(join(paths.workspace, "ready"));
        assert.ok(running.child.kill(signal));
        const result = await running.finished;
        assert.equal(result.code, 2, result.stderr);
        assert.equal(result.signal, null, "the wrapper finalized normally rather than being killed");
        assert.equal(await readFile(join(paths.workspace, "forwarded-signal"), "utf8"), signal);
        const values = outputs(await readFile(paths.output, "utf8"));
        assert.equal(values["exit-code"], "2");
        assert.equal(values["setup-status"], "success");
        assert.equal(values["scan-status"], "incomplete");
        assert.equal(values["finding-count"], "1");
        assert.equal(values["incomplete-count"], "1");
        assert.equal(values["report-agent"], join(paths.workspace, "reports/agent-report.json"));
        const status = JSON.parse(await readFile(join(paths.workspace, "reports/action-status.json"), "utf8"));
        assert.equal(status.exitCode, 2);
        assert.equal(status.scanStatus, "incomplete");
        assert.equal(status.cancellationSignal, signal);
        assert.equal(status.incompleteCount, 1);
        const summary = await readFile(paths.summary, "utf8");
        assert.match(summary, /Scan: \*\*incomplete\*\* \(exit code 2\)/);
        assert.match(summary, /scan\.cancelled: partial/);
      } finally {
        running?.child.kill("SIGKILL");
        await running?.finished.catch(() => undefined);
        await rm(top, { recursive: true, force: true });
      }
    });
  }
}

test("DAST Action cancellation bounds ignored/repeated signals and kills the owned child process group", { timeout: 12000, skip: process.platform === "win32" }, async () => {
  const top = await mkdtemp(join(tmpdir(), "wakeio-action-kill-"));
  let running: ReturnType<typeof controlledAction> | undefined;
  let ownedPid: number | undefined;
  try {
    const action = await syntheticAction(top, `
import { spawn } from 'node:child_process';
import { writeFileSync, appendFileSync } from 'node:fs';
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {});
const child = spawn(process.execPath, ['--input-type=module', '-e', ${JSON.stringify(`
  import { writeFileSync, appendFileSync } from 'node:fs';
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {});
  setInterval(() => appendFileSync('descendant-heartbeat', '.'), 10);
  writeFileSync('descendant-ready', String(process.pid));
`)}], { stdio: 'inherit' });
setInterval(() => appendFileSync('child-heartbeat', '.'), 10);
writeFileSync('ready', String(process.pid));
`);
    const paths = await workspaceFor(top);
    await seedSuccess(paths);
    running = controlledAction(action, syntheticEnv(action, paths, "dast"), paths.workspace);
    ownedPid = Number(await waitForFile(join(paths.workspace, "ready")));
    await waitForFile(join(paths.workspace, "descendant-ready"));
    await waitForFile(join(paths.workspace, "child-heartbeat"));
    await waitForFile(join(paths.workspace, "descendant-heartbeat"));
    const started = Date.now();
    assert.ok(running.child.kill("SIGTERM"));
    await delay(50);
    assert.ok(running.child.kill("SIGINT"));
    assert.ok(running.child.kill("SIGTERM"));
    const result = await running.finished;
    assert.equal(result.code, 2, result.stderr);
    assert.equal(result.signal, null);
    assert.ok(Date.now() - started < 5000, "uncooperative child cannot extend cancellation indefinitely");
    const values = outputs(await readFile(paths.output, "utf8"));
    assert.equal(values["exit-code"], "2");
    assert.equal(values["scan-status"], "incomplete");
    assert.equal(values["report-agent"], "", "stale digest-matched success is not exposed");
    assert.equal(values["finding-count"], "0");
    const status = JSON.parse(await readFile(join(paths.workspace, "reports/action-status.json"), "utf8"));
    assert.equal(status.exitCode, 2);
    assert.equal(status.cancellationSignal, "SIGTERM", "repeated signals do not replace the original cancellation");
    for (const name of ["child-heartbeat", "descendant-heartbeat"]) {
      const before = await readFile(join(paths.workspace, name), "utf8");
      await delay(100);
      assert.equal(await readFile(join(paths.workspace, name), "utf8"), before, `${name} stopped before receipts were finalized`);
    }
    assert.match(await readFile(join(paths.workspace, "reports/report.json"), "utf8"), /old.success/, "old report is preserved but never counted as this run");
  } finally {
    running?.child.kill("SIGKILL");
    if (ownedPid) { try { process.kill(-ownedPid, "SIGKILL"); } catch { /* already reaped */ } }
    await running?.finished.catch(() => undefined);
    await rm(top, { recursive: true, force: true });
  }
});

for (const mode of ["source", "dast"] as const) {
  test(`${mode} Action cancellation during tool setup prevents scan launch and removes its temporary tools`, { timeout: 12000 }, async () => {
    const top = await mkdtemp(join(tmpdir(), "wakeio-action-setup-cancel-"));
    let running: ReturnType<typeof controlledAction> | undefined;
    let installerPid: number | undefined;
    try {
      const action = await syntheticAction(top, `import { writeFileSync } from 'node:fs'; writeFileSync('unexpected-scan', 'started');`, `
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
const workspace = process.env.GITHUB_WORKSPACE;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  process.stdout.write(JSON.stringify({ paths: { nuclei: '/unused' }, metadata: {} }));
  process.exit(0);
});
writeFileSync(join(workspace, 'tools-root'), process.argv[process.argv.indexOf('--dir') + 1]);
writeFileSync(join(workspace, 'ready'), String(process.pid));
setInterval(() => {}, 1000);
`);
      const paths = await workspaceFor(top);
      await seedSuccess(paths);
      const env = syntheticEnv(action, paths, mode);
      if (mode === "dast") {
        await mkdir(join(paths.workspace, "templates"));
        const manifest = "owned-template.yaml:abc\n";
        await writeFile(join(paths.workspace, "templates/templates-checksum.txt"), manifest);
        Object.assign(env, { WAKEIO_ENGINES: "nuclei", WAKEIO_URL: "http://owned.example.test",
          WAKEIO_NUCLEI_TEMPLATES: "templates", WAKEIO_NUCLEI_TEMPLATES_SHA256: createHash("sha256").update(manifest).digest("hex") });
      }
      running = controlledAction(action, env, paths.workspace);
      installerPid = Number(await waitForFile(join(paths.workspace, "ready")));
      const toolsRoot = await waitForFile(join(paths.workspace, "tools-root"));
      assert.ok(running.child.kill("SIGTERM"));
      const result = await running.finished;
      assert.equal(result.code, 2, result.stderr);
      assert.equal(result.signal, null);
      const values = outputs(await readFile(paths.output, "utf8"));
      assert.equal(values["exit-code"], "2");
      assert.equal(values["setup-status"], "failure");
      assert.equal(values["scan-status"], "not-run");
      assert.equal(values["report-agent"], "");
      const status = JSON.parse(await readFile(join(paths.workspace, "reports/action-status.json"), "utf8"));
      assert.equal(status.exitCode, 2);
      assert.equal(status.cancellationSignal, "SIGTERM");
      await assert.rejects(readFile(join(paths.workspace, "unexpected-scan")), { code: "ENOENT" });
      await assert.rejects(readdir(toolsRoot), { code: "ENOENT" });
    } finally {
      running?.child.kill("SIGKILL");
      if (installerPid) { try { process.kill(installerPid, "SIGKILL"); } catch { /* already reaped */ } }
      await running?.finished.catch(() => undefined);
      await rm(top, { recursive: true, force: true });
    }
  });
}

test("Action cancellation while a successful receipt is being written corrects status and outputs before exit", { timeout: 12000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), "wakeio-action-finalize-cancel-"));
  try {
    const action = await syntheticAction(top, `
import { writeFileSync } from 'node:fs';
writeFileSync('reports/report.json', JSON.stringify({ checks: [{ id: 'new.success', status: 'completed', findings: [] }] }));
`);
    const paths = await workspaceFor(top);
    await seedSuccess(paths);
    const preload = join(top, "cancel-after-status.mjs");
    await writeFile(preload, `
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
if (process.argv[1].endsWith('action-run.mjs')) {
  const write = fs.promises.writeFile;
  fs.promises.writeFile = async (...args) => {
    const result = await write(...args);
    if (String(args[0]).endsWith('action-status.json') && String(args[1]).includes('"exitCode": 0')) {
      process.kill(process.pid, 'SIGTERM');
      await new Promise((done) => setTimeout(done, 25));
    }
    return result;
  };
  syncBuiltinESMExports();
}
`);
    const result = await launch(join(action, "scripts/action-run.mjs"), {
      ...syntheticEnv(action, paths, "dast"), NODE_OPTIONS: `--import=${preload}`,
    }, paths.workspace);
    assert.equal(result.code, 2, result.stderr);
    const status = JSON.parse(await readFile(join(paths.workspace, "reports/action-status.json"), "utf8"));
    assert.equal(status.exitCode, 2);
    assert.equal(status.scanStatus, "incomplete");
    assert.equal(status.cancellationSignal, "SIGTERM");
    const values = outputs(await readFile(paths.output, "utf8"));
    assert.equal(values["exit-code"], "2");
    assert.equal(values["scan-status"], "incomplete");
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});
