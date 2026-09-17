import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runUrl } from "../src/url.js";

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

function findings(checks: Awaited<ReturnType<typeof runUrl>>) {
  return checks.flatMap((check) => check.findings);
}

test("URL CSP analysis respects fallback, nonce/hash, strict-dynamic, and multiple policies", async () => {
  const cases = [
    {
      name: "unsafe source is effective through default-src",
      headers: { "Content-Security-Policy": "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'" },
      inline: true,
      eval: true,
    },
    {
      name: "nonce and hash override unsafe-inline",
      headers: { "Content-Security-Policy": "script-src 'nonce-aGVsbG8=' 'sha256-YWJj' 'unsafe-inline' 'unsafe-eval'" },
      inline: false,
      eval: true,
    },
    {
      name: "strict-dynamic overrides unsafe-inline for scripts",
      headers: { "Content-Security-Policy": "script-src 'strict-dynamic' 'unsafe-inline'" },
      inline: false,
      eval: false,
    },
    {
      name: "two policies intersect and the restrictive one wins",
      headers: { "Content-Security-Policy": ["script-src 'self' 'unsafe-inline'", "script-src 'self'"] },
      inline: false,
      eval: false,
    },
  ] as const;
  for (const entry of cases) {
    const server = createServer((_request, response) => {
      response.setHeader("Content-Type", "text/html");
      response.setHeader("Content-Security-Policy", entry.headers["Content-Security-Policy"]);
      response.end("<!doctype html><script>eval('1')</script>");
    });
    const url = await listen(server);
    try {
      const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
      const observed = findings(checks);
      assert.equal(observed.some((finding) => finding.ruleId === "url.csp-unsafe-inline"), entry.inline, entry.name);
      assert.equal(observed.some((finding) => finding.ruleId === "url.csp-unsafe-eval"), entry.eval, entry.name);
      if (!entry.inline && entry.name.includes("nonce")) {
        assert.ok(checks[0]?.notes.some((note) => /unsafe-inline was overridden/i.test(note)));
      }
      if (entry.name.includes("policies")) {
        assert.ok(checks[0]?.notes.some((note) => /Multiple Content-Security-Policy policies/i.test(note)));
      }
    } finally {
      await close(server);
    }
  }
});

test("URL CSP does not let malformed nonce or hash tokens hide unsafe-inline", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.setHeader("Content-Security-Policy", "script-src 'nonce-====' 'sha256-abc===' 'unsafe-inline'");
    response.end("<!doctype html><script>window.fixture = true</script>");
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    assert.ok(findings(checks).some((finding) => finding.ruleId === "url.csp-unsafe-inline"));
    assert.equal(checks[0]?.notes.some((note) => /unsafe-inline was overridden/i.test(note)), false);
  } finally {
    await close(server);
  }
});

test("URL observes invalid nosniff and Referrer-Policy values without copying them", async () => {
  const secret = "synthetic-invalid-header-value-should-not-escape";
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.setHeader("X-Content-Type-Options", secret);
    response.setHeader("Referrer-Policy", "not-a-referrer-policy");
    response.end("<!doctype html><p>fixture</p>");
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const observed = findings(checks);
    assert.ok(observed.some((finding) => finding.ruleId === "url.header-invalid-nosniff"));
    assert.ok(observed.some((finding) => finding.ruleId === "url.header-invalid-referrer-policy"));
    assert.equal(JSON.stringify(checks).includes(secret), false);
  } finally {
    await close(server);
  }
});

test("URL follows same-origin pages and static import/export modules, but never dynamic or remote imports", async () => {
  const token = `ghp_${"A1b2C3d4E5f6G7h8I9j0".repeat(2)}`;
  const requested: string[] = [];
  let outsideRequests = 0;
  const outside = createServer((_request, response) => {
    outsideRequests += 1;
    response.end("outside");
  });
  const outsideUrl = await listen(outside);
  const marker = join(await import("node:fs/promises").then((module) => module.mkdtemp(join(tmpdir(), "wakeio-url-module-"))), "executed");
  const server = createServer((request, response) => {
    const path = request.url?.split("?", 1)[0] ?? "/";
    requested.push(request.url ?? "");
    response.setHeader("Content-Type", path.endsWith(".js") ? "application/javascript" : "text/html");
    if (path === "/main.js") {
      response.end(`import './dep.js'; export { value } from './exported.js'; import '${outsideUrl}/remote.js'; import('${outsideUrl}/dynamic.js'); import(remoteName);`);
    } else if (path === "/dep.js") {
      response.end(`const apiKey = '${token}';`);
    } else if (path === "/exported.js") {
      response.end(`export const value = 1; document.body.innerHTML = 'candidate';`);
    } else if (path === "/page.js") {
      response.end(`import './page-dep.js';`);
    } else if (path === "/page-dep.js") {
      response.end(`require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed');`);
    } else if (path === "/page") {
      response.end("<!doctype html><script type=module src='/page.js'></script>");
    } else {
      response.end("<!doctype html><script type=module src='/main.js'></script>");
    }
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, pages: [`${url}/page`], allowPrivate: true, maxPages: 2, maxScripts: 10, timeoutMs: 2_000 });
    const observed = findings(checks);
    assert.ok(requested.includes("/main.js"));
    assert.ok(requested.includes("/dep.js"));
    assert.ok(requested.includes("/exported.js"));
    assert.ok(requested.includes("/page"));
    assert.ok(requested.includes("/page.js"));
    assert.ok(requested.includes("/page-dep.js"));
    assert.equal(requested.some((entry) => entry.includes("dynamic.js")), false);
    assert.equal(outsideRequests, 0);
    assert.ok(checks[0]?.notes.some((note) => /Dynamic module imports.*not fetched/i.test(note)));
    assert.ok(checks[0]?.notes.some((note) => /cross-origin static module/i.test(note)));
    assert.ok(observed.some((finding) => finding.ruleId === "url.secret-provider-token"));
    assert.equal(JSON.stringify(checks).includes(token), false);
    await assert.rejects(readFile(marker));
    assert.equal(checks[0]?.metrics?.pagesFetched, 2);
    assert.equal(checks[0]?.metrics?.moduleReferencesDiscovered, 4);
    assert.equal(checks[0]?.metrics?.dynamicImportsObserved, 2);
    assert.equal(checks[0]?.metrics?.computedImportsObserved, 1);
  } finally {
    await close(server);
    await close(outside);
    await rm(marker.replace(/\/executed$/, ""), { recursive: true, force: true });
  }
});

test("URL page, script, byte, and request limits are shared and escape pages are rejected before fetch", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    const path = request.url?.split("?", 1)[0] ?? "/";
    response.setHeader("Content-Type", path.endsWith(".js") ? "application/javascript" : "text/html");
    if (path === "/one") response.end("<!doctype html><p>one</p>");
    else if (path === "/two") response.end("<!doctype html><p>two</p>");
    else response.end("<!doctype html><script src='/one.js'></script><script src='/two.js'></script>");
  });
  const url = await listen(server);
  try {
    const pageLimited = await runUrl({ url, pages: [`${url}/one`, `${url}/two`], maxPages: 2, maxScripts: 0, allowPrivate: true, timeoutMs: 2_000 });
    assert.equal(pageLimited[0]?.metrics?.pagesFetched, 2);
    assert.equal(pageLimited[0]?.metrics?.pagesSkipped, 1);
    assert.equal(pageLimited[0]?.status, "partial");
    assert.equal(requested.includes("/two"), false);

    requested.length = 0;
    const scriptLimited = await runUrl({ url, maxScripts: 1, allowPrivate: true, timeoutMs: 2_000 });
    assert.equal(scriptLimited[0]?.metrics?.scriptsFetched, 1);
    assert.equal(scriptLimited[0]?.status, "partial");
    assert.equal(requested.filter((entry) => entry.endsWith(".js")).length, 1);

    const escaped = await runUrl({ url, pages: ["http://example.invalid/escape"], allowPrivate: true, timeoutMs: 2_000 });
    assert.equal(escaped[0]?.status, "error");
    assert.equal(requested.includes("/"), true);
    assert.equal(JSON.stringify(escaped).includes("example.invalid"), false);
  } finally {
    await close(server);
  }
});

test("URL shared byte budget prevents later page collection and redacts page query values", async () => {
  const secret = "synthetic-page-query-secret-do-not-report";
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    response.setHeader("Content-Type", "text/html");
    if ((request.url ?? "").startsWith("/later")) response.end("<!doctype html><p>later</p>");
    else response.end("<!doctype html>" + "x".repeat(100));
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url: `${url}/?token=${secret}`, pages: [`${url}/later?token=${secret}`], maxBytes: 128, allowPrivate: true, timeoutMs: 2_000 });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.metrics?.pagesFetched, 1);
    assert.equal(requested.length, 2);
    assert.equal(JSON.stringify(checks).includes(secret), false);
  } finally {
    await close(server);
  }
});
