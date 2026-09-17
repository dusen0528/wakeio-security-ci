import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
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

test("URL mode rejects loopback by default before a request is made", async () => {
  let requests = 0;
  const server = createServer((_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, timeoutMs: 500 });
    assert.equal(requests, 0);
    assert.ok(["error", "partial"].includes(checks[0]?.status ?? "completed"));
  } finally {
    await close(server);
  }
});

test("URL mode collects same-origin JavaScript and redacts candidate values", async () => {
  const token = `ghp_${"A1b2C3d4E5f6G7h8I9j0".repeat(2)}`;
  const cookieValue = "synthetic_cookie_value_should_not_escape";
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    if (request.url === "/app.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end(`const apiKey = '${token}'; document.body.innerHTML = location.hash;`);
      return;
    }
    response.setHeader("Content-Type", "text/html");
    response.setHeader("Set-Cookie", `session=${cookieValue}; Path=/`);
    response.end("<!doctype html><script src='/app.js'></script>");
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings);
    assert.ok(requested.includes("/app.js"));
    assert.ok(findings.some((finding) => /dom|sink|innerhtml/i.test(`${finding.ruleId} ${finding.title}`)));
    const serialised = JSON.stringify(checks);
    assert.equal(serialised.includes(token), false);
    assert.equal(serialised.includes(cookieValue), false);
  } finally {
    await close(server);
  }
});

test("URL mode blocks out-of-origin script redirects before the second request", async () => {
  let outsideRequests = 0;
  const outside = createServer((_request, response) => {
    outsideRequests += 1;
    response.end("outside");
  });
  const outsideUrl = await listen(outside);
  const inside = createServer((request, response) => {
    if (request.url === "/redirect.js") {
      response.writeHead(302, { Location: `${outsideUrl}/escaped.js` });
      response.end();
      return;
    }
    response.setHeader("Content-Type", "text/html");
    response.end("<script src='/redirect.js'></script>");
  });
  const insideUrl = await listen(inside);
  try {
    const checks = await runUrl({ url: insideUrl, allowPrivate: true, timeoutMs: 2_000 });
    assert.equal(outsideRequests, 0);
    assert.ok(checks.some((check) => ["error", "partial"].includes(check.status)));
  } finally {
    await close(inside);
    await close(outside);
  }
});

test("URL mode treats timeout and decompressed body limits as incomplete", async () => {
  const slow = createServer((_request, response) => {
    setTimeout(() => response.end("late"), 200);
  });
  const slowUrl = await listen(slow);
  const large = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.end("a".repeat(32_768));
  });
  const largeUrl = await listen(large);
  try {
    const timedOut = await runUrl({ url: slowUrl, allowPrivate: true, timeoutMs: 30 });
    const capped = await runUrl({ url: largeUrl, allowPrivate: true, maxBytes: 1_024, timeoutMs: 1_000 });
    assert.ok(["error", "partial"].includes(timedOut[0]?.status ?? "completed"));
    assert.ok(["error", "partial"].includes(capped[0]?.status ?? "completed"));
  } finally {
    await close(slow);
    await close(large);
  }
});

test("URL mode rejects numeric and metadata SSRF spellings without a request", async () => {
  for (const url of [
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:127.0.0.1]/",
  ]) {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 500 });
    assert.ok(["error", "partial"].includes(checks[0]?.status ?? "completed"), url);
  }
});

test("URL mode records a legal public CORS wildcard without treating it as a finding", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.end("<!doctype html><p>public</p>");
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings);
    assert.equal(findings.some((finding) => finding.ruleId.startsWith("url.cors-")), false);
    assert.ok(checks[0]?.notes.some((note) => /Observed CORS policy.*wildcard/i.test(note)));
  } finally {
    await close(server);
  }
});

test("URL mode marks wildcard plus credential permission as an unverified CORS candidate", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Credentials", "true");
    response.end("<!doctype html><p>public</p>");
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const finding = checks.flatMap((check) => check.findings).find((item) => item.ruleId === "url.cors-wildcard-credentials");
    assert.ok(finding);
    assert.equal(finding?.kind, "candidate");
    assert.equal(finding?.confidence, "low");
    assert.match(finding?.description ?? "", /does not establish data exposure or a browser bypass/i);
  } finally {
    await close(server);
  }
});

test("URL mode treats an uppercase CORS credential token as invalid", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Credentials", "TRUE");
    response.end("<!doctype html><p>public</p>");
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings);
    assert.equal(findings.some((finding) => finding.ruleId === "url.cors-wildcard-credentials"), false);
    assert.ok(checks[0]?.notes.some((note) => /Observed CORS policy.*credentials not enabled/i.test(note)));
  } finally {
    await close(server);
  }
});

test("URL mode reports source-map and debug references without following their targets", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    if (request.url === "/app.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.setHeader("SourceMap", "https://outside.example/private.map");
      response.end('console.error("Internal Server Error");\n//# sourceMappingURL=https://outside.example/private.map');
      return;
    }
    response.setHeader("Content-Type", "text/html");
    response.end('<!doctype html><script src="/app.js"></script>');
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings);
    assert.ok(findings.some((finding) => finding.ruleId === "url.disclosure-source-map-reference"));
    assert.ok(findings.some((finding) => finding.ruleId === "url.disclosure-source-map-header"));
    assert.ok(findings.some((finding) => finding.ruleId === "url.disclosure-debug-trace"));
    assert.deepEqual(requested.sort(), ["/", "/app.js"]);
    assert.equal(JSON.stringify(checks).includes("private.map"), false);
  } finally {
    await close(server);
  }
});

test("URL mode reports explicit public component versions but ignores ambiguous filenames", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.end('<!doctype html><script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"></script><script src="/assets/react.min.js"></script>');
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings).filter((finding) => finding.ruleId === "url.component-version-clue");
    assert.ok(findings.some((finding) => /React.*18\.2\.0/.test(finding.description)));
    assert.equal(findings.some((finding) => /react\.min\.js/i.test(finding.description)), false);
  } finally {
    await close(server);
  }
});

test("URL mode keeps ordinary Next and React runtime markers as inventory notes", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.end(`<!doctype html>
      <div id="root" data-reactroot></div>
      <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}}}</script>
      <script>window.__next_f = window.__next_f || []; window.webpackJsonp = window.webpackJsonp || []; window.__BUILD_ID__ = "public";</script>`);
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings);
    assert.equal(findings.some((finding) => finding.ruleId === "url.disclosure-framework-runtime"), false);
    assert.ok(checks[0]?.notes.some((note) => /framework runtime marker/i.test(note)));
  } finally {
    await close(server);
  }
});

test("URL mode does not classify public Supabase keys as secrets and distinguishes service keys", async () => {
  const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0.synthetic_signature_value";
  const service = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ.synthetic_service_signature";
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.end(`<!doctype html><script>
      const SUPABASE_ANON_KEY = '${anon}';
      const SUPABASE_SERVICE_ROLE_KEY = '${service}';
      const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_public_fixture_value';
    </script>`);
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings);
    assert.equal(findings.some((finding) => finding.ruleId === "url.secret-jwt-candidate"), false);
    const serviceFinding = findings.find((finding) => finding.ruleId === "url.secret-supabase-service-key");
    assert.ok(serviceFinding);
    assert.equal(serviceFinding?.severity, "high");
    const serialised = JSON.stringify(checks);
    assert.equal(serialised.includes(anon), false);
    assert.equal(serialised.includes(service), false);
  } finally {
    await close(server);
  }
});

test("URL mode keeps neighboring Supabase and generic key classifications local", async () => {
  const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0.neighbor_anon_signature";
  const service = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ.neighbor_service_signature";
  const github = `ghp_${"A1b2C3d4E5f6G7h8I9j0".repeat(2)}`;
  const placeholder = "placeholder_service_value_123456";
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.end(`<!doctype html><script>const config = {
      "SUPABASE_SERVICE_ROLE_KEY": "${service}",
      "SUPABASE_ANON_KEY": "${anon}",
      "SUPABASE_SECRET_KEY": "${placeholder}",
      "SUPABASE_PUBLISHABLE_KEY": "${github}"
    };</script>`);
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 2_000 });
    const findings = checks.flatMap((check) => check.findings);
    const serviceFindings = findings.filter((finding) => finding.ruleId === "url.secret-supabase-service-key");
    assert.equal(serviceFindings.length, 1);
    assert.equal(findings.some((finding) => finding.ruleId === "url.secret-jwt-candidate"), false);
    assert.ok(findings.some((finding) => finding.ruleId === "url.secret-provider-token"));
    assert.ok(findings.some((finding) => finding.ruleId === "url.secret-assignment"));
  } finally {
    await close(server);
  }
});
