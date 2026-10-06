import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { getEventListeners } from "node:events";
import { runUrl } from "../src/url.js";
import { decodeUrlText } from "../src/url-decoding.js";
import { createReport, exitCode } from "../src/report.js";

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

const marker = "synthetic_collection_secret_482913";

function assertSecret(checks: Awaited<ReturnType<typeof runUrl>>, url: string): void {
  assert.ok(checks.flatMap((check) => check.findings).some((finding) => finding.ruleId === "url.secret-assignment" && finding.location.url === url));
  assert.equal(JSON.stringify(checks).includes(marker), false);
}

test("first document base resolves scripts and inline modules, external imports use their own final URL", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    const path = request.url ?? "";
    requested.push(path);
    response.setHeader("content-type", path.endsWith(".js") ? "application/javascript" : "text/html");
    if (path === "/page/index.html") response.end(`<script src="main.js"></script>
      <base target="_blank"><base href="../assets/"><base href="/ignored/">
      <script type="module">import './inline.js';</script>`);
    else if (path === "/assets/main.js") response.writeHead(302, { location: "/scripts/final.js" }).end();
    else if (path === "/scripts/final.js") response.end(`import './nested.js';`);
    else if (path === "/assets/inline.js") response.end(`const apiKey = '${marker}';`);
    else response.end("export const value = 1;");
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: `${base}/page/index.html`, allowPrivate: true });
    assert.equal(checks[0].status, "completed");
    assert.deepEqual(requested, ["/page/index.html", "/assets/main.js", "/scripts/final.js", "/assets/inline.js", "/scripts/nested.js"]);
    assertSecret(checks, `${base}/assets/inline.js`);
  } finally { await close(server); }
});

test("foreign-namespace base elements do not override the first HTML document base", async () => {
  const cases = [
    { prefix: "<svg><base href='/wrong/'></base></svg>", path: "/page/actual.js" },
    { prefix: "<math><base href='/wrong/'></base></math><base href='/assets/'>", path: "/assets/actual.js" },
    { prefix: "<svg><base href='/wrong/'></base></svg><base href='/assets/'>", path: "/assets/actual.js" },
    { prefix: "<svg><foreignObject><base href='/assets/'></foreignObject></svg>", path: "/assets/actual.js" },
  ];
  for (const entry of cases) {
    const requested: string[] = [];
    const server = createServer((request, response) => {
      requested.push(request.url ?? "");
      response.setHeader("content-type", request.url === "/page/index.html" ? "text/html" : "application/javascript");
      response.end(request.url === "/page/index.html" ? `${entry.prefix}<script src='actual.js'></script>` : `const apiKey = '${marker}';`);
    });
    const base = await listen(server);
    try {
      const checks = await runUrl({ url: `${base}/page/index.html`, allowPrivate: true });
      assert.equal(checks[0].status, "completed");
      assert.deepEqual(requested, ["/page/index.html", entry.path]);
      assertSecret(checks, base + entry.path);
    } finally { await close(server); }
  }
});

test("document base fragments do not change linked-script and inline-module paths", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    response.setHeader("content-type", request.url === "/" ? "text/html" : "application/javascript");
    response.end(request.url === "/" ? "<base href='/assets/#anchor'><script src='actual.js'></script><script type=module>import './inline.js';</script>" : `const apiKey = '${marker}';`);
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, allowPrivate: true });
    assert.equal(checks[0].status, "completed");
    assert.deepEqual(requested, ["/", "/assets/actual.js", "/assets/inline.js"]);
    assertSecret(checks, `${base}/assets/actual.js`);
    assertSecret(checks, `${base}/assets/inline.js`);
  } finally { await close(server); }
});

test("cross-origin document bases never widen collection, including root-relative references", async () => {
  let outsideRequests = 0;
  const outside = createServer((_request, response) => { outsideRequests += 1; response.end("unexpected"); });
  const outsideUrl = await listen(outside);
  const requested: string[] = [];
  let base = "";
  const inside = createServer((request, response) => {
    requested.push(request.url ?? "");
    response.setHeader("content-type", request.url === "/owned.js" ? "application/javascript" : "text/html");
    response.end(request.url === "/owned.js" ? "export const owned = true;" : `<base href="${outsideUrl}/assets/">
      <script src="relative.js"></script><script src="/root.js"></script>
      <script src="${base}/owned.js"></script><script type="module">import './inline.js';</script>`);
  });
  base = await listen(inside);
  try {
    const checks = await runUrl({ url: base, allowPrivate: true });
    assert.equal(outsideRequests, 0);
    assert.deepEqual(requested, ["/", "/owned.js"]);
    assert.equal(checks[0].metrics?.scriptsSkipped, 3);
    assert.ok(checks[0].notes.some((note) => /cross-origin/i.test(note)));
  } finally { await close(inside); await close(outside); }
});

test("invalid first base uses page fallback with partial status and does not accept a later base", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    response.setHeader("content-type", request.url?.endsWith(".js") ? "application/javascript" : "text/html");
    response.end(request.url === "/page/app.js" ? `const apiKey = '${marker}';` :
      `<base href="http://[invalid-secret-marker"><base href="/wrong/"><script src="app.js"></script>`);
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: `${base}/page/index.html`, allowPrivate: true });
    assert.equal(checks[0].status, "partial");
    assert.deepEqual(requested, ["/page/index.html", "/page/app.js"]);
    assert.ok(checks[0].notes.some((note) => /first document base URL/.test(note)));
    assert.equal(JSON.stringify(checks).includes("invalid-secret-marker"), false);
    assertSecret(checks, `${base}/page/app.js`);
  } finally { await close(server); }
});

test("each explicit page has its own base and empty first href wins over later bases", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    response.setHeader("content-type", request.url?.endsWith(".js") ? "application/javascript" : "text/html");
    if (request.url === "/") response.end("<base href='/assets/'><script src='root.js'></script>");
    else if (request.url === "/page/index.html") response.end("<base href=''><base href='/wrong/'><script src='child.js'></script>");
    else response.end("export const okay = true;");
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, pages: ["/page/index.html"], allowPrivate: true });
    assert.equal(checks[0].status, "completed");
    assert.deepEqual(requested, ["/", "/assets/root.js", "/page/index.html", "/page/child.js"]);
  } finally { await close(server); }
});

test("explicit decoding precedence is BOM, HTTP charset, early HTML meta, then UTF-8", () => {
  const body = "<script>const apiKey = 'synthetic_café_secret';</script>";
  const littleEndian = Buffer.from(body, "utf16le");
  const bigEndian = Buffer.from(littleEndian).swap16();
  for (const [bytes, header] of [
    [Buffer.concat([Buffer.from([0xff, 0xfe]), littleEndian]), "text/html; charset=utf-8"],
    [Buffer.concat([Buffer.from([0xfe, 0xff]), bigEndian]), "text/html; charset=windows-1252"],
    [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(body)]), "text/html; charset=unknown"],
    [littleEndian, "text/html; charset=\"utf-16le\""],
    [bigEndian, "text/html; charset=utf-16be"],
    [Buffer.from(body, "latin1"), "text/html; charset=iso-8859-1"],
    [Buffer.from(body), "text/html"],
  ] as const) {
    assert.deepEqual(decodeUrlText(bytes, header, "html"), { text: body, notes: [] });
  }
  for (const meta of ["<meta charset=windows-1252>", "<meta content='text/html; charset=windows-1252' http-equiv=content-type>"]) {
    assert.deepEqual(decodeUrlText(Buffer.from(meta + body, "latin1"), "text/html", "html"), { text: meta + body, notes: [] });
  }
  const misleadingMeta = "<meta charset=windows-1252>" + body;
  assert.deepEqual(decodeUrlText(Buffer.from(misleadingMeta), "text/html; charset=utf-8", "html"), { text: misleadingMeta, notes: [] });
});

test("HTML meta UTF-16 labels and aliases normalize to UTF-8 without losing script collection", async () => {
  for (const label of ["utf-16le", "utf-16be", "utf-16", "unicode", "ucs-2", "unicodefeff", "unicodefffe"]) {
    for (const declaration of [`<meta charset=${label}>`, `<meta http-equiv=content-type content='text/html; charset=${label}'>`]) {
      const unitBody = declaration + "<p>café</p>";
      assert.deepEqual(decodeUrlText(Buffer.from(unitBody), "text/html", "html"), { text: unitBody, notes: [] });
      // The same UTF-16 label from HTTP remains a real UTF-16 declaration.
      const utf16Body = Buffer.from(unitBody, "utf16le");
      assert.deepEqual(decodeUrlText(utf16Body, "text/html; charset=utf-16le", "html"), { text: unitBody, notes: [] });
      assert.deepEqual(decodeUrlText(Buffer.concat([Buffer.from([0xff, 0xfe]), utf16Body]), "text/html; charset=utf-8", "html"), { text: unitBody, notes: [] });

      const requested: string[] = [];
      const server = createServer((request, response) => {
        requested.push(request.url ?? "");
        response.setHeader("content-type", request.url === "/" ? "text/html" : "application/javascript");
        let body = declaration + "<script src='/actual.js'></script>";
        if (body.length % 2) body += " "; // Reproduce the previous silent, valid UTF-16 misdecode.
        response.end(request.url === "/" ? body : `const apiKey = '${marker}';`);
      });
      const base = await listen(server);
      try {
        const checks = await runUrl({ url: base, allowPrivate: true });
        assert.equal(checks[0].status, "completed", declaration);
        assert.deepEqual(requested, ["/", "/actual.js"], declaration);
        assertSecret(checks, `${base}/actual.js`);
      } finally { await close(server); }
    }
  }
});

test("meta charset prescan is bounded and ignores comments, script strings and template content", () => {
  const bodies = [
    "<!-- <meta charset=windows-1252> -->café",
    "<script>const s = '<meta charset=windows-1252>';</script>café",
    "<template><meta charset=windows-1252></template>café",
    " ".repeat(1024) + "<meta charset=windows-1252>café",
  ];
  for (const body of bodies) assert.deepEqual(decodeUrlText(Buffer.from(body), "text/html", "html"), { text: body, notes: [] });
  const notHtml = "<meta charset=windows-1252>café";
  assert.deepEqual(decodeUrlText(Buffer.from(notHtml), "application/javascript", "text"), { text: notHtml, notes: [] });
});

test("unsupported, malformed and ambiguous encoding declarations produce redacted partial notes", () => {
  for (const header of ["text/html; charset=private-encoding-marker", "text/html; charset=", "text/html; charset", "text/html; charset='utf-8", "text/html; charset=utf-8; charset=windows-1252"]) {
    const decoded = decodeUrlText(Buffer.from("<p>okay</p>"), header, "html");
    assert.equal(decoded.text, "<p>okay</p>");
    assert.ok(decoded.notes.some((note) => /unsupported or malformed/.test(note)));
    assert.equal(JSON.stringify(decoded.notes).includes("private-encoding-marker"), false);
  }
  assert.ok(decodeUrlText(Buffer.from([0xff]), "text/html; charset=utf-8", "html").notes.some((note) => /Malformed byte/.test(note)));
  assert.ok(decodeUrlText(Buffer.from([0xff, 0xfe, 0, 0, 65, 0, 0, 0]), undefined, "html").notes.some((note) => /unsupported or malformed/.test(note)));
});

test("encoded HTML and scripts keep findings and decoded URL references", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    if (request.url === "/") {
      response.setHeader("content-type", "text/html; charset=utf-16le");
      response.end(Buffer.from("<base href='/assets/'><script src='café.js'></script>", "utf16le"));
    } else {
      response.setHeader("content-type", "application/javascript; charset=utf-16be");
      response.end(Buffer.from(`const apiKey = '${marker}';`, "utf16le").swap16());
    }
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, allowPrivate: true });
    assert.equal(checks[0].status, "completed");
    assert.deepEqual(requested, ["/", "/assets/caf%C3%A9.js"]);
    assertSecret(checks, `${base}/assets/caf%C3%A9.js`);
  } finally { await close(server); }
});

test("malformed encoding retains observed findings and cannot yield a successful gate", async () => {
  const server = createServer((_request, response) => {
    response.setHeader("content-type", "text/html; charset=unknown-private-charset");
    response.end(Buffer.concat([Buffer.from(`<script>const apiKey = '${marker}';</script>`), Buffer.from([0xff])]));
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, allowPrivate: true });
    assert.equal(checks[0].status, "partial");
    assertSecret(checks, `${base}/`);
    assert.equal(exitCode(createReport(checks, "url", new Date()), "none"), 2);
    assert.equal(JSON.stringify(checks).includes("unknown-private-charset"), false);
  } finally { await close(server); }
});

test("module parser stack failure retains root and script findings and marks coverage partial", async () => {
  const server = createServer((request, response) => {
    response.setHeader("content-type", request.url === "/app.js" ? "application/javascript" : "text/html");
    response.end(request.url === "/app.js" ? `const apiKey = '${marker}';` + "(".repeat(40000) + "x" + ")".repeat(40000) :
      `<script>const apiKey = '${marker}';</script><script src='/app.js'></script>`);
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, allowPrivate: true });
    assert.equal(checks[0].status, "partial");
    assertSecret(checks, `${base}/`);
    assertSecret(checks, `${base}/app.js`);
    assert.ok(checks[0].notes.some((note) => /module parser failed/.test(note)));
  } finally { await close(server); }
});

test("URL pre-cancellation sends no requests and validates cancellation signal", async () => {
  let requests = 0;
  const server = createServer((_request, response) => { requests += 1; response.end("unused"); });
  const base = await listen(server);
  const controller = new AbortController(); controller.abort();
  try {
    const [cancelled] = await runUrl({ url: base, allowPrivate: true, signal: controller.signal });
    assert.equal(cancelled.status, "partial");
    assert.equal(cancelled.metrics?.requestCount, 0);
    assert.ok(cancelled.notes.some((note) => /cancelled/.test(note)));
    const [invalid] = await runUrl({ url: base, allowPrivate: true, signal: {} as AbortSignal });
    assert.equal(invalid.metrics?.errorCode, "invalid_cancellation_signal");
    assert.equal(requests, 0);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  } finally { await close(server); }
});

test("URL cancellation preserves root findings, stops stalled scripts and skips later pages", async () => {
  const controller = new AbortController();
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? "");
    if (request.url === "/stalled.js") { controller.abort(); return; }
    response.setHeader("content-type", "text/html");
    response.end(`<script>const apiKey = '${marker}';</script><script src='/stalled.js'></script><script src='/later.js'></script>`);
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, pages: ["/later-page"], allowPrivate: true, timeoutMs: 30_000, signal: controller.signal });
    assert.equal(checks[0].status, "partial");
    assertSecret(checks, `${base}/`);
    assert.deepEqual(requested, ["/", "/stalled.js"]);
    assert.equal(checks[0].metrics?.scriptsSkipped, 2);
    assert.equal(checks[0].metrics?.pagesSkipped, 1);
    assert.ok(checks[0].notes.some((note) => /was cancelled/.test(note)));
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  } finally { await close(server); }
});

test("URL cancellation listener is removed on success and root network error", async () => {
  const controller = new AbortController();
  const server = createServer((_request, response) => { response.setHeader("content-type", "text/html"); response.end("<p>okay</p>"); });
  const base = await listen(server);
  try {
    assert.equal((await runUrl({ url: base, allowPrivate: true, signal: controller.signal }))[0].status, "completed");
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
    assert.equal((await runUrl({ url: base, signal: controller.signal }))[0].status, "error");
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  } finally { await close(server); }
});

test("external and imported module responses use UTF-8 regardless of HTTP charset", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    const path = request.url ?? "";
    requested.push(path);
    if (path === "/") {
      response.setHeader("content-type", "text/html");
      response.end("<script type=module src='/entry.js'></script>");
    } else if (path === "/entry.js") {
      response.setHeader("content-type", "application/javascript; charset=windows-1252");
      response.end("import './café.js';");
    } else if (path === "/caf%C3%A9.js") {
      response.setHeader("content-type", "application/javascript; charset=utf-16le");
      response.end("export { value } from './次.js';");
    } else {
      response.setHeader("content-type", "application/javascript; charset=unknown-ignored-module-encoding");
      response.end(`export const value = 1; const apiKey = '${marker}';`);
    }
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, allowPrivate: true });
    assert.equal(checks[0].status, "completed");
    assert.deepEqual(requested, ["/", "/entry.js", "/caf%C3%A9.js", "/%E6%AC%A1.js"]);
    assertSecret(checks, `${base}/%E6%AC%A1.js`);
  } finally { await close(server); }
});

test("classic and module references to the same URL retain distinct decoding and shared budgets", async () => {
  const requested: string[] = [];
  const server = createServer((request, response) => {
    const path = request.url ?? "";
    requested.push(path);
    if (path === "/") {
      response.setHeader("content-type", "text/html");
      response.end("<script src='/entry.js'></script><script src='/entry.js'></script><script type=module src='/entry.js'></script><script type=module src='/entry.js'></script>");
    } else {
      response.setHeader("content-type", "application/javascript; charset=windows-1252");
      response.end(path === "/entry.js" ? "import './café.js';" : `const apiKey = '${marker}';`);
    }
  });
  const base = await listen(server);
  try {
    const checks = await runUrl({ url: base, allowPrivate: true });
    assert.equal(checks[0].status, "completed");
    assert.deepEqual(requested, ["/", "/entry.js", "/entry.js", "/caf%C3%83%C2%A9.js", "/caf%C3%A9.js"]);
    assertSecret(checks, `${base}/caf%C3%A9.js`);
    assert.equal(checks[0].metrics?.scriptsFetched, 4);

    requested.length = 0;
    const limited = await runUrl({ url: base, allowPrivate: true, maxScripts: 1 });
    assert.equal(limited[0].status, "partial");
    assert.equal(limited[0].metrics?.scriptsFetched, 1);
    assert.deepEqual(requested, ["/", "/entry.js"]);
  } finally { await close(server); }
});

test("module decoding ignores UTF-16 BOMs and flags malformed UTF-8", () => {
  const text = "export const café = 1;";
  assert.deepEqual(decodeUrlText(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]), "application/javascript; charset=utf-16le", "module"), { text, notes: [] });
  const utf16Bytes = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);
  const malformed = decodeUrlText(utf16Bytes, "application/javascript; charset=utf-16le", "module");
  assert.notEqual(malformed.text, text);
  assert.ok(malformed.notes.some((note) => /Malformed byte/.test(note)));
});
