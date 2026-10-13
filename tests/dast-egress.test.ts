import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request, type IncomingMessage, type Server } from "node:http";
import { createServer as createNetServer, type AddressInfo, type Socket } from "node:net";
import { gzipSync } from "node:zlib";
import { setTimeout as delay } from "node:timers/promises";
import { resolveDastOrigin, startEgressGate, type EgressPolicy } from "../src/dast-egress.js";

interface Seen { method: string; path: string; encoding: string | undefined; host: string | undefined }

async function target(handler: (req: IncomingMessage, res: import("node:http").ServerResponse) => void): Promise<{ server: Server; port: number; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    seen.push({ method: req.method ?? "", path: req.url ?? "", encoding: req.headers["accept-encoding"] as string | undefined, host: req.headers.host });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return { server, port: typeof address === "object" && address ? address.port : 0, seen };
}

function viaProxy(proxyUrl: string, url: string, method = "GET", auth = true): Promise<{ status: number; body: string; headers: IncomingMessage["headers"] }> {
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const req = request({ host: proxy.hostname, port: proxy.port, method, path: url, agent: false,
      headers: auth ? { "proxy-authorization": `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}` } : {} }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString(), headers: res.headers }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

async function gateFor(port: number, overrides: Partial<EgressPolicy> = {}) {
  const controller = new AbortController();
  const { origin, address } = await resolveDastOrigin(`http://127.0.0.1:${port}/`, true, controller.signal);
  const gate = await startEgressGate({ origin, address, methods: new Set(["GET", "HEAD"]), maxRequests: 10,
    maxSingleBodyBytes: 1024, maxTotalBytes: 4096, signal: controller.signal, deadlineAt: Date.now() + 10_000, ...overrides });
  return { gate, controller };
}

test("egress gate forwards only same-origin GET/HEAD with identity encoding and exact counts", async () => {
  const fixture = await target((_req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  const { gate } = await gateFor(fixture.port);
  try {
    const base = `http://127.0.0.1:${fixture.port}`;
    assert.equal((await viaProxy(gate.proxyUrl, `${base}/a?x=1`)).status, 200);
    assert.equal((await viaProxy(gate.proxyUrl, `${base}/b`, "HEAD")).status, 200);
    const otherPort = await viaProxy(gate.proxyUrl, `http://127.0.0.1:${fixture.port + 1}/`);
    assert.equal(otherPort.status, 502);
    assert.equal(otherPort.headers["x-wakeio-egress"], "refused");
    assert.equal(otherPort.body, "");
    assert.equal((await viaProxy(gate.proxyUrl, `${base}/c`, "POST")).status, 405);
    assert.equal((await viaProxy(gate.proxyUrl, `${base}/d`, "GET", false)).status, 407);
    assert.deepEqual(fixture.seen.map((item) => [item.method, item.path, item.encoding, item.host]),
      [["GET", "/a?x=1", "identity", `127.0.0.1:${fixture.port}`], ["HEAD", "/b", "identity", `127.0.0.1:${fixture.port}`]]);
    assert.deepEqual({ ...gate.counters }, { forwarded: 2, tunnels: 0, blockedOrigin: 1, blockedMethod: 1, blockedBudget: 0,
      upstreamErrors: 0, rejectedEncoding: 0, responseBytes: 2 });
    assert.equal(gate.stopReason(), undefined);
  } finally { await gate.close(); fixture.server.close(); }
});

test("egress gate enforces request, single-body and total-body budgets on the wire", async () => {
  const fixture = await target((req, res) => {
    const size = req.url === "/big" ? 2048 : 600;
    res.writeHead(200, { "content-type": "text/plain" }); res.end("x".repeat(size));
  });
  const base = `http://127.0.0.1:${fixture.port}`;
  try {
    const requests = await gateFor(fixture.port, { maxRequests: 2, maxTotalBytes: 1_000_000 });
    const stops: string[] = [];
    requests.gate.onStop((reason) => stops.push(reason));
    await viaProxy(requests.gate.proxyUrl, `${base}/1`);
    await viaProxy(requests.gate.proxyUrl, `${base}/2`);
    assert.equal((await viaProxy(requests.gate.proxyUrl, `${base}/3`)).status, 503);
    assert.deepEqual(stops, ["request_limit"]);
    assert.equal(requests.gate.counters.forwarded, 2);
    assert.equal(requests.gate.counters.blockedBudget, 1);
    await requests.gate.close();

    const single = await gateFor(fixture.port);
    await assert.rejects(viaProxy(single.gate.proxyUrl, `${base}/big`));
    assert.equal(single.gate.stopReason(), "body_limit");
    await single.gate.close();

    const total = await gateFor(fixture.port, { maxTotalBytes: 1000 });
    assert.equal((await viaProxy(total.gate.proxyUrl, `${base}/1`)).status, 200);
    await assert.rejects(viaProxy(total.gate.proxyUrl, `${base}/2`));
    assert.equal(total.gate.stopReason(), "body_limit");
    await total.gate.close();
    assert.equal(fixture.seen.length, 5);
  } finally { fixture.server.close(); }
});

function connectVia(proxyUrl: string, authority: string): Promise<number> {
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const req = request({ host: proxy.hostname, port: proxy.port, method: "CONNECT", path: authority, agent: false,
      headers: { "proxy-authorization": `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}` } });
    req.once("connect", (res, socket) => { socket.destroy(); resolve(res.statusCode ?? 0); });
    req.once("error", reject);
    req.end();
  });
}

test("egress gate caps HTTPS CONNECT tunnels at the request budget and stops", async () => {
  // The gate never terminates TLS, so a plain TCP listener stands in for the HTTPS peer.
  const accepted: Socket[] = [];
  const peer = createNetServer((socket) => { accepted.push(socket); socket.on("error", () => undefined); });
  await new Promise<void>((resolve) => peer.listen(0, "127.0.0.1", resolve));
  const port = (peer.address() as AddressInfo).port;
  const controller = new AbortController();
  const { origin, address } = await resolveDastOrigin(`https://127.0.0.1:${port}/`, true, controller.signal);
  const gate = await startEgressGate({ origin, address, methods: new Set(["GET", "HEAD"]), maxRequests: 2,
    maxSingleBodyBytes: 1024, maxTotalBytes: 4096, signal: controller.signal, deadlineAt: Date.now() + 10_000 });
  const stops: string[] = [];
  gate.onStop((reason) => stops.push(reason));
  try {
    const authority = `127.0.0.1:${port}`;
    assert.equal(await connectVia(gate.proxyUrl, `127.0.0.1:${port + 1}`), 502);
    assert.equal(await connectVia(gate.proxyUrl, authority), 200);
    assert.equal(await connectVia(gate.proxyUrl, authority), 200);
    assert.deepEqual(stops, [], "tunnels within the request budget are not refused");
    assert.equal(await connectVia(gate.proxyUrl, authority), 503);
    assert.equal(await connectVia(gate.proxyUrl, authority), 503);
    assert.deepEqual(stops, ["request_limit"]);
    assert.equal(gate.stopReason(), "request_limit");
    assert.equal(gate.counters.tunnels, 2);
    assert.equal(gate.counters.blockedBudget, 2);
    assert.equal(gate.counters.blockedOrigin, 1);
    assert.equal(gate.counters.forwarded, 0);
  } finally {
    await gate.close();
    for (const socket of accepted) socket.destroy();
    await new Promise<void>((resolve) => peer.close(() => resolve()));
  }
});

test("egress gate counts upstream failures and refuses compressed responses", async () => {
  const fixture = await target((req, res) => {
    if (req.url === "/gzip") { res.writeHead(200, { "content-encoding": "gzip" }); res.end(gzipSync("x".repeat(100))); return; }
    req.socket.destroy();
  });
  const { gate } = await gateFor(fixture.port);
  try {
    const base = `http://127.0.0.1:${fixture.port}`;
    assert.equal((await viaProxy(gate.proxyUrl, `${base}/gzip`)).status, 502);
    await assert.rejects(viaProxy(gate.proxyUrl, `${base}/reset`));
    assert.equal(gate.counters.rejectedEncoding, 1);
    assert.equal(gate.counters.upstreamErrors, 1);
    assert.equal(gate.stopReason(), undefined, "an upstream failure marks the run partial without stopping it");
  } finally { await gate.close(); fixture.server.close(); }
});

test("DAST origin validation reuses URL-network policy before any connection", async () => {
  const signal = new AbortController().signal;
  await assert.rejects(resolveDastOrigin("http://127.0.0.1:9/", false, signal), (error: Error & { code?: string }) => error.code === "blocked_address");
  await assert.rejects(resolveDastOrigin("http://169.254.169.254/", true, signal), (error: Error & { code?: string }) => error.code === "blocked_address");
  await assert.rejects(resolveDastOrigin("http://metadata.google.internal/", true, signal), (error: Error & { code?: string }) => error.code === "metadata_host");
  await assert.rejects(resolveDastOrigin("http://127.0.0.1:9/app", true, signal), /dast_origin_required/);
  await assert.rejects(resolveDastOrigin("http://user:pw@127.0.0.1:9/", true, signal), (error: Error & { code?: string }) => error.code === "userinfo_not_allowed");
  const ok = await resolveDastOrigin("http://127.0.0.1:9/", true, signal);
  assert.deepEqual(ok.address, { address: "127.0.0.1", family: 4 });
});

async function within<T>(promise: Promise<T>, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(message)), 1000);
    })]);
  } finally { clearTimeout(timer); }
}

for (const mode of ["abort", "close", "client disconnect"] as const) {
  for (const streaming of [true, false]) {
    test(`egress gate ${mode} closes the target while ${streaming ? "streaming" : "waiting for headers"}`, { timeout: 5000 }, async () => {
      let received!: () => void, disconnected!: () => void;
      const targetReceived = new Promise<void>((resolve) => { received = resolve; });
      const targetDisconnected = new Promise<void>((resolve) => { disconnected = resolve; });
      let writes: NodeJS.Timeout | undefined;
      const fixture = await target((_req, res) => {
        res.once("close", () => { clearInterval(writes); disconnected(); });
        if (streaming) {
          res.writeHead(200, { "content-type": "text/plain" });
          res.write("x");
          // Activity must not extend the run after cancellation or close.
          writes = setInterval(() => res.write("x"), 10);
        }
        received();
      });
      const { gate, controller } = await gateFor(fixture.port, { maxSingleBodyBytes: 1_000_000, maxTotalBytes: 1_000_000 });
      const proxy = new URL(gate.proxyUrl);
      const client = request({ host: proxy.hostname, port: proxy.port, path: `http://127.0.0.1:${fixture.port}/`, agent: false,
        headers: { "proxy-authorization": `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}` } });
      client.on("error", () => { /* teardown deliberately interrupts this response */ });
      client.end();
      try {
        await within(targetReceived, "target request never started");
        if (streaming) {
          const deadline = Date.now() + 1000;
          while (gate.counters.responseBytes === 0 && Date.now() < deadline) await delay(5);
          assert.ok(gate.counters.responseBytes > 0, "the gate buffered response bytes before teardown");
        }
        if (mode === "abort") controller.abort();
        else if (mode === "close") await gate.close();
        else client.destroy();
        await within(targetDisconnected, "target connection survived teardown");
        const firstClose = gate.close();
        assert.equal(gate.close(), firstClose, "close is idempotent while cleanup is pending");
        await firstClose;
        const bytesAtClose = gate.counters.responseBytes;
        await delay(30);
        assert.equal(gate.counters.responseBytes, bytesAtClose, "no response data is collected after close resolves");
        assert.equal(gate.counters.forwarded, 1);
        assert.equal(gate.counters.upstreamErrors, 0, "intentional cleanup is not a target transport failure");
      } finally {
        client.destroy();
        clearInterval(writes);
        fixture.server.closeAllConnections();
        await gate.close();
        await new Promise<void>((resolve) => fixture.server.close(() => resolve()));
      }
    });
  }
}

test("egress gate already-aborted startup never forwards a target request", async () => {
  const fixture = await target((_req, res) => res.end("unexpected"));
  const controller = new AbortController();
  controller.abort();
  const { gate } = await gateFor(fixture.port, { signal: controller.signal });
  try {
    await assert.rejects(viaProxy(gate.proxyUrl, `http://127.0.0.1:${fixture.port}/`));
    assert.equal(fixture.seen.length, 0);
    assert.equal(gate.counters.forwarded, 0);
  } finally { await gate.close(); fixture.server.close(); }
});

test("egress gate incomplete upstream body remains one transport failure", async () => {
  const fixture = await target((req, res) => {
    res.writeHead(200, { "content-length": "100" });
    res.write("x");
    setTimeout(() => req.socket.destroy(), 20);
  });
  const { gate } = await gateFor(fixture.port);
  try {
    await assert.rejects(viaProxy(gate.proxyUrl, `http://127.0.0.1:${fixture.port}/`));
    assert.equal(gate.counters.upstreamErrors, 1);
    assert.equal(gate.counters.forwarded, 1);
  } finally { await gate.close(); fixture.server.close(); }
});

for (const mode of ["abort", "close", "client disconnect"] as const) {
  test(`egress gate CONNECT ${mode} awaits both tunnel sockets`, { timeout: 5000 }, async () => {
    let disconnected!: () => void;
    const targetDisconnected = new Promise<void>((resolve) => { disconnected = resolve; });
    let peer: Socket | undefined, writes: NodeJS.Timeout | undefined;
    // Synthetic opaque tunnel bytes exercise cleanup without an external host or TLS bypass.
    const server = createNetServer((socket) => {
      peer = socket;
      socket.on("error", () => {});
      socket.once("close", () => { clearInterval(writes); disconnected(); });
      socket.write("x");
      writes = setInterval(() => socket.write("x"), 10);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const controller = new AbortController();
    const resolved = await resolveDastOrigin(`https://127.0.0.1:${port}/`, true, controller.signal);
    const gate = await startEgressGate({ ...resolved, methods: new Set(["GET"]), maxRequests: 1,
      maxSingleBodyBytes: 1024, maxTotalBytes: 4096, signal: controller.signal, deadlineAt: Date.now() + 10_000 });
    const proxy = new URL(gate.proxyUrl);
    const client = request({ host: proxy.hostname, port: proxy.port, method: "CONNECT", path: `127.0.0.1:${port}`, agent: false,
      headers: { "proxy-authorization": `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}` } });
    client.on("error", () => {});
    let tunnel: Socket | undefined;
    const connected = new Promise<void>((resolve) => client.once("connect", (response, socket, head) => {
      assert.equal(response.statusCode, 200);
      tunnel = socket;
      socket.on("error", () => {});
      socket.resume();
      if (head.length) resolve();
      else socket.once("data", () => resolve());
    }));
    client.end();
    try {
      await within(connected, "CONNECT tunnel never relayed target bytes");
      assert.ok(gate.counters.responseBytes > 0);
      if (mode === "abort") controller.abort();
      else if (mode === "close") await gate.close();
      else tunnel!.destroy();
      await within(targetDisconnected, "target tunnel survived teardown");
      await gate.close();
      const bytes = gate.counters.responseBytes;
      await delay(30);
      assert.equal(gate.counters.responseBytes, bytes);
      assert.equal(gate.counters.tunnels, 1);
      assert.equal(gate.counters.upstreamErrors, 0);
    } finally {
      client.destroy(); tunnel?.destroy(); peer?.destroy(); clearInterval(writes);
      await gate.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
}
