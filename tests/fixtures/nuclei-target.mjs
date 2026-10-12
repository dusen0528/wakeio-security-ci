#!/usr/bin/env node
// Local-only Nuclei fixture. `risk` omits browser security headers and exposes a
// synthetic Git config; `normal` sends the headers and exposes nothing else.
// Prints the bound loopback port on stdout and serves until killed.
import { appendFileSync } from "node:fs";
import { createServer } from "node:http";

const variant = process.argv[2];
if (variant !== "risk" && variant !== "normal") {
  process.stderr.write("usage: nuclei-target.mjs risk|normal [port]\n");
  process.exit(2);
}
const port = Number(process.argv[3] ?? 0);
// Optional request log so tests can prove every engine request crossed the egress gate.
const log = process.env.WAKEIO_FIXTURE_LOG;
const SECURITY_HEADERS = {
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-permitted-cross-domain-policies": "none",
  "cross-origin-embedder-policy": "require-corp",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "clear-site-data": "\"cache\"",
};

const server = createServer((request, response) => {
  const headers = variant === "normal" ? { ...SECURITY_HEADERS } : {};
  const path = (request.url ?? "/").split("?")[0];
  if (log) appendFileSync(log, `${JSON.stringify({ method: request.method, path, encoding: request.headers["accept-encoding"] ?? null })}\n`);
  if (variant === "risk" && path === "/.git/config") {
    response.writeHead(200, { ...headers, "content-type": "text/plain" });
    response.end("[core]\n\trepositoryformatversion = 0\n\tbare = false\n");
    return;
  }
  if (path === "/") {
    response.writeHead(200, { ...headers, "content-type": "text/html; charset=utf-8" });
    response.end("<!doctype html><title>wakeio nuclei fixture</title><p>fixture</p>");
    return;
  }
  response.writeHead(404, { ...headers, "content-type": "text/plain" });
  response.end("not found");
});
server.keepAliveTimeout = 1000;
server.listen(port, "127.0.0.1", () => {
  const address = server.address();
  process.stdout.write(`${typeof address === "object" && address ? address.port : port}\n`);
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.close(() => process.exit(0)));
