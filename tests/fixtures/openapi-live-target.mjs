#!/usr/bin/env node
// Local-only Schemathesis live fixture for tests/fixtures/openapi-live.json.
// `risk`: odd item IDs return a non-string name; quotes or non-ASCII search input
// returns 500. `normal`: always schema-conformant. Writes are never accepted.
import { appendFileSync } from "node:fs";
import { createServer } from "node:http";

const variant = process.argv[2];
if (variant !== "risk" && variant !== "normal") {
  process.stderr.write("usage: openapi-live-target.mjs risk|normal [port]\n");
  process.exit(2);
}
const log = process.env.WAKEIO_FIXTURE_LOG;
const json = (response, status, value) => {
  const body = JSON.stringify(value);
  response.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  response.end(body);
};
const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://fixture.invalid");
  if (log) appendFileSync(log, `${JSON.stringify({ method: request.method, path: url.pathname, encoding: request.headers["accept-encoding"] ?? null })}\n`);
  if (request.method !== "GET") return json(response, 405, { error: "read-only fixture" });
  const item = url.pathname.match(/^\/items\/(-?\d+)$/);
  if (item) {
    const id = Number(item[1]);
    return json(response, 200, { id, name: variant === "risk" && id % 2 === 1 ? id : `item-${id}` });
  }
  if (url.pathname === "/search") {
    const q = url.searchParams.get("q") ?? "";
    if (variant === "risk" && /['"\\]|[^\x00-\x7f]/.test(q)) return json(response, 500, { error: "unhandled" });
    return json(response, 200, { results: [{ id: 1, name: `match-${q.length}` }] });
  }
  return json(response, 404, { error: "not found" });
});
server.listen(Number(process.argv[3] ?? 0), "127.0.0.1", () => process.stdout.write(`${server.address().port}\n`));
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.close(() => process.exit(0)));
