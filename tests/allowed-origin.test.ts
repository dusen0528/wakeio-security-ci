import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, parseCliArgs, type CliOptions } from "../src/cli.js";

function parsed(argv: string[]): CliOptions {
  const options = parseCliArgs(argv);
  assert.equal("help" in options, false);
  return options as CliOptions;
}

test("--allowed-origin accepts canonical http(s) origins only", () => {
  const options = parsed(["scan", "--url", "https://staging.example.test/app", "--allowed-origin", "https://Staging.Example.test:443/",
    "--allowed-origin=http://127.0.0.1:8080", "--allowed-origin", "https://staging.example.test"]);
  assert.deepEqual(options.allowedOrigins, ["https://staging.example.test", "http://127.0.0.1:8080"]);
  assert.deepEqual(parsed(["scan", "--url", "https://a.example.test"]).allowedOrigins, [], "unrestricted by default");
  for (const bad of ["https://staging.example.test/api", "https://staging.example.test/?x=1", "https://staging.example.test/#f",
    "https://user:pw@staging.example.test", "ftp://staging.example.test", "staging.example.test"]) {
    assert.throws(() => parseCliArgs(["scan", "--url", "https://staging.example.test", "--allowed-origin", bad]), /--allowed-origin must be/, bad);
  }
  const many = Array.from({ length: 17 }, (_, index) => ["--allowed-origin", `https://h${index}.example.test`]).flat();
  assert.throws(() => parseCliArgs(["scan", "--url", "https://h0.example.test", ...many]), /at most 16/);
});

test("--allowed-origin refuses an unlisted --url or --api-base before any request", () => {
  assert.throws(() => parseCliArgs(["scan", "--url", "https://prod.example.test/", "--allowed-origin", "https://staging.example.test"]), /--url origin/);
  assert.throws(() => parseCliArgs(["scan", "--url", "http://staging.example.test/", "--allowed-origin", "https://staging.example.test"]), /--url origin/, "scheme is part of the origin");
  assert.throws(() => parseCliArgs(["scan", "--openapi", "o.json", "--api-base", "https://prod.example.test", "--operation", "/items",
    "--active-consent", "--allowed-origin", "https://staging.example.test"]), /--api-base origin/);
  assert.throws(() => parseCliArgs(["scan", "--source", ".", "--allowed-origin", "https://staging.example.test"]), /requires URL or API mode/);
  assert.equal(parsed(["scan", "--openapi", "o.json", "--api-base", "https://staging.example.test", "--operation", "/items",
    "--active-consent", "--allowed-origin", "https://staging.example.test"]).apiBase, "https://staging.example.test");
});

test("an API policy whose baseUrl is outside --allowed-origin sends no request and is incomplete", async () => {
  let requests = 0;
  const server = createServer((request, response) => {
    requests += 1;
    const owner = request.headers.authorization === "Bearer allowed-origin-owner";
    if (request.url === "/whoami") return response.writeHead(owner ? 200 : 401, { "content-type": "application/json" }).end(JSON.stringify({ userId: "owner" }));
    return response.writeHead(owner ? 200 : 403, { "content-type": "application/json" }).end(JSON.stringify(owner ? { id: "doc", canary: "c" } : { error: "denied" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const root = await mkdtemp(join(tmpdir(), "wakeio-allowed-origin-"));
  process.env.ALLOWED_ORIGIN_OWNER_AUTH = "Bearer allowed-origin-owner";
  try {
    const policyPath = join(root, "policy.json");
    await writeFile(policyPath, JSON.stringify({
      version: 2, baseUrl: `http://127.0.0.1:${port}`,
      actors: [{ id: "owner", authorizationEnv: "ALLOWED_ORIGIN_OWNER_AUTH", identity: { path: "/whoami", status: 200, jsonPointer: "/userId", equals: "owner" } }, { id: "anonymous" }],
      cases: [{ id: "doc", path: "/doc", allow: { actor: "owner", status: 200, resource: { jsonPointer: "/id", equals: "doc" }, protected: { jsonPointer: "/canary", equals: "c" } },
        deny: [{ actor: "anonymous", statuses: [403] }] }],
    }));
    const refusedOut = join(root, "refused");
    assert.equal(await main(["scan", "--api-policy", policyPath, "--allow-private", "--allowed-origin", "https://staging.example.test", "--out", refusedOut]), 2);
    assert.equal(requests, 0, "the refused policy reached the target");
    const report = JSON.parse(await readFile(join(refusedOut, "report.json"), "utf8"));
    assert.deepEqual(report.checks.map((check: { id: string; status: string }) => [check.id, check.status]), [["api.authorization", "error"]]);

    assert.equal(await main(["scan", "--api-policy", policyPath, "--allow-private", "--allowed-origin", `http://127.0.0.1:${port}`, "--out", join(root, "allowed")]), 0);
    assert.ok(requests > 0, "a listed policy origin is scanned");
  } finally {
    delete process.env.ALLOWED_ORIGIN_OWNER_AUTH;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
});
