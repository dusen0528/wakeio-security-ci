import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { runApiPolicy, parseApiPolicy } from "../src/api.js";

const ENV = {
  WAKEIO_OWNER_AUTH: "Bearer owner-fixture-token",
  WAKEIO_OTHER_AUTH: "Bearer other-fixture-token",
};

function policy(baseUrl: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    baseUrl,
    actors: [
      { id: "owner", authorizationEnv: "WAKEIO_OWNER_AUTH" },
      { id: "other", authorizationEnv: "WAKEIO_OTHER_AUTH" },
      { id: "anonymous" },
    ],
    cases: [{
      id: "object-read",
      path: "/documents/test-one",
      allow: { actor: "owner", status: 200, jsonPointer: "/id", equals: "test-one" },
      deny: [
        { actor: "other", statuses: [401, 403, 404] },
        { actor: "anonymous", statuses: [401, 403, 404] },
      ],
    }],
    ...overrides,
  };
}

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

function json(response: ServerResponse, status: number, value: unknown): void {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json");
  response.end(JSON.stringify(value));
}

type Handler = (request: IncomingMessage, response: ServerResponse) => void;

function fixtureServer(handler: Handler): { server: Server; requests: Array<{ path: string; authorization: string | undefined }> } {
  const requests: Array<{ path: string; authorization: string | undefined }> = [];
  const server = createServer((request, response) => {
    requests.push({ path: request.url ?? "", authorization: request.headers.authorization });
    handler(request, response);
  });
  return { server, requests };
}

function policyV2(baseUrl: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 2,
    baseUrl,
    actors: [
      {
        id: "owner",
        authorizationEnv: "WAKEIO_OWNER_AUTH",
        identity: {
          path: "/whoami",
          status: 200,
          jsonPointer: "/userId",
          equals: "owner-user",
          organization: { jsonPointer: "/orgId", equals: "shared-org" },
        },
      },
      {
        id: "other",
        authorizationEnv: "WAKEIO_OTHER_AUTH",
        identity: {
          path: "/whoami",
          status: 200,
          jsonPointer: "/userId",
          equals: "other-user",
          organization: { jsonPointer: "/orgId", equals: "shared-org" },
        },
      },
      { id: "anonymous" },
    ],
    cases: [{
      id: "object-read",
      path: "/documents/test-one",
      allow: {
        actor: "owner",
        status: 200,
        resource: { jsonPointer: "/id", equals: "test-one" },
        protected: { jsonPointer: "/canary", equals: "synthetic-private-canary" },
      },
      deny: [
        { actor: "other", statuses: [401, 403, 404] },
        { actor: "anonymous", statuses: [401, 403, 404] },
      ],
    }],
    ...overrides,
  };
}

function identityResponse(request: IncomingMessage, response: ServerResponse, mode: "normal" | "expired" | "reuse" | "weak" = "normal"): boolean {
  if (request.url !== "/whoami") return false;
  if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) {
    json(response, 200, { userId: "owner-user", orgId: "shared-org" });
  } else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) {
    json(response, mode === "expired" ? 401 : 200, { userId: mode === "reuse" ? "owner-user" : mode === "weak" ? "" : "other-user", orgId: "shared-org" });
  } else {
    json(response, 401, { error: "unauthorized" });
  }
  return true;
}

test("legacy API policy keeps leaked resource IDs partial and credentials out of the result", async () => {
  const fixture = fixtureServer((request, response) => {
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) {
      json(response, 200, { id: "test-one", secret: "fixture-response-secret" });
    } else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) {
      json(response, 403, { id: "test-one", secret: "fixture-response-secret" });
    } else {
      json(response, 401, { error: "unauthorized" });
    }
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policy(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    const check = checks[0];
    assert.equal(check?.status, "partial");
    assert.equal(check?.findings.some((finding) => finding.ruleId === "api.authorization-data-exposure"), false);
    assert.equal(JSON.stringify(checks).includes(ENV.WAKEIO_OWNER_AUTH), false);
    assert.equal(JSON.stringify(checks).includes(ENV.WAKEIO_OTHER_AUTH), false);
    assert.equal(JSON.stringify(checks).includes("fixture-response-secret"), false);
    assert.deepEqual(fixture.requests.map((entry) => entry.authorization), [
      ENV.WAKEIO_OWNER_AUTH,
      ENV.WAKEIO_OTHER_AUTH,
      undefined,
      ENV.WAKEIO_OWNER_AUTH,
    ]);
  } finally {
    await close(fixture.server);
  }
});

test("legacy API policy remains partial for expected denials without identity controls", async () => {
  const fixture = fixtureServer((request, response) => {
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one" });
    else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) json(response, 403, { error: "forbidden" });
    else json(response, 404, { error: "not-found" });
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policy(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.findings.length, 0);
    assert.ok(checks[0]?.notes.some((note) => note.includes("scoped evidence only")));
  } finally {
    await close(fixture.server);
  }
});

test("API policy stops before deny checks when the owner control marker is invalid", async () => {
  const fixture = fixtureServer((_request, response) => json(response, 200, { id: "wrong-fixture" }));
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policy(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.findings.length, 0);
    assert.equal(fixture.requests.length, 1);
    assert.ok(checks[0]?.notes.some((note) => /positive control before failed/.test(note)));
  } finally {
    await close(fixture.server);
  }
});

test("missing credentials are rejected before any request", async () => {
  const fixture = fixtureServer((_request, response) => json(response, 200, { id: "test-one" }));
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policy(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: {} });
    assert.equal(checks[0]?.status, "error");
    assert.equal(fixture.requests.length, 0);
    assert.ok(checks[0]?.notes.some((note) => /no requests were made/.test(note)));
  } finally {
    await close(fixture.server);
  }
});

test("identical owner and deny credentials are rejected before any request", async () => {
  const fixture = fixtureServer((_request, response) => json(response, 200, { id: "test-one" }));
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({
      policy: policy(baseUrl),
      allowPrivate: true,
      timeoutMs: 2_000,
      env: { WAKEIO_OWNER_AUTH: "Bearer same-fixture-token", WAKEIO_OTHER_AUTH: "Bearer same-fixture-token" },
    });
    assert.equal(checks[0]?.status, "error");
    assert.equal(fixture.requests.length, 0);
  } finally {
    await close(fixture.server);
  }
});

test("redirects are rejected and never forward an Authorization header", async () => {
  let redirectedRequests = 0;
  let redirectedAuthorization: string | undefined;
  const fixture = fixtureServer((request, response) => {
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) {
      json(response, 200, { id: "test-one" });
    } else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) {
      response.writeHead(302, { Location: "/redirect-target" });
      response.end();
    } else if (request.url === "/redirect-target") {
      redirectedRequests += 1;
      redirectedAuthorization = request.headers.authorization;
      json(response, 200, { id: "test-one" });
    } else {
      json(response, 401, { error: "unauthorized" });
    }
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policy(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(redirectedRequests, 0);
    assert.equal(redirectedAuthorization, undefined);
    assert.ok(checks[0]?.notes.some((note) => /redirect_rejected/.test(note)));
  } finally {
    await close(fixture.server);
  }
});

test("429 and non-JSON responses remain incomplete even when listed as deny statuses", async () => {
  const fixture = fixtureServer((request, response) => {
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one" });
    else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) {
      response.statusCode = 429;
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ id: "test-one" }));
    } else {
      response.setHeader("Content-Type", "text/html");
      response.statusCode = 403;
      response.end("<html>forbidden</html>");
    }
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({
      policy: policy(baseUrl, {
        cases: [{
          id: "rate-limited",
          path: "/documents/test-one",
          allow: { actor: "owner", status: 200, jsonPointer: "/id", equals: "test-one" },
          deny: [
            { actor: "other", statuses: [429] },
            { actor: "anonymous", statuses: [403] },
          ],
        }],
      }),
      allowPrivate: true,
      timeoutMs: 2_000,
      env: ENV,
    });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.findings.length, 0);
  } finally {
    await close(fixture.server);
  }
});

test("malformed JSON, wrong-marker success, 5xx, and unexpected 4xx remain incomplete", async () => {
  let mode: "malformed" | "wrong-marker" | "server-error" | "unexpected-status" = "malformed";
  const fixture = fixtureServer((request, response) => {
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) {
      json(response, 200, { id: "test-one" });
    } else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) {
      if (mode === "malformed") {
        response.statusCode = 403;
        response.setHeader("Content-Type", "application/json");
        response.end("{ malformed");
      } else if (mode === "wrong-marker") {
        json(response, 200, { id: "another-object" });
      } else if (mode === "server-error") {
        json(response, 503, { error: "temporarily unavailable" });
      } else {
        json(response, 400, { error: "unexpected request" });
      }
    } else {
      json(response, 403, { error: "forbidden" });
    }
  });
  const baseUrl = await listen(fixture.server);
  try {
    for (const nextMode of ["malformed", "wrong-marker", "server-error", "unexpected-status"] as const) {
      mode = nextMode;
      const checks = await runApiPolicy({
        policy: policy(baseUrl, {
          cases: [{
            id: `inconclusive-${nextMode}`,
            path: "/documents/test-one",
            allow: { actor: "owner", status: 200, jsonPointer: "/id", equals: "test-one" },
            deny: [{ actor: "other", statuses: [403] }, { actor: "anonymous", statuses: [403] }],
          }],
        }),
        allowPrivate: true,
        timeoutMs: 2_000,
        env: ENV,
      });
      assert.equal(checks[0]?.status, "partial", nextMode);
      assert.equal(checks[0]?.findings.length, 0, nextMode);
    }
  } finally {
    await close(fixture.server);
  }
});

test("malformed policy, duplicate IDs, and an over-budget policy make no requests", async () => {
  const fixture = fixtureServer((_request, response) => json(response, 200, { id: "test-one" }));
  const baseUrl = await listen(fixture.server);
  try {
    const unknown = await runApiPolicy({ policy: { ...policy(baseUrl), extra: true }, allowPrivate: true, env: ENV });
    assert.equal(unknown[0]?.status, "error");
    const duplicateActors = await runApiPolicy({
      policy: policy(baseUrl, { actors: [{ id: "owner", authorizationEnv: "WAKEIO_OWNER_AUTH" }, { id: "owner", authorizationEnv: "WAKEIO_OTHER_AUTH" }] }),
      allowPrivate: true,
      env: ENV,
    });
    assert.equal(duplicateActors[0]?.status, "error");
    const duplicateCases = [
      { id: "same", path: "/a", allow: { actor: "owner", status: 200, jsonPointer: "/id", equals: "test-one" }, deny: [{ actor: "other", statuses: [403] }] },
      { id: "same", path: "/b", allow: { actor: "owner", status: 200, jsonPointer: "/id", equals: "test-one" }, deny: [{ actor: "other", statuses: [403] }] },
    ];
    const duplicateCaseResult = await runApiPolicy({ policy: policy(baseUrl, { cases: duplicateCases }), allowPrivate: true, env: ENV });
    assert.equal(duplicateCaseResult[0]?.status, "error");
    const tooManyRequests = Array.from({ length: 20 }, (_, index) => ({
      id: `case-${index}`,
      path: `/documents/${index}`,
      allow: { actor: "owner", status: 200, jsonPointer: "/id", equals: "test-one" },
      deny: [{ actor: "other", statuses: [403] }, { actor: "anonymous", statuses: [401] }],
    }));
    const overBudget = await runApiPolicy({ policy: policy(baseUrl, { cases: tooManyRequests }), allowPrivate: true, env: ENV });
    assert.equal(overBudget[0]?.status, "error");
    assert.equal(fixture.requests.length, 0);
  } finally {
    await close(fixture.server);
  }
});

test("timeout leaves the API preview incomplete", async () => {
  const fixture = fixtureServer((_request, response) => {
    setTimeout(() => json(response, 200, { id: "test-one" }), 100);
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policy(baseUrl), allowPrivate: true, timeoutMs: 20, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.findings.length, 0);
  } finally {
    await close(fixture.server);
  }
});

test("an oversized response stops the remaining policy requests", async () => {
  const fixture = fixtureServer((_request, response) => {
    response.statusCode = 200;
    response.setHeader("Content-Type", "application/json");
    response.end(`{"id":"test-one","padding":"${"x".repeat(2 * 1024 * 1024)}"}`);
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policy(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(fixture.requests.length, 1);
    assert.equal(checks[0]?.metrics?.bytesInspected, 0);
    assert.equal(checks[0]?.metrics?.bodyBudgetExhausted, true);
    assert.equal(checks[0]?.metrics?.bodyReadIncomplete, true);
  } finally {
    await close(fixture.server);
  }
});

test("parseApiPolicy is synchronous and does not resolve or request the target", () => {
  const parsed = parseApiPolicy(policy("http://127.0.0.1:12345"));
  assert.equal(parsed.expectedRequests, 4);
  assert.equal(new URL(parsed.cases[0]?.requestUrl.href ?? "http://invalid").pathname, "/documents/test-one");
});

test("v2 API policy records a protected canary exposure after distinct identity controls", async () => {
  const fixture = fixtureServer((request, response) => {
    if (identityResponse(request, response)) return;
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one", canary: "synthetic-private-canary" });
    else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) json(response, 403, { id: "test-one", canary: "synthetic-private-canary" });
    else json(response, 401, { error: "unauthorized" });
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policyV2(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "completed");
    assert.equal(checks[0]?.findings.filter((finding) => finding.ruleId === "api.authorization-data-exposure").length, 1);
    assert.equal(checks[0]?.metrics?.identityControlsPassed, 2);
    assert.equal(checks[0]?.metrics?.expectedRequestCount, 8);
    assert.equal(fixture.requests.length, 8);
    assert.equal(JSON.stringify(checks).includes("synthetic-private-canary"), false);
    assert.equal(JSON.stringify(checks).includes(ENV.WAKEIO_OWNER_AUTH), false);
    assert.equal(JSON.stringify(checks).includes(ENV.WAKEIO_OTHER_AUTH), false);
  } finally {
    await close(fixture.server);
  }
});

test("v2 API policy completes for normal denials when both principals and the owner controls pass", async () => {
  const fixture = fixtureServer((request, response) => {
    if (identityResponse(request, response)) return;
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one", canary: "synthetic-private-canary" });
    else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) json(response, 403, { error: "forbidden" });
    else json(response, 404, { error: "not-found" });
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policyV2(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "completed");
    assert.equal(checks[0]?.findings.length, 0);
    assert.equal(checks[0]?.metrics?.identityControlsPassed, 2);
  } finally {
    await close(fixture.server);
  }
});

test("an expired authenticated actor remains partial even when its 401 is listed", async () => {
  const fixture = fixtureServer((request, response) => {
    if (identityResponse(request, response, "expired")) return;
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one", canary: "synthetic-private-canary" });
    else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) json(response, 401, { error: "expired" });
    else json(response, 401, { error: "unauthorized" });
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policyV2(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.findings.length, 0);
    assert.ok(checks[0]?.notes.some((note) => note.includes("actor other") && note.includes("identity positive control failed")));
  } finally {
    await close(fixture.server);
  }
});

test("different tokens that resolve to the same principal remain partial, while a shared organization is allowed", async () => {
  const fixture = fixtureServer((request, response) => {
    if (identityResponse(request, response, "reuse")) return;
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one", canary: "synthetic-private-canary" });
    else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) json(response, 403, { error: "forbidden" });
    else json(response, 401, { error: "unauthorized" });
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policyV2(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.findings.length, 0);
    assert.ok(checks[0]?.notes.some((note) => note.includes("same principal identity")));
  } finally {
    await close(fixture.server);
  }
});

test("an ID-only denial echo is weak evidence and never a protected-data finding", async () => {
  const fixture = fixtureServer((request, response) => {
    if (identityResponse(request, response)) return;
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one", canary: "synthetic-private-canary" });
    else if (request.headers.authorization === ENV.WAKEIO_OTHER_AUTH) json(response, 403, { id: "test-one" });
    else json(response, 401, { error: "unauthorized" });
  });
  const baseUrl = await listen(fixture.server);
  try {
    const checks = await runApiPolicy({ policy: policyV2(baseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "completed");
    assert.equal(checks[0]?.findings.length, 0);
    assert.ok(checks[0]?.notes.some((note) => note.includes("weak authorization evidence")));
  } finally {
    await close(fixture.server);
  }
});

test("a policy-declared empty-body denial is accepted only with verified identity", async () => {
  const fixture = fixtureServer((request, response) => {
    if (identityResponse(request, response)) return;
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one", canary: "synthetic-private-canary" });
    else response.writeHead(request.headers.authorization ? 403 : 401, { "Content-Type": "application/json" }).end();
  });
  const baseUrl = await listen(fixture.server);
  try {
    const configured = policyV2(baseUrl, {
      cases: [{
        id: "empty-denial",
        path: "/documents/test-one",
        allow: { actor: "owner", status: 200, resource: { jsonPointer: "/id", equals: "test-one" }, protected: { jsonPointer: "/canary", equals: "synthetic-private-canary" } },
        deny: [{ actor: "other", statuses: [403], allowEmptyBody: true }, { actor: "anonymous", statuses: [401], allowEmptyBody: true }],
      }],
    });
    const checks = await runApiPolicy({ policy: configured, allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "completed");
    assert.equal(checks[0]?.findings.length, 0);
    assert.ok(checks[0]?.notes.some((note) => note.includes("allowed empty-body denial")));
  } finally {
    await close(fixture.server);
  }
});

test("weak protected canaries and weak principal markers are rejected or remain partial", async () => {
  const fixture = fixtureServer((_request, response) => json(response, 200, { id: "test-one", canary: "synthetic-private-canary" }));
  const baseUrl = await listen(fixture.server);
  try {
    const weakCanary = policyV2(baseUrl, {
      cases: [{
        id: "weak-canary",
        path: "/documents/test-one",
        allow: { actor: "owner", status: 200, resource: { jsonPointer: "/id", equals: "test-one" }, protected: { jsonPointer: "/canary", equals: "" } },
        deny: [{ actor: "other", statuses: [403] }],
      }],
    });
    const rejected = await runApiPolicy({ policy: weakCanary, allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(rejected[0]?.status, "error");
    assert.equal(fixture.requests.length, 0);
  } finally {
    await close(fixture.server);
  }

  const weakFixture = fixtureServer((request, response) => {
    if (identityResponse(request, response, "weak")) return;
    if (request.headers.authorization === ENV.WAKEIO_OWNER_AUTH) json(response, 200, { id: "test-one", canary: "synthetic-private-canary" });
    else json(response, 403, { error: "forbidden" });
  });
  const weakBaseUrl = await listen(weakFixture.server);
  try {
    const checks = await runApiPolicy({ policy: policyV2(weakBaseUrl), allowPrivate: true, timeoutMs: 2_000, env: ENV });
    assert.equal(checks[0]?.status, "partial");
    assert.equal(checks[0]?.findings.length, 0);
    assert.ok(checks[0]?.notes.some((note) => note.includes("principal marker mismatch")));
  } finally {
    await close(weakFixture.server);
  }
});
