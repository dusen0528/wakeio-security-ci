import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type ServerResponse } from "node:http";
import {
  buildOpenApiPolicy,
  runOpenApiPolicy,
  OpenApiPolicyError,
  OPENAPI_MAX_INPUT_BYTES,
  OPENAPI_MAX_INPUT_NODES,
  OPENAPI_MAX_REFERENCES,
  type OpenApiPolicyInput,
  type OpenApiRunOptions,
  type OpenApiOperationSelection,
  type OpenApiPolicyCase,
  type OpenApiPathValue,
} from "../src/index.js";
import { parseApiPolicy } from "../src/api.js";

const ENV = { OPENAPI_OWNER_AUTH: "Bearer synthetic-owner-token", OPENAPI_OTHER_AUTH: "Bearer synthetic-other-token" };
const CANARY = "openapi-synthetic-private-canary";
type JsonObject = Record<string, any>;

function input(baseUrl = "https://fixture.example.test"): OpenApiPolicyInput {
  const operations: OpenApiOperationSelection[] = [
    { id: "identity", method: "GET", path: "/whoami", operationId: "readIdentity" },
    { id: "document", method: "GET", path: "/documents/{id}", operationId: "readDocument", pathParameters: { id: "fixture-a" } },
  ];
  const cases: OpenApiPolicyCase[] = [{
    id: "document-read", operation: "document",
    allow: { actor: "owner", status: 200, resource: { jsonPointer: "/id", equals: "fixture-a" }, protected: { jsonPointer: "/private", equals: CANARY } },
    deny: [{ actor: "other", statuses: [403] }, { actor: "anonymous", statuses: [401] }],
  }];
  return {
    document: {
      openapi: "3.1.0", info: { title: "Owned synthetic API", version: "1.0.0" },
      servers: [{ url: "https://ignored.example.test/never-use" }],
      paths: {
        "/whoami": { get: { operationId: "readIdentity", responses: { "200": { description: "Identity" } } } },
        "/documents/{id}": {
          parameters: [{ $ref: "#/components/parameters/DocumentId" }],
          get: { operationId: "readDocument", responses: { "200": { description: "Document" } } },
          post: { operationId: "neverWrite", requestBody: { required: true } },
        },
        "/unselected": { get: { operationId: "neverRead", responses: {} } },
      },
      components: { parameters: { DocumentId: { name: "id", in: "path", required: true, schema: { $ref: "#/components/schemas/Id" } } }, schemas: { Id: { type: "string" } } },
    },
    baseUrl,
    actors: [
      { id: "owner", authorizationEnv: "OPENAPI_OWNER_AUTH", identity: { path: "/whoami", status: 200, jsonPointer: "/user", equals: "owner" } },
      { id: "other", authorizationEnv: "OPENAPI_OTHER_AUTH", identity: { path: "/whoami", status: 200, jsonPointer: "/user", equals: "other" } },
      { id: "anonymous" },
    ], operations, cases,
  };
}

function document(value: OpenApiPolicyInput): JsonObject { return value.document as JsonObject; }
function parameter(value: OpenApiPolicyInput): JsonObject { return document(value).components.parameters.DocumentId; }
function schema(value: OpenApiPolicyInput): JsonObject { return document(value).components.schemas.Id; }

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
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(value));
}
function fixture(mode: "fixed" | "vulnerable" | "expired" | "wrong-owner" | "redirect" | "slow" | "oversized" = "fixed") {
  const requests: Array<{ path: string; method: string; authorization: string | undefined }> = [];
  const server = createServer((request, response) => {
    const authorization = request.headers.authorization;
    requests.push({ path: request.url ?? "", method: request.method ?? "", authorization });
    if (mode === "slow") return;
    if (mode === "oversized") { response.writeHead(200, { "Content-Type": "application/json" }); response.end(`"${"x".repeat(3 * 1024 * 1024)}"`); return; }
    if (request.url === "/whoami") {
      if (authorization === ENV.OPENAPI_OWNER_AUTH) json(response, 200, { user: "owner" });
      else if (authorization === ENV.OPENAPI_OTHER_AUTH) json(response, mode === "expired" ? 401 : 200, { user: "other" });
      else json(response, 401, { error: "unauthorized" });
    } else if (request.url === "/documents/fixture-a") {
      if (authorization === ENV.OPENAPI_OWNER_AUTH) json(response, 200, { id: mode === "wrong-owner" ? "wrong" : "fixture-a", private: CANARY });
      else if (authorization === ENV.OPENAPI_OTHER_AUTH) {
        if (mode === "redirect") { response.writeHead(302, { Location: "/unselected" }); response.end(); }
        else json(response, 403, mode === "vulnerable" ? { private: CANARY } : { error: "denied" });
      } else json(response, 401, { error: "unauthorized" });
    } else json(response, 500, { error: "unselected request" });
  });
  return { server, requests };
}

test("OpenAPI public compiler deterministically emits v2 with explicit origin, bindings and assertions", () => {
  const source = input();
  const before = JSON.stringify(source);
  const compiled = buildOpenApiPolicy(source);
  assert.equal(compiled.version, 2);
  assert.equal(compiled.baseUrl, "https://fixture.example.test/");
  assert.equal(compiled.cases[0]!.path, "/documents/fixture-a");
  assert.deepEqual(compiled.cases[0]!.allow, source.cases[0]!.allow);
  assert.equal(parseApiPolicy(compiled).expectedRequests, 8);
  assert.equal(JSON.stringify(source), before);
  assert.deepEqual(compiled, buildOpenApiPolicy(source));
  source.cases[0]!.allow.protected.equals = "changed-after-compilation";
  assert.equal(compiled.cases[0]!.allow.protected.equals, CANARY);
});

test("OpenAPI compiler supports local path-item, parameter and escaped-pointer schema references", () => {
  const source = input();
  const doc = document(source);
  doc.openapi = "3.0.3";
  doc.components.pathItems = { Identity: doc.paths["/whoami"] };
  doc.paths["/whoami"] = { $ref: "#/components/pathItems/Identity" };
  doc.components.schemas["ID/with~escape"] = { type: "string" };
  parameter(source).schema.$ref = "#/components/schemas/ID~1with~0escape";
  assert.equal(buildOpenApiPolicy(source).cases[0]!.path, "/documents/fixture-a");
});

test("operation-level parameter overrides take precedence and optional non-path parameters are omitted", () => {
  const source = input();
  schema(source).type = "integer";
  document(source).paths["/documents/{id}"].get.parameters = [
    { name: "id", in: "path", required: true, schema: { type: "string", enum: ["fixture-a"] }, style: "simple", explode: false },
    { name: "filter", in: "query", required: false, schema: { type: "array" } },
  ];
  assert.equal(buildOpenApiPolicy(source).cases[0]!.path, "/documents/fixture-a");
});

test("finite primitive synthetic path bindings are accepted without schema-derived generation", () => {
  const examples: Array<[string, OpenApiPathValue, string]> = [["integer", 7, "7"], ["number", -1.5, "-1.5"], ["boolean", false, "false"], ["string", "fixture_a-1", "fixture_a-1"]];
  for (const [type, value, text] of examples) {
    const source = input();
    schema(source).type = type;
    source.operations[1]!.pathParameters = { id: value };
    assert.equal(buildOpenApiPolicy(source).cases[0]!.path, `/documents/${text}`);
  }
  const noBindings = input();
  schema(noBindings).default = "fixture-a";
  delete noBindings.operations[1]!.pathParameters;
  assert.throws(() => buildOpenApiPolicy(noBindings));
});

test("OpenAPI compiler fails closed on non-GET, missing selections and identity paths outside the allowlist", () => {
  const mutations: Array<(value: OpenApiPolicyInput) => void> = [
    (value) => { (value.operations[1] as JsonObject).method = "POST"; },
    (value) => { delete document(value).paths["/documents/{id}"].get; },
    (value) => { value.operations[1]!.operationId = "neverWrite"; },
    (value) => { value.operations[1]!.path = "/missing"; },
    (value) => { value.operations[1]!.id = value.operations[0]!.id; },
    (value) => { value.cases[0]!.operation = "missing"; },
    (value) => { value.operations.shift(); },
    (value) => { value.actors[0]!.identity!.path = "/unselected"; },
    (value) => { (value.operations[0] as JsonObject).automaticDiscovery = true; },
    (value) => { (value as unknown as JsonObject).version = 1; },
    (value) => { value.operations.push({ ...value.operations[1]!, id: "duplicate" }); },
    (value) => { value.baseUrl = "https://fixture.example.test/prefix"; },
    (value) => { value.baseUrl = "https://fixture.example.test/?query=1"; },
    (value) => { value.baseUrl = "https://user:password@fixture.example.test"; },
    (value) => { document(value).openapi = "2.0"; },
  ];
  for (const mutate of mutations) { const source = input(); mutate(source); assert.throws(() => buildOpenApiPolicy(source), OpenApiPolicyError); }
});

test("OpenAPI compiler rejects unsupported request semantics, duplicate parameters and invalid bindings", () => {
  const mutations: Array<(value: OpenApiPolicyInput) => void> = [
    (value) => { document(value).paths["/documents/{id}"].get.requestBody = {}; },
    (value) => { document(value).paths["/documents/{id}"].get.callbacks = {}; },
    (value) => { parameter(value).style = "matrix"; },
    (value) => { parameter(value).explode = true; },
    (value) => { parameter(value).allowReserved = true; },
    (value) => { parameter(value).content = {}; },
    (value) => { parameter(value).required = false; },
    (value) => { parameter(value).name = "extra"; },
    (value) => { document(value).paths["/documents/{id}"].parameters.push({ $ref: "#/components/parameters/DocumentId" }); },
    (value) => { sourceRequired(value, "query"); },
    (value) => { sourceRequired(value, "header"); },
    (value) => { sourceRequired(value, "cookie"); },
    (value) => { schema(value).type = "object"; },
    (value) => { schema(value).pattern = "(a+)+$"; },
    (value) => { schema(value).enum = ["other"] ; },
    (value) => { schema(value).type = "integer"; },
    (value) => { value.operations[1]!.pathParameters = { id: "fixture-a", extra: "unused" }; },
    (value) => { value.operations[1]!.pathParameters = {}; },
    (value) => { delete document(value).paths["/documents/{id}"].parameters; },
  ];
  for (const mutate of mutations) { const source = input(); mutate(source); assert.throws(() => buildOpenApiPolicy(source)); }
  function sourceRequired(value: OpenApiPolicyInput, location: string) {
    document(value).paths["/documents/{id}"].get.parameters = [{ name: "required-input", in: location, required: true, schema: { type: "string" } }];
  }
});

test("path binding and template validation rejects traversal, percent encoding and route ambiguity", () => {
  for (const value of ["", ".", "..", "../else", "a/b", "a\\b", "%2e%2e", "%252f", "?q=1", "#fragment", "a\u0000b", "café", "x".repeat(129)]) {
    const source = input(); source.operations[1]!.pathParameters = { id: value };
    assert.throws(() => buildOpenApiPolicy(source));
  }
  for (const path of ["//else.test/path", "/documents/../{id}", "/documents/%2e%2e/{id}", "/documents/{id}?q=1", "/documents/id-{id}", "/documents//{id}"]) {
    const source = input(); const doc = document(source);
    doc.paths[path] = doc.paths["/documents/{id}"]; delete doc.paths["/documents/{id}"];
    source.operations[1]!.path = path;
    assert.throws(() => buildOpenApiPolicy(source));
  }
  for (const other of ["/documents/fixture-a", "/documents/{other}", "/{collection}/fixture-a"]) {
    const source = input(); document(source).paths[other] = { get: {} };
    assert.throws(() => buildOpenApiPolicy(source), /ambiguous/);
  }
});

test("all references are local, own-property JSON pointers with no cycles or ambiguous siblings", () => {
  for (const ref of ["https://127.0.0.1/openapi.json", "file:///tmp/openapi.json", "./schema.json#/Id", "#/components/schemas/Missing", "#/toString", "#/components/schemas/Id~2", "#/components/schemas/%49d", "#", "#anchor"]) {
    const source = input(); parameter(source).schema.$ref = ref;
    assert.throws(() => buildOpenApiPolicy(source));
  }
  const siblings = input(); parameter(siblings).schema.description = "ambiguous";
  assert.throws(() => buildOpenApiPolicy(siblings));
  const direct = input(); document(direct).components.schemas.Id = { $ref: "#/components/schemas/Id" };
  assert.throws(() => buildOpenApiPolicy(direct), /Cyclic/);
  const nested = input(); schema(nested).properties = { child: { $ref: "#/components/schemas/Id" } };
  assert.throws(() => buildOpenApiPolicy(nested), /Cyclic/);
  const unused = input(); document(unused).components.schemas.Unused = { $ref: "https://never-fetch.example.test" };
  assert.throws(() => buildOpenApiPolicy(unused));
});

test("JSON input snapshot rejects executable, cyclic, inherited, sparse and non-JSON data without invoking getters", () => {
  let invoked = 0;
  const accessor = input();
  Object.defineProperty(document(accessor), "description", { enumerable: true, get() { invoked++; return "must not run"; } });
  assert.throws(() => buildOpenApiPolicy(accessor));
  assert.equal(invoked, 0);
  const cyclic = input(); document(cyclic).cycle = cyclic.document;
  assert.throws(() => buildOpenApiPolicy(cyclic));
  const inherited = input(); Object.setPrototypeOf(parameter(inherited), { required: true });
  assert.throws(() => buildOpenApiPolicy(inherited));
  const sparse = input(); document(sparse).data = new Array(3);
  assert.throws(() => buildOpenApiPolicy(sparse));
  for (const value of [undefined, () => {}, NaN, Infinity, 1n, new Date(), Symbol("invalid")]) {
    const source = input(); document(source).data = value;
    assert.throws(() => buildOpenApiPolicy(source));
  }
});

test("OpenAPI compilation bounds bytes, nodes, depth, references, cases and planned requests", () => {
  const bytes = input(); document(bytes).description = "x".repeat(OPENAPI_MAX_INPUT_BYTES);
  assert.throws(() => buildOpenApiPolicy(bytes), (error: unknown) => error instanceof OpenApiPolicyError && error.code === "openapi_limit");
  const escaped = input(); document(escaped).description = "\u0000".repeat(OPENAPI_MAX_INPUT_BYTES / 4);
  assert.throws(() => buildOpenApiPolicy(escaped), (error: unknown) => error instanceof OpenApiPolicyError && error.code === "openapi_limit");
  const nodes = input(); document(nodes).data = Array.from({ length: OPENAPI_MAX_INPUT_NODES }, () => null);
  assert.throws(() => buildOpenApiPolicy(nodes));
  const depth = input(); let current = document(depth); for (let i = 0; i < 50; i++) { current.child = {}; current = current.child; }
  assert.throws(() => buildOpenApiPolicy(depth));
  const refs = input(); document(refs).many = Array.from({ length: OPENAPI_MAX_REFERENCES + 1 }, () => ({ $ref: "#/components/schemas/Id" }));
  assert.throws(() => buildOpenApiPolicy(refs));
  const cases = input(); cases.cases = Array.from({ length: 21 }, (_, i) => ({ ...cases.cases[0]!, id: `case-${i}` }));
  assert.throws(() => buildOpenApiPolicy(cases));
  const requests = input(); requests.cases = Array.from({ length: 16 }, (_, i) => ({ ...requests.cases[0]!, id: `case-${i}` }));
  assert.throws(() => buildOpenApiPolicy(requests), /request budget/);
});

test("OpenAPI adapter reuses v2 loopback authorization evidence and sends only allowlisted GETs", async () => {
  for (const mode of ["fixed", "vulnerable"] as const) {
    const target = fixture(mode); const baseUrl = await listen(target.server);
    try {
      const options: OpenApiRunOptions = { input: input(baseUrl), allowPrivate: true, timeoutMs: 2000, env: ENV };
      const checks = await runOpenApiPolicy(options);
      assert.equal(checks[0]!.status, "completed");
      assert.equal(checks[0]!.findings.some((entry) => entry.ruleId === "api.authorization-data-exposure"), mode === "vulnerable");
      assert.equal(checks[0]!.metrics!.requestCount, 8);
      assert.deepEqual(target.requests.map((request) => request.path), ["/whoami", "/whoami", "/documents/fixture-a", "/documents/fixture-a", "/documents/fixture-a", "/documents/fixture-a", "/whoami", "/whoami"]);
      assert.ok(target.requests.every((request) => request.method === "GET"));
      const report = JSON.stringify(checks);
      for (const value of [CANARY, ENV.OPENAPI_OWNER_AUTH, ENV.OPENAPI_OTHER_AUTH, "ignored.example.test", "Owned synthetic API"]) assert.equal(report.includes(value), false);
    } finally { await close(target.server); }
  }
});

test("adapter rejects invalid input, off-list identity, missing credentials and insecure transport before requests", async () => {
  const target = fixture(); const baseUrl = await listen(target.server);
  try {
    const invalid = input(baseUrl); parameter(invalid).schema.$ref = `${baseUrl}/unselected`;
    const invalidChecks = await runOpenApiPolicy({ input: invalid, allowPrivate: true, env: ENV });
    assert.equal(invalidChecks[0]!.status, "error");
    assert.equal(invalidChecks[0]!.metrics!.requestCount, 0);
    assert.equal(JSON.stringify(invalidChecks).includes(baseUrl), false);
    const offList = input(baseUrl); offList.actors[0]!.identity!.path = "/unselected";
    assert.equal((await runOpenApiPolicy({ input: offList, allowPrivate: true, env: ENV }))[0]!.status, "error");
    assert.equal((await runOpenApiPolicy({ input: input(baseUrl), allowPrivate: true, env: {} }))[0]!.status, "error");
    assert.equal((await runOpenApiPolicy({ input: input(baseUrl), env: ENV }))[0]!.metrics!.errorCode, "insecure_authenticated_transport");
    const duplicateEnv = { OPENAPI_OWNER_AUTH: ENV.OPENAPI_OWNER_AUTH, OPENAPI_OTHER_AUTH: ENV.OPENAPI_OWNER_AUTH };
    assert.equal((await runOpenApiPolicy({ input: input(baseUrl), allowPrivate: true, env: duplicateEnv }))[0]!.status, "error");
    assert.equal(target.requests.length, 0);
  } finally { await close(target.server); }
});

test("adapter preserves incomplete identity/owner/redirect/body-budget outcomes", async () => {
  for (const mode of ["expired", "wrong-owner", "redirect", "oversized"] as const) {
    const target = fixture(mode); const baseUrl = await listen(target.server);
    try {
      const checks = await runOpenApiPolicy({ input: input(baseUrl), allowPrivate: true, timeoutMs: 2000, env: ENV });
      assert.equal(checks[0]!.status, "partial", mode);
      assert.equal(target.requests.some((request) => request.path === "/unselected"), false);
      if (mode === "wrong-owner") assert.equal(target.requests.filter((request) => request.path.startsWith("/documents") && request.authorization !== ENV.OPENAPI_OWNER_AUTH).length, 0);
      if (mode === "oversized") assert.equal(target.requests.length, 1);
    } finally { await close(target.server); }
  }
});

test("adapter preserves pre-abort, in-flight cancellation and timeout with no later requests", async () => {
  const target = fixture("slow"); const baseUrl = await listen(target.server);
  try {
    const before = new AbortController(); before.abort();
    assert.equal((await runOpenApiPolicy({ input: input(baseUrl), allowPrivate: true, env: ENV, signal: before.signal }))[0]!.status, "partial");
    assert.equal(target.requests.length, 0);
    const during = new AbortController();
    target.server.once("request", () => during.abort());
    assert.equal((await runOpenApiPolicy({ input: input(baseUrl), allowPrivate: true, env: ENV, signal: during.signal, timeoutMs: 2000 }))[0]!.status, "partial");
    assert.equal(target.requests.length, 1);
    assert.equal((await runOpenApiPolicy({ input: input(baseUrl), allowPrivate: true, env: ENV, timeoutMs: 40 }))[0]!.status, "partial");
    assert.equal(target.requests.length, 2);
  } finally { await close(target.server); }
});

test("adapter runtime validation returns a redacted error for invalid options and never invokes option getters", async () => {
  let invoked = 0;
  const options = Object.defineProperty({}, "input", { enumerable: true, get() { invoked++; return input(); } });
  const inherited = Object.assign(Object.create({ get signal() { invoked++; return undefined; } }), { input: input() });
  for (const value of [undefined, null, {}, { input: input(), unknown: true }, options, inherited]) {
    const checks = await runOpenApiPolicy(value as OpenApiRunOptions);
    assert.equal(checks[0]!.status, "error");
    assert.equal(checks[0]!.metrics!.requestCount, 0);
  }
  assert.equal(invoked, 0);
});
