import test from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, mkdir, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect, promisify } from "node:util";
import {
  preflightApiPolicy, preflightOpenApiPolicy, runApiPolicy,
  type ApiPreflightResult, type ApiRunOptions, type OpenApiPolicyInput,
} from "../src/index.js";

type JsonObject = Record<string, any>;
const MARKERS = {
  host: "private-sentinel-host.example.test",
  owner: "PrivateOwnerSentinel", other: "PrivateOtherSentinel", case: "PrivateCaseSentinel",
  identityPath: "/private-identity-sentinel", resourcePath: "/private-resource-sentinel",
  ownerEnv: "PRIVATE_OWNER_SENTINEL_AUTH", otherEnv: "PRIVATE_OTHER_SENTINEL_AUTH",
  ownerToken: "Bearer private-owner-token-sentinel", otherToken: "Bearer private-other-token-sentinel",
  ownerPrincipal: "private-owner-principal-sentinel", otherPrincipal: "private-other-principal-sentinel",
  resource: "private-resource-value-sentinel", canary: "private-canary-value-sentinel",
  principalPointer: "/private-principal-pointer", resourcePointer: "/private-resource-pointer",
  canaryPointer: "/private-canary-pointer", operation: "PrivateOperationSentinel",
  operationId: "PrivateOperationIdSentinel", identityOperation: "PrivateIdentityOperationSentinel",
};
const ENV = { [MARKERS.ownerEnv]: MARKERS.ownerToken, [MARKERS.otherEnv]: MARKERS.otherToken };

function policy(baseUrl = `https://${MARKERS.host}`): JsonObject {
  return {
    version: 2, baseUrl,
    actors: [
      { id: MARKERS.owner, authorizationEnv: MARKERS.ownerEnv, identity: { path: MARKERS.identityPath, status: 200, jsonPointer: MARKERS.principalPointer, equals: MARKERS.ownerPrincipal } },
      { id: MARKERS.other, authorizationEnv: MARKERS.otherEnv, identity: { path: MARKERS.identityPath, status: 200, jsonPointer: MARKERS.principalPointer, equals: MARKERS.otherPrincipal } },
      { id: "anonymous" },
    ],
    cases: [{ id: MARKERS.case, path: MARKERS.resourcePath,
      allow: { actor: MARKERS.owner, status: 200, resource: { jsonPointer: MARKERS.resourcePointer, equals: MARKERS.resource }, protected: { jsonPointer: MARKERS.canaryPointer, equals: MARKERS.canary } },
      deny: [{ actor: MARKERS.other, statuses: [403] }, { actor: "anonymous", statuses: [401] }],
    }],
  };
}

function openapi(baseUrl = `https://${MARKERS.host}`): OpenApiPolicyInput {
  const source = policy(baseUrl);
  return {
    document: { openapi: "3.1.0", info: { title: "Synthetic preflight fixture", version: "1" },
      servers: [{ url: "https://ignored-server-sentinel.example.test" }],
      paths: {
        [MARKERS.identityPath]: { get: { responses: {} } },
        [MARKERS.resourcePath]: { get: { operationId: MARKERS.operationId, responses: {} }, post: { requestBody: {} } },
      },
    }, baseUrl, actors: source.actors,
    operations: [
      { id: MARKERS.identityOperation, method: "GET", path: MARKERS.identityPath },
      { id: MARKERS.operation, method: "GET", path: MARKERS.resourcePath, operationId: MARKERS.operationId },
    ],
    cases: [{ id: MARKERS.case, operation: MARKERS.operation, allow: source.cases[0].allow, deny: source.cases[0].deny }],
  };
}

function assertRedacted(value: unknown, extra: string[] = []): void {
  const serialized = typeof value === "string" ? value : JSON.stringify(value) + inspect(value, { depth: null });
  for (const marker of [...Object.values(MARKERS), "ignored-server-sentinel.example.test", ...extra]) {
    assert.equal(serialized.includes(marker), false, `output included private sentinel ${marker}`);
  }
}

function assertOffline(value: ApiPreflightResult): void {
  assert.equal(value.execution, "not_run");
  assert.equal(value.networkRequests, 0);
  assert.equal(value.dnsLookups, 0);
  for (const forbidden of ["findings", "checks", "verdict", "scanResult", "scope", "policy", "credentials"]) {
    assert.equal(Object.hasOwn(value, forbidden), false);
  }
  assertRedacted(value);
}

// Trap before importing the SDK: named ESM imports must also see the patched functions.
const NETWORK_TRAP = `
import assert from 'node:assert/strict';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { syncBuiltinESMExports } from 'node:module';
let networkCalls = 0;
const denyNetwork = () => { networkCalls++; throw new Error('private-network-error-sentinel'); };
for (const api of [dns, dnsPromises]) for (const key of Object.keys(api)) {
  if (/^(lookup|resolve|reverse)/.test(key) && typeof api[key] === 'function') api[key] = denyNetwork;
}
for (const api of [http, https]) { api.request = denyNetwork; api.get = denyNetwork; }
net.connect = denyNetwork; net.createConnection = denyNetwork; net.Socket.prototype.connect = denyNetwork;
tls.connect = denyNetwork; dgram.createSocket = denyNetwork; globalThis.fetch = denyNetwork;
syncBuiltinESMExports();
`;
const SDK_URL = new URL("../src/index.js", import.meta.url).href;
const CLI_URL = new URL("../src/cli.js", import.meta.url).href;
const CLI_TRAPPED = `${NETWORK_TRAP}\nconst { main } = await import(${JSON.stringify(CLI_URL)});\nconst code = await main(process.argv.slice(1));\nassert.equal(networkCalls, 0);\nprocess.exitCode = code;`;

async function child(script: string, args: string[] = [], cwd = process.cwd(), env: NodeJS.ProcessEnv = ENV): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const processChild = spawn(process.execPath, ["--input-type=module", "--eval", script, ...args], {
      cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "";
    const timer = setTimeout(() => { processChild.kill("SIGKILL"); reject(new Error("preflight subprocess did not terminate")); }, 15_000);
    processChild.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    processChild.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    processChild.once("error", (error) => { clearTimeout(timer); reject(error); });
    processChild.once("close", (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

test("API preflight produces deterministic ordinal-only GET controls without mutating input", () => {
  const input = policy();
  const before = JSON.stringify(input);
  const result = preflightApiPolicy({ policy: input, env: ENV });
  assert.equal(result.kind, "api-preflight");
  assert.equal(result.status, "ready");
  assert.equal(result.policyVersion, 2);
  assert.deepEqual(result.issues, []);
  assertOffline(result);
  assert.equal(JSON.stringify(input), before);
  assert.deepEqual(result, preflightApiPolicy({ policy: input, env: ENV }));
  assert.ok(result.plan);
  assert.equal(result.plan.logicalRequests, 8);
  assert.equal(result.plan.maximumHttpAttempts, 64);
  assert.equal(result.plan.actorCount, 3);
  assert.equal(result.plan.caseCount, 1);
  assert.equal(result.plan.timeoutMs, 30_000);
  assert.deepEqual(result.plan.steps, [
    { ordinal: 0, method: "GET", phase: "identity-before", actorIndex: 0 },
    { ordinal: 1, method: "GET", phase: "identity-before", actorIndex: 1 },
    { ordinal: 2, method: "GET", phase: "owner-before", actorIndex: 0, caseIndex: 0 },
    { ordinal: 3, method: "GET", phase: "deny", actorIndex: 1, caseIndex: 0 },
    { ordinal: 4, method: "GET", phase: "deny", actorIndex: 2, caseIndex: 0 },
    { ordinal: 5, method: "GET", phase: "owner-after", actorIndex: 0, caseIndex: 0 },
    { ordinal: 6, method: "GET", phase: "identity-after", actorIndex: 0 },
    { ordinal: 7, method: "GET", phase: "identity-after", actorIndex: 1 },
  ]);
  input.actors[0].id = "mutated-after-preflight";
  assert.equal(JSON.stringify(result).includes("mutated-after-preflight"), false);
});

test("OpenAPI preflight preserves explicit finite GET plan and omits schema/caller material", () => {
  const input = openapi();
  const before = JSON.stringify(input);
  const result = preflightOpenApiPolicy({ input, env: ENV });
  assert.equal(result.status, "ready");
  assertOffline(result);
  assert.equal(JSON.stringify(input), before);
  assert.equal(result.plan?.logicalRequests, 8);
  assert.deepEqual(result.plan?.steps, preflightApiPolicy({ policy: policy(), env: ENV }).plan?.steps);
});

test("SDK preflight success and failure paths invoke no DNS, HTTP, sockets or fetch", async () => {
  const script = `${NETWORK_TRAP}
    const sdk = await import(${JSON.stringify(SDK_URL)});
    const policy = ${JSON.stringify(policy())}, input = ${JSON.stringify(openapi())}, env = ${JSON.stringify(ENV)};
    assert.equal(sdk.preflightApiPolicy({ policy, env }).status, 'ready');
    assert.equal(sdk.preflightOpenApiPolicy({ input, env }).status, 'ready');
    assert.equal(sdk.preflightApiPolicy({ policy, env: {} }).status, 'blocked');
    policy.baseUrl = 'https://169.254.169.254';
    assert.equal(sdk.preflightApiPolicy({ policy, env, allowPrivate: true }).status, 'blocked');
    input.document.components = { schemas: { Remote: { $ref: 'https://forbidden.example.test/schema' } } };
    assert.equal(sdk.preflightOpenApiPolicy({ input, env }).status, 'blocked');
    assert.equal(networkCalls, 0); process.stdout.write('offline');`;
  const result = await child(script);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, "offline");
});

test("owned localhost fixture receives no requests from SDK or CLI planning", async () => {
  let requests = 0;
  const server = createServer((_request, response) => { requests++; response.end("unexpected"); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const root = await mkdtemp(join(tmpdir(), "wakeio-preflight-local-"));
  try {
    assert.equal(preflightApiPolicy({ policy: policy(baseUrl), env: ENV, allowPrivate: true }).status, "ready");
    assert.equal(preflightOpenApiPolicy({ input: openapi(baseUrl), env: ENV, allowPrivate: true }).status, "ready");
    const file = join(root, "policy.json");
    await writeFile(file, JSON.stringify(policy(baseUrl)));
    const result = await child(CLI_TRAPPED, ["plan", "--api-policy", file, "--allow-private"], root);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, "ready");
    assert.equal(requests, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await rm(root, { recursive: true, force: true });
  }
});

test("ordinal preflight plan matches successful execution order on an owned localhost fixture", async () => {
  const requests: Array<{ actorIndex: number; path: string; method: string }> = [];
  const server = createServer((request, response) => {
    const actorIndex = request.headers.authorization === MARKERS.ownerToken ? 0 : request.headers.authorization === MARKERS.otherToken ? 1 : 2;
    requests.push({ actorIndex, path: request.url ?? "", method: request.method ?? "" });
    response.setHeader("Content-Type", "application/json");
    if (request.url === MARKERS.identityPath && actorIndex < 2) {
      response.end(JSON.stringify({ [MARKERS.principalPointer.slice(1)]: actorIndex === 0 ? MARKERS.ownerPrincipal : MARKERS.otherPrincipal }));
    } else if (request.url === MARKERS.resourcePath && actorIndex === 0) {
      response.end(JSON.stringify({ [MARKERS.resourcePointer.slice(1)]: MARKERS.resource, [MARKERS.canaryPointer.slice(1)]: MARKERS.canary }));
    } else {
      response.statusCode = actorIndex === 2 ? 401 : 403;
      response.end(JSON.stringify({ denied: true }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address === "object");
  try {
    const options = { policy: policy(`http://127.0.0.1:${address.port}`), env: ENV, allowPrivate: true, timeoutMs: 2000 };
    const plan = preflightApiPolicy(options);
    assert.equal(plan.status, "ready"); assert.ok(plan.plan);
    assert.deepEqual(requests, []);
    const result = await runApiPolicy(options);
    assert.equal(result[0]?.status, "completed");
    assert.equal(result[0]?.metrics?.requestCount, plan.plan.logicalRequests);
    assert.deepEqual(requests, plan.plan.steps.map(step => ({ actorIndex: step.actorIndex, method: step.method,
      path: step.phase.startsWith("identity-") ? MARKERS.identityPath : MARKERS.resourcePath })));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test("static target checks enforce transport, private ranges and metadata restrictions offline", () => {
  const cases: Array<[string, boolean, "ready" | "blocked"]> = [
    [`https://${MARKERS.host}`, false, "ready"],
    ["http://localhost", true, "ready"], ["http://127.0.0.1", true, "ready"], ["http://[::1]", true, "ready"],
    ["http://localhost", false, "blocked"], ["http://127.0.0.1", false, "blocked"],
    [`http://${MARKERS.host}`, true, "blocked"], ["http://10.1.2.3", true, "blocked"],
    ["https://10.1.2.3", false, "blocked"], ["https://10.1.2.3", true, "ready"],
    ["https://127.0.0.1", false, "blocked"], ["https://[::1]", false, "blocked"],
    ["https://printer.local", false, "blocked"],
  ];
  for (const target of ["169.254.169.254", "100.100.100.200", "metadata", "host.docker.internal", "service.internal", "service.svc", "service.cluster.local", "192.0.2.1", "224.0.0.1", "[fd00:ec2::254]", "[::ffff:169.254.169.254]", "[64:ff9b::a9fe:a9fe]", "[2002:a9fe:a9fe::1]", "[2001:db8::1]"]) {
    for (const allowPrivate of [false, true]) cases.push([`https://${target}`, allowPrivate, "blocked"]);
  }
  for (const target of ["https://2130706433", "https://0x7f000001", "https://127.1", "https://0177.0.0.1", "https://fixture.example.test.", "https://user:secret@fixture.example.test", "https://[fe80::1%25eth0]"]) cases.push([target, true, "blocked"]);
  for (const [baseUrl, allowPrivate, expected] of cases) {
    const result = preflightApiPolicy({ policy: policy(baseUrl), allowPrivate, env: ENV });
    assert.equal(result.status, expected, `${baseUrl} private=${allowPrivate}`);
    assertOffline(result);
    assert.equal(JSON.stringify(result).includes(baseUrl), false);
  }
});

test("credential diagnostics are indexed and reject invalid, inherited or accessor values", async () => {
  for (const value of [undefined, "", "Bearer\r\nInjected: value", "Bearer\0value", "Bearer\x7fvalue", "Bearer\u0100", "x".repeat(8193), 42]) {
    const env = { ...ENV, [MARKERS.otherEnv]: value } as NodeJS.ProcessEnv;
    const result = preflightApiPolicy({ policy: policy(), env });
    assert.equal(result.status, "blocked");
    assert.equal(result.issues[0]?.location, "policy.actors[1].authorizationEnv");
    assertOffline(result);
    const executed = await runApiPolicy({ policy: policy("http://127.0.0.1:1"), allowPrivate: true, timeoutMs: 100, env });
    assert.equal(executed[0]?.status, "error");
    assert.equal(executed[0]?.metrics?.requestCount, 0);
  }
  const duplicate = preflightApiPolicy({ policy: policy(), env: { ...ENV, [MARKERS.otherEnv]: MARKERS.ownerToken } });
  assert.equal(duplicate.status, "blocked");
  assert.equal(duplicate.issues[0]?.location, "policy.actors[1].authorizationEnv");
  assertOffline(duplicate);
  let called = 0;
  const accessor = { [MARKERS.ownerEnv]: MARKERS.ownerToken };
  Object.defineProperty(accessor, MARKERS.otherEnv, { get() { called++; throw new Error(MARKERS.otherToken); } });
  const inherited = Object.assign(Object.create({ [MARKERS.otherEnv]: MARKERS.otherToken }), { [MARKERS.ownerEnv]: MARKERS.ownerToken });
  for (const env of [accessor, inherited]) {
    const result = preflightApiPolicy({ policy: policy(), env });
    assert.equal(result.status, "blocked");
    assertOffline(result);
  }
  assert.equal(called, 0);
  const nullEnv = Object.assign(Object.create(null), ENV);
  assert.equal(preflightApiPolicy({ policy: policy(), env: nullEnv }).status, "ready");
});

test("SDK options and API policy fail closed on executable, inherited or non-JSON values", () => {
  let invoked = 0;
  const accessorOptions = Object.defineProperty({}, "policy", { enumerable: true, get() { invoked++; throw new Error(MARKERS.canary); } });
  const inheritedOptions = Object.assign(Object.create({ get signal() { invoked++; throw new Error(MARKERS.canary); } }), { policy: policy(), env: ENV });
  for (const options of [undefined, null, [], {}, accessorOptions, inheritedOptions, { policy: policy(), env: ENV, extra: MARKERS.canary }, { policy: policy(), env: [] }, { policy: policy(), signal: {} }, { policy: policy(), allowPrivate: "true" }]) {
    const result = preflightApiPolicy(options as ApiRunOptions);
    assert.equal(result.status, "blocked");
    assertOffline(result);
  }
  const mutations: Array<(value: JsonObject) => void> = [
    value => Object.defineProperty(value.actors[1].identity, "equals", { enumerable: true, get() { invoked++; throw new Error(MARKERS.canary); } }),
    value => Object.setPrototypeOf(value.actors[1], { authorizationEnv: MARKERS.otherEnv }),
    value => { value.toJSON = () => { invoked++; return policy(); }; },
    value => { value.cases = new Array(2); },
    value => { value.cases[0].allow.protected.equals = Infinity; },
    value => { value.cases[0].allow.protected.equals = NaN; },
    value => { value.cases[0].allow.protected.equals = 1n; },
    value => { value.cases[0].allow.protected.equals = new Date(); },
    value => { value.cases[0].allow.protected.equals = undefined; },
    value => { value.cycle = value; },
    value => { Object.defineProperty(value, Symbol("private-symbol-sentinel"), { value: true }); },
    value => Object.defineProperty(value, "hidden", { value: MARKERS.canary, enumerable: false }),
  ];
  for (const mutate of mutations) {
    const input = policy(); mutate(input);
    const result = preflightApiPolicy({ policy: input, env: ENV });
    assert.equal(result.status, "blocked");
    assertOffline(result);
  }
  assert.equal(invoked, 0);
  const nullInput = Object.assign(Object.create(null), policy());
  assert.equal(preflightApiPolicy({ policy: nullInput, env: ENV }).status, "ready");
});

test("SDK rejects proxies before executing traps and reads native cancellation state without caller getters", () => {
  let invoked = 0;
  const proxy = new Proxy({}, {
    get() { invoked++; throw new Error(MARKERS.canary); },
    getPrototypeOf() { invoked++; throw new Error(MARKERS.canary); },
    ownKeys() { invoked++; throw new Error(MARKERS.canary); },
    getOwnPropertyDescriptor() { invoked++; throw new Error(MARKERS.canary); },
  });
  for (const result of [
    preflightApiPolicy(proxy as ApiRunOptions),
    preflightApiPolicy({ policy: proxy, env: ENV }),
    preflightApiPolicy({ policy: policy(), env: proxy }),
    preflightApiPolicy({ policy: policy(), env: ENV, signal: proxy as AbortSignal }),
    preflightOpenApiPolicy({ input: proxy as OpenApiPolicyInput, env: ENV }),
  ]) { assert.equal(result.status, "blocked"); assertOffline(result); }
  const signal = new AbortController().signal;
  Object.defineProperty(signal, "aborted", { get() { invoked++; throw new Error(MARKERS.canary); } });
  const result = preflightApiPolicy({ policy: policy(), env: ENV, signal });
  assert.equal(result.status, "ready"); assertOffline(result);
  assert.equal(invoked, 0);
});

test("preflight rejects budget overflows and accepts exactly 64 planned GETs", () => {
  const exact = policy();
  exact.cases = Array.from({ length: 15 }, (_, index) => ({ ...exact.cases[0], id: `case${index}` }));
  const result = preflightApiPolicy({ policy: exact, env: ENV });
  assert.equal(result.status, "ready");
  assert.equal(result.plan?.logicalRequests, 64);
  assert.equal(result.plan?.steps.length, 64);
  assert.equal(result.plan?.maximumHttpAttempts, 64);
  const over = policy();
  over.cases = Array.from({ length: 16 }, (_, index) => ({ ...over.cases[0], id: `case${index}` }));
  over.cases[0].deny = [over.cases[0].deny[0]];
  over.cases[1].deny = [over.cases[1].deny[0]];
  over.cases[2].deny = [over.cases[2].deny[0]];
  assert.equal(preflightApiPolicy({ policy: over, env: ENV }).status, "blocked"); // 65
  for (const timeoutMs of [0, -1, 120_001, 1.5, NaN, Infinity]) {
    assert.equal(preflightApiPolicy({ policy: policy(), env: ENV, timeoutMs }).status, "blocked");
  }
  for (const timeoutMs of [1, 120_000]) {
    assert.equal(preflightApiPolicy({ policy: policy(), env: ENV, timeoutMs }).plan?.timeoutMs, timeoutMs);
  }
  for (const mutate of [
    (value: JsonObject) => { value.cases[0].allow.protected.equals = "x".repeat(1024 * 1024); },
    (value: JsonObject) => { value.extra = Array.from({ length: 20_001 }, () => null); },
    (value: JsonObject) => { let child = value; for (let index = 0; index < 45; index++) child = child.extra = {}; },
  ]) {
    const input = policy(); mutate(input);
    assert.equal(preflightApiPolicy({ policy: input, env: ENV }).status, "blocked");
  }
});

test("legacy, cancelled and duplicate-principal configurations never appear ready", () => {
  const legacy = policy(); legacy.version = 1;
  for (const actor of legacy.actors) delete actor.identity;
  legacy.cases[0].allow = { actor: MARKERS.owner, status: 200, jsonPointer: MARKERS.resourcePointer, equals: MARKERS.resource };
  const cancellation = new AbortController(); cancellation.abort();
  const duplicate = policy(); duplicate.actors[1].identity.equals = duplicate.actors[0].identity.equals;
  const results = [preflightApiPolicy({ policy: legacy, env: ENV }), preflightApiPolicy({ policy: policy(), env: ENV, signal: cancellation.signal }), preflightApiPolicy({ policy: duplicate, env: ENV })];
  for (const result of results) { assert.equal(result.status, "blocked"); assertOffline(result); }
  assert.ok(results[0].issues.some(issue => issue.code === "legacy_policy"));
  assert.ok(results[1].issues.some(issue => issue.code === "cancelled"));
  assert.ok(results[2].issues.some(issue => issue.location === "policy.actors[1].identity.equals"));
});

test("duplicate expected principals also block execution before a connection is attempted", async () => {
  const input = policy("http://127.0.0.1:1"); input.actors[1].identity.equals = input.actors[0].identity.equals;
  const results = await runApiPolicy({ policy: input, allowPrivate: true, timeoutMs: 100, env: ENV });
  assert.equal(results[0]?.status, "error");
  assert.equal(results[0]?.metrics?.requestCount, 0);
});

test("API validation identifies nonzero actor, case and deny indexes without caller identifiers", () => {
  const scenarios: Array<[(input: JsonObject) => void, RegExp]> = [
    [input => { input.actors[1].identity.status = 500; }, /actors\[1\]/],
    [input => { input.actors[1].authorizationEnv = input.actors[0].authorizationEnv; }, /actors\[1\]/],
    [input => { input.cases.push({ ...structuredClone(input.cases[0]), id: "SecondCaseSentinel" }); input.cases[1].path = "//private-sentinel-host.example.test"; }, /cases\[1\]/],
    [input => { input.cases[0].deny[1].statuses = []; }, /cases\[0\].*deny\[1\]/],
    [input => { input.actors[1].id = input.actors[0].id; }, /actors\[1\]/],
    [input => { input.cases.push(structuredClone(input.cases[0])); }, /cases\[1\]/],
    [input => { input.cases[0].allow.actor = "UnknownOwnerSentinel"; }, /cases\[0\].*allow/],
    [input => { input.cases[0].deny[1].actor = "UnknownDenySentinel"; }, /cases\[0\].*deny\[1\]/],
  ];
  for (const [mutate, location] of scenarios) {
    const input = policy(); mutate(input);
    const result = preflightApiPolicy({ policy: input, env: ENV });
    assert.equal(result.status, "blocked");
    assert.ok(result.issues.some(issue => location.test(issue.location)), JSON.stringify(result.issues));
    assertRedacted(result, ["SecondCaseSentinel", "UnknownOwnerSentinel", "UnknownDenySentinel"]);
  }
});

test("OpenAPI rejects remote references, non-GET selections, hidden controls and hostile data offline", () => {
  let invoked = 0;
  const mutations: Array<(value: JsonObject) => void> = [
    value => { value.operations[1].method = "POST"; },
    value => { value.operations[1].operationId = "MismatchOperationSentinel"; },
    value => { value.operations.shift(); },
    value => { value.document.components = { schemas: { Remote: { $ref: "https://remote-ref-sentinel.example.test/schema" } } }; },
    value => { value.document.components = { schemas: { Remote: { $ref: "file:///private-path-sentinel/schema.json" } } }; },
    value => { value.document.components = { schemas: { Cycle: { $ref: "#/components/schemas/Cycle" } } }; },
    value => { value.document.paths[MARKERS.resourcePath].get.requestBody = {}; },
    value => { value.document.paths[MARKERS.resourcePath].get.parameters = [{ name: "HeaderSentinel", in: "header", required: true, schema: { type: "string" } }]; },
    value => Object.defineProperty(value.document, "description", { enumerable: true, get() { invoked++; throw new Error(MARKERS.canary); } }),
    value => { value.document.description = "x".repeat(1024 * 1024); },
  ];
  for (const mutate of mutations) {
    const input = openapi(); mutate(input);
    const result = preflightOpenApiPolicy({ input, env: ENV });
    assert.equal(result.status, "blocked");
    assertOffline(result);
    assertRedacted(result, ["MismatchOperationSentinel", "remote-ref-sentinel", "private-path-sentinel", "HeaderSentinel"]);
  }
  assert.equal(invoked, 0);
  const input = openapi(); (input.operations[1] as unknown as JsonObject).method = "POST";
  const indexed = preflightOpenApiPolicy({ input, env: ENV });
  assert.ok(indexed.issues.some(issue => /operations\[1\]/.test(issue.location)), JSON.stringify(indexed.issues));
  for (const [mutate, location] of [
    [(value: JsonObject) => { value.actors[1].identity.status = 500; }, /actors\[1\]/],
    [(value: JsonObject) => { value.cases[0].deny[1].statuses = []; }, /cases\[0\].*deny\[1\]/],
  ] as const) {
    const malformed = openapi(); mutate(malformed);
    const result = preflightOpenApiPolicy({ input: malformed, env: ENV });
    assert.equal(result.status, "blocked"); assertOffline(result);
    assert.ok(result.issues.some(issue => location.test(issue.location)), JSON.stringify(result.issues));
  }
});

test("CLI plans produce only redacted JSON with configuration exit codes and no scan artifacts", async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-preflight-cli-private-path-sentinel-"));
  try {
    const apiFile = join(root, "private-policy-filename-sentinel.json"), openapiFile = join(root, "private-openapi-filename-sentinel.json");
    await writeFile(apiFile, JSON.stringify(policy())); await writeFile(openapiFile, JSON.stringify(openapi()));
    const before = await readdir(root);
    for (const [flag, file] of [["--api-policy", apiFile], ["--openapi-input", openapiFile]]) {
      const result = await child(CLI_TRAPPED, ["plan", flag, file, "--timeout-ms", "1234"], root);
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.stderr, "");
      const parsed = JSON.parse(result.stdout) as ApiPreflightResult;
      assert.equal(parsed.status, "ready"); assertOffline(parsed);
      assert.equal(parsed.plan?.timeoutMs, 1234);
      assertRedacted(result.stdout + result.stderr, [root, file]);
      assert.doesNotMatch(result.stdout, /COMPLETED:|FINDINGS:|INCOMPLETE:|Reports:|report\.sarif|report\.json|scanning/);
    }
    const blocked = await child(CLI_TRAPPED, ["plan", "--api-policy", apiFile], root, { [MARKERS.ownerEnv]: "", [MARKERS.otherEnv]: "" });
    assert.equal(blocked.code, 2, blocked.stderr);
    assert.equal(JSON.parse(blocked.stdout).status, "blocked");
    assert.deepEqual(await readdir(root), before);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("CLI rejects ambiguous grammar and unsafe input files without leaking argument or file values", async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-preflight-cli-input-sentinel-"));
  try {
    const valid = join(root, "valid.json"), malformed = join(root, "private-malformed-sentinel.json"), oversized = join(root, "oversized.json"), link = join(root, "link.json"), directory = join(root, "directory"), badUtf8 = join(root, "bad-utf8.json");
    await writeFile(valid, JSON.stringify(policy())); await writeFile(malformed, '{"private-json-sentinel":');
    await writeFile(oversized, "x".repeat(1024 * 1024 + 1)); await symlink(valid, link); await mkdir(directory);
    const invalidUtf8Policy = policy(); invalidUtf8Policy.cases[0].allow.protected.equals = "UTF8_SENTINEL";
    const prefix = Buffer.from(JSON.stringify(invalidUtf8Policy).split("UTF8_SENTINEL")[0]);
    const suffix = Buffer.from(JSON.stringify(invalidUtf8Policy).split("UTF8_SENTINEL")[1]);
    await writeFile(badUtf8, Buffer.concat([prefix, Buffer.from([0xff]), suffix]));
    const commands = [
      ["plan"], ["plan", "--api-policy"], ["plan", "--api-policy", "--allow-private"],
      ["plan", "--api-policy", valid, "--openapi-input", valid],
      ["plan", "--api-policy", valid, "--api-policy", valid],
      ["plan", "--api-policy", valid, "--allow-private", "--allow-private"],
      ["plan", "--api-policy", valid, "--timeout-ms", "120001"],
      ["plan", "--api-policy", valid, "--timeout-ms=1.5"],
      ["plan", "--api-policy", valid, "--out", join(root, "reports")],
      ["plan", "--api-policy", valid, "--source", root],
      ["plan", "--api-policy", valid, "--url", `https://${MARKERS.host}`],
      ["plan", "--api-policy", valid, "--unknown-private-flag-sentinel"],
      ...[malformed, oversized, link, directory, badUtf8, join(root, "missing-private-sentinel.json")].map(file => ["plan", "--api-policy", file]),
    ];
    const before = await readdir(root);
    for (const args of commands) {
      const result = await child(CLI_TRAPPED, args, root);
      assert.equal(result.code, 2, `${JSON.stringify(args)}: ${result.stderr}`);
      const output = JSON.parse(result.stdout) as ApiPreflightResult;
      assert.equal(output.status, "blocked"); assertOffline(output);
      assertRedacted(result.stdout + result.stderr, [root, "private-json-sentinel", "unknown-private-flag-sentinel", "missing-private-sentinel"]);
      assert.doesNotMatch(result.stdout + result.stderr, /scanning|Reports:|COMPLETED:|FINDINGS:/);
    }
    assert.deepEqual(await readdir(root), before);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("CLI rejects FIFO input without blocking or scanning", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-preflight-fifo-"));
  try {
    const fifo = join(root, "private-fifo-path-sentinel");
    await promisify(execFile)("mkfifo", [fifo]);
    const result = await child(CLI_TRAPPED, ["plan", "--api-policy", fifo], root);
    assert.equal(result.code, 2, result.stderr);
    const output = JSON.parse(result.stdout) as ApiPreflightResult;
    assert.equal(output.status, "blocked"); assertOffline(output);
    assertRedacted(result.stdout + result.stderr, [root, fifo]);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('API and OpenAPI wrappers ignore inherited option getters without invoking them', async () => {
  const result = await child(`
    import assert from 'node:assert/strict';
    const { preflightApiPolicy, runApiPolicy, preflightOpenApiPolicy, runOpenApiPolicy } = await import(${JSON.stringify(SDK_URL)});
    const policy = ${JSON.stringify(policy('http://127.0.0.1:9'))};
    const input = ${JSON.stringify(openapi('http://127.0.0.1:9'))};
    const env = ${JSON.stringify(ENV)};
    let getterCalls = 0;
    const values = { allowPrivate: true, env, timeoutMs: 1, signal: new AbortController().signal, policy, input };
    for (const key of Object.keys(values)) {
      const original = Object.getOwnPropertyDescriptor(Object.prototype, key);
      Object.defineProperty(Object.prototype, key, { configurable: true, get() { getterCalls++; return values[key]; } });
      try {
        const apiOptions = key === 'policy' ? { env } : key === 'env' ? { policy } : { policy, env };
        const openOptions = key === 'input' ? { env } : key === 'env' ? { input } : { input, env };
        const plan = preflightApiPolicy(apiOptions);
        const openPlan = preflightOpenApiPolicy(openOptions);
        const [check] = await runApiPolicy(apiOptions);
        const [openCheck] = await runOpenApiPolicy(openOptions);
        assert.equal(plan.status, 'blocked', key);
        assert.equal(openPlan.status, 'blocked', key);
        assert.equal(check.status, 'error', key);
        assert.equal(openCheck.status, 'error', key);
        assert.equal(check.metrics.requestCount, 0, key);
        assert.equal(openCheck.metrics.requestCount, 0, key);
      } finally {
        if (original) Object.defineProperty(Object.prototype, key, original);
        else delete Object.prototype[key];
      }
    }
    assert.equal(getterCalls, 0);
  `);
  assert.equal(result.code, 0, result.stderr);
});
