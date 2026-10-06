import {
  API_MAX_REQUESTS,
  parseApiPolicy,
  runApiPolicy,
  type ApiAllowExpectationV2,
  type ApiDenyExpectationV2,
  type ApiPolicyV2,
  type ApiRunOptions,
} from "./api.js";
import type { CheckResult } from "./contracts.js";

/** Compilation is bounded independently of the existing API execution budgets. */
export const OPENAPI_MAX_INPUT_BYTES = 1024 * 1024;
export const OPENAPI_MAX_INPUT_NODES = 20_000;
export const OPENAPI_MAX_DEPTH = 40;
export const OPENAPI_MAX_REFERENCES = 256;
export const OPENAPI_MAX_PATHS = 1_000;
export const OPENAPI_MAX_PARAMETERS = 32;

export type OpenApiPathValue = string | number | boolean;

/** An explicit, finite GET allowlist entry, including identity-control routes. */
export interface OpenApiOperationSelection {
  id: string;
  method: "GET";
  path: string;
  /** When provided, must match the selected operation exactly. Never a discovery selector. */
  operationId?: string;
  pathParameters?: Record<string, OpenApiPathValue>;
}

export interface OpenApiPolicyCase {
  id: string;
  operation: string;
  allow: ApiAllowExpectationV2;
  deny: ApiDenyExpectationV2[];
}

export interface OpenApiPolicyInput {
  /** Parsed JSON only. No URLs, YAML, file loading or external reference resolution. */
  document: unknown;
  /** Explicit HTTP(S) origin; OpenAPI servers are never used. */
  baseUrl: string;
  actors: ApiPolicyV2["actors"];
  operations: OpenApiOperationSelection[];
  cases: OpenApiPolicyCase[];
}

export interface OpenApiRunOptions extends Omit<ApiRunOptions, "policy"> {
  input: OpenApiPolicyInput;
}

/** Messages and codes are fixed; untrusted schema text and values are never included. */
export class OpenApiPolicyError extends Error {
  readonly code: "invalid_openapi_policy" | "openapi_limit" | "unsupported_openapi";
  constructor(code: OpenApiPolicyError["code"], message: string) {
    super(message);
    this.name = "OpenApiPolicyError";
    this.code = code;
  }
}

type RecordValue = Record<string, unknown>;
function invalid(message = "OpenAPI policy input is invalid."): never {
  throw new OpenApiPolicyError("invalid_openapi_policy", message);
}
function unsupported(message = "The selected OpenAPI feature is unsupported."): never {
  throw new OpenApiPolicyError("unsupported_openapi", message);
}
function limit(): never { throw new OpenApiPolicyError("openapi_limit", "OpenAPI compilation budget exceeded."); }
function record(value: unknown): value is RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function own(value: RecordValue, key: string): boolean { return Object.prototype.hasOwnProperty.call(value, key); }
function keys(value: RecordValue, required: string[], optional: string[] = []): void {
  if (required.some((key) => !own(value, key)) || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) invalid();
}
function identifier(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(value)) invalid();
  return value;
}

/** Snapshot data properties without invoking getters, toJSON, or caller mutation later. */
function snapshot(input: unknown): unknown {
  let nodes = 0, bytes = 0;
  const active = new Set<object>();
  const count = (value: string) => { bytes += Buffer.byteLength(value, "utf8"); if (bytes > OPENAPI_MAX_INPUT_BYTES) limit(); };
  const string = (value: string) => { if (value.length > OPENAPI_MAX_INPUT_BYTES) limit(); count(JSON.stringify(value)); };
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > OPENAPI_MAX_INPUT_NODES || depth > OPENAPI_MAX_DEPTH) limit();
    if (value === null || typeof value === "boolean") { count(String(value)); return value; }
    if (typeof value === "string") { string(value); return value; }
    if (typeof value === "number") { if (!Number.isFinite(value)) invalid(); count(String(value)); return value; }
    if (typeof value !== "object" || active.has(value)) invalid();
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) invalid();
    if (Object.getOwnPropertySymbols(value).length !== 0) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const names = Object.keys(descriptors);
    if (names.length > OPENAPI_MAX_INPUT_NODES - nodes) limit();
    active.add(value);
    count("{}"); // Container delimiters have the same byte count for arrays.
    if (array) {
      if (value.length > OPENAPI_MAX_INPUT_NODES - nodes || names.length !== value.length + 1) invalid();
      const result: unknown[] = [];
      for (let i = 0; i < value.length; i++) {
        const descriptor = descriptors[String(i)];
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
        if (i > 0) count(",");
        result.push(copy(descriptor.value, depth + 1));
      }
      active.delete(value);
      return result;
    }
    const result = Object.create(null) as RecordValue;
    for (let i = 0; i < names.length; i++) {
      const name = names[i]!;
      const descriptor = descriptors[name]!;
      if (!descriptor.enumerable || !("value" in descriptor)) invalid();
      if (i > 0) count(",");
      string(name);
      count(":");
      result[name] = copy(descriptor.value, depth + 1);
    }
    active.delete(value);
    return result;
  };
  return copy(input, 0);
}

/** Resolve JSON pointers in the supplied document only. Never access a network or file. */
function references(document: RecordValue): (value: unknown) => RecordValue {
  let referenceCount = 0;
  const targets = new WeakMap<object, RecordValue>();
  const pointer = (ref: unknown): RecordValue => {
    if (typeof ref !== "string" || ref.length > 512 || !ref.startsWith("#/") || ref.includes("%")) unsupported();
    let current: unknown = document;
    for (const encoded of ref.slice(2).split("/")) {
      if (/~(?![01])/.test(encoded)) invalid();
      const part = encoded.replace(/~1/g, "/").replace(/~0/g, "~");
      if (Array.isArray(current)) {
        if (!/^(0|[1-9][0-9]*)$/.test(part) || !Number.isSafeInteger(Number(part)) || Number(part) >= current.length) invalid();
        current = current[Number(part)];
      } else {
        if (!record(current) || !own(current, part)) invalid();
        current = current[part];
      }
    }
    if (!record(current)) invalid();
    return current;
  };
  const active = new Set<object>(), done = new Set<object>();
  const visit = (value: unknown, depth: number): void => {
    if (value === null || typeof value !== "object") return;
    if (depth > OPENAPI_MAX_DEPTH) limit();
    if (active.has(value)) invalid("Cyclic OpenAPI references are unsupported.");
    if (done.has(value)) return;
    active.add(value);
    if (record(value) && own(value, "$ref")) {
      if (++referenceCount > OPENAPI_MAX_REFERENCES) limit();
      if (Object.keys(value).length !== 1) unsupported("OpenAPI reference siblings are unsupported.");
      const target = pointer(value.$ref);
      targets.set(value, target);
      visit(target, depth + 1);
    } else {
      for (const child of Object.values(value)) visit(child, depth + 1);
    }
    active.delete(value);
    done.add(value);
  };
  visit(document, 0);
  return (value: unknown): RecordValue => {
    let depth = 0;
    while (record(value) && own(value, "$ref")) {
      if (++depth > OPENAPI_MAX_DEPTH) limit();
      value = targets.get(value);
    }
    if (!record(value)) invalid();
    return value;
  };
}

function pathParts(value: unknown): string[] {
  if (typeof value !== "string" || value.length > 2048 || !value.startsWith("/") || value.startsWith("//")) invalid();
  const parts = value.slice(1).split("/");
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    if (part === "" && i === parts.length - 1) continue;
    if (/^\{[A-Za-z][A-Za-z0-9_-]{0,63}\}$/.test(part)) continue;
    if (!/^[A-Za-z0-9_.~-]+$/.test(part) || part === "." || part === "..") unsupported("Only simple absolute OpenAPI path templates are supported.");
  }
  return parts;
}

function parameterName(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || /[\x00-\x20\x7f]/.test(value)) invalid();
  return value;
}

function parameters(path: RecordValue, operation: RecordValue, resolve: (value: unknown) => RecordValue): Map<string, RecordValue> {
  const merged = new Map<string, RecordValue>();
  for (const container of [path, operation]) {
    if (!own(container, "parameters")) continue;
    if (!Array.isArray(container.parameters) || container.parameters.length > OPENAPI_MAX_PARAMETERS) invalid();
    const seen = new Set<string>();
    for (const item of container.parameters) {
      const parameter = resolve(item);
      const name = parameterName(parameter.name);
      if (!["path", "query", "header", "cookie"].includes(parameter.in as string)) invalid();
      if (own(parameter, "required") && typeof parameter.required !== "boolean") invalid();
      const key = `${parameter.in}:${name}`;
      if (seen.has(key)) invalid();
      seen.add(key);
      merged.set(key, parameter);
    }
  }
  if (merged.size > OPENAPI_MAX_PARAMETERS) limit();
  return merged;
}

function bind(parameter: RecordValue, value: unknown, resolve: (value: unknown) => RecordValue): string {
  if (parameter.required !== true || own(parameter, "content") || (own(parameter, "style") && parameter.style !== "simple") ||
      (own(parameter, "explode") && parameter.explode !== false) || (own(parameter, "allowReserved") && parameter.allowReserved !== false)) unsupported();
  const schema = resolve(parameter.schema);
  keys(schema, ["type"], ["enum", "title", "description", "example", "examples", "default", "deprecated"]);
  if (!["string", "integer", "number", "boolean"].includes(schema.type as string)) unsupported();
  const typeMatches = schema.type === "integer" ? typeof value === "number" && Number.isSafeInteger(value) : typeof value === schema.type;
  if (!typeMatches || value === null || (typeof value === "number" && !Number.isFinite(value))) invalid();
  if (own(schema, "enum")) {
    if (!Array.isArray(schema.enum) || schema.enum.length < 1 || schema.enum.length > 128 ||
        schema.enum.some((entry) => entry !== null && !["string", "number", "boolean"].includes(typeof entry)) || !schema.enum.includes(value)) invalid();
  }
  const text = String(value);
  if (text.length < 1 || text.length > 128 || !/^[A-Za-z0-9_~-][A-Za-z0-9_.~-]*$/.test(text)) invalid("Path bindings must be short synthetic URL-safe segments.");
  return text;
}

/** Compile only explicit synthetic GET selections into the existing v2 policy contract. */
export function buildOpenApiPolicy(input: unknown): ApiPolicyV2 {
  const copied = snapshot(input);
  if (!record(copied)) invalid();
  keys(copied, ["document", "baseUrl", "actors", "operations", "cases"]);
  const document = copied.document;
  if (!record(document) || typeof document.openapi !== "string" || !/^3\.(0|1)\.[0-9]+$/.test(document.openapi) || !record(document.paths)) unsupported();
  const resolve = references(document);
  const paths = Object.keys(document.paths).filter((key) => !key.startsWith("x-"));
  if (paths.length === 0 || paths.length > OPENAPI_MAX_PATHS) limit();
  const templates = new Map(paths.map((path) => [path, pathParts(path)]));
  if (typeof copied.baseUrl !== "string" || copied.baseUrl.includes("?") || copied.baseUrl.includes("#")) invalid();
  try {
    const base = new URL(copied.baseUrl);
    if (!["http:", "https:"].includes(base.protocol) || base.pathname !== "/" || base.username || base.password) invalid();
  } catch { invalid("An explicit HTTP(S) origin is required."); }
  if (!Array.isArray(copied.operations) || copied.operations.length < 1 || copied.operations.length > API_MAX_REQUESTS) invalid();
  const selected = new Map<string, string>(), concrete = new Set<string>();
  for (const value of copied.operations) {
    if (!record(value)) invalid();
    keys(value, ["id", "path", "method"], ["operationId", "pathParameters"]);
    const id = identifier(value.id);
    if (selected.has(id) || value.method !== "GET" || typeof value.path !== "string" || !templates.has(value.path) || !own(document.paths, value.path)) invalid();
    const parts = templates.get(value.path)!;
    const pathItem = resolve(document.paths[value.path]);
    if (!own(pathItem, "get") || !record(pathItem.get) || own(pathItem.get, "$ref")) unsupported();
    const operation = pathItem.get;
    if (own(operation, "requestBody") || own(operation, "callbacks")) unsupported();
    if (own(value, "operationId") && (typeof value.operationId !== "string" || value.operationId.length < 1 || value.operationId.length > 128 || value.operationId !== operation.operationId)) invalid();
    const bindings = own(value, "pathParameters") ? value.pathParameters : Object.create(null) as RecordValue;
    if (!record(bindings)) invalid();
    const names = new Set(parts.filter((part) => part.startsWith("{")).map((part) => part.slice(1, -1)));
    if (Object.keys(bindings).length !== names.size || Object.keys(bindings).some((name) => !names.has(name))) invalid();
    const parametersByName = parameters(pathItem, operation, resolve);
    const bound = new Map<string, string>();
    for (const parameter of parametersByName.values()) {
      if (parameter.in !== "path") { if (parameter.required === true) unsupported(); continue; }
      const name = parameter.name as string;
      if (!names.has(name) || !own(bindings, name)) invalid();
      bound.set(name, bind(parameter, bindings[name], resolve));
    }
    if (bound.size !== names.size) invalid();
    const rendered = `/${parts.map((part) => part.startsWith("{") ? bound.get(part.slice(1, -1))! : part).join("/")}`;
    if (rendered.length > 2048 || new URL(rendered, copied.baseUrl).pathname !== rendered || concrete.has(rendered)) invalid();
    // A binding must not land on a different documented static/templated operation.
    const renderedParts = rendered.slice(1).split("/");
    for (const [otherPath, otherParts] of templates) {
      if (otherPath !== value.path && otherParts.length === renderedParts.length && otherParts.every((part, i) => part.startsWith("{") || part === renderedParts[i])) invalid("An OpenAPI path binding is ambiguous.");
    }
    selected.set(id, rendered);
    concrete.add(rendered);
  }
  if (!Array.isArray(copied.cases)) invalid();
  const cases = copied.cases.map((value) => {
    if (!record(value)) invalid();
    keys(value, ["id", "operation", "allow", "deny"]);
    const operation = identifier(value.operation);
    const path = selected.get(operation);
    if (path === undefined) invalid();
    return { id: value.id, path, allow: value.allow, deny: value.deny };
  });
  // Keep v2 assertions intact: the policy parser, not this adapter, owns them.
  const parsed = parseApiPolicy({ version: 2, baseUrl: copied.baseUrl, actors: copied.actors, cases });
  if (parsed.policy.version !== 2) invalid();
  for (const actor of parsed.policy.actors) {
    if (actor.identity && !concrete.has(actor.identity.path)) invalid("Identity controls must be explicitly allowlisted GET paths.");
  }
  return parsed.policy;
}

/** A bounded, self-contained OpenAPI document with an explicit GET allowlist for generated testing. */
export interface OpenApiLiveSelection {
  document: Record<string, unknown>;
  operations: Array<{ method: "GET"; path: string }>;
}

export const OPENAPI_MAX_LIVE_OPERATIONS = 16;

/**
 * Validate a document for an engine that generates its own inputs. The same
 * compile budgets and same-document `$ref` rule apply; remote/file/cyclic
 * references and request bodies are rejected before any engine starts.
 */
export function selectOpenApiLiveOperations(documentInput: unknown, selections: unknown): OpenApiLiveSelection {
  const document = snapshot(documentInput);
  if (!record(document) || typeof document.openapi !== "string" || !/^3\.(0|1)\.[0-9]+$/.test(document.openapi) || !record(document.paths)) unsupported();
  const resolve = references(document);
  const documentPaths = document.paths as RecordValue;
  const paths = Object.keys(documentPaths).filter((key) => !key.startsWith("x-"));
  if (paths.length === 0 || paths.length > OPENAPI_MAX_PATHS) limit();
  for (const path of paths) pathParts(path);
  if (!Array.isArray(selections) || selections.length < 1 || selections.length > OPENAPI_MAX_LIVE_OPERATIONS) invalid();
  const seen = new Set<string>();
  const operations = selections.map((value: unknown) => {
    if (!record(value)) invalid();
    keys(value, ["method", "path"]);
    if (value.method !== "GET" || typeof value.path !== "string" || !own(documentPaths, value.path) || seen.has(value.path)) invalid();
    seen.add(value.path);
    const pathItem = resolve(documentPaths[value.path]);
    if (!own(pathItem, "get") || !record(pathItem.get) || own(pathItem.get, "$ref")) unsupported();
    if (own(pathItem.get, "requestBody") || own(pathItem.get, "callbacks")) unsupported();
    parameters(pathItem, pathItem.get, resolve);
    return { method: "GET" as const, path: value.path };
  });
  return { document: JSON.parse(JSON.stringify(document)) as Record<string, unknown>, operations };
}

const SCOPE_NOTE = "OpenAPI adapter uses only explicit synthetic GET selections and caller assertions; it does not discover targets, generate payloads, validate response schemas, or establish whole-API coverage.";
function errorCheck(code: string): CheckResult[] {
  return [{ id: "api.authorization", status: "error", findings: [], notes: [SCOPE_NOTE, "OpenAPI policy could not be validated; no requests were made."], metrics: { requestCount: 0, bytesInspected: 0, errorCode: code } }];
}

/** Reuse the API runner's credential, network, request/body-budget and cancellation controls. */
export async function runOpenApiPolicy(options: OpenApiRunOptions): Promise<CheckResult[]> {
  let policy: ApiPolicyV2;
  try {
    if (!record(options)) invalid();
    const prototype = Object.getPrototypeOf(options);
    if ((prototype !== Object.prototype && prototype !== null) || Object.getOwnPropertySymbols(options).length !== 0) invalid();
    keys(options as unknown as RecordValue, ["input"], ["allowPrivate", "timeoutMs", "env", "signal"]);
    if (Object.values(Object.getOwnPropertyDescriptors(options)).some((descriptor) => !("value" in descriptor))) invalid();
    policy = buildOpenApiPolicy(options.input);
  } catch (error) {
    return errorCheck(error instanceof OpenApiPolicyError ? error.code : "invalid_openapi_policy");
  }
  const checks = await runApiPolicy({ policy, allowPrivate: options.allowPrivate, timeoutMs: options.timeoutMs, env: options.env, signal: options.signal });
  for (const check of checks) check.notes.unshift(SCOPE_NOTE);
  return checks;
}
