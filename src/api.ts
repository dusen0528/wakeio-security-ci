import { apiRequestPlanDigest, createApiExecutionLedger, finishApiExecutionLedger } from "./api-execution.js";
import type { ApiExecutionLedger, ApiExecutionStep, ApiRequestPlan, ApiRequestPlanStep } from "./contracts.js";
export type { ApiRequestPlan, ApiRequestPlanStep } from "./contracts.js";
import { ApiPolicyError } from "./api-policy-error.js";
import { types } from "node:util";
import { snapshotJsonData } from "./json-snapshot.js";
import { ownedApiCapture, type ApiStateCaptureSession } from './api-state-capture.js';
import type { CheckResult, Finding } from "./contracts.js";
import {
  MAX_REQUESTS,
  MAX_SINGLE_BODY_BYTES,
  UrlNetworkError,
  fetchResource,
  normalizeUrl,
  validateStaticTarget,
  safeUrl,
  type FetchedResource,
  type NormalizedUrl,
  type UrlNetworkContext,
} from "./url-network.js";

/** The current API policy document version accepted by this preview. */
export const API_POLICY_VERSION = 2 as const;
/** Version 1 remains readable during migration, but cannot produce a clean result. */
export const API_POLICY_LEGACY_VERSION = 1 as const;
export const API_MAX_CASES = 20;
export const API_MAX_REQUESTS = Math.min(MAX_REQUESTS, 64);
export const API_MAX_TIMEOUT_MS = 120_000;
export const API_DEFAULT_TIMEOUT_MS = 30_000;
export const API_MAX_SINGLE_BODY_BYTES = MAX_SINGLE_BODY_BYTES;
export const API_MAX_TOTAL_BODY_BYTES = 10 * 1024 * 1024;

/** Shared deadline/cancellation contract for API runners and worker adapters. */
export function createApiRunControl(timeoutMs: number, signal?: AbortSignal, maxTimeoutMs: number = API_MAX_TIMEOUT_MS) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > maxTimeoutMs) {
    throw new RangeError("invalid API time budget");
  }
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError("invalid API cancellation signal");
  const controller = new AbortController();
  const deadlineAt = Date.now() + timeoutMs;
  const cancel = () => controller.abort();
  signal?.addEventListener("abort", cancel, { once: true });
  if (signal?.aborted) cancel();
  const timer = setTimeout(cancel, timeoutMs);
  return { signal: controller.signal, deadlineAt, dispose() {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
  } };
}

const MAX_ACTORS = 32;
const MAX_PATH_LENGTH = 2048;
const MAX_POINTER_LENGTH = 512;
const MAX_STATUS_VALUES = 16;
const MAX_AUTHORIZATION_LENGTH = 8192;
const API_SCOPE_NOTE = "API authorization preview sends bounded read-only GET requests from an explicit policy; it does not write, fuzz, execute browser code, follow redirects, or prove complete API security.";

export type JsonScalar = string | number | boolean | null;

export interface ApiScalarExpectation {
  jsonPointer: string;
  equals: JsonScalar;
}

/** Only the configured synthetic canary is searched; response values are never reported. */
export interface ApiProtectedExpectation extends ApiScalarExpectation {
  /** Default: pointer. json-values also checks exact scalar values at other JSON positions. */
  match?: "pointer" | "json-values";
}

export const API_MAX_EVIDENCE_NODES = 10_000;
export const API_MAX_EVIDENCE_DEPTH = 64;

/**
 * A GET identity control. The primary marker identifies the principal. An
 * optional organization marker may be shared by multiple principals.
 */
export interface ApiIdentityExpectation extends ApiScalarExpectation {
  path: string;
  status: number;
  organization?: ApiScalarExpectation;
}

export interface ApiActor {
  id: string;
  authorizationEnv?: string;
  identity?: ApiIdentityExpectation;
}

export interface ApiAllowExpectationV1 {
  actor: string;
  status: number;
  jsonPointer: string;
  equals: JsonScalar;
}

export interface ApiAllowExpectationV2 {
  actor: string;
  status: number;
  resource: ApiScalarExpectation;
  protected: ApiProtectedExpectation;
}

export type ApiAllowExpectation = ApiAllowExpectationV1 | ApiAllowExpectationV2;

export interface ApiDenyExpectationV1 {
  actor: string;
  statuses: number[];
}

export interface ApiDenyExpectationV2 {
  actor: string;
  statuses: number[];
  /** Empty response bodies are accepted only after actor identity succeeds. */
  allowEmptyBody?: boolean;
}

export type ApiDenyExpectation = ApiDenyExpectationV1 | ApiDenyExpectationV2;

export interface ApiPolicyCase {
  id: string;
  path: string;
  allow: ApiAllowExpectation;
  deny: ApiDenyExpectation[];
}

export interface ApiPolicyV1 {
  version: 1;
  baseUrl: string;
  actors: ApiActor[];
  cases: Array<ApiPolicyCase & { allow: ApiAllowExpectationV1; deny: ApiDenyExpectationV1[] }>;
}

export interface ApiAuthenticatedActorV2 extends ApiActor {
  authorizationEnv: string;
  identity: ApiIdentityExpectation;
}

export interface ApiAnonymousActorV2 extends ApiActor {
  id: "anonymous";
  authorizationEnv?: undefined;
  identity?: undefined;
}

export interface ApiPolicyV2 {
  version: 2;
  baseUrl: string;
  actors: Array<ApiAuthenticatedActorV2 | ApiAnonymousActorV2>;
  cases: Array<ApiPolicyCase & { allow: ApiAllowExpectationV2; deny: ApiDenyExpectationV2[] }>;
}

export type ApiPolicy = ApiPolicyV1 | ApiPolicyV2;

interface NormalizedIdentity extends ApiIdentityExpectation {
  requestUrl: NormalizedUrl;
}

interface NormalizedAllow {
  actor: string;
  status: number;
  resource: ApiScalarExpectation;
  protected?: ApiProtectedExpectation;
}

interface NormalizedDeny {
  actor: string;
  statuses: number[];
  allowEmptyBody: boolean;
}

interface ParsedApiCase {
  id: string;
  path: string;
  requestUrl: NormalizedUrl;
  allow: NormalizedAllow;
  deny: NormalizedDeny[];
}

interface ParsedApiPolicy {
  policy: ApiPolicy;
  baseUrl: NormalizedUrl;
  cases: ParsedApiCase[];
  identities: Map<string, NormalizedIdentity>;
  expectedRequests: number;
  legacy: boolean;
}

export interface ApiRunOptions {
  policy: unknown;
  allowPrivate?: boolean;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}

interface CredentialSet {
  values: Map<string, string | undefined>;
  hasAuthenticatedActor: boolean;
}

/** Fixed counters only: no credentials, response values or caller identifiers. */
interface SessionDiagnostics {
  authenticatedDeny401Count: number;
  identityStatusMismatches: number;
  identityResponseFailures: number;
  identityPrincipalMismatches: number;
  identityOrganizationMismatches: number;
  identityRequestFailures: number;
}

interface RequestContextState {
  execution: ApiExecutionLedger;
  requestOffset: number;
  activeStep?: ApiExecutionStep;
  actorIndexes: Map<string, number>;
  caseIndexes: Map<string, number>;
  session: SessionDiagnostics;
  ownedCapture?: ApiStateCaptureSession;
  context: UrlNetworkContext;
  bytes: number;
  stopRequests: boolean;
  bodyBudgetExhausted: boolean;
  bodyReadIncomplete: boolean;
}

interface RequestSuccess {
  resource: FetchedResource;
}

interface RequestFailure {
  errorCode: string;
}

type RequestOutcome = RequestSuccess | RequestFailure;

interface JsonRead {
  valid: true;
  value: unknown;
}

interface JsonReadFailure {
  valid: false;
  reason: "non_json" | "malformed_json";
}

type JsonReadResult = JsonRead | JsonReadFailure;

interface ControlResult {
  valid: boolean;
}


function invalid(message: string): never {
  throw new ApiPolicyError("invalid_policy", message);
}

function policyLocation<T>(location: string, read: () => T): T {
  try { return read(); }
  catch (error) {
    if (error instanceof ApiPolicyError) {
      if (error.location === 'policy') error.location = location;
      else if (!error.location.startsWith('policy.')) error.location = `${location}.${error.location}`;
    }
    throw error;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !types.isProxy(value) && !Array.isArray(value);
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], label: string): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) invalid(`${label} contains an unknown key`);
  }
  for (const key of required) {
    if (!hasOwn(value, key)) invalid(`${label} is missing a required key`);
  }
}

function safeIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(value)) {
    invalid(`${label} must be a strict identifier`);
  }
  return value;
}

function safeEnvironmentName(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Z][A-Z0-9_]{0,127}$/.test(value)) {
    invalid("authorizationEnv must be a strict environment variable name");
  }
  return value;
}

function safePolicyPath(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_PATH_LENGTH ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("?") ||
    value.includes("#") ||
    value.includes("\\") ||
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  ) {
    invalid("case path must be an absolute same-origin path without query or fragment");
  }
  return value;
}

function safeJsonPointer(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > MAX_POINTER_LENGTH ||
    (value.length > 0 && !value.startsWith("/")) ||
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  ) {
    invalid("jsonPointer must be an RFC 6901 pointer");
  }
  for (const segment of value.split("/")) {
    if (segment.includes("~") && /~(?![01])/.test(segment)) invalid("jsonPointer contains an invalid escape");
  }
  return value;
}

function scalar(value: unknown, label: string): JsonScalar {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  invalid(`${label} must be a JSON scalar`);
}

function integerStatus(value: unknown, label: string, allowSuccess: boolean): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 100 || value > 599) {
    invalid(`${label} must be an HTTP status code`);
  }
  if (allowSuccess && (value < 200 || value > 299)) invalid(`${label} must be a successful 2xx status`);
  return value;
}

function parseScalarExpectation(value: unknown, label: string): ApiScalarExpectation {
  if (!isRecord(value)) invalid(`${label} must be an object`);
  exactKeys(value, ["jsonPointer", "equals"], [], label);
  return {
    jsonPointer: safeJsonPointer(value.jsonPointer),
    equals: scalar(value.equals, `${label} equals`),
  };
}

function parseIdentity(value: unknown): ApiIdentityExpectation {
  if (!isRecord(value)) invalid("identity must be an object");
  exactKeys(value, ["path", "status", "jsonPointer", "equals"], ["organization"], "identity");
  const principal = scalar(value.equals, "identity equals");
  if (typeof principal !== "string" || principal.trim().length === 0) invalid("identity equals must be a non-empty string principal marker");
  const identity: ApiIdentityExpectation = {
    path: safePolicyPath(value.path),
    status: integerStatus(value.status, "identity status", true),
    jsonPointer: safeJsonPointer(value.jsonPointer),
    equals: principal,
  };
  if (hasOwn(value, "organization")) identity.organization = parseScalarExpectation(value.organization, "identity organization");
  return identity;
}

function parseActor(value: unknown, version: 1 | 2): ApiActor {
  if (!isRecord(value)) invalid("actor must be an object");
  exactKeys(value, ["id"], version === 2 ? ["authorizationEnv", "identity"] : ["authorizationEnv"], "actor");
  const id = safeIdentifier(value.id, "actor id");
  const actor: ApiActor = { id };
  if (hasOwn(value, "authorizationEnv")) actor.authorizationEnv = policyLocation("authorizationEnv", () => safeEnvironmentName(value.authorizationEnv));
  if (id === "anonymous" && actor.authorizationEnv !== undefined) invalid("anonymous actor cannot carry credentials");
  if (hasOwn(value, "identity")) actor.identity = policyLocation("identity", () => parseIdentity(value.identity));
  if (version === 1 && actor.identity !== undefined) invalid("policy version 1 actors may not declare identity; migrate to version 2");
  if (version === 2) {
    if (id === "anonymous" && actor.identity !== undefined) invalid("anonymous actor cannot carry identity");
    if (actor.authorizationEnv === undefined && id !== "anonymous") invalid("unauthenticated actors must use the anonymous id");
    if (actor.authorizationEnv !== undefined && actor.identity === undefined) invalid("authenticated version 2 actors must declare an identity control");
  }
  return actor;
}

function parseAllow(value: unknown, version: 1 | 2): ApiAllowExpectation {
  if (!isRecord(value)) invalid("allow must be an object");
  const actor = safeIdentifier(value.actor, "allow actor");
  const status = integerStatus(value.status, "allow status", true);
  if (version === 1) {
    exactKeys(value, ["actor", "status", "jsonPointer", "equals"], [], "allow");
    return { actor, status, jsonPointer: safeJsonPointer(value.jsonPointer), equals: scalar(value.equals, "allow equals") };
  }
  exactKeys(value, ["actor", "status", "resource", "protected"], [], "allow");
  const resource = parseScalarExpectation(value.resource, "allow resource");
  if (!isRecord(value.protected)) invalid("allow protected must be an object");
  exactKeys(value.protected, ["jsonPointer", "equals"], ["match"], "allow protected");
  if (hasOwn(value.protected, "match") && value.protected.match !== "pointer" && value.protected.match !== "json-values") invalid("allow protected match is unsupported");
  const protectedMarker: ApiProtectedExpectation = {
    ...parseScalarExpectation({ jsonPointer: value.protected.jsonPointer, equals: value.protected.equals }, "allow protected"),
    ...(hasOwn(value.protected, "match") ? { match: value.protected.match as "pointer" | "json-values" } : {}),
  };
  if (resource.jsonPointer === protectedMarker.jsonPointer) invalid("allow resource and protected assertions must use separate JSON pointers");
  if (typeof protectedMarker.equals !== "string" || protectedMarker.equals.trim().length === 0) invalid("allow protected equals must be a non-empty string canary");
  if (scalarMatches(protectedMarker.equals, resource.equals)) invalid("allow protected canary must differ from the resource identity marker");
  return { actor, status, resource, protected: protectedMarker };
}

function parseDeny(value: unknown, version: 1 | 2): ApiDenyExpectation {
  if (!isRecord(value)) invalid("deny entry must be an object");
  exactKeys(value, ["actor", "statuses"], version === 2 ? ["allowEmptyBody"] : [], "deny entry");
  const actor = safeIdentifier(value.actor, "deny actor");
  if (!Array.isArray(value.statuses) || value.statuses.length === 0 || value.statuses.length > MAX_STATUS_VALUES) {
    invalid("deny statuses must be a bounded non-empty array");
  }
  const statuses = value.statuses.map((status, index) => integerStatus(status, `deny status ${index}`, false));
  if (new Set(statuses).size !== statuses.length) invalid("deny statuses may not contain duplicates");
  if (version === 2 && hasOwn(value, "allowEmptyBody") && typeof value.allowEmptyBody !== "boolean") invalid("allowEmptyBody must be boolean");
  return version === 2 ? { actor, statuses, ...(value.allowEmptyBody === true ? { allowEmptyBody: true } : {}) } : { actor, statuses };
}

function parseCase(value: unknown, version: 1 | 2): ApiPolicyCase {
  if (!isRecord(value)) invalid("case must be an object");
  exactKeys(value, ["id", "path", "allow", "deny"], [], "case");
  const id = safeIdentifier(value.id, "case id");
  const path = safePolicyPath(value.path);
  const allow = policyLocation("allow", () => parseAllow(value.allow, version));
  if (!Array.isArray(value.deny) || value.deny.length === 0 || value.deny.length > MAX_ACTORS) {
    invalid("case deny must be a bounded non-empty array");
  }
  const deny = value.deny.map((entry, index) => policyLocation(`deny[${index}]`, () => parseDeny(entry, version)));
  if (new Set(deny.map((entry) => entry.actor)).size !== deny.length) invalid("case deny actors may not be duplicated");
  return { id, path, allow, deny };
}

function normalizeBaseUrl(value: unknown): NormalizedUrl {
  if (typeof value !== "string") invalid("baseUrl must be an HTTP(S) URL");
  let normalized: NormalizedUrl;
  try {
    normalized = normalizeUrl(value);
  } catch {
    invalid("baseUrl must be an HTTP(S) URL without credentials");
  }
  const parsed = new URL(normalized.href);
  if (parsed.search || parsed.hash) invalid("baseUrl may not contain a query or fragment");
  return normalized;
}

/**
 * Parse and validate the deliberately small API policy contract. This is
 * synchronous and performs no DNS lookup or other network operation.
 */
export function parseApiPolicy(input: unknown): ParsedApiPolicy {
  try { input = snapshotJsonData(input); } catch { invalid("policy must be bounded JSON data without accessors or custom objects"); }
  if (!isRecord(input)) invalid("policy must be a JSON object");
  exactKeys(input, ["version", "baseUrl", "actors", "cases"], [], "policy");
  const version = input.version === API_POLICY_VERSION || input.version === API_POLICY_LEGACY_VERSION ? input.version : undefined;
  if (version === undefined) invalid("policy version is unsupported");
  const baseUrl = policyLocation("policy.baseUrl", () => normalizeBaseUrl(input.baseUrl));
  if (!Array.isArray(input.actors) || input.actors.length === 0 || input.actors.length > MAX_ACTORS) {
    invalid("actors must be a bounded non-empty array");
  }
  const actors = input.actors.map((actor, index) => policyLocation(`policy.actors[${index}]`, () => parseActor(actor, version)));
  const actorIds = new Set<string>();
  actors.forEach((actor, index) => {
    if (actorIds.has(actor.id)) policyLocation(`policy.actors[${index}].id`, () => invalid("actor ids may not be duplicated"));
    actorIds.add(actor.id);
  });
  const seenEnvs = new Set<string>();
  actors.forEach((actor, index) => {
    if (actor.authorizationEnv === undefined) return;
    if (seenEnvs.has(actor.authorizationEnv)) policyLocation(`policy.actors[${index}].authorizationEnv`, () => invalid("authorizationEnv may not be reused"));
    seenEnvs.add(actor.authorizationEnv);
  });
  if (!Array.isArray(input.cases) || input.cases.length === 0 || input.cases.length > API_MAX_CASES) {
    invalid(`cases must contain between 1 and ${API_MAX_CASES} entries`);
  }
  const cases = input.cases.map((entry, index) => policyLocation(`policy.cases[${index}]`, () => parseCase(entry, version)));
  const caseIds = new Set<string>();
  cases.forEach((entry, index) => {
    if (caseIds.has(entry.id)) policyLocation(`policy.cases[${index}].id`, () => invalid("case ids may not be duplicated"));
    caseIds.add(entry.id);
  });
  const parsedCases: ParsedApiCase[] = [];
  const resolvePath = (path: string, label: string): NormalizedUrl => {
    let requestUrl: NormalizedUrl;
    try {
      requestUrl = normalizeUrl(new URL(path, baseUrl.href).toString());
    } catch {
      invalid(`${label} path could not be resolved safely`);
    }
    const resolved = new URL(requestUrl.href);
    if (requestUrl.origin !== baseUrl.origin || resolved.username || resolved.password || resolved.hash || resolved.search) {
      invalid(`${label} path must resolve to the base origin without credentials or query values`);
    }
    return requestUrl;
  };
  for (const entry of cases) {
    let normalizedAllow: NormalizedAllow;
    if (version === 1) {
      const allow = entry.allow as ApiAllowExpectationV1;
      normalizedAllow = { actor: allow.actor, status: allow.status, resource: { jsonPointer: allow.jsonPointer, equals: allow.equals } };
    } else {
      const allow = entry.allow as ApiAllowExpectationV2;
      normalizedAllow = { actor: allow.actor, status: allow.status, resource: allow.resource, protected: allow.protected };
    }
    parsedCases.push({
      id: entry.id,
      path: entry.path,
      requestUrl: resolvePath(entry.path, "case"),
      allow: normalizedAllow,
      deny: entry.deny.map((deny) => {
        if (version === 1) {
          const normalized = deny as ApiDenyExpectationV1;
          return { actor: normalized.actor, statuses: normalized.statuses, allowEmptyBody: false };
        }
        const normalized = deny as ApiDenyExpectationV2;
        return { actor: normalized.actor, statuses: normalized.statuses, allowEmptyBody: normalized.allowEmptyBody === true };
      }),
    });
  }
  const actorById = new Map(actors.map((actor) => [actor.id, actor]));
  const identities = new Map<string, NormalizedIdentity>();
  for (const actor of actors) {
    if (actor.identity) identities.set(actor.id, { ...actor.identity, requestUrl: resolvePath(actor.identity.path, "identity") });
  }
  for (const [caseIndex, entry] of parsedCases.entries()) {
    policyLocation(`policy.cases[${caseIndex}].allow.actor`, () => {
      if (!actorById.has(entry.allow.actor)) invalid("allow actor must refer to a configured actor");
      if (actorById.get(entry.allow.actor)?.authorizationEnv === undefined) invalid("allow actor must have an authorizationEnv");
    });
    for (const [denyIndex, deny] of entry.deny.entries()) policyLocation(`policy.cases[${caseIndex}].deny[${denyIndex}].actor`, () => {
      if (!actorById.has(deny.actor)) invalid("deny actor must refer to a configured actor");
      if (deny.actor === entry.allow.actor) invalid("deny actor may not equal the allow actor");
    });
  }
  const identityCount = version === 2 ? actors.filter((actor) => actor.authorizationEnv !== undefined).length : 0;
  const expectedRequests = identityCount * 2 + parsedCases.reduce((sum, entry) => sum + 2 + entry.deny.length, 0);
  if (expectedRequests > API_MAX_REQUESTS) invalid(`policy exceeds the ${API_MAX_REQUESTS}-request budget`);
  const policy: ApiPolicy = version === 2
    ? {
      version: 2,
      baseUrl: baseUrl.href,
      actors: actors as ApiPolicyV2["actors"],
      cases: cases as ApiPolicyV2["cases"],
    }
    : {
      version: 1,
      baseUrl: baseUrl.href,
      actors,
      cases: cases as ApiPolicyV1["cases"],
    };
  return { policy, baseUrl, cases: parsedCases, identities, expectedRequests, legacy: version === API_POLICY_LEGACY_VERSION };
}

/** Alias for callers that prefer a validation-named API. Throws on invalid input. */
export function validateApiPolicy(input: unknown): ParsedApiPolicy {
  return parseApiPolicy(input);
}

/** A configuration check, never a scan result or authorization to contact a target. */
export interface ApiPreflightIssue { code: string; location: string; message: string }
export interface ApiPreflightResult {
  version: 1;
  kind: 'api-preflight';
  status: 'ready' | 'blocked';
  execution: 'not_run';
  networkRequests: 0;
  dnsLookups: 0;
  policyVersion: 1 | 2 | null;
  /** Redacted plan identity only; no target, credential or assertion values are hashed. */
  planSha256: string | null;
  issues: ApiPreflightIssue[];
  plan: ApiRequestPlan | null;
  limitations: string[];
}
const PREFLIGHT_LIMITATIONS = [
  'Configuration only: no requests or DNS lookups were made; no scan findings or security verdict exist.',
  'Indexes refer to the input arrays; target URLs, paths, caller identifiers, environment names and assertion values are omitted.',
  'Runtime must revalidate credentials, DNS answers, pinned connections, responses, principal identity and owner controls.',
  'The logical GET plan includes before/after controls; failed controls or cancellation may skip steps. Address retries share the HTTP attempt cap.',
  'An authenticated probe returning HTTP 401 remains incomplete even if listed; before/after identity checks cannot establish uninterrupted session or tenant continuity.',
  'GET-only does not establish that an application route has no side effects. Use only explicitly authorized synthetic resources.',
  'No target discovery, write requests, fuzzing, response-schema validation or whole-service security coverage.',
];
/** Fixed diagnostic envelope also used by the OpenAPI adapter and CLI. */
function blockedApiPreflight(code: string, location: string, message: string): ApiPreflightResult {
  // This constructor accepts only fixed strings at internal call sites, not errors from input.
  return { version: 1, kind: 'api-preflight', status: 'blocked', execution: 'not_run', networkRequests: 0, dnsLookups: 0,
    policyVersion: null, planSha256: null, issues: [{ code, location, message }], plan: null, limitations: [...PREFLIGHT_LIMITATIONS] };
}

class ApiPreparationError extends Error {
  constructor(readonly issue: ApiPreflightIssue) { super(issue.message); }
}
function preparationError(code: string, location: string, message: string): never {
  throw new ApiPreparationError({ code, location, message });
}

/** Shared with execution; no network, no retained secret-bearing public output. */
function prepareApiRun(options: ApiRunOptions): { parsed: ParsedApiPolicy; credentials: CredentialSet; timeoutMs: number; allowPrivate: boolean; signal?: AbortSignal } {
  if (!isRecord(options)) preparationError('invalid_options', 'options', 'Provide a plain API run options object.');
  const proto = Object.getPrototypeOf(options);
  const descriptors = Object.getOwnPropertyDescriptors(options);
  if ((proto !== Object.prototype && proto !== null) || Object.getOwnPropertySymbols(options).length
    || Object.keys(descriptors).some(key => !['policy', 'allowPrivate', 'timeoutMs', 'env', 'signal'].includes(key))
    || Object.values(descriptors).some(value => !('value' in value) || !value.enumerable)) {
    preparationError('invalid_options', 'options', 'Use only documented data properties; accessors and custom objects are unsupported.');
  }
  // Read only this bounded own-data snapshot. Inherited getters must never
  // enable private transport or supply credentials; later caller mutation must
  // not change execution options or the report's account of those options.
  options = Object.create(null, descriptors) as ApiRunOptions;
  if (options.signal !== undefined && (types.isProxy(options.signal) || !(options.signal instanceof AbortSignal))) preparationError('invalid_options', 'signal', 'signal must be an AbortSignal.');
  if (options.allowPrivate !== undefined && typeof options.allowPrivate !== 'boolean') preparationError('invalid_options', 'allowPrivate', 'allowPrivate must be boolean.');
  const timeoutMs = options.timeoutMs === undefined ? API_DEFAULT_TIMEOUT_MS : options.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > API_MAX_TIMEOUT_MS) preparationError('invalid_options', 'timeoutMs', `Set timeoutMs between 1 and ${API_MAX_TIMEOUT_MS}.`);
  let parsed: ParsedApiPolicy;
  try { parsed = parseApiPolicy(options.policy); }
  catch (error) { preparationError('invalid_policy', error instanceof ApiPolicyError ? error.location : 'policy', error instanceof ApiPolicyError ? error.message : 'Provide a valid bounded API policy JSON object.'); }
  const env = options.env === undefined ? process.env : options.env;
  if (!env || typeof env !== 'object' || types.isProxy(env) || Array.isArray(env)) preparationError('invalid_environment', 'env', 'Provide an environment object with data properties.');
  const principals = new Set<JsonScalar>();
  parsed.policy.actors.forEach((actor, actorIndex) => {
    if (!actor.identity) return;
    if (principals.has(actor.identity.equals)) preparationError('duplicate_principal', `policy.actors[${actorIndex}].identity.equals`, 'Distinct authenticated actors require distinct expected principal markers; organization markers may be shared.');
    principals.add(actor.identity.equals);
  });
  const credentials = resolveCredentials(parsed, env);
  if (parsed.baseUrl.protocol === 'http:' && credentials.hasAuthenticatedActor && !(options.allowPrivate === true && isLoopbackHostname(parsed.baseUrl.hostname))) {
    preparationError('insecure_authenticated_transport', 'policy.baseUrl', 'Use HTTPS for authenticated targets; HTTP is limited to explicit private loopback fixtures.');
  }
  return { parsed, credentials, timeoutMs, allowPrivate: options.allowPrivate === true, signal: options.signal };
}

function requestPlan(parsed: ParsedApiPolicy, timeoutMs: number, allowPrivate: boolean): ApiRequestPlan {
  const steps: ApiRequestPlanStep[] = [];
  const indexes = new Map(parsed.policy.actors.map((actor, index) => [actor.id, index]));
  const add = (phase: ApiRequestPlanStep['phase'], actor: string, caseIndex?: number) => {
    steps.push({ ordinal: steps.length, method: 'GET', phase, actorIndex: indexes.get(actor)!, ...(caseIndex === undefined ? {} : { caseIndex }) });
  };
  if (!parsed.legacy) for (const actor of parsed.policy.actors) if (actor.identity) add('identity-before', actor.id);
  parsed.cases.forEach((entry, caseIndex) => {
    add('owner-before', entry.allow.actor, caseIndex);
    for (const deny of entry.deny) add('deny', deny.actor, caseIndex);
    add('owner-after', entry.allow.actor, caseIndex);
  });
  if (!parsed.legacy) for (const actor of parsed.policy.actors) if (actor.identity) add('identity-after', actor.id);
  return { actorCount: parsed.policy.actors.length, caseCount: parsed.cases.length, logicalRequests: parsed.expectedRequests,
    maximumHttpAttempts: API_MAX_REQUESTS, timeoutMs, maximumResponseBytes: API_MAX_SINGLE_BODY_BYTES,
    maximumTotalResponseBytes: API_MAX_TOTAL_BODY_BYTES, allowPrivate, steps };
}

/** Offline, redacted configuration and execution-plan preview. Ready is not a scan pass. */
export function preflightApiPolicy(options: ApiRunOptions): ApiPreflightResult {
  try {
    const { parsed, timeoutMs, allowPrivate, signal } = prepareApiRun(options);
    const issues: ApiPreflightIssue[] = [];
    if (parsed.legacy) issues.push({ code: 'legacy_policy', location: 'policy.version', message: 'Migrate to version 2 with identity and protected-canary assertions; version 1 cannot establish a clean authorization result.' });
    if (signal && Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(signal)) issues.push({ code: 'cancelled', location: 'signal', message: 'The supplied cancellation signal is already aborted.' });
    try { validateStaticTarget(parsed.baseUrl, allowPrivate); }
    catch { issues.push({ code: 'blocked_target', location: 'policy.baseUrl', message: 'The target violates static network policy; metadata and forbidden ranges stay blocked even with allowPrivate.' }); }
    const plan = requestPlan(parsed, timeoutMs, allowPrivate);
    return { version: 1, kind: 'api-preflight', status: issues.length ? 'blocked' : 'ready', execution: 'not_run',
      networkRequests: 0, dnsLookups: 0, policyVersion: parsed.policy.version, issues,
      plan, planSha256: apiRequestPlanDigest(parsed.policy.version, plan),
      limitations: [...PREFLIGHT_LIMITATIONS] };
  } catch (error) {
    return error instanceof ApiPreparationError ? blockedApiPreflight(error.issue.code, error.issue.location, error.issue.message)
      : blockedApiPreflight('invalid_options', 'options', 'Could not validate the supplied configuration data.');
  }
}

function codeOf(error: unknown): string {
  if (error instanceof UrlNetworkError) return error.code;
  if (error instanceof ApiPolicyError) return error.code;
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && /^[a-z0-9_:-]+$/i.test(code)) return code.slice(0, 80);
  }
  return "collection_error";
}

function validAuthorization(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_AUTHORIZATION_LENGTH) return false;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 0x20 || code === 0x7f || code > 0xff) return false;
  }
  return true;
}

function resolveCredentials(parsed: ParsedApiPolicy, env: NodeJS.ProcessEnv): CredentialSet {
  const values = new Map<string, string | undefined>();
  const seenValues = new Set<string>();
  let hasAuthenticatedActor = false;
  for (const [actorIndex, actor] of parsed.policy.actors.entries()) {
    if (actor.authorizationEnv === undefined) continue;
    hasAuthenticatedActor = true;
    const descriptor = Object.getOwnPropertyDescriptor(env, actor.authorizationEnv);
    const value = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    const location = `policy.actors[${actorIndex}].authorizationEnv`;
    if (!validAuthorization(value)) preparationError('invalid_credentials', location, 'Set the referenced environment variable to a non-empty valid HTTP header value; accessors and inherited values are unsupported.');
    if (seenValues.has(value)) preparationError('duplicate_credentials', location, 'The referenced authorization value must differ from every other authenticated actor.');
    seenValues.add(value);
    values.set(actor.id, value);
  }
  return { values, hasAuthenticatedActor };
}

function isLoopbackHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return lower === "localhost" || lower === "127.0.0.1" || lower === "::1";
}

function isJsonContentType(resource: FetchedResource): boolean {
  const values = Object.entries(resource.headers).find(([key]) => key.toLowerCase() === "content-type")?.[1];
  const contentType = Array.isArray(values) ? values[0] : values;
  if (typeof contentType !== "string") return false;
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/json" || mediaType === "text/json" || mediaType.endsWith("+json");
}

function readJson(resource: FetchedResource): JsonReadResult {
  if (!isJsonContentType(resource)) return { valid: false, reason: "non_json" };
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(resource.body);
    return { valid: true, value: JSON.parse(text) as unknown };
  } catch {
    return { valid: false, reason: "malformed_json" };
  }
}

function pointerParts(pointer: string): string[] {
  if (pointer === "") return [];
  return pointer.slice(1).split("/").map((segment) => segment.replace(/~1/g, "/").replace(/~0/g, "~"));
}

function atJsonPointer(value: unknown, pointer: string): unknown {
  let current: unknown = value;
  for (const part of pointerParts(pointer)) {
    if (Array.isArray(current)) {
      if (!/^0$|^[1-9]\d*$/.test(part)) return undefined;
      const index = Number(part);
      if (!Number.isSafeInteger(index) || index >= current.length) return undefined;
      current = current[index];
    } else if (isRecord(current) && Object.prototype.hasOwnProperty.call(current, part)) {
      current = current[part];
    } else {
      return undefined;
    }
  }
  return current;
}

function scalarMatches(actual: unknown, expected: JsonScalar): boolean {
  if (actual === null || typeof actual === "string" || typeof actual === "boolean") return actual === expected && typeof actual === typeof expected;
  return typeof actual === "number" && Number.isFinite(actual) && typeof expected === "number" && actual === expected;
}

function expectedStatusNote(statuses: readonly number[]): string {
  return `[${statuses.join(", ")}]`;
}

function addNote(notes: string[], note: string): void {
  if (!notes.includes(note)) notes.push(note);
}

interface ActorIdentityState {
  actorId: string;
  required: boolean;
  beforeValid: boolean;
  afterValid: boolean;
  beforePrincipal?: JsonScalar;
  afterPrincipal?: JsonScalar;
  identityReuse: boolean;
}

function findingForExposure(entry: ParsedApiCase, deny: NormalizedDeny, status: number): Finding {
  return {
    id: `api.authorization-data-exposure:${entry.id}:${deny.actor}`,
    ruleId: "api.authorization-data-exposure",
    title: `Unauthorized actor ${deny.actor} received the protected canary in case ${entry.id}`,
    description: `Case ${entry.id}: actor ${deny.actor} received the configured protected canary with HTTP status ${status}; this is a scoped authorization data-exposure finding.`,
    severity: "high",
    confidence: "high",
    kind: "candidate",
    location: { url: safeUrl(entry.requestUrl) },
    remediation: "Enforce object-level authorization for the requested resource and repeat this policy with distinct test accounts after the fix.",
    references: ["https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/"],
  };
}

async function requestApi(
  url: NormalizedUrl,
  authorization: string | undefined,
  state: RequestContextState,
): Promise<RequestOutcome> {
  if (state.stopRequests || state.ownedCapture?.budget?.bodyExhausted) { state.bodyBudgetExhausted = true; state.bodyReadIncomplete ||= state.ownedCapture?.budget?.bodyReadIncomplete ?? false; if (state.activeStep) state.activeStep.reason = state.ownedCapture?.budget ? "shared_body_budget" : "body_budget"; return { errorCode: state.bodyReadIncomplete ? "body_limit" : "total_body_limit" }; }
  const bodyBytes = () => state.ownedCapture?.budget?.bytes ?? state.bytes;
  if (bodyBytes() >= API_MAX_TOTAL_BODY_BYTES) {
    state.stopRequests = true;
    state.bodyBudgetExhausted = true;
    if (state.ownedCapture?.budget) state.ownedCapture.budget.bodyExhausted = true;
    if (state.activeStep) state.activeStep.reason = state.ownedCapture?.budget ? "shared_body_budget" : "body_budget";
    return { errorCode: "total_body_limit" };
  }
  const capture = state.ownedCapture;
  let capturedOrdinal: number | undefined;
  try { capturedOrdinal = capture?.start(url, authorization); } catch { /* Passive observation never changes API adjudication. */ }
  try {
    const resource = await fetchResource(
      url,
      {
        ...state.context,
        authorization,
        rejectRedirects: true,
        acceptJson: true,
      },
      url.origin,
      Math.min(MAX_SINGLE_BODY_BYTES, API_MAX_TOTAL_BODY_BYTES - bodyBytes()),
      Math.min(MAX_SINGLE_BODY_BYTES, API_MAX_TOTAL_BODY_BYTES - bodyBytes()),
    );
    state.bytes += resource.body.byteLength;
    if (state.ownedCapture?.budget) state.ownedCapture.budget.bytes += resource.body.byteLength;
    if (state.activeStep) state.activeStep.httpStatus = resource.status;
    try { capture?.finish(capturedOrdinal, resource); } catch { /* Oracle handles missing capture. */ }
    return { resource };
  } catch (error) {
    try { capture?.finish(capturedOrdinal); } catch { /* Oracle handles missing capture. */ }
    const errorCode = codeOf(error);
    if (state.activeStep) state.activeStep.reason = requestFailureReason(errorCode, state);
    // readResponseBody can reject after consuming a final chunk that crosses
    // the cap. Stop the whole preview on that terminal condition so repeated
    // cases cannot accumulate unaccounted response bytes.
    if (errorCode === "body_limit") {
      state.stopRequests = true;
      state.bodyBudgetExhausted = true;
      state.bodyReadIncomplete = true;
      if (state.ownedCapture?.budget) { state.ownedCapture.budget.bodyExhausted = true; state.ownedCapture.budget.bodyReadIncomplete = true; }
    }
    return { errorCode };
  }
}

function requestFailureReason(code: string, state: RequestContextState): ApiExecutionStep['reason'] {
  if (Date.now() >= state.context.deadlineAt) return 'deadline';
  if (state.context.signal.aborted) return 'cancelled';
  if (['body_limit', 'total_body_limit'].includes(code)) return state.ownedCapture?.budget ? 'shared_body_budget' : 'body_budget';
  if (code === 'request_limit') return state.ownedCapture?.budget ? 'shared_request_budget' : 'request_budget';
  if (/blocked|private|metadata|redirect|scheme|port|address/.test(code)) return 'network_policy';
  return 'transport_error';
}

async function recordStep<T>(state: RequestContextState, phase: ApiRequestPlanStep['phase'], actor: string,
  caseId: string | undefined, execute: () => Promise<T>, evaluated: (result: T) => boolean): Promise<T> {
  const plan = state.execution.plan!;
  const actorIndex = state.actorIndexes.get(actor), caseIndex = caseId === undefined ? undefined : state.caseIndexes.get(caseId);
  const planned = plan.steps.find(step => step.phase === phase && step.actorIndex === actorIndex && step.caseIndex === caseIndex)!;
  const step = state.execution.steps[planned.ordinal];
  step.attemptStart = state.context.budget.count - state.requestOffset;
  state.activeStep = step;
  try {
    const result = await execute();
    step.httpAttempts = state.context.budget.count - state.requestOffset - step.attemptStart;
    step.outcome = step.httpAttempts === 0 ? 'not_attempted' : evaluated(result) ? 'evaluated' : 'inconclusive';
    if (step.outcome === 'evaluated') step.reason = 'evaluated';
    else if (step.reason === 'not_reached') step.reason = 'assertion_inconclusive';
    return result;
  } finally { state.activeStep = undefined; }
}

function controlFailureNote(caseId: string, phase: "before" | "after", detail: string): string {
  return `API case ${caseId}: owner positive control ${phase} failed (${detail}); authorization results are incomplete.`;
}

async function checkPositiveControl(
  entry: ParsedApiCase,
  actorAuthorization: string,
  phase: "before" | "after",
  state: RequestContextState,
  notes: string[],
): Promise<ControlResult> {
  const outcome = await requestApi(entry.requestUrl, actorAuthorization, state);
  if ("errorCode" in outcome) {
    addNote(notes, controlFailureNote(entry.id, phase, outcome.errorCode));
    return { valid: false };
  }
  const { resource } = outcome;
  if (resource.status !== entry.allow.status) {
    addNote(notes, controlFailureNote(entry.id, phase, `HTTP ${resource.status}`));
    return { valid: false };
  }
  const parsed = readJson(resource);
  if (!parsed.valid) {
    addNote(notes, controlFailureNote(entry.id, phase, parsed.reason));
    return { valid: false };
  }
  const resourceMarker = atJsonPointer(parsed.value, entry.allow.resource.jsonPointer);
  if (!scalarMatches(resourceMarker, entry.allow.resource.equals)) {
    addNote(notes, controlFailureNote(entry.id, phase, "resource identity marker mismatch"));
    return { valid: false };
  }
  if (entry.allow.protected) {
    const protectedMarker = atJsonPointer(parsed.value, entry.allow.protected.jsonPointer);
    if (!scalarMatches(protectedMarker, entry.allow.protected.equals)) {
      addNote(notes, controlFailureNote(entry.id, phase, "protected canary mismatch"));
      return { valid: false };
    }
  }
  addNote(notes, `API case ${entry.id}: owner positive control ${phase} passed with HTTP ${resource.status} and the configured resource${entry.allow.protected ? " and protected" : ""} assertions.`);
  return { valid: true };
}

function identityFailureNote(actorId: string, detail: string): string {
  return `API actor ${actorId}: identity positive control failed (${detail}); authorization results are incomplete.`;
}

async function checkIdentity(
  actorId: string,
  identity: NormalizedIdentity,
  authorization: string,
  phase: "before" | "after",
  state: RequestContextState,
  notes: string[],
): Promise<{ valid: boolean; principal?: JsonScalar }> {
  const outcome = await requestApi(identity.requestUrl, authorization, state);
  if ("errorCode" in outcome) {
    state.session.identityRequestFailures += 1;
    addNote(notes, identityFailureNote(actorId, `${phase} ${outcome.errorCode}`));
    return { valid: false };
  }
  const { resource } = outcome;
  if (resource.status !== identity.status) {
    state.session.identityStatusMismatches += 1;
    addNote(notes, identityFailureNote(actorId, `${phase} HTTP ${resource.status}`));
    return { valid: false };
  }
  const parsed = readJson(resource);
  if (!parsed.valid) {
    state.session.identityResponseFailures += 1;
    addNote(notes, identityFailureNote(actorId, `${phase} ${parsed.reason}`));
    return { valid: false };
  }
  const principal = atJsonPointer(parsed.value, identity.jsonPointer);
  if (!scalarMatches(principal, identity.equals)) {
    state.session.identityPrincipalMismatches += 1;
    addNote(notes, identityFailureNote(actorId, `${phase} principal marker mismatch`));
    // Keep a non-empty scalar in memory for the duplicate-principal guard.
    // It is never copied into notes, findings, or report output.
    return { valid: false, principal: typeof principal === "string" && principal.length > 0 ? principal : undefined };
  }
  if (identity.organization) {
    const organization = atJsonPointer(parsed.value, identity.organization.jsonPointer);
    if (!scalarMatches(organization, identity.organization.equals)) {
      state.session.identityOrganizationMismatches += 1;
      addNote(notes, identityFailureNote(actorId, `${phase} organization marker mismatch`));
      return { valid: false };
    }
  }
  addNote(notes, `API actor ${actorId}: identity positive control ${phase} passed with HTTP ${resource.status}.`);
  return { valid: true, principal: principal as JsonScalar };
}

function principalKey(value: JsonScalar): string {
  return JSON.stringify(value);
}

function markIdentityReuse(states: Map<string, ActorIdentityState>, phase: "before" | "after", notes: string[]): number {
  const seen = new Map<string, string[]>();
  for (const state of states.values()) {
    const principal = phase === "before" ? state.beforePrincipal : state.afterPrincipal;
    if (principal === undefined) continue;
    const key = principalKey(principal);
    const actors = seen.get(key) ?? [];
    actors.push(state.actorId);
    seen.set(key, actors);
  }
  let reused = 0;
  for (const actors of seen.values()) {
    if (actors.length < 2) continue;
    reused += 1;
    for (const actorId of actors) {
      const state = states.get(actorId);
      if (state) state.identityReuse = true;
    }
    addNote(notes, `API actors ${actors.join(", ")} returned the same principal identity in the ${phase} control; actors are not proven distinct.`);
  }
  return reused;
}

async function runIdentityControls(
  parsed: ParsedApiPolicy,
  credentials: CredentialSet,
  phase: "before" | "after",
  states: Map<string, ActorIdentityState>,
  state: RequestContextState,
  notes: string[],
): Promise<boolean> {
  let incomplete = false;
  for (const actor of parsed.policy.actors) {
    if (actor.authorizationEnv === undefined) continue;
    const identity = parsed.identities.get(actor.id);
    const authorization = credentials.values.get(actor.id);
    const current = states.get(actor.id);
    if (!identity || authorization === undefined || !current) {
      addNote(notes, identityFailureNote(actor.id, `${phase} identity is not configured`));
      incomplete = true;
      continue;
    }
    const result = await recordStep(state, phase === "before" ? "identity-before" : "identity-after", actor.id, undefined,
      () => checkIdentity(actor.id, identity, authorization, phase, state, notes), result => result.valid);
    if (phase === "before") {
      current.beforeValid = result.valid;
      current.beforePrincipal = result.principal;
    } else {
      current.afterValid = result.valid;
      current.afterPrincipal = result.principal;
    }
    if (!result.valid) incomplete = true;
    if (controllerAborted(state)) incomplete = true;
  }
  if (markIdentityReuse(states, phase, notes) > 0) incomplete = true;
  return incomplete;
}

function controllerAborted(state: RequestContextState): boolean {
  return state.context.signal.aborted;
}

function actorIdentityVerified(actorId: string, actor: ApiActor | undefined, states: Map<string, ActorIdentityState>): boolean {
  if (actor?.authorizationEnv === undefined) return actor?.id === "anonymous";
  const state = states.get(actorId);
  // The before-case control is the evidence available at the deny request.
  // The after-case control is checked separately so a token that expires or
  // changes principal during the run cannot yield a clean final result.
  return state?.beforeValid === true && state.identityReuse === false && state.beforePrincipal !== undefined;
}

function protectedEvidence(value: unknown, marker: ApiProtectedExpectation | undefined): { matched: boolean; complete: boolean } {
  if (!marker) return { matched: false, complete: true };
  if (marker.match !== "json-values") return { matched: scalarMatches(atJsonPointer(value, marker.jsonPointer), marker.equals), complete: true };
  if (scalarMatches(atJsonPointer(value, marker.jsonPointer), marker.equals)) return { matched: true, complete: true };
  // Iterative, bounded traversal. Keys, substrings, encoded values and arbitrary
  // secrets are deliberately outside this exact known-canary contract.
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let visited = 0;
  let complete = true;
  while (pending.length) {
    if (++visited > API_MAX_EVIDENCE_NODES) return { matched: false, complete: false };
    const current = pending.pop()!;
    if (scalarMatches(current.value, marker.equals)) return { matched: true, complete };
    if (current.value === null || typeof current.value !== "object") continue;
    if (current.depth >= API_MAX_EVIDENCE_DEPTH) { complete = false; continue; }
    const children = Object.values(current.value);
    // Never queue more work than the remaining node budget. A skipped branch
    // cannot justify a clean denial, even when the HTTP status was expected.
    if (children.length > API_MAX_EVIDENCE_NODES - visited - pending.length) return { matched: false, complete: false };
    for (let index = children.length - 1; index >= 0; index -= 1) pending.push({ value: children[index], depth: current.depth + 1 });
  }
  return { matched: false, complete };
}

function resourceMatches(value: unknown, marker: ApiScalarExpectation): boolean {
  return scalarMatches(atJsonPointer(value, marker.jsonPointer), marker.equals);
}

async function checkDeny(
  entry: ParsedApiCase,
  deny: NormalizedDeny,
  actor: ApiActor | undefined,
  denyAuthorization: string | undefined,
  identityVerified: boolean,
  legacy: boolean,
  state: RequestContextState,
  notes: string[],
  findings: Finding[],
): Promise<boolean> {
  const outcome = await requestApi(entry.requestUrl, denyAuthorization, state);
  if ("errorCode" in outcome) {
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} request failed (${outcome.errorCode}); denial is inconclusive.`);
    return true;
  }
  const { resource } = outcome;
  const status = resource.status;
  const expected = deny.statuses.includes(status);
  const parsed = readJson(resource);
  const evidence = parsed.valid ? protectedEvidence(parsed.value, entry.allow.protected) : { matched: false, complete: true };
  const protectedExposed = evidence.matched;

  if (protectedExposed) {
    findings.push(findingForExposure(entry, deny, status));
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned the protected canary with HTTP ${status}; exposure is recorded.`);
  }

  // Identity controls are point-in-time evidence, not proof that this request
  // authenticated. A 401 is inconclusive for an authenticated actor even if
  // whoami succeeds before and after (endpoint-local rejection or recovery).
  // Preserve observed canary exposure, including in a 401 response.
  if (status === 401 && actor?.authorizationEnv !== undefined) {
    state.session.authenticatedDeny401Count += 1;
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned HTTP 401 on an authenticated probe; authentication was not established for this request, so denial is inconclusive. Check credential validity and endpoint authentication requirements before rerunning.`);
    return true;
  }

  if (!evidence.complete) {
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} response exceeded the bounded canary evidence traversal; denial is inconclusive.`);
    return true;
  }

  // A rate limit or server failure is never a denial, even when the policy
  // lists its status. Preserve a canary finding, but keep the run partial.
  if (status === 429 || status >= 500) {
    if (!protectedExposed) addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned HTTP ${status}; this response was incomplete, not an authorization denial.`);
    return true;
  }

  // A successful response carrying the protected canary is the useful BOLA
  // observation itself. It is a completed control with a high finding when
  // the actor identity was verified. A successful response without the
  // canary, or a 3xx response, remains inconclusive.
  if (status >= 200 && status < 300) {
    if (protectedExposed) return !identityVerified;
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned HTTP ${status}; this response was incomplete, not an authorization denial.`);
    return true;
  }
  if (status >= 300 && status < 400) {
    if (!protectedExposed) addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned HTTP ${status}; this response was incomplete, not an authorization denial.`);
    return true;
  }
  if (status < 200) {
    if (!protectedExposed) addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned HTTP ${status}; this response was incomplete, not an authorization denial.`);
    return true;
  }

  if (!parsed.valid) {
    if (resource.body.byteLength === 0 && deny.allowEmptyBody && expected && identityVerified) {
      addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned an allowed empty-body denial with HTTP ${status} after identity verification.`);
      return false;
    }
    if (resource.body.byteLength === 0 && deny.allowEmptyBody && expected && !identityVerified) {
      addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned an empty-body denial, but identity was not verified; denial is inconclusive.`);
    } else {
      addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned HTTP ${status} with ${parsed.reason}; denial is inconclusive.`);
    }
    return true;
  }

  if (protectedExposed) {
    if (!expected) {
      addNote(notes, `API case ${entry.id}: actor ${deny.actor} exposed the protected canary with unexpected HTTP ${status}; denial is inconclusive.`);
      return true;
    }
    return !identityVerified;
  }

  if (!expected) {
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned unexpected HTTP ${status}; expected ${expectedStatusNote(deny.statuses)}; denial is inconclusive.`);
    return true;
  }

  const echoedResource = resourceMatches(parsed.value, entry.allow.resource);
  if (echoedResource) {
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} echoed the public resource identity without the protected canary; this is weak authorization evidence.`);
    // A legacy resource marker cannot establish that protected data was
    // withheld. Version 2 can still accept an expected denial when identity
    // is verified; the note keeps the weaker evidence visible to reviewers.
    return legacy || !identityVerified;
  }
  if (!identityVerified) {
    addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned an expected denial status HTTP ${status}, but its identity was not verified; denial is inconclusive.`);
    return true;
  }
  addNote(notes, `API case ${entry.id}: actor ${deny.actor} returned an expected denial status HTTP ${status} without the protected canary; this is scoped evidence only.`);
  return false;
}

function errorCheck(code: string, note: string, metrics: Record<string, number | string | boolean> = {}): CheckResult {
  return {
    id: "api.authorization",
    status: "error",
    findings: [],
    notes: [API_SCOPE_NOTE, note],
    metrics: { requestCount: 0, bytesInspected: 0, errorCode: code, ...metrics },
  };
}

/**
 * Run the bounded API authorization preview. The caller supplies a parsed
 * policy; this function never interprets a policy string or executes it.
 */
export async function runApiPolicy(options: ApiRunOptions): Promise<CheckResult[]> {
  const startedAt = performance.now();
  let prepared: ReturnType<typeof prepareApiRun>;
  try { prepared = prepareApiRun(options); }
  catch (error) {
    return [errorCheck(error instanceof ApiPreparationError ? (['invalid_credentials', 'duplicate_credentials'].includes(error.issue.code) ? 'invalid_policy' : error.issue.code) : 'invalid_options',
      error instanceof ApiPreparationError ? `${error.issue.message} Validation failed; no requests were made.` : 'API options could not be validated; no requests were made.')];
  }
  const { parsed, credentials, timeoutMs, allowPrivate, signal } = prepared;

  const notes: string[] = [API_SCOPE_NOTE];
  const findings: Finding[] = [];
  const controller = createApiRunControl(timeoutMs, signal);
  const capture = ownedApiCapture(signal);
  const budget: UrlNetworkContext["budget"] = capture?.budget?.requests ?? { count: 0, max: API_MAX_REQUESTS };
  const requestOffset = budget.count;
  const state: RequestContextState = {
    requestOffset,
    execution: createApiExecutionLedger(parsed.policy.version, requestPlan(parsed, timeoutMs, allowPrivate)),
    actorIndexes: new Map(parsed.policy.actors.map((actor, index) => [actor.id, index])),
    caseIndexes: new Map(parsed.cases.map((entry, index) => [entry.id, index])),
    session: { authenticatedDeny401Count: 0, identityStatusMismatches: 0, identityResponseFailures: 0,
      identityPrincipalMismatches: 0, identityOrganizationMismatches: 0, identityRequestFailures: 0 },
    ownedCapture: capture,
    context: {
      allowPrivate,
      signal: controller.signal,
      budget,
      deadlineAt: controller.deadlineAt,
    },
    bytes: 0,
    stopRequests: false,
    bodyBudgetExhausted: false,
    bodyReadIncomplete: false,
  };
  let incomplete = parsed.legacy;
  let controlsPassed = 0;
  let identityControlsPassed = 0;
  let identityReuseCount = 0;
  const identityStates = new Map<string, ActorIdentityState>();
  for (const actor of parsed.policy.actors) {
    if (actor.authorizationEnv !== undefined) identityStates.set(actor.id, {
      actorId: actor.id,
      required: true,
      beforeValid: false,
      afterValid: false,
      identityReuse: false,
    });
  }
  if (parsed.legacy) {
    addNote(notes, "API policy version 1 is accepted for migration, but it has no actor identity controls or protected-data assertion; authorization results are unverified and remain partial. Migrate to version 2.");
  }
  const actors = new Map(parsed.policy.actors.map((actor) => [actor.id, actor]));
  try {
    if (!parsed.legacy) {
      if (await runIdentityControls(parsed, credentials, "before", identityStates, state, notes)) incomplete = true;
    }
    for (const entry of parsed.cases) {
      const ownerAuthorization = credentials.values.get(entry.allow.actor);
      // parseApiPolicy guarantees this actor and credential exist. Keep the
      // guard so a future policy adapter cannot accidentally send undefined.
      if (ownerAuthorization === undefined) {
        addNote(notes, `API case ${entry.id}: owner positive control could not be configured.`);
        incomplete = true;
        continue;
      }
      const before = await recordStep(state, "owner-before", entry.allow.actor, entry.id,
        () => checkPositiveControl(entry, ownerAuthorization, "before", state, notes), result => result.valid);
      if (!before.valid) {
        for (const step of state.execution.plan!.steps) if (step.caseIndex === state.caseIndexes.get(entry.id) && step.phase !== "owner-before") {
          state.execution.steps[step.ordinal].reason = "prerequisite_failed";
        }
        incomplete = true;
        continue;
      }
      controlsPassed += 1;
      for (const deny of entry.deny) {
        const actor = actors.get(deny.actor);
        const authorization = actor?.authorizationEnv === undefined ? undefined : credentials.values.get(deny.actor);
        const identityVerified = actorIdentityVerified(deny.actor, actor, identityStates);
        if (await recordStep(state, "deny", deny.actor, entry.id,
          () => checkDeny(entry, deny, actor, authorization, identityVerified, parsed.legacy, state, notes, findings), result => !result)) incomplete = true;
        if (controller.signal.aborted) incomplete = true;
      }
      const after = await recordStep(state, "owner-after", entry.allow.actor, entry.id,
        () => checkPositiveControl(entry, ownerAuthorization, "after", state, notes), result => result.valid);
      if (!after.valid) incomplete = true;
    }
    if (!parsed.legacy) {
      if (await runIdentityControls(parsed, credentials, "after", identityStates, state, notes)) incomplete = true;
      identityReuseCount = [...identityStates.values()].filter((identity) => identity.identityReuse).length;
      for (const identity of identityStates.values()) {
        if (identity.beforeValid && identity.afterValid && !identity.identityReuse && identity.beforePrincipal !== undefined && identity.afterPrincipal !== undefined && principalKey(identity.beforePrincipal) === principalKey(identity.afterPrincipal)) {
          identityControlsPassed += 1;
        } else {
          incomplete = true;
          if (identity.beforeValid && identity.afterValid && identity.beforePrincipal !== undefined && identity.afterPrincipal !== undefined && principalKey(identity.beforePrincipal) !== principalKey(identity.afterPrincipal)) {
            addNote(notes, `API actor ${identity.actorId}: principal identity changed between controls; authorization results are incomplete.`);
          }
        }
      }
    }
  } finally {
    controller.dispose();
  }
  if (controller.signal.aborted || Date.now() >= state.context.deadlineAt) {
    addNote(notes, signal?.aborted
      ? "The API policy was cancelled; the authorization preview is incomplete."
      : "The API policy time budget elapsed; the authorization preview is incomplete.");
    incomplete = true;
  }
  const apiExecution = finishApiExecutionLedger(state.execution, incomplete);
  if (apiExecution.status === 'invalid') addNote(notes, 'API execution metadata was inconsistent; the run remains incomplete.');
  const status: CheckResult["status"] = incomplete || apiExecution.status !== 'complete' ? "partial" : "completed";
  return [{
    id: "api.authorization",
    status,
    findings,
    apiExecution,
    notes: notes.slice(0, 128),
    metrics: {
      caseCount: parsed.cases.length,
      actorCount: parsed.policy.actors.length,
      identityActorCount: identityStates.size,
      identityControlsPassed,
      identityReuseCount,
      ...state.session,
      legacyPolicy: parsed.legacy,
      controlsPassed,
      expectedRequestCount: parsed.expectedRequests,
      requestCount: budget.count - requestOffset,
      bytesInspected: state.bytes,
      elapsedMs: Math.round(performance.now() - startedAt),
      jsonValueEvidenceCases: parsed.cases.filter((entry) => entry.allow.protected?.match === "json-values").length,
      bodyBudgetExhausted: state.bodyBudgetExhausted,
      bodyReadIncomplete: state.bodyReadIncomplete,
      allowPrivate,
    },
  }];
}
