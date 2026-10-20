import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { compileZapOpenApi, type ZapOpenApiInput, type ZapCompiledRequest } from './zap-openapi.js';
import { parseZapSessionPolicy, snapshotZapLogin, type ZapSessionPolicy } from './zap-session.js';
import { snapshotJsonData } from './json-snapshot.js';
import { parseAuthAssertion, snapshotSchemathesisCredential, type SchemathesisAuthAssertion } from './schemathesis-auth.js';
import { normalizeUrl, validateStaticTarget } from './url-network.js';

export const ZAP_POLICY_REVISION = 'zap-bounded-http-json-v1';
export const ZAP_OPENAPI_REVISION = 'zap-openapi-session-v2';
export const ZAP_RELAY_ORIGIN = 'http://wakeio-zap.invalid';
export type ZapRequest = { method: 'GET'; path: string } | { method: 'POST'; path: string; body: Record<string, string | number> };
export interface ZapPolicy {
  version: 1; kind: 'zap-active'; origin: string; requests: ZapRequest[];
  authentication?: { authorizationEnv: string; identity: SchemathesisAuthAssertion };
}
export interface ZapPolicyV2 { version: 2; kind: 'zap-active'; origin: string; openapi: ZapOpenApiInput;
  authentication?: ZapSessionPolicy | ZapPolicy['authentication'] }
export type ZapPolicyInput = ZapPolicy | ZapPolicyV2;
function invalid(): never { throw new TypeError('invalid_zap_policy'); }
function object(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some(key => !Object.hasOwn(value, key))
    || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) invalid();
}
/** Exact relative paths: no normalization, credentials, fragments or encoded separators. */
export function zapRequestUrl(origin: string, path: string): URL {
  if (typeof path !== 'string' || path.length > 2048 || !path.startsWith('/') || path.startsWith('//') || /[\u0000-\u0020\u007f#\\]/.test(path)) invalid();
  const url = new URL(path, origin);
  if (url.origin !== origin || `${url.pathname}${url.search}` !== path) invalid();
  for (const part of url.pathname.split('/')) {
    const decoded = decodeURIComponent(part);
    if (decoded === '.' || decoded === '..' || /[%\\/;\u0000-\u001f\u007f]/.test(decoded)) invalid();
  }
  return url;
}
function staticAuthentication(value: unknown, origin: string): NonNullable<ZapPolicy['authentication']> {
  object(value, ['authorizationEnv', 'identity']);
  if (typeof value.authorizationEnv !== 'string' || !/^[A-Z][A-Z0-9_]{0,127}$/.test(value.authorizationEnv)) invalid();
  const identity = parseAuthAssertion(value.identity, true); zapRequestUrl(origin, identity.path);
  return { authorizationEnv: value.authorizationEnv, identity };
}
/** Owner data only; version 1 retains its single-field contract. */
export function parseZapPolicy(input: unknown): { policy: ZapPolicyInput; policySha256: string; requests: ZapCompiledRequest[]; sourceSha256?: string } {
  const value = snapshotJsonData(input, invalid, invalid);
  if (value && typeof value === 'object' && (value as any).version === 2) {
    object(value, ['version', 'kind', 'origin', 'openapi'], ['authentication']);
    if (value.kind !== 'zap-active' || typeof value.origin !== 'string' || normalizeUrl(value.origin).origin !== value.origin) invalid();
    const compiled = compileZapOpenApi(value.openapi);
    for (const request of compiled.requests) { zapRequestUrl(value.origin, request.path); if (new URL(request.path, value.origin).pathname === '/__wakeio_session') invalid(); }
    const policy: ZapPolicyV2 = { version: 2, kind: 'zap-active', origin: value.origin, openapi: compiled.openapi };
    if (value.authentication !== undefined) {
      if (Object.hasOwn(value.authentication, 'authorizationEnv')) {
        policy.authentication = staticAuthentication(value.authentication, value.origin);
      } else policy.authentication = parseZapSessionPolicy(value.authentication, value.origin);
      const auth = policy.authentication!;
      const controls = 'login' in auth ? [auth.login.path, auth.refresh?.path, auth.identity.path] : [auth.identity.path];
      if (compiled.requests.some(r => controls.some(p => p && new URL(p, value.origin).pathname === new URL(r.path, value.origin).pathname))) invalid();
    }
    return { policy, policySha256: createHash('sha256').update(JSON.stringify(policy)).digest('hex'), requests: compiled.requests, sourceSha256: compiled.sourceSha256 };
  }
  object(value, ['version', 'kind', 'origin', 'requests'], ['authentication']);
  if (value.version !== 1 || value.kind !== 'zap-active' || typeof value.origin !== 'string') invalid();
  const base = normalizeUrl(value.origin), origin = base.origin;
  if (value.origin !== origin || !Array.isArray(value.requests) || !value.requests.length || value.requests.length > 16) invalid();
  const seen = new Set<string>();
  const requests: ZapRequest[] = value.requests.map((item: unknown) => {
    object(item, ['method', 'path'], ['body']);
    const url = zapRequestUrl(origin, item.path), key = `${item.method}:${url.pathname}`;
    if (seen.has(key)) invalid(); seen.add(key);
    if (item.method === 'GET') {
      if (Object.hasOwn(item, 'body') || !url.search || ![...url.searchParams.keys()].length
        || new Set(url.searchParams.keys()).size !== [...url.searchParams.keys()].length) invalid();
      return { method: 'GET', path: item.path };
    }
    if (item.method !== 'POST' || url.search) invalid();
    object(item.body, [], Object.keys(item.body ?? {}));
    const fields = Object.keys(item.body);
    if (fields.length !== 1 || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(fields[0]) || ['__proto__', 'prototype', 'constructor'].includes(fields[0])) invalid();
    const bodyValue = item.body[fields[0]];
    if (!(typeof bodyValue === 'string' && bodyValue.length > 0 && bodyValue.length <= 512 && !/[\u0000-\u001f\u007f]/.test(bodyValue)
      || typeof bodyValue === 'number' && Number.isSafeInteger(bodyValue))) invalid();
    return { method: 'POST', path: item.path, body: { [fields[0]]: bodyValue } };
  });
  const policy: ZapPolicy = { version: 1, kind: 'zap-active', origin, requests };
  if (Object.hasOwn(value, 'authentication')) {
    policy.authentication = staticAuthentication(value.authentication, origin);
    if (requests.some(request => new URL(request.path, origin).pathname === new URL(policy.authentication!.identity.path, origin).pathname)) invalid();
  }
  return { policy, policySha256: createHash('sha256').update(JSON.stringify(policy)).digest('hex'), requests };
}
/** Snapshot one credential before any asynchronous work; never pass it to ZAP. */
export function prepareZapPolicy(input: unknown, allowPrivate = false, env: NodeJS.ProcessEnv = process.env): ReturnType<typeof parseZapPolicy> & { authorization?: string; loginEnv?: Record<string, string> } {
  const parsed = parseZapPolicy(input), url = new URL(parsed.policy.origin);
  validateStaticTarget(normalizeUrl(url.href), allowPrivate);
  if (parsed.policy.authentication && url.protocol !== 'https:' && !(allowPrivate && ['127.0.0.1', '[::1]'].includes(url.hostname))) invalid();
  if (!env || typeof env !== 'object' || types.isProxy(env) || Array.isArray(env)) invalid();
  const auth = parsed.policy.authentication;
  return { ...parsed, ...(auth && 'login' in auth ? { loginEnv: snapshotZapLogin(auth, env) } : auth ? { authorization: snapshotSchemathesisCredential(auth, env) } : {}) };

}
export function zapSurfaceKey(plugin: string, request: Pick<ZapRequest, 'method' | 'path'>, parameter: string): string {
  const path = new URL(request.path, 'http://scope.invalid').pathname;
  const parts = request.method === 'GET' ? [plugin, path, parameter] : [plugin, 'POST', path, parameter];
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}
