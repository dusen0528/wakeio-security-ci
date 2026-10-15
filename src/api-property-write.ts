import { randomBytes } from 'node:crypto';
import { types } from 'node:util';
import { createApiRunControl, API_DEFAULT_TIMEOUT_MS, API_MAX_TIMEOUT_MS } from './api.js';
import type { ApiPropertyReason, ApiPropertyWriteEvidence, ApiPropertyWriteStep, CheckResult } from './contracts.js';
import { apiPropertySteps } from './api-property-evidence.js';
import { parseApiPropertyPolicy, parsePropertyJsonText, propertyPointer, propertyPolicyDigest, type ApiPropertyPolicyV1, type PropertyScalar } from './api-property-policy.js';
import { normalizeUrl, requestPropertyResource, UrlNetworkError, validateStaticTarget, type PropertyFetchedResource } from './url-network.js';

export const PROPERTY_WRITE_MAX_REQUESTS = 23;
export const PROPERTY_WRITE_PLANNED_REQUESTS = 22;
export const PROPERTY_WRITE_MAX_PATCHES = 8;
export const PROPERTY_WRITE_RESPONSE_BYTES = 65536;
export const PROPERTY_WRITE_TOTAL_BYTES = 1048576;
export interface ApiPropertyWriteOptions {
  policy: ApiPropertyPolicyV1;
  activeConsent: true;
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxRequests?: number;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}
class Stop extends Error { constructor(readonly reason: ApiPropertyReason) { super(reason); } }
function stop(reason: ApiPropertyReason): never { throw new Stop(reason); }
function ownOptions(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object' || types.isProxy(input) || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) stop('invalid_policy');
  if (Object.getOwnPropertySymbols(input).length) stop('invalid_policy');
  const output: Record<string, unknown> = {};
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(input))) {
    if (!['policy', 'activeConsent', 'allowPrivate', 'timeoutMs', 'maxRequests', 'env', 'signal'].includes(key) || !('value' in descriptor) || !descriptor.enumerable) stop('invalid_policy');
    output[key] = descriptor.value;
  }
  return output;
}
function credential(env: unknown, name: string): string {
  if (!env || typeof env !== 'object' || types.isProxy(env)) stop('credential_unavailable');
  const descriptor = Object.getOwnPropertyDescriptor(env, name);
  if (!descriptor || !('value' in descriptor) || typeof descriptor.value !== 'string' || !descriptor.value.length || descriptor.value.length > 8192
    || /[\x00-\x1f\x7f]/.test(descriptor.value) || /[^\x00-\xff]/.test(descriptor.value)) stop('credential_unavailable');
  return descriptor.value;
}
function prepared(input: unknown, consent: boolean) {
  const options = ownOptions(input);
  if (consent && options.activeConsent !== true) stop('consent_missing');
  if (options.allowPrivate !== undefined && typeof options.allowPrivate !== 'boolean') stop('invalid_policy');
  if (options.signal !== undefined && (types.isProxy(options.signal) || !(options.signal instanceof AbortSignal))) stop('invalid_policy');
  if ((options.signal as AbortSignal | undefined)?.aborted) stop('cancelled');
  const timeoutMs = options.timeoutMs ?? API_DEFAULT_TIMEOUT_MS, maxRequests = options.maxRequests ?? PROPERTY_WRITE_MAX_REQUESTS;
  if (!Number.isSafeInteger(timeoutMs) || (timeoutMs as number) < 1 || (timeoutMs as number) > API_MAX_TIMEOUT_MS) stop('invalid_policy');
  if (!Number.isSafeInteger(maxRequests) || (maxRequests as number) < 1 || (maxRequests as number) > PROPERTY_WRITE_MAX_REQUESTS) stop('invalid_policy');
  const policy = parseApiPropertyPolicy(options.policy);
  validateStaticTarget(normalizeUrl(policy.origin), options.allowPrivate === true);
  const env = options.env ?? process.env;
  const tokens = [credential(env, policy.actors.owner.authorizationEnv), credential(env, policy.actors.verifier.authorizationEnv)] as const;
  if (tokens[0] === tokens[1]) stop('credential_unavailable');
  if ((maxRequests as number) < PROPERTY_WRITE_PLANNED_REQUESTS) stop('request_limit');
  return { policy, tokens, timeoutMs: timeoutMs as number, maxRequests: maxRequests as number,
    allowPrivate: options.allowPrivate === true, signal: options.signal as AbortSignal | undefined };
}
function reason(error: unknown): ApiPropertyReason {
  if (error instanceof Stop) return error.reason;
  if (error instanceof UrlNetworkError) {
    if (error.code === 'timeout' || error.code === 'dns_timeout') return 'deadline';
    if (error.code === 'request_limit') return 'request_limit';
    if (['body_limit', 'request_body_limit', 'decompression_failed'].includes(error.code)) return 'body_limit';
    if (['request_error', 'body_read_error', 'dns_error'].includes(error.code)) return 'transport_error';
    return 'target_refused';
  }
  return 'invalid_policy';
}
/** Offline validation only: ready is not a security gate, and no DNS/HTTP is performed. */
export function preflightApiPropertyWrite(options: Omit<ApiPropertyWriteOptions, 'activeConsent'>) {
  try { prepared(options, false); return { version: 1, status: 'ready', execution: 'not_run', plannedRequests: 22, maximumHttpAttempts: 23,
    maximumPatchAttempts: 8, fields: [0, 1], reasons: [] } as const; }
  catch (error) { return { version: 1, status: 'blocked', execution: 'not_run', plannedRequests: 22, maximumHttpAttempts: 23,
    maximumPatchAttempts: 8, fields: [0, 1], reasons: [reason(error)] } as const; }
}
function initialEvidence(): ApiPropertyWriteEvidence {
  return { version: 1, scope: 'policy-resource-property-write', basis: 'authenticated-http-readback', execution: 'partial', effect: 'unknown', provisional: 'unknown',
    controls: { identityBefore: 'not_run', ownerResource: 'not_run', ownerPrecondition: 'not_run', verifierPrecondition: 'not_run',
      normal: 'not_run', positive: 'not_run', restore: 'not_run', freshness: 'not_run', identityAfter: 'not_run' },
    cleanup: 'not_run', stopReason: 'none', reasons: [], counts: { plannedRequests: 22, httpAttempts: 0, patchAttempts: 0, capturedResponses: 0 },
    budget: { maxRequests: null, timeoutMs: null, maxRequestBodyBytes: 4096, maxResponseBodyBytes: PROPERTY_WRITE_RESPONSE_BYTES, maxTotalResponseBytes: PROPERTY_WRITE_TOTAL_BYTES },
    ledger: { version: 1, status: 'partial', maximumHttpAttempts: 23, maximumPatchAttempts: 8,
      steps: apiPropertySteps().map((step, ordinal) => ({ ...step, ordinal, attempted: false, outcome: 'not_attempted', httpStatus: null, reason: 'none' })) } };
}
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, (item as Record<string, unknown>)[key]])) : item);
}
/** JSON.parse accepts duplicate keys. Refuse these before identity/snapshot assertions. */
function json(response: PropertyFetchedResource): Record<string, unknown> {
  const mime = String(response.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
  if (!(mime === 'application/json' || /^application\/[a-z0-9.+-]+\+json$/.test(mime))) stop('response_invalid');
  let data: unknown;
  try { data = parsePropertyJsonText(new TextDecoder('utf-8', { fatal: true }).decode(response.body)); } catch { stop('response_invalid'); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) stop('response_invalid');
  return data as Record<string, unknown>;
}

/** Explicit single-resource HTTP experiment. No retries, redirects, external observers or post-cancel cleanup. */
export async function runApiPropertyWrite(options: ApiPropertyWriteOptions): Promise<CheckResult[]> {
  const evidence = initialEvidence();
  let current: ApiPropertyWriteStep | undefined, writes = false, ambiguous = false, forbidReconcile = false;
  let dispose = () => {}, signal: AbortSignal | undefined, abortCause: 'cancelled' | 'deadline' | undefined;
  let abortListener: (() => void) | undefined;
  let perform: ((ordinal: number, body?: Record<string, PropertyScalar>, invalidTag?: string) => Promise<PropertyFetchedResource>) | undefined;
  let baseline: Record<string, unknown> | undefined, tag = '', lastJson = '';
  const failControl = (control: keyof ApiPropertyWriteEvidence['controls'], cause: ApiPropertyReason): never => {
    evidence.controls[control] = 'failed'; return stop(cause);
  };
  try {
    const selected = ownOptions(options), selectedMax = selected.maxRequests ?? PROPERTY_WRITE_MAX_REQUESTS,
      selectedTimeout = selected.timeoutMs ?? API_DEFAULT_TIMEOUT_MS;
    if (Number.isSafeInteger(selectedMax) && (selectedMax as number) >= 1 && (selectedMax as number) <= 23) evidence.budget.maxRequests = selectedMax as number;
    if (Number.isSafeInteger(selectedTimeout) && (selectedTimeout as number) >= 1 && (selectedTimeout as number) <= API_MAX_TIMEOUT_MS) evidence.budget.timeoutMs = selectedTimeout as number;
    const config = prepared(options, true), { policy } = config;
    evidence.policySha256 = propertyPolicyDigest(policy);
    const control = createApiRunControl(config.timeoutMs, config.signal);
    signal = control.signal; dispose = control.dispose;
    abortListener = () => { abortCause ??= config.signal?.aborted ? 'cancelled' : 'deadline'; };
    if (signal.aborted) abortListener(); else signal.addEventListener('abort', abortListener, { once: true });
    const budget = { count: 0, max: config.maxRequests };
    let totalBytes = 0;
    perform = async (ordinal, body, invalidTag) => {
      current = evidence.ledger.steps[ordinal]!;
      if (signal!.aborted) stop(abortCause ?? 'cancelled');
      if (current.method === 'PATCH' && evidence.counts.patchAttempts >= PROPERTY_WRITE_MAX_PATCHES) stop('request_limit');
      const actor = current.actorIndex === 0 ? policy.actors.owner : policy.actors.verifier;
      const identity = current.phase.includes('identity');
      const url = normalizeUrl(policy.origin + (identity ? actor.identity.path : policy.resource.path));
      const before = budget.count;
      const remaining = PROPERTY_WRITE_TOTAL_BYTES - totalBytes;
      if (remaining <= 0) { forbidReconcile = true; stop('body_limit'); }
      try {
        const response = await requestPropertyResource(url, { allowPrivate: config.allowPrivate, signal: signal!, budget,
          deadlineAt: control.deadlineAt, authorization: config.tokens[current.actorIndex], rejectRedirects: true, acceptJson: true }, policy.origin,
        current.method === 'PATCH' ? { method: 'PATCH', ifMatch: invalidTag ?? tag, body: JSON.stringify(body) } : { method: 'GET' },
        Math.min(PROPERTY_WRITE_RESPONSE_BYTES, remaining), Math.min(PROPERTY_WRITE_RESPONSE_BYTES, remaining));
        current.httpStatus = response.status; evidence.counts.capturedResponses++;
        totalBytes += Math.max(response.body.byteLength, response.compressedBytes);
        if (totalBytes > PROPERTY_WRITE_TOTAL_BYTES) { forbidReconcile = true; stop('body_limit'); }
        return response;
      } catch (error) {
        if (current.method === 'PATCH' && budget.count > before) { ambiguous = true; evidence.cleanup = 'unknown'; }
        const mapped = abortCause ?? reason(error);
        if (['body_limit', 'deadline', 'cancelled'].includes(mapped)) forbidReconcile = true;
        if (budget.count > before) { current.reason = mapped; current.outcome = 'inconclusive'; }
        throw new Stop(mapped);
      } finally {
        if (budget.count > before) {
          current.attempted = true; evidence.counts.httpAttempts += budget.count - before;
          if (current.method === 'PATCH') { evidence.counts.patchAttempts++; writes = true; if (evidence.cleanup === 'not_run') evidence.cleanup = 'unknown'; }
        }
      }
    };
    const evaluated = () => { current!.outcome = 'evaluated'; current!.reason = 'none'; };
    const identity = async (ordinal: number) => {
      const response = await perform!(ordinal), actor = ordinal === 0 || ordinal === 20 ? policy.actors.owner : policy.actors.verifier;
      if (response.status !== 200 || propertyPointer(json(response), actor.identity.pointer) !== actor.identity.equals) stop('identity_failed');
      evaluated();
    };
    const assertResource = (data: Record<string, unknown>) => {
      if (propertyPointer(data, policy.resource.id.pointer) !== policy.resource.id.equals || propertyPointer(data, policy.resource.ownerPointer) !== policy.actors.owner.identity.equals) stop('resource_mismatch');
      if (propertyPointer(data, policy.resource.runMarker.pointer) !== policy.resource.runMarker.equals) stop('run_marker_mismatch');
    };
    const other = (data: Record<string, unknown>) => canonical(Object.fromEntries(Object.entries(data).filter(([key]) => key !== policy.normal.field && key !== policy.protected.field)));
    const read = async (ordinal: number, expectedNormal?: string, expectedProtected?: PropertyScalar, unchanged = false) => {
      const response = await perform!(ordinal);
      if (response.status !== 200) stop('readback_unobservable');
      const data = json(response); assertResource(data);
      if (response.etag.kind !== 'strong') stop('unsupported_validator');
      if (baseline && other(data) !== other(baseline)) stop('unexpected_mutation');
      const mismatch: ApiPropertyReason = ordinal === 3 ? 'baseline_mismatch' : ordinal === 5 || ordinal === 7 ? 'precondition_not_enforced' : ordinal === 19 ? 'cleanup_failed'
        : ordinal === 17 ? 'freshness_failed' : ordinal === 13 ? 'restore_failed' : ordinal === 11 ? 'positive_control_failed' : 'normal_failed';
      if (expectedNormal !== undefined && data[policy.normal.field] !== expectedNormal) stop(mismatch);
      if (expectedProtected !== undefined && data[policy.protected.field] !== expectedProtected) stop(mismatch);
      const now = canonical(data);
      if (lastJson && ((now !== lastJson && response.etag.value === tag) || (unchanged && (now !== lastJson || response.etag.value !== tag)))) stop('stale_or_conflicting_state');
      tag = response.etag.value; lastJson = now; evaluated(); return data;
    };
    const patch = async (ordinal: number, body: Record<string, PropertyScalar>, expected: readonly number[] = [200, 204], invalidTag?: string) => {
      const response = await perform!(ordinal, body, invalidTag);
      if (!expected.includes(response.status)) {
        ambiguous = true;
        stop(ordinal === 4 || ordinal === 6 ? 'precondition_not_enforced' : response.status === 412 ? 'stale_or_conflicting_state' : 'write_ambiguous');
      }
      evaluated();
    };
    const generated = new Set<string>([policy.normal.initial]);
    const nonce = () => {
      for (let attempt = 0; attempt < 16; attempt++) {
        const value = `wakeio-property-v1-${randomBytes(16).toString('hex')}`;
        if (!generated.has(value)) { generated.add(value); return value; }
      }
      return stop('normal_failed');
    };
    const N = policy.normal.field, P = policy.protected.field, P0 = policy.protected.initial;
    await identity(0); await identity(1); evidence.controls.identityBefore = 'passed';
    const ownerResponse = await perform(2);
    if (ownerResponse.status !== 200) failControl('ownerResource', 'readback_unobservable');
    const ownerData = json(ownerResponse); assertResource(ownerData);
    if (ownerData[N] !== policy.normal.initial) failControl('ownerResource', 'baseline_mismatch');
    evaluated(); evidence.controls.ownerResource = 'passed';
    baseline = await read(3, policy.normal.initial, P0);
    // Wrong tags are random and explicitly unequal to the currently observed validator.
    const wrongTag = () => {
      for (let attempt = 0; attempt < 16; attempt++) {
        const value = `"wakeio-invalid-${randomBytes(16).toString('hex')}"`;
        if (value !== tag) return value;
      }
      return stop('unsupported_validator');
    };
    await patch(4, { [N]: nonce() }, [412], wrongTag()); await read(5, policy.normal.initial, P0, true); evidence.controls.ownerPrecondition = 'passed';
    await patch(6, { [P]: policy.protected.control }, [412], wrongTag()); await read(7, policy.normal.initial, P0, true); evidence.controls.verifierPrecondition = 'passed';
    const normalNonce = nonce(); await patch(8, { [N]: normalNonce }); await read(9, normalNonce, P0); evidence.controls.normal = 'passed';
    const controlNonce = nonce(); await patch(10, { [N]: controlNonce, [P]: policy.protected.control }); await read(11, controlNonce, policy.protected.control); evidence.controls.positive = 'passed';
    const restoreNonce = nonce(); await patch(12, { [N]: restoreNonce, [P]: P0 }); await read(13, restoreNonce, P0); evidence.controls.restore = 'passed';
    await patch(14, { [P]: policy.protected.probe }, [200, 204, 403]);
    const provisional = await read(15, restoreNonce), seen = provisional[P];
    if (seen !== P0 && seen !== policy.protected.probe) stop('unexpected_mutation');
    evidence.provisional = seen === policy.protected.probe ? 'observed' : 'not_observed';
    const barrierNonce = nonce(); await patch(16, { [N]: barrierNonce }); await read(17, barrierNonce, seen as PropertyScalar);
    evidence.controls.freshness = 'passed'; evidence.effect = evidence.provisional;
    await patch(18, { [N]: policy.normal.initial, [P]: P0 });
    await read(19, policy.normal.initial, P0);
    if (lastJson !== canonical(baseline)) stop('cleanup_failed');
    evidence.cleanup = 'confirmed';
    await identity(20); await identity(21); evidence.controls.identityAfter = 'passed';
    evidence.execution = 'completed'; evidence.ledger.status = 'complete';
  } catch (error) {
    const cause = abortCause ?? reason(error);
    evidence.stopReason = cause; evidence.reasons = [cause];
    if (current?.attempted) { current.outcome = 'inconclusive'; current.reason = cause; }
    const controlAt: Partial<Record<number, keyof ApiPropertyWriteEvidence['controls']>> = {
      0: 'identityBefore', 1: 'identityBefore', 2: 'ownerResource', 4: 'ownerPrecondition', 5: 'ownerPrecondition',
      6: 'verifierPrecondition', 7: 'verifierPrecondition', 8: 'normal', 9: 'normal', 10: 'positive', 11: 'positive',
      12: 'restore', 13: 'restore', 14: 'freshness', 15: 'freshness', 16: 'freshness', 17: 'freshness', 20: 'identityAfter', 21: 'identityAfter' };
    const failed = current && controlAt[current.ordinal];
    if (failed && evidence.controls[failed] !== 'passed') evidence.controls[failed] =
      ['deadline', 'cancelled', 'transport_error', 'body_limit', 'request_limit'].includes(cause) ? 'unknown' : 'failed';
    if (!writes) evidence.cleanup = 'not_needed';
    else if (evidence.cleanup !== 'confirmed') evidence.cleanup = 'unknown';
    // Ambiguity never authorizes a retry or restoration write. One optional read is diagnostic only.
    if (ambiguous && !forbidReconcile && !['body_limit', 'deadline', 'cancelled'].includes(cause) && signal && !signal.aborted && perform && evidence.counts.httpAttempts < PROPERTY_WRITE_MAX_REQUESTS) {
      try { const response = await perform(22); current!.outcome = 'inconclusive'; current!.reason = response.status === 200 ? 'write_ambiguous' : 'readback_unobservable'; }
      catch { /* The primary failure/effect is retained, with the reconcile slot recording its own failure. */ }
    }
  } finally {
    if (signal && abortListener) signal.removeEventListener('abort', abortListener);
    dispose();
  }
  return [{ id: 'api.property-write', status: evidence.execution === 'completed' ? 'completed' : 'partial', propertyWriteEvidence: evidence,
    findings: evidence.effect === 'observed' ? [{ ruleId: 'api.property-write-unauthorized-effect', title: 'Protected property change observed after owner probe',
      description: 'The configured protected scalar was returned by the privileged verifier after the owner-only protected write and a fresh normal-field read barrier. This is scoped API readback, not independent storage or exclusive causality proof.',
      severity: 'high', confidence: 'low', kind: 'candidate', location: {},
      remediation: 'Enforce field-level write authorization on this resource and repeat the explicit controls on a disposable resource. Review API evidence and cleanup status before taking further action.' }] : [],
    notes: ['Explicit disposable-resource GET/PATCH experiment; operator declarations are not ownership proof. Only the two configured fields are restored. API readback does not establish database state or complete authorization security.'],
    metrics: { httpAttempts: evidence.counts.httpAttempts, patchAttempts: evidence.counts.patchAttempts } }];
}
