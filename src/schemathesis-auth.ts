import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { snapshotJsonData } from './json-snapshot.js';
import { normalizeUrl } from './url-network.js';

export const SCHEMATHESIS_AUTH_REVISION = 'schemathesis-get-auth-v1' as const;
export type AuthScalar = string | number | boolean;
export interface SchemathesisAuthAssertion { path: string; status: number; jsonPointer: string; equals: AuthScalar }
export interface SchemathesisAuthPolicy {
  version: 1; kind: 'schemathesis-get-auth'; baseUrl: string; authorizationEnv: string;
  identity: SchemathesisAuthAssertion;
  operations: Array<{ path: string; normal: SchemathesisAuthAssertion }>;
}
export type SchemathesisAuthStop = 'complete' | 'identity_mismatch' | 'anonymous_control_failed' | 'normal_control_mismatch'
  | 'generated_auth_denied' | 'request_limit' | 'body_limit' | 'timeout' | 'cancelled' | 'transport_error'
  | 'egress_refused' | 'worker_invalid' | 'worker_failed' | 'unknown';
export interface SchemathesisAuthRecord {
  ordinal: number; operationIndex: number; attempt: number; status: number; check: 'passed' | 'response_contract'; inputFingerprint: string;
  failures: Array<{ rule: 'not_a_server_error' | 'response_schema_conformance'; kind: 'server_error' | 'malformed_json' | 'schema_violation' | 'unclassified'; keyword?: string }>;
}
export interface SchemathesisAuthEvidence {
  version: 1; profileRevision: typeof SCHEMATHESIS_AUTH_REVISION; status: 'completed' | 'partial'; stopReason: SchemathesisAuthStop;
  policySha256: string; schemaSha256: string; workerSha256: string;
  limits: { maxRequests: number; timeoutMs: number; maxBodyBytes: number; maxTotalBytes: number }; seed: number;
  operations: Array<{ operation: string; generatedRequests: number; deniedRequests: number }>;
  controls: Array<{ ordinal: number; phase: 'identity-before' | 'anonymous-normal' | 'normal-before' | 'normal-after' | 'identity-after';
    operationIndex: number | null; outcome: 'matched' | 'not_matched' | 'not_attempted' | 'transport_error'; httpStatus: number | null; attempt: number | null }>;
  requests: { attempted: number; generated: number; completedGenerated: number; responseBytes: number };
  records: SchemathesisAuthRecord[];
  engineVersion: '4.2.0' | 'unknown'; runtime: null | Record<'python' | 'hypothesis' | 'jsonschema' | 'requests', string>;
}
const record = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
const exact = (value: unknown, keys: readonly string[]): value is Record<string, any> => record(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
function fail(): never { throw new TypeError('Invalid Schemathesis authentication policy'); }
const scalar = (value: unknown): value is AuthScalar => typeof value === 'string' ? value.length > 0 && value.length <= 512 && !/[\u0000-\u001f\u007f]/.test(value)
  : typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value);
export function operationPathMatches(template: string, path: string): boolean {
  const wanted = template.split('/'), actual = path.split('/');
  return wanted.length === actual.length && wanted.every((part, index) => /^\{[A-Za-z0-9_.-]+\}$/.test(part) ? !!actual[index] : part === actual[index]);
}
function relativePath(value: unknown, query: boolean): string {
  if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('/') || value.startsWith('//') || /[\\#\u0000-\u0020\u007f]/.test(value) || !query && value.includes('?')) fail();
  const pathname = value.split('?')[0];
  for (const part of pathname.split('/')) {
    let decoded: string; try { decoded = decodeURIComponent(part); } catch { return fail(); }
    if (decoded === '.' || decoded === '..' || /[\\/\u0000-\u001f\u007f]/.test(decoded)) fail();
  }
  return value;
}
export function parseAuthAssertion(value: unknown, query: boolean): SchemathesisAuthAssertion {
  if (!exact(value, ['path', 'status', 'jsonPointer', 'equals']) || !Number.isSafeInteger(value.status) || value.status < 200 || value.status > 299
    || typeof value.jsonPointer !== 'string' || value.jsonPointer.length > 512 || value.jsonPointer !== '' && !value.jsonPointer.startsWith('/')
    || /~(?![01])/.test(value.jsonPointer) || /[\u0000-\u001f\u007f]/.test(value.jsonPointer) || !scalar(value.equals)) fail();
  return { path: relativePath(value.path, query), status: value.status, jsonPointer: value.jsonPointer, equals: value.equals };
}
export function parseSchemathesisAuthPolicy(input: unknown): { policy: SchemathesisAuthPolicy; policySha256: string } {
  const value = snapshotJsonData(input, fail, fail);
  if (!exact(value, ['version', 'kind', 'baseUrl', 'authorizationEnv', 'identity', 'operations']) || value.version !== 1 || value.kind !== 'schemathesis-get-auth'
    || typeof value.baseUrl !== 'string' || typeof value.authorizationEnv !== 'string' || !/^[A-Z][A-Z0-9_]{0,127}$/.test(value.authorizationEnv)
    || !Array.isArray(value.operations) || value.operations.length < 1 || value.operations.length > 16) fail();
  const base = normalizeUrl(value.baseUrl); if (new URL(base.href).pathname !== '/' || new URL(base.href).search) fail();
  const seen = new Set<string>();
  const operations = value.operations.map((item: unknown) => {
    if (!exact(item, ['path', 'normal'])) fail();
    const path = relativePath(item.path, false), normal = parseAuthAssertion(item.normal, true);
    if (seen.has(path) || !operationPathMatches(path, normal.path.split('?')[0])) fail(); seen.add(path);
    return { path, normal };
  });
  const policy: SchemathesisAuthPolicy = { version: 1, kind: 'schemathesis-get-auth', baseUrl: base.href, authorizationEnv: value.authorizationEnv,
    identity: parseAuthAssertion(value.identity, false), operations };
  const bytes = JSON.stringify(policy); if (Buffer.byteLength(bytes) > 64 * 1024) fail();
  return { policy, policySha256: createHash('sha256').update(bytes).digest('hex') };
}
/** Select a single own data value before asynchronous work; never enumerate environment secrets. */
export function snapshotSchemathesisCredential(policy: Pick<SchemathesisAuthPolicy, 'authorizationEnv'>, env: NodeJS.ProcessEnv = process.env): string {
  if (!env || typeof env !== 'object' || types.isProxy(env) || Array.isArray(env)) fail();
  const descriptor = Object.getOwnPropertyDescriptor(env, policy.authorizationEnv), value: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
  if (typeof value !== 'string' || !value.trim() || value.length > 8192 || /[^\x20-\x7e\x80-\xff]/.test(value)) fail();
  return value;
}
export function authScalarObservation(body: Buffer, control: SchemathesisAuthAssertion): { validJson: boolean; matched: boolean } {
  let value: unknown; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); } catch { return { validJson: false, matched: false }; }
  for (const encoded of control.jsonPointer === '' ? [] : control.jsonPointer.slice(1).split('/')) {
    const key = encoded.replace(/~1/g, '/').replace(/~0/g, '~');
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, key)) return { validJson: true, matched: false };
    value = (value as Record<string, unknown>)[key];
  }
  return { validJson: true, matched: typeof value === typeof control.equals && value === control.equals };
}
export function authScalarMatches(body: Buffer, control: SchemathesisAuthAssertion): boolean { return authScalarObservation(body, control).matched; }

const stops: readonly SchemathesisAuthStop[] = ['complete','identity_mismatch','anonymous_control_failed','normal_control_mismatch','generated_auth_denied','request_limit','body_limit','timeout','cancelled','transport_error','egress_refused','worker_invalid','worker_failed','unknown'];
const count = (value: unknown, max = 64): value is number => Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= max;
const digest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const KEYWORDS = new Set(['type','required','enum','const','format','pattern','minimum','maximum','exclusiveMinimum','exclusiveMaximum','minLength','maxLength','minItems','maxItems','uniqueItems','additionalProperties','properties','items','oneOf','anyOf','allOf','not','other']);
/** Closed canonical JSON projection, shape/coherence checks only; not attestation of the producer. */
export function sanitiseSchemathesisAuth(input: unknown): SchemathesisAuthEvidence | undefined {
  try {
    const v = snapshotJsonData(input);
    if (!exact(v, ['version','profileRevision','status','stopReason','policySha256','schemaSha256','workerSha256','limits','seed','operations','controls','requests','records','engineVersion','runtime'])
      || v.version !== 1 || v.profileRevision !== SCHEMATHESIS_AUTH_REVISION || !stops.includes(v.stopReason)
      || v.status !== (v.stopReason === 'complete' ? 'completed' : 'partial') || ![v.policySha256,v.schemaSha256,v.workerSha256].every(digest)
      || !exact(v.limits,['maxRequests','timeoutMs','maxBodyBytes','maxTotalBytes']) || !count(v.limits.maxRequests) || v.limits.maxRequests < 1
      || !count(v.limits.timeoutMs,120000) || v.limits.timeoutMs < 1 || !count(v.limits.maxBodyBytes,2097152) || v.limits.maxBodyBytes < 1
      || !count(v.limits.maxTotalBytes,10485760) || v.limits.maxTotalBytes < 1 || !count(v.seed,2147483647) || v.seed < 1
      || !Array.isArray(v.operations) || !v.operations.length || v.operations.length > 16 || !Array.isArray(v.controls)
      || !Array.isArray(v.records) || v.records.length > 64 || !exact(v.requests,['attempted','generated','completedGenerated','responseBytes'])) return undefined;
    const n = v.operations.length, labels = new Set<string>();
    if (v.limits.maxRequests < 2 + 4*n) return undefined;
    for (const op of v.operations) {
      if (!exact(op,['operation','generatedRequests','deniedRequests']) || typeof op.operation !== 'string' || !op.operation.startsWith('GET ') || op.operation.length > 2052
        || labels.has(op.operation) || !count(op.generatedRequests) || !count(op.deniedRequests) || op.deniedRequests > op.generatedRequests) return undefined;
      relativePath(op.operation.slice(4),false); labels.add(op.operation);
    }
    if (!count(v.requests.attempted,v.limits.maxRequests) || !count(v.requests.generated) || !count(v.requests.completedGenerated)
      || !count(v.requests.responseBytes,v.limits.maxTotalBytes+v.limits.maxBodyBytes) || v.requests.completedGenerated > v.requests.generated
      || v.operations.reduce((sum:number,op:any)=>sum+op.generatedRequests,0) !== v.requests.generated) return undefined;
    const plans = [{ phase:'identity-before', operationIndex:null }, ...v.operations.flatMap((_:unknown,i:number)=>[
      {phase:'anonymous-normal',operationIndex:i},{phase:'normal-before',operationIndex:i}]),
      ...v.operations.map((_:unknown,i:number)=>({phase:'normal-after',operationIndex:i})),{phase:'identity-after',operationIndex:null}];
    if (v.controls.length !== plans.length) return undefined;
    const attempts = new Set<number>(); let prior = 0, unattempted = false;
    for (let i=0;i<plans.length;i++) {
      const step = v.controls[i], plan = plans[i];
      if (!exact(step,['ordinal','phase','operationIndex','outcome','httpStatus','attempt']) || step.ordinal !== i+1 || step.phase !== plan.phase
        || step.operationIndex !== plan.operationIndex || !['matched','not_matched','not_attempted','transport_error'].includes(step.outcome)) return undefined;
      if (step.outcome === 'not_attempted') { if (step.attempt !== null || step.httpStatus !== null) return undefined; unattempted = true; }
      else {
        if (unattempted || !count(step.attempt,v.requests.attempted) || step.attempt < 1 || step.attempt <= prior || attempts.has(step.attempt)) return undefined;
        prior=step.attempt; attempts.add(step.attempt);
        if (step.outcome === 'transport_error' ? step.httpStatus !== null : !Number.isSafeInteger(step.httpStatus) || step.httpStatus < 100 || step.httpStatus > 599) return undefined;
        if (step.outcome === 'matched' && (step.phase === 'anonymous-normal' ? ![401,403].includes(step.httpStatus) : step.httpStatus < 200 || step.httpStatus > 299)) return undefined;
      }
    }
    let previousRecordAttempt = 0;
    const perOperation = v.operations.map(()=>({ generated:0, denied:0 }));
    const initialEnd = v.controls[2*n].attempt;
    const trailingStart = v.controls[2*n+1].attempt;
    for (let i=0;i<v.records.length;i++) {
      const r=v.records[i];
      if (!exact(r,['ordinal','operationIndex','attempt','status','check','inputFingerprint','failures']) || r.ordinal !== i+1 || !count(r.operationIndex,n-1)
        || !count(r.attempt,v.requests.attempted) || r.attempt < 1 || r.attempt <= previousRecordAttempt || attempts.has(r.attempt) || !digest(r.inputFingerprint)
        || !Number.isSafeInteger(r.status) || r.status < 100 || r.status > 599 || !['passed','response_contract'].includes(r.check)
        || !Array.isArray(r.failures) || r.failures.length > 4 || (r.check === 'passed') !== (r.failures.length === 0)) return undefined;
      if (initialEnd === null || r.attempt <= initialEnd || trailingStart !== null && r.attempt >= trailingStart) return undefined;
      previousRecordAttempt=r.attempt; attempts.add(r.attempt);
      perOperation[r.operationIndex].generated += 1;
      if ([401,403].includes(r.status)) perOperation[r.operationIndex].denied += 1;
      const failures = new Set<string>();
      for (const f of r.failures) {
        if (!exact(f,f.keyword===undefined?['rule','kind']:['rule','kind','keyword'])) return undefined;
        if (f.rule==='not_a_server_error' ? f.kind!=='server_error' || f.keyword!==undefined
          : f.rule!=='response_schema_conformance' || !['malformed_json','schema_violation','unclassified'].includes(f.kind)
            || f.keyword!==undefined && (f.kind!=='schema_violation' || typeof f.keyword!=='string' || !KEYWORDS.has(f.keyword))) return undefined;
        const key = `${f.rule}:${f.kind}:${f.keyword ?? ''}`;
        if (failures.has(key)) return undefined; failures.add(key);
      }
      if (r.failures.some((f:any)=>f.rule==='not_a_server_error') !== (r.status>=500)) return undefined;
    }
    if (v.records.length > v.requests.completedGenerated || v.requests.attempted !== v.controls.filter((s:any)=>s.attempt!==null).length + v.requests.generated) return undefined;
    if (v.engineVersion==='unknown' ? v.runtime!==null : v.engineVersion!=='4.2.0' || !exact(v.runtime,['python','hypothesis','jsonschema','requests'])
      || Object.values(v.runtime).some(value=>typeof value!=='string' || !/^\d{1,4}\.\d{1,4}\.\d{1,4}(?:[a-z]+\d{0,4})?$/.test(value))) return undefined;
    if (v.status==='completed' && (v.controls.some((s:any)=>s.outcome!=='matched') || v.operations.some((op:any)=>op.generatedRequests<1 || op.deniedRequests>0)
      || v.records.length !== v.requests.generated || v.requests.completedGenerated !== v.requests.generated || v.engineVersion==='unknown'
      || v.records.some((r:any)=>[401,403].includes(r.status) || r.status>=300 && r.status<=399))) return undefined;
    for (let i=0;i<n;i++) {
      if (perOperation[i].generated > v.operations[i].generatedRequests || perOperation[i].denied > v.operations[i].deniedRequests
        || v.status === 'completed' && (perOperation[i].generated !== v.operations[i].generatedRequests || perOperation[i].denied !== v.operations[i].deniedRequests)) return undefined;
    }
    if (v.status === 'completed' && (attempts.size !== v.requests.attempted || Array.from({length:v.requests.attempted},(_,i)=>i+1).some(i=>!attempts.has(i))
      || v.requests.responseBytes > v.limits.maxTotalBytes)) return undefined;
    return structuredClone(v) as SchemathesisAuthEvidence;
  } catch { return undefined; }
}
