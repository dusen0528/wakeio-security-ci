import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { TASK_ID } from '../../agent-dast/result.js';
import { snapshotJsonData } from '../../json-snapshot.js';
import { issuedMarkerSurfaces } from '../markers.js';
import type { IssuedMarkers } from '../markers.js';
import type { AttackAttempt, JsonData, MarkerRow, RuntimeParameter, RuntimeRequestPort, RuntimeResponse,
  RuntimeSurface } from '../types.js';

export interface NativeSqlPlan { taskId: string; snapshotHash: string; surfaces: readonly RuntimeSurface[] }
export interface NativeSqlBinding {
  logicalOrdinal: number; phase: 'control' | 'probe'; markerHash: string; snapshotHash: string;
}
export interface NativeSqlWindow extends NativeSqlBinding { admissionOrdinal: number; opened: true }
/** Trusted R3 capabilities, not caller assertions: each acknowledgement must describe actual completed barriers. */
export interface NativeSqlHooks {
  restore(binding: Readonly<NativeSqlBinding>): Promise<NativeSqlBinding>;
  begin(binding: Readonly<NativeSqlBinding>): Promise<NativeSqlWindow>;
  complete(binding: Readonly<NativeSqlWindow>, delivery: Readonly<NativeSqlDelivery>):
    Promise<NativeSqlWindow & { closed: true; drained: true; coverageComplete: true }>;
}
export interface NativeSqlDelivery {
  logicalOrdinal: number; admissionOrdinal: number | null; expectedAdmissionOrdinal: number | null;
  sent: RuntimeResponse['sent']; outcome: RuntimeResponse['outcome'] | 'not_started' | 'invalid_response';
  rawBodySha256: string | null; bodyBytes: number; truncated: boolean;
}
export type NativeSqlReason = 'invalid_input' | 'unsupported_surface' | 'aborted' | 'restore_failed'
  | 'begin_failed' | 'complete_failed' | 'admission_binding' | 'response_invalid' | 'response_incomplete'
  | 'control_failed' | 'stopped';
export interface NativeSqlResult {
  status: 'completed' | 'unknown'; attempts: AttackAttempt[]; deliveries: NativeSqlDelivery[];
  gaps: { requestOrdinal: number | null; reason: NativeSqlReason }[];
}
type Wire = Pick<Parameters<RuntimeRequestPort['request']>[0], 'method' | 'path' | 'query' | 'body'>;
type Prepared = { taskId: string; row: MarkerRow; wire: Wire; attempt: AttackAttempt;
  binding: Readonly<NativeSqlBinding> };
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
class NativeSqlError extends Error { constructor(readonly reason: NativeSqlReason) { super(reason); } }
function check(value: unknown, reason: NativeSqlReason = 'invalid_input'): asserts value {
  if (!value) throw new NativeSqlError(reason);
}
function data<T>(value: unknown): T { return snapshotJsonData(value) as T; }
function fields(value: unknown, names: string): Record<string, unknown> {
  check(value && typeof value === 'object' && !Array.isArray(value)); const row = value as Record<string, unknown>;
  const keys = names.split(' ');
  check(Object.keys(row).length === keys.length && keys.every(k => Object.hasOwn(row, k)));
  return row;
}
function sha(value: unknown): asserts value is string {
  check(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value));
}
function own(value: unknown): Record<string, unknown> {
  check(value && typeof value === 'object' && !types.isProxy(value));
  const descriptors = Object.getOwnPropertyDescriptors(value), result = Object.create(null) as Record<string, unknown>;
  check(Object.values(descriptors).every(d => 'value' in d));
  for (const [key, descriptor] of Object.entries(descriptors)) result[key] = descriptor.value;
  return result;
}
function capabilities(port: RuntimeRequestPort, hooks: NativeSqlHooks) {
  const p = own(port), h = own(hooks);
  check(p.transport === 'stdio-relay' && typeof p.leaseId === 'string' && p.leaseId.length > 0
    && typeof p.origin === 'string' && Number.isSafeInteger(p.deadlineAt) && (p.deadlineAt as number) > 0
    && Number.isSafeInteger(p.maxRequests) && (p.maxRequests as number) > 0 && typeof p.request === 'function');
  check(['restore', 'begin', 'complete'].every(k => typeof h[k] === 'function' && !types.isProxy(h[k]))
    && !types.isProxy(p.request));
  const request: RuntimeRequestPort['request'] = input => Reflect.apply(p.request as Function, port, [input]);
  const restore: NativeSqlHooks['restore'] = input => Reflect.apply(h.restore as Function, hooks, [input]);
  const begin: NativeSqlHooks['begin'] = input => Reflect.apply(h.begin as Function, hooks, [input]);
  const complete: NativeSqlHooks['complete'] = (input, delivery) =>
    Reflect.apply(h.complete as Function, hooks, [input, delivery]);
  return { port: { ...p, request } as unknown as RuntimeRequestPort, hooks: { restore, begin, complete } };
}
function parameter(surface: RuntimeSurface, row: MarkerRow): RuntimeParameter {
  check(surface.readiness === 'ready' && Array.isArray(surface.reasons) && surface.reasons.length === 0
    && Array.isArray(surface.params) && surface.params.length > 0 && surface.params.length <= 128,
  'unsupported_surface');
  const matches = surface.params.filter(p => ['in', 'name', 'jsonPointer', 'schemaLocator']
    .every(k => p[k as keyof RuntimeParameter] === row.param[k as keyof MarkerRow['param']]));
  check(matches.length === 1, 'unsupported_surface'); const target = matches[0];
  check(target.type === 'string' && typeof target.required === 'boolean'
    && surface.params.every(p => typeof p.required === 'boolean' && p.type !== 'unknown'
      && (p === target || !p.required && p.in === 'query')), 'unsupported_surface');
  return target;
}
function jsonBody(pointer: string | null, name: string, value: string): JsonData {
  check(typeof pointer === 'string' && pointer.startsWith('/') && !/~(?![01])/.test(pointer), 'unsupported_surface');
  const parts = pointer.slice(1).split('/').map(p => p.replace(/~1/g, '/').replace(/~0/g, '~'));
  check(parts.length === 1 && parts.at(-1) === name && parts.every(p => p.length > 0
    && !/^\d+$/.test(p) && !['__proto__', 'prototype', 'constructor'].includes(p)), 'unsupported_surface');
  let result: JsonData = value;
  for (const key of parts.reverse()) { const next = Object.create(null); next[key] = result; result = next; }
  return result;
}
function payload(kind: MarkerRow['payload'], marker: string): string {
  if (kind === 'benign') return marker;
  if (kind === 'sql-quote') return marker + "'";
  return marker + "' OR '" + marker + "'='" + marker;
}
function wire(surface: RuntimeSurface, row: MarkerRow, value: string): Wire {
  const p = parameter(surface, row), s = p.serialization, path = surface.pathTemplate;
  check(s && typeof s === 'object', 'unsupported_surface');
  if (surface.method === 'POST') {
    check(p.in === 'body' && p.mediaType === 'application/json' && surface.params.length === 1
      && !/[{}]/.test(path) && s.style === null && s.explode === null && s.allowReserved === null,
    'unsupported_surface');
    return { method: 'POST', path, query: [], body: { mediaType: 'application/json',
      data: jsonBody(p.jsonPointer, p.name, value) } };
  }
  check(surface.method === 'GET' && p.mediaType === null && p.jsonPointer === null
    && s.allowReserved === false && typeof s.explode === 'boolean', 'unsupported_surface');
  if (p.in === 'query') {
    check(s.style === 'form' && !/[{}]/.test(path), 'unsupported_surface');
    return { method: 'GET', path, query: [[p.name, value]], body: null };
  }
  const placeholders = [...path.matchAll(/\{([^{}]+)\}/g)];
  check(p.in === 'path' && s.style === 'simple' && s.explode === false && placeholders.length === 1
    && placeholders[0][1] === p.name, 'unsupported_surface');
  const encoded = encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return { method: 'GET', path: path.replace('{' + p.name + '}', encoded), query: [], body: null };
}
function prepare(raw: NativeSqlPlan, issued: IssuedMarkers): Prepared[] {
  const issuedSurfaces = issuedMarkerSurfaces(issued); check(issuedSurfaces);
  const plan = data<NativeSqlPlan>(raw); fields(plan, 'taskId snapshotHash surfaces');
  check(TASK_ID.test(plan.taskId)); sha(plan.snapshotHash);
  check(Array.isArray(plan.surfaces) && plan.surfaces.length > 0 && plan.surfaces.length <= 1000);
  check(new Set(plan.surfaces.map(s => s.id)).size === plan.surfaces.length);
  return issued.ledger.rows.map(row => {
    const surface = plan.surfaces.find(s => s.id === row.surfaceId);
    const bound = issuedSurfaces.find(s => s.id === row.surfaceId);
    check(surface && bound && surface.method === row.method && surface.method === bound.method
      && surface.pathTemplate === bound.pathTemplate, 'unsupported_surface');
    const marker = issued.markerForExecutor(row.requestOrdinal); check(hash(marker) === row.markerHash);
    const value = payload(row.payload, marker), request = wire(surface, row, value);
    const phase = row.payload === 'benign' ? 'control' : 'probe';
    const binding = Object.freeze({ logicalOrdinal: row.requestOrdinal, phase, markerHash: row.markerHash,
      snapshotHash: plan.snapshotHash });
    return { taskId: plan.taskId, row, wire: request, binding, attempt: { ordinal: row.requestOrdinal,
      surfaceId: row.surfaceId,
      markerHash: row.markerHash, payloadHash: hash(value), requestHash: hash(JSON.stringify(request)), phase,
      snapshotHash: plan.snapshotHash, outcome: 'not_started', httpStatus: null } };
  });
}
function binding(raw: unknown, expected: NativeSqlBinding, extra = ''): Record<string, unknown> {
  const b = fields(data(raw), 'logicalOrdinal phase markerHash snapshotHash' + extra);
  check(Object.entries(expected).every(([key, value]) => b[key] === value)); return b;
}
function emptyDelivery(ordinal: number): NativeSqlDelivery {
  return { logicalOrdinal: ordinal, admissionOrdinal: null, expectedAdmissionOrdinal: null, sent: 'not_sent',
    outcome: 'not_started', rawBodySha256: null, bodyBytes: 0, truncated: false };
}
function bodyCopy(raw: unknown, max: number): Buffer {
  check(!types.isProxy(raw) && types.isUint8Array(raw));
  const proto = Object.getPrototypeOf(Uint8Array.prototype);
  const field = (name: string) => Object.getOwnPropertyDescriptor(proto, name)!.get!.call(raw);
  const size = field('byteLength'), offset = field('byteOffset'), buffer = field('buffer');
  check(size <= max && types.isArrayBuffer(buffer)); return Buffer.from(new Uint8Array(buffer, offset, size));
}
function response(raw: unknown, delivery: NativeSqlDelivery, max: number): number | null {
  const r = fields(own(raw), 'ordinal outcome sent status bodyBytes rawBodySha256 truncated');
  const meta = data<Omit<RuntimeResponse, 'bodyBytes'>>({ ordinal: r.ordinal, outcome: r.outcome, sent: r.sent,
    status: r.status, rawBodySha256: r.rawBodySha256, truncated: r.truncated });
  check(Number.isSafeInteger(meta.ordinal) && meta.ordinal > 0
    && ['confirmed', 'not_sent', 'unknown'].includes(meta.sent)
    && ['response', 'transport_error', 'cancelled', 'limit'].includes(meta.outcome)
    && typeof meta.truncated === 'boolean');
  check(meta.status === null || Number.isInteger(meta.status) && meta.status >= 100 && meta.status <= 599);
  Object.assign(delivery, { admissionOrdinal: meta.ordinal, sent: meta.sent, outcome: meta.outcome,
    truncated: meta.truncated });
  const bytes = bodyCopy(r.bodyBytes, max);
  try {
    if (meta.rawBodySha256 !== null) { sha(meta.rawBodySha256); check(meta.rawBodySha256 === hash(bytes)); }
    check(meta.outcome !== 'response' || meta.sent === 'confirmed' && meta.status !== null
      && meta.rawBodySha256 !== null);
    check(meta.sent !== 'not_sent' || meta.status === null && bytes.length === 0 && meta.rawBodySha256 === null);
    delivery.rawBodySha256 = meta.rawBodySha256; delivery.bodyBytes = bytes.length; return meta.status;
  } finally { bytes.fill(0); }
}
const aborted = (signal: AbortSignal) =>
  Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(signal);
async function executeOne(item: Prepared, port: RuntimeRequestPort, hooks: NativeSqlHooks,
  options: { signal: AbortSignal; deadlineAt: number; maxResponseBytes: number }, delivery: NativeSqlDelivery,
  previousOrdinal: number) {
  check(!aborted(options.signal), 'aborted');
  try { binding(await hooks.restore(item.binding), item.binding); }
  catch { throw new NativeSqlError('restore_failed'); }
  check(!aborted(options.signal), 'aborted'); let window: NativeSqlWindow;
  try {
    window = binding(await hooks.begin(item.binding), item.binding,
      ' admissionOrdinal opened') as unknown as NativeSqlWindow;
    check(window.opened === true && Number.isSafeInteger(window.admissionOrdinal) && window.admissionOrdinal > 0);
  } catch { throw new NativeSqlError('begin_failed'); }
  delivery.expectedAdmissionOrdinal = window.admissionOrdinal;
  let reason: NativeSqlReason | undefined, status: number | null = null;
  if (window.admissionOrdinal > port.maxRequests || window.admissionOrdinal <= previousOrdinal)
    reason = 'admission_binding';
  else if (aborted(options.signal)) { delivery.outcome = 'cancelled'; reason = 'aborted'; }
  else {
    Object.assign(delivery, { sent: 'unknown', outcome: 'transport_error' });
    try {
      const raw = await port.request({ taskId: item.taskId, phase: item.binding.phase, ...item.wire,
        deadlineAt: options.deadlineAt, maxResponseBytes: options.maxResponseBytes, signal: options.signal });
      try { status = response(raw, delivery, options.maxResponseBytes); }
      catch { delivery.outcome = 'invalid_response'; reason = 'response_invalid'; }
    } catch { reason = 'response_incomplete'; }
    item.attempt.outcome = delivery.sent === 'not_sent' ? 'not_started' : 'transport_error';
    if (!reason && delivery.admissionOrdinal !== window.admissionOrdinal) reason = 'admission_binding';
    if (!reason && delivery.outcome === 'response' && !delivery.truncated) {
      item.attempt.outcome = 'response'; item.attempt.httpStatus = status;
      if (item.binding.phase === 'control' && (status === null || status < 200 || status >= 300))
        reason = 'control_failed';
    } else reason ??= 'response_incomplete';
  }
  try {
    const ack = binding(await hooks.complete(Object.freeze(window), Object.freeze({ ...delivery })), item.binding,
      ' admissionOrdinal opened closed drained coverageComplete');
    check(ack.admissionOrdinal === window.admissionOrdinal && ack.opened === true && ack.closed === true
      && ack.drained === true && ack.coverageComplete === true);
  } catch { throw new NativeSqlError('complete_failed'); }
  if (reason) throw new NativeSqlError(reason);
}
/** Internal sequential execution only. The injected request port alone owns actual admission and transport. */
export async function runNativeSql(rawPlan: NativeSqlPlan, issued: IssuedMarkers, rawPort: RuntimeRequestPort,
  rawHooks: NativeSqlHooks, rawOptions: { signal: AbortSignal; deadlineAt: number; maxResponseBytes: number }):
  Promise<NativeSqlResult> {
  let prepared: Prepared[] = [];
  const result: NativeSqlResult = { status: 'unknown', attempts: [], deliveries: [], gaps: [] };
  try {
    prepared = prepare(rawPlan, issued);
    result.attempts = prepared.map(p => p.attempt);
    result.deliveries = prepared.map(p => emptyDelivery(p.row.requestOrdinal));
    const caps = capabilities(rawPort, rawHooks), options = own(rawOptions);
    fields(options, 'signal deadlineAt maxResponseBytes'); check(!types.isProxy(options.signal));
    aborted(options.signal as AbortSignal);
    check(Number.isSafeInteger(options.deadlineAt) && (options.deadlineAt as number) > 0
      && Number.isSafeInteger(options.maxResponseBytes) && (options.maxResponseBytes as number) >= 1
      && (options.maxResponseBytes as number) <= 1048576);
    const settings = { signal: options.signal as AbortSignal,
      deadlineAt: Math.min(options.deadlineAt as number, caps.port.deadlineAt),
      maxResponseBytes: options.maxResponseBytes as number };
    for (const [index, item] of prepared.entries()) {
      try { await executeOne(item, caps.port, caps.hooks, settings, result.deliveries[index],
        index === 0 ? 0 : result.deliveries[index - 1].expectedAdmissionOrdinal ?? 0); }
      catch (error) {
        const reason = error instanceof NativeSqlError ? error.reason : 'invalid_input';
        result.gaps.push({ requestOrdinal: item.row.requestOrdinal, reason });
        for (const pending of prepared.slice(index + 1)) result.gaps.push({
          requestOrdinal: pending.row.requestOrdinal, reason: 'stopped' });
        return result;
      }
    }
    result.status = 'completed'; return result;
  } catch (error) {
    const reason = error instanceof NativeSqlError ? error.reason : 'invalid_input';
    const ordinals = issuedMarkerSurfaces(issued) ? issued.ledger.rows.map(r => r.requestOrdinal) : [null];
    result.gaps.push(...ordinals.map(requestOrdinal => ({ requestOrdinal, reason }))); return result;
  }
}
