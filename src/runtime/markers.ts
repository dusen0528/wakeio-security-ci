import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { snapshotJsonData } from '../json-snapshot.js';
import type { MarkerLedger, MarkerRow, SurfaceRef } from './types.js';

export type MarkerReservation = Omit<MarkerRow, 'markerHash'>;
export interface MarkerIssueInput {
  reproductionKey: string;
  /** Explicit nonsecret label; the caller must never derive it from credentials. */
  seed: string;
  /** Remaining shared admission budget, including controls; issuance does not consume/send requests. */
  remainingBudget: number;
  reservations: readonly MarkerReservation[];
  /** Existing validated surface identities; this issuer does not discover or create routes/DTOs. */
  surfaces: readonly SurfaceRef[];
}
export interface IssuedMarkers {
  /** Only this data belongs in the report/stage artifact. It contains no raw marker or payload. */
  readonly ledger: Readonly<MarkerLedger>;
  /** Private transient lookup for the trusted executor only; never send to reports/agents/loggers. */
  readonly markerForExecutor: (requestOrdinal: number) => string;
}
const MAX_RESERVATIONS = 2000, MAX_ORDINAL = 32768, MAX_BYTES = 1024 * 1024;
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const hash = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
function invalid(): never { throw new TypeError('invalid_marker_reservation'); }
function requireData(value: unknown): asserts value { if (!value) invalid(); }
function integer(raw: unknown, min: number, max: number): void {
  requireData(Number.isSafeInteger(raw) && (raw as number) >= min && (raw as number) <= max);
}
function object(raw: unknown): asserts raw is Record<string, unknown> {
  requireData(raw && typeof raw === 'object' && !Array.isArray(raw));
}
function keys(raw: unknown, names: string): void {
  object(raw); const expected = names.split(' ');
  requireData(Object.keys(raw).length === expected.length && expected.every(name => Object.hasOwn(raw, name)));
}
function label(raw: unknown, max: number): asserts raw is string {
  requireData(typeof raw === 'string' && raw.length > 0 && raw.length <= max && /^[\x21-\x7e]+$/.test(raw));
}
function descriptors(raw: unknown) {
  requireData(raw && typeof raw === 'object' && !types.isProxy(raw));
  const prototype = Object.getPrototypeOf(raw);
  requireData(Array.isArray(raw) ? prototype === Array.prototype
    : prototype === Object.prototype || prototype === null);
  requireData(Object.getOwnPropertySymbols(raw).length === 0);
  const data = Object.getOwnPropertyDescriptors(raw);
  requireData(Object.keys(data).length <= 20001 && Object.values(data).every(d => 'value' in d));
  return data;
}
function capture(raw: MarkerIssueInput): MarkerIssueInput {
  const fields = descriptors(raw), names = ['reproductionKey', 'seed', 'remainingBudget', 'reservations', 'surfaces'];
  requireData(Object.keys(fields).length === names.length && names.every(name => fields[name]?.enumerable));
  const metadata = snapshotJsonData({ reproductionKey: fields.reproductionKey.value, seed: fields.seed.value,
    remainingBudget: fields.remainingBudget.value, surfaces: fields.surfaces.value }) as Omit<MarkerIssueInput,
      'reservations'>;
  const list = fields.reservations.value, entries = descriptors(list), length = entries.length?.value;
  requireData(Array.isArray(list)); integer(length, 2, MAX_RESERVATIONS);
  requireData(Object.keys(entries).length === length + 1);
  const reservations: MarkerReservation[] = []; let bytes = Buffer.byteLength(JSON.stringify(metadata));
  for (let i = 0; i < length; i++) {
    requireData(entries[String(i)]?.enumerable);
    const row = snapshotJsonData(entries[String(i)].value, invalid, invalid) as MarkerReservation;
    bytes += Buffer.byteLength(JSON.stringify(row)); requireData(bytes <= MAX_BYTES); reservations.push(row);
  }
  return { ...metadata, reservations };
}
function path(raw: unknown): asserts raw is string {
  label(raw, 512); requireData(raw.startsWith('/') && !raw.startsWith('//') && !/[\\%?#:]/.test(raw));
  const segments = raw.slice(1).split('/');
  for (const [index, segment] of segments.entries()) {
    requireData(segment !== '.' && segment !== '..');
    requireData(segment === '' ? index === segments.length - 1 : /^[A-Za-z0-9._~-]+$/.test(segment)
      || /^\{[A-Za-z_][A-Za-z0-9_-]{0,79}\}$/.test(segment));
  }
}
function surfaceTable(raw: readonly SurfaceRef[]): Map<string, SurfaceRef> {
  requireData(Array.isArray(raw) && raw.length > 0 && raw.length <= 1000);
  const result = new Map<string, SurfaceRef>();
  for (const s of raw) {
    keys(s, 'id method pathTemplate'); path(s.pathTemplate);
    requireData(typeof s.id === 'string' && /^[A-Za-z0-9_][A-Za-z0-9 _./{}-]{0,159}$/.test(s.id)
      && ['GET', 'POST'].includes(s.method) && !result.has(s.id)); result.set(s.id, s);
  }
  return result;
}
function pointer(raw: unknown): string[] {
  label(raw, 256); requireData(raw.startsWith('/') && !/~(?![01])/.test(raw));
  const parts = raw.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'));
  requireData(parts.every(part => part.length > 0 && !['__proto__', 'prototype', 'constructor'].includes(part)));
  return parts;
}
function parameter(raw: MarkerRow['param'], method: string, route: string): void {
  keys(raw, 'in name jsonPointer schemaLocator'); label(raw.name, 80); label(raw.schemaLocator, 512);
  requireData(!/[\\%\s]/.test(raw.schemaLocator) && !raw.schemaLocator.includes('://')
    && (raw.schemaLocator.startsWith('#/') || /^(query|path|json)\//.test(raw.schemaLocator))
    && !raw.schemaLocator.split('/').some(part => part === '.' || part === '..'));
  if (method === 'POST') {
    requireData(raw.in === 'body' && pointer(raw.jsonPointer).at(-1) === raw.name);
    // The caller already verified application/json + scalar leaf in RuntimeSurface; no DTO is inferred here.
  } else {
    requireData(['query', 'path'].includes(raw.in) && raw.jsonPointer === null
      && /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(raw.name));
    if (raw.in === 'path') requireData(route.split('/').includes('{' + raw.name + '}'));
  }
}
const paramKey = (p: MarkerRow['param']) => JSON.stringify([p.in, p.name, p.jsonPointer, p.schemaLocator]);
function reservations(data: MarkerIssueInput): MarkerReservation[] {
  requireData(typeof data.reproductionKey === 'string' && /^[a-f0-9]{64}$/.test(data.reproductionKey));
  requireData(typeof data.seed === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(data.seed));
  integer(data.remainingBudget, 0, MAX_RESERVATIONS); requireData(data.reservations.length <= data.remainingBudget);
  const surfaces = surfaceTable(data.surfaces), ordinals = new Set<number>();
  const pairs = new Map<string, MarkerReservation[]>();
  for (const r of data.reservations) {
    keys(r, 'surfaceId method param payload requestOrdinal controlPairId'); integer(r.requestOrdinal, 1, MAX_ORDINAL);
    const s = surfaces.get(r.surfaceId); requireData(s && s.method === r.method && !ordinals.has(r.requestOrdinal));
    requireData(typeof r.controlPairId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(r.controlPairId)
      && ['benign', 'sql-boolean', 'sql-quote'].includes(r.payload)); parameter(r.param, r.method, s.pathTemplate);
    ordinals.add(r.requestOrdinal); pairs.set(r.controlPairId, [...pairs.get(r.controlPairId) ?? [], r]);
  }
  for (const rows of pairs.values()) {
    rows.sort((a, b) => a.requestOrdinal - b.requestOrdinal);
    requireData(rows.length === 2 && rows[0].payload === 'benign'
      && ['sql-boolean', 'sql-quote'].includes(rows[1].payload) && rows[0].surfaceId === rows[1].surfaceId
      && rows[0].method === rows[1].method && paramKey(rows[0].param) === paramKey(rows[1].param));
  }
  return [...data.reservations].sort((a, b) => a.requestOrdinal - b.requestOrdinal);
}
function base32(value: number, width: number): string {
  let result = '';
  for (let i = 0; i < width; i++) { result = ALPHABET[value % 32] + result; value = Math.floor(value / 32); }
  requireData(value === 0); return result;
}
/** Deterministic logical-run reservation only. No request, admission consumption or verdict is produced. */
export function issueMarkers(raw: MarkerIssueInput): IssuedMarkers {
  const data = capture(raw), planned = reservations(data), values = new Map<number, string>();
  const prefix = base32(Number.parseInt(hash(JSON.stringify(['wakeio.markers/v1', data.reproductionKey,
    data.seed])).slice(0, 5), 16), 4), unique = new Set<string>(), hashes = new Set<string>();
  const rows: MarkerRow[] = planned.map(r => {
    // Fixed-width ordinal encoding is injective within this ledger; a truncated hash is not used as a suffix.
    const value = 'wk' + prefix + base32(r.requestOrdinal, 8), markerHash = hash(value);
    requireData(value.length === 14 && !unique.has(value) && !hashes.has(markerHash));
    unique.add(value); hashes.add(markerHash); values.set(r.requestOrdinal, value);
    return Object.freeze({ surfaceId: r.surfaceId, method: r.method, payload: r.payload,
      param: Object.freeze({ in: r.param.in, name: r.param.name, jsonPointer: r.param.jsonPointer,
        schemaLocator: r.param.schemaLocator }), requestOrdinal: r.requestOrdinal, controlPairId: r.controlPairId,
      markerHash });
  });
  const ledger = Object.freeze({ reproductionKey: data.reproductionKey, seed: data.seed, rows: Object.freeze(rows) });
  return Object.freeze({ ledger, markerForExecutor: (ordinal: number) => {
    integer(ordinal, 1, MAX_ORDINAL); const value = values.get(ordinal); requireData(value !== undefined); return value;
  } });
}
