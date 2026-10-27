import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';

export const PG_LOG_LIMITS = Object.freeze({ recordBytes: 65536, sqlBytes: 32768, markers: 2000, parameters: 128 });
/** Values independently verified by the trusted collector; this module does not authenticate their claims. */
export interface PgLogPrerequisites {
  pgMajor: 18; serverEncoding: 'UTF8'; lcMessages: 'C'; logErrorVerbosity: 'verbose';
  logStatement: 'all'; logMinErrorStatement: 'error'; logParameterMaxLength: -1;
}
/** Private issued-marker lookup, never a Stage/report field or an authentication secret. */
export interface PgLogIssuedMarker { marker: string; markerHash: string }
declare const statementHandle: unique symbol;
export interface PgLogStatementHandle { readonly [statementHandle]: true }
export interface PgLogMetadata {
  channel: 'statement' | 'bind'; emitter: 'simple-query' | 'extended-execute'; markerHash: string;
  pgSessionId: string; pgSessionLine: number; rawEventSha256: string; rawStatementSha256: string;
  statementBytes: number;
}
export type PgLogReason = 'encoding' | 'framing' | 'limit' | 'shape' | 'invalid_markers' | 'prerequisites'
  | 'missing_origin' | 'origin_mismatch' | 'unsupported_message' | 'unsupported_error' | 'invalid_bind'
  | 'ambiguous_marker';
export type PgLogResult = Readonly<{ status: 'ignored' } | { status: 'unknown'; reason: PgLogReason }
  | { status: 'parsed'; metadata: Readonly<PgLogMetadata>; statement: PgLogStatementHandle }>;
const statements = new WeakMap<PgLogStatementHandle, string>();
const sha = (raw: string | Uint8Array) => createHash('sha256').update(raw).digest('hex');
class InvalidPgLog extends Error { constructor(readonly reason: PgLogReason) { super(reason); } }
function fail(reason: PgLogReason): never { throw new InvalidPgLog(reason); }
function check(value: unknown, reason: PgLogReason = 'shape'): asserts value { if (!value) fail(reason); }
function record(value: unknown): Record<string, unknown> {
  check(value !== null && typeof value === 'object' && !Array.isArray(value));
  return value as Record<string, unknown>;
}
function text(raw: unknown): asserts raw is string { check(typeof raw === 'string'); }
function positive(raw: unknown): asserts raw is number {
  check(Number.isSafeInteger(raw) && (raw as number) > 0);
}
function scalarStrings(raw: unknown): void {
  if (typeof raw === 'string') {
    check(!raw.includes('\0'), 'encoding');
    for (const ch of raw) check(!(ch.codePointAt(0)! >= 0xd800 && ch.codePointAt(0)! <= 0xdfff), 'encoding');
  } else if (raw !== null && typeof raw === 'object') {
    for (const [key, value] of Object.entries(raw)) { scalarStrings(key); scalarStrings(value); }
  }
}
function byteCopy(raw: Uint8Array): Buffer {
  check(!types.isProxy(raw) && types.isUint8Array(raw), 'encoding');
  const proto = Object.getPrototypeOf(Uint8Array.prototype);
  const field = (name: string) => Object.getOwnPropertyDescriptor(proto, name)!.get!.call(raw);
  const size = field('byteLength'), offset = field('byteOffset'), buffer = field('buffer');
  check(size > 0 && size <= PG_LOG_LIMITS.recordBytes, 'limit');
  check(types.isArrayBuffer(buffer), 'encoding'); // SharedArrayBuffer is never copied or retained.
  return Buffer.from(new Uint8Array(buffer, offset, size));
}
function decode(bytes: Buffer): Record<string, unknown> {
  check(bytes[0] === 123 && bytes.at(-2) === 125 && bytes.at(-1) === 10, 'framing');
  check(!bytes.subarray(0, -1).includes(10) && !bytes.includes(13), 'framing');
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { return fail('encoding'); }
  const data = snapshotJsonData(parsed, () => fail('shape'), () => fail('limit'));
  scalarStrings(data); return record(data);
}
function prerequisites(raw: PgLogPrerequisites): void {
  const expected: PgLogPrerequisites = { pgMajor: 18, serverEncoding: 'UTF8', lcMessages: 'C',
    logErrorVerbosity: 'verbose', logStatement: 'all', logMinErrorStatement: 'error', logParameterMaxLength: -1 };
  const data = record(snapshotJsonData(raw, () => fail('prerequisites'), () => fail('limit')));
  check(Object.keys(data).length === Object.keys(expected).length
    && Object.entries(expected).every(([key, value]) => data[key] === value), 'prerequisites');
}
function issuedMarkers(raw: readonly PgLogIssuedMarker[]): Map<string, string> {
  const data = snapshotJsonData(raw, () => fail('invalid_markers'), () => fail('limit'));
  check(Array.isArray(data) && data.length <= PG_LOG_LIMITS.markers, 'invalid_markers');
  const result = new Map<string, string>(), hashes = new Set<string>();
  for (const value of data) {
    const row = record(value);
    check(Object.keys(row).length === 2 && typeof row.marker === 'string' && typeof row.markerHash === 'string'
      && /^wk[a-z0-9]{4}[a-z2-7]{8}$/.test(row.marker) && /^[a-f0-9]{64}$/.test(row.markerHash)
      && row.markerHash === sha(row.marker) && !result.has(row.marker)
      && !hashes.has(row.markerHash), 'invalid_markers');
    result.set(row.marker, row.markerHash); hashes.add(row.markerHash);
  }
  return result;
}
// Fixed marker lookup only, never SQL tokenization or a statement/payload security classification.
function markers(value: string, issued: Map<string, string>): Set<string> {
  const found = new Set<string>(); let index = value.indexOf('wk');
  while (index !== -1) {
    const hash = issued.get(value.slice(index, index + 14)); if (hash) found.add(hash);
    index = value.indexOf('wk', index + 2);
  }
  return found;
}
const stringFields = ['timestamp', 'user', 'dbname', 'remote_host', 'session_id', 'ps', 'session_start', 'vxid',
  'error_severity', 'state_code', 'message', 'detail', 'hint', 'internal_query', 'context', 'statement', 'func_name',
  'file_name', 'application_name', 'backend_type'];
const numberFields = ['pid', 'remote_port', 'line_num', 'txid', 'internal_position', 'cursor_position',
  'file_line_num', 'leader_pid', 'query_id'];
function sourceFields(data: Record<string, unknown>): void {
  check(typeof data.file_name === 'string' && typeof data.func_name === 'string'
    && Number.isSafeInteger(data.file_line_num) && (data.file_line_num as number) > 0
    && typeof data.backend_type === 'string', 'missing_origin');
}
function shape(data: Record<string, unknown>): void {
  for (const key of stringFields) if (Object.hasOwn(data, key)) text(data[key]);
  for (const key of numberFields) if (Object.hasOwn(data, key)) {
    check(Number.isInteger(data[key]));
    if (key !== 'query_id') check(Number.isSafeInteger(data[key]) && (data[key] as number) >= 0);
  }
  for (const key of ['timestamp', 'message', 'session_id', 'error_severity', 'state_code']) text(data[key]);
  check(/^[0-9a-f]{1,16}\.[0-9a-f]{1,8}$/.test(data.session_id as string)); positive(data.line_num);
  check(/^[0-9A-Z]{5}$/.test(data.state_code as string));
  check(['DEBUG1', 'DEBUG2', 'DEBUG3', 'DEBUG4', 'DEBUG5', 'LOG', 'INFO', 'NOTICE', 'WARNING', 'ERROR',
    'FATAL', 'PANIC'].includes(data.error_severity as string));
  sourceFields(data);
}
function origin(data: Record<string, unknown>): 'simple-query' | 'extended-execute' {
  check(data.file_name === 'postgres.c' && data.backend_type === 'client backend', 'origin_mismatch');
  if (data.func_name === 'exec_simple_query') return 'simple-query';
  if (data.func_name === 'exec_execute_message') return 'extended-execute';
  return fail('origin_mismatch');
}
function statement(data: Record<string, unknown>, emitter: PgLogMetadata['emitter']): string {
  const message = data.message as string;
  if (emitter === 'simple-query') {
    check(message.startsWith('statement: ') && !Object.hasOwn(data, 'detail'), 'unsupported_message');
    return message.slice(11);
  }
  const end = message.indexOf(': ');
  // Only the C-locale logging envelope is matched; no SQL grammar is inferred with this expression.
  check(end !== -1 && /^execute (?:<unnamed>|[A-Za-z_][A-Za-z0-9_]{0,62})(?:\/[A-Za-z_][A-Za-z0-9_]{0,62})?$/
    .test(message.slice(0, end)), 'unsupported_message');
  return message.slice(end + 2);
}
function quotedEnd(detail: string, start: number): number {
  check(detail[start] === "'", 'invalid_bind');
  for (let index = start + 1; index < detail.length; index++) {
    if (detail[index] !== "'") continue;
    if (detail[index + 1] === "'") { index++; continue; }
    check(!detail.slice(start + 1, index).endsWith('...'), 'invalid_bind'); return index + 1;
  }
  return fail('invalid_bind');
}
function bindMarkers(raw: unknown, issued: Map<string, string>): Set<string> {
  if (raw === undefined) return new Set();
  text(raw); check(raw.startsWith('Parameters: '), 'invalid_bind');
  const found = new Set<string>(); let index = 12, count = 0;
  while (index < raw.length) {
    check(++count <= PG_LOG_LIMITS.parameters, 'limit');
    const prefix = '$' + count + ' = '; check(raw.startsWith(prefix, index), 'invalid_bind'); index += prefix.length;
    if (raw.startsWith('NULL', index)) index += 4;
    else {
      const end = quotedEnd(raw, index);
      for (const hash of markers(raw.slice(index + 1, end - 1), issued)) found.add(hash);
      index = end;
    }
    if (index === raw.length) break;
    check(raw.slice(index, index + 2) === ', ', 'invalid_bind'); index += 2;
    check(index < raw.length, 'invalid_bind');
  }
  check(count > 0, 'invalid_bind'); return found;
}
function normalize(bytes: Buffer, data: Record<string, unknown>, issued: Map<string, string>): PgLogResult {
  shape(data);
  const candidate = [data.message, data.detail, data.statement, data.internal_query, data.context, data.hint]
    .some(value => typeof value === 'string' && markers(value, issued).size > 0);
  if (!candidate) return Object.freeze({ status: 'ignored' }); // No raw event or statement digest is computed.
  // Every error source/position is currently unsupported, including scanner_yyerror and PL/pgSQL RAISE.
  if (data.error_severity !== 'LOG' || data.state_code !== '00000'
    || Object.hasOwn(data, 'statement') || Object.hasOwn(data, 'cursor_position')) fail('unsupported_error');
  const emitter = origin(data), sql = statement(data, emitter), size = Buffer.byteLength(sql);
  check(size > 0 && size <= PG_LOG_LIMITS.sqlBytes, 'limit');
  const direct = markers(sql, issued), bound = emitter === 'extended-execute' ? bindMarkers(data.detail, issued)
    : new Set<string>(), matches = new Set([...direct, ...bound]);
  if (matches.size === 0) return Object.freeze({ status: 'ignored' });
  check(matches.size === 1 && !(direct.size > 0 && bound.size > 0), 'ambiguous_marker');
  const handle = Object.freeze(Object.create(null)) as PgLogStatementHandle;
  const metadata: PgLogMetadata = { channel: bound.size > 0 ? 'bind' : 'statement', emitter,
    markerHash: [...matches][0], pgSessionId: data.session_id as string, pgSessionLine: data.line_num as number,
    rawEventSha256: sha(bytes), rawStatementSha256: sha(sql), statementBytes: size };
  statements.set(handle, sql);
  return Object.freeze({ status: 'parsed', metadata: Object.freeze(metadata), statement: handle });
}
/** Format normalization only: no SQL judgement, source authentication, Observation or collection capability. */
export function parsePgJsonLogRecord(raw: Uint8Array, issued: readonly PgLogIssuedMarker[],
  settings: PgLogPrerequisites): PgLogResult {
  try {
    prerequisites(settings); const lookup = issuedMarkers(issued), bytes = byteCopy(raw);
    return normalize(bytes, decode(bytes), lookup);
  } catch (error) {
    return Object.freeze({ status: 'unknown', reason: error instanceof InvalidPgLog ? error.reason : 'shape' });
  }
}
/** Trusted synchronous parser-input sink only. The raw SQL is never returned or placed on an enumerable object. */
export function consumePgLogStatement(handle: PgLogStatementHandle, sink: (sql: string) => void):
  'consumed' | 'unavailable' | 'parser_failed' {
  if (!handle || typeof handle !== 'object' || types.isProxy(handle)) return 'unavailable';
  const sql = statements.get(handle); statements.delete(handle);
  if (sql === undefined) return 'unavailable';
  if (typeof sink !== 'function' || types.isProxy(sink) || types.isAsyncFunction(sink)) return 'parser_failed';
  try { return sink(sql) === undefined ? 'consumed' : 'parser_failed'; } catch { return 'parser_failed'; }
}
/** Call on abandoned/error paths too; reference removal is not a guarantee of immediate physical memory erasure. */
export function discardPgLogStatement(handle: PgLogStatementHandle): void {
  if (handle && typeof handle === 'object' && !types.isProxy(handle)) statements.delete(handle);
}
