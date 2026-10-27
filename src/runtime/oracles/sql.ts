import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';
import type { AttackAttempt, AttackLog, CaseOutcome, MarkerLedger, MarkerRow, Observation, PgCursor,
  RuntimeGap, RuntimeVerdict, SurfaceRef } from '../types.js';

type ParserPin = Observation['sql']['parser'];
type Span = [number, number];
/** Supplied by the trusted pipeline after stage provenance and collector identity verification.
 * Hash equality is not authentication. No target-provided projection or binding belongs here.
 * Positions are independently verified PG-character/UTF-8-byte correspondences, not a promotion flag.
 */
export interface SqlRequestBinding {
  attempt: AttackAttempt; marker: MarkerRow; pgSessionId: string; pgSessionLine: number; sequence: number;
  rawStatementSha256: string; rawEventSha256: string;
  begin: PgCursor; end: PgCursor; statementBytes: number; utf8Valid: boolean; truncated: boolean;
  complete: boolean; drainComplete: boolean;
  positions: { pgCharPosition1Based: number; parserByteOffset0Based: number }[];
}
export interface SqlOracleBinding {
  runId: string; epoch: string; runNonce: string; observerSession: string; sourceContainerId: string;
  parser: ParserPin; plan: AttackLog['plan']; markers: AttackLog['markers'];
  seedCursor: PgCursor; drainCursor: PgCursor; complete: boolean; drainComplete: boolean;
  surfaces: readonly SurfaceRef[]; requests: readonly SqlRequestBinding[];
}
/** Coverage is a trusted, request-bound projection; unknown accounting never cancels SQL findings. */
export interface SqlCoverage {
  requestOrdinal: number; surfaceId: string; snapshotHash: string;
  accounting: 'exact' | 'unknown'; reached: boolean | null;
}
export interface SqlOracleInput {
  attackLog: Readonly<AttackLog>; ledger: Readonly<MarkerLedger>; observations: readonly Observation[];
  binding: Readonly<SqlOracleBinding>; coverage: readonly SqlCoverage[];
}
export interface SqlOracleResult { verdicts: RuntimeVerdict[]; cases: CaseOutcome[]; gaps: RuntimeGap[] }
const REVISION = 'sql-projection/v1';
function invalid(): never { throw new TypeError('invalid_sql_oracle_input'); }
function requireData(ok: unknown): asserts ok { if (!ok) invalid(); }
function object(raw: unknown): asserts raw is Record<string, unknown> {
  requireData(raw && typeof raw === 'object' && !Array.isArray(raw));
}
function keys(raw: unknown, expected: string): void {
  object(raw); const names = expected.split(' ');
  requireData(Object.keys(raw).length === names.length && names.every(name => Object.hasOwn(raw, name)));
}
function text(raw: unknown): void { requireData(typeof raw === 'string' && raw.length > 0 && raw.length <= 160
  && !/[\x00-\x1f\x7f]/.test(raw)); }
function hash(raw: unknown): void { requireData(typeof raw === 'string' && /^[a-f0-9]{64}$/.test(raw)); }
function integer(raw: unknown, min = 0, max = 32768): void {
  requireData(Number.isSafeInteger(raw) && (raw as number) >= min && (raw as number) <= max);
}
function array(raw: unknown, max = 4096): asserts raw is unknown[] {
  requireData(Array.isArray(raw) && raw.length <= max);
}
function flag(raw: unknown): void { requireData(typeof raw === 'boolean'); }
function same(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  const left = Object.keys(a).sort(), right = Object.keys(b).sort();
  return left.length === right.length && left.every((key, i) => key === right[i]
    && same((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]));
}
function ref(raw: AttackLog['plan']): void {
  keys(raw, 'path bytes sha256'); text(raw.path); hash(raw.sha256); integer(raw.bytes, 0, 8 * 1024 * 1024);
  requireData(/^[a-zA-Z0-9_./-]+$/.test(raw.path) && !raw.path.startsWith('/')
    && raw.path.split('/').every(part => part !== '..' && part !== '.' && part !== ''));
}
function cursor(raw: PgCursor): void {
  keys(raw, 'dbLeaseId logIdentity rotation byteOffset'); text(raw.dbLeaseId); text(raw.logIdentity);
  integer(raw.rotation); integer(raw.byteOffset, 0, Number.MAX_SAFE_INTEGER);
}
function ordered(a: PgCursor, b: PgCursor): boolean {
  return a.dbLeaseId === b.dbLeaseId && a.logIdentity === b.logIdentity
    && a.rotation === b.rotation && a.byteOffset <= b.byteOffset;
}
function pin(raw: ParserPin): void {
  keys(raw, 'version pgMajor lockSha256 wasmSha256'); text(raw.version); integer(raw.pgMajor, 18, 18);
  hash(raw.lockSha256); hash(raw.wasmSha256);
}
function marker(raw: MarkerRow): void {
  keys(raw, 'markerHash surfaceId method param payload requestOrdinal controlPairId');
  hash(raw.markerHash); text(raw.surfaceId); text(raw.method); text(raw.controlPairId); integer(raw.requestOrdinal, 1);
  keys(raw.param, 'in name jsonPointer schemaLocator'); text(raw.param.in); text(raw.param.name);
  text(raw.param.schemaLocator); if (raw.param.jsonPointer !== null) text(raw.param.jsonPointer);
  requireData(['path', 'query', 'header', 'cookie', 'body'].includes(raw.param.in)
    && ['benign', 'sql-quote', 'sql-boolean'].includes(raw.payload));
}
function attempt(raw: AttackAttempt): void {
  keys(raw, 'ordinal surfaceId markerHash payloadHash requestHash phase snapshotHash outcome httpStatus');
  integer(raw.ordinal, 1); text(raw.surfaceId); hash(raw.markerHash); hash(raw.payloadHash);
  hash(raw.requestHash); hash(raw.snapshotHash);
  requireData(['control', 'probe'].includes(raw.phase)
    && ['response', 'transport_error', 'not_started'].includes(raw.outcome));
  if (raw.httpStatus !== null) integer(raw.httpStatus, 100, 599);
}
function request(raw: SqlRequestBinding, binding: SqlOracleBinding): void {
  keys(raw, 'attempt marker pgSessionId pgSessionLine sequence rawStatementSha256 rawEventSha256 '
    + 'begin end statementBytes utf8Valid truncated '
    + 'complete drainComplete positions');
  attempt(raw.attempt); marker(raw.marker); text(raw.pgSessionId); integer(raw.pgSessionLine, 1);
  integer(raw.sequence, 1); cursor(raw.begin); cursor(raw.end); integer(raw.statementBytes);
  hash(raw.rawStatementSha256); hash(raw.rawEventSha256);
  for (const value of [raw.utf8Valid, raw.truncated, raw.complete, raw.drainComplete]) flag(value);
  requireData(ordered(binding.seedCursor, raw.begin) && ordered(raw.begin, raw.end)
    && ordered(raw.end, binding.drainCursor) && raw.begin.byteOffset < raw.end.byteOffset);
  array(raw.positions); for (const position of raw.positions) {
    keys(position, 'pgCharPosition1Based parserByteOffset0Based');
    integer(position.pgCharPosition1Based, 1, 32769); integer(position.parserByteOffset0Based);
    requireData(position.parserByteOffset0Based <= raw.statementBytes);
  }
  requireData(raw.positions.every((p, i) => i === 0
    || p.pgCharPosition1Based > raw.positions[i - 1].pgCharPosition1Based
    && p.parserByteOffset0Based > raw.positions[i - 1].parserByteOffset0Based));
  requireData(raw.attempt.ordinal === raw.marker.requestOrdinal
    && raw.attempt.markerHash === raw.marker.markerHash && raw.attempt.surfaceId === raw.marker.surfaceId);
}
function metadata(data: Omit<SqlOracleInput, 'observations'>): void {
  const b = data.binding; keys(data.attackLog, 'plan markers attempts'); ref(data.attackLog.plan);
  ref(data.attackLog.markers); array(data.attackLog.attempts); data.attackLog.attempts.forEach(attempt);
  keys(data.ledger, 'reproductionKey seed rows'); hash(data.ledger.reproductionKey); text(data.ledger.seed);
  array(data.ledger.rows); data.ledger.rows.forEach(marker);
  keys(b, 'runId epoch runNonce observerSession sourceContainerId parser plan markers seedCursor drainCursor '
    + 'complete drainComplete surfaces requests');
  [b.runId, b.epoch, b.runNonce, b.observerSession, b.sourceContainerId].forEach(text);
  pin(b.parser); ref(b.plan); ref(b.markers); cursor(b.seedCursor); cursor(b.drainCursor);
  requireData(ordered(b.seedCursor, b.drainCursor)); flag(b.complete); flag(b.drainComplete);
  requireData(same(b.plan, data.attackLog.plan) && same(b.markers, data.attackLog.markers));
  array(b.surfaces); for (const s of b.surfaces) {
    keys(s, 'id method pathTemplate'); text(s.id); text(s.method); text(s.pathTemplate);
  }
  array(b.requests); b.requests.forEach(r => request(r, b)); array(data.coverage);
  for (const c of data.coverage) {
    keys(c, 'requestOrdinal surfaceId snapshotHash accounting reached'); integer(c.requestOrdinal, 1);
    text(c.surfaceId); hash(c.snapshotHash); requireData(['exact', 'unknown'].includes(c.accounting));
    requireData(c.reached === null || typeof c.reached === 'boolean');
  }
  for (const values of [data.attackLog.attempts.map(a => a.ordinal), data.ledger.rows.map(r => r.requestOrdinal),
    data.ledger.rows.map(r => r.markerHash), b.requests.map(r => r.attempt.ordinal), b.surfaces.map(s => s.id),
    b.requests.map(r => r.sequence), b.requests.map(r => r.pgSessionId + ':' + r.pgSessionLine)]) {
    requireData(new Set<string | number>(values).size === values.length);
  }
  const windows = [...b.requests].sort((a, b) => a.attempt.ordinal - b.attempt.ordinal);
  requireData(windows.every((r, i) => i === 0 || ordered(windows[i - 1].end, r.begin)));
}
function properties(raw: unknown): Record<string, PropertyDescriptor> {
  requireData(raw && typeof raw === 'object' && !types.isProxy(raw));
  const proto = Object.getPrototypeOf(raw);
  requireData(proto === Object.prototype || proto === null || proto === Array.prototype);
  requireData(Object.getOwnPropertySymbols(raw).length === 0);
  const result = Object.getOwnPropertyDescriptors(raw);
  requireData(Object.keys(result).length <= 20000 && Object.values(result).every(d => 'value' in d));
  return result;
}
function capture(raw: SqlOracleInput) {
  const p = properties(raw), names = ['attackLog', 'ledger', 'observations', 'binding', 'coverage'];
  requireData(Object.keys(p).length === names.length && names.every(n => p[n]?.enumerable));
  const data = snapshotJsonData({ attackLog: p.attackLog.value, ledger: p.ledger.value,
    binding: p.binding.value, coverage: p.coverage.value }) as Omit<SqlOracleInput, 'observations'>;
  metadata(data); const list = p.observations.value, descriptors = properties(list);
  requireData(Array.isArray(list) && list.length <= 4096 && Object.keys(descriptors).length === list.length + 1);
  const observations: unknown[] = []; let bytes = Buffer.byteLength(JSON.stringify(data));
  for (let i = 0; i < list.length; i++) {
    const d = descriptors[String(i)]; requireData(d?.enumerable);
    try {
      const value = snapshotJsonData(d.value); bytes += Buffer.byteLength(JSON.stringify(value));
      requireData(bytes <= 8 * 1024 * 1024); observations.push(value);
    } catch { observations.push(null); }
  }
  requireData(bytes <= 8 * 1024 * 1024); return { ...data, observations };
}
function span(raw: Span, max: number): void {
  array(raw, 2); requireData(raw.length === 2); integer(raw[0]); integer(raw[1]);
  requireData(raw[0] < raw[1] && raw[1] <= max);
}
const contains = (a: Span, b: Span) => a[0] <= b[0] && b[1] <= a[1];
const overlaps = (a: Span, b: Span) => a[0] < b[1] && b[0] < a[1];
function projection(o: Observation, r: SqlRequestBinding): void {
  const s = o.sql; keys(s, 'channel dialect rawStatementSha256 rawEventSha256 parser ast tokens insertions error '
    + 'controlContextHash outsidePayloadTokenHash');
  requireData(['statement', 'bind'].includes(s.channel) && s.dialect === 'postgres'); pin(s.parser);
  [s.rawStatementSha256, s.rawEventSha256, s.controlContextHash, s.outsidePayloadTokenHash].forEach(hash);
  array(s.ast); array(s.tokens); array(s.insertions); const nodes = new Map(s.ast.map(n => [n.id, n]));
  requireData(nodes.size === s.ast.length);
  requireData(s.ast.length === 0 || s.ast.filter(n => n.parent === null).length === 1);
  for (const node of s.ast) {
    keys(node, 'id kind parent span'); integer(node.id); text(node.kind); span(node.span, r.statementBytes);
    if (node.parent !== null) integer(node.parent);
    let parent = node.parent; const seen = new Set([node.id]);
    while (parent !== null) {
      const n = nodes.get(parent); requireData(n && !seen.has(parent) && seen.size < 40);
      requireData(contains(n.span, node.span)); seen.add(parent); parent = n.parent;
    }
  }
  let previous = 0;
  for (const t of s.tokens) {
    keys(t, 'kind span role'); text(t.kind); span(t.span, r.statementBytes);
    requireData(t.span[0] >= previous); previous = t.span[1];
    requireData(['literal', 'identifier', 'operator', 'syntax', 'comment', 'parameter'].includes(t.role));
  }
  for (const insertion of s.insertions) {
    keys(insertion, 'payloadHash span tokenIndexes nodeIds'); hash(insertion.payloadHash);
    span(insertion.span, r.statementBytes); array(insertion.tokenIndexes); array(insertion.nodeIds);
    requireData(insertion.payloadHash === r.attempt.payloadHash);
    for (const index of insertion.tokenIndexes) {
      integer(index); requireData(s.tokens[index] && overlaps(insertion.span, s.tokens[index].span));
    }
    for (const id of insertion.nodeIds) {
      integer(id); const n = nodes.get(id); requireData(n && overlaps(n.span, insertion.span));
    }
    requireData(new Set(insertion.tokenIndexes).size === insertion.tokenIndexes.length
      && new Set(insertion.nodeIds).size === insertion.nodeIds.length);
    requireData(s.tokens.every((token, index) => !overlaps(insertion.span, token.span)
      || insertion.tokenIndexes.includes(index)));
  }
  keys(s.error, 'sqlState pgCharPosition1Based parserByteOffset0Based kind');
  requireData(['none', 'quote_imbalance', 'other_syntax', 'unsupported', 'invalid'].includes(s.error.kind));
  if (s.error.sqlState !== null) requireData(/^[0-9A-Z]{5}$/.test(s.error.sqlState));
  if (s.error.pgCharPosition1Based !== null) integer(s.error.pgCharPosition1Based, 1, 32769);
  if (s.error.parserByteOffset0Based !== null) integer(s.error.parserByteOffset0Based, 0, r.statementBytes);
  if (s.error.kind === 'none') requireData(s.error.sqlState === null
    && s.error.pgCharPosition1Based === null && s.error.parserByteOffset0Based === null && s.ast.length > 0);
}
function observation(raw: unknown, r: SqlRequestBinding, b: SqlOracleBinding): Observation {
  const o = raw as Observation;
  keys(o, 'id runId epoch runNonce observerSession sequence requestOrdinal markerHash sourceContainerId '
    + 'pgSessionId pgSessionLine cursor requestWindow sql evidence'); text(o.id); ref(o.evidence);
  requireData(o.runId === b.runId && o.epoch === b.epoch && o.runNonce === b.runNonce
    && o.observerSession === b.observerSession && o.sourceContainerId === b.sourceContainerId
    && o.pgSessionId === r.pgSessionId && o.pgSessionLine === r.pgSessionLine && o.sequence === r.sequence
    && o.requestOrdinal === r.attempt.ordinal && o.markerHash === r.marker.markerHash);
  cursor(o.cursor); keys(o.requestWindow, 'begin end closed'); cursor(o.requestWindow.begin);
  cursor(o.requestWindow.end); requireData(o.requestWindow.closed === true && same(o.requestWindow.begin, r.begin)
    && same(o.requestWindow.end, r.end) && ordered(r.begin, o.cursor) && ordered(o.cursor, r.end));
  requireData(o.cursor.byteOffset > r.begin.byteOffset && o.cursor.byteOffset < r.end.byteOffset);
  requireData(same(o.sql.parser, b.parser) && o.sql.rawStatementSha256 === r.rawStatementSha256
    && o.sql.rawEventSha256 === r.rawEventSha256); projection(o, r); return o;
}
function eventFor(data: ReturnType<typeof capture>, r: SqlRequestBinding): Observation | undefined {
  const candidates = data.observations.filter(o => o && typeof o === 'object'
    && (o as Observation).requestOrdinal === r.attempt.ordinal);
  if (candidates.length !== 1) return undefined;
  try {
    const event = observation(candidates[0], r, data.binding);
    requireData(data.observations.filter(o => o && typeof o === 'object'
      && (o as Observation).id === event.id).length === 1);
    return event;
  } catch { return undefined; }
}
function newGrammar(probe: Observation, control: Observation): boolean {
  const s = probe.sql;
  return s.insertions.some(i => i.tokenIndexes.some(index => {
    const t = s.tokens[index];
    if (t.role !== 'syntax' || !['OR', 'AND'].includes(t.kind) || !contains(i.span, t.span)
      || s.tokens.some(other => ['literal', 'comment', 'parameter'].includes(other.role)
        && overlaps(other.span, t.span))) return false;
    return i.nodeIds.some(id => {
      const n = s.ast.find(node => node.id === id);
      if (!n || n.kind !== 'BoolExpr' || !contains(n.span, t.span)
        || control.sql.ast.some(c => c.kind === n.kind)) return false;
      const children = s.ast.filter(child => child.parent === n.id);
      return children.length >= 2 && children.some(child => child.span[1] <= t.span[0])
        && children.some(child => child.span[0] >= t.span[1])
        && !s.ast.some(node => ['StringConst', 'ParamRef'].includes(node.kind) && overlaps(node.span, t.span));
    });
  }));
}
function classification(probe: Observation, control: Observation, r: SqlRequestBinding) {
  const s = probe.sql, c = control.sql;
  if (c.error.kind !== 'none') return { reason: 'control_missing_or_failed' };
  if (s.controlContextHash !== c.controlContextHash || s.outsidePayloadTokenHash !== c.outsidePayloadTokenHash)
    return { reason: 'unrelated_syntax_error' };
  if (s.error.kind === 'quote_imbalance') {
    const e = s.error, matched = r.positions.some(p => p.pgCharPosition1Based === e.pgCharPosition1Based
      && p.parserByteOffset0Based === e.parserByteOffset0Based);
    const token = s.tokens.find(t => t.kind === 'UNTERMINATED_LITERAL'
      && t.span[0] === e.parserByteOffset0Based && t.role === 'literal');
    if (s.channel === 'statement' && c.channel === 'statement'
      && r.marker.payload === 'sql-quote' && e.sqlState === '42601' && matched
      && token && s.insertions.some(i => i.tokenIndexes.includes(s.tokens.indexOf(token))))
      return { grade: 'confirmed' as const, reason: 'quote_imbalance' };
    return { reason: 'unrelated_syntax_error' };
  }
  if (s.error.kind !== 'none') return { reason: 'truncated_or_unsupported_input' };
  if (s.channel === 'bind') return s.insertions.length === 0
    && s.tokens.some(t => t.role === 'parameter' && t.kind === 'PARAM'
      && s.ast.some(n => n.kind === 'ParamRef' && contains(n.span, t.span)))
    ? { reason: 'bound_parameter', complete: true } : { reason: 'truncated_or_unsupported_input' };
  if (!s.insertions.length) return { reason: 'truncated_or_unsupported_input' };
  const tokens = s.insertions.flatMap(i => i.tokenIndexes.map(index => s.tokens[index]));
  if (tokens.length && tokens.every(t => t.role === 'comment'))
    return { reason: 'comment_not_executable', complete: true };
  if (newGrammar(probe, control)) return { grade: 'confirmed' as const, reason: 'syntax_promotion' };
  if (!tokens.length || tokens.some(t => !['literal', 'comment'].includes(t.role)))
    return { reason: 'truncated_or_unsupported_input' };
  if (s.insertions.some(i => i.tokenIndexes.some(index => s.tokens[index].role === 'literal'
    && !i.nodeIds.some(id => s.ast.some(n => n.id === id && n.kind === 'StringConst'
      && contains(n.span, s.tokens[index].span)))))) return { reason: 'truncated_or_unsupported_input' };
  return { grade: 'strong' as const, reason: r.marker.payload === 'sql-boolean'
    ? 'escaped_literal_without_promotion' : 'unbound_statement_without_promotion' };
}
function pairReason(data: ReturnType<typeof capture>, group: SqlRequestBinding[]): string | undefined {
  const b = data.binding, [control, probe] = group;
  if (group.length !== 2 || control.attempt.phase !== 'control' || probe.attempt.phase !== 'probe'
    || control.marker.payload !== 'benign' || control.attempt.ordinal >= probe.attempt.ordinal
    || !same(control.marker.param, probe.marker.param) || control.marker.method !== probe.marker.method
    || control.marker.surfaceId !== probe.marker.surfaceId
    || control.attempt.snapshotHash !== probe.attempt.snapshotHash || !ordered(control.end, probe.begin))
    return 'control_missing_or_failed';
  if (!b.complete || !b.drainComplete || group.some(r => !r.complete || !r.drainComplete))
    return 'observer_incomplete';
  for (const r of group) {
    if (!r.utf8Valid || r.truncated) return 'truncated_or_unsupported_input';
    const a = data.attackLog.attempts.find(a => a.ordinal === r.attempt.ordinal);
    const m = data.ledger.rows.find(m => m.requestOrdinal === r.attempt.ordinal);
    if (!a || !m || !same(a, r.attempt) || !same(m, r.marker))
      return r.attempt.phase === 'control' ? 'control_missing_or_failed' : 'event_binding_rejected';
    if (a.outcome !== 'response' || a.httpStatus === null
      || a.phase === 'control' && (a.httpStatus < 200 || a.httpStatus >= 400))
      return 'control_missing_or_failed';
  }
  return undefined;
}
function reach(data: ReturnType<typeof capture>, r: SqlRequestBinding, confirmed: boolean) {
  const rows = data.coverage.filter(c => c.requestOrdinal === r.attempt.ordinal);
  if (rows.length !== 1 || rows[0].accounting !== 'exact' || rows[0].reached === null
    || rows[0].surfaceId !== r.marker.surfaceId || rows[0].snapshotHash !== r.attempt.snapshotHash)
    return 'unknown' as const;
  return rows[0].reached ? confirmed ? 'triggered' as const : 'reached_not_triggered' as const : 'not_reached' as const;
}
function evaluate(data: ReturnType<typeof capture>): SqlOracleResult {
  const result: SqlOracleResult = { verdicts: [], cases: [], gaps: [] };
  const groups = new Map<string, SqlRequestBinding[]>();
  for (const r of data.binding.requests) groups.set(r.marker.controlPairId,
    [...groups.get(r.marker.controlPairId) ?? [], r]);
  for (const [pairId, rows] of [...groups].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    const group = rows.sort((a, b) => a.attempt.ordinal - b.attempt.ordinal), probe = group.at(-1)!;
    const surface = data.binding.surfaces.find(s => s.id === probe.marker.surfaceId
      && s.method === probe.marker.method);
    let reason = pairReason(data, group); if (!surface) reason = 'event_binding_rejected';
    const controlEvent = eventFor(data, group[0]), probeEvent = eventFor(data, probe);
    if (!reason && !controlEvent) reason = 'control_missing_or_failed';
    if (!reason && !probeEvent) reason = data.observations.some(o => o && typeof o === 'object'
      && (o as Observation).requestOrdinal === probe.attempt.ordinal)
      ? 'event_binding_rejected' : 'http_error_is_not_db_evidence';
    const judged = reason ? { reason } : classification(probeEvent!, controlEvent!, probe);
    const state = 'grade' in judged && judged.grade ? 'triggered' : 'complete' in judged && judged.complete
      ? 'not_triggered' : 'unknown';
    result.cases.push({ surfaceId: probe.marker.surfaceId, state, reasons: [judged.reason] });
    if (state === 'unknown') result.gaps.push({ area: 'oracle.sql', code: judged.reason,
      surfaceId: probe.marker.surfaceId });
    if ('grade' in judged && judged.grade && surface) {
      const reached = reach(data, probe, judged.grade === 'confirmed');
      result.verdicts.push({ surface: { id: surface.id, method: surface.method, pathTemplate: surface.pathTemplate },
        vulnClass: 'sql', grade: judged.grade, reach: reached, markers: group.map(r => r.marker.markerHash).sort(),
        evidence: [controlEvent!.evidence, probeEvent!.evidence].map(e =>
          ({ path: e.path, bytes: e.bytes, sha256: e.sha256 })),
        ruleRevision: REVISION, controlPairId: pairId });
      if (reached === 'unknown')
        result.gaps.push({ area: 'coverage', code: 'coverage_unknown', surfaceId: surface.id });
    }
  }
  if (data.observations.some(o => o === null || !data.binding.requests.some(r =>
    r.attempt.ordinal === (o as Observation)?.requestOrdinal)))
    result.gaps.push({ area: 'oracle.sql', code: 'unassigned_observation' });
  return result;
}
/** Pure SQL projection judge. Raw discard, parser execution, cleanup and CLI exit are outside this API. */
export function judgeSql(input: SqlOracleInput): SqlOracleResult {
  try { return evaluate(capture(input)); }
  catch { return { verdicts: [], cases: [], gaps: [{ area: 'oracle.sql', code: 'invalid_input' }] }; }
}
