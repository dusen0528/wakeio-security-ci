import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';
import type { Observation } from '../types.js';

export const PG_PARSER_PROTOCOL_REVISION = 'wakeio.pg-parser/v1';
export const PG_PARSER_LIMITS = Object.freeze({ sqlBytes: 32768, stdinBytes: 65536, stdoutBytes: 1048576 });
export const PG_PARSER_PIN = Object.freeze({ version: '18.2.1', pgMajor: 18,
  lockSha256: 'adc4e4026559ed0e5229acb4cb5354a82437420efdb58056d4a9d73969e37493',
  wasmSha256: '355c489d8b0bf2bac28b48408f656e818852d7000e1e66a67503ad2bc7cc6062' });
type Span = [number, number];
type Sql = Observation['sql'];
export type PgParserReason = 'none' | 'invalid_request' | 'encoding' | 'limit' | 'pin_mismatch'
  | 'asset_mismatch' | 'parser_unavailable' | 'parser_failure' | 'unsupported_shape' | 'invalid_projection';
export interface PgParserAssets { workerSha256: string; manifestSha256: string }
export interface PgParserRequest {
  protocolRevision: string; requestId: string; pin: Sql['parser']; assets: PgParserAssets; sql: string;
  insertions: { payloadHash: string; span: Span }[];
}
export interface PgParserBinding {
  requestId: string; assets: PgParserAssets; statementSha256: string; statementBytes: number;
  insertions: PgParserRequest['insertions'];
}
export interface PgParserProjection {
  ast: Sql['ast']; tokens: Sql['tokens']; tokenHashes: string[]; insertions: Sql['insertions'];
  controlContextHash: string; outsidePayloadTokenHash: string;
}
export interface PgParserReply {
  protocolRevision: string; requestId: string | null; pin: Sql['parser']; assets: PgParserAssets | null;
  status: 'ok' | 'unknown' | 'error'; reason: PgParserReason;
  statementSha256: string | null; statementBytes: number | null; projection: PgParserProjection | null;
}
export class PgParserProtocolError extends Error {
  constructor(readonly reason: PgParserReason) { super(reason); }
}
const sha = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
function fail(reason: PgParserReason = 'unsupported_shape'): never { throw new PgParserProtocolError(reason); }
function check(value: unknown, reason?: PgParserReason): asserts value { if (!value) fail(reason); }
function record(value: unknown): Record<string, unknown> {
  check(value && typeof value === 'object' && !Array.isArray(value)); return value as Record<string, unknown>;
}
function keys(raw: unknown, required: string, optional = ''): Record<string, unknown> {
  const value = record(raw), names = required ? required.split(' ') : [], extras = optional ? optional.split(' ') : [];
  check(names.every(k => Object.hasOwn(value, k))
    && Object.keys(value).every(k => names.includes(k) || extras.includes(k)));
  return value;
}
function integer(raw: unknown, min: number = 0, max: number = PG_PARSER_LIMITS.sqlBytes): asserts raw is number {
  check(Number.isSafeInteger(raw) && (raw as number) >= min && (raw as number) <= max);
}
function hash(raw: unknown): asserts raw is string { check(typeof raw === 'string' && /^[a-f0-9]{64}$/.test(raw)); }
function array(raw: unknown, max = 20000): asserts raw is unknown[] { check(Array.isArray(raw) && raw.length <= max); }
const same = (a: Span, b: Span) => a[0] === b[0] && a[1] === b[1];
const overlap = (a: Span, b: Span) => a[0] < b[1] && b[0] < a[1];
const inside = (a: Span, b: Span) => a[0] <= b[0] && b[1] <= a[1];
function span(raw: unknown, size: number): asserts raw is Span {
  array(raw, 2); check(raw.length === 2); integer(raw[0]); integer(raw[1]); check(raw[0] < raw[1] && raw[1] <= size);
}
function pinned(raw: unknown): void {
  const p = keys(raw, 'version pgMajor lockSha256 wasmSha256');
  check(Object.entries(PG_PARSER_PIN).every(([k, v]) => p[k] === v), 'pin_mismatch');
}
function assets(raw: unknown): PgParserAssets {
  const a = keys(raw, 'workerSha256 manifestSha256'); hash(a.workerSha256); hash(a.manifestSha256);
  return { workerSha256: a.workerSha256, manifestSha256: a.manifestSha256 };
}
function byteCopy(raw: Uint8Array, max: number): Buffer {
  check(!types.isProxy(raw) && types.isUint8Array(raw), 'encoding');
  const proto = Object.getPrototypeOf(Uint8Array.prototype);
  const field = (name: string) => Object.getOwnPropertyDescriptor(proto, name)!.get!.call(raw);
  const size = field('byteLength'), offset = field('byteOffset'), buffer = field('buffer');
  check(size <= max, 'limit'); check(types.isArrayBuffer(buffer), 'encoding');
  return Buffer.from(new Uint8Array(buffer, offset, size));
}
function json(raw: Uint8Array, max: number): unknown {
  const bytes = byteCopy(raw, max); let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { return fail('encoding'); }
  return snapshotJsonData(value, () => fail('invalid_request'), () => fail('limit'));
}
function boundary(bytes: Buffer, offset: number): boolean {
  return offset === bytes.length || (bytes[offset] & 0xc0) !== 0x80;
}
/** Pure closed protocol validation. No package import, WASM, filesystem or execution capability. */
export function validatePgParserRequest(raw: unknown): PgParserRequest {
  const data = snapshotJsonData(raw, () => fail('invalid_request'), () => fail('limit'));
  const r = keys(data, 'protocolRevision requestId pin assets sql insertions');
  check(r.protocolRevision === PG_PARSER_PROTOCOL_REVISION, 'pin_mismatch'); hash(r.requestId); pinned(r.pin);
  const a = assets(r.assets); check(typeof r.sql === 'string' && r.sql.length > 0, 'invalid_request');
  check(!r.sql.includes('\0'), 'encoding');
  for (const ch of r.sql) check(!(ch.codePointAt(0)! >= 0xd800 && ch.codePointAt(0)! <= 0xdfff), 'encoding');
  const bytes = Buffer.from(r.sql); check(bytes.length <= PG_PARSER_LIMITS.sqlBytes, 'limit');
  array(r.insertions, 128); let end = 0;
  const insertions = r.insertions.map(raw => {
    const i = keys(raw, 'payloadHash span'); hash(i.payloadHash); span(i.span, bytes.length);
    check(i.span[0] >= end && boundary(bytes, i.span[0]) && boundary(bytes, i.span[1])); end = i.span[1];
    return { payloadHash: i.payloadHash, span: [...i.span] as Span };
  });
  const result = { protocolRevision: PG_PARSER_PROTOCOL_REVISION, requestId: r.requestId,
    pin: { ...PG_PARSER_PIN }, assets: a, sql: r.sql, insertions };
  check(Buffer.byteLength(JSON.stringify(result)) <= PG_PARSER_LIMITS.stdinBytes, 'limit'); return result;
}
export function decodePgParserRequest(bytes: Uint8Array): PgParserRequest {
  return validatePgParserRequest(json(bytes, PG_PARSER_LIMITS.stdinBytes));
}
export function pgParserBinding(request: PgParserRequest): PgParserBinding {
  const r = validatePgParserRequest(request);
  return { requestId: r.requestId, assets: r.assets, statementSha256: sha(r.sql),
    statementBytes: Buffer.byteLength(r.sql), insertions: r.insertions };
}
const reasons: PgParserReason[] = ['none', 'invalid_request', 'encoding', 'limit', 'pin_mismatch', 'asset_mismatch',
  'parser_unavailable', 'parser_failure', 'unsupported_shape', 'invalid_projection'];
export function pgParserFailure(reason: Exclude<PgParserReason, 'none'>, request?: PgParserRequest): PgParserReply {
  const b = request ? pgParserBinding(request) : undefined;
  return { protocolRevision: PG_PARSER_PROTOCOL_REVISION, requestId: b?.requestId ?? null, pin: { ...PG_PARSER_PIN },
    assets: b?.assets ?? null, statementSha256: b?.statementSha256 ?? null, statementBytes: b?.statementBytes ?? null,
    status: 'unknown', reason, projection: null };
}
function context(tokens: Sql['tokens'], hashes: string[], insertions: PgParserRequest['insertions']): string {
  return sha(JSON.stringify(tokens.flatMap((t, index) => insertions.some(i => overlap(i.span, t.span)) ? []
    : [[t.kind, t.role, hashes[index]]])));
}
function projection(raw: unknown, binding: PgParserBinding): PgParserProjection {
  const p = keys(raw, 'ast tokens tokenHashes insertions controlContextHash outsidePayloadTokenHash');
  array(p.ast); array(p.tokens); array(p.tokenHashes); array(p.insertions, 128);
  const ast = p.ast as Sql['ast'], tokens = p.tokens as Sql['tokens'], hashes = p.tokenHashes as string[];
  const nodes = new Map(ast.map(n => [n.id, n])); check(nodes.size === ast.length && ast.length > 0);
  const kinds = ['SelectStmt', 'ColumnRef', 'StringConst', 'ParamRef', 'A_Expr', 'BoolExpr'];
  for (const n of ast) {
    keys(n, 'id kind parent span'); integer(n.id, 0, 19999); check(kinds.includes(n.kind));
    span(n.span, binding.statementBytes);
    if (n.parent !== null) integer(n.parent, 0, 19999);
    let parent = n.parent; const seen = new Set([n.id]);
    while (parent !== null) {
      const node = nodes.get(parent); check(node && !seen.has(parent) && seen.size < 40 && inside(node.span, n.span));
      seen.add(parent); parent = node.parent;
    }
  }
  check(ast.filter(n => n.parent === null).length === 1 && ast[0].parent === null && ast[0].kind === 'SelectStmt'
    && same(ast[0].span, [0, binding.statementBytes]));
  check(tokens.length === hashes.length); let end = 0;
  for (const [index, t] of tokens.entries()) {
    keys(t, 'kind span role'); span(t.span, binding.statementBytes); hash(hashes[index]); check(t.span[0] >= end);
    end = t.span[1];
    check(/^(IDENT|SCONST|CONST|PARAM|OR|AND|EQUALS|COMMENT|TOKEN_[0-9]{1,5})$/.test(t.kind));
    const role = t.kind === 'IDENT' ? 'identifier' : ['SCONST', 'CONST'].includes(t.kind) ? 'literal'
      : t.kind === 'PARAM' ? 'parameter' : t.kind === 'COMMENT' ? 'comment'
        : t.kind === 'EQUALS' ? 'operator' : 'syntax';
    check(t.role === role);
  }
  check(p.insertions.length === binding.insertions.length);
  for (const [index, rawInsertion] of p.insertions.entries()) {
    const i = keys(rawInsertion, 'payloadHash span tokenIndexes nodeIds'), expected = binding.insertions[index];
    hash(i.payloadHash); span(i.span, binding.statementBytes); check(i.payloadHash === expected.payloadHash
      && same(i.span, expected.span)); array(i.tokenIndexes); array(i.nodeIds);
    const expectedTokens = tokens.flatMap((t, index) => overlap(t.span, expected.span) ? [index] : []);
    const expectedNodes = ast.flatMap(n => n.id !== 0 && overlap(n.span, expected.span) ? [n.id] : []);
    check(JSON.stringify(i.tokenIndexes) === JSON.stringify(expectedTokens)
      && JSON.stringify(i.nodeIds) === JSON.stringify(expectedNodes));
  }
  const normalized = context(tokens, hashes, binding.insertions);
  check(p.controlContextHash === normalized && p.outsidePayloadTokenHash === normalized);
  return { ast, tokens, tokenHashes: hashes, insertions: p.insertions as Sql['insertions'],
    controlContextHash: normalized, outsidePayloadTokenHash: normalized };
}
function expectedBinding(raw: PgParserBinding): PgParserBinding {
  const b = keys(snapshotJsonData(raw), 'requestId assets statementSha256 statementBytes insertions');
  hash(b.requestId); hash(b.statementSha256); integer(b.statementBytes, 1); array(b.insertions, 128);
  const a = assets(b.assets); let end = 0;
  for (const item of b.insertions) {
    const i = keys(item, 'payloadHash span'); hash(i.payloadHash); span(i.span, b.statementBytes);
    check(i.span[0] >= end); end = i.span[1];
  }
  return { requestId: b.requestId, assets: a, statementSha256: b.statementSha256,
    statementBytes: b.statementBytes, insertions: b.insertions as PgParserRequest['insertions'] };
}
export function validatePgParserReply(raw: unknown, expected?: PgParserBinding): PgParserReply {
  const r = keys(snapshotJsonData(raw, () => fail('invalid_projection'), () => fail('limit')),
    'protocolRevision requestId pin assets status reason statementSha256 statementBytes projection');
  check(r.protocolRevision === PG_PARSER_PROTOCOL_REVISION, 'pin_mismatch'); pinned(r.pin);
  check(['ok', 'unknown', 'error'].includes(r.status as string) && reasons.includes(r.reason as PgParserReason));
  if (!expected) {
    check(r.status !== 'ok' && r.reason !== 'none' && r.requestId === null && r.assets === null
      && r.statementSha256 === null && r.statementBytes === null && r.projection === null, 'invalid_projection');
  } else {
    expected = expectedBinding(expected);
    const a = assets(r.assets);
    check(r.requestId === expected.requestId && a.workerSha256 === expected.assets.workerSha256
      && a.manifestSha256 === expected.assets.manifestSha256 && r.statementSha256 === expected.statementSha256
      && r.statementBytes === expected.statementBytes, 'asset_mismatch');
    if (r.status === 'ok') { check(r.reason === 'none'); r.projection = projection(r.projection, expected); }
    else check(r.reason !== 'none' && r.projection === null, 'invalid_projection');
  }
  return r as unknown as PgParserReply;
}
export function encodePgParserReply(raw: unknown, expected?: PgParserBinding): Buffer {
  const data = validatePgParserReply(raw, expected), bytes = Buffer.from(JSON.stringify(data) + '\n');
  check(bytes.length <= PG_PARSER_LIMITS.stdoutBytes, 'limit'); return bytes;
}
export function decodePgParserReply(bytes: Uint8Array, expected?: PgParserBinding): PgParserReply {
  return validatePgParserReply(json(bytes, PG_PARSER_LIMITS.stdoutBytes), expected);
}
interface ScanFact { start: number; end: number; text: string; tokenType: number; tokenName: string;
  keywordKind: number; keywordName: string }
function scanFacts(raw: unknown, sql: string): { version: number; tokens: Sql['tokens']; hashes: string[] } {
  const s = keys(snapshotJsonData(raw), 'version tokens'); integer(s.version, 180000, 189999); array(s.tokens);
  const bytes = Buffer.from(sql), tokens: Sql['tokens'] = [], hashes: string[] = []; let end = 0;
  for (const item of s.tokens) {
    keys(item, 'start end text tokenType tokenName keywordKind keywordName'); const t = item as ScanFact;
    span([t.start, t.end], bytes.length); integer(t.tokenType, 0, 99999); integer(t.keywordKind, 0, 4);
    check(t.start >= end && boundary(bytes, t.start) && boundary(bytes, t.end)); end = t.end;
    check(typeof t.text === 'string' && t.text === bytes.subarray(t.start, t.end).toString('utf8'));
    let kind = 'TOKEN_' + t.tokenType, role: Sql['tokens'][number]['role'] = 'syntax';
    if (['IDENT', 'UIDENT'].includes(t.tokenName)) { kind = 'IDENT'; role = 'identifier'; }
    else if (['SCONST', 'USCONST'].includes(t.tokenName)) { kind = 'SCONST'; role = 'literal'; }
    else if (['ICONST', 'FCONST', 'BCONST', 'XCONST'].includes(t.tokenName)) { kind = 'CONST'; role = 'literal'; }
    else if (t.tokenName === 'PARAM') { kind = 'PARAM'; role = 'parameter'; }
    else if (['SQL_COMMENT', 'C_COMMENT'].includes(t.tokenName)) { kind = 'COMMENT'; role = 'comment'; }
    else if (t.tokenType === 61 && t.text === '=') { kind = 'EQUALS'; role = 'operator'; }
    else if (t.keywordKind === 4 && ['OR', 'AND'].includes(t.text.toUpperCase())) kind = t.text.toUpperCase();
    tokens.push({ kind, role, span: [t.start, t.end] }); hashes.push(sha(bytes.subarray(t.start, t.end)));
  }
  return { version: s.version, tokens, hashes };
}
function strings(raw: unknown): void {
  array(raw, 8); check(raw.length > 0);
  for (const item of raw) {
    const value = keys(keys(item, 'String').String, 'sval'); check(typeof value.sval === 'string');
  }
}
function select(raw: unknown, size: number, version: number): Record<string, unknown> {
  const root = keys(raw, 'version stmts'); integer(root.version, 180000, 189999); array(root.stmts, 1);
  check(root.version === version);
  check(root.stmts.length === 1); const stmt = keys(root.stmts[0], 'stmt', 'stmt_location stmt_len');
  check(stmt.stmt_location === undefined || stmt.stmt_location === 0);
  if (stmt.stmt_len !== undefined) integer(stmt.stmt_len, 0, size);
  const s = keys(keys(stmt.stmt, 'SelectStmt').SelectStmt, 'targetList fromClause whereClause', 'op limitOption');
  check(s.op === undefined || s.op === 'SETOP_NONE');
  check(s.limitOption === undefined || s.limitOption === 'LIMIT_OPTION_DEFAULT');
  array(s.targetList, 32); array(s.fromClause, 1); check(s.targetList.length > 0 && s.fromClause.length === 1);
  for (const target of s.targetList) {
    const t = keys(keys(target, 'ResTarget').ResTarget, 'val', 'location name');
    const column = keys(keys(t.val, 'ColumnRef').ColumnRef, 'fields location'); strings(column.fields);
  }
  const table = keys(keys(s.fromClause[0], 'RangeVar').RangeVar, 'relname',
    'catalogname schemaname inh relpersistence location'); check(typeof table.relname === 'string');
  for (const k of ['catalogname', 'schemaname', 'relpersistence'])
    check(table[k] === undefined || typeof table[k] === 'string');
  return s;
}
function astFacts(raw: unknown, tokens: Sql['tokens'], size: number, version: number): Sql['ast'] {
  const s = select(snapshotJsonData(raw), size, version);
  const ast: Sql['ast'] = [{ id: 0, kind: 'SelectStmt', parent: null, span: [0, size] }];
  const locate = (value: unknown, kind: string) => {
    integer(value); const token = tokens.find(t => t.span[0] === value && t.kind === kind);
    check(token); return token.span;
  };
  const visit = (rawNode: unknown, parent: number, depth: number): number => {
    check(depth <= 40 && ast.length < 20000); const wrapper = record(rawNode), names = Object.keys(wrapper);
    check(names.length === 1); const kind = names[0], node = record(wrapper[kind]), id = ast.length;
    const out = { id, kind, parent, span: [0, size] as Span }; ast.push(out);
    if (kind === 'ColumnRef') {
      keys(node, 'fields location'); strings(node.fields); check((node.fields as unknown[]).length === 1);
      out.span = locate(node.location, 'IDENT');
    }
    else if (kind === 'ParamRef') {
      keys(node, 'number location'); integer(node.number, 1); out.span = locate(node.location, 'PARAM');
    } else if (kind === 'A_Const') {
      keys(node, 'sval location'); check(typeof keys(node.sval, 'sval').sval === 'string');
      out.kind = 'StringConst'; out.span = locate(node.location, 'SCONST');
    } else if (kind === 'A_Expr') {
      keys(node, 'kind name lexpr rexpr location'); check(node.kind === 'AEXPR_OP'); strings(node.name);
      const operator = (node.name as { String: { sval: string } }[]);
      check(operator.length === 1 && operator[0].String.sval === '=');
      const token = locate(node.location, 'EQUALS'), left = ast[visit(node.lexpr, id, depth + 1)].span;
      const right = ast[visit(node.rexpr, id, depth + 1)].span;
      check(left[1] <= token[0] && token[1] <= right[0]); out.span = [left[0], right[1]];
    } else if (kind === 'BoolExpr') {
      keys(node, 'boolop args location'); check(['OR_EXPR', 'AND_EXPR'].includes(node.boolop as string));
      array(node.args, 128); check(node.args.length >= 2);
      const token = locate(node.location, node.boolop === 'OR_EXPR' ? 'OR' : 'AND');
      const children = node.args.map(child => ast[visit(child, id, depth + 1)].span);
      check(children.every((child, i) => i === 0 || children[i - 1][1] <= child[0])
        && children.some(c => c[1] <= token[0]) && children.some(c => c[0] >= token[1]));
      out.span = [children[0][0], children.at(-1)![1]];
    } else fail('unsupported_shape');
    return id;
  };
  visit(s.whereClause, 0, 1); return ast;
}
/** Package facts remain private. This produces roles/ranges/hashes, never a security verdict. */
export function projectPgParserFacts(request: PgParserRequest, parsed: unknown, scanned: unknown): PgParserReply {
  const r = validatePgParserRequest(request), binding = pgParserBinding(r);
  try {
    const { version, tokens, hashes } = scanFacts(scanned, r.sql);
    const ast = astFacts(parsed, tokens, binding.statementBytes, version);
    const insertions = r.insertions.map(i => ({ ...i,
      tokenIndexes: tokens.flatMap((t, index) => overlap(t.span, i.span) ? [index] : []),
      nodeIds: ast.flatMap(n => n.id !== 0 && overlap(n.span, i.span) ? [n.id] : []) }));
    const digest = context(tokens, hashes, r.insertions);
    return validatePgParserReply({ protocolRevision: PG_PARSER_PROTOCOL_REVISION, requestId: r.requestId,
      pin: r.pin, assets: r.assets, status: 'ok', reason: 'none', statementSha256: binding.statementSha256,
      statementBytes: binding.statementBytes, projection: { ast, tokens, tokenHashes: hashes, insertions,
        controlContextHash: digest, outsidePayloadTokenHash: digest } }, binding);
  } catch { return pgParserFailure('unsupported_shape', r); }
}
