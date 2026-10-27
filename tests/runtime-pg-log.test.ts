import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { decodePgParserReply, decodePgParserRequest, encodePgParserReply, pgParserBinding, pgParserFailure,
  projectPgParserFacts, validatePgParserRequest, PG_PARSER_LIMITS, PG_PARSER_PIN, PG_PARSER_PROTOCOL_REVISION }
  from '../src/runtime/observers/pg-parser-helper.js';
import type { PgParserReply, PgParserRequest } from '../src/runtime/observers/pg-parser-helper.js';

const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
// Synthetic package-shape contract data only. No parser/WASM/PG was run and no security verdict is asserted.
function fixture() {
  const sql = "SELECT label FROM owned WHERE label = 'private_literal'";
  const target = sql.indexOf('label'), column = sql.lastIndexOf('label'), operator = sql.indexOf('=');
  const literal = sql.indexOf("'"), end = Buffer.byteLength(sql);
  const columnRef = (location: number) => ({ ColumnRef: { fields: [{ String: { sval: 'label' } }], location } });
  const parsed = { version: 180004, stmts: [{ stmt: { SelectStmt: {
    targetList: [{ ResTarget: { val: columnRef(target), location: target } }],
    fromClause: [{ RangeVar: { relname: 'owned', inh: true, relpersistence: 'p', location: sql.indexOf('owned') } }],
    whereClause: { A_Expr: { kind: 'AEXPR_OP', name: [{ String: { sval: '=' } }], lexpr: columnRef(column),
      rexpr: { A_Const: { sval: { sval: 'private_literal' }, location: literal } }, location: operator } },
    op: 'SETOP_NONE', limitOption: 'LIMIT_OPTION_DEFAULT',
  } } }] };
  const fact = (start: number, end: number, tokenType: number, tokenName = 'UNKNOWN', keywordKind = 0) => ({
    start, end, text: sql.slice(start, end), tokenType, tokenName, keywordKind, keywordName: 'synthetic-keyword',
  });
  const scanned = { version: 180004, tokens: [fact(0, 6, 600, 'UNKNOWN', 4), fact(target, target + 5, 258, 'IDENT'),
    fact(13, 17, 601, 'UNKNOWN', 4), fact(18, 23, 258, 'IDENT'), fact(24, 29, 602, 'UNKNOWN', 4),
    fact(column, column + 5, 258, 'IDENT'), fact(operator, operator + 1, 61, 'ASCII_61'),
    fact(literal, end, 261, 'SCONST')] };
  const request: PgParserRequest = { protocolRevision: PG_PARSER_PROTOCOL_REVISION, requestId: hash('synthetic-row'),
    pin: { ...PG_PARSER_PIN }, assets: { workerSha256: hash('synthetic-worker-not-built'),
      manifestSha256: hash('synthetic-manifest-not-built') }, sql,
    insertions: [{ payloadHash: hash('synthetic-payload'), span: [literal + 1, end - 1] }] };
  return { request, parsed, scanned };
}
test('closed request framing binds explicit revision, deployment digests, statement and byte spans', () => {
  const { request } = fixture(), copy = decodePgParserRequest(bytes(request)), binding = pgParserBinding(copy);
  assert.deepEqual(copy, request); assert.equal(binding.statementSha256, hash(request.sql));
  assert.equal(binding.statementBytes, Buffer.byteLength(request.sql));
  request.sql = 'caller-mutation'; assert.notEqual(copy.sql, request.sql);
  const newline = Buffer.concat([bytes(copy), Buffer.from('\n')]);
  assert.deepEqual(decodePgParserRequest(newline), copy);
});
test('bad UTF8, NUL, surrogate, stdin/SQL sizes, nesting and unknown flags fail before any parser', () => {
  const mutations: Array<(r: PgParserRequest) => void> = [
    r => { r.protocolRevision = 'unreviewed/v2'; }, r => { r.pin.pgMajor = 17; },
    r => { r.pin.lockSha256 = hash('other-lock'); }, r => { r.pin.wasmSha256 = hash('other-wasm'); },
    r => { r.sql = 'nul\0value'; }, r => { r.sql = '\ud800'; },
    r => { r.sql = 'x'.repeat(PG_PARSER_LIMITS.sqlBytes + 1); },
    r => { Object.assign(r, { promoted: true }); }, r => { Object.assign(r.insertions[0], { raw: 'private' }); },
    r => { r.insertions[0].span = [20, 10]; }, r => { r.insertions[0].payloadHash = 'not-a-hash'; },
    r => { r.insertions.push(clone(r.insertions[0])); },
  ];
  for (const mutate of mutations) { const { request } = fixture(); mutate(request);
    assert.throws(() => decodePgParserRequest(bytes(request))); }
  for (const raw of [Buffer.from([0xff]), Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
    Buffer.alloc(PG_PARSER_LIMITS.stdinBytes + 1), Buffer.from('{}{}'),
    Buffer.from('['.repeat(42) + '0' + ']'.repeat(42))]) assert.throws(() => decodePgParserRequest(raw));
});
test('request snapshots reject getters/proxies and non-data bytes without invoking caller functions', () => {
  let calls = 0; const { request } = fixture();
  const accessor = Object.defineProperty(clone(request), 'sql', {
    enumerable: true, get() { calls++; throw Error('forbidden'); },
  });
  const proxy = new Proxy(request, { ownKeys() { calls++; throw Error('forbidden'); } });
  for (const raw of [accessor, proxy]) assert.throws(() => validatePgParserRequest(raw));
  const input = new Proxy(bytes(request), { get() { calls++; throw Error('forbidden'); } });
  assert.throws(() => decodePgParserRequest(input)); assert.equal(calls, 0);
});
test('projection emits only closed kinds, roles, byte ranges and hashes from package-shaped data', () => {
  const f = fixture(), original = JSON.stringify(f), reply = projectPgParserFacts(f.request, f.parsed, f.scanned);
  assert.equal(reply.status, 'ok'); assert.equal(reply.reason, 'none');
  const encoded = encodePgParserReply(reply, pgParserBinding(f.request));
  const roundTrip = decodePgParserReply(encoded, pgParserBinding(f.request));
  assert.equal(roundTrip.projection!.ast.at(-1)!.kind, 'StringConst');
  assert.ok(roundTrip.projection!.tokens.every(t => !Object.hasOwn(t, 'text')));
  for (const raw of ['private_literal', 'owned', f.request.sql, 'stack', 'sval', 'tokenName'])
    assert.equal(encoded.toString().includes(raw), false);
  assert.equal(JSON.stringify(f), original); assert.throws(() => decodePgParserReply(encoded));
});
test('damaged projection metadata, roles, order, references or binding cannot pass the host validator', () => {
  const f = fixture(), valid = projectPgParserFacts(f.request, f.parsed, f.scanned);
  const binding = pgParserBinding(f.request);
  const mutations: Array<(r: PgParserReply) => void> = [
    r => { r.protocolRevision = 'wrong'; }, r => { r.statementSha256 = hash('other-statement'); },
    r => { r.assets!.workerSha256 = hash('other-worker'); }, r => { r.requestId = hash('other-row'); },
    r => { Object.assign(r, { rawSql: f.request.sql }); },
    r => { Object.assign(r.projection!.tokens[0], { text: f.request.sql }); },
    r => { r.projection!.tokens.reverse(); }, r => { r.projection!.ast[1].parent = 1; },
    r => { r.projection!.tokens[0].role = 'literal'; },
    r => { r.projection!.insertions[0].nodeIds = []; },
    r => { r.projection!.controlContextHash = hash('other-context'); },
    r => { r.reason = 'private-error-excerpt' as PgParserReply['reason']; },
  ];
  for (const mutate of mutations) { const reply = clone(valid); mutate(reply);
    assert.throws(() => encodePgParserReply(reply, binding)); }
  let calls = 0;
  const expected = new Proxy(binding, { get() { calls++; throw Error('forbidden'); } });
  assert.throws(() => encodePgParserReply(valid, expected)); assert.equal(calls, 0);
  assert.throws(() => decodePgParserReply(Buffer.alloc(PG_PARSER_LIMITS.stdoutBytes + 1), binding));
});
test('unsupported ASTs, unproven locations and damaged scanner facts become unknown without diagnostics', () => {
  const mutations: Array<(f: ReturnType<typeof fixture>) => void> = [
    f => { f.scanned.tokens.reverse(); }, f => { f.scanned.tokens[0].text = 'private_bad_scan'; },
    f => { f.scanned.version = 170000; },
    f => { f.scanned.version = 180005; },
    f => { f.parsed.stmts[0].stmt.SelectStmt.whereClause.A_Expr.location = 9999; },
    f => { Object.assign(f.parsed.stmts[0].stmt.SelectStmt, { withClause: { private: 'canary' } }); },
    f => { Object.assign(f.parsed.stmts[0].stmt.SelectStmt.whereClause, { FuncCall: { private: 'canary' } }); },
  ];
  for (const mutate of mutations) {
    const f = fixture(); mutate(f); const reply = projectPgParserFacts(f.request, f.parsed, f.scanned);
    assert.equal(reply.status, 'unknown'); assert.equal(reply.projection, null);
    assert.equal(JSON.stringify(reply).includes('private'), false);
  }
});
test('Unicode byte boundaries are checked without assuming PG character offsets equal JS indexes', () => {
  const { request } = fixture(); request.sql = '한글';
  request.insertions = [{ payloadHash: hash('synthetic'), span: [1, 3] }];
  assert.throws(() => validatePgParserRequest(request)); request.insertions[0].span = [0, 3];
  assert.equal(pgParserBinding(validatePgParserRequest(request)).statementBytes, 6);
});
test('failure replies expose only closed reasons and carry no parser exception or location claim', () => {
  const { request } = fixture();
  for (const reason of ['parser_failure', 'parser_unavailable', 'asset_mismatch', 'unsupported_shape'] as const) {
    const failure = pgParserFailure(reason, request), encoded = encodePgParserReply(failure, pgParserBinding(request));
    assert.equal(decodePgParserReply(encoded, pgParserBinding(request)).status, 'unknown');
    assert.equal(encoded.includes(Buffer.from(request.sql)), false); assert.equal(failure.projection, null);
  }
  const anonymous = pgParserFailure('invalid_request');
  assert.equal(decodePgParserReply(encodePgParserReply(anonymous)).requestId, null);
  // Actual CJS/WASM initialization, trap/reinitialization, 1s/256MiB/network and owned DB logs remain R3/R9 work.
});
