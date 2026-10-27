import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { decodePgParserReply, decodePgParserRequest, encodePgParserReply, pgParserBinding, pgParserFailure,
  projectPgParserFacts, validatePgParserRequest, PG_PARSER_LIMITS, PG_PARSER_PIN, PG_PARSER_PROTOCOL_REVISION }
  from '../src/runtime/observers/pg-parser-helper.js';
import type { PgParserReply, PgParserRequest } from '../src/runtime/observers/pg-parser-helper.js';
import { consumePgLogStatement, discardPgLogStatement, parsePgJsonLogRecord, PG_LOG_LIMITS }
  from '../src/runtime/observers/pg-log.js';
import type { PgLogIssuedMarker, PgLogPrerequisites, PgLogStatementHandle }
  from '../src/runtime/observers/pg-log.js';
import r8SqlCases from './fixtures/runtime-m1/sql-cases.json' with { type: 'json' };

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

const logSettings: PgLogPrerequisites = { pgMajor: 18, serverEncoding: 'UTF8', lcMessages: 'C',
  logErrorVerbosity: 'verbose', logStatement: 'all', logMinErrorStatement: 'error', logParameterMaxLength: -1 };
const logMarker = r8SqlCases.cases[0].requests[0].marker;
const issued = () => [{ marker: logMarker, markerHash: hash(logMarker) }];
const logSql = (name: keyof typeof r8SqlCases.rawTemplates) =>
  r8SqlCases.rawTemplates[name].statement!.replaceAll('{marker}', logMarker);
// Inline envelope data is synthetic, not a captured PG log, parser output or security ground truth.
function logEnvelope(sql = logSql('literal')): Record<string, unknown> {
  return { timestamp: '2026-01-01 00:00:00.000 UTC', session_id: '6789abcd.1234', line_num: 1,
    error_severity: 'LOG', state_code: '00000', message: 'statement: ' + sql, file_name: 'postgres.c',
    func_name: 'exec_simple_query', file_line_num: 1003, backend_type: 'client backend', user: 'private_user',
    dbname: 'private_db', remote_host: 'private_host', application_name: 'private_app' };
}
const logBytes = (row: Record<string, unknown>) => Buffer.from(JSON.stringify(row) + '\n');
const parseLog = (row: Record<string, unknown>, lookup = issued()) =>
  parsePgJsonLogRecord(logBytes(row), lookup, logSettings);
function extendedLog(detail: string, sql = logSql('bound-control')) {
  return { ...logEnvelope(sql), func_name: 'exec_execute_message', message: 'execute S_1: ' + sql, detail };
}
test('jsonlog normalization separates public digests from one-use private parser input', () => {
  const row = logEnvelope(), raw = logBytes(row), original = Buffer.from(raw), lookup = issued();
  const result = parsePgJsonLogRecord(raw, lookup, logSettings); assert.equal(result.status, 'parsed');
  if (result.status !== 'parsed') return;
  assert.equal(result.metadata.channel, 'statement'); assert.equal(result.metadata.emitter, 'simple-query');
  assert.equal(result.metadata.markerHash, hash(logMarker)); assert.equal(result.metadata.pgSessionLine, 1);
  assert.equal(result.metadata.rawEventSha256, hash(raw.toString()));
  assert.equal(result.metadata.rawStatementSha256, hash(logSql('literal')));
  assert.deepEqual(raw, original); raw.fill(0); lookup[0].marker = 'caller-mutation';
  const serialized = JSON.stringify({ ...result, spreadHandle: { ...result.statement } });
  for (const secret of [logMarker, logSql('literal'), 'private_user', 'private_db', 'private_host', 'private_app',
    'tokenHashes', 'message', 'detail']) assert.equal(serialized.includes(secret), false);
  let calls = 0;
  assert.equal(consumePgLogStatement(result.statement, sql => { calls++; assert.equal(sql, logSql('literal')); }),
    'consumed');
  assert.equal(consumePgLogStatement(result.statement, () => { calls++; }), 'unavailable');
  assert.equal(calls, 1); assert.ok(Object.isFrozen(result.metadata)); assert.ok(Object.isFrozen(result.statement));
});
test('extended Execute Bind detail stays a value channel and never becomes parser SQL', () => {
  for (const name of ['bound-control', 'bound-boolean', 'bound-quote'] as const) {
    const value = r8SqlCases.rawTemplates[name].bind[0].replaceAll('{marker}', logMarker);
    const detail = "Parameters: $1 = '" + value.replaceAll("'", "''") + "'";
    const row = extendedLog(detail), before = JSON.stringify(row), result = parseLog(row);
    assert.equal(result.status, 'parsed'); if (result.status !== 'parsed') continue;
    assert.equal(result.metadata.channel, 'bind'); assert.equal(result.metadata.emitter, 'extended-execute');
    assert.equal(result.metadata.rawStatementSha256, hash(logSql('bound-control')));
    assert.equal(JSON.stringify(result).includes(value), false);
    assert.equal(consumePgLogStatement(result.statement, sql => {
      assert.equal(sql, logSql('bound-control')); assert.equal(sql.includes(logMarker), false);
    }), 'consumed'); assert.equal(JSON.stringify(row), before);
  }
  const row = extendedLog("Parameters: $1 = NULL, $2 = '" + logMarker + "'");
  const result = parseLog(row); assert.equal(result.status, 'parsed');
  if (result.status === 'parsed') discardPgLogStatement(result.statement);
});
test('valid non-marker events are ignored without even an event or statement digest', () => {
  const row = logEnvelope(logSql('canary'));
  for (const input of [row, { ...row, application_name: logMarker },
    { ...row, file_name: 'pl_exec.c', func_name: 'exec_stmt_raise' }])
    assert.deepEqual(parseLog(input), { status: 'ignored' });
  assert.deepEqual(parseLog(logEnvelope(), []), { status: 'ignored' });
});
test('message lookalikes, missing source metadata and unsupported origins cannot produce parsed records', () => {
  const changes: Array<(r: Record<string, unknown>) => void> = [
    r => { delete r.file_name; }, r => { delete r.func_name; }, r => { delete r.file_line_num; },
    r => { r.file_name = 'pl_exec.c'; r.func_name = 'exec_stmt_raise'; },
    r => { r.file_name = 'extension.c'; }, r => { r.file_name = '../postgres.c'; },
    r => { r.func_name = 'exec_parse_message'; }, r => { r.backend_type = 'parallel worker'; },
    r => { r.func_name = 'caller-forged'; }, r => { r.file_line_num = '1003'; },
    r => { r.message = 'duration: 0 ms  statement: ' + logSql('literal'); },
    r => { delete r.file_name; r.source_file = 'postgres.c'; r.funcname = 'exec_simple_query'; },
  ];
  for (const change of changes) { const row = logEnvelope(); change(row);
    const result = parseLog(row); assert.equal(result.status, 'unknown');
    assert.equal(JSON.stringify(result).includes(logMarker), false); }
  const row = extendedLog("Parameters: $1 = '" + logMarker + "'");
  row.message = 'execute fetch from S_1: ' + logSql('bound-control');
  assert.equal(parseLog(row).status, 'unknown');
});
test('errors and PG character locations remain unsupported rather than suggesting syntax promotion', () => {
  for (const position of [1, 40, 999999, null, '40']) {
    const row = { ...logEnvelope(), error_severity: 'ERROR', state_code: '42601',
      message: 'private_error_excerpt', statement: logSql('quote'), cursor_position: position,
      file_name: 'scan.l', func_name: 'scanner_yyerror', internal_query: 'private_internal' };
    const result = parseLog(row); assert.equal(result.status, 'unknown');
    assert.equal(JSON.stringify(result).includes('private'), false);
    assert.equal(Object.hasOwn(result, 'metadata'), false);
  }
});
test('byte framing, UTF8, escaped NUL, surrogates and bounded shapes fail closed without raw output', () => {
  const valid = logBytes(logEnvelope()), huge = logEnvelope(logMarker + 'x'.repeat(PG_LOG_LIMITS.sqlBytes));
  const deep: Record<string, unknown> = logEnvelope(); let child = deep;
  for (let n = 0; n < 42; n++) { const next = {}; child.extra = next; child = next; }
  const malformed = [valid.subarray(0, -1), Buffer.concat([valid, valid]), Buffer.from([0xff, 10]),
    Buffer.from('{"message":"\0"}\n'), logBytes({ ...logEnvelope(), message: '\ud800' }),
    logBytes({ ...logEnvelope(), extra: '\0' }), logBytes(deep),
    logBytes({ ...logEnvelope(), extra: Array(21000).fill(0) }), logBytes(huge),
    Buffer.alloc(PG_LOG_LIMITS.recordBytes + 1), logBytes({ ...logEnvelope(), line_num: 0 }),
    logBytes({ ...logEnvelope(), session_id: 'private/session' }),
    logBytes({ ...logEnvelope(), state_code: 'bad' })];
  for (const raw of malformed) {
    const result = parsePgJsonLogRecord(raw, issued(), logSettings);
    assert.equal(result.status, 'unknown'); assert.equal(JSON.stringify(result).includes(logMarker), false);
  }
});
test('snapshots and intrinsic byte reads reject Proxy/getter/shared memory without calling supplied code', () => {
  let calls = 0; const trap = () => { calls++; throw Error('private_getter'); };
  const raw = logBytes(logEnvelope());
  const proxy = new Proxy(raw, { get: trap, ownKeys: trap });
  const shared = new Uint8Array(new SharedArrayBuffer(raw.length)); shared.set(raw);
  for (const input of [proxy, shared])
    assert.equal(parsePgJsonLogRecord(input, issued(), logSettings).status, 'unknown');
  const settings = Object.defineProperty(clone(logSettings), 'lcMessages', { enumerable: true, get: trap });
  const lookup = Object.defineProperty(issued()[0], 'marker', { enumerable: true, get: trap });
  assert.equal(parsePgJsonLogRecord(raw, [lookup], logSettings).status, 'unknown');
  assert.equal(parsePgJsonLogRecord(raw, issued(), settings).status, 'unknown');
  assert.equal(parsePgJsonLogRecord(raw, new Proxy(issued(), { ownKeys: trap }), logSettings).status, 'unknown');
  Object.defineProperty(raw, 'byteLength', { get: trap }); Object.defineProperty(raw, 'buffer', { get: trap });
  Object.defineProperty(raw, 'toJSON', { value: trap });
  const result = parsePgJsonLogRecord(raw, issued(), logSettings); assert.equal(result.status, 'parsed');
  if (result.status === 'parsed') discardPgLogStatement(result.statement);
  assert.equal(calls, 0);
});
test('issued lookup binding, duplicates and mixed statement/Bind markers fail without inventing requests', () => {
  const lookups: PgLogIssuedMarker[][] = [[...issued(), ...issued()],
    [{ marker: logMarker, markerHash: hash('wrong') }], [{ marker: 'short', markerHash: hash('short') }],
    Array(PG_LOG_LIMITS.markers + 1).fill(issued()[0])];
  for (const lookup of lookups) assert.equal(parseLog(logEnvelope(), lookup).status, 'unknown');
  const second = r8SqlCases.cases[0].requests[1].marker;
  const lookup = [...issued(), { marker: second, markerHash: hash(second) }];
  assert.equal(parseLog(logEnvelope(logSql('literal') + second), lookup).status, 'unknown');
  assert.equal(parseLog(extendedLog("Parameters: $1 = '" + logMarker + "'", logSql('literal'))).status, 'unknown');
  const result = parseLog(logEnvelope(logSql('promotion'))); assert.equal(result.status, 'parsed');
  if (result.status === 'parsed') discardPgLogStatement(result.statement); // Format only; no grade is asserted.
});
test('Bind envelope parsing rejects truncation, unbalanced values, gaps and localized variants', () => {
  const details = ["parameters: $1 = '" + logMarker + "'", "Parameters: $1 = '" + logMarker,
    "Parameters: $1 = '" + logMarker + "...'", "Parameters: $2 = '" + logMarker + "'",
    "Parameters: $1 = '" + logMarker + "', ", "Parameters: $1 = '" + logMarker + "' garbage",
    "Parameters: $1 = '" + logMarker + "', $1 = NULL",
    'Parameters: ' + Array.from({ length: 129 }, (_, n) => '$' + (n + 1) + " = '" + logMarker + "'").join(', ')];
  for (const detail of details) assert.equal(parseLog(extendedLog(detail)).status, 'unknown');
  for (const change of [{ lcMessages: 'ko_KR' }, { logErrorVerbosity: 'default' }, { logParameterMaxLength: 10 },
    { pgMajor: 17 }, { trusted: true }]) {
    assert.equal(parsePgJsonLogRecord(logBytes(logEnvelope()), issued(),
      { ...logSettings, ...change } as PgLogPrerequisites).status, 'unknown');
  }
});
test('parser-input handles can be discarded and failed sinks expose only a closed consumption status', () => {
  const take = () => { const result = parseLog(logEnvelope()); assert.equal(result.status, 'parsed');
    if (result.status !== 'parsed') throw Error('test_format_failed'); return result.statement; };
  let calls = 0; const trap = () => { calls++; throw Error(logSql('literal')); };
  const discarded = take(); discardPgLogStatement(discarded);
  assert.equal(consumePgLogStatement(discarded, trap), 'unavailable');
  assert.equal(consumePgLogStatement(take(), trap), 'parser_failed'); assert.equal(calls, 1);
  assert.equal(consumePgLogStatement(take(), new Proxy(trap, { apply: trap })), 'parser_failed');
  assert.equal(consumePgLogStatement(take(), async () => { calls++; }), 'parser_failed');
  const forged = new Proxy({}, { get: trap }) as PgLogStatementHandle;
  assert.equal(consumePgLogStatement(forged, trap), 'unavailable'); discardPgLogStatement(forged);
  assert.equal(calls, 1);
});
