import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import casesJson from './fixtures/runtime-m1/sql-cases.json' with { type: 'json' };
import projectionsJson from './fixtures/runtime-m1/sql-projections.json' with { type: 'json' };
import { judgeSql } from '../src/runtime/oracles/sql.js';
import type { SqlOracleBinding, SqlOracleInput, SqlRequestBinding } from '../src/runtime/oracles/sql.js';
import type { AttackAttempt, MarkerRow, Observation, SurfaceRef } from '../src/runtime/types.js';

type Request = { ordinal: number; phase: 'control' | 'probe'; marker: string; raw: string };
type Pair = { surface: SurfaceRef; param: MarkerRow['param']; requests: Request[]; faults: Record<string, unknown> };
type Expected = { confirmed: number; strong: number; unknown: boolean; reason: string };
type Fixture = Pair & { id: string; expected: Expected; faultAlternatives?: Record<string, unknown>[];
  probeAlternatives?: string[]; additionalPair?: Pair; reflectionCheck?: Pair & { expected: Expected } };
type Raw = { statement: string | null; bind: string[]; payload: string; channel: 'bind' | 'statement';
  profile: string; httpStatus: number; payloadKind: MarkerRow['payload']; error: Observation['sql']['error'] | null };
type Profile = Pick<Observation['sql'], 'ast' | 'tokens' | 'insertions' | 'controlContextHash'
  | 'outsidePayloadTokenHash'> & { statementBytes: number };
type MutableInput = Omit<SqlOracleInput, 'binding'> & { binding: SqlOracleBinding };
const fixtures = casesJson as unknown as { cases: Fixture[]; rawTemplates: Record<string, Raw>;
  bindingTemplate: { snapshotHash: string } };
const profiles = projectionsJson.profiles as unknown as Record<string, Profile>;
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const artifact = (name: string) => ({ path: 'synthetic/' + name + '.json', bytes: 1, sha256: hash(name) });
// These hashes identify synthetic test labels only; they are NOT measured parser/WASM identities.
const parser = { version: 'synthetic-r8-manual-pg18', pgMajor: 18,
  lockSha256: hash('synthetic-lock-not-installed'), wasmSha256: hash('synthetic-wasm-not-executed') };
function append(input: MutableInput, fixture: Fixture, pair: Pair) {
  const { binding, attackLog, ledger } = input, surfaces = binding.surfaces as SurfaceRef[];
  if (!surfaces.some(s => s.id === pair.surface.id)) surfaces.push(clone(pair.surface));
  for (const q of pair.requests) {
    const raw = fixtures.rawTemplates[q.raw], replace = (s: string) => s.replaceAll('{marker}', q.marker);
    const statement = raw.statement === null ? null : replace(raw.statement), payload = replace(raw.payload);
    const marker: MarkerRow = { markerHash: hash(q.marker), surfaceId: pair.surface.id, method: pair.surface.method,
      param: clone(pair.param), payload: raw.payloadKind, requestOrdinal: q.ordinal,
      controlPairId: `pair-${fixture.id}-${pair.requests[0].ordinal}-${pair.requests[1].ordinal}` };
    const attempt: AttackAttempt = { ordinal: q.ordinal, surfaceId: marker.surfaceId, markerHash: marker.markerHash,
      payloadHash: hash(payload), requestHash: hash(`${q.ordinal}:${payload}`), phase: q.phase,
      snapshotHash: fixtures.bindingTemplate.snapshotHash, outcome: 'response', httpStatus: raw.httpStatus };
    (attackLog.attempts as AttackAttempt[]).push(attempt); (ledger.rows as MarkerRow[]).push(marker);
    if (statement === null) continue; // Reflection alone creates no SQL judgement assignment.
    const profile = clone(profiles[raw.profile]);
    assert.equal(Buffer.byteLength(statement), profile.statementBytes);
    const at = (offset: number) => ({ ...binding.seedCursor, byteOffset: q.ordinal * 256 + offset });
    const error = clone(raw.error ?? projectionsJson.noError) as Observation['sql']['error'];
    const request: SqlRequestBinding = { attempt: clone(attempt), marker: clone(marker),
      rawStatementSha256: hash(statement),
      rawEventSha256: hash(JSON.stringify({ statement, bind: raw.bind.map(replace), error: raw.error })),
      pgSessionId: 'pg-session-' + fixture.id, pgSessionLine: q.ordinal, sequence: q.ordinal,
      begin: at(0), end: at(255), statementBytes: profile.statementBytes, utf8Valid: true,
      truncated: false, complete: true, drainComplete: true, positions: error.pgCharPosition1Based === null ? []
        : [{ pgCharPosition1Based: error.pgCharPosition1Based, parserByteOffset0Based:
          Buffer.byteLength(statement.slice(0, error.pgCharPosition1Based - 1)) }] };
    (binding.requests as SqlRequestBinding[]).push(request);
    const sql: Observation['sql'] = { channel: raw.channel, dialect: 'postgres', rawStatementSha256: hash(statement),
      rawEventSha256: hash(JSON.stringify({ statement, bind: raw.bind.map(replace), error: raw.error })),
      parser: clone(parser), ast: profile.ast, tokens: profile.tokens,
      insertions: profile.insertions.map(i => ({ ...i, payloadHash: attempt.payloadHash })), error,
      controlContextHash: profile.controlContextHash, outsidePayloadTokenHash: profile.outsidePayloadTokenHash };
    const evidenceBytes = JSON.stringify(sql), evidence = { path: `synthetic/${fixture.id}/${q.ordinal}.json`,
      bytes: Buffer.byteLength(evidenceBytes), sha256: hash(evidenceBytes) };
    (input.observations as Observation[]).push({ id: `${fixture.id}:${q.ordinal}`, runId: binding.runId,
      epoch: binding.epoch, runNonce: binding.runNonce, observerSession: binding.observerSession,
      sequence: q.ordinal, requestOrdinal: q.ordinal, markerHash: marker.markerHash,
      sourceContainerId: binding.sourceContainerId, pgSessionId: request.pgSessionId, pgSessionLine: q.ordinal,
      cursor: at(128), requestWindow: { begin: at(0), end: at(255), closed: true }, sql, evidence });
    (input.coverage as Array<SqlOracleInput['coverage'][number]>).push({ requestOrdinal: q.ordinal,
      surfaceId: marker.surfaceId, snapshotHash: attempt.snapshotHash, accounting: 'exact', reached: true });
  }
}
function applyFaults(input: MutableInput, pair: Pair, faults: Record<string, unknown>) {
  for (const [key, value] of Object.entries(faults)) {
    const q = pair.requests[key.startsWith('control.') ? 0 : 1], ordinal = q.ordinal;
    const a = input.attackLog.attempts.find(a => a.ordinal === ordinal)!;
    const r = input.binding.requests.find(r => r.attempt.ordinal === ordinal)!;
    const o = input.observations.find(o => o.requestOrdinal === ordinal)!;
    const m = input.ledger.rows.find(m => m.requestOrdinal === ordinal)!;
    if (key === 'collection.complete') input.binding.complete = value as boolean;
    else if (key === 'collection.drainComplete') input.binding.drainComplete = value as boolean;
    else if (key === 'collection.reason') input.binding.complete = false;
    else if (key.endsWith('.observations')) (input.observations as Observation[]).splice(
      0, input.observations.length, ...input.observations.filter(o => o.requestOrdinal !== ordinal));
    else if (key.endsWith('.outcome')) a.outcome = value as AttackAttempt['outcome'];
    else if (key.endsWith('.httpStatus')) a.httpStatus = value as number;
    else if (key.endsWith('.issued') || key.endsWith('.markerIssued'))
      (input.ledger.rows as MarkerRow[]).splice(input.ledger.rows.indexOf(m), 1);
    else if (key === 'control.raw') { o.sql.error = { sqlState: '42601', pgCharPosition1Based: 1,
      parserByteOffset0Based: 0, kind: 'other_syntax' }; a.httpStatus = 500; }
    else if (key === 'probe.truncated') r.truncated = true;
    else if (key === 'probe.utf8Valid') r.utf8Valid = false;
    else if (key === 'parser.pgMajor') o.sql.parser.pgMajor = value as number;
    else if (key.endsWith('.error.kind')) o.sql.error.kind = value as Observation['sql']['error']['kind'];
    else if (key === 'probe.surfaceId') a.surfaceId = value as string;
    else if (key === 'probe.param.jsonPointer') m.param.jsonPointer = value as string;
    else if (key.startsWith('probe.cursor.')) Object.assign(o.cursor, { [key.slice(13)]: value });
    else if (key.startsWith('probe.')) Object.assign(o, { [key.slice(6)]: value });
    else if (key === 'coverage.accounting') {
      input.coverage.find(c => c.requestOrdinal === ordinal)!.accounting = value as 'unknown';
    } else if (!key.startsWith('cleanup.')) throw Error('unsupported_fixture_fault:' + key);
  }
}
function materialize(fixture: Fixture, faults = fixture.faults): MutableInput {
  const cursor = { dbLeaseId: 'lease-' + fixture.id, logIdentity: 'log-' + fixture.id, rotation: 0, byteOffset: 0 };
  const input: MutableInput = { attackLog: { plan: artifact('plan'), markers: artifact('markers'), attempts: [] },
    ledger: { reproductionKey: hash('synthetic-input-chain'), seed: 'r8-synthetic-seed', rows: [] },
    observations: [], coverage: [], binding: { runId: 'r8-' + fixture.id, epoch: 'fixture-epoch-1',
      runNonce: 'nonce-' + fixture.id, observerSession: 'observer-' + fixture.id,
      sourceContainerId: 'pg-owned-' + fixture.id, parser: clone(parser), plan: artifact('plan'),
      markers: artifact('markers'), seedCursor: cursor, drainCursor: { ...cursor, byteOffset: 4096 },
      complete: true, drainComplete: true, surfaces: [], requests: [] } };
  append(input, fixture, fixture); applyFaults(input, fixture, faults);
  if (fixture.additionalPair) {
    append(input, fixture, fixture.additionalPair);
    applyFaults(input, fixture.additionalPair, fixture.additionalPair.faults);
  }
  return input;
}
function compare(input: SqlOracleInput, expected: Expected) {
  const result = judgeSql(input);
  assert.equal(result.verdicts.filter(v => v.grade === 'confirmed').length, expected.confirmed);
  assert.equal(result.verdicts.filter(v => v.grade === 'strong').length, expected.strong);
  assert.equal(result.cases.some(c => c.state === 'unknown'), expected.unknown);
  assert.equal(result.gaps.some(g => g.code === 'invalid_input'), false);
  if (['syntax_promotion', 'quote_imbalance', 'unbound_statement_without_promotion',
    'escaped_literal_without_promotion', 'comment_not_executable', 'bound_parameter'].includes(expected.reason))
    assert.ok(result.cases.some(c => c.reasons.includes(expected.reason)));
  return result;
}
for (const f of fixtures.cases.filter(f => !['N11', 'N12'].includes(f.id))) {
  test('independent R8 ' + f.id + ': manual projection, synthetic pin only', () => {
    assert.equal(projectionsJson.parserMetadata, null); compare(materialize(f), f.expected);
    for (const alternative of f.faultAlternatives ?? []) compare(materialize(f, alternative), f.expected);
    for (const raw of f.probeAlternatives ?? []) {
      const alternative = clone(f); alternative.requests[1].raw = raw;
      compare(materialize(alternative), f.expected);
    }
  });
}
const positive = fixtures.cases.find(f => f.id === 'V1')!;
test('N4 reflection is unscheduled, or unknown if a SQL pair is explicitly scheduled', () => {
  const f = fixtures.cases.find(f => f.id === 'N4')!, input = materialize(f), ping = f.reflectionCheck!;
  append(input, f, ping); compare(input, f.expected);
  const sqlPair = clone(input.binding.requests).map((r, i) => ({ ...r,
    attempt: clone(input.attackLog.attempts[i + 2]), marker: clone(input.ledger.rows[i + 2]),
    begin: { ...r.begin, byteOffset: (i + 3) * 256 }, end: { ...r.end, byteOffset: (i + 3) * 256 + 255 },
    sequence: i + 3, pgSessionLine: i + 3 }));
  (input.binding.requests as SqlRequestBinding[]).push(...sqlPair);
  assert.ok(judgeSql(input).cases.some(c => c.surfaceId === ping.surface.id && c.state === 'unknown'));
});
test('deterministic data snapshots reject getters/proxies without invoking them', () => {
  const input = materialize(positive), before = JSON.stringify(input), result = judgeSql(input);
  const reordered = clone(input); (reordered.observations as Observation[]).reverse();
  (reordered.binding.requests as SqlRequestBinding[]).reverse();
  assert.deepEqual(judgeSql(reordered), result); assert.equal(JSON.stringify(input), before);
  let called = 0;
  const accessor = Object.defineProperty(clone(input), 'binding', { get() { called++; throw Error('forbidden'); } });
  const proxy = new Proxy(input, { ownKeys() { called++; throw Error('forbidden'); } });
  for (const bad of [accessor, proxy]) assert.equal(judgeSql(bad).gaps[0].code, 'invalid_input');
  const badEvent = materialize(positive);
  (badEvent.observations as Observation[])[1] = new Proxy(badEvent.observations[1], {
    get() { called++; throw Error('forbidden'); },
  });
  assert.equal(judgeSql(badEvent).verdicts.length, 0); assert.equal(called, 0);
});
test('existing V1 projection cannot confirm with malformed references, binding, context or parser pin', () => {
  const mutations: Array<(i: SqlOracleInput) => void> = [
    i => { i.observations[1].sql.ast[1].parent = 1; },
    i => { i.observations[1].sql.ast[1].span = [90, 1]; },
    i => { i.observations[1].sql.insertions[0].tokenIndexes = [999]; },
    i => { i.observations[1].sql.insertions[0].nodeIds = [999]; },
    i => { i.observations[1].sql.tokens[1].role = 'literal'; },
    i => { i.observations[1].sql.outsidePayloadTokenHash = hash('other-context'); },
    i => { i.observations[1].requestWindow.closed = false; },
    i => { i.observations[1].sql.parser.wasmSha256 = hash('other-wasm'); },
    i => { i.observations[1].id = i.observations[0].id; },
    i => { Object.assign(i.observations[1].sql, { promoted: true }); },
    i => { i.observations[1].sql.rawStatementSha256 = hash('another-statement'); },
    i => { i.attackLog.attempts[1].snapshotHash = hash('other-snapshot'); },
    i => { i.ledger.rows[1].param.name = 'other'; },
    i => { (i.observations as Observation[]).push(clone(i.observations[1])); },
  ];
  for (const mutate of mutations) {
    const input = materialize(positive); mutate(input);
    assert.equal(judgeSql(input).verdicts.filter(v => v.grade === 'confirmed').length, 0);
  }
});
test('quote confirmation needs independently verified position conversion; coverage does not cancel SQL', () => {
  const quote = materialize(fixtures.cases.find(f => f.id === 'V3')!);
  quote.binding.requests[1].positions = [];
  assert.equal(judgeSql(quote).verdicts.filter(v => v.grade === 'confirmed').length, 0);
  const input = materialize(positive); input.coverage[1].accounting = 'unknown';
  const result = compare(input, positive.expected);
  assert.equal(result.verdicts[0].reach, 'unknown'); assert.ok(result.gaps.some(g => g.area === 'coverage'));
  const serialized = JSON.stringify(result);
  for (const q of positive.requests) assert.equal(serialized.includes(q.marker), false);
  assert.equal(serialized.includes('SELECT'), false); assert.equal(serialized.includes('statement'), false);
});
test('N13 retains its valid finding when another pair has a malformed observation', () => {
  const f = fixtures.cases.find(f => f.id === 'N13')!, input = materialize(f);
  const damaged = clone(input.observations[1]); damaged.id = 'damaged-other-pair'; damaged.requestOrdinal = 4;
  (input.observations as Observation[]).push(damaged);
  const result = compare(input, f.expected), reordered = clone(input);
  (reordered.observations as Observation[]).reverse(); (reordered.binding.requests as SqlRequestBinding[]).reverse();
  assert.deepEqual(judgeSql(reordered), result);
});
test('bounded data and output copies cannot grant execution or mutable input authority', () => {
  const large = materialize(positive);
  (large.observations as Observation[]).push(...Array(4096).fill(large.observations[0]));
  assert.equal(judgeSql(large).gaps[0].code, 'invalid_input');
  const input = materialize(positive), result = judgeSql(input), before = JSON.stringify(input);
  result.verdicts[0].surface.id = 'changed'; result.verdicts[0].evidence[0].path = 'changed';
  assert.equal(JSON.stringify(input), before);
  function freeze(value: unknown): void {
    if (value && typeof value === 'object') {
      Object.values(value).forEach(freeze); Object.freeze(value);
    }
  }
  freeze(input); compare(input, positive.expected);
  // N11 raw discard, N12 cleanup, actual parser/target execution and final exit are deliberately NOT tested here.
});
