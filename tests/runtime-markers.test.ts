import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { issueMarkers } from '../src/runtime/markers.js';
import type { MarkerIssueInput, MarkerReservation } from '../src/runtime/markers.js';

const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
function input(): MarkerIssueInput {
  const reservation: MarkerReservation = { surfaceId: 'GET /owned/items', method: 'GET',
    param: { in: 'query', name: 'name', jsonPointer: null, schemaLocator: 'query/name' },
    payload: 'benign', requestOrdinal: 1, controlPairId: 'pair-1' };
  return { reproductionKey: hash('synthetic-logical-chain'), seed: 'nonsecret-contract-seed', remainingBudget: 2,
    surfaces: [{ id: reservation.surfaceId, method: reservation.method, pathTemplate: '/owned/items' }],
    reservations: [reservation, { ...clone(reservation), payload: 'sql-boolean', requestOrdinal: 2 }] };
}
function rejects(value: unknown): void {
  assert.throws(() => issueMarkers(value as MarkerIssueInput), /invalid_/);
}
test('markers have the PLAN format and only hashed rows belong in ledger JSON', () => {
  const issued = issueMarkers(input()), serialized = JSON.stringify(issued.ledger);
  assert.equal(issued.ledger.rows.length, 2);
  for (const row of issued.ledger.rows) {
    const marker = issued.markerForExecutor(row.requestOrdinal);
    assert.match(marker, /^wk[a-z2-7]{12}$/); assert.equal(Buffer.byteLength(marker), 14);
    assert.equal(row.markerHash, hash(marker)); assert.equal(serialized.includes(marker), false);
    assert.equal(JSON.stringify(issued).includes(marker), false);
    assert.deepEqual(Object.keys(row).sort(), ['surfaceId', 'method', 'param', 'payload', 'requestOrdinal',
      'controlPairId', 'markerHash'].sort());
  }
  assert.equal(issued.markerForExecutor(1).slice(0, 6), issued.markerForExecutor(2).slice(0, 6));
  assert.notEqual(issued.markerForExecutor(1), issued.markerForExecutor(2));
  assert.throws(() => issued.markerForExecutor(3), /invalid_marker_reservation/);
});
test('logical input and ordinal, including reordered reservations/keys, deterministically identify markers', () => {
  const original = input(), issued = issueMarkers(original), reordered = clone(original);
  (reordered.reservations as MarkerReservation[]).reverse();
  const row = reordered.reservations[0]; row.param = { schemaLocator: row.param.schemaLocator,
    jsonPointer: row.param.jsonPointer, name: row.param.name, in: row.param.in };
  const again = issueMarkers(reordered);
  assert.equal(JSON.stringify(again.ledger), JSON.stringify(issued.ledger));
  for (const ordinal of [1, 2]) assert.equal(again.markerForExecutor(ordinal), issued.markerForExecutor(ordinal));
  const seed = input(); seed.seed = 'another-nonsecret-seed';
  assert.notEqual(issueMarkers(seed).markerForExecutor(1), issued.markerForExecutor(1));
  const key = input(); key.reproductionKey = hash('different-synthetic-chain');
  assert.notEqual(issueMarkers(key).markerForExecutor(1), issued.markerForExecutor(1));
});
test('GET path and POST nested JSON scalar locations remain explicit, without building a request', () => {
  const path = input(); path.surfaces[0].pathTemplate = '/owned/items/{itemId}';
  for (const r of path.reservations) r.param = { in: 'path', name: 'itemId', jsonPointer: null,
    schemaLocator: 'path/itemId' };
  assert.equal(issueMarkers(path).ledger.rows[0].param.in, 'path');
  const post = input(); post.surfaces[0].method = 'POST';
  for (const r of post.reservations) { r.method = 'POST'; r.param = { in: 'body', name: 'display/name',
    jsonPointer: '/profile/display~1name', schemaLocator: 'json/profile/display~1name' }; }
  const issued = issueMarkers(post);
  assert.equal(issued.ledger.rows[1].param.jsonPointer, '/profile/display~1name');
  assert.equal(Object.hasOwn(issued, 'request'), false);
});
test('root and terminal slash routes retain exact identities and distinct reservation mappings', () => {
  const value = input(); value.remainingBudget = 4;
  value.surfaces = [{ id: 'GET /items', method: 'GET', pathTemplate: '/items' },
    { id: 'GET /items/', method: 'GET', pathTemplate: '/items/' }];
  value.reservations = [false, true].flatMap((trailing, pair) => input().reservations.map(r => ({
    ...clone(r), surfaceId: 'GET /items' + (trailing ? '/' : ''),
    controlPairId: 'pair-' + pair, requestOrdinal: r.requestOrdinal + pair * 2,
  })));
  const before = JSON.stringify(value), issued = issueMarkers(value);
  assert.deepEqual(issued.ledger.rows.map(r => r.surfaceId),
    ['GET /items', 'GET /items', 'GET /items/', 'GET /items/']);
  assert.equal(new Set(issued.ledger.rows.map(r => issued.markerForExecutor(r.requestOrdinal))).size, 4);
  assert.equal(JSON.stringify(value), before);
  const root = input(); root.surfaces[0].pathTemplate = '/';
  assert.equal(issueMarkers(root).ledger.rows.length, 2);
  for (const path of ['/a//', '/a//b', '//host', '/a/.', '/a/..', '/a/%2f', '/a?q=x', '/a#x', '/a\\b']) {
    const invalid = input(); invalid.surfaces[0].pathTemplate = path; rejects(invalid);
  }
});
test('ordinal collisions and incomplete, duplicate or mismatched control/probe pairs reject atomically', () => {
  const mutations: Array<(value: MarkerIssueInput) => void> = [
    i => { i.reservations[1].requestOrdinal = 1; },
    i => { i.reservations[0].requestOrdinal = 3; },
    i => { i.reservations[0].payload = 'sql-quote'; },
    i => { i.reservations[1].payload = 'benign'; },
    i => { i.reservations[1].controlPairId = 'another-pair'; },
    i => { i.reservations[1].param.name = 'other'; },
    i => { i.reservations[1].param.schemaLocator = 'query/other'; },
    i => { i.reservations[1].method = 'POST'; },
    i => { i.reservations[1].surfaceId = 'other'; },
    i => { const rows = i.reservations as MarkerReservation[];
      rows.push(...clone(rows).map(r => ({ ...r, requestOrdinal: r.requestOrdinal + 2 }))); i.remainingBudget = 4; },
  ];
  for (const mutate of mutations) { const value = input(); mutate(value); rejects(value); }
});
test('unsafe strings, unsupported locations and malformed pointers never reserve a marker', () => {
  const mutations: Array<(value: MarkerIssueInput) => void> = [
    i => { i.reproductionKey = 'not-a-digest'; },
    i => { i.seed = 'credential=must-not-be-accepted'; },
    i => { i.seed = 'line\nbreak'; },
    i => { i.seed = '한글'; },
    i => { i.reservations[0].requestOrdinal = 32769; },
    i => { i.reservations[0].requestOrdinal = 1.5; },
    i => { i.reservations[0].param.in = 'header'; },
    i => { i.reservations[0].param.jsonPointer = '/name'; },
    i => { i.reservations[0].param.name = 'name\u0000suffix'; },
    i => { i.reservations[0].param.schemaLocator = 'https://external.example/schema'; },
    i => { Object.assign(i.reservations[0], { markerHash: hash('caller-supplied') }); },
    i => { Object.assign(i.reservations[0].param, { extra: true }); },
    i => { Object.assign(i, { runNonce: 'not-part-of-logical-marker-identity' }); },
    i => { i.surfaces[0].pathTemplate = 'https://external.example/items'; },
    i => { i.surfaces[0].pathTemplate = '//external.example/items'; },
    i => { i.surfaces[0].pathTemplate = '/owned/../items'; },
    i => { i.surfaces[0].pathTemplate = '/owned/%2fitems'; },
    i => { i.surfaces[0].pathTemplate = '/owned/items?token=value'; },
    i => { i.surfaces[0].pathTemplate = '/owned/\u0000items'; },
  ];
  for (const mutate of mutations) { const value = input(); mutate(value); rejects(value); }
  for (const pointer of ['name', '/profile/name~2', '/__proto__/name', '/profile//name', '/profile/other']) {
    const post = input(); post.surfaces[0].method = 'POST';
    for (const row of post.reservations) {
      row.method = 'POST'; row.param.in = 'body'; row.param.jsonPointer = pointer;
    }
    rejects(post);
  }
  const path = input(); for (const row of path.reservations) row.param.in = 'path'; rejects(path);
});
test('getters, proxies, custom prototypes, symbols and sparse arrays execute no caller functions', () => {
  let called = 0;
  const value = input(), accessor = Object.defineProperty(clone(value), 'seed', {
    enumerable: true, get() { called++; throw Error('forbidden'); },
  });
  const proxy = new Proxy(value, { ownKeys() { called++; throw Error('forbidden'); } });
  const rowGetter = input(); Object.defineProperty(rowGetter.reservations[0].param, 'name', {
    enumerable: true, get() { called++; throw Error('forbidden'); },
  });
  const rowProxy = input(); (rowProxy.reservations as MarkerReservation[])[0] = new Proxy(rowProxy.reservations[0], {
    get() { called++; throw Error('forbidden'); }, ownKeys() { called++; throw Error('forbidden'); },
  });
  const inherited = Object.assign(Object.create({ inherited: true }), input());
  const symbol = input(); Object.assign(symbol.reservations[0], { [Symbol('unexpected')]: true });
  const sparse = input(); delete (sparse.reservations as MarkerReservation[])[0];
  const array = input(); Object.setPrototypeOf(array.reservations, Object.create(Array.prototype));
  for (const bad of [accessor, proxy, rowGetter, rowProxy, inherited, symbol, sparse, array]) rejects(bad);
  assert.equal(called, 0);
});
test('2000 reservation limit and the shared remaining budget reject instead of truncating', () => {
  const max = input(), base = max.reservations[0], rows: MarkerReservation[] = [];
  for (let n = 0; n < 2000; n++) rows.push({ ...clone(base), requestOrdinal: n + 1,
    controlPairId: 'pair-' + Math.floor(n / 2), payload: n % 2 ? 'sql-quote' : 'benign' });
  max.reservations = rows; max.remainingBudget = 2000;
  const issued = issueMarkers(max);
  assert.equal(issued.ledger.rows.length, 2000);
  assert.equal(new Set(rows.map(r => issued.markerForExecutor(r.requestOrdinal))).size, 2000);
  assert.equal(new Set(issued.ledger.rows.map(r => r.markerHash)).size, 2000);
  max.remainingBudget = 1999; rejects(max); max.remainingBudget = 2000;
  rows.push({ ...clone(rows[0]), requestOrdinal: 2001, controlPairId: 'overflow' }); rejects(max);
  for (const budget of [0, 1, 2001, -1, 1.5]) { const value = input(); value.remainingBudget = budget; rejects(value); }
  const empty = input(); empty.reservations = []; rejects(empty);
});
test('input mutation cannot change an issued ledger or private marker lookup', () => {
  const value = input(), before = JSON.stringify(value), issued = issueMarkers(value);
  assert.equal(JSON.stringify(value), before); const marker = issued.markerForExecutor(1);
  value.seed = 'changed'; value.reservations[0].param.name = 'changed';
  assert.equal(issued.markerForExecutor(1), marker); assert.equal(issued.ledger.rows[0].param.name, 'name');
  assert.throws(() => { issued.ledger.rows[0].param.name = 'changed'; }, TypeError);
  assert.throws(() => { (issued.ledger.rows as unknown as MarkerReservation[]).reverse(); }, TypeError);
  assert.throws(() => issued.markerForExecutor(0), /invalid_marker_reservation/);
  const high = input(); high.reservations[0].requestOrdinal = 32767; high.reservations[1].requestOrdinal = 32768;
  assert.equal(issueMarkers(high).ledger.rows.length, 2);
});
