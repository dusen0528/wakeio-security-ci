import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { issueMarkers } from '../src/runtime/markers.js';
import type { MarkerIssueInput, MarkerReservation } from '../src/runtime/markers.js';
import { runNativeSql } from '../src/runtime/attacks/native-sql.js';
import type { NativeSqlHooks, NativeSqlPlan }
  from '../src/runtime/attacks/native-sql.js';
import type { RuntimeParameter, RuntimeRequestPort, RuntimeResponse, RuntimeSurface } from '../src/runtime/types.js';

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

// Trusted capabilities below are contract fakes only. No HTTP/PG/target execution or security verdict is asserted.
function execution(location: 'query' | 'path' | 'body' = 'query', probe: 'sql-boolean' | 'sql-quote' = 'sql-boolean',
  pointer = '/name', name = 'name') {
  const value = input(), row = value.reservations[0]; value.reservations[1].payload = probe;
  const method = location === 'body' ? 'POST' : 'GET', path = location === 'path' ? '/owned/{name}' : '/owned/items';
  value.surfaces = [{ id: 'surface-contract', method, pathTemplate: path }];
  for (const r of value.reservations) { r.surfaceId = 'surface-contract'; r.method = method;
    r.param = { in: location, name, jsonPointer: location === 'body' ? pointer : null,
      schemaLocator: location === 'body' ? 'json' + pointer : location + '/' + name }; }
  const param: RuntimeParameter = { ...row.param, in: location, required: true, type: 'string',
    mediaType: location === 'body' ? 'application/json' : null,
    serialization: location === 'body' ? { style: null, explode: null, allowReserved: null }
      : { style: location === 'path' ? 'simple' : 'form', explode: location !== 'path', allowReserved: false } };
  const surface: RuntimeSurface = { ...value.surfaces[0], params: [param], provenance: [],
    readiness: 'ready', reasons: [] };
  const plan: NativeSqlPlan = { taskId: 't-native-contract', snapshotHash: hash('snapshot-contract'),
    surfaces: [surface] };
  const markers = issueMarkers(value), controller = new AbortController(), events: string[] = [];
  const requests: Parameters<RuntimeRequestPort['request']>[0][] = [], responses: RuntimeResponse[] = [];
  let next = 40;
  const hooks: NativeSqlHooks = {
    async restore(binding) { assert.equal(this, hooks);
      events.push('restore-' + binding.logicalOrdinal); return { ...binding }; },
    async begin(binding) { assert.equal(this, hooks); events.push('begin-' + binding.logicalOrdinal);
      return { ...binding, admissionOrdinal: ++next, opened: true }; },
    async complete(binding) { assert.equal(this, hooks); events.push('complete-' + binding.logicalOrdinal);
      return { ...binding, closed: true, drained: true, coverageComplete: true }; },
  };
  const port: RuntimeRequestPort = { transport: 'stdio-relay', leaseId: 'trusted-lease',
    origin: 'http://owned.internal:8080',
    maxRequests: 100, deadlineAt: 1000, async request(request) { assert.equal(this, port);
      events.push('send-' + next); requests.push(request);
      const bodyBytes = Buffer.from('private-response-canary'), response: RuntimeResponse = { ordinal: next,
        outcome: 'response', sent: 'confirmed', status: 200, bodyBytes, rawBodySha256: hash(bodyBytes.toString()),
        truncated: false }; responses.push(response); return response; } };
  const options = { signal: controller.signal, deadlineAt: 2000, maxResponseBytes: 1024 };
  const run = () => runNativeSql(plan, markers, port, hooks, options);
  return { value, plan, markers, port, hooks, options, controller, events, requests, responses, run };
}
test('native GET and POST use issued pairs, per-request restore/drain and separate admission ordinals', async () => {
  for (const location of ['query', 'body'] as const) {
    const f = execution(location), original = JSON.stringify(f.plan), result = await f.run();
    assert.equal(result.status, 'completed'); assert.deepEqual(result.gaps, []);
    assert.deepEqual(f.events, ['restore-1', 'begin-1', 'send-41', 'complete-1',
      'restore-2', 'begin-2', 'send-42', 'complete-2']);
    assert.deepEqual(result.attempts.map(a => [a.ordinal, a.phase, a.snapshotHash, a.outcome]),
      [[1, 'control', f.plan.snapshotHash, 'response'], [2, 'probe', f.plan.snapshotHash, 'response']]);
    assert.deepEqual(result.deliveries.map(d => [d.logicalOrdinal, d.admissionOrdinal, d.sent]),
      [[1, 41, 'confirmed'], [2, 42, 'confirmed']]);
    for (const [index, request] of f.requests.entries()) {
      assert.equal(request.deadlineAt, 1000); assert.equal(request.signal, f.controller.signal);
      const value = location === 'body' ? (request.body!.data as Record<string, string>).name : request.query[0][1];
      assert.equal(hash(value), result.attempts[index].payloadHash);
      assert.equal(request.body === null, location === 'query');
      if (location === 'body') assert.deepEqual(Object.keys(request.body!.data as object), ['name']);
      assert.equal(result.attempts[index].markerHash, f.markers.ledger.rows[index].markerHash);
      assert.equal(JSON.stringify(result).includes(f.markers.markerForExecutor(index + 1)), false);
    }
    assert.equal(JSON.stringify(result).includes('private-response-canary'), false);
    assert.equal(JSON.stringify(f.plan), original);
    assert.equal(Buffer.from(f.responses[0].bodyBytes).toString(), 'private-response-canary');
  }
});
test('path payload is one strict percent-encoded segment; quote policy also applies to JSON leaves', async () => {
  const path = execution('path', 'sql-quote'), result = await path.run(); assert.equal(result.status, 'completed');
  assert.equal(path.requests[1].path, '/owned/' + path.markers.markerForExecutor(2) + '%27');
  assert.deepEqual(path.requests[1].query, []); assert.equal(path.requests[1].body, null);
  const post = execution('body', 'sql-quote', '/profile/name');
  assert.equal((await post.run()).status, 'unknown'); assert.equal(post.requests.length, 0);
  const quote = execution('body', 'sql-quote'); assert.equal((await quote.run()).status, 'completed');
  assert.equal((quote.requests[1].body!.data as Record<string, string>).name,
    quote.markers.markerForExecutor(2) + "'");
});
test('pre-abort sends nothing and snapshot/window binding failures stop before the next request', async () => {
  const aborted = execution(); aborted.controller.abort(); const stopped = await aborted.run();
  assert.equal(stopped.status, 'unknown'); assert.equal(aborted.requests.length, 0);
  assert.deepEqual(aborted.events, []);
  assert.ok(stopped.attempts.every(a => a.outcome === 'not_started'));
  for (const failure of ['restore', 'begin', 'complete'] as const) {
    const f = execution();
    if (failure === 'restore') f.hooks.restore = async b => ({ ...b, snapshotHash: hash('different') });
    if (failure === 'begin') f.hooks.begin = async b => ({ ...b, phase: 'probe', admissionOrdinal: 41, opened: true });
    if (failure === 'complete') f.hooks.complete = async b => ({ ...b, closed: true, drained: false,
      coverageComplete: true }) as never;
    const result = await f.run(); assert.equal(result.status, 'unknown');
    assert.equal(f.requests.length, failure === 'complete' ? 1 : 0);
    assert.equal(result.attempts[1].outcome, 'not_started'); assert.equal(result.gaps[1].reason, 'stopped');
  }
});
test('required siblings, arrays, unsupported serialization/methods and changed identities remain unknown', async () => {
  const mutations: Array<(s: RuntimeSurface) => void> = [
    s => { s.params.push({ ...clone(s.params[0]), name: 'required-sibling' }); },
    s => { s.params[0].type = 'unknown'; }, s => { s.params[0].type = 'integer'; },
    s => { s.params[0].serialization.style = 'deepObject'; }, s => { s.params[0].serialization.allowReserved = true; },
    s => { s.readiness = 'unresolved'; }, s => { s.method = 'DELETE'; },
    s => { s.pathTemplate = '/other'; }, s => { s.pathTemplate = '//external/owned'; },
  ];
  for (const mutate of mutations) { const f = execution(); mutate(f.plan.surfaces[0]);
    const result = await f.run(); assert.equal(result.status, 'unknown'); assert.equal(f.requests.length, 0);
    assert.equal(result.gaps.length, 2); }
  const body = execution('body'); body.plan.surfaces[0].params.push({ ...clone(body.plan.surfaces[0].params[0]),
    name: 'optional-sibling', jsonPointer: '/optional-sibling', required: false });
  assert.equal((await body.run()).status, 'unknown'); assert.equal(body.requests.length, 0);
});
test('shared cap, ordinal reuse/mismatch and not-sent outcomes never become reservation-based sends', async () => {
  const cap = execution(); Object.assign(cap.port, { maxRequests: 40 });
  const limited = await cap.run(); assert.equal(cap.requests.length, 0);
  assert.ok(limited.deliveries.every(d => d.sent === 'not_sent')); assert.equal(limited.status, 'unknown');
  for (const fault of ['ordinal', 'sent', 'cancelled', 'limit', 'truncated', 'reuse'] as const) {
    const f = execution(), request = f.port.request;
    f.port.request = async input => {
      const r = await request.call(f.port, input);
      if (fault === 'ordinal') r.ordinal++;
      if (fault === 'reuse') r.ordinal = 41;
      if (fault === 'sent') r.sent = 'not_sent';
      if (fault === 'cancelled' || fault === 'limit') Object.assign(r, { outcome: fault, sent: 'not_sent',
        status: null, bodyBytes: Buffer.alloc(0), rawBodySha256: null });
      if (fault === 'truncated') r.truncated = true;
      return r;
    };
    if (fault === 'reuse') f.hooks.begin = async b => ({ ...b, admissionOrdinal: 41, opened: true });
    const result = await f.run(); assert.equal(result.status, 'unknown');
    assert.equal(f.requests.length, 1); assert.equal(result.attempts[1].outcome, 'not_started');
    if (fault === 'cancelled' || fault === 'limit') assert.equal(result.deliveries[0].outcome, fault);
  }
});
test('port exceptions and response byte/hash damage preserve uncertainty and still require completion', async () => {
  for (const fault of ['throw', 'hash', 'shared'] as const) {
    const f = execution(), request = f.port.request;
    f.port.request = async input => {
      if (fault === 'throw') throw Error('private-exception');
      const r = await request.call(f.port, input);
      if (fault === 'hash') r.rawBodySha256 = hash('wrong');
      if (fault === 'shared') r.bodyBytes = new Uint8Array(new SharedArrayBuffer(23));
      return r;
    };
    const result = await f.run(); assert.equal(result.status, 'unknown');
    assert.ok(f.events.includes('complete-1')); assert.equal(result.attempts[1].outcome, 'not_started');
    assert.equal(JSON.stringify(result).includes('private'), false);
    if (fault === 'throw') assert.equal(result.deliveries[0].sent, 'unknown');
  }
});
test('abort closes an opened window without sending; failed control suppresses its probe', async () => {
  const cancelled = execution(), begin = cancelled.hooks.begin;
  cancelled.hooks.begin = async function (binding) {
    const ack = await begin.call(this, binding); cancelled.controller.abort(); return ack;
  };
  const result = await cancelled.run(); assert.equal(result.status, 'unknown');
  assert.equal(cancelled.requests.length, 0); assert.ok(cancelled.events.includes('complete-1'));
  assert.equal(result.deliveries[0].outcome, 'cancelled'); assert.equal(result.deliveries[0].sent, 'not_sent');
  const failed = execution(), request = failed.port.request;
  failed.port.request = async function (input) { const r = await request.call(this, input); r.status = 500; return r; };
  const output = await failed.run(); assert.equal(output.status, 'unknown'); assert.equal(failed.requests.length, 1);
  assert.equal(output.attempts[0].httpStatus, 500); assert.equal(output.attempts[1].outcome, 'not_started');
});
test('only genuine issuance is executable; hostile plans/response getters execute no supplied code', async () => {
  let calls = 0; const trap = () => { calls++; throw Error('private-getter'); };
  const f = execution(), forged = { ledger: f.markers.ledger, markerForExecutor: trap };
  assert.equal((await runNativeSql(f.plan, forged, f.port, f.hooks, f.options)).status, 'unknown');
  const plan = Object.defineProperty(clone(f.plan), 'snapshotHash', { enumerable: true, get: trap });
  assert.equal((await runNativeSql(plan, f.markers, f.port, f.hooks, f.options)).status, 'unknown');
  const proxied = new Proxy(f.plan, { ownKeys: trap });
  assert.equal((await runNativeSql(proxied, f.markers, f.port, f.hooks, f.options)).status, 'unknown');
  f.port.request = async () => Object.defineProperty({}, 'bodyBytes', {
    enumerable: true, get: trap }) as RuntimeResponse;
  assert.equal((await f.run()).status, 'unknown'); assert.equal(calls, 0);
});
test('root JSON keys decode pointer escapes without enabling nested, numeric or dangerous leaves', async () => {
  for (const [pointer, name] of [['/display~1name', 'display/name'], ['/display~0name', 'display~name']]) {
    const f = execution('body', 'sql-quote', pointer, name), result = await f.run();
    assert.equal(result.status, 'completed');
    assert.equal(Object.getPrototypeOf(f.requests[0].body!.data), null);
    assert.deepEqual(Object.keys(f.requests[0].body!.data as object), [name]);
    assert.equal((f.requests[0].body!.data as Record<string, string>)[name], f.markers.markerForExecutor(1));
  }
  for (const [pointer, name] of [['/profile/name', 'name'], ['/0', '0']]) {
    const f = execution('body', 'sql-quote', pointer, name);
    assert.equal((await f.run()).status, 'unknown'); assert.equal(f.requests.length, 0);
  }
  for (const name of ['__proto__', 'prototype', 'constructor', 'x'.repeat(256)])
    assert.throws(() => execution('body', 'sql-quote', '/' + name, name), /invalid_marker_reservation/);
});
test('fake AbortSignal brands fail as invalid_input without invoking accessors, hooks or transport', async () => {
  let calls = 0; const trap = () => { calls++; throw Error('forbidden-signal-access'); };
  const lookalike = Object.defineProperty({}, 'aborted', { get: trap });
  const forgedBrand = Object.create(AbortSignal.prototype);
  const proxy = new Proxy(new AbortController().signal, { get: trap, getPrototypeOf: trap });
  for (const signal of [lookalike, forgedBrand, proxy]) {
    const f = execution(), result = await runNativeSql(f.plan, f.markers, f.port, f.hooks,
      { ...f.options, signal: signal as AbortSignal });
    assert.equal(result.status, 'unknown'); assert.ok(result.gaps.every(g => g.reason === 'invalid_input'));
    assert.equal(f.requests.length, 0); assert.deepEqual(f.events, []);
    assert.ok(result.deliveries.every(d => d.sent === 'not_sent'));
  }
  const genuine = execution(); Object.defineProperty(genuine.options.signal, 'aborted', { get: trap });
  assert.equal((await genuine.run()).status, 'completed'); assert.equal(calls, 0);
});
