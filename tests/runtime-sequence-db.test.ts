import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { RunStore, RunStoreError, PROVIDERS, RUN_DB_VERSION } from '../src/agent-dast/store.js';
import {
  DatabaseArtifactError, InitializationFailure, RunStoreError as ContractError, PROVIDERS as ContractProviders,
} from '../src/agent-dast/store-contract.js';
import { initializeDatabase, inspectRunDatabase } from '../src/agent-dast/store-schema.js';
import { SEQUENCE_DB_MIGRATION } from '../src/runtime/sequence-db-schema.js';
import { openSequenceDatabaseReader } from '../src/runtime/sequence-db-reader.js';

const oldTables = ['runs', 'surface', 'tasks', 'task_gaps', 'findings', 'coverage', 'ledger',
  'coverage_plan', 'finding_observations'] as const;
const additive = ['edges', 'observation_refs', 'planned_cells', 'sequence_steps'];
const fixture = (version: 1 | 2) => readFileSync(
  resolve('tests/fixtures/runtime-sequence-db/v' + version + '.sql'), 'utf8',
);
function oldRows(db: DatabaseSync, version: 1 | 2 = 2) {
  return oldTables.filter(table => version === 2 || !['coverage_plan', 'finding_observations'].includes(table))
    .map(table => ({ table, rows: db.prepare('SELECT * FROM "' + table + '" ORDER BY rowid').all() }));
}
function state(db: DatabaseSync) {
  return {
    version: db.prepare('PRAGMA user_version').get()?.user_version,
    catalog: db.prepare('SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name').all(),
    rows: oldRows(db),
  };
}
function migrationFailure(work: () => void): InitializationFailure {
  let failure: unknown;
  try { work(); } catch (error) { failure = error; }
  assert.ok(failure instanceof InitializationFailure);
  return failure;
}
const constraintFailure = (error: unknown) => error instanceof Error && 'errcode' in error
  && typeof error.errcode === 'number' && (error.errcode & 255) === 19;
function seeded(path = ':memory:') {
  const db = new DatabaseSync(path);
  db.exec(fixture(2));
  initializeDatabase(db);
  const step = db.prepare('INSERT INTO sequence_steps VALUES(?,?,?,?,?,?,?,?,?,?)');
  for (const ordinal of [0, 1]) step.run(
    'r-owned', 'seq', 1, ordinal, 'state', 'operation', 's-owned', 'GET', 'actor', 'a'.repeat(64),
  );
  const cell = db.prepare('INSERT INTO planned_cells VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
  for (const ordinal of [0, 1]) cell.run(
    'r-owned', 'seq', 1, 's-owned', 'check', 'actor', ordinal, 1, 'a'.repeat(64),
    'completed', 'observed', 't-owned', null,
  );
  const observation = db.prepare('INSERT INTO observation_refs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
  for (const ordinal of [0, 1]) observation.run(
    'r-owned', 'obs-' + ordinal, 'seq', 1, 's-owned', 'check', 'actor', ordinal,
    'admission-' + ordinal, 'channel', 'evidence/a.json', 'b'.repeat(64), ordinal + 1,
  );
  return db;
}

test('v2 append preserves every old row and SQL object and creates four STRICT empty tables', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(fixture(2));
    const before = state(db);
    initializeDatabase(db);
    assert.equal(RUN_DB_VERSION, 3);
    assert.equal(inspectRunDatabase(db, 'write').version, 3);
    assert.deepEqual(oldRows(db), before.rows);
    const after = db.prepare('SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name').all();
    assert.deepEqual(after.filter(row => !additive.includes(String(row.name))), before.catalog);
    assert.equal(after.length, 17);
    for (const table of additive) {
      assert.equal(db.prepare('SELECT count(*) n FROM "' + table + '"').get()?.n, 0);
      assert.equal(db.prepare('SELECT strict FROM pragma_table_list WHERE name=?').get(table)?.strict, 1);
    }
    initializeDatabase(db);
    assert.deepEqual(oldRows(db), before.rows);
  } finally { db.close(); }
});

test('legitimate populated v1 reads as untrusted and refuses writes without changing its state', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(fixture(1));
    const before = oldRows(db, 1);
    assert.deepEqual(inspectRunDatabase(db, 'history'), { version: 1, kind: 'legacy', trust: 'untrusted' });
    const error = migrationFailure(() => initializeDatabase(db));
    assert.equal(error.primary.kind, 'contract');
    if (error.primary.kind === 'contract') assert.equal(error.primary.error.code, 'legacy_evidence_untrusted');
    assert.equal(error.rollback.kind, 'not_started');
    assert.deepEqual(oldRows(db, 1), before);
    db.exec('DELETE FROM coverage; DELETE FROM ledger; DELETE FROM findings; DELETE FROM task_gaps;'
      + ' DELETE FROM tasks; DELETE FROM surface; DELETE FROM runs');
    initializeDatabase(db);
    assert.equal(inspectRunDatabase(db, 'write').version, 3);
  } finally { db.close(); }
});

test('empty and incompatible catalogs use the canonical initializer and old public error identity', () => {
  assert.equal(RunStoreError, ContractError);
  assert.equal(PROVIDERS, ContractProviders);
  const db = new DatabaseSync(':memory:');
  try {
    assert.equal(inspectRunDatabase(db, 'history').version, 0);
    new RunStore(db);
    assert.equal(inspectRunDatabase(db, 'write').version, 3);
    db.exec('PRAGMA user_version=4');
    assert.throws(() => new RunStore(db), error =>
      error instanceof RunStoreError && error.code === 'unsupported_version');
  } finally { db.close(); }
});

test('native STRICT keys checks NULL branches and reference membership reject invalid rows', () => {
  const db = seeded();
  try {
    const edge = db.prepare('INSERT INTO edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
    const base = ['r-owned', 'seq', 1, 0, 1, 'binding', 'extract', 'body', '["body",[]]',
      'declared', 'string', 'value', null, null] as const;
    edge.run(...base);
    db.exec('DELETE FROM edges');
    for (const patch of [
      { index: 10, value: null }, { index: 11, value: null }, { index: 9, value: 'observed' },
      { index: 12, value: 'obs-0' }, { index: 3, value: 1 }, { index: 6, value: 'constructor' },
      { index: 8, value: '' }, { index: 2, value: 0 },
    ]) {
      const values: (string | number | null)[] = [...base];
      values[patch.index] = patch.value;
      assert.throws(() => edge.run(...values), constraintFailure);
    }
    edge.run('r-owned', 'seq', 1, 0, 1, 'binding', 'extract', 'body', '["body",[""]]',
      'observed', 'string', 'value', 'obs-0', 'obs-1');
    assert.throws(() => edge.run('r-owned', 'seq', 1, 0, 1, 'binding', 'other', 'body', '["body",[]]',
      'observed', 'string', 'value', 'missing', 'obs-1'));
    assert.throws(() => db.exec("INSERT INTO sequence_steps SELECT * FROM sequence_steps WHERE ordinal=0"),
      constraintFailure);
    assert.throws(() => db.exec("UPDATE planned_cells SET execution_state='queued'"), constraintFailure);
    assert.throws(() => db.exec("UPDATE planned_cells SET execution_state='error',reason_code=NULL"),
      constraintFailure);
    assert.throws(() => db.exec('UPDATE sequence_steps SET ordinal=NULL'), constraintFailure);
    assert.throws(() => db.exec('UPDATE planned_cells SET first_iteration=65'), constraintFailure);
    assert.throws(() => db.exec('UPDATE observation_refs SET logical_ordinal=0'), constraintFailure);
    assert.throws(() => db.exec("UPDATE observation_refs SET observation_id='missing'"), constraintFailure);
    assert.throws(() => db.exec('UPDATE sequence_steps SET reset_generation=9007199254740992'), constraintFailure);
    assert.throws(() => db.prepare('INSERT INTO sequence_steps VALUES(?,?,?,?,?,?,?,?,?,?)').run(
      null, 'extra', 1, 0, 'state', 'operation', 's-owned', 'GET', 'actor', 'a'.repeat(64)), constraintFailure);
    assert.throws(() => db.exec('INSERT INTO planned_cells SELECT run_id,sequence_id,reset_generation,'
      + 'surface_id,check_id,actor_ref,ordinal,first_iteration+1,plan_digest,execution_state,'
      + 'observation_outcome,task_id,reason_code FROM planned_cells WHERE ordinal=0'), constraintFailure);
    db.prepare('UPDATE planned_cells SET plan_digest=? WHERE ordinal=0').run('c'.repeat(64));
    assert.throws(() => inspectRunDatabase(db, 'history'), error =>
      error instanceof DatabaseArtifactError && error.code === 'invalid_record');
  } finally { db.close(); }
});

test('physical FULL retains numeric provenance and old state on the same connection before close', () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-full-')), path = join(directory, 'owned.db');
  let db = new DatabaseSync(path);
  const control = new DatabaseSync(join(directory, 'control.db'));
  try {
    db.exec(fixture(2));
    control.exec(fixture(2));
    const pages = control.prepare('PRAGMA page_count').get()?.page_count;
    assert.equal(typeof pages, 'number');
    control.exec(SEQUENCE_DB_MIGRATION.slice(0, SEQUENCE_DB_MIGRATION.indexOf('CREATE TABLE planned_cells')));
    assert.ok(control.prepare("SELECT 1 FROM sqlite_master WHERE name='sequence_steps'").get());
    const prefixPages = control.prepare('PRAGMA page_count').get()?.page_count;
    assert.equal(typeof prefixPages, 'number');
    assert.ok(Number(prefixPages) > Number(pages));
    db.exec('PRAGMA max_page_count=' + Number(prefixPages));
    const before = state(db), error = migrationFailure(() => initializeDatabase(db));
    assert.deepEqual(state(db), before);
    assert.equal(error.primary.kind, 'native');
    if (error.primary.kind === 'native') assert.equal(error.primary.sqlite.primary, 13);
    assert.equal(error.phase, 'migration');
    console.log('T5_NATIVE ' + JSON.stringify({ case: 'FULL', phase: error.phase,
      primary: error.primary, rollback: error.rollback, sameConnectionOldState: true }));
    db.close();
    db = new DatabaseSync(path);
    assert.deepEqual(state(db), before);
  } finally { db.close(); control.close(); rmSync(directory, { recursive: true }); }
});

test('held native reader makes COMMIT BUSY and application rollback restores before either connection closes', () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-busy-')), path = join(directory, 'owned.db');
  let db: DatabaseSync | undefined = new DatabaseSync(path), peer: DatabaseSync | undefined;
  try {
    db.exec(fixture(2));
    const before = state(db);
    db.exec('PRAGMA journal_mode=DELETE; PRAGMA cache_spill=OFF; PRAGMA cache_size=-8192');
    peer = new DatabaseSync(path);
    peer.exec('BEGIN');
    assert.ok(peer.prepare('SELECT * FROM runs LIMIT 1').get());
    const connection = db, error = migrationFailure(() => initializeDatabase(connection));
    assert.equal(error.primary.kind, 'native');
    if (error.primary.kind === 'native') assert.equal(error.primary.sqlite.primary, 5);
    assert.equal(error.phase, 'commit');
    assert.equal(error.rollback.kind, 'explicit_rollback_completed');
    assert.deepEqual(state(db), before);
    console.log('T5_NATIVE ' + JSON.stringify({ case: 'COMMIT_BUSY', phase: error.phase,
      primary: error.primary, rollback: error.rollback, sameConnectionOldState: true, peerStillHeld: true }));
    peer.exec('ROLLBACK');
    peer.close();
    peer = undefined;
    db.close();
    db = new DatabaseSync(path);
    assert.deepEqual(state(db), before);
    initializeDatabase(db);
    assert.equal(inspectRunDatabase(db, 'write').version, 3);
    assert.deepEqual(oldRows(db), before.rows);
  } finally {
    peer?.close();
    db?.close();
    rmSync(directory, { recursive: true });
  }
});

test('typed reader pages are bounded scoped and resolve real observed witnesses and body identities', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-typed-')), path = join(directory, 'source.db');
  const producer = seeded(path), step = producer.prepare('INSERT INTO sequence_steps VALUES(?,?,?,?,?,?,?,?,?,?)');
  for (let i = 0; i < 257; i++) step.run('r-owned', 'bulk' + i.toString().padStart(3, '0'),
    1, 0, 'state', 'operation', 's-owned', 'GET', 'actor', 'a'.repeat(64));
  const edge = producer.prepare('INSERT INTO edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
  for (const identity of ['["body",[]]', '["body",[""]]']) edge.run('r-owned', 'seq', 1, 0, 1,
    'binding', 'extract', 'body', identity, 'observed', 'string', 'value', 'obs-0', 'obs-1');
  producer.close();
  chmodSync(path, 0o600);
  const source = { kind: 'closed-rollback-snapshot', path } as const, before = readFileSync(path);
  const reader = await openSequenceDatabaseReader(source), other = await openSequenceDatabaseReader(source);
  try {
    const first = reader.steps('r-owned');
    assert.ok(first.kind === 'metadata');
    assert.equal(first.items.length, 256);
    assert.ok(first.nextCursor);
    const next = reader.steps('r-owned', first.nextCursor);
    assert.ok(next.kind === 'metadata');
    assert.equal(next.items.length, 3);
    for (const read of [() => other.steps('r-owned', first.nextCursor ?? undefined),
      () => reader.steps('r-other', first.nextCursor ?? undefined),
      () => reader.cells('r-owned', first.nextCursor ?? undefined),
      () => Reflect.apply(reader.steps, reader, ['r-owned', ['forged']])]) assert.throws(read, error =>
        error instanceof DatabaseArtifactError && error.code === 'invalid_input');
    const edges = reader.edges('r-owned');
    assert.ok(edges.kind === 'metadata');
    assert.deepEqual(edges.items.map(item => {
      assert.ok(item.kind === 'binding' && item.provenance === 'observed' && item.destination.location === 'body');
      assert.equal(item.producerObservation.observationId, 'obs-0');
      assert.equal(item.consumerObservation.observationId, 'obs-1');
      return item.destination.pointer;
    }).sort(), ['', '/']);
    assert.equal(edges.qualification, 'not_assessed');
    const cells = reader.cells('r-owned'), observations = reader.observations('r-owned');
    assert.ok(cells.kind === 'metadata' && observations.kind === 'metadata');
    assert.equal(cells.items.length, 2);
    assert.deepEqual(observations.items.map(item => item.observationId), ['obs-0', 'obs-1']);
    assert.deepEqual(readFileSync(path), before);
  } finally { reader.close(); other.close(); rmSync(directory, { recursive: true }); }
});
