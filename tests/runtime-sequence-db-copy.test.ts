import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readlinkSync, readdirSync,
  rmSync, symlinkSync, writeFileSync,
  truncateSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { backup, DatabaseSync } from 'node:sqlite';
import { DatabaseArtifactError } from '../src/agent-dast/store-contract.js';
import { initializeDatabase, inspectRunDatabase } from '../src/agent-dast/store-schema.js';
import { createOwnedDatabaseCopy, type ClosedRunDatabaseSource } from '../src/runtime/run-db-copy.js';
import { migrateSequenceDatabase } from '../src/runtime/sequence-db.js';
import { openSequenceDatabaseReader } from '../src/runtime/sequence-db-reader.js';

function fixture(directory: string, version: 1 | 2 = 2): ClosedRunDatabaseSource {
  const path = join(directory, 'source.db'), db = new DatabaseSync(path);
  try { db.exec(readFileSync(resolve('tests/fixtures/runtime-sequence-db/v' + version + '.sql'), 'utf8')); }
  finally { db.close(); }
  chmodSync(path, 0o600);
  return { kind: 'closed-rollback-snapshot', path };
}
function conserved(path: string) {
  return ['', '-wal', '-shm', '-journal'].map(suffix => {
    const name = path + suffix;
    if (!existsSync(name)) return { suffix, exists: false };
    const stat = lstatSync(name);
    return { suffix, exists: true, bytes: readFileSync(name),
      mode: stat.mode, dev: stat.dev, ino: stat.ino, nlink: stat.nlink };
  });
}
function validStage(path: string): void {
  const db = new DatabaseSync(path);
  try { initializeDatabase(db); } finally { db.close(); }
}
function complete(path: string): void {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    assert.equal(inspectRunDatabase(db, 'history').version, 3);
    assert.equal(db.prepare('SELECT bytes FROM ledger').get()?.bytes, 42);
  } finally { db.close(); }
}

test('production migration publishes a complete single-link v3 and leaves every original byte unchanged', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-copy-'));
  try {
    const source = fixture(directory), before = conserved(source.path), final = join(directory, 'final.db');
    const result = await migrateSequenceDatabase(source, final);
    assert.deepEqual(result, { path: final, sourceVersion: 2, schemaVersion: 3, cleanup: 'complete' });
    complete(final);
    assert.equal(lstatSync(final).nlink, 1);
    assert.deepEqual(conserved(source.path), before);
    assert.deepEqual(readdirSync(directory).sort(), ['final.db', 'source.db']);
  } finally { rmSync(directory, { recursive: true }); }
});

test('native no-replace EEXIST preserves foreign file bytes and symlink targets after real preparation', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-exists-'));
  try {
    const source = fixture(directory), before = conserved(source.path), final = join(directory, 'foreign.db');
    for (const symlink of [false, true]) {
      const copy = await createOwnedDatabaseCopy(source, directory);
      validStage(copy.path);
      if (symlink) symlinkSync('source.db', final);
      else writeFileSync(final, 'foreign bytes', { mode: 0o600, flag: 'wx' });
      const identity = lstatSync(final);
      assert.throws(() => copy.publish(final), error => {
        assert.ok(error instanceof DatabaseArtifactError);
        assert.equal(error.code, 'destination_exists');
        assert.equal(error.state.filesystemCode, 'EEXIST');
        assert.equal(error.state.publication, 'absent');
        return true;
      });
      assert.equal(lstatSync(final).ino, identity.ino);
      if (symlink) assert.equal(readlinkSync(final), 'source.db');
      else assert.equal(readFileSync(final, 'utf8'), 'foreign bytes');
      assert.equal(copy.close().kind, 'complete');
      rmSync(final);
    }
    assert.deepEqual(conserved(source.path), before);
  } finally { rmSync(directory, { recursive: true }); }
});

for (const phase of ['pre-link', 'post-link'] as const) {
  test('real non-root ' + phase + ' permission failure retains publication and actual residue ownership', async () => {
    assert.ok(process.getuid && process.getuid() !== 0, 'native permission proof requires non-root ownership');
    const directory = mkdtempSync(join(tmpdir(), 't5-permission-'));
    const source = fixture(directory), before = conserved(source.path), final = join(directory, 'final.db');
    const copy = await createOwnedDatabaseCopy(source, directory), stage = dirname(copy.path);
    try {
      validStage(copy.path);
      chmodSync(phase === 'pre-link' ? directory : stage, 0o500);
      assert.throws(() => copy.publish(final), error => {
        assert.ok(error instanceof DatabaseArtifactError);
        assert.equal(error.state.publication, phase === 'pre-link' ? 'absent' : 'complete');
        assert.equal(error.state.cleanup.kind, 'incomplete');
        if (error.state.cleanup.kind === 'incomplete') {
          assert.match(error.state.cleanup.code, /^(EACCES|EPERM)$/);
          assert.equal(error.state.cleanup.ownerId, copy.ownerId);
        }
        if (phase === 'pre-link') assert.match(error.state.filesystemCode ?? '', /^(EACCES|EPERM)$/);
        console.log('T5_NATIVE ' + JSON.stringify({ case: phase, code: error.code,
          publication: error.state.publication, cleanup: error.state.cleanup, noReadyValue: true }));
        return true;
      });
      if (phase === 'post-link') {
        complete(final);
        assert.equal(lstatSync(copy.path).ino, lstatSync(final).ino);
        assert.equal(lstatSync(final).nlink, 2);
      } else assert.equal(existsSync(final), false);
      assert.deepEqual(conserved(source.path), before);
    } finally {
      chmodSync(directory, 0o700);
      chmodSync(stage, 0o700);
      assert.equal(copy.close().kind, 'complete');
      rmSync(directory, { recursive: true });
    }
  });
}

test('WAL-only committed data is refused byte-exactly then survives a separate existing-owner export', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-wal-')), source = fixture(directory);
  const owner = new DatabaseSync(source.path);
  try {
    owner.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; UPDATE ledger SET bytes=987");
    const before = conserved(source.path), final = join(directory, 'final.db');
    await assert.rejects(migrateSequenceDatabase(source, final), error =>
      error instanceof DatabaseArtifactError && error.code === 'source_requires_snapshot');
    assert.deepEqual(conserved(source.path), before);
    assert.equal(existsSync(final), false);
    const exported = join(directory, 'export.db');
    await backup(owner, exported);
    const exportOwner = new DatabaseSync(exported);
    try { exportOwner.exec('PRAGMA journal_mode=DELETE'); } finally { exportOwner.close(); }
    chmodSync(exported, 0o600);
    const exportedBefore = conserved(exported);
    await migrateSequenceDatabase({ kind: 'closed-rollback-snapshot', path: exported }, final);
    const reader = new DatabaseSync(final, { readOnly: true });
    try { assert.equal(reader.prepare('SELECT bytes FROM ledger').get()?.bytes, 987); }
    finally { reader.close(); }
    assert.deepEqual(conserved(exported), exportedBefore);
  } finally { owner.close(); rmSync(directory, { recursive: true }); }
});

test('missing corrupt incompatible and aliased originals never become ready destinations', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-invalid-'));
  try {
    const missing = join(directory, 'missing.db');
    await assert.rejects(migrateSequenceDatabase({ kind: 'closed-rollback-snapshot', path: missing },
      join(directory, 'absent.db')));
    assert.equal(existsSync(missing), false);
    const source = fixture(directory), before = conserved(source.path);
    await assert.rejects(migrateSequenceDatabase(source, source.path), error =>
      error instanceof DatabaseArtifactError && error.code === 'unsafe_path');
    assert.deepEqual(conserved(source.path), before);
    const incompatible = new DatabaseSync(source.path);
    try { incompatible.exec('PRAGMA user_version=99'); } finally { incompatible.close(); }
    const incompatibleBefore = conserved(source.path);
    await assert.rejects(migrateSequenceDatabase(source, join(directory, 'incompatible.db')), error =>
      error instanceof DatabaseArtifactError && error.code === 'unsupported_version');
    assert.deepEqual(conserved(source.path), incompatibleBefore);
    writeFileSync(source.path, Buffer.alloc(100), { mode: 0o600 });
    const corruptBefore = conserved(source.path);
    await assert.rejects(migrateSequenceDatabase(source, join(directory, 'corrupt.db')), error =>
      error instanceof DatabaseArtifactError && error.code === 'corrupt_input');
    assert.deepEqual(conserved(source.path), corruptBefore);
    assert.deepEqual(readdirSync(directory), ['source.db']);
  } finally { rmSync(directory, { recursive: true }); }
});

test('all sidecar suffixes and oversized snapshots are refused without changing original bytes', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-input-boundary-'));
  try {
    const source = fixture(directory);
    for (const suffix of ['-wal', '-shm', '-journal']) {
      writeFileSync(source.path + suffix, 'owned sidecar', { mode: 0o600, flag: 'wx' });
      const before = conserved(source.path);
      await assert.rejects(migrateSequenceDatabase(source, join(directory, 'final.db')), error =>
        error instanceof DatabaseArtifactError && error.code === 'source_requires_snapshot');
      assert.deepEqual(conserved(source.path), before);
      rmSync(source.path + suffix);
    }
    truncateSync(source.path, 16 * 1024 * 1024 + 1);
    const before = conserved(source.path);
    await assert.rejects(migrateSequenceDatabase(source, join(directory, 'final.db')), error =>
      error instanceof DatabaseArtifactError && error.code === 'input_limit');
    assert.deepEqual(conserved(source.path), before);
    assert.deepEqual(readdirSync(directory), ['source.db']);
  } finally { rmSync(directory, { recursive: true }); }
});

test('publication detects a real producer change and preserves the newly changed original', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-source-change-'));
  const source = fixture(directory), copy = await createOwnedDatabaseCopy(source, directory);
  try {
    validStage(copy.path);
    const producer = new DatabaseSync(source.path);
    try { producer.exec('UPDATE ledger SET bytes=43'); } finally { producer.close(); }
    const afterProducer = conserved(source.path), final = join(directory, 'final.db');
    assert.throws(() => copy.publish(final), error =>
      error instanceof DatabaseArtifactError && error.code === 'source_changed');
    assert.equal(existsSync(final), false);
    assert.deepEqual(conserved(source.path), afterProducer);
    assert.equal(copy.close().kind, 'complete');
  } finally { copy.close(); rmSync(directory, { recursive: true }); }
});

test('old and empty snapshot readers conserve originals and close their actual owned directories', async () => {
  for (const version of [0, 1, 2, 3] as const) {
    const directory = mkdtempSync(join(tmpdir(), 't5-history-source-')), path = join(directory, 'source.db');
    const source = version === 0 ? { kind: 'closed-rollback-snapshot', path } as const
      : fixture(directory, version === 3 ? 2 : version);
    if (version === 0) {
      const owner = new DatabaseSync(path);
      try { owner.exec('VACUUM'); } finally { owner.close(); }
      chmodSync(path, 0o600);
    }
    if (version === 3) validStage(path);
    const before = conserved(path), previousTmp = process.env.TMPDIR;
    assert.ok(previousTmp);
    process.env.TMPDIR = directory;
    const reader = await openSequenceDatabaseReader(source);
    try {
      assert.equal(reader.schema().version, version);
      assert.equal(reader.legacySummary('r-owned').summary?.gaps.timeout, version === 0 ? undefined : 2);
      assert.deepEqual(reader.cells('r-owned'), { kind: 'unavailable',
        reason: version === 3 ? 'no_registered_cells' : 'legacy_schema' });
      const edges = reader.edges('r-owned');
      if (version === 3) assert.deepEqual(edges,
        { kind: 'metadata', items: [], nextCursor: null, qualification: 'not_assessed' });
      else assert.deepEqual(edges, { kind: 'unavailable', reason: 'legacy_schema' });
      reader.close();
      assert.deepEqual(conserved(path), before);
      assert.deepEqual(readdirSync(directory), ['source.db']);
    } finally { reader.close(); process.env.TMPDIR = previousTmp; rmSync(directory, { recursive: true }); }
  }
});

test('native valid-schema rows with invalid controller identifiers never escape typed decoding', async () => {
  const directory = mkdtempSync(join(tmpdir(), 't5-invalid-row-')), source = fixture(directory);
  validStage(source.path);
  const owner = new DatabaseSync(source.path);
  try {
    owner.exec("INSERT INTO surface VALUES('invalid','r-owned','GET','/owned',NULL,NULL,'user')");
    owner.prepare('INSERT INTO sequence_steps VALUES(?,?,?,?,?,?,?,?,?,?)').run(
      'r-owned', 'badseq', 1, 0, 'state', 'operation', 'invalid', 'GET', 'actor', 'a'.repeat(64));
  } finally { owner.close(); }
  const before = conserved(source.path), reader = await openSequenceDatabaseReader(source);
  try {
    assert.throws(() => reader.steps('r-owned'), error =>
      error instanceof DatabaseArtifactError && error.code === 'invalid_record');
    assert.deepEqual(conserved(source.path), before);
  } finally { reader.close(); rmSync(directory, { recursive: true }); }
});
