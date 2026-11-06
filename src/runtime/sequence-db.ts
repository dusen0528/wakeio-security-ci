import type { DatabaseSync } from 'node:sqlite';
import { dirname, resolve } from 'node:path';
import {
  DatabaseArtifactError, artifactFailure, sqliteModule, type Cleanup,
} from '../agent-dast/store-contract.js';
import {
  initializeDatabase, inspectRunDatabase, type RunDatabaseSchema,
} from '../agent-dast/store-schema.js';
import { createOwnedDatabaseCopy, type ClosedRunDatabaseSource, type OwnedDatabaseCopy } from './run-db-copy.js';

export interface OwnedSequenceDatabase {
  readonly path: string;
  readonly sourceVersion: RunDatabaseSchema['version'];
  readonly schemaVersion: 3;
  readonly cleanup: 'complete';
}
export function inspectOwnedDatabase(db: DatabaseSync, purpose: 'history' | 'write'): RunDatabaseSchema {
  db.exec('PRAGMA trusted_schema=OFF');
  const integrity = db.prepare('PRAGMA integrity_check(1)').get()?.integrity_check;
  if (integrity !== 'ok') throw new DatabaseArtifactError('corrupt_input', 'inspect');
  return inspectRunDatabase(db, purpose);
}
export async function migrateSequenceDatabase(
  source: ClosedRunDatabaseSource, destination: string,
): Promise<OwnedSequenceDatabase> {
  let copy: OwnedDatabaseCopy | undefined, db: DatabaseSync | undefined;
  let phase: 'inspect' | 'migrate' = 'inspect';
  try {
    const sqlite = await sqliteModule();
    copy = await createOwnedDatabaseCopy(source, dirname(resolve(destination)));
    db = new sqlite.DatabaseSync(copy.path, { readOnly: true });
    db.exec('PRAGMA query_only=ON');
    const schema = inspectOwnedDatabase(db, 'write');
    db.close();
    db = undefined;
    phase = 'migrate';
    db = new sqlite.DatabaseSync(copy.path);
    initializeDatabase(db);
    const migrated = inspectOwnedDatabase(db, 'write');
    if (migrated.version !== 3) throw new DatabaseArtifactError('unsupported_version', 'inspect');
    db.close();
    db = undefined;
    copy.publish(destination);
    return { path: resolve(destination), sourceVersion: schema.version, schemaVersion: 3, cleanup: 'complete' };
  } catch (error) {
    db?.close();
    const cleanup: Cleanup = copy ? copy.close()
      : error instanceof DatabaseArtifactError ? error.state.cleanup : { kind: 'complete' };
    const primary = artifactFailure(error, phase);
    throw new DatabaseArtifactError(primary.code, primary.phase, {
      ...primary.state, cleanup: primary.state.cleanup.kind === 'incomplete' ? primary.state.cleanup : cleanup,
    });
  }
}
