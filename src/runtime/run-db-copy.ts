import {
  closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdtempSync, openSync, readSync,
  realpathSync, rmdirSync, unlinkSync, writeSync, type Stats,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import {
  DatabaseArtifactError, artifactFailure, filesystemCode, requireSqliteRuntime,
  type Cleanup, type Publication,
} from '../agent-dast/store-contract.js';
import { openOriginal, privateDirectory, type ClosedRunDatabaseSource } from '../agent-dast/store-path.js';

export type { ClosedRunDatabaseSource } from '../agent-dast/store-path.js';
export const RUN_DB_MAX_BYTES = 16 * 1024 * 1024;
type Original = ReturnType<typeof openOriginal>;
function refuseSidecars(path: string): void {
  for (const suffix of ['-wal', '-shm', '-journal']) {
    try { lstatSync(path + suffix); }
    catch (error) {
      if (filesystemCode(error) === 'ENOENT') continue;
      throw error;
    }
    throw new DatabaseArtifactError('source_requires_snapshot', 'source');
  }
}
function readOriginal(original: Original): Buffer {
  const { descriptor, stat } = original;
  if (stat.size < 100) throw new DatabaseArtifactError('corrupt_input', 'source');
  if (stat.size > RUN_DB_MAX_BYTES) throw new DatabaseArtifactError('input_limit', 'source');
  const bytes = Buffer.alloc(stat.size);
  let offset = 0;
  while (offset < bytes.length) {
    const n = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (n === 0) throw new DatabaseArtifactError('source_changed', 'source');
    offset += n;
  }
  if (!bytes.subarray(0, 16).equals(Buffer.from('SQLite format 3\x00'))) {
    throw new DatabaseArtifactError('corrupt_input', 'source');
  }
  if (bytes[18] === 2 || bytes[19] === 2) {
    throw new DatabaseArtifactError('source_requires_snapshot', 'source');
  }
  if (bytes[18] !== 1 || bytes[19] !== 1) throw new DatabaseArtifactError('corrupt_input', 'source');
  return bytes;
}
function sameFile(before: Stats, after: Stats): boolean {
  return after.isFile() && !after.isSymbolicLink() && before.dev === after.dev && before.ino === after.ino
    && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs
    && before.mode === after.mode && before.uid === after.uid && before.nlink === after.nlink;
}
function syncPublishedDirectory(path: string, ownerId: string): void {
  try {
    const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(descriptor); }
    finally { closeSync(descriptor); }
  } catch (error) {
    const code = filesystemCode(error);
    if (!code) throw error;
    throw new DatabaseArtifactError('cleanup_failed', 'cleanup', {
      publication: 'complete', cleanup: { kind: 'incomplete', code, ownerId },
    });
  }
}
function unlinkOwned(path: string, identity: Stats, expectedLinks: number): void {
  try {
    const file = lstatSync(path);
    if (!file.isFile() || file.isSymbolicLink() || file.dev !== identity.dev || file.ino !== identity.ino
      || file.uid !== process.getuid?.() || file.nlink !== expectedLinks || (file.mode & 0o777) !== 0o600) {
      throw new DatabaseArtifactError('unsafe_path', 'cleanup');
    }
    unlinkSync(path);
  } catch (error) {
    if (filesystemCode(error) !== 'ENOENT') throw error;
  }
}
export class OwnedDatabaseCopy {
  readonly path: string;
  readonly ownerId: string;
  private readonly identity: Stats;
  private sourceClosed = false;
  private publication: Publication = 'absent';
  private cleanup: Cleanup = { kind: 'complete' };
  constructor(
    private readonly original: Original,
    private readonly bytes: Buffer,
    private readonly directory: string,
  ) {
    this.path = join(directory, 'run.db');
    this.ownerId = basename(directory);
    this.identity = lstatSync(this.path);
  }
  private verifyOriginal(): void {
    refuseSidecars(this.original.path);
    const { stat, descriptor, path } = this.original;
    if (!sameFile(stat, fstatSync(descriptor)) || !sameFile(stat, lstatSync(path))
      || !this.bytes.equals(readOriginal(this.original))) {
      throw new DatabaseArtifactError('source_changed', 'source');
    }
  }
  private removeOwnedNames(): void {
    privateDirectory(this.directory, false);
    unlinkOwned(this.path, this.identity, this.publication === 'complete' ? 2 : 1);
    rmdirSync(this.directory);
  }
  close(): Cleanup {
    try {
      this.removeOwnedNames();
      this.cleanup = { kind: 'complete' };
    } catch (error) {
      const code = error instanceof DatabaseArtifactError ? error.code : filesystemCode(error);
      if (code !== 'ENOENT') {
        if (!code) throw error;
        this.cleanup = { kind: 'incomplete', code, ownerId: this.ownerId };
      }
    } finally {
      if (!this.sourceClosed) {
        closeSync(this.original.descriptor);
        this.sourceClosed = true;
      }
    }
    return this.cleanup;
  }
  publish(destination: string): void {
    if (this.sourceClosed || this.publication !== 'absent') {
      throw new DatabaseArtifactError('invalid_transition', 'publish');
    }
    let linkAttempted = false;
    try {
      const final = resolve(destination), parent = dirname(final);
      privateDirectory(parent, false);
      if (resolve(realpathSync(parent), basename(final)) === this.original.path
        || realpathSync(parent) !== dirname(this.directory)) {
        throw new DatabaseArtifactError('unsafe_path', 'publish');
      }
      privateDirectory(this.directory, false);
      const file = lstatSync(this.path);
      if (file.dev !== this.identity.dev || file.ino !== this.identity.ino || !file.isFile()
        || file.isSymbolicLink() || file.nlink !== 1 || file.uid !== process.getuid?.()
        || (file.mode & 0o777) !== 0o600) throw new DatabaseArtifactError('unsafe_path', 'publish');
      if (file.size > RUN_DB_MAX_BYTES) throw new DatabaseArtifactError('input_limit', 'publish');
      refuseSidecars(this.path);
      this.verifyOriginal();
      const descriptor = openSync(this.path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try { fsyncSync(descriptor); }
      finally { closeSync(descriptor); }
      linkAttempted = true;
      linkSync(this.path, final);
      this.publication = 'complete';
      const cleanup = this.close();
      if (cleanup.kind === 'incomplete') throw new DatabaseArtifactError('cleanup_failed', 'cleanup');
      syncPublishedDirectory(parent, this.ownerId);
    } catch (error) {
      if (linkAttempted && this.publication === 'absent'
        && !['EEXIST', 'EACCES', 'EPERM', 'EXDEV', 'ENOENT', 'ENOTDIR', 'EMLINK', 'ENOSPC']
          .includes(filesystemCode(error) ?? '')) this.publication = 'unknown';
      const cleanup = this.close();
      const primary = artifactFailure(error, 'publish');
      throw new DatabaseArtifactError(primary.code, primary.phase, {
        ...primary.state, publication: this.publication,
        cleanup: primary.state.cleanup.kind === 'incomplete' ? primary.state.cleanup : cleanup,
      });
    }
  }
}

export async function createOwnedDatabaseCopy(
  source: ClosedRunDatabaseSource, privateParent: string,
): Promise<OwnedDatabaseCopy> {
  let original: Original | undefined, directory: string | undefined, copy: OwnedDatabaseCopy | undefined;
  let created: { readonly path: string; readonly identity: Stats } | undefined;
  let phase: 'source' | 'copy' = 'source';
  try {
    requireSqliteRuntime();
    original = openOriginal(source);
    refuseSidecars(original.path);
    const bytes = readOriginal(original);
    const parent = realpathSync(privateParent);
    privateDirectory(parent);
    phase = 'copy';
    directory = mkdtempSync(join(parent, 't5-db-'));
    const path = join(directory, 'run.db');
    const descriptor = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
      | constants.O_NOFOLLOW, 0o600);
    try {
      created = { path, identity: fstatSync(descriptor) };
      let offset = 0;
      while (offset < bytes.length) {
        const written = writeSync(descriptor, bytes, offset, bytes.length - offset);
        if (written === 0) throw new DatabaseArtifactError('storage_error', 'copy');
        offset += written;
      }
      fsyncSync(descriptor);
    } finally { closeSync(descriptor); }
    copy = new OwnedDatabaseCopy(original, bytes, directory);
    if (!sameFile(original.stat, fstatSync(original.descriptor))
      || !sameFile(original.stat, lstatSync(original.path)) || !bytes.equals(readOriginal(original))) {
      throw new DatabaseArtifactError('source_changed', 'source');
    }
    refuseSidecars(original.path);
    return copy;
  } catch (error) {
    let cleanup: Cleanup = { kind: 'complete' };
    if (copy) cleanup = copy.close();
    else {
      if (original) closeSync(original.descriptor);
      if (directory) {
        try {
          if (created) unlinkOwned(created.path, created.identity, 1);
          rmdirSync(directory);
        }
        catch (cleanupError) {
          const code = cleanupError instanceof DatabaseArtifactError ? cleanupError.code : filesystemCode(cleanupError);
          if (!code) throw cleanupError;
          cleanup = { kind: 'incomplete', code, ownerId: basename(directory) };
        }
      }
    }
    const primary = artifactFailure(error, phase);
    throw new DatabaseArtifactError(primary.code, primary.phase, { ...primary.state, cleanup });
  }
}
