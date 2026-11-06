import {
  closeSync, constants, fstatSync, lstatSync, openSync, realpathSync, type Stats,
} from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { RunStoreError } from './store-contract.js';

function pathText(path: string): void {
  if (typeof path !== 'string' || path.length === 0 || path.length > 4096
    || /[\x00-\x1f\x7f]/.test(path) || path.startsWith('file:')) {
    throw new RunStoreError('invalid_input', 'path');
  }
}
export function privateDirectory(path: string, writable = true): Stats {
  const directory = lstatSync(path), uid = process.getuid?.();
  const mode = directory.mode & 0o777;
  if (!directory.isDirectory() || directory.isSymbolicLink() || uid === undefined || directory.uid !== uid
    || (writable ? mode !== 0o700 : mode !== 0o700 && mode !== 0o500)) {
    throw new RunStoreError('unsafe_path');
  }
  return directory;
}
function canonicalPath(path: string): string {
  pathText(path);
  const absolute = resolve(path), parent = dirname(absolute);
  privateDirectory(parent);
  return resolve(realpathSync(parent), basename(absolute));
}
function privateFile(file: Stats): void {
  if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1
    || file.uid !== process.getuid?.() || (file.mode & 0o777) !== 0o600) {
    throw new RunStoreError('unsafe_path');
  }
}
export function privatePath(path: string): { path: string; existing: boolean; dev: number; ino: number } {
  try {
    const canonical = canonicalPath(path);
    let file: Stats | undefined;
    try { file = lstatSync(canonical); }
    catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
    }
    if (file) {
      privateFile(file);
      return { path: canonical, existing: true, dev: file.dev, ino: file.ino };
    }
    const descriptor = openSync(canonical, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
      | constants.O_NOFOLLOW, 0o600);
    closeSync(descriptor);
    const created = lstatSync(canonical);
    return { path: canonical, existing: false, dev: created.dev, ino: created.ino };
  } catch (error) {
    if (error instanceof RunStoreError) throw error;
    throw new RunStoreError('unsafe_path');
  }
}
export interface ClosedRunDatabaseSource {
  readonly kind: 'closed-rollback-snapshot';
  readonly path: string;
}
export function openOriginal(source: ClosedRunDatabaseSource): {
  readonly path: string; readonly descriptor: number; readonly stat: Stats;
} {
  if (source.kind !== 'closed-rollback-snapshot') throw new RunStoreError('unsafe_path');
  const path = canonicalPath(source.path), stat = lstatSync(path);
  privateFile(stat);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino) {
      throw new RunStoreError('unsafe_path');
    }
    return { path, descriptor, stat: opened };
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}
