import { constants, type Stats } from 'node:fs';
import { lstat, mkdtemp, open, realpath, readdir, mkdir, chmod, unlink, rmdir } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { assetGuard, assetRemaining, ProvisionAssetError } from './provision-asset-error.js';

export interface AssetIdentity {
  readonly dev: number; readonly ino: number; readonly size: number;
  readonly mode: number; readonly mtimeMs: number; readonly ctimeMs: number;
}
export interface BoundAssetFile {
  readonly path: string; readonly identity: AssetIdentity; readonly sha256: string;
}
export const ASSET_READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;

function fileIdentity(s: Stats): AssetIdentity {
  assetGuard(s.isFile() && s.uid === process.getuid?.() && s.nlink === 1
    && (s.mode & 0o022) === 0 && s.size >= 0 && s.size <= 2 * 1024 ** 3, 'identity_changed');
  return { dev: s.dev, ino: s.ino, size: s.size, mode: s.mode, mtimeMs: s.mtimeMs, ctimeMs: s.ctimeMs };
}
function equalIdentity(a: AssetIdentity, b: AssetIdentity): void {
  assetGuard(a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mode === b.mode
    && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs, 'identity_changed');
}
export async function namedAsset(path: string, fd: FileHandle): Promise<AssetIdentity> {
  const current = fileIdentity(await fd.stat());
  equalIdentity(current, fileIdentity(await lstat(path)));
  return current;
}

/** No-follow names, stable FDs, bounded regular files, no hardlinks or group/other write access. */
export async function hashAsset(path: string, signal: AbortSignal): Promise<BoundAssetFile> {
  assetRemaining(signal);
  const fd = await open(path, ASSET_READ_FLAGS);
  try {
    const before = await namedAsset(path, fd), hash = createHash('sha256'), chunk = Buffer.alloc(65536);
    let position = 0;
    while (true) {
      assetRemaining(signal);
      const { bytesRead } = await fd.read(chunk, 0, chunk.length, position);
      if (!bytesRead) break;
      position += bytesRead;
      assetGuard(position <= before.size, 'identity_changed');
      hash.update(chunk.subarray(0, bytesRead));
    }
    equalIdentity(before, await namedAsset(path, fd));
    assetGuard(position === before.size, 'identity_changed');
    return Object.freeze({ path, identity: Object.freeze(before), sha256: hash.digest('hex') });
  } finally { await fd.close(); }
}
export async function checkAsset(bound: BoundAssetFile, signal: AbortSignal): Promise<void> {
  equalIdentity(bound.identity, fileIdentity(await lstat(bound.path)));
  const current = await hashAsset(bound.path, signal);
  equalIdentity(bound.identity, current.identity);
  assetGuard(bound.sha256 === current.sha256, 'identity_changed');
}
export async function openBoundAsset(bound: BoundAssetFile, signal: AbortSignal): Promise<FileHandle> {
  await checkAsset(bound, signal);
  const fd = await open(bound.path, ASSET_READ_FLAGS);
  try {
    equalIdentity(bound.identity, await namedAsset(bound.path, fd));
    return fd;
  } catch (error) { await fd.close(); throw error; }
}

export function archivePath(raw: string): string {
  assetGuard(raw.length <= 240 && !/[^A-Za-z0-9_./+-]/.test(raw), 'archive_invalid');
  const value = raw.startsWith('./') ? raw.slice(2) : raw;
  const path = value.endsWith('/') ? value.slice(0, -1) : value;
  assetGuard(path.length > 0 && path.split('/').every(p => p !== '' && p !== '.' && p !== '..')
    && !isAbsolute(path), 'archive_invalid');
  return path;
}

/** Private namespace; never recursively delete an unenumerated or identity-substituted tree. */
export class AssetDirectory {
  private readonly directories = new Map<string, { readonly dev: number; readonly ino: number }>();
  private readonly files = new Map<string, { readonly dev: number; readonly ino: number }>();
  private closed = false;
  private constructor(readonly root: string) {}

  static async create(base: string): Promise<AssetDirectory> {
    assetGuard(isAbsolute(base) && resolve(base) === base, 'options_invalid');
    let part = '/';
    for (const name of base.split('/').filter(Boolean)) {
      part = join(part, name);
      assetGuard((await lstat(part)).isDirectory(), 'identity_changed');
    }
    assetGuard(await realpath(base) === base, 'identity_changed');
    const owner = new AssetDirectory(await mkdtemp(join(base, 'wk-t6p-assets-')));
    await chmod(owner.root, 0o700);
    const s = await lstat(owner.root);
    owner.directories.set(owner.root, { dev: s.dev, ino: s.ino });
    return owner;
  }
  async check(): Promise<void> {
    assetGuard(!this.closed, 'asset_expired');
    for (const [path, expected] of this.directories) {
      const s = await lstat(path);
      assetGuard(s.isDirectory() && s.uid === process.getuid?.() && (s.mode & 0o077) === 0
        && s.dev === expected.dev && s.ino === expected.ino, 'identity_changed');
    }
  }
  async createFile(relative: string): Promise<{ readonly path: string; readonly fd: FileHandle }> {
    await this.check();
    const path = join(this.root, archivePath(relative));
    const parents = dirname(path).slice(this.root.length).split('/').filter(Boolean);
    let parent = this.root;
    for (const name of parents) {
      parent = join(parent, name);
      if (!this.directories.has(parent)) {
        await mkdir(parent, { mode: 0o700 });
        const s = await lstat(parent);
        this.directories.set(parent, { dev: s.dev, ino: s.ino });
      }
    }
    await this.check();
    const fd = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
      | constants.O_NOFOLLOW, 0o600);
    try {
      const s = await namedAsset(path, fd);
      this.files.set(path, { dev: s.dev, ino: s.ino });
      return { path, fd };
    } catch (error) { await fd.close(); throw error; }
  }
  async freeze(): Promise<void> {
    await this.check();
    for (const path of [...this.directories.keys()].reverse()) await chmod(path, 0o500);
  }
  async cleanup(): Promise<void> {
    if (this.closed) return;
    try {
      await this.check();
      for (const [path, expected] of this.directories) {
        const known = [...this.files.keys(), ...this.directories.keys()].filter(p => dirname(p) === path);
        const names = (await readdir(path)).map(n => join(path, n));
        assetGuard(names.length === known.length && names.every(n => known.includes(n)), 'identity_changed');
        const s = await lstat(path);
        assetGuard(s.dev === expected.dev && s.ino === expected.ino, 'identity_changed');
      }
      for (const [path, expected] of this.files) {
        const s = await lstat(path);
        assetGuard(s.isFile() && s.nlink === 1 && s.uid === process.getuid?.()
          && s.dev === expected.dev && s.ino === expected.ino, 'identity_changed');
      }
      for (const path of this.directories.keys()) await chmod(path, 0o700);
      for (const path of this.files.keys()) await unlink(path);
      for (const path of [...this.directories.keys()].reverse()) await rmdir(path);
      this.closed = true;
    } catch (cause) {
      throw new ProvisionAssetError('cleanup_unconfirmed', { cause, retainedDirectory: this.root });
    }
  }
}
