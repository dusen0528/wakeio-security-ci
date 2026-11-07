import { constants, fstatSync, type Stats } from 'node:fs';
import { lstat, open, realpath, mkdtemp, chmod, mkdir, readdir, unlink, rmdir } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { ProvisionError, requireProvision } from './provision-types.js';

interface FileIdentity {
  readonly uid: number;
  readonly dev: number;
  readonly ino: number;
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
}

function identity(s: Stats, uid = process.getuid?.()): FileIdentity {
  requireProvision(s.isFile() && s.nlink === 1 && s.uid === uid
    && (s.mode & 0o022) === 0, 'file_identity_changed');
  return { uid: s.uid, dev: s.dev, ino: s.ino, size: s.size, mtimeMs: s.mtimeMs, ctimeMs: s.ctimeMs };
}

function equal(a: FileIdentity, b: FileIdentity): void {
  requireProvision(a.uid === b.uid && a.dev === b.dev && a.ino === b.ino && a.size === b.size
    && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs, 'file_identity_changed');
}

/** Narrow reuse of immutable M1 namedFile/capture guards, retaining the original FD. */
export class ProvisionFile {
  private constructor(readonly path: string, private readonly handle: FileHandle,
    private readonly original: FileIdentity) {}

  static async open(path: string, uid = process.getuid?.()): Promise<ProvisionFile> {
    requireProvision(await realpath(dirname(path)) === dirname(path), 'file_parent_changed');
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const file = new ProvisionFile(path, handle, identity(await handle.stat(), uid));
      await file.check();
      return file;
    } catch (error) { await handle.close(); throw error; }
  }

  /** Join the producer's still-open original descriptor, not a newly captured name. */
  static async borrow(path: string, fd: number): Promise<ProvisionFile> {
    const original = identity(fstatSync(fd));
    const file = await ProvisionFile.open(path);
    try {
      equal(original, file.original);
      equal(original, identity(fstatSync(fd)));
      return file;
    } catch (error) { await file.close(); throw error; }
  }

  async check(): Promise<void> {
    equal(this.original, identity(await this.handle.stat(), this.original.uid));
    equal(this.original, identity(await lstat(this.path), this.original.uid));
  }

  async bytes(limit: number): Promise<Buffer> {
    await this.check();
    requireProvision(this.original.size > 0 && this.original.size <= limit, 'file_bound');
    const bytes = Buffer.alloc(this.original.size + 1);
    const result = await this.handle.read(bytes, 0, bytes.length, 0);
    requireProvision(result.bytesRead === this.original.size, 'file_identity_changed');
    await this.check();
    return bytes.subarray(0, this.original.size);
  }

  async digest(limit: number): Promise<string> {
    return createHash('sha256').update(await this.bytes(limit)).digest('hex');
  }

  close(): Promise<void> { return this.handle.close(); }
}

/** Only explicitly allocated files/directories enter the removal ledger. */
export class ProvisionDirectory {
  private readonly directories = new Map<string, { readonly dev: number; readonly ino: number }>();
  private readonly files = new Map<string, FileIdentity>();
  private constructor(readonly root: string) {}

  static async create(): Promise<ProvisionDirectory> {
    const base = process.platform === 'darwin' ? '/private/tmp' : '/tmp';
    requireProvision(await realpath(base) === base, 'directory_identity_changed');
    const owner = new ProvisionDirectory(await mkdtemp(join(base, 'wk-t6p-')));
    await chmod(owner.root, 0o700);
    owner.directories.set(owner.root, await lstat(owner.root));
    return owner;
  }

  async check(): Promise<void> {
    for (const [path, expected] of this.directories) {
      const s = await lstat(path);
      requireProvision(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid?.()
        && (s.mode & 0o077) === 0 && s.dev === expected.dev && s.ino === expected.ino,
      'directory_identity_changed');
    }
  }

  async directory(relative: string): Promise<string> {
    requireProvision(/^[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*$/.test(relative)
      && !relative.split('/').some(part => part === '.' || part === '..'), 'directory_path_invalid');
    await this.check();
    let path = this.root;
    for (const part of relative.split('/')) {
      path = join(path, part);
      if (!this.directories.has(path)) {
        await mkdir(path, { mode: 0o700 });
        this.directories.set(path, await lstat(path));
      }
    }
    return path;
  }

  async write(name: string, bytes: string | Buffer): Promise<string> {
    requireProvision(/^[a-zA-Z0-9_.-]+$/.test(name) && name !== '.' && name !== '..', 'file_path_invalid');
    await this.check();
    const path = join(this.root, name);
    const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
      | constants.O_NOFOLLOW, 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
      this.files.set(path, identity(await handle.stat()));
    } finally { await handle.close(); }
    return path;
  }

  async cleanup(): Promise<boolean> {
    await this.check();
    for (const path of this.directories.keys()) {
      const known = [...this.directories.keys(), ...this.files.keys()].filter(item => dirname(item) === path);
      const actual = (await readdir(path)).map(name => join(path, name));
      if (actual.length !== known.length || actual.some(item => !known.includes(item))) return false;
    }
    for (const [path, expected] of this.files) {
      const current = identity(await lstat(path));
      equal(current, expected);
    }
    for (const path of this.files.keys()) await unlink(path);
    for (const path of [...this.directories.keys()].reverse()) await rmdir(path);
    return true;
  }

  /** Pinned Lima creates only these global key/config entries in this fresh namespace.
   * Unknown entries remain unowned and force retention at cleanup.
   */
  async captureLimaConfig(): Promise<void> {
    await this.check();
    const path = join(this.root, '.lima/_config');
    const info = await lstat(path);
    requireProvision(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid?.()
      && (info.mode & 0o077) === 0 && !this.directories.has(path), 'lima_config_identity');
    const names = await readdir(path);
    requireProvision(names.includes('user') && names.includes('user.pub')
      && names.every(name => ['user', 'user.pub', 'networks.yaml'].includes(name)), 'lima_config_entries');
    this.directories.set(path, { dev: info.dev, ino: info.ino });
    for (const name of names) this.files.set(join(path, name), identity(await lstat(join(path, name))));
  }
}

export async function provisionAbsent(path: string): Promise<boolean> {
  try { await lstat(path); return false; }
  catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return true;
    throw new ProvisionError('absence_unconfirmed', [path], { cause: error });
  }
}
