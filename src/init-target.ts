import { createHash, randomUUID } from 'node:crypto';
import { constants, type Stats } from 'node:fs';
import { link, lstat, open, realpath, unlink } from 'node:fs/promises';
import { basename, dirname, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify } from 'yaml';
import { parseFrameworkPackYaml, type FrameworkPack } from './runtime/packs/schema.js';
import { parseTargetSpec, parseTargetYaml } from './runtime/target.js';

const CAP = 256 * 1024;
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
function fail(reason = 'unsafe_init_target_path'): never { throw new Error(reason); }
type Directory = { path: string; chain: Array<{ path: string; dev: number; ino: number }> };
export interface InitTargetDraft {
  status: 'draft'; pack: { id: string; version: number; sha256: string };
  detection: Array<{ file: string; sha256: string; reason: 'pack_detect_match' }>;
  missing: readonly string[];
}

async function directory(raw: string): Promise<Directory> {
  let current = parse(resolve(raw)).root;
  for (const part of resolve(raw).slice(current.length).split(sep).filter(Boolean)) {
    current = join(current, part); const info = await lstat(current);
    if (info.isSymbolicLink()) {
      if (process.platform !== 'darwin' || !['/tmp', '/var'].includes(current)
        || await realpath(current) !== '/private' + current) fail();
    } else if (!info.isDirectory()) fail();
  }
  const path = await realpath(raw), chain: Directory['chain'] = [];
  current = parse(path).root;
  for (const part of path.slice(current.length).split(sep).filter(Boolean)) {
    current = join(current, part); const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) fail();
    chain.push({ path: current, dev: info.dev, ino: info.ino });
  }
  return { path, chain };
}
async function unchanged(dir: Directory): Promise<void> {
  for (const saved of dir.chain) {
    const info = await lstat(saved.path);
    if (!info.isDirectory() || info.isSymbolicLink() || info.dev !== saved.dev || info.ino !== saved.ino) fail();
  }
}
function same(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.nlink === right.nlink && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}
async function bytes(file: string, parent: Directory): Promise<Buffer> {
  await unchanged(parent);
  const named = await lstat(file);
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1 || named.size > CAP) fail();
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!same(named, before) || !before.isFile()) fail();
    const buffer = Buffer.alloc(before.size + 1); let count = 0;
    while (count < buffer.length) {
      const read = await handle.read(buffer, count, buffer.length - count, count);
      if (!read.bytesRead) break; count += read.bytesRead;
    }
    if (count !== before.size || !same(before, await handle.stat()) || !same(before, await lstat(file))) fail();
    await unchanged(parent); return buffer.subarray(0, count);
  } finally { await handle.close(); }
}
const text = (raw: Buffer) => new TextDecoder('utf-8', { fatal: true }).decode(raw);

/** Tool-local assets only: emitted npm module and generated Action have different depths. */
async function builtinPack(): Promise<{ pack: FrameworkPack; sha256: string }> {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const emitted = basename(here) === 'src' && basename(dirname(here)) === 'build';
    if (!emitted && basename(here) !== 'dist-action') fail();
    const path = resolve(here, emitted ? '../../packs' : '../packs');
    const parent = await directory(path), raw = await bytes(join(parent.path, 'spring-boot.v1.yml'), parent);
    return { pack: parseFrameworkPackYaml(text(raw)), sha256: hash(raw) };
  } catch { return fail('invalid_builtin_pack'); }
}
async function detect(source: Directory, pack: FrameworkPack): Promise<InitTargetDraft['detection']> {
  const found: InitTargetDraft['detection'] = [];
  for (const file of pack.detect.anyFile) {
    try {
      await unchanged(source);
      const parent = await directory(dirname(join(source.path, file)));
      const raw = await bytes(join(parent.path, basename(file)), parent);
      if (pack.detect.contains.some(token => text(raw).includes(token))) {
        found.push({ file, sha256: hash(raw), reason: 'pack_detect_match' });
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') fail('invalid_init_target_source');
    }
  }
  await unchanged(source);
  if (!found.length) fail('unsupported_runtime_source');
  return found;
}
async function absent(output: string): Promise<void> {
  try { await lstat(output); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  fail('init_target_output_exists');
}
async function publish(parent: Directory, output: string, yaml: string): Promise<void> {
  await unchanged(parent); await absent(output);
  const temporary = join(parent.path, `.wakeio-target-${randomUUID()}.tmp`);
  const handle = await open(temporary,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(yaml); await handle.sync(); await unchanged(parent);
    const written = await handle.stat(), named = await lstat(temporary);
    if (!same(written, named) || named.nlink !== 1 || (named.mode & 0o777) !== 0o600) fail();
    // Atomic no-replace: a competing writer cannot overwrite an existing destination.
    try { await link(temporary, output); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') fail('init_target_output_exists');
      throw error;
    }
    await unlink(temporary); await unchanged(parent);
  } finally {
    await handle.close();
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

/** No scripts, subprocess, target traffic or env inheritance; only bounded data reads and a new draft. */
export async function writeInitTargetDraft(sourceInput: string, outputInput: string): Promise<InitTargetDraft> {
  for (const value of [sourceInput, outputInput]) {
    if (typeof value !== 'string' || !value.trim() || /[\x00-\x1f\x7f\\]/.test(value)
      || value.split('/').includes('..')) fail();
  }
  const source = await directory(resolve(sourceInput)), parent = await directory(dirname(resolve(outputInput)));
  const output = join(parent.path, basename(resolve(outputInput)));
  if (output === source.path || output.startsWith(source.path + sep)) fail();
  const sourceRef = relative(parent.path, source.path).split(sep).join('/');
  if (!sourceRef || sourceRef.length > 512 || sourceRef.split('/').some(part => part === '.' || part === '..'
    || !/^[\w.][\w.-]*$/.test(part))) fail('init_target_source_reference');
  await absent(output);
  const loaded = await builtinPack(), detection = await detect(source, loaded.pack), pack = loaded.pack;
  const missing = ['compose_file', 'compose_service', 'dependencies', 'seed_sql', 'scope_review'];
  // PLAN 10's bounded example values; endpoint and port come exclusively from Pack data.
  const draft = parseTargetSpec({ version: 1, project: 'runtime-draft', source: sourceRef,
    build: { kind: 'compose', file: 'compose.runtime.missing.json', service: 'app' },
    pack: { id: pack.id, version: pack.version },
    entry: { port: pack.runtime.defaultPort, health: pack.runtime.health, startupTimeoutSec: 180 },
    dependencies: [], seed: { sql: [], snapshot: 'per-request' }, scope: { include: ['/**'], exclude: [] },
    budget: { maxRequests: 2000, maxMinutes: 15, ratePerSecond: 1 } });
  const result: InitTargetDraft = { status: 'draft',
    pack: { id: pack.id, version: pack.version, sha256: loaded.sha256 },
    detection, missing };
  const comments = ['# Draft only; compose, service, dependencies, seed and scope require review.',
    '# Pack detection is not source-routes or binding-hint compiler/execution support.',
    '# ' + JSON.stringify(result)];
  const yaml = comments.join('\n') + '\n' + stringify(draft);
  if (JSON.stringify(parseTargetYaml(yaml)) !== JSON.stringify(draft)) fail('invalid_init_target_source');
  await unchanged(source); await publish(parent, output, yaml); return result;
}
