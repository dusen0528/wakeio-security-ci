import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, realpath, unlink } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { types } from 'node:util';
import { JSON_MAX_INPUT_BYTES, snapshotJsonData } from '../json-snapshot.js';
import type { ArtifactRef, ArtifactVault, RuntimeGap, Stage, StageBinding } from './types.js';

const MAX_BYTES = 64 * 1024 * 1024;
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
function invalid(): never { throw new TypeError('invalid_runtime_artifact'); }
function record(value: unknown): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
}
function keys(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some(key => !Object.hasOwn(value, key))
    || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) invalid();
}
function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value || value.length > 120 || /[\x00-\x1f\x7f]/.test(value)) invalid();
}
function filename(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,119}$/.test(value)) invalid();
}
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
function typedField(name: string, value: Uint8Array): unknown {
  const getter = Object.getOwnPropertyDescriptor(typedArrayPrototype, name)?.get;
  if (!getter) invalid();
  return getter.call(value);
}
function byteSnapshot(raw: Uint8Array): Buffer {
  if (types.isProxy(raw) || !types.isUint8Array(raw)) invalid();
  const length = typedField('byteLength', raw), offset = typedField('byteOffset', raw);
  const buffer = typedField('buffer', raw);
  if (typeof length !== 'number' || length > MAX_BYTES || typeof offset !== 'number'
    || !types.isArrayBuffer(buffer)) invalid();
  return Buffer.from(new Uint8Array(buffer, offset, length));
}
function reference(raw: unknown): ArtifactRef {
  record(raw); keys(raw, ['path', 'bytes', 'sha256']); filename(raw.path);
  if (typeof raw.bytes !== 'number' || !Number.isSafeInteger(raw.bytes) || raw.bytes < 0 || raw.bytes > MAX_BYTES
    || typeof raw.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(raw.sha256)) invalid();
  return { path: raw.path, bytes: raw.bytes, sha256: raw.sha256 };
}
function stageData(raw: unknown): Stage<unknown> {
  record(raw); keys(raw, ['schema', 'stage', 'runId', 'epoch', 'runNonce', 'inputs', 'output', 'status', 'gaps']);
  if (raw.schema !== 'wakeio.verify-stage/v1' || !Array.isArray(raw.inputs) || raw.inputs.length > 256
    || !Array.isArray(raw.gaps) || raw.gaps.length > 256) invalid();
  text(raw.stage); text(raw.runId); text(raw.epoch); text(raw.runNonce);
  const status = raw.status;
  if (status !== 'completed' && status !== 'partial' && status !== 'error') invalid();
  const inputs = raw.inputs.map(reference);
  if (new Set(inputs.map(input => input.path)).size !== inputs.length) invalid();
  const gaps: RuntimeGap[] = raw.gaps.map(value => {
    record(value); keys(value, ['area', 'code'], ['surfaceId']); text(value.area); text(value.code);
    if (Object.hasOwn(value, 'surfaceId')) text(value.surfaceId);
    return { area: value.area, code: value.code,
      ...(typeof value.surfaceId === 'string' ? { surfaceId: value.surfaceId } : {}) };
  });
  return { schema: raw.schema, stage: raw.stage, runId: raw.runId, epoch: raw.epoch, runNonce: raw.runNonce,
    inputs, output: raw.output, status, gaps };
}
function bindingData(raw: StageBinding): StageBinding {
  const data = snapshotJsonData(raw); record(data); keys(data, ['stage', 'runId', 'epoch', 'runNonce', 'inputs']);
  return stageData({ ...data, schema: 'wakeio.verify-stage/v1', output: null, status: 'completed', gaps: [] });
}
/** Placement guard only. R10's full report parser must still validate every report field. */
export function assertRuntimeScopeLocation(raw: unknown): void {
  const data = snapshotJsonData(raw); record(data);
  if (data.mode !== 'runtime' || Object.hasOwn(data, 'scope')) invalid();
  record(data.runtime);
  if (data.runtime.revision !== 'verify-m1-v1' || !Object.hasOwn(data.runtime, 'scope')) invalid();
  record(data.runtime.scope);
}
async function directory(raw: string) {
  if (typeof raw !== 'string' || !raw || /[\x00-\x1f\x7f]/.test(raw)) invalid();
  const absolute = resolve(raw); let current = resolve(absolute, '/');
  for (const part of absolute.slice(current.length).split(sep).filter(Boolean)) {
    current = join(current, part); const info = await lstat(current);
    if (info.isSymbolicLink()) {
      if (process.platform !== 'darwin' || !['/tmp', '/var'].includes(current)
        || await realpath(current) !== '/private' + current) invalid();
    } else if (!info.isDirectory()) invalid();
  }
  const path = await realpath(absolute), info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) invalid();
  return { path, dev: info.dev, ino: info.ino, mode: info.mode };
}
function within(path: string, parent: string): boolean {
  const part = relative(parent, path); return part === '' || !part.startsWith('..' + sep) && part !== '..';
}

class Vault {
  constructor(readonly root: string, private readonly identity: Awaited<ReturnType<typeof directory>>) {}
  private async checkRoot(): Promise<void> {
    const now = await directory(this.root);
    if (now.path !== this.root || now.dev !== this.identity.dev || now.ino !== this.identity.ino
      || (now.mode & 0o777) !== 0o700) invalid();
  }
  async readBytes(raw: ArtifactRef): Promise<Buffer> {
    const ref = reference(snapshotJsonData(raw)); await this.checkRoot();
    const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
    const handle = await open(join(this.root, ref.path), flags);
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o777) !== 0o600
        || before.size !== ref.bytes || before.size > MAX_BYTES) invalid();
      const buffer = Buffer.alloc(before.size + 1); let used = 0;
      while (used < buffer.length) {
        const result = await handle.read(buffer, used, buffer.length - used, used);
        if (!result.bytesRead) break; used += result.bytesRead;
      }
      const after = await handle.stat(), named = await lstat(join(this.root, ref.path));
      if (used !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs || after.nlink !== 1 || named.isSymbolicLink()
        || before.dev !== named.dev || before.ino !== named.ino
        || sha(buffer.subarray(0, used)) !== ref.sha256) invalid();
      await this.checkRoot(); return buffer.subarray(0, used);
    } finally { await handle.close(); }
  }
  async writeBytes(path: string, raw: Uint8Array): Promise<ArtifactRef> {
    filename(path);
    const bytes = byteSnapshot(raw), temporary = join(this.root, `.pending-${randomUUID()}`);
    await this.checkRoot();
    const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try {
      await handle.writeFile(bytes); await handle.sync(); await this.checkRoot();
      // link is an atomic no-replace publication; rename would overwrite a racing destination.
      await link(temporary, join(this.root, path)); await unlink(temporary);
      const ref = { path, bytes: bytes.length, sha256: sha(bytes) };
      await this.readBytes(ref); return Object.freeze(ref);
    } finally { await handle.close(); await unlink(temporary).catch(() => undefined); }
  }
  private async verifyChain(inputs: ArtifactRef[], context: StageBinding, ownBytes: number): Promise<void> {
    const seen = new Set<string>(), active = new Set<string>(); let total = ownBytes;
    const visit = async (ref: ArtifactRef, depth: number): Promise<void> => {
      if (depth > 16 || active.has(ref.path)) invalid();
      const key = ref.path + ':' + ref.sha256;
      if (seen.has(key)) return;
      if (seen.size + 1 >= 256) invalid(); // Include the root Stage in the chain bound.
      const bytes = await this.readBytes(ref); total += bytes.length;
      if (total > MAX_BYTES) invalid();
      seen.add(key); active.add(ref.path);
      let data: unknown;
      if (ref.path.endsWith('.json') && bytes.length > JSON_MAX_INPUT_BYTES) invalid();
      try {
        data = bytes.length <= JSON_MAX_INPUT_BYTES
          ? JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) : null;
      } catch { data = null; }
      if (data && typeof data === 'object' && Object.hasOwn(data, 'schema')
        && 'schema' in data && data.schema === 'wakeio.verify-stage/v1') {
        const stage = stageData(snapshotJsonData(data));
        if (stage.runId !== context.runId || stage.epoch !== context.epoch
          || stage.runNonce !== context.runNonce) invalid();
        for (const input of stage.inputs) await visit(input, depth + 1);
      }
      active.delete(ref.path);
    };
    for (const input of inputs) await visit(input, 1);
  }
  async writeStage(path: string, raw: Stage<unknown>): Promise<ArtifactRef> {
    filename(path); if (!path.endsWith('.json')) invalid();
    const stage = stageData(snapshotJsonData(raw));
    const bytes = Buffer.from(JSON.stringify(stage) + '\n');
    if (bytes.length > JSON_MAX_INPUT_BYTES) invalid();
    await this.verifyChain(stage.inputs, stage, bytes.length);
    return this.writeBytes(path, bytes);
  }
  async readStage(ref: ArtifactRef, rawBinding: StageBinding): Promise<Stage<unknown>> {
    const selected = reference(snapshotJsonData(ref)); if (!selected.path.endsWith('.json')) invalid();
    const binding = bindingData(rawBinding);
    const bytes = await this.readBytes(selected);
    if (bytes.length > JSON_MAX_INPUT_BYTES) invalid();
    const stage = stageData(snapshotJsonData(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))));
    if (stage.stage !== binding.stage || stage.runId !== binding.runId || stage.epoch !== binding.epoch
      || stage.runNonce !== binding.runNonce
      || JSON.stringify(stage.inputs) !== JSON.stringify(binding.inputs)) invalid();
    await this.verifyChain(stage.inputs, binding, bytes.length); return stage;
  }
}

function safe<A extends unknown[], R>(fn: (...args: A) => Promise<R>) {
  return async (...args: A): Promise<R> => { try { return await fn(...args); } catch { return invalid(); } };
}

/** New, private, flat vault only: target containers must never receive this directory. */
export async function createArtifactVault(source: string, destination: string): Promise<ArtifactVault> {
  try {
    if (typeof destination !== 'string' || !destination || /[\x00-\x1f\x7f]/.test(destination)) invalid();
    const sourceDir = await directory(source), parent = await directory(dirname(destination));
    const name = destination.slice(destination.lastIndexOf(sep) + 1); filename(name);
    const root = join(parent.path, name);
    if (within(root, sourceDir.path)) invalid();
    await mkdir(root, { mode: 0o700 });
    const identity = await directory(root);
    if ((identity.mode & 0o777) !== 0o700) invalid();
    const vault = new Vault(root, identity);
    return Object.freeze({ root, writeBytes: safe(vault.writeBytes.bind(vault)),
      readBytes: safe(vault.readBytes.bind(vault)), writeStage: safe(vault.writeStage.bind(vault)),
      readStage: safe(vault.readStage.bind(vault)) });
  } catch { return invalid(); }
}
