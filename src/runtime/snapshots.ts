import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import { snapshotJsonData } from '../json-snapshot.js';
import { cleanupObservation, invalid, observation, record, SourceSnapshotError } from './source-snapshot-protocol.js';
import type {
  Selection, SourceSnapshotCleanupObservation, SourceSnapshotObservation,
} from './source-snapshot-protocol.js';
export { SourceSnapshotError } from './source-snapshot-protocol.js';
export type { SourceSnapshotObservation } from './source-snapshot-protocol.js';

class Handle {
  readonly #brand = 'source-snapshot';
}
export type SourceSnapshotHandle = Handle;
type Request = {
  readonly executeTargetConsent: true;
  readonly sourceRoot: string;
  readonly build: readonly string[];
  readonly scanner: readonly string[];
};
const active = new WeakMap<object, Session>();
const MAX_OUTPUT = 2 * 1024 * 1024;

function files(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 5) invalid();
  return value.map(item => {
    if (typeof item !== 'string' || item.length > 256) invalid();
    return item;
  });
}
function request(raw: unknown): Request {
  // This gate precedes even the JSON snapshot traversal, and never invokes a proxy trap/getter.
  if (!raw || typeof raw !== 'object' || types.isProxy(raw)) throw new SourceSnapshotError('consent');
  const consent = Object.getOwnPropertyDescriptor(raw, 'executeTargetConsent');
  if (!consent || !('value' in consent) || consent.value !== true) throw new SourceSnapshotError('consent');
  const data = snapshotJsonData(raw, invalid);
  record(data);
  if (Object.keys(data).sort().join(',') !== 'build,executeTargetConsent,scanner,sourceRoot'
    || typeof data['sourceRoot'] !== 'string') invalid();
  return { executeTargetConsent: true, sourceRoot: data['sourceRoot'],
    build: files(data['build']), scanner: files(data['scanner']) };
}

class Session {
  readonly child;
  readonly lines;
  readonly closed: Promise<{ readonly code: number | null; readonly signal: NodeJS.Signals | null }>;
  private queue: Promise<unknown> = Promise.resolve();
  private fault: Error | undefined;
  private outputBytes = 0;
  private clean = false;
  private failed = false;
  private readonly received: Record<string, unknown>[] = [];
  private recovery: SourceSnapshotCleanupObservation | undefined;

  constructor() {
    const script = fileURLToPath(new URL('../../../workers/runtime-source/snapshot.py', import.meta.url));
    this.child = spawn('/usr/bin/python3', ['-I', '-S', '-B', script], {
      cwd: '/', env: { LANG: 'C', LC_ALL: 'C' }, shell: false, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.closed = new Promise(resolve => {
      this.child.once('close', (code, signal) => resolve({ code, signal }));
    });
    this.child.on('error', error => { this.fault = error; });
    this.child.stdin.on('error', error => { this.fault = error; });
    this.child.stdout.on('data', (chunk: Buffer) => {
      this.outputBytes += chunk.length;
      if (this.outputBytes > MAX_OUTPUT) {
        this.fault = new SourceSnapshotError('refused');
        this.child.kill('SIGTERM');
      }
    });
    this.child.stderr.on('data', () => {
      this.fault = new SourceSnapshotError('refused');
      this.child.kill('SIGTERM');
    });
    const reader = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    reader.on('line', line => {
      try {
        const value: unknown = JSON.parse(line);
        record(value);
        if ('cleanup' in value) this.recovery = cleanupObservation(value['cleanup']);
        this.received.push(value);
        if (this.received.length > 128) throw new SourceSnapshotError('refused');
      } catch (error) {
        this.fault = error instanceof Error ? error : new SourceSnapshotError('refused');
        this.child.kill('SIGTERM');
      }
    });
    this.lines = reader[Symbol.asyncIterator]();
  }

  private async bounded<T>(pending: Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        this.fault = new SourceSnapshotError('cleanup_unknown', this.recovery);
        this.child.kill('SIGKILL');
        reject(this.fault);
      }, 5000);
    });
    try {
      return await Promise.race([pending, deadline]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async next(): Promise<unknown> {
    for (;;) {
      const line = await this.bounded(this.lines.next());
      if (line.done || this.fault) throw this.fault ?? new SourceSnapshotError('refused');
      const value = this.received.shift();
      if (!value) throw new SourceSnapshotError('refused');
      if ('cleanup' in value) continue;
      if ('error' in value) throw new SourceSnapshotError('refused');
      if (value['closed'] === true) this.clean = true;
      return value;
    }
  }

  exchange(value: unknown): Promise<unknown> {
    const result = this.queue.then(async () => {
      if (this.fault || this.child.exitCode !== null) throw new SourceSnapshotError('refused');
      this.outputBytes = 0;
      this.child.stdin.write(JSON.stringify(value) + '\n');
      return this.next();
    });
    this.queue = result.then(() => undefined, () => { this.failed = true; });
    return result;
  }

  async finish(): Promise<void> {
    await this.queue;
    try {
      if (!this.fault) {
        if (this.failed) await this.next();
        else await this.exchange({ op: 'close' });
      }
    } finally {
      this.child.stdin.end();
      const closed = await this.bounded(this.closed);
      await this.lines.return?.();
      if (closed.code !== 0 || closed.signal !== null || !this.clean) {
        throw new SourceSnapshotError('cleanup_unknown', this.recovery);
      }
    }
  }
}

function session(handle: unknown): Session {
  if (!handle || typeof handle !== 'object' || types.isProxy(handle)) throw new SourceSnapshotError('revoked');
  const owner = active.get(handle);
  if (!owner) throw new SourceSnapshotError('revoked');
  return owner;
}

/** Observations are data only: these paths grant no target, mount, or backend authority. */
export async function observeSourceSnapshot(handle: unknown): Promise<SourceSnapshotObservation> {
  const owner = session(handle);
  const result = observation(await owner.exchange({ op: 'observe' }));
  session(handle);
  return result;
}

export async function readSourceSnapshot(handle: unknown, raw: Selection): Promise<Buffer> {
  const owner = session(handle);
  const selection = snapshotJsonData(raw, invalid);
  record(selection);
  const receipt = await observeSourceSnapshot(handle);
  const file = receipt.files.find(row => row.role === selection['role'] && row.path === selection['path']);
  if (!file) invalid();
  const result = await owner.exchange({ op: 'read', role: file.role, path: file.path });
  session(handle);
  record(result);
  const encoded = result['data'];
  if (typeof encoded !== 'string') invalid();
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length !== file.bytes || createHash('sha256').update(bytes).digest('hex') !== file.sha256) invalid();
  return bytes;
}

/** Capture first; issue only an original, callback-scoped identity. Never adopts caller receipts. */
export async function withSourceSnapshot<T>(
  raw: unknown, callback: (handle: SourceSnapshotHandle) => Promise<T>,
): Promise<T> {
  const input = request(raw);
  const owner = new Session();
  const handle = new Handle();
  Object.freeze(handle);
  owner.child.once('close', () => { active.delete(handle); });
  try {
    observation(await owner.exchange(input));
    active.set(handle, owner);
    return await callback(handle);
  } finally {
    active.delete(handle);
    await owner.finish();
  }
}
