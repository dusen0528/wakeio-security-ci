import { watch, type FSWatcher } from 'node:fs';
import { open } from 'node:fs/promises';
import { join } from 'node:path';
import { ProvisionError, provisionRecord, requireProvision } from './provision-types.js';
import { snapshotJsonData } from '../../json-snapshot.js';

/** Lima 1.0.3 foreground exec redirects stdout to ha.stdout.log, not our pipe.
 * Subscribe to its containing directory before start, then reconcile bytes on each event.
 * There is no readiness timer: the only timer is the owner's failure deadline.
 */
export class LimaEvents {
  readonly running: Promise<void>;
  readonly exiting: Promise<void>;
  private readonly watcher: FSWatcher;
  private readonly watcherClosed: Promise<void>;
  private observationClosed = false;
  private closing: Promise<void> | undefined;
  private position = 0;
  private pending = Buffer.alloc(0);
  private serial = Promise.resolve();
  private failure: Error | undefined;
  private readonly failureController = new AbortController();
  readonly failureSignal = this.failureController.signal;
  private runningSeen = false;
  private exitingSeen = false;
  private resolveRunning: () => void = () => {};
  private rejectRunning: (error: Error) => void = () => {};
  private resolveExiting: () => void = () => {};
  private rejectExiting: (error: Error) => void = () => {};
  private readonly abort = () => this.fail(new ProvisionError('boot_aborted'));

  constructor(private readonly directory: string, private readonly signal: AbortSignal) {
    this.running = new Promise((resolve, reject) => { this.resolveRunning = resolve; this.rejectRunning = reject; });
    this.exiting = new Promise((resolve, reject) => { this.resolveExiting = resolve; this.rejectExiting = reject; });
    void this.running.catch(() => undefined);
    void this.exiting.catch(() => undefined);
    this.watcher = watch(directory, (_event, name) => {
      if (name === 'ha.stdout.log') this.schedule();
    });
    this.watcherClosed = new Promise(resolve => {
      this.watcher.once('close', () => {
        this.observationClosed = true;
        if (!this.closing) this.fail(new ProvisionError('boot_event_closed'));
        resolve();
      });
    });
    this.watcher.on('error', error => this.fail(error));
    signal.addEventListener('abort', this.abort, { once: true });
    if (signal.aborted) this.abort();
    this.schedule();
  }

  waitRunning(publicSignal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const abort = () => {
        publicSignal.removeEventListener('abort', abort);
        reject(new ProvisionError('boot_aborted'));
      };
      publicSignal.addEventListener('abort', abort, { once: true });
      if (publicSignal.aborted) abort();
      void this.running.then(() => {
        publicSignal.removeEventListener('abort', abort);
        resolve();
      }, error => {
        publicSignal.removeEventListener('abort', abort);
        reject(error);
      });
    });
  }

  private schedule(): void {
    if (this.observationClosed) return;
    this.serial = this.serial.then(() => this.read()).catch(error => {
      if (!(error instanceof Error)) throw error;
      this.fail(error);
    });
  }

  private async read(): Promise<void> {
    if (this.failure) return;
    let fd;
    try { fd = await open(join(this.directory, 'ha.stdout.log'), 'r'); }
    catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT' && this.position === 0) return;
      throw error;
    }
    try {
      const info = await fd.stat();
      requireProvision(info.isFile() && info.nlink === 1 && info.uid === process.getuid?.()
        && info.size >= this.position && info.size <= 1024 * 1024, 'boot_event_identity');
      const chunk = Buffer.alloc(info.size - this.position);
      const result = await fd.read(chunk, 0, chunk.length, this.position);
      this.position += result.bytesRead;
      this.pending = Buffer.concat([this.pending, chunk.subarray(0, result.bytesRead)]);
      while (this.pending.includes(10)) {
        const end = this.pending.indexOf(10);
        const line = this.pending.subarray(0, end).toString('utf8');
        this.pending = this.pending.subarray(end + 1);
        this.frame(line);
      }
      requireProvision(this.pending.length <= 16384, 'boot_event_bound');
    } finally { await fd.close(); }
  }

  private frame(line: string): void {
    requireProvision(Buffer.byteLength(line) <= 16384, 'boot_event_bound');
    const event = provisionRecord(snapshotJsonData(JSON.parse(line)));
    const status = provisionRecord(event.status);
    requireProvision(status.degraded !== true && status.errors === undefined, 'boot_failed');
    if (status.exiting === true) {
      this.exitingSeen = true;
      this.resolveExiting();
      if (!this.runningSeen) this.fail(new ProvisionError('boot_exited'));
    }
    if (status.running === true) {
      requireProvision(!this.exitingSeen, 'boot_event_order');
      this.runningSeen = true;
      this.resolveRunning();
    }
  }

  private fail(error: Error): void {
    this.failure ??= error;
    this.failureController.abort(this.failure);
    this.rejectRunning(this.failure);
    this.rejectExiting(this.failure);
  }

  close(): Promise<void> {
    this.closing ??= Promise.resolve().then(async () => {
      this.watcher.close();
      await this.watcherClosed;
      this.signal.removeEventListener('abort', this.abort);
      await this.serial;
      if (this.failure) throw this.failure;
    });
    return this.closing;
  }
}
