import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { isAbsolute, join } from 'node:path';
import { ProvisionError, requireProvision } from './provision-types.js';

export interface ProvisionCommand {
  readonly executable: string;
  readonly argv: readonly string[];
  readonly home: string;
  readonly limaHome: string;
  readonly temporary: string;
}

export interface ClosedProvisionProcess {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly groupAbsent: boolean;
}

/** Adapted from immutable M1 process.ts argv/minimal-env guards.
 * Unlike its polling adapter, close is never synthesized from a timeout or kill request.
 * A surviving PGID after close is retained, not polled into an invented cleanup receipt.
 */
export class ProvisionProcess {
  readonly child: ChildProcessWithoutNullStreams;
  readonly closed: Promise<ClosedProvisionProcess>;
  private closedObserved = false;
  private stopping = false;
  private observed = false;
  private signalFailed = false;
  private killTimer: NodeJS.Timeout | undefined;
  private readonly abort = () => this.stop();

  constructor(command: ProvisionCommand, private readonly signal: AbortSignal) {
    requireProvision(!signal.aborted, 'operation_aborted');
    requireProvision([command.executable, command.home, command.limaHome, command.temporary]
      .every(path => isAbsolute(path) && !/[\0\r\n]/.test(path)), 'command_invalid');
    requireProvision(command.argv.length <= 256 && command.argv.every(arg => !arg.includes('\0'))
      && Buffer.byteLength(command.argv.join('\0')) <= 65536, 'command_invalid');
    this.child = spawn(command.executable, [...command.argv], {
      cwd: command.home, shell: false, detached: true, stdio: ['pipe', 'pipe', 'pipe'],
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'C', LANG: 'C',
        HOME: command.home, LIMA_HOME: command.limaHome, TMPDIR: command.temporary,
        RUN_TMP: command.temporary, NODE_COMPILE_CACHE: join(command.temporary, 'node'),
        BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(command.temporary, 'bun'),
        XDG_CACHE_HOME: join(command.home, '.cache'), XDG_CONFIG_HOME: join(command.home, '.config'),
        XDG_DATA_HOME: join(command.home, '.local/share') },
    });
    this.closed = new Promise(resolve => {
      this.child.once('close', (code, exitSignal) => {
        this.closedObserved = true;
        clearTimeout(this.killTimer);
        signal.removeEventListener('abort', this.abort);
        let groupAbsent = this.child.pid === undefined;
        if (this.child.pid !== undefined) {
          try { process.kill(-this.child.pid, 0); }
          catch (error) {
            groupAbsent = error instanceof Error && 'code' in error && error.code === 'ESRCH';
          }
        }
        resolve(Object.freeze({ code, signal: exitSignal,
          groupAbsent: groupAbsent && !this.signalFailed }));
      });
    });
    // Errors do not prove close; Node emits close separately after spawn failure.
    this.child.once('error', this.abort);
    this.child.stdin.on('error', this.abort);
    signal.addEventListener('abort', this.abort, { once: true });
    if (signal.aborted) this.abort();
  }

  stop(): void {
    if (this.closedObserved || this.stopping) return;
    this.stopping = true;
    if (this.send('SIGINT')) this.killTimer = setTimeout(() => this.send('SIGKILL'), 5_000);
  }

  private send(signal: NodeJS.Signals): boolean {
    if (this.closedObserved || this.child.pid === undefined) return false;
    try { process.kill(-this.child.pid, signal); return true; }
    catch (error) {
      if (!(error instanceof Error) || !('code' in error) || error.code !== 'ESRCH') {
        this.signalFailed = true;
      }
      // ESRCH is not a close acknowledgement and never resolves this.closed.
      return false;
    }
  }

  async output(input?: string): Promise<string> {
    const result = await this.capture(input, true);
    requireProvision(result.code === 0 && result.signal === null, 'command_failed');
    return result.stdout;
  }

  observeOpenInput() { return this.capture(undefined, false); }

  private async capture(input: string | undefined, endInput: boolean) {
    requireProvision(!this.observed, 'command_output_replay');
    this.observed = true;
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    let bytes = 0, failed = false;
    const append = (chunks: Buffer[], chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 1024 * 1024) { failed = true; this.stop(); }
      else chunks.push(chunk);
    };
    const out = (chunk: Buffer) => append(stdout, chunk), err = (chunk: Buffer) => append(stderr, chunk);
    this.child.stdout.on('data', out);
    this.child.stderr.on('data', err);
    void this.closed.then(() => {
      this.child.stdout.removeListener('data', out);
      this.child.stderr.removeListener('data', err);
    });
    let cancel = () => {};
    const cancelled = new Promise<never>((_resolve, reject) => {
      cancel = () => reject(new ProvisionError('command_aborted'));
      this.signal.addEventListener('abort', cancel, { once: true });
      if (this.signal.aborted) cancel();
    });
    try {
      if (endInput) this.child.stdin.end(input);
      const result = await Promise.race([this.closed, cancelled]);
      requireProvision(!failed && !this.signal.aborted && result.groupAbsent, 'command_failed');
      return Object.freeze({ ...result, stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8') });
    } finally { this.signal.removeEventListener('abort', cancel); }
  }

  async drain(): Promise<void> {
    const result = await this.closed;
    if (!result.groupAbsent) throw new ProvisionError('process_group_unconfirmed',
      this.child.pid === undefined ? [] : [String(this.child.pid)]);
  }
}
