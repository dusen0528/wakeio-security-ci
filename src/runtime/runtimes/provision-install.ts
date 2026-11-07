import { randomBytes } from 'node:crypto';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';

export class InstallOperationError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'InstallOperationError';
  }
}

export interface InstallObservation {
  readonly kind: 'install-observation';
  readonly preparationSha256: string;
  readonly hookSha256: string;
  readonly installedStatusSha256: string;
  readonly backendVerified: false;
  readonly sourceExecutionAuthorized: false;
  readonly daemonObserved: false;
}

/** Trusted guest-controller composition only. This is not an executor or a backend handle.
 * The controller must keep its live VM/boot/assets owner until this child closes.
 * Run argv through the authenticated fixed guest-admin transport, never on the host.
 */
export function installInvocation(): Readonly<{ unit: string; argv: readonly string[] }> {
  const unit = `wakeio-install-${randomBytes(16).toString('hex')}.service`;
  return Object.freeze({ unit, argv: Object.freeze([
    '/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect', '--service-type=exec',
    `--unit=${unit}`, '--property=CPUQuota=200%', '--property=MemoryMax=4294967296',
    '--property=TasksMax=256', '--property=RuntimeMaxSec=900', '--property=TimeoutStopSec=120',
    '--property=KillMode=control-group', '--property=UMask=0077',
    '/usr/bin/python3', '-I', '-B', '/usr/local/lib/wakeio-install/install_supervisor.py',
  ]) });
}

const consumed = new WeakSet<ChildProcessWithoutNullStreams>();

export interface InstallOperation {
  readonly result: Promise<InstallObservation>;
  /** Resolves ONLY on the real child close event, never on abort or timeout.
   * Local transport closure is NOT confirmation of guest unit/descendant cleanup.
   * The controller retains all asset borrowers until both this and its independent
   * guest-unit/VM drain barrier have completed. On unknown drain, retain the prefix.
   */
  readonly drained: Promise<Readonly<{ transportClosed: true; guestCleanupConfirmed: false }>>;
  abort(): void;
}

/** Observe the one persistent supervisor, never restore one from JSON or a digest.
 * The result deliberately has no backend/lease authority. VM cleanup and joined
 * qualification remain the controller's responsibility, including on transport loss.
 */
export function consumeInstallOperation(
  child: ChildProcessWithoutNullStreams,
  signal: AbortSignal,
): InstallOperation {
  if (consumed.has(child)) {
    child.stdin.destroy();
    child.kill('SIGTERM');
    throw new InstallOperationError('operation_replay');
  }
  consumed.add(child);
  let exchange: InstallExchange | undefined;
  let confirmDrain: (() => void) | undefined;
  const drained = new Promise<Readonly<{ transportClosed: true; guestCleanupConfirmed: false }>>(resolve => {
    confirmDrain = () => resolve(Object.freeze({ transportClosed: true, guestCleanupConfirmed: false }));
  });
  const drain = confirmDrain;
  if (!drain) throw new InstallOperationError('drain_initialization');
  const result = new Promise<InstallObservation>((resolve, reject) => {
    exchange = new InstallExchange(child, signal, { resolve, reject, drain });
  });
  const active = exchange;
  if (!active) throw new InstallOperationError('exchange_initialization');
  return Object.freeze({ result, drained, abort: () => active.abort() });
}

class InstallExchange {
  private prepared: string | undefined;
  private observation: InstallObservation | undefined;
  private failure: InstallOperationError | undefined;
  private buffer = '';
  private bytes = 0;
  private done = false;
  private stopTimer: NodeJS.Timeout | undefined;
  private readonly deadline: NodeJS.Timeout;
  constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly signal: AbortSignal,
    private readonly completion: Readonly<{
      resolve: (value: InstallObservation) => void;
      reject: (error: InstallOperationError) => void;
      drain: () => void;
    }>,
  ) {
    this.deadline = setTimeout(() => this.fail('operation_deadline'), 900_000);
    child.stdout.on('data', this.output);
    child.stderr.on('data', this.stderr);
    child.once('error', this.processError);
    child.stdin.on('error', this.inputError);
    child.once('close', this.settle);
    signal.addEventListener('abort', this.abort, { once: true });
    if (signal.aborted) this.abort();
    if (child.exitCode !== null || child.signalCode !== null) this.fail('transport_already_exited');
  }

  readonly abort = () => this.fail('operation_aborted');
  private readonly processError = () => this.fail('transport_error');
  private readonly inputError = () => this.fail('controller_pipe_closed');
  private readonly stderr = (chunk: Buffer) => {
    this.bytes += chunk.length;
    if (this.bytes > 1024) this.fail('diagnostic_bound');
  };

  private fail(code: string): void {
    if (this.done) return;
    this.failure ??= new InstallOperationError(code);
    this.completion.reject(this.failure);
    this.child.stdin.destroy();
    this.child.kill('SIGTERM');
    this.stopTimer ??= setTimeout(() => {
      this.child.kill('SIGKILL');
      // Keep listeners and the drain promise alive. SIGKILL is a request, not a
      // process-close observation; the controller must retain borrowed assets.
    }, 5000);
  }

  private readonly settle = (code: number | null) => {
    if (this.done) return;
    this.done = true;
    clearTimeout(this.deadline);
    clearTimeout(this.stopTimer);
    this.signal.removeEventListener('abort', this.abort);
    this.child.stdout.removeListener('data', this.output);
    this.child.stderr.removeListener('data', this.stderr);
    this.child.removeListener('error', this.processError);
    this.child.stdin.removeListener('error', this.inputError);
    this.completion.drain();
    if (this.failure || code !== 0 || this.buffer || !this.observation) {
      this.completion.reject(this.failure ?? new InstallOperationError('incomplete_install_observation'));
    } else this.completion.resolve(this.observation);
  };

  private readonly output = (chunk: Buffer) => {
    this.bytes += chunk.length;
    if (this.bytes > 1024 || /[^\x20-\x7e\n]/.test(chunk.toString('latin1'))) return this.fail('protocol_bound');
    this.buffer += chunk.toString('ascii');
    while (this.buffer.includes('\n') && !this.failure) {
      const end = this.buffer.indexOf('\n'), line = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(end + 1);
      const first = /^PREPARED ([a-f0-9]{64})$/.exec(line);
      const last = /^INSTALLED ([a-f0-9]{64}) ([a-f0-9]{64}) ([a-f0-9]{64})$/.exec(line);
      if (first?.[1] && !this.prepared && !this.observation) {
        this.prepared = first[1];
        if (this.signal.aborted) return this.fail('operation_aborted');
        this.child.stdin.write('INSTALL\n');
      } else if (last?.[1] && last[2] && last[3] && this.prepared === last[1] && !this.observation) {
        this.observation = Object.freeze({ kind: 'install-observation', preparationSha256: last[1],
          hookSha256: last[2], installedStatusSha256: last[3], backendVerified: false,
          sourceExecutionAuthorized: false, daemonObserved: false });
      } else this.fail('protocol_order_or_binding');
    }
  };
}
