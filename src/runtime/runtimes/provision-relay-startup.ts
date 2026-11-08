import type { ProvisionProcess } from './provision-controller-process.js';
import type { ProvisionVm } from './provision-controller-vm.js';
import type { ProvisionRelay } from './provision-relay.js';
import { ProvisionError, requireProvision, unreachable } from './provision-types.js';

export function relayServiceArgv(run: string): readonly string[] {
  return ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
    '--service-type=exec', '--unit=wakeio-backend-' + run + '.service',
    '--property=CPUQuota=50%', '--property=MemoryMax=268435456', '--property=TasksMax=64',
    '--property=RuntimeMaxSec=900', '--property=TimeoutStopSec=30', '--property=KillMode=control-group',
    '/usr/bin/python3', '-I', '-B', '/usr/local/lib/wakeio-controller/relay.py', run];
}

export function startupBudgetRecord(remainingMs: number): string {
  requireProvision(Number.isSafeInteger(remainingMs) && remainingMs > 0 && remainingMs <= 900_000,
    'relay_startup_budget');
  return JSON.stringify({ v: 1, remainingMs }) + '\n';
}

/** Bounded DATA only; neither marker grants ownership or clock qualification. */
export class RelayStartupData {
  private marker = 'WAKEIO_STARTUP_1\n';
  private offset = 0;
  private first = true;
  private complete = false;
  private failure: ProvisionError | undefined;

  push(chunk: Buffer): 'startup' | 'ready' | undefined {
    if (this.failure) throw this.failure;
    if (chunk.length === 0) return;
    if (this.complete || chunk.length > this.marker.length - this.offset) this.invalid();
    for (const byte of chunk) {
      if (byte !== this.marker.charCodeAt(this.offset)) this.invalid();
      this.offset++;
    }
    if (this.offset !== this.marker.length) return;
    const event = this.first ? 'startup' : 'ready';
    if (this.first) {
      this.first = false;
      this.marker = 'RELAY_READY\n';
      this.offset = 0;
    } else this.complete = true;
    return event;
  }

  finish(): void {
    if (this.failure) throw this.failure;
    if (!this.complete) this.invalid();
  }

  private invalid(): never {
    this.failure ??= new ProvisionError('relay_startup_data');
    throw this.failure;
  }
}

/** Only the original VM can allocate this service; work abort never stops its observer. */
export class ProvisionRelayStartup {
  private service: ProvisionProcess | undefined;
  private attempted = false;
  private inputEnded = false;
  private inputEndSent = false;
  private writeUsed = false;
  private acknowledged = false;
  private sawReady = false;
  private stderrBytes = 0;
  private failure: Error | undefined;
  private observationFailure: Error | undefined;
  private readonly data = new RelayStartupData();
  private readonly resolveReady: () => void;
  private readonly rejectReady: (error: Error) => void;
  private readonly ready: Promise<void>;
  private readonly abort = () => {
    const reason: unknown = this.vm.owner.signal.reason;
    this.fail(reason instanceof Error ? reason : new ProvisionError('relay_aborted'));
  };

  constructor(private readonly vm: ProvisionVm, private readonly relay: ProvisionRelay) {
    vm.checkRelay(relay);
    let resolveReady: (() => void) | undefined, rejectReady: ((error: Error) => void) | undefined;
    this.ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
    requireProvision(resolveReady && rejectReady, 'relay_startup_initialization');
    this.resolveReady = resolveReady;
    this.rejectReady = rejectReady;
    void this.ready.catch(() => undefined);
    vm.owner.signal.addEventListener('abort', this.abort, { once: true });
    if (vm.owner.signal.aborted) this.abort();
  }

  async start(): Promise<Readonly<{ process: ProvisionProcess; ready: Promise<void> }>> {
    this.vm.checkRelay(this.relay);
    this.vm.owner.check();
    requireProvision(!this.attempted && !this.inputEnded, 'relay_startup_replay');
    this.attempted = true;
    const service = await this.vm.startRelayService(this.relay).catch((error: unknown) => {
      this.vm.owner.signal.removeEventListener('abort', this.abort);
      if (!(error instanceof Error)) throw error;
      this.fail(error);
      throw error;
    });
    this.service = service;
    this.observe(service);
    if (this.inputEnded) this.endInput();
    // Never await readiness here: Relay must retain the actual child even on startup failure.
    return Object.freeze({ process: service, ready: this.ready });
  }

  beginClose(): void {
    const reason: unknown = this.vm.owner.signal.reason;
    this.endInput();
    this.rejectReady(this.failure ?? (reason instanceof Error ? reason : new ProvisionError('relay_closed')));
  }

  private endInput(): void {
    this.inputEnded = true;
    if (!this.service || this.inputEndSent) return;
    this.inputEndSent = true;
    this.service.child.stdin.end();
  }

  private fail(error: Error): void {
    if (this.failure) return;
    this.failure = error;
    this.rejectReady(error);
    this.endInput();
    if (!this.vm.owner.signal.aborted) {
      this.vm.owner.revoke(error instanceof ProvisionError ? error.code : 'relay_startup_failed');
    }
  }

  private observationFailed(error: Error): void {
    this.observationFailure ??= error;
    this.fail(error);
  }

  async drain(): Promise<void> {
    this.vm.checkRelay(this.relay);
    const service = this.service;
    if (!service) {
      requireProvision(!this.vm.relayServiceAttempted, 'relay_startup_service_unconfirmed');
      return;
    }
    await service.drain();
    const result = await service.closed;
    this.data.finish();
    requireProvision(!this.observationFailure && result.code === 0 && result.signal === null,
      'relay_startup_observation_unconfirmed');
  }

  private observe(service: ProvisionProcess): void {
    const child = service.child;
    child.stdout.pause();
    child.stderr.pause();
    child.on('error', error => this.observationFailed(error));
    child.stdin.on('error', error => this.observationFailed(error));
    child.stdout.on('error', error => this.observationFailed(error));
    child.stderr.on('error', error => this.observationFailed(error));
    child.stdout.once('end', () => {
      try { this.data.finish(); }
      catch (error) {
        if (!(error instanceof Error)) throw error;
        this.observationFailed(error);
      }
      if (!this.inputEnded) this.observationFailed(new ProvisionError('relay_startup_stdout_ended'));
    });
    child.stdout.once('close', () => {
      if (!child.stdout.readableEnded) this.observationFailed(new ProvisionError('relay_startup_stdout_closed'));
    });
    child.stderr.once('end', () => {
      if (!this.inputEnded) this.observationFailed(new ProvisionError('relay_startup_stderr_ended'));
    });
    child.stderr.once('close', () => {
      if (!child.stderr.readableEnded) this.observationFailed(new ProvisionError('relay_startup_stderr_closed'));
    });
    service.failureSignal.addEventListener('abort',
      () => this.observationFailed(new ProvisionError('relay_startup_process_failed')), { once: true });
    child.stdout.on('data', (chunk: Buffer) => this.receive(chunk));
    child.stderr.on('data', (chunk: Buffer) => {
      if (this.observationFailure) return;
      this.stderrBytes += chunk.length;
      if (this.stderrBytes > 65_536) this.observationFailed(new ProvisionError('relay_startup_stderr_bound'));
    });
    void service.closed.then(result => {
      if (!this.inputEnded || result.code !== 0 || result.signal !== null) {
        this.observationFailed(new ProvisionError('guest_relay_exited'));
      }
      this.vm.owner.signal.removeEventListener('abort', this.abort);
    });
    if (service.failureSignal.aborted || child.stdout.destroyed || child.stdout.readableEnded
      || child.stderr.destroyed || child.stderr.readableEnded) {
      this.observationFailed(new ProvisionError('relay_startup_process_failed'));
    }
    child.stdout.resume();
    child.stderr.resume();
  }

  private receive(chunk: Buffer): void {
    if (this.observationFailure) return;
    try {
      const marker = this.data.push(chunk);
      switch (marker) {
        case 'startup': this.writeBudget(); break;
        case 'ready': this.sawReady = true; this.complete(); break;
        case undefined: break;
        default: unreachable(marker);
      }
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      if (error instanceof ProvisionError && error.code === 'relay_startup_data') this.observationFailed(error);
      else this.fail(error);
    }
  }

  private writeBudget(): void {
    this.vm.owner.check();
    const service = this.service;
    requireProvision(service && !this.inputEnded && !this.writeUsed, 'relay_startup_write_denied');
    const record = startupBudgetRecord(this.vm.owner.deadlineAt - Date.now());
    this.writeUsed = true;
    service.child.stdin.write(record, 'ascii', error => {
      if (error) { this.fail(error); return; }
      try {
        this.vm.owner.check();
        requireProvision(!this.inputEnded, 'relay_startup_write_denied');
        this.acknowledged = true;
        this.complete();
      } catch (failure) {
        if (!(failure instanceof Error)) throw failure;
        this.fail(failure);
      }
    });
  }

  private complete(): void {
    if (!this.acknowledged || !this.sawReady || this.failure) return;
    this.vm.owner.check();
    requireProvision(!this.inputEnded, 'relay_startup_write_denied');
    this.resolveReady();
  }
}
