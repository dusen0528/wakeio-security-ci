import { watch, type FSWatcher } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProvisionProcess } from './provision-controller-process.js';
import { ProvisionRelayWire, type RelayRequest } from './provision-relay-wire.js';
import type { BuildRequest, BuildReply } from './provision-build-wire.js';
import type { ProvisionVm } from './provision-controller-vm.js';
import { ProvisionError, provisionRecord, requireProvision, type BackendIdentity } from './provision-types.js';

export function relayServiceArgv(run: string): readonly string[] {
  return ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
    '--service-type=exec', '--unit=wakeio-backend-' + run + '.service',
    '--property=CPUQuota=50%', '--property=MemoryMax=268435456', '--property=TasksMax=64',
    '--property=RuntimeMaxSec=900', '--property=TimeoutStopSec=30', '--property=KillMode=control-group',
    '/usr/bin/python3', '-I', '-B', '/usr/local/lib/wakeio-controller/relay.py', run];
}

/** Same original VM, connection and private prerequisite lifetime. */
export class ProvisionRelay {
  private socket: { readonly dev: number; readonly ino: number } | undefined;
  private watcher: FSWatcher | undefined;
  private service: ProvisionProcess | undefined;
  private bridge: ProvisionProcess | undefined;
  private wire: ProvisionRelayWire | undefined;
  private starting: Promise<void> | undefined;
  private cleanup: Promise<boolean> | undefined;
  private closing = false;
  private mayShutdown = false;
  private confirmed = false;
  private cutoff = false;
  private failure: Error | undefined;
  private grace: Promise<void> | undefined;
  private graceTimer: NodeJS.Timeout | undefined;
  private finishGrace: () => void = () => {};
  private serial = Promise.resolve();
  private watcherClosed = Promise.resolve();
  private readonly resolveDrain: () => void;
  private readonly rejectDrain: (error: Error) => void;
  readonly drained: Promise<void>;

  constructor(private readonly vm: ProvisionVm, private readonly nonce: string,
    private readonly signal: AbortSignal) {
    let resolveDrain: (() => void) | undefined, rejectDrain: ((error: Error) => void) | undefined;
    this.drained = new Promise((resolve, reject) => { resolveDrain = resolve; rejectDrain = reject; });
    requireProvision(resolveDrain && rejectDrain, 'drain_initialization');
    this.resolveDrain = resolveDrain;
    this.rejectDrain = rejectDrain;
    void this.drained.catch(() => undefined);
  }

  async start(): Promise<void> {
    this.vm.checkRelay(this);
    this.vm.owner.check();
    requireProvision(!this.starting && !this.closing, 'relay_replay');
    let abort = () => {};
    const cancelled = new Promise<never>((_resolve, reject) => {
      abort = () => reject(new ProvisionError('relay_aborted'));
      this.vm.owner.signal.addEventListener('abort', abort, { once: true });
      if (this.vm.owner.signal.aborted) abort();
    });
    this.starting = Promise.resolve().then(() => this.startOriginal());
    try { await Promise.race([this.starting, cancelled]); }
    finally { this.vm.owner.signal.removeEventListener('abort', abort); }
  }

  private async startOriginal(): Promise<void> {
    this.vm.owner.check();
    let ready: (() => void) | undefined, failed: ((error: Error) => void) | undefined;
    const socketReady = new Promise<void>((resolve, reject) => { ready = resolve; failed = reject; });
    const abort = () => failed?.(new ProvisionError('relay_aborted'));
    this.vm.owner.signal.addEventListener('abort', abort, { once: true });
    void socketReady.catch(() => undefined);
    const reconcile = () => {
      if (this.closing) return;
      this.serial = this.serial.then(async () => {
        try {
          if (this.closing) return;
          await this.checkSocket();
          ready?.();
        } catch (error) {
          if (error instanceof Error && 'code' in error && error.code === 'ENOENT' && !this.socket) return;
          if (!(error instanceof Error)) throw error;
          this.failure ??= error;
          this.vm.owner.revoke('relay_socket_changed');
          failed?.(error);
        }
      });
    };
    try {
      this.watcher = watch(dirname(this.vm.endpoint), reconcile);
      this.watcherClosed = new Promise(resolve => this.watcher?.once('close', () => {
        if (!this.closing) {
          this.failure ??= new ProvisionError('relay_watch_closed');
          this.vm.owner.revoke('relay_watch_closed');
        }
        resolve();
      }));
      this.watcher.on('error', error => {
        this.failure ??= error;
        this.vm.owner.revoke('relay_watch_failed');
        failed?.(error);
      });
      reconcile();
      await this.startService();
      await socketReady;
      this.vm.owner.check();
      const temporary = await this.vm.root.directory('relay-transport');
      this.vm.owner.check();
      requireProvision(!this.closing, 'relay_closed');
      const bridge = new ProvisionProcess({ executable: '/usr/bin/python3', home: this.vm.root.root,
        limaHome: join(this.vm.root.root, '.lima'), temporary,
        argv: ['-I', '-B', fileURLToPath(new URL('../../../../workers/runtime-controller/relay_transport.py',
          import.meta.url)), this.vm.endpoint] }, this.signal);
      this.bridge = bridge;
      this.vm.owner.own({ identity: 'relay:' + this.vm.owner.run, stop: () => this.vm.stop(),
        drained: bridge.drain(), remove: async () => (await bridge.closed).groupAbsent });
      const wire = new ProvisionRelayWire(bridge.child, { nonce: this.nonce, run: this.vm.owner.run }, this.signal);
      this.wire = wire;
      const revoke = () => this.vm.owner.revoke('relay_transport_closed');
      wire.failureSignal.addEventListener('abort', revoke, { once: true });
      if (wire.failureSignal.aborted) revoke();
      bridge.failureSignal.addEventListener('abort', () => wire.close(), { once: true });
      if (bridge.failureSignal.aborted) wire.close();
    } finally { this.vm.owner.signal.removeEventListener('abort', abort); }
  }

  private async startService(): Promise<void> {
    this.service = await this.vm.startRelayService(this);
    this.service.child.stdin.end();
    this.service.child.stdout.resume();
    this.service.child.stderr.resume();
    void this.service.closed.then(() => {
      if (!this.closing) this.vm.owner.revoke('guest_relay_exited');
    });
  }

  private async checkSocket(): Promise<void> {
    const parent = await lstat(dirname(this.vm.endpoint)), current = await lstat(this.vm.endpoint);
    requireProvision(parent.isDirectory() && !parent.isSymbolicLink() && parent.uid === process.getuid?.()
      && (parent.mode & 0o077) === 0 && current.isSocket() && current.uid === process.getuid?.()
      && (current.mode & 0o177) === 0, 'relay_socket_identity');
    if (this.socket) requireProvision(current.dev === this.socket.dev && current.ino === this.socket.ino,
      'relay_socket_changed');
    else this.socket = { dev: current.dev, ino: current.ino };
  }

  async request(request: RelayRequest): Promise<Record<string, unknown>> {
    this.vm.checkRelay(this);
    this.vm.owner.check();
    requireProvision(this.wire && !this.closing, 'relay_closed');
    try {
      await this.vm.frame('Running');
      await this.checkSocket();
      this.vm.owner.check();
      requireProvision(!this.closing, 'relay_closed');
      const value = await this.wire.request(request);
      await this.checkSocket();
      this.vm.owner.check();
      requireProvision(!this.closing, 'relay_closed');
      return value;
    } catch (error) {
      this.vm.owner.revoke('relay_operation_failed');
      throw error;
    }
  }

  async identity(vmDigest: string): Promise<BackendIdentity> {
    const data = provisionRecord(await this.request({ operation: 'identity' }));
    requireProvision(data.run === this.vm.owner.run && typeof data.boot === 'string'
      && typeof data.daemon === 'string' && typeof data.helper === 'string', 'backend_identity_invalid');
    return Object.freeze({ run: data.run, vm: vmDigest, boot: data.boot, daemon: data.daemon, helper: data.helper });
  }

  async build(request: BuildRequest): Promise<BuildReply> {
    this.vm.checkRelay(this);
    this.vm.owner.check();
    requireProvision(this.wire && !this.closing, 'relay_closed');
    try {
      await this.vm.frame('Running');
      await this.checkSocket();
      this.vm.owner.check();
      requireProvision(!this.closing, 'relay_closed');
      const value = await this.wire.build(request);
      await this.checkSocket();
      this.vm.owner.check();
      requireProvision(!this.closing, 'relay_closed');
      return value;
    } catch (error) {
      this.vm.owner.revoke('relay_operation_failed');
      throw error;
    }
  }

  beginClose(): void {
    if (this.closing) return;
    this.vm.checkRelay(this);
    this.closing = true;
    this.grace = new Promise(resolve => {
      this.finishGrace = resolve;
      this.graceTimer = setTimeout(() => { this.cutoff = true; resolve(); }, 30_000);
    });
    this.mayShutdown = this.wire?.beginClose() ?? false;
  }

  stop(): void {
    this.vm.checkRelay(this);
    this.vm.stop();
  }

  private async shutdownOriginal(): Promise<void> {
    await this.checkSocket();
    requireProvision(this.wire && this.closing && !this.cutoff, 'relay_closed');
    const result = await this.wire.shutdown();
    requireProvision(!this.cutoff && result.closed === true && Object.keys(result).length === 1,
      'guest_cleanup_unconfirmed');
    this.confirmed = true;
  }

  async beforeVmStop(): Promise<void> {
    this.vm.checkRelay(this);
    const grace = this.grace;
    requireProvision(this.closing && grace, 'relay_close_not_started');
    if (this.mayShutdown) {
      this.cleanup = this.shutdownOriginal().then(() => true, () => { this.wire?.close(); return false; });
      if (!await Promise.race([this.cleanup, grace.then(() => false)])) await grace;
    } else if (this.vm.relayServiceAttempted) await grace;
    this.cutoff = true;
    clearTimeout(this.graceTimer);
    this.finishGrace();
    this.wire?.close();
    try { this.watcher?.close(); }
    catch (error) {
      if (!(error instanceof Error)) throw error;
      this.failure ??= error;
    }
    this.bridge?.stop();
    this.service?.stop();
    let timer: NodeJS.Timeout | undefined;
    const expired = new Promise<void>(resolve => { timer = setTimeout(resolve, 5_000); });
    try {
      if (this.service) await Promise.race([this.service.closed, expired]);
      else if (this.vm.relayServiceAttempted) await expired;
    }
    finally { clearTimeout(timer); }
    void this.drainOriginal().then(this.resolveDrain,
      error => this.rejectDrain(error instanceof Error ? error : new ProvisionError('relay_drain_unconfirmed')));
  }

  private async drainOriginal(): Promise<void> {
    await Promise.allSettled([this.starting, this.cleanup]);
    const physical = await Promise.allSettled([this.service?.drain(), this.bridge?.drain(), this.watcherClosed]);
    await this.serial;
    requireProvision(!this.failure && physical.every(row => row.status === 'fulfilled'), 'relay_drain_unconfirmed');
  }

  async remove(): Promise<boolean> {
    this.vm.checkRelay(this);
    await this.drained;
    return !this.vm.relayServiceAttempted || this.confirmed;
  }

  async shutdown(): Promise<void> {
    this.stop();
    await this.vm.drained;
    requireProvision(await this.remove(), 'guest_cleanup_unconfirmed');
  }
}
