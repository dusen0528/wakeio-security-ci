import { watch, type FSWatcher } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProvisionProcess } from './provision-controller-process.js';
import { ProvisionRelayWire, type RelayRequest } from './provision-relay-wire.js';
import type { BuildRequest, BuildReply } from './provision-build-wire.js';
import type { ProvisionVm } from './provision-controller-vm.js';
import { ProvisionError, provisionRecord, requireProvision, type BackendIdentity } from './provision-types.js';

/** Same-socket peer credentials plus per-frame MACs; no secret is transmitted in the relay protocol. */
export class ProvisionRelay {
  private socket: { readonly dev: number; readonly ino: number } | undefined;
  private watcher: FSWatcher | undefined;
  private bridge: ProvisionProcess | undefined;
  private wire: ProvisionRelayWire | undefined;
  private closed = false;
  private closing = false;
  private serial = Promise.resolve();
  private watcherClosed = Promise.resolve();
  private readonly resolveDrain: () => void;
  private readonly rejectDrain: (error: Error) => void;
  readonly drained: Promise<void>;

  constructor(private readonly vm: ProvisionVm, private readonly nonce: string) {
    let resolveDrain: (() => void) | undefined, rejectDrain: ((error: Error) => void) | undefined;
    this.drained = new Promise((resolve, reject) => { resolveDrain = resolve; rejectDrain = reject; });
    requireProvision(resolveDrain && rejectDrain, 'drain_initialization');
    this.resolveDrain = resolveDrain;
    this.rejectDrain = rejectDrain;
    void this.drained.catch(() => undefined);
    vm.owner.own({ identity: 'relay-watch:' + vm.owner.run, stop: () => this.stop(), drained: this.drained,
      remove: async () => { await this.drained; return this.closed; } });
  }

  async start(): Promise<void> {
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
          this.vm.owner.revoke('relay_socket_changed');
          failed?.(error);
        }
      });
    };
    this.watcher = watch(dirname(this.vm.endpoint), reconcile);
    this.watcherClosed = new Promise(resolve => this.watcher?.once('close', resolve));
    this.watcher.on('error', error => { this.vm.owner.revoke('relay_watch_failed'); failed?.(error); });
    reconcile();
    const server = await this.vm.admin(['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
      '--service-type=exec', '--unit=wakeio-backend-' + this.vm.owner.run + '.service',
      '--property=CPUQuota=50%', '--property=MemoryMax=268435456', '--property=TasksMax=64',
      '--property=RuntimeMaxSec=900', '--property=TimeoutStopSec=30', '--property=KillMode=control-group',
      '/usr/bin/python3', '-I', '-B', '/usr/local/lib/wakeio-controller/relay.py', this.vm.owner.run]);
    server.child.stdin.end();
    server.child.stdout.resume();
    server.child.stderr.resume();
    void server.closed.then(() => {
      if (!this.closing) this.vm.owner.revoke('guest_relay_exited');
      failed?.(new ProvisionError('guest_relay_exited'));
    });
    try { await socketReady; }
    finally { this.vm.owner.signal.removeEventListener('abort', abort); }
    this.vm.owner.check();
    const temporary = await this.vm.root.directory('relay-transport');
    const bridge = new ProvisionProcess({
      executable: '/usr/bin/python3', home: this.vm.root.root,
      limaHome: join(this.vm.root.root, '.lima'), temporary,
      argv: ['-I', '-B', fileURLToPath(new URL('../../../../workers/runtime-controller/relay_transport.py',
        import.meta.url)), this.vm.endpoint],
    }, this.vm.owner.signal);
    this.bridge = bridge;
    this.vm.owner.own({ identity: 'relay:' + this.vm.owner.run, stop: () => bridge.stop(),
      drained: bridge.drain(), remove: async () => (await bridge.closed).groupAbsent });
    this.wire = new ProvisionRelayWire(bridge.child,
      { nonce: this.nonce, run: this.vm.owner.run }, this.vm.owner.signal);
    void bridge.closed.then(() => { if (!this.closing) this.vm.owner.revoke('relay_transport_closed'); });
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
    this.vm.owner.check();
    requireProvision(this.wire && !this.closed && (!this.closing || request.operation === 'shutdown'), 'relay_closed');
    await this.vm.frame('Running');
    await this.checkSocket();
    try {
      requireProvision(!this.closing || request.operation === 'shutdown', 'relay_closed');
      const value = await this.wire.request(request);
      this.vm.owner.check();
      if (request.operation !== 'shutdown') {
        requireProvision(!this.closing, 'relay_closed');
        await this.checkSocket();
      }
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

  /** Same original connection and owner; observations do not issue a build capability. */
  async build(request: BuildRequest): Promise<BuildReply> {
    this.vm.owner.check();
    requireProvision(this.wire && !this.closed && !this.closing, 'relay_closed');
    await this.vm.frame('Running');
    await this.checkSocket();
    try {
      requireProvision(!this.closing, 'relay_closed');
      const value = await this.wire.build(request);
      this.vm.owner.check();
      requireProvision(!this.closing, 'relay_closed');
      await this.checkSocket();
      return value;
    } catch (error) {
      this.vm.owner.revoke('relay_operation_failed');
      throw error;
    }
  }

  beginClose(): void { this.closing = true; }

  stop(): void {
    if (this.closed) return;
    this.beginClose();
    this.closed = true;
    this.wire?.close();
    this.watcher?.close();
    this.bridge?.stop();
    void Promise.all([this.watcherClosed, this.serial]).then(this.resolveDrain,
      error => this.rejectDrain(error instanceof Error ? error : new ProvisionError('relay_drain_unconfirmed')));
  }

  async shutdown(): Promise<void> {
    this.beginClose();
    if (!this.vm.owner.signal.aborted && this.wire) {
      const result = await this.request({ operation: 'shutdown' });
      requireProvision(result.closed === true, 'guest_cleanup_unconfirmed');
    }
    this.stop();
    await this.drained;
  }
}
