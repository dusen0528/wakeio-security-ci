import { lstat, chmod, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { ProvisionDirectory, ProvisionFile, provisionAbsent } from './provision-controller-files.js';
import { ProvisionOwner } from './provision-controller-owner.js';
import { ProvisionProcess } from './provision-controller-process.js';
import { ProvisionRelay, relayServiceArgv } from './provision-relay.js';
import { LimaEvents } from './provision-controller-events.js';
import { ProvisionError, provisionRecord, requireProvision } from './provision-types.js';
import { snapshotJsonData } from '../../json-snapshot.js';
import { authenticateGuest, guestChallenge, sshArgv, type GuestAuthentication } from './provision-controller-auth.js';

/** Created only inside the retained asset borrow. No tool path comes from TargetSpec. */
export class ProvisionVm {
  readonly name: string;
  readonly directory: string;
  readonly endpoint: string;
  private profile: { readonly dev: number; readonly ino: number } | undefined;
  private machine: ProvisionFile | undefined;
  private config: ProvisionFile | undefined;
  private foreground: ProvisionProcess | undefined;
  private events: LimaEvents | undefined;
  private relay: ProvisionRelay | undefined;
  private relayClaimed = false;
  private service: ProvisionProcess | undefined;
  private serviceAttempted = false;
  private pending = 0;
  private resolveAllocations: () => void = () => {};
  private readonly allocationsDrained = new Promise<void>(resolve => { this.resolveAllocations = resolve; });
  private readonly containment = new AbortController();
  private readonly abort = () => this.stop();
  private closing: Promise<void> | undefined;
  private readonly commands = new Set<ProvisionProcess>();
  private temporaryOrdinal = 0;
  private stopped = false;
  private sshPort: number | undefined;
  private knownHosts: string | undefined;
  private key: ProvisionFile | undefined;
  private readonly resolveDrain: () => void;
  private readonly rejectDrain: (error: Error) => void;
  readonly drained: Promise<void>;

  constructor(readonly owner: ProvisionOwner, readonly root: ProvisionDirectory,
    private readonly assets: Readonly<{
      executable: ProvisionFile; guestagent: ProvisionFile; rootfs: ProvisionFile
    }>) {
    this.name = 'wk-' + owner.run.slice(0, 12);
    this.directory = join(root.root, '.lima', this.name);
    this.endpoint = join(this.directory, 'sock/docker.sock');
    requireProvision(Buffer.byteLength(this.endpoint) <= 100, 'socket_path_bound');
    let resolveDrain: (() => void) | undefined, rejectDrain: ((error: Error) => void) | undefined;
    this.drained = new Promise((resolve, reject) => { resolveDrain = resolve; rejectDrain = reject; });
    requireProvision(resolveDrain && rejectDrain, 'drain_initialization');
    this.resolveDrain = resolveDrain;
    this.rejectDrain = rejectDrain;
    void this.drained.catch(() => undefined);
    owner.signal.addEventListener('abort', this.abort, { once: true });
    if (owner.signal.aborted) this.abort();
  }

  createRelay(nonce: string): ProvisionRelay {
    this.owner.check();
    requireProvision(!this.relayClaimed && !this.stopped, 'relay_replay');
    this.relayClaimed = true;
    const relay = new ProvisionRelay(this, nonce, this.containment.signal);
    this.relay = relay;
    this.owner.own({ identity: 'relay-watch:' + this.owner.run, stop: () => this.stop(), drained: relay.drained,
      remove: () => relay.remove() });
    return relay;
  }

  checkRelay(relay: ProvisionRelay): void {
    requireProvision(this.relay === relay, 'relay_owner_changed');
  }

  command(argv: readonly string[], signal = this.owner.signal): Promise<ProvisionProcess> {
    return this.commandProcess(argv, signal);
  }

  private async commandProcess(argv: readonly string[], signal: AbortSignal,
    foreground = false): Promise<ProvisionProcess> {
    this.pending++;
    try {
      await this.root.check();
      await this.assets.executable.check();
      await this.assets.guestagent.check();
      await this.assets.rootfs.check();
      const temporary = await this.root.directory('command-' + this.temporaryOrdinal++);
      if (foreground) requireProvision(!this.stopped, 'vm_closed');
      const child = new ProvisionProcess({ executable: this.assets.executable.path, argv: ['--tty=false', ...argv],
        home: this.root.root, limaHome: join(this.root.root, '.lima'), temporary }, signal);
      this.commands.add(child);
      if (foreground) this.foreground = child;
      this.observeProcess(child);
      return child;
    } finally { this.settledAllocation(); }
  }

  private settledAllocation(): void {
    this.pending--;
    if (this.stopped && this.pending === 0) this.resolveAllocations();
  }

  private observeProcess(child: ProvisionProcess): void {
    const failed = () => {
      this.owner.revoke('process_failed');
      if (child !== this.foreground && child !== this.service) child.stop();
    };
    child.failureSignal.addEventListener('abort', failed, { once: true });
    if (child.failureSignal.aborted) failed();
  }

  async start(configPath: string): Promise<void> {
    this.owner.check();
    await this.root.directory('.lima');
    requireProvision(await provisionAbsent(this.directory), 'vm_exists');
    const create = await this.command(['create', '--name=' + this.name, configPath]);
    await create.output();
    const info = await lstat(this.directory);
    requireProvision(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid?.(), 'vm_identity');
    this.profile = { dev: info.dev, ino: info.ino };
    await chmod(this.directory, 0o700);
    await mkdir(join(this.directory, 'sock'), { mode: 0o700 });
    this.machine = await ProvisionFile.open(join(this.directory, 'vz-identifier'));
    this.config = await ProvisionFile.open(join(this.directory, 'lima.yaml'));
    await this.frame('Stopped');
    this.owner.check();
    this.events = new LimaEvents(this.directory, this.containment.signal);
    this.events.failureSignal.addEventListener('abort', () => this.owner.revoke('vm_event_failed'), { once: true });
    const foreground = await this.commandProcess(['start', '--foreground', '--timeout=300s', this.name],
      this.containment.signal, true);
    foreground.child.stdin.end();
    foreground.child.stdout.resume();
    foreground.child.stderr.resume();
    void Promise.race([foreground.closed, this.events.exiting]).then(
      () => this.owner.revoke('vm_exited'), () => this.owner.revoke('vm_event_failed'));
    await Promise.race([this.events.waitRunning(this.owner.signal), foreground.closed.then(() => {
      throw new ProvisionError('vm_exited');
    })]);
    await this.frame('Running');
    await this.root.captureLimaConfig();
  }

  async frame(status: 'Running' | 'Stopped', signal = this.owner.signal): Promise<void> {
    requireProvision(this.profile && this.machine && this.config, 'vm_unbound');
    await this.root.check();
    const actual = await lstat(this.directory);
    requireProvision(actual.isDirectory() && actual.dev === this.profile.dev && actual.ino === this.profile.ino,
      'vm_identity_changed');
    await this.machine.check();
    await this.config.check();
    const command = await this.command(['list', '--format=json', this.name], signal);
    const data = provisionRecord(snapshotJsonData(JSON.parse(await command.output())));
    requireProvision(data.name === this.name && data.dir === this.directory && data.vmType === 'vz'
      && data.arch === 'aarch64' && data.protected === false && data.errors === undefined
      && (data.limaVersion === '1.0.3' || data.limaVersion === 'v1.0.3') && data.status === status,
    'vm_identity_changed');
    if (status === 'Running') {
      requireProvision(data.hostAgentPID === this.foreground?.child.pid && data.hostAgentPID === data.driverPID,
        'vm_process_changed');
      requireProvision(typeof data.sshLocalPort === 'number' && Number.isInteger(data.sshLocalPort)
        && data.sshLocalPort > 1024 && data.sshLocalPort <= 65535
        && (this.sshPort === undefined || this.sshPort === data.sshLocalPort), 'vm_ssh_port_changed');
      this.sshPort = data.sshLocalPort;
    } else {
      requireProvision((data.hostAgentPID ?? 0) === 0 && (data.driverPID ?? 0) === 0, 'vm_stop_unconfirmed');
    }
  }

  async machineDigest(): Promise<string> {
    requireProvision(this.machine, 'vm_unbound');
    return this.machine.digest(4096);
  }

  async authenticate(expected: Readonly<{ nonce: string; helper: string }>): Promise<GuestAuthentication> {
    const challenge = guestChallenge();
    const bootstrap = await this.command(['shell', '--workdir=/', '--shell=/bin/sh', this.name, '--',
      '/usr/bin/sudo', '-n', '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
      '/usr/bin/python3', '-I', '-B', '/usr/local/lib/wakeio-controller/bootstrap_identity.py', challenge]);
    const identity = authenticateGuest(await bootstrap.output(), { ...expected, challenge });
    this.knownHosts = await this.root.write('known-hosts', this.name + ' ' + identity.key + '\n');
    this.key = await ProvisionFile.open(join(this.root.root, '.lima/_config/user'));
    return identity;
  }

  admin(argv: readonly string[], signal = this.owner.signal): Promise<ProvisionProcess> {
    return this.adminProcess(argv, signal);
  }

  startRelayService(relay: ProvisionRelay): Promise<ProvisionProcess> {
    this.checkRelay(relay);
    this.owner.check();
    return this.adminProcess(relayServiceArgv(this.owner.run), this.containment.signal, true);
  }

  get relayServiceAttempted(): boolean {
    return this.serviceAttempted;
  }

  private async adminProcess(argv: readonly string[], signal: AbortSignal,
    service = false): Promise<ProvisionProcess> {
    this.pending++;
    try {
      await this.frame('Running', service ? this.owner.signal : signal);
      requireProvision(this.key && this.knownHosts && this.sshPort, 'guest_unauthenticated');
      requireProvision(argv.every(arg => /^[A-Za-z0-9_./:=,@%+-]+$/.test(arg)), 'admin_argv_invalid');
      await this.key.check();
      const temporary = await this.root.directory('command-' + this.temporaryOrdinal++);
      if (service) requireProvision(!this.stopped, 'vm_closed');
      if (service) this.serviceAttempted = true;
      const child = new ProvisionProcess({
        executable: '/usr/bin/ssh', home: this.root.root, limaHome: join(this.root.root, '.lima'), temporary,
        argv: sshArgv({ knownHosts: this.knownHosts, name: this.name,
          key: this.key.path, port: this.sshPort }, argv),
      }, signal);
      this.commands.add(child);
      if (service) this.service = child;
      this.observeProcess(child);
      return child;
    } finally { this.settledAllocation(); }
  }

  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.closing = Promise.resolve().then(() => this.contain());
    void this.closing.then(this.resolveDrain,
      error => this.rejectDrain(error instanceof Error ? error : new ProvisionError('vm_drain_unconfirmed')));
    this.relay?.beginClose();
    this.owner.revoke('vm_closed');
    for (const command of this.commands) {
      if (command !== this.foreground && command !== this.service) command.stop();
    }
    if (this.pending === 0) this.resolveAllocations();
  }

  private async contain(): Promise<void> {
    let failure: unknown;
    try { await this.relay?.beforeVmStop(); }
    catch (error) { failure = error; }
    this.foreground?.stop();
    await this.allocationsDrained;
    const processes = await Promise.allSettled([...this.commands].map(command => command.drain()));
    const observers = await Promise.allSettled([this.relay?.drained, this.events?.close()]);
    this.owner.signal.removeEventListener('abort', this.abort);
    this.containment.abort();
    requireProvision(failure === undefined && [...processes, ...observers]
      .every(result => result.status === 'fulfilled'), 'vm_drain_unconfirmed');
  }

  async remove(): Promise<boolean> {
    const cleanupSignal = AbortSignal.timeout(120_000);
    try {
      await this.drained;
      if (this.profile) {
        await this.frame('Stopped', cleanupSignal);
        const deletion = await this.command(['delete', this.name], cleanupSignal);
        await deletion.output();
        requireProvision(await provisionAbsent(this.directory), 'vm_delete_unconfirmed');
      }
      await this.events?.close();
      await this.machine?.close();
      await this.config?.close();
      await this.key?.close();
      return true;
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      return false;
    }
  }
}
