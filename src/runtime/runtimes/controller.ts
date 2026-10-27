import { randomUUID } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';
import { runRuntimeProcess } from '../process.js';

export interface LimaPins {
  rootfs: { url: string; sha256: string; arch: 'aarch64' | 'x86_64' };
  dockerExtras: { url: string; version: string; sha256: string };
}
export interface LimaProfileOptions {
  executeTargetConsent: true; baseDirectory: string; limactlExecutable: string;
  pins: LimaPins; deadlineAt: number; signal?: AbortSignal;
}
export interface ProfileCleanup { confirmed: boolean; reasons: string[] }
export interface OwnedLimaProfile {
  readonly name: string; readonly home: string; readonly directory: string;
  readonly profileIdentity: Readonly<{ dev: number; ino: number }>;
  cleanup(): Promise<ProfileCleanup>;
}
export interface LimaPreparation {
  status: 'unavailable'; verified: false; reason: 'consent_required' | 'missing_prerequisite' | 'prepare_failed';
  missingPrerequisites: readonly string[]; lease?: OwnedLimaProfile; cleanup?: ProfileCleanup; pendingHome?: string;
}
const MISSING = ['rootfs-and-docker-extras-byte-verification', 'rootless-daemon-and-admin-relay',
  'proxy-and-nft-readiness', 'vm-id-and-resource-egress-probes'] as const;
function invalid(): never { throw new TypeError('invalid_lima_profile'); }
function object(raw: unknown, keys: string[]): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) invalid();
  const value = raw as Record<string, unknown>;
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) invalid();
  return value;
}
function consent(raw: unknown): boolean {
  if (!raw || typeof raw !== 'object' || types.isProxy(raw)) return false;
  return Object.getOwnPropertyDescriptor(raw, 'executeTargetConsent')?.value === true;
}
function pins(raw: unknown): LimaPins {
  const p = object(snapshotJsonData(raw, invalid), ['rootfs', 'dockerExtras']);
  const image = object(p.rootfs, ['url', 'sha256', 'arch']);
  const extras = object(p.dockerExtras, ['url', 'version', 'sha256']);
  const arch = image.arch === 'aarch64' ? 'arm64' : image.arch === 'x86_64' ? 'amd64' : invalid();
  const imageUrl = new RegExp('^https://cloud-images\\.ubuntu\\.com/releases/noble/release-\\d{8}/'
    + `ubuntu-24\\.04-server-cloudimg-${arch}\\.img$`);
  const version = extras.version;
  if (typeof version !== 'string' || !/^(?:\d+:)?\d+\.\d+\.\d+-\d+~ubuntu\.24\.04~noble$/.test(version)) invalid();
  const packageUrl = 'https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/'
    + `${arch}/docker-ce-rootless-extras_${version.replace(/^\d+:/, '')}_${arch}.deb`;
  if (typeof image.url !== 'string' || !imageUrl.test(image.url)
    || extras.url !== packageUrl
    || ![image.sha256, extras.sha256].every(hash => typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash))) invalid();
  return p as unknown as LimaPins;
}
function options(raw: LimaProfileOptions): LimaProfileOptions {
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  if (Object.values(descriptors).some(d => !('value' in d) || !d.enumerable)) invalid();
  const signal = descriptors.signal?.value;
  if (signal !== undefined && (types.isProxy(signal) || !(signal instanceof AbortSignal))) invalid();
  const data = snapshotJsonData(Object.fromEntries(Object.entries(descriptors)
    .filter(([name]) => name !== 'signal').map(([name, d]) => [name, d.value])), invalid);
  const value = object(data, ['executeTargetConsent', 'baseDirectory', 'limactlExecutable', 'pins', 'deadlineAt']);
  for (const name of ['baseDirectory', 'limactlExecutable']) {
    if (typeof value[name] !== 'string' || !isAbsolute(value[name]) || /[\x00-\x1f\x7f]/.test(value[name])) invalid();
  }
  if (!Number.isSafeInteger(value.deadlineAt) || Number(value.deadlineAt) <= Date.now()) invalid();
  return { ...value, pins: pins(value.pins), signal } as unknown as LimaProfileOptions;
}

// Trusted setup only. No Docker install/start or source is permitted before the remaining barriers exist.
const BOOT = [
  '#!/bin/sh', 'set -eu',
  "sed -i '/host\\.lima\\.internal/d; /host\\.docker\\.internal/d' /etc/hosts",
  "if grep -Eq 'host\\.(lima|docker)\\.internal' /etc/hosts; then exit 125; fi",
  'test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs || exit 125',
  'id wakeio-m1 >/dev/null 2>&1 || useradd --uid 10001 --create-home --shell /bin/bash wakeio-m1',
  'test "$(id -u wakeio-m1)" = 10001 || exit 125',
  'if sudo -n -l -U wakeio-m1 >/dev/null 2>&1; then exit 125; fi',
  'for file in /etc/subuid /etc/subgid; do',
  '  touch "$file"',
  '  awk -F: \'$1 != "wakeio-m1" && $2 <= 296607 && $2 + $3 > 231072 {exit 1}\' "$file" || exit 125',
  '  if grep -q "^wakeio-m1:" "$file"; then',
  '    test "$(grep "^wakeio-m1:" "$file")" = "wakeio-m1:231072:65536" || exit 125',
  '  else echo "wakeio-m1:231072:65536" >> "$file"; fi', 'done',
  'mkdir -p /etc/systemd/system/user@10001.service.d',
  'cat > /etc/systemd/system/user@10001.service.d/wakeio.conf <<\'EOF\'',
  '[Service]', 'Delegate=cpu cpuset io memory pids', 'CPUQuota=200%', 'MemoryMax=2G', 'TasksMax=256', 'EOF',
  'systemctl daemon-reload', 'loginctl enable-linger wakeio-m1',
  'echo "wakeio_missing_prerequisite: verified packages, daemon relay, nft/proxy and probes" >&2', 'exit 125',
].join('\n') + '\n';

/** Pure config compilation; input is trusted tool metadata, never TargetSpec/source config or shell text. */
export function compileLimaProfileConfig(raw: LimaPins): string {
  const p = pins(raw);
  return JSON.stringify({ minimumLimaVersion: '1.0.3', vmType: 'vz', arch: p.rootfs.arch,
    images: [{ location: p.rootfs.url, digest: 'sha256:' + p.rootfs.sha256, arch: p.rootfs.arch }],
    cpus: 2, memory: '4GiB', disk: '20GiB', mounts: [], additionalDisks: [], networks: [],
    ssh: { forwardAgent: false, loadDotSSHPubKeys: false, forwardX11: false, forwardX11Trusted: false },
    propagateProxyEnv: false, hostResolver: { enabled: false, hosts: {} }, env: {},
    containerd: { system: false, user: false }, rosetta: { enabled: false, binfmt: false },
    user: { name: 'wakeio-admin', uid: 10000, home: '/home/wakeio-admin' },
    portForwards: [{ guestSocket: '/run/wakeio-m1/relay.sock', hostSocket: '{{.Dir}}/sock/docker.sock' },
      { guestIP: '0.0.0.0', guestPortRange: [1, 65535], proto: 'any', ignore: true }],
    param: { dockerExtrasUrl: p.dockerExtras.url, dockerExtrasSha256: p.dockerExtras.sha256,
      dockerExtrasVersion: p.dockerExtras.version, rootlessSocket: '/run/user/10001/docker.sock' },
    provision: [{ mode: 'system', script: BOOT }],
    message: 'unavailable: bootstrap/probes incomplete; management SSH22 is the sole TCP forwarding exception',
  }) + '\n';
}
type Identity = { dev: number; ino: number };
async function identity(path: string): Promise<Identity> {
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.()) invalid();
  return { dev: info.dev, ino: info.ino };
}
async function same(path: string, expected: Identity): Promise<void> {
  const now = await identity(path);
  if (now.dev !== expected.dev || now.ino !== expected.ino) invalid();
}
async function absent(path: string): Promise<boolean> {
  try { await lstat(path); return false; }
  catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return true; }
  return false;
}

class Profile {
  readonly name = 'wk-' + randomUUID().replaceAll('-', '').slice(0, 12);
  readonly store: string; readonly directory: string;
  profileId?: Identity; storeId?: Identity; groupConfirmed = true; done = false;
  private cleaning?: Promise<ProfileCleanup>;
  constructor(readonly config: LimaProfileOptions, readonly home: string, readonly homeId: Identity) {
    this.store = join(home, '.lima'); this.directory = join(this.store, this.name);
  }
  async tool(args: string[], deadlineAt: number, signal?: AbortSignal) {
    await same(this.home, this.homeId);
    if (((await lstat(this.home)).mode & 0o777) !== 0o700) invalid();
    const result = await runRuntimeProcess(this.config.limactlExecutable, ['--tty=false', ...args], {
      cwd: this.home, home: this.home, timeoutMs: 30_000, deadlineAt, maxOutputBytes: 16 * 1024, signal });
    this.groupConfirmed = result.cleanupConfirmed === true;
    if (!result.completed) invalid();
    return result.stdout.trim();
  }
  async listed(deadline: number, signal?: AbortSignal): Promise<Record<string, unknown>> {
    await this.checkIdentity();
    const raw = await this.tool(['list', '--format=json', this.name], deadline, signal);
    const data = snapshotJsonData(JSON.parse(raw), invalid) as Record<string, unknown>;
    if (data.name !== this.name || data.dir !== this.directory || data.protected !== false
      || data.status !== 'Stopped' || data.hostAgentPID !== undefined && data.hostAgentPID !== 0
      || data.driverPID !== undefined && data.driverPID !== 0) invalid();
    await this.checkIdentity(); return data;
  }
  async checkIdentity(): Promise<void> {
    if (!this.profileId || !this.storeId) invalid();
    await same(this.home, this.homeId); await same(this.store, this.storeId);
    await same(this.directory, this.profileId);
  }
  cleanup(): Promise<ProfileCleanup> {
    if (this.done) return Promise.resolve({ confirmed: true, reasons: [] });
    if (!this.cleaning) this.cleaning = this.remove().finally(() => { this.cleaning = undefined; });
    return this.cleaning;
  }
  private async remove(): Promise<ProfileCleanup> {
    try {
      if (!this.groupConfirmed) invalid();
      const deadline = Date.now() + 10_000;
      await same(this.home, this.homeId);
      if (((await lstat(this.home)).mode & 0o777) !== 0o700) invalid();
      if (this.profileId) {
        await this.listed(deadline);
        await this.tool(['delete', this.name], deadline); // No force, running VM stop or global prune authority.
      }
      if (!await absent(this.directory)) invalid();
      if (this.storeId) {
        await same(this.store, this.storeId);
        const metadata = ['_config', '_networks', '_disks', '_cache'];
        if ((await readdir(this.store)).some(name => !metadata.includes(name))) invalid();
      }
      await same(this.home, this.homeId);
      await rm(this.home, { recursive: true });
      if (!await absent(this.home)) invalid();
      this.done = true; return { confirmed: true, reasons: [] };
    } catch { return { confirmed: false, reasons: ['owned_profile_cleanup_unconfirmed'] }; }
  }
  lease(): OwnedLimaProfile {
    if (!this.profileId) invalid();
    return Object.freeze({ name: this.name, home: this.home, directory: this.directory,
      profileIdentity: Object.freeze({ ...this.profileId }), cleanup: () => this.cleanup() });
  }
}

/** Only creates an owned, stopped profile. No start/shell/Docker/target authority; backend stays unavailable. */
export async function prepareLimaProfile(raw: LimaProfileOptions): Promise<LimaPreparation> {
  if (!consent(raw)) return { status: 'unavailable', verified: false, reason: 'consent_required',
    missingPrerequisites: ['execute-target-consent'] };
  let profile: Profile | undefined;
  try {
    const selected = options(raw), config = compileLimaProfileConfig(selected.pins);
    if (selected.signal?.aborted) invalid();
    const base = await realpath(selected.baseDirectory);
    if (!base.startsWith(await realpath('/tmp') + '/')) invalid();
    await identity(base);
    const home = await mkdtemp(join(base, 'wk-lima-'));
    profile = new Profile(selected, home, await identity(home));
    if (Buffer.byteLength(join(profile.directory, 'sock/docker.sock')) > 100) invalid();
    await mkdir(profile.store, { mode: 0o700 }); profile.storeId = await identity(profile.store);
    const filename = join(home, 'profile.yaml');
    await writeFile(filename, config, { flag: 'wx', mode: 0o600 });
    const version = await profile.tool(['--version'], selected.deadlineAt, selected.signal);
    if (version !== 'limactl version 1.0.3') invalid();
    if (!await absent(profile.directory)) invalid();
    try {
      await profile.tool(['create', '--name=' + profile.name, '--cpus=2', '--memory=4', '--disk=20', filename],
        selected.deadlineAt, selected.signal);
    } finally {
      if (profile.groupConfirmed && !await absent(profile.directory)) {
        if (!profile.storeId) invalid();
        await same(profile.home, profile.homeId); await same(profile.store, profile.storeId);
        profile.profileId = await identity(profile.directory);
      }
    }
    await profile.listed(selected.deadlineAt, selected.signal);
    return { status: 'unavailable', verified: false, reason: 'missing_prerequisite',
      missingPrerequisites: MISSING, lease: profile.lease() };
  } catch {
    // Never infer VM ownership from an unbound partial directory or a serialized lease file.
    const cleanup = profile ? await profile.cleanup() : undefined;
    return { status: 'unavailable', verified: false, reason: 'prepare_failed', missingPrerequisites: MISSING,
      ...(cleanup ? { cleanup } : {}), ...(profile && cleanup?.confirmed === false ? {
        pendingHome: profile.home, ...(profile.profileId ? { lease: profile.lease() } : {}),
      } : {}) };
  }
}
