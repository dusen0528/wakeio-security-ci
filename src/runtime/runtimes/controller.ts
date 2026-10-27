import { createHash, randomUUID } from 'node:crypto';
import { constants, type Stats } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readdir, realpath, rm, writeFile, type FileHandle } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';
import { runRuntimeProcess, type RuntimeProcessResult } from '../process.js';

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
const MISSING = ['rootfs-and-docker-extras-byte-verification', 'lima-helper-assets-byte-verification',
  'rootless-daemon-and-admin-relay',
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
const BOOT_GUARDS = [
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
].join('\n') + '\n';
const MISSING_PREREQUISITE_TRAILER = [
  'echo "wakeio_missing_prerequisite: verified packages, daemon relay, nft/proxy and probes" >&2', 'exit 125',
].join('\n') + '\n';
const BOOT = BOOT_GUARDS + MISSING_PREREQUISITE_TRAILER;

/** Pure config compilation; input is trusted tool metadata, never TargetSpec/source config or shell text. */
export function compileLimaProfileConfig(raw: LimaPins): string {
  const p = pins(raw);
  // Package pins remain in trusted controller input; neither provision script consumes Docker assets yet.
  // Lima param is reserved for actual template references, not unused metadata or a socket readiness claim.
  return JSON.stringify({ minimumLimaVersion: '1.0.3', vmType: 'vz', arch: p.rootfs.arch,
    images: [{ location: p.rootfs.url, digest: 'sha256:' + p.rootfs.sha256, arch: p.rootfs.arch }],
    cpus: 2, memory: '4GiB', disk: '20GiB', mounts: [], additionalDisks: [], networks: [],
    ssh: { forwardAgent: false, loadDotSSHPubKeys: false, forwardX11: false, forwardX11Trusted: false },
    propagateProxyEnv: false, hostResolver: { enabled: false, hosts: {} }, env: {},
    containerd: { system: false, user: false }, rosetta: { enabled: false, binfmt: false },
    user: { name: 'wakeio-admin', uid: 10000, home: '/home/wakeio-admin' },
    portForwards: [{ guestSocket: '/run/wakeio-m1/relay.sock', hostSocket: '{{.Dir}}/sock/docker.sock' },
      { guestIP: '0.0.0.0', guestPortRange: [1, 65535], proto: 'any', ignore: true }],
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
  profileId?: Identity; storeId?: Identity; groupConfirmed = true; done = false; busy = false;
  protected cleaning?: Promise<ProfileCleanup>;
  constructor(readonly config: LimaProfileOptions, readonly home: string, readonly homeId: Identity,
    protected readonly execute: typeof runRuntimeProcess) {
    this.store = join(home, '.lima'); this.directory = join(this.store, this.name);
  }
  async tool(args: string[], deadlineAt: number, signal?: AbortSignal) {
    await same(this.home, this.homeId);
    if (((await lstat(this.home)).mode & 0o777) !== 0o700) invalid();
    await this.verifyAssets();
    let result: RuntimeProcessResult;
    try {
      result = await this.execute(this.config.limactlExecutable, ['--tty=false', ...args], {
        cwd: this.home, home: this.home, timeoutMs: 30_000, deadlineAt, maxOutputBytes: 16 * 1024, signal });
    } catch { this.groupConfirmed = false; return invalid(); }
    this.groupConfirmed &&= result.cleanupConfirmed === true;
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
  async verifyAssets(_profileExists = true): Promise<void> { /* Default stopped-only lane has no OS assets. */ }
  cleanup(): Promise<ProfileCleanup> {
    if (this.busy) return Promise.resolve({ confirmed: false, reasons: ['owned_profile_boot_in_progress'] });
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
      await this.verifyAssets();
      if (this.profileId) {
        await this.listed(deadline);
        await this.tool(['delete', this.name], deadline); // No force, running VM stop or global prune authority.
      }
      if (!this.groupConfirmed || !await absent(this.directory)) invalid();
      if (this.storeId) {
        await same(this.store, this.storeId);
        const metadata = ['_config', '_networks', '_disks', '_cache'];
        if ((await readdir(this.store)).some(name => !metadata.includes(name))) invalid();
      }
      await this.verifyAssets(false);
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
  return prepare(raw, runRuntimeProcess);
}

/** @internal Trusted composition/fault-injection seam; never supplied through source or profile options. */
export function createLimaProfilePreparer(execute: typeof runRuntimeProcess) {
  return (raw: LimaProfileOptions): Promise<LimaPreparation> => prepare(raw, execute);
}

async function prepare(raw: LimaProfileOptions, execute: typeof runRuntimeProcess): Promise<LimaPreparation> {
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
    profile = new Profile(selected, home, await identity(home), execute);
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

export const MAX_LIMA_ROOTFS_BYTES = 2 * 1024 * 1024 * 1024;
export interface LimaOsOptions extends LimaProfileOptions { rootfsFile: string }
export interface LimaOsBoot {
  status: 'unavailable'; verified: false; phase: 'running_observed_then_stopped' | 'failed';
  cleanup?: ProfileCleanup;
}
export interface OwnedLimaOsProfile extends OwnedLimaProfile {
  readonly rootfsSha256: string; readonly machineIdentitySha256: string;
  boot(): Promise<LimaOsBoot>;
}
export interface LimaOsPreparation extends Omit<LimaPreparation, 'lease'> { lease?: OwnedLimaOsProfile }
export interface OsPrerequisites {
  kind: 'os-prerequisites'; observed: boolean; backendVerified: false;
}
export interface LimaOsProbeCapability { probe(): Promise<Readonly<OsPrerequisites>> }
export type LimaOsSessionUse = (capability: Readonly<LimaOsProbeCapability>) => Promise<void>;
export interface LimaOsSessionResult {
  status: 'unavailable'; verified: false; phase: 'consent_required' | 'failed' | 'callback_completed';
  guestPrerequisitesObserved: boolean; cleanup?: ProfileCleanup; pendingHome?: string;
}
const OS_OWNERS = new WeakMap<OwnedLimaOsProfile, OsProfile>();
const OS_SESSION_MS = 30_000;
const GUEST_PROBE = [
  'set -eu', 'test "$(/usr/bin/id -u wakeio-m1)" = 10001 || exit 125',
  'if /usr/bin/sudo -n -l -U wakeio-m1 >/dev/null 2>&1; then exit 125; fi',
  'test "$(/usr/bin/stat -fc %T /sys/fs/cgroup)" = cgroup2fs || exit 125',
  'cg=/sys/fs/cgroup/user.slice/user-10001.slice/user@10001.service',
  'for controller in cpu memory pids; do /usr/bin/grep -qw "$controller" "$cg/cgroup.controllers" || exit 125; done',
  'test "$(/usr/bin/sudo -n -u wakeio-m1 /usr/bin/id -u)" = 10001 || exit 125',
  '/usr/bin/sudo -n -u wakeio-m1 /usr/bin/test -w "$cg/cgroup.procs" || exit 125',
  '/usr/bin/sudo -n -u wakeio-m1 /usr/bin/test -w "$cg/cgroup.subtree_control" || exit 125',
  "printf 'wakeio-os-prerequisites/v1\\n'",
].join('\n');
type FileIdentity = Identity & { size: number; mtimeMs: number; ctimeMs: number };
type BoundFile = { path: string; identity: FileIdentity };
const FILE_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
function fileIdentity(info: Stats, limit = MAX_LIMA_ROOTFS_BYTES): FileIdentity {
  if (!info.isFile() || info.nlink !== 1 || info.uid !== process.getuid?.() || info.size > limit
    || (info.mode & 0o022) !== 0) invalid();
  return { dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs };
}
function equalFile(a: FileIdentity, b: FileIdentity): void {
  if (Object.keys(a).some(key => a[key as keyof FileIdentity] !== b[key as keyof FileIdentity])) invalid();
}
async function namedFile(path: string, handle: FileHandle, expected?: FileIdentity): Promise<FileIdentity> {
  const actual = fileIdentity(await handle.stat()), named = await lstat(path);
  if (named.isSymbolicLink()) invalid();
  equalFile(actual, fileIdentity(named)); if (expected) equalFile(actual, expected);
  return actual;
}
function remaining(config: LimaProfileOptions): void {
  if (config.signal?.aborted || Date.now() >= config.deadlineAt) invalid();
}
async function inputPath(raw: string): Promise<string> {
  if (Buffer.byteLength(raw) > 4096 || !isAbsolute(raw) || resolve(raw) !== raw
    || /[\x00-\x1f\x7f]/.test(raw)) invalid();
  let current = '/';
  for (const part of dirname(raw).split('/').filter(Boolean)) {
    current = join(current, part); const info = await lstat(current);
    if (info.isSymbolicLink()) {
      if (process.platform !== 'darwin' || !['/tmp', '/var'].includes(current)
        || await realpath(current) !== '/private' + current) invalid();
    } else if (!info.isDirectory()) invalid();
  }
  return join(await realpath(dirname(raw)), raw.slice(raw.lastIndexOf('/') + 1));
}
function osOptions(raw: LimaOsOptions): LimaOsOptions {
  const descriptors = Object.getOwnPropertyDescriptors(raw), rootfsFile = descriptors.rootfsFile;
  if (!rootfsFile || !('value' in rootfsFile) || !rootfsFile.enumerable
    || typeof rootfsFile.value !== 'string') invalid();
  const rest = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (key !== 'rootfsFile') Object.defineProperty(rest, key, descriptor);
  }
  return { ...options(rest), rootfsFile: rootfsFile.value };
}

class OsFiles {
  readonly homeFiles: BoundFile[] = []; readonly vmFiles: BoundFile[] = []; unsafe = false;
  constructor(readonly profile: Profile) {}
  async verify(includeVm = true): Promise<void> {
    if (this.unsafe) invalid();
    await same(this.profile.home, this.profile.homeId);
    if (((await lstat(this.profile.home)).mode & 0o777) !== 0o700) invalid();
    for (const bound of [...this.homeFiles, ...(includeVm ? this.vmFiles : [])]) {
      const handle = await open(bound.path, FILE_FLAGS);
      try { await namedFile(bound.path, handle, bound.identity); } finally { await handle.close(); }
    }
  }
  async seal(path: string, handle: FileHandle): Promise<void> {
    try { this.homeFiles.push({ path, identity: await namedFile(path, handle) }); }
    catch { this.unsafe = true; throw new TypeError('owned_os_file_identity_unknown'); }
    finally { await handle.close(); }
  }
  async write(name: string, bytes: string): Promise<void> {
    await this.verify(false);
    const path = join(this.profile.home, name);
    const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
      | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); }
    finally { await this.seal(path, handle); }
  }
  async capture(name: string, limit: number): Promise<Buffer> {
    await this.profile.checkIdentity();
    const path = join(this.profile.directory, name), handle = await open(path, FILE_FLAGS);
    try {
      const before = fileIdentity(await handle.stat(), limit);
      if (!before.size) invalid();
      const bytes = Buffer.alloc(before.size + 1), read = await handle.read(bytes, 0, bytes.length, 0);
      if (read.bytesRead !== before.size) invalid();
      await namedFile(path, handle, before); this.vmFiles.push({ path, identity: before });
      return bytes.subarray(0, before.size);
    } finally { await handle.close(); }
  }
}

async function copyRootfs(profile: OsProfile, config: LimaOsOptions): Promise<void> {
  remaining(config);
  const path = await inputPath(config.rootfsFile), source = await open(path, FILE_FLAGS);
  try {
    const before = fileIdentity(await source.stat());
    if (!before.size) invalid();
    await namedFile(path, source, before);
    const output = await open(join(profile.home, 'rootfs.img'), constants.O_CREAT | constants.O_EXCL
      | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try {
      const hash = createHash('sha256'), chunk = Buffer.alloc(64 * 1024); let used = 0;
      while (true) {
        remaining(config); await same(profile.home, profile.homeId);
        const { bytesRead } = await source.read(chunk, 0, chunk.length, used);
        if (!bytesRead) break;
        used += bytesRead; if (used > before.size || used > MAX_LIMA_ROOTFS_BYTES) invalid();
        hash.update(chunk.subarray(0, bytesRead)); await output.writeFile(chunk.subarray(0, bytesRead));
      }
      remaining(config); await namedFile(path, source, before);
      if (used !== before.size || hash.digest('hex') !== config.pins.rootfs.sha256) invalid();
      await output.sync();
    } finally { await profile.files.seal(join(profile.home, 'rootfs.img'), output); }
  } finally { await source.close(); }
}

async function verifyRootfs(profile: OsProfile): Promise<void> {
  await profile.files.verify(false); remaining(profile.config);
  const path = join(profile.home, 'rootfs.img'), handle = await open(path, FILE_FLAGS);
  try {
    const before = fileIdentity(await handle.stat()), hash = createHash('sha256');
    const bytes = Buffer.alloc(64 * 1024); let used = 0;
    while (true) {
      remaining(profile.config);
      const read = await handle.read(bytes, 0, bytes.length, used);
      if (!read.bytesRead) break;
      used += read.bytesRead; if (used > before.size) invalid();
      hash.update(bytes.subarray(0, read.bytesRead));
    }
    await namedFile(path, handle, before); await profile.files.verify(false);
    if (used !== before.size || hash.digest('hex') !== profile.config.pins.rootfs.sha256) invalid();
  } finally { await handle.close(); }
}

function osConfig(config: LimaOsOptions, home: string): string {
  const value = JSON.parse(compileLimaProfileConfig(config.pins));
  value.images[0].location = join(home, 'rootfs.img');
  value.upgradePackages = false; value.copyToHost = [];
  // Trusted OS-only provisioning: same boundary setup, with no package install, Docker or source execution.
  value.provision[0].script = BOOT_GUARDS;
  value.message = 'unavailable: OS-only boot observation; Docker, source and target execution remain disabled';
  return JSON.stringify(value) + '\n';
}

function startingStatus(data: Record<string, unknown>): 'Running' | 'pending' {
  const host = data.hostAgentPID === undefined ? 0 : data.hostAgentPID;
  const driver = data.driverPID === undefined ? 0 : data.driverPID;
  if (![host, driver].every(pid => typeof pid === 'number' && Number.isSafeInteger(pid) && pid >= 0)
    || Number(driver) > 0 && (host !== driver || Number(host) <= 0)
    || data.errors !== undefined && !Array.isArray(data.errors)) invalid();
  if (data.status === 'Running') {
    if (Number(host) <= 0 || host !== driver || data.errors !== undefined) invalid();
    return 'Running';
  }
  if (data.status === 'Stopped') {
    if (host !== 0 || driver !== 0 || data.errors !== undefined) invalid();
  } else if (data.status !== 'Installing' && data.status !== 'Broken') invalid();
  return 'pending'; // Even an identity-bound Broken frame is never readiness or cleanup evidence.
}

class OsProfile extends Profile {
  readonly files = new OsFiles(this); machineIdentitySha256?: string;
  private sessionUnknown = false;
  async verifyAssets(includeVm = true): Promise<void> {
    await this.files.verify(includeVm);
    if (includeVm && this.profileId && !this.machineIdentitySha256) invalid();
  }
  async bindMachine(): Promise<void> {
    // Lima 1.0.3 VZ Initialize creates opaque GenericMachineIdentifier bytes, not a list JSON UUID field.
    const machine = await this.files.capture('vz-identifier', 4096);
    await this.files.capture('lima.yaml', 1024 * 1024);
    this.machineIdentitySha256 = createHash('sha256').update(machine).digest('hex');
  }
  private async frame(deadline: number, signal?: AbortSignal): Promise<Record<string, unknown>> {
    await this.checkIdentity();
    const data = snapshotJsonData(JSON.parse(await this.tool(['list', '--format=json', this.name], deadline, signal)),
      invalid) as Record<string, unknown>;
    if (data.name !== this.name || data.dir !== this.directory || data.protected !== false
      || data.vmType !== 'vz' || data.arch !== this.config.pins.rootfs.arch
      || (data.limaVersion !== '1.0.3' && data.limaVersion !== 'v1.0.3')) invalid();
    await this.checkIdentity(); await this.verifyAssets(); return data;
  }
  async observe(deadline: number, signal?: AbortSignal): Promise<'Running' | 'Stopped'> {
    const data = await this.frame(deadline, signal);
    if (data.errors !== undefined) invalid();
    if (data.status === 'Running') {
      if (!Number.isSafeInteger(data.hostAgentPID) || Number(data.hostAgentPID) <= 0
        || data.hostAgentPID !== data.driverPID) invalid();
    } else if (data.status !== 'Stopped' || Number(data.hostAgentPID ?? 0) !== 0
      || Number(data.driverPID ?? 0) !== 0) invalid();
    return data.status as 'Running' | 'Stopped';
  }
  async listed(deadline: number, signal?: AbortSignal): Promise<Record<string, unknown>> {
    if (await this.observe(deadline, signal) !== 'Stopped') invalid();
    return { status: 'Stopped' };
  }
  async sessionPid(deadline: number, signal: AbortSignal): Promise<number | undefined> {
    const data = await this.frame(deadline, signal);
    return startingStatus(data) === 'Running' ? Number(data.hostAgentPID) : undefined;
  }
  foreground(deadline: number, signal: AbortSignal): Promise<RuntimeProcessResult | undefined> {
    return this.execute(this.config.limactlExecutable,
      ['--tty=false', 'start', '--foreground', '--timeout=30s', this.name], {
        cwd: this.home, home: this.home, timeoutMs: OS_SESSION_MS, deadlineAt: deadline,
        maxOutputBytes: 16 * 1024, signal }).then(result => {
      this.groupConfirmed &&= result.cleanupConfirmed === true && result.closeConfirmed === true; return result;
    }, () => { this.groupConfirmed = false; return undefined; });
  }
  async guestProbe(deadline: number, signal: AbortSignal): Promise<Readonly<OsPrerequisites>> {
    const args = ['--tty=false', 'shell', '--workdir=/', '--shell=/bin/bash', this.name, '--',
      '/usr/bin/sudo', '-n', '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
      '/bin/sh', '-c', GUEST_PROBE];
    let result: RuntimeProcessResult;
    try {
      result = await this.execute(this.config.limactlExecutable, args, { cwd: this.home, home: this.home,
        timeoutMs: 5_000, deadlineAt: deadline, maxOutputBytes: 16 * 1024, signal });
    } catch { this.groupConfirmed = false; return invalid(); }
    this.groupConfirmed &&= result.cleanupConfirmed === true && result.closeConfirmed === true;
    const absent = [125, 255].includes(result.exitCode ?? -1) && !result.signal && !result.stopReason
      && !result.spawnError && !result.timedOut && !result.cancelled
      && !result.outputLimitExceeded && result.stdout === '';
    if (!this.groupConfirmed || !result.completed && !absent) invalid();
    if (result.completed && result.stdout !== 'wakeio-os-prerequisites/v1\n') invalid();
    return Object.freeze({ kind: 'os-prerequisites', observed: result.completed, backendVerified: false });
  }
  markSessionUnknown(): void { this.sessionUnknown = true; }
  cleanup(): Promise<ProfileCleanup> {
    return this.sessionUnknown ? Promise.resolve({ confirmed: false, reasons: ['owned_session_cleanup_unconfirmed'] })
      : super.cleanup();
  }
  async session(use: LimaOsSessionUse): Promise<LimaOsSessionResult> {
    if (this.busy || this.done || this.cleaning || this.sessionUnknown) return sessionResult('failed');
    this.busy = true;
    const scope = new OsSession(this);
    try {
      remaining(this.config); await verifyRootfs(this); await this.files.verify();
      if (await this.observe(this.config.deadlineAt, this.config.signal) !== 'Stopped') invalid();
      await scope.run(use);
    } catch { scope.fail(); }
    finally { await scope.close(); this.busy = false; }
    const cleanup = await this.cleanup();
    if (!cleanup.confirmed) this.markSessionUnknown();
    return { ...sessionResult(!scope.failed && cleanup.confirmed ? 'callback_completed' : 'failed'),
      guestPrerequisitesObserved: !scope.failed && scope.observed, cleanup,
      ...(!cleanup.confirmed ? { pendingHome: this.home } : {}) };
  }
  async boot(): Promise<LimaOsBoot> {
    if (this.busy || this.done || this.cleaning) return { status: 'unavailable', verified: false, phase: 'failed' };
    this.busy = true;
    let observed = false, stopped = false, settled = false, deadline = 0;
    let supervised: RuntimeProcessResult | undefined;
    let pending: Promise<RuntimeProcessResult | undefined> | undefined;
    const controller = new AbortController(), onAbort = () => controller.abort();
    try {
      remaining(this.config); await verifyRootfs(this); await this.files.verify();
      if (await this.observe(this.config.deadlineAt, this.config.signal) !== 'Stopped') invalid();
      deadline = Math.min(this.config.deadlineAt, Date.now() + 30_000);
      this.config.signal?.addEventListener('abort', onAbort, { once: true });
      pending = this.execute(this.config.limactlExecutable,
        ['--tty=false', 'start', '--foreground', '--timeout=30s', this.name], {
          cwd: this.home, home: this.home, timeoutMs: 30_000, deadlineAt: deadline,
          maxOutputBytes: 16 * 1024, signal: controller.signal }).then(result => {
        this.groupConfirmed &&= result.cleanupConfirmed === true && result.closeConfirmed === true;
        settled = true; return result;
      }, () => { this.groupConfirmed = false; settled = true; return undefined; });
      while (!settled) {
        remaining(this.config);
        if (Date.now() >= deadline) invalid();
        const state = startingStatus(await this.frame(deadline, this.config.signal));
        if (settled) break;
        if (state === 'Running') {
          observed = true; break;
        }
        await delay(20);
      }
    } catch { /* The owned foreground group is always stopped before any VM deletion is attempted. */ }
    finally {
      controller.abort(); supervised = await pending;
      this.config.signal?.removeEventListener('abort', onAbort);
      try {
        if (!this.groupConfirmed) invalid();
        stopped = await this.observe(Date.now() + 10_000) === 'Stopped';
      } catch { /* Running, reused PID, changed identity or unknown status never authorizes delete. */ }
      this.busy = false;
    }
    if (observed && stopped && supervised?.cancelled === true && supervised.cleanupConfirmed === true
      && this.groupConfirmed && !this.config.signal?.aborted && Date.now() < deadline) {
      return { status: 'unavailable', verified: false, phase: 'running_observed_then_stopped' };
    }
    return { status: 'unavailable', verified: false, phase: 'failed', cleanup: await this.cleanup() };
  }
  osLease(): OwnedLimaOsProfile {
    if (!this.machineIdentitySha256) invalid();
    const lease = Object.freeze({ ...this.lease(), rootfsSha256: this.config.pins.rootfs.sha256,
      machineIdentitySha256: this.machineIdentitySha256, boot: () => this.boot() });
    OS_OWNERS.set(lease, this); return lease;
  }
}

function sessionResult(phase: LimaOsSessionResult['phase']): LimaOsSessionResult {
  return { status: 'unavailable', verified: false, phase, guestPrerequisitesObserved: false };
}
type SessionBinary = BoundFile & { sha256: string };
async function bindSessionBinary(owner: OsProfile, deadline: number, signal?: AbortSignal): Promise<SessionBinary> {
  const path = await inputPath(owner.config.limactlExecutable), handle = await open(path, FILE_FLAGS);
  try {
    const before = fileIdentity(await handle.stat(), 64 * 1024 * 1024), bytes = Buffer.alloc(64 * 1024);
    const hash = createHash('sha256'); let offset = 0;
    while (true) {
      if (signal?.aborted || Date.now() >= deadline) invalid();
      const { bytesRead } = await handle.read(bytes, 0, bytes.length, offset);
      if (!bytesRead) break;
      offset += bytesRead; if (offset > before.size) invalid(); hash.update(bytes.subarray(0, bytesRead));
    }
    await namedFile(path, handle, before);
    if (offset !== before.size) invalid();
    return { path, identity: before, sha256: hash.digest('hex') };
  } finally { await handle.close(); }
}

class OsSession {
  readonly controller = new AbortController(); readonly deadline: number;
  failed = false; observed = false; private open = false; private stopping = false; private pid?: number;
  private foreground?: Promise<RuntimeProcessResult | undefined>; private monitor?: Promise<void>;
  private active?: Promise<Readonly<OsPrerequisites>>; private binary?: SessionBinary; private timer?: NodeJS.Timeout;
  private wake!: () => void; private readonly lost = new Promise<void>(resolve => { this.wake = resolve; });
  private readonly onAbort = () => this.fail();
  constructor(readonly owner: OsProfile) {
    this.deadline = Math.min(owner.config.deadlineAt, Date.now() + OS_SESSION_MS);
  }
  fail(): void {
    this.failed = true; this.open = false; this.controller.abort(); this.wake();
  }
  private async checkBinary(): Promise<void> {
    if (!this.binary) invalid();
    const handle = await open(this.binary.path, FILE_FLAGS);
    try { await namedFile(this.binary.path, handle, this.binary.identity); }
    finally { await handle.close(); }
  }
  private async checkpoint(): Promise<void> {
    if (this.controller.signal.aborted || Date.now() >= this.deadline) invalid();
    await this.checkBinary();
    const pid = await this.owner.sessionPid(this.deadline, this.controller.signal);
    await this.checkBinary();
    if (pid === undefined || pid !== this.pid) invalid();
  }
  private probe(args: unknown[]): Promise<Readonly<OsPrerequisites>> {
    if (!this.open || this.failed || this.controller.signal.aborted || args.length || this.active) {
      if (this.open) this.fail();
      return Promise.reject(new TypeError('closed_os_probe_capability'));
    }
    const job = (async () => {
      await this.checkpoint();
      const answer = await this.owner.guestProbe(this.deadline, this.controller.signal);
      await this.checkpoint(); this.observed = answer.observed; return answer;
    })().catch(() => { this.fail(); return invalid(); });
    this.active = job;
    void job.then(() => { if (this.active === job) this.active = undefined; },
      () => { if (this.active === job) this.active = undefined; });
    return job;
  }
  private async watch(): Promise<void> {
    try {
      while (!this.stopping) {
        await this.checkpoint(); await delay(20, undefined, { signal: this.controller.signal });
      }
    } catch { if (!this.stopping) this.fail(); }
  }
  async run(use: LimaOsSessionUse): Promise<void> {
    this.binary = await bindSessionBinary(this.owner, this.deadline, this.owner.config.signal);
    await this.checkBinary();
    this.owner.config.signal?.addEventListener('abort', this.onAbort, { once: true });
    this.timer = setTimeout(() => this.fail(), Math.max(0, this.deadline - Date.now()));
    this.foreground = this.owner.foreground(this.deadline, this.controller.signal).then(result => {
      if (!this.stopping) this.fail(); return result;
    });
    while (!this.controller.signal.aborted) {
      await this.checkBinary();
      const pid = await this.owner.sessionPid(this.deadline, this.controller.signal);
      if (this.failed) invalid();
      if (pid !== undefined) { this.pid = pid; break; }
      await delay(20, undefined, { signal: this.controller.signal });
    }
    await this.checkpoint(); if (this.failed) invalid(); this.open = true; this.monitor = this.watch();
    const capability = Object.freeze({ probe: (...args: unknown[]) => this.probe(args) });
    const callback = Promise.resolve().then(() => {
      if (!this.open || this.failed || Date.now() >= this.deadline) invalid(); return use(capability);
    }).then(() => undefined, () => { this.fail(); });
    await Promise.race([callback, this.lost]);
    if (this.active) this.fail();
  }
  async close(): Promise<void> {
    this.open = false; this.stopping = true; this.controller.abort(); clearTimeout(this.timer);
    this.owner.config.signal?.removeEventListener('abort', this.onAbort);
    await Promise.allSettled([this.foreground, this.monitor, this.active]);
    try {
      const deadline = Date.now() + 10_000;
      if (!this.owner.groupConfirmed) invalid();
      await this.checkBinary();
      if ((await bindSessionBinary(this.owner, deadline)).sha256 !== this.binary?.sha256) invalid();
      if (await this.owner.observe(deadline) !== 'Stopped') invalid();
      await this.checkBinary();
    } catch { this.failed = true; this.owner.markSessionUnknown(); }
  }
}

/** Trusted asynchronous callback only; options remain data and cannot supply shell/code/installation authority. */
export async function withLimaOsSession(raw: LimaOsOptions, use: LimaOsSessionUse): Promise<LimaOsSessionResult> {
  return session(raw, use, runRuntimeProcess);
}
/** @internal Uses the same supervised default; fault injection never enters raw TargetSpec/options. */
export function createLimaOsSessionRunner(execute: typeof runRuntimeProcess) {
  return (raw: LimaOsOptions, use: LimaOsSessionUse) => session(raw, use, execute);
}
async function session(raw: LimaOsOptions, use: LimaOsSessionUse,
  execute: typeof runRuntimeProcess): Promise<LimaOsSessionResult> {
  if (!consent(raw)) return sessionResult('consent_required');
  if (typeof use !== 'function' || types.isProxy(use)) return sessionResult('failed');
  const prepared = await prepareOs(raw, execute);
  if (!prepared.lease || prepared.reason !== 'missing_prerequisite') return {
    ...sessionResult('failed'), ...(prepared.cleanup ? { cleanup: prepared.cleanup } : {}),
    ...(prepared.pendingHome ? { pendingHome: prepared.pendingHome } : {}) };
  const owner = OS_OWNERS.get(prepared.lease);
  return owner ? owner.session(use) : sessionResult('failed');
}

/** Internal OS-only lane, disconnected from target execution and isolation verification. Local bytes only. */
export async function prepareLimaOsProfile(raw: LimaOsOptions): Promise<LimaOsPreparation> {
  return prepareOs(raw, runRuntimeProcess);
}
/** @internal Synthetic trusted tool seam; not a TargetSpec/raw option capability. */
export function createLimaOsPreparer(execute: typeof runRuntimeProcess) {
  return (raw: LimaOsOptions): Promise<LimaOsPreparation> => prepareOs(raw, execute);
}
async function prepareOs(raw: LimaOsOptions, execute: typeof runRuntimeProcess): Promise<LimaOsPreparation> {
  if (!consent(raw)) return { status: 'unavailable', verified: false, reason: 'consent_required',
    missingPrerequisites: ['execute-target-consent'] };
  let profile: OsProfile | undefined;
  try {
    const selected = osOptions(raw); remaining(selected);
    selected.deadlineAt = Math.min(selected.deadlineAt, Date.now() + 600_000);
    const base = await realpath(selected.baseDirectory);
    if (!base.startsWith(await realpath('/tmp') + '/')) invalid();
    await identity(base); const home = await mkdtemp(join(base, 'wk-lima-'));
    profile = new OsProfile(selected, home, await identity(home), execute);
    if (Buffer.byteLength(join(profile.directory, 'sock/docker.sock')) > 100) invalid();
    await copyRootfs(profile, selected);
    await verifyRootfs(profile);
    await profile.files.write('profile.yaml', osConfig(selected, home));
    await mkdir(profile.store, { mode: 0o700 }); profile.storeId = await identity(profile.store);
    if (await profile.tool(['--version'], selected.deadlineAt, selected.signal) !== 'limactl version 1.0.3') invalid();
    if (!await absent(profile.directory)) invalid();
    try {
      await profile.tool(['create', '--name=' + profile.name, '--cpus=2', '--memory=4', '--disk=20',
        join(home, 'profile.yaml')], selected.deadlineAt, selected.signal);
    } finally {
      if (profile.groupConfirmed && !await absent(profile.directory)) {
        await same(home, profile.homeId); await same(profile.store, profile.storeId);
        profile.profileId = await identity(profile.directory); await profile.bindMachine();
      }
    }
    if (await profile.observe(selected.deadlineAt, selected.signal) !== 'Stopped') invalid();
    return { status: 'unavailable', verified: false, reason: 'missing_prerequisite',
      missingPrerequisites: ['docker-extras-byte-verification', ...MISSING.slice(1)], lease: profile.osLease() };
  } catch {
    const cleanup = profile ? await profile.cleanup() : undefined;
    return { status: 'unavailable', verified: false, reason: 'prepare_failed', missingPrerequisites: MISSING,
      ...(cleanup ? { cleanup } : {}), ...(profile && cleanup?.confirmed === false ? { pendingHome: profile.home,
        ...(profile.machineIdentitySha256 ? { lease: profile.osLease() } : {}) } : {}) };
  }
}
