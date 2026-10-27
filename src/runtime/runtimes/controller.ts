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
const BOOT_FAILURES = ['bootstrap_failed', 'host_alias_present', 'cgroup_v2_missing', 'user_create_failed',
  'uid_mismatch', 'sudo_allowed', 'subid_overlap', 'subuid_mismatch', 'subgid_mismatch', 'delegation_missing'] as const;
const OS_STATE_COMMON = String.raw`
state_dir=/run/wakeio-m1-boot
state_file=$state_dir/boot-status
boot_identity() {
  boot=$(/usr/bin/cat /proc/sys/kernel/random/boot_id) || return 1
  printf '%s\n' "$boot" | /usr/bin/grep -Eq '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
}
state_directory() {
  test -d "$state_dir" && test ! -L "$state_dir" &&
    test "$(/usr/bin/stat -c '%u:%g:%a' "$state_dir")" = 0:0:700
}
state_metadata() {
  test -f "$state_file" && test ! -L "$state_file" &&
    test "$(/usr/bin/stat -c '%u:%g:%a:%h' "$state_file")" = 0:0:600:1 || return 1
  size=$(/usr/bin/stat -c %s "$state_file") || return 1
  test "$size" -gt 0 && test "$size" -le 192
}
`;
const BOOT_GUARDS = '#!/bin/sh\nset -eu\nexport LC_ALL=C\numask 077\nexec >/dev/null 2>&1\n'
  + OS_STATE_COMMON + String.raw`
test "$(id -u)" = 0 && boot_identity || exit 125
if test -L "$state_dir"; then exit 125; fi
if test ! -e "$state_dir"; then (umask 077; mkdir -m 700 "$state_dir") || exit 125; fi
state_directory || exit 125
write_state() {
  state_directory || return 1
  if test -e "$state_file" || test -L "$state_file"; then state_metadata || return 1; fi
  temporary=$(mktemp "$state_dir/.boot.XXXXXX") || return 1
  if ! printf 'wakeio-os-boot/v1 %s %s %s\n' "$boot" "$1" "$2" >"$temporary"; then
    rm -f -- "$temporary"; return 1
  fi
  if ! mv -T -- "$temporary" "$state_file"; then rm -f -- "$temporary"; return 1; fi
  state_metadata
}
step=bootstrap_failed
trap 'trap - EXIT; write_state failed "$step" || :; exit 125' EXIT
write_state pending bootstrap_pending
step=host_alias_present
sed -i '/host\.lima\.internal/d; /host\.docker\.internal/d' /etc/hosts
if grep -Eq 'host\.(lima|docker)\.internal' /etc/hosts; then exit 125
else test "$?" -eq 1 || exit 125; fi
step=cgroup_v2_missing
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs || exit 125
step=user_create_failed
id wakeio-m1 >/dev/null 2>&1 || useradd --uid 10001 --create-home --shell /bin/bash \
  -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 wakeio-m1
step=uid_mismatch
test "$(id -u wakeio-m1)" = 10001 || exit 125
step=sudo_allowed
if sudo -n -l -U wakeio-m1 >/dev/null 2>&1; then exit 125; fi
for file in /etc/subuid /etc/subgid; do
  step=bootstrap_failed
  touch "$file"
  step=subid_overlap
  awk -F: '$1 != "wakeio-m1" && $2 <= 296607 && $2 + $3 > 231072 {exit 1}' "$file" || exit 125
  case "$file" in /etc/subuid) step=subuid_mismatch;; /etc/subgid) step=subgid_mismatch;; esac
  if grep -q '^wakeio-m1:' "$file"; then
    test "$(grep '^wakeio-m1:' "$file")" = 'wakeio-m1:231072:65536' || exit 125
  else echo 'wakeio-m1:231072:65536' >> "$file"; fi
done
step=delegation_missing
mkdir -p /etc/systemd/system/user@10001.service.d
cat > /etc/systemd/system/user@10001.service.d/wakeio.conf <<'EOF'
[Service]
Delegate=cpu cpuset io memory pids
CPUQuota=200%
MemoryMax=2G
TasksMax=256
EOF
systemctl daemon-reload
loginctl enable-linger wakeio-m1
write_state complete none
trap - EXIT
`;
// Guard complete records only source-free OS preparation. Stopped profiles still reject the absent backend.
const MISSING_PREREQUISITE_TRAILER = 'exit 125\n';
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
    propagateProxyEnv: false, hostResolver: { enabled: false, hosts: {} }, env: {
      ftp_proxy: '', http_proxy: '', https_proxy: '', no_proxy: '',
      FTP_PROXY: '', HTTP_PROXY: '', HTTPS_PROXY: '', NO_PROXY: '' },
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
export type OsGuardReason = typeof BOOT_FAILURES[number] | 'none' | 'bootstrap_pending' | 'ssh_unavailable'
  | 'guard_unknown' | 'boot_metadata_invalid' | 'cgroup_procs_unwritable' | 'cgroup_subtree_unwritable';
export interface OsPrerequisites {
  kind: 'os-prerequisites'; observed: boolean; backendVerified: false;
  bootPhase: 'unknown' | 'pending' | 'failed' | 'complete'; reason: OsGuardReason;
}
export interface LimaOsProbeCapability { probe(): Promise<Readonly<OsPrerequisites>> }
export type LimaOsSessionUse = (capability: Readonly<LimaOsProbeCapability>) => Promise<void>;
export interface LimaOsSessionResult {
  status: 'unavailable'; verified: false; phase: 'consent_required' | 'failed' | 'callback_completed';
  guestPrerequisitesObserved: boolean; cleanup?: ProfileCleanup; pendingHome?: string;
}
const OS_OWNERS = new WeakMap<OwnedLimaOsProfile, OsProfile>();
const OS_SESSION_MS = 30_000;
const GUEST_PROBE = 'set -eu\nexec 2>/dev/null\n' + OS_STATE_COMMON + String.raw`
phase=unknown
probe_failure() { printf 'wakeio-os-prerequisites/v1:%s:%s\n' "$phase" "$1"; exit 125; }
metadata_failure() { phase=unknown; probe_failure boot_metadata_invalid; }
boot_identity || metadata_failure
if test ! -e "$state_dir"; then
  test ! -L "$state_dir" || metadata_failure
  phase=pending; probe_failure bootstrap_pending
fi
state_directory || metadata_failure
if test ! -e "$state_file"; then
  test ! -L "$state_file" || metadata_failure
  phase=pending; probe_failure bootstrap_pending
fi
state_metadata || metadata_failure
metadata=$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "$state_file") || metadata_failure
exec 3< "$state_file" || metadata_failure
fd_metadata=$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%s:%y:%z' /proc/self/fd/3) || metadata_failure
test "$metadata" = "$fd_metadata" || metadata_failure
IFS=' ' read -r tag saved_boot phase step extra <&3 || metadata_failure
trailing=''
if IFS= read -r trailing <&3; then metadata_failure; fi
exec 3<&-
test -z "$trailing" && test -z "$extra" && test "$tag" = wakeio-os-boot/v1 || metadata_failure
test "$saved_boot" = "$boot" || metadata_failure
expected_size=$(printf '%s %s %s %s\n' "$tag" "$saved_boot" "$phase" "$step" | /usr/bin/wc -c)
test "$size" -eq "$expected_size" || metadata_failure
state_directory && state_metadata || metadata_failure
test "$metadata" = "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "$state_file")" || metadata_failure
case "$phase:$step" in
  complete:none|pending:bootstrap_pending) ;;
  __BOOT_FAILURES__) ;;
  *) metadata_failure;;
esac
if test "$phase" != complete; then probe_failure "$step"; fi
if /usr/bin/grep -Eq 'host\.(lima|docker)\.internal' /etc/hosts; then probe_failure host_alias_present
else test "$?" -eq 1 || probe_failure host_alias_present; fi
test "$(/usr/bin/id -u wakeio-m1)" = 10001 || probe_failure uid_mismatch
if /usr/bin/sudo -n -l -U wakeio-m1 >/dev/null 2>&1; then probe_failure sudo_allowed; fi
test "$(/usr/bin/stat -fc %T /sys/fs/cgroup)" = cgroup2fs || probe_failure cgroup_v2_missing
for file in /etc/subuid /etc/subgid; do
  /usr/bin/awk -F: '$1 != "wakeio-m1" && $2 <= 296607 && $2 + $3 > 231072 {exit 1}' "$file" ||
    probe_failure subid_overlap
  case "$file" in /etc/subuid) reason=subuid_mismatch;; /etc/subgid) reason=subgid_mismatch;; esac
  test "$(/usr/bin/grep '^wakeio-m1:' "$file")" = 'wakeio-m1:231072:65536' || probe_failure "$reason"
done
cg=/sys/fs/cgroup/user.slice/user-10001.slice/user@10001.service
for controller in cpu memory pids; do
  /usr/bin/grep -qw "$controller" "$cg/cgroup.controllers" || probe_failure delegation_missing
done
test "$(/usr/bin/sudo -n -u wakeio-m1 /usr/bin/id -u)" = 10001 || probe_failure uid_mismatch
/usr/bin/sudo -n -u wakeio-m1 /usr/bin/test -w "$cg/cgroup.procs" || probe_failure cgroup_procs_unwritable
/usr/bin/sudo -n -u wakeio-m1 /usr/bin/test -w "$cg/cgroup.subtree_control" || probe_failure cgroup_subtree_unwritable
printf 'wakeio-os-prerequisites/v1\n'
`.replace('__BOOT_FAILURES__', BOOT_FAILURES.map(reason => 'failed:' + reason).join('|'));

function probeMetadata(result: RuntimeProcessResult): Readonly<OsPrerequisites> {
  const base = { kind: 'os-prerequisites', observed: false, backendVerified: false } as const;
  if (result.completed) {
    if (result.exitCode !== 0 || result.stdout !== 'wakeio-os-prerequisites/v1\n') invalid();
    return Object.freeze({ ...base, observed: true, bootPhase: 'complete', reason: 'none' });
  }
  if (result.exitCode === 255 && result.stdout === '') {
    return Object.freeze({ ...base, bootPhase: 'unknown', reason: 'ssh_unavailable' });
  }
  if (result.exitCode === 125 && result.stdout === '') {
    return Object.freeze({ ...base, bootPhase: 'unknown', reason: 'guard_unknown' });
  }
  const match = /^wakeio-os-prerequisites\/v1:(pending|failed|complete|unknown):([a-z0-9_]+)\n$/.exec(result.stdout);
  if (result.exitCode !== 125 || !match) invalid();
  const phase = match[1] as OsPrerequisites['bootPhase'], reason = match[2] as OsGuardReason;
  const allowed: readonly string[] = phase === 'pending' ? ['bootstrap_pending']
    : phase === 'unknown' ? ['boot_metadata_invalid']
    : phase === 'failed' ? BOOT_FAILURES : [...BOOT_FAILURES.filter(value =>
      value !== 'bootstrap_failed' && value !== 'user_create_failed'),
    'cgroup_procs_unwritable', 'cgroup_subtree_unwritable'];
  if (!allowed.includes(reason)) invalid();
  return Object.freeze({ ...base, bootPhase: phase, reason });
}
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
      && !result.spawnError && !result.timedOut && !result.cancelled && !result.outputLimitExceeded;
    if (!this.groupConfirmed || !result.completed && !absent) invalid();
    return probeMetadata(result);
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

// Host approval pins are independent of worker-directory/request data. Updates require the R1 review bundle.
const PG_HOST_PROTOCOL = 'wakeio.pg-parser/v1';
const PG_HOST_LOCK = 'adc4e4026559ed0e5229acb4cb5354a82437420efdb58056d4a9d73969e37493';
const PG_HOST_FILES = [
  ['manifest.json', 5984, '80a61d6f7161911df1bc8d7e4d26ff6827426aa736d2319f7d3b275c85548afb'],
  ['pg-parser-worker.cjs', 143151, '824507106ba66437c0200ef4db9f86cd3b4a3c4e2c159896fa6199fb590bc6f6'],
  ['libpg-query.wasm', 1717872, '355c489d8b0bf2bac28b48408f656e818852d7000e1e66a67503ad2bc7cc6062'],
  ['THIRD_PARTY_LICENSES.txt', 2632, 'f892a1d91c887c3a8cff7457834c88a2b025b03985179b9129ce629c5026df76'],
  ['LICENSE.libpg_query', 1561, 'f9352c20940619a380a5e9f23cebe34d8f797cfbd747fc236a7a3e5fc8ef9b41'],
  ['COPYRIGHT.PostgreSQL', 1198, '5ed3ce5c9373dff7f98b1fae7a6c7ccd98df7d734d46d24c1bcebf1240be8307'],
] as const;
export interface PgParserAssetHandle {
  readonly kind: 'pg-parser-assets'; readonly protocolRevision: 'wakeio.pg-parser/v1';
  readonly lockSha256: string; readonly executionAuthorized: false;
}
export interface PgParserAssetPreparation {
  status: 'unavailable'; verified: false; reason: 'consent_required' | 'asset_mismatch' | 'assets_bound';
  handle?: Readonly<PgParserAssetHandle>;
}
type PgAssetFile = { path: string; bytes: Buffer };
const PG_ASSET_BYTES = new WeakMap<Readonly<PgParserAssetHandle>, readonly PgAssetFile[]>();
function assetMismatch(): never { throw new TypeError('asset_mismatch'); }

/** Data copies only. Neither this process-local brand nor JSON metadata authorizes worker execution. */
export function copyPgParserAssetFiles(raw: unknown): readonly PgAssetFile[] {
  if (!raw || typeof raw !== 'object' || types.isProxy(raw)) assetMismatch();
  const files = PG_ASSET_BYTES.get(raw as PgParserAssetHandle);
  if (!files) assetMismatch();
  return files.map(file => ({ path: file.path, bytes: Buffer.from(file.bytes) }));
}
function parserManifest(bytes: Buffer): void {
  // The independent raw manifest pin already binds every body field; retain only host protocol/header consistency.
  const m = JSON.parse(bytes.toString('utf8'));
  if (m.protocolRevision !== PG_HOST_PROTOCOL || m.pin?.lockSha256 !== PG_HOST_LOCK) assetMismatch();
}
type PgAssetDirectory = { path: string; id: Identity; mtimeMs: number; ctimeMs: number };
async function parserDirectory(path: string): Promise<PgAssetDirectory> {
  const info = await lstat(path), id = await identity(path);
  if ((info.mode & 0o022) !== 0) assetMismatch();
  return { path, id, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs };
}
async function checkParserDirectories(bound: readonly PgAssetDirectory[]): Promise<void> {
  for (const before of bound) {
    const after = await parserDirectory(before.path);
    if (after.id.dev !== before.id.dev || after.id.ino !== before.id.ino
      || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) assetMismatch();
  }
  const actual = (await readdir(bound[2].path)).sort();
  if (JSON.stringify(actual) !== JSON.stringify(PG_HOST_FILES.map(row => row[0]).sort())) assetMismatch();
}
async function readParserFile(path: string, handle: FileHandle, expected: typeof PG_HOST_FILES[number]) {
  const before = fileIdentity(await handle.stat(), 2 * 1024 * 1024);
  if (before.size !== expected[1]) assetMismatch();
  await namedFile(path, handle, before);
  const bytes = Buffer.alloc(before.size + 1); let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
    if (!bytesRead) break; offset += bytesRead;
  }
  await namedFile(path, handle, before);
  if (offset !== before.size
    || createHash('sha256').update(bytes.subarray(0, offset)).digest('hex') !== expected[2]) assetMismatch();
  return { path, handle, identity: before, bytes: bytes.subarray(0, offset) };
}
async function bindParserAssets(root: string, openTrustedFile: typeof open): Promise<PgAssetFile[]> {
  // This locator belongs to trusted host composition only, never Target/cwd/PATH/env or load options.
  if (typeof root !== 'string' || !isAbsolute(root) || resolve(root) !== root
    || Buffer.byteLength(root) > 4096 || /[\x00-\x1f\x7f]/.test(root)) assetMismatch();
  await inputPath(join(root, 'workers/pg-parser/manifest.json'));
  const directories: PgAssetDirectory[] = [];
  for (const path of [root, join(root, 'workers'), join(root, 'workers/pg-parser')]) {
    directories.push(await parserDirectory(path));
  }
  await checkParserDirectories(directories);
  const opened: Awaited<ReturnType<typeof readParserFile>>[] = [], handles: FileHandle[] = [];
  try {
    for (const expected of PG_HOST_FILES) {
      const path = join(root, 'workers/pg-parser', expected[0]), handle = await openTrustedFile(path, FILE_FLAGS);
      handles.push(handle); opened.push(await readParserFile(path, handle, expected));
    }
    parserManifest(opened[0].bytes);
    for (const file of opened) await namedFile(file.path, file.handle, file.identity);
    await checkParserDirectories(directories);
    return opened.map((file, index) => ({ path: 'workers/pg-parser/' + PG_HOST_FILES[index][0], bytes: file.bytes }));
  } finally {
    const closed = await Promise.allSettled(handles.map(handle => handle.close()));
    if (closed.some(result => result.status === 'rejected')) assetMismatch();
  }
}

/** @internal Trusted installation locator and real-FD test seam, never an option/Target execution capability. */
export function createPgParserAssetLoader(trustedInstallationRoot: string, openTrustedFile: typeof open = open) {
  return async (raw: unknown): Promise<PgParserAssetPreparation> => {
    if (!consent(raw)) return { status: 'unavailable', verified: false, reason: 'consent_required' };
    try {
      object(snapshotJsonData(raw, assetMismatch), ['executeTargetConsent']);
      const files = await bindParserAssets(trustedInstallationRoot, openTrustedFile);
      const handle = Object.freeze({ kind: 'pg-parser-assets', protocolRevision: PG_HOST_PROTOCOL,
        lockSha256: PG_HOST_LOCK, executionAuthorized: false } as const);
      PG_ASSET_BYTES.set(handle, files);
      return { status: 'unavailable', verified: false, reason: 'assets_bound', handle };
    } catch { return { status: 'unavailable', verified: false, reason: 'asset_mismatch' }; }
  };
}
