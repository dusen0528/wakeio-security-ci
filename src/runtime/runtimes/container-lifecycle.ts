import { createHash } from 'node:crypto';
import { snapshotJsonData } from '../../json-snapshot.js';

// Host-selected pins, independent of guest output, signed indexes, manifests and TargetSpec.
const DOCKER_VERSION = '5:29.9.2-1~ubuntu.24.04~noble';
const DOCKER_PINS = [
  ['docker-ce', DOCKER_VERSION, 21023748, 'c34d0bd4a58891b1fd9bab57702d7ce84c0f0c77db5fbabcf192288fe52d2535'],
  ['docker-ce-cli', DOCKER_VERSION, 15847216, 'de18f48f32758568af16d73aa758678af472c2e780dc2aaa9fd9279b8260f7a9'],
  ['docker-ce-rootless-extras', DOCKER_VERSION, 9128964,
    '12584930245f79a0fb82c835edc6004c82b9ce790eae1fe99c833625c76d0536'],
  ['containerd.io', '2.4.2-3~ubuntu.24.04~noble', 19561964,
    '7837470e586f0b5d228a5eefdd9674b6bd0f127c47841ae808b086ae7fe3f41a'],
] as const;
const KEY_SHA = '1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570';
const KEY_FINGERPRINT = '9DC858229FC7DD38854AE2D88D81803C0EBFCD88';
export interface PreparedPackage {
  name: string; version: string; arch: 'arm64' | 'all'; size: number; sha256: string;
  origin: 'docker' | 'ubuntu';
}
const PREPARATION_STAGES = ['prerequisites', 'key', 'apt-config', 'index-update', 'index-snapshot',
  'selection', 'download', 'digest', 'state-recheck', 'manifest'] as const;
type PreparationStage = typeof PREPARATION_STAGES[number];
const INDEX_FAILURE_DETAILS = ['index-list-io', 'index-name', 'index-kind-translation', 'index-kind-other',
  'index-type', 'index-owner', 'index-links', 'index-mode', 'index-size', 'index-read', 'index-consistency',
  'index-count', 'index-repo-presence'] as const;
type IndexFailureDetail = typeof INDEX_FAILURE_DETAILS[number];
export interface RootlessPackagePreparation {
  kind: 'rootless-package-preparation'; phase: 'download_prepared' | 'unknown';
  reason: 'none' | 'prepare_unavailable' | 'invalid_metadata' | 'identity_unknown' | 'operation_failed';
  failureStage?: PreparationStage; failureDetail?: IndexFailureDetail;
  backendVerified: false; sourceExecutionAuthorized: false; daemonObserved: false;
  manifestSha256: string | null; indexManifestSha256: string | null; installedStatusSha256: string | null;
  packages: readonly Readonly<PreparedPackage>[];
}
export function packagePreparationUnknown(reason: RootlessPackagePreparation['reason']) {
  return Object.freeze({ kind: 'rootless-package-preparation', phase: 'unknown', reason,
    backendVerified: false, sourceExecutionAuthorized: false, daemonObserved: false,
    manifestSha256: null, indexManifestSha256: null, installedStatusSha256: null,
    packages: Object.freeze([]) }) as RootlessPackagePreparation;
}
function invalid(): never { throw new TypeError('invalid_package_preparation'); }
function exact(value: Record<string, unknown>, keys: string[]): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== keys.sort().join(',')) invalid();
}
/** Data only: this never creates an installation/daemon/source capability, even for a forged success wire. */
export function parseRootlessPackagePreparation(raw: string): Readonly<RootlessPackagePreparation> {
  try {
    if (Buffer.byteLength(raw) > 16 * 1024 || /[^\x20-\x7e\n]/.test(raw) || !raw.endsWith('\n')) invalid();
    const value = snapshotJsonData(JSON.parse(raw), invalid) as Record<string, unknown>;
    exact(value, ['protocol', 'signatureVerified', 'keySha256', 'keyFingerprint', 'indexManifestSha256',
      'installedStatusSha256', 'packages']);
    if (value.protocol !== 'wakeio-rootless-packages/v1' || value.signatureVerified !== true
      || value.keySha256 !== KEY_SHA || value.keyFingerprint !== KEY_FINGERPRINT
      || typeof value.indexManifestSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.indexManifestSha256)
      || typeof value.installedStatusSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.installedStatusSha256)
      || !Array.isArray(value.packages) || value.packages.length < 4 || value.packages.length > 48) invalid();
    let previous = '', total = 0;
    const packages = value.packages.map(rawPackage => {
      const p = rawPackage as Record<string, unknown>;
      exact(p, ['name', 'version', 'arch', 'size', 'sha256', 'origin']);
      if (typeof p.name !== 'string' || !/^[a-z0-9][a-z0-9+.-]{0,63}$/.test(p.name) || p.name <= previous
        || typeof p.version !== 'string' || !/^[0-9][A-Za-z0-9.+:~_-]{0,127}$/.test(p.version)
        || !['arm64', 'all'].includes(String(p.arch)) || !['docker', 'ubuntu'].includes(String(p.origin))
        || !Number.isSafeInteger(p.size) || Number(p.size) <= 0 || Number(p.size) > 128 * 1024 * 1024
        || typeof p.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(p.sha256)) invalid();
      const pin = DOCKER_PINS.find(record => record[0] === p.name);
      if (pin ? p.origin !== 'docker' || p.arch !== 'arm64' || p.version !== pin[1]
        || p.size !== pin[2] || p.sha256 !== pin[3] : p.origin !== 'ubuntu') invalid();
      previous = p.name; total += Number(p.size); return Object.freeze(p) as unknown as Readonly<PreparedPackage>;
    });
    if (total > 512 * 1024 * 1024 || DOCKER_PINS.some(pin => !packages.some(p => p.name === pin[0]))) invalid();
    return Object.freeze({ kind: 'rootless-package-preparation', phase: 'download_prepared', reason: 'none',
      backendVerified: false, sourceExecutionAuthorized: false, daemonObserved: false,
      manifestSha256: createHash('sha256').update(raw.slice(0, -1)).digest('hex'),
      indexManifestSha256: value.indexManifestSha256, installedStatusSha256: value.installedStatusSha256,
      packages: Object.freeze(packages) });
  } catch { return packagePreparationUnknown('invalid_metadata'); }
}

/** Failure diagnostics are data, never signature verification, prepared bytes or execution authority. */
export function parseRootlessPackageFailure(raw: string): Readonly<RootlessPackagePreparation> {
  if (Buffer.byteLength(raw) <= 128) {
    for (const stage of PREPARATION_STAGES) {
      const prefix = `wakeio-rootless-packages-failure/v1:${stage}:operation_failed`;
      if (raw === prefix + '\n') {
        return Object.freeze({ ...packagePreparationUnknown('operation_failed'), failureStage: stage });
      }
      if (stage !== 'index-snapshot' && stage !== 'state-recheck') continue;
      for (const detail of INDEX_FAILURE_DETAILS) {
        if (raw === prefix + ':' + detail + '\n') return Object.freeze({
          ...packagePreparationUnknown('operation_failed'), failureStage: stage, failureDetail: detail });
      }
    }
  }
  return packagePreparationUnknown('invalid_metadata');
}

// Fixed trusted guest preparation only. There is deliberately no install, commit, unit start or Docker API here.
// Standard signed APT performs dependency resolution and download; this program only verifies its selections.
const PACKAGE_PREPARE_PY = String.raw`
import os, sys, json, hashlib, stat, re, urllib.request, importlib.util
PINS = __PINS__
KEY_SHA = '__KEY_SHA__'
KEY_FINGERPRINT = '__KEY_FINGERPRINT__'
BASE = '/run/wakeio-m1-packages'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C', 'HOME':'/root'}
stage = 'prerequisites'
failure_detail = ''

def index_check(ok, code):
    global failure_detail
    if not ok:
        failure_detail = code
        require(False)

def require(ok):
    if not ok: raise ValueError('closed_preparation_failure')

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def read_file(path, limit, indexing=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        check = index_check if indexing else lambda ok, code: require(ok)
        check(stat.S_ISREG(before.st_mode), 'index-type')
        check(before.st_uid == 0, 'index-owner')
        check(before.st_nlink == 1, 'index-links')
        check(not before.st_mode & 0o022, 'index-mode')
        check(0 < before.st_size <= limit, 'index-size')
        chunks, used = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk: break
            used += len(chunk); check(used <= limit, 'index-size'); chunks.append(chunk)
        check(used == before.st_size and identity(before) == identity(os.fstat(fd)), 'index-consistency')
        check(identity(before) == identity(os.stat(path, follow_symlinks=False)), 'index-consistency')
        return b''.join(chunks)
    finally: os.close(fd)

def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try: stream = os.fdopen(fd, 'wb')
    except BaseException:
        os.close(fd)
        raise
    with stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('redirect_rejected')

def key():
    global stage
    stage = 'key'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open('https://download.docker.com/linux/ubuntu/gpg', timeout=8) as response:
        require(response.status == 200)
        body = response.read(3818)
    require(len(body) == 3817 and hashlib.sha256(body).hexdigest() == KEY_SHA)
    write_new(BASE + '/docker.asc', body)

def apt_config():
    global stage
    stage = 'apt-config'
    os.mkdir(BASE, 0o700)
    for directory in ['lists', 'lists/partial', 'archives', 'archives/partial', 'empty']:
        os.mkdir(BASE + '/' + directory, 0o700)
    key()
    stage = 'apt-config'
    sources = ('deb [arch=arm64 signed-by=' + BASE + '/docker.asc] '
        'https://download.docker.com/linux/ubuntu noble stable\n')
    for suite in ['noble', 'noble-updates', 'noble-security']:
        sources += ('deb [arch=arm64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] '
            'https://ports.ubuntu.com/ubuntu-ports ' + suite + ' main universe\n')
    write_new(BASE + '/sources.list', sources.encode('ascii'))
    config = {
        'Dir::Etc::Parts': BASE + '/empty', 'Dir::Etc::main': BASE + '/absent',
        'Dir::Etc::sourcelist': BASE + '/sources.list', 'Dir::Etc::sourceparts': BASE + '/empty',
        'Dir::Etc::preferences': BASE + '/absent', 'Dir::Etc::preferencesparts': BASE + '/empty',
        'Dir::Etc::trusted': BASE + '/absent', 'Dir::Etc::trustedparts': BASE + '/empty',
        'Dir::State::lists': BASE + '/lists', 'Dir::State::status': '/var/lib/dpkg/status',
        'Dir::Cache::archives': BASE + '/archives', 'Dir::Cache::pkgcache': '', 'Dir::Cache::srcpkgcache': '',
        'APT::Architecture': 'arm64', 'APT::Install-Recommends': 'false', 'APT::Install-Suggests': 'false',
        'APT::Get::AllowUnauthenticated': 'false', 'Acquire::AllowInsecureRepositories': 'false',
        'Acquire::AllowDowngradeToInsecureRepositories': 'false', 'Acquire::Check-Valid-Until': 'true',
        'Acquire::AllowWeakRepositories': 'false',
        'Acquire::https::AllowRedirect': 'false', 'Acquire::https::Proxy': 'DIRECT',
        'Acquire::http::Proxy': 'DIRECT', 'Acquire::Retries': '0', 'Acquire::https::Timeout': '8',
        'Acquire::https::Verify-Peer': 'true', 'Acquire::https::Verify-Host': 'true',
        'APT::Sandbox::User': 'root', 'Dir::Log': BASE, 'Dir::State::extended_states': BASE + '/extended',
    }
    write_new(BASE + '/apt.conf', ''.join(k + ' "' + v + '";\n' for k,v in config.items()).encode('ascii'))
    os.environ.clear(); os.environ.update(ENV); os.environ['APT_CONFIG'] = BASE + '/apt.conf'

def index_file(path):
    global failure_detail
    try: return read_file(path, 256 * 1024 * 1024, True)
    except OSError:
        failure_detail = 'index-read'
        raise

def indexes():
    global failure_detail
    failure_detail = ''
    try: names = sorted(os.listdir(BASE + '/lists'))
    except OSError:
        failure_detail = 'index-list-io'
        raise
    records = []
    for name in names:
        if name in ['lock', 'partial', 'auxfiles']: continue
        index_check(re.fullmatch(r'[A-Za-z0-9_.-]{1,240}', name) is not None, 'index-name')
        kind = 'index-kind-translation' if '_Translation-' in name else 'index-kind-other'
        index_check(name.endswith('InRelease') or '_Packages' in name, kind)
        body = index_file(BASE + '/lists/' + name)
        records.append({'file':name, 'size':len(body), 'sha256':hashlib.sha256(body).hexdigest()})
    index_check(4 <= len(records) <= 32, 'index-count')
    index_check(any('download.docker.com' in r['file'] and r['file'].endswith('InRelease') for r in records),
        'index-repo-presence')
    index_check(any('ports.ubuntu.com' in r['file'] and r['file'].endswith('InRelease') for r in records),
        'index-repo-presence')
    failure_detail = ''
    return records

def selected(cache):
    for name, version, size, sha in PINS:
        package = cache[name]
        versions = [v for v in package.versions if v.version == version and v.architecture == 'arm64']
        require(len(versions) == 1); package.candidate = versions[0]
    for name in [p[0] for p in PINS] + ['uidmap', 'slirp4netns', 'dbus-user-session', 'iptables', 'nftables']:
        cache[name].mark_install(auto_fix=True, auto_inst=True, from_user=True)
    require(cache.broken_count == 0)
    changes = cache.get_changes()
    require(4 <= len(changes) <= 48 and not any(p.marked_delete or p.marked_downgrade for p in changes))
    records = []
    for package in changes:
        v = package.candidate
        require(v and v.architecture in ['arm64', 'all'] and 0 < v.size <= 128 * 1024 * 1024)
        require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,63}', package.name) is not None)
        require(re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', v.version) is not None)
        require(all(o.trusted for o in v.origins) and len(v.origins) > 0)
        uri = v.uri
        require(all(u.startswith(('https://download.docker.com/linux/ubuntu/',
            'https://ports.ubuntu.com/ubuntu-ports/')) for u in v.uris))
        docker = uri.startswith('https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/arm64/')
        ubuntu = uri.startswith('https://ports.ubuntu.com/ubuntu-ports/pool/')
        require((docker or ubuntu) and re.fullmatch(r'https://[A-Za-z0-9./+~_:%-]+', uri) is not None)
        require('..' not in uri and '%' not in uri and '?' not in uri and '#' not in uri)
        sha = v.record.get('SHA256', '')
        require(re.fullmatch(r'[a-f0-9]{64}', sha) is not None)
        record = dict(name=package.name, version=v.version, arch=v.architecture, size=v.size,
            sha256=sha, origin='docker' if docker else 'ubuntu')
        pin = next((p for p in PINS if p[0] == package.name), None)
        require((not pin and ubuntu) or (pin and docker and (v.version,v.size,sha) == tuple(pin[1:])))
        records.append((record, v))
    require(all(any(r['name'] == pin[0] for r,v in records) for pin in PINS))
    require(sum(r['size'] for r,v in records) <= 512 * 1024 * 1024)
    return sorted(records, key=lambda pair: pair[0]['name'])

def prepare():
    global stage
    stage = 'prerequisites'
    require(os.geteuid() == 0 and os.uname().machine == 'aarch64')
    require(b'ID=ubuntu\n' in read_file('/usr/lib/os-release', 8192))
    require(importlib.util.find_spec('apt') is not None)
    status = read_file('/var/lib/dpkg/status', 32 * 1024 * 1024)
    apt_config()
    import apt, apt.progress.base
    cache = apt.Cache(progress=apt.progress.base.OpProgress())
    stage = 'index-update'
    require(cache.update(fetch_progress=apt.progress.base.AcquireProgress()))
    cache.open(apt.progress.base.OpProgress())
    stage = 'index-snapshot'
    index_records = indexes()
    stage = 'selection'
    records = selected(cache)
    for record, version in records:
        # python-apt uses the selected signed record's archive name; no extraction/lifecycle runs here.
        # Public APT download-only API preserves authentication; no commit/install is called.
        stage = 'download'
        path = version.fetch_binary(destdir=BASE + '/archives', progress=apt.progress.base.AcquireProgress(),
            allow_unauthenticated=False)
        stage = 'digest'
        require(os.path.dirname(path) == BASE + '/archives')
        body = read_file(path, 128 * 1024 * 1024)
        require(len(body) == record['size'] and hashlib.sha256(body).hexdigest() == record['sha256'])
    stage = 'state-recheck'
    require(indexes() == index_records and status == read_file('/var/lib/dpkg/status', 32 * 1024 * 1024))
    stage = 'manifest'
    index_body = encoded(index_records); write_new(BASE + '/indexes.json', index_body)
    manifest = dict(protocol='wakeio-rootless-packages/v1', signatureVerified=True, keySha256=KEY_SHA,
        keyFingerprint=KEY_FINGERPRINT, indexManifestSha256=hashlib.sha256(index_body).hexdigest(),
        installedStatusSha256=hashlib.sha256(status).hexdigest(), packages=[r for r,v in records])
    body = encoded(manifest); require(len(body) < 16 * 1024)
    write_new(BASE + '/manifest.json', body)
    return body

# Tool chatter never becomes metadata. The owned VM and PGID are reclaimed even on abrupt termination.
out = os.dup(1)
with open('/dev/null', 'wb') as sink:
    os.dup2(sink.fileno(), 1); os.dup2(sink.fileno(), 2)
try:
    body = prepare()
    os.write(out, body + b'\n')
except BaseException:
    detail = ':' + failure_detail if failure_detail else ''
    token = 'wakeio-rootless-packages-failure/v1:' + stage + ':operation_failed' + detail + '\n'
    os.write(out, token.encode('ascii'))
    sys.exit(125)
finally:
    os.close(out)
`.replace('__PINS__', JSON.stringify(DOCKER_PINS)).replace('__KEY_SHA__', KEY_SHA)
  .replace('__KEY_FINGERPRINT__', KEY_FINGERPRINT);
// Fixed Python is product code. No raw Target/options/text can select this script or its input.
export const ROOTLESS_PACKAGE_PREPARE = '/usr/bin/python3 -I -c '
  + "'" + PACKAGE_PREPARE_PY.replaceAll("'", "'\"'\"'") + "'";
