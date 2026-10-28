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
const SELECTION_FAILURE_DETAILS = ['selection-package-lookup', 'selection-candidate-lookup', 'selection-pinned-version',
  'selection-mark-install', 'selection-broken', 'selection-change-set', 'selection-name', 'selection-version',
  'selection-arch-size', 'selection-origin', 'selection-uri', 'selection-sha', 'selection-pin',
  'selection-required-set', 'selection-total', 'selection-uri-read', 'selection-uri-type', 'selection-uri-host',
  'selection-uri-path', 'selection-uri-encoding', 'selection-uri-record', 'selection-uri-binding'] as const;
type SelectionFailureDetail = typeof SELECTION_FAILURE_DETAILS[number];
export interface RootlessPackagePreparation {
  kind: 'rootless-package-preparation'; phase: 'download_prepared' | 'unknown';
  reason: 'none' | 'prepare_unavailable' | 'invalid_metadata' | 'identity_unknown' | 'operation_failed';
  failureStage?: PreparationStage; failureDetail?: IndexFailureDetail | SelectionFailureDetail;
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
export interface RootlessPackageInstallation {
  kind: 'rootless-package-installation'; phase: 'unknown'; reason: 'installer_unavailable' | 'identity_unknown';
  backendVerified: false; sourceExecutionAuthorized: false; daemonObserved: false;
}
/** Inactive until the owned network/resource/autostart/installer cleanup barriers are implemented. */
export function packageInstallationUnknown(reason: RootlessPackageInstallation['reason']) {
  return Object.freeze({ kind: 'rootless-package-installation', phase: 'unknown', reason,
    backendVerified: false, sourceExecutionAuthorized: false, daemonObserved: false }) as RootlessPackageInstallation;
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
      const details = stage === 'selection' ? SELECTION_FAILURE_DETAILS
        : stage === 'index-snapshot' || stage === 'state-recheck' ? INDEX_FAILURE_DETAILS : [];
      for (const detail of details) {
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
import os, sys, json, hashlib, stat, re, urllib.request, urllib.parse, importlib.util
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

def read_file(path, limit, indexing=False, bindings=None):
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
        body = b''.join(chunks)
        if bindings is not None:
            bindings.append(dict(file=os.path.basename(path), identity=list(identity(before)),
                sha256=hashlib.sha256(body).hexdigest()))
        return body
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
        'Acquire::Languages': 'none',
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
        if not failure_detail: failure_detail = 'index-read'
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

def selection_step(code):
    global failure_detail
    failure_detail = code

def record_filename(filename):
    selection_step('selection-uri-record')
    require(isinstance(filename, str) and re.fullmatch(r'[A-Za-z0-9+~_.:/-]+', filename) is not None)
    require('..' not in filename and all(p not in ['', '.'] for p in filename.split('/')))
    basename = filename.rsplit('/', 1)[-1]
    require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*_[A-Za-z0-9.+:~_-]+_(arm64|all)\.deb', basename) is not None)
    if filename.startswith('dists/noble/pool/stable/arm64/'):
        require(len(filename.split('/')) == 6 and basename.endswith('_arm64.deb'))
        return 'docker'
    match = re.fullmatch(r'pool/(main|universe)/([a-z0-9]|lib[a-z0-9])/([a-z0-9][a-z0-9+.-]*)/[^/]+', filename)
    require(match is not None)
    source = match.group(3)
    require(match.group(2) == (source[:4] if source.startswith('lib') else source[:1]))
    return 'ubuntu'

def package_uri(uri, filename):
    origin = record_filename(filename)
    selection_step('selection-uri-type')
    require(isinstance(uri, str) and re.fullmatch(r'[\x21-\x7e]+', uri) is not None and '\\' not in uri)
    selection_step('selection-uri-host')
    require(uri.startswith('https://') and '?' not in uri and '#' not in uri)
    parts = urllib.parse.urlsplit(uri)
    roots = {'download.docker.com':('docker', '/linux/ubuntu/'),
        'ports.ubuntu.com':('ubuntu', '/ubuntu-ports/')}
    require(parts.scheme == 'https' and parts.netloc in roots and not parts.query and not parts.fragment)
    host_origin, root = roots[parts.netloc]
    selection_step('selection-uri-path')
    require(parts.path.startswith(root))
    tail = parts.path[len(root):]
    require('..' not in tail and all(p not in ['', '.'] for p in tail.split('/')))
    selection_step('selection-uri-encoding')
    require(re.fullmatch(r'(?:[A-Za-z0-9.+~_:/-]|%2b|%7e)+', tail) is not None)
    # Decode only after the two safe escapes were allowlisted; no general URL normalization is accepted.
    decoded = urllib.parse.unquote_to_bytes(tail)
    raw = decoded.decode('ascii')
    canonical = raw.replace('+', '%2b').replace('~', '%7e')
    require(tail == raw or tail == canonical)
    selection_step('selection-uri-binding')
    require(decoded == filename.encode('ascii') and host_origin == origin)
    return origin

def selected_record(package):
    selection_step('selection-candidate-lookup')
    v = package.candidate; require(v is not None)
    selection_step('selection-arch-size')
    arch, size = v.architecture, v.size
    require(arch in ['arm64', 'all'] and 0 < size <= 128 * 1024 * 1024)
    selection_step('selection-name')
    name = package.name; require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,63}', name) is not None)
    selection_step('selection-version')
    version = v.version; require(re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', version) is not None)
    selection_step('selection-origin')
    origins = v.origins; require(all(o.trusted for o in origins) and len(origins) > 0)
    selection_step('selection-uri-read')
    uri, uris = v.uri, v.uris
    selection_step('selection-uri-type')
    require(isinstance(uris, list) and len(uris) > 0 and isinstance(uri, str))
    selection_step('selection-uri-record')
    signed_record = v.record; filename = signed_record.get('Filename', '')
    origin = package_uri(uri, filename)
    require(all(package_uri(other, filename) == origin for other in uris))
    selection_step('selection-sha')
    # Noble Record explicitly defines get; the expected digest still comes from the signed record.
    sha = signed_record.get('SHA256', ''); require(re.fullmatch(r'[a-f0-9]{64}', sha) is not None)
    record = dict(name=name, version=version, arch=arch, size=size, sha256=sha, origin=origin)
    selection_step('selection-pin')
    pin = next((p for p in PINS if p[0] == name), None)
    require((not pin and origin == 'ubuntu') or (pin and origin == 'docker' and (version,size,sha) == tuple(pin[1:])))
    return record, v

def selected(cache):
    global failure_detail
    for name, version, size, sha in PINS:
        selection_step('selection-package-lookup')
        package = cache[name]
        selection_step('selection-pinned-version')
        versions = [v for v in package.versions if v.version == version and v.architecture == 'arm64']
        require(len(versions) == 1); package.candidate = versions[0]
    for name in [p[0] for p in PINS] + ['uidmap', 'slirp4netns', 'dbus-user-session', 'iptables', 'nftables']:
        selection_step('selection-mark-install')
        cache[name].mark_install(auto_fix=True, auto_inst=True, from_user=True)
    selection_step('selection-broken')
    require(cache.broken_count == 0)
    selection_step('selection-change-set')
    changes = cache.get_changes()
    require(4 <= len(changes) <= 48 and not any(p.marked_delete or p.marked_downgrade for p in changes))
    records = [selected_record(package) for package in changes]
    selection_step('selection-required-set')
    require(all(any(r['name'] == pin[0] for r,v in records) for pin in PINS))
    selection_step('selection-total')
    require(sum(r['size'] for r,v in records) <= 512 * 1024 * 1024)
    failure_detail = ''
    return sorted(records, key=lambda pair: pair[0]['name'])

def boot_digest():
    path = '/proc/sys/kernel/random/boot_id'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        body = os.read(fd, 38)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1)
        require(not before.st_mode & 0o022)
        require(re.fullmatch(rb'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}\n', body) is not None)
        require(identity(before) == identity(os.fstat(fd)) == identity(os.stat(path, follow_symlinks=False)))
        return hashlib.sha256(body).hexdigest()
    finally: os.close(fd)

def owned_directory(path):
    info = os.stat(path, follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o777 == 0o700)
    return list(identity(info))

def prepared_snapshot():
    global stage
    stage = 'state-recheck'
    directories = [owned_directory(BASE + suffix) for suffix in ['', '/archives', '/archives/partial']]
    captured = []
    for name, limit in [('apt.conf',16384), ('sources.list',8192), ('docker.asc',3817)]:
        read_file(BASE + '/' + name, limit, bindings=captured)
    manifest_body = read_file(BASE + '/manifest.json', 16384, bindings=captured)
    manifest = json.loads(manifest_body)
    index_body = read_file(BASE + '/indexes.json', 16384, bindings=captured)
    require(indexes() == json.loads(index_body))
    index_sha = hashlib.sha256(index_body).hexdigest()
    status_sha = hashlib.sha256(read_file('/var/lib/dpkg/status', 32 * 1024 * 1024)).hexdigest()
    require(index_sha == manifest['indexManifestSha256'] and status_sha == manifest['installedStatusSha256'])
    boot = boot_digest()
    require(read_file(BASE + '/boot.sha256', 64, bindings=captured) == boot.encode('ascii'))
    bindings = json.loads(read_file(BASE + '/deb-bindings.json', 65536, bindings=captured))
    require(isinstance(bindings, list) and 4 <= len(bindings) == len(manifest['packages']) <= 48)
    names = [entry['file'] for entry in bindings]
    require(all(isinstance(n, str) and re.fullmatch(r'[A-Za-z0-9+~_.:-]+\.deb', n) and '..' not in n for n in names))
    require(len(set(names)) == len(names) and set(os.listdir(BASE + '/archives')) == set(names) | {'partial'})
    require(os.listdir(BASE + '/archives/partial') == [])
    current = []
    for record, bound in zip(manifest['packages'], bindings):
        body = read_file(BASE + '/archives/' + bound['file'], 128 * 1024 * 1024, bindings=current)
        require(len(body) == record['size'] and hashlib.sha256(body).hexdigest() == record['sha256'])
    require(current == bindings)
    require(directories == [owned_directory(BASE + suffix) for suffix in ['', '/archives', '/archives/partial']])
    state = hashlib.sha256(encoded([directories, captured, current])).hexdigest()
    fields = [hashlib.sha256(manifest_body).hexdigest(), index_sha, status_sha, boot, state]
    return ('wakeio-rootless-packages-snapshot/v1:' + ':'.join(fields)).encode('ascii')

def hook_config(lines):
    result = []
    for line in lines:
        key, separator, value = line.partition('=')
        require(separator == '=' and key)
        fields = []
        for field in [key, value]:
            require(re.fullmatch(r'(?:[^%]|%[0-9a-f]{2})*', field) is not None)
            decoded = urllib.parse.unquote_to_bytes(field).decode('ascii')
            require(len(decoded) <= 4096 and re.fullmatch(r'[\x20-\x7e]*', decoded) is not None)
            fields.append(decoded)
        require(re.fullmatch(r'[A-Za-z0-9:/_.+-]{1,256}', fields[0]) is not None)
        result.append(tuple(fields))
    return result

def hook_plan(plan):
    require(isinstance(plan, dict) and 4 <= len(plan) <= 48)
    for name, expected in plan.items():
        require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,63}', name) is not None)
        require(set(expected) == {'old', 'new', 'direction', 'deb'})
        for version, arch, multi in [expected['old'], expected['new']]:
            require(multi in ['none', 'no', 'same', 'foreign', 'allowed'])
            require((version == '-' and arch == '-' and multi in ['none','no']) or
                (re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', version) is not None
                    and arch in ['arm64','all']))
        require(expected['new'][0] != '-' and expected['direction'] in ['<','='])
        if expected['direction'] == '=': require(expected['old'] == expected['new'])
        if expected['old'][0] != '-':
            from apt_pkg import version_compare
            delta = version_compare(expected['new'][0], expected['old'][0])
            require((expected['direction'] == '<' and delta > 0)
                or (expected['direction'] == '=' and delta == 0))
        require(isinstance(expected['deb'], str) and expected['deb'].startswith(BASE + '/archives/'))
        tail = expected['deb'][len(BASE + '/archives/'):]
        require(re.fullmatch(r'[A-Za-z0-9+~_.:-]+\.deb', tail) is not None and '..' not in tail)

def validate_install_hook(payload, plan, configuration):
    # Data validation only. No current action dispatches an installer or grants authority from this result.
    # The future plan must be private, built by standard APT/version_compare from the sealed clean baseline.
    hook_plan(plan)
    required = {'apt::get::download':'false', 'apt::get::remove':'false',
        'apt::get::allowunauthenticated':'false', 'acquire::allowinsecurerepositories':'false',
        'acquire::allowdowngradetoinsecurerepositories':'false', 'acquire::allowweakrepositories':'false',
        'acquire::check-valid-until':'true', 'acquire::https::verify-peer':'true',
        'acquire::https::verify-host':'true', 'acquire::https::allowredirect':'false',
        'dpkg::configurepending':'false', 'dpkg::triggerspending':'false', 'dpkg::notriggers':'false',
        ('dpkg::tools::options::'+BASE+'/install-hook::version'):'3',
        ('dpkg::tools::options::'+BASE+'/install-hook::infofd'):'0'}
    for key, expected in required.items():
        require([value for name, value in configuration if name.lower() == key] == [expected])
    require(isinstance(payload, bytes) and 0 < len(payload) <= 16384)
    text = payload.decode('ascii')
    require(re.fullmatch(r'[\x20-\x7e\n]+', text) is not None and text.endswith('\n'))
    lines = text[:-1].split('\n')
    require(lines[0] == 'VERSION 3')
    end = lines.index('', 1)
    require(hook_config(lines[1:end]) == configuration)
    seen = set()
    for line in lines[end+1:]:
        fields = line.split(' ')
        require(len(fields) == 9 and all(fields))
        name, direction, action = fields[0], fields[4], fields[8]
        require(name in plan)
        expected = plan[name]
        require(tuple(fields[1:4]) == expected['old'] and tuple(fields[5:8]) == expected['new'])
        require(direction == expected['direction'] and direction in ['<','='])
        kind = 'configure' if action == '**CONFIGURE**' else 'unpack'
        require(kind == 'configure' or action == expected['deb'])
        require((name, kind) not in seen)
        seen.add((name, kind))
    require(seen == {(name, kind) for name in plan for kind in ['unpack','configure']})
    return hashlib.sha256(payload).hexdigest()

def prepare():
    global stage
    stage = 'prerequisites'
    require(os.geteuid() == 0 and os.uname().machine == 'aarch64')
    require(b'ID=ubuntu\n' in read_file('/usr/lib/os-release', 8192))
    require(importlib.util.find_spec('apt') is not None)
    boot = boot_digest()
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
    bindings = []
    for record, version in records:
        # python-apt uses the selected signed record's archive name; no extraction/lifecycle runs here.
        # Public APT download-only API preserves authentication; no commit/install is called.
        stage = 'download'
        path = version.fetch_binary(destdir=BASE + '/archives', progress=apt.progress.base.AcquireProgress(),
            allow_unauthenticated=False)
        stage = 'digest'
        require(os.path.dirname(path) == BASE + '/archives')
        body = read_file(path, 128 * 1024 * 1024, bindings=bindings)
        require(len(body) == record['size'] and hashlib.sha256(body).hexdigest() == record['sha256'])
    stage = 'state-recheck'
    require(indexes() == index_records and status == read_file('/var/lib/dpkg/status', 32 * 1024 * 1024))
    stage = 'manifest'
    require(boot_digest() == boot)
    write_new(BASE + '/boot.sha256', boot.encode('ascii'))
    write_new(BASE + '/deb-bindings.json', encoded(bindings))
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
    body = __ACTION__()
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
function fixedPython(action: 'prepare' | 'prepared_snapshot'): string {
  return '/usr/bin/python3 -I -c '
    + "'" + PACKAGE_PREPARE_PY.replace('__ACTION__', action).replaceAll("'", "'\"'\"'") + "'";
}
export const ROOTLESS_PACKAGE_PREPARE = fixedPython('prepare');
export const ROOTLESS_PACKAGE_SNAPSHOT = fixedPython('prepared_snapshot');
