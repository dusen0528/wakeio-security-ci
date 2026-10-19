// Explicit Linux CI preparation only. Product scans never install these engines.
import { createHash } from 'node:crypto';
import { appendFile, chmod, lstat, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { installToolsDetailed } from './install-tools.mjs';
import { runBounded } from './ci-process.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
export const SECURITY_TOOLCHAIN_RELEASES = Object.freeze({
  semgrep: '1.147.0', govulncheck: 'v1.9.0',
  go: { version: '1.27.2', url: 'https://go.dev/dl/go1.27.2.linux-amd64.tar.gz',
    sha256: 'ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5' },
  zap: { version: '2.17.0', url: 'https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip',
    sha256: '94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0' },
  // Alpine 3.18.0 Linux AMD64 member of the official 02bb6f42... manifest list.
  alpine: 'docker.io/library/alpine@sha256:c0669ef34cdc14332c0f1ab0c2c01acb91d96014b172f1a76f3a39e63d1f0bda',
});
const MAX_ARCHIVE_BYTES = 320 * 1024 * 1024;

export function verifySecurityArchive(bytes, expectedSha256) {
  if (!bytes.length || bytes.length > MAX_ARCHIVE_BYTES) throw Error('security_archive_size');
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || createHash('sha256').update(bytes).digest('hex') !== expectedSha256) throw Error('security_archive_checksum');
}

async function download(spec, path) {
  const response = await fetch(spec.url, { signal: AbortSignal.timeout(120_000), redirect: 'follow' });
  if (!response.ok || !response.body) throw Error('security_download_failed');
  if (Number(response.headers.get('content-length')) > MAX_ARCHIVE_BYTES) throw Error('security_archive_size');
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > MAX_ARCHIVE_BYTES) throw Error('security_archive_size');
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, size);
  verifySecurityArchive(bytes, spec.sha256);
  await writeFile(path, bytes, { mode: 0o600, flag: 'wx' });
}

async function command(name, executable, args, cwd, timeoutMs, env = process.env) {
  const result = await runBounded(executable, args, { cwd, timeoutMs, env });
  if (result.reason || !result.cleanupConfirmed || result.exitCode !== 0) {
    process.stderr.write(result.stderr + result.stdout);
    throw Error(`${name}:${result.reason ?? (result.cleanupConfirmed ? 'command_failed' : 'cleanup_unknown')}:exit=${result.exitCode}:reason=${result.reason}:cleanup=${result.cleanup}:signal=${result.signal}`);
  }
  return result.stdout;
}

const shellQuote = value => `'${value.replaceAll("'", "'\\''")}'`;
function pathValue(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || /[\0\r\n]/.test(value)) throw Error('security_setup_path');
  return value;
}

async function writableDirectories(directory) {
  const stat = await lstat(directory).catch(error => { if (error.code === 'ENOENT') return undefined; throw error; });
  if (!stat?.isDirectory() || stat.isSymbolicLink()) return;
  // Go caches use read-only directories. Only the fresh owned setup tree is changed.
  await chmod(directory, 0o700);
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && !entry.isSymbolicLink()) await writableDirectories(join(directory, entry.name));
  }
}

export async function failSecuritySetup(directory, originalError) {
  try { await writableDirectories(directory); await rm(directory, { recursive: true, force: true }); }
  catch (cleanupError) { process.stderr.write(`Security setup cleanup failed (${cleanupError.code ?? 'unknown'}); preserving the original setup failure.\n`); }
  throw originalError;
}

export async function bootstrapSecurityToolchain() {
  if (process.platform !== 'linux' || process.arch !== 'x64') throw Error('security_setup_requires_linux_x64');
  const githubEnv = pathValue(process.env.GITHUB_ENV), javaHome = pathValue(process.env.JAVA_HOME_21_X64);
  const destination = join(root, 'artifacts/ci-tools');
  await mkdir(destination, { recursive: true, mode: 0o700 });
  const directory = pathValue(await mkdtemp(join(destination, 'security-toolchain-')));
  const python = process.env.WAKEIO_BOOTSTRAP_PYTHON ?? 'python3';
  const environment = {};
  try {
    const outcomes = await Promise.allSettled([
      (async () => {
        await command('python-version', python, ['-I', '-c', 'import sys; assert sys.version_info[:2] == (3,12)'], directory, 10_000);
        const venv = join(directory, 'semgrep');
        await command('semgrep-venv', python, ['-m', 'venv', venv], directory, 30_000);
        await command('semgrep-install', join(venv, 'bin/python'), ['-I', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
          '--only-binary=:all:', '--no-cache-dir', '--index-url', 'https://pypi.org/simple', '--timeout', '20', '--retries', '1', `semgrep==${SECURITY_TOOLCHAIN_RELEASES.semgrep}`], directory, 180_000);
        await command('semgrep-version', join(venv, 'bin/python'), ['-I', '-c', `import importlib.metadata; assert importlib.metadata.version('semgrep') == '${SECURITY_TOOLCHAIN_RELEASES.semgrep}'`], directory, 10_000);
        environment.WAKEIO_SEMGREP_TEST_PATH = join(venv, 'bin/semgrep');
      })(),
      (async () => {
        const archive = join(directory, 'go.tar.gz'); await download(SECURITY_TOOLCHAIN_RELEASES.go, archive);
        await command('go-extract', 'tar', ['-xzf', archive, '-C', directory, '--no-same-owner'], directory, 30_000); await rm(archive);
        const go = join(directory, 'go/bin/go'), gopath = join(directory, 'gopath'), bin = join(directory, 'bin');
        const env = { ...process.env, HOME: directory, GOPATH: gopath, GOBIN: bin, GOMODCACHE: join(gopath, 'pkg/mod'),
          GOROOT: join(directory, 'go'), GOCACHE: join(directory, 'go-build'),
          GOTOOLCHAIN: 'local', GOWORK: 'off', GOENV: 'off', GOFLAGS: '', GOPROXY: 'https://proxy.golang.org', GOSUMDB: 'sum.golang.org',
          GOPRIVATE: '', GONOPROXY: '', GONOSUMDB: '' };
        await command('govulncheck-install', go, ['install', `golang.org/x/vuln/cmd/govulncheck@${SECURITY_TOOLCHAIN_RELEASES.govulncheck}`], directory, 180_000, env);
        await command('go-fixture-cache', go, ['mod', 'download', 'golang.org/x/text@v0.3.6', 'golang.org/x/text@v0.3.7', 'golang.org/x/tools@v0.0.0-20180917221912-90fa682c2a6e'], directory, 90_000, env);
        const buildInfo = await command('govulncheck-pin', go, ['version', '-m', join(bin, 'govulncheck')], directory, 10_000, env);
        if (!buildInfo.includes(`golang.org/x/vuln\t${SECURITY_TOOLCHAIN_RELEASES.govulncheck}\t`)) throw Error('govulncheck_version_mismatch');
        Object.assign(environment, { WAKEIO_GOVULNCHECK_EXECUTABLE: join(bin, 'govulncheck'), WAKEIO_GO_EXECUTABLE: go,
          WAKEIO_GO_MODULE_CACHE: join(gopath, 'pkg/mod'), WAKEIO_REQUIRE_GOVULNCHECK: '1' });
      })(),
      (async () => {
        const installed = await installToolsDetailed({ tools: ['trivy'], destination: join(directory, 'trivy'), cacheDirectory: process.env.WAKEIO_TOOL_CACHE });
        const trivy = installed.paths.trivy, cache = join(directory, 'trivy-cache'), config = join(directory, 'trivy.yaml');
        await writeFile(config, '{}\n', { mode: 0o600, flag: 'wx' });
        await command('trivy-database', trivy, ['image', '--download-db-only', '--disable-telemetry', '--skip-version-check', '--config', config, '--cache-dir', cache], directory, 120_000);
        await command('image-pull', 'docker', ['pull', '--platform', 'linux/amd64', SECURITY_TOOLCHAIN_RELEASES.alpine], directory, 120_000);
        const image = (await command('image-inspect', 'docker', ['image', 'inspect', '--format', '{{.Architecture}} {{.Id}}', SECURITY_TOOLCHAIN_RELEASES.alpine], directory, 10_000)).trim();
        if (!/^amd64 sha256:[a-f0-9]{64}$/.test(image)) throw Error('image_architecture_or_id');
        const archive = join(directory, 'alpine-3.18.0.tar');
        await command('image-save', 'docker', ['save', '--output', archive, image.split(' ')[1]], directory, 30_000);
        Object.assign(environment, { WAKEIO_TRIVY_EXECUTABLE: trivy, WAKEIO_TRIVY_CACHE: cache,
          WAKEIO_TRIVY_IMAGE_ARCHIVE: archive, WAKEIO_REQUIRE_TRIVY_VULN: '1' });
      })(),
      (async () => {
        const javaVersion = await command('java-version', join(javaHome, 'bin/java'), ['--version'], directory, 10_000);
        if (!/^(?:openjdk|java) 21[.\s]/m.test(javaVersion)) throw Error('java_21_required');
        const archive = join(directory, 'zap.zip'); await download(SECURITY_TOOLCHAIN_RELEASES.zap, archive);
        await command('zap-extract', 'unzip', ['-q', archive, '-d', directory], directory, 60_000); await rm(archive);
        const zap = join(directory, 'ZAP_2.17.0/zap.sh'), wrapper = join(directory, 'zap'); await chmod(zap, 0o700);
        // The scan supervisor strips inherited environment. Bind Java explicitly in this CI-only wrapper.
        await writeFile(wrapper, `#!/bin/sh\nJAVA_HOME=${shellQuote(javaHome)}\nexport JAVA_HOME\nexec ${shellQuote(zap)} "$@"\n`, { mode: 0o700, flag: 'wx' });
        // runZap checks the version in its isolated environment before any target request.
        environment.WAKEIO_ZAP_PATH = wrapper;
      })(),
    ]);
    const failed = outcomes.find(outcome => outcome.status === 'rejected');
    if (failed) throw failed.reason;
    const lines = Object.entries(environment).sort().map(([name, value]) => {
      if (!/^WAKEIO_[A-Z_]+$/.test(name) || (name.startsWith('WAKEIO_REQUIRE_') ? value !== '1' : !pathValue(value))) throw Error('security_setup_environment');
      return `${name}=${value}\n`;
    }).join('');
    await appendFile(githubEnv, lines);
    await mkdir(join(root, 'artifacts/ci'), { recursive: true, mode: 0o700 });
    await writeFile(join(root, 'artifacts/ci/security-toolchain-setup.json'), JSON.stringify({ version: 1, releases: SECURITY_TOOLCHAIN_RELEASES,
      environment, imageExecuted: false, packageVerification: 'Go/ZAP archive SHA256; existing Trivy archive SHA256; Go module checksum database; Semgrep version pin via PyPI (not a transitive hash lock)' }, null, 2) + '\n', { mode: 0o600 });
    return environment;
  } catch (error) { return failSecuritySetup(directory, error); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await bootstrapSecurityToolchain(); process.stdout.write('Prepared pinned Semgrep, govulncheck/Go, Trivy and ZAP for required real-engine tests. No target application was scanned during setup.\n'); }
  catch (error) { process.stderr.write(`Security toolchain setup failed: ${error.message}; no required tests may be skipped.\n`); process.exitCode = 2; }
}
