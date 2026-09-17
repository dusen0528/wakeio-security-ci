#!/usr/bin/env node

/**
 * Install the pinned, upstream scanner binaries used by source scans.
 *
 * This file intentionally uses Node's HTTPS implementation rather than a
 * shell installer. Every asset URL is a versioned GitHub release URL and the
 * digest is copied from that project's release checksum metadata. The
 * caller supplies an isolated directory (the action uses a system temporary
 * directory outside the checkout).
 */

import { createHash } from 'node:crypto';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';

const execFileAsync = promisify(execFile);

export const TOOL_RELEASES = Object.freeze({
  gitleaks: Object.freeze({
    version: '8.30.1',
    license: 'MIT',
    baseUrl: 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/',
    assets: Object.freeze({
      'linux-x64': Object.freeze({
        file: 'gitleaks_8.30.1_linux_x64.tar.gz',
        sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
      }),
      'linux-arm64': Object.freeze({
        file: 'gitleaks_8.30.1_linux_arm64.tar.gz',
        sha256: 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080',
      }),
      'darwin-x64': Object.freeze({
        file: 'gitleaks_8.30.1_darwin_x64.tar.gz',
        sha256: 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709',
      }),
      'darwin-arm64': Object.freeze({
        file: 'gitleaks_8.30.1_darwin_arm64.tar.gz',
        sha256: 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5',
      }),
    }),
  }),
  osv: Object.freeze({
    version: '2.6.0',
    license: 'Apache-2.0',
    baseUrl: 'https://github.com/google/osv-scanner/releases/download/v2.6.0/',
    assets: Object.freeze({
      'linux-x64': Object.freeze({
        file: 'osv-scanner_linux_amd64',
        sha256: 'ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108',
      }),
      'linux-arm64': Object.freeze({
        file: 'osv-scanner_linux_arm64',
        sha256: '2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4',
      }),
      'darwin-x64': Object.freeze({
        file: 'osv-scanner_darwin_amd64',
        sha256: '60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca',
      }),
      'darwin-arm64': Object.freeze({
        file: 'osv-scanner_darwin_arm64',
        sha256: '98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4',
      }),
    }),
  }),
  trivy: Object.freeze({
    version: '0.74.0',
    license: 'Apache-2.0',
    baseUrl: 'https://github.com/aquasecurity/trivy/releases/download/v0.74.0/',
    assets: Object.freeze({
      'linux-x64': Object.freeze({
        file: 'trivy_0.74.0_Linux-64bit.tar.gz',
        sha256: '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
      }),
      'linux-arm64': Object.freeze({
        file: 'trivy_0.74.0_Linux-ARM64.tar.gz',
        sha256: 'b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5',
      }),
      'darwin-x64': Object.freeze({
        file: 'trivy_0.74.0_macOS-64bit.tar.gz',
        sha256: '472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485',
      }),
      'darwin-arm64': Object.freeze({
        file: 'trivy_0.74.0_macOS-ARM64.tar.gz',
        sha256: '1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11',
      }),
    }),
  }),
});

const TOOL_NAMES = Object.freeze(Object.keys(TOOL_RELEASES));

/**
 * Install selected tools and return absolute executable paths.
 *
 * `platform` and `arch` are injectable so unsupported runner behavior can be
 * tested without making a network request.
 */
export async function installTools({
  tools = TOOL_NAMES,
  destination = undefined,
  platform = process.platform,
  arch = process.arch,
  cacheDirectory = undefined,
  cacheDir = undefined,
  offline = false,
} = {}) {
  const result = await installToolsDetailed({
    tools,
    destination,
    platform,
    arch,
    cacheDirectory: cacheDirectory ?? cacheDir,
    offline,
  });
  return result.paths;
}

/**
 * Install selected tools and retain provenance for each installed executable.
 *
 * The cache stores the original upstream archive, never an unverified binary
 * or an unversioned manifest. A cache hit re-hashes that archive against the
 * pinned release SHA before extraction. `installTools` above keeps the small
 * path-map API used by existing callers; this detailed form is used by the
 * Action to explain cache hits and misses without exposing scanner output.
 */
export async function installToolsDetailed({
  tools = TOOL_NAMES,
  destination = undefined,
  platform = process.platform,
  arch = process.arch,
  cacheDirectory = undefined,
  cacheDir = undefined,
  offline = false,
} = {}) {
  const selected = normaliseTools(tools);
  if (selected.length === 0) return { paths: {}, metadata: {} };

  const platformKey = platformAssetKey(platform, arch);
  if (!platformKey) {
    throw new Error(
      `Unsupported runner platform ${platform}/${arch}. Pinned scanner installers support Linux x64/arm64 and macOS x64/arm64.`,
    );
  }

  const root = destination
    ? resolve(destination)
    : await mkdtemp(join(tmpdir(), 'wakeio-security-ci-tools-'));
  await ensureDirectory(root);

  const cacheRoot = cacheDirectory ?? cacheDir;
  if (cacheRoot) await ensureDirectory(cacheRoot);

  const paths = {};
  const metadata = {};
  for (const toolName of selected) {
    const spec = TOOL_RELEASES[toolName];
    const asset = spec.assets[platformKey];
    if (!asset) {
      throw new Error(`No pinned ${toolName} asset is available for ${platform}/${arch}`);
    }
    const installed = await installOne(toolName, spec, asset, root, platformKey, cacheRoot, offline);
    paths[toolName] = installed.path;
    metadata[toolName] = installed.metadata;
  }
  return { paths, metadata };
}

export function platformAssetKey(platform, arch) {
  if ((platform === 'linux' || platform === 'darwin') && (arch === 'x64' || arch === 'arm64')) {
    return `${platform}-${arch}`;
  }
  return undefined;
}

async function installOne(toolName, spec, asset, root, platformKey, cacheRoot, offline) {
  const toolDir = join(root, toolName);
  await ensureDirectory(toolDir);
  const staging = await mkdtemp(join(toolDir, '.staging-'));
  try {
    const archivePath = join(staging, asset.file);
    const url = `${spec.baseUrl}${asset.file}`;
    const cachedArchive = cacheRoot
      ? join(cacheRoot, `${toolName}-${spec.version}-${platformKey}-${asset.sha256}-${asset.file}`)
      : undefined;
    let body;
    let cacheHit = false;
    if (cachedArchive) {
      body = await readVerifiedCache(cachedArchive, toolName, asset);
      cacheHit = Boolean(body);
    }
    if (!body) {
      if (offline) {
        throw new Error(`No verified cached ${toolName} archive is available for offline installation`);
      }
      body = await download(url);
      verifyChecksum(toolName, asset, body);
      if (cachedArchive) await writeVerifiedCache(cachedArchive, body);
    } else {
      // readVerifiedCache already checked the bytes. Keep the check adjacent
      // to extraction so a future refactor cannot accidentally trust metadata
      // or an executable copied from the cache instead of the archive itself.
      verifyChecksum(toolName, asset, body);
    }
    const actual = createHash('sha256').update(body).digest('hex');
    await writeFile(archivePath, body, { mode: 0o600, flag: 'wx' });

    const executableName = toolName === 'osv' ? 'osv-scanner' : toolName;
    const executable = join(root, `${toolName}-${spec.version}`, executableName);
    await ensureDirectory(dirname(executable));
    await ensureRegularTarget(executable);

    if (asset.file.endsWith('.tar.gz')) {
      await validateTarEntries(archivePath);
      await execFileAsync('tar', ['-xzf', archivePath, '-C', staging]);
      const extracted = join(staging, executableName);
      const stats = await lstat(extracted).catch(() => undefined);
      if (!stats || !stats.isFile() || stats.isSymbolicLink()) {
        throw new Error(`Pinned ${toolName} archive did not contain a regular ${executableName} binary`);
      }
      await copyFile(extracted, executable);
    } else {
      await copyFile(archivePath, executable);
    }
    await chmod(executable, 0o755);
    return {
      path: executable,
      metadata: {
        version: spec.version,
        platform: platformKey,
        asset: asset.file,
        archiveSha256: asset.sha256,
        verifiedSha256: actual,
        verification: 'pinned-upstream-archive-sha256',
        cacheHit,
        ...(cachedArchive ? { cachePath: cachedArchive } : {}),
      },
    };
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
  }
}

function verifyChecksum(toolName, asset, body) {
  const actual = createHash('sha256').update(body).digest('hex');
  if (actual !== asset.sha256) {
    throw new Error(
      `Checksum mismatch for ${toolName} ${asset.file}: expected ${asset.sha256}, received ${actual}`,
    );
  }
}

async function readVerifiedCache(cachePath, toolName, asset) {
  let info;
  try {
    info = await lstat(cachePath);
  } catch (error) {
    if (isMissing(error)) return undefined;
    throw error;
  }
  if (info.isSymbolicLink()) throw new Error(`Refusing symlink cached archive: ${cachePath}`);
  if (!info.isFile()) throw new Error(`Cached archive is not a regular file: ${cachePath}`);
  if (info.size > MAX_ASSET_BYTES) {
    await rm(cachePath, { force: true });
    return undefined;
  }
  const body = await readFile(cachePath);
  try {
    verifyChecksum(toolName, asset, body);
    return body;
  } catch {
    // A stale or interrupted cache entry is disposable. It is never used as
    // a binary merely because a sidecar or filename claims a matching build.
    await rm(cachePath, { force: true });
    return undefined;
  }
}

async function writeVerifiedCache(cachePath, body) {
  await ensureRegularTarget(cachePath);
  const temporary = join(dirname(cachePath), `.${cachePath.split(sep).pop()}.staging-${process.pid}-${Date.now()}`);
  await writeFile(temporary, body, { mode: 0o600, flag: 'wx' });
  try {
    // The destination is checked before this replacement. Renaming a regular
    // temporary file never follows a destination symlink.
    await rename(temporary, cachePath);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

const MAX_ASSET_BYTES = 256 * 1024 * 1024;

async function download(url, timeoutMs = 60_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { redirect: 'follow', signal: controller.signal });
    if (!response.ok) {
      throw new Error(`Download failed (${response.status}) for pinned release asset ${url}`);
    }
    const declaredLength = Number(response.headers.get('content-length') || 0);
    if (declaredLength > MAX_ASSET_BYTES) {
      throw new Error(`Pinned release asset is larger than the ${MAX_ASSET_BYTES} byte limit`);
    }
    if (!response.body) throw new Error(`Pinned release asset returned no body: ${url}`);
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > MAX_ASSET_BYTES) {
        await reader.cancel();
        throw new Error(`Pinned release asset exceeded the ${MAX_ASSET_BYTES} byte limit`);
      }
      chunks.push(Buffer.from(next.value));
    }
    return Buffer.concat(chunks, total);
  } finally {
    clearTimeout(timer);
  }
}

async function validateTarEntries(archivePath) {
  const { stdout } = await execFileAsync('tar', ['-tzf', archivePath]);
  for (const rawEntry of stdout.split(/\r?\n/)) {
    const entry = rawEntry.trim();
    if (!entry) continue;
    const normal = entry.replace(/^\.\//, '');
    if (normal.startsWith('/') || /^[A-Za-z]:[\\/]/.test(normal) || normal.includes('\u0000')) {
      throw new Error(`Refusing unsafe path in pinned archive: ${entry}`);
    }
    const parts = normal.split('/');
    const stack = [];
    for (const part of parts) {
      if (!part || part === '.') continue;
      if (part === '..') {
        if (stack.length === 0) throw new Error(`Refusing traversal path in pinned archive: ${entry}`);
        stack.pop();
      } else {
        stack.push(part);
      }
    }
  }
}

function normaliseTools(value) {
  const list = Array.isArray(value)
    ? value
    : typeof value === 'string'
      ? value.split(',')
      : TOOL_NAMES;
  const result = [];
  for (const raw of list) {
    const name = String(raw).trim().toLowerCase();
    if (!name || name === 'none') continue;
    if (!TOOL_NAMES.includes(name)) throw new Error(`Unknown scanner tool: ${name}`);
    if (!result.includes(name)) result.push(name);
  }
  return result;
}

async function ensureDirectory(directory) {
  const absolute = resolve(directory);
  const root = resolve(absolute, sep);
  const parts = absolute.slice(root.length).split(sep).filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = resolve(current, part);
    let stats;
    try {
      stats = await lstat(current);
    } catch (error) {
      if (!isMissing(error)) throw error;
      await mkdir(current);
      stats = await lstat(current);
    }
    if (stats.isSymbolicLink()) {
      if (isStableSystemAlias(current)) {
        current = await realpath(current);
        continue;
      }
      throw new Error(`Refusing symlink in tools directory: ${current}`);
    }
    if (!stats.isDirectory()) throw new Error(`Tools path is not a directory: ${current}`);
  }
}

async function ensureRegularTarget(file) {
  try {
    const stats = await lstat(file);
    if (stats.isSymbolicLink()) throw new Error(`Refusing symlink tool target: ${file}`);
    if (!stats.isFile()) throw new Error(`Tool target is not a regular file: ${file}`);
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
}

function isStableSystemAlias(path) {
  return path === '/tmp' || path === '/var';
}

function isMissing(error) {
  return Boolean(error && typeof error === 'object' && error.code === 'ENOENT');
}

function parseArgs(argv) {
  const options = {
    tools: TOOL_NAMES,
    destination: undefined,
    cacheDirectory: undefined,
    offline: false,
    json: false,
    metadata: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
      continue;
    }
    if (arg === '--json') {
      options.json = true;
      continue;
    }
    if (arg === '--metadata') {
      options.metadata = true;
      continue;
    }
    if (arg === '--offline') {
      options.offline = true;
      continue;
    }
    if (arg === '--tools') {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) throw new Error('--tools requires a value');
      options.tools = value;
      i += 1;
      continue;
    }
    if (arg === '--dir') {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) throw new Error('--dir requires a value');
      options.destination = value;
      i += 1;
      continue;
    }
    if (arg === '--cache-dir') {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) throw new Error('--cache-dir requires a value');
      options.cacheDirectory = value;
      i += 1;
      continue;
    }
    throw new Error(`Unknown installer option: ${arg}`);
  }
  if (options.destination === '') throw new Error('--dir requires a non-empty path');
  if (options.cacheDirectory === '') throw new Error('--cache-dir requires a non-empty path');
  return options;
}

function usage() {
  return [
    'Usage: node scripts/install-tools.mjs [--tools gitleaks,osv,trivy|none] [--dir DIR] [--cache-dir DIR] [--offline] [--json] [--metadata]',
    '',
    'Downloads only pinned upstream release assets and verifies their SHA-256 digests.',
    'A cache stores the original release archive and is re-verified against that pinned digest on every hit.',
  ].join('\n');
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const result = options.metadata ? await installToolsDetailed(options) : undefined;
  const paths = result?.paths ?? await installTools(options);
  if (options.json) {
    process.stdout.write(`${JSON.stringify(result ?? paths)}\n`);
  } else {
    for (const [name, path] of Object.entries(paths)) {
      process.stdout.write(`${name}=${path}\n`);
    }
  }
}

const entrypoint = process.argv[1] && resolve(process.argv[1]);
if (entrypoint === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`wakeio-security-ci tool installation failed: ${error.message}\n`);
    process.exitCode = 2;
  });
}
