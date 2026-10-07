// Explicit CI setup only. Scans never download engines or templates.
import { createHash } from 'node:crypto';
import { appendFile, lstat, mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { installToolsDetailed, TOOL_RELEASES } from './install-tools.mjs';
import { runBounded } from './ci-process.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
export const NUCLEI_SETUP_FILE = join(root, 'artifacts/ci/nuclei-setup.json');
export const NUCLEI_TEMPLATES = Object.freeze({
  version: 'v10.5.0',
  commit: 'f8b8b8dcd70d93826c3767e1829ef8243af9f03b',
  archiveSha256: '64728ab1b7854d5e65657995eb61945c98395578bb5cb13f4efe7024ea051641',
  url: 'https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/f8b8b8dcd70d93826c3767e1829ef8243af9f03b',
});
const prefix = `nuclei-templates-${NUCLEI_TEMPLATES.commit}`;
const MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;

export function verifyTemplateArchive(bytes) {
  if (!bytes.length || bytes.length > MAX_ARCHIVE_BYTES) throw Error('templates_archive_size');
  if (createHash('sha256').update(bytes).digest('hex') !== NUCLEI_TEMPLATES.archiveSha256) throw Error('templates_archive_checksum');
}

export function validateTemplateEntries(names, details) {
  const entries = names.trim().split('\n');
  if (!entries.length || entries.length > 20000) throw Error('templates_archive_entries');
  for (const entry of entries) {
    if (entry !== prefix + '/' && !entry.startsWith(prefix + '/')) throw Error('templates_archive_path');
    if (entry.includes('\\') || entry.includes('\0') || entry.split('/').some(part => part === '.' || part === '..')) throw Error('templates_archive_path');
  }
  // Refuse links and special files before extraction, including hardlinks.
  if (details.trim().split('\n').some(line => !/^[-d]/.test(line))) throw Error('templates_archive_type');
  for (const required of ['http/misconfiguration/', 'http/exposures/', 'LICENSE.md', 'templates-checksum.txt']) {
    if (!entries.includes(prefix + '/' + required)) throw Error('templates_archive_required_entry');
  }
}

// Bound local overrides before allocation and reject special files even if the path
// changes between lstat and open. The injectable operations support deterministic
// filesystem-race tests; the CLI always uses the real filesystem operations.
export async function readLocalTemplateArchive(path, operations = { lstat, open }) {
  const initial = await operations.lstat(path, { bigint: true });
  const valid = stat => stat.isFile() && stat.size > 0n && stat.size <= BigInt(MAX_ARCHIVE_BYTES);
  if (!valid(initial)) throw Error('templates_local_archive_type_or_size');
  if (![constants.O_NOFOLLOW, constants.O_NONBLOCK].every(Number.isInteger)) throw Error('templates_local_archive_platform');
  const handle = await operations.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stable = stat => valid(stat) && ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => stat[key] === initial[key]);
    if (!stable(await handle.stat({ bigint: true }))) throw Error('templates_local_archive_changed');
    // One extra byte detects growth without an unbounded readFile allocation.
    const bytes = Buffer.alloc(Number(initial.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, Math.min(64 * 1024, bytes.length - offset), offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== Number(initial.size) || !stable(await handle.stat({ bigint: true })) ||
        !stable(await operations.lstat(path, { bigint: true }))) throw Error('templates_local_archive_changed');
    return bytes.subarray(0, offset);
  } finally { await handle.close(); }
}

async function downloadTemplates() {
  const response = await fetch(NUCLEI_TEMPLATES.url, { signal: AbortSignal.timeout(90000), redirect: 'error' });
  if (!response.ok || !response.body) throw Error('templates_download_failed');
  if (Number(response.headers.get('content-length')) > MAX_ARCHIVE_BYTES) throw Error('templates_archive_size');
  const chunks = []; let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > MAX_ARCHIVE_BYTES) { await response.body.cancel().catch(() => {}); throw Error('templates_archive_size'); }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, length);
}

async function tar(args) {
  const result = await runBounded('tar', args, { timeoutMs: 30000 });
  if (result.reason || !result.cleanupConfirmed || result.exitCode !== 0) throw Error('templates_tar_failed');
  return result.stdout;
}

// The manifest is a local setup receipt, not authority to run a different engine.
export function requiredNucleiEnvironment(environment, setup) {
  if ((!environment.WAKEIO_NUCLEI || !environment.WAKEIO_NUCLEI_TEMPLATES) &&
      (setup?.engine?.version !== TOOL_RELEASES.nuclei.version || setup?.templates?.commit !== NUCLEI_TEMPLATES.commit ||
       setup?.templates?.archiveSha256 !== NUCLEI_TEMPLATES.archiveSha256)) throw Error('nuclei_setup_missing_or_unpinned');
  const executable = environment.WAKEIO_NUCLEI || setup?.engine?.path;
  const templates = environment.WAKEIO_NUCLEI_TEMPLATES || setup?.templates?.path;
  if (![executable, templates].every(value => typeof value === 'string' && value.length && !/[\r\n\0]/.test(value))) throw Error('nuclei_setup_paths_required');
  return { ...environment, WAKEIO_NUCLEI: resolve(executable), WAKEIO_NUCLEI_TEMPLATES: resolve(templates), WAKEIO_REQUIRE_NUCLEI: '1' };
}

export async function bootstrapNuclei({ destination = join(root, 'artifacts/ci-tools'), cacheDirectory = process.env.WAKEIO_TOOL_CACHE,
  archivePath = process.env.WAKEIO_NUCLEI_TEMPLATE_ARCHIVE, githubEnv = process.env.GITHUB_ENV } = {}) {
  await mkdir(destination, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(join(destination, 'nuclei-setup-'));
  try {
    const installed = await installToolsDetailed({ tools: ['nuclei'], destination: directory, cacheDirectory });
    const bytes = archivePath ? await readLocalTemplateArchive(archivePath) : await downloadTemplates();
    verifyTemplateArchive(bytes);
    const archive = join(directory, 'templates.tar.gz');
    await writeFile(archive, bytes, { mode: 0o600, flag: 'wx' });
    validateTemplateEntries(await tar(['-tzf', archive]), await tar(['-tvzf', archive]));
    await tar(['-xzf', archive, '-C', directory, '--no-same-owner', '--no-same-permissions']);
    await rm(archive);
    const templates = join(directory, prefix);
    for (const name of ['http/misconfiguration', 'http/exposures']) {
      const stat = await lstat(join(templates, name));
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error('templates_scope_missing');
    }
    // Upstream source archives lack the config normally written by nuclei -ut.
    await writeFile(join(templates, '.templates-config.json'), JSON.stringify({ 'nuclei-templates-version': NUCLEI_TEMPLATES.version,
      'nuclei-templates-directory': templates }) + '\n', { mode: 0o600, flag: 'wx' });
    const setup = { version: 1, engine: { ...installed.metadata.nuclei, path: installed.paths.nuclei, version: TOOL_RELEASES.nuclei.version },
      templates: { ...NUCLEI_TEMPLATES, path: templates, checksumSha256: createHash('sha256').update(await readFile(join(templates, 'templates-checksum.txt'))).digest('hex') } };
    const environment = requiredNucleiEnvironment({}, setup);
    if (githubEnv) await appendFile(githubEnv, `WAKEIO_NUCLEI=${environment.WAKEIO_NUCLEI}\nWAKEIO_NUCLEI_TEMPLATES=${environment.WAKEIO_NUCLEI_TEMPLATES}\nWAKEIO_REQUIRE_NUCLEI=1\n`);
    await mkdir(join(root, 'artifacts/ci'), { recursive: true, mode: 0o700 });
    await writeFile(NUCLEI_SETUP_FILE, JSON.stringify(setup, null, 2) + '\n', { mode: 0o600 });
    return setup;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const setup = await bootstrapNuclei();
    process.stdout.write(`Prepared Nuclei ${setup.engine.version} and official templates ${setup.templates.version} at ${setup.templates.commit}.\nSetup receipt: ${NUCLEI_SETUP_FILE}\n`);
  } catch (error) {
    process.stderr.write(`Nuclei setup failed: ${error.message}; no required tests may be skipped.\n`); process.exitCode = 2;
  }
}
