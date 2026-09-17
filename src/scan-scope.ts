import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readdir } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import type { Mode, ScanScope, ToolName } from './contracts.js';
import { findExecutable } from './source/process.js';

const MAX_PROJECT_ID_LENGTH = 128;
const MAX_HASH_FILES = 10_000;
const MAX_HASH_BYTES = 128 * 1024 * 1024;
// Trivy and other native scanners can be well over 64 MiB once bundled with
// their runtime. Keep provenance hashing bounded while covering normal
// release binaries; a larger file is reported as unreadable.
const MAX_ENGINE_BYTES = 256 * 1024 * 1024;
const IGNORED_DIRECTORIES = new Set([
  '.git', '.hg', '.svn', 'node_modules', '.venv', 'venv', '__pycache__',
  '.pytest_cache', '.mypy_cache', '.ruff_cache', '.intent-review', 'vendor',
  'build', 'dist', 'coverage', '.next', '.nuxt', '.turbo', '.cache',
  '.parcel-cache', 'out',
]);
const IGNORED_FILES = new Set([
  'report.json', 'report.sarif', 'report.md', 'comparison.json', 'comparison.md',
  '.gitleaks.toml', '.gitleaksignore', '.bandit', 'bandit.yaml', 'bandit.yml',
  'bandit.toml', '.trivyignore', '.trivy.yaml', 'trivy.yaml', 'trivy.yml',
  '.osv-scanner.toml', '.osv-scanner.yaml', '.osv-scanner.yml',
  'osv-scanner.toml', 'osv-scanner.yaml', 'osv-scanner.yml',
]);

export interface ScopeInputs {
  mode: Mode;
  source?: string;
  url?: string;
  projectId?: string;
  tools?: ToolName[];
  toolPaths?: Partial<Record<ToolName, string>>;
  allowPrivate?: boolean;
  timeoutMs?: number;
  osvOffline?: boolean;
  pages?: string[];
  maxPages?: number;
  apiPolicy?: unknown;
  ruleset: string;
}

export function validateProjectId(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PROJECT_ID_LENGTH) return undefined;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(value)) return undefined;
  return value;
}

function hashText(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

async function sourceContentHash(root: string): Promise<string | undefined> {
  const target = resolve(root);
  const hash = createHash('sha256');
  let files = 0;
  let bytes = 0;
  const walk = async (directory: string): Promise<void> => {
    const entries = (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files >= MAX_HASH_FILES || bytes >= MAX_HASH_BYTES) throw new Error('source hash budget');
      const entryName = entry.name.toLowerCase();
      if (entry.name === '.' || entry.name === '..' || (entry.isDirectory() && IGNORED_DIRECTORIES.has(entryName))) continue;
      if (entry.isFile() && IGNORED_FILES.has(entryName)) continue;
      const path = resolve(directory, entry.name);
      const stat = await lstat(path);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        await walk(path);
        continue;
      }
      if (!stat.isFile()) continue;
      if (stat.size > MAX_HASH_BYTES - bytes) throw new Error('source hash budget');
      const relativePath = relative(target, path).split(sep).join('/');
      hash.update(relativePath, 'utf8');
      hash.update('\0', 'utf8');
      const stream = createReadStream(path);
      await new Promise<void>((resolvePromise, reject) => {
        stream.on('data', (chunk: Buffer | string) => {
          bytes += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.byteLength;
          if (bytes > MAX_HASH_BYTES) {
            stream.destroy(new Error('source hash budget'));
            return;
          }
          hash.update(chunk);
        });
        stream.on('error', reject);
        stream.on('end', resolvePromise);
      });
      hash.update('\0', 'utf8');
      files += 1;
    }
  };
  try {
    await walk(target);
    return hash.digest('hex');
  } catch {
    return undefined;
  }
}

async function hashEngine(path: string): Promise<string | undefined> {
  try {
    const stat = await lstat(path);
    if (!stat.isFile() || stat.size > MAX_ENGINE_BYTES) return undefined;
    const hash = createHash('sha256');
    let bytes = 0;
    await new Promise<void>((resolvePromise, reject) => {
      const stream = createReadStream(path);
      stream.on('data', (chunk: Buffer | string) => {
        bytes += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.byteLength;
        if (bytes > MAX_ENGINE_BYTES) {
          stream.destroy(new Error('engine hash budget'));
          return;
        }
        hash.update(chunk);
      });
      stream.on('error', reject);
      stream.on('end', resolvePromise);
    });
    return hash.digest('hex');
  } catch {
    return undefined;
  }
}

async function engineProvenance(inputs: ScopeInputs): Promise<ScanScope['provenance']> {
  const engines: NonNullable<NonNullable<ScanScope['provenance']>['engines']> = [];
  for (const name of inputs.tools ?? []) {
    const configured = inputs.toolPaths?.[name];
    const command = configured ?? (name === 'osv' ? 'osv-scanner' : name);
    const executable = await findExecutable(command);
    if (!executable) {
      engines.push({ name, status: 'missing' });
      continue;
    }
    const sha256 = await hashEngine(executable);
    engines.push(sha256 ? { name, status: 'available', sha256 } : { name, status: 'unreadable' });
  }
  engines.sort((a, b) => a.name.localeCompare(b.name));
  const dataSources: Record<string, string> = {};
  if ((inputs.tools ?? []).includes('osv')) dataSources.osvDatabase = inputs.osvOffline ? 'offline-unknown' : 'online-unknown';
  if ((inputs.tools ?? []).includes('trivy')) {
    dataSources.trivyDatabase = 'unknown';
    dataSources.trivyChecksBundle = 'unknown';
  }
  // Bandit's configured entry point is commonly a small virtualenv wrapper;
  // hashing that file cannot prove the Python package/runtime underneath it.
  if ((inputs.tools ?? []).includes('bandit')) dataSources.banditRuntime = 'unknown';
  const sourceHash = inputs.source ? await sourceContentHash(inputs.source) : undefined;
  const sortedDataSources = Object.fromEntries(Object.entries(dataSources).sort(([a], [b]) => a.localeCompare(b)));
  const provenance = {
    ...(sourceHash ? { sourceContentHash: sourceHash } : {}),
    ...(engines.length ? { engines } : {}),
    ...(Object.keys(sortedDataSources).length ? { dataSources: sortedDataSources } : {}),
  };
  return Object.keys(provenance).length ? provenance : undefined;
}

/** Build stable scope identity and bounded run provenance separately. */
export async function buildScanScope(inputs: ScopeInputs): Promise<ScanScope> {
  const projectId = validateProjectId(inputs.projectId);
  const stable = {
    mode: inputs.mode,
    projectId: projectId ?? null,
    // A project ID intentionally replaces an absolute checkout path. Without
    // it, retain the old conservative path identity for local comparisons.
    sourceRoot: projectId ? null : inputs.source ? resolve(inputs.source) : null,
    url: inputs.url ?? null,
    tools: [...(inputs.tools ?? [])].sort(),
    allowPrivate: inputs.allowPrivate === true,
    timeoutMs: inputs.timeoutMs ?? null,
    osvOffline: inputs.osvOffline === true,
    pages: [...(inputs.pages ?? [])],
    maxPages: inputs.maxPages ?? null,
    apiPolicy: inputs.apiPolicy ?? null,
  };
  const fingerprint = hashText(JSON.stringify(stable));
  const provenance = await engineProvenance(inputs);
  return {
    fingerprint,
    ruleset: inputs.ruleset,
    ...(projectId ? { projectId } : {}),
    ...(provenance ? { provenance } : {}),
  };
}
