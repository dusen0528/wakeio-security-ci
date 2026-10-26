import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { ScanReport, ToolName } from '../src/contracts.js';
import { runtimeM0SemanticHash } from './helpers/runtime-m0-hash.js';

const BASE = '7a4ada160963fd6e9e0b700bf4ed638a0043a1ac';
const REFERENCE_SHA256 = '33bfbce6379c1d09a9094599d9a67276e2f77c25303ab9430bbcff61a8d09faa';
const NATIVE_UNSUPPORTED_SHA256 = '84bb065dfd9fca08aaafeb7e1ee26cd301d163d0fcc23b030463a5c158b4866c';
const NATIVE_PROVENANCE_SHA256 = '5cea1f28c239d48022f5664672be7d27da1ed1301e23a1cca01281749b8841e2';
const HASH_SOURCE_SHA256 = '3bd5279ac418a73c5ea6859cc32d5185186af8ea15e5a655c1bfccbc8335d514';
const fixtures = resolve('tests/fixtures');
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
interface MatrixCase {
  id: string; sourceId: string; tools: ToolName[]; nativePreview: boolean;
  failOn: 'high' | 'none' | 'critical'; sourceMaxFiles?: number; exitCode: 0 | 1 | 2;
  semanticHash: string; checks: Array<{ id: string; status: string }>; goProviderRows?: number;
}
interface Reference {
  revision: string;
  sourceFiles: Record<string, Array<{ name: string; sha256: string }>>;
  cases: MatrixCase[];
}
interface NativeProvenance {
  baselineRevision: string;
  macReferenceSha256: string;
  hashFunction: { source: string; fileSha256: string };
  sourceFiles: Reference['sourceFiles'];
  case: MatrixCase;
}
const pathFlag: Record<ToolName, string> = {
  gitleaks: '--gitleaks', osv: '--osv', trivy: '--trivy', bandit: '--bandit',
  semgrep: '--semgrep', govulncheck: '--govulncheck', 'trivy-vuln': '--trivy',
};

async function reference(): Promise<Reference> {
  const bytes = await readFile(join(fixtures, 'runtime-m0-baseline.json'));
  assert.equal(sha(bytes), REFERENCE_SHA256, 'the original R9 reference bytes must remain frozen');
  const value = JSON.parse(bytes.toString('utf8')) as Reference;
  assert.equal(value.revision, BASE);
  assert.equal(value.cases.length, 23);
  return value;
}

async function nativeUnsupported(value: Reference): Promise<MatrixCase> {
  const [bytes, provenanceBytes] = await Promise.all([
    readFile(join(fixtures, 'runtime-m0-native-unsupported.json')),
    readFile(join(fixtures, 'runtime-m0-native-unsupported-provenance.json')),
  ]);
  assert.equal(sha(bytes), NATIVE_UNSUPPORTED_SHA256);
  assert.equal(sha(provenanceBytes), NATIVE_PROVENANCE_SHA256);
  const row = JSON.parse(bytes.toString('utf8')) as MatrixCase;
  const provenance = JSON.parse(provenanceBytes.toString('utf8')) as NativeProvenance;
  assert.equal(provenance.baselineRevision, BASE);
  assert.equal(provenance.macReferenceSha256, REFERENCE_SHA256);
  assert.deepEqual(provenance.hashFunction,
    { source: `${BASE}:scripts/kpi.mjs#semanticHash`, fileSha256: HASH_SOURCE_SHA256 });
  assert.deepEqual(provenance.sourceFiles, value.sourceFiles);
  assert.deepEqual(provenance.case, row);
  assert.equal(row.id, 'native-on');
  const original = value.cases.find(item => item.id === row.id);
  assert.ok(original);
  const { semanticHash: unsupportedHash, ...unsupportedFields } = row;
  const { semanticHash: macHash, ...originalFields } = original;
  assert.deepEqual(unsupportedFields, originalFields);
  return row;
}

async function verifyInputs(value: Reference, sources: Record<string, string>): Promise<void> {
  assert.deepEqual(Object.keys(sources).sort(), Object.keys(value.sourceFiles).sort());
  for (const [sourceId, source] of Object.entries(sources)) {
    const files = await Promise.all((await readdir(source)).sort().map(async name =>
      ({ name, sha256: sha(await readFile(join(source, name))) })));
    assert.deepEqual(files, value.sourceFiles[sourceId], `input bytes: ${sourceId}`);
  }
}

function argumentsFor(item: MatrixCase, source: string, out: string, missing: string): string[] {
  const projectId = item.sourceId.startsWith('compat-')
    ? item.sourceId.replace('compat-', 'compat-0.5-') : `m0-${item.sourceId}`;
  const args = ['build/src/cli.js', 'scan', '--source', source,
    '--tools', item.tools.length ? item.tools.join(',') : 'none',
    '--project-id', projectId, '--out', out, '--fail-on', item.failOn];
  if (item.sourceMaxFiles) args.push('--source-max-files', String(item.sourceMaxFiles));
  const seen = new Set<string>();
  for (const tool of item.tools) {
    const flag = pathFlag[tool];
    assert.ok(flag, `registered tool: ${tool}`);
    if (!seen.has(flag)) args.push(flag, join(missing, tool));
    seen.add(flag);
  }
  if (item.nativePreview) args.push('--opengrep-core', join(missing, 'opengrep-core'));
  return args;
}

async function runCase(item: MatrixCase, source: string, top: string, missing: string): Promise<void> {
  const out = join(top, 'reports', item.id);
  const run = spawnSync(process.execPath, argumentsFor(item, source, out, missing),
    { cwd: process.cwd(), encoding: 'utf8', timeout: 60000 });
  assert.ifError(run.error);
  assert.equal(run.status, item.exitCode, `scan exit: ${item.id}`);
  const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8')) as ScanReport;
  const goRow = report.checks.find(check => check.id === 'source.code-coverage')
    ?.codeCoverage?.languages.find(row => row.language === 'go');
  const observed: MatrixCase = {
    id: item.id, sourceId: item.sourceId, tools: item.tools, nativePreview: item.nativePreview,
    failOn: item.failOn, ...(item.sourceMaxFiles ? { sourceMaxFiles: item.sourceMaxFiles } : {}),
    exitCode: run.status as MatrixCase['exitCode'], semanticHash: runtimeM0SemanticHash(report),
    checks: report.checks.map(check => ({ id: check.id, status: check.status })),
    ...(goRow ? { goProviderRows: goRow.providers.length } : {}),
  };
  assert.deepEqual(observed, item, `frozen report semantics: ${item.id}`);
}

test('M0 source dispatch preserves all 23 frozen pre-refactor report hashes and scan exits', async t => {
  const value = await reference();
  const unsupported = await nativeUnsupported(value);
  const nativeSupported = process.platform === 'darwin' && process.arch === 'arm64';
  const top = await mkdtemp(join(tmpdir(), 'wakeio-runtime-m0-compat-'));
  const empty = join(top, 'empty'), missing = join(top, 'intentionally-absent-tools');
  try {
    await mkdir(empty);
    await assert.rejects(readdir(missing), { code: 'ENOENT' });
    const sources: Record<string, string> = {
      'compat-pass': join(fixtures, 'compat-0.5/pass/source'),
      'compat-findings': join(fixtures, 'compat-0.5/findings/source'),
      'compat-partial': join(fixtures, 'compat-0.5/partial/source'),
      matrix: join(fixtures, 'runtime-m0/matrix'), empty,
    };
    await t.test('R9 baseline raw SHA and all admitted source bytes remain unchanged',
      () => verifyInputs(value, sources));
    for (const original of value.cases) {
      const item = !nativeSupported && original.id === unsupported.id ? unsupported : original;
      await t.test(item.id, () => runCase(item, sources[item.sourceId], top, missing));
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});
