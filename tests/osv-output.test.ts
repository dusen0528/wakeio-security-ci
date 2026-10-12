import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseOsvOutput } from '../src/source/parsers.js';
import type { ScanReport } from '../src/contracts.js';
import type { CollectedFile } from '../src/source/types.js';

const files: CollectedFile[] = [{ path: 'package-lock.json', bytes: 2, text: '{}', category: 'dependency', sensitive: false }];
const identity = { name: 'synthetic-osv-fixture', version: '1.0.0', ecosystem: 'npm' };
const advisory = { id: 'GHSA-test-osv-fixture', database_specific: { severity: 'HIGH' }, details: 'RAW_ADVISORY_CANARY' };
const cleanPackage = () => ({ package: { ...identity } });
const affectedPackage = () => ({ package: { ...identity }, vulnerabilities: [advisory] });
const envelope = (packages: unknown[]) => ({ results: [{ source: { path: 'package-lock.json', type: 'lockfile' }, packages }] });
const parse = (packages: unknown[]) => parseOsvOutput(JSON.stringify(envelope(packages)), '/scan', files);

test('OSV 2.6 clean package output accepts omitted and explicitly empty vulnerabilities', () => {
  // The pinned scanner omits empty slices in PackageVulns.MarshalJSON:
  // https://github.com/google/osv-scanner/blob/v2.6.0/pkg/models/results.go#L191-L235
  for (const row of [cleanPackage(), { ...cleanPackage(), vulnerabilities: [] }]) {
    const parsed = parse([row]);
    assert.deepEqual(parsed.findings, []);
    assert.equal(parsed.metrics?.packageCount, 1);
    assert.equal(parsed.metrics?.findingCount, 0);
  }
});

test('OSV omitted vulnerabilities on a clean package never hide an adjacent advisory', () => {
  const parsed = parse([cleanPackage(), affectedPackage(), { ...cleanPackage(), vulnerabilities: [] }]);
  assert.equal(parsed.metrics?.packageCount, 3);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].ruleId, 'osv:npm:synthetic-osv-fixture:1.0.0:GHSA-test-osv-fixture');
  assert.equal(parsed.findings[0].kind, 'advisory');
  assert.equal(parsed.findings[0].severity, 'high');
  assert.equal(parsed.findings[0].location.path, 'package-lock.json');
  assert.equal(JSON.stringify(parsed).includes('RAW_ADVISORY_CANARY'), false);
});

test('OSV explicit null, malformed collections, and malformed advisory records still fail closed', () => {
  for (const vulnerabilities of [null, false, 0, '', '[]', {}, [null], [[]], [{}], [{ id: '' }], [{ id: 42 }]]) {
    assert.throws(() => parse([{ ...cleanPackage(), vulnerabilities }]), /OSV-Scanner/,
      `accepted vulnerabilities=${JSON.stringify(vulnerabilities)}`);
  }
  for (const groups of [null, false, {}, [null], [{ ids: 'GHSA-test-osv-fixture' }]]) {
    assert.throws(() => parse([{ ...cleanPackage(), groups }]), /OSV-Scanner/);
  }
});

test('OSV optional vulnerabilities do not relax required package identity or inventory fields', () => {
  for (const row of [null, {}, { package: null }, { package: [] }, ...Object.keys(identity).map((key) => {
    const incomplete: Record<string, unknown> = { ...identity };
    delete incomplete[key];
    return { package: incomplete };
  })]) assert.throws(() => parse([row]), /OSV-Scanner/);
  for (const raw of [
    {}, { results: [] }, { results: null },
    { results: [{ source: { path: 'package-lock.json' } }] },
    { results: [{ source: { path: 'package-lock.json' }, packages: [] }] },
    { results: [{ source: {}, packages: [cleanPackage()] }] },
  ]) assert.throws(() => parseOsvOutput(JSON.stringify(raw), '/scan', files), /OSV-Scanner/);
});

async function writeStub(path: string, output: unknown, code: number, requireAllPackages = false): Promise<void> {
  // These local synthetic executables test the adapter contract, not a live
  // scanner or vulnerability database. Keep them outside the scanned root.
  await writeFile(path, `#!/usr/bin/env node
if (process.argv.includes('--version')) { console.log('synthetic scanner fixture'); process.exit(0); }
${requireAllPackages ? "if (!process.argv.includes('--all-packages')) process.exit(3);" : ''}
process.stdout.write(${JSON.stringify(JSON.stringify(output))});
process.exitCode = ${code};
`);
  await chmod(path, 0o700);
}

async function launch(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../src/cli.js', import.meta.url)), ...args]);
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('default-tools CLI with synthetic scanners preserves OSV clean, advisory, and error gates', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-osv-output-'));
  const root = join(top, 'source');
  const gitleaks = join(top, 'gitleaks'), osv = join(top, 'osv-scanner'), trivy = join(top, 'trivy');
  try {
    await mkdir(root);
    await writeFile(join(root, 'app.ts'), 'export const ready = true;\n');
    await writeFile(join(root, 'Dockerfile'), 'FROM scratch\nUSER 1000\n');
    await writeFile(join(root, 'package-lock.json'), JSON.stringify({ name: 'synthetic-root', lockfileVersion: 3,
      packages: { '': { name: 'synthetic-root' }, 'node_modules/synthetic-osv-fixture': { version: '1.0.0' } } }));
    await writeStub(gitleaks, [], 0);
    await writeStub(trivy, { SchemaVersion: 2, Results: [{ Target: 'Dockerfile', Misconfigurations: [] }] }, 0);
    for (const scenario of [
      { name: 'omitted', packages: [cleanPackage()], scannerCode: 0, code: 0, status: 'completed', findings: 0 },
      { name: 'empty', packages: [{ ...cleanPackage(), vulnerabilities: [] }], scannerCode: 0, code: 0, status: 'completed', findings: 0 },
      { name: 'mixed-advisory', packages: [cleanPackage(), affectedPackage()], scannerCode: 1, code: 1, status: 'completed', findings: 1 },
      { name: 'null', packages: [{ ...cleanPackage(), vulnerabilities: null }], scannerCode: 0, code: 2, status: 'error', findings: 0 },
      { name: 'malformed', packages: [{ ...cleanPackage(), vulnerabilities: {} }], scannerCode: 0, code: 2, status: 'error', findings: 0 },
      { name: 'missing-identity', packages: [{}], scannerCode: 0, code: 2, status: 'error', findings: 0 },
      { name: 'exit-contradiction', packages: [cleanPackage()], scannerCode: 1, code: 2, status: 'error', findings: 0 },
    ]) {
      const out = join(top, `reports-${scenario.name}`);
      await writeStub(osv, envelope(scenario.packages), scenario.scannerCode, true);
      // Deliberately omit --tools: exercise the real default selection.
      const result = await launch(['scan', '--source', root, '--gitleaks', gitleaks, '--osv', osv, '--trivy', trivy,
        '--out', out, '--timeout-ms', '10000', '--fail-on', 'high']);
      assert.equal(result.code, scenario.code, `${scenario.name}: ${result.stdout}\n${result.stderr}`);
      const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8')) as ScanReport;
      const check = report.checks.find((entry) => entry.id === 'source.osv');
      assert.equal(check?.status, scenario.status, scenario.name);
      assert.equal(check?.findings.length, scenario.findings, scenario.name);
      assert.equal(report.checks.find((entry) => entry.id === 'source.gitleaks')?.status, 'completed');
      assert.equal(report.checks.find((entry) => entry.id === 'source.trivy')?.status, 'completed');
      if (scenario.status === 'completed') assert.equal(check?.metrics?.packageCount, scenario.packages.length);
      if (scenario.code === 0) assert.match(result.stdout, /COMPLETED:/);
      if (scenario.code === 1) assert.match(result.stdout, /FINDINGS:/);
      if (scenario.code === 2) assert.match(result.stdout, /INCOMPLETE:/);
      for (const name of ['report.json', 'report.sarif', 'report.md', 'agent-report.json']) {
        const rendered = await readFile(join(out, name), 'utf8');
        assert.equal(rendered.includes('RAW_ADVISORY_CANARY'), false, name);
      }
    }
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});
