import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { readScanReport, compareReports, comparisonExitCode } from '../src/compare.js';
import { evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { parseExecutionPlan, parseExecutionInputs } from '../src/agent-dast/plan.js';

const exec = promisify(execFile), root = resolve('tests/fixtures/compat-0.5');
const manifest = JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8'));
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

test('frozen main 0.5 reports remain readable with raw binding and unchanged gate, Markdown and SARIF projections', async () => {
  assert.equal(manifest.sourceSha, '536d968357c31a7c681164ef7afa6307b138d1a7');
  for (const item of manifest.cases) {
    const base = join(root, item.id, 'reports');
    for (const [name, digest] of Object.entries(item.artifacts)) assert.equal(sha(await readFile(join(base, name))), digest);
    const bytes = await readFile(join(base, 'report.json'));
    const report = await readScanReport(join(base, 'report.json'));
    assert.equal(report.toolVersion, '0.5.0'); assert.deepEqual(report, JSON.parse(bytes.toString('utf8')));
    assert.equal(evaluateGate(report).exitCode, item.exitCode);
    const agent = JSON.parse(await readFile(join(base, 'agent-report.json'), 'utf8'));
    assert.equal(agent.reportArtifact.digest, sha(bytes)); assert.deepEqual(toAgentReport(report), agent);
    assert.equal(toMarkdown(report), await readFile(join(base, 'report.md'), 'utf8'));
    assert.deepEqual(toSarif(report), JSON.parse(await readFile(join(base, 'report.sarif'), 'utf8')));
    const comparison = compareReports(report, report);
    assert.equal(comparisonExitCode(comparison, 'high'), item.compareSelfExitCode);
  }
});

test('existing tools none, fail-on and source-max-files CLI semantics keep exits 0, 1 and 2', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-compat-cli-'));
  try {
    for (const item of manifest.cases) for (const failOn of ['high', 'none', 'critical']) {
      const out = join(top, item.id + '-' + failOn);
      const flags = ['scan', '--source', join(root, item.id, 'source'), '--tools', 'none',
        '--project-id', 'compat-0.5-' + item.id, '--out', out, '--fail-on', failOn];
      if (item.id === 'partial') flags.push('--source-max-files', '1');
      let code = 0;
      try { await exec(process.execPath, ['build/src/cli.js', ...flags]); }
      catch (error: any) { assert.equal(typeof error.code, 'number'); code = error.code; }
      assert.equal(code, item.id === 'partial' ? 2 : item.id === 'findings' && failOn === 'high' ? 1 : 0);
      assert.equal(JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8')).scanGate.exitCode, code);
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('all five historical check states retain their meaning, including error and not_applicable', async () => {
  const item = manifest.serializedStates, base = join(root, item.path);
  for (const [name, digest] of Object.entries(item.artifacts)) assert.equal(sha(await readFile(join(base, name))), digest);
  const report = await readScanReport(join(base, 'report.json'));
  assert.deepEqual(report.checks.map(check => check.status), item.states);
  assert.equal(evaluateGate(report, 'none').exitCode, 2);
  assert.deepEqual(toAgentReport(report), JSON.parse(await readFile(join(base, 'agent-report.json'), 'utf8')));
  assert.equal(toMarkdown(report), await readFile(join(base, 'report.md'), 'utf8'));
  assert.deepEqual(toSarif(report), JSON.parse(await readFile(join(base, 'report.sarif'), 'utf8')));
});

test('v1 plan retains strict data-only keys and raw input SHA binding shape without adding v2 authority', () => {
  const plan = { version: 1, kind: 'wakeio.execution-plan', origin: 'https://owned.invalid',
    tasks: [{ id: 't-owned', engine: 'native-dast', policy: 'policy', maxRequests: 8 }] };
  assert.deepEqual(parseExecutionPlan(plan), plan);
  for (const extra of [{ presetSha256: 'a'.repeat(64) }, { maxRequests: 20000 }, { database: 'run.db' }, { credential: 'synthetic-canary' }]) {
    assert.throws(() => parseExecutionPlan({ ...plan, ...extra }));
  }
  assert.throws(() => parseExecutionPlan({ ...plan, version: 2 }));
  const inputs = { version: 1, inputs: [{ id: 'policy', path: 'owner.json', sha256: 'a'.repeat(64) }] };
  assert.deepEqual(parseExecutionInputs(inputs), inputs);
});

test('source-only CLI never runs project lifecycle scripts or executable config files', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-no-target-code-'));
  try {
    const source = join(top, 'source'), marker = join(top, 'target-executed');
    await mkdir(source);
    const code = 'require("node:fs").writeFileSync(' + JSON.stringify(marker) + ', "executed");';
    await writeFile(join(source, 'next.config.js'), code);
    await writeFile(join(source, 'package.json'), JSON.stringify({ scripts: Object.fromEntries(
      ['preinstall', 'install', 'prepare', 'build', 'test'].map(name => [name, 'node -e ' + JSON.stringify(code)])) }));
    await exec(process.execPath, ['build/src/cli.js', 'scan', '--source', source, '--tools', 'none', '--out', join(top, 'reports'), '--fail-on', 'none']);
    await assert.rejects(readFile(marker), { code: 'ENOENT' });
  } finally { await rm(top, { recursive: true, force: true }); }
});
