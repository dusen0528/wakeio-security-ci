import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, mkdtemp, mkdir, readFile, readdir, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const exec = promisify(execFile), cli = process.env.WAKEIO_TEST_DOCTOR_CLI ?? resolve('build/src/cli.js');
async function fixture(t: TestContext, files: Record<string, string>) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-doctor-readiness-')), source = join(top, 'source');
  t.after(() => rm(top, { recursive: true, force: true })); await mkdir(source);
  for (const [name, value] of Object.entries(files)) await writeFile(join(source, name), value);
  return { top, source };
}
async function doctor(source: string, flags: string[] = [], env: NodeJS.ProcessEnv = process.env) {
  const args = [cli, 'doctor', '--source', source, ...(flags.includes('--tools') ? [] : ['--tools', 'none']), '--json', ...flags];
  try { const result = await exec(process.execPath, args, { env, timeout: 15_000 }); return { code: 0, data: JSON.parse(result.stdout) }; }
  catch (error) { const e = error as { code: number; stdout: string; stderr: string }; return { code: e.code, data: JSON.parse(e.stdout) }; }
}
function metadataOnly(data: any) {
  assert.deepEqual(data.execution, { targetCode: 'none', network: 'none', packageManager: 'none' });
  assert.equal(data.codeAnalysisReadiness.basis, 'metadata_estimate_not_collector_coverage');
  for (const forbidden of ['completed', 'eligible', 'collected']) assert.equal(Object.hasOwn(data.codeAnalysisReadiness, forbidden), false);
  for (const row of data.codeAnalysisReadiness.languages) for (const forbidden of ['completed', 'eligible', 'collected']) assert.equal(Object.hasOwn(row, forbidden), false);
}

for (const [filename, language] of [['app.py', 'python'], ['App.java', 'java']] as const) {
  test(`doctor strict required code analysis blocks unsupported selected provider for ${language}`, async t => {
    const f = await fixture(t, { [filename]: 'OWNED_DATA_ONLY_DO_NOT_EXECUTE' });
    const loose = await doctor(f.source, ['--require-code-analysis']); assert.equal(loose.code, 0);
    const result = await doctor(f.source, ['--strict', '--require-code-analysis']); assert.equal(result.code, 2);
    metadataOnly(result.data); assert.equal(result.data.codeAnalysisReadiness.state, 'blocked');
    assert.deepEqual(result.data.codeAnalysisReadiness.languages, [{ language, observedFiles: 1, selectedProviders: [] }]);
    assert.equal(await readFile(join(f.source, filename), 'utf8'), 'OWNED_DATA_ONLY_DO_NOT_EXECUTE');
    assert.deepEqual(await readdir(f.source), [filename]);
  });
}

test('doctor JS metadata reports provider readiness without claiming completed analysis', async t => {
  const f = await fixture(t, { 'app.js': 'throw new Error("must never execute");', '.env.py': 'classified as private data, not Python code' });
  const result = await doctor(f.source, ['--strict', '--require-code-analysis']); assert.equal(result.code, 0);
  metadataOnly(result.data); assert.equal(result.data.codeAnalysisReadiness.state, 'ready');
  assert.deepEqual(result.data.codeAnalysisReadiness.languages, [{ language: 'javascript', observedFiles: 1, selectedProviders: ['builtin_ast'] }]);
});

test('doctor missing code inputs never claim required analysis readiness', async t => {
  const cases: Record<string, string>[] = [{}, { 'blob.unknown-extension': 'outside allowlist' }];
  for (const files of cases) {
    const f = await fixture(t, files), result = await doctor(f.source, ['--strict', '--require-code-analysis']);
    assert.equal(result.code, 2); metadataOnly(result.data);
    assert.equal(result.data.codeAnalysisReadiness.state, 'blocked'); assert.deepEqual(result.data.codeAnalysisReadiness.languages, []);
  }
});

test('doctor metadata budgets and links stay unknown, even with an observed JS input', async t => {
  const limited = await fixture(t, { 'a.js': 'data', 'b.js': 'data' });
  const result = await doctor(limited.source, ['--strict', '--require-code-analysis', '--source-max-files', '1']);
  assert.equal(result.code, 2); metadataOnly(result.data); assert.equal(result.data.codeAnalysisReadiness.state, 'unknown');
  const linked = await fixture(t, { 'app.js': 'data' }); await symlink(join(linked.source, 'app.js'), join(linked.source, 'linked.js'));
  const unknown = await doctor(linked.source, ['--strict', '--require-code-analysis']);
  assert.equal(unknown.code, 2); assert.equal(unknown.data.codeAnalysisReadiness.state, 'unknown');
});

test('doctor prepared Bandit is metadata only and never runs the executable', async t => {
  const f = await fixture(t, { 'app.py': 'OWNED_SOURCE_MARKER' }), bin = join(f.top, 'bin'), marker = join(f.top, 'executed');
  await mkdir(bin); const bandit = join(bin, 'bandit');
  await writeFile(bandit, `#!/bin/sh\nprintf executed > '${marker}'\nexit 97\n`); await chmod(bandit, 0o700);
  const result = await doctor(f.source, ['--tools', 'bandit', '--strict', '--require-code-analysis'], { ...process.env, PATH: bin });
  assert.equal(result.code, 0); metadataOnly(result.data); assert.equal(result.data.codeAnalysisReadiness.state, 'ready');
  assert.deepEqual(result.data.codeAnalysisReadiness.languages, [{ language: 'python', observedFiles: 1, selectedProviders: ['bandit'] }]);
  await assert.rejects(readFile(marker), { code: 'ENOENT' });
});

test('doctor readiness follows collector exclusions before counting languages or byte budgets', async t => {
  const f = await fixture(t, { 'app.js': 'data', 'report.json': '', 'opaque.unknown-extension': '' });
  for (const directory of ['.next', '.nuxt', 'node_modules', 'build', 'VENDOR']) {
    await mkdir(join(f.source, directory)); await writeFile(join(f.source, directory, 'App.java'), 'outside collector');
  }
  await truncate(join(f.source, 'report.json'), 3 * 1024 * 1024);
  await truncate(join(f.source, 'opaque.unknown-extension'), 3 * 1024 * 1024);
  const result = await doctor(f.source, ['--strict', '--require-code-analysis', '--source-max-files', '1', '--source-max-bytes', '4']);
  assert.equal(result.code, 0); metadataOnly(result.data); assert.equal(result.data.codeAnalysisReadiness.state, 'ready');
  assert.deepEqual(result.data.codeAnalysisReadiness.languages, [{ language: 'javascript', observedFiles: 1, selectedProviders: ['builtin_ast'] }]);
});

test('doctor supported input over byte or per-file bound cannot claim readiness', async t => {
  const total = await fixture(t, { 'app.js': '12345' });
  const result = await doctor(total.source, ['--strict', '--require-code-analysis', '--source-max-bytes', '4']);
  assert.equal(result.code, 2); metadataOnly(result.data); assert.equal(result.data.codeAnalysisReadiness.state, 'unknown');
  const single = await fixture(t, { 'app.js': '' }); await truncate(join(single.source, 'app.js'), 2 * 1024 * 1024 + 1);
  const capped = await doctor(single.source, ['--strict', '--require-code-analysis']);
  assert.equal(capped.code, 2); metadataOnly(capped.data); assert.equal(capped.data.codeAnalysisReadiness.state, 'unknown');
});

test('doctor directory depth bound retains unknown even with ready code near root', async t => {
  const f = await fixture(t, { 'app.js': 'data' });
  const deep = join(f.source, ...Array.from({ length: 66 }, () => 'd'));
  await mkdir(deep, { recursive: true }); await writeFile(join(deep, 'App.java'), 'not reached within collector depth');
  const result = await doctor(f.source, ['--strict', '--require-code-analysis']);
  assert.equal(result.code, 2); metadataOnly(result.data); assert.equal(result.data.codeAnalysisReadiness.state, 'unknown');
});

test('doctor optional Go and CVE engines do not block an unrelated JavaScript project', async t => {
  const f = await fixture(t, { 'app.js': 'OWNED_DATA_ONLY' });
  const result = await doctor(f.source, ['--tools', 'semgrep,govulncheck,trivy-vuln', '--strict']);
  assert.equal(result.code, 0); metadataOnly(result.data);
  assert.deepEqual(result.data.tools, ['semgrep', 'govulncheck', 'trivy-vuln'].map(name => ({ name, applicability: 'not_applicable', availability: 'not_applicable' })));
  assert.deepEqual(result.data.expectedTransfers, []); assert.deepEqual(result.data.runtimeNetwork, []);
  assert.equal(result.data.inventory.goFiles, 0); assert.equal(result.data.inventory.goModules, 0); assert.equal(result.data.inventory.trivyVulnerabilityManifests, 0);
});

test('doctor uses actual Go and Trivy filenames and collector exclusions for applicability', async t => {
  const f = await fixture(t, { 'app.js': 'data', '.env.go': 'private', 'GO.MOD': 'unsupported case', 'cargo.lock': 'unsupported case', 'package.json': '{}', 'requirements-extra.txt': 'not in collector or Trivy allowlist' });
  await mkdir(join(f.source, 'vendor')); await writeFile(join(f.source, 'vendor', 'main.go'), 'ignored');
  const result = await doctor(f.source, ['--tools', 'semgrep,govulncheck,trivy-vuln', '--strict']);
  assert.equal(result.code, 0);
  assert.ok(result.data.tools.every((tool: any) => tool.applicability === 'not_applicable'));
  assert.deepEqual(result.data.runtimeNetwork, []);
});

test('doctor recognizes native uv and named requirements without executing Trivy', async t => {
  const f = await fixture(t, { 'uv.lock': 'OWNED_METADATA_ONLY', 'requirements-dev.txt': 'OWNED_METADATA_ONLY', 'requirements-prod.txt': 'OWNED_METADATA_ONLY' });
  const bin = join(f.top, 'bin'), marker = join(f.top, 'executed'); await mkdir(bin);
  const executable = join(bin, 'trivy'); await writeFile(executable, `#!/bin/sh\nprintf executed > '${marker}'\nexit 97\n`); await chmod(executable, 0o700);
  const result = await doctor(f.source, ['--tools', 'trivy-vuln', '--strict'], { ...process.env, PATH: bin });
  assert.equal(result.code, 0); metadataOnly(result.data);
  assert.equal(result.data.inventory.trivyVulnerabilityManifests, 3);
  assert.equal(result.data.tools[0].applicability, 'applicable'); assert.equal(result.data.tools[0].availability, 'available');
  await assert.rejects(readFile(marker), { code: 'ENOENT' });
});

test('doctor observes supported Go inputs without executing tools or claiming Go runtime readiness', async t => {
  const f = await fixture(t, { 'main.go': 'OWNED_DATA_ONLY', 'go.mod': 'module example.test/app\ngo 1.23\n', 'package-lock.json': '{}' });
  const bin = join(f.top, 'bin'), marker = join(f.top, 'executed'); await mkdir(bin);
  for (const name of ['semgrep', 'govulncheck', 'trivy']) { const file = join(bin, name); await writeFile(file, `#!/bin/sh\nprintf executed > '${marker}'\nexit 97\n`); await chmod(file, 0o700); }
  const result = await doctor(f.source, ['--tools', 'semgrep,govulncheck,trivy-vuln', '--strict', '--require-code-analysis'], { ...process.env, PATH: bin });
  assert.equal(result.code, 0); metadataOnly(result.data);
  assert.ok(result.data.tools.every((tool: any) => tool.applicability === 'applicable' && tool.availability === 'available'));
  assert.equal(result.data.inventory.goFiles, 1); assert.equal(result.data.inventory.goModules, 1); assert.equal(result.data.inventory.trivyVulnerabilityManifests, 2);
  assert.equal(result.data.runtimeNetwork.length, 2);
  assert.ok(result.data.codeAnalysisReadiness.limitations.some((note: string) => /does not verify the Go toolchain/.test(note)));
  await assert.rejects(readFile(marker), { code: 'ENOENT' });
});

test('doctor cannot infer inapplicability when the bounded metadata walk stops early', async t => {
  const f = await fixture(t, { 'a.js': 'data', 'go.mod': 'module example.test/app\n', 'z.go': 'data' });
  const result = await doctor(f.source, ['--tools', 'semgrep,govulncheck,trivy-vuln', '--source-max-files', '1', '--strict']);
  assert.equal(result.code, 2); metadataOnly(result.data);
  assert.ok(result.data.tools.every((tool: any) => tool.applicability === 'unknown'));
  assert.deepEqual(result.data.runtimeNetwork, []);
});
