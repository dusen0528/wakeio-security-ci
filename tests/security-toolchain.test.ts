import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main, parseCliArgs } from '../src/cli.js';
import { readScanReport } from '../src/compare.js';
import { runProcess } from '../src/source/process.js';

async function workspace(t: TestContext) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-toolchain-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'), out = join(top, 'reports');
  await mkdir(source);
  return { top, source, out };
}
async function executable(path: string, program: string) {
  await writeFile(path, `#!${process.execPath}\n${program}\n`, { mode: 0o700 });
  await chmod(path, 0o700);
  return path;
}

test('toolchain selection preserves defaults and refuses dependent options without their target', () => {
  const defaults = parseCliArgs(['scan', '--source', '.']);
  assert.ok(!('help' in defaults));
  assert.deepEqual(defaults.tools, ['gitleaks', 'osv', 'trivy']);
  const selected = parseCliArgs(['scan', '--source', '.', '--tools', 'semgrep,govulncheck,trivy-vuln', '--go-module-cache', '/prepared/modules', '--trivy-offline']);
  assert.ok(!('help' in selected));
  assert.deepEqual(selected.tools, ['semgrep', 'govulncheck', 'trivy-vuln']);
  assert.equal(selected.trivyOffline, true);
  for (const args of [
    ['--go', '/go'], ['--go-module-cache', '/cache'], ['--govuln-db', 'file:///db'], ['--go-build-tags', 'release'],
    ['--trivy-cache', '/cache'], ['--trivy-offline'], ['--zap', '/zap.sh'],
  ]) assert.throws(() => parseCliArgs(['scan', '--source', '.', '--tools', 'none', ...args]));
  const scope = parseCliArgs(['scan', '--source', '.', '--tools', 'govulncheck', '--go-build-tags', 'release,feature,release']);
  assert.ok(!('help' in scope)); assert.deepEqual(scope.goBuildTags, ['feature', 'release']);
  for (const value of ['', 'release,,feature', 'release -ldflags=x']) assert.throws(() => parseCliArgs(['scan', '--source', '.', '--tools', 'govulncheck', '--go-build-tags', value]));
  for (const args of [
    ['--url', 'http://example.test', '--engine', 'zap', '--zap-path', '/search?q=test'],
    ['--url', 'https://example.test', '--engine', 'zap', '--zap-path', '/search?q=test', '--active-consent'],
    ['--url', 'http://example.test', '--engine', 'zap', '--active-consent'],
    ['--url', 'http://example.test', '--engine', 'zap', '--zap-path', '//other.test/q', '--active-consent'],
    ['--url', 'http://example.test', '--engine', 'zap', '--zap-path', '/q?a=1', '--zap-max-requests', '2001', '--active-consent'],
    ['--url', 'http://example.test', '--engine', 'zap', '--zap-path', '/q?a=1', '--page', 'http://example.test/other', '--active-consent'],
    ['--url', 'http://example.test', '--engine', 'zap', '--zap-path', '/q?a=1', '--max-pages', '2', '--active-consent'],
  ]) assert.throws(() => parseCliArgs(['scan', ...args]));
});

test('Semgrep completion reaches all report formats and missing engine remains exit 2', async t => {
  const w = await workspace(t);
  await writeFile(join(w.source, 'app.go'), 'package app\nfunc ready() {}\n');
  const scanner = await executable(join(w.top, 'semgrep'), `const files=process.argv.slice(process.argv.indexOf('--')+1);process.stdout.write(JSON.stringify({version:'1.147.0',results:[],errors:[],paths:{scanned:files},skipped_rules:[]}));`);
  const args = ['scan', '--source', w.source, '--tools', 'semgrep', '--require-code-analysis', '--out', w.out];
  assert.equal(await main([...args, '--semgrep', scanner]), 0);
  const report = await readScanReport(join(w.out, 'report.json'));
  assert.equal(report.checks.find(check => check.id === 'source.code-coverage')?.codeCoverage?.totals.completed, 1);
  assert.equal(report.checks.find(check => check.id === 'source.code-coverage')?.codeCoverage?.totals.uncovered, 0);
  assert.equal(report.scope?.provenance?.dataSources?.semgrepRuntime, 'unknown');
  for (const name of ['report.sarif', 'report.md', 'agent-report.json']) assert.ok((await readFile(join(w.out, name))).length);
  assert.equal(await main([...args, '--semgrep', join(w.top, 'missing'), '--fail-on', 'none']), 2);
  const missing = JSON.parse(await readFile(join(w.out, 'report.json'), 'utf8'));
  assert.equal(missing.checks.find((check: { id: string }) => check.id === 'source.semgrep').status, 'partial');
});

test('Go advisory output with engine exit zero is retained but cannot satisfy code-analysis coverage', async t => {
  const w = await workspace(t);
  await writeFile(join(w.source, 'go.mod'), 'module example.test/app\n\ngo 1.24\n');
  await writeFile(join(w.source, 'app.go'), 'package app\nfunc ready() {}\n');
  const stream = [
    { config: { protocol_version: 'v1.0.0', scan_level: 'symbol', scan_mode: 'source' } },
    { SBOM: { roots: ['example.test/app'], modules: [{ path: 'example.test/app' }, { path: 'example.test/library', version: 'v1.0.0' }] } },
    { osv: { id: 'GO-2024-1234' } },
    { finding: { osv: 'GO-2024-1234', fixed_version: 'v1.2.3', trace: [{ module: 'example.test/library', version: 'v1.0.0', package: 'example.test/library', function: 'Unsafe' }] } },
  ].map(value => JSON.stringify(value)).join('\n');
  const scanner = await executable(join(w.top, 'govulncheck'), `process.stdout.write(${JSON.stringify(stream)});`);
  assert.equal(await main(['scan', '--source', w.source, '--tools', 'govulncheck', '--govulncheck', scanner, '--go', process.execPath, '--require-code-analysis', '--fail-on', 'none', '--out', w.out]), 2);
  const report = await readScanReport(join(w.out, 'report.json'));
  assert.equal(report.checks.find(check => check.id === 'source.govulncheck')?.findings.length, 1);
  assert.equal(report.checks.find(check => check.id === 'source.code-coverage')?.codeCoverage?.totals.completed, 0);
});

test('Go runtime additions are explicit fixed settings and never forward caller credentials or proxies', async t => {
  const w = await workspace(t);
  const result = await runProcess(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(process.env))'], {
    cwd: w.top, home: w.top, timeoutMs: 2000, runtimePath: '/prepared/go/bin',
    environment: { GOTOOLCHAIN: 'local', GOPROXY: 'off', GOWORK: 'off', GOFLAGS: '-mod=readonly', GOCACHE: '/prepared/build',
      GOMODCACHE: 'relative/path', HTTPS_PROXY: 'http://must-not-forward.test', ANTHROPIC_API_KEY: 'must-not-forward', NODE_OPTIONS: '--inspect' },
  });
  assert.equal(result.exitCode, 0);
  const env = JSON.parse(result.stdout);
  assert.equal(env.GOTOOLCHAIN, 'local'); assert.equal(env.GOPROXY, 'off');
  assert.equal(env.GOFLAGS, '-mod=readonly'); assert.equal(env.GOCACHE, '/prepared/build');
  assert.ok(env.PATH.startsWith('/prepared/go/bin:'));
  for (const key of ['GOMODCACHE', 'HTTPS_PROXY', 'ANTHROPIC_API_KEY', 'NODE_OPTIONS']) assert.equal(env[key], undefined);
});
