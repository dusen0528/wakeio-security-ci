import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { normalizeGoBuildTags, parseGovulncheckOutput, runGovulncheck } from '../src/source/govulncheck.js';
import type { SourceSnapshot } from '../src/source/types.js';

function snapshot(): SourceSnapshot {
  return { root: '/fixture', files: [
    { path: 'go.mod', text: 'module example.test/app\ngo 1.23\n', bytes: 37, category: 'dependency', sensitive: false },
    { path: 'main.go', text: 'package main\nfunc main() {}\n', bytes: 28, category: 'code', sensitive: false },
  ], issues: [], ignoredFiles: 0, totalBytes: 65, complete: true };
}
function stream(...rest: unknown[]): string {
  return [{ config: { protocol_version: 'v1.0.0', scan_level: 'symbol', scan_mode: 'source', scanner_version: 'v1.1.4' } },
    { SBOM: { modules: [{ path: 'example.test/app' }, { path: 'example.test/dependency', version: 'v1.0.0' }], roots: ['example.test/app'] } }, ...rest].map(value => JSON.stringify(value, null, 2)).join('\n');
}
const osv = { osv: { id: 'GO-2024-1234', summary: 'PRIVATE_ADVISORY_PAYLOAD' } };
const moduleFinding = { finding: { osv: 'GO-2024-1234', fixed_version: 'v1.1.0', trace: [{ module: 'example.test/dependency', version: 'v1.0.0' }] } };
const calledFinding = { finding: { ...moduleFinding.finding, trace: [
  { module: 'example.test/dependency', version: 'v1.0.0', package: 'example.test/dependency', function: 'Vulnerable' },
  { module: 'example.test/app', package: 'example.test/app', function: 'main', position: { filename: 'main.go', line: 2, column: 1, offset: 13 } },
] } };

test('govulncheck streaming JSON deduplicates stages and retains static reachability without scanner text', () => {
  const result = parseGovulncheckOutput(stream(osv, moduleFinding, calledFinding, calledFinding), snapshot().files);
  assert.equal(result.status, 'completed');
  assert.equal(result.findings.length, 1);
  assert.equal(result.metrics?.reachableFindings, 1);
  assert.equal(result.findings[0]?.location.path, 'main.go');
  assert.equal(result.findings[0]?.location.line, 2);
  assert.equal(result.findings[0]?.severity, 'medium');
  assert.match(result.findings[0]!.remediation, /v1.1.0/);
  assert.equal(JSON.stringify(result).includes('PRIVATE_ADVISORY_PAYLOAD'), false);
});

test('govulncheck rejects malformed/truncated streams, absent inventory and unbound finding positions', () => {
  const badPosition = { finding: { ...calledFinding.finding, trace: [...calledFinding.finding.trace.slice(0, 1), { module: 'example.test/app', position: { filename: '../secret.go', line: 2 } }] } };
  for (const text of [stream().slice(0, -1), '{}', stream().replace('v1.0.0', 'v2.0.0'), stream(calledFinding), stream(osv, badPosition), stream({ error: { message: 'failure' } })]) {
    assert.throws(() => parseGovulncheckOutput(text, snapshot().files));
  }
});

test('govulncheck binds findings to the inventoried module version', () => {
  for (const frame of [{ module: 'unrelated.test/module', version: 'v1.0.0' }, { module: 'example.test/dependency', version: 'v9.0.0' }, { module: 'example.test/dependency' }]) {
    assert.throws(() => parseGovulncheckOutput(stream(osv, { finding: { ...moduleFinding.finding, trace: [frame] } }), snapshot().files), /unbound finding/);
  }
});

test('Go build tags are bounded names and invalid SDK build scope cannot launch an engine', async () => {
  assert.deepEqual(normalizeGoBuildTags(['release', 'go1.23', 'release']), ['go1.23', 'release']);
  for (const tags of [[''], ['release -ldflags=x'], ['../file'], ['tag\nINJECTED'], Array(33).fill('tag')]) {
    assert.throws(() => normalizeGoBuildTags(tags));
    assert.equal((await runGovulncheck({ snapshot: snapshot(), stageDir: '/unused', toolPath: '/never/run', buildTags: tags, timeoutMs: 1000 })).status, 'error');
  }
});

test('govulncheck binds its module inventory and unique package roots to the staged go.mod', () => {
  const withInventory = (modules: string[], roots: string[]) => [
    { config: { protocol_version: 'v1.0.0', scan_level: 'symbol', scan_mode: 'source' } },
    { SBOM: { modules: modules.map(path => ({ path })), roots } },
  ].map(message => JSON.stringify(message)).join('\n');
  for (const [modules, roots] of [
    [['unrelated.test/app'], ['unrelated.test/app']],
    [['unrelated.test/app'], ['example.test/app']],
    [['example.test/app'], ['unrelated.test/app']],
    [['example.test/app'], ['example.test/app-other']],
    [['example.test/app'], []],
    [['example.test/app'], ['example.test/app', 'example.test/app']],
    [['example.test/app', 'example.test/app'], ['example.test/app']],
    [['example.test/app'], ['example.test/app/../outside']],
  ]) assert.throws(() => parseGovulncheckOutput(withInventory(modules!, roots!), snapshot().files));
  const subpackages = parseGovulncheckOutput(withInventory(['example.test/app'], ['example.test/app/cmd/server', 'example.test/app/internal/handlers']), snapshot().files);
  assert.equal(subpackages.status, 'completed'); assert.equal(subpackages.metrics?.rootsAnalyzed, 2);
  for (const text of ['go 1.23\n', 'module example.test/app\nmodule another.test/app\n']) {
    const input = snapshot(); input.files[0]!.text = text;
    assert.throws(() => parseGovulncheckOutput(stream(), input.files));
  }
});

test('govulncheck refuses incomplete modules, nested modules and local replacements before execution', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-go-test-'));
  try {
    for (const change of ['incomplete', 'nested', 'replace']) {
      const input = snapshot();
      if (change === 'incomplete') input.complete = false;
      if (change === 'nested') input.files[0]!.path = 'nested/go.mod';
      if (change === 'replace') input.files[0]!.text += '\nreplace example.test/dependency => "../outside"\n';
      const result = await runGovulncheck({ snapshot: input, stageDir: root, toolPath: '/never/run', timeoutMs: 1000 });
      assert.equal(result.status, 'partial');
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('govulncheck accepts findings despite JSON exit zero, isolates Go env, and treats load failures as errors', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-go-adapter-'));
  try {
    const stage = join(top, 'stage'), home = join(top, 'tool'), moduleCache = join(top, 'modules');
    await Promise.all([stage, home, moduleCache].map(path => mkdir(path)));
    const receipt = join(top, 'receipt.json'), executable = join(home, 'govulncheck'), go = join(home, 'go');
    await writeFile(go, '#!/bin/sh\nexit 0\n'); await chmod(go, 0o755);
    await writeFile(executable, `#!${process.execPath}\nconst fs=require('node:fs'); fs.writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({argv:process.argv.slice(2), env:process.env})); process.stdout.write(${JSON.stringify(stream(osv, calledFinding))});\n`);
    await chmod(executable, 0o755);
    const result = await runGovulncheck({ snapshot: snapshot(), stageDir: stage, toolPath: executable, goPath: go, moduleCache: relative(process.cwd(), moduleCache), timeoutMs: 5000 });
    assert.equal(result.status, 'completed'); assert.equal(result.findings.length, 1);
    const captured = JSON.parse(await readFile(receipt, 'utf8'));
    assert.deepEqual(captured.argv, ['-json', '-mode', 'source', '-scan', 'symbol', './...']);
    assert.equal(captured.env.GOTOOLCHAIN, 'local'); assert.equal(captured.env.GOPROXY, 'off');
    assert.equal(captured.env.GOFLAGS, '-mod=readonly'); assert.equal(captured.env.GOWORK, 'off');
    assert.equal(captured.env.GOMODCACHE, moduleCache); assert.equal(captured.env.CGO_ENABLED, '0');
    assert.equal(captured.env.PATH.split(':')[0], home);
    const scoped = await runGovulncheck({ snapshot: snapshot(), stageDir: stage, toolPath: executable, goPath: go, buildTags: ['release', 'feature', 'release'], timeoutMs: 5000 });
    const scopedArgs = JSON.parse(await readFile(receipt, 'utf8')).argv;
    assert.deepEqual(scopedArgs, ['-json', '-mode', 'source', '-scan', 'symbol', '-tags', 'feature,release', './...']);
    assert.equal(scoped.metrics?.buildTags, 'feature,release'); assert.equal(scoped.metrics?.testPackages, false);
    await writeFile(executable, `#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(stream())}); process.exit(1);\n`);
    assert.equal((await runGovulncheck({ snapshot: snapshot(), stageDir: stage, toolPath: executable, goPath: go, timeoutMs: 5000 })).status, 'error');
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('real govulncheck distinguishes an affected Go call from its fixed dependency and a clean module', {
  skip: !process.env.WAKEIO_GOVULNCHECK_EXECUTABLE && process.env.WAKEIO_REQUIRE_GOVULNCHECK !== '1',
}, async () => {
  const toolPath = process.env.WAKEIO_GOVULNCHECK_EXECUTABLE, goPath = process.env.WAKEIO_GO_EXECUTABLE, moduleCache = process.env.WAKEIO_GO_MODULE_CACHE;
  assert.ok(toolPath && goPath && moduleCache, 'Supply the prepared govulncheck, Go executable and module cache; the test never downloads dependencies.');
  const root = await mkdtemp(join(tmpdir(), 'wakeio-real-go-'));
  try {
    for (const [version, affected] of [['v0.3.6', true], ['v0.3.7', false], ['', false]] as const) {
      const input = snapshot();
      input.files[0]!.text = `module example.test/app\ngo 1.23\n${version ? `require golang.org/x/text ${version}\n` : ''}`;
      input.files[1]!.text = version ? 'package main\nimport "golang.org/x/text/language"\nfunc main() { _, _ = language.Parse("en") }\n' : 'package main\nfunc main() {}\n';
      if (!version) input.files[1]!.path = 'cmd/server/main.go';
      if (version) {
        const sums = version === 'v0.3.6'
          ? 'golang.org/x/text v0.3.6 h1:aRYxNxv6iGQlyVaZmk6ZgYEDa+Jg18DxebPSrd6bg1M=\ngolang.org/x/text v0.3.6/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=\n'
          : 'golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=\ngolang.org/x/text v0.3.7/go.mod h1:u+2+/6zg+i71rQMx5EYifcz6MCKuco9NR6JIITiCfzQ=\n';
        input.files.push({ path: 'go.sum', category: 'dependency', sensitive: false, bytes: sums.length, text: sums });
      }
      const result = await runGovulncheck({ snapshot: input, stageDir: root, toolPath, goPath, moduleCache, timeoutMs: 120_000 });
      assert.equal(result.status, 'completed', result.notes.join(' '));
      assert.equal(result.findings.some(finding => finding.ruleId === 'govulncheck:GO-2021-0113'), affected);
      if (affected) assert.ok(Number(result.metrics?.reachableFindings) > 0);
      if (affected) {
        const scoped = structuredClone(input);
        scoped.files[1]!.text = 'package main\nfunc main() {}\n';
        const text = '//go:build feature\n\npackage main\nimport "golang.org/x/text/language"\nfunc init() { _, _ = language.Parse("en") }\n';
        scoped.files.push({ path: 'feature.go', category: 'code', sensitive: false, bytes: Buffer.byteLength(text), text });
        const defaultScope = await runGovulncheck({ snapshot: scoped, stageDir: root, toolPath, goPath, moduleCache, timeoutMs: 120_000 });
        assert.equal(defaultScope.status, 'completed', defaultScope.notes.join(' '));
        assert.equal(defaultScope.metrics?.reachableFindings, 0);
        const enabled = await runGovulncheck({ snapshot: scoped, stageDir: root, toolPath, goPath, moduleCache, buildTags: ['feature'], timeoutMs: 120_000 });
        assert.equal(enabled.status, 'completed', enabled.notes.join(' '));
        assert.ok(Number(enabled.metrics?.reachableFindings) > 0, JSON.stringify(enabled));
      }
      if (!version) assert.equal(result.findings.length, 0);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});
