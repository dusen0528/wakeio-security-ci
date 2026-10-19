import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseTrivyVulnerabilityOutput, runTrivyVulnerabilities } from '../src/trivy-vuln.js';
import type { SourceSnapshot } from '../src/source/types.js';

const vulnerability = { VulnerabilityID: 'CVE-2024-12345', PkgName: 'example', InstalledVersion: '1.0.0', FixedVersion: '1.0.1', Severity: 'HIGH', Description: 'PRIVATE_RAW_ADVISORY' };
function report(image = false): Record<string, unknown> {
  return { SchemaVersion: 2, ArtifactType: image ? 'container_image' : 'filesystem', Results: [
    { Target: image ? 'PRIVATE_IMAGE_NAME (alpine 3.18)' : 'package-lock.json', Class: image ? 'os-pkgs' : 'lang-pkgs', Type: image ? 'alpine' : 'npm', Packages: [{ Name: 'example', Version: '1.0.0' }], Vulnerabilities: [vulnerability, vulnerability] },
  ] };
}
function snapshot(): SourceSnapshot {
  return { root: '/fixture', files: [{ path: 'package-lock.json', text: '{}', bytes: 2, category: 'dependency', sensitive: false }], issues: [], ignoredFiles: 0, totalBytes: 2, complete: true };
}

test('Trivy package CVEs deduplicate and retain package/fix guidance without raw descriptions', () => {
  const parsed = parseTrivyVulnerabilityOutput(JSON.stringify(report()), { stageDir: '/stage', allowedPaths: ['package-lock.json'] });
  assert.equal(parsed.status, 'completed'); assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0]?.severity, 'high'); assert.match(parsed.findings[0]!.remediation, /1.0.1/);
  assert.equal(JSON.stringify(parsed).includes('PRIVATE_RAW_ADVISORY'), false);
  const image = parseTrivyVulnerabilityOutput(JSON.stringify(report(true)), { image: true });
  assert.equal(image.findings[0]?.location.path, 'image/os-pkgs/alpine');
  assert.equal(JSON.stringify(image).includes('PRIVATE_IMAGE_NAME'), false);
});

test('Trivy rejects malformed, wrong-lane and unbound vulnerability inventories', () => {
  const options = { stageDir: '/stage', allowedPaths: ['package-lock.json'] };
  const outside = JSON.stringify(report()).replace('package-lock.json', '../private.json');
  const noInventory = JSON.stringify(report()).replace('"Packages":[{"Name":"example","Version":"1.0.0"}],', '');
  const wrongPackage = JSON.stringify(report()).replace('"Name":"example"', '"Name":"different"');
  for (const text of ['{}', JSON.stringify(report(true)), outside, noInventory, wrongPackage, JSON.stringify(report()).replace('"HIGH"', '"UNKNOWN_SCORE"')]) {
    assert.throws(() => parseTrivyVulnerabilityOutput(text, options));
  }
  assert.equal(parseTrivyVulnerabilityOutput(JSON.stringify({ SchemaVersion: 2, ArtifactType: 'filesystem', Results: [] }), options).status, 'partial');
  assert.equal(parseTrivyVulnerabilityOutput(JSON.stringify(report()), { ...options, allowedPaths: ['package-lock.json', 'requirements.txt'] }).status, 'partial');
});

test('Trivy accepts an unversioned root Go module while requiring versions for affected dependencies', () => {
  const rootPackage = { Name: 'example.test/app', Relationship: 'root', DependsOn: ['golang.org/x/text@v0.3.6'] };
  const dependency = { Name: 'golang.org/x/text', Version: 'v0.3.6', Relationship: 'direct' };
  const goReport = { SchemaVersion: 2, ArtifactType: 'filesystem', Results: [{ Target: 'go.mod', Class: 'lang-pkgs', Type: 'gomod',
    Packages: [rootPackage, dependency], Vulnerabilities: [{ VulnerabilityID: 'CVE-2021-38561', PkgName: dependency.Name, InstalledVersion: dependency.Version, FixedVersion: '0.3.7', Severity: 'HIGH' }] }] };
  const options = { stageDir: '/stage', allowedPaths: ['go.mod', 'go.sum'] };
  const parsed = parseTrivyVulnerabilityOutput(JSON.stringify(goReport), options);
  assert.equal(parsed.status, 'completed'); assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.metrics?.packages, 2); assert.equal(parsed.metrics?.unreportedInputs, 0);
  assert.equal(parsed.findings[0]?.location.path, 'go.mod');
  const invalid = structuredClone(goReport); invalid.Results[0]!.Packages[0]!.Relationship = 'direct';
  assert.throws(() => parseTrivyVulnerabilityOutput(JSON.stringify(invalid), options));
  const unbound = structuredClone(goReport); unbound.Results[0]!.Vulnerabilities[0]!.PkgName = rootPackage.Name;
  assert.throws(() => parseTrivyVulnerabilityOutput(JSON.stringify(unbound), options));
});

test('Trivy CVE adapter uses neutral config, no remote resolution and explicit image archive only', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-trivy-test-'));
  try {
    const stage = join(top, 'stage'); await mkdir(stage);
    const executable = join(top, 'trivy'), receipt = join(top, 'receipt.json');
    await writeFile(executable, `#!${process.execPath}\nconst fs=require('node:fs'); const args=process.argv.slice(2); fs.writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({args,config:fs.readFileSync(args[args.indexOf('--config')+1],'utf8'),ignore:fs.readFileSync(args[args.indexOf('--ignorefile')+1],'utf8')})); process.stdout.write(JSON.stringify(args[0]==='image'?${JSON.stringify(report(true))}:${JSON.stringify(report())}));\n`);
    await chmod(executable, 0o755);
    const result = await runTrivyVulnerabilities({ snapshot: snapshot(), stageDir: stage, toolPath: executable, timeoutMs: 5000, offline: true });
    assert.equal(result.status, 'completed'); assert.equal(result.findings.length, 1);
    const captured = JSON.parse(await readFile(receipt, 'utf8'));
    assert.equal(captured.args[0], 'fs'); assert.ok(captured.args.includes('--skip-db-update')); assert.ok(captured.args.includes('--offline-scan'));
    assert.equal(captured.config, '{}\n'); assert.equal(captured.ignore, '');
    const archive = join(top, 'fixture.tar'); await writeFile(archive, 'test archive');
    const image = await runTrivyVulnerabilities({ imageArchive: archive, toolPath: executable, timeoutMs: 5000 });
    assert.equal(image.id, 'image.trivy'); assert.equal(image.status, 'completed');
    const imageArgs = JSON.parse(await readFile(receipt, 'utf8')).args;
    assert.equal(imageArgs[0], 'image'); assert.equal(imageArgs[imageArgs.indexOf('--input') + 1], archive);
    assert.equal((await runTrivyVulnerabilities({ snapshot: snapshot(), stageDir: stage, imageArchive: archive, toolPath: executable, timeoutMs: 5000 })).status, 'error');
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('Trivy selected but missing or failed tools cannot become clean scans', async () => {
  assert.equal((await runTrivyVulnerabilities({ snapshot: snapshot(), stageDir: '/stage', toolPath: '', timeoutMs: 1000 })).status, 'partial');
  const empty = snapshot(); empty.files = [];
  assert.equal((await runTrivyVulnerabilities({ snapshot: empty, stageDir: '/stage', toolPath: '', timeoutMs: 1000 })).status, 'not_applicable');
  assert.equal((await runTrivyVulnerabilities({ snapshot: snapshot(), stageDir: '/stage', toolPath: '/nonexistent-trivy', timeoutMs: 1000 })).status, 'error');
});

test('real Trivy detects a known package CVE, accepts a clean inventory, and reads an image without running it', {
  skip: !process.env.WAKEIO_TRIVY_EXECUTABLE && process.env.WAKEIO_REQUIRE_TRIVY_VULN !== '1',
}, async () => {
  const toolPath = process.env.WAKEIO_TRIVY_EXECUTABLE, cacheDir = process.env.WAKEIO_TRIVY_CACHE, imageArchive = process.env.WAKEIO_TRIVY_IMAGE_ARCHIVE;
  assert.ok(toolPath && cacheDir && imageArchive, 'Supply Trivy, its prepared database cache, and an Alpine 3.18.0 Docker/OCI tar archive.');
  const root = await mkdtemp(join(tmpdir(), 'wakeio-real-trivy-'));
  try {
    for (const [name, version, affected] of [['lodash', '4.17.20', true], ['picocolors', '1.1.1', false]] as const) {
      const input = snapshot();
      input.files[0]!.text = JSON.stringify({ name: 'fixture', version: '1.0.0', lockfileVersion: 2, requires: true,
        packages: { '': { name: 'fixture', version: '1.0.0', dependencies: { [name]: version } }, [`node_modules/${name}`]: { version } }, dependencies: { [name]: { version } } });
      const result = await runTrivyVulnerabilities({ snapshot: input, stageDir: root, toolPath, cacheDir, offline: true, timeoutMs: 120_000 });
      assert.equal(result.status, 'completed', result.notes.join(' '));
      if (affected) assert.ok(result.findings.some(finding => finding.ruleId === 'trivy-vuln:CVE-2021-23337'));
      else assert.equal(result.findings.length, 0);
    }
    const goInput = snapshot();
    goInput.files = [{ path: 'go.mod', category: 'dependency', sensitive: false, bytes: 81,
      text: 'module example.test/app\ngo 1.23\nrequire golang.org/x/text v0.3.6\n' }];
    const go = await runTrivyVulnerabilities({ snapshot: goInput, stageDir: root, toolPath, cacheDir, offline: true, timeoutMs: 120_000 });
    assert.equal(go.status, 'completed', go.notes.join(' '));
    assert.ok(go.findings.some(finding => finding.ruleId === 'trivy-vuln:CVE-2021-38561'));
    const image = await runTrivyVulnerabilities({ imageArchive, toolPath, cacheDir, offline: true, timeoutMs: 120_000 });
    assert.equal(image.status, 'completed', image.notes.join(' '));
    assert.ok(Number(image.metrics?.packages) > 0);
    assert.ok(image.findings.some(finding => finding.location.path === 'image/os-pkgs/alpine'));
  } finally { await rm(root, { recursive: true, force: true }); }
});
