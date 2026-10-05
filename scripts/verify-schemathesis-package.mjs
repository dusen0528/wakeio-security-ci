// Local delivery check only. Installs the specified tarball offline, never publishes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const archive = resolve(process.argv[2]);
const python = process.env.WAKEIO_SCHEMATHESIS_PYTHON;
assert.ok(python, 'WAKEIO_SCHEMATHESIS_PYTHON is required');
const consumer = await mkdtemp(join(tmpdir(), 'wakeio-schemathesis-consumer-'));
const outputDirectory = resolve('artifacts/schemathesis-installed');
await mkdir(outputDirectory, { recursive: true });
try {
  await writeFile(join(consumer, 'package.json'), '{"name":"fixture-consumer","private":true,"type":"module"}\n');
  const install = spawnSync('npm', ['install', '--ignore-scripts', '--offline', '--no-audit', '--fund=false', archive],
    { cwd: consumer, encoding: 'utf8' });
  assert.equal(install.status, 0, install.stderr);
  const root = join(consumer, 'node_modules/wakeio-security-ci');
  const { runSchemathesisFixture, pythonFixtureWorker, localArtifactStorage } =
    await import(pathToFileURL(join(root, 'build/src/index.js')).href);
  const results = [];
  for (const fixture of ['broken', 'fixed']) {
    const result = await runSchemathesisFixture({ environment: 'staging', fixture, operations: ['readItems'],
      maxRequests: 3, seed: 1, timeoutMs: 30000,
      worker: pythonFixtureWorker(python), storage: localArtifactStorage(outputDirectory) });
    assert.equal(result.artifact.status, 'completed');
    assert.equal(result.artifact.requestCount, 3);
    const failures = result.artifact.records.filter(r => r.check === 'response_contract').length;
    assert.equal(failures, fixture === 'broken' ? 3 : 0);
    const bytes = await readFile(result.artifactRef);
    assert.ok(!bytes.includes(Buffer.from('synthetic-secret-canary')));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), result.sha256);
    for (const [field, file] of [['workerSha256', 'worker.py'], ['schemaSha256', 'openapi.json'], ['dependencyLockSha256', 'requirements.lock.txt']]) {
      assert.equal(result.artifact[field], createHash('sha256').update(await readFile(join(root, 'workers/schemathesis', file))).digest('hex'));
    }
    results.push({ fixture, failures, artifactRef: result.artifactRef, sha256: result.sha256,
      runtime: result.artifact.runtime, engineVersion: result.artifact.engineVersion });
  }
  const summary = { node: process.versions.node, archiveSha256: createHash('sha256').update(await readFile(archive)).digest('hex'), results };
  await writeFile('artifacts/schemathesis-installed-verification.json', JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify(summary));
} finally { await rm(consumer, { recursive: true, force: true }); }
