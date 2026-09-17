import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { basename, join } from 'node:path';
import { tmpdir } from 'node:os';

const exec = promisify(execFile);
const packageRelease = join(process.cwd(), 'scripts', 'package-release.mjs');
const tar = process.platform === 'win32' ? 'tar.exe' : 'tar';

async function runRelease(root: string, outDir: string) {
  return exec(process.execPath, [packageRelease, '--root', root, '--out-dir', outDir], {
    cwd: root,
    env: { ...process.env, npm_config_update_notifier: 'false' },
    maxBuffer: 10 * 1024 * 1024,
  });
}

async function archivePaths(archive: string): Promise<string[]> {
  const { stdout } = await exec(tar, ['-tzf', archive]);
  return stdout.trim().split('\n').filter(Boolean).map((entry) => entry.replace(/\r$/, ''));
}

async function createFixture() {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-security-ci-release-fixture-'));
  await mkdir(join(root, 'build', 'src'), { recursive: true });
  await mkdir(join(root, 'src', 'source'), { recursive: true });
  await mkdir(join(root, 'tests'), { recursive: true });
  await mkdir(join(root, 'scripts'), { recursive: true });
  await mkdir(join(root, 'docs', 'benchmarks', 'future'), { recursive: true });
  await mkdir(join(root, 'benchmarks'), { recursive: true });
  await mkdir(join(root, 'examples'), { recursive: true });
  await mkdir(join(root, '.github', 'workflows'), { recursive: true });
  await writeFile(join(root, 'package.json'), JSON.stringify({
    name: 'wakeio-security-ci',
    version: '9.8.7',
    type: 'module',
    bin: { 'wakeio-security-ci': './build/src/cli.js' },
    files: ['build/src', 'README.md', 'LICENSE'],
  }));
  await writeFile(join(root, 'package-lock.json'), JSON.stringify({ name: 'wakeio-security-ci', version: '9.8.7', lockfileVersion: 3, packages: { '': { name: 'wakeio-security-ci', version: '9.8.7' } } }));
  await writeFile(join(root, 'build', 'src', 'cli.js'), '#!/usr/bin/env node\n');
  await mkdir(join(root, 'build', 'src', 'results'), { recursive: true });
  await writeFile(join(root, 'build', 'src', 'results', 'latest.json'), '{"secret":"build-fixture"}\n');
  await chmod(join(root, 'build', 'src', 'cli.js'), 0o755);
  await writeFile(join(root, 'src', 'index.ts'), 'export const releaseFixture = true;\n');
  await writeFile(join(root, 'src', 'source', 'collector.ts'), 'export const collector = true;\n');
  await writeFile(join(root, 'tests', 'fixture.test.ts'), 'export {};\n');
  await writeFile(join(root, 'scripts', 'helper.mjs'), 'export {};\n');
  await writeFile(join(root, 'docs', 'benchmarks', 'future', 'README.md'), '# Future benchmark notes\n');
  await writeFile(join(root, 'docs', '.env'), 'DOCS_TOKEN=fixture-secret\n');
  await mkdir(join(root, 'benchmarks', 'results'), { recursive: true });
  await writeFile(join(root, 'benchmarks', 'results', 'latest.json'), '{"secret":"fixture"}\n');
  await writeFile(join(root, 'benchmarks', 'fixture.mjs'), 'export const benchmark = true;\n');
  await writeFile(join(root, 'examples', 'local.yml'), 'name: local\n');
  await writeFile(join(root, 'scripts', 'benchmark.mjs'), 'export const benchmark = true;\n');
  await writeFile(join(root, '.github', 'workflows', 'release-check.yml'), 'name: release-check\n');
  for (const name of ['README.md', 'LICENSE', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'CONTRIBUTING.md', 'action.yml', 'tsconfig.json', '.nvmrc', '.gitignore']) {
    await writeFile(join(root, name), `${name}\n`);
  }

  // These entries model files that must never enter either release artifact.
  await writeFile(join(root, '.env'), 'TOKEN=fixture-secret\n');
  await writeFile(join(root, '.env.local'), 'TOKEN=fixture-secret\n');
  await mkdir(join(root, 'realreports'), { recursive: true });
  await writeFile(join(root, 'realreports', 'report.json'), 'fixture-report\n');
  await mkdir(join(root, 'artifacts'), { recursive: true });
  await writeFile(join(root, 'artifacts', 'old.tgz'), 'old-artifact\n');
  await mkdir(join(root, 'node_modules', 'private-module'), { recursive: true });
  await writeFile(join(root, 'node_modules', 'private-module', 'index.js'), 'private-module\n');
  await mkdir(join(root, 'build', 'reports'), { recursive: true });
  await writeFile(join(root, 'build', 'reports', 'build-report.json'), 'build-report\n');
  await mkdir(join(root, '.git'), { recursive: true });
  await writeFile(join(root, '.git', 'config'), 'private-git-state\n');

  return root;
}

test('release package includes full source, future docs, npm runtime, and excludes sensitive/generated paths', async () => {
  const root = await createFixture();
  const outDir = join(root, 'release-artifacts');
  const outside = join(root, '..', `${basename(root)}-outside-secret.txt`);
  try {
    await writeFile(outside, 'OUTSIDE_SECRET=fixture-secret\n');
    await runRelease(root, outDir);
    const files = (await readdir(outDir)).sort();
    assert.deepEqual(files, ['wakeio-security-ci-9.8.7-SHA256SUMS.txt', 'wakeio-security-ci-9.8.7.tgz', 'wakeio-security-ci-source-9.8.7.tar.gz']);

    const source = join(outDir, 'wakeio-security-ci-source-9.8.7.tar.gz');
    const npm = join(outDir, 'wakeio-security-ci-9.8.7.tgz');
    const sourcePaths = await archivePaths(source);
    assert.ok(sourcePaths.includes('wakeio-security-ci/'));
    assert.ok(sourcePaths.includes('wakeio-security-ci/src/index.ts'));
    assert.ok(sourcePaths.includes('wakeio-security-ci/src/source/collector.ts'));
    assert.ok(sourcePaths.includes('wakeio-security-ci/docs/benchmarks/future/README.md'));
    assert.ok(sourcePaths.includes('wakeio-security-ci/benchmarks/fixture.mjs'));
    assert.ok(sourcePaths.includes('wakeio-security-ci/scripts/benchmark.mjs'));
    assert.ok(sourcePaths.includes('wakeio-security-ci/tests/fixture.test.ts'));
    assert.equal(sourcePaths.some((entry) => /(^|\/)(\.git|node_modules|build|artifacts|realreports)(\/|$)/.test(entry)), false);
    assert.equal(sourcePaths.some((entry) => /(^|\/)results(\/|$)/.test(entry)), false);
    assert.equal(sourcePaths.some((entry) => /(^|\/)\.env(?:\.|$)/.test(entry)), false);
    assert.equal(sourcePaths.some((entry) => entry.includes('private-git-state') || entry.includes('fixture-secret')), false);
    assert.equal(sourcePaths.some((entry) => entry.includes('outside')), false);

    const npmPaths = await archivePaths(npm);
    assert.ok(npmPaths.includes('package/build/src/cli.js'));
    assert.ok(npmPaths.includes('package/package.json'));
    assert.equal(npmPaths.some((entry) => entry.includes('package/src/') || entry.includes('package/tests/')), false);
    assert.equal(npmPaths.some((entry) => /(^|\/)(\.env|realreports|artifacts|node_modules|build\/reports)(\/|$)/.test(entry)), false);
    assert.equal(npmPaths.some((entry) => /(^|\/)build\/src\/results(\/|$)/.test(entry)), false);

    const sums = await readFile(join(outDir, 'wakeio-security-ci-9.8.7-SHA256SUMS.txt'), 'utf8');
    for (const artifact of [source, npm]) {
      const digest = createHash('sha256').update(await readFile(artifact)).digest('hex');
      assert.match(sums, new RegExp(`^${digest}  ${artifact.replace(`${outDir}/`, '')}$`, 'm'));
    }
  } finally {
    await rm(outside, { force: true });
    await rm(root, { recursive: true, force: true });
  }
});

test('release package can atomically overwrite regular artifacts but refuses an output directory symlink', async () => {
  const root = await createFixture();
  const outDir = join(root, 'release-artifacts');
  const target = join(root, 'real-output-target');
  const linkedOutput = join(root, 'linked-output');
  try {
    await runRelease(root, outDir);
    const source = join(outDir, 'wakeio-security-ci-source-9.8.7.tar.gz');
    const npm = join(outDir, 'wakeio-security-ci-9.8.7.tgz');
    const firstHash = createHash('sha256').update(await readFile(source)).digest('hex');
    const firstNpmHash = createHash('sha256').update(await readFile(npm)).digest('hex');
    await writeFile(source, 'replace-me\n');
    await writeFile(npm, 'replace-me-too\n');
    await runRelease(root, outDir);
    const secondHash = createHash('sha256').update(await readFile(source)).digest('hex');
    const secondNpmHash = createHash('sha256').update(await readFile(npm)).digest('hex');
    assert.notEqual(secondHash, createHash('sha256').update('replace-me\n').digest('hex'));
    assert.equal(secondHash, firstHash);
    assert.equal(secondNpmHash, firstNpmHash);

    await mkdir(target);
    await symlink(target, linkedOutput);
    await assert.rejects(runRelease(root, linkedOutput), /output directory.*symlink|symbolic link/i);
    assert.deepEqual(await readdir(target), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('release package refuses to replace a symlinked artifact and preserves its target', async () => {
  const root = await createFixture();
  const outDir = join(root, 'release-artifacts');
  const preserved = join(root, 'preserved.txt');
  const source = join(outDir, 'wakeio-security-ci-source-9.8.7.tar.gz');
  try {
    await runRelease(root, outDir);
    await writeFile(preserved, 'KEEP_THIS_FILE\n');
    await rm(source);
    await symlink(preserved, source);
    await assert.rejects(runRelease(root, outDir), /symlink|symbolic link/i);
    assert.equal(await readFile(preserved, 'utf8'), 'KEEP_THIS_FILE\n');
    assert.equal((await lstat(source)).isSymbolicLink(), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('release package refuses symlinked output ancestors and source allowlist subdirectories', async () => {
  const root = await createFixture();
  const ancestorTarget = join(root, 'ancestor-target');
  const ancestorLink = join(root, 'ancestor-link');
  const linkedOutput = join(ancestorLink, 'release');
  const sourceSubdirectoryOutput = join(root, 'docs', 'releases');
  try {
    await mkdir(ancestorTarget);
    await symlink(ancestorTarget, ancestorLink);
    await assert.rejects(runRelease(root, linkedOutput), /output path ancestor.*symbolic link/i);
    assert.deepEqual(await readdir(ancestorTarget), []);

    await assert.rejects(runRelease(root, sourceSubdirectoryOutput), /inside source allowlist entry docs/i);
    await assert.rejects(lstat(sourceSubdirectoryOutput));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
