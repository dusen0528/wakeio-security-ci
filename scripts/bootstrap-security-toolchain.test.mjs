import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bootstrapSecurityToolchain, failSecuritySetup, verifySecurityArchive } from './bootstrap-security-toolchain.mjs';
import { runBounded } from './ci-process.mjs';
import { fileURLToPath } from 'node:url';

test('preflight CLI retains command identity and errno without exposing argv or environment', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-preflight-diagnostic-'));
  try {
    for (const code of ['ETXTBSY', 'ENOENT']) {
      const executable = join(directory, 'missing-python');
      const preload = `import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
Object.defineProperty(process,'platform',{value:'linux'});
Object.defineProperty(process,'arch',{value:'x64'});
globalThis.fetch=async()=>{throw Error('offline_test_network_blocked')};
${code === 'ETXTBSY' ? `childProcess.spawn=()=>{throw Object.assign(Error('spawn ETXTBSY secret-argv'),{code:'ETXTBSY',errno:-26,syscall:'spawn'})}; syncBuiltinESMExports();` : ''}`;
      const env = { ...process.env, GITHUB_ENV: join(directory, 'github-env'), JAVA_HOME_21_X64: directory,
        WAKEIO_BOOTSTRAP_PYTHON: executable, DIAGNOSTIC_TEST_SECRET: 'secret-environment' };
      delete env.NODE_TEST_CONTEXT;
      const result = await runBounded(process.execPath, ['--import', 'data:text/javascript,' + encodeURIComponent(preload),
        fileURLToPath(new URL('./bootstrap-security-toolchain.mjs', import.meta.url))], { timeoutMs: 10000, env });
      assert.equal(result.exitCode, 2);
      assert.equal(result.cleanupConfirmed, true);
      const diagnostics = result.stderr.split('\n').filter(line => line.startsWith('Security toolchain command failed: '))
        .map(line => JSON.parse(line.slice('Security toolchain command failed: '.length)));
      const diagnostic = diagnostics.find(value => value.name === 'python-version');
      assert.ok(diagnostic, result.stderr);
      assert.equal(diagnostic.executable, executable);
      assert.equal(diagnostic.code, code);
      assert.equal(diagnostic.errno, code === 'ETXTBSY' ? -26 : -2);
      assert.equal(diagnostic.syscall, code === 'ETXTBSY' ? 'spawn' : 'spawn ' + executable);
      assert.equal(diagnostic.writerContext, 'not_observed');
      assert.equal(typeof diagnostic.parentPid, 'number');
      assert.equal(JSON.stringify(diagnostic).includes('secret-'), false);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('security bootstrap rejects corrupt or empty downloaded archives before extraction', () => {
  const archive = Buffer.from('owned checksum boundary fixture');
  const digest = createHash('sha256').update(archive).digest('hex');
  assert.doesNotThrow(() => verifySecurityArchive(archive, digest));
  assert.throws(() => verifySecurityArchive(Buffer.concat([archive, Buffer.from('tampered')]), digest), /checksum/);
  assert.throws(() => verifySecurityArchive(archive, 'invalid'), /checksum/);
  assert.throws(() => verifySecurityArchive(Buffer.alloc(0), digest), /size/);
});

test('security bootstrap refuses unsupported platforms or invalid CI environment before installation', async () => {
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    await assert.rejects(bootstrapSecurityToolchain(), /requires_linux_x64/);
    return;
  }
  const previous = process.env.GITHUB_ENV;
  try {
    process.env.GITHUB_ENV = '/tmp/receipt\nINJECTED=value';
    await assert.rejects(bootstrapSecurityToolchain(), /setup_path/);
  } finally { if (previous === undefined) delete process.env.GITHUB_ENV; else process.env.GITHUB_ENV = previous; }
});

test('failed setup removes readonly Go cache directories without following external symlinks', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-setup-cleanup-'));
  const owned = join(top, 'owned'), outside = join(top, 'outside'), cache = join(owned, 'gopath/pkg/mod/module@v1.0.0');
  try {
    await mkdir(cache, { recursive: true }); await mkdir(outside);
    await writeFile(join(cache, 'LICENSE'), 'owned cache'); await chmod(join(cache, 'LICENSE'), 0o444);
    await writeFile(join(outside, 'preserve'), 'outside fixture'); await chmod(outside, 0o555);
    await symlink(outside, join(owned, 'external-directory')); await chmod(cache, 0o555);
    const original = Error('zap-version:command_failed:exit=2');
    await assert.rejects(failSecuritySetup(owned, original), error => error === original);
    await assert.rejects(lstat(owned), { code: 'ENOENT' });
    assert.equal(await readFile(join(outside, 'preserve'), 'utf8'), 'outside fixture');
    assert.equal((await lstat(outside)).mode & 0o777, 0o555);
  } finally { await chmod(outside, 0o700).catch(() => {}); await rm(top, { recursive: true, force: true }); }
});

test('cleanup filesystem errors never replace the original bootstrap failure', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-setup-error-'));
  try {
    const blocker = join(top, 'file'); await writeFile(blocker, 'not a directory');
    const original = Error('zap-version:timeout:exit=null');
    await assert.rejects(failSecuritySetup(join(blocker, 'child'), original), error => error === original);
    assert.equal(await readFile(blocker, 'utf8'), 'not a directory');
  } finally { await rm(top, { recursive: true, force: true }); }
});
