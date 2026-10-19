import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bootstrapSecurityToolchain, failSecuritySetup, verifySecurityArchive } from './bootstrap-security-toolchain.mjs';

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
