import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bootstrapSecurityToolchain, verifySecurityArchive } from './bootstrap-security-toolchain.mjs';

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
