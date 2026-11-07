import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtemp, realpath, mkdir, writeFile, readFile, rm, rmdir, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import { AssetDirectory } from '../src/runtime/runtimes/provision-paths.js';
import { writeAssetStream } from '../src/runtime/runtimes/provision-asset-transfer.js';
import { materializeAssetPrefix, validateArchiveListing } from '../src/runtime/runtimes/provision-asset-archive.js';
import type { SelectedAsset } from '../src/runtime/runtimes/provision-asset-catalog.js';
import { verifyRootfsFormat, verifySelectedFormat } from '../src/runtime/runtimes/provision-asset-format.js';

test('native tar validates synthetic bytes before copying selected regular files', async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-tar-'));
  const directory = await AssetDirectory.create(base), signal = AbortSignal.timeout(10000);
  const source = join(base, 'source'), archivePath = join(base, 'synthetic.tar.gz');
  const body = Buffer.alloc(64, 'x');
  try {
    await mkdir(join(source, 'bin'), { recursive: true });
    await writeFile(join(source, 'bin', 'sample'), body, { mode: 0o644 });
    const child = spawn('/usr/bin/tar', ['-czf', archivePath, '-C', source, '.'],
      { env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, stdio: 'ignore', signal });
    await new Promise<void>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', code => code === 0 ? resolve() : reject(new Error('fixture_tar_failed')));
    });
    const archive = await writeAssetStream(Readable.from([await readFile(archivePath)]),
      { directory, relative: 'archive', limit: 65536, signal });
    const selected: readonly SelectedAsset[] = [{ path: 'bin/sample', bytes: 64, mode: 0o444, format: 'license',
      sha256: createHash('sha256').update(body).digest('hex') }];
    const files = await materializeAssetPrefix(archive,
      { archiveEntries: 3, regularEntries: 1, regularBytes: 64, selected }, { directory, signal });
    assert.equal(files.length, 1);
    assert.deepEqual(await readFile(files[0].path), body);
    const tampered = await AssetDirectory.create(base);
    try {
      await assert.rejects(materializeAssetPrefix(archive, {
        archiveEntries: 3, regularEntries: 1, regularBytes: 64,
        selected: [{ ...selected[0], sha256: '0'.repeat(64) }],
      }, { directory: tampered, signal }), { code: 'asset_integrity' });
    } finally { await tampered.cleanup(); }
  } finally {
    await directory.cleanup();
    await rm(source, { recursive: true }); await rm(archivePath, { force: true }); await rmdir(base);
  }
});

test('all archive member metadata rejects links devices collisions writable modes and oversized sets', () => {
  const row = (mode: string, size: number, path: string) => `${mode}  0 0 0 ${size} Nov  5 00:00 ${path}\n`;
  const root = row('drwxr-xr-x', 0, './'), bin = row('drwxr-xr-x', 0, './bin/');
  const file = row('-rw-r--r--', 64, './bin/sample');
  const expected = { archiveEntries: 3, regularEntries: 1, regularBytes: 64, selected: [] };
  assert.equal(validateArchiveListing(root + bin + file, expected).length, 3);
  for (const bad of [
    row('lrwxr-xr-x', 0, './bin/sample -> /etc/passwd'),
    row('hrw-r--r--', 64, './bin/sample link to ./other'),
    row('crw-r--r--', 0, './bin/sample'),
    row('-rw-rw-r--', 64, './bin/sample'),
    row('-rw-r--r--', 64, './bin/../sample'),
    row('-rw-r--r--', 64, '/absolute'),
    row('-rw-r--r--', 134217729, './bin/sample'),
  ]) assert.throws(() => validateArchiveListing(root + bin + bad, expected), { code: 'archive_invalid' });
  assert.throws(() => validateArchiveListing(root + file + file,
    { ...expected, regularEntries: 2, regularBytes: 128 }), { code: 'archive_invalid' });
  assert.throws(() => validateArchiveListing(root + file + file.replace('sample', 'SAMPLE'),
    { ...expected, regularEntries: 2, regularBytes: 128 }), { code: 'archive_invalid' });
});

test('bounded decompression rejects an oversized stream rather than trusting small compressed bytes', async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-inflate-'));
  const directory = await AssetDirectory.create(base), signal = AbortSignal.timeout(10000);
  try {
    const archive = await writeAssetStream(Readable.from([gzipSync(Buffer.alloc(2048))]),
      { directory, relative: 'compressed', limit: 65536, signal });
    const { inflateAssetArchive } = await import('../src/runtime/runtimes/provision-asset-archive.js');
    await assert.rejects(inflateAssetArchive(archive,
      { directory, relative: 'inflated', limit: 1024, signal }), { code: 'asset_integrity' });
  } finally { await directory.cleanup(); await rmdir(base); }
});

test('format gates reject architecture backing images encryption and version mismatches', async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-format-'));
  const { open } = await import('node:fs/promises');
  const path = join(base, 'header'), header = Buffer.alloc(104);
  header.writeUInt32BE(0x514649fb, 0); header.writeUInt32BE(3, 4);
  header.writeUInt32BE(16, 20); header.writeBigUInt64BE(1024n ** 3n, 24); header.writeUInt32BE(104, 100);
  try {
    await writeFile(path, header, { mode: 0o600 });
    let fd = await open(path, 'r');
    try { await verifyRootfsFormat(fd); } finally { await fd.close(); }
    for (const position of [8, 32, 72]) {
      const changed = Buffer.from(header); changed[position] = 1;
      await writeFile(path, changed);
      fd = await open(path, 'r');
      try { await assert.rejects(verifyRootfsFormat(fd), { code: 'asset_integrity' }); }
      finally { await fd.close(); }
    }
    await writeFile(path, Buffer.alloc(64));
    fd = await open(path, 'r');
    try {
      for (const format of ['macho-arm64', 'elf-aarch64', 'version'] as const) {
        await assert.rejects(verifySelectedFormat(fd, format), { code: 'asset_integrity' });
      }
    } finally { await fd.close(); }
  } finally { await chmod(path, 0o600); await rm(path); await rmdir(base); }
});
