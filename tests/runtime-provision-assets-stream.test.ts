import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer, get } from 'node:http';
import { once } from 'node:events';
import { Readable, PassThrough } from 'node:stream';
import { createHash } from 'node:crypto';
import { mkdtemp, realpath, rmdir, readFile, writeFile, unlink, link, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AssetDirectory, checkAsset } from '../src/runtime/runtimes/provision-paths.js';
import { writeAssetStream, verifyAssetResponse } from '../src/runtime/runtimes/provision-asset-transfer.js';

const digest = (body: Buffer) => createHash('sha256').update(body).digest('hex');

test('an immediately flushed producer cannot lose bytes while the owned output file is opening', async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-flush-'));
  const directory = await AssetDirectory.create(base), signal = AbortSignal.timeout(10000);
  const source = new PassThrough(), body = Buffer.from('flush before asynchronous file allocation');
  try {
    const writing = writeAssetStream(source, { directory, relative: 'flushed', limit: 128, signal },
      { bytes: body.length, sha256: digest(body) });
    source.end(body);
    source.resume();
    const file = await writing;
    assert.deepEqual(await readFile(file.path), body);
  } finally { await directory.cleanup(); await rmdir(base); }
});

test('real HTTP response streams become exact immutable owned files and reject wire header mismatches', async () => {
  const body = Buffer.from('owned synthetic response'), signal = AbortSignal.timeout(10000);
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-wire-'));
  const directory = await AssetDirectory.create(base);
  const server = createServer((request, response) => {
    response.writeHead(request.url === '/redirect' ? 302 : 200, {
      'Content-Length': request.url === '/short' ? body.length + 1 : body.length,
      ...(request.url === '/encoded' ? { 'Content-Encoding': 'gzip' } : {}),
    });
    response.end(body);
  });
  const listening = once(server, 'listening');
  server.listen(0, '127.0.0.1');
  await listening;
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const pin = { url: 'not-a-production-pin', bytes: body.length, sha256: digest(body) };
  try {
    for (const path of ['/ok', '/redirect', '/short', '/encoded']) {
      const incoming = await new Promise<import('node:http').IncomingMessage>((resolve, reject) => {
        get({ host: '127.0.0.1', port: address.port, path, signal }, resolve).once('error', reject);
      });
      try {
        if (path !== '/ok') assert.throws(() => verifyAssetResponse(incoming, pin), { code: 'asset_transfer' });
        else {
          verifyAssetResponse(incoming, pin);
          const file = await writeAssetStream(incoming, { directory, relative: 'wire', limit: 1024, signal }, pin);
          assert.deepEqual(await readFile(file.path), body);
          assert.equal(file.identity.mode & 0o777, 0o400);
        }
      } finally { incoming.destroy(); }
    }
  } finally {
    const closed = once(server, 'close');
    server.close(); server.closeAllConnections();
    await closed;
    await directory.cleanup(); await rmdir(base);
  }
});

test('stream size digest and abort guards fail on actual bytes and close partial files for owned cleanup', async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-stream-'));
  try {
    for (const kind of ['digest', 'short', 'overflow', 'abort'] as const) {
      const directory = await AssetDirectory.create(base), controller = new AbortController();
      const body = Buffer.from('12345678'), pin = { bytes: 8, sha256: digest(body) };
      const source = kind === 'abort' ? new PassThrough() : Readable.from([
        kind === 'short' ? body.subarray(1) : body,
      ]);
      try {
        const reading = writeAssetStream(source, { directory, relative: 'partial',
          limit: kind === 'overflow' ? 7 : 8, signal: controller.signal },
        kind === 'digest' ? { ...pin, sha256: '0'.repeat(64) } : pin);
        if (kind === 'abort') {
          assert.ok(source instanceof PassThrough);
          source.once('data', () => controller.abort());
          source.write(body.subarray(0, 1));
        }
        await assert.rejects(reading, { code: kind === 'abort' ? 'asset_expired' : 'asset_integrity' });
      } finally { await directory.cleanup(); }
    }
  } finally { await rmdir(base); }
});

test('same-byte inode swaps hardlinks and content changes invalidate original FD bindings', async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-identity-'));
  try {
    for (const kind of ['content', 'inode', 'hardlink'] as const) {
      const directory = await AssetDirectory.create(base), signal = AbortSignal.timeout(10000);
      const file = await writeAssetStream(Readable.from([Buffer.from('original')]),
        { directory, relative: 'file', limit: 8, signal });
      const sibling = join(directory.root, 'replacement');
      try {
        if (kind === 'hardlink') await link(file.path, sibling);
        else if (kind === 'inode') {
          await writeFile(sibling, 'original', { mode: 0o400 });
          await rename(sibling, file.path);
        } else {
          const { chmod } = await import('node:fs/promises');
          await chmod(file.path, 0o600); await writeFile(file.path, 'modified');
        }
        await assert.rejects(checkAsset(file, signal), { code: 'identity_changed' });
        if (kind === 'inode') await assert.rejects(directory.cleanup(), { code: 'cleanup_unconfirmed' });
      } finally {
        if (kind === 'hardlink') await unlink(sibling);
        if (kind === 'inode') { await unlink(file.path); await rmdir(directory.root); }
        else await directory.cleanup();
      }
    }
  } finally { await rmdir(base); }
});

test('frozen private trees clean exactly known entries and preserve unexpected files on refusal', async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-cleanup-'));
  const directory = await AssetDirectory.create(base), signal = AbortSignal.timeout(10000);
  const file = await writeAssetStream(Readable.from([Buffer.from('safe')]),
    { directory, relative: 'nested/file', limit: 4, signal });
  const foreign = join(directory.root, 'foreign');
  try {
    await writeFile(foreign, 'retain');
    await assert.rejects(directory.cleanup(), { code: 'cleanup_unconfirmed' });
    assert.equal(await readFile(foreign, 'utf8'), 'retain');
    assert.equal(await readFile(file.path, 'utf8'), 'safe');
    await unlink(foreign);
    await directory.freeze();
    await checkAsset(file, signal);
    await directory.cleanup();
  } finally { await rmdir(base); }
});
