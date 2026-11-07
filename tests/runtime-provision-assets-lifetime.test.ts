import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { mkdtemp, realpath, rmdir, readFile, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AssetDirectory } from '../src/runtime/runtimes/provision-paths.js';
import { writeAssetStream } from '../src/runtime/runtimes/provision-asset-transfer.js';
import { startAssetUse, finishAssetDirectory,
  ProvisionAssetCleanupPending } from '../src/runtime/runtimes/provision-asset-lifetime.js';

test('abort retains FD and prefix until owned child close', { timeout: 10000 }, async () => {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-drain-'));
  const directory = await AssetDirectory.create(base), controller = new AbortController();
  const file = await writeAssetStream(Readable.from([Buffer.from('owned borrowed bytes')]),
    { directory, relative: 'borrowed', limit: 64, signal: controller.signal });
  const fd = await open(file.path, 'r');
  const program = "process.stdin.on('end',()=>process.exit(0));process.stdin.resume();"
    + "process.stdout.write(require('node:fs').readFileSync(3,'utf8')+'\\n');";
  const child = spawn(process.execPath, ['-e', program], {
    env: { PATH: '/usr/bin:/bin' }, stdio: ['pipe', 'pipe', 'pipe', fd.fd],
  });
  assert.ok(child.stdout && child.stdin);
  const input = child.stdin, output = child.stdout;
  const closed = new Promise<void>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => code === 0 && signal === null ? resolve()
      : reject(new Error('owned_child_close_failed')));
  });
  const ready = new Promise<string>((resolve, reject) => {
    output.once('error', reject);
    output.once('data', (chunk: Buffer) => resolve(chunk.toString('utf8')));
  });
  const use = startAssetUse(async () => {
    try { await closed; } finally { await fd.close(); }
  }, controller.signal);
  let retained: ProvisionAssetCleanupPending | undefined, directoryCleaned = false;
  try {
    assert.equal(await ready, 'owned borrowed bytes\n');
    controller.abort();
    await assert.rejects(use.result, { code: 'asset_expired' });
    assert.equal(use.isDrained(), false);
    assert.equal((await fd.stat()).size, 20);
    const finishing = finishAssetDirectory(directory, [use]).then(() => { directoryCleaned = true; });
    await assert.rejects(finishing, error => {
      if (!(error instanceof ProvisionAssetCleanupPending)) return false;
      retained = error;
      return true;
    });
    assert.ok(retained);
    assert.equal(retained.retainedDirectory, directory.root);
    const cleanup = retained.cleanupAfterDrain();
    assert.equal(await readFile(file.path, 'utf8'), 'owned borrowed bytes');
    input.end();
    await closed;
    await retained.drained;
    assert.equal(use.isDrained(), true);
    await assert.rejects(fd.stat(), { code: 'EBADF' });
    await cleanup;
    await assert.rejects(readFile(file.path), { code: 'ENOENT' });
  } finally {
    input.end();
    await closed;
    if (retained) await retained.cleanupAfterDrain();
    else if (!directoryCleaned) await directory.cleanup();
    await rmdir(base);
  }
});
