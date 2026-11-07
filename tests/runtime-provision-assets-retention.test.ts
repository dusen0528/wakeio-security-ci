import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { fstatSync } from 'node:fs';
import { mkdtemp, realpath, rm, readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AssetDirectory } from '../src/runtime/runtimes/provision-paths.js';
import { writeAssetStream } from '../src/runtime/runtimes/provision-asset-transfer.js';
import { startAssetUse, finishAssetDirectory } from '../src/runtime/runtimes/provision-asset-lifetime.js';
import { withAssetBorrow, permitProvisionAssetBorrowReleaseAfterDrain,
  retainedAssetDirectory, ProvisionAssetRetentionError,
  type AssetBorrowView } from '../src/runtime/runtimes/provision-asset-borrow.js';

async function fixture() {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-retain-'));
  const directory = await AssetDirectory.create(base), controller = new AbortController();
  const file = await writeAssetStream(Readable.from([Buffer.from('owned fixture bytes')]),
    { directory, relative: 'borrowed', limit: 64, signal: controller.signal });
  let revoked = false;
  return { base, directory, controller, file, binding: { directory, files: [file], signal: controller.signal,
    revoke: () => { revoked = true; } }, revoked: () => revoked };
}

function ownedChild(fd: number) {
  const child = spawn(process.execPath, ['-e', "process.stdin.on('end',()=>process.exit(0));"
    + "process.stdin.resume();process.stdout.write(require('node:fs').readFileSync(3,'utf8')+'\\n');"],
  { env: { PATH: '/usr/bin:/bin' }, stdio: ['pipe', 'pipe', 'pipe', fd] });
  assert.ok(child.stdin && child.stdout);
  const input = child.stdin;
  const ready = new Promise<void>((resolve, reject) => {
    child.stdout?.once('error', reject);
    child.stdout?.once('data', (chunk: Buffer) => {
      if (chunk.toString('utf8') === 'owned fixture bytes\n') resolve();
      else reject(new Error('unexpected_owned_child_bytes'));
    });
  });
  const closed = new Promise<void>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => code === 0 && signal === null ? resolve()
      : reject(new Error('owned_child_close_unconfirmed')));
  });
  return { input, ready, closed };
}

async function disposeFixture(f: Awaited<ReturnType<typeof fixture>>): Promise<void> {
  const retained = retainedAssetDirectory(f.directory);
  if (retained) {
    await permitProvisionAssetBorrowReleaseAfterDrain(retained.owner, retained.retention);
    await retained.retention.disposed;
  }
  await rm(f.base, { recursive: true });
}

test('missing owner drain retains descriptors and refuses serialized or foreign release', async () => {
  const a = await fixture(), b = await fixture();
  let av: AssetBorrowView | undefined, bv: AssetBorrowView | undefined;
  try {
    await assert.rejects(withAssetBorrow(a.binding, async view => { av = view; }), ProvisionAssetRetentionError);
    await assert.rejects(withAssetBorrow(b.binding, async view => { bv = view; }), ProvisionAssetRetentionError);
    const ar = retainedAssetDirectory(a.directory), br = retainedAssetDirectory(b.directory);
    assert.ok(av && bv && ar && br);
    const borrowedFd = av.files[0].fd;
    assert.equal(fstatSync(borrowedFd).size, 19);
    assert.equal(a.revoked(), true);
    assert.deepEqual(JSON.parse(JSON.stringify(ar)), { code: 'cleanup_unconfirmed', retained: true });
    assert.throws(() => JSON.stringify(ar.retention), { code: 'asset_handle_invalid' });
    assert.throws(() => ar.retention.release.call(br.retention), { code: 'asset_handle_invalid' });
    for (const [owner, token] of [[ar.owner, br.retention], [JSON.parse('{}'), ar.retention],
      [ar.owner, JSON.parse('{}')], [new Proxy(ar.owner, {}), ar.retention]]) {
      assert.throws(() => permitProvisionAssetBorrowReleaseAfterDrain(owner, token), { code: 'asset_handle_invalid' });
    }
    await assert.rejects(finishAssetDirectory(a.directory, []), ProvisionAssetRetentionError);
    assert.equal(await readFile(a.file.path, 'utf8'), 'owned fixture bytes');
    const releasing = permitProvisionAssetBorrowReleaseAfterDrain(ar.owner, ar.retention);
    assert.equal(permitProvisionAssetBorrowReleaseAfterDrain(ar.owner, ar.retention), releasing);
    await releasing;
    await ar.retention.disposed;
    await assert.rejects(readFile(a.file.path), { code: 'ENOENT' });
    assert.throws(() => fstatSync(borrowedFd), { code: 'EBADF' });
  } finally {
    for (const f of [a, b]) await disposeFixture(f);
  }
});

test('cleanup-failure callback rejection keeps FD and prefix after callback settlement until actual child drain',
  { timeout: 10000 }, async () => {
    const f = await fixture();
    let child: ReturnType<typeof ownedChild> | undefined, view: AssetBorrowView | undefined;
    try {
      await assert.rejects(withAssetBorrow(f.binding, async borrowed => {
        borrowed.retainForDrain();
        view = borrowed; child = ownedChild(borrowed.files[0].fd);
        await child.ready;
        throw new Error('controller_cleanup_unconfirmed');
      }), ProvisionAssetRetentionError);
      assert.ok(view && child);
      f.controller.abort();
      assert.equal(fstatSync(view.files[0].fd).size, 19);
      await assert.rejects(finishAssetDirectory(f.directory, []), ProvisionAssetRetentionError);
      assert.equal(await readFile(f.file.path, 'utf8'), 'owned fixture bytes');
      child.input.end();
      await child.closed;
      assert.equal(fstatSync(view.files[0].fd).size, 19);
    } finally {
      if (child) { child.input.end(); await child.closed; }
      await disposeFixture(f);
    }
  });

test('abort revokes immediately but neither callback settlement nor actual child close alone releases retained FD',
  { timeout: 10000 }, async () => {
    const f = await fixture();
    let child: ReturnType<typeof ownedChild> | undefined, view: AssetBorrowView | undefined;
    let entered = () => {};
    const ready = new Promise<void>(resolve => { entered = resolve; });
    const use = startAssetUse(() => withAssetBorrow(f.binding, async borrowed => {
      borrowed.retainForDrain();
      view = borrowed; child = ownedChild(borrowed.files[0].fd);
      await child.ready; entered(); await child.closed;
    }), f.controller.signal);
    try {
      await ready;
      f.controller.abort();
      await assert.rejects(use.result, { code: 'asset_expired' });
      assert.ok(view && child);
      assert.equal(f.revoked(), true);
      assert.equal(fstatSync(view.files[0].fd).size, 19);
      await assert.rejects(finishAssetDirectory(f.directory, [use]), ProvisionAssetRetentionError);
      child.input.end(); await child.closed; await use.drained;
      assert.equal(fstatSync(view.files[0].fd).size, 19);
    } finally {
      if (child) { child.input.end(); await child.closed; }
      await use.drained;
      await disposeFixture(f);
    }
  });

test('in-callback release records permission without deadlock or early disposal', async () => {
  const f = await fixture();
  let fd = -1;
  try {
    await withAssetBorrow(f.binding, async view => {
      const retention = view.retainForDrain();
      fd = view.files[0].fd;
      const permission = await retention.release();
      assert.deepEqual(permission, { kind: 'drain-permission-recorded', disposalConfirmed: false });
      assert.equal(fstatSync(fd).size, 19);
      assert.equal(await readFile(f.file.path, 'utf8'), 'owned fixture bytes');
    });
    assert.equal(f.revoked(), true);
    assert.throws(() => fstatSync(fd), { code: 'EBADF' });
    await finishAssetDirectory(f.directory, []);
  } finally { await disposeFixture(f); }
});

test('post-permission callback rejection waits disposal before returning the original error', async () => {
  const f = await fixture(), failure = new Error('owned_consumer_failed_after_drain');
  let fd = -1;
  try {
    await assert.rejects(withAssetBorrow(f.binding, async view => {
      const retention = view.retainForDrain();
      fd = view.files[0].fd;
      await retention.release();
      assert.equal(fstatSync(fd).size, 19);
      throw failure;
    }), error => error === failure);
    assert.throws(() => fstatSync(fd), { code: 'EBADF' });
    await assert.rejects(readFile(f.file.path), { code: 'ENOENT' });
  } finally { await disposeFixture(f); }
});
