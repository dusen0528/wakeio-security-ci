import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { fstatSync } from 'node:fs';
import { mkdtemp, realpath, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { withProvisionedBackend, withVerifiedBackend } from '../src/runtime/runtimes/provision-backend.js';
import { ProvisionOwner } from '../src/runtime/runtimes/provision-controller-owner.js';
import { AssetDirectory } from '../src/runtime/runtimes/provision-paths.js';
import { writeAssetStream } from '../src/runtime/runtimes/provision-asset-transfer.js';
import { withAssetBorrow, ProvisionAssetRetentionError,
  type ProvisionAssetRetention } from '../src/runtime/runtimes/provision-asset-borrow.js';
import { withPreparedBackend } from '../src/runtime/runtimes/provision-backend-capability.js';
import { withControllerPeer } from './runtime-provision-backend-fixture.js';

test('production entry refuses missing consent and unsupported grade before acquisition', async () => {
  let callbacks = 0;
  await assert.rejects(withProvisionedBackend({}, async () => { callbacks++; }), { code: 'consent_required' });
  await assert.rejects(withProvisionedBackend({
    executeTargetConsent: true, deadlineAt: Date.now() + 10000, acquisitionDeadlineAt: Date.now() + 5000,
    requiredGrade: 'gvisor', catalog: {},
  }, async () => { callbacks++; }), { code: 'required_runtime_unavailable' });
  assert.equal(callbacks, 0);
});

test('serialized substituted and proxied backend handles cannot acquire authority', async () => {
  const fake = Object.freeze({ kind: 'provisioned-backend' as const });
  let callbacks = 0;
  for (const handle of [fake, { ...fake }, JSON.parse(JSON.stringify(fake)), new Proxy(fake, {})]) {
    await assert.rejects(withVerifiedBackend(handle, async () => { callbacks++; }),
      { code: 'backend_handle_invalid' });
  }
  assert.equal(callbacks, 0);
});

test('prepared backend producer rejects structural copied and proxied handles before publication', async () => {
  const fake = Object.freeze({ kind: 'prepared-provision-controller' as const });
  let callbacks = 0;
  for (const prepared of [fake, { ...fake }, new Proxy(fake, {})]) {
    await assert.rejects(withPreparedBackend(prepared, async () => { callbacks++; }),
      { code: 'prepared_handle_invalid' });
  }
  assert.equal(callbacks, 0);
});

test('bounded owner cleanup retains the original asset descriptors until later actual child close',
  { timeout: 10000 }, async t => {
    const base = await mkdtemp(join(await realpath(tmpdir()), 'backend-join-'));
    const directory = await AssetDirectory.create(base);
    const signal = new AbortController();
    const file = await writeAssetStream(Readable.from([Buffer.from('controller-join')]),
      { directory, relative: 'asset', limit: 64, signal: signal.signal });
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const owner = new ProvisionOwner(Date.now() + 10000);
    let retention: ProvisionAssetRetention | undefined;
    let fd = -1;
    let child: ReturnType<typeof spawn> | undefined;
    let closed = Promise.resolve();
    try {
      await assert.rejects(withAssetBorrow({ directory, files: [file], signal: signal.signal, revoke() {} },
        async view => {
          retention = view.retainForDrain();
          fd = view.files[0].fd;
          child = spawn(process.execPath, ['-e', "process.stdin.resume();"
            + "process.stdin.on('end',()=>process.exit(0));"
            + "process.stdout.write(require('node:fs').readFileSync(3,'utf8'));"],
          { stdio: ['pipe', 'pipe', 'pipe', fd], env: {
            RUN_TMP: base, TMPDIR: base, NODE_COMPILE_CACHE: join(base, 'node'),
            BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(base, 'bun'),
          } });
          const ready = new Promise<void>((resolve, reject) => {
            child?.stdout?.once('data', (bytes: Buffer) => bytes.toString() === 'controller-join'
              ? resolve() : reject(new Error('child_asset_mismatch')));
            child?.once('error', reject);
          });
          closed = new Promise<void>((resolve, reject) => {
            child?.once('close', code => code === 0 ? resolve() : reject(new Error('child_close_failed')));
          });
          await ready;
          owner.own({ identity: 'owned-child', drained: closed, async remove() { return true; } });
          const closing = owner.close();
          t.mock.timers.tick(120000);
          assert.equal((await closing).confirmed, false);
          t.mock.timers.reset();
        }), ProvisionAssetRetentionError);
      assert.ok(retention && child?.stdin);
      assert.equal(fstatSync(fd).size, 15);
      assert.equal(await readFile(file.path, 'utf8'), 'controller-join');
      child.stdin.end();
      await closed;
      assert.equal((await owner.cleanupAfterDrain()).confirmed, true);
      assert.equal(fstatSync(fd).size, 15);
      await retention.release();
      await retention.disposed;
      assert.throws(() => fstatSync(fd), { code: 'EBADF' });
    } finally {
      t.mock.timers.reset();
      child?.stdin?.end();
      await closed;
      await owner.close();
      if (retention) { await retention.release(); await retention.disposed; }
      await rm(base, { recursive: true });
    }
  });


const lifecycleInput = () => ({ executeTargetConsent: true, deadlineAt: Date.now() + 900000,
  acquisitionDeadlineAt: Date.now() + 300000, requiredGrade: 'rootless-docker', catalog: {} });

test('ordinary producer refusal joins real child CLOSE and original descriptor disposal before throwing',
  { timeout: 10000 }, async t => {
    await withControllerPeer(t, async (api, peer) => {
      let published = 0;
      await assert.rejects(api.withProvisionedBackend(lifecycleInput(), async () => { published++; }), error => {
        assert.ok(error instanceof Error && 'code' in error);
        assert.equal(error.code, 'delegation_missing');
        const cause = error.cause;
        assert.ok(cause && typeof cause === 'object' && 'cleanup' in cause && 'assetDisposalConfirmed' in cause);
        assert.deepEqual(cause.cleanup, { confirmed: true, retained: [], failures: [] });
        assert.equal(cause.assetDisposalConfirmed, true);
        assert.throws(() => fstatSync(peer.fd), { code: 'EBADF' });
        return true;
      });
      assert.equal(published, 0);
    });
  });

test('new common cleanup deadline retains real FD and settles the same late-drain continuation',
  { timeout: 10000 }, async t => {
    await withControllerPeer(t, async (api, peer) => {
      peer.releaseOnShutdown = false;
      t.mock.timers.enable({ apis: ['setTimeout'] });
      const pending = api.withProvisionedBackend(lifecycleInput(), async () => { throw new Error('must not publish'); })
        .then(() => { throw new Error('must refuse'); }, error => error);
      await peer.draining;
      t.mock.timers.tick(120000);
      const observation: unknown = await pending;
      assert.ok(observation instanceof api.ProvisionBackendCleanupPending);
      await peer.settled;
      assert.equal(fstatSync(peer.fd).size, 19);
      peer.finish();
      assert.deepEqual(await observation.cleanupAfterDrain(), { confirmed: true, retained: [], failures: [] });
      assert.throws(() => fstatSync(peer.fd), { code: 'EBADF' });
      t.mock.timers.reset();
    });
  });
