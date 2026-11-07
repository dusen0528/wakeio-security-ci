import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { spawn } from 'node:child_process';
import { fstatSync } from 'node:fs';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { PROVISION_ASSET_CATALOG } from '../src/runtime/runtimes/provision-asset-catalog.js';
import { AssetDirectory } from '../src/runtime/runtimes/provision-paths.js';
import { writeAssetStream } from '../src/runtime/runtimes/provision-asset-transfer.js';
import { ProvisionError } from '../src/runtime/runtimes/provision-types.js';
import type { ProvisionOwner } from '../src/runtime/runtimes/provision-controller-owner.js';
import type { ProvisionAssetFiles } from '../src/runtime/runtimes/provision-assets.js';

function input() {
  return { executeNativeInstallRegressionConsent: true, consentPacketSha256: '42'.repeat(32),
    catalog: PROVISION_ASSET_CATALOG, deadlineAt: Date.now() + 900000,
    acquisitionDeadlineAt: Date.now() + 300000 };
}

test('native ingress refuses non-data consent and open inputs before any acquisition', async t => {
  const assetsUrl = new URL('../src/runtime/runtimes/provision-assets.js', import.meta.url);
  const assets = await import(assetsUrl.href);
  let acquisitions = 0, reads = 0;
  t.mock.module(assetsUrl, { namedExports: { ...assets,
    async withProvisionAssets() { acquisitions++; throw new Error('acquisition forbidden'); } } });
  const api: typeof import('../src/runtime/runtimes/provision-backend.js') = await import(
    new URL('../src/runtime/runtimes/provision-backend.js?ingress=' + randomUUID(), import.meta.url).href);
  for (const value of [undefined, {}, { executeNativeInstallRegressionConsent: false },
    Object.create({ executeNativeInstallRegressionConsent: true }),
    { get executeNativeInstallRegressionConsent() { reads++; return true; } },
    new Proxy({}, { getOwnPropertyDescriptor() { reads++; return undefined; } })]) {
    await assert.rejects(api.observeNativeInstallCase(value, 'mount-original'), { code: 'consent_required' });
  }
  for (const value of [{ ...input(), argv: ['INSTALL'] },
    { ...input(), catalog: { get secret() { reads++; return true; } } }]) {
    await assert.rejects(api.observeNativeInstallCase(value, 'mount-original'), { code: 'options_invalid' });
  }
  await assert.rejects(api.observeNativeInstallCase(input(), 'caller-script'), { code: 'native_case_invalid' });
  await assert.rejects(api.observeNativeInstallCase({ ...input(), consentPacketSha256: 'wrong' },
    'mount-original'), { code: 'native_packet_invalid' });
  assert.equal(reads, 0);
  assert.equal(acquisitions, 0);
});

class NativeRefusal {
  fd = -1;
  childClosed = false;
  child: ReturnType<typeof spawn> | undefined;
  closed: Promise<void> = Promise.resolve();
  constructor(readonly root: string) {}

  async install(t: TestContext) {
    const create = AssetDirectory.create.bind(AssetDirectory);
    t.mock.method(AssetDirectory, 'create', () => create(this.root));
    // Substitute acquisition/static review/native dispatch only. Ownership and disposal stay real.
    t.mock.module(new URL('../src/runtime/runtimes/provision-asset-prefix.js', import.meta.url), {
      namedExports: { prepareAssetPrefix: async (directory: AssetDirectory, signal: AbortSignal) => {
        const bound = await writeAssetStream(Readable.from([Buffer.from('original-native-borrow')]),
          { directory, relative: 'anchor', limit: 64, signal });
        await directory.freeze();
        return { files: [bound], limactl: bound, guestagent: bound, rootfs: bound };
      } },
    });
    const assetsUrl = new URL('../src/runtime/runtimes/provision-assets.js', import.meta.url);
    const assets = await import(new URL(assetsUrl.href + '?native=' + randomUUID()).href);
    t.mock.module(assetsUrl, { namedExports: assets });
    const artifactsUrl = new URL('../src/runtime/runtimes/provision-controller-artifacts.js', import.meta.url);
    const artifacts = await import(artifactsUrl.href);
    t.mock.module(artifactsUrl, { namedExports: { ...artifacts,
      nativeInstallPacket: async () => ({ sha256: '42'.repeat(32), policy: { cases: [{
        caseId: 'mount-original', helperDigest: '34'.repeat(32),
        test: 'runtime_provision_install_mount_test.py', testSha256: '56'.repeat(32),
      }] } }),
    } });
    const nativeUrl = new URL('../src/runtime/runtimes/provision-native-install.js', import.meta.url);
    const native = await import(new URL(nativeUrl.href + '?native=' + randomUUID()).href);
    t.mock.module(nativeUrl, { namedExports: native });
    const guestUrl = new URL('../src/runtime/runtimes/provision-controller-guest.js', import.meta.url);
    const guest = await import(guestUrl.href);
    t.mock.module(guestUrl, { namedExports: { ...guest,
      executeOwnedNativeInstallCase: (owner: ProvisionOwner, files: ProvisionAssetFiles) => this.refuse(owner, files),
    } });
  }

  async refuse(owner: ProvisionOwner, files: ProvisionAssetFiles): Promise<never> {
    this.fd = files.rootfs.fd;
    const owned = spawn(process.execPath, ['-e', "process.stdin.resume();"
      + "process.stdin.on('end',()=>process.exit(0));"
      + "process.stdout.write(require('node:fs').readFileSync(3));"],
    { stdio: ['pipe', 'pipe', 'pipe', this.fd], env: { RUN_TMP: this.root, TMPDIR: this.root,
      NODE_COMPILE_CACHE: join(this.root, 'node'), BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(this.root, 'bun') } });
    this.child = owned;
    this.closed = new Promise<void>((resolve, reject) => {
      owned.once('error', reject);
      owned.once('close', code => {
        this.childClosed = true;
        if (code === 0) resolve();
        else reject(new Error('child_exit:' + code));
      });
    });
    const ready = new Promise<void>((resolve, reject) => {
      let received = '';
      owned.stdout?.on('data', (chunk: Buffer) => {
        received += chunk;
        if (received === 'original-native-borrow') resolve();
        else if (received.length >= 22) reject(new Error('child_binding'));
      });
      owned.once('error', reject);
    });
    owner.own({ identity: 'native-owned-fd-child', stop() { owned.stdin?.end(); }, drained: this.closed,
      remove: async () => { assert.equal(this.childClosed, true); return true; } });
    await ready;
    throw new ProvisionError('native_fixture_refused');
  }
}

test('native refusal joins the original asset borrow and real child CLOSE without backend publication',
  { timeout: 10000 }, async t => {
    const root = await mkdtemp(join(await realpath(tmpdir()), 'native-lifetime-'));
    const fixture = new NativeRefusal(root);
    let disposed = false;
    try {
      await fixture.install(t);
      const api: typeof import('../src/runtime/runtimes/provision-backend.js') = await import(
        new URL('../src/runtime/runtimes/provision-backend.js?native=' + randomUUID(), import.meta.url).href);
      const result = await api.observeNativeInstallCase(input(), 'mount-original');
      assert.equal(result.status, 'unavailable');
      assert.equal(result.reason, 'native_fixture_refused');
      assert.equal(result.published, false);
      assert.equal(result.runtimeQualified, false);
      assert.equal(fixture.childClosed, true);
      assert.deepEqual(result.cleanup, { confirmed: true, retained: [], failures: [] });
      assert.equal(result.assetDisposalConfirmed, true);
      assert.throws(() => fstatSync(fixture.fd), { code: 'EBADF' });
      disposed = true;
    } finally {
      fixture.child?.stdin?.end();
      await fixture.closed;
      if (disposed) await rm(root, { recursive: true });
      else console.log('NATIVE_FIXTURE_RETAINED_UNTIL_WORKER_EXIT=' + root);
    }
  });
