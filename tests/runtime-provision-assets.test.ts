import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PROVISION_ASSET_CATALOG, validateProvisionAssetCatalog, withProvisionAssets,
  withProvisionAssetFiles, ProvisionAssetError } from '../src/runtime/runtimes/provision-assets.js';
import { archivePath, AssetDirectory } from '../src/runtime/runtimes/provision-paths.js';
import { runAssetUse } from '../src/runtime/runtimes/provision-asset-lifetime.js';

test('asset catalog accepts exact own data and rejects any pin or authority substitution', () => {
  const catalog = structuredClone(PROVISION_ASSET_CATALOG);
  assert.equal(validateProvisionAssetCatalog(catalog), PROVISION_ASSET_CATALOG);
  for (const changed of [
    { ...catalog, archive: { ...catalog.archive, sha256: '0'.repeat(64) } },
    { ...catalog, rootfs: { ...catalog.rootfs, bytes: catalog.rootfs.bytes - 1 } },
    { ...catalog, archive: { ...catalog.archive, url: 'https://example.com/latest' } },
    { ...catalog, backendVerified: true },
    { ...catalog, selected: catalog.selected.slice(1) },
  ]) assert.throws(() => validateProvisionAssetCatalog(changed), { code: 'catalog_invalid' });
  assert.equal(Object.isFrozen(PROVISION_ASSET_CATALOG.selected[0]), true);
});

test('consent rejects getters proxies inherited and absent values without invoking caller code', async () => {
  let calls = 0;
  const getter = Object.defineProperty({}, 'executeTargetConsent', {
    enumerable: true, get() { calls++; throw new Error('getter_invoked'); },
  });
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { calls++; throw new Error('proxy_invoked'); } });
  const invalid = Object.defineProperty({ executeTargetConsent: false }, 'catalog', {
    enumerable: true, get() { calls++; throw new Error('catalog_invoked'); },
  });
  for (const input of [null, {}, getter, proxy, invalid,
    Object.create({ executeTargetConsent: true }), { executeTargetConsent: 1 }]) {
    await assert.rejects(withProvisionAssets(input, async () => { calls++; }), { code: 'consent_required' });
  }
  const approvedGetter = Object.defineProperty({ executeTargetConsent: true }, 'catalog', {
    enumerable: true, get() { calls++; throw new Error('catalog_invoked'); },
  });
  await assert.rejects(withProvisionAssets(approvedGetter, async () => { calls++; }), { code: 'options_invalid' });
  assert.equal(calls, 0);
});

test('catalog and deadline failures reject at asset ingress', async () => {
  const input = { executeTargetConsent: true, catalog: PROVISION_ASSET_CATALOG,
    acquisitionDeadlineAt: Date.now() + 10000, deadlineAt: Date.now() + 20000 };
  await assert.rejects(withProvisionAssets({ ...input, catalog: {} }, async () => {}), { code: 'catalog_invalid' });
  await assert.rejects(withProvisionAssets({ ...input, deadlineAt: 1 }, async () => {}), { code: 'options_invalid' });
  await assert.rejects(withProvisionAssets({ ...input, extra: true }, async () => {}), { code: 'options_invalid' });
});

test('aborted and accessor-bearing signals reject before acquisition without invoking their hooks', async () => {
  const input = { executeTargetConsent: true, catalog: PROVISION_ASSET_CATALOG,
    acquisitionDeadlineAt: Date.now() + 10000, deadlineAt: Date.now() + 20000 };
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  await assert.rejects(withProvisionAssets(input, async () => { calls++; }, controller.signal),
    { code: 'asset_expired' });
  const accessor = new AbortController().signal;
  Object.defineProperty(accessor, 'aborted', { get() { calls++; throw new Error('must_not_run'); } });
  const proxy = new Proxy(new AbortController().signal,
    { getPrototypeOf() { calls++; throw new Error('must_not_run'); } });
  for (const signal of [accessor, proxy]) {
    await assert.rejects(withProvisionAssets(input, async () => { calls++; }, signal), { code: 'options_invalid' });
  }
  assert.equal(calls, 0);
});

test('JSON lookalikes and proxies cannot recreate a private verified asset handle', async () => {
  let calls = 0;
  const forged = { kind: 'verified-asset-prefix' } as const;
  for (const handle of [forged, Object.freeze({ ...forged }), new Proxy(forged, {})]) {
    await assert.rejects(withProvisionAssetFiles(handle, async () => { calls++; }), { code: 'asset_handle_invalid' });
  }
  assert.equal(calls, 0);
});

test('archive paths reject absolute traversal encoding controls and ambiguous separators', () => {
  for (const path of ['/bin/x', '../x', 'a/../x', 'a//x', '././x', 'x\\y', 'x%2fy', 'x\n', '', '.']) {
    assert.throws(() => archivePath(path), ProvisionAssetError);
  }
  assert.equal(archivePath('./share/lima/agent'), 'share/lima/agent');
});

test('private directory refuses a symlinked base without creating a prefix', async () => {
  // macOS tmpdir resolves through /var; a caller must pass its canonical spelling instead.
  const { realpath, symlink, unlink } = await import('node:fs/promises');
  const base = await mkdtemp(join(await realpath(tmpdir()), 'asset-base-'));
  const alias = join(base, 'alias');
  try {
    await symlink(base, alias);
    await assert.rejects(AssetDirectory.create(alias), { code: 'identity_changed' });
  } finally { await unlink(alias); await rmdir(base); }
});

test('asset callback abort is subscribed before dispatch and remains invalid after late completion', async () => {
  const controller = new AbortController();
  let finish: (value: number) => void = () => { throw new Error('not_dispatched'); };
  let started: () => void = () => { throw new Error('not_subscribed'); };
  const ready = new Promise<void>(resolve => { started = resolve; });
  const running = runAssetUse(() => new Promise<number>(resolve => { finish = resolve; started(); }),
    controller.signal);
  await ready;
  controller.abort();
  await assert.rejects(running, { code: 'asset_expired' });
  finish(123);
  let calls = 0;
  await assert.rejects(runAssetUse(async () => { calls++; return 1; }, controller.signal),
    { code: 'asset_expired' });
  assert.equal(calls, 0);
});
