import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';
import { validateProvisionAssetCatalog } from './provision-asset-catalog.js';
import { assetGuard, assetRemaining, ProvisionAssetError } from './provision-asset-error.js';
import { AssetDirectory } from './provision-paths.js';
import { prepareAssetPrefix, type PreparedAssetPrefix } from './provision-asset-prefix.js';
import { startAssetUse, finishAssetDirectory, type AssetUse, type AssetDrain } from './provision-asset-lifetime.js';
import { withAssetBorrow, type ProvisionAssetBorrowOwner,
  type ProvisionAssetRetention } from './provision-asset-borrow.js';

export { PROVISION_ASSET_CATALOG, validateProvisionAssetCatalog } from './provision-asset-catalog.js';
export { ProvisionAssetError } from './provision-asset-error.js';
export { ProvisionAssetCleanupPending } from './provision-asset-lifetime.js';
export { retainProvisionAssetBorrow, permitProvisionAssetBorrowReleaseAfterDrain,
  ProvisionAssetRetentionError } from './provision-asset-borrow.js';
export type { ProvisionAssetBorrowOwner, ProvisionAssetRetention,
  AssetDrainPermission } from './provision-asset-borrow.js';

export interface VerifiedProvisionAssets { readonly kind: 'verified-asset-prefix' }
export interface ProvisionAssetFiles {
  readonly limactl: { readonly path: string; readonly fd: number };
  readonly guestagent: { readonly path: string; readonly fd: number };
  readonly rootfs: { readonly path: string; readonly fd: number };
  readonly signal: AbortSignal;
  readonly retentionOwner: ProvisionAssetBorrowOwner;
  readonly retainForDrain: () => ProvisionAssetRetention;
  readonly authentication: {
    readonly publisherTlsAndExpectedDigests: true; readonly vendorCodeSignatureVerified: true;
    readonly detachedSignatureVerified: false; readonly notarizationVerified: false;
    readonly currentHostVzCompatibilityVerified: false; readonly backendVerified: false;
  };
}
interface Owner {
  readonly directory: AssetDirectory;
  readonly prefix: PreparedAssetPrefix;
  readonly signal: AbortSignal;
  active: boolean;
  busy: boolean;
}
const OWNERS = new WeakMap<VerifiedProvisionAssets, Owner>();

/** One borrow encloses all VM/installer/backend consumers and rechecks consumed bytes/FD identity.
 * Arm retainForDrain before consumers. release acknowledges owner drain permission, not physical disposal.
 * Unconfirmed drain keeps FDs/prefix; actual disposal is joined after callback settlement.
 * This is asset access, never VM/backend authority.
 */
export async function withProvisionAssetFiles<T>(handle: VerifiedProvisionAssets,
  use: (files: ProvisionAssetFiles) => Promise<T>): Promise<T> {
  assetGuard(typeof handle === 'object' && handle !== null && !types.isProxy(handle), 'asset_handle_invalid');
  const owner = OWNERS.get(handle);
  assetGuard(owner?.active && !owner.busy, 'asset_handle_invalid');
  assetRemaining(owner.signal);
  owner.busy = true;
  try {
    return await withAssetBorrow({ directory: owner.directory, files: owner.prefix.files, signal: owner.signal,
      revoke: () => { owner.active = false; } }, async view => {
      assetGuard(owner.active, 'asset_handle_invalid');
      const find = (path: string) => {
        const file = view.files.find(f => f.path === path);
        assetGuard(file, 'asset_handle_invalid');
        return file;
      };
      const result = await use(Object.freeze({ limactl: find(owner.prefix.limactl.path),
        guestagent: find(owner.prefix.guestagent.path), rootfs: find(owner.prefix.rootfs.path),
        retentionOwner: view.owner, retainForDrain: view.retainForDrain, signal: owner.signal,
        authentication: Object.freeze({ publisherTlsAndExpectedDigests: true, vendorCodeSignatureVerified: true,
          detachedSignatureVerified: false, notarizationVerified: false,
          currentHostVzCompatibilityVerified: false, backendVerified: false }) }));
      await owner.directory.check();
      return result;
    });
  } catch (error) {
    owner.active = false;
    throw error;
  } finally {
    owner.busy = false;
  }
}

function assetOptions(raw: unknown): { readonly deadlineAt: number; readonly acquisitionDeadlineAt: number } {
  const invalid = (): never => { throw new ProvisionAssetError('options_invalid'); };
  assetGuard(typeof raw === 'object' && raw !== null && !types.isProxy(raw), 'consent_required');
  const consent = Object.getOwnPropertyDescriptor(raw, 'executeTargetConsent');
  assetGuard(consent && 'value' in consent && consent.enumerable && consent.value === true, 'consent_required');
  const snapshot = snapshotJsonData(raw, invalid, invalid);
  assetGuard(snapshot && typeof snapshot === 'object' && !Array.isArray(snapshot), 'options_invalid');
  assetGuard('catalog' in snapshot && 'deadlineAt' in snapshot && 'acquisitionDeadlineAt' in snapshot
    && Object.keys(snapshot).length === 4, 'options_invalid');
  validateProvisionAssetCatalog(snapshot.catalog);
  const deadlineAt = snapshot.deadlineAt, acquisitionDeadlineAt = snapshot.acquisitionDeadlineAt, now = Date.now();
  // Ownership spans acquisition, provisioning, one consumer run, and cleanup; not just provisioning.
  const maximumLifetimeMs = 300000 + 900000 + 900000 + 120000;
  assetGuard(typeof deadlineAt === 'number' && Number.isSafeInteger(deadlineAt)
    && deadlineAt > now && deadlineAt <= now + maximumLifetimeMs
    && typeof acquisitionDeadlineAt === 'number' && Number.isSafeInteger(acquisitionDeadlineAt)
    && acquisitionDeadlineAt > now && acquisitionDeadlineAt <= now + 300000
    && acquisitionDeadlineAt <= deadlineAt, 'options_invalid');
  return { deadlineAt, acquisitionDeadlineAt };
}

/** Trusted integration entry. Design/catalog approval is not startup consent.
 * Caller must drain its use and child resources on signal before returning; no detached asset consumer is allowed.
 */
export async function withProvisionAssets<T>(input: unknown, use: (assets: VerifiedProvisionAssets) => Promise<T>,
  signal?: AbortSignal): Promise<T> {
  const options = assetOptions(input);
  assetGuard(process.platform === 'darwin' && process.arch === 'arm64', 'platform_unavailable');
  assetGuard(!signal || !types.isProxy(signal) && Object.getPrototypeOf(signal) === AbortSignal.prototype
    && Object.getOwnPropertyNames(signal).length === 0, 'options_invalid');
  const lifetime = new AbortController(), externalAbort = () => lifetime.abort();
  signal?.addEventListener('abort', externalAbort, { once: true });
  if (signal?.aborted) lifetime.abort();
  const timer = setTimeout(externalAbort, options.deadlineAt - Date.now());
  let directory: AssetDirectory | undefined, owner: Owner | undefined, callback: AssetUse<T> | undefined;
  try {
    assetRemaining(lifetime.signal);
    directory = await AssetDirectory.create('/private/tmp');
    const acquisitionMs = options.acquisitionDeadlineAt - Date.now();
    assetGuard(acquisitionMs > 0, 'asset_expired');
    const acquisition = AbortSignal.any([lifetime.signal,
      AbortSignal.timeout(acquisitionMs)]);
    const prefix = await prepareAssetPrefix(directory, acquisition);
    owner = { directory, prefix, signal: lifetime.signal, active: true, busy: false };
    const handle: VerifiedProvisionAssets = Object.freeze({ kind: 'verified-asset-prefix' });
    OWNERS.set(handle, owner);
    const invalidate = () => { if (owner) owner.active = false; };
    lifetime.signal.addEventListener('abort', invalidate, { once: true });
    try {
      callback = startAssetUse(() => use(handle), lifetime.signal);
      const result = await callback.result;
      assetRemaining(lifetime.signal);
      return result;
    } finally {
      owner.active = false;
      OWNERS.delete(handle);
      lifetime.signal.removeEventListener('abort', invalidate);
    }
  } finally {
    if (owner) owner.active = false;
    lifetime.abort();
    clearTimeout(timer);
    signal?.removeEventListener('abort', externalAbort);
    const drains: AssetDrain[] = [];
    if (callback) drains.push(callback);
    if (directory) await finishAssetDirectory(directory, drains);
  }
}
