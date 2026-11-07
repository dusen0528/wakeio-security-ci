import type { FileHandle } from 'node:fs/promises';
import { assetGuard, assetRemaining, ProvisionAssetError } from './provision-asset-error.js';
import { AssetDirectory, openBoundAsset, type BoundAssetFile } from './provision-paths.js';

const OWNER = Symbol('asset-borrow-owner'), RETENTION = Symbol('asset-borrow-retention');
export interface ProvisionAssetBorrowOwner { readonly [OWNER]: true }
export interface AssetDrainPermission {
  readonly kind: 'drain-permission-recorded';
  readonly disposalConfirmed: false;
}
export interface ProvisionAssetRetention {
  readonly [RETENTION]: true;
  readonly disposed: Promise<void>;
  release(): Promise<AssetDrainPermission>;
  toJSON(): never;
}
export interface AssetBorrowBinding {
  readonly directory: AssetDirectory;
  readonly files: readonly BoundAssetFile[];
  readonly signal: AbortSignal;
  readonly revoke: () => void;
}
export interface AssetBorrowView {
  readonly owner: ProvisionAssetBorrowOwner;
  readonly files: readonly { readonly path: string; readonly fd: number }[];
  readonly retainForDrain: () => ProvisionAssetRetention;
}
interface BorrowState {
  readonly owner: ProvisionAssetBorrowOwner;
  readonly binding: AssetBorrowBinding;
  readonly files: { readonly path: string; readonly fd: FileHandle }[];
  readonly callbackDrained: Promise<void>;
  readonly finishCallback: () => void;
  readonly disposed: Promise<void>;
  readonly resolveDisposed: () => void;
  readonly rejectDisposed: (error: unknown) => void;
  retention?: ProvisionAssetRetention;
  permission?: Promise<AssetDrainPermission>;
  disposal?: Promise<void>;
}
// Strong ownership is deliberate: unconfirmed resources MUST survive discarded handles/callback failure.
const BORROWS = new Map<object, BorrowState>();
const RETAINED = new Map<object, BorrowState>();
const PERMITTED = new WeakMap<object, {
  readonly owner: ProvisionAssetBorrowOwner; readonly result: Promise<AssetDrainPermission>;
}>();

export class ProvisionAssetRetentionError extends ProvisionAssetError {
  constructor(readonly owner: ProvisionAssetBorrowOwner, readonly retention: ProvisionAssetRetention,
    root: string) {
    super('cleanup_unconfirmed', { retainedDirectory: root });
  }
  toJSON(): { readonly code: string; readonly retained: true } {
    return { code: this.code, retained: true };
  }
}

function retainedError(state: BorrowState): ProvisionAssetRetentionError {
  const retention = retainProvisionAssetBorrow(state.owner);
  return new ProvisionAssetRetentionError(state.owner, retention, state.binding.directory.root);
}

/** Immediate irreversible revocation. Does NOT close descriptors, unlink files, or certify process drain. */
export function retainProvisionAssetBorrow(owner: unknown): ProvisionAssetRetention {
  assetGuard(typeof owner === 'object' && owner !== null, 'asset_handle_invalid');
  const state = BORROWS.get(owner);
  assetGuard(state, 'asset_handle_invalid');
  if (!state.retention) {
    const token: ProvisionAssetRetention = Object.freeze({ [RETENTION]: true as const, disposed: state.disposed,
      release(this: ProvisionAssetRetention) {
        assetGuard(this === token, 'asset_handle_invalid');
        return permitProvisionAssetBorrowReleaseAfterDrain(state.owner, token);
      },
      toJSON(): never { throw new ProvisionAssetError('asset_handle_invalid'); },
    });
    state.retention = token;
    RETAINED.set(token, state);
  }
  state.binding.revoke();
  return state.retention;
}

async function closeBorrow(state: BorrowState): Promise<void> {
  const results = await Promise.allSettled(state.files.map(file => file.fd.close()));
  if (!results.every(result => result.status === 'fulfilled')) throw retainedError(state);
}

/** Same-owner actual-drain permission. Safe to await INSIDE the callback: it does not await disposal.
 * Physical disposal starts only after callback settlement; token.disposed is its actual joined outcome.
 */
export function permitProvisionAssetBorrowReleaseAfterDrain(owner: unknown,
  retention: unknown): Promise<AssetDrainPermission> {
  assetGuard(typeof owner === 'object' && owner !== null && typeof retention === 'object'
    && retention !== null, 'asset_handle_invalid');
  const permitted = PERMITTED.get(retention);
  if (permitted) {
    assetGuard(permitted.owner === owner, 'asset_handle_invalid');
    return permitted.result;
  }
  const state = RETAINED.get(retention);
  assetGuard(state && state.owner === owner && BORROWS.get(owner) === state, 'asset_handle_invalid');
  if (!state.permission) {
    state.permission = Promise.resolve<AssetDrainPermission>(Object.freeze({ kind: 'drain-permission-recorded',
      disposalConfirmed: false }));
    state.disposal = state.callbackDrained.then(async () => {
      await closeBorrow(state);
      await state.binding.directory.cleanup();
      RETAINED.delete(retention);
      BORROWS.delete(owner);
    });
    state.disposal.then(state.resolveDisposed, state.rejectDisposed);
  }
  PERMITTED.set(retention, { owner: state.owner, result: state.permission });
  return state.permission;
}

export function retainedAssetDirectory(directory: AssetDirectory): ProvisionAssetRetentionError | undefined {
  for (const state of BORROWS.values()) {
    if (state.binding.directory === directory && state.retention) return retainedError(state);
  }
  return undefined;
}

function createBorrow(binding: AssetBorrowBinding): BorrowState {
  const owner: ProvisionAssetBorrowOwner = Object.freeze({ [OWNER]: true as const });
  let finishCallback = () => {};
  const callbackDrained = new Promise<void>(resolve => { finishCallback = resolve; });
  let resolveDisposed = () => {}, rejectDisposed: (error: unknown) => void = () => {};
  const disposed = new Promise<void>((resolve, reject) => {
    resolveDisposed = resolve; rejectDisposed = reject;
  });
  return { owner, binding, files: [], callbackDrained, finishCallback, disposed, resolveDisposed, rejectDisposed };
}

/** No attestation. One borrow encloses all consumers; return/throw/abort cannot manufacture drain. */
export async function withAssetBorrow<T>(binding: AssetBorrowBinding,
  use: (view: AssetBorrowView) => Promise<T>): Promise<T> {
  assetRemaining(binding.signal);
  const state = createBorrow(binding);
  BORROWS.set(state.owner, state);
  const onAbort = () => { retainProvisionAssetBorrow(state.owner); };
  binding.signal.addEventListener('abort', onAbort, { once: true });
  let outcome: { readonly kind: 'returned'; readonly value: T } | { readonly kind: 'threw'; readonly error: unknown };
  try {
    if (binding.signal.aborted) onAbort();
    for (const file of binding.files) {
      assetRemaining(binding.signal);
      await binding.directory.check();
      state.files.push({ path: file.path, fd: await openBoundAsset(file, binding.signal) });
    }
    assetRemaining(binding.signal);
    const value = await use(Object.freeze({ owner: state.owner,
      retainForDrain: () => retainProvisionAssetBorrow(state.owner),
      files: Object.freeze(state.files.map(file => Object.freeze({ path: file.path, fd: file.fd.fd }))) }));
    outcome = { kind: 'returned', value };
  } catch (error) {
    retainProvisionAssetBorrow(state.owner);
    outcome = { kind: 'threw', error };
  } finally {
    binding.signal.removeEventListener('abort', onAbort);
    state.finishCallback();
  }
  if (!state.permission) {
    const retained = retainedError(state);
    throw retained;
  }
  try { await state.disposed; }
  catch (error) { const retained = retainedError(state); retained.cause = error; throw retained; }
  switch (outcome.kind) {
    case 'threw': throw outcome.error;
    case 'returned': assetRemaining(binding.signal); return outcome.value;
    default: { const exhaustive: never = outcome; throw new TypeError(String(exhaustive)); }
  }
}
