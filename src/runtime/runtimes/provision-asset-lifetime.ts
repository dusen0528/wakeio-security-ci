import { assetRemaining, ProvisionAssetError } from './provision-asset-error.js';
import type { AssetDirectory } from './provision-paths.js';
import { retainedAssetDirectory } from './provision-asset-borrow.js';

export interface AssetDrain {
  readonly drained: Promise<void>;
  readonly isDrained: () => boolean;
}
export interface AssetUse<T> extends AssetDrain { readonly result: Promise<T> }

export class ProvisionAssetCleanupPending extends ProvisionAssetError {
  constructor(root: string, readonly drained: Promise<void>,
    readonly cleanupAfterDrain: () => Promise<void>) {
    super('cleanup_unconfirmed', { retainedDirectory: root });
  }
}

/** Subscribe before callback dispatch. Timeout/abort is sticky, never a polling/retry strategy. */
export async function runAssetUse<T>(use: () => Promise<T>, signal: AbortSignal): Promise<T> {
  let onAbort = () => {};
  const cancelled = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(new ProvisionAssetError('asset_expired'));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    assetRemaining(signal);
    const result = await Promise.race([Promise.resolve().then(use), cancelled]);
    assetRemaining(signal);
    return result;
  } finally { signal.removeEventListener('abort', onAbort); }
}

/** The result can reject on abort; drained resolves ONLY when the actual callback has settled. */
export function startAssetUse<T>(use: () => Promise<T>, signal: AbortSignal): AssetUse<T> {
  let settled = false;
  const operation = Promise.resolve().then(() => { assetRemaining(signal); return use(); });
  const drained = operation.then(() => { settled = true; }, () => { settled = true; });
  const result = runAssetUse(() => operation, signal);
  return Object.freeze({ result, drained, isDrained: () => settled });
}

/** No timeout, aborted flag, or result rejection is evidence that consumers have drained. */
export async function finishAssetDirectory(directory: AssetDirectory, uses: readonly AssetDrain[]): Promise<void> {
  const retained = retainedAssetDirectory(directory);
  if (retained) throw retained;
  const drained = Promise.all(uses.map(use => use.drained)).then(() => undefined);
  if (!uses.every(use => use.isDrained())) {
    let cleaning: Promise<void> | undefined;
    const cleanupAfterDrain = () => cleaning ??= drained.then(() => {
      const pending = retainedAssetDirectory(directory);
      if (pending) throw pending;
      return directory.cleanup();
    });
    throw new ProvisionAssetCleanupPending(directory.root, drained, cleanupAfterDrain);
  }
  await directory.cleanup();
}
