export type AssetFailure = 'consent_required' | 'catalog_invalid' | 'options_invalid' | 'asset_integrity'
  | 'archive_invalid' | 'identity_changed' | 'asset_expired' | 'tool_failed' | 'platform_unavailable'
  | 'asset_transfer' | 'cleanup_unconfirmed' | 'asset_handle_invalid';

export class ProvisionAssetError extends Error {
  readonly name = 'ProvisionAssetError';
  readonly retainedDirectory: string | undefined;
  constructor(readonly code: AssetFailure, options?: ErrorOptions & { readonly retainedDirectory?: string }) {
    super(code, options);
    this.retainedDirectory = options?.retainedDirectory;
  }
  toJSON(): { readonly code: string } { return { code: this.code }; }
}

export function assetGuard(condition: unknown, code: AssetFailure): asserts condition {
  if (!condition) throw new ProvisionAssetError(code);
}

export function assetRemaining(signal: AbortSignal): void {
  if (signal.aborted) throw new ProvisionAssetError('asset_expired');
}
