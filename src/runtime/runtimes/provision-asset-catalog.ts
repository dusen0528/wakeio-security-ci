import { isDeepStrictEqual } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';
import { assetGuard, ProvisionAssetError } from './provision-asset-error.js';

export interface AssetPin {
  readonly url: string;
  readonly bytes: number;
  readonly sha256: string;
}
export interface SelectedAsset {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly mode: number;
  readonly format: 'macho-arm64' | 'elf-aarch64' | 'version' | 'license';
}

// Public publisher integrity expectations only. No approval, provenance, or execution authority.
const BASE = 'https://github.com/lima-vm/lima/releases/download/v1.0.3/';
const ROOT = 'https://cloud-images.ubuntu.com/releases/noble/release-20261017/';
const SELECTED: readonly SelectedAsset[] = Object.freeze([
  Object.freeze({ path: 'bin/limactl', bytes: 28162688, mode: 0o555, format: 'macho-arm64',
    sha256: '6eaef00c03e479f5cff53f55106085bcf5d57b80fd6935b3d090562af812b927' }),
  Object.freeze({ path: 'share/lima/lima-guestagent.Linux-aarch64', bytes: 47120536,
    mode: 0o444, format: 'elf-aarch64',
    sha256: '76a7be69469f607c48c8e9f753045fcd7c8361cf2aaf3cd467d3669dddcbeb9a' }),
  Object.freeze({ path: 'share/doc/lima/VERSION', bytes: 7, mode: 0o444, format: 'version',
    sha256: '49a83c617e37f8a9fb1f3f393f1d17399cf63a911cb43eba0493389f84d02d61' }),
  Object.freeze({ path: 'share/doc/lima/LICENSE', bytes: 11358, mode: 0o444, format: 'license',
    sha256: 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30' }),
]);

export const PROVISION_ASSET_CATALOG = Object.freeze({
  version: 1, platform: 'darwin-arm64', limaVersion: '1.0.3',
  checksum: Object.freeze({ url: BASE + 'SHA256SUMS', bytes: 488,
    sha256: '69423d9f9044fc9264925d24cd38c1d0efb4367cfb46c568313f53d6f0ed7ee2' }),
  archive: Object.freeze({ url: BASE + 'lima-1.0.3-Darwin-arm64.tar.gz', bytes: 61608689,
    sha256: '5033cadcf49b0297bac897c5b81ee5f9f83858327e6e08609f06f46e8c56dd2f' }),
  rootfs: Object.freeze({ url: ROOT + 'ubuntu-24.04-server-cloudimg-arm64.img', bytes: 616522752,
    sha256: '50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e' }),
  selected: SELECTED,
  archiveEntries: 110, regularEntries: 99, regularBytes: 215170982,
});
export type ProvisionAssetCatalog = typeof PROVISION_ASSET_CATALOG;

/** Exact closed expectation set. The caller cannot select a URL, newer pin, companion, or extra field. */
export function validateProvisionAssetCatalog(input: unknown): ProvisionAssetCatalog {
  const invalid = (): never => { throw new ProvisionAssetError('catalog_invalid'); };
  const actual = snapshotJsonData(input, invalid, invalid);
  assetGuard(isDeepStrictEqual(actual, snapshotJsonData(PROVISION_ASSET_CATALOG)), 'catalog_invalid');
  return PROVISION_ASSET_CATALOG;
}

export function verifyChecksumManifest(bytes: Buffer): void {
  const rows = bytes.toString('ascii').trimEnd().split('\n');
  assetGuard(rows.every(row => /^[a-f0-9]{64}  [A-Za-z0-9_.-]+$/.test(row)), 'asset_integrity');
  const selected = rows.filter(row => row.endsWith('  lima-1.0.3-Darwin-arm64.tar.gz'));
  assetGuard(selected.length === 1
    && selected[0] === PROVISION_ASSET_CATALOG.archive.sha256 + '  lima-1.0.3-Darwin-arm64.tar.gz',
  'asset_integrity');
}
