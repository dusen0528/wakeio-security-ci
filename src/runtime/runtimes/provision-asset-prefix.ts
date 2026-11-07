import { chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { PROVISION_ASSET_CATALOG, verifyChecksumManifest } from './provision-asset-catalog.js';
import { assetGuard, assetRemaining } from './provision-asset-error.js';
import { AssetDirectory, checkAsset, hashAsset, openBoundAsset, type BoundAssetFile } from './provision-paths.js';
import { downloadAsset } from './provision-asset-transfer.js';
import { materializeAssetPrefix } from './provision-asset-archive.js';
import { assetTool, toolText } from './provision-asset-tool.js';
import { verifyRootfsFormat } from './provision-asset-format.js';

export interface PreparedAssetPrefix {
  readonly files: readonly BoundAssetFile[];
  readonly limactl: BoundAssetFile;
  readonly guestagent: BoundAssetFile;
  readonly rootfs: BoundAssetFile;
}

/** Acquisition only. It never executes limactl, opens an image in VZ, or issues backend authority. */
export async function prepareAssetPrefix(directory: AssetDirectory,
  signal: AbortSignal): Promise<PreparedAssetPrefix> {
  const catalog = PROVISION_ASSET_CATALOG;
  const checksum = await downloadAsset(catalog.checksum,
    { directory, relative: 'cache/SHA256SUMS', limit: catalog.checksum.bytes, signal });
  const checksumFd = await openBoundAsset(checksum, signal);
  try { verifyChecksumManifest(await checksumFd.readFile()); } finally { await checksumFd.close(); }
  await assetTool({ tool: '/usr/bin/codesign', args: ['--verify', '--strict', '/usr/bin/bsdtar'] },
    { cwd: directory.root, signal }, toolText);
  const archive = await downloadAsset(catalog.archive,
    { directory, relative: 'cache/lima.tar.gz', limit: catalog.archive.bytes, signal });
  const selected = await materializeAssetPrefix(archive, catalog, { directory, signal });
  const limactlPath = join(directory.root, 'tools/lima-1.0.3/bin/limactl');
  await assetTool({ tool: '/usr/bin/codesign',
    args: ['--verify', '--strict', '--all-architectures', limactlPath] },
  { cwd: directory.root, signal }, toolText);
  const entitlements = await assetTool({ tool: '/usr/bin/codesign',
    args: ['--display', '--entitlements', ':-', limactlPath] },
  { cwd: directory.root, signal }, toolText);
  assetGuard(/<key>com\.apple\.security\.virtualization<\/key>\s*<true\s*\/>/.test(entitlements),
    'platform_unavailable');
  for (const entry of catalog.selected) {
    assetRemaining(signal);
    await directory.check();
    await chmod(join(directory.root, 'tools/lima-1.0.3', entry.path), entry.mode);
  }
  const files: BoundAssetFile[] = [];
  for (const [index, file] of selected.entries()) {
    const current = await hashAsset(file.path, signal), pin = catalog.selected[index];
    assetGuard(pin && current.sha256 === pin.sha256 && current.identity.size === pin.bytes, 'asset_integrity');
    files.push(current);
  }
  const limactl = files.find(f => f.path === limactlPath);
  const guestagent = files.find(f => f.path.endsWith('/share/lima/lima-guestagent.Linux-aarch64'));
  assetGuard(limactl && guestagent, 'asset_integrity');
  const rootfs = await downloadAsset(catalog.rootfs,
    { directory, relative: 'images/rootfs.img', limit: catalog.rootfs.bytes, signal });
  const rootFd = await openBoundAsset(rootfs, signal);
  try { await verifyRootfsFormat(rootFd); } finally { await rootFd.close(); }
  for (const file of [...files, checksum, archive, rootfs]) await checkAsset(file, signal);
  await directory.freeze();
  return Object.freeze({ files: Object.freeze([...files, checksum, archive, rootfs]), limactl, guestagent, rootfs });
}
