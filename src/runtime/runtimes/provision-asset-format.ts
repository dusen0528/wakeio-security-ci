import type { FileHandle } from 'node:fs/promises';
import type { SelectedAsset } from './provision-asset-catalog.js';
import { assetGuard } from './provision-asset-error.js';

/** Header recognition supplements exact whole-file hashes; it never attests executable compatibility. */
export async function verifySelectedFormat(fd: FileHandle, format: SelectedAsset['format']): Promise<void> {
  const header = Buffer.alloc(64);
  const read = await fd.read(header, 0, header.length, 0);
  switch (format) {
    case 'macho-arm64':
      assetGuard(read.bytesRead === 64 && header.readUInt32LE(0) === 0xfeedfacf
        && header.readUInt32LE(4) === 0x0100000c && header.readUInt32LE(12) === 2, 'asset_integrity');
      break;
    case 'elf-aarch64':
      assetGuard(read.bytesRead === 64 && header.subarray(0, 6).equals(Buffer.from([127, 69, 76, 70, 2, 1]))
        && header.readUInt16LE(18) === 183, 'asset_integrity');
      break;
    case 'version':
      assetGuard(header.subarray(0, read.bytesRead).equals(Buffer.from('v1.0.3\n')), 'asset_integrity');
      break;
    case 'license':
      assetGuard(read.bytesRead === 64 && !header.includes(0), 'asset_integrity');
      break;
    default: {
      const exhaustive: never = format;
      throw new TypeError(String(exhaustive));
    }
  }
}

export async function verifyRootfsFormat(fd: FileHandle): Promise<void> {
  const header = Buffer.alloc(104);
  const read = await fd.read(header, 0, header.length, 0), version = header.readUInt32BE(4);
  assetGuard(read.bytesRead === 104 && header.readUInt32BE(0) === 0x514649fb
    && [2, 3].includes(version) && header.readBigUInt64BE(8) === 0n && header.readUInt32BE(16) === 0
    && header.readUInt32BE(20) >= 9 && header.readUInt32BE(20) <= 21
    && header.readBigUInt64BE(24) > 0n && header.readBigUInt64BE(24) <= 40n * 1024n ** 3n
    && header.readUInt32BE(32) === 0 && header.readUInt32BE(60) === 0, 'asset_integrity');
  if (version === 3) assetGuard(header.readBigUInt64BE(72) === 0n
    && header.readUInt32BE(100) >= 104, 'asset_integrity');
}
