import { createGunzip } from 'node:zlib';
import { PassThrough } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { SelectedAsset } from './provision-asset-catalog.js';
import { assetGuard } from './provision-asset-error.js';
import { archivePath, checkAsset, openBoundAsset, type BoundAssetFile } from './provision-paths.js';
import { writeAssetStream, type AssetWrite } from './provision-asset-transfer.js';
import { assetTool, toolText, type AssetToolOptions } from './provision-asset-tool.js';
import { verifySelectedFormat } from './provision-asset-format.js';

export interface ArchiveExpectations {
  readonly archiveEntries: number;
  readonly regularEntries: number;
  readonly regularBytes: number;
  readonly selected: readonly SelectedAsset[];
}
type Entry = { readonly path: string; readonly archivePath: string; readonly type: string;
  readonly bytes: number; readonly mode: string };

/** libarchive is the archive parser; this closed adapter validates every reported member before materialization. */
export function validateArchiveListing(text: string, expected: ArchiveExpectations): readonly Entry[] {
  assetGuard(text.endsWith('\n') && !/[^\x20-\x7e\n]/.test(text), 'archive_invalid');
  const lines = text.slice(0, -1).split('\n'), entries: Entry[] = [], names = new Set<string>();
  assetGuard(lines.length === expected.archiveEntries && lines.length <= 2048, 'archive_invalid');
  let bytes = 0, regular = 0;
  for (const line of lines) {
    const pattern = '^([-dl][rwx-]{9})\\s+\\d+\\s+\\d+\\s+\\d+\\s+(\\d+)\\s+'
      + '[A-Z][a-z]{2}\\s+\\d{1,2}\\s+(?:\\d\\d:\\d\\d|\\d{4})\\s+(.+)$';
    const match = new RegExp(pattern).exec(line);
    assetGuard(match, 'archive_invalid');
    const [, mode = '', size = '', member = ''] = match, type = mode[0], count = Number(size);
    assetGuard(type && Number.isSafeInteger(count) && count >= 0 && count <= 128 * 1024 * 1024
      && mode[5] !== 'w' && mode[8] !== 'w', 'archive_invalid');
    const alias = member === './share/doc/lima/templates -> ../../lima/templates' && type === 'l';
    assetGuard(type !== 'l' || alias, 'archive_invalid');
    const name = alias ? './share/doc/lima/templates' : member;
    assetGuard(!name.endsWith('/') || type === 'd', 'archive_invalid');
    const path = name === './' && type === 'd' ? '.' : archivePath(name);
    assetGuard(!names.has(path.toLowerCase()), 'archive_invalid');
    names.add(path.toLowerCase());
    if (type === '-') { regular++; bytes += count; }
    else assetGuard(count === 0, 'archive_invalid');
    assetGuard(bytes <= 512 * 1024 * 1024, 'archive_invalid');
    entries.push({ path, archivePath: name, type, bytes: count, mode });
  }
  for (const entry of entries) {
    const parts = entry.path.split('/');
    for (let i = 1; i < parts.length; i++) {
      const parent = entries.find(e => e.path === parts.slice(0, i).join('/'));
      assetGuard(parent?.type === 'd', 'archive_invalid');
    }
  }
  assetGuard(regular === expected.regularEntries && bytes === expected.regularBytes, 'archive_invalid');
  for (const selected of expected.selected) {
    const member = entries.find(e => e.path === selected.path);
    assetGuard(member?.type === '-' && member.bytes === selected.bytes
      && (selected.mode === 0o555 ? member.mode === '-rwxr-xr-x' : member.mode === '-rw-r--r--'),
    'archive_invalid');
  }
  return entries;
}

export async function inflateAssetArchive(archive: BoundAssetFile, output: AssetWrite): Promise<BoundAssetFile> {
  const fd = await openBoundAsset(archive, output.signal);
  const source = fd.createReadStream({ autoClose: false }), inflated = new PassThrough();
  const pumping = pipeline(source, createGunzip(), inflated, { signal: output.signal });
  try {
    const results = await Promise.allSettled([writeAssetStream(inflated, output), pumping]);
    const [written, pumped] = results;
    if (written.status === 'rejected') throw written.reason;
    if (pumped.status === 'rejected') throw pumped.reason;
    await checkAsset(archive, output.signal);
    return written.value;
  } finally {
    source.destroy(); inflated.destroy();
    await fd.close();
  }
}

export async function materializeAssetPrefix(archive: BoundAssetFile, expected: ArchiveExpectations,
  output: Omit<AssetWrite, 'relative' | 'limit'>): Promise<readonly BoundAssetFile[]> {
  const tar = await inflateAssetArchive(archive, { ...output, relative: 'cache/bundle.tar', limit: 512 * 1024 ** 2 });
  const listFd = await openBoundAsset(tar, output.signal);
  let listing: string;
  try {
    listing = await assetTool({ tool: '/usr/bin/bsdtar', args: ['--numeric-owner', '-tvf', '/dev/fd/3'] },
      { cwd: output.directory.root, signal: output.signal, inputFd: listFd.fd }, toolText);
  } finally { await listFd.close(); }
  const entries = validateArchiveListing(listing, expected), files: BoundAssetFile[] = [];
  for (const selected of expected.selected) {
    const entry = entries.find(e => e.path === selected.path);
    assetGuard(entry, 'archive_invalid');
    const fd = await openBoundAsset(tar, output.signal);
    try {
      const options: AssetToolOptions = { cwd: output.directory.root, signal: output.signal, inputFd: fd.fd };
      const file = await assetTool({ tool: '/usr/bin/bsdtar', args: ['-xOf', '/dev/fd/3', '--', entry.archivePath] },
        options, stream => writeAssetStream(stream, { ...output,
          relative: 'tools/lima-1.0.3/' + selected.path, limit: selected.bytes }, selected));
      const read = await openBoundAsset(file, output.signal);
      try { await verifySelectedFormat(read, selected.format); } finally { await read.close(); }
      files.push(file);
    } finally { await fd.close(); }
    await checkAsset(tar, output.signal);
  }
  return Object.freeze(files);
}
