import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve } from 'node:path';
import { types } from 'node:util';
import type { SourceSnapshotEvidence } from '../contracts.js';
import type { SourceSnapshot } from './types.js';
import { COLLECTION_MAX_BYTES, COLLECTION_MAX_FILES, sanitiseCollectionBudget } from './collection-budget.js';

/** Hash only the immutable collected strings used by the detectors. Never expose file/hash lists. */
export function sourceSnapshotEvidence(snapshot: SourceSnapshot, outDir?: string): SourceSnapshotEvidence {
  const hash = createHash('sha256');
  hash.update(JSON.stringify(['source-snapshot-v1', snapshot.collectionBudget ?? null]));
  for (const file of [...snapshot.files].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) {
    // JSON framing preserves embedded separators and string boundaries.
    hash.update(JSON.stringify([file.path, file.category, file.sensitive, file.bytes, file.text]));
  }
  const output = outDir === undefined ? undefined : relative(resolve(snapshot.root), resolve(outDir));
  return {
    revision: 'source-snapshot-v1', basis: 'collected_utf8_strings', algorithm: 'sha256', digest: hash.digest('hex'),
    filesSelected: snapshot.files.length, bytesSelected: snapshot.totalBytes,
    complete: snapshot.complete && !snapshot.rootError && !!sanitiseCollectionBudget(snapshot.collectionBudget),
    outputDirectoryExcluded: output !== undefined && (output === '' || output !== '..' && !output.startsWith('../') && !output.startsWith('..\\') && !isAbsolute(output)),
  };
}

/** Closed data shape; missing/malformed legacy metadata stays unknown. */
export function sanitiseSourceSnapshotEvidence(input: unknown): SourceSnapshotEvidence | undefined {
  if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input)) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = ['revision', 'basis', 'algorithm', 'digest', 'filesSelected', 'bytesSelected', 'complete', 'outputDirectoryExcluded'];
  if (Reflect.ownKeys(descriptors).length !== keys.length || !keys.every(key => descriptors[key]?.enumerable && Object.hasOwn(descriptors[key], 'value'))) return undefined;
  const value = input as Record<string, unknown>;
  if (value.revision !== 'source-snapshot-v1' || value.basis !== 'collected_utf8_strings' || value.algorithm !== 'sha256'
    || typeof value.digest !== 'string' || !/^[a-f0-9]{64}$/.test(value.digest)
    || !Number.isSafeInteger(value.filesSelected) || Number(value.filesSelected) < 0 || Number(value.filesSelected) > COLLECTION_MAX_FILES
    || !Number.isSafeInteger(value.bytesSelected) || Number(value.bytesSelected) < 0 || Number(value.bytesSelected) > COLLECTION_MAX_BYTES
    || typeof value.complete !== 'boolean' || typeof value.outputDirectoryExcluded !== 'boolean') return undefined;
  return { revision: 'source-snapshot-v1', basis: 'collected_utf8_strings', algorithm: 'sha256', digest: value.digest,
    filesSelected: Number(value.filesSelected), bytesSelected: Number(value.bytesSelected), complete: value.complete,
    outputDirectoryExcluded: value.outputDirectoryExcluded };
}

export function sameSourceSnapshot(left: SourceSnapshotEvidence | undefined, right: SourceSnapshotEvidence | undefined): boolean {
  return !!left && !!right && JSON.stringify(left) === JSON.stringify(right);
}
