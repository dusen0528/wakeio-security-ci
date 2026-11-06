export type SourceSnapshotCleanupObservation = {
  readonly directory: string | null;
  readonly pending: readonly {
    readonly name: string;
    readonly device: string;
    readonly inode: string;
    readonly slot: string | null;
    readonly location: 'original' | 'operation_pending' | 'unknown';
  }[];
  readonly uncertain: boolean;
};

export class SourceSnapshotError extends Error {
  constructor(
    readonly code: 'consent' | 'input' | 'refused' | 'revoked' | 'cleanup_unknown',
    readonly cleanup: SourceSnapshotCleanupObservation | undefined = undefined,
  ) {
    super(code);
    this.name = 'SourceSnapshotError';
  }
}

type Role = 'build' | 'scanner';
export type Selection = { readonly role: Role; readonly path: string };
type FileReceipt = Selection & { readonly bytes: number; readonly sha256: string };
export type SourceSnapshotObservation = {
  readonly root: string;
  readonly files: readonly FileReceipt[];
};

export function invalid(): never {
  throw new SourceSnapshotError('input');
}

export function record(value: unknown): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
}

export function observation(raw: unknown): SourceSnapshotObservation {
  record(raw);
  const root = raw['root'], rows = raw['files'];
  if (typeof root !== 'string' || !/^\/(?:private\/)?tmp\/wakeio-source-[a-f0-9]{32}$/.test(root)
    || !Array.isArray(rows) || rows.length > 10) throw new SourceSnapshotError('refused');
  const receipts = rows.map((row: unknown): FileReceipt => {
    record(row);
    const role = row['role'], path = row['path'], bytes = row['bytes'], sha256 = row['sha256'];
    if ((role !== 'build' && role !== 'scanner') || typeof path !== 'string'
      || typeof bytes !== 'number' || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > 1024 * 1024
      || typeof sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(sha256)) invalid();
    return Object.freeze({ role, path, bytes, sha256 });
  });
  return Object.freeze({ root, files: Object.freeze(receipts) });
}

/** Recovery locations are terminal diagnostics, never resource-registration inputs. */
export function cleanupObservation(raw: unknown): SourceSnapshotCleanupObservation {
  record(raw);
  const directory = raw['directory'], pending = raw['pending'], uncertain = raw['uncertain'];
  if ((directory !== null && (typeof directory !== 'string'
    || !/^\/(?:private\/)?tmp\/wakeio-source-cleanup-[A-Za-z0-9_-]{6,64}$/.test(directory)))
    || !Array.isArray(pending) || pending.length > 64 || typeof uncertain !== 'boolean') invalid();
  const entries = pending.map((value: unknown) => {
    record(value);
    const name = value['name'], device = value['device'], inode = value['inode'];
    const slot = value['slot'], location = value['location'];
    if (typeof name !== 'string' || !/^[A-Za-z0-9_.-]{1,256}$/.test(name)
      || typeof device !== 'string' || !/^[0-9]{1,30}$/.test(device)
      || typeof inode !== 'string' || !/^[0-9]{1,30}$/.test(inode)
      || (slot !== null && (typeof slot !== 'string' || !/^[0-9]{1,3}$/.test(slot)))
      || (location !== 'original' && location !== 'operation_pending' && location !== 'unknown')) invalid();
    return Object.freeze({ name, device, inode, slot, location });
  });
  return Object.freeze({ directory, pending: Object.freeze(entries), uncertain });
}
