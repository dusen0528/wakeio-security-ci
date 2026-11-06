import { constants as systemConstants } from 'node:os';

export const PROVIDERS = ['codex', 'claude', 'mixed', 'fixed'] as const;
export const AUTH_STATES = ['anonymous', 'user', 'other_user', 'admin'] as const;
export const PARAM_LOCATIONS = ['query', 'body', 'header', 'path', 'cookie'] as const;
export const FINDING_STATES = ['candidate', 'confirmed', 'rejected'] as const;
export const TASK_STATUSES = ['queued', 'running', 'completed', 'partial', 'error', 'skipped'] as const;
export const RUN_STATUSES = ['running', 'completed', 'partial', 'error'] as const;
export type Provider = typeof PROVIDERS[number];
export type AuthState = typeof AUTH_STATES[number];
export type ParamLocation = typeof PARAM_LOCATIONS[number];
export type FindingState = typeof FINDING_STATES[number];
export type TaskStatus = typeof TASK_STATUSES[number];
export type RunStatus = typeof RUN_STATUSES[number];

type StoreErrorCode = 'node_sqlite_unavailable' | 'unsupported_version' | 'legacy_evidence_untrusted'
  | 'unsafe_path' | 'storage_error' | 'invalid_input' | 'invalid_transition' | 'not_found';
export class RunStoreError extends Error {
  constructor(readonly code: StoreErrorCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
  }
}
export function requireSqliteRuntime(): void {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(process.versions.node);
  if (!match) throw new RunStoreError('node_sqlite_unavailable');
  const major = Number(match[1]), minor = Number(match[2]);
  if (!(major === 22 && minor >= 13 || major === 23 && minor >= 4 || major >= 24)) {
    throw new RunStoreError('node_sqlite_unavailable');
  }
}

export interface NativeSqliteCode {
  readonly code: 'ERR_SQLITE_ERROR';
  readonly extended: number;
  readonly primary: number;
}
export function nativeSqliteCode(error: unknown): NativeSqliteCode | undefined {
  if (!(error instanceof Error) || !('code' in error) || error.code !== 'ERR_SQLITE_ERROR'
    || !('errcode' in error) || typeof error.errcode !== 'number'
    || !Number.isInteger(error.errcode) || error.errcode < 0 || error.errcode > 0x7fffffff) return;
  return { code: 'ERR_SQLITE_ERROR', extended: error.errcode, primary: error.errcode & 0xff };
}
export type InitializationPrimary =
  | { readonly kind: 'contract'; readonly error: RunStoreError }
  | { readonly kind: 'native'; readonly sqlite: NativeSqliteCode }
  | { readonly kind: 'unexpected'; readonly error: unknown };
export type RollbackDisposition =
  | { readonly kind: 'not_started' | 'explicit_rollback_completed' }
  | { readonly kind: 'sqlite_already_ended'; readonly failure: NativeSqliteCode }
  | { readonly kind: 'unknown'; readonly failure: NativeSqliteCode | undefined };
export type InitializationPhase = 'preflight' | 'configure' | 'begin' | 'migration' | 'version' | 'commit';
export class InitializationFailure extends Error {
  constructor(
    readonly primary: InitializationPrimary,
    readonly phase: InitializationPhase,
    readonly rollback: RollbackDisposition,
  ) {
    super('run_database_initialization_failed');
  }
}
export function initializationPrimary(error: unknown): InitializationPrimary {
  if (error instanceof RunStoreError) return { kind: 'contract', error };
  const sqlite = nativeSqliteCode(error);
  return sqlite ? { kind: 'native', sqlite } : { kind: 'unexpected', error };
}

export type ArtifactCode = StoreErrorCode | 'source_requires_snapshot' | 'source_changed' | 'input_limit'
  | 'corrupt_input' | 'invalid_record' | 'destination_exists' | 'migration_failed' | 'cleanup_failed';
export type ArtifactPhase = 'source' | 'copy' | 'inspect' | 'migrate' | 'publish' | 'cleanup';
export type Publication = 'absent' | 'complete' | 'unknown';
export type Cleanup =
  | { readonly kind: 'complete' }
  | { readonly kind: 'incomplete'; readonly code: string; readonly ownerId: string };
export interface ArtifactFailureState {
  readonly publication: Publication;
  readonly cleanup: Cleanup;
  readonly native?: NativeSqliteCode;
  readonly rollback?: RollbackDisposition;
  readonly filesystemCode?: string;
  readonly initializationPhase?: InitializationPhase;
}
export class DatabaseArtifactError extends Error {
  constructor(
    readonly code: ArtifactCode,
    readonly phase: ArtifactPhase,
    readonly state: ArtifactFailureState = { publication: 'absent', cleanup: { kind: 'complete' } },
  ) {
    super(code);
  }
}
export function filesystemCode(error: unknown): string | undefined {
  if (error instanceof Error && 'code' in error && typeof error.code === 'string'
    && Object.hasOwn(systemConstants.errno, error.code)) return error.code;
}
export function artifactFailure(error: unknown, phase: ArtifactPhase): DatabaseArtifactError {
  if (error instanceof InitializationFailure) {
    const state = {
      publication: 'absent', cleanup: { kind: 'complete' },
      rollback: error.rollback, initializationPhase: error.phase,
    } as const;
    switch (error.primary.kind) {
      case 'contract': return new DatabaseArtifactError(error.primary.error.code, phase, state);
      case 'native': return new DatabaseArtifactError('migration_failed', phase, {
        ...state, native: error.primary.sqlite,
      });
      case 'unexpected': throw error.primary.error;
      default: { const impossible: never = error.primary; throw impossible; }
    }
  }
  if (error instanceof DatabaseArtifactError) return error;
  if (error instanceof RunStoreError) return new DatabaseArtifactError(error.code, phase);
  const native = nativeSqliteCode(error), filesystem = filesystemCode(error);
  if (native) {
    const code = native.primary === 11 || native.primary === 26 ? 'corrupt_input' : 'storage_error';
    return new DatabaseArtifactError(code, phase, {
      publication: 'absent', cleanup: { kind: 'complete' }, native,
    });
  }
  if (filesystem) return new DatabaseArtifactError(
    filesystem === 'EEXIST' ? 'destination_exists' : 'storage_error', phase,
    { publication: 'absent', cleanup: { kind: 'complete' }, filesystemCode: filesystem },
  );
  throw error;
}
export async function sqliteModule(): Promise<typeof import('node:sqlite')> {
  requireSqliteRuntime();
  try { return await import('node:sqlite'); }
  catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ERR_UNKNOWN_BUILTIN_MODULE') {
      throw new RunStoreError('node_sqlite_unavailable');
    }
    throw error;
  }
}
