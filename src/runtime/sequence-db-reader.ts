import { mkdtempSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';
import {
  DatabaseArtifactError, artifactFailure, filesystemCode, sqliteModule, type Cleanup,
} from '../agent-dast/store-contract.js';
import { RUN_ID, GAP_REASONS, SEVERITIES } from '../agent-dast/result.js';
import type { RoundSummary } from '../agent-dast/store.js';
import type { RunDatabaseSchema } from '../agent-dast/store-schema.js';
import { SEQUENCE_DB_COLUMNS } from './sequence-db-schema.js';
import { inspectOwnedDatabase } from './sequence-db.js';
import { createOwnedDatabaseCopy, type ClosedRunDatabaseSource, type OwnedDatabaseCopy } from './run-db-copy.js';
import {
  decodeStep, decodeCell, decodeObservation, decodeEdge, sqlNumber, invalid, range, member, type SqlRow,
} from './sequence-db-decode.js';

type Table = keyof typeof SEQUENCE_DB_COLUMNS;
export type SequenceCursor = readonly [readerId: string, runId: string, table: Table,
  after: readonly (string | number)[]];
export type SequencePage<T> =
  | { readonly kind: 'unavailable'; readonly reason: 'legacy_schema' | 'no_registered_cells' }
  | { readonly kind: 'metadata'; readonly items: readonly T[]; readonly nextCursor: SequenceCursor | null;
      readonly qualification: 'not_assessed' };
const keys = {
  sequence_steps: ['sequence_id', 'reset_generation', 'ordinal'],
  planned_cells: ['sequence_id', 'reset_generation', 'surface_id', 'check_id', 'actor_ref', 'ordinal'],
  observation_refs: ['observation_id'],
  edges: ['sequence_id', 'reset_generation', 'producer_ordinal', 'consumer_ordinal', 'kind',
    'extraction_ref', 'destination_location', 'destination_ref'],
} as const;
interface PageRequest { readonly runId: string; readonly cursor?: SequenceCursor }
class SequenceDatabaseReader {
  private readonly readerId = randomUUID();
  private readonly cursors = new WeakSet<SequenceCursor>();
  private closed = false;
  constructor(
    private readonly db: DatabaseSync,
    private readonly copy: OwnedDatabaseCopy,
    private readonly schemaValue: RunDatabaseSchema,
  ) {}
  schema(): RunDatabaseSchema { this.active(); return this.schemaValue; }
  private active(): void {
    if (this.closed) throw new DatabaseArtifactError('invalid_transition', 'inspect');
  }
  private page<T>(table: Table, request: PageRequest, decode: (row: SqlRow) => T): SequencePage<T> {
    this.active();
    const { runId, cursor } = request;
    if (typeof runId !== 'string' || !RUN_ID.test(runId) || cursor !== undefined && (
      !this.cursors.has(cursor) || cursor[0] !== this.readerId || cursor[1] !== runId || cursor[2] !== table)) {
      throw new DatabaseArtifactError('invalid_input', 'inspect');
    }
    if (this.schemaValue.version !== 3) return { kind: 'unavailable', reason: 'legacy_schema' };
    const pk = keys[table], prefix = pk.map(key => 'r.' + key).join(',');
    const after = cursor ? ' AND (' + prefix + ')>(' + pk.map(() => '?').join(',') + ')' : '';
    const projection = table === 'observation_refs' ? 'r.*,s.state_scope' : 'r.*';
    const parent = table === 'observation_refs' ? ' LEFT JOIN sequence_steps s ON s.run_id=r.run_id'
      + ' AND s.sequence_id=r.sequence_id AND s.reset_generation=r.reset_generation AND s.ordinal=r.ordinal' : '';
    const statement = this.db.prepare('SELECT ' + projection + ' FROM ' + table + ' r' + parent
      + ' WHERE r.run_id=?' + after + ' ORDER BY ' + prefix + ' LIMIT 257');
    statement.setReadBigInts(true);
    const parameters: SQLInputValue[] = cursor ? [runId, ...cursor[3]] : [runId];
    const rows = statement.all(...parameters), visible = rows.slice(0, 256);
    const items = visible.map(decode);
    if (table === 'planned_cells' && rows.length === 0) return { kind: 'unavailable', reason: 'no_registered_cells' };
    let nextCursor: SequenceCursor | null = null;
    if (rows.length > 256) {
      const last = visible.at(-1);
      if (!last) throw new DatabaseArtifactError('invalid_record', 'inspect');
      const values = pk.map(key => {
        const value = sqlNumber(last[key]);
        if (typeof value !== 'string' && typeof value !== 'number') {
          throw new DatabaseArtifactError('invalid_record', 'inspect');
        }
        return value;
      });
      nextCursor = Object.freeze([this.readerId, runId, table, Object.freeze(values)] as const);
      this.cursors.add(nextCursor);
    }
    return Object.freeze({ kind: 'metadata', items: Object.freeze(items), nextCursor,
      qualification: 'not_assessed' } as const);
  }
  steps(runId: string, cursor?: SequenceCursor) { return this.page('sequence_steps', { runId, cursor }, decodeStep); }
  cells(runId: string, cursor?: SequenceCursor) { return this.page('planned_cells', { runId, cursor }, decodeCell); }
  observations(runId: string, cursor?: SequenceCursor) {
    return this.page('observation_refs', { runId, cursor }, decodeObservation);
  }
  edges(runId: string, cursor?: SequenceCursor) {
    return this.page('edges', { runId, cursor }, row => decodeEdge(row, this.db));
  }
  legacySummary(runId: string) {
    this.active();
    if (typeof runId !== 'string' || !RUN_ID.test(runId)) throw new DatabaseArtifactError('invalid_input', 'inspect');
    if (this.schemaValue.version === 0 || !this.db.prepare('SELECT 1 FROM runs WHERE run_id=?').get(runId)) {
      return { schema: this.schemaValue, summary: null };
    }
    const summary: RoundSummary = { run_id: runId,
      tasks: { queued: 0, running: 0, completed: 0, partial: 0, error: 0, skipped: 0 },
      findings: { candidate: 0, confirmed: 0, rejected: 0 },
      open_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      gaps: {}, needs_verify: 0, needs_retry: 0 };
    const tasks = this.db.prepare('SELECT status,count(*) n FROM tasks WHERE run_id=? GROUP BY status');
    for (const row of tasks.all(runId)) {
      const status = member(row.status, ['queued', 'running', 'completed', 'partial', 'error', 'skipped'] as const);
      const count = sqlNumber(row.n);
      if (!range(count, 0, Number.MAX_SAFE_INTEGER) || typeof count !== 'number') return invalid();
      summary.tasks[status] = count;
    }
    for (const row of this.db.prepare('SELECT state,severity,count(*) n FROM findings'
      + ' WHERE run_id=? GROUP BY state,severity').all(runId)) {
      const state = member(row.state, ['candidate', 'confirmed', 'rejected'] as const);
      const severity = member(row.severity, SEVERITIES), count = sqlNumber(row.n);
      if (!range(count, 0, Number.MAX_SAFE_INTEGER) || typeof count !== 'number') return invalid();
      summary.findings[state] += count;
      if (state !== 'rejected') summary.open_by_severity[severity] += count;
    }
    for (const row of this.db.prepare('SELECT g.reason,total(g.count) n FROM task_gaps g JOIN tasks t'
      + ' ON t.task_id=g.task_id WHERE t.run_id=? GROUP BY g.reason').all(runId)) {
      const reason = member(row.reason, GAP_REASONS), count = sqlNumber(row.n);
      if (!range(count, 1, Number.MAX_SAFE_INTEGER) || typeof count !== 'number') return invalid();
      summary.gaps[reason] = count;
    }
    for (const row of this.db.prepare("SELECT next_hint,count(*) n FROM tasks WHERE run_id=?"
      + " AND next_hint IN ('verify','retry') GROUP BY next_hint").all(runId)) {
      const count = sqlNumber(row.n);
      if (!range(count, 0, Number.MAX_SAFE_INTEGER) || typeof count !== 'number') return invalid();
      switch (row.next_hint) {
        case 'verify': summary.needs_verify = count; break;
        case 'retry': summary.needs_retry = count; break;
        default: return invalid();
      }
    }
    return { schema: this.schemaValue, summary };
  }
  close(): void {
    if (!this.closed) { this.db.close(); this.closed = true; }
    const cleanup = closeReaderCopy(this.copy, dirname(dirname(this.copy.path)));
    if (cleanup.kind === 'incomplete') {
      throw new DatabaseArtifactError('cleanup_failed', 'cleanup', { publication: 'absent', cleanup });
    }
  }
}
export async function openSequenceDatabaseReader(source: ClosedRunDatabaseSource): Promise<SequenceDatabaseReader> {
  let parent: string | undefined, copy: OwnedDatabaseCopy | undefined, db: DatabaseSync | undefined;
  try {
    const sqlite = await sqliteModule();
    parent = mkdtempSync(join(tmpdir(), 't5-history-'));
    copy = await createOwnedDatabaseCopy(source, parent);
    db = new sqlite.DatabaseSync(copy.path, { readOnly: true });
    db.exec('PRAGMA query_only=ON');
    return new SequenceDatabaseReader(db, copy, inspectOwnedDatabase(db, 'history'));
  } catch (error) {
    db?.close();
    const cleanup = parent ? closeReaderCopy(copy, parent) : { kind: 'complete' } as const;
    const primary = artifactFailure(error, 'inspect');
    throw new DatabaseArtifactError(primary.code, primary.phase, { ...primary.state, cleanup });
  }
}
function closeReaderCopy(copy: OwnedDatabaseCopy | undefined, parent: string): Cleanup {
  const cleanup = copy?.close() ?? { kind: 'complete' } as const;
  if (cleanup.kind === 'incomplete') return cleanup;
  try { rmdirSync(parent); return { kind: 'complete' }; }
  catch (error) {
    const code = filesystemCode(error);
    if (!code) throw error;
    return code === 'ENOENT' ? { kind: 'complete' } : { kind: 'incomplete', code, ownerId: basename(parent) };
  }
}
