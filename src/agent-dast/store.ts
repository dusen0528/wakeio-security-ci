/**
 * run.db — the shared artifact of one agent-dast run.
 *
 * Workers write here; agents never read raw rows. The orchestrator reads only
 * `roundSummary`, a fixed-size aggregate, so its context grows with the number
 * of rounds, not with the number of tasks or findings.
 *
 * Uses Node's built-in `node:sqlite` (Node >= 22.5) so the package keeps its
 * two-runtime-dependency footprint. Raw requests and responses never go in
 * this database; findings point to `evidence/<finding_id>.json` instead.
 */
import { createHash } from 'node:crypto';
import type { DatabaseSync, StatementSync } from 'node:sqlite';
import {
  FINDING_ID, GAP_REASONS, RUN_ID, SEVERITIES, TASK_ID, WORKER_CATEGORIES,
  type GapReason, type NextHint, type Severity, type WorkerCategory, type WorkerResultV1, type WorkerStatus,
} from './result.js';

export const SURFACE_ID = /^s-[0-9a-z-]{1,60}$/;
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

const quoted = (values: readonly string[]) => values.map(v => `'${v}'`).join(',');

/** Ordered migrations. user_version records how many have been applied. */
const MIGRATIONS: readonly string[] = [
  `
  CREATE TABLE runs (
    run_id        TEXT PRIMARY KEY,
    target_origin TEXT NOT NULL,
    scope_hash    TEXT NOT NULL,
    provider      TEXT NOT NULL CHECK (provider IN (${quoted(PROVIDERS)})),
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT NOT NULL CHECK (status IN (${quoted(RUN_STATUSES)}))
  );
  CREATE TABLE surface (
    surface_id TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL REFERENCES runs(run_id),
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    param      TEXT,
    location   TEXT CHECK (location IN (${quoted(PARAM_LOCATIONS)})),
    auth_state TEXT NOT NULL CHECK (auth_state IN (${quoted(AUTH_STATES)}))
  );
  CREATE TABLE tasks (
    task_id     TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    category    TEXT NOT NULL CHECK (category IN (${quoted(WORKER_CATEGORIES)})),
    surface_ids TEXT NOT NULL,
    provider    TEXT NOT NULL CHECK (provider IN (${quoted(PROVIDERS)})),
    script_ref  TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN (${quoted(TASK_STATUSES)})),
    next_hint   TEXT,
    duration_ms INTEGER
  );
  CREATE TABLE task_gaps (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    reason  TEXT NOT NULL CHECK (reason IN (${quoted(GAP_REASONS)})),
    count   INTEGER NOT NULL CHECK (count >= 1),
    PRIMARY KEY (task_id, reason)
  );
  CREATE TABLE findings (
    finding_id   TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES runs(run_id),
    task_id      TEXT NOT NULL REFERENCES tasks(task_id),
    surface_id   TEXT REFERENCES surface(surface_id),
    rule_id      TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN (${quoted(SEVERITIES)})),
    state        TEXT NOT NULL CHECK (state IN (${quoted(FINDING_STATES)})),
    dedupe_key   TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    UNIQUE (run_id, dedupe_key)
  );
  CREATE TABLE coverage (
    task_id    TEXT NOT NULL REFERENCES tasks(task_id),
    surface_id TEXT NOT NULL REFERENCES surface(surface_id),
    "check"    TEXT NOT NULL,
    result     TEXT NOT NULL CHECK (result IN ('executed','skipped','error')),
    reason     TEXT CHECK (reason IS NULL OR reason IN (${quoted(GAP_REASONS)})),
    PRIMARY KEY (task_id, surface_id, "check")
  );
  CREATE TABLE ledger (
    task_id       TEXT PRIMARY KEY REFERENCES tasks(task_id),
    provider      TEXT NOT NULL CHECK (provider IN (${quoted(PROVIDERS)})),
    input_tokens  INTEGER,
    output_tokens INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0,
    bytes         INTEGER NOT NULL DEFAULT 0,
    exit_code     INTEGER,
    stdout_bytes  INTEGER NOT NULL DEFAULT 0,
    truncated     INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1))
  );
  CREATE INDEX idx_findings_state ON findings(run_id, state, severity);
  CREATE INDEX idx_tasks_run ON tasks(run_id, status);
  CREATE INDEX idx_coverage_result ON coverage(task_id, result);
  `,
];

export const RUN_DB_VERSION = MIGRATIONS.length;

export class RunStoreError extends Error {
  constructor(readonly code: 'node_sqlite_unavailable' | 'unsupported_version' | 'invalid_input' | 'invalid_transition' | 'not_found', detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

function invalid(field: string): never { throw new RunStoreError('invalid_input', field); }
function check(ok: boolean, field: string): void { if (!ok) invalid(field); }
function member<T extends string>(value: string, options: readonly T[], field: string): T {
  check((options as readonly string[]).includes(value), field);
  return value as T;
}
const nonNegative = (n: number | undefined) => n === undefined || (Number.isSafeInteger(n) && n >= 0);

/**
 * Collapse ID-like path segments so `/users/12` and `/users/34` are the same
 * place, and drop query and fragment. Parameters are compared separately.
 */
export function normalizePath(path: string): string {
  const bare = path.split(/[?#]/, 1)[0] || '/';
  const segments = bare.split('/').map(segment =>
    /^\d+$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment) ? '{id}' : segment);
  const joined = segments.join('/');
  return joined.length > 1 && joined.endsWith('/') ? joined.slice(0, -1) : joined;
}

/** One problem, found by any number of workers, is one finding. */
export function dedupeKey(ruleId: string, method: string, path: string, param: string | null): string {
  return createHash('sha256')
    .update([ruleId, method.toUpperCase(), normalizePath(path), param ?? ''].join('\u0000'))
    .digest('hex');
}

export interface NewRun { runId: string; targetOrigin: string; scopeHash: string; provider: Provider; startedAt: string }
export interface NewSurface { surfaceId: string; method: string; path: string; param?: string | null; location?: ParamLocation | null; authState: AuthState }
export interface NewTask { taskId: string; runId: string; category: WorkerCategory; surfaceIds: string[]; provider: Provider; scriptRef: string }
export interface NewFinding {
  findingId: string; runId: string; taskId: string; surfaceId?: string | null;
  ruleId: string; severity: Severity; method: string; path: string; param?: string | null;
}
export interface CoverageRow { taskId: string; surfaceId: string; check: string; result: 'executed' | 'skipped' | 'error'; reason?: GapReason | null }
export interface LedgerEntry {
  provider: Provider; inputTokens?: number; outputTokens?: number; requestCount: number; bytes: number;
  exitCode: number | null; stdoutBytes: number; truncated: boolean;
}

/** The only view of a run the orchestrator reads. Fixed shape, no rows. */
export interface RoundSummary {
  run_id: string;
  tasks: Record<TaskStatus, number>;
  findings: Record<FindingState, number>;
  open_by_severity: Record<Severity, number>;
  gaps: Partial<Record<GapReason, number>>;
  needs_verify: number;
  needs_retry: number;
}

const zeros = <T extends string>(keys: readonly T[]) => Object.fromEntries(keys.map(k => [k, 0])) as Record<T, number>;

export class RunStore {
  private readonly statements = new Map<string, StatementSync>();

  constructor(private readonly db: DatabaseSync) {}

  private prepare(sql: string): StatementSync {
    let statement = this.statements.get(sql);
    if (!statement) { statement = this.db.prepare(sql); this.statements.set(sql, statement); }
    return statement;
  }

  private transaction<T>(work: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value = work(); this.db.exec('COMMIT'); return value; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }

  createRun(run: NewRun): void {
    check(RUN_ID.test(run.runId), 'runId');
    let origin: URL;
    try { origin = new URL(run.targetOrigin); } catch { invalid('targetOrigin'); }
    check(['http:', 'https:'].includes(origin.protocol) && origin.origin === run.targetOrigin, 'targetOrigin');
    check(/^[0-9a-f]{64}$/.test(run.scopeHash), 'scopeHash');
    member(run.provider, PROVIDERS, 'provider');
    this.prepare('INSERT INTO runs (run_id, target_origin, scope_hash, provider, started_at, status) VALUES (?, ?, ?, ?, ?, \'running\')')
      .run(run.runId, run.targetOrigin, run.scopeHash, run.provider, run.startedAt);
  }

  finishRun(runId: string, status: Exclude<RunStatus, 'running'>, finishedAt: string): void {
    member(status, RUN_STATUSES, 'status');
    const changed = this.prepare('UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ? AND status = \'running\'')
      .run(status, finishedAt, runId).changes;
    if (!changed) throw new RunStoreError('invalid_transition', 'run is not running');
  }

  /** Returns how many surfaces were new. Re-adding the same surface is a no-op. */
  addSurfaces(runId: string, surfaces: NewSurface[]): number {
    return this.transaction(() => {
      let added = 0;
      for (const s of surfaces) {
        check(SURFACE_ID.test(s.surfaceId), 'surfaceId');
        check(/^[A-Z]{3,7}$/.test(s.method), 'method');
        check(s.path.startsWith('/'), 'path');
        if (s.location != null) member(s.location, PARAM_LOCATIONS, 'location');
        member(s.authState, AUTH_STATES, 'authState');
        added += Number(this.prepare(`INSERT INTO surface (surface_id, run_id, method, path, param, location, auth_state)
          VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(surface_id) DO NOTHING`)
          .run(s.surfaceId, runId, s.method, s.path, s.param ?? null, s.location ?? null, s.authState).changes);
      }
      return added;
    });
  }

  createTask(task: NewTask): void {
    check(TASK_ID.test(task.taskId), 'taskId');
    member(task.category, WORKER_CATEGORIES, 'category');
    member(task.provider, PROVIDERS, 'provider');
    check(task.surfaceIds.every(id => SURFACE_ID.test(id)), 'surfaceIds');
    check(task.scriptRef.length > 0 && task.scriptRef.length <= 200, 'scriptRef');
    this.prepare(`INSERT INTO tasks (task_id, run_id, category, surface_ids, provider, script_ref, status)
      VALUES (?, ?, ?, ?, ?, ?, 'queued')`)
      .run(task.taskId, task.runId, task.category, JSON.stringify(task.surfaceIds), task.provider, task.scriptRef);
  }

  startTask(taskId: string): void {
    const changed = this.prepare('UPDATE tasks SET status = \'running\' WHERE task_id = ? AND status = \'queued\'').run(taskId).changes;
    if (!changed) throw new RunStoreError('invalid_transition', 'task is not queued');
  }

  /**
   * Record a candidate. If another worker already found the same problem,
   * nothing is inserted and the existing finding ID is returned.
   */
  recordFinding(finding: NewFinding): { findingId: string; inserted: boolean } {
    check(FINDING_ID.test(finding.findingId), 'findingId');
    member(finding.severity, SEVERITIES, 'severity');
    check(/^[a-z0-9][a-z0-9._-]{0,99}$/.test(finding.ruleId), 'ruleId');
    const owner = this.prepare('SELECT run_id FROM tasks WHERE task_id = ?').get(finding.taskId) as { run_id: string } | undefined;
    check(owner?.run_id === finding.runId, 'taskId');
    if (finding.surfaceId != null) {
      const surface = this.prepare('SELECT run_id FROM surface WHERE surface_id = ?').get(finding.surfaceId) as { run_id: string } | undefined;
      check(surface?.run_id === finding.runId, 'surfaceId');
    }
    const key = dedupeKey(finding.ruleId, finding.method, finding.path, finding.param ?? null);
    const inserted = this.prepare(`INSERT INTO findings
      (finding_id, run_id, task_id, surface_id, rule_id, severity, state, dedupe_key, evidence_ref)
      VALUES (?, ?, ?, ?, ?, ?, 'candidate', ?, ?) ON CONFLICT(run_id, dedupe_key) DO NOTHING`)
      .run(finding.findingId, finding.runId, finding.taskId, finding.surfaceId ?? null, finding.ruleId,
        finding.severity, key, `evidence/${finding.findingId}.json`).changes === 1;
    if (inserted) return { findingId: finding.findingId, inserted };
    const existing = this.prepare('SELECT finding_id FROM findings WHERE run_id = ? AND dedupe_key = ?')
      .get(finding.runId, key) as { finding_id: string } | undefined;
    if (!existing) throw new RunStoreError('not_found', 'finding');
    return { findingId: existing.finding_id, inserted: false };
  }

  /** Only a candidate can be confirmed or rejected, and only once. */
  setFindingState(findingId: string, state: Exclude<FindingState, 'candidate'>): void {
    check(state === 'confirmed' || state === 'rejected', 'state');
    const changed = this.prepare('UPDATE findings SET state = ? WHERE finding_id = ? AND state = \'candidate\'').run(state, findingId).changes;
    if (!changed) throw new RunStoreError('invalid_transition', 'finding is not a candidate');
  }

  recordCoverage(rows: CoverageRow[]): void {
    this.transaction(() => {
      for (const row of rows) {
        check(row.check.length > 0 && row.check.length <= 100, 'check');
        check(row.result === 'executed' ? row.reason == null : row.reason != null, 'reason');
        if (row.reason != null) member(row.reason, GAP_REASONS, 'reason');
        this.prepare(`INSERT INTO coverage (task_id, surface_id, "check", result, reason) VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(task_id, surface_id, "check") DO UPDATE SET result = excluded.result, reason = excluded.reason`)
          .run(row.taskId, row.surfaceId, row.check, row.result, row.reason ?? null);
      }
    });
  }

  /** Close a running task with its validated result and the runner's ledger, atomically. */
  completeTask(result: WorkerResultV1, ledger: LedgerEntry): void {
    member(ledger.provider, PROVIDERS, 'provider');
    check([ledger.inputTokens, ledger.outputTokens, ledger.requestCount, ledger.bytes, ledger.stdoutBytes].every(nonNegative), 'ledger');
    this.transaction(() => {
      const status: WorkerStatus = result.status;
      const changed = this.prepare(`UPDATE tasks SET status = ?, next_hint = ?, duration_ms = ?
        WHERE task_id = ? AND run_id = ? AND category = ? AND status = 'running'`)
        .run(status, result.next_hint, result.duration_ms, result.task_id, result.run_id, result.category).changes;
      if (!changed) throw new RunStoreError('invalid_transition', 'task is not running');
      for (const gap of result.gaps) {
        this.prepare('INSERT INTO task_gaps (task_id, reason, count) VALUES (?, ?, ?)').run(result.task_id, gap.reason, gap.count);
      }
      this.prepare(`INSERT INTO ledger (task_id, provider, input_tokens, output_tokens, request_count, bytes, exit_code, stdout_bytes, truncated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(result.task_id, ledger.provider, ledger.inputTokens ?? null, ledger.outputTokens ?? null, ledger.requestCount,
          ledger.bytes, ledger.exitCode, ledger.stdoutBytes, ledger.truncated || result.truncated ? 1 : 0);
    });
  }

  roundSummary(runId: string): RoundSummary {
    const summary: RoundSummary = {
      run_id: runId,
      tasks: zeros(TASK_STATUSES),
      findings: zeros(FINDING_STATES),
      open_by_severity: zeros(SEVERITIES),
      gaps: {},
      needs_verify: 0,
      needs_retry: 0,
    };
    for (const row of this.prepare('SELECT status, count(*) AS n FROM tasks WHERE run_id = ? GROUP BY status').all(runId) as { status: TaskStatus; n: number }[]) {
      summary.tasks[row.status] = Number(row.n);
    }
    for (const row of this.prepare('SELECT state, severity, count(*) AS n FROM findings WHERE run_id = ? GROUP BY state, severity').all(runId) as { state: FindingState; severity: Severity; n: number }[]) {
      summary.findings[row.state] += Number(row.n);
      if (row.state === 'candidate') summary.open_by_severity[row.severity] += Number(row.n);
    }
    for (const row of this.prepare(`SELECT g.reason, sum(g.count) AS n FROM task_gaps g JOIN tasks t ON t.task_id = g.task_id
      WHERE t.run_id = ? GROUP BY g.reason`).all(runId) as { reason: GapReason; n: number }[]) {
      summary.gaps[row.reason] = Number(row.n);
    }
    const hints = this.prepare(`SELECT next_hint, count(*) AS n FROM tasks WHERE run_id = ? AND next_hint IN ('verify','retry') GROUP BY next_hint`)
      .all(runId) as { next_hint: NextHint; n: number }[];
    for (const row of hints) {
      if (row.next_hint === 'verify') summary.needs_verify = Number(row.n);
      if (row.next_hint === 'retry') summary.needs_retry = Number(row.n);
    }
    return summary;
  }

  close(): void { this.statements.clear(); this.db.close(); }
}

/**
 * Open (and if needed migrate) a run database. Fails with
 * `node_sqlite_unavailable` on a Node without `node:sqlite` instead of
 * breaking the rest of the CLI at import time.
 */
export async function openRunStore(path: string): Promise<RunStore> {
  let sqlite: typeof import('node:sqlite');
  try { sqlite = await import('node:sqlite'); } catch {
    throw new RunStoreError('node_sqlite_unavailable', `Node ${process.versions.node}; agent-dast needs Node >= 22.5`);
  }
  const db = new sqlite.DatabaseSync(path);
  try {
    db.exec('PRAGMA foreign_keys = ON');
    db.exec('PRAGMA busy_timeout = 5000');
    if (path !== ':memory:') db.exec('PRAGMA journal_mode = WAL');
    const { user_version: version } = db.prepare('PRAGMA user_version').get() as { user_version: number };
    if (version > MIGRATIONS.length) throw new RunStoreError('unsupported_version', `run.db v${version} is newer than v${MIGRATIONS.length}`);
    for (let i = version; i < MIGRATIONS.length; i++) {
      db.exec('BEGIN IMMEDIATE');
      try { db.exec(MIGRATIONS[i]); db.exec(`PRAGMA user_version = ${i + 1}`); db.exec('COMMIT'); }
      catch (error) { db.exec('ROLLBACK'); throw error; }
    }
    return new RunStore(db);
  } catch (error) { db.close(); throw error; }
}
