/**
 * run.db — the shared artifact of one agent-dast run.
 *
 * A trusted controller writes metadata and evidence references through this
 * API; worker claims alone do not create findings or authorize completion.
 * `roundSummary` is a fixed-shape aggregate. A caller with direct SQLite/file
 * access can bypass these rules: this module is not a worker or OS sandbox.
 *
 * Uses Node's built-in `node:sqlite` (22.13+, 23.4+, or 24+) so the package keeps its
 * two-runtime-dependency footprint. Raw requests and responses never go in
 * this database; findings point to `evidence/<finding_id>.json` instead.
 */
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import type { DatabaseSync, StatementSync } from 'node:sqlite';
import { snapshotJsonData } from '../json-snapshot.js';
import {
  FINDING_ID, GAP_REASONS, MAX_FINDING_IDS, RUN_ID, SEVERITIES, TASK_ID, WORKER_CATEGORIES,
  WORKER_RESULT_MAX_BYTES, validateWorkerResult,
  type GapReason, type NextHint, type Severity, type WorkerCategory, type WorkerResultV1, type WorkerStatus,
} from './result.js';

export const SURFACE_ID = /^s-[0-9a-z-]{1,60}$/;
export const PROVIDERS = ['codex', 'claude', 'mixed', 'fixed'] as const;
export const AUTH_STATES = ['anonymous', 'user', 'other_user', 'admin'] as const;
export const PARAM_LOCATIONS = ['query', 'body', 'header', 'path', 'cookie'] as const;
export const FINDING_STATES = ['candidate', 'confirmed', 'rejected'] as const;
export const TASK_STATUSES = ['queued', 'running', 'completed', 'partial', 'error', 'skipped'] as const;
export const RUN_STATUSES = ['running', 'completed', 'partial', 'error'] as const;
export const MAX_COVERAGE_PLAN = 256;
export const MAX_STORE_BATCH = 256;
export const MAX_RUN_ITEMS = 4096;
export const MAX_TASK_OBSERVATIONS = 4096;
export const MAX_LEDGER_COUNT = 1_000_000_000;
export const MAX_LEDGER_BYTES = 1024 * 1024 * 1024;

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
  `CREATE TABLE coverage_plan (
    task_id TEXT NOT NULL REFERENCES tasks(task_id), surface_id TEXT NOT NULL REFERENCES surface(surface_id),
    "check" TEXT NOT NULL, PRIMARY KEY(task_id,surface_id,"check")
  );
  CREATE TABLE finding_observations (
    observation_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    task_id TEXT NOT NULL, surface_id TEXT NOT NULL, "check" TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN (${quoted(SEVERITIES)})), evidence_ref TEXT NOT NULL,
    FOREIGN KEY(task_id,surface_id,"check") REFERENCES coverage_plan(task_id,surface_id,"check")
  );
  CREATE INDEX idx_observations_task ON finding_observations(task_id,finding_id);
  DROP TABLE coverage;
  CREATE TABLE coverage (
    task_id TEXT NOT NULL, surface_id TEXT NOT NULL, "check" TEXT NOT NULL,
    result TEXT NOT NULL CHECK(result IN ('executed','skipped','error')),
    reason TEXT CHECK(reason IS NULL OR reason IN (${quoted(GAP_REASONS)})),
    PRIMARY KEY(task_id,surface_id,"check"),
    FOREIGN KEY(task_id,surface_id,"check") REFERENCES coverage_plan(task_id,surface_id,"check")
  );
  CREATE INDEX idx_coverage_result ON coverage(task_id,result);`,
];

export const RUN_DB_VERSION = MIGRATIONS.length;

export class RunStoreError extends Error {
  constructor(readonly code: 'node_sqlite_unavailable' | 'unsupported_version' | 'legacy_evidence_untrusted' | 'unsafe_path' | 'storage_error' | 'invalid_input' | 'invalid_transition' | 'not_found', detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

function invalid(field: string): never { throw new RunStoreError('invalid_input', field); }
function check(ok: unknown, field: string): asserts ok { if (!ok) invalid(field); }
function member<T extends string>(value: unknown, options: readonly T[], field: string): T {
  check(typeof value === 'string' && (options as readonly string[]).includes(value), field);
  return value as T;
}
const nonNegative = (n: number | undefined) => n === undefined || (Number.isSafeInteger(n) && n >= 0);
function snapshot<T>(input: T, field: string): T { return snapshotJsonData(input, () => invalid(field), () => invalid(field)) as T; }
function keys(value: unknown, required: readonly string[], optional: readonly string[], field: string): void {
  check(value !== null && typeof value === 'object' && !Array.isArray(value), field);
  const object = value as Record<string, unknown>, allowed = [...required, ...optional];
  check(required.every(key => Object.hasOwn(object, key)) && Object.keys(object).every(key => allowed.includes(key)), field);
}
function text(value: unknown, maximum: number, field: string): asserts value is string {
  check(typeof value === 'string' && value.length > 0 && value.length <= maximum && !/[\x00-\x1f\x7f]/.test(value), field);
}
function identifier(value: unknown, pattern: RegExp, field: string): asserts value is string { check(typeof value === 'string' && pattern.test(value), field); }
function boundedArray(value: unknown, maximum: number, field: string): void { check(Array.isArray(value) && value.length > 0 && value.length <= maximum, field); }
function timestamp(value: unknown): void {
  text(value, 32, 'timestamp'); check(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)), 'timestamp');
}
const CHECK = /^[a-z0-9][a-z0-9._-]{0,99}$/;
function evidenceRef(value: unknown): asserts value is string {
  text(value, 200, 'evidenceRef'); check(/^evidence\/[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*\.json$/.test(value) && !value.split('/').some(part => part === '.' || part === '..'), 'evidenceRef');
}

/**
 * Collapse ID-like path segments so `/users/12` and `/users/34` are the same
 * place, and drop query and fragment. Parameters are compared separately.
 */
export function normalizePath(path: string): string {
  text(path, 2048, 'path');
  const bare = path.split(/[?#]/, 1)[0] || '/';
  const segments = bare.split('/').map(segment =>
    /^\d+$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment) ? '{id}' : segment);
  const joined = segments.join('/');
  return joined.length > 1 && joined.endsWith('/') ? joined.slice(0, -1) : joined;
}

/** One problem, found by any number of workers, is one finding. */
export function dedupeKey(ruleId: string, method: string, path: string, param: string | null, authState: AuthState, location: ParamLocation | null): string {
  identifier(ruleId, CHECK, 'ruleId'); text(method, 7, 'method'); member(authState, AUTH_STATES, 'authState');
  check(param === null || typeof param === 'string' && param.length <= 100 && !/[\x00-\x1f\x7f]/.test(param), 'param');
  if (location !== null) member(location, PARAM_LOCATIONS, 'location');
  return createHash('sha256')
    .update(JSON.stringify([ruleId, method.toUpperCase(), normalizePath(path), param, authState, location]))
    .digest('hex');
}

export interface NewRun { runId: string; targetOrigin: string; scopeHash: string; provider: Provider; startedAt: string }
export interface NewSurface { surfaceId: string; method: string; path: string; param?: string | null; location?: ParamLocation | null; authState: AuthState }
export interface CoveragePlanEntry { surfaceId: string; check: string }
export interface NewTask { taskId: string; runId: string; category: WorkerCategory; surfaceIds: string[]; coveragePlan: CoveragePlanEntry[]; provider: Provider; scriptRef: string }
export interface NewFinding {
  findingId: string; runId: string; taskId: string; surfaceId: string; check: string;
  ruleId: string; severity: Severity; evidenceRef?: string;
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
type Task = { task_id: string; run_id: string; category: WorkerCategory; provider: Provider; status: TaskStatus };
type Surface = { surface_id: string; run_id: string; method: string; path: string; param: string | null; location: ParamLocation | null; auth_state: AuthState };
function requireSqliteRuntime(): void {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(process.versions.node);
  if (!match) throw new RunStoreError('node_sqlite_unavailable');
  const major = Number(match[1]), minor = Number(match[2]);
  if (!(major === 22 && minor >= 13 || major === 23 && minor >= 4 || major >= 24)) throw new RunStoreError('node_sqlite_unavailable');
}

export class RunStore {
  private readonly statements = new Map<string, StatementSync>();

  constructor(private readonly db: DatabaseSync) { requireSqliteRuntime(); initializeDatabase(db); }

  private prepare(sql: string): StatementSync {
    let statement = this.statements.get(sql);
    if (!statement) { statement = this.db.prepare(sql); this.statements.set(sql, statement); }
    return statement;
  }

  private transaction<T>(work: () => T, mode: 'read' | 'write' = 'write'): T {
    try {
      this.db.exec(mode === 'read' ? 'BEGIN DEFERRED' : 'BEGIN IMMEDIATE');
      try { const value = work(); this.db.exec('COMMIT'); return value; }
      catch (error) { try { this.db.exec('ROLLBACK'); } catch { /* Operation remains failed. */ } throw error; }
    } catch (error) { if (error instanceof RunStoreError) throw error; throw new RunStoreError('storage_error'); }
  }
  private runningRun(runId: string): void {
    identifier(runId, RUN_ID, 'runId');
    const row = this.prepare('SELECT status FROM runs WHERE run_id=?').get(runId) as { status: RunStatus } | undefined;
    if (!row || row.status !== 'running') throw new RunStoreError('invalid_transition', 'run is not running');
  }
  private task(taskId: string, status: 'queued' | 'running'): Task {
    identifier(taskId, TASK_ID, 'taskId');
    const row = this.prepare('SELECT task_id,run_id,category,provider,status FROM tasks WHERE task_id=?').get(taskId) as Task | undefined;
    if (!row || row.status !== status) throw new RunStoreError('invalid_transition', 'task state');
    this.runningRun(row.run_id); return row;
  }
  private assigned(taskId: string, surfaceId: string, checkName: string): Surface {
    const task = this.task(taskId, 'running'); identifier(surfaceId, SURFACE_ID, 'surfaceId'); identifier(checkName, CHECK, 'check');
    const row = this.prepare(`SELECT s.* FROM surface s JOIN coverage_plan p ON p.surface_id=s.surface_id
      WHERE p.task_id=? AND p.surface_id=? AND p."check"=? AND s.run_id=?`).get(taskId, surfaceId, checkName, task.run_id) as Surface | undefined;
    check(row, 'coveragePlan'); return row;
  }
  private belowLimit(sql: string, id: string, maximum: number): void {
    const row = this.prepare(sql).get(id) as { n: number }; check(Number(row.n) < maximum, 'storeLimit');
  }

  createRun(run: NewRun): void {
    run = snapshot(run, 'run'); keys(run, ['runId', 'targetOrigin', 'scopeHash', 'provider', 'startedAt'], [], 'run');
    identifier(run.runId, RUN_ID, 'runId'); text(run.targetOrigin, 2048, 'targetOrigin');
    let origin: URL;
    try { origin = new URL(run.targetOrigin); } catch { invalid('targetOrigin'); }
    check(['http:', 'https:'].includes(origin.protocol) && origin.origin === run.targetOrigin, 'targetOrigin');
    identifier(run.scopeHash, /^[0-9a-f]{64}$/, 'scopeHash');
    member(run.provider, PROVIDERS, 'provider');
    timestamp(run.startedAt);
    this.transaction(() => {
      this.belowLimit('SELECT count(*) n FROM runs WHERE ? IS NOT NULL', run.runId, MAX_RUN_ITEMS);
      this.prepare('INSERT INTO runs (run_id, target_origin, scope_hash, provider, started_at, status) VALUES (?, ?, ?, ?, ?, \'running\')')
        .run(run.runId, run.targetOrigin, run.scopeHash, run.provider, run.startedAt);
    });
  }

  finishRun(runId: string, status: Exclude<RunStatus, 'running'>, finishedAt: string): void {
    member(status, ['completed', 'partial', 'error'], 'status'); timestamp(finishedAt);
    this.transaction(() => {
      this.runningRun(runId);
      if (status === 'completed') {
        const rows = this.prepare('SELECT status,count(*) n FROM tasks WHERE run_id=? GROUP BY status').all(runId) as { status: TaskStatus; n: number }[];
        check(rows.length === 1 && rows[0].status === 'completed' && Number(rows[0].n) > 0, 'runCompletion');
      }
      this.prepare('UPDATE runs SET status=?,finished_at=? WHERE run_id=?').run(status, finishedAt, runId);
    });
  }

  /** Returns how many surfaces were new. Re-adding the same surface is a no-op. */
  addSurfaces(runId: string, surfaces: NewSurface[]): number {
    surfaces = snapshot(surfaces, 'surfaces'); boundedArray(surfaces, MAX_STORE_BATCH, 'surfaces');
    return this.transaction(() => {
      this.runningRun(runId);
      let added = 0;
      for (const s of surfaces) {
        keys(s, ['surfaceId', 'method', 'path', 'authState'], ['param', 'location'], 'surface');
        identifier(s.surfaceId, SURFACE_ID, 'surfaceId');
        identifier(s.method, /^[A-Z]{3,7}$/, 'method');
        text(s.path, 2048, 'path'); check(s.path.startsWith('/') && !/[?#]/.test(s.path), 'path');
        if (s.param != null) text(s.param, 100, 'param');
        if (s.location != null) member(s.location, PARAM_LOCATIONS, 'location');
        check((s.param == null) === (s.location == null), 'paramLocation');
        member(s.authState, AUTH_STATES, 'authState');
        const old = this.prepare('SELECT * FROM surface WHERE surface_id=?').get(s.surfaceId) as Surface | undefined;
        if (old) {
          check(old.run_id === runId && old.method === s.method && old.path === s.path && old.param === (s.param ?? null) &&
            old.location === (s.location ?? null) && old.auth_state === s.authState, 'surfaceConflict');
          continue;
        }
        this.belowLimit('SELECT count(*) n FROM surface WHERE run_id=?', runId, MAX_RUN_ITEMS);
        added += Number(this.prepare(`INSERT INTO surface (surface_id, run_id, method, path, param, location, auth_state)
          VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(surface_id) DO NOTHING`)
          .run(s.surfaceId, runId, s.method, s.path, s.param ?? null, s.location ?? null, s.authState).changes);
      }
      return added;
    });
  }

  createTask(task: NewTask): void {
    task = snapshot(task, 'task'); keys(task, ['taskId', 'runId', 'category', 'surfaceIds', 'coveragePlan', 'provider', 'scriptRef'], [], 'task');
    identifier(task.taskId, TASK_ID, 'taskId');
    member(task.category, WORKER_CATEGORIES, 'category');
    member(task.provider, PROVIDERS, 'provider');
    boundedArray(task.surfaceIds, MAX_COVERAGE_PLAN, 'surfaceIds'); boundedArray(task.coveragePlan, MAX_COVERAGE_PLAN, 'coveragePlan');
    task.surfaceIds.forEach(id => identifier(id, SURFACE_ID, 'surfaceIds'));
    check(new Set(task.surfaceIds).size === task.surfaceIds.length, 'surfaceIds'); text(task.scriptRef, 200, 'scriptRef');
    const seen = new Set<string>();
    for (const item of task.coveragePlan) {
      keys(item, ['surfaceId', 'check'], [], 'coveragePlan'); identifier(item.surfaceId, SURFACE_ID, 'surfaceId'); identifier(item.check, CHECK, 'check');
      const key = JSON.stringify([item.surfaceId, item.check]); check(!seen.has(key) && task.surfaceIds.includes(item.surfaceId), 'coveragePlan'); seen.add(key);
    }
    check(task.surfaceIds.every(id => task.coveragePlan.some(item => item.surfaceId === id)), 'coveragePlan');
    this.transaction(() => {
      this.runningRun(task.runId); this.belowLimit('SELECT count(*) n FROM tasks WHERE run_id=?', task.runId, MAX_RUN_ITEMS);
      for (const id of task.surfaceIds) check(this.prepare('SELECT 1 FROM surface WHERE surface_id=? AND run_id=?').get(id, task.runId), 'surfaceIds');
      this.prepare(`INSERT INTO tasks (task_id, run_id, category, surface_ids, provider, script_ref, status)
        VALUES (?, ?, ?, ?, ?, ?, 'queued')`).run(task.taskId, task.runId, task.category, JSON.stringify([...task.surfaceIds].sort()), task.provider, task.scriptRef);
      for (const item of task.coveragePlan) this.prepare('INSERT INTO coverage_plan(task_id,surface_id,"check") VALUES(?,?,?)').run(task.taskId, item.surfaceId, item.check);
    });
  }

  startTask(taskId: string): void {
    this.transaction(() => { this.task(taskId, 'queued'); this.prepare("UPDATE tasks SET status='running' WHERE task_id=?").run(taskId); });
  }

  /**
   * Record a candidate. If another worker already found the same problem,
   * its observation/evidence reference is retained under the canonical ID.
   */
  recordFinding(finding: NewFinding): { findingId: string; inserted: boolean } { return this.recordFindings([finding])[0]; }
  recordFindings(input: NewFinding[]): { findingId: string; inserted: boolean }[] {
    const findings = snapshot(input, 'findings'); boundedArray(findings, MAX_STORE_BATCH, 'findings');
    return this.transaction(() => findings.map(finding => {
      keys(finding, ['findingId', 'runId', 'taskId', 'surfaceId', 'check', 'ruleId', 'severity'], ['evidenceRef'], 'finding');
      identifier(finding.findingId, FINDING_ID, 'findingId'); identifier(finding.ruleId, CHECK, 'ruleId'); member(finding.severity, SEVERITIES, 'severity');
      const surface = this.assigned(finding.taskId, finding.surfaceId, finding.check); check(surface.run_id === finding.runId, 'runId');
      const ref = finding.evidenceRef ?? `evidence/${finding.findingId}.json`; evidenceRef(ref);
      const key = dedupeKey(finding.ruleId, surface.method, surface.path, surface.param, surface.auth_state, surface.location);
      const old = this.prepare('SELECT finding_id,severity,state FROM findings WHERE run_id=? AND dedupe_key=?').get(finding.runId, key) as
        { finding_id: string; severity: Severity; state: FindingState } | undefined;
      const observation = this.prepare('SELECT * FROM finding_observations WHERE observation_id=?').get(finding.findingId) as
        { finding_id: string; task_id: string; surface_id: string; check: string; severity: Severity; evidence_ref: string } | undefined;
      if (observation) {
        check(old && observation.finding_id === old.finding_id && observation.task_id === finding.taskId && observation.surface_id === finding.surfaceId &&
          observation.check === finding.check && observation.severity === finding.severity && observation.evidence_ref === ref, 'observationConflict');
        return { findingId: observation.finding_id, inserted: false };
      }
      this.belowLimit('SELECT count(*) n FROM finding_observations WHERE task_id=?', finding.taskId, MAX_TASK_OBSERVATIONS);
      const canonical = old?.finding_id ?? finding.findingId;
      if (!old) this.prepare("INSERT INTO findings(finding_id,run_id,task_id,surface_id,rule_id,severity,state,dedupe_key,evidence_ref) VALUES(?,?,?,?,?,?,'candidate',?,?)")
        .run(canonical, finding.runId, finding.taskId, finding.surfaceId, finding.ruleId, finding.severity, key, ref);
      else {
        const severity = SEVERITIES.indexOf(finding.severity) < SEVERITIES.indexOf(old.severity) ? finding.severity : old.severity;
        this.prepare("UPDATE findings SET severity=?,state=CASE WHEN state='rejected' THEN 'candidate' ELSE state END WHERE finding_id=?").run(severity, canonical);
      }
      this.prepare('INSERT INTO finding_observations(observation_id,finding_id,task_id,surface_id,"check",severity,evidence_ref) VALUES(?,?,?,?,?,?,?)')
        .run(finding.findingId, canonical, finding.taskId, finding.surfaceId, finding.check, finding.severity, ref);
      return { findingId: canonical, inserted: !old };
    }));
  }

  /** Only a candidate can be confirmed or rejected, and only once. */
  setFindingState(findingId: string, state: Exclude<FindingState, 'candidate'>): void {
    identifier(findingId, FINDING_ID, 'findingId'); member(state, ['confirmed', 'rejected'], 'state');
    this.transaction(() => {
      const row = this.prepare('SELECT run_id,state FROM findings WHERE finding_id=?').get(findingId) as { run_id: string; state: FindingState } | undefined;
      if (!row || row.state !== 'candidate') throw new RunStoreError('invalid_transition', 'finding is not candidate');
      this.runningRun(row.run_id);
      check(this.prepare("SELECT 1 FROM finding_observations o JOIN tasks t ON t.task_id=o.task_id WHERE o.finding_id=? AND t.status='running' LIMIT 1").get(findingId), 'findingTask');
      this.prepare('UPDATE findings SET state=? WHERE finding_id=?').run(state, findingId);
    });
  }

  recordCoverage(rows: CoverageRow[]): void {
    rows = snapshot(rows, 'coverage'); boundedArray(rows, MAX_STORE_BATCH, 'coverage');
    this.transaction(() => {
      for (const row of rows) {
        keys(row, ['taskId', 'surfaceId', 'check', 'result'], ['reason'], 'coverage');
        this.assigned(row.taskId, row.surfaceId, row.check); member(row.result, ['executed', 'skipped', 'error'], 'result');
        check(row.result === 'executed' ? row.reason == null : row.reason != null, 'reason');
        if (row.reason != null) member(row.reason, GAP_REASONS, 'reason');
        const old = this.prepare('SELECT result,reason FROM coverage WHERE task_id=? AND surface_id=? AND "check"=?').get(row.taskId, row.surfaceId, row.check) as { result: string; reason: string | null } | undefined;
        if (old) { check(old.result === row.result && old.reason === (row.reason ?? null), 'coverageConflict'); continue; }
        this.prepare('INSERT INTO coverage(task_id,surface_id,"check",result,reason) VALUES(?,?,?,?,?)').run(row.taskId, row.surfaceId, row.check, row.result, row.reason ?? null);
      }
    });
  }

  /** Close a running task with its validated result and the runner's ledger, atomically. */
  completeTask(result: WorkerResultV1, ledger: LedgerEntry): void {
    try { result = validateWorkerResult(result); } catch { invalid('workerResult'); }
    check([result.duration_ms, result.coverage.planned, result.coverage.executed, result.coverage.skipped,
      result.findings.candidate, ...Object.values(result.findings.by_severity), ...result.gaps.map(gap => gap.count)]
      .every(value => Number.isSafeInteger(value) && value >= 0 && value <= MAX_LEDGER_COUNT), 'workerResult');
    ledger = snapshot(ledger, 'ledger');
    keys(ledger, ['provider', 'requestCount', 'bytes', 'exitCode', 'stdoutBytes', 'truncated'], ['inputTokens', 'outputTokens'], 'ledger');
    member(ledger.provider, PROVIDERS, 'provider');
    check([ledger.inputTokens, ledger.outputTokens, ledger.requestCount, ledger.stdoutBytes].every(value => nonNegative(value) && (value === undefined || value <= MAX_LEDGER_COUNT)), 'ledger');
    check(nonNegative(ledger.bytes) && ledger.bytes <= MAX_LEDGER_BYTES, 'ledger');
    check(ledger.exitCode === null || Number.isInteger(ledger.exitCode) && ledger.exitCode >= 0 && ledger.exitCode <= 255, 'exitCode');
    check(typeof ledger.truncated === 'boolean', 'truncated');
    this.transaction(() => {
      const task = this.task(result.task_id, 'running');
      check(task.run_id === result.run_id && task.category === result.category, 'workerIdentity'); check(task.provider === ledger.provider, 'provider');
      if (result.status === 'completed') {
        const planned = this.prepare('SELECT count(*) n FROM coverage_plan WHERE task_id=?').get(task.task_id) as { n: number };
        const executed = this.prepare(`SELECT count(*) n FROM coverage_plan p JOIN coverage c
          ON c.task_id=p.task_id AND c.surface_id=p.surface_id AND c."check"=p."check"
          WHERE p.task_id=? AND c.result='executed' AND c.reason IS NULL`).get(task.task_id) as { n: number };
        check(planned.n > 0 && planned.n === executed.n && result.coverage.planned === planned.n && result.coverage.executed === executed.n && result.coverage.skipped === 0, 'coverageCompletion');
        check(ledger.exitCode === 0 && ledger.stdoutBytes > 0 && ledger.stdoutBytes <= WORKER_RESULT_MAX_BYTES && !ledger.truncated && !result.truncated, 'ledgerCompletion');
        const observations = this.prepare('SELECT finding_id,severity FROM finding_observations WHERE task_id=?').all(task.task_id) as { finding_id: string; severity: Severity }[];
        const severities = new Map<string, Severity>();
        for (const row of observations) {
          const prior = severities.get(row.finding_id);
          if (!prior || SEVERITIES.indexOf(row.severity) < SEVERITIES.indexOf(prior)) severities.set(row.finding_id, row.severity);
        }
        const counts = zeros(SEVERITIES); for (const severity of severities.values()) counts[severity]++;
        check(severities.size <= MAX_FINDING_IDS && result.findings.candidate === severities.size && result.finding_ids.length === severities.size &&
          result.finding_ids.every(id => severities.has(id)) && SEVERITIES.every(severity => (result.findings.by_severity[severity] ?? 0) === counts[severity]), 'findingCompletion');
      }
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
    identifier(runId, RUN_ID, 'runId');
    return this.transaction(() => {
      check(this.prepare('SELECT 1 FROM runs WHERE run_id=?').get(runId), 'runId');
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
        if (row.state !== 'rejected') summary.open_by_severity[row.severity] += Number(row.n);
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
    }, 'read');
  }

  close(): void { this.statements.clear(); this.db.close(); }
}

/**
 * Open (and if needed migrate) a run database. Fails with
 * `node_sqlite_unavailable` on a Node without `node:sqlite` instead of
 * breaking the rest of the CLI at import time.
 */
const V1_TABLES = ['runs', 'surface', 'tasks', 'task_gaps', 'findings', 'coverage', 'ledger'];
const TABLE_COLUMNS: Record<string, readonly string[]> = {
  runs: ['run_id', 'target_origin', 'scope_hash', 'provider', 'started_at', 'finished_at', 'status'],
  surface: ['surface_id', 'run_id', 'method', 'path', 'param', 'location', 'auth_state'],
  tasks: ['task_id', 'run_id', 'category', 'surface_ids', 'provider', 'script_ref', 'status', 'next_hint', 'duration_ms'],
  task_gaps: ['task_id', 'reason', 'count'],
  findings: ['finding_id', 'run_id', 'task_id', 'surface_id', 'rule_id', 'severity', 'state', 'dedupe_key', 'evidence_ref'],
  coverage: ['task_id', 'surface_id', 'check', 'result', 'reason'],
  ledger: ['task_id', 'provider', 'input_tokens', 'output_tokens', 'request_count', 'bytes', 'exit_code', 'stdout_bytes', 'truncated'],
  coverage_plan: ['task_id', 'surface_id', 'check'],
  finding_observations: ['observation_id', 'finding_id', 'task_id', 'surface_id', 'check', 'severity', 'evidence_ref'],
};
function canonicalSql(sql: string): string {
  const tokens = sql.match(/'(?:''|[^'])*'|"(?:""|[^"])*"|[a-z_][a-z_0-9]*|\d+|[^\s]/gi) ?? [];
  return tokens.map(token => token.startsWith("'") ? token : token.startsWith('"') ? token.slice(1, -1).replace(/""/g, '"').toLowerCase() : token.toLowerCase()).join(' ');
}
function schemaStatements(version: number): Map<string, string> {
  const statements = new Map<string, string>();
  for (const migration of MIGRATIONS.slice(0, version)) for (const statement of migration.split(';')) {
    const create = /^\s*CREATE (?:TABLE|INDEX) ([a-z_]+)/i.exec(statement);
    const drop = /^\s*DROP TABLE ([a-z_]+)/i.exec(statement);
    if (drop) statements.delete(drop[1]);
    if (create) statements.set(create[1], canonicalSql(statement));
  }
  return statements;
}
function preflight(db: DatabaseSync): number {
  const version = (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 20").all() as { name: string }[]).map(row => row.name);
  if (version !== 0 && version !== 1 && version !== RUN_DB_VERSION) throw new RunStoreError('unsupported_version');
  const expected = version === 2 ? [...V1_TABLES, 'coverage_plan', 'finding_observations'] : version === 1 ? V1_TABLES : [];
  if (JSON.stringify(tables) !== JSON.stringify([...expected].sort())) throw new RunStoreError('unsupported_version');
  if (version === 1 && V1_TABLES.some(table => db.prepare(`SELECT 1 FROM "${table}" LIMIT 1`).get())) throw new RunStoreError('legacy_evidence_untrusted');
  const objects = db.prepare("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name LIMIT 30").all() as { name: string; sql: string }[];
  const expectedStatements = schemaStatements(version);
  if (objects.length !== expectedStatements.size || objects.some(object => expectedStatements.get(object.name) !== canonicalSql(object.sql))) throw new RunStoreError('unsupported_version');
  for (const table of expected) {
    const columns = (db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map(row => row.name);
    if (JSON.stringify(columns) !== JSON.stringify(TABLE_COLUMNS[table])) throw new RunStoreError('unsupported_version');
  }
  if (version === 2) {
    // Compile authoritative queries and check FK integrity before accepting an existing store.
    db.prepare('SELECT observation_id,finding_id,task_id,surface_id,"check",severity,evidence_ref FROM finding_observations LIMIT 0');
    db.prepare('SELECT task_id,surface_id,"check" FROM coverage_plan LIMIT 0');
    db.prepare('SELECT provider,exit_code,stdout_bytes,truncated FROM ledger LIMIT 0');
    if (db.prepare('SELECT 1 FROM pragma_foreign_key_check LIMIT 1').get()) throw new RunStoreError('unsupported_version');
  }
  return version;
}
function initializeDatabase(db: DatabaseSync): void {
  try {
    preflight(db); // Legacy refusal precedes writes and journal settings.
    db.exec('PRAGMA foreign_keys=ON'); db.exec('PRAGMA busy_timeout=5000'); db.exec('BEGIN IMMEDIATE');
    try {
      const version = preflight(db);
      for (let i = version; i < MIGRATIONS.length; i++) { db.exec(MIGRATIONS[i]); db.exec(`PRAGMA user_version=${i + 1}`); }
      db.exec('COMMIT');
    } catch (error) { try { db.exec('ROLLBACK'); } catch { /* Preserve refusal. */ } throw error; }
  } catch (error) { if (error instanceof RunStoreError) throw error; throw new RunStoreError('unsupported_version'); }
}
function privatePath(path: string): { path: string; existing: boolean; dev: number; ino: number } {
  text(path, 4096, 'path'); check(!path.startsWith('file:'), 'path');
  try {
    const absolute = resolve(path), parent = dirname(absolute), directory = lstatSync(parent), uid = process.getuid?.();
    if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o777) !== 0o700 || uid === undefined || directory.uid !== uid) throw new RunStoreError('unsafe_path');
    // Ancestors are canonicalized, including macOS /var. A hostile same-UID path swap is outside this local contract.
    const canonical = resolve(realpathSync(parent), basename(absolute));
    let file;
    try { file = lstatSync(canonical); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (file) {
      if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || file.uid !== uid || (file.mode & 0o777) !== 0o600) throw new RunStoreError('unsafe_path');
      return { path: canonical, existing: true, dev: file.dev, ino: file.ino };
    }
    const descriptor = openSync(canonical, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    closeSync(descriptor); const created = lstatSync(canonical);
    return { path: canonical, existing: false, dev: created.dev, ino: created.ino };
  } catch (error) { if (error instanceof RunStoreError) throw error; throw new RunStoreError('unsafe_path'); }
}
export async function openRunStore(path: string): Promise<RunStore> {
  requireSqliteRuntime();
  text(path, 4096, 'path');
  let sqlite: typeof import('node:sqlite');
  try { sqlite = await import('node:sqlite'); } catch {
    throw new RunStoreError('node_sqlite_unavailable');
  }
  const file = path === ':memory:' ? undefined : privatePath(path);
  if (file?.existing) {
    // Read-only SQLite can still create WAL sidecars. Refuse before opening it.
    for (const suffix of ['-wal', '-shm']) {
      try { lstatSync(`${file.path}${suffix}`); throw new RunStoreError('legacy_evidence_untrusted'); }
      catch (error) { if (error instanceof RunStoreError) throw error; if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new RunStoreError('unsafe_path'); }
    }
    let descriptor: number | undefined;
    try {
      descriptor = openSync(file.path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const current = fstatSync(descriptor);
      if (!current.isFile() || current.dev !== file.dev || current.ino !== file.ino) throw new RunStoreError('unsafe_path');
      const header = Buffer.alloc(100), length = readSync(descriptor, header, 0, header.length, 0);
      if (length >= 20 && header.subarray(0, 16).equals(Buffer.from('SQLite format 3\x00')) && (header[18] === 2 || header[19] === 2)) throw new RunStoreError('legacy_evidence_untrusted');
    } catch (error) { if (error instanceof RunStoreError) throw error; throw new RunStoreError('unsafe_path'); }
    finally { if (descriptor !== undefined) closeSync(descriptor); }
    let readonly: DatabaseSync | undefined;
    try { readonly = new sqlite.DatabaseSync(file.path, { readOnly: true }); preflight(readonly); }
    catch (error) { if (error instanceof RunStoreError) throw error; throw new RunStoreError('unsupported_version'); }
    finally { readonly?.close(); }
  }
  let db: DatabaseSync | undefined;
  try {
    const unchanged = () => {
      if (!file) return;
      const current = lstatSync(file.path);
      if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1 || current.uid !== process.getuid?.() || (current.mode & 0o777) !== 0o600 || current.dev !== file.dev || current.ino !== file.ino) throw new RunStoreError('unsafe_path');
    };
    unchanged(); db = new sqlite.DatabaseSync(file?.path ?? ':memory:'); unchanged();
    return new RunStore(db);
  } catch (error) { db?.close(); if (error instanceof RunStoreError) throw error; throw new RunStoreError('storage_error'); }
}
