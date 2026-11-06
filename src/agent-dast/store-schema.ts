import type { DatabaseSync } from 'node:sqlite';
import { GAP_REASONS, SEVERITIES, WORKER_CATEGORIES } from './result.js';
import {
  AUTH_STATES, FINDING_STATES, PARAM_LOCATIONS, PROVIDERS, RUN_STATUSES, TASK_STATUSES,
  DatabaseArtifactError, InitializationFailure, RunStoreError, initializationPrimary, nativeSqliteCode,
  requireSqliteRuntime, type InitializationPhase, type RollbackDisposition,
} from './store-contract.js';
import {
  SEQUENCE_DB_COLUMNS, SEQUENCE_DB_INTEGRITY_QUERIES, SEQUENCE_DB_MIGRATION,
} from '../runtime/sequence-db-schema.js';

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
  SEQUENCE_DB_MIGRATION,
];

export const RUN_DB_VERSION = MIGRATIONS.length;

const V1_TABLES = ['runs', 'surface', 'tasks', 'task_gaps', 'findings', 'coverage', 'ledger'];
const TABLE_COLUMNS: Record<string, readonly string[]> = {
  runs: ['run_id', 'target_origin', 'scope_hash', 'provider', 'started_at', 'finished_at', 'status'],
  surface: ['surface_id', 'run_id', 'method', 'path', 'param', 'location', 'auth_state'],
  tasks: [
    'task_id', 'run_id', 'category', 'surface_ids', 'provider', 'script_ref', 'status', 'next_hint', 'duration_ms',
  ],
  task_gaps: ['task_id', 'reason', 'count'],
  findings: [
    'finding_id', 'run_id', 'task_id', 'surface_id', 'rule_id', 'severity', 'state', 'dedupe_key', 'evidence_ref',
  ],
  coverage: ['task_id', 'surface_id', 'check', 'result', 'reason'],
  ledger: [
    'task_id', 'provider', 'input_tokens', 'output_tokens', 'request_count', 'bytes', 'exit_code',
    'stdout_bytes', 'truncated',
  ],
  coverage_plan: ['task_id', 'surface_id', 'check'],
  finding_observations: ['observation_id', 'finding_id', 'task_id', 'surface_id', 'check', 'severity', 'evidence_ref'],
};

export type RunDatabaseSchema =
  | { readonly version: 0; readonly kind: 'empty' }
  | { readonly version: 1; readonly kind: 'legacy'; readonly trust: 'untrusted' }
  | { readonly version: 2; readonly kind: 'legacy'; readonly trust: 'schema-validated' }
  | { readonly version: 3; readonly kind: 'sequence'; readonly trust: 'schema-validated' };
function canonicalSql(sql: string): string {
  const tokens = sql.match(/'(?:''|[^'])*'|"(?:""|[^"])*"|[a-z_][a-z_0-9]*|\d+|[^\s]/gi) ?? [];
  return tokens.map(token => {
    if (token.startsWith("'")) return token;
    return token.startsWith('"') ? token.slice(1, -1).replace(/""/g, '"').toLowerCase() : token.toLowerCase();
  }).join(' ');
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
export function inspectRunDatabase(db: DatabaseSync, purpose: 'history' | 'write'): RunDatabaseSchema {
  const version = db.prepare('PRAGMA user_version').get()?.user_version;
  if (version !== 0 && version !== 1 && version !== 2 && version !== 3) {
    throw new RunStoreError('unsupported_version');
  }
  const expected = version === 0 ? [] : [...V1_TABLES,
    ...(version >= 2 ? ['coverage_plan', 'finding_observations'] : []),
    ...(version === 3 ? Object.keys(SEQUENCE_DB_COLUMNS) : [])];
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'"
    + " AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 20").all().map(row => row.name);
  if (JSON.stringify(tables) !== JSON.stringify([...expected].sort())) {
    throw new RunStoreError('unsupported_version');
  }
  if (purpose === 'write' && version === 1 && V1_TABLES.some(table =>
    db.prepare('SELECT 1 FROM "' + table + '" LIMIT 1').get())) {
    throw new RunStoreError('legacy_evidence_untrusted');
  }
  const objects = db.prepare('SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name LIMIT 30').all();
  const statements = schemaStatements(version);
  if (objects.length !== statements.size || objects.some(object => typeof object.name !== 'string'
    || typeof object.sql !== 'string' || statements.get(object.name) !== canonicalSql(object.sql))) {
    throw new RunStoreError('unsupported_version');
  }
  const columns: Readonly<Record<string, readonly string[]>> = { ...TABLE_COLUMNS, ...SEQUENCE_DB_COLUMNS };
  for (const table of expected) {
    const actual = db.prepare('PRAGMA table_info("' + table + '")').all().map(row => row.name);
    if (JSON.stringify(actual) !== JSON.stringify(columns[table])) throw new RunStoreError('unsupported_version');
  }
  if (version >= 2) {
    db.prepare('SELECT observation_id,finding_id,task_id,surface_id,"check",severity,evidence_ref'
      + ' FROM finding_observations LIMIT 0');
    db.prepare('SELECT task_id,surface_id,"check" FROM coverage_plan LIMIT 0');
    db.prepare('SELECT provider,exit_code,stdout_bytes,truncated FROM ledger LIMIT 0');
    if (db.prepare('SELECT 1 FROM pragma_foreign_key_check LIMIT 1').get()) {
      throw new RunStoreError('unsupported_version');
    }
  }
  if (version === 3 && SEQUENCE_DB_INTEGRITY_QUERIES.some(sql => db.prepare(sql).get())) {
    throw new DatabaseArtifactError('invalid_record', 'inspect');
  }
  switch (version) {
    case 0: return { version, kind: 'empty' };
    case 1: return { version, kind: 'legacy', trust: 'untrusted' };
    case 2: return { version, kind: 'legacy', trust: 'schema-validated' };
    case 3: return { version, kind: 'sequence', trust: 'schema-validated' };
  }
}
function transactionState(db: DatabaseSync): boolean | undefined {
  return 'isTransaction' in db && typeof db.isTransaction === 'boolean' ? db.isTransaction : undefined;
}
export function initializeDatabase(db: DatabaseSync): void {
  let phase: InitializationPhase = 'preflight', begun = false;
  try {
    requireSqliteRuntime();
    inspectRunDatabase(db, 'write');
    phase = 'configure';
    db.exec('PRAGMA foreign_keys=ON');
    db.exec('PRAGMA busy_timeout=5000');
    phase = 'begin';
    db.exec('BEGIN IMMEDIATE');
    begun = true;
    phase = 'preflight';
    const version = inspectRunDatabase(db, 'write').version;
    for (let i = version; i < MIGRATIONS.length; i++) {
      phase = 'migration';
      db.exec(MIGRATIONS[i]);
      phase = 'version';
      db.exec('PRAGMA user_version=' + (i + 1));
    }
    phase = 'commit';
    db.exec('COMMIT');
  } catch (error) {
    let rollback: RollbackDisposition = { kind: 'not_started' };
    if (begun) {
      const before = transactionState(db);
      try {
        db.exec('ROLLBACK');
        rollback = { kind: 'explicit_rollback_completed' };
      } catch (rollbackError) {
        const failure = nativeSqliteCode(rollbackError);
        rollback = before === false && transactionState(db) === false && failure
          ? { kind: 'sqlite_already_ended', failure } : { kind: 'unknown', failure };
      }
    }
    throw new InitializationFailure(initializationPrimary(error), phase, rollback);
  }
}
