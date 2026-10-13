import test from 'node:test';
import assert from 'node:assert/strict';
import { access, chmod, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { failedWorkerResult, parseWorkerResult, validateWorkerResult } from '../src/agent-dast/result.js';
import { openRunStore, RunStore, RUN_DB_VERSION } from '../src/agent-dast/store.js';

// Independent owned SQL/result inputs; root alone executes this file.
// No agent, scanner, target application, shell worker or network is invoked.
const RUN = 'r-owned-integrity', TASK = 't-owned-integrity', SURFACE = 's-owned-search';
const SECRET = 'owned-private-token-body-canary-53c1';
const identity = { runId: RUN, taskId: TASK, category: 'injection' as const };
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
function result(task = TASK, overrides: Record<string, unknown> = {}): any {
  return { schema: 'wakeio.worker-result/v1', run_id: RUN, task_id: task, category: 'injection', status: 'completed',
    coverage: { planned: 1, executed: 1, skipped: 0 }, findings: { candidate: 0, by_severity: {} }, finding_ids: [], gaps: [],
    next_hint: 'none', duration_ms: 5, truncated: false, ...overrides };
}

test('integrity independent: completed worker needs nonempty fully executed plan and no gaps/skips/truncation; normal and explicit incomplete remain valid', () => {
  const good = parseWorkerResult(JSON.stringify(result()), identity); assert.equal(good.ok, true);
  for (const coverage of [{ planned: 40, executed: 0, skipped: 0 }, { planned: 0, executed: 0, skipped: 0 },
    { planned: 2, executed: 1, skipped: 0 }, { planned: 2, executed: 1, skipped: 1 }]) {
    assert.equal(parseWorkerResult(JSON.stringify(result(TASK, { coverage })), identity).ok, false);
  }
  assert.equal(parseWorkerResult(JSON.stringify(result(TASK, { gaps: [{ reason: 'auth_required', count: 1 }] })), identity).ok, false);
  assert.equal(parseWorkerResult(JSON.stringify(result(TASK, { truncated: true })), identity).ok, false);
  for (const status of ['partial', 'error']) {
    const incomplete = result(TASK, { status, coverage: { planned: 1, executed: 0, skipped: 1 }, gaps: [{ reason: 'timeout', count: 1 }] });
    assert.equal(parseWorkerResult(JSON.stringify(incomplete), identity).ok, true);
  }
  assert.equal(parseWorkerResult(JSON.stringify(result('t-other')), identity).ok, false);
  assert.equal(parseWorkerResult(JSON.stringify(result(TASK, { category: 'authz' })), identity).ok, false);
  const fallback = failedWorkerResult(identity, 'output_too_large', 4); assert.equal(fallback.status, 'error');
  assert.equal(validateWorkerResult(fallback).status, 'error'); assert.equal(fallback.truncated, true);
});

test('integrity independent: rejected unknown keys never echo canaries and SDK validation never fires getters/proxies', () => {
  const mutate: Array<(v: any) => void> = [v => { v[SECRET] = 'x'; }, v => { v.coverage[SECRET] = 0; },
    v => { v.findings[SECRET] = 0; }, v => { v.findings.by_severity[SECRET] = 0; },
    v => { v.status = 'partial'; v.gaps = [{ reason: 'timeout', count: 1, [SECRET]: 'x' }]; }];
  for (const alter of mutate) {
    const value = result(); alter(value); const rejected = parseWorkerResult(JSON.stringify(value), identity);
    assert.equal(rejected.ok, false); assert.equal(JSON.stringify(rejected).includes(SECRET), false);
    if (!rejected.ok && rejected.path) assert.ok(rejected.path.length <= 120, 'Rejection diagnostic remains bounded');
  }
  let fired = 0;
  const values: unknown[] = [new Proxy(result(), { get() { fired++; throw Error(SECRET); }, ownKeys() { fired++; throw Error(SECRET); } }),
    { ...result(), get coverage() { fired++; return { planned: 1, executed: 1, skipped: 0 }; } },
    { ...result(), coverage: { planned: 1, get executed() { fired++; return 1; }, skipped: 0 } },
    Object.assign(Object.create({}), result()), Object.assign(() => { fired++; }, result())];
  for (const value of values) assert.throws(() => validateWorkerResult(value));
  for (const expected of [new Proxy(identity, { get() { fired++; throw Error(SECRET); } }),
    { ...identity, get runId() { fired++; return RUN; } }]) {
    const rejected = parseWorkerResult(JSON.stringify(result()), expected); assert.equal(rejected.ok, false);
    assert.equal(JSON.stringify(rejected).includes(SECRET), false);
  }
  assert.equal(fired, 0);
});

const PROVIDER = 'fixed', CHECK = 'owned.check';
const ledger = (): any => ({ provider: PROVIDER, requestCount: 1, bytes: 100, exitCode: 0, stdoutBytes: 400, truncated: false });
function newRun(store: any, runId = RUN) {
  store.createRun({ runId, targetOrigin: 'https://owned.invalid', scopeHash: 'a'.repeat(64), provider: PROVIDER, startedAt: '2026-10-14T00:00:00Z' });
}
function surface(surfaceId = SURFACE, extra: Record<string, unknown> = {}): any {
  return { surfaceId, method: 'GET', path: '/owned/1', param: 'id', location: 'query', authState: 'user', ...extra };
}
function task(taskId = TASK, extra: Record<string, unknown> = {}): any {
  return { taskId, runId: RUN, category: 'injection', surfaceIds: [SURFACE], provider: PROVIDER, scriptRef: 'owned/constant-worker',
    coveragePlan: [{ surfaceId: SURFACE, check: CHECK }], ...extra };
}
function coverage(taskId = TASK, extra: Record<string, unknown> = {}): any {
  return { taskId, surfaceId: SURFACE, check: CHECK, result: 'executed', ...extra };
}
function finding(findingId: string, taskId = TASK, extra: Record<string, unknown> = {}): any {
  return { findingId, taskId, runId: RUN, surfaceId: SURFACE, check: CHECK, ruleId: 'owned.rule', severity: 'low', ...extra };
}
const TABLES = ['runs', 'surface', 'tasks', 'coverage_plan', 'coverage', 'findings', 'finding_observations', 'task_gaps', 'ledger'];
function state(db: DatabaseSync) { return clone(Object.fromEntries(TABLES.map(name => [name, db.prepare(`SELECT * FROM ${name} ORDER BY rowid`).all()]))); }
function rows(db: DatabaseSync, table: string) { return clone(db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()) as any[]; }
async function sqlFixture(kind: 'memory' | 'disk') {
  let directory: string | undefined, path: string | undefined;
  let store: any, oracle: DatabaseSync;
  if (kind === 'memory') { oracle = new DatabaseSync(':memory:'); store = new RunStore(oracle); }
  else { directory = await mkdtemp(join(tmpdir(), 'wakeio-owned-integrity-')); await chmod(directory, 0o700);
    path = join(directory, 'run.db'); store = await openRunStore(path); oracle = new DatabaseSync(path, { readOnly: true }); }
  newRun(store); store.addSurfaces(RUN, [surface()]);
  return { store, oracle, path, directory,
    fault(sql: string) { if (kind === 'memory') oracle.exec(sql); else { const owner = new DatabaseSync(path!); try { owner.exec(sql); } finally { owner.close(); } } },
    async close() { if (kind === 'disk') oracle.close(); store.close(); if (directory) await rm(directory, { recursive: true, force: true }); } };
}
function rejectsWithoutMutation(db: DatabaseSync, action: () => unknown) {
  const before = state(db); assert.throws(action); assert.deepEqual(state(db), before, 'Rejected operation changed independently observed SQLite rows');
}

test('integrity independent: actual memory/disk SQLite enforces declared same-run assigned coverage and immutable outcomes', async () => {
  for (const kind of ['memory', 'disk'] as const) {
    const f = await sqlFixture(kind); const { store: s, oracle: db } = f;
    try {
      newRun(s, 'r-other'); s.addSurfaces('r-other', [surface('s-other')]); s.addSurfaces(RUN, [surface('s-unassigned')]);
      for (const input of [task(TASK, { coveragePlan: [] }), task(TASK, { coveragePlan: [{ surfaceId: 's-other', check: CHECK }] }),
        task(TASK, { surfaceIds: ['s-other'], coveragePlan: [{ surfaceId: 's-other', check: CHECK }] }),
        task(TASK, { coveragePlan: [{ surfaceId: 's-unassigned', check: CHECK }] }),
        task(TASK, { coveragePlan: [{ surfaceId: SURFACE, check: CHECK }, { surfaceId: SURFACE, check: CHECK }] })]) {
        rejectsWithoutMutation(db, () => s.createTask(input));
      }
      const declared = task(); s.createTask(declared); declared.coveragePlan[0].check = 'changed-after-call'; declared.surfaceIds.push('s-other');
      assert.deepEqual(rows(db, 'coverage_plan').map(r => [r.task_id, r.surface_id, r.check]), [[TASK, SURFACE, CHECK]]);
      rejectsWithoutMutation(db, () => s.recordCoverage([coverage()])); s.startTask(TASK);
      for (const row of [coverage(TASK, { surfaceId: 's-other' }), coverage(TASK, { surfaceId: 's-unassigned' }), coverage(TASK, { check: 'unplanned' })]) {
        rejectsWithoutMutation(db, () => s.recordCoverage([row]));
      }
      rejectsWithoutMutation(db, () => s.recordCoverage([coverage(), coverage(TASK, { check: 'unplanned' })]));
      s.recordCoverage([coverage()]); const accepted = state(db); s.recordCoverage([coverage()]); assert.deepEqual(state(db), accepted);
      rejectsWithoutMutation(db, () => s.recordCoverage([coverage(TASK, { result: 'error', reason: 'tool_error' })]));
      s.createTask(task('t-error')); s.startTask('t-error'); s.recordCoverage([coverage('t-error', { result: 'error', reason: 'tool_error' })]);
      rejectsWithoutMutation(db, () => s.recordCoverage([coverage('t-error')]));
      assert.deepEqual(rows(db, 'coverage').map(r => [r.task_id, r.result, r.reason]), [[TASK, 'executed', null], ['t-error', 'error', 'tool_error']]);
      s.finishRun(RUN, 'partial', '2026-10-14T00:01:00Z');
      rejectsWithoutMutation(db, () => s.recordCoverage([coverage()])); rejectsWithoutMutation(db, () => s.recordFinding(finding('f-late')));
      rejectsWithoutMutation(db, () => s.createTask(task('t-late'))); rejectsWithoutMutation(db, () => s.addSurfaces(RUN, [surface('s-late')]));
    } finally { await f.close(); }
  }
});

test('integrity independent: worker claims cannot close missing/error plans or bad trusted ledger; coherent task/run closure is positive control', async () => {
  for (const kind of ['memory', 'disk'] as const) {
    const f = await sqlFixture(kind); const { store: s, oracle: db } = f;
    try {
      s.createTask(task()); s.startTask(TASK);
      rejectsWithoutMutation(db, () => s.completeTask(result(), ledger()));
      rejectsWithoutMutation(db, () => s.finishRun(RUN, 'completed', '2026-10-14T00:01:00Z'));
      s.recordCoverage([coverage()]);
      const badLedgers = [ { ...ledger(), provider: 'codex' }, { ...ledger(), exitCode: 1 }, { ...ledger(), exitCode: null },
        { ...ledger(), truncated: true }, { ...ledger(), stdoutBytes: 0 }, { ...ledger(), stdoutBytes: 2049 },
        { ...ledger(), requestCount: -1 }, { ...ledger(), requestCount: 1_000_000_001 }, { ...ledger(), bytes: 1_073_741_825 },
        { ...ledger(), truncated: 'false' }, { ...ledger(), inputTokens: 1.5 } ];
      for (const entry of badLedgers) rejectsWithoutMutation(db, () => s.completeTask(result(), entry));
      for (const claim of [result(TASK, { coverage: { planned: 2, executed: 2, skipped: 0 } }),
        result(TASK, { findings: { candidate: 1, by_severity: { high: 1 } }, finding_ids: ['f-invented'] }),
        result(TASK, { category: 'authz' }), result(TASK, { run_id: 'r-other' })]) rejectsWithoutMutation(db, () => s.completeTask(claim, ledger()));
      s.createTask(task('t-next')); s.startTask('t-next');
      s.completeTask(result(), ledger()); assert.equal(rows(db, 'tasks').find(r => r.task_id === TASK).status, 'completed');
      rejectsWithoutMutation(db, () => s.completeTask(result(), ledger())); rejectsWithoutMutation(db, () => s.recordCoverage([coverage()]));
      rejectsWithoutMutation(db, () => s.recordFinding(finding('f-after-task'))); rejectsWithoutMutation(db, () => s.startTask(TASK));
      rejectsWithoutMutation(db, () => s.finishRun(RUN, 'completed', '2026-10-14T00:01:00Z'));
      s.recordCoverage([coverage('t-next')]); s.completeTask(result('t-next'), ledger());
      s.finishRun(RUN, 'completed', '2026-10-14T00:01:00Z'); assert.equal(rows(db, 'runs').find(r => r.run_id === RUN).status, 'completed');
      assert.equal(rows(db, 'ledger').length, 2); assert.equal(s.roundSummary(RUN).tasks.completed, 2);
      rejectsWithoutMutation(db, () => s.finishRun(RUN, 'completed', '2026-10-14T00:02:00Z'));
      if (f.path) {
        const reopened = await openRunStore(f.path); try { assert.equal(reopened.roundSummary(RUN).tasks.completed, 2);
          rejectsWithoutMutation(db, () => reopened.createTask(task('t-after-reopen'))); } finally { reopened.close(); }
      }
    } finally { await f.close(); }
  }
});

test('integrity independent: dedupe preserves per-task evidence/max severity including confirmed and distinct auth/location; rejected new observation reopens', async () => {
  for (const kind of ['memory', 'disk'] as const) {
    const f = await sqlFixture(kind); const { store: s, oracle: db } = f;
    try {
      s.createTask(task()); s.startTask(TASK); s.createTask(task('t-peer')); s.startTask('t-peer');
      const low = finding('f-low', TASK, { evidenceRef: 'evidence/owned-low.json' });
      assert.deepEqual(s.recordFinding(low), { findingId: 'f-low', inserted: true });
      assert.deepEqual(s.recordFinding(finding('f-high', 't-peer', { severity: 'high', evidenceRef: 'evidence/owned-high.json' })), { findingId: 'f-low', inserted: false });
      low.evidenceRef = 'evidence/changed-after-call.json';
      assert.equal(rows(db, 'findings')[0].severity, 'high');
      assert.deepEqual(rows(db, 'finding_observations').map(r => [r.observation_id, r.finding_id, r.task_id, r.severity, r.evidence_ref]),
        [['f-low', 'f-low', TASK, 'low', 'evidence/owned-low.json'], ['f-high', 'f-low', 't-peer', 'high', 'evidence/owned-high.json']]);
      const beforeRepeat = state(db); s.recordFinding(finding('f-high', 't-peer', { severity: 'high', evidenceRef: 'evidence/owned-high.json' })); assert.deepEqual(state(db), beforeRepeat);
      s.setFindingState('f-low', 'confirmed'); assert.equal(s.roundSummary(RUN).open_by_severity.high, 1);
      s.recordCoverage([coverage(), coverage('t-peer')]);
      rejectsWithoutMutation(db, () => s.completeTask(result(TASK, { findings: { candidate: 1, by_severity: { high: 1 } }, finding_ids: ['f-low'] }), ledger()));
      rejectsWithoutMutation(db, () => s.completeTask(result('t-peer', { findings: { candidate: 1, by_severity: { high: 1 } }, finding_ids: ['f-high'] }), ledger()));
      s.completeTask(result(TASK, { findings: { candidate: 1, by_severity: { low: 1 } }, finding_ids: ['f-low'] }), ledger());
      s.completeTask(result('t-peer', { findings: { candidate: 1, by_severity: { high: 1 } }, finding_ids: ['f-low'] }), ledger());
      s.addSurfaces(RUN, [surface('s-admin', { authState: 'admin' }), surface('s-body', { location: 'body' }), surface('s-rejected', { path: '/another/1' })]);
      s.createTask(task('t-context', { surfaceIds: ['s-admin', 's-body', 's-rejected'], coveragePlan: ['s-admin', 's-body', 's-rejected'].map(surfaceId => ({ surfaceId, check: CHECK })) })); s.startTask('t-context');
      s.recordFinding(finding('f-admin', 't-context', { surfaceId: 's-admin', severity: 'high' })); s.recordFinding(finding('f-body', 't-context', { surfaceId: 's-body', severity: 'high' }));
      assert.equal(rows(db, 'findings').length, 3, 'Auth/location contexts cannot merge');
      s.recordFinding(finding('f-rejected', 't-context', { surfaceId: 's-rejected' })); s.setFindingState('f-rejected', 'rejected');
      const rejectedState = state(db); s.recordFinding(finding('f-rejected', 't-context', { surfaceId: 's-rejected' })); assert.deepEqual(state(db), rejectedState);
      s.recordFinding(finding('f-new', 't-context', { surfaceId: 's-rejected', severity: 'critical' }));
      const reopened = rows(db, 'findings').find(r => r.finding_id === 'f-rejected'); assert.equal(reopened.state, 'candidate'); assert.equal(reopened.severity, 'critical');
      assert.equal(rows(db, 'finding_observations').filter(r => r.finding_id === 'f-rejected').length, 2); assert.equal(s.roundSummary(RUN).open_by_severity.critical, 1);
    } finally { await f.close(); }
  }
});

test('integrity independent: batch/SQLite closure faults are atomic, fallback retains findings, hostile inputs do not execute and disk history survives', async () => {
  for (const kind of ['memory', 'disk'] as const) {
    const f = await sqlFixture(kind); const { store: s, oracle: db } = f; let fired = 0;
    try {
      s.createTask(task()); s.startTask(TASK); s.recordFinding(finding('f-kept')); s.setFindingState('f-kept', 'rejected');
      rejectsWithoutMutation(db, () => s.recordFindings([finding('f-batch-high', TASK, { severity: 'high' }), finding('f-batch-invalid', TASK, { check: 'unplanned' })]));
      assert.equal(rows(db, 'findings')[0].state, 'rejected'); assert.equal(rows(db, 'finding_observations').length, 1);
      for (const input of [new Proxy(finding('f-proxy'), { get() { fired++; throw Error(SECRET); }, ownKeys() { fired++; throw Error(SECRET); } }),
        { ...finding('f-getter'), get evidenceRef() { fired++; return 'evidence/owned.json'; } }]) rejectsWithoutMutation(db, () => s.recordFinding(input));
      const hostileLedger = { ...ledger(), get provider() { fired++; return PROVIDER; } };
      rejectsWithoutMutation(db, () => s.completeTask(result(), hostileLedger)); assert.equal(fired, 0);
      s.recordFinding(finding('f-reopened'));
      s.recordCoverage([coverage()]);
      f.fault("CREATE TRIGGER owned_ledger_fault BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT,'owned transaction fault'); END");
      const coherent = result(TASK, { findings: { candidate: 1, by_severity: { low: 1 } }, finding_ids: ['f-kept'] });
      rejectsWithoutMutation(db, () => s.completeTask(coherent, ledger())); f.fault('DROP TRIGGER owned_ledger_fault');
      s.completeTask(coherent, ledger()); assert.equal(rows(db, 'tasks')[0].status, 'completed', 'Same coherent input succeeds once owned SQL fault is removed');
      s.createTask(task('t-fallback')); s.startTask('t-fallback');
      s.recordFinding(finding('f-fallback', 't-fallback', { ruleId: 'owned.fallback', severity: 'high' }));
      const fallback = failedWorkerResult({ ...identity, taskId: 't-fallback' }, 'timeout', 300);
      s.completeTask(fallback, { ...ledger(), exitCode: null, truncated: false });
      assert.equal(rows(db, 'tasks').find(r => r.task_id === 't-fallback').status, 'error');
      assert.equal(rows(db, 'findings').length, 2); assert.equal(rows(db, 'finding_observations').length, 3);
      rejectsWithoutMutation(db, () => s.finishRun(RUN, 'completed', '2026-10-14T00:01:00Z'));
      s.finishRun(RUN, 'error', '2026-10-14T00:01:00Z');
      if (f.path) { const before = state(db); const reopened = await openRunStore(f.path);
        try { assert.deepEqual(state(db), before); assert.equal(reopened.roundSummary(RUN).findings.candidate, 2);
          rejectsWithoutMutation(db, () => reopened.recordFinding(finding('f-after-close'))); } finally { reopened.close(); } }
    } finally { await f.close(); }
  }
});

// Independent owned prototype-v1 schema fixture. No producer SQL or migration
// helper is imported/extracted; populated legacy evidence cannot acquire plans.
const LEGACY_SQL = `
CREATE TABLE runs(run_id TEXT PRIMARY KEY,target_origin TEXT NOT NULL,scope_hash TEXT NOT NULL,provider TEXT NOT NULL CHECK(provider IN('codex','claude','mixed','fixed')),started_at TEXT NOT NULL,finished_at TEXT,status TEXT NOT NULL CHECK(status IN('running','completed','partial','error')));
CREATE TABLE surface(surface_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),method TEXT NOT NULL,path TEXT NOT NULL,param TEXT,location TEXT CHECK(location IN('query','body','header','path','cookie')),auth_state TEXT NOT NULL CHECK(auth_state IN('anonymous','user','other_user','admin')));
CREATE TABLE tasks(task_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),category TEXT NOT NULL CHECK(category IN('recon','injection','authz','config','verify')),surface_ids TEXT NOT NULL,provider TEXT NOT NULL CHECK(provider IN('codex','claude','mixed','fixed')),script_ref TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('queued','running','completed','partial','error','skipped')),next_hint TEXT,duration_ms INTEGER);
CREATE TABLE task_gaps(task_id TEXT NOT NULL REFERENCES tasks(task_id),reason TEXT NOT NULL CHECK(reason IN('auth_required','timeout','budget_exhausted','out_of_scope','tool_error','unsupported')),count INTEGER NOT NULL CHECK(count>=1),PRIMARY KEY(task_id,reason));
CREATE TABLE findings(finding_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),task_id TEXT NOT NULL REFERENCES tasks(task_id),surface_id TEXT REFERENCES surface(surface_id),rule_id TEXT NOT NULL,severity TEXT NOT NULL CHECK(severity IN('critical','high','medium','low','info')),state TEXT NOT NULL CHECK(state IN('candidate','confirmed','rejected')),dedupe_key TEXT NOT NULL,evidence_ref TEXT NOT NULL,UNIQUE(run_id,dedupe_key));
CREATE TABLE coverage(task_id TEXT NOT NULL REFERENCES tasks(task_id),surface_id TEXT NOT NULL REFERENCES surface(surface_id),"check" TEXT NOT NULL,result TEXT NOT NULL CHECK(result IN('executed','skipped','error')),reason TEXT CHECK(reason IS NULL OR reason IN('auth_required','timeout','budget_exhausted','out_of_scope','tool_error','unsupported')),PRIMARY KEY(task_id,surface_id,"check"));
CREATE TABLE ledger(task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),provider TEXT NOT NULL CHECK(provider IN('codex','claude','mixed','fixed')),input_tokens INTEGER,output_tokens INTEGER,request_count INTEGER NOT NULL DEFAULT 0,bytes INTEGER NOT NULL DEFAULT 0,exit_code INTEGER,stdout_bytes INTEGER NOT NULL DEFAULT 0,truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN(0,1)));
CREATE INDEX idx_findings_state ON findings(run_id,state,severity);
CREATE INDEX idx_tasks_run ON tasks(run_id,status);
CREATE INDEX idx_coverage_result ON coverage(task_id,result);
PRAGMA user_version=1;
`;
test('integrity independent: new private disk schema works, populated prototypev1 refusal preserves exact bytes and empty v1 is explicit migration', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-owned-legacy-')); await chmod(top, 0o700);
  try {
    assert.equal(RUN_DB_VERSION, 2); const freshPath = join(top, 'fresh.db'); const fresh = await openRunStore(freshPath);
    try { newRun(fresh); assert.equal((await stat(freshPath)).mode & 0o777, 0o600); } finally { fresh.close(); }
    const legacy = join(top, 'legacy.db'), db = new DatabaseSync(legacy); db.exec(LEGACY_SQL);
    db.prepare("INSERT INTO runs VALUES(?,?,?,?,?,NULL,'running')").run(RUN, 'https://owned.invalid', 'a'.repeat(64), PROVIDER, '2026-10-14T00:00:00Z');
    db.close(); await chmod(legacy, 0o600); const before = await readFile(legacy);
    await assert.rejects(openRunStore(legacy)); assert.deepEqual(await readFile(legacy), before);
    for (const suffix of ['-wal', '-shm']) await assert.rejects(access(legacy + suffix));
    const empty = join(top, 'empty-v1.db'), emptyDb = new DatabaseSync(empty); emptyDb.exec(LEGACY_SQL); emptyDb.close(); await chmod(empty, 0o600);
    const migrated = await openRunStore(empty); try { newRun(migrated); migrated.addSurfaces(RUN, [surface()]); migrated.createTask(task()); migrated.startTask(TASK);
      migrated.recordCoverage([coverage()]); migrated.completeTask(result(), ledger()); assert.equal(migrated.roundSummary(RUN).tasks.completed, 1); }
    finally { migrated.close(); }
  } finally { await rm(top, { recursive: true, force: true }); }
});
