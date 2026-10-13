import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { RUN_DB_VERSION, RunStore, RunStoreError, dedupeKey, normalizePath, openRunStore, type NewFinding, type LedgerEntry } from '../src/agent-dast/store.js';
import { failedWorkerResult, WORKER_RESULT_SCHEMA, type WorkerResultV1 } from '../src/agent-dast/result.js';

const at = '2026-10-14T00:00:00.000Z';
const runId = 'r-owned';
const ledger: LedgerEntry = { provider: 'fixed', requestCount: 2, bytes: 100, exitCode: 0, stdoutBytes: 400, truncated: false };
function seeded() {
  const db = new DatabaseSync(':memory:'), store = new RunStore(db);
  store.createRun({ runId, targetOrigin: 'http://127.0.0.1:3000', scopeHash: 'a'.repeat(64), provider: 'fixed', startedAt: at });
  store.addSurfaces(runId, [
    { surfaceId: 's-search', method: 'GET', path: '/search', param: 'q', location: 'query', authState: 'anonymous' },
    { surfaceId: 's-user', method: 'GET', path: '/search', param: 'q', location: 'query', authState: 'user' },
    { surfaceId: 's-body', method: 'GET', path: '/search', param: 'q', location: 'body', authState: 'anonymous' },
  ]);
  for (const taskId of ['t-a', 't-b']) store.createTask({ taskId, runId, category: 'injection', surfaceIds: ['s-search', 's-user', 's-body'],
    coveragePlan: ['s-search', 's-user', 's-body'].map(surfaceId => ({ surfaceId, check: 'sqli' })), provider: 'fixed', scriptRef: 'owned-worker.mjs' });
  return { store, db };
}
function finding(overrides: Partial<NewFinding> = {}): NewFinding {
  return { findingId: 'f-a', runId, taskId: 't-a', surfaceId: 's-search', check: 'sqli', ruleId: 'sqli', severity: 'low', ...overrides };
}
function completed(overrides: Partial<WorkerResultV1> = {}): WorkerResultV1 {
  return { schema: WORKER_RESULT_SCHEMA, run_id: runId, task_id: 't-a', category: 'injection', status: 'completed',
    coverage: { planned: 3, executed: 3, skipped: 0 }, findings: { candidate: 0, by_severity: {} }, finding_ids: [], gaps: [],
    next_hint: 'none', duration_ms: 5, truncated: false, ...overrides };
}
function executePlan(store: RunStore, taskId = 't-a') {
  store.recordCoverage(['s-search', 's-user', 's-body'].map(surfaceId => ({ taskId, surfaceId, check: 'sqli', result: 'executed' as const })));
}
const invalid = (error: unknown) => error instanceof RunStoreError && error.code === 'invalid_input';

test('dedupe identity preserves auth and parameter location without delimiter collisions', () => {
  assert.equal(normalizePath('/users/12/?ignored=1'), '/users/{id}');
  assert.equal(dedupeKey('sqli', 'get', '/users/1', 'id', 'user', 'path'), dedupeKey('sqli', 'GET', '/users/2/', 'id', 'user', 'path'));
  assert.notEqual(dedupeKey('sqli', 'GET', '/search', 'q', 'user', 'query'), dedupeKey('sqli', 'GET', '/search', 'q', 'anonymous', 'query'));
  assert.notEqual(dedupeKey('sqli', 'GET', '/search', 'q', 'user', 'query'), dedupeKey('sqli', 'GET', '/search', 'q', 'user', 'body'));
});

test('plans bind same-run assigned surfaces before execution; batches roll back', () => {
  const { store, db } = seeded();
  try {
    const base = { taskId: 't-new', runId, category: 'injection' as const, surfaceIds: ['s-search'], coveragePlan: [{ surfaceId: 's-search', check: 'sqli' }], provider: 'fixed' as const, scriptRef: 'owned.mjs' };
    for (const bad of [{ ...base, coveragePlan: [] }, { ...base, surfaceIds: ['s-missing'] }, { ...base, coveragePlan: [...base.coveragePlan, ...base.coveragePlan] },
      { ...base, coveragePlan: [{ surfaceId: 's-user', check: 'sqli' }] }]) assert.throws(() => store.createTask(bad), RunStoreError);
    assert.equal(db.prepare('SELECT count(*) n FROM tasks').get()?.n, 2);
    assert.throws(() => store.recordFinding(finding()), RunStoreError);
    store.startTask('t-a');
    assert.throws(() => store.recordCoverage([{ taskId: 't-a', surfaceId: 's-search', check: 'sqli', result: 'executed' }, { taskId: 't-a', surfaceId: 's-user', check: 'other', result: 'executed' }]), RunStoreError);
    assert.equal(db.prepare('SELECT count(*) n FROM coverage').get()?.n, 0);
    assert.throws(() => store.recordFindings([finding(), finding({ findingId: 'f-b', surfaceId: 's-user', check: 'other' })]), RunStoreError);
    assert.equal(db.prepare('SELECT count(*) n FROM findings').get()?.n, 0);
    store.createRun({ runId: 'r-other', targetOrigin: 'http://127.0.0.1:3001', scopeHash: 'b'.repeat(64), provider: 'fixed', startedAt: at });
    store.addSurfaces('r-other', [{ surfaceId: 's-other', method: 'GET', path: '/other', authState: 'anonymous' }]);
    assert.throws(() => store.recordCoverage([{ taskId: 't-a', surfaceId: 's-other', check: 'sqli', result: 'executed' }]), RunStoreError);
  } finally { store.close(); }
});

test('coverage is immutable, exact retries idempotent and conflicting retries atomic', () => {
  const { store, db } = seeded();
  try {
    store.startTask('t-a');
    const row = { taskId: 't-a', surfaceId: 's-search', check: 'sqli', result: 'error' as const, reason: 'timeout' as const };
    store.recordCoverage([row]); store.recordCoverage([row]);
    assert.throws(() => store.recordCoverage([{ taskId: 't-a', surfaceId: 's-user', check: 'sqli', result: 'executed' }, { ...row, result: 'executed', reason: null }]), RunStoreError);
    assert.equal(db.prepare('SELECT count(*) n FROM coverage').get()?.n, 1);
    assert.equal(db.prepare('SELECT result FROM coverage').get()?.result, 'error');
    assert.throws(() => store.recordCoverage([{ ...row, reason: 'tool_error' }]), RunStoreError);
  } finally { store.close(); }
});

test('canonical findings retain all task observations, max severity and fresh rejected observations', () => {
  const { store, db } = seeded();
  try {
    store.startTask('t-a'); store.startTask('t-b');
    assert.deepEqual(store.recordFinding(finding()), { findingId: 'f-a', inserted: true });
    const high = finding({ findingId: 'f-b', taskId: 't-b', severity: 'high', evidenceRef: 'evidence/second.json' });
    assert.deepEqual(store.recordFinding(high), { findingId: 'f-a', inserted: false });
    store.recordFinding(high); assert.equal(db.prepare('SELECT count(*) n FROM finding_observations').get()?.n, 2);
    assert.throws(() => store.recordFinding({ ...high, severity: 'critical' }), RunStoreError);
    assert.equal(store.roundSummary(runId).open_by_severity.high, 1);
    store.setFindingState('f-a', 'confirmed'); assert.equal(store.roundSummary(runId).open_by_severity.high, 1);
    store.recordFinding(finding({ findingId: 'f-c', severity: 'info' }));
    assert.equal(db.prepare('SELECT severity,state FROM findings WHERE finding_id=?').get('f-a')?.state, 'confirmed');
    store.recordFinding(finding({ findingId: 'f-user', surfaceId: 's-user' })); store.recordFinding(finding({ findingId: 'f-body', surfaceId: 's-body' }));
    assert.equal(store.roundSummary(runId).findings.candidate, 2);
    store.setFindingState('f-user', 'rejected');
    store.recordFinding(finding({ findingId: 'f-user', surfaceId: 's-user' })); assert.equal(store.roundSummary(runId).findings.rejected, 1);
    store.recordFinding(finding({ findingId: 'f-fresh', surfaceId: 's-user', severity: 'critical' })); assert.equal(store.roundSummary(runId).findings.rejected, 0);
    assert.throws(() => store.recordFinding(finding({ findingId: 'f-a', ruleId: 'different' })), RunStoreError);
    assert.equal(db.prepare('SELECT count(*) n FROM finding_observations').get()?.n, 6);
  } finally { store.close(); }
});

test('completion reconciles persisted full plan, task-local findings and successful ledger', () => {
  const { store, db } = seeded();
  try {
    store.startTask('t-a'); store.startTask('t-b');
    store.recordFinding(finding()); store.recordFinding(finding({ findingId: 'f-b', taskId: 't-b', severity: 'high' }));
    assert.throws(() => store.completeTask(completed(), ledger), RunStoreError);
    executePlan(store);
    const coherent = completed({ findings: { candidate: 1, by_severity: { low: 1 } }, finding_ids: ['f-a'] });
    for (const bad of [{ ...ledger, provider: 'codex' as const }, { ...ledger, exitCode: null }, { ...ledger, exitCode: 1 }, { ...ledger, stdoutBytes: 0 }, { ...ledger, stdoutBytes: 2049 }, { ...ledger, truncated: true }]) assert.throws(() => store.completeTask(coherent, bad), RunStoreError);
    for (const bad of [completed(), { ...coherent, finding_ids: ['f-invented'] }, { ...coherent, findings: { candidate: 1, by_severity: { high: 1 } } }]) assert.throws(() => store.completeTask(bad, ledger), RunStoreError);
    assert.equal(db.prepare('SELECT count(*) n FROM ledger').get()?.n, 0);
    store.completeTask(coherent, ledger);
    assert.equal(store.roundSummary(runId).tasks.completed, 1);
    assert.equal(store.roundSummary(runId).open_by_severity.high, 1);
    assert.throws(() => store.completeTask(coherent, ledger), RunStoreError);
    assert.throws(() => store.recordFinding(finding({ findingId: 'f-late' })), RunStoreError);
    assert.throws(() => store.recordCoverage([{ taskId: 't-a', surfaceId: 's-search', check: 'sqli', result: 'executed' }]), RunStoreError);
    assert.throws(() => store.finishRun(runId, 'completed', at), RunStoreError);
    executePlan(store, 't-b'); store.completeTask(completed({ task_id: 't-b', findings: { candidate: 1, by_severity: { high: 1 } }, finding_ids: ['f-a'] }), ledger);
    store.finishRun(runId, 'completed', at);
    assert.throws(() => store.addSurfaces(runId, [{ surfaceId: 's-late', method: 'GET', path: '/late', authState: 'anonymous' }]), RunStoreError);
    assert.throws(() => store.setFindingState('f-a', 'confirmed'), RunStoreError);
    assert.throws(() => store.finishRun(runId, 'completed', at), RunStoreError);
  } finally { store.close(); }
});

test('error fallback preserves accepted observations and incomplete run state', () => {
  const { store, db } = seeded();
  try {
    store.startTask('t-a'); store.recordFinding(finding());
    store.recordCoverage([{ taskId: 't-a', surfaceId: 's-search', check: 'sqli', result: 'error', reason: 'timeout' }]);
    store.completeTask(failedWorkerResult({ runId, taskId: 't-a', category: 'injection' }, 'output_too_large', 5), { ...ledger, exitCode: null, stdoutBytes: 4000, truncated: true });
    assert.equal(store.roundSummary(runId).findings.candidate, 1); assert.equal(store.roundSummary(runId).tasks.error, 1);
    assert.equal(db.prepare('SELECT count(*) n FROM finding_observations').get()?.n, 1);
    assert.throws(() => store.finishRun(runId, 'completed', at), RunStoreError);
    store.finishRun(runId, 'partial', at); assert.throws(() => store.startTask('t-b'), RunStoreError);
  } finally { store.close(); }
});

test('SDK snapshots reject caller code and fixed errors exclude unknown secret keys', () => {
  const { store } = seeded(); let fired = 0;
  try {
    const accessor = Object.defineProperty({}, 'runId', { enumerable: true, get() { fired++; return runId; } });
    assert.throws(() => store.createRun(accessor as never), invalid);
    const proxy = new Proxy({}, { ownKeys() { fired++; return []; } }); assert.throws(() => store.createTask(proxy as never), invalid);
    assert.throws(() => store.recordFinding({ ...finding(), owned_secret_canary: 'token' } as never), (error: unknown) => invalid(error) && !String(error).includes('owned_secret_canary'));
    assert.equal(fired, 0);
    for (const run of [null, [], { runId: {}, targetOrigin: 'http://127.0.0.1', scopeHash: 'a'.repeat(64), provider: 'fixed', startedAt: at }]) assert.throws(() => store.createRun(run as never), invalid);
  } finally { store.close(); }
});

test('SQLite task-close failure rolls back status/gaps/ledger while retaining prior observations', () => {
  const { store, db } = seeded();
  try {
    store.startTask('t-a'); store.recordFinding(finding());
    db.exec("CREATE TRIGGER owned_ledger_fault BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT,'owned-fault'); END");
    const fallback = failedWorkerResult({ runId, taskId: 't-a', category: 'injection' }, 'timeout', 5);
    assert.throws(() => store.completeTask(fallback, { ...ledger, exitCode: null }), (error: unknown) => error instanceof RunStoreError && error.code === 'storage_error');
    assert.equal(db.prepare('SELECT status FROM tasks WHERE task_id=?').get('t-a')?.status, 'running');
    assert.equal(db.prepare('SELECT count(*) n FROM task_gaps').get()?.n, 0);
    assert.equal(db.prepare('SELECT count(*) n FROM ledger').get()?.n, 0);
    assert.equal(db.prepare('SELECT count(*) n FROM finding_observations').get()?.n, 1);
    db.exec('DROP TRIGGER owned_ledger_fault'); store.completeTask(fallback, { ...ledger, exitCode: null });
    assert.equal(store.roundSummary(runId).tasks.error, 1);
  } finally { store.close(); }
});

test('more than twenty distinct findings stays incomplete and preserves every observation', () => {
  const { store, db } = seeded();
  try {
    store.startTask('t-a'); executePlan(store);
    const ids = Array.from({ length: 21 }, (_, i) => `f-owned-${i}`);
    store.recordFindings(ids.map((findingId, i) => finding({ findingId, ruleId: `rule-${i}` })));
    const result = completed({ findings: { candidate: 21, by_severity: { low: 21 } }, finding_ids: ids.slice(0, 20) });
    assert.throws(() => store.completeTask(result, ledger), RunStoreError);
    store.completeTask({ ...result, status: 'partial', gaps: [{ reason: 'budget_exhausted', count: 1 }] }, ledger);
    assert.equal(db.prepare('SELECT count(*) n FROM finding_observations').get()?.n, 21);
    assert.equal(store.roundSummary(runId).findings.candidate, 21); assert.equal(store.roundSummary(runId).tasks.partial, 1);
  } finally { store.close(); }
});

test('disk reopen retains evidence, serial connections dedupe and files stay private', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'wakeio-store-')); const path = join(directory, 'run.db');
  try {
    const first = await openRunStore(path);
    first.createRun({ runId, targetOrigin: 'http://127.0.0.1', scopeHash: 'a'.repeat(64), provider: 'fixed', startedAt: at });
    first.addSurfaces(runId, [{ surfaceId: 's-owned', method: 'GET', path: '/owned', authState: 'anonymous' }]);
    for (const taskId of ['t-a', 't-b']) first.createTask({ taskId, runId, category: 'injection', surfaceIds: ['s-owned'], coveragePlan: [{ surfaceId: 's-owned', check: 'sqli' }], provider: 'fixed', scriptRef: 'owned.mjs' });
    first.startTask('t-a'); first.startTask('t-b'); const second = await openRunStore(path);
    first.recordFinding(finding({ surfaceId: 's-owned' })); second.recordFinding(finding({ findingId: 'f-b', taskId: 't-b', surfaceId: 's-owned', severity: 'high' }));
    first.close(); second.close(); const reopened = await openRunStore(path);
    assert.equal(reopened.roundSummary(runId).open_by_severity.high, 1); reopened.close();
    assert.equal(lstatSync(path).mode & 0o777, 0o600);
    const observer = new DatabaseSync(path, { readOnly: true }); assert.equal(observer.prepare('PRAGMA user_version').get()?.user_version, RUN_DB_VERSION);
    assert.equal(observer.prepare('SELECT count(*) n FROM finding_observations').get()?.n, 2); observer.close();
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('summary uses one read snapshot while an independently owned WAL connection commits', () => {
  const directory = mkdtempSync(join(tmpdir(), 'wakeio-summary-')), path = join(directory, 'run.db');
  const db = new DatabaseSync(path), store = new RunStore(db);
  let peer: RunStore | undefined;
  try {
    store.createRun({ runId, targetOrigin: 'http://127.0.0.1', scopeHash: 'a'.repeat(64), provider: 'fixed', startedAt: at });
    store.addSurfaces(runId, [{ surfaceId: 's-owned', method: 'GET', path: '/owned', authState: 'anonymous' }]);
    const task = { runId, category: 'injection' as const, surfaceIds: ['s-owned'], coveragePlan: [{ surfaceId: 's-owned', check: 'sqli' }], provider: 'fixed' as const, scriptRef: 'owned.mjs' };
    store.createTask({ ...task, taskId: 't-a' }); store.startTask('t-a');
    store.recordCoverage([{ taskId: 't-a', surfaceId: 's-owned', check: 'sqli', result: 'executed' }]);
    store.completeTask(completed({ coverage: { planned: 1, executed: 1, skipped: 0 } }), ledger);
    // Only caller-owned native connections use WAL; the private factory still refuses WAL input.
    assert.equal(db.prepare('PRAGMA journal_mode=WAL').get()?.journal_mode, 'wal');
    const other = new DatabaseSync(path); peer = new RunStore(other); other.exec('PRAGMA busy_timeout=0');
    const nativePrepare = db.prepare.bind(db); let peerCommitted = false;
    db.prepare = sql => {
      const statement = nativePrepare(sql);
      if (sql !== 'SELECT status, count(*) AS n FROM tasks WHERE run_id = ? GROUP BY status') return statement;
      return new Proxy(statement, { get(target, key) {
        if (key === 'all') return (...parameters: unknown[]) => {
          const rows = Reflect.apply(target.all, target, parameters);
          if (!peerCommitted) {
            peer!.createTask({ ...task, taskId: 't-peer' }); peer!.startTask('t-peer');
            peer!.recordFinding(finding({ findingId: 'f-peer', taskId: 't-peer', surfaceId: 's-owned', severity: 'high' }));
            peerCommitted = true;
          }
          return rows;
        };
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    };
    const snapshot = store.roundSummary(runId);
    assert.equal(peerCommitted, true); assert.equal(snapshot.tasks.completed, 1);
    assert.equal(snapshot.tasks.running, 0); assert.equal(snapshot.findings.candidate, 0);
    const next = store.roundSummary(runId); assert.equal(next.tasks.running, 1); assert.equal(next.findings.candidate, 1);
  } finally { peer?.close(); store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('populated prototype v1 refuses without altering its bytes; malformed empty schema refuses', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'wakeio-legacy-')); const path = join(directory, 'run.db');
  try {
    const db = new DatabaseSync(path);
    // An independently owned minimal prototype table set cannot acquire invented plans.
    for (const name of ['runs', 'surface', 'tasks', 'task_gaps', 'findings', 'coverage', 'ledger']) db.exec(`CREATE TABLE ${name}(owned TEXT)`);
    db.exec("INSERT INTO findings VALUES('retained-owned-evidence'); PRAGMA user_version=1"); db.close(); chmodSync(path, 0o600);
    const bytes = readFileSync(path);
    await assert.rejects(openRunStore(path), (error: unknown) => error instanceof RunStoreError && error.code === 'legacy_evidence_untrusted');
    assert.deepEqual(readFileSync(path), bytes);
    const empty = new DatabaseSync(path); empty.exec('DELETE FROM findings'); empty.close();
    // Malformed empty schema is not a supported prototype. It must fail without a clean store.
    await assert.rejects(openRunStore(path), RunStoreError);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('unsafe paths and unsupported versions fail without a clean result', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'wakeio-private-')), path = join(directory, 'run.db');
  try {
    const store = await openRunStore(path); store.close();
    chmodSync(path, 0o644); await assert.rejects(openRunStore(path), (error: unknown) => error instanceof RunStoreError && error.code === 'unsafe_path'); chmodSync(path, 0o600);
    symlinkSync(path, join(directory, 'linked.db')); await assert.rejects(openRunStore(join(directory, 'linked.db')), (error: unknown) => error instanceof RunStoreError && error.code === 'unsafe_path');
    const db = new DatabaseSync(path); db.exec(`PRAGMA user_version=${RUN_DB_VERSION + 1}`); db.close(); const bytes = readFileSync(path);
    await assert.rejects(openRunStore(path), (error: unknown) => error instanceof RunStoreError && error.code === 'unsupported_version'); assert.deepEqual(readFileSync(path), bytes);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('WAL-mode input is refused before SQLite opening and all original bytes remain', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'wakeio-wal-')), path = join(directory, 'run.db');
  try {
    const db = new DatabaseSync(path); db.exec("PRAGMA journal_mode=WAL; CREATE TABLE retained(owned TEXT); INSERT INTO retained VALUES('owned'); PRAGMA user_version=1");
    chmodSync(path, 0o600);
    const before = [path, `${path}-wal`, `${path}-shm`].map(file => readFileSync(file));
    await assert.rejects(openRunStore(path), (error: unknown) => error instanceof RunStoreError && error.code === 'legacy_evidence_untrusted');
    assert.deepEqual([path, `${path}-wal`, `${path}-shm`].map(file => readFileSync(file)), before); db.close();
    const closed = readFileSync(path); await assert.rejects(openRunStore(path), (error: unknown) => error instanceof RunStoreError && error.code === 'legacy_evidence_untrusted');
    assert.deepEqual(readFileSync(path), closed); assert.equal(existsSync(`${path}-wal`), false); assert.equal(existsSync(`${path}-shm`), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('mock unsupported runtime guards precede factory file writes and constructor schema writes', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'wakeio-runtime-')), path = join(directory, 'run.db');
  const descriptor = Object.getOwnPropertyDescriptor(process.versions, 'node')!;
  const db = new DatabaseSync(':memory:');
  try {
    for (const version of ['22.5.0', '22.12.0', '23.3.0', '20.18.0']) {
      Object.defineProperty(process.versions, 'node', { ...descriptor, value: version });
      await assert.rejects(openRunStore(path), (error: unknown) => error instanceof RunStoreError && error.code === 'node_sqlite_unavailable');
      assert.throws(() => new RunStore(db), (error: unknown) => error instanceof RunStoreError && error.code === 'node_sqlite_unavailable');
      assert.equal(existsSync(path), false);
      assert.equal(db.prepare("SELECT count(*) n FROM sqlite_master WHERE type='table'").get()?.n, 0);
    }
  } finally { Object.defineProperty(process.versions, 'node', descriptor); db.close(); rmSync(directory, { recursive: true, force: true }); }
});
