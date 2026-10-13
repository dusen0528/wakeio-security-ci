import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RUN_DB_VERSION, RunStoreError, dedupeKey, normalizePath, openRunStore, type RunStore } from '../src/agent-dast/store.js';
import { failedWorkerResult, type WorkerResultV1 } from '../src/agent-dast/result.js';

const runId = 'r-test-01';
const scopeHash = 'a'.repeat(64);

async function seeded(): Promise<RunStore> {
  const store = await openRunStore(':memory:');
  store.createRun({ runId, targetOrigin: 'http://127.0.0.1:3000', scopeHash, provider: 'fixed', startedAt: '2026-10-13T00:00:00Z' });
  store.addSurfaces(runId, [
    { surfaceId: 's-users-get', method: 'GET', path: '/api/users/{id}', param: 'id', location: 'path', authState: 'user' },
    { surfaceId: 's-search', method: 'GET', path: '/rest/products/search', param: 'q', location: 'query', authState: 'anonymous' },
  ]);
  store.createTask({ taskId: 't-a', runId, category: 'injection', surfaceIds: ['s-search'], provider: 'fixed', scriptRef: 'injection/sqli' });
  store.createTask({ taskId: 't-b', runId, category: 'injection', surfaceIds: ['s-search'], provider: 'fixed', scriptRef: 'injection/sqli-alt' });
  return store;
}

function result(taskId: string, overrides: Partial<WorkerResultV1> = {}): WorkerResultV1 {
  return {
    schema: 'wakeio.worker-result/v1', run_id: runId, task_id: taskId, category: 'injection', status: 'completed',
    coverage: { planned: 2, executed: 2, skipped: 0 }, findings: { candidate: 0, by_severity: {} },
    finding_ids: [], gaps: [], next_hint: 'none', duration_ms: 5, truncated: false, ...overrides,
  };
}
const ledger = { provider: 'fixed' as const, requestCount: 2, bytes: 100, exitCode: 0, stdoutBytes: 300, truncated: false };

test('path normalization collapses ID segments, query and trailing slash', () => {
  assert.equal(normalizePath('/api/users/12/orders/?x=1#y'), '/api/users/{id}/orders');
  assert.equal(normalizePath('/a/0f8fad5b-d9cb-469f-a165-70867728950e'), '/a/{id}');
  assert.equal(normalizePath('/'), '/');
  assert.equal(dedupeKey('sqli', 'get', '/users/1', 'id'), dedupeKey('sqli', 'GET', '/users/2/', 'id'));
  assert.notEqual(dedupeKey('sqli', 'GET', '/users/1', 'id'), dedupeKey('sqli', 'GET', '/users/1', 'name'));
});

test('two workers reporting the same problem produce one finding', async () => {
  const store = await seeded();
  const base = { runId, surfaceId: 's-search', ruleId: 'sqli.boolean', severity: 'high' as const, method: 'GET', path: '/rest/products/search?q=1', param: 'q' };
  assert.deepEqual(store.recordFinding({ ...base, findingId: 'f-1', taskId: 't-a' }), { findingId: 'f-1', inserted: true });
  assert.deepEqual(store.recordFinding({ ...base, findingId: 'f-2', taskId: 't-b' }), { findingId: 'f-1', inserted: false });
  assert.equal(store.roundSummary(runId).findings.candidate, 1);
  store.close();
});

test('a finding must belong to a task and surface of the same run', async () => {
  const store = await seeded();
  store.createRun({ runId: 'r-other', targetOrigin: 'http://127.0.0.1:4000', scopeHash, provider: 'fixed', startedAt: 'now' });
  const finding = { findingId: 'f-x', taskId: 't-a', ruleId: 'r', severity: 'low' as const, method: 'GET', path: '/' };
  assert.throws(() => store.recordFinding({ ...finding, runId: 'r-other' }), RunStoreError);
  assert.throws(() => store.recordFinding({ ...finding, runId, findingId: 'f-../x' }), RunStoreError);
  store.close();
});

test('task and finding state only move forward', async () => {
  const store = await seeded();
  assert.throws(() => store.completeTask(result('t-a'), ledger), /task is not running/);
  store.startTask('t-a');
  assert.throws(() => store.startTask('t-a'), /task is not queued/);
  store.recordFinding({ findingId: 'f-1', runId, taskId: 't-a', ruleId: 'xss', severity: 'medium', method: 'GET', path: '/x' });
  store.setFindingState('f-1', 'confirmed');
  assert.throws(() => store.setFindingState('f-1', 'rejected'), /not a candidate/);
  store.close();
});

test('a result cannot close another run\'s or another category\'s task', async () => {
  const store = await seeded();
  store.startTask('t-a');
  assert.throws(() => store.completeTask(result('t-a', { category: 'authz' }), ledger), /task is not running/);
  assert.throws(() => store.completeTask(result('t-a', { run_id: 'r-other' }), ledger), /task is not running/);
  store.close();
});

test('round summary is a fixed-shape aggregate of tasks, findings, gaps and hints', async () => {
  const store = await seeded();
  store.startTask('t-a');
  store.recordFinding({ findingId: 'f-1', runId, taskId: 't-a', surfaceId: 's-search', ruleId: 'sqli', severity: 'high', method: 'GET', path: '/rest/products/search', param: 'q' });
  store.completeTask(result('t-a', {
    status: 'partial', findings: { candidate: 1, by_severity: { high: 1 } }, finding_ids: ['f-1'],
    gaps: [{ reason: 'auth_required', count: 3 }], next_hint: 'verify',
  }), { ...ledger, inputTokens: 900, outputTokens: 120 });
  store.startTask('t-b');
  store.completeTask(failedWorkerResult({ runId, taskId: 't-b', category: 'injection' }, 'timeout', 60_000), { ...ledger, exitCode: null });

  const summary = store.roundSummary(runId);
  assert.deepEqual(summary, {
    run_id: runId,
    tasks: { queued: 0, running: 0, completed: 0, partial: 1, error: 1, skipped: 0 },
    findings: { candidate: 1, confirmed: 0, rejected: 0 },
    open_by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    gaps: { auth_required: 3, timeout: 1 },
    needs_verify: 1,
    needs_retry: 1,
  });
  // The summary carries counts only: no paths, parameters or evidence references.
  const text = JSON.stringify(summary);
  for (const leak of ['/rest/products', 's-search', 'f-1', 'evidence/', 'sqli']) assert.ok(!text.includes(leak), leak);
  store.close();
});

test('coverage rows need a reason exactly when a check did not execute', async () => {
  const store = await seeded();
  store.recordCoverage([{ taskId: 't-a', surfaceId: 's-search', check: 'sqli.boolean', result: 'executed' }]);
  assert.throws(() => store.recordCoverage([{ taskId: 't-a', surfaceId: 's-search', check: 'x', result: 'skipped' }]), RunStoreError);
  assert.throws(() => store.recordCoverage([{ taskId: 't-a', surfaceId: 's-search', check: 'y', result: 'executed', reason: 'timeout' }]), RunStoreError);
  store.close();
});

test('a run.db file is migrated once, reopened, and refused when newer than this build', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wakeio-run-db-'));
  try {
    const path = join(dir, 'run.db');
    const first = await openRunStore(path);
    first.createRun({ runId, targetOrigin: 'https://example.test', scopeHash, provider: 'codex', startedAt: 'now' });
    first.close();
    const again = await openRunStore(path);
    assert.equal(again.roundSummary(runId).run_id, runId);
    again.close();

    const { DatabaseSync } = await import('node:sqlite');
    const raw = new DatabaseSync(path);
    raw.exec(`PRAGMA user_version = ${RUN_DB_VERSION + 1}`);
    raw.close();
    await assert.rejects(openRunStore(path), (error: unknown) => error instanceof RunStoreError && error.code === 'unsupported_version');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('run inputs are validated before they reach SQL', async () => {
  const store = await openRunStore(':memory:');
  const run = { runId, targetOrigin: 'http://127.0.0.1:3000', scopeHash, provider: 'fixed' as const, startedAt: 'now' };
  assert.throws(() => store.createRun({ ...run, targetOrigin: 'http://127.0.0.1:3000/path' }), RunStoreError);
  assert.throws(() => store.createRun({ ...run, targetOrigin: 'file:///etc/passwd' }), RunStoreError);
  assert.throws(() => store.createRun({ ...run, runId: 'R_1' }), RunStoreError);
  assert.throws(() => store.createRun({ ...run, provider: 'gpt' as never }), RunStoreError);
  store.close();
});
