import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { RunStore } from '../src/agent-dast/store.js';

// Owned native WAL connections, not openRunStore: the native-connection caller
// owns storage policy. Factory WAL refusal remains its separate contract.
// The hook returns actual SQLite rows unchanged; it only schedules a genuine
// peer SDK commit after the first real task-count SELECT has completed.
test('integrity independent supplement: deferred WAL summary permits peer commit while retaining one old read snapshot, then sees new snapshot', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-owned-summary-'));
  await chmod(top, 0o700); const path = join(top, 'run.db');
  const reader = new DatabaseSync(path); await chmod(path, 0o600); reader.exec('PRAGMA journal_mode=WAL');
  let readerStore: RunStore | undefined, writer: DatabaseSync | undefined, writerStore: RunStore | undefined;
  try {
    readerStore = new RunStore(reader);
    writer = new DatabaseSync(path); writerStore = new RunStore(writer);
    const runId = 'r-owned-snapshot', surfaceId = 's-owned-snapshot';
    readerStore.createRun({ runId, targetOrigin: 'https://owned.invalid', scopeHash: 'a'.repeat(64), provider: 'fixed', startedAt: '2026-10-14T00:00:00Z' });
    readerStore.addSurfaces(runId, [{ surfaceId, method: 'GET', path: '/owned/1', param: 'id', location: 'query', authState: 'user' }]);
    const task = (taskId: string) => ({ taskId, runId, category: 'injection' as const, surfaceIds: [surfaceId],
      coveragePlan: [{ surfaceId, check: 'owned.check' }], provider: 'fixed' as const, scriptRef: 'owned/snapshot' });
    readerStore.createTask(task('t-a')); readerStore.startTask('t-a');
    readerStore.recordCoverage([{ taskId: 't-a', surfaceId, check: 'owned.check', result: 'executed' }]);
    readerStore.completeTask({ schema: 'wakeio.worker-result/v1', run_id: runId, task_id: 't-a', category: 'injection', status: 'completed',
      coverage: { planned: 1, executed: 1, skipped: 0 }, findings: { candidate: 0, by_severity: {} }, finding_ids: [], gaps: [],
      next_hint: 'none', duration_ms: 1, truncated: false },
    { provider: 'fixed', requestCount: 1, bytes: 10, exitCode: 0, stdoutBytes: 400, truncated: false });
    let scheduled = 0; const realPrepare = reader.prepare.bind(reader);
    reader.prepare = ((sql: string) => {
      const statement = realPrepare(sql);
      if (/SELECT\s+status,\s*count\(\*\)\s+AS\s+n\s+FROM\s+tasks\s+WHERE/i.test(sql)) {
        const realAll: any = statement.all.bind(statement);
        statement.all = ((...args: any[]) => {
          const actual = realAll(...args);
          if (scheduled === 0) {
            assert.deepEqual(JSON.parse(JSON.stringify(actual)), [{ status: 'completed', n: 1 }]);
            scheduled++;
            writerStore!.createTask(task('t-b')); writerStore!.startTask('t-b');
            writerStore!.recordFinding({ findingId: 'f-peer', runId, taskId: 't-b', surfaceId, check: 'owned.check', ruleId: 'owned.rule', severity: 'high' });
            // Direct native peer reads independently prove committed writes;
            // no product summary or invented rows serve as this witness.
            assert.equal((writer!.prepare("SELECT count(*) AS n FROM tasks WHERE run_id=? AND status='running'").get(runId) as any).n, 1);
            assert.equal((writer!.prepare("SELECT count(*) AS n FROM findings WHERE run_id=? AND severity='high'").get(runId) as any).n, 1);
          }
          return actual;
        }) as typeof statement.all;
      }
      return statement;
    }) as typeof reader.prepare;
    const before = readerStore.roundSummary(runId);
    assert.equal(scheduled, 1, 'Owned peer COMMIT must actually occur during the summary read');
    assert.equal(before.tasks.completed, 1); assert.equal(before.tasks.running, 0); assert.equal(before.tasks.queued, 0);
    assert.deepEqual(before.findings, { candidate: 0, confirmed: 0, rejected: 0 });
    assert.equal(before.open_by_severity.high, 0); assert.deepEqual(before.gaps, {});
    const after = readerStore.roundSummary(runId);
    assert.equal(after.tasks.completed, 1); assert.equal(after.tasks.running, 1); assert.equal(after.tasks.queued, 0);
    assert.deepEqual(after.findings, { candidate: 1, confirmed: 0, rejected: 0 }); assert.equal(after.open_by_severity.high, 1);
    assert.deepEqual(readerStore.roundSummary(runId), after, 'Next unchanged read remains coherent');
  } finally {
    if (writerStore) writerStore.close(); else writer?.close();
    if (readerStore) readerStore.close(); else reader.close();
    await rm(top, { recursive: true, force: true });
  }
});
