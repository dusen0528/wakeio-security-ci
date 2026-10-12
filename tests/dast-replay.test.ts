import test from 'node:test';
import assert from 'node:assert/strict';
import { createReport } from '../src/report.js';
import { runDast, type DastPolicy } from '../src/dast.js';
import { replayDastFinding, dastReplayExitCode } from '../src/dast-replay.js';

const fixtureModule = new URL('../../examples/native-dast-sqlite.mjs', import.meta.url).href;
type Fixture = { origin: string; url: string; requests: Array<{ method: string; path: string; id: string | null }>;
  setMode(mode: string): void; close(): Promise<void> };
async function fixture(): Promise<Fixture> {
  return (await import(fixtureModule)).startNativeDastSqlite('vulnerable') as Promise<Fixture>;
}
function policy(target: Fixture): DastPolicy {
  return { version: 1, kind: 'sql-boolean-differential', baseUrl: `${target.origin}/`, url: target.url,
    parameter: 'id', profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
}
async function original(target: Fixture) {
  const currentPolicy = policy(target);
  const [check] = await runDast({ policy: currentPolicy, consent: true, allowPrivate: true, maxRequests: 9, timeoutMs: 5000 });
  assert.equal(check.status, 'completed');
  assert.equal(check.findings.length, 1);
  const report = JSON.parse(JSON.stringify(createReport([check], 'url', '2026-10-13T00:00:00Z')));
  const findingId: string = report.checks[0].findings[0].id;
  target.requests.length = 0;
  return { currentPolicy, report, findingId };
}

test('same owned SQLite endpoint rechecks candidate, bound fix control and broken response distinctly', async () => {
  const target = await fixture();
  try {
    const { currentPolicy, report, findingId } = await original(target);
    const args = { report, policy: currentPolicy, findingId, consent: true, allowPrivate: true };
    const reproduced = await replayDastFinding(args);
    assert.equal(reproduced.outcome, 'reproduced');
    assert.equal(dastReplayExitCode(reproduced), 1);
    assert.equal(reproduced.check?.dastExecution?.maxRequests, 9);
    assert.equal(reproduced.check?.dastExecution?.timeoutMs, 5000);
    assert.equal(reproduced.check?.metrics?.requestCount, 8);
    assert.equal(target.requests.length, 8);
    assert.match(reproduced.sourceReportSha256!, /^[a-f0-9]{64}$/);
    assert.match(reproduced.sourceExecutionSha256!, /^[a-f0-9]{64}$/);
    assert.match(reproduced.freshExecutionSha256!, /^[a-f0-9]{64}$/);

    target.requests.length = 0;
    target.setMode('bound');
    const notReproduced = await replayDastFinding(args);
    assert.equal(notReproduced.outcome, 'not_reproduced');
    assert.equal(dastReplayExitCode(notReproduced), 0);
    assert.equal(notReproduced.check?.status, 'completed');
    assert.equal(notReproduced.check?.dastExecution?.outcome, 'not_observed');
    assert.equal(notReproduced.check?.findings.length, 0);
    assert.equal(target.requests.length, 8);

    target.requests.length = 0;
    target.setMode('server-error');
    const inconclusive = await replayDastFinding(args);
    assert.equal(inconclusive.outcome, 'inconclusive');
    assert.equal(dastReplayExitCode(inconclusive), 2);
    assert.equal(inconclusive.check?.status, 'partial');
    assert.equal(inconclusive.check?.findings.length, 0);
    assert.equal(target.requests.length, 1);
    for (const result of [reproduced, notReproduced, inconclusive]) {
      const serialized = JSON.stringify(result);
      assert.equal(serialized.includes('1 AND 1=1'), false);
      assert.equal(serialized.includes('1 AND 1=2'), false);
      assert.equal(serialized.includes('"expectedBaseline":1'), false);
    }
  } finally { await target.close(); }
});

test('changed policy, no consent, missing private grant and forged source evidence refuse before traffic', async () => {
  const target = await fixture();
  try {
    const { currentPolicy, report, findingId } = await original(target);
    const args = { report, policy: currentPolicy, findingId, consent: true, allowPrivate: true };
    const changedPolicy = { ...currentPolicy, url: `${target.origin}/items?id=2` };
    const partial = structuredClone(report); partial.checks[0].dastExecution.steps.pop();
    const duplicate = structuredClone(report); duplicate.checks[0].findings.push(structuredClone(duplicate.checks[0].findings[0]));
    const missingId = structuredClone(report); delete missingId.checks[0].findings[0].id;
    const changedId = structuredClone(report); changedId.checks[0].findings[0].id = 'a'.repeat(64);
    const changedTitle = structuredClone(report); changedTitle.checks[0].findings[0].title = 'Forged candidate title';
    const scenarios = [
      [{ ...args, consent: false }, 'consent_required'],
      [{ ...args, allowPrivate: false }, 'private_consent_required'],
      [{ ...args, policy: changedPolicy }, 'policy_mismatch'],
      [{ ...args, findingId: 'f'.repeat(64) }, 'finding_not_found'],
      [{ ...args, report: partial }, 'not_replayable'],
      [{ ...args, report: duplicate }, 'not_replayable'],
      [{ ...args, report: missingId }, 'finding_not_found'],
      [{ ...args, report: changedId }, 'finding_not_found'],
      [{ ...args, report: changedTitle }, 'not_replayable'],
      [{ ...args, report: { ...report, schemaVersion: '9' } }, 'invalid_report'],
    ] as const;
    for (const [options, reason] of scenarios) {
      const result = await replayDastFinding(options);
      assert.equal(result.outcome, 'refused', reason);
      assert.equal(result.reason, reason);
      assert.equal(dastReplayExitCode(result), 2);
    }
    assert.equal(target.requests.length, 0);
  } finally { await target.close(); }
});

test('accessor/proxy inputs are not evaluated, and cancellation cannot become non-reproduction', async () => {
  const target = await fixture();
  try {
    const { currentPolicy, report, findingId } = await original(target);
    let read = 0;
    const accessor = { report, policy: currentPolicy, findingId, consent: true,
      get allowPrivate() { read++; return true; } };
    assert.equal((await replayDastFinding(accessor)).reason, 'invalid_options');
    assert.equal(read, 0);
    const hostileReport = { ...report, get checks() { read++; return report.checks; } };
    assert.equal((await replayDastFinding({ report: hostileReport, policy: currentPolicy, findingId,
      consent: true, allowPrivate: true })).reason, 'invalid_report');
    assert.equal(read, 0);
    assert.equal((await replayDastFinding(new Proxy({ report, policy: currentPolicy, findingId,
      consent: true, allowPrivate: true }, {}))).reason, 'invalid_options');
    const controller = new AbortController(); controller.abort();
    const cancelled = await replayDastFinding({ report, policy: currentPolicy, findingId,
      consent: true, allowPrivate: true, signal: controller.signal });
    assert.equal(cancelled.outcome, 'inconclusive');
    assert.equal(dastReplayExitCode(cancelled), 2);
    assert.equal(cancelled.check?.dastExecution?.stopReason, 'cancelled');
    assert.equal(target.requests.length, 0);
  } finally { await target.close(); }
});
