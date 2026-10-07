import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Server } from 'node:http';
import { mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runOwnedApiStatePilot, deliverOwnedApiStatePilot } from '../src/api-state.js';
import { sanitiseApiStateEvidence, observeOwnedPhase, parseOwnedState, resourceDigest, type OwnedState,
  type OwnedArrival, type OwnedRead } from '../src/api-state-observer.js';
import { openOwnedApiCapture, ownedApiCapture, type ApiStateCaptureRecord } from '../src/api-state-capture.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, sanitiseReport } from '../src/report.js';

const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const state: OwnedState = { version: 1, runId: '11111111-1111-4111-8111-111111111111', resources: [
  { id: 'resource-owner', owner: 'owner', canary: 'owned-canary-' + 'a'.repeat(32), title: 'Title for owner', contents: 'Stored normal contents for owner' },
  { id: 'resource-other', owner: 'other', canary: 'owned-canary-' + 'b'.repeat(32), title: 'Title for other', contents: 'Stored normal contents for other' }] };
function observation() {
  const records: ApiStateCaptureRecord[] = [], arrivals: OwnedArrival[] = [], reads: OwnedRead[] = [];
  const add = (path: string, actor: 'owner' | 'other' | 'anonymous', status: number, body: unknown) => {
    const ordinal = records.length;
    records.push({ ordinal, path, actor, status, body: Buffer.from(JSON.stringify(body)) });
    arrivals.push({ path, actor, finished: true });
  };
  add('/whoami', 'owner', 200, { userId: 'principal-owner', orgId: 'owned-org' });
  add('/whoami', 'other', 200, { userId: 'principal-other', orgId: 'owned-org' });
  for (const row of state.resources) {
    const path = `/resources/${row.id}`;
    for (const actor of [row.owner, row.owner === 'owner' ? 'other' : 'owner', 'anonymous', row.owner] as const) {
      const ordinal = records.length;
      add(path, actor, actor === row.owner ? 200 : 403, actor === row.owner ? { id: row.id, canary: row.canary, title: row.title, contents: row.contents } : { error: 'denied' });
      reads.push({ ordinal, actor, resourceId: row.id, rowSha256: resourceDigest(row) });
    }
  }
  add('/whoami', 'owner', 200, { userId: 'principal-owner', orgId: 'owned-org' });
  add('/whoami', 'other', 200, { userId: 'principal-other', orgId: 'owned-org' });
  return { records, arrivals, reads };
}

test('owned actual V/F source bytes preserve original API gates and independently compare stored data', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 5000 });
  assert.equal(result.before?.scanGate.exitCode, 1);
  assert.equal(result.before?.report.checks[0].findings.length, 2);
  assert.equal(result.after?.scanGate.exitCode, 0);
  assert.equal(result.verificationGate.exitCode, 0);
  assert.equal(result.execution.apiRequests, 24); assert.equal(result.execution.acceptedRequests, 24);
  assert.equal(result.execution.cleanup, 'confirmed');
  const e = result.verification.checks[0].apiStateEvidence!;
  assert.equal(e.verification, 'scoped_fix_effect_observed'); assert.equal(e.normal, 'passed');
  assert.notEqual(e.lineage.handlerSha256, e.lineage.baselineHandlerSha256);
  assert.equal(e.lineage.stateBeforeSha256, e.lineage.stateAfterSha256);
  assert.match(e.lineage.patchSha256!, /^[a-f0-9]{64}$/);
  assert.equal(Object.isFrozen(result.before!.report.checks), true);
  assert.equal(JSON.stringify(result).includes('owned-canary-'), false);
  assert.equal(JSON.stringify(result).includes('Bearer '), false);
  assert.deepEqual(toAgentReport(result.before!.report).findings[0].verification,
    { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
});
test('status-only actual patch retains unauthorized stored data and fails comparison', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'ineffective', timeoutMs: 5000 });
  assert.equal(result.after?.scanGate.exitCode, 1); assert.equal(result.verificationGate.exitCode, 1);
  assert.equal(result.after?.evidence.effect, 'observed');
  assert.equal(result.verification.checks[0].apiStateEvidence?.verification, 'effect_persists');
});
test('all-deny is API partial and independently normal failed, never a verified fix', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'all-deny', timeoutMs: 5000 });
  assert.equal(result.after?.report.checks[0].status, 'partial');
  assert.equal(result.after?.evidence.normal, 'failed');
  assert.equal(result.verificationGate.exitCode, 2);
  assert.equal(evaluateGate(result.verification, 'none').exitCode, 2);
});
test('canary/id remain valid while real normal field regresses: API0 and verification1', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'normal-regression', timeoutMs: 5000 });
  assert.equal(result.after?.report.checks[0].status, 'completed'); assert.equal(result.after?.scanGate.exitCode, 0);
  assert.equal(result.after?.evidence.normal, 'failed'); assert.equal(result.verificationGate.exitCode, 1);
  assert.equal(result.verification.checks[0].apiStateEvidence?.verification, 'normal_regression');
});
test('concurrent pilots sharing a caller signal use separate phase captures and state', async () => {
  const controller = new AbortController();
  const results = await Promise.all([runOwnedApiStatePilot({ candidate: 'fixed', signal: controller.signal, timeoutMs: 5000 }),
    runOwnedApiStatePilot({ candidate: 'ineffective', signal: controller.signal, timeoutMs: 5000 })]);
  assert.deepEqual(results.map(r => r.verificationGate.exitCode), [0, 1]);
  assert.deepEqual(results.map(r => r.execution.apiRequests), [24, 24]);
  assert.notEqual(results[0].after?.evidence.lineage.stateBeforeSha256, results[1].after?.evidence.lineage.stateBeforeSha256);
  assert.equal(ownedApiCapture(controller.signal), undefined);
});
test('pre-abort opens no phase or requests and records incomplete', async () => {
  const controller = new AbortController(); controller.abort();
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', signal: controller.signal });
  assert.equal(result.execution.phaseInvocations, 0); assert.equal(result.execution.apiRequests, 0);
  assert.equal(result.verificationGate.exitCode, 2);
  assert.ok(result.verification.checks[0].apiStateEvidence?.reasons.includes('cancelled'));
});
test('cleanup aggregation retains executed cleanup on active and between-phase cancellation', async (t) => {
  for (const mode of ['active', 'between-phase'] as const) {
    const controller = new AbortController();
    const emit = Server.prototype.emit;
    let dispatched = 0, closed = 0;
    t.mock.method(Server.prototype, 'emit', function (this: Server, event: string, ...args: unknown[]) {
      const emitted = Reflect.apply(emit, this, [event, ...args]);
      if (event === 'request') {
        dispatched++;
        if (mode === 'active') controller.abort();
      }
      if (event === 'close') {
        closed++;
        if (mode === 'between-phase') controller.abort();
      }
      return emitted;
    });
    try {
      const result = await runOwnedApiStatePilot({ candidate: 'fixed', signal: controller.signal, timeoutMs: 5000 });
      assert.ok(dispatched > 0); assert.equal(closed, 1);
      assert.equal(result.execution.phaseInvocations, 1); assert.equal(result.after, null);
      assert.ok(result.execution.apiRequests > 0);
      assert.equal(result.before?.evidence.cleanup, 'confirmed');
      assert.equal(result.execution.cleanup, 'confirmed');
      assert.equal(result.verification.checks[0].apiStateEvidence?.cleanup, 'confirmed');
      assert.equal(result.verificationGate.exitCode, 2);
      assert.ok(result.verification.checks[0].apiStateEvidence?.reasons.includes('cancelled'));
      if (mode === 'between-phase') assert.equal(result.execution.apiRequests, 12);
    } finally { t.mock.restoreAll(); }
  }
});
test('owned SDK rejects target/worker/observer inputs and invalid budgets', async () => {
  await assert.rejects(runOwnedApiStatePilot({ candidate: 'fixed', baseUrl: 'https://invalid.test' } as never), /invalid_owned/);
  await assert.rejects(runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 120001 }), /time budget/);
  await assert.rejects(runOwnedApiStatePilot({ candidate: 'unknown' } as never), /invalid_owned/);
});
test('observer needs actual row read, actor, received body and ordered completed dispatch', () => {
  const o = observation();
  assert.deepEqual(observeOwnedPhase(state, o.records, o.arrivals, o.reads, false),
    { effect: 'not_observed', normal: 'passed', incomplete: false, reasons: [], capturedResponses: 12,
      controlOutcomes: ['identity_passed', 'identity_passed', 'normal_passed', 'denial_observed', 'denial_observed', 'normal_passed',
        'normal_passed', 'denial_observed', 'denial_observed', 'normal_passed', 'identity_passed', 'identity_passed'] });
  o.reads[0].rowSha256 = '0'.repeat(64);
  assert.ok(observeOwnedPhase(state, o.records, o.arrivals, o.reads, false).reasons.includes('read_mismatch'));
  assert.equal(observeOwnedPhase(state, [], [], [], false).effect, 'unknown');
  const wrong = observation(); wrong.records[0].body = Buffer.from('{"userId":"principal-other","orgId":"owned-org"}');
  assert.ok(observeOwnedPhase(state, wrong.records, wrong.arrivals, wrong.reads, false).reasons.includes('identity_mismatch'));
});
test('independent observer rejects wrong/empty resource, normal regression, and 5xx leakage', () => {
  const o = observation();
  o.records[2].body = Buffer.from(JSON.stringify({ ...state.resources[1] }));
  assert.equal(observeOwnedPhase(state, o.records, o.arrivals, o.reads, false).normal, 'failed');
  const leaked = observation(); leaked.records[3].status = 500;
  leaked.records[3].body = Buffer.from(JSON.stringify({ id: state.resources[0].id, canary: state.resources[0].canary }));
  const result = observeOwnedPhase(state, leaked.records, leaked.arrivals, leaked.reads, false);
  assert.equal(result.effect, 'observed'); assert.equal(result.incomplete, true);
  assert.throws(() => parseOwnedState(Buffer.from('{"version":1,"resources":[]}'), state.runId), /invalid_state/);
  assert.throws(() => parseOwnedState(Buffer.from(JSON.stringify(state)), 'other-run'), /invalid_state/);
});
test('capture seal/dispose and cap failures never fabricate successful received evidence', () => {
  const c = new AbortController(); const session = openOwnedApiCapture(c.signal, 'http://127.0.0.1:1', new Map());
  assert.equal(ownedApiCapture(c.signal), session);
  assert.throws(() => openOwnedApiCapture(c.signal, 'http://127.0.0.1:1', new Map()), /conflict/);
  session.start({ href: 'http://other.invalid/', origin: 'http://other.invalid' } as never, undefined);
  assert.equal(session.seal().incomplete, true); session.dispose(); assert.equal(ownedApiCapture(c.signal), undefined);
});
test('untrusted evidence contradictions remain unknown and only comparison check is fail-closed', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 5000 });
  const valid = result.verification.checks[0].apiStateEvidence!;
  const malformed = { ...valid, effect: 'observed', counts: { ...valid.counts, apiRequests: Number.MAX_SAFE_INTEGER } };
  assert.equal(sanitiseApiStateEvidence(malformed).verification, 'inconclusive');
  assert.equal(sanitiseApiStateEvidence(malformed).counts.apiRequests, null);
  const original = { ...result.after!.report.checks[0], apiStateEvidence: malformed as never };
  assert.equal(createReport([original], 'api', new Date()).checks[0].status, 'completed');
  assert.equal(createReport([{ ...original, id: 'api.owned-state-oracle' }], 'api', new Date()).checks[0].status, 'partial');
  assert.deepEqual(sanitiseReport(result.verification), sanitiseReport(sanitiseReport(result.verification)));
});
test('owned phase/comparison evidence stays consistent in all four report projections', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 5000 });
  for (const report of [result.before!.report, result.after!.report, result.verification]) {
    const e = report.checks[0].apiStateEvidence!;
    assert.deepEqual(toAgentReport(report).checks[0].apiStateEvidence, e);
    const sarif = toSarif(report) as unknown as { runs: Array<{ properties: { apiStateEvidence: Array<{ apiStateEvidence: unknown }> } }> };
    assert.deepEqual(sarif.runs[0].properties.apiStateEvidence[0].apiStateEvidence, e);
    assert.match(toMarkdown(report), new RegExp(`effect=${e.effect}, normal=${e.normal}`));
  }
});
test('delivery failure retries exact retained bytes without HTTP rerun or mutable-storage corruption', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 5000 });
  const hashes: string[] = []; let first = true;
  const storage = { async put(_id: string, bytes: Uint8Array) {
    hashes.push(digest(bytes)); if (first) { first = false; bytes.fill(0); throw new Error('owned-write-failure'); } return 'owned-ack';
  } };
  const failed = await deliverOwnedApiStatePilot(result, { storage });
  assert.equal(failed.finalExitCode, 2); assert.equal(failed.status, 'unknown');
  const delivered = await deliverOwnedApiStatePilot(result, { storage });
  assert.equal(delivered.finalExitCode, 0); assert.deepEqual(hashes, [delivered.artifactSha256, delivered.artifactSha256]);
  assert.equal(result.execution.apiRequests, 24); assert.equal(delivered.apiReexecuted, false);
});
test('delivery publishes phase files first and rejects symlinks without rerunning API', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 5000 });
  const folder = await mkdtemp(join(tmpdir(), 'api-state-test-'));
  try {
    const receipt = await deliverOwnedApiStatePilot(result, { outDir: join(folder, 'good') });
    assert.equal(receipt.status, 'delivered');
    for (const phase of ['before', 'after', 'verification'] as const) {
      const bytes = await readFile(join(folder, 'good', receipt.outputRelativePath, phase, 'report.json'));
      assert.equal(digest(bytes), receipt.reportDigests[phase]);
    }
    const stored = JSON.parse(await readFile(join(folder, 'good', receipt.outputRelativePath, 'api-state-delivery.json'), 'utf8'));
    assert.equal(stored.apiReexecuted, false); assert.equal(stored.provesFinalProcessExit, false);
    assert.equal(stored.deliveryAttemptId, receipt.deliveryAttemptId);
    await symlink(join(folder, 'good'), join(folder, 'linked'));
    assert.equal((await deliverOwnedApiStatePilot(result, { outDir: join(folder, 'linked') })).finalExitCode, 2);
    assert.equal(result.execution.apiRequests, 24);
  } finally { await rm(folder, { recursive: true, force: true }); }
});
test('stalled storage is delivery unknown with no HTTP reexecution', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 5000 });
  const receipt = await deliverOwnedApiStatePilot(result, { storage: { put: async () => new Promise<string>(() => {}) } });
  assert.equal(receipt.status, 'unknown'); assert.equal(receipt.reason, 'delivery_timeout');
  assert.equal(receipt.finalExitCode, 2); assert.equal(result.execution.apiRequests, 24);
});

test('lineage accepts primitive strings only and comparison cannot claim an unevaluated completion', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 5000 });
  const valid = result.verification.checks[0].apiStateEvidence!;
  for (const key of ['handlerSha256', 'runId', 'runtimeVersion'] as const) {
    const invalid = { ...valid, lineage: { ...valid.lineage, [key]: [valid.lineage[key]] } };
    assert.equal(sanitiseApiStateEvidence(invalid).execution, 'partial');
  }
  assert.equal(sanitiseApiStateEvidence({ ...valid, verification: 'not_evaluated' }).execution, 'partial');
  assert.equal(sanitiseApiStateEvidence({ ...valid, counts: { ...valid.counts, plannedRequests: 0 } }).execution, 'partial');
  const o = observation(); o.reads.push({ ...o.reads[0] });
  assert.ok(observeOwnedPhase(state, o.records, o.arrivals, o.reads, false).reasons.includes('read_mismatch'));
});
