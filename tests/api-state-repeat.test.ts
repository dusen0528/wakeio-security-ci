import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, Server } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runOwnedApiStatePilot, deliverOwnedApiStatePilot, type ApiStatePilotOptions } from '../src/api-state.js';
import { openOwnedApiCapture, ownedApiCapture, type OwnedApiBudget } from '../src/api-state-capture.js';
import { sanitiseApiStateEvidence } from '../src/api-state-observer.js';
import { runApiPolicy, API_MAX_REQUESTS, API_MAX_TOTAL_BODY_BYTES, type ApiPolicyV2 } from '../src/api.js';
import { sanitiseApiExecutionLedger } from '../src/api-execution.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { CheckResult, ScanReport } from '../src/contracts.js';

const serialise = (value: unknown) => JSON.stringify(value, null, 2) + '\n';
const digest = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const RAW = 'repeat-raw-private-sentinel';
function outputs(report: ScanReport): string[] {
  return [JSON.stringify(sanitiseReport(report)), JSON.stringify(toAgentReport(report)), JSON.stringify(toSarif(report)), toMarkdown(report)];
}
function assertLocalLedger(check: CheckResult, attempts: number): void {
  const value = check.apiExecution;
  assert.ok(value); assert.notEqual(value.status, 'invalid');
  assert.equal(check.metrics?.requestCount, attempts); assert.equal(value.counts.httpAttempts, attempts);
  let offset = 0;
  for (const step of value.steps) {
    assert.equal(step.attemptStart, offset);
    offset += step.httpAttempts;
  }
  assert.equal(offset, attempts);
  assert.deepEqual(sanitiseApiExecutionLedger(value), value);
}

test('two owned rounds retain four independent phase ledgers and 48 actual requests for a stable fix', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
  const phases = [result.before!, result.after!, result.beforeRepeat!, result.afterRepeat!];
  assert.equal(result.verificationRounds, 2); assert.equal(result.verificationGate.exitCode, 0);
  assert.equal(result.execution.phaseInvocations, 4);
  assert.equal(result.execution.apiRequests, 48); assert.equal(result.execution.acceptedRequests, 48);
  assert.ok(result.execution.bytesInspected > 0); assert.ok(result.execution.bytesInspected < API_MAX_TOTAL_BODY_BYTES);
  assert.equal(result.execution.cleanup, 'confirmed');
  assert.deepEqual(phases.map(p => p.scanGate.exitCode), [1, 0, 1, 0]);
  for (const p of phases) {
    assert.equal(p.evidence.execution, 'completed'); assert.equal(p.evidence.normal, 'passed');
    assert.equal(p.evidence.counts.apiRequests, 12); assertLocalLedger(p.report.checks[0], 12);
    assert.equal(p.evidence.lineage.runId, result.runId);
    assert.equal(p.evidence.lineage.stateBeforeSha256, result.before!.evidence.lineage.stateBeforeSha256);
    assert.equal(p.evidence.lineage.stateAfterSha256, p.evidence.lineage.stateBeforeSha256);
  }
  const evidence = result.verification.checks[0].apiStateEvidence!;
  assert.equal(evidence.verification, 'scoped_fix_effect_observed'); assert.equal(evidence.effect, 'not_observed');
  assert.deepEqual(evidence.counts, { plannedRequests: 48, apiRequests: 48, acceptedRequests: 48, capturedResponses: 48 });
  assert.deepEqual(evidence.repetition, { rounds: 2, completedPhases: 4, consistency: 'consistent',
    phaseReportSha256: phases.map(p => digest(serialise(p.report))) });
  assert.deepEqual(result.after!.evidence.controlOutcomes, ['identity_passed', 'identity_passed', 'normal_passed',
    'denial_observed', 'denial_observed', 'normal_passed', 'normal_passed', 'denial_observed', 'denial_observed',
    'normal_passed', 'identity_passed', 'identity_passed']);
  assert.deepEqual(result.beforeRepeat!.evidence.controlOutcomes, result.before!.evidence.controlOutcomes);
  assert.deepEqual(result.afterRepeat!.evidence.controlOutcomes, result.after!.evidence.controlOutcomes);
  assert.equal(evidence.controlOutcomes, undefined);
  assert.equal(Object.isFrozen(result.afterRepeat!.evidence.controlOutcomes), true);
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.afterRepeat!.report.checks), true);
  assert.equal(Object.isFrozen(evidence.repetition!.phaseReportSha256), true);
  assert.throws(() => { result.afterRepeat!.report.checks.length = 0; }, TypeError);
});

test('stable repeated ineffective and normal-regression candidates retain failing evidence and original gates', async () => {
  for (const candidate of ['ineffective', 'normal-regression'] as const) {
    const result = await runOwnedApiStatePilot({ candidate, verificationRounds: 2, timeoutMs: 5000 });
    const evidence = result.verification.checks[0].apiStateEvidence!;
    assert.equal(result.verificationGate.exitCode, 1, candidate);
    assert.equal(result.execution.apiRequests, 48); assert.equal(result.execution.phaseInvocations, 4);
    assert.equal(evidence.repetition?.consistency, 'consistent');
    assert.equal(evidence.repetition?.completedPhases, 4);
    assert.equal(evidence.verification, candidate === 'ineffective' ? 'effect_persists' : 'normal_regression');
    for (const p of [result.after!, result.afterRepeat!]) {
      assert.equal(p.scanGate.exitCode, candidate === 'ineffective' ? 1 : 0);
      assert.equal(p.evidence.effect, candidate === 'ineffective' ? 'observed' : 'not_observed');
      assert.equal(p.evidence.normal, candidate === 'ineffective' ? 'passed' : 'failed');
    }
    const findings = toAgentReport(result.verification).findings;
    assert.equal(findings.length, 1);
    assert.deepEqual(findings[0].verification, { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
  }
});

test('repeated all-deny remains partial and cannot manufacture missing repeat evidence', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'all-deny', verificationRounds: 2, timeoutMs: 5000 });
  assert.equal(result.verificationGate.exitCode, 2); assert.equal(evaluateGate(result.verification, 'none').exitCode, 2);
  assert.equal(result.after?.scanGate.exitCode, 2); assert.equal(result.after?.evidence.normal, 'failed');
  assert.equal(result.beforeRepeat, null); assert.equal(result.afterRepeat, null);
  assert.equal(result.execution.phaseInvocations, 2); assert.ok(result.execution.apiRequests < 48);
  const evidence = result.verification.checks[0].apiStateEvidence!;
  assert.equal(evidence.execution, 'partial'); assert.equal(evidence.verification, 'inconclusive');
  assert.equal(evidence.normal, 'failed'); assert.equal(evidence.repetition?.consistency, 'incomplete');
  assert.equal(evidence.repetition?.completedPhases, 1); assert.equal(evidence.repetition?.phaseReportSha256.length, 2);
  assert.ok(result.verification.checks[0].findings.some(f => f.ruleId === 'api.owned-state-normal_regression'));
});

test('omitted and explicit single-round options keep the original two-phase 24-request behavior', async () => {
  for (const verificationRounds of [undefined, 1] as const) {
    const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds, timeoutMs: 5000 });
    assert.equal(result.verificationRounds, 1); assert.equal(result.verificationGate.exitCode, 0);
    assert.equal(result.execution.phaseInvocations, 2); assert.equal(result.execution.apiRequests, 24);
    assert.equal(Object.hasOwn(result, 'beforeRepeat'), false); assert.equal(Object.hasOwn(result, 'afterRepeat'), false);
    const evidence = result.verification.checks[0].apiStateEvidence!;
    assert.equal(evidence.counts.plannedRequests, 24); assert.equal(Object.hasOwn(evidence, 'repetition'), false);
    assert.equal(evidence.verification, 'scoped_fix_effect_observed');
  }
});

test('repeat options reject every non-enumerated round count without running a fixture', async (t) => {
  const listen = t.mock.method(Server.prototype, 'listen', () => { throw new Error('unexpected_fixture_start'); });
  for (const verificationRounds of [0, 3, -1, 1.5, NaN, Infinity, null, '2', true, [], {}]) {
    await assert.rejects(runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds } as never), /invalid_owned_pilot_options/);
  }
  assert.equal(listen.mock.callCount(), 0);
});

test('pre-cancelled repeated pilot opens no fixture and retains incomplete zero-attempt repetition', async (t) => {
  const controller = new AbortController(); controller.abort();
  const listen = t.mock.method(Server.prototype, 'listen', () => { throw new Error('unexpected_fixture_start'); });
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, signal: controller.signal });
  assert.equal(listen.mock.callCount(), 0); assert.equal(result.execution.phaseInvocations, 0);
  assert.equal(result.execution.apiRequests, 0); assert.equal(result.execution.bytesInspected, 0);
  assert.equal(result.execution.cleanup, 'not_run'); assert.equal(result.verificationGate.exitCode, 2);
  assert.deepEqual([result.before, result.after, result.beforeRepeat, result.afterRepeat], [null, null, null, null]);
  const evidence = result.verification.checks[0].apiStateEvidence!;
  assert.ok(evidence.reasons.includes('cancelled'));
  assert.deepEqual(evidence.repetition, { rounds: 2, completedPhases: 0, consistency: 'incomplete', phaseReportSha256: [] });
});

test('repeat execution snapshots candidate, rounds, timeout and cancellation signal before the first await', async () => {
  const original = new AbortController(), replacement = new AbortController(); replacement.abort();
  const options: ApiStatePilotOptions = { candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000, signal: original.signal };
  const pending = runOwnedApiStatePilot(options);
  options.candidate = 'ineffective'; options.verificationRounds = 1; options.timeoutMs = 1; options.signal = replacement.signal;
  const result = await pending;
  assert.equal(result.verificationRounds, 2); assert.equal(result.execution.apiRequests, 48);
  assert.equal(result.verificationGate.exitCode, 0); assert.equal(result.afterRepeat?.evidence.effect, 'not_observed');
  assert.deepEqual(result.verification.checks[0].apiStateEvidence?.reasons, []);
});

test('repeat delivery freezes all five reports, retains exact hashes on retries and never reruns HTTP', async (t) => {
  let requests = 0;
  const emit = Server.prototype.emit;
  t.mock.method(Server.prototype, 'emit', function (this: Server, event: string, ...args: unknown[]) {
    if (event === 'request') requests++;
    return Reflect.apply(emit, this, [event, ...args]);
  });
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
  assert.equal(requests, 48);
  const hashes: string[] = [];
  const storage = { async put(_runId: string, bytes: Uint8Array) {
    hashes.push(digest(bytes));
    if (hashes.length === 1) { bytes.fill(0); throw Error('synthetic_delivery_failure'); }
    return 'synthetic_delivery_ack';
  } };
  const failed = await deliverOwnedApiStatePilot(result, { storage });
  assert.equal(failed.finalExitCode, 2); assert.equal(failed.status, 'unknown');
  const folder = await mkdtemp(join(tmpdir(), 'api-state-repeat-test-'));
  try {
    const delivered = await deliverOwnedApiStatePilot(result, { storage, outDir: folder });
    assert.equal(delivered.status, 'delivered'); assert.equal(delivered.finalExitCode, 0);
    assert.equal(delivered.apiReexecuted, false); assert.equal(requests, 48);
    assert.deepEqual(hashes, [delivered.artifactSha256, delivered.artifactSha256]);
    assert.equal(delivered.artifactSha256, digest(serialise(result)));
    assert.deepEqual(Object.keys(delivered.reportDigests).sort(), ['after', 'afterRepeat', 'before', 'beforeRepeat', 'verification']);
    for (const phase of ['before', 'after', 'beforeRepeat', 'afterRepeat', 'verification'] as const) {
      const report = phase === 'verification' ? result.verification : result[phase]!.report;
      const bytes = await readFile(join(folder, delivered.outputRelativePath, phase, 'report.json'));
      assert.equal(digest(bytes), delivered.reportDigests[phase]);
      assert.equal(bytes.toString(), serialise(sanitiseReport(report)));
      for (const artifact of ['report.json', 'report.sarif', 'report.md', 'agent-report.json']) {
        const text = await readFile(join(folder, delivered.outputRelativePath, phase, artifact), 'utf8');
        for (const secret of ['owned-canary-', 'Bearer ', 'Stored normal contents for', 'Title for owner', RAW]) assert.equal(text.includes(secret), false, `${phase}/${artifact}: ${secret}`);
      }
    }
    const evidence = result.verification.checks[0].apiStateEvidence!;
    assert.deepEqual(evidence.repetition?.phaseReportSha256,
      ['before', 'after', 'beforeRepeat', 'afterRepeat'].map(phase => delivered.reportDigests[phase as keyof typeof delivered.reportDigests]));
    assert.equal(requests, 48);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('repeat evidence is preserved in JSON, agent, SARIF and Markdown without raw response fields', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
  for (const report of [result.before!.report, result.after!.report, result.beforeRepeat!.report, result.afterRepeat!.report, result.verification]) {
    const original = report.checks[0].apiStateEvidence!;
    const untrusted = structuredClone(report);
    Object.assign(untrusted.checks[0].apiStateEvidence!, { responseBody: RAW, authorization: RAW, resourceContents: RAW });
    Object.assign(untrusted.checks[0].apiStateEvidence!.lineage, { rawState: RAW });
    const safe = sanitiseReport(untrusted);
    assert.deepEqual(safe.checks[0].apiStateEvidence, original);
    assert.deepEqual(toAgentReport(untrusted).checks[0].apiStateEvidence, original);
    const sarif = toSarif(untrusted) as unknown as { runs: Array<{ properties: { apiStateEvidence: Array<{ apiStateEvidence: unknown }> } }> };
    assert.deepEqual(sarif.runs[0].properties.apiStateEvidence[0].apiStateEvidence, original);
    for (const output of outputs(untrusted)) {
      assert.equal(output.includes(RAW), false); assert.equal(output.includes('owned-canary-'), false);
      assert.equal(output.includes('Bearer '), false);
    }
    assert.deepEqual(sanitiseReport(safe), safe);
  }
  assert.match(toMarkdown(result.verification), /requested rounds=2; completed phases=4\/4; consistency=consistent/);
});

test('malformed repetition fails closed in every projection and cannot claim a completed fix', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
  const valid = result.verification.checks[0].apiStateEvidence!;
  const mutations: Array<(value: any) => void> = [
    x => x.repetition.rounds = 1,
    x => x.repetition.rounds = '2',
    x => x.repetition.completedPhases = -1,
    x => x.repetition.completedPhases = 5,
    x => x.repetition.completedPhases = 3.5,
    x => x.repetition.completedPhases = 3,
    x => x.repetition.consistency = 'incomplete',
    x => x.repetition.consistency = 'inconsistent',
    x => x.repetition.phaseReportSha256.pop(),
    x => x.repetition.phaseReportSha256.push('a'.repeat(64)),
    x => x.repetition.phaseReportSha256[0] = '0'.repeat(64),
    x => x.repetition.phaseReportSha256[1] = '0'.repeat(64),
    x => x.repetition.phaseReportSha256[2] = RAW,
    x => x.repetition.phaseReportSha256[2] = ['a'.repeat(64)],
    x => x.repetition.responseBody = RAW,
    x => { delete x.repetition.consistency; },
    x => x.repetition = [],
    x => x.repetition = null,
    x => { delete x.repetition; },
    x => x.counts.plannedRequests = 24,
    x => x.phase = 'candidate',
    x => x.reasons = ['repeat_inconsistent'],
  ];
  for (const mutate of mutations) {
    const value = structuredClone(valid); mutate(value);
    const evidence = sanitiseApiStateEvidence(value);
    assert.equal(evidence.execution, 'partial', mutate.toString());
    assert.equal(evidence.verification, 'inconclusive'); assert.equal(evidence.effect, 'unknown');
    assert.deepEqual(evidence.reasons, ['invalid_evidence']); assert.equal(evidence.repetition, undefined);
    const report = createReport([{ ...result.verification.checks[0], apiStateEvidence: value }], 'api', new Date());
    assert.equal(report.checks[0].status, 'partial'); assert.equal(evaluateGate(report, 'none').exitCode, 2);
    assert.equal(toAgentReport(report).scanGate.exitCode, 2);
    for (const output of outputs(report)) {
      assert.equal(output.includes(RAW), false); assert.match(output, /inconclusive/);
      assert.equal(output.includes('scoped_fix_effect_observed'), false);
    }
    assert.deepEqual(sanitiseApiStateEvidence(evidence), evidence);
  }
});

test('malformed control vectors fail closed while valid phase vectors stay passive metadata', async () => {
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
  const valid = result.after!.evidence;
  const mutations: Array<(value: any) => void> = [
    x => x.controlOutcomes.pop(),
    x => x.controlOutcomes.push('identity_passed'),
    x => x.controlOutcomes = {},
    x => x.controlOutcomes = null,
    x => x.controlOutcomes[0] = RAW,
    x => x.controlOutcomes[0] = 'normal_passed',
    x => x.controlOutcomes[2] = 'denial_observed',
    x => x.controlOutcomes[3] = 'normal_passed',
    x => x.controlOutcomes[0] = 'identity_failed',
    x => x.controlOutcomes[3] = 'unknown',
    x => x.controlOutcomes[3] = 'effect_observed',
    x => x.controlOutcomes[2] = 'normal_failed',
    x => x.effect = 'observed',
    x => x.normal = 'failed',
    x => { delete x.controlOutcomes[0]; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(valid); mutate(value);
    const evidence = sanitiseApiStateEvidence(value);
    assert.equal(evidence.execution, 'partial', mutate.toString());
    assert.deepEqual(evidence.reasons, ['invalid_evidence']); assert.equal(evidence.controlOutcomes, undefined);
    const report = createReport([{ ...result.after!.report.checks[0], apiStateEvidence: value }], 'api', new Date());
    // A malformed passive observation cannot rewrite the original API result.
    assert.equal(report.checks[0].status, 'completed'); assert.equal(evaluateGate(report).exitCode, 0);
    for (const output of outputs(report)) {
      assert.equal(output.includes(RAW), false); assert.match(output, /inconclusive/);
    }
  }
  const comparison = { ...result.verification.checks[0].apiStateEvidence!, controlOutcomes: valid.controlOutcomes };
  assert.deepEqual(sanitiseApiStateEvidence(comparison).reasons, ['invalid_evidence']);
});

// Internal-only capture sessions are used here to test coordinator accounting.
// Every response, principal, resource and credential belongs to this loopback fixture.
const ENV = { REPEAT_OWNER_AUTH: 'Bearer repeat-synthetic-owner', REPEAT_OTHER_AUTH: 'Bearer repeat-synthetic-other' };
const credentials = new Map<string, 'owner' | 'other'>([[ENV.REPEAT_OWNER_AUTH, 'owner'], [ENV.REPEAT_OTHER_AUTH, 'other']]);
const identityBody = (actor: 'owner' | 'other') => JSON.stringify({ userId: `principal-${actor}` });
const resourceBody = (actor: 'owner' | 'other') => JSON.stringify({ id: `resource-${actor}`, canary: `synthetic-canary-${actor}` });
const deniedBody = JSON.stringify({ error: 'denied' });
const PHASE_BYTES = 2 * Buffer.byteLength(identityBody('owner')) + 2 * Buffer.byteLength(identityBody('other'))
  + 2 * Buffer.byteLength(resourceBody('owner')) + 2 * Buffer.byteLength(resourceBody('other')) + 4 * Buffer.byteLength(deniedBody);
function newBudget(bytes = 0): OwnedApiBudget {
  return { requests: { count: 0, max: API_MAX_REQUESTS }, bytes, bodyExhausted: false, bodyReadIncomplete: false };
}
async function budgetFixture() {
  let arrivals = 0;
  const server = createServer((request, response) => {
    arrivals++;
    const actor = credentials.get(request.headers.authorization ?? '');
    const row = request.url === '/resources/resource-owner' ? 'owner' : request.url === '/resources/resource-other' ? 'other' : undefined;
    const identity = request.url === '/whoami' && actor;
    const allowed = row !== undefined && actor === row;
    response.writeHead(identity || allowed ? 200 : actor ? 403 : 401, { 'content-type': 'application/json' });
    response.end(identity ? identityBody(actor!) : allowed ? resourceBody(row!) : deniedBody);
  });
  await new Promise<void>((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  const policy: ApiPolicyV2 = { version: 2, baseUrl: origin, actors: [
    { id: 'owner', authorizationEnv: 'REPEAT_OWNER_AUTH', identity: { path: '/whoami', status: 200, jsonPointer: '/userId', equals: 'principal-owner' } },
    { id: 'other', authorizationEnv: 'REPEAT_OTHER_AUTH', identity: { path: '/whoami', status: 200, jsonPointer: '/userId', equals: 'principal-other' } },
    { id: 'anonymous' },
  ], cases: (['owner', 'other'] as const).map(actor => ({ id: `read-${actor}`, path: `/resources/resource-${actor}`,
    allow: { actor, status: 200, resource: { jsonPointer: '/id', equals: `resource-${actor}` }, protected: { jsonPointer: '/canary', equals: `synthetic-canary-${actor}` } },
    deny: [{ actor: actor === 'owner' ? 'other' : 'owner', statuses: [403] }, { actor: 'anonymous', statuses: [401] }] })) };
  const run = async (budget?: OwnedApiBudget) => {
    const controller = new AbortController();
    const capture = budget ? openOwnedApiCapture(controller.signal, origin, credentials, budget) : undefined;
    try {
      const [check] = await runApiPolicy({ policy, env: ENV, allowPrivate: true, timeoutMs: 5000, signal: controller.signal });
      return check;
    } finally {
      capture?.dispose(); assert.equal(ownedApiCapture(controller.signal), undefined);
    }
  };
  return { run, arrivals: () => arrivals, close: async () => {
    server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  } };
}

test('owned calls share the 64-request cap while partial and exhausted ledgers keep local attempt offsets', async () => {
  const fixture = await budgetFixture(), budget = newBudget();
  try {
    for (let phase = 0; phase < 5; phase++) {
      const check = await fixture.run(budget);
      assert.equal(check.status, 'completed'); assertLocalLedger(check, 12);
      assert.equal(check.metrics?.bytesInspected, PHASE_BYTES);
      assert.equal(budget.requests.count, (phase + 1) * 12);
      assert.equal(budget.bytes, (phase + 1) * PHASE_BYTES);
    }
    const partial = await fixture.run(budget);
    assert.equal(partial.status, 'partial'); assertLocalLedger(partial, 4);
    assert.equal(partial.apiExecution!.steps[4].reason, 'shared_request_budget');
    assert.equal(partial.apiExecution!.steps[4].outcome, 'not_attempted');
    assert.equal(partial.apiExecution!.steps[4].attemptStart, 4);
    assert.equal(budget.requests.count, API_MAX_REQUESTS); assert.equal(fixture.arrivals(), API_MAX_REQUESTS);
    const exhausted = await fixture.run(budget);
    assert.equal(exhausted.status, 'partial'); assertLocalLedger(exhausted, 0);
    assert.equal(exhausted.apiExecution!.steps[0].reason, 'shared_request_budget');
    assert.ok(exhausted.apiExecution!.steps.every(step => step.attemptStart === 0 && step.httpStatus === null));
    assert.equal(fixture.arrivals(), API_MAX_REQUESTS); assert.equal(budget.requests.count, API_MAX_REQUESTS);
    assert.equal(evaluateGate(createReport([exhausted], 'api', new Date()), 'none').exitCode, 2);
  } finally { await fixture.close(); }
});

test('shared body counter reaches its total limit across calls without opening another HTTP request', async () => {
  const fixture = await budgetFixture(), budget = newBudget(API_MAX_TOTAL_BODY_BYTES - PHASE_BYTES);
  try {
    const complete = await fixture.run(budget);
    assert.equal(complete.status, 'completed'); assertLocalLedger(complete, 12);
    assert.equal(complete.metrics?.bytesInspected, PHASE_BYTES); assert.equal(budget.bytes, API_MAX_TOTAL_BODY_BYTES);
    for (let phase = 0; phase < 2; phase++) {
      const stopped = await fixture.run(budget);
      assert.equal(stopped.status, 'partial'); assertLocalLedger(stopped, 0);
      assert.equal(stopped.apiExecution!.steps[0].reason, 'shared_body_budget');
      assert.equal(stopped.metrics?.bytesInspected, 0); assert.equal(stopped.metrics?.bodyBudgetExhausted, true);
      assert.equal(stopped.metrics?.bodyReadIncomplete, false);
    }
    assert.equal(budget.bodyExhausted, true); assert.equal(budget.bodyReadIncomplete, false);
    assert.equal(fixture.arrivals(), 12); assert.equal(budget.requests.count, 12);
  } finally { await fixture.close(); }
});

test('crossing the remaining shared byte limit is terminal even when the next call has a fresh capture', async () => {
  const fixture = await budgetFixture(), budget = newBudget(API_MAX_TOTAL_BODY_BYTES - PHASE_BYTES - 1);
  try {
    const complete = await fixture.run(budget);
    assert.equal(complete.status, 'completed'); assertLocalLedger(complete, 12);
    assert.equal(budget.bytes, API_MAX_TOTAL_BODY_BYTES - 1);
    const crossed = await fixture.run(budget);
    assert.equal(crossed.status, 'partial'); assertLocalLedger(crossed, 1);
    assert.equal(crossed.apiExecution!.steps[0].reason, 'shared_body_budget');
    assert.equal(crossed.apiExecution!.steps[0].outcome, 'inconclusive');
    assert.equal(crossed.apiExecution!.steps[0].httpStatus, null);
    assert.equal(crossed.metrics?.bytesInspected, 0); assert.equal(crossed.metrics?.bodyReadIncomplete, true);
    assert.equal(budget.bodyExhausted, true); assert.equal(budget.bodyReadIncomplete, true);
    const stopped = await fixture.run(budget);
    assert.equal(stopped.status, 'partial'); assertLocalLedger(stopped, 0);
    assert.equal(stopped.apiExecution!.steps[0].reason, 'shared_body_budget');
    assert.equal(stopped.metrics?.bodyReadIncomplete, true);
    assert.equal(budget.bytes, API_MAX_TOTAL_BODY_BYTES - 1);
    assert.equal(budget.requests.count, 13); assert.equal(fixture.arrivals(), 13);
  } finally { await fixture.close(); }
});

test('ordinary runApiPolicy calls stay independent of an exhausted owned-run budget', async () => {
  const fixture = await budgetFixture(), budget = newBudget(API_MAX_TOTAL_BODY_BYTES);
  budget.requests.count = API_MAX_REQUESTS; budget.bodyExhausted = true; budget.bodyReadIncomplete = true;
  try {
    const stopped = await fixture.run(budget); assertLocalLedger(stopped, 0);
    for (let call = 0; call < 2; call++) {
      const ordinary = await fixture.run();
      assert.equal(ordinary.status, 'completed'); assertLocalLedger(ordinary, 12);
      assert.equal(ordinary.metrics?.bytesInspected, PHASE_BYTES);
      assert.equal(ordinary.metrics?.bodyBudgetExhausted, false); assert.equal(ordinary.metrics?.bodyReadIncomplete, false);
      assert.equal(ordinary.apiStateEvidence, undefined);
      assert.ok(ordinary.apiExecution!.steps.every(step => step.reason === 'evaluated'));
    }
    assert.equal(fixture.arrivals(), 24); assert.equal(budget.requests.count, API_MAX_REQUESTS);
    assert.equal(budget.bytes, API_MAX_TOTAL_BODY_BYTES);
  } finally { await fixture.close(); }
});
