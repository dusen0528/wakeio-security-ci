import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { runOwnedApiStatePilot, type ApiStateCandidate } from '../src/api-state.js';

type Perturbation = 'leak' | 'moving-leak' | 'normal-regression' | 'fixed-baseline' | 'server-error' | 'identity-drift' | 'stall';

/** Perturb only local fixture responses; never edit pinned source or replay HTTP. */
function perturbResponses(t: TestContext, targetPhase: number, change: Perturbation, delayEarlierMs = 0) {
  const emit = Server.prototype.emit;
  const phases = new WeakMap<Server, number>();
  const rows = new Map<string, Record<string, unknown>>();
  const principals = new Map<string | undefined, string>();
  const delayed = new Set<number>();
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let nextPhase = 0;
  t.after(() => { for (const timer of timers) clearTimeout(timer); });
  t.mock.method(Server.prototype, 'emit', function (this: Server, event: string, ...args: unknown[]) {
    if (event === 'request') {
      if (!phases.has(this)) phases.set(this, ++nextPhase);
      const phase = phases.get(this)!;
      const [req, res] = args as [IncomingMessage, ServerResponse];
      const end = res.end, writeHead = res.writeHead;
      const resource = req.url?.startsWith('/resources/') ?? false;
      const repairBaseline = phase === targetPhase && change === 'fixed-baseline' && resource
        && !!req.headers.authorization && req.url !== `/resources/resource-${principals.get(req.headers.authorization)}`;
      const serverError = phase === targetPhase && change === 'server-error' && req.url === '/whoami';
      res.writeHead = function (this: ServerResponse, status: number, ...rest: unknown[]) {
        return Reflect.apply(writeHead, this, [repairBaseline ? 403 : serverError ? 503 : status, ...rest]);
      } as typeof res.writeHead;
      res.end = function (this: ServerResponse, body?: unknown, ...rest: unknown[]) {
        let value: Record<string, unknown> | undefined;
        try { value = JSON.parse(String(body)) as Record<string, unknown>; } catch { /* Leave non-JSON untouched. */ }
        if (typeof value?.userId === 'string') principals.set(req.headers.authorization, value.userId.replace('principal-', ''));
        if (value?.canary) rows.set(req.url!, value);
        if (phase === targetPhase || (change === 'moving-leak' && phase === 4)) {
          if (change === 'stall') return this;
          const leakHere = change === 'leak' || (change === 'moving-leak'
            && req.url === `/resources/resource-${phase === 2 ? 'owner' : 'other'}`);
          if (leakHere && resource && this.statusCode === 403 && rows.has(req.url!)) body = JSON.stringify(rows.get(req.url!));
          if (change === 'normal-regression' && resource && this.statusCode === 200 && value) {
            delete value.contents; body = JSON.stringify(value);
          }
          if (repairBaseline || serverError) body = JSON.stringify({ error: 'synthetic-denial' });
          if (change === 'identity-drift' && req.url === '/whoami' && value) body = JSON.stringify({ ...value, userId: 'principal-changed' });
        }
        if (phase < targetPhase && delayEarlierMs && !delayed.has(phase)) {
          delayed.add(phase);
          const timer = setTimeout(() => { timers.delete(timer); Reflect.apply(end, this, [body, ...rest]); }, delayEarlierMs);
          timers.add(timer);
          return this;
        }
        return Reflect.apply(end, this, [body, ...rest]);
      } as typeof res.end;
    }
    return Reflect.apply(emit, this, [event, ...args]);
  });
}

for (const changedPhase of [2, 4]) {
  for (const change of ['leak', 'normal-regression'] as const) {
    test(`two-round ${change} in candidate phase ${changedPhase} remains inconclusive and preserves either-round failure`, async t => {
      perturbResponses(t, changedPhase, change);
      const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
      const evidence = result.verification.checks[0].apiStateEvidence!;
      assert.equal(result.verificationGate.exitCode, 2);
      assert.equal(evidence.verification, 'inconclusive');
      assert.equal(evidence.repetition?.consistency, 'inconsistent');
      assert.equal(evidence.repetition.completedPhases, 4);
      assert.ok(evidence.reasons.includes('repeat_inconsistent'));
      assert.equal(result.execution.apiRequests, 48);
      assert.equal(result.before?.scanGate.exitCode, 1);
      assert.equal(result.before?.report.checks[0].findings.length, 2);
      const changed = changedPhase === 2 ? result.after! : result.afterRepeat!;
      const unchanged = changedPhase === 2 ? result.afterRepeat! : result.after!;
      assert.equal(unchanged.scanGate.exitCode, 0);
      assert.equal(unchanged.evidence.effect, 'not_observed');
      assert.equal(unchanged.evidence.normal, 'passed');
      if (change === 'leak') {
        assert.equal(changed.scanGate.exitCode, 1);
        assert.equal(changed.report.checks[0].findings.length, 2);
        assert.equal(evidence.effect, 'observed');
        assert.ok(result.verification.checks[0].findings.some(f => f.ruleId === 'api.owned-state-effect_persists'));
      } else {
        assert.equal(changed.scanGate.exitCode, 0);
        assert.equal(changed.evidence.normal, 'failed');
        assert.equal(evidence.normal, 'failed');
        assert.ok(result.verification.checks[0].findings.some(f => f.ruleId === 'api.owned-state-normal_regression'));
      }
    });
  }
}

test('moving a leak between resources disagrees even when aggregate effect and normal results match', async t => {
  perturbResponses(t, 2, 'moving-leak');
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
  const evidence = result.verification.checks[0].apiStateEvidence!;
  assert.equal(result.after?.evidence.effect, 'observed');
  assert.equal(result.afterRepeat?.evidence.effect, 'observed');
  assert.equal(result.after?.evidence.normal, 'passed');
  assert.equal(result.afterRepeat?.evidence.normal, 'passed');
  assert.equal(result.after?.report.checks[0].findings.length, 1);
  assert.equal(result.afterRepeat?.report.checks[0].findings.length, 1);
  assert.equal(result.execution.apiRequests, 48);
  assert.equal(result.verificationGate.exitCode, 2);
  assert.equal(evidence.verification, 'inconclusive');
  assert.equal(evidence.repetition?.consistency, 'inconsistent');
  assert.ok(evidence.reasons.includes('repeat_inconsistent'));
  assert.equal(evidence.effect, 'observed');
});

test('a completed baseline repeat without the original leak stops candidate repeat and records disagreement', async t => {
  perturbResponses(t, 3, 'fixed-baseline');
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 5000 });
  const evidence = result.verification.checks[0].apiStateEvidence!;
  assert.equal(result.before?.scanGate.exitCode, 1);
  assert.equal(result.before?.report.checks[0].findings.length, 2);
  assert.equal(result.beforeRepeat?.evidence.execution, 'completed');
  assert.equal(result.beforeRepeat?.evidence.effect, 'not_observed');
  assert.equal(result.beforeRepeat?.scanGate.exitCode, 0);
  assert.equal(result.afterRepeat, null);
  assert.equal(result.execution.apiRequests, 36);
  assert.equal(result.verificationGate.exitCode, 2);
  assert.equal(evidence.repetition?.consistency, 'inconsistent');
  assert.equal(evidence.repetition.completedPhases, 3);
  assert.ok(evidence.reasons.includes('baseline_unconfirmed'));
  assert.ok(evidence.reasons.includes('repeat_inconsistent'));
});

for (const change of ['server-error', 'identity-drift'] as const) {
  test(`late ${change} cannot clear earlier candidate findings`, async t => {
    perturbResponses(t, 4, change);
    const result = await runOwnedApiStatePilot({ candidate: 'ineffective', verificationRounds: 2, timeoutMs: 5000 });
    const evidence = result.verification.checks[0].apiStateEvidence!;
    assert.equal(result.verificationGate.exitCode, 2);
    assert.equal(evidence.verification, 'inconclusive');
    assert.equal(evidence.effect, 'observed');
    assert.equal(evidence.repetition?.consistency, 'incomplete');
    assert.equal(evidence.repetition.completedPhases, 3);
    assert.equal(result.after?.evidence.execution, 'completed');
    assert.equal(result.after?.scanGate.exitCode, 1);
    assert.equal(result.after?.report.checks[0].findings.length, 2);
    assert.equal(result.afterRepeat?.evidence.execution, 'partial');
    assert.ok(result.afterRepeat?.evidence.reasons.includes(change === 'server-error' ? 'response_incomplete' : 'identity_mismatch'));
    assert.ok(result.verification.checks[0].findings.some(f => f.ruleId === 'api.owned-state-effect_persists'));
    assert.equal(result.execution.cleanup, 'confirmed');
  });
}

for (const [name, target, eventType] of [
  ['during baseline repeat', 25, 'request'], ['during candidate repeat', 37, 'request'],
  ['before baseline repeat', 2, 'close'], ['before candidate repeat', 3, 'close'],
] as const) {
  test(`cancellation ${name} retains prior observations and confirmed cleanup`, async t => {
    const controller = new AbortController(), emit = Server.prototype.emit;
    let requests = 0, closes = 0;
    t.mock.method(Server.prototype, 'emit', function (this: Server, event: string, ...args: unknown[]) {
      const returned = Reflect.apply(emit, this, [event, ...args]);
      if (event === 'request' && ++requests === target && eventType === 'request') controller.abort();
      if (event === 'close' && ++closes === target && eventType === 'close') controller.abort();
      return returned;
    });
    const candidate: ApiStateCandidate = 'ineffective';
    const result = await runOwnedApiStatePilot({ candidate, verificationRounds: 2, signal: controller.signal, timeoutMs: 5000 });
    const evidence = result.verification.checks[0].apiStateEvidence!;
    assert.equal(result.verificationGate.exitCode, 2);
    assert.equal(evidence.verification, 'inconclusive');
    assert.equal(evidence.repetition?.consistency, 'incomplete');
    assert.ok(evidence.reasons.includes('cancelled'));
    assert.equal(evidence.effect, 'observed');
    assert.equal(result.before?.scanGate.exitCode, 1);
    assert.equal(result.after?.scanGate.exitCode, 1);
    assert.equal(result.after?.report.checks[0].findings.length, 2);
    assert.ok(result.verification.checks[0].findings.some(f => f.ruleId === 'api.owned-state-effect_persists'));
    assert.equal(result.execution.apiRequests, eventType === 'request' ? target : target * 12);
    assert.equal(result.execution.apiRequests, requests);
    assert.equal(result.execution.phaseInvocations, eventType === 'request' ? Math.ceil(target / 12) : target);
    assert.equal(result.execution.cleanup, 'confirmed');
  });
}

test('all four phases consume one deadline despite delayed earlier responses and a stalled final phase', async t => {
  perturbResponses(t, 4, 'stall', 80);
  const started = performance.now();
  const result = await runOwnedApiStatePilot({ candidate: 'fixed', verificationRounds: 2, timeoutMs: 3000 });
  const elapsed = performance.now() - started;
  const evidence = result.verification.checks[0].apiStateEvidence!;
  assert.equal(result.execution.phaseInvocations, 4);
  for (const phase of [result.before, result.after, result.beforeRepeat]) assert.equal(phase?.evidence.execution, 'completed');
  assert.equal(result.afterRepeat?.evidence.execution, 'partial');
  assert.equal(result.verificationGate.exitCode, 2);
  assert.ok(evidence.reasons.includes('timeout'));
  assert.equal(evidence.repetition?.consistency, 'incomplete');
  assert.equal(evidence.repetition.completedPhases, 3);
  assert.equal(result.execution.apiRequests, 37);
  assert.equal(result.execution.cleanup, 'confirmed');
  const budgets = [result.before!, result.after!, result.beforeRepeat!, result.afterRepeat!]
    .map(phase => phase.report.checks[0].apiExecution!.plan!.timeoutMs);
  for (let index = 1; index < budgets.length; index++) assert.ok(budgets[index] <= budgets[index - 1] - 50);
  assert.ok(elapsed < 7000, 'the stalled final fixture should return cooperatively with bounded cleanup');
});
