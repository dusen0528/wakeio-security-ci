import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { fork, execFile, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const targetScript = fileURLToPath(new URL('../../tests/fixtures/owned-property-target.mjs', import.meta.url));
const EFFECT = 'api.property-write-unauthorized-effect';
const ownerToken = 'Bearer synthetic-owner-secret-c438d';
const verifierToken = 'Bearer synthetic-verifier-secret-a79c1';
type Json = Record<string, unknown>;
interface Window { ordinal: number; before: Json; after?: Json }
interface Arrival { ordinal: number; actor: string; method: string; path: string; ifMatch?: string | null; body?: Json }
interface Scenario {
  mode: string; normalField?: string; protectedField?: string;
  initial?: string | boolean; probe?: string | boolean; control?: string | boolean;
  cancel?: boolean; deadline?: boolean; maxRequests?: number; deliveryFailure?: boolean;
}

// These expectations were authored from the frozen 22-step policy contract,
// before inspecting the runner. Only this original owned target is executed.
async function scenario(t: TestContext, spec: Scenario) {
  const base = await mkdtemp(join(tmpdir(), 'owned-property-independent-'));
  const storePath = join(base, 'state.json'), journalPath = join(base, 'commit-journal.jsonl');
  const out = join(base, 'report'), policyPath = join(base, 'policy.json');
  const N = spec.normalField ?? 'displayTitle', P = spec.protectedField ?? 'privilegedFlag';
  const initialP = spec.initial ?? 'initial-protected-c15a', probeP = spec.probe ?? 'probe-protected-e92b';
  const controlP = spec.control ?? probeP;
  const initial = { object: { id: 'opaque-object-724b', owner: 'owner-1', marker: 'owned-resource-marker-b1951234',
    [N]: 'initial-normal-924d', [P]: initialP, guard: 'immutable-other-value' },
    decoy: { id: 'decoy-object', [N]: 'decoy-normal', [P]: initialP } };
  await writeFile(storePath, JSON.stringify(initial), { mode: 0o600 });
  await writeFile(journalPath, '', { mode: 0o600 });
  const windows: Window[] = [], arrivals: Arrival[] = [];
  let scanner: ChildProcess | undefined, closedSockets: number | undefined;
  let inspectReady!: () => void;
  const inspected = new Promise<void>(resolve => { inspectReady = resolve; });
  let ready!: (origin: string) => void;
  const originReady = new Promise<string>(resolve => { ready = resolve; });
  const target = fork(targetScript, [JSON.stringify({ storePath, journalPath, mode: spec.mode,
    normalField: N, protectedField: P, ownerToken, verifierToken, control: controlP })],
  { silent: true, env: { PATH: process.env.PATH ?? '/usr/bin:/bin' } });
  let targetError = '';
  target.stderr?.on('data', chunk => { targetError += String(chunk); });
  target.on('message', (message: unknown) => {
    const m = message as { kind: string; id?: number; ordinal: number; origin: string; sockets: number; arrivals: Arrival[] };
    if (m.kind === 'ready') ready(m.origin);
    if (m.kind === 'arrival') {
      arrivals.push(m as unknown as Arrival);
      if (spec.deliveryFailure && m.ordinal === 21) {
        rmSync(out, { recursive: true, force: true }); writeFileSync(out, 'owned blocked artifact slot', { mode: 0o600 });
      }
    }
    if (m.kind === 'before-write') windows.push({ ordinal: m.ordinal, before: JSON.parse(readFileSync(storePath, 'utf8')) });
    if (m.kind === 'after-write') {
      const window = windows.find(window => window.ordinal === m.ordinal); assert.ok(window);
      window.after = JSON.parse(readFileSync(storePath, 'utf8'));
    }
    if (m.kind === 'stalled-write' && spec.cancel) scanner?.kill('SIGINT');
    if (m.kind === 'socket-state') { closedSockets = m.sockets; arrivals.splice(0, arrivals.length, ...m.arrivals); inspectReady(); }
    if (m.id !== undefined) target.send({ ack: m.id });
  });
  t.after(async () => {
    if (target.exitCode === null && target.connected) {
      const exit = once(target, 'exit'); target.send({ stop: true });
      const timer = setTimeout(() => target.kill('SIGKILL'), 2000);
      await exit; clearTimeout(timer);
    }
    await rm(base, { recursive: true, force: true });
  });
  const origin = await Promise.race([originReady, once(target, 'exit').then(() => { throw Error('owned target exited: ' + targetError); })]);
  const policy = { version: 1, origin,
    declarations: { disposable: true, staging: true, sharedStrongEtag: true, normalNonceFormat: 'wakeio-property-v1' },
    actors: {
      owner: { authorizationEnv: 'OWNED_PROPERTY_OWNER', identity: { path: '/identity', pointer: '/principal', equals: 'owner-1' } },
      verifier: { authorizationEnv: 'OWNED_PROPERTY_VERIFIER', identity: { path: '/identity', pointer: '/principal', equals: 'verifier-1' } },
    },
    resource: { path: '/resources/opaque-object', id: { pointer: '/id', equals: initial.object.id },
      ownerPointer: '/owner', runMarker: { pointer: '/marker', equals: initial.object.marker } },
    normal: { field: N, initial: initial.object[N] }, protected: { field: P, initial: initialP, probe: probeP, control: controlP } };
  await writeFile(policyPath, JSON.stringify(policy), { mode: 0o600 });
  const args = [cli, 'api-property-write', '--policy', policyPath, '--active-consent', '--allow-private',
    '--timeout-ms', spec.deadline ? '2000' : '30000', '--out', out];
  if (spec.maxRequests !== undefined) args.push('--max-requests', String(spec.maxRequests));
  const result = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve, reject) => {
    scanner = execFile(process.execPath, args, { timeout: 15000, maxBuffer: 2 * 1024 * 1024,
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', OWNED_PROPERTY_OWNER: ownerToken, OWNED_PROPERTY_VERIFIER: verifierToken } },
    (error, stdout, stderr) => {
      const intendedCancelExit = spec.cancel === true && error?.killed === true && error.code === 2 && error.signal === null;
      if (error && (typeof error.code !== 'number' || error.signal !== null || error.killed && !intendedCancelExit)) { reject(error); return; }
      resolve({ code: error ? Number(error.code) : 0, stdout, stderr });
    });
  });
  const finalState = JSON.parse(await readFile(storePath, 'utf8')) as { object: Json; decoy: Json };
  const atReturn = arrivals.length;
  target.send({ inspect: true }); await inspected;
  const closed = once(target, 'exit'); target.send({ stop: true }); await closed;
  const effectWindows = windows.filter(window => {
    const arrival = arrivals.find(row => row.ordinal === window.ordinal);
    if (arrival?.actor !== 'owner' || !arrival.body || !(P in arrival.body) || !window.after) return false;
    const before = window.before.object as Json, after = window.after.object as Json;
    return before[P] !== after[P] && after[P] === probeP;
  });
  const qaDirectory = process.env.OWNED_PROPERTY_QA_RECEIPT_DIR;
  const label = [spec.mode, spec.cancel ? 'cancel' : '', spec.deadline ? 'deadline' : '',
    spec.maxRequests ? 'budget-' + spec.maxRequests : '', spec.deliveryFailure ? 'delivery' : '', spec.normalField ?? ''].filter(Boolean).join('-');
  const facts: Record<string, unknown> = { version: 1, label, processExit: result.code,
    httpArrivals: arrivals.length, patchArrivals: arrivals.filter(row => row.method === 'PATCH').length,
    arrivals: arrivals.map(({ ordinal, actor, method }) => ({ ordinal, actor, method })),
    independentStoredEffect: effectWindows.length > 0, independentEffectWindows: effectWindows.map(window => window.ordinal),
    storeRestored: isDeepStrictEqual(finalState, initial), tcpClosedBeforeHarnessShutdown: closedSockets === 0,
    lateArrivals: arrivals.length - atReturn, targetExecution: 'owned_synthetic_only', provider: 'not_run',
    evidence: 'not_read', publicFormats: 'not_read' };
  async function saveFacts() {
    if (!qaDirectory) return;
    await mkdir(qaDirectory, { recursive: true, mode: 0o700 });
    await writeFile(join(qaDirectory, label + '.json'), JSON.stringify(facts, null, 2) + '\n', { mode: 0o600 });
  }
  await saveFacts();
  assert.equal(closedSockets, 0, 'actual client TCP sockets closed before harness-forced shutdown');
  assert.equal(arrivals.length, atReturn, 'no late API request after runner returned');
  if (spec.deliveryFailure) return { result, arrivals, windows, effectWindows, finalState, initial, N, P, evidence: undefined, check: undefined, agent: undefined };
  const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8'));
  const agent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
  const check = report.checks.find((check: { id: string }) => check.id === 'api.property-write'); assert.ok(check);
  const evidence = check.propertyWriteEvidence; assert.ok(evidence, 'typed property-write evidence, not old owned fixture evidence');
  facts.evidence = evidence; facts.agentGate = agent.scanGate; await saveFacts();
  assert.equal(evidence.scope, 'policy-resource-property-write');
  assert.equal(evidence.basis, 'authenticated-http-readback');
  assert.equal(evidence.counts.plannedRequests, 22);
  assert.equal(evidence.counts.httpAttempts, arrivals.length, 'every actual loopback call, including reset, consumes one attempt');
  assert.equal(evidence.counts.patchAttempts, arrivals.filter(row => row.method === 'PATCH').length);
  assert.equal(evidence.ledger.maximumHttpAttempts, 23); assert.equal(evidence.ledger.maximumPatchAttempts, 8);
  assert.equal(evidence.ledger.steps.length, 23);
  const attempted = evidence.ledger.steps.filter((step: { attempted: boolean }) => step.attempted);
  assert.equal(attempted.length, arrivals.length, 'no unledgered retry or hidden cleanup request');
  for (const [index, step] of attempted.entries()) {
    assert.equal(step.method, arrivals[index].method);
    assert.equal(step.actorIndex, arrivals[index].actor === 'owner' ? 0 : 1);
  }
  for (const step of evidence.ledger.steps.filter((step: { attempted: boolean }) => !step.attempted)) {
    assert.equal(step.outcome, 'not_attempted'); assert.equal(step.httpStatus, null);
  }
  assert.deepEqual(agent.checks.find((row: { checkId: string }) => row.checkId === 'api.property-write').propertyWriteEvidence, evidence);
  const sarif = JSON.parse(await readFile(join(out, 'report.sarif'), 'utf8'));
  function evidenceObjects(value: unknown): unknown[] {
    if (!value || typeof value !== 'object') return [];
    const record = value as Record<string, unknown>;
    if (record.scope === 'policy-resource-property-write' && record.basis === 'authenticated-http-readback') return [value];
    return Object.values(record).flatMap(evidenceObjects);
  }
  assert.ok(evidenceObjects(sarif).some(value => isDeepStrictEqual(value, evidence)), 'SARIF preserves the same typed redacted evidence');
  assert.equal(result.code, agent.scanGate.exitCode);
  assert.ok(!check.apiWriteStateEvidence, 'remote readback is not the independent owned-store oracle');
  const formatNames = ['report.json', 'agent-report.json', 'report.md', 'report.sarif'];
  const formatBytes = await Promise.all(formatNames.map(name => readFile(join(out, name), 'utf8')));
  const publicText = formatBytes.join('\n');
  const rawValues = [ownerToken, verifierToken, origin, '/resources/opaque-object', 'OWNED_PROPERTY_OWNER', 'OWNED_PROPERTY_VERIFIER',
    initial.object.id, initial.object.marker, initial.object[N],
    ...[initialP, probeP, controlP].filter(value => typeof value === 'string'),
    ...arrivals.flatMap(row => row.ifMatch ? [row.ifMatch, row.ifMatch.slice(1, -1)] : []),
    ...arrivals.flatMap(row => row.body && typeof row.body[N] === 'string' ? [row.body[N]] : [])];
  for (const value of rawValues) assert.ok(!publicText.includes(String(value)), 'public formats redact target/credentials/canaries/nonces');
  assert.ok(!publicText.includes(storePath));
  facts.publicFormats = Object.fromEntries(formatNames.map((name, index) => [name,
    { sha256: createHash('sha256').update(formatBytes[index]).digest('hex'), privacyPassed: true }]));
  facts.projectionsConsistent = true;
  await saveFacts();
  if (qaDirectory) {
    const artifactDirectory = join(qaDirectory, label); await mkdir(artifactDirectory, { mode: 0o700 });
    for (const [index, name] of formatNames.entries()) await writeFile(join(artifactDirectory, name), formatBytes[index], { mode: 0o600 });
  }
  return { result, arrivals, windows, effectWindows, finalState, initial, N, P, evidence, check, agent };
}

function gate(result: Awaited<ReturnType<typeof scenario>>, expected: number) { assert.equal(result.result.code, expected); }
function effectRows(result: Awaited<ReturnType<typeof scenario>>) { return result.check?.findings.filter((row: { ruleId: string }) => row.ruleId === EFFECT) ?? []; }

test('property independent: real CLI distinguishes stored effects from PATCH status and restores the exact object', async t => {
  for (const [mode, effect, code] of [['vulnerable', true, 1], ['fixed', false, 0], ['status-mutation', true, 1], ['status-noop', false, 0]] as const) {
    const r = await scenario(t, { mode }); gate(r, code);
    assert.equal(r.effectWindows.length > 0, effect, 'oracle reads persisted write windows, not HTTP status');
    assert.equal(effectRows(r).length, effect ? 1 : 0);
    assert.equal(r.arrivals.length, 22); assert.equal(r.arrivals.filter(row => row.method === 'PATCH').length, 8);
    assert.deepEqual(r.finalState, r.initial, 'conditional cleanup restores both fields and leaves decoy untouched');
    assert.equal(r.evidence.execution, 'completed'); assert.equal(r.evidence.cleanup, 'confirmed');
    for (const f of effectRows(r)) { assert.equal(f.kind, 'candidate'); assert.equal(f.severity, 'high'); assert.equal(f.confidence, 'low'); }
    for (const f of r.agent.findings) assert.deepEqual(f.verification, { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
  }
});

test('property independent: renamed ordinary fields and owner-hidden protected representation retain the same contract', async t => {
  const r = await scenario(t, { mode: 'vulnerable', normalField: 'caption', protectedField: 'opaquePreference' });
  gate(r, 1); assert.equal(r.effectWindows.length, 1); assert.equal(r.arrivals.length, 22);
  assert.deepEqual(r.finalState, r.initial);
});

test('property independent: deny-all, no-op normal writes, wrong objects and missing/stale readback never look clean', async t => {
  const minimum: Record<string, number> = { 'deny-all': 9, 'normal-noop': 10, 'wrong-object': 3, 'write-decoy': 10, 'hidden-field': 4, 'stale-control': 12 };
  for (const mode of ['deny-all', 'normal-noop', 'wrong-object', 'write-decoy', 'hidden-field', 'stale-control']) {
    const r = await scenario(t, { mode }); gate(r, 2);
    assert.ok(r.arrivals.length >= minimum[mode], mode + ' reached its adversarial control, rather than failing preflight');
    assert.notEqual(r.evidence.execution, 'completed');
    assert.equal(r.arrivals.some(row => row.actor === 'owner' && row.body && r.P in row.body), false, 'failed prerequisites prevent dangerous property probe');
  }
});

test('property independent: freshness barrier rejects stale boolean control reads and shared-CAS violations', async t => {
  for (const mode of ['stale-probe', 'ignore-etag', 'concurrent-writer']) {
    const r = await scenario(t, { mode, initial: false, probe: true, control: true }); gate(r, 2);
    assert.notEqual(r.evidence.execution, 'completed');
    assert.ok(r.arrivals.length <= 23); assert.ok(r.arrivals.filter(row => row.method === 'PATCH').length <= 8);
    if (mode === 'stale-probe') {
      assert.ok(r.arrivals.length >= 17, 'normal nonce barrier is attempted after stale provisional read');
      assert.equal(r.effectWindows.length, 0, 'stale positive control is not persisted owner effect');
    }
    if (mode === 'ignore-etag') assert.ok(r.windows.some(window => window.after && (window.before.object as Json)[r.N] !== (window.after.object as Json)[r.N]), 'invalid If-Match actually reached a mutating target');
    if (mode === 'concurrent-writer') {
      assert.ok(r.arrivals.length >= 15); assert.notEqual(r.finalState.object.guard, r.initial.object.guard);
    }
  }
});

test('property independent: late identity drift and ambiguous committed PATCH preserve evidence without retrying writes', async t => {
  const drift = await scenario(t, { mode: 'identity-drift' }); gate(drift, 2);
  assert.equal(drift.effectWindows.length, 1); assert.equal(effectRows(drift).length, 1);
  const ambiguous = await scenario(t, { mode: 'ambiguous-commit' }); gate(ambiguous, 2);
  assert.equal(ambiguous.effectWindows.length, 1);
  const probe = ambiguous.arrivals.find(row => row.actor === 'owner' && row.body && ambiguous.P in row.body); assert.ok(probe);
  const later = ambiguous.arrivals.filter(row => row.ordinal > probe.ordinal);
  assert.ok(later.length <= 1); assert.ok(later.every(row => row.method === 'GET'), 'only one read reconcile; no barrier, restore or retry');
  assert.notEqual(ambiguous.evidence.cleanup, 'confirmed');
});

test('property independent: cancellation and deadline close sockets and admit no later cleanup HTTP', async t => {
  for (const spec of [{ mode: 'cancel-stall', cancel: true }, { mode: 'cancel-stall', deadline: true }]) {
    const r = await scenario(t, spec); gate(r, 2);
    assert.notEqual(r.evidence.execution, 'completed');
    const probe = r.arrivals.find(row => row.actor === 'owner' && row.body && r.P in row.body); assert.ok(probe);
    assert.equal(r.arrivals.some(row => row.ordinal > probe.ordinal), false);
    assert.notEqual(r.evidence.cleanup, 'confirmed');
  }
});

test('property independent: undersized admission budget and response limit fail closed; artifact failure never reruns API', async t => {
  const budget = await scenario(t, { mode: 'vulnerable', maxRequests: 21 }); gate(budget, 2); assert.equal(budget.arrivals.length, 0);
  const body = await scenario(t, { mode: 'body-limit' }); gate(body, 2); assert.ok(body.arrivals.length > 0);
  const delivery = await scenario(t, { mode: 'vulnerable', deliveryFailure: true }); gate(delivery, 2);
  assert.equal(delivery.effectWindows.length, 1); assert.equal(delivery.arrivals.length, 22);
  assert.deepEqual(delivery.finalState, delivery.initial);
});
