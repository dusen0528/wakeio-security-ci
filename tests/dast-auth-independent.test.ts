import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runDast, parseDastPolicy } from '../src/dast.js';
import { replayDastFinding, dastReplayExitCode } from '../src/dast-replay.js';
import { createReport, exitCode, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';
import { parseScanReport } from '../src/compare.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';
import type { CheckResult, ScanReport } from '../src/contracts.js';

const token = 'Bearer owned-native-secret-739c';
const principal = 'owned-principal-739c';
const environment = 'OWNED_NATIVE_AUTH';
type Target = { origin: string; url: string; requests: Array<{ path: string; id: string | null; authorization: string }>;
  firstRequest: Promise<void>; setToken(value: string): void; setMode(value: string): void; close(): Promise<void> };
async function fixture(options: Record<string, string | undefined> = {}): Promise<Target> {
  const module = await import(new URL('../../tests/fixtures/native-dast-auth-sqlite.mjs', import.meta.url).href);
  return module.startAuthenticatedSqlite(options) as Promise<Target>;
}
function policy(target: Target) {
  return { version: 2, kind: 'sql-boolean-differential', baseUrl: `${target.origin}/`, url: target.url,
    parameter: 'id', profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 },
    authorizationEnv: environment, identity: { path: '/identity', status: 200, jsonPointer: '/principal', equals: principal } };
}
function run(target: Target, extra: Record<string, unknown> = {}) {
  // Existing public entry point keeps the baseline runnable before the v2 types exist.
  return runDast({ policy: policy(target), consent: true, allowPrivate: true,
    env: { [environment]: token }, ...extra } as unknown as Parameters<typeof runDast>[0]);
}
function execution(check: CheckResult | undefined): any { assert.ok(check?.dastExecution); return check.dastExecution; }
function report(check: CheckResult): ScanReport { return createReport([check], 'url', new Date()); }
function noSecrets(value: string) {
  for (const forbidden of [token, token.slice(7), createHash('sha256').update(token).digest('hex'),
    principal, environment, '1 AND 1=1', '1 AND 1=2', 'id=1', 'owned-expired', 'owned-query-error', '/principal']) {
    assert.equal(value.includes(forbidden), false, `public evidence leaked ${forbidden}`);
  }
}

test('independent protected real SQLite vulnerable/fixed pair exposes ten-step useful outcomes', async () => {
  for (const mode of ['vulnerable', 'bound']) {
    const target = await fixture({ mode });
    try {
      assert.equal(parseDastPolicy(policy(target)).policy.version, 2);
      const [check] = await run(target);
      assert.equal(check?.status, 'completed', mode);
      const e = execution(check);
      assert.equal(e.version, 2); assert.equal(e.plannedRequests, 10);
      assert.deepEqual(e.identityControls, { before: 'matched', after: 'matched' });
      assert.equal(e.probeOutcome, mode === 'vulnerable' ? 'observed' : 'not_observed');
      assert.equal(e.counts.httpAttempts, 10); assert.equal(target.requests.length, 10);
      assert.deepEqual(target.requests.map(item => item.path), ['/identity', ...Array(8).fill('/items'), '/identity']);
      assert.ok(target.requests.every(item => item.authorization === token));
      assert.deepEqual(target.requests.slice(1, 9).map(item => item.id),
        ['1', '1 AND 1=1', '1 AND 1=2', '1', '1', '1 AND 1=1', '1 AND 1=2', '1']);
      assert.equal(check?.findings.length, mode === 'vulnerable' ? 1 : 0);
      if (mode === 'vulnerable') assert.equal(check?.findings[0]?.confidence, 'medium');
      assert.equal(exitCode(report(check!), 'high'), mode === 'vulnerable' ? 1 : 0);
      noSecrets(JSON.stringify(check));
    } finally { await target.close(); }
  }
});

test('independent selected credential rejects missing/inherited/getter/proxy/CRLF without traffic or side effects', async () => {
  const target = await fixture(); let invoked = 0;
  try {
    const accessor = Object.defineProperty({}, environment, { enumerable: true, get() { invoked++; return token; } });
    const proxy = new Proxy({ [environment]: token }, { getOwnPropertyDescriptor() { invoked++; throw new Error('must not reflect'); }, get() { invoked++; throw new Error('must not read'); } });
    for (const env of [{}, Object.create({ [environment]: token }), accessor, proxy, { [environment]: '' }, { [environment]: `${token}\r\nInjected: value` }]) {
      const [check] = await run(target, { env });
      assert.equal(exitCode(report(check!), 'none'), 2);
      assert.equal(check?.findings.length, 0); assert.equal(target.requests.length, 0);
      noSecrets(JSON.stringify(check));
    }
    assert.equal(invoked, 0);
  } finally { await target.close(); }
});

test('independent wrong principal and expired token before prevent every SQL request', async () => {
  for (const options of [{ principal: `${principal}-wrong` }, { token: `${token}-expired` }]) {
    const target = await fixture(options);
    try {
      const [check] = await run(target);
      assert.equal(exitCode(report(check!), 'none'), 2); assert.equal(check?.findings.length, 0);
      assert.equal(target.requests.length, 1); assert.equal(target.requests[0]?.path, '/identity');
      assert.notEqual(execution(check).identityControls.before, 'matched');
      assert.equal(execution(check).probeOutcome, 'inconclusive');
    } finally { await target.close(); }
  }
});

test('independent after expiry/change retains observed SQL as low incomplete evidence without replay authority', async () => {
  for (const mode of ['expire-after', 'change-after']) {
    const target = await fixture({ mode });
    try {
      const [check] = await run(target); const e = execution(check);
      assert.equal(check?.status, 'partial'); assert.equal(exitCode(report(check!), 'none'), 2);
      assert.equal(e.probeOutcome, 'observed'); assert.equal(e.outcome, 'inconclusive');
      assert.equal(e.identityControls.before, 'matched'); assert.notEqual(e.identityControls.after, 'matched');
      assert.equal(target.requests.length, 10); assert.equal(check?.findings.length, 1);
      assert.equal(check?.findings[0]?.kind, 'candidate'); assert.equal(check?.findings[0]?.confidence, 'low');
      assert.equal(check?.findings[0]?.controlVerification, undefined);
      const publicReport = report(check!); assert.equal(publicReport.checks[0]?.findings.length, 1);
      const advice = JSON.stringify(projectAdviceContext(toAgentReport(publicReport), true));
      assert.equal(advice.includes('replay_native_finding_same_policy'), false); noSecrets(advice);
      const before = target.requests.length;
      const replay = await replayDastFinding({ report: publicReport, policy: policy(target), findingId: publicReport.checks[0]!.findings[0]!.id,
        consent: true, allowPrivate: true, env: { [environment]: token } } as unknown as Parameters<typeof replayDastFinding>[0]);
      assert.equal(replay.outcome, 'refused'); assert.equal(dastReplayExitCode(replay), 2);
      assert.equal(target.requests.length, before);
    } finally { await target.close(); }
  }
});

test('independent nine-attempt cap retains observed probe but cannot infer after identity', async () => {
  const target = await fixture();
  try {
    const [check] = await run(target, { maxRequests: 9 }); const e = execution(check);
    assert.equal(check?.status, 'partial'); assert.equal(e.stopReason, 'request_budget');
    assert.equal(e.probeOutcome, 'observed'); assert.equal(e.identityControls.after, 'not_attempted');
    assert.equal(target.requests.length, 9); assert.equal(e.counts.httpAttempts, 9);
    assert.equal(check?.findings[0]?.confidence, 'low'); assert.equal(report(check!).checks[0]?.findings.length, 1);
    assert.equal(exitCode(report(check!), 'none'), 2);
  } finally { await target.close(); }
});

test('independent auth snapshot stays fixed while caller changes env and cancellation stops remaining steps', async () => {
  const target = await fixture();
  try {
    const env = { [environment]: token }; const pending = run(target, { env });
    env[environment] = `${token}-changed`;
    const [check] = await pending;
    assert.equal(check?.status, 'completed'); assert.ok(target.requests.every(item => item.authorization === token));
  } finally { await target.close(); }
  const slow = await fixture({ mode: 'slow-identity' });
  try {
    const controller = new AbortController(); const pending = run(slow, { signal: controller.signal });
    await slow.firstRequest; controller.abort(); const [check] = await pending;
    assert.equal(check?.status, 'partial'); assert.equal(execution(check).stopReason, 'cancelled');
    assert.equal(slow.requests.length, 1); assert.equal(check?.findings.length, 0);
  } finally { await slow.close(); }
});

test('independent identity redirect is never followed or used as an authenticated SQL control', async () => {
  const other = await fixture();
  try {
    for (const redirect of ['/identity-redirected', `${other.origin}/identity`]) {
      const target = await fixture({ mode: 'redirect', redirect });
      try {
        const [check] = await run(target);
        assert.equal(check?.status, 'partial'); assert.equal(check?.findings.length, 0);
        assert.equal(target.requests.length, 1); assert.equal(other.requests.length, 0);
        assert.equal(execution(check).probeOutcome, 'inconclusive');
      } finally { await target.close(); }
    }
  } finally { await other.close(); }
});

test('independent replay obtains rotated credentials for the same principal and never edits the original report', async () => {
  const target = await fixture();
  try {
    const [check] = await run(target); const original = report(check!); const bytes = JSON.stringify(original);
    const rotated = `${token}-rotated`; target.setToken(rotated);
    const replay = await replayDastFinding({ report: original, policy: policy(target), findingId: original.checks[0]!.findings[0]!.id,
      consent: true, allowPrivate: true, env: { [environment]: rotated } } as unknown as Parameters<typeof replayDastFinding>[0]);
    assert.equal(replay.outcome, 'reproduced'); assert.equal(dastReplayExitCode(replay), 1);
    assert.equal(target.requests.length, 20); assert.ok(target.requests.slice(10).every(item => item.authorization === rotated));
    assert.deepEqual(execution(replay.check).identityControls, { before: 'matched', after: 'matched' });
    assert.equal(JSON.stringify(original), bytes); noSecrets(JSON.stringify(replay));
    assert.equal(JSON.stringify(replay).includes(rotated), false);
  } finally { await target.close(); }
});

test('independent four public artifacts preserve partial identity/probe distinction without secret payloads', async () => {
  const target = await fixture({ mode: 'expire-after' }); const directory = await mkdtemp(join(tmpdir(), 'wakeio-auth-report-'));
  try {
    const [check] = await run(target); const original = report(check!); const snapshot = JSON.stringify(original);
    await writeReports(original, directory);
    const texts = await Promise.all(['report.json', 'report.md', 'report.sarif', 'agent-report.json'].map(name => readFile(join(directory, name), 'utf8')));
    texts.forEach(noSecrets);
    const json = parseScanReport(JSON.parse(texts[0]!));
    const agent = JSON.parse(texts[3]!); const sarif = JSON.parse(texts[2]!);
    assert.deepEqual(json.checks[0]?.dastExecution, check?.dastExecution);
    assert.deepEqual(agent.checks[0]?.dastExecution, check?.dastExecution);
    assert.deepEqual(sarif.runs[0]?.properties?.dastExecution?.[0]?.dastExecution, check?.dastExecution);
    assert.ok(JSON.stringify(sarif).includes('"probeOutcome":"observed"'));
    assert.match(texts[1]!, /SQL probe outcome: observed/); assert.match(texts[1]!, /identity.*before=matched.*after=/i);
    assert.equal(agent.findings.length, 1); assert.equal(agent.findings[0]?.confidence, 'low');
    assert.equal(agent.findings[0]?.verification?.state, 'not_run');
    assert.equal(JSON.stringify(original), snapshot);
    assert.equal(toMarkdown(original), texts[1]); assert.deepEqual(toSarif(original), sarif);
  } finally { await target.close(); await rm(directory, { recursive: true, force: true }); }
});

test('independent malformed/auth-inconsistent ledgers cannot survive as completed or replayable evidence', async () => {
  const target = await fixture();
  try {
    const [check] = await run(target); const e = execution(check);
    for (const changed of [
      { ...e, identityControls: { before: 'matched', after: 'mismatched' } },
      { ...e, probeOutcome: 'not_observed' }, { ...e, plannedRequests: 8 },
      { ...e, steps: e.steps.map((step: any, index: number) => index === 0 ? { ...step, oracleMatch: 'baseline' } : step) },
      { ...e, token },
    ]) {
      const safe = report({ ...check!, dastExecution: changed });
      assert.equal(exitCode(safe, 'none'), 2); assert.notEqual(safe.checks[0]?.status, 'completed');
      assert.equal(safe.checks[0]?.findings.length, 0); noSecrets(JSON.stringify(safe));
      assert.throws(() => parseScanReport({ ...safe, checks: [{ ...check!, dastExecution: changed }] }));
    }
  } finally { await target.close(); }
});
