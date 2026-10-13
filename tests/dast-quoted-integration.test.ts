import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../src/cli.js';
import { createReport, exitCode, toAgentReport, toSarif, toMarkdown } from '../src/report.js';
import { compareReports, parseScanReport } from '../src/compare.js';
import type { CheckResult, Finding } from '../src/contracts.js';
import type { DastExecution } from '../src/dast-execution.js';

const execute = promisify(execFile), cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const envName = 'OWNED_QUOTED_INTEGRATION_AUTH', token = 'Bearer owned-quoted-integration-token';
const scalar = 'owned_seed_23';
function policy(origin: string, authenticated: boolean) {
  return { version: 3, kind: 'sql-boolean-differential', profile: 'single-quoted', baseUrl: `${origin}/`,
    url: `${origin}/items?name=${scalar}`, parameter: 'name',
    oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 },
    ...(authenticated ? { authorizationEnv: envName, identity: { path: '/owned-identity', status: 200, jsonPointer: '/principal', equals: 'owned-principal-23' } } : {}) };
}

test('quoted offline plans derive eight/ten phases, paired auth and bounded budget without network or seed disclosure', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-quoted-plan-'));
  try {
    for (const authenticated of [false, true]) {
      const path = join(top, `policy-${authenticated}.json`); const input = policy('http://127.0.0.1:1', authenticated);
      await writeFile(path, JSON.stringify(input)); const env = { ...process.env, [envName]: token };
      const result = await execute(process.execPath, [cli, 'plan', '--dast-policy', path, '--allow-private'], { env });
      const plan = JSON.parse(result.stdout); assert.equal(plan.status, 'ready');
      assert.equal(plan.plannedRequests, authenticated ? 10 : 8); assert.equal(plan.steps.length, plan.plannedRequests);
      assert.equal(plan.profileRevision, authenticated ? 'sql-boolean-single-quoted-auth-v3' : 'sql-boolean-single-quoted-v3');
      assert.equal(plan.steps[0].phase, authenticated ? 'identity-before' : 'baseline-before');
      for (const forbidden of [scalar, envName, token, 'owned-principal-23', '/owned-identity', '/principal']) assert.equal(result.stdout.includes(forbidden), false);
      await assert.rejects(execute(process.execPath, [cli, 'plan', '--dast-policy', path, '--allow-private', '--dast-max-requests', authenticated ? '9' : '7'], { env }),
        (error: any) => error.code === 2 && error.stdout.includes('insufficient_request_budget'));
      if (authenticated) {
        const missing = { ...process.env }; delete missing[envName];
        await assert.rejects(execute(process.execPath, [cli, 'plan', '--dast-policy', path, '--allow-private'], { env: missing }), (error: any) => error.code === 2);
      }
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});

// Synthetic HTTP protocol fixture: phase responses validate only CLI/replay
// plumbing. Independently owned real SQLite tests establish SQL behavior.
test('quoted CLI and replay retain profile, default budgets, auth controls, partial candidates and immutable originals', async () => {
  let hits = 0, sql = 0, identity = 0, authenticated = false, fixed = false, failAfter = false;
  let selectedToken = token;
  const server = createServer((request, response) => {
    hits++;
    assert.equal(request.headers.authorization, authenticated ? selectedToken : undefined);
    response.setHeader('content-type', 'application/json');
    if (request.url === '/owned-identity') {
      identity++;
      response.end(JSON.stringify({ principal: failAfter && identity % 2 === 0 ? 'changed-principal' : 'owned-principal-23' }));
    } else {
      const phase = sql++ % 4;
      response.end(JSON.stringify({ count: phase === 2 || fixed && phase === 1 ? 0 : 1 }));
    }
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const top = await mkdtemp(join(tmpdir(), 'wakeio-quoted-cli-')), previous = process.env[envName];
  try {
    const origin = `http://127.0.0.1:${address.port}`;
    for (authenticated of [false, true]) {
      fixed = false; failAfter = false; sql = 0; identity = 0; selectedToken = token;
      process.env[envName] = token;
      const path = join(top, `policy-${authenticated}.json`); await writeFile(path, JSON.stringify(policy(origin, authenticated)));
      const original = join(top, `original-${authenticated}`), before = hits;
      assert.equal(await main(['scan', '--dast-policy', path, '--active-consent', '--allow-private', '--out', original]), 1);
      const files = ['report.json', 'report.md', 'report.sarif', 'agent-report.json'];
      const snapshots = await Promise.all(files.map(file => readFile(join(original, file), 'utf8')));
      const report = JSON.parse(snapshots[0]!); const e = report.checks[0].dastExecution;
      assert.equal(e.profile, 'single-quoted'); assert.equal(e.maxRequests, authenticated ? 10 : 8);
      assert.equal(hits - before, e.plannedRequests); assert.equal(e.authentication, authenticated ? 'authorization' : 'none');
      const replay = ['replay', '--report', join(original, 'report.json'), '--dast-policy', path, '--finding', report.checks[0].findings[0].id, '--active-consent', '--allow-private'];
      if (authenticated) { selectedToken = `${token}-rotated`; process.env[envName] = selectedToken; }
      const reproduced = join(top, `reproduced-${authenticated}`);
      assert.equal(await main([...replay, '--out', reproduced]), 1);
      assert.equal(JSON.parse(await readFile(join(reproduced, 'replay.json'), 'utf8')).outcome, 'reproduced');
      fixed = true;
      const bound = join(top, `bound-${authenticated}`);
      assert.equal(await main([...replay, '--out', bound]), 0);
      assert.equal(JSON.parse(await readFile(join(bound, 'replay.json'), 'utf8')).outcome, 'not_reproduced');
      if (authenticated) {
        fixed = false; failAfter = true;
        const partialOut = join(top, 'partial-auth');
        assert.equal(await main(['scan', '--dast-policy', path, '--active-consent', '--allow-private', '--out', partialOut]), 2);
        const partial = JSON.parse(await readFile(join(partialOut, 'report.json'), 'utf8'));
        assert.equal(partial.checks[0].dastExecution.probeOutcome, 'observed'); assert.equal(partial.checks[0].findings[0].confidence, 'low');
        const prior = hits;
        assert.equal(await main(['replay', '--report', join(partialOut, 'report.json'), '--dast-policy', path, '--finding', partial.checks[0].findings[0].id,
          '--active-consent', '--allow-private', '--out', join(top, 'refused-partial')]), 2);
        assert.equal(hits, prior);
      }
      assert.deepEqual(await Promise.all(files.map(file => readFile(join(original, file), 'utf8'))), snapshots);
      for (const text of snapshots) for (const forbidden of [scalar, token, envName, 'owned-principal-23', '/owned-identity', "AND '1'"])
        assert.equal(text.includes(forbidden), false, `public profile evidence leaked ${forbidden}`);
    }
  } finally {
    if (previous === undefined) delete process.env[envName]; else process.env[envName] = previous;
    server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); await rm(top, { recursive: true, force: true });
  }
});

function fixtureLedger(authenticated: boolean): DastExecution {
  const phases = ['baseline-before', 'true', 'false', 'baseline-after'] as const, total = authenticated ? 10 : 8;
  return { version: 3, profile: 'single-quoted', authentication: authenticated ? 'authorization' : 'none',
    profileRevision: authenticated ? 'sql-boolean-single-quoted-auth-v3' : 'sql-boolean-single-quoted-v3',
    policySha256: 'a'.repeat(64), maxRequests: total, timeoutMs: 30000, allowPrivate: false,
    status: 'complete', outcome: 'observed', plannedRequests: total,
    steps: Array.from({ length: total }, (_, ordinal) => {
      const index = authenticated ? ordinal - 1 : ordinal, isIdentity = authenticated && (ordinal === 0 || ordinal === 9);
      return { ordinal, round: isIdentity ? 0 : index < 4 ? 1 : 2, phase: isIdentity ? ordinal === 0 ? 'identity-before' : 'identity-after' : phases[index % 4],
        outcome: 'evaluated', reason: 'evaluated', attemptStart: ordinal, httpAttempts: 1, httpStatus: 200,
        oracleMatch: isIdentity ? 'unavailable' : index % 4 === 2 ? 'false' : 'baseline' };
    }), counts: { evaluated: total, inconclusive: 0, notAttempted: 0, httpAttempts: total }, stopReason: 'none',
    ...(authenticated ? { identityControls: { before: 'matched', after: 'matched' }, probeOutcome: 'observed' } : {}) } as DastExecution;
}
const finding: Finding = { ruleId: 'dast.sql-boolean-differential', title: 'SQL boolean response differential observed',
  description: 'Owned schema fixture.', remediation: 'Bind values.', severity: 'high', confidence: 'medium', kind: 'candidate', location: { url: 'https://owned.example/items' } };
const metadataReport = (e: DastExecution) => createReport([{ id: 'url.sql-boolean', status: 'completed', findings: [finding], notes: [], metrics: { requestCount: e.counts.httpAttempts }, dastExecution: e }],
  'url', '2026-10-13T00:00:00Z', { fingerprint: 'b'.repeat(64), ruleset: 'profile-test' });

test('validated quoted revisions namespace IDs; numeric historical IDs and normalization remain stable', () => {
  const quoted = metadataReport(fixtureLedger(false)), auth = metadataReport(fixtureLedger(true));
  const numeric = { ...fixtureLedger(false), version: 1, profile: 'numeric', profileRevision: 'sql-boolean-numeric-v1' } as unknown as DastExecution;
  delete (numeric as any).authentication;
  const old = metadataReport(numeric);
  assert.notEqual(quoted.checks[0]?.findings[0]?.id, old.checks[0]?.findings[0]?.id);
  assert.notEqual(auth.checks[0]?.findings[0]?.id, quoted.checks[0]?.findings[0]?.id);
  for (const report of [old, quoted, auth]) {
    assert.equal(createReport(report.checks, report.mode, report.startedAt, report.scope).checks[0]?.findings[0]?.id, report.checks[0]?.findings[0]?.id);
    assert.equal(toSarif(report).runs[0]?.results[0]?.fingerprints['wakeio-security-ci/v2'], report.checks[0]?.findings[0]?.id);
    assert.deepEqual(parseScanReport(report), report); assert.equal(toAgentReport(report).findings[0]?.verification.state, 'not_run');
  }
  const comparison = compareReports(old, quoted); assert.equal(comparison.comparable, false);
  assert.equal(comparison.summary.not_observed, 0); assert.ok(comparison.summary.unverified > 0);
  assert.match(toMarkdown(quoted), /single-quoted SQL differential rounds/);
});

test('strict quoted metadata cannot lose authentication or invent an empty completed observed result', () => {
  const e = fixtureLedger(true), report = metadataReport(e);
  const forged: any = { ...e }; delete forged.identityControls;
  const malformed: CheckResult = { ...report.checks[0]!, dastExecution: forged };
  assert.equal(exitCode(createReport([malformed], 'url', new Date()), 'none'), 2);
  assert.throws(() => parseScanReport({ ...report, checks: [malformed] }));
  const missing = { ...report.checks[0]!, findings: [] };
  const partial = createReport([missing], 'url', report.startedAt);
  assert.equal(exitCode(partial, 'none'), 2); assert.deepEqual(parseScanReport(partial), partial);
  assert.throws(() => parseScanReport({ ...report, checks: [missing] }));
});
