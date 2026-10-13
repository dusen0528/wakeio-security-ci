import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, parseCliArgs } from '../src/cli.js';
import { createReport, exitCode, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { compareReports } from '../src/compare.js';
import type { CheckResult, DastExecution } from '../src/contracts.js';

const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const policy = (origin: string) => ({ version: 1, kind: 'sql-boolean-differential', baseUrl: `${origin}/`,
  url: `${origin}/items?id=1`, parameter: 'id', profile: 'numeric',
  oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } });

function ledger(): DastExecution {
  const phases = ['baseline-before', 'true', 'false', 'baseline-after'] as const;
  return { version: 1, policySha256: 'a'.repeat(64), profile: 'numeric', profileRevision: 'sql-boolean-numeric-v1', maxRequests: 8, timeoutMs: 30000, allowPrivate: false, status: 'complete', outcome: 'observed', plannedRequests: 8,
    steps: Array.from({ length: 8 }, (_, ordinal) => ({ ordinal, round: (ordinal < 4 ? 1 : 2) as 1 | 2,
      phase: phases[ordinal % 4]!, outcome: 'evaluated' as const, reason: 'evaluated' as const, attemptStart: ordinal,
      httpAttempts: 1, httpStatus: 200, oracleMatch: ordinal % 4 === 2 ? 'false' as const : 'baseline' as const })),
    counts: { evaluated: 8, inconclusive: 0, notAttempted: 0, httpAttempts: 8 }, stopReason: 'none' };
}
function check(): CheckResult {
  return { id: 'url.sql-boolean', status: 'completed', notes: [], metrics: { requestCount: 8 }, dastExecution: ledger(),
    findings: [{ ruleId: 'url.sql-boolean.differential', title: 'Repeated numeric differential', description: 'Scoped candidate.',
      severity: 'high', confidence: 'high', kind: 'candidate', location: { url: 'https://example.test/items' }, remediation: 'Use parameter binding.' }] };
}

test('native DAST CLI requires consent, a policy, bounded attempts and explicit origin syntax', () => {
  assert.throws(() => parseCliArgs(['scan', '--dast-policy', 'policy.json']), /active-consent/);
  assert.throws(() => parseCliArgs(['scan', '--url', 'https://example.test', '--dast-max-requests', '8']), /requires --dast-policy/);
  assert.throws(() => parseCliArgs(['scan', '--dast-policy', 'p.json', '--active-consent', '--dast-max-requests', '65']));
  const parsed = parseCliArgs(['scan', '--dast-policy', 'p.json', '--active-consent', '--dast-max-requests', '7', '--allow-private', '--allowed-origin', 'https://example.test']);
  assert.ok(!('help' in parsed));
  assert.equal(parsed.dastMaxRequests, 7);
});

test('native DAST report retains scoped evidence and never converts it to independent verification', () => {
  const report = createReport([check()], 'url', '2026-10-13T00:00:00Z');
  assert.equal(exitCode(report, 'high'), 1);
  const agent = toAgentReport(report, 'high');
  assert.equal(agent.checks[0]!.dastExecution!.outcome, 'observed');
  assert.deepEqual(agent.findings[0]!.verification, { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
  assert.equal(agent.findings[0]!.evidence.kind, 'candidate');
  assert.match(toMarkdown(report, 'high'), /Native DAST: complete; observed/);
  assert.match(JSON.stringify(toSarif(report)), /dastExecution/);
  assert.deepEqual(toAgentReport(createReport(report.checks, 'url', report.startedAt), 'high').checks, agent.checks);
});

test('missing, mismatched or forged DAST evidence cannot produce a completed report', () => {
  const cases = [
    (c: CheckResult) => { delete c.dastExecution; },
    (c: CheckResult) => { c.metrics!.requestCount = 7; },
    (c: CheckResult) => { c.dastExecution!.steps.pop(); },
    (c: CheckResult) => { c.dastExecution!.steps[2]!.oracleMatch = 'baseline'; },
    (c: CheckResult) => { c.dastExecution!.outcome = 'not_observed'; c.dastExecution!.steps[0]!.oracleMatch = 'other'; },
    (c: CheckResult) => { c.dastExecution!.policySha256 = 'raw-response-secret'; },
  ];
  for (const mutate of cases) {
    const input = check(); mutate(input);
    const report = createReport([input], 'url', '2026-10-13T00:00:00Z');
    assert.equal(exitCode(report, 'none'), 2);
    assert.equal(report.checks[0]!.status, 'partial');
    assert.equal(report.checks[0]!.findings.length, 0);
    assert.ok(!JSON.stringify(report).includes('raw-response-secret'));
  }
});

test('DAST comparison refuses changed policy and execution budgets even with a reused external scope', () => {
  const scope = { fingerprint: 'b'.repeat(64), ruleset: 'test' };
  const before = createReport([check()], 'url', '2026-10-13T00:00:00Z', scope);
  const mutations = [
    (execution: DastExecution) => { execution.policySha256 = 'c'.repeat(64); },
    (execution: DastExecution) => { execution.maxRequests = 9; },
    (execution: DastExecution) => { execution.timeoutMs = 31000; },
    (execution: DastExecution) => { execution.allowPrivate = true; },
  ];
  for (const mutate of mutations) {
    const afterCheck = check(); mutate(afterCheck.dastExecution!);
    const after = createReport([afterCheck], 'url', '2026-10-13T00:00:00Z', scope);
    const result = compareReports(before, after);
    assert.equal(result.comparable, false);
    assert.ok(result.reasons.some(reason => reason.includes('Native DAST policy')));
  }
});

// This server checks integration only. The engine suite owns real vulnerable/bound SQLite fixtures.
test('plan is offline; CLI writes all reports, applies origin policy and preserves incomplete budgets', async () => {
  let hits = 0;
  const server = createServer((req, res) => {
    hits++;
    const id = new URL(req.url!, 'http://test').searchParams.get('id')!;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ count: id.includes('1=2') ? 0 : 1 }));
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-dast-integration-'));
  try {
    const input = join(directory, 'policy.json'); await writeFile(input, JSON.stringify(policy(origin)));
    await assert.rejects(exec(process.execPath, [cli, 'plan', '--dast-policy', input]), (error: any) => error.code === 2);
    assert.equal(hits, 0, 'v1 offline private-target refusal remains unchanged');
    const plan = await exec(process.execPath, [cli, 'plan', '--dast-policy', input, '--allow-private']);
    const planned = JSON.parse(plan.stdout);
    assert.equal(planned.status, 'ready'); assert.equal(planned.plannedRequests, 8);
    assert.equal(hits, 0); assert.ok(!plan.stdout.includes('expectedBaseline') && !plan.stdout.includes('?id='));
    await assert.rejects(exec(process.execPath, [cli, 'plan', '--dast-policy', input, '--allow-private', '--dast-max-requests', '7']),
      (error: any) => error.code === 2 && error.stdout.includes('insufficient_request_budget'));
    assert.equal(hits, 0);
    const blocked = join(directory, 'blocked');
    assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--allowed-origin', 'https://example.test', '--out', blocked]), 2);
    assert.equal(hits, 0);
    const out = join(directory, 'reports');
    assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--out', out]), 1);
    assert.equal(hits, 8);
    const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8'));
    assert.equal(report.checks[0].dastExecution.outcome, 'observed');
    for (const file of ['report.json', 'report.md', 'report.sarif', 'agent-report.json']) {
      const text = await readFile(join(out, file), 'utf8');
      assert.ok(!text.includes('expectedBaseline') && !text.includes('AND 1='));
    }
    assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--dast-max-requests', '7', '--fail-on', 'none', '--out', join(directory, 'partial')]), 2);
    assert.equal(hits, 15);
  } finally { await new Promise<void>(done => server.close(() => done())); await rm(directory, { recursive: true, force: true }); }
});

test('advise help dispatches independently of scan and requires explicit upload and auth selection', async () => {
  const help = await exec(process.execPath, [cli, 'advise', '--help']);
  assert.match(help.stdout, /cli-login\|api-key/);
  assert.match(help.stdout, /allow-report-upload/);
});

test('authenticated v2 offline plan validates fresh credentials and transport without disclosing identity values', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-auth-plan-'));
  const authName = 'WAKEIO_OWNED_AUTH_PLAN';
  const secret = 'Bearer owned-plan-credential-sentinel';
  try {
    const input = join(directory, 'policy.json');
    const v2 = { ...policy('http://127.0.0.1:1'), version: 2, authorizationEnv: authName,
      identity: { path: '/private-identity-sentinel', status: 200, jsonPointer: '/principal-sentinel', equals: 'private-principal-sentinel' } };
    await writeFile(input, JSON.stringify(v2));
    const env = { ...process.env, [authName]: secret };
    const ready = await exec(process.execPath, [cli, 'plan', '--dast-policy', input, '--allow-private'], { env });
    const planned = JSON.parse(ready.stdout);
    assert.equal(planned.status, 'ready'); assert.equal(planned.profileRevision, 'sql-boolean-numeric-auth-v2');
    assert.equal(planned.plannedRequests, 10); assert.equal(planned.maxHttpAttempts, 10);
    assert.deepEqual(planned.steps.map((step: { phase: string }) => step.phase),
      ['identity-before', 'baseline-before', 'true', 'false', 'baseline-after', 'baseline-before', 'true', 'false', 'baseline-after', 'identity-after']);
    for (const forbidden of [authName, secret, 'private-identity-sentinel', 'principal-sentinel', 'private-principal-sentinel', 'expectedBaseline']) assert.equal(ready.stdout.includes(forbidden), false);
    await assert.rejects(exec(process.execPath, [cli, 'plan', '--dast-policy', input, '--allow-private', '--dast-max-requests', '9'], { env }),
      (error: any) => error.code === 2 && error.stdout.includes('insufficient_request_budget'));
    const missing: NodeJS.ProcessEnv = { ...env }; delete missing[authName];
    for (const blockedEnv of [missing, { ...env, [authName]: 'Bearer bad\r\nheader' }]) {
      await assert.rejects(exec(process.execPath, [cli, 'plan', '--dast-policy', input, '--allow-private'], { env: blockedEnv }),
        (error: any) => error.code === 2 && !error.stdout.includes(authName) && !error.stdout.includes(secret));
    }
    await writeFile(input, JSON.stringify({ ...v2, baseUrl: 'http://no-dns-auth-plan.invalid/', url: 'http://no-dns-auth-plan.invalid/items?id=1' }));
    await assert.rejects(exec(process.execPath, [cli, 'plan', '--dast-policy', input, '--allow-private'], { env }),
      (error: any) => error.code === 2 && !error.stdout.includes('private-identity-sentinel'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

// Synthetic protocol fixture only: the core SQLite suite separately validates SQL behavior.
test('authenticated v2 CLI uses ten shared attempts, binds effective scope without token, and retains failed-after probe evidence', async () => {
  const authName = 'WAKEIO_OWNED_AUTH_INTEGRATION';
  const originalEnv = process.env[authName];
  const tokens = ['Bearer owned-first-secret', 'Bearer owned-rotated-secret'];
  let hits = 0, identityHits = 0, failAfter = false;
  const server = createServer((request, response) => {
    hits++; assert.ok(tokens.includes(request.headers.authorization!));
    response.setHeader('content-type', 'application/json');
    if (request.url === '/private-identity-integration') {
      identityHits++;
      response.end(JSON.stringify({ principal: failAfter && identityHits % 2 === 0 ? 'changed-private-principal' : 'owned-private-principal' }));
    } else {
      const value = new URL(request.url!, 'http://owned.invalid').searchParams.get('id')!;
      response.end(JSON.stringify({ count: value.includes('1=2') ? 0 : 1 }));
    }
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const top = await mkdtemp(join(tmpdir(), 'wakeio-auth-cli-'));
  try {
    const origin = `http://127.0.0.1:${address.port}`;
    const input = join(top, 'policy.json');
    const v2 = { ...policy(origin), version: 2, authorizationEnv: authName,
      identity: { path: '/private-identity-integration', status: 200, jsonPointer: '/principal', equals: 'owned-private-principal' } };
    await writeFile(input, JSON.stringify(v2));
    delete process.env[authName];
    assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--out', join(top, 'missing')]), 2);
    assert.equal(hits, 0);
    const successful: any[] = [];
    for (const [index, token] of tokens.entries()) {
      process.env[authName] = token;
      const out = join(top, `scan-${index}`);
      assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--out', out]), 1);
      successful.push(JSON.parse(await readFile(join(out, 'report.json'), 'utf8')));
      const execution = successful[index].checks[0].dastExecution;
      assert.equal(execution.maxRequests, 10); assert.equal(execution.counts.httpAttempts, 10);
      assert.equal(execution.profileRevision, 'sql-boolean-numeric-auth-v2');
      assert.deepEqual(execution.identityControls, { before: 'matched', after: 'matched' });
      for (const file of ['report.json', 'agent-report.json', 'report.md', 'report.sarif']) {
        const text = await readFile(join(out, file), 'utf8');
        for (const forbidden of [...tokens, authName, '/private-identity-integration', 'owned-private-principal', '"authorization"', 'AND 1=']) assert.equal(text.includes(forbidden), false, `${file}: ${forbidden}`);
      }
    }
    assert.equal(hits, 20); assert.equal(successful[0].scope.fingerprint, successful[1].scope.fingerprint, 'token changes do not alter approved scope');
    failAfter = true;
    const partialOut = join(top, 'failed-after');
    assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--out', partialOut]), 2);
    const incomplete = JSON.parse(await readFile(join(partialOut, 'report.json'), 'utf8'));
    assert.equal(incomplete.checks[0].status, 'partial'); assert.equal(incomplete.checks[0].dastExecution.probeOutcome, 'observed');
    assert.equal(incomplete.checks[0].dastExecution.identityControls.after, 'mismatched');
    assert.equal(incomplete.checks[0].findings.length, 1); assert.equal(incomplete.checks[0].findings[0].confidence, 'low');
    assert.equal(hits, 30);
  } finally {
    if (originalEnv === undefined) delete process.env[authName]; else process.env[authName] = originalEnv;
    await new Promise<void>(done => server.close(() => done())); await rm(top, { recursive: true, force: true });
  }
});
