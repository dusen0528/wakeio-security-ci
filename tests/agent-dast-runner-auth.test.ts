import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runExecutionPlan } from '../src/agent-dast/runner.js';

// One public-controller auth integration group, reusing the independent owned
// target. Author writes only; root supplies the real runtime and executes.
const fixtureUrl = new URL('../../tests/fixtures/schemathesis-auth-target.mjs', import.meta.url).href;
const python = process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(process.cwd(), '.venv-schemathesis/bin/python');
const present = await stat(python).then(value => value.isFile()).catch(() => false);
const required = process.env.WAKEIO_REQUIRE_RUNNER_ENGINES === '1';
const skip = present || required ? false : 'provide reviewed Schemathesis Python; required runner suite refuses absence';
const hash = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
async function artifacts(root: string): Promise<string[]> {
  const paths: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) paths.push(...await artifacts(path)); else if (entry.isFile()) paths.push(path);
  }
  return paths;
}

test('runner auth independent: real authenticated Schemathesis public plan retains identity normal generated controls and global1/0/2 gates without secrets', { skip, timeout: 90_000 }, async () => {
  assert.ok(present, 'Required runner suite needs the reviewed Schemathesis runtime');
  const fixture = await import(fixtureUrl);
  for (const [mode, cap, expected] of [['vulnerable', 12, 1], ['fixed', 12, 0], ['fixed', 5, 2]] as const) {
    const root = await mkdtemp(join(tmpdir(), `wakeio-runner-auth-${mode}-${cap}-`));
    const target = await fixture.startSchemathesisAuthTarget(mode);
    try {
      const policy = target.policy();
      const bindings = [];
      for (const [id, value] of [['contract', target.schema], ['auth_policy', policy]] as const) {
        const bytes = JSON.stringify(value); await writeFile(join(root, `${id}.json`), bytes);
        bindings.push({ id, path: `${id}.json`, sha256: hash(bytes) });
      }
      const out = join(root, 'reports');
      const result = await runExecutionPlan({ plan: { version: 1, kind: 'wakeio.execution-plan', origin: target.origin,
        tasks: [{ id: 't-owned-auth', engine: 'schemathesis', schema: 'contract', authPolicy: 'auth_policy',
          operations: ['/items/{id}'], seed: 7, maxRequests: 12 }] }, inputs: { version: 1, inputs: bindings },
        inputBaseDir: root, outDir: out, consent: true, allowedOrigin: target.origin, allowPrivate: true,
        maxRequests: cap, timeoutMs: 20_000, ratePerSecond: 50, concurrency: 1, failOn: expected === 2 ? 'none' : 'medium',
        schemathesisPython: python, env: { [policy.authorizationEnv]: target.authorization } });
      assert.equal(result.exitCode, expected); assert.equal(result.delivery, 'published');
      assert.equal(result.status, expected === 2 ? 'partial' : 'completed');
      assert.equal(result.tasks.length, 1); assert.equal(result.tasks[0].exitCode, expected);
      assert.equal(result.requests.requestCount, target.requests.length);
      assert.equal(result.tasks[0].requests.requestCount, target.requests.length);
      assert.equal(result.requests.pending, 0); assert.ok(target.requests.length <= cap);
      const task = join(out, 'tasks/t-owned-auth');
      const reportBytes = await readFile(join(task, 'report.json'));
      const report = JSON.parse(reportBytes.toString('utf8'));
      const agent = JSON.parse(await readFile(join(task, 'agent-report.json'), 'utf8'));
      assert.equal(agent.reportArtifact.digest, hash(reportBytes)); assert.equal(agent.scanGate.exitCode, expected);
      const check = report.checks.find((check: any) => check.id === 'api.schemathesis');
      assert.ok(check?.schemathesisAuth, 'Authenticated engine evidence must survive the new controller projection');
      const evidence = check.schemathesisAuth;
      assert.equal(evidence.requests.attempted, target.requests.length);
      assert.equal(evidence.requests.completedGenerated, evidence.records.length);
      assert.deepEqual(evidence.controls.map((control: any) => control.phase),
        ['identity-before', 'anonymous-normal', 'normal-before', 'normal-after', 'identity-after']);
      const controlAttempts = evidence.controls.filter((control: any) => Number.isSafeInteger(control.attempt) && control.attempt > 0).length;
      assert.equal(evidence.requests.attempted, controlAttempts + evidence.requests.generated,
        'Identity/anonymous/normal controls and generated probes share the same admitted request count');
      assert.equal(result.tasks[0].requests.attempts.filter(attempt => attempt.kind === 'control').length, controlAttempts);
      assert.equal(result.tasks[0].requests.attempts.filter(attempt => attempt.kind === 'probe').length, evidence.requests.generated);
      assert.deepEqual(target.requests.slice(0, 3).map((request: any) => [request.path, request.credentialMatched]),
        [['/whoami', true], ['/items/1', false], ['/items/1', true]]);
      assert.ok(target.requests.every((request: any) => request.method === 'GET' && request.contentBytes === 0));
      assert.ok(target.requests.every((request: any) => request.path === '/whoami' || /^\/items\/[12]$/.test(request.path)));
      assert.equal(target.stats.stateUnchanged, true);
      if (expected !== 2) {
        assert.equal(evidence.status, 'completed'); assert.equal(controlAttempts, 5);
        assert.ok(evidence.controls.every((control: any) => control.outcome === 'matched'));
        assert.ok(evidence.records.length >= 1); assert.ok(target.stats.generatedIdTwoRequests > 0);
        assert.equal(target.requests.at(-1).path, '/whoami'); assert.equal(target.requests.at(-2).path, '/items/1');
        assert.equal(result.requests.responseCompleted, target.requests.length);
        for (const record of evidence.records) {
          const actual = target.requests[record.attempt - 1];
          assert.equal(actual.protectedHandler, true); assert.equal(actual.credentialMatched, true);
          assert.equal(actual.principal, target.principal); assert.equal(actual.status, record.status);
        }
      } else {
        assert.equal(target.requests.length, 5); assert.notEqual(evidence.status, 'completed');
        assert.ok(result.requests.refused >= 1, 'The global cap, not a per-engine cap, refused trailing work');
        assert.ok(evidence.controls.some((control: any) => control.outcome !== 'matched'));
      }
      const findings = report.checks.flatMap((check: any) => check.findings);
      if (expected === 1) assert.ok(findings.some((finding: any) => finding.ruleId === 'api.schemathesis.server_error' && finding.severity === 'medium'));
      else assert.deepEqual(findings, []);
      const secrets = [policy.authorizationEnv, target.authorization, target.authorization.slice(7), hash(target.authorization),
        hash(target.authorization.slice(7)), target.principal, target.marker, 'owned-private-identity-body', 'owned-private-failure-body'];
      for (const path of await artifacts(out)) {
        const bytes = (await readFile(path)).toString('utf8');
        for (const secret of secrets) assert.equal(bytes.includes(secret), false, 'Private owned auth value escaped an artifact');
      }
      for (const secret of secrets) assert.equal(JSON.stringify(result).includes(secret), false);
      const receipt = JSON.parse(await readFile(join(out, 'run-receipt.json'), 'utf8')); assert.equal(receipt.exitCode, expected);
    } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
    assert.equal(target.socketCount, 0);
  }
});
