import test from 'node:test';
import assert from 'node:assert/strict';

const fixtureModule = '../benchmarks/agent-eval/targets/local-sqlite/fixture.mjs';
test('owned evaluation fixture requires consent and separates positive, negative and tuning sites', async () => {
  const { startFixture } = await import(new URL('../../' + fixtureModule.slice(3), import.meta.url).href);
  await assert.rejects(startFixture(), /active_consent_required/);
  const fixture = await startFixture({ activeConsent: true });
  try {
    for (const path of ['/items','/catalog']) {
      const result = await fetch(fixture.origin + path + '?id=' + encodeURIComponent('1 AND 1=1'));
      assert.deepEqual(await result.json(), { count: 1 });
    }
    for (const path of ['/lookup','/inventory']) {
      const result = await fetch(fixture.origin + path + '?id=' + encodeURIComponent('1 AND 1=1'));
      assert.deepEqual(await result.json(), { count: 0 });
    }
    assert.equal((await fetch(fixture.origin + '/items?id=1', { method: 'POST' })).status, 404);
    fixture.reset(); assert.equal(fixture.requests.length, 0);
    assert.deepEqual(await (await fetch(fixture.origin + '/items?id=1')).json(), { count: 1 });
  } finally { await fixture.close(); }
});

test('owned runner projection preserves admitted requests, source observations and predefined coverage', async () => {
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const base = new URL('../../benchmarks/agent-eval/targets/local-sqlite/', import.meta.url);
  const { startFixture } = await import(new URL('fixture.mjs', base).href);
  const { prepare, runArm } = await import(new URL('run.mjs', base).href);
  const { projectArm } = await import(new URL('score.mjs', base).href);
  const fixture = await startFixture({ activeConsent: true });
  const out = await mkdtemp(join(tmpdir(), 'owned-eval-test-'));
  try {
    const plan = await prepare(fixture, join(out, 'inputs'), ['/catalog','/inventory']);
    const run = await runArm('A', fixture, plan, join(out, 'A'));
    assert.equal(run.exitCode, 1); assert.equal(run.actualRequests, 16);
    const arm = await projectArm(run);
    assert.deepEqual(arm.coverage, { plannedCells: 2, executedCells: 2 });
    assert.equal(arm.findings.length, 1); assert.equal(arm.findings[0].path, '/catalog');
    assert.equal(arm.findings[0].state, 'candidate'); assert.equal(arm.rounds[0].requestCount, 16);
    await assert.rejects(projectArm({ ...run, actualRequests: 0 }));
    await assert.rejects(projectArm({ ...run, rounds: [...run.rounds, ...run.rounds] }), /multi_round_cli_support_required/);
  } finally { await fixture.close(); await rm(out, { recursive: true, force: true }); }
});


test('owned evaluation preserves provider setup failures as incomplete arms', async () => {
  const { mkdtemp, readFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { recordArm } = await import(new URL('../../benchmarks/agent-eval/targets/local-sqlite/run.mjs', import.meta.url).href);
  const out = await mkdtemp(join(tmpdir(), 'owned-failure-'));
  const previous = process.env.WAKEIO_AGENT_LIVE;
  delete process.env.WAKEIO_AGENT_LIVE;
  try {
    const fixture = { origin: 'http://127.0.0.1:1', requests: [], reset() {} };
    const result = await recordArm('B', fixture, { plan: {}, inputs: {} }, join(out, 'B'));
    assert.equal(result.exitCode, 2); assert.equal(result.status, 'error');
    assert.equal(result.actualRequests, 0); assert.equal(result.requestCount, null);
    assert.ok(result.durationMs >= 0);
    assert.deepEqual(JSON.parse(await readFile(join(out, 'B.json'), 'utf8')), result);
  } finally {
    if (previous === undefined) delete process.env.WAKEIO_AGENT_LIVE; else process.env.WAKEIO_AGENT_LIVE = previous;
    await rm(out, { recursive: true, force: true });
  }
});


test('incomplete loop retains admissions even when no child report was delivered', async () => {
  const { execFileSync } = await import('node:child_process');
  execFileSync(process.execPath, ['--experimental-test-module-mocks', '--input-type=module', '-e', `
    import { mock } from 'node:test';
    import assert from 'node:assert/strict';
    mock.module('./build/src/agent-dast/providers/codex.js', { namedExports: { createAgent: async () => ({}) } });
    mock.module('./build/src/agent-dast/loop/loop.js', { namedExports: { runAgentLoop: async () => ({
      status: 'partial', reason: 'ledger_mismatch', requestCount: 2,
      rounds: [{ round: 1, requestCount: 2, outDir: '/missing-owned-report', ledgerVerified: false }]
    }) } });
    const { runArm } = await import('./benchmarks/agent-eval/targets/local-sqlite/run.mjs');
    const result = await runArm('B', { origin: 'http://127.0.0.1:1', requests: [1,2], reset() {} },
      { plan: { tasks: [] }, coverageCells: [], inputs: {} }, '/unused');
    assert.equal(result.exitCode, 2); assert.equal(result.requestCount, 2);
    assert.equal(result.rounds[0].ledgerVerified, false); assert.equal(result.reason, 'ledger_mismatch');
  `], { stdio: 'pipe' });
});
