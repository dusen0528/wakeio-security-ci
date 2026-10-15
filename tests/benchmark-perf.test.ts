import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runSource } from '../src/index.js';
const script = fileURLToPath(new URL('../../scripts/benchmark-perf.mjs', import.meta.url));
const perf = await import(pathToFileURL(script).href);
const exec = promisify(execFile);

async function fixture(fn: (root: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'perf-test-'));
  try { await writeFile(join(root, 'app.ts'), 'export function test(req, db) { db.query(req.query.sql); }\n'); await fn(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}
async function result(root: string, caseId = 'one') { return { caseId, root, checks: await runSource({ root, tools: [] }) }; }

test('nearest rank percentiles cover one, five, equal and unsorted samples', () => {
  assert.deepEqual(perf.statistics([7]), { n: 1, min: 7, p50: 7, p95: 7, max: 7 });
  assert.deepEqual(perf.statistics([5, 2, 4, 1, 3]), { n: 5, min: 1, p50: 3, p95: 5, max: 5 });
  assert.deepEqual(perf.statistics([2, 2, 2, 2, 2]), { n: 5, min: 2, p50: 2, p95: 2, max: 2 });
});

test('runs default to five and reject out of range and noninteger CLI values with exit 2', async () => {
  assert.equal(perf.parseArgs([]).runs, 5);
  assert.equal(perf.parseArgs(['--runs', '50']).runs, 50);
  for (const value of ['0', '51', '1.5', '-1', 'NaN', '1e1']) {
    assert.throws(() => perf.parseArgs(['--runs', value]));
    await assert.rejects(exec(process.execPath, [script, '--runs', value]), (error: any) => error.code === 2);
  }
});

test('same filename remains distinct across case IDs; duplicate signatures deduplicate', async () => fixture(async root => {
  const one = await result(root), two = { ...one, caseId: 'two' };
  const single = perf.normalizeRun([one]);
  assert.ok(single.findings.length > 0);
  const both = perf.normalizeRun([one, two]);
  assert.equal(both.findings.length, single.findings.length * 2);
  assert.deepEqual(perf.normalizeRun([one, one]).findings, single.findings);
  assert.notEqual(both.findingDigest, single.findingDigest);
}));

test('finding, check status, collection file identity and applied budget drift are nondeterministic exit 2', async () => fixture(async root => {
  const base = await result(root);
  const reference = { ...perf.normalizeRun([base]), errors: perf.validateRun([base], 'S') };
  assert.deepEqual(reference.errors, []);
  for (const mutate of [
    (r: any) => { r.checks.find((c: any) => c.findings.length).findings[0].location.line++; },
    (r: any) => { r.checks[1].status = 'partial'; },
    (r: any) => { r.checks[0].sourceSnapshot.digest = '0'.repeat(64); },
    (r: any) => { r.checks[0].collectionBudget.limits.maxFiles++; },
  ]) {
    const changed = structuredClone(base); mutate(changed);
    const outcome = perf.assessRuns([reference, { ...perf.normalizeRun([changed]), errors: perf.validateRun([changed], 'S') }]);
    assert.equal(outcome.status, 'nondeterministic'); assert.equal(outcome.exitCode, 2);
  }
}));

test('identical empty/error/skipped executions cannot become successful determinism', async () => fixture(async root => {
  for (const checks of [[], [{ id: 'source.inventory', status: 'error', findings: [] }]]) {
    const runs = [{ caseId: 'bad', root, checks }];
    const r = { ...perf.normalizeRun(runs), errors: perf.validateRun(runs, 'S') };
    assert.equal(perf.assessRuns([r, r]).status, 'failed'); assert.equal(perf.assessRuns([r, r]).exitCode, 2);
  }
  const skipped = await result(root); skipped.checks[1].status = 'skipped';
  assert.ok(perf.validateRun([skipped], 'M').length);
}));

test('seeded L tree is reproducible and only intended file-limit incompleteness is allowed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'perf-large-test-'));
  try {
    const { DEFAULT_MAX_FILES } = await import('../src/source/collector.js');
    const a = join(root, 'a'), b = join(root, 'b');
    await perf.generateLarge(a, DEFAULT_MAX_FILES); await perf.generateLarge(b, DEFAULT_MAX_FILES);
    assert.deepEqual(await perf.treeManifest(a), await perf.treeManifest(b));
    const r = await result(a);
    assert.deepEqual(perf.validateRun([r], 'L'), []);
    const broken = structuredClone(r);
    broken.checks[0].collectionEvidence!.issues.push({ code: 'read_error', count: 1 });
    assert.ok(perf.validateRun([broken], 'L').length);
    broken.checks[1].status = 'error';
    assert.ok(perf.validateRun([broken], 'L').length);
    await writeFile(join(b, 'file-000000.ts'), 'changed\n');
    assert.notEqual((await perf.treeManifest(a)).digest, (await perf.treeManifest(b)).digest);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('real children return complete IPC payload, cold lifetime RSS and one excluded warmup', async () => fixture(async root => {
  const cases = [{ caseId: 'one', root }];
  const cold = await perf.runChild({ mode: 'process-cold', tier: 'S', cases });
  assert.ok(cold.wallMs > 0); assert.ok(cold.maxRSS > 0);
  assert.deepEqual(perf.validateRun(cold.results, 'S'), []);
  const warm = await perf.runChild({ mode: 'warm', tier: 'S', cases, runs: 2 });
  assert.equal(warm.runs.length, 3); assert.equal(warm.runs[0].warmup, true);
  assert.ok(warm.runs.slice(1).every((r: any) => !r.warmup && r.elapsedMs > 0));
  assert.equal(perf.assessRuns([perf.normalizeRun(cold.results), ...warm.runs]).status, 'deterministic');
}));

test('profile reports sampled leaf self-time and marks sparse samples', () => {
  const p = perf.summarizeProfile({ nodes: [{ id: 1, callFrame: { functionName: 'a', url: 'node:fs', lineNumber: 0 } },
    { id: 2, callFrame: { functionName: 'b', url: 'node:fs', lineNumber: 1 } }], samples: [1, 2, 1], timeDeltas: [10, 20, 30] });
  assert.equal(p.insufficientSamples, true); assert.equal(p.top[0].selfTimeUs, 40);
  assert.ok(Math.abs(p.top[0].percent - 100 * 40 / 60) < 1e-10);
});

test('missing M checkout fails with reproducible preparation instructions, never succeeds by skipping', async () => {
  await assert.rejects(exec(process.execPath, [script, '--runs', '1']), (error: any) =>
    error.code === 2 && error.stderr.includes('git clone --no-checkout') && error.stderr.includes('checkout --detach'));
});
