import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
const kpi = await import(pathToFileURL(resolve('scripts/kpi.mjs')).href);
const exec = promisify(execFile), hash = 'a'.repeat(64);

function sample(): any {
  const checks = ['source.inventory', 'source.builtin-ast', 'source.framework', 'source.code-coverage'].map(id => ({ id, status: 'completed' }));
  const runs = [30, 10, 20].map(reportMs => ({ reportMs, processMs: reportMs + 1, scanExitCode: 0, semanticSha256: hash, checks, complete: true }));
  return { schema: 'wakeio.kpi/v1', revision: 'a'.repeat(40), engineSha256: hash, fixtureDigest: hash, corpusDigest: hash, harnessDigest: hash,
    environment: { os: 'linux', release: 'test', arch: 'arm64', node: 'v22.23.1', npm: '10', imageDigest: 'sha256:' + hash },
    engine: { dependencyLock: hash },
    phase: 'source_offline_warm', parameters: { tools: 'none', runs: 3, analysisProfile: 'default', projectId: 'wakeio-kpi-nodegoat' },
    medium: { coverageComplete: true, runs }, measurementStatus: 'completed', metrics: [
      { id: 'first_report_ms', status: 'measured', value: 20, runs: [30, 10, 20] },
      { id: 'analysis_ms', status: 'measured', value: 10, runs: [10, 10, 10] },
      ...['planned_state_completeness', 'wire_budget_overflow', 'loop_stop_reason_rate', 'inventory_recall']
        .map(id => ({ id, status: 'unavailable', value: null, reason: 'not_measured' })),
      { id: 'determinism', status: 'measured', value: 1, numerator: 3, denominator: 3 },
      { id: 'source_regression', status: 'measured', value: { tp: 27, fp: 0, fn: 1, completedCases: 56, totalCases: 56 },
        identities: { fp: [], fn: [hash] } },
    ] };
}

test('KPI CLI requires a checkout and fresh output; rejects unknown, duplicate and mixed mode flags', async () => {
  assert.equal(kpi.parseArgs(['--help']).help, true);
  assert.equal(kpi.parseArgs(['--checkout', '/fixture', '--out', '/out']).mode, 'measure');
  for (const args of [[], ['--out', '/out'], ['--checkout', '/fixture'], ['--checkout', '/f', '--out', '/o', '--url', 'https://owned.invalid'],
    ['--checkout', '/f', '--out', '/o', '--out', '/x'], ['compare', '--before', '/b', '--after', '/a', '--checkout', '/f', '--out', '/o']]) {
    assert.throws(() => kpi.parseArgs(args));
  }
  const out = await mkdtemp(join(tmpdir(), 'wakeio-kpi-invalid-'));
  try {
    await assert.rejects(exec(process.execPath, ['scripts/kpi.mjs', '--out', join(out, 'missing')]), (error: any) => {
      assert.equal(error.code, 2); assert.doesNotMatch(error.stderr, /credential|CANARY/); return true;
    });
    await assert.rejects(readFile(join(out, 'missing', 'kpi.json')));
  } finally { await rm(out, { recursive: true, force: true }); }
});

test('determinism removes only top-level timestamps, preserving evidence and array order', () => {
  const input = { startedAt: 'one', finishedAt: 'two', checks: [{ metrics: { startedAt: 'evidence' }, gaps: ['one', 'two'] }] };
  assert.equal(kpi.semanticHash(input), kpi.semanticHash({ ...input, startedAt: 'changed', finishedAt: 'changed' }));
  assert.notEqual(kpi.semanticHash(input), kpi.semanticHash({ ...input, checks: [{ metrics: { startedAt: 'changed' }, gaps: ['one', 'two'] }] }));
  assert.notEqual(kpi.semanticHash(input), kpi.semanticHash({ ...input, checks: [{ metrics: { startedAt: 'evidence' }, gaps: ['two', 'one'] }] }));
});

test('accuracy identity preserves case and detects a new miss even when aggregate FN is unchanged', () => {
  const expected = { ruleId: 'rule', path: 'app.ts', line: 1, support: 'supported' };
  const identities = kpi.accuracyIdentities({ cases: [
    { id: 'case-a', expectedFindings: [expected], observedFindings: [] },
    { id: 'case-b', expectedFindings: [expected], observedFindings: [{ ruleId: 'extra', path: 'app.ts', line: 2 }] },
  ] });
  assert.equal(new Set(identities.fn).size, 2); assert.equal(identities.fp.length, 1);
  const before = sample(), after = sample();
  after.metrics.find((m: any) => m.id === 'source_regression').identities.fn = ['b'.repeat(64)];
  const result = kpi.compareKpi(before, after);
  assert.equal(result.exitCode, 1); assert.equal(result.newFalseNegatives, 1);
});

test('comparison preserves unavailable/null, reports latency without imposing a target, and refuses unlike contexts', () => {
  const before = sample(), after = sample();
  assert.equal(kpi.compareKpi(before, after).exitCode, 0);
  assert.equal(kpi.compareKpi(before, after).performanceTarget, null);
  assert.equal(kpi.compareKpi(before, after).unavailable.length, 4);
  for (const key of ['fixtureDigest', 'corpusDigest', 'harnessDigest', 'environment']) {
    const changed = sample();
    if (key === 'environment') changed.environment.arch = 'x64';
    else changed[key] = 'b'.repeat(64);
    assert.equal(kpi.compareKpi(before, changed).exitCode, 2);
    assert.equal(kpi.compareKpi(before, changed).comparable, false);
  }
  const failed = sample(); failed.measurementStatus = 'failed';
  assert.equal(kpi.compareKpi(before, failed).exitCode, 2);
});

test('forged successful numbers, missing metric identities and hidden incomplete coverage reject', () => {
  const changes = [
    (x: any) => { x.metrics[2].value = 0; },
    (x: any) => { x.metrics[0].value = -1; },
    (x: any) => { x.metrics[0].value = 19; },
    (x: any) => { x.metrics[1].runs = [1, 2, 3]; },
    (x: any) => { x.engine.dependencyLock = 'invalid'; },
    (x: any) => { x.environment.imageDigest = 'invalid'; },
    (x: any) => { x.metrics.at(-1).identities.fn = []; },
    (x: any) => { x.metrics.push(x.metrics[0]); },
    (x: any) => { x.environment = {}; },
    (x: any) => { x.medium.runs[0].checks[0].status = 'partial'; },
    (x: any) => { x.medium.runs[0].semanticSha256 = 'b'.repeat(64); },
  ];
  for (const change of changes) { const invalid = structuredClone(sample()); change(invalid); assert.throws(() => kpi.compareKpi(sample(), invalid)); }
});

test('medium coverage degradation fails even when synthetic TP/FP/FN counts do not change', () => {
  const before = sample(), after = sample();
  after.medium.coverageComplete = false;
  for (const run of after.medium.runs) {
    run.complete = false; run.scanExitCode = 2;
    run.checks = run.checks.map((check: any) => check.id === 'source.builtin-ast' ? { ...check, status: 'partial', reasons: ['module_export_unsupported'], reasonCounts: [{ reason: 'module_export_unsupported', count: 1 }] } : check);
  }
  const result = kpi.compareKpi(before, after);
  assert.equal(result.exitCode, 1); assert.equal(result.newIncompleteChecks, 1);
});

test('dependency-only changes remain comparable while runtime image changes do not', () => {
  const before = sample(), after = sample();
  after.engine.dependencyLock = 'b'.repeat(64);
  assert.equal(kpi.compareKpi(before, after).exitCode, 0);
  after.environment.release = 'different kernel';
  assert.equal(kpi.compareKpi(before, after).exitCode, 0);
  after.environment.imageDigest = 'sha256:' + 'b'.repeat(64);
  assert.equal(kpi.compareKpi(before, after).exitCode, 2);
});

test('analysis median exceeding 1.5x warns without failing the comparison', () => {
  const before = sample(), after = sample();
  const timing = after.metrics.find((m: any) => m.id === 'analysis_ms');
  assert.ok(timing);
  timing.runs = [16, 16, 16]; timing.value = 16;
  const result = kpi.compareKpi(before, after);
  assert.equal(result.exitCode, 0); assert.equal(result.analysisTiming.warning, true);
  timing.runs = [15, 15, 15]; timing.value = 15;
  assert.equal(kpi.compareKpi(before, after).analysisTiming.warning, false);
});

test('same incomplete reason with increased events is a regression and exposes both counts', () => {
  const before = sample(), after = sample();
  for (const [report, count] of [[before, 1], [after, 2]] as const) {
    report.medium.coverageComplete = false;
    for (const run of report.medium.runs) {
      run.complete = false; run.scanExitCode = 2;
      run.checks = run.checks.map((check: any) => check.id === 'source.builtin-ast' ? { ...check, status: 'partial',
        reasons: ['module_export_unsupported'], reasonCounts: [{ reason: 'module_export_unsupported', count }] } : check);
    }
  }
  const result = kpi.compareKpi(before, after);
  assert.equal(result.exitCode, 1);
  assert.deepEqual(result.incompleteReasonCounts, [{ checkId: 'source.builtin-ast', reason: 'module_export_unsupported', before: 1, after: 2 }]);
  assert.equal(result.increasedIncompleteReasons, 1);
  assert.equal(kpi.compareKpi(after, before).exitCode, 0);
  for (const run of after.medium.runs) run.checks.find((c: any) => c.id === 'source.builtin-ast').reasonCounts[0].count = null;
  assert.equal(kpi.compareKpi(before, after).exitCode, 2);
  after.medium.runs[0].checks.find((c: any) => c.id === 'source.builtin-ast').reasonCounts[0].count = -1;
  assert.throws(() => kpi.compareKpi(before, after));
});

test('inventory recall measures exact reviewed GET sets and preserves zero/unknown denominator status', async () => {
  const { enumerateOpenApiGetOperations } = await import('../src/openapi.js');
  const metric = await kpi.measureInventory(enumerateOpenApiGetOperations);
  assert.equal(metric.status, 'measured'); assert.equal(metric.value, 1);
  assert.equal(metric.numerator, 10); assert.equal(metric.denominator, 10);
  assert.equal(metric.unexpectedGetOperations, 0); assert.equal(metric.missingGetOperations, 0); assert.equal(metric.exactSetMatch, true);
  assert.equal(metric.cases.length, 8);
  assert.equal(metric.cases.filter((c: any) => c.status === 'not_applicable' && c.value === null).length, 2);
  assert.equal(metric.cases.filter((c: any) => c.status === 'unavailable' && c.value === null).length, 1);
  assert.equal((await kpi.measureInventory(undefined)).status, 'unavailable');
  const after = sample(); after.metrics = after.metrics.map((m: any) => m.id === 'inventory_recall' ? metric : m);
  assert.equal(kpi.compareKpi(sample(), after).exitCode, 0);
  const forged = structuredClone(after); forged.metrics.find((m: any) => m.id === 'inventory_recall').denominator = 11;
  assert.throws(() => kpi.compareKpi(sample(), forged));
});

test('inventory gate rejects unexpected, equal-sized wrong, duplicate and nondeterministic GET sets', async () => {
  const { enumerateOpenApiGetOperations } = await import('../src/openapi.js');
  let calls = 0;
  for (const mode of ['added', 'wrong', 'duplicate', 'nondeterministic']) {
    const metric = await kpi.measureInventory((document: unknown) => {
      const result = enumerateOpenApiGetOperations(document);
      if (!result.operations.length) return result;
      if (mode === 'wrong' || mode === 'nondeterministic' && ++calls % 3 === 0) result.operations[0]!.path = '/unexpected';
      else if (mode === 'added') result.operations.push({ method: 'GET', path: '/unexpected' });
      else if (mode === 'duplicate') result.operations.push({ ...result.operations[0]! });
      return result;
    });
    assert.equal(metric.exactSetMatch, false, mode);
    if (mode === 'added') { assert.equal(metric.value, 1); assert.ok(metric.unexpectedGetOperations > 0); }
    const after = sample(); after.metrics = after.metrics.map((m: any) => m.id === 'inventory_recall' ? metric : m);
    assert.equal(kpi.compareKpi(sample(), after).exitCode, 1, mode);
  }
});
