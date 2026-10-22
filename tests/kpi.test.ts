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
    environment: { os: 'linux', release: 'test', arch: 'arm64', node: 'v22.23.1', npm: '10', dependencyLock: hash },
    phase: 'source_offline_warm', parameters: { tools: 'none', runs: 3, analysisProfile: 'default', projectId: 'wakeio-kpi-nodegoat' },
    medium: { coverageComplete: true, runs }, measurementStatus: 'completed', metrics: [
      { id: 'first_report_ms', status: 'measured', value: 20, runs: [30, 10, 20] },
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
    (x: any) => { x.metrics[1].value = 0; },
    (x: any) => { x.metrics[0].value = -1; },
    (x: any) => { x.metrics[0].value = 19; },
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
    run.checks = run.checks.map((check: any) => check.id === 'source.builtin-ast' ? { ...check, status: 'partial', reasons: ['module_export_unsupported'] } : check);
  }
  const result = kpi.compareKpi(before, after);
  assert.equal(result.exitCode, 1); assert.equal(result.newIncompleteChecks, 1);
});
