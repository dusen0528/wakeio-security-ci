import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const api = await import(pathToFileURL(resolve('scripts/kpi-policy.mjs')).href);
const policy = JSON.parse(await readFile('benchmarks/kpi-policy.json', 'utf8'));
const legacy = JSON.parse(await readFile('benchmarks/kpi-baseline.json', 'utf8'));
const hash = 'a'.repeat(64);

function sample() {
  const provenance = { revision: 'a'.repeat(40), fixtureDigest: hash, environmentDigest: hash };
  const row = (id: string, unit: string, value: number | Record<string, number>) => ({
    id, unit, status: 'measured', value, numerator: 1, denominator: 1, provenance,
  });
  return {
    schema: 'wakeio.kpi/v2', ...provenance, measurementStatus: 'completed',
    gates: policy.gates.map((g: { id: string; unit: string; target: { value: number } }) => row(g.id, g.unit, g.target.value)),
    metrics: [
      { ...row('first_report_ms', 'ms', 100), runs: [90, 100, 110] },
      { ...row('analysis_ms', 'ms', 10), runs: [10, 10, 10] },
      row('planned_state_completeness', 'ratio', 1),
      { ...row('determinism', 'ratio', 1), numerator: 3, denominator: 3 },
      row('wire_budget_overflow', 'count', 0),
      { ...row('loop_stop_reason_rate', 'ratio', 1), numerator: 4, denominator: 4 },
      row('inventory_recall', 'ratio', 1),
      row('source_regression', 'count', { fp: 0, fn: 0, analysisGapEvents: 0 }),
    ],
  };
}

test('v1 reader validates existing reports without inventing release qualification', async () => {
  const p = await api.loadPolicy();
  assert.equal(api.readKpi(legacy).schema, 'wakeio.kpi/v1');
  assert.equal(api.qualify(p, { report: legacy, baseline: legacy, release: '0.6' }).exitCode, 2);
  assert.throws(() => api.readKpi({ ...legacy, schema: 'wakeio.kpi/v99' }));
});

test('policy rejects omitted gates, duplicated identities and changed release obligations', async () => {
  for (const mutate of [
    (p: typeof policy) => { p.gates = p.gates.filter((g: { id: string }) => g.id !== 'G5'); },
    (p: typeof policy) => { p.metrics.push(p.metrics[0]); },
    (p: typeof policy) => { p.metrics[0].target.maximum = 60001; },
    (p: typeof policy) => { p.metrics[0].minRelease = '0.7'; },
  ]) {
    const changed = structuredClone(policy); mutate(changed);
    assert.throws(() => api.validatePolicy(changed));
  }
});

test('latency requires both absolute bound and same-environment baseline median', async () => {
  const p = await api.loadPolicy();
  for (const [candidate, base, expected] of [[60000, 60000, 0], [60001, 70000, 1], [101, 100, 1], [99, 100, 0]]) {
    const report = sample(), baseline = sample();
    report.metrics[0] = { ...report.metrics[0], value: candidate, runs: [candidate, candidate, candidate] };
    baseline.metrics[0] = { ...baseline.metrics[0], value: base, runs: [base, base, base] };
    assert.equal(api.qualify(p, { report, baseline, release: '0.6' }).exitCode, expected);
  }
  const report = sample(), baseline = sample();
  baseline.environmentDigest = 'b'.repeat(64);
  baseline.gates.forEach((r: { provenance: { environmentDigest: string } }) => { r.provenance.environmentDigest = baseline.environmentDigest; });
  assert.equal(api.qualify(p, { report, baseline, release: '0.6' }).exitCode, 2);
});

test('analysis warning remains non-gating and future release metrics remain required only later', async () => {
  const p = await api.loadPolicy(), report = sample();
  report.metrics[1] = { ...report.metrics[1], value: 16, runs: [16, 16, 16] };
  const result = api.qualify(p, { report, baseline: sample(), release: '0.6' });
  assert.equal(result.exitCode, 0);
  assert.equal(result.analysisTiming.warning, true);
  assert.equal(result.analysisTiming.gating, false);
  assert.equal(api.qualify(p, { report, baseline: sample(), release: '0.7' }).exitCode, 2);
});

test('source regression compares baseline counts instead of requiring existing misses to be zero', async () => {
  const p = await api.loadPolicy(), baseline = sample();
  baseline.metrics[7].value = { fp: 2, fn: 3, analysisGapEvents: 4 };
  for (const [fn, exit] of [[2, 0], [3, 0], [4, 1]]) {
    const report = sample();
    report.metrics[7].value = { fp: 1, fn, analysisGapEvents: 4 };
    assert.equal(api.qualify(p, { report, baseline, release: '0.6' }).exitCode, exit);
  }
});

test('comparative baselines reject empty denominators and incompatible units', async t => {
  const p = await api.loadPolicy();
  for (const index of [0, 7]) {
    for (const field of ['denominator', 'unit']) {
      await t.test(`${sample().metrics[index].id} baseline ${field}`, () => {
        const baseline = sample();
        if (field === 'denominator') baseline.metrics[index].denominator = 0;
        else baseline.metrics[index].unit = 'incompatible';
        const result = api.qualify(p, { report: sample(), baseline, release: '0.6' });
        assert.equal(result.exitCode, 2);
        assert.equal(result.results.find((row: { id: string }) => row.id === baseline.metrics[index].id).status, 'unavailable');
      });
    }
  }
});

test('invalid analysis operands suppress only the non-gating warning', async () => {
  const p = await api.loadPolicy();
  for (const operand of ['report', 'baseline']) {
    for (const field of ['denominator', 'unit']) {
      const report = sample(), baseline = sample();
      report.metrics[1] = { ...report.metrics[1], value: 16, runs: [16, 16, 16] };
      const invalid = operand === 'report' ? report : baseline;
      if (field === 'denominator') invalid.metrics[1].denominator = 0;
      else invalid.metrics[1].unit = 'seconds';
      const result = api.qualify(p, { report, baseline, release: '0.6' });
      assert.equal(result.exitCode, 0);
      assert.equal(result.analysisTiming.warning, null);
      assert.equal(result.analysisTiming.gating, false);
    }
  }
});

test('recorded finding counts require integers but zero findings may qualify for stable promotion', async t => {
  const p = await api.loadPolicy();
  const cases: readonly (readonly [unknown, unknown, number])[] = [
    ['unknown', 0, 2], [-1, 0, 2], [0.5, 0, 2], [null, 0, 2],
    [0, 'unknown', 2], [0, 0.5, 2], [0, 0, 0], [1, 0, 0],
  ];
  for (const [value, recordedBaseline, exitCode] of cases) {
    await t.test(`findings=${String(value)} baseline=${String(recordedBaseline)}`, () => {
      const base = sample();
      const metrics = [
        { id: 'first_plan_validity', unit: 'ratio', value: 0.9, numerator: 9, denominator: 10 },
        { id: 'coverage_gain', unit: 'ratio', value: 1, independent: true,
          pairs: Array.from({ length: 10 }, () => ({ delta: 1, retainedBaseline: true })) },
        { id: 'new_confirmed_findings', unit: 'count', value, recorded: true, baseline: recordedBaseline },
        { id: 'injection_boundary_escapes', unit: 'count', value: 0, denominator: 5 },
        { id: 'planner_input_bytes', unit: 'bytes', value: 8192 },
        { id: 'agent_token_cost', unit: 'tokens', value: { input: 1, output: 1 } },
        { id: 'proposal_overflow', unit: 'count', value: 0 },
        { id: 'promotion_rule', unit: 'boolean', value: { experimental: false } },
      ].map(row => ({ status: 'measured', numerator: 1, denominator: 1, provenance: base.metrics[0].provenance, ...row }));
      const report = { ...base, metrics: [...base.metrics, ...metrics] };
      const result = api.qualify(p, { report, baseline: sample(), release: '0.7' });
      assert.equal(result.exitCode, exitCode);
      assert.equal(result.results.find((row: { id: string }) => row.id === 'new_confirmed_findings').status,
        exitCode === 0 ? 'pass' : 'unavailable');
      assert.equal(result.results.find((row: { id: string }) => row.id === 'promotion_rule').status,
        exitCode === 0 ? 'pass' : 'fail');
    });
  }
});

test('missing or misleading evidence cannot be promoted by a claimed pass status', async t => {
  const p = await api.loadPolicy();
  const mutations: readonly (readonly [string, (r: ReturnType<typeof sample>) => void])[] = [
    ['unavailable-null', r => { r.gates[4].status = 'unavailable'; r.gates[4].value = null; }],
    ['forged-pass-status', r => { r.gates[4].status = 'pass'; }],
    ['zero-denominator', r => { r.gates[4].denominator = 0; }],
    ['missing-G5', r => { r.gates.splice(4, 1); }],
    ['duplicate-gate', r => { r.gates.push(r.gates[0]); }],
    ['stale-revision', r => { r.gates[4].provenance.revision = 'b'.repeat(40); }],
    ['forged-median', r => { r.metrics[0] = { ...r.metrics[0], runs: [1, 2, 3] }; }],
    ['forged-ratio', r => { r.metrics[3].numerator = 0; }],
    ['wrong-unit', r => { r.metrics[0].unit = 'seconds'; }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, () => {
      const report = sample(); mutate(report);
      const result = api.qualify(p, { report, baseline: sample(), release: '0.6' });
      assert.equal(result.exitCode, 2);
      assert.equal(result.status, 'unavailable');
    });
  }
  const report = sample(); report.gates[4].value = 1;
  assert.equal(api.qualify(p, { report, baseline: sample(), release: '0.6' }).exitCode, 1);
});

test('CLI reads production policy and refuses stale output directories', async () => {
  const out = await mkdtemp(join(tmpdir(), 'wakeio-policy-test-'));
  const execute = (args: readonly string[]) => new Promise<{ code: number | null; stdout: string }>((resolveResult, reject) => {
    const child = spawn(process.execPath, ['scripts/kpi-policy.mjs', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
    child.stderr.resume();
    child.once('error', reject);
    child.once('close', code => resolveResult({ code, stdout }));
  });
  try {
    const args = ['validate', '--policy', 'benchmarks/kpi-policy.json', '--input', 'benchmarks/kpi-baseline.json', '--out', join(out, 'fresh')];
    const good = await execute(args);
    assert.equal(good.code, 0);
    assert.equal(JSON.parse(good.stdout).readerSchema, 'wakeio.kpi/v1');
    assert.equal((await execute(args)).code, 2);
    const malformed = join(out, 'malformed.json');
    await writeFile(malformed, '{"schema":');
    assert.equal((await execute(['validate', '--policy', malformed, '--out', join(out, 'bad')])).code, 2);
    assert.equal((await execute(['validate', '--out', join(out, 'x'), '--out', join(out, 'y')])).code, 2);
  } finally { await rm(out, { recursive: true, force: true }); }
});
