#!/usr/bin/env node
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve, dirname, join } from 'node:path';
import { compareKpi } from './kpi.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const frozen = JSON.parse(await readFile(join(ROOT, 'schemas/kpi-policy.v1.json'), 'utf8')).const;
const hash = /^[a-f0-9]{64}$/;
const finite = n => typeof n === 'number' && Number.isFinite(n) && n >= 0;
const isCount = n => Number.isSafeInteger(n) && n >= 0;
const median = runs => [...runs].sort((a, b) => a - b)[1];

export class PolicyError extends Error {
  constructor(reason) { super(reason); this.name = 'PolicyError'; this.reason = reason; }
}

export function validatePolicy(policy) {
  for (const gate of frozen.gates) {
    if (!policy?.gates?.some(row => row.id === gate.id)) throw new PolicyError('missing_gate:' + gate.id);
  }
  // JSON Schema const intentionally freezes all approved obligations, including units and release timing.
  if (!isDeepStrictEqual(policy, frozen)) throw new PolicyError('policy_schema_mismatch');
  return policy;
}

export async function loadPolicy(path = join(ROOT, 'benchmarks/kpi-policy.json')) {
  return validatePolicy(JSON.parse(await readFile(path, 'utf8')));
}

export function readKpi(report) {
  switch (report?.schema) {
    case 'wakeio.kpi/v1':
      compareKpi(report, report); // Reuse the actual v1 parser without widening its accepted inputs.
      return report;
    case 'wakeio.kpi/v2': {
      if (!/^[a-f0-9]{40}$/.test(report.revision ?? '') || !hash.test(report.fixtureDigest ?? '')
        || !hash.test(report.environmentDigest ?? '') || !['completed', 'failed'].includes(report.measurementStatus)
        || !Array.isArray(report.metrics) || !Array.isArray(report.gates)) throw new PolicyError('invalid_v2');
      for (const rows of [report.metrics, report.gates]) {
        if (new Set(rows.map(row => row.id)).size !== rows.length) throw new PolicyError('duplicate_evidence');
        for (const row of rows) {
          if (typeof row.id !== 'string' || !['measured', 'unavailable', 'failed', 'not_applicable'].includes(row.status)
            || !row.provenance || ['revision', 'fixtureDigest', 'environmentDigest'].some(k => row.provenance[k] !== report[k])
            || row.status !== 'measured' && (row.value !== null || typeof row.reason !== 'string' || !row.reason)) {
            throw new PolicyError('invalid_evidence');
          }
        }
      }
      return report;
    }
    default: throw new PolicyError('unsupported_kpi_schema');
  }
}

function validMeasurement(row, definition) {
  if (!row || row.status !== 'measured' || row.value === null || row.unit !== definition.unit
    || !isCount(row.numerator) || !isCount(row.denominator) || row.denominator === 0) return false;
  switch (definition.unit) {
    case 'count':
      return (definition.target.fields ? definition.target.fields.map(key => row.value?.[key]) : [row.value]).every(isCount)
        && (!definition.target.baselineRequired || isCount(row.baseline));
    case 'ms': return finite(row.value);
    default: return true; // Other units retain their target-specific value validation below.
  }
}

function evaluate(row, definition, context) {
  const target = definition.target;
  if (!validMeasurement(row, definition)) return 'unavailable';
  if (definition.unit === 'ratio' && (!finite(row.value) || row.value !== row.numerator / row.denominator
    || row.numerator > row.denominator)) return 'unavailable';
  if (target.runs && definition.id !== 'dashboard_first_screen' && definition.id !== 'determinism'
    && (!Array.isArray(row.runs) || row.runs.length !== target.runs || row.runs.some(n => !finite(n))
      || row.value !== median(row.runs))) return 'unavailable';
  if (definition.id === 'determinism' && row.denominator !== target.runs
    || target.fixtures && row.denominator !== target.fixtures
    || target.minimumFixtures && row.denominator < target.minimumFixtures) return 'unavailable';
  const old = context.baseline?.metrics.find(m => m.id === definition.id);
  switch (target.kind) {
    case 'latency':
      if (!validMeasurement(old, definition) || !Array.isArray(old.runs)
        || old.runs.length !== 3 || old.runs.some(n => !finite(n)) || old.value !== median(old.runs)
        || ['fixtureDigest', 'environmentDigest'].some(k => context.report[k] !== context.baseline[k])) return 'unavailable';
      return finite(row.value) && row.value <= target.maximum && row.value <= old.value ? 'pass' : 'fail';
    case 'eq': return finite(row.value) && row.value === target.value ? 'pass' : 'fail';
    case 'max':
      if (target.tasks && (row.runs !== target.runs || row.tasks !== target.tasks)) return 'unavailable';
      return finite(row.value) && row.value <= target.value ? 'pass' : 'fail';
    case 'min':
      if (target.authentic && (row.authentic !== true || row.consecutive !== true)) return 'unavailable';
      if (target.trialsPerFixtureProvider && row.denominator !== target.trialsPerFixtureProvider) return 'unavailable';
      return finite(row.value) && row.value >= target.value ? 'pass' : 'fail';
    case 'regression':
      if (!validMeasurement(old, definition)) return 'unavailable';
      return target.fields.every(k => row.value[k] - old.value[k] <= target.maximumIncrease) ? 'pass' : 'fail';
    case 'paired':
      if (!Array.isArray(row.pairs) || row.pairs.length !== target.pairs || row.independent !== true) return 'unavailable';
      return row.pairs.every(p => finite(p.delta) && p.delta > 0 && p.retainedBaseline === true) ? 'pass' : 'fail';
    case 'tokens':
      return target.fields.every(k => Number.isSafeInteger(row.value?.[k]) && row.value[k] >= 0) ? 'pass' : 'unavailable';
    case 'promotion': {
      if (typeof row.value?.experimental !== 'boolean') return 'unavailable';
      const eligible = frozen.gates.every(d => evaluate(context.report.gates.find(r => r.id === d.id), d, context) === 'pass')
        && frozen.metrics.filter(d => frozen.releases.indexOf(d.minRelease) <= frozen.releases.indexOf('0.7')
          && !['promotion', 'diagnostic'].includes(d.target.kind))
          .every(d => evaluate(context.report.metrics.find(r => r.id === d.id), d, context) === 'pass');
      return row.value.experimental || eligible ? 'pass' : 'fail';
    }
    case 'record':
      if (target.authentic && row.authentic !== true) return 'unavailable';
      return row.recorded === true && row.value !== undefined ? 'pass' : 'unavailable';
    case 'diagnostic': return 'pass';
    default: throw new PolicyError('unsupported_target');
  }
}

export function qualify(policy, input) {
  validatePolicy(policy);
  const unavailable = reason => ({ schema: 'wakeio.kpi-qualification/v1', status: 'unavailable', exitCode: 2, reasons: [reason] });
  if (!policy.releases.includes(input.release)) return unavailable('unsupported_release');
  let report, baseline;
  try {
    report = readKpi(input.report);
    baseline = input.baseline === undefined ? undefined : readKpi(input.baseline);
  } catch (error) {
    if (error instanceof Error) return unavailable(error instanceof PolicyError ? error.reason : 'invalid_kpi');
    throw error;
  }
  if (report.schema !== 'wakeio.kpi/v2' || baseline && baseline.schema !== 'wakeio.kpi/v2') return unavailable('v1_has_no_release_gate_evidence');
  if (report.measurementStatus !== 'completed' || baseline && baseline.measurementStatus !== 'completed') return unavailable('measurement_incomplete');
  const applicable = row => policy.releases.indexOf(row.minRelease) <= policy.releases.indexOf(input.release);
  const context = { report, baseline };
  const results = [
    ...policy.gates.map(d => ({ id: d.id, status: evaluate(report.gates.find(r => r.id === d.id), d, context) })),
    ...policy.metrics.filter(d => applicable(d) && d.target.gating !== false)
      .map(d => ({ id: d.id, status: evaluate(report.metrics.find(r => r.id === d.id), d, context) })),
  ];
  const analysis = report.metrics.find(r => r.id === 'analysis_ms'), oldAnalysis = baseline?.metrics.find(r => r.id === 'analysis_ms');
  const analysisDefinition = policy.metrics.find(r => r.id === 'analysis_ms');
  const exitCode = results.some(r => r.status === 'unavailable') ? 2 : results.some(r => r.status === 'fail') ? 1 : 0;
  return { schema: 'wakeio.kpi-qualification/v1', release: input.release, status: ['pass', 'fail', 'unavailable'][exitCode], exitCode, results,
    analysisTiming: { warning: validMeasurement(analysis, analysisDefinition) && validMeasurement(oldAnalysis, analysisDefinition)
      ? analysis.value > oldAnalysis.value * 1.5 : null, threshold: 1.5, gating: false },
    qualificationScope: 'policy_input_only; source/artifact authenticity is verified by release-gates integration' };
}

async function main(argv) {
  const [mode, ...args] = argv;
  if (!['validate', 'qualify'].includes(mode)) throw new PolicyError('invalid_arguments');
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--policy', '--input', '--baseline', '--release', '--out'].includes(args[i])
      || options[args[i]] !== undefined || !args[i + 1] || args[i + 1].startsWith('--')) throw new PolicyError('invalid_arguments');
    options[args[i]] = args[i + 1];
  }
  if (!options['--out'] || mode === 'qualify' && (!options['--input'] || !options['--release'])) throw new PolicyError('invalid_arguments');
  const policy = await loadPolicy(options['--policy']);
  const input = options['--input'] ? readKpi(JSON.parse(await readFile(options['--input'], 'utf8'))) : undefined;
  const baseline = options['--baseline'] ? readKpi(JSON.parse(await readFile(options['--baseline'], 'utf8'))) : undefined;
  const result = mode === 'validate' ? { status: 'pass', exitCode: 0, gates: policy.gates.length, metrics: policy.metrics.length,
    readerSchema: input?.schema ?? null, releaseQualified: false } : qualify(policy, { report: input, baseline, release: options['--release'] });
  const out = resolve(options['--out']);
  await mkdir(dirname(out), { recursive: true, mode: 0o700 });
  await mkdir(out, { mode: 0o700 }); // Existing output must never mask this attempt.
  await writeFile(join(out, 'policy-result.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify(result) + '\n');
  return result.exitCode;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(error => {
    process.stderr.write(JSON.stringify({ status: 'unavailable', reason: error instanceof PolicyError ? error.reason : 'invalid_input_or_output' }) + '\n');
    process.exitCode = 2;
  });
}
