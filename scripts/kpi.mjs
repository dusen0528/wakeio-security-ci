#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, lstat, realpath, rm, writeFile } from 'node:fs/promises';
import { arch, platform, release, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { loadCorpus, runBenchmark, writeBenchmarkReports } from './benchmark.mjs';
import { loadOssCorpus, verifyCheckout } from './benchmark-oss.mjs';
import { runBounded } from './ci-process.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RUNS = 3;
const REQUIRED = ['source.inventory', 'source.builtin-ast', 'source.framework', 'source.code-coverage'];
const METRICS = ['first_report_ms', 'planned_state_completeness', 'determinism', 'wire_budget_overflow',
  'loop_stop_reason_rate', 'inventory_recall', 'source_regression'];
const sha = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => sha(JSON.stringify(stable(value)));
const unavailable = (id, reason) => ({ id, status: 'unavailable', value: null, reason });
const usage = 'node scripts/kpi.mjs --checkout ABS_NODEGOAT --out NEW_DIR [--engine-root DIR]\n'
  + 'node scripts/kpi.mjs compare --before KPI_JSON --after KPI_JSON --out NEW_DIR\n'
  + 'Source-only, tools none, three warm npx runs. No installation, HTTP target or model.\n';

export function parseArgs(argv) {
  const args = [...argv], mode = args[0] === 'compare' ? args.shift() : 'measure';
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const allowed = mode === 'compare' ? ['--before', '--after', '--out'] : ['--checkout', '--out', '--engine-root'];
  const values = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.includes(args[i]) || values[args[i]] || !args[i + 1] || args[i + 1].startsWith('--')) throw Error('invalid_arguments');
    values[args[i]] = resolve(args[i + 1]);
  }
  if (!values['--out'] || (mode === 'compare' ? !values['--before'] || !values['--after'] : !values['--checkout'])) throw Error('invalid_arguments');
  return { mode, out: values['--out'], before: values['--before'], after: values['--after'],
    checkout: values['--checkout'], engineRoot: values['--engine-root'] ?? ROOT };
}

/** Only source report timestamps are excluded; findings, gaps, scope and array order remain. */
export function semanticHash(report) {
  const { startedAt, finishedAt, ...content } = report;
  return digest(content);
}

export function accuracyIdentities(report) {
  const fp = [], fn = [];
  for (const item of report.cases) {
    const remaining = [...item.observedFindings];
    for (const expected of item.expectedFindings) {
      const index = remaining.findIndex(observed => expected.ruleId === observed.ruleId && expected.path === observed.path
        && expected.line === observed.line && (expected.column === undefined || expected.column === observed.column));
      if (index >= 0) remaining.splice(index, 1);
      else fn.push(digest([item.id, expected]));
    }
    for (const observed of remaining) fp.push(digest([item.id, observed]));
  }
  return { fp: fp.sort(), fn: fn.sort() };
}

async function fixtureDigest(root) {
  const files = [];
  async function walk(directory, prefix = '') {
    for (const name of (await readdir(directory)).sort()) {
      const path = join(directory, name), info = await lstat(path), relative = prefix + name;
      if (info.isSymbolicLink()) throw Error('fixture_symlink');
      if (info.isDirectory()) await walk(path, relative + '/');
      else {
        if (!info.isFile() || files.length >= 10000 || info.size > 32 * 1024 * 1024) throw Error('fixture_limit');
        files.push([relative, sha(await readFile(path))]);
      }
    }
  }
  await walk(root);
  return digest(files);
}

async function corpusDigest(corpus) {
  return digest({ manifest: sha(await readFile(corpus.corpusPath)), files: await fixtureDigest(join(ROOT, 'benchmarks/fixtures')) });
}

async function revision(root) {
  return execFileSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '--no-optional-locks',
    '-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 5000,
    env: { PATH: '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0' } }).trim();
}

async function measureOne(root, checkout, out, home, reportModule, compareModule) {
  const path = join(out, 'report.json');
  let reportMs = null, polling = false;
  const start = performance.now();
  const timer = setInterval(async () => {
    if (polling || reportMs !== null) return;
    polling = true;
    try { JSON.parse(await readFile(path, 'utf8')); reportMs = performance.now() - start; }
    catch { /* Report is not fully published yet. */ }
    finally { polling = false; }
  }, 2);
  let result;
  try {
    result = await runBounded(join(dirname(process.execPath), 'npx'),
      ['--offline', '--no-install', 'wakeio-security-ci', 'scan', '--source', checkout, '--tools', 'none',
        '--project-id', 'wakeio-kpi-nodegoat', '--out', out], {
        cwd: root, timeoutMs: 120000, maxOutputBytes: 1024 * 1024,
        env: { PATH: dirname(process.execPath) + ':/usr/bin:/bin', HOME: home, LC_ALL: 'C',
          npm_config_offline: 'true', npm_config_ignore_scripts: 'true', npm_config_audit: 'false', npm_config_fund: 'false',
          npm_config_userconfig: join(home, 'user.npmrc'), npm_config_globalconfig: join(home, 'global.npmrc') },
      });
  } finally { clearInterval(timer); }
  if (result.reason || !result.cleanupConfirmed || ![0, 1, 2].includes(result.exitCode)) throw Error('scan_process_failed');
  const bytes = await readFile(path), raw = JSON.parse(bytes);
  const report = compareModule.parseScanReport(raw);
  if (report.mode !== 'source' || REQUIRED.some(id => report.checks.filter(c => c.id === id).length !== 1)
    || report.checks.some(c => c.status === 'error') || !report.checks.find(c => c.id === 'source.inventory').sourceSnapshot?.digest
    || reportModule.evaluateGate(report).exitCode !== result.exitCode) throw Error('invalid_scan_evidence');
  const agent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
  if (agent.reportArtifact?.digest !== sha(bytes) || JSON.stringify(agent) !== JSON.stringify(reportModule.toAgentReport(report))) throw Error('invalid_artifact_binding');
  return { reportMs: reportMs ?? performance.now() - start, processMs: result.elapsedMs,
    scanExitCode: result.exitCode, semanticSha256: semanticHash(raw),
    checks: report.checks.map(c => ({ id: c.id, status: c.status,
      reasons: [...new Set((c.analysisGaps?.reasonSummary?.rows ?? []).map(row => row.reason))].sort() })),
    complete: report.checks.every(c => ['completed', 'not_applicable'].includes(c.status)) };
}

export async function measure(options) {
  const corpus = await loadCorpus(), oss = await loadOssCorpus();
  const medium = oss.data.repositories.find(repo => repo.id === 'nodegoat');
  const verified = await verifyCheckout(medium, await realpath(options.checkout));
  const root = await realpath(options.engineRoot);
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  if (pkg.name !== 'wakeio-security-ci' || pkg.bin?.['wakeio-security-ci'] !== './build/src/cli.js') throw Error('unsupported_engine');
  const engine = await import(pathToFileURL(join(root, 'build/src/index.js')).href);
  const reportModule = await import(pathToFileURL(join(root, 'build/src/report.js')).href);
  const compareModule = await import(pathToFileURL(join(root, 'build/src/compare.js')).href);
  const sourceRevision = await revision(root);
  const engineSha256 = await fixtureDigest(join(root, 'build/src'));
  const context = {
    measuredAt: new Date().toISOString(), revision: sourceRevision, engineSha256, toolVersion: pkg.version,
    fixtureDigest: digest({ commit: verified.commit, tree: verified.tree, manifest: oss.sha256 }),
    corpusDigest: await corpusDigest(corpus),
    harnessDigest: digest(await Promise.all(['scripts/kpi.mjs', 'scripts/benchmark.mjs', 'scripts/benchmark-oss.mjs', 'scripts/ci-process.mjs', 'benchmarks/kpi.Dockerfile'].map(async name => [name, sha(await readFile(join(ROOT, name)))]))),
    environment: { os: platform(), release: release(), arch: arch(), node: process.version,
      npm: execFileSync(join(dirname(process.execPath), 'npm'), ['--version'], { encoding: 'utf8', timeout: 5000 }).trim(),
      dependencyLock: sha(await readFile(join(root, 'package-lock.json'))) },
    phase: 'source_offline_warm', parameters: { tools: 'none', runs: RUNS, analysisProfile: 'default', projectId: 'wakeio-kpi-nodegoat' },
  };
  await mkdir(dirname(options.out), { recursive: true, mode: 0o700 });
  await mkdir(options.out, { mode: 0o700 });
  const home = await mkdtemp(join(tmpdir(), 'wakeio-kpi-home-'));
  try {
    await writeFile(join(home, 'user.npmrc'), ''); await writeFile(join(home, 'global.npmrc'), '');
    const runs = [];
    for (let i = 0; i < RUNS; i++) runs.push(await measureOne(root, verified.root, join(options.out, 'run-' + (i + 1)), home, reportModule, compareModule));
    const accuracy = await runBenchmark(engine.runSource, { engine: { label: sourceRevision, version: pkg.version, modulePath: 'build/src/index.js' } });
    await writeBenchmarkReports(accuracy, join(options.out, 'accuracy'));
    if (!accuracy.success || !accuracy.cases.length || accuracy.summary.incompleteCases
      || engineSha256 !== await fixtureDigest(join(root, 'build/src')) || sourceRevision !== await revision(root)
      || context.corpusDigest !== await corpusDigest(corpus)
      || context.environment.dependencyLock !== sha(await readFile(join(root, 'package-lock.json')))) throw Error('incomplete_or_changed_engine');
    await verifyCheckout(medium, verified.root);
    const deterministic = new Set(runs.map(run => run.semanticSha256)).size === 1;
    const report = { schema: 'wakeio.kpi/v1', ...context, measurementStatus: deterministic ? 'completed' : 'failed',
      medium: { id: medium.id, commit: verified.commit, tree: verified.tree, files: verified.trackedFiles, runs,
        coverageComplete: runs.every(run => run.complete), scope: 'whole pinned source; partial analysis is preserved, not clean coverage' },
      metrics: [
        { id: 'first_report_ms', status: 'measured', value: runs.map(r => r.reportMs).sort((a, b) => a - b)[1],
          runs: runs.map(r => r.reportMs), timingBoundary: 'npx spawn to first parseable primary report, 2ms polling; warm checkout bin, no registry install' },
        unavailable('planned_state_completeness', 'no_predeclared_cell_denominator'),
        { id: 'determinism', status: 'measured', value: deterministic ? 1 : 0, numerator: deterministic ? RUNS : null, denominator: RUNS },
        unavailable('wire_budget_overflow', 'http_targets_excluded'),
        unavailable('loop_stop_reason_rate', 'run_loop_not_implemented'),
        unavailable('inventory_recall', 'surface_inventory_not_implemented'),
        { id: 'source_regression', status: 'measured', value: { tp: accuracy.summary.truePositives, fp: accuracy.summary.falsePositives,
          fn: accuracy.summary.falseNegatives, completedCases: accuracy.summary.completedCases, totalCases: accuracy.summary.totalCases },
          identities: accuracyIdentities(accuracy) },
      ], limits: ['network isolation is enforced externally, not attested by this script', 'registry cold install and HTTP/model/release KPIs are not measured',
        'no absolute latency gate; compare only identical environments and inputs'], performanceTarget: null };
    await writeFile(join(options.out, 'kpi.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    return report;
  } finally { await rm(home, { recursive: true, force: true }); }
}

function validate(report) {
  if (report?.schema !== 'wakeio.kpi/v1' || !['completed', 'failed'].includes(report.measurementStatus)
    || !/^[a-f0-9]{40}$/.test(report.revision ?? '') || !report.environment || !report.parameters
    || !Array.isArray(report.metrics) || report.metrics.length !== METRICS.length) throw Error('invalid_kpi');
  if (report.phase !== 'source_offline_warm' || ['os', 'release', 'arch', 'node', 'npm'].some(key => typeof report.environment[key] !== 'string' || !report.environment[key])
    || !/^[a-f0-9]{64}$/.test(report.environment.dependencyLock ?? '')
    || digest(report.parameters) !== digest({ tools: 'none', runs: RUNS, analysisProfile: 'default', projectId: 'wakeio-kpi-nodegoat' })
    || !Array.isArray(report.medium?.runs) || report.medium.runs.length !== RUNS) throw Error('invalid_kpi');
  for (const run of report.medium.runs) {
    if (!Number.isFinite(run.reportMs) || run.reportMs < 0 || !Number.isFinite(run.processMs) || run.processMs < 0
      || ![0, 1, 2].includes(run.scanExitCode) || !/^[a-f0-9]{64}$/.test(run.semanticSha256 ?? '')
      || !Array.isArray(run.checks) || REQUIRED.some(id => run.checks.filter(c => c.id === id).length !== 1)
      || run.checks.some(c => !['completed', 'partial', 'skipped', 'not_applicable'].includes(c.status))
      || run.checks.some(c => c.reasons !== undefined && (!Array.isArray(c.reasons) || c.reasons.some(reason => !/^[a-z][a-z0-9_]{1,79}$/.test(reason))))
      || run.complete !== run.checks.every(c => ['completed', 'not_applicable'].includes(c.status))
      || !run.complete && run.scanExitCode !== 2) throw Error('invalid_kpi');
  }
  if (report.medium.coverageComplete !== report.medium.runs.every(run => run.complete)) throw Error('invalid_kpi');
  for (const key of ['engineSha256', 'fixtureDigest', 'corpusDigest', 'harnessDigest']) if (!/^[a-f0-9]{64}$/.test(report[key] ?? '')) throw Error('invalid_kpi');
  for (const id of METRICS) {
    const items = report.metrics.filter(metric => metric.id === id);
    if (items.length !== 1 || !['measured', 'unavailable', 'failed', 'not_applicable'].includes(items[0].status)) throw Error('invalid_kpi');
    const metric = items[0];
    if (metric.status !== 'measured' && (metric.value !== null || typeof metric.reason !== 'string' || !metric.reason)) throw Error('invalid_kpi');
    if (metric.status === 'measured') {
      if (id === 'source_regression') {
        if (['tp', 'fp', 'fn', 'completedCases', 'totalCases'].some(k => !Number.isSafeInteger(metric.value?.[k]) || metric.value[k] < 0)
          || !['fp', 'fn'].every(k => Array.isArray(metric.identities?.[k]) && metric.identities[k].every(x => /^[a-f0-9]{64}$/.test(x))
            && new Set(metric.identities[k]).size === metric.identities[k].length && metric.identities[k].length === metric.value[k])) throw Error('invalid_kpi');
      } else if (!Number.isFinite(metric.value) || metric.value < 0 || id === 'determinism' && ![0, 1].includes(metric.value)) throw Error('invalid_kpi');
    }
  }
  const latency = report.metrics.find(m => m.id === 'first_report_ms');
  const determinism = report.metrics.find(m => m.id === 'determinism');
  if (latency.status === 'measured' && (latency.value !== report.medium.runs.map(r => r.reportMs).sort((a, b) => a - b)[1]
    || digest(latency.runs) !== digest(report.medium.runs.map(r => r.reportMs)))
    || determinism.status === 'measured' && (determinism.value !== (new Set(report.medium.runs.map(r => r.semanticSha256)).size === 1 ? 1 : 0)
      || determinism.denominator !== RUNS || determinism.numerator !== (determinism.value === 1 ? RUNS : null))) throw Error('invalid_kpi');
}

export function compareKpi(before, after) {
  validate(before); validate(after);
  const incompatible = ['fixtureDigest', 'corpusDigest', 'harnessDigest', 'environment', 'phase', 'parameters']
    .filter(key => digest(before[key]) !== digest(after[key]));
  if (incompatible.length) return { schema: 'wakeio.kpi-comparison/v1', comparable: false, status: 'incomparable', exitCode: 2, reasons: incompatible };
  if (before.measurementStatus !== 'completed' || after.measurementStatus !== 'completed'
    || after.metrics.some(metric => metric.status === 'failed')) {
    return { schema: 'wakeio.kpi-comparison/v1', comparable: true, status: 'failed', exitCode: 2, reasons: ['measurement_failed'] };
  }
  const oldAccuracy = before.metrics.find(m => m.id === 'source_regression'), accuracy = after.metrics.find(m => m.id === 'source_regression');
  if (oldAccuracy.status !== 'measured' || accuracy.status !== 'measured'
    || [oldAccuracy, accuracy].some(m => !m.value.totalCases || m.value.completedCases !== m.value.totalCases)
    || accuracy.value.totalCases !== oldAccuracy.value.totalCases) throw Error('incomplete_accuracy');
  const newFp = accuracy.identities.fp.filter(id => !oldAccuracy.identities.fp.includes(id));
  const newFn = accuracy.identities.fn.filter(id => !oldAccuracy.identities.fn.includes(id));
  const missing = before.metrics.filter(m => m.status === 'measured' && after.metrics.find(n => n.id === m.id).status !== 'measured').map(m => m.id);
  if (missing.length) return { schema: 'wakeio.kpi-comparison/v1', comparable: true, status: 'failed', exitCode: 2, reasons: missing };
  const incomplete = report => report.medium.runs[0].checks.filter(c => !['completed', 'not_applicable'].includes(c.status)).map(c => digest([c.id, c.status, c.reasons ?? []]));
  const previousIncomplete = incomplete(before), newIncomplete = incomplete(after).filter(key => !previousIncomplete.includes(key));
  const regression = newFp.length || newFn.length || newIncomplete.length || after.metrics.find(m => m.id === 'determinism').value !== 1;
  return { schema: 'wakeio.kpi-comparison/v1', comparable: true, status: regression ? 'regression' : 'no_regression', exitCode: regression ? 1 : 0,
    newFalsePositives: newFp.length, newFalseNegatives: newFn.length, newIncompleteChecks: newIncomplete.length,
    firstReportDeltaMs: after.metrics.find(m => m.id === 'first_report_ms').value - before.metrics.find(m => m.id === 'first_report_ms').value,
    performanceTarget: null, unavailable: after.metrics.filter(m => m.status === 'unavailable').map(m => m.id) };
}

async function main(argv) {
  const options = parseArgs(argv);
  if (options.help) { process.stdout.write(usage); return 0; }
  if (options.mode === 'compare') {
    const result = compareKpi(JSON.parse(await readFile(options.before, 'utf8')), JSON.parse(await readFile(options.after, 'utf8')));
    await mkdir(dirname(options.out), { recursive: true, mode: 0o700 });
    await mkdir(options.out, { mode: 0o700 });
    await writeFile(join(options.out, 'comparison.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    process.stdout.write(JSON.stringify(result) + '\n');
    return result.exitCode;
  }
  const report = await measure(options);
  process.stdout.write(JSON.stringify({ status: report.measurementStatus, metrics: report.metrics }) + '\n');
  return report.measurementStatus === 'completed' ? 0 : 2;
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(() => {
    process.stderr.write('KPI failed: invalid input, incomplete evidence, or measurement/publication failure. No HTTP target or model is invoked.\n');
    process.exitCode = 2;
  });
}
