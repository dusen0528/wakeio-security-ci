#!/usr/bin/env node
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { fork, execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, lstat, realpath, rm, writeFile, cp } from 'node:fs/promises';
import { cpus, totalmem, platform, release, arch, tmpdir } from 'node:os';
import { dirname, join, resolve, relative, isAbsolute } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { loadCorpus } from './benchmark.mjs';
import { loadOssCorpus, verifyCheckout } from './benchmark-oss.mjs';

const SCRIPT = fileURLToPath(import.meta.url);
const ROOT = resolve(dirname(SCRIPT), '..');
export const BASE_SHA = 'f18b75bb0731e71620f8638c1b3482d91139d9b2';
const hash = value => createHash('sha256').update(value).digest('hex');
const digest = value => hash(JSON.stringify(value));
const sortedUnique = values => [...new Set(values.map(v => JSON.stringify(v)))].sort().map(v => JSON.parse(v));
const REQUIRED = ['source.inventory', 'source.builtin-ast', 'source.framework', 'source.code-coverage'];

export function parseArgs(argv) {
  const options = { runs: 5, outDir: join(ROOT, 'benchmarks/results'), profile: false, ossId: 'nodegoat' };
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i];
    if (name === '--profile') { options.profile = true; continue; }
    if (name === '--help') { options.help = true; continue; }
    if (!['--runs', '--out-dir', '--checkout', '--oss-id'].includes(name)) throw Error('unknown_option');
    const value = argv[++i];
    if (!value || value.startsWith('--')) throw Error('missing_option_value');
    if (name === '--runs') {
      if (!/^[1-9][0-9]*$/.test(value) || Number(value) > 50) throw Error('runs_must_be_integer_1_to_50');
      options.runs = Number(value);
    } else if (name === '--out-dir') options.outDir = resolve(value);
    else if (name === '--checkout') options.checkout = resolve(value);
    else options.ossId = value;
  }
  return options;
}

/** Nearest rank: sorted[ceil(p*n)-1], no interpolation. */
export function statistics(samples) {
  if (!samples.length || samples.some(v => !Number.isFinite(v) || v < 0)) throw Error('invalid_samples');
  const sorted = [...samples].sort((a, b) => a - b);
  return { n: sorted.length, min: sorted[0], p50: sorted[Math.ceil(sorted.length * .5) - 1],
    p95: sorted[Math.ceil(sorted.length * .95) - 1], max: sorted.at(-1) };
}

/** Hash all regular input bytes, including files the engine will exclude; omit Git metadata only. */
export async function treeManifest(root) {
  const files = [];
  async function visit(dir, prefix = '') {
    for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
      if (!prefix && entry.name === '.git') continue;
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = join(dir, entry.name);
      const stat = await lstat(full);
      if (stat.isDirectory()) await visit(full, path);
      else if (stat.isFile() && stat.nlink === 1) {
        const bytes = await readFile(full);
        files.push({ path, bytes: bytes.length, sha256: hash(bytes) });
      } else throw Error('input_not_regular');
    }
  }
  await visit(root);
  return { files: files.length, bytes: files.reduce((n, f) => n + f.bytes, 0), digest: digest(files) };
}

export async function generateLarge(root, maxFiles, seed = 0x5030) {
  await mkdir(root, { recursive: true });
  let state = seed >>> 0;
  for (let i = 0; i < maxFiles + 1; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    await writeFile(join(root, `file-${String(i).padStart(6, '0')}.ts`), `export const value${i} = ${state};\n`);
  }
  return { seed, generator: 'lcg-u32-1664525-1013904223-v1', generatedFiles: maxFiles + 1 };
}

function localPath(path, root) {
  if (typeof path !== 'string') throw Error('invalid_finding_path');
  const result = isAbsolute(path) ? relative(root, path) : path;
  if (!result || result === '..' || result.startsWith('../') || isAbsolute(result)) throw Error('finding_outside_root');
  return result.replaceAll('\\', '/');
}

export function normalizeRun(results) {
  const findings = [], states = [];
  for (const { caseId, root, checks } of results) {
    if (!Array.isArray(checks)) throw Error('invalid_checks');
    for (const check of checks) {
      if (!Array.isArray(check.findings)) throw Error('invalid_findings');
      for (const f of check.findings) {
        if (typeof f.ruleId !== 'string') throw Error('invalid_finding');
        findings.push([caseId, f.ruleId, localPath(f.location?.path, root), f.location?.line ?? null]);
      }
      // Explicit semantic fields exclude prose, timing, and temporary absolute roots.
      states.push({ caseId, id: check.id, status: check.status, metrics: check.metrics ?? null,
        collectionBudget: check.collectionBudget ?? null, collectionEvidence: check.collectionEvidence ?? null,
        sourceSnapshot: check.sourceSnapshot ?? null, analysisBudget: check.analysisBudget ?? null,
        analysisGaps: check.analysisGaps ?? null, codeCoverage: check.codeCoverage ?? null });
    }
  }
  const normalized = { findings: sortedUnique(findings), states: sortedUnique(states) };
  return { ...normalized, findingDigest: digest(normalized.findings), stateDigest: digest(normalized.states), resultDigest: digest(normalized) };
}

export function validateRun(results, tier) {
  const errors = [];
  if (!results.length) return ['empty_suite'];
  for (const result of results) {
    const { checks, caseId } = result;
    const fail = reason => errors.push(`${caseId}:${reason}`);
    if (!Array.isArray(checks)) { fail('missing_checks'); continue; }
    if (checks.length !== REQUIRED.length || REQUIRED.some(id => checks.filter(c => c.id === id).length !== 1)) { fail('unexpected_check_set'); continue; }
    const inventory = checks.find(c => c.id === 'source.inventory');
    const ast = checks.find(c => c.id === 'source.builtin-ast');
    if (!inventory.sourceSnapshot?.digest || !(inventory.metrics?.filesSelected > 0) || !inventory.collectionBudget || !inventory.collectionEvidence) fail('missing_collection_evidence');
    const issues = inventory.collectionEvidence?.issues ?? [];
    const allowedIssues = tier === 'L' ? ['file_limit'] : tier === 'M' ? ['file_limit', 'size_limit', 'unsupported_file'] : [];
    if (issues.some(i => !allowedIssues.includes(i.code))) fail('unexpected_collection_issue');
    if (tier === 'L' && (inventory.metrics?.complete !== false || issues.length !== 1 || issues[0].code !== 'file_limit'
      || inventory.metrics.filesSelected !== inventory.collectionBudget?.limits.maxFiles)) fail('expected_file_limit_missing');
    if (tier === 'S' && inventory.metrics?.complete !== true) fail('incomplete_collection');
    if (inventory.metrics?.complete === false && !issues.length) fail('unexplained_incomplete_collection');
    if (ast.metrics?.parseErrorCount !== 0 || !ast.analysisBudget) fail('parse_or_analysis_error');
    for (const c of checks) {
      if (!Array.isArray(c.findings)) { fail('invalid_findings'); continue; }
      if (c.status === 'completed') continue;
      if (c.id === 'source.framework' && c.status === 'not_applicable' && c.metrics?.filesAnalyzed === 0) continue;
      if (c.id === 'source.inventory' && c.status === 'partial' && tier !== 'S' && issues.length) continue;
      if (tier === 'M' && c.id === 'source.builtin-ast' && c.status === 'partial' && c.metrics?.incompleteReasons) continue;
      fail(`${c.id}:${c.status}`);
    }
    if (tier !== 'M' && (ast.metrics?.indexComplete !== true || ast.metrics?.analysisIncomplete !== false)) fail('unexpected_incomplete_analysis');
  }
  return errors;
}

export function assessRuns(runs) {
  const nondeterministic = new Set(runs.map(r => r.resultDigest)).size > 1;
  const errors = runs.flatMap(r => r.errors ?? []);
  return { status: nondeterministic ? 'nondeterministic' : errors.length ? 'failed' : 'deterministic',
    exitCode: nondeterministic || errors.length ? 2 : 0, errors: [...new Set(errors)] };
}

async function scan(runSource, cases) {
  const results = [];
  for (const c of cases) results.push({ ...c, checks: await runSource({ root: c.root, tools: [] }) });
  return results;
}

async function childMain() {
  const job = await new Promise(resolveJob => process.once('message', resolveJob));
  const { runSource } = await import('../build/src/index.js');
  const runs = [];
  const count = job.mode === 'warm' ? job.runs + 1 : 1;
  for (let i = 0; i < count; i++) {
    const start = performance.now();
    const results = await scan(runSource, job.cases);
    const elapsedMs = performance.now() - start;
    if (job.mode === 'process-cold') {
      // Send raw analysis immediately: parent stops the clock before normalization/hashing.
      await new Promise((resolveSend, reject) => process.send({ results, maxRSS: process.resourceUsage().maxRSS }, error => error ? reject(error) : resolveSend()));
    } else {
      const normalized = normalizeRun(results);
      runs.push({ elapsedMs, warmup: i === 0, ...normalized, errors: validateRun(results, job.tier) });
    }
  }
  if (job.mode === 'warm') await new Promise((resolveSend, reject) => process.send({ runs, maxRSS: process.resourceUsage().maxRSS }, error => error ? reject(error) : resolveSend()));
  process.disconnect();
}

export function runChild(job, profilePath) {
  return new Promise((resolveChild, reject) => {
    const execArgv = profilePath ? ['--cpu-prof', `--cpu-prof-dir=${dirname(profilePath)}`, `--cpu-prof-name=${profilePath.split('/').at(-1)}`] : [];
    const start = performance.now();
    const child = fork(SCRIPT, ['--child'], { execArgv, stdio: ['ignore', 'ignore', 'inherit', 'ipc'], env: { ...process.env, NODE_OPTIONS: '' } });
    let response;
    child.once('message', message => { response = { ...message, wallMs: performance.now() - start }; });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 && !signal && response ? resolveChild(response) : reject(Error('child_execution_failed')));
    child.send(job);
  });
}

export function summarizeProfile(profile) {
  const nodes = new Map(profile.nodes.map(n => [n.id, n.callFrame]));
  const times = new Map();
  const samples = profile.samples ?? [], deltas = profile.timeDeltas ?? [];
  let totalUs = 0;
  for (let i = 0; i < samples.length; i++) {
    const frame = nodes.get(samples[i]);
    if (!frame || !Number.isFinite(deltas[i]) || deltas[i] < 0) continue;
    const url = frame.url.replaceAll(ROOT, '<repo>').replace(/^.*\/node_modules\//, 'node_modules/');
    const key = JSON.stringify([frame.functionName || '(anonymous)', url, frame.lineNumber + 1]);
    times.set(key, (times.get(key) ?? 0) + deltas[i]); totalUs += deltas[i];
  }
  return { sampleCount: samples.length, sampledTimeUs: totalUs, insufficientSamples: samples.length < 100,
    method: 'timeDeltas attributed to sampled leaf frames; self time, not inclusive time or wall-time causality',
    top: [...times].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([key, selfTimeUs]) => {
      const [functionName, url, line] = JSON.parse(key);
      return { functionName, url, line, selfTimeUs, percent: totalUs ? selfTimeUs / totalUs * 100 : 0 };
    }) };
}

async function prepare(options, temp) {
  const corpus = await loadCorpus();
  const oss = await loadOssCorpus();
  const repo = oss.data.repositories.find(r => r.id === options.ossId);
  if (!repo) throw Error('unknown_oss_id');
  if (!options.checkout) throw Error(`M checkout required. Prepare without installing/executing target code: git clone --no-checkout ${repo.url} <checkout>; git -C <checkout> checkout --detach ${repo.commit}; rerun with --checkout <checkout>`);
  const verified = await verifyCheckout(repo, options.checkout);
  const tiers = [{ id: 'S', cases: [], corpusVersion: corpus.corpusVersion, caseOrder: 'corpus manifest order' },
    { id: 'M', cases: [{ caseId: repo.id, root: verified.root }], repository: { id: repo.id, url: repo.url, commit: repo.commit, tree: repo.tree,
      verification: 'verifyCheckout: exact tracked blob hashes/modes/tree/commit, expected SHA256, no extra files, symlinks or submodules' } },
    { id: 'L', cases: [{ caseId: 'generated-large', root: join(temp, 'L') }] }];
  for (const entry of corpus.cases) {
    const source = resolve(corpus.fixtureRoot, entry.fixture);
    if (!source.startsWith(`${corpus.fixtureRoot}/fixtures/`)) throw Error('fixture_outside_root');
    await treeManifest(source);
    const root = join(temp, 'S', String(tiers[0].cases.length));
    await cp(source, root, { recursive: true });
    tiers[0].cases.push({ caseId: entry.id, root });
  }
  const { collectSource, DEFAULT_MAX_FILES } = await import('../build/src/source/collector.js');
  const { sourceSnapshotEvidence } = await import('../build/src/source/snapshot-evidence.js');
  tiers[2].generator = await generateLarge(tiers[2].cases[0].root, DEFAULT_MAX_FILES);
  for (const tier of tiers) {
    tier.inputs = [];
    for (const c of tier.cases) {
      const input = await treeManifest(c.root);
      const snapshot = await collectSource({ root: c.root });
      tier.inputs.push({ caseId: c.caseId, ...input, collected: { files: snapshot.files.map(f => f.path), bytes: snapshot.totalBytes,
        complete: snapshot.complete, issues: snapshot.issues, budget: snapshot.collectionBudget, evidence: sourceSnapshotEvidence(snapshot) } });
    }
    tier.inputDigest = digest(tier.inputs.map(({ caseId, digest }) => [caseId, digest]));
    tier.totalInput = { files: tier.inputs.reduce((n, i) => n + i.files, 0), bytes: tier.inputs.reduce((n, i) => n + i.bytes, 0) };
  }
  return { tiers, repo };
}

function git(...args) { return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim(); }
async function fingerprint() {
  const build = await treeManifest(join(ROOT, 'build/src'));
  return { build, packageLock: hash(await readFile(join(ROOT, 'package-lock.json'))),
    typescript: hash(await readFile(join(ROOT, 'node_modules/typescript/lib/typescript.js'))),
    harness: hash(await readFile(SCRIPT)), corpus: hash(await readFile(join(ROOT, 'benchmarks/corpus.json'))),
    ossCorpus: hash(await readFile(join(ROOT, 'benchmarks/oss-corpus.json'))) };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) { console.log('Usage: npm run benchmark:perf -- --checkout PATH [--oss-id nodegoat|juice-shop] [--runs 1..50] [--out-dir PATH] [--profile]\nDefault runs=5. Official baseline runs=30. Target checkout must exactly match benchmarks/oss-corpus.json.'); return 0; }
  const temp = await realpath(await mkdtemp(join(tmpdir(), 'wakeio-source-perf-')));
  try {
    const before = await fingerprint();
    const { tiers, repo } = await prepare(options, temp);
    if (options.outDir === options.checkout || options.outDir.startsWith(`${options.checkout}/`)) throw Error('output_inside_checkout');
    await mkdir(options.outDir, { recursive: true });
    const realOut = await realpath(options.outDir);
    if (realOut === options.checkout || realOut.startsWith(`${options.checkout}/`)) throw Error('output_inside_checkout');
    for (const name of ['perf.json', 'S.cpuprofile', 'M.cpuprofile']) {
      const stat = await lstat(join(realOut, name)).catch(error => { if (error.code !== 'ENOENT') throw error; });
      if (stat && (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1)) throw Error('unsafe_output_file');
    }
    options.outDir = realOut;
    const report = { schemaVersion: 'source-perf-v1', generatedAt: new Date().toISOString(), baseSha: BASE_SHA, head: git('rev-parse', 'HEAD'),
      dirty: !!git('status', '--porcelain'), fingerprint: before,
      environment: { node: process.version, os: platform(), release: release(), arch: arch(), cpu: cpus()[0]?.model, cores: cpus().length, totalMemoryBytes: totalmem() },
      reproduction: `npm run benchmark:perf -- --checkout <verified-checkout> --oss-id ${options.ossId} --runs ${options.runs}${options.profile ? ' --profile' : ''} --out-dir <output-directory>`,
      options: { tools: [], root: '<each prepared case root>', otherOptions: 'omitted; engine defaults, no OSS benchmark overrides' }, runs: options.runs,
      boundaries: { 'process-cold': 'parent immediately before fork through raw analysis IPC receipt; includes startup, module loading, sequential analysis and result transfer; excludes parent normalization, hash, storage and child exit',
        warm: 'new process per tier; module loading and one unaggregated suite warmup, then runSource/sequential suite wall time only; normalization between runs excluded',
        preparation: 'copy/generation/checkout verification/input hashing/collector manifest outside timing; OS file caches are not flushed',
        rss: 'Node resourceUsage().maxRSS in KiB; child lifetime high-water mark through result send, warm whole-process high-water mark including warmup and normalization; not independent per-iteration peaks' },
      percentile: 'nearest rank: sorted[ceil(p*n)-1], no interpolation',
      limitations: ['Built-in source analysis only; not product end-to-end latency.', 'External scanners, installation, dashboard, CI communication excluded.',
        'OS caches retained; preparation reads input. Warm includes JIT/GC variability.', 'CI timing is not an absolute performance acceptance gate.',
        'CPU samples include startup and transfer; self time does not establish wall-time bottlenecks.', 'M may be partial under default analysis budgets; determinism does not imply complete coverage.'], tiers: [] };
    for (const tier of tiers) {
      const observed = [], cold = [], coldRSS = [];
      function record(results) {
        const run = { ...normalizeRun(results), errors: validateRun(results, tier.id) };
        for (const state of run.states.filter(s => s.id === 'source.inventory')) {
          const expected = tier.inputs.find(i => i.caseId === state.caseId)?.collected.evidence;
          if (JSON.stringify(state.sourceSnapshot) !== JSON.stringify(expected)) run.errors.push(`${state.caseId}:collection_changed_from_preparation`);
        }
        return run;
      }
      for (let i = 0; i < options.runs; i++) {
        const child = await runChild({ mode: 'process-cold', tier: tier.id, cases: tier.cases });
        cold.push(child.wallMs); coldRSS.push(child.maxRSS);
        observed.push({ mode: 'process-cold', iteration: i + 1, ...record(child.results) });
      }
      const warm = await runChild({ mode: 'warm', tier: tier.id, cases: tier.cases, runs: options.runs });
      for (const [i, run] of warm.runs.entries()) observed.push({ mode: 'warm', iteration: i, ...run });
      const profilePath = join(options.outDir, `${tier.id}.cpuprofile`);
      let profile;
      if (options.profile && tier.id !== 'L') {
        const child = await runChild({ mode: 'process-cold', tier: tier.id, cases: tier.cases }, profilePath);
        observed.push({ mode: 'profile', iteration: 1, ...record(child.results) });
        profile = { file: `${tier.id}.cpuprofile`, ...summarizeProfile(JSON.parse(await readFile(profilePath, 'utf8'))) };
      }
      const first = observed[0];
      const output = { ...tier, cases: tier.cases.map(c => c.caseId),
        modes: { 'process-cold': { samplesMs: cold, ...statistics(cold), maxRSSKiB: coldRSS },
          warm: { samplesMs: warm.runs.slice(1).map(r => r.elapsedMs), ...statistics(warm.runs.slice(1).map(r => r.elapsedMs)), warmupRuns: 1, lifetimeMaxRSSKiB: warm.maxRSS } },
        determinism: assessRuns(observed), reference: { findings: first.findings, states: first.states },
        executions: observed.map(({ findings, states, elapsedMs, ...run }) => run), ...(profile ? { profile } : {}) };
      report.tiers.push(output);
      console.log(`${tier.id}: ${output.determinism.status}; process-cold p50=${output.modes['process-cold'].p50.toFixed(2)} ms, warm p50=${output.modes.warm.p50.toFixed(2)} ms`);
    }
    await verifyCheckout(repo, options.checkout);
    if (JSON.stringify(before) !== JSON.stringify(await fingerprint())) throw Error('build_or_harness_changed');
    for (const tier of tiers) for (const [i, c] of tier.cases.entries()) {
      if ((await treeManifest(c.root)).digest !== tier.inputs[i].digest) throw Error('input_changed');
    }
    report.exitCode = report.tiers.some(t => t.determinism.exitCode !== 0) ? 2 : 0;
    await writeFile(join(options.outDir, 'perf.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW });
    return report.exitCode;
  } finally { await rm(temp, { recursive: true, force: true }); }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  (process.argv[2] === '--child' ? childMain() : main().then(code => { process.exitCode = code; }))
    .catch(error => { console.error(`perf benchmark failed: ${process.argv[2] === '--child' ? 'child_execution_failed' : error.message}`); process.exitCode = 2; if (process.connected) process.disconnect(); });
}
