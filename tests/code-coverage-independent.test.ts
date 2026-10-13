import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { runSource } from '../src/source.js';
import { main } from '../src/cli.js';
import { doctorMain } from '../src/doctor.js';
import { initMain } from '../src/init.js';
import { buildScanScope } from '../src/scan-scope.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toReportSummary, toSarif, writeReports } from '../src/report.js';
import { compareReports } from '../src/compare.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';

// Independent expectations precede producer output. Own target files are read
// as DATA ONLY; fake external children test protocol admission, not engine efficacy.
// Existing public imports keep this file loadable against the baseline build.
const NOW = '2026-10-13T00:00:00.000Z', ID = 'source.code-coverage';
const CANARY = 'owned-coverage-source-marker-80ad';
const PYTHON = "import subprocess\ndef route(request):\n subprocess.run(request.args['command'], shell=True)\n";
const JS = 'export const ready = true;\n';
const LANGUAGES = ['javascript', 'typescript', 'python', 'c', 'cpp', 'csharp', 'go', 'java', 'kotlin', 'php', 'ruby', 'rust', 'shell', 'swift', 'vue'];
const PROVIDERS = ['builtin_ast', 'bandit', 'opengrep_native'];
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const sha = (bytes: string) => createHash('sha256').update(bytes).digest('hex');
async function workspace(t: TestContext) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-coverage-independent-'));
  t.after(() => rm(top, { recursive: true, force: true })); return top;
}
async function source(top: string, files: Record<string, string>, name = 'source') {
  const root = join(top, name); await mkdir(root, { recursive: true });
  for (const [path, text] of Object.entries(files)) { await mkdir(dirname(join(root, path)), { recursive: true }); await writeFile(join(root, path), text); }
  return root;
}
function report(checks: any[], required = false) {
  return createReport(checks, 'source', NOW, { fingerprint: 'a'.repeat(64), ruleset: 'owned-coverage-independent', projectId: 'owned-coverage',
    ...(required ? { codeAnalysisPolicy: { revision: 'code-coverage-v1', requireCodeAnalysis: true } } : {}) } as any);
}
async function scan(root: string, required = false, extra: Record<string, unknown> = {}) {
  const checks = await runSource({ root, tools: [], requireCodeAnalysis: required, ...extra } as any);
  return { checks, report: report(checks, required) };
}
function evidence(checks: any[]) {
  const entries = checks.filter(c => c.id === ID); assert.equal(entries.length, 1, 'each source scan must expose one coverage record');
  const value = entries[0].codeCoverage; assert.ok(value, 'missing typed collected-code evidence');
  assert.equal(value.version, 1); assert.equal(value.basis, 'collected_code_inputs');
  assert.ok(['exact', 'unknown'].includes(value.accounting));
  assert.equal(new Set(value.languages.map((r: any) => r.language)).size, value.languages.length);
  const positions = value.languages.map((r: any) => LANGUAGES.indexOf(r.language));
  assert.ok(positions.every((p: number, i: number) => p >= 0 && (i === 0 || p > positions[i - 1])), 'language rows must have canonical bounded order');
  for (const row of value.languages) {
    assert.deepEqual(row.providers.map((p: any) => p.provider), PROVIDERS);
    if (value.accounting === 'exact') {
      assert.ok(row.collected > 0); assert.equal(row.uncovered, row.collected - row.completed);
      assert.ok(row.completed <= row.eligible && row.eligible <= row.collected);
      assert.equal(row.eligible, Math.max(...row.providers.map((p: any) => p.eligible)));
      assert.equal(row.completed, Math.max(...row.providers.map((p: any) => p.completed)));
    }
  }
  if (value.accounting === 'exact') for (const field of ['collected', 'eligible', 'completed', 'uncovered']) {
    assert.equal(value.totals[field], value.languages.reduce((n: number, r: any) => n + r[field], 0));
  }
  return value;
}
function row(value: any, language: string) { const result = value.languages.find((r: any) => r.language === language); assert.ok(result, language); return result; }
function provider(value: any, language: string, name: string) { return row(value, language).providers.find((p: any) => p.provider === name); }
function gate(value: any, code: number, failOn: 'high' | 'none' = 'high') {
  assert.equal(evaluateGate(value, failOn).exitCode, code); assert.equal(toAgentReport(value, failOn).scanGate.exitCode, code);
}
async function captured(fn: () => Promise<number>) {
  const stdout = process.stdout.write, stderr = process.stderr.write; let out = '', err = '';
  process.stdout.write = ((chunk: any) => { out += String(chunk); return true; }) as any;
  process.stderr.write = ((chunk: any) => { err += String(chunk); return true; }) as any;
  try { return { code: await fn(), out, err }; } finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
async function child(entry: string, env: NodeJS.ProcessEnv) {
  return await new Promise<{ code: number | null; out: string; err: string }>((resolveResult, reject) => {
    const p = spawn(process.execPath, [entry], { cwd: process.cwd(), env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; const timer = setTimeout(() => { p.kill('SIGKILL'); reject(Error('owned Action child timeout')); }, 15_000);
    p.stdout.on('data', data => { out += data; }); p.stderr.on('data', data => { err += data; });
    p.once('error', error => { clearTimeout(timer); reject(error); });
    p.once('close', code => { clearTimeout(timer); resolveResult({ code, out, err }); });
  });
}
async function fakeBandit(top: string, mode: 'complete' | 'omit' | 'error') {
  const path = join(top, `owned-bandit-${mode}`), trace = join(top, `bandit-${mode}-argv.json`);
  // This executable is outside the scanned root. Root executes the suite; the
  // independent author never executes the fake provider or target sources.
  await writeFile(path, '#!/usr/bin/env node\n' + `const fs=require('node:fs');
const files=process.argv.slice(process.argv.indexOf('--')+1); fs.writeFileSync(${JSON.stringify(trace)},JSON.stringify(files));
const selected=${JSON.stringify(mode)}==='omit'?files.slice(0,-1):files;
const metrics={_totals:{loc:4}}; for(const file of selected) metrics[file]={loc:2};
process.stdout.write(JSON.stringify({generated_at:'2026-10-13T00:00:00Z',metrics,results:[],errors:${JSON.stringify(mode)}==='error'?[{filename:files[0],reason:'owned parse failure'}]:[]}));\n`);
  await chmod(path, 0o700); return { path, trace };
}

test('code coverage independent: unrelated JS cannot hide an unselected Python input', async t => {
  const top = await workspace(t), py = await source(top, { 'app.py': PYTHON + `# ${CANARY}\n` }, 'python');
  const mixed = await source(top, { 'app.py': PYTHON + `# ${CANARY}\n`, 'boot.js': JS }, 'mixed');
  for (const [root, total, legacy] of [[py, 1, 2], [mixed, 2, 0]] as const) {
    for (const required of [false, true]) {
      const result = await scan(root, required), value = evidence(result.checks);
      assert.equal(value.requireCodeAnalysis, required); assert.equal(value.accounting, 'exact'); assert.equal(value.collectionComplete, true);
      assert.equal(value.totals.collected, total); assert.equal(row(value, 'python').collected, 1);
      assert.equal(row(value, 'python').eligible, 0); assert.equal(row(value, 'python').completed, 0); assert.equal(row(value, 'python').uncovered, 1);
      assert.equal(provider(value, 'python', 'bandit').selected, false); assert.equal(provider(value, 'python', 'bandit').status, 'not_selected');
      assert.equal(result.checks.find(c => c.id === 'source.inventory')?.metrics?.codeFilesSelected, total);
      gate(result.report, required ? 2 : legacy); gate(result.report, required ? 2 : legacy, 'none');
      assert.equal(JSON.stringify(value).includes(CANARY), false);
    }
  }
});

test('code coverage independent: complete input admission preserves risky and fixed semantic gates', async t => {
  const top = await workspace(t);
  for (const [name, text, expected] of [
    ['risky', "export function route(req){db.query(req.query.sql)}", 1],
    ['fixed', "export function route(req){db.query('SELECT id FROM owned_rows WHERE id = $1',[req.query.id])}", 0],
  ] as const) {
    const root = await source(top, { 'route.ts': text }, name), result = await scan(root, true), value = evidence(result.checks);
    assert.deepEqual(value.totals, { collected: 1, eligible: 1, completed: 1, uncovered: 0 });
    assert.equal(provider(value, 'typescript', 'builtin_ast').completed, 1); gate(result.report, expected);
    gate(createReport(result.checks, 'source', NOW), expected);
    assert.equal(result.checks.find(c => c.id === 'source.builtin-ast')!.findings.some(f => f.ruleId === 'ast:sql-input-sink'), expected === 1);
    const agent = toAgentReport(result.report);
    assert.ok(agent.findings.every(f => !f.verification.vulnerabilityConfirmed && !f.verification.remediationVerified));
  }
  // Strict typed SDK proof does not require an invented scope. CLI handoff does
  // preserve its declared policy and accepts the new informational fourth check.
  const handoffRoot = await source(top, { 'route.ts': "function route(req){db.query('SELECT '+req.query.sql)}\n" }, 'handoff-source');
  const before = join(top, 'handoff-before'), after = join(top, 'handoff-after'), packet = join(top, 'handoff'), finish = join(top, 'handoff-finish');
  const args = ['scan', '--source', handoffRoot, '--tools', 'none', '--require-code-analysis', '--project-id', 'owned/strict-handoff'];
  assert.equal((await captured(() => main([...args, '--out', before]))).code, 1);
  const original = await readFile(join(before, 'report.json'), 'utf8'), originalAgent = await readFile(join(before, 'agent-report.json'), 'utf8');
  const selected = JSON.parse(originalAgent).findings.find((f: any) => f.ruleId === 'ast:sql-input-sink'); assert.ok(selected);
  assert.equal((await captured(() => main(['handoff', 'create', '--report', before, '--source', handoffRoot,
    '--finding', selected.findingId, '--check-index', String(selected.checkIndex), '--out', packet]))).code, 0);
  await writeFile(join(handoffRoot, 'route.ts'), "function route(req){db.query('SELECT id FROM owned_rows WHERE id = $1',[req.query.id])}\n");
  assert.equal((await captured(() => main([...args, '--out', after]))).code, 0);
  assert.equal((await captured(() => main(['handoff', 'finish', '--handoff', packet, '--report', after, '--source', handoffRoot, '--out', finish]))).code, 0);
  assert.equal(await readFile(join(before, 'report.json'), 'utf8'), original);
  assert.equal(await readFile(join(before, 'agent-report.json'), 'utf8'), originalAgent);
});

test('code coverage independent: Bandit completion requires every actual selected input; native refusal cannot cover Python', async t => {
  const top = await workspace(t), root = await source(top, { 'boot.js': JS, 'one.py': 'print("one")\n', 'two.py': 'print("two")\n' });
  for (const mode of ['complete', 'omit', 'error'] as const) {
    const fake = await fakeBandit(top, mode);
    const result = await scan(root, true, { tools: ['bandit'], toolPaths: { bandit: fake.path }, timeoutMs: 5000 });
    const value = evidence(result.checks), p = provider(value, 'python', 'bandit');
    const actual = JSON.parse(await readFile(fake.trace, 'utf8'));
    assert.equal(actual.length, 2); assert.deepEqual(actual.map((path: string) => path.split('/').at(-1)).sort(), ['one.py', 'two.py']);
    assert.equal(p.selected, true); assert.equal(p.eligible, 2); assert.equal(p.completed, mode === 'complete' ? 2 : 0);
    assert.equal(row(value, 'python').uncovered, mode === 'complete' ? 0 : 2); gate(result.report, mode === 'complete' ? 0 : 2);
  }
  const missing = await scan(root, true, { tools: ['bandit'], toolPaths: { bandit: join(top, 'missing-provider') } });
  assert.equal(provider(evidence(missing.checks), 'python', 'bandit').completed, 0); gate(missing.report, 2, 'none');
  const native = await scan(root, true, { nativePreview: { executable: join(top, 'missing-native') } });
  assert.equal(provider(evidence(native.checks), 'python', 'opengrep_native').selected, true);
  assert.equal(provider(evidence(native.checks), 'python', 'opengrep_native').completed, 0); gate(native.report, 2);
});

test('code coverage independent: unsupported code differs from unselected Python; advisory-only intent stays explicit', async t => {
  const top = await workspace(t), root = await source(top, {
    'boot.js': JS, 'app.py': PYTHON, 'Widget.vue': '<template><div>owned</div></template>\n', 'Legacy.java': 'class Legacy {}\n',
  });
  for (const required of [false, true]) {
    const result = await scan(root, required), value = evidence(result.checks);
    assert.deepEqual(value.languages.map((r: any) => r.language), ['javascript', 'python', 'java', 'vue']);
    assert.deepEqual(value.totals, { collected: 4, eligible: 1, completed: 1, uncovered: 3 });
    for (const language of ['java', 'vue']) { assert.equal(row(value, language).eligible, 0); assert.equal(row(value, language).completed, 0); }
    gate(result.report, required ? 2 : 0);
  }
  const pyRoot = await source(top, { 'app.py': 'print("normal")\n', 'poetry.lock': '[[package]]\nname="owned-package"\nversion="1.0.0"\n' }, 'advisory');
  const executable = join(top, 'owned-osv');
  await writeFile(executable, '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({results:[{source:{path:"poetry.lock",type:"lockfile"},packages:[{package:{name:"owned-package",ecosystem:"PyPI",version:"1.0.0"},vulnerabilities:[]}]}]}));\n');
  await chmod(executable, 0o700);
  for (const required of [false, true]) {
    const result = await scan(pyRoot, required, { tools: ['osv'], toolPaths: { osv: executable }, timeoutMs: 5000 });
    assert.equal(result.checks.find(c => c.id === 'source.osv')?.status, 'completed');
    assert.equal(evidence(result.checks).totals.completed, 0); gate(result.report, required ? 2 : 0);
  }
  const assets = await source(top, { 'readme.md': 'Owned documentation only.\n' }, 'assets');
  const assetResult = await scan(assets, true); assert.equal(evidence(assetResult.checks).totals.collected, 0); gate(assetResult.report, 2, 'none');
  const assetDefault = await scan(assets);
  gate(report(assetDefault.checks.filter(c => c.id === ID || c.id === 'source.inventory')), 2, 'none');
});

test('code coverage independent: missing, malformed and contradictory SDK evidence cannot become strict pass', async t => {
  const top = await workspace(t), root = await source(top, { 'boot.js': JS });
  const result = await scan(root, true), base = result.report as any; gate(base, 0);
  const mutations: Array<(r: any) => void> = [
    r => { r.checks = r.checks.filter((c: any) => c.id !== ID); },
    r => { delete r.checks.find((c: any) => c.id === ID).codeCoverage; },
    r => { r.checks.push(copy(r.checks.find((c: any) => c.id === ID))); },
    r => { r.checks.find((c: any) => c.id === ID).id = 'fixture:unrelated'; },
    r => { r.checks.find((c: any) => c.id === ID).codeCoverage.languages[0].language = 'unbounded'; },
    r => { const c = r.checks.find((c: any) => c.id === ID).codeCoverage; c.languages.push(copy(c.languages[0])); },
    r => { r.checks.find((c: any) => c.id === ID).codeCoverage.totals.collected = -1; },
    r => { r.checks.find((c: any) => c.id === ID).codeCoverage.languages = []; },
    r => { r.checks.find((c: any) => c.id === ID).codeCoverage.collectionComplete = false; },
    r => { const c = r.checks.find((c: any) => c.id === 'source.builtin-ast'); c.status = 'partial'; c.notes = ['completed all files']; c.metrics.filesAnalyzed = 1; },
    r => { r.checks.find((c: any) => c.id === 'source.inventory').metrics.codeFilesSelected = 0; },
    r => { r.checks.find((c: any) => c.id === ID).codeCoverage.extraBody = CANARY; },
    r => { r.checks.find((c: any) => c.id === ID).codeCoverage.requireCodeAnalysis = false; },
    r => { r.scope.codeAnalysisPolicy.requireCodeAnalysis = false; },
    r => { r.scope.codeAnalysisPolicy.revision = 'unknown'; },
    ...[{}, [], null, 5].map(status => (r: any) => { r.checks.find((c: any) => c.id === ID).codeCoverage.languages[0].providers[0].status = status; }),
  ];
  for (const mutate of mutations) {
    const raw = copy(base); mutate(raw); const safe = sanitiseReport(raw);
    gate(safe, 2); gate(safe, 2, 'none');
    const formats = [JSON.stringify(safe), JSON.stringify(toAgentReport(raw)), toMarkdown(raw), JSON.stringify(toSarif(raw))];
    for (const text of formats) assert.equal(text.includes(CANARY), false);
    assert.equal(safe.checks.find(c => c.id === ID)?.status, 'partial');
    assert.match(toMarkdown(raw), /Scan gate: incomplete; exit 2/);
    assert.equal(toSarif(raw).runs[0].invocations[0].executionSuccessful, false);
    let comparison: ReturnType<typeof compareReports> | undefined;
    try { comparison = compareReports(base, raw); }
    catch (error) { assert.ok(error instanceof Error); assert.equal(error.message, 'Invalid scan report'); }
    if (comparison) assert.equal(comparison.comparable, false);
  }
  const malformedDefault = copy(base); delete malformedDefault.scope.codeAnalysisPolicy;
  malformedDefault.checks.find((c: any) => c.id === ID).codeCoverage.requireCodeAnalysis = false;
  malformedDefault.checks.find((c: any) => c.id === ID).codeCoverage.totals.completed = 99; gate(malformedDefault, 2, 'none');
  for (const invalid of ['true', 1, null]) gate((await scan(root, false, { requireCodeAnalysis: invalid })).report, 2);
  for (const inheritedPolicy of [true, false]) {
    const inherited = Object.assign(Object.create({ requireCodeAnalysis: inheritedPolicy }), { root, tools: [] });
    const checks = await runSource(inherited);
    assert.equal(checks.find(c => c.id === 'source.options')?.status, 'error', 'inherited policy must be refused rather than erased');
    gate(createReport(checks, 'source', NOW), 2, 'none');
  }
  let invoked = false;
  const callable = Object.assign(() => { invoked = true; }, { root, tools: [], requireCodeAnalysis: true });
  const callableChecks = await runSource(callable as any);
  assert.equal(callableChecks.find(c => c.id === 'source.options')?.status, 'error', 'callable SDK options must not erase strict intent');
  gate(createReport(callableChecks, 'source', NOW), 2, 'none'); assert.equal(invoked, false);
  const partial = await scan(await source(top, { 'a.js': JS, 'b.py': 'print("normal")\n' }, 'limited'), true, { maxFiles: 1 });
  assert.equal(evidence(partial.checks).collectionComplete, false); gate(partial.report, 2, 'none');
  let read = false; const raw = copy(base), value = raw.checks.find((c: any) => c.id === ID).codeCoverage;
  Object.defineProperty(value, 'languages', { enumerable: true, get() { read = true; throw Error('must not read accessor'); } });
  gate(raw, 2); assert.equal(read, false);
  const proxied = copy(base);
  proxied.checks.find((c: any) => c.id === ID).codeCoverage = new Proxy(copy(evidence(result.checks)), { get() { read = true; throw Error('must not inspect proxy'); } });
  gate(proxied, 2); assert.equal(read, false);
  const unknown = copy(base), unknownValue = unknown.checks.find((c: any) => c.id === ID).codeCoverage;
  unknownValue.accounting = 'unknown'; for (const key of Object.keys(unknownValue.totals)) unknownValue.totals[key] = null;
  gate(unknown, 2, 'none');
});

test('code coverage independent: doctor, init, CLI and actual Action preserve policy and all consumers receive the denominator', async t => {
  const top = await workspace(t), root = await source(top, { 'boot.js': JS, 'app.py': PYTHON + `# ${CANARY}\n` });
  const doctor = await captured(() => doctorMain(['doctor', '--source', root, '--tools', 'none', '--json', '--require-code-analysis']));
  assert.equal(doctor.code, 0); assert.match(JSON.parse(doctor.out).nextCommand, /--require-code-analysis/);
  const init = await captured(() => initMain(['init', '--source', root, '--tools', 'none', '--require-code-analysis']));
  assert.equal(init.code, 0); assert.match(await readFile(join(root, '.github/workflows/wakeio-security-ci.yml'), 'utf8'), /--require-code-analysis/);
  // Generated workflow is configuration, never imported or executed by this test.
  await rm(join(root, '.github'), { recursive: true });
  const result = await scan(root, true), value = evidence(result.checks), agent = toAgentReport(result.report) as any;
  assert.deepEqual(copy((toReportSummary(result.report) as any).scope.codeCoverage), copy(value));
  assert.deepEqual(copy(agent.checks.find((c: any) => c.checkId === ID).codeCoverage), copy(value));
  const advice = projectAdviceContext(agent, false).input as any;
  assert.deepEqual(copy(advice.checks.find((c: any) => c.checkId === ID).codeCoverage), copy(value));
  const formats = join(top, 'formats'); await writeReports(result.report, formats, { failOn: 'none' });
  const json = await readFile(join(formats, 'report.json'), 'utf8'), projected = JSON.parse(await readFile(join(formats, 'agent-report.json'), 'utf8'));
  assert.equal(projected.reportArtifact.digest, sha(json)); assert.equal(projected.scanGate.exitCode, 2);
  assert.match(await readFile(join(formats, 'report.md'), 'utf8'), /python/i);
  assert.ok(JSON.stringify(toSarif(result.report)).includes('collected_code_inputs'));
  for (const name of ['report.json', 'agent-report.json', 'report.md', 'report.sarif']) assert.equal((await readFile(join(formats, name), 'utf8')).includes(CANARY), false);
  const inputs = { mode: 'source', source: root, tools: [], projectId: 'owned-coverage', ruleset: 'owned-coverage-independent' };
  const defaultScope = await buildScanScope(inputs as any), strictScope = await buildScanScope({ ...inputs, requireCodeAnalysis: true } as any);
  assert.notEqual(defaultScope.fingerprint, strictScope.fingerprint);
  const a = createReport(result.checks, 'source', NOW, defaultScope), b = createReport(result.checks, 'source', NOW, strictScope);
  assert.equal(compareReports(a, b).comparable, false);
  for (const required of [false, true]) {
    const out = join(top, `cli-${required}`), args = ['scan', '--source', root, '--tools', 'none', '--fail-on', 'none', '--out', out];
    if (required) args.push('--require-code-analysis'); const cli = await captured(() => main(args)); assert.equal(cli.code, required ? 2 : 0);
    assert.equal(JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8')).scanGate.exitCode, required ? 2 : 0);
  }
  const clean = await source(top, { 'boot.js': JS }, 'clean');
  for (const [input, required, expected] of [[root, false, 0], [root, true, 2], [clean, true, 0]] as const) {
    const out = join(top, `action-${required}-${expected}`), gh = join(top, `gh-${required}-${expected}`); await writeFile(gh, '');
    const actual = await child(resolve('scripts/action-run.mjs'), { ...process.env, GITHUB_WORKSPACE: top, GITHUB_OUTPUT: gh,
      WAKEIO_ACTION_PATH: process.cwd(), WAKEIO_SOURCE: input, WAKEIO_TOOLS: 'none', WAKEIO_OUT: out,
      WAKEIO_FAIL_ON: 'none', WAKEIO_REQUIRE_CODE_ANALYSIS: String(required), WAKEIO_TIMEOUT_MS: '5000' });
    assert.equal(actual.code, expected, 'actual bundled Action lost strict code-analysis gate');
    const outputs = Object.fromEntries((await readFile(gh, 'utf8')).trim().split('\n').map(line => { const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)]; }));
    assert.equal(outputs['exit-code'], String(expected));
    const published = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
    assert.equal(published.scanGate.exitCode, expected); assert.equal(published.checks.find((c: any) => c.checkId === ID).codeCoverage.requireCodeAnalysis, required);
  }
  assert.equal((await captured(() => main(['scan', '--url', 'https://owned.invalid', '--require-code-analysis']))).code, 2);
  assert.equal((await captured(() => main(['scan', '--source', root, '--tools', 'none', '--require-code-analysis', '--require-code-analysis']))).code, 2);
});
