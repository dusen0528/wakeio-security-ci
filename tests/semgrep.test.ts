import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { collectSource } from '../src/source/collector.js';
import { parseSemgrepOutput, runSemgrep, semgrepFiles } from '../src/source/semgrep.js';
import { codeCoverageCheck, codeCoverageConsistent, collectedCodeMetrics, parseCodeCoverage } from '../src/source/code-coverage.js';
import type { CheckResult } from '../src/contracts.js';
import type { CollectedFile } from '../src/source/types.js';

const RISKY = `package app
import("database/sql";"net/http";"html/template";"crypto/tls";"os/exec";"os";"path/filepath")
func handler(w http.ResponseWriter,r *http.Request,db *sql.DB){
q := r.URL.Query().Get("q")
db.Query("SELECT * FROM users WHERE id=" + q)
_ = template.HTML(r.FormValue("html"))
_ = &tls.Config{InsecureSkipVerify:true}
_ = exec.Command("sh", "-c", r.FormValue("cmd"))
http.Get(r.Header.Get("X-Callback"))
os.ReadFile(filepath.Join("/srv/files", r.PathValue("file")))
}
`;
const FIXED = `package app
import("database/sql";"net/http";"html/template";"crypto/tls";"os/exec";"os";"strings")
func handler(w http.ResponseWriter,r *http.Request,db *sql.DB,t *template.Template){
db.Query("SELECT * FROM users WHERE id=$1", r.URL.Query().Get("q"))
t.Execute(w,r.FormValue("html"))
_ = &tls.Config{InsecureSkipVerify:false}
_ = exec.Command("printf", "%s", r.FormValue("cmd"))
http.Post("https://example.test/fixed", "text/plain", strings.NewReader(r.FormValue("body")))
os.ReadFile("/srv/files/public.txt")
root, _ := os.OpenRoot("/srv/files")
root.Open(r.PathValue("file"))
}
`;
const sample: CollectedFile = { path: 'app.go', text: 'package app\nvar x = "한글"\n', bytes: Buffer.byteLength('package app\nvar x = "한글"\n'), category: 'code', sensitive: false };
const envelope = () => ({ version: '1.147.0', results: [] as any[], errors: [] as any[], paths: { scanned: ['app.go'] }, skipped_rules: [] });

async function fixture(t: TestContext, text = RISKY) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-semgrep-test-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const root = join(top, 'source'); await mkdir(root);
  await writeFile(join(root, 'app.go'), text);
  return { top, root, snapshot: await collectSource({ root }) };
}

test('Semgrep output requires complete scanned accounting and no errors', () => {
  const valid = envelope();
  assert.equal(parseSemgrepOutput(JSON.stringify(valid), '/stage', [sample], 0).status, 'completed');
  for (const changed of [ { ...valid, errors: [{ message: 'parse error' }] }, { ...valid, paths: { scanned: [] } }, { ...valid, skipped_rules: [{ id: 'skipped' }] }, { ...valid, paths: { scanned: ['app.go'], skipped: [{}] } } ]) {
    assert.equal(parseSemgrepOutput(JSON.stringify(changed), '/stage', [sample], 0).status, 'partial');
  }
  assert.equal(parseSemgrepOutput(JSON.stringify(valid), '/stage', [sample], 1).status, 'partial');
  assert.equal(parseSemgrepOutput(JSON.stringify(valid), '/stage', [sample], 2).status, 'partial');
});

test('Semgrep rejects malformed envelopes, duplicate identities and out-of-snapshot paths', () => {
  for (const text of ['', '{}', 'not json', '{"version":"1.147.0","errors":[],"errors":[],"paths":{"scanned":[]},"results":[]}']) assert.throws(() => parseSemgrepOutput(text, '/stage', [sample], 0));
  for (const paths of [['app.go', 'app.go'], ['../app.go'], ['/other/app.go'], ['app.go\\evil']]) assert.throws(() => parseSemgrepOutput(JSON.stringify({ ...envelope(), paths: { scanned: paths } }), '/stage', [sample], 0));
});

test('Semgrep validates source byte positions and keeps source and engine messages out of findings', () => {
  const output = envelope();
  const raw = { check_id: 'wakeio.go.sql-request-input', path: 'app.go', start: { line: 2, col: 9, offset: 20 }, end: { line: 2, col: 17, offset: 28 }, extra: { severity: 'ERROR', message: 'DO_NOT_RETAIN_SOURCE', lines: 'DO_NOT_RETAIN_SOURCE', metavars: { '$X': 'DO_NOT_RETAIN_SOURCE' } } };
  // The two Korean characters occupy six bytes; public columns use UTF-16 units.
  output.results = [raw, raw];
  const check = parseSemgrepOutput(JSON.stringify(output), '/stage', [sample], 1);
  assert.equal(check.status, 'completed'); assert.equal(check.findings.length, 1);
  assert.equal(JSON.stringify(check).includes('DO_NOT_RETAIN_SOURCE'), false);
  assert.deepEqual(check.findings[0].location, { path: 'app.go', line: 2, column: 9 });
  for (const mutation of [ { ...raw, check_id: 'unknown' }, { ...raw, start: { line: 9, col: 1, offset: 0 } }, { ...raw, end: raw.start }, { ...raw, start: { line: 2, col: 11, offset: 22 } } ]) {
    assert.throws(() => parseSemgrepOutput(JSON.stringify({ ...output, results: [mutation] }), '/stage', [sample], 1));
  }
});

test('Semgrep subprocess receives only Go inputs and owned config with telemetry disabled', async t => {
  const w = await fixture(t); const trace = join(w.top, 'trace.json'), binary = join(w.top, 'semgrep');
  await writeFile(join(w.root, '.semgrepignore'), '*\n'); await writeFile(join(w.root, '.env'), 'SECRET=DO_NOT_RETAIN_SOURCE\n');
  const snapshot = await collectSource({ root: w.root });
  await writeFile(binary, '#!/usr/bin/env node\n' + `const fs=require('node:fs'),path=require('node:path');const args=process.argv.slice(2),files=args.slice(args.indexOf('--')+1);fs.writeFileSync(${JSON.stringify(trace)},JSON.stringify({args,home:process.env.HOME,config:fs.readFileSync(args[args.indexOf('--config')+1],'utf8'),files:fs.readdirSync(process.cwd())}));process.stdout.write(JSON.stringify({version:'1.147.0',results:[],errors:[],paths:{scanned:files},skipped_rules:[]}));`);
  await chmod(binary, 0o700);
  const result = await runSemgrep({ snapshot, stageDir: w.root, toolPath: binary, timeoutMs: 5000 });
  assert.equal(result.status, 'completed'); assert.equal(result.metrics?.filesAnalyzed, 1);
  const captured = JSON.parse(await readFile(trace, 'utf8'));
  assert.deepEqual(captured.files, ['app.go']);
  assert.equal(captured.args[captured.args.indexOf('--metrics') + 1], 'off');
  for (const flag of ['--oss-only', '--disable-version-check', '--disable-nosem', '--no-git-ignore', '--strict']) assert.ok(captured.args.includes(flag));
  assert.ok(!captured.args.includes('--autofix')); assert.ok(captured.config.includes('Apache-2.0'));
  assert.notEqual(captured.home, process.env.HOME); assert.ok(!captured.config.includes('p/default'));
  await assert.rejects(readFile(captured.args[captured.args.indexOf('--config') + 1]));
  assert.equal((await runSemgrep({ snapshot: { ...snapshot, complete: false }, stageDir: w.root, toolPath: binary, timeoutMs: 5000 })).status, 'partial');
});

test('Semgrep missing, malformed, cancelled and incomplete runs cannot look clean', async t => {
  const w = await fixture(t), binary = join(w.top, 'bad-semgrep');
  const context = { snapshot: w.snapshot, stageDir: w.root, toolPath: binary, timeoutMs: 1000 };
  assert.notEqual((await runSemgrep(context)).status, 'completed');
  await writeFile(binary, '#!/bin/sh\nprintf invalid\n'); await chmod(binary, 0o700);
  assert.equal((await runSemgrep(context)).status, 'error');
  const abort = new AbortController(); abort.abort();
  assert.equal((await runSemgrep({ ...context, signal: abort.signal })).status, 'partial');
  assert.equal((await runSemgrep({ ...context, snapshot: { ...w.snapshot, files: [] } })).status, 'not_applicable');
  assert.equal(semgrepFiles({ ...w.snapshot, files: [{ ...sample, path: 'app.js' }, { ...sample, sensitive: true }] }).length, 0);
  await writeFile(binary, '#!/usr/bin/env node\nsetTimeout(()=>{},10000);\n');
  assert.equal((await runSemgrep({ ...context, timeoutMs: 25 })).status, 'partial');
});

test('Semgrep Go coverage preserves legacy three-provider records and rejects missing selected evidence', async t => {
  const w = await fixture(t);
  const done: CheckResult = { id: 'source.semgrep', status: 'completed', findings: [], notes: [], metrics: { filesRequested: 1, filesAnalyzed: 1, errorCount: 0 } };
  const checks: CheckResult[] = [ { id: 'source.inventory', status: 'completed', findings: [], notes: [], metrics: { ...collectedCodeMetrics(w.snapshot), filesSelected: 1, codeFilesSelected: 1, complete: true, requestedTools: 'semgrep', nativePreviewSelected: false } }, { id: 'source.builtin-ast', status: 'not_applicable', findings: [], notes: [], metrics: { filesAnalyzed: 0, filesParseValid: 0 } }, done ];
  const coverage = codeCoverageCheck(w.snapshot, checks, { tools: ['semgrep'], requireCodeAnalysis: true }).codeCoverage!;
  assert.deepEqual(coverage.totals, { collected: 1, eligible: 1, completed: 1, uncovered: 0 });
  assert.equal(coverage.languages[0].providers.length, 4); assert.ok(parseCodeCoverage(coverage)); assert.equal(codeCoverageConsistent(coverage, checks), true);
  const incomplete = codeCoverageCheck(w.snapshot, [{ ...done, status: 'partial' }], { tools: ['semgrep'], requireCodeAnalysis: true }).codeCoverage!;
  assert.equal(incomplete.totals.completed, 0); assert.equal(incomplete.totals.uncovered, 1);
  const legacy = codeCoverageCheck(w.snapshot, [], { tools: [] }).codeCoverage!;
  assert.equal(legacy.languages[0].providers.length, 3); assert.ok(parseCodeCoverage(legacy));
  assert.equal(codeCoverageConsistent(legacy, checks), false);
  const unsupported = structuredClone(coverage); unsupported.languages[0].language = 'python';
  assert.equal(parseCodeCoverage(unsupported), undefined);
});

test('Semgrep CE real owned Go fixtures detect six risky patterns and reject fixed counterparts', { skip: !process.env.WAKEIO_SEMGREP_TEST_PATH }, async t => {
  const toolPath = resolve(process.env.WAKEIO_SEMGREP_TEST_PATH!);
  for (const [source, expected] of [[RISKY, 6], [FIXED, 0]] as const) {
    const w = await fixture(t, source);
    const result = await runSemgrep({ snapshot: w.snapshot, stageDir: w.root, toolPath, timeoutMs: 30_000 });
    assert.equal(result.status, 'completed', JSON.stringify(result));
    assert.equal(result.findings.length, expected, JSON.stringify(result));
    if (expected) assert.deepEqual(result.findings.map(f => f.ruleId).sort(), ['semgrep:wakeio.go.command-request-input', 'semgrep:wakeio.go.html-request-input', 'semgrep:wakeio.go.insecure-tls', 'semgrep:wakeio.go.path-request-input', 'semgrep:wakeio.go.sql-request-input', 'semgrep:wakeio.go.ssrf-request-input']);
  }
});
