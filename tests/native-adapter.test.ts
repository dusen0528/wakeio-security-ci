import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main, parseCliArgs } from '../src/cli.js';
import { runSource } from '../src/source.js';
import { createReport, exitCode, sanitiseReport, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';
import { buildScanScope } from '../src/scan-scope.js';
import { NATIVE_DENY_POLICY, nativeCheckFromProcess, nativeFiles, nativeSandboxCommand, parseNativeOutput, verifyNativePostRun } from '../src/source/opengrep.js';
import { OWN_RULE_IDS, OWN_RULES, OWN_RULES_SHA256 } from '../src/source/opengrep-rules.js';
import type { CollectedFile, ProcessResult, SourceSnapshot } from '../src/source/types.js';

const stage = '/private/owned-native-stage';
const text = 'const q = req.query.x;\ndb.query(q);\n';
const file: CollectedFile = { path: 'app.js', text, bytes: Buffer.byteLength(text), category: 'code', sensitive: false };
function location(source: string, part: string, path = join(stage, 'app.js')) {
  const startIndex = source.indexOf(part), endIndex = startIndex + part.length;
  const point = (index: number) => { const prefix = source.slice(0, index), last = prefix.lastIndexOf('\n'); return {
    offset: Buffer.byteLength(prefix), line: prefix.split('\n').length, col: Buffer.byteLength(prefix.slice(last + 1)) + 1 }; };
  return { path, start: point(startIndex), end: point(endIndex) };
}
function output(source = text, path = join(stage, 'app.js')) {
  const sink = location(source, 'q);', path); sink.end = { ...sink.start, offset: sink.start.offset + 1, col: sink.start.col + 1 };
  const origin = location(source, 'req.query.x', path), intermediate = location(source, 'q =', path);
  intermediate.end = { ...intermediate.start, offset: intermediate.start.offset + 1, col: intermediate.start.col + 1 };
  return { version: '1.30.0', errors: [] as unknown[], paths: { scanned: [path] as unknown[] }, skipped_rules: [] as unknown[], interfile_languages_used: [],
    results: [{ check_id: OWN_RULE_IDS[0], ...sink, extra: { message: 'RAW_CANARY', lines: source, metavars: { '$1': { abstract_content: 'RAW_CANARY', start: { offset: 0 } } },
      metadata: { license: 'Apache-2.0' }, severity: 'ERROR', is_ignored: false, validation_state: 'NO_VALIDATOR', engine_kind: 'OSS',
      dataflow_trace: { taint_source: ['CliLoc', [origin, 'req.query.x']], intermediate_vars: [{ location: intermediate, content: 'q' }], taint_sink: ['CliLoc', [sink, 'q']] } } }] };
}
const completedProcess = (stdout: string, exitCode = 1): ProcessResult => ({ stdout, stderr: '', exitCode, signal: null, timedOut: false, outputLimitExceeded: false,
  exited: true, closeConfirmed: true, cleanupConfirmed: true, cleanupState: 'terminated', rss: { assessment: 'measured', samples: 1, failedSamples: 0, peakBytes: 1024, capBytes: 512 * 1024 * 1024 } });
const parse = (data: unknown, code = 1) => parseNativeOutput(JSON.stringify(data), code, stage, [file]);

test('native own pack hash and CLI opt-in preserve defaults and reject ambiguous paths', () => {
  assert.equal(createHash('sha256').update(OWN_RULES).digest('hex'), OWN_RULES_SHA256);
  const options = parseCliArgs(['scan', '--source', '/source', '--tools', 'none', '--opengrep-core', '/owned/core']);
  assert.ok(!('help' in options)); assert.deepEqual(options.nativePreview, { executable: '/owned/core' }); assert.deepEqual(options.tools, []);
  for (const args of [ ['scan', '--url', 'https://example.test', '--opengrep-core', '/core'], ['scan', '--source', '/source', '--opengrep-core'],
    ['scan', '--source', '/source', '--opengrep-core', 'core'], ['scan', '--source', '/source', '--opengrep-core='] ]) assert.throws(() => parseCliArgs(args));
  const defaults = parseCliArgs(['scan', '--source', '/source']); assert.ok(!('help' in defaults)); assert.equal(defaults.nativePreview, undefined);
});

test('native valid JSON creates position-only candidate with no duplicate sink or invented edge', () => {
  const check = parse(output()); assert.equal(check.status, 'completed'); assert.equal(check.findings.length, 1);
  assert.equal(check.findings[0].confidence, 'low'); assert.equal(check.findings[0].kind, 'candidate');
  assert.deepEqual(check.findings[0].staticFlow?.steps.map((step) => step.role), ['source', 'intermediate', 'sink']);
  assert.equal(check.findings[0].staticFlow?.truncated, true); assert.equal(JSON.stringify(check).includes('RAW_CANARY'), false);
  assert.equal(JSON.stringify(check).includes('req.query.x'), false); assert.equal(JSON.stringify(check).includes(stage), false);
});

test('native OP01 error, OP02 missing coverage and OP04 ignored/exit0 retain valid candidates but gate2 even none', () => {
  for (const kind of ['errors', 'coverage', 'ignored'] as const) {
    const raw = output(); if (kind === 'errors') raw.errors.push({ message: 'RAW_CANARY' });
    if (kind === 'coverage') raw.paths.scanned = [];
    if (kind === 'ignored') raw.results[0].extra.is_ignored = true;
    const check = parse(raw, kind === 'ignored' ? 0 : 1);
    assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 1);
    const report = createReport([check], 'source', '2026-10-05T00:00:00.000Z'); assert.equal(exitCode(report, 'none'), 2); assert.equal(toAgentReport(report, 'none').scanGate.exitCode, 2);
    assert.equal(JSON.stringify(report).includes('RAW_CANARY'), false);
  }
});

test('native incomplete schema, duplicates, skips, unknown fields and exit contradictions cannot become clean', () => {
  for (const edit of [ (raw: any) => delete raw.paths, (raw: any) => delete raw.errors, (raw: any) => raw.skipped_rules.push({ id: 'skip' }),
    (raw: any) => raw.paths.skipped = [{ reason: 'unknown' }], (raw: any) => raw.paths.scanned.push(raw.paths.scanned[0]),
    (raw: any) => raw.unknown = 'opaque', (raw: any) => raw.results[0].check_id = 'foreign.rule', (raw: any) => raw.results[0].start.offset = -1 ]) {
    const raw = output(); edit(raw); assert.notEqual(parse(raw).status, 'completed');
  }
  assert.equal(parseNativeOutput('{"version":"x","version":"1.30.0"}', 0, stage, [file]).status, 'error');
  assert.equal(parseNativeOutput('{"x":1e999}', 0, stage, [file]).status, 'error');
  assert.equal(parse(output(), 0).status, 'partial'); const empty = output(); empty.results = []; assert.equal(parse(empty, 1).status, 'partial');
});

test('native paths, byte offsets and intrafile trace are validated; absent trace remains unavailable', () => {
  const absent: any = output(); delete absent.results[0].extra.dataflow_trace;
  assert.equal(parse(absent).status, 'completed'); assert.equal(parse(absent).findings[0].staticFlow, undefined);
  const invalid: any = output(); invalid.results[0].extra.dataflow_trace.taint_source[1][0].path = '/outside/app.js';
  assert.equal(parse(invalid).status, 'partial'); assert.equal(parse(invalid).findings.length, 1); assert.equal(parse(invalid).findings[0].staticFlow, undefined);
  const other: any = output(); other.results[0].extra.dataflow_trace.taint_source[1][0].path = join(stage, 'second.js');
  assert.equal(parseNativeOutput(JSON.stringify(other), 1, stage, [file, { ...file, path: 'second.js' }]).metrics?.incompleteReasons.toString().includes('invalid_trace'), true);
  const outside: any = output(); outside.results[0].path = '/outside/app.js'; assert.equal(parse(outside).findings.length, 0);
  const unicode = 'const label="가😀"; const q = req.query.x;\ndb.query(q);\n', ufile = { ...file, text: unicode, bytes: Buffer.byteLength(unicode) };
  const ucheck = parseNativeOutput(JSON.stringify(output(unicode)), 1, stage, [ufile]); assert.equal(ucheck.status, 'completed');
  assert.equal(ucheck.findings[0].staticFlow?.steps[0].location.column, unicode.indexOf('req.query.x') + 1);
  const wrong: any = output(unicode); wrong.results[0].extra.dataflow_trace.taint_source[1][0].start.col--;
  assert.equal(parseNativeOutput(JSON.stringify(wrong), 1, stage, [ufile]).status, 'partial');
});

test('native trace cap preserves one terminal sink and never promotes verification in four projections', async () => {
  const raw = output(); const intermediate = raw.results[0].extra.dataflow_trace.intermediate_vars[0];
  raw.results[0].extra.dataflow_trace.intermediate_vars = Array.from({ length: 30 }, () => intermediate);
  const report = createReport([parse(raw)], 'source', '2026-10-05T00:00:00.000Z'); report.finishedAt = report.startedAt;
  const safe = sanitiseReport(report); assert.deepEqual(sanitiseReport(safe), safe);
  assert.equal(safe.checks[0].findings[0].staticFlow?.steps.length, 24);
  assert.equal(safe.checks[0].findings[0].staticFlow?.steps.filter((step) => step.role === 'sink').length, 1);
  const agent = toAgentReport(safe); assert.equal(agent.findings[0].evidence.traceStatus, 'static_truncated');
  assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false); assert.equal(agent.findings[0].remediation.state, 'not_verified');
  assert.match(toMarkdown(safe), /intermediate/); assert.match(JSON.stringify(toSarif(safe)), /codeFlows/);
  const out = await mkdtemp(join(tmpdir(), 'wakeio-native-reports-'));
  try { await writeReports(report, out); for (const name of ['report.json', 'report.sarif', 'report.md', 'agent-report.json']) {
    const rendered = await readFile(join(out, name), 'utf8'); assert.equal(rendered.includes('RAW_CANARY'), false); assert.equal(rendered.includes(stage), false);
  } } finally { await rm(out, { recursive: true, force: true }); }
});

test('native operational unknown/timeout/cancel/output/cleanup takes priority over a valid report', () => {
  for (const edit of [ (p: ProcessResult) => p.timedOut = true, (p: ProcessResult) => p.cancelled = true, (p: ProcessResult) => p.outputLimitExceeded = true, (p: ProcessResult) => p.signal = 'SIGTERM',
    (p: ProcessResult) => p.cleanupConfirmed = false, (p: ProcessResult) => p.cleanupState = 'running', (p: ProcessResult) => p.closeConfirmed = false,
    (p: ProcessResult) => p.rss!.assessment = 'unassessed', (p: ProcessResult) => p.rss!.capBytes = 2 * 1024 * 1024 * 1024 ]) {
    const p = completedProcess(JSON.stringify(output())); edit(p); const check = nativeCheckFromProcess(p, stage, [file], true);
    assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 1); assert.equal(exitCode(createReport([check], 'source', '2026-10-05T00:00:00.000Z'), 'none'), 2);
  }
  assert.equal(nativeCheckFromProcess(completedProcess(JSON.stringify(output())), stage, [file], false).status, 'partial');
});

test('native post identity read/deletion/symlink failures revoke completed while preserving valid candidate', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-native-post-'));
  try {
    const staged = join(top, 'snapshot'); await mkdir(staged); await writeFile(join(staged, file.path), file.text);
    const pack = join(top, 'pack'); await writeFile(pack, OWN_RULES);
    const policy = join(top, 'policy'); await writeFile(policy, NATIVE_DENY_POLICY);
    for (const mode of ['missing', 'link'] as const) {
      const engine = join(top, `engine-${mode}`); if (mode === 'link') await symlink(pack, engine);
      const check = parse(output()); assert.equal(check.status, 'completed');
      await verifyNativePostRun(check, staged, [file], pack, policy, engine);
      assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 1); assert.match(String(check.metrics?.incompleteReasons), /identity_changed/);
    }
    await rm(pack); const check = parse(output()); await verifyNativePostRun(check, staged, [file], pack, policy, '/absent/core'); assert.equal(check.status, 'partial');
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('native input policy excludes config/secret/non-language inputs and wrapper is fixed offline', () => {
  const snapshot: SourceSnapshot = { root: '/root', files: [file, { ...file, path: '.semgrepignore', category: 'text' }, { ...file, path: '.env', category: 'secret', sensitive: true },
    { ...file, path: 'package.json', category: 'dependency' }, { ...file, path: 'app.py' }], issues: [], ignoredFiles: 0, totalBytes: 0, complete: true };
  assert.deepEqual(nativeFiles(snapshot).map((f) => f.path), ['app.js', 'app.py']);
  assert.deepEqual(nativeSandboxCommand('/owned/deny', '/owned/core', ['scan']), { executable: '/usr/bin/sandbox-exec', args: ['-f', '/owned/deny', '/owned/core', 'scan'] });
  assert.match(NATIVE_DENY_POLICY, /deny network/); assert.throws(() => nativeSandboxCommand('relative', '/core', []));
});

test('SDK pre-abort starts no scanner and pin/symlink failures cannot execute an owned fake', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-native-pin-'));
  try {
    const root = join(top, 'source'); await mkdir(root); await writeFile(join(root, 'app.py'), 'print("safe")\n');
    const marker = join(top, 'executed'), fake = join(top, 'core');
    await writeFile(fake, '#!/bin/sh\ntouch "' + marker + '"\n'); await chmod(fake, 0o700);
    const controller = new AbortController(); controller.abort();
    const aborted = await runSource({ root, tools: [], nativePreview: { executable: fake }, signal: controller.signal });
    assert.equal(aborted[0].status, 'partial'); await assert.rejects(readFile(marker));
    for (const path of [fake, join(top, 'link')]) {
      if (path.endsWith('link')) await symlink(fake, path);
      const checks = await runSource({ root, tools: [], nativePreview: { executable: path } });
      const native = checks.find((check) => check.id === 'source.opengrep.preview'); assert.equal(native?.status, 'error');
      assert.equal(checks.find((check) => check.id === 'source.builtin-ast')?.status, 'not_applicable');
      assert.ok(checks[0].notes.some((note) => note.includes('native preview remains selected')));
      assert.equal(exitCode(createReport(checks, 'source', '2026-10-05T00:00:00.000Z'), 'none'), 2); await assert.rejects(readFile(marker));
    }
    const base = { mode: 'source' as const, source: root, tools: [], ruleset: '2026-10-05.3' };
    const before = await buildScanScope(base), selected = await buildScanScope({ ...base, nativePreview: { executable: fake } });
    assert.notEqual(before.fingerprint, selected.fingerprint); assert.equal(selected.provenance?.engines?.[0].status, 'unknown');
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('command cancellation after native preflight cannot return completed through a later scanner', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-native-command-'));
  try {
    const root = join(top, 'source'), out = join(top, 'out'), fake = join(top, 'gitleaks'); await mkdir(root); await writeFile(join(root, 'app.py'), 'print("safe")\n');
    await writeFile(fake, '#!' + process.execPath + '\nprocess.kill(process.ppid,"SIGTERM");setTimeout(()=>{process.stdout.write("[]");},200);\n'); await chmod(fake, 0o700);
    const previous = process.listenerCount('SIGTERM');
    const code = await main(['scan', '--source', root, '--tools', 'gitleaks', '--gitleaks', fake, '--opengrep-core', '/missing/core', '--fail-on', 'none', '--out', out]);
    assert.equal(code, 2); assert.equal(process.listenerCount('SIGTERM'), previous);
    const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8')); assert.ok(report.checks.some((check: any) => check.id === 'scan.cancelled' && check.status === 'partial'));
    const agent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8')); assert.equal(agent.scanGate.exitCode, 2);
  } finally { await rm(top, { recursive: true, force: true }); }
});
