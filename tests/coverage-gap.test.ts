import test from 'node:test';
import assert from 'node:assert/strict';
import * as ts from 'typescript';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { AnalysisGapRecorder, capAnalysisGaps, sanitiseAnalysisGaps } from '../src/analysis-gaps.js';
import type { AnalysisGap, AnalysisGaps, CheckResult } from '../src/contracts.js';
import { runBuiltinAst } from '../src/source/ast.js';
import { observedGapLocation } from '../src/source/dataflow.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';

const started = '2026-10-05T00:00:00.000Z';
const snapshot = (texts: Record<string, string>) => ({ root: '/never-read', files: Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false })), issues: [], ignoredFiles: 0, totalBytes: Object.values(texts).reduce((n, t) => n + Buffer.byteLength(t), 0), complete: true });
const item = (line = 1): AnalysisGap => ({ reason: 'module_missing', phase: 'flow', extent: 'site', observations: 1, location: { path: 'app.ts', line, column: 1 }, nextReview: 'review_collected_source_context' });
const envelope = (items: AnalysisGap[]): AnalysisGaps => ({ accounting: 'exact', items, eventsObserved: items.reduce((n, i) => n + i.observations, 0), eventsDropped: 0, truncated: false });
const check = (gaps?: AnalysisGaps): CheckResult => ({ id: 'fixture', status: 'partial', findings: [], notes: [], ...(gaps ? { analysisGaps: gaps } : {}) });

test('missing supported imports expose actual call positions without specifiers or source text', () => {
  for (const text of ["import { helper } from './not-collected';\nfunction route(req){db.query(helper(req.query.sql))}", "const { helper } = require('./not-collected');\nfunction route(req){db.query(helper(req.query.sql))}"]) {
    const result = runBuiltinAst(snapshot({ 'app.ts': text }), false);
    assert.equal(result.status, 'partial');
    const gap = result.analysisGaps?.items.find(i => i.reason === 'module_missing');
    assert.ok(gap?.location); assert.equal(gap.extent, 'site'); assert.equal(gap.location.line, 2);
    assert.equal(gap.location.column, text.split('\n')[1].indexOf('helper(') + 1);
    assert.equal(gap.location.path, 'app.ts');
    assert.equal(JSON.stringify(result.analysisGaps).includes('not-collected'), false);
    const report = createReport([result], 'source', started);
    for (const failOn of ['high', 'none'] as const) assert.equal(evaluateGate(report, failOn).exitCode, 2);
  }
});

test('ambiguous imports and module budget have call locations; external calls create no new incomplete events', () => {
  const text = "import { helper } from './lib'; function route(req){db.query(helper(req.query.sql))}";
  const files = { 'app.ts': text, 'lib.ts': 'export function helper(x){return x}', 'lib.js': 'export function helper(x){return x}' };
  const ambiguous = runBuiltinAst(snapshot(files), false);
  assert.ok(ambiguous.analysisGaps?.items.some(i => i.reason === 'module_ambiguous' && i.location?.path === 'app.ts'));
  const limited = runBuiltinAst(snapshot({ 'app.ts': text, 'lib.ts': files['lib.ts'] }), false, { ...FLOW_LIMITS, moduleEdges: 0 });
  assert.ok(limited.analysisGaps?.items.some(i => i.reason === 'module_module_budget' && i.extent === 'site'));
  const external = runBuiltinAst(snapshot({ 'app.ts': "import helper from 'external-package'; function route(req){db.query(helper(req.query.sql))}" }), false);
  assert.equal(external.status, 'completed'); assert.equal(external.analysisGaps, undefined);
  const resolved = runBuiltinAst(snapshot({ 'app.ts': text, 'lib.ts': files['lib.ts'] }), false);
  assert.equal(resolved.status, 'completed'); assert.equal(resolved.analysisGaps, undefined);
});

test('index and flow remain check-wide; parser diagnostics expose observed file coordinates', () => {
  for (const [limits, reason] of [[{ ...FLOW_LIMITS, indexWork: 1 }, 'index_work_limit'], [{ ...FLOW_LIMITS, flowWork: 1 }, 'flow_work_limit']] as const) {
    const result = runBuiltinAst(snapshot({ 'app.ts': 'function route(req){db.query(req.query.sql)}' }), false, limits);
    const gap = result.analysisGaps?.items.find(i => i.reason === reason);
    assert.ok(gap); assert.equal(gap.extent, 'check'); assert.equal(gap.location, undefined);
    assert.equal(result.status, 'partial');
  }
  const parsed = runBuiltinAst(snapshot({ 'broken.ts': 'function {', 'app.ts': 'const x=1;' }), false);
  assert.equal(parsed.analysisGaps?.items.find(i => i.reason === 'parse_error')?.observations, parsed.metrics?.parseErrorCount);
  assert.equal(parsed.analysisGaps?.items.find(i => i.reason === 'parse_error')?.location?.path, 'broken.ts');
});

test('producer location requires the exact collected SourceFile and valid actual range', () => {
  const file = ts.createSourceFile('app.ts', 'helper(value);', ts.ScriptTarget.Latest, true);
  const call = (file.statements[0] as ts.ExpressionStatement).expression;
  const files = new Map([['app.ts', file]]);
  assert.deepEqual(observedGapLocation(call, files), { path: 'app.ts', line: 1, column: 1 });
  const other = ts.createSourceFile('app.ts', 'helper(value);', ts.ScriptTarget.Latest, true);
  assert.equal(observedGapLocation((other.statements[0] as ts.ExpressionStatement).expression, files), undefined);
  assert.equal(observedGapLocation(call, new Map([['other.ts', file]])), undefined);
  const bad = { getSourceFile: () => file, getStart: () => file.text.length + 1, getEnd: () => file.text.length + 2 } as unknown as ts.Node;
  assert.equal(observedGapLocation(bad, files), undefined);
});

test('recorder retains first 32 keys, aggregates retained duplicates and accounts dropped events exactly', () => {
  const recorder = new AnalysisGapRecorder();
  for (let line = 1; line <= 35; line++) recorder.record('module_missing', 'flow', item(line).location);
  recorder.record('module_missing', 'flow', item(1).location, 2);
  const gaps = recorder.result()!;
  assert.equal(gaps.items.length, 32); assert.equal(gaps.items[0].observations, 3);
  assert.equal(gaps.eventsObserved, 37); assert.equal(gaps.eventsDropped, 3); assert.equal(gaps.truncated, true);
  gaps.items[0].location!.line = 999;
  assert.equal(recorder.result()!.items[0].location!.line, 1);
  const overflow = new AnalysisGapRecorder(); overflow.record('node_limit', 'index', undefined, Number.MAX_SAFE_INTEGER); overflow.record('node_limit', 'index');
  assert.equal(overflow.result()!.accounting, 'unknown'); assert.equal(overflow.result()!.eventsObserved, null);
});

test('malformed accounting and unsafe numbers cannot become exact empty records', () => {
  const valid = envelope([item()]);
  for (const patch of [{ eventsObserved: -1 }, { eventsObserved: 1.5 }, { eventsDropped: Infinity }, { eventsObserved: '1' }, { eventsObserved: 2 }, { truncated: true }, { items: Array.from({ length: 33 }, () => item()) }, { items: [{ ...item(), reason: 'run_command' }] }]) {
    const cleaned = sanitiseAnalysisGaps({ ...valid, ...patch }, p => p)!;
    assert.equal(cleaned.accounting, 'unknown'); assert.equal(cleaned.eventsObserved, null); assert.equal(cleaned.eventsDropped, null); assert.equal(cleaned.truncated, true);
    assert.deepEqual(sanitiseAnalysisGaps(cleaned, p => p), cleaned);
  }
});

test('invalid site/enums preserve valid rows as unknown; duplicate rows canonicalize with exact sums', () => {
  const good = item();
  for (const bad of [
    { ...item(2), phase: 'execute' }, { ...item(2), extent: 'repo' },
    { ...item(2), reason: 'parse_error' }, { ...item(2), observations: 0 },
    { ...item(2), location: { path: 'app.ts', line: 0, column: 1 } },
    { ...item(2), location: { path: 'app.ts', line: 1, column: Number.MAX_SAFE_INTEGER } },
    { ...item(2), extent: 'check' },
  ]) {
    const cleaned = sanitiseAnalysisGaps({ ...envelope([good]), items: [good, bad], eventsObserved: 2 }, p => p)!;
    assert.equal(cleaned.accounting, 'unknown'); assert.deepEqual(cleaned.items, [good]);
    assert.deepEqual(sanitiseAnalysisGaps(cleaned, p => p), cleaned);
  }
  const canonical = sanitiseAnalysisGaps(envelope([good, { ...good, observations: 2 }]), p => p)!;
  assert.equal(canonical.accounting, 'exact'); assert.equal(canonical.items.length, 1);
  assert.equal(canonical.items[0].observations, 3); assert.equal(canonical.eventsObserved, 3);
  assert.deepEqual(sanitiseAnalysisGaps(canonical, p => p), canonical);
});

test('report sanitation rejects protected paths and canonicalizes actions without retaining raw fields', () => {
  const forbidden = ['/private/app.ts', '../app.ts', 'file:///private/app.ts', 'a\\b.ts', 'ghp_A1b2C3d4E5f6G7h8I9j0/app.ts'];
  for (const path of forbidden) {
    const result = createReport([check(envelope([{ ...item(), location: { path, line: 1, column: 1 } }]))], 'source', started);
    assert.equal(result.checks[0].analysisGaps?.accounting, 'unknown'); assert.equal(result.checks[0].analysisGaps?.items.length, 0);
    assert.equal(JSON.stringify(result).includes(path), false);
  }
  const injected = { ...item(), nextReview: 'execute_remote_command', source: 'private-source', importSpecifier: './private-module' };
  const result = createReport([check(envelope([injected as AnalysisGap]))], 'source', started);
  assert.equal(result.checks[0].analysisGaps?.items[0].nextReview, 'review_collected_source_context');
  assert.equal(JSON.stringify(result).includes('private-source'), false); assert.equal(JSON.stringify(result).includes('private-module'), false);
});

test('global 256-item cap and repeated report/agent sanitation preserve exact accounting and digest', () => {
  const checks = Array.from({ length: 9 }, (_, index) => ({ ...check(envelope(Array.from({ length: 32 }, (_, line) => item(line + 1)))), id: `check-${index}` }));
  const report = createReport(checks, 'source', started);
  assert.equal(report.checks.reduce((n, c) => n + c.analysisGaps!.items.length, 0), 256);
  assert.equal(report.checks[8].analysisGaps!.eventsDropped, 32); assert.equal(report.checks[8].analysisGaps!.eventsObserved, 32);
  assert.equal(report.checks[8].analysisGaps!.items.length, 0);
  assert.deepEqual(sanitiseReport(sanitiseReport(report)), report);
  assert.deepEqual(toAgentReport(report, 'none'), toAgentReport(sanitiseReport(report), 'none'));
  assert.equal(toAgentReport(report, 'none').scanGate.exitCode, 2);
});

test('four artifact projections preserve diagnostic linkage without altering findings or SARIF result identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-gap-report-'));
  const detected = runBuiltinAst(snapshot({ 'app.ts': 'function route(req){db.query(req.query.sql)}' }), false);
  const base = createReport([detected], 'source', started);
  const report = createReport([{ ...detected, analysisGaps: envelope([item()]) }], 'source', started);
  assert.deepEqual(report.checks[0].findings, base.checks[0].findings); assert.deepEqual(evaluateGate(report, 'high'), evaluateGate(base, 'high'));
  const sarif = toSarif(report) as any; const old = toSarif(base) as any;
  assert.deepEqual(sarif.runs[0].results, old.runs[0].results); assert.deepEqual(sarif.runs[0].tool.driver.rules, old.runs[0].tool.driver.rules);
  assert.deepEqual(sarif.runs[0].properties.analysisGaps[0], { checkIndex: 0, checkId: detected.id, analysisGaps: report.checks[0].analysisGaps });
  assert.ok(toMarkdown(report).includes('module\\_missing')); assert.ok(toMarkdown(report).includes('app\\.ts:1:1'));
  try {
    await writeReports(report, root, { failOn: 'high' });
    const bytes = await readFile(join(root, 'report.json')); const json = JSON.parse(bytes.toString());
    const agent = JSON.parse(await readFile(join(root, 'agent-report.json'), 'utf8'));
    assert.deepEqual(json.checks[0].analysisGaps, report.checks[0].analysisGaps); assert.deepEqual(agent.checks[0].analysisGaps, report.checks[0].analysisGaps);
    assert.equal(agent.reportArtifact.digest, createHash('sha256').update(bytes).digest('hex'));
    assert.deepEqual(JSON.parse(await readFile(join(root, 'report.sarif'), 'utf8')).runs[0].properties.analysisGaps, sarif.runs[0].properties.analysisGaps);
    assert.ok((await readFile(join(root, 'report.md'), 'utf8')).includes('module\\_missing'));
  } finally { await rm(root, { recursive: true, force: true }); }
});


test('reason counters retain weighted distribution after key saturation without selecting new items', () => {
  const recorder = new AnalysisGapRecorder();
  for (let line = 1; line <= 35; line++) recorder.record('module_missing', 'flow', item(line).location);
  recorder.record('module_missing', 'flow', item(1).location, 2);
  recorder.record('module_missing', 'flow', item(35).location, 2);
  recorder.record('parse_error', 'parse', undefined, 4);
  recorder.record('module_export_unsupported', 'flow', item(1).location, 3);
  const gaps = recorder.result()!;
  assert.equal(gaps.eventsObserved, 46); assert.equal(gaps.eventsDropped, 12);
  assert.equal(gaps.items.length, 32); assert.equal(gaps.items.reduce((n, i) => n + i.observations, 0), 34);
  assert.deepEqual(gaps.reasonSummary, { accounting: 'exact', rows: [
    { reason: 'module_export_unsupported', eventsObserved: 3, eventsDropped: 3 },
    { reason: 'module_missing', eventsObserved: 39, eventsDropped: 5 },
    { reason: 'parse_error', eventsObserved: 4, eventsDropped: 4 },
  ] });
  assert.deepEqual(sanitiseAnalysisGaps(gaps, p => p), gaps);
  gaps.reasonSummary!.rows[0].eventsObserved = 999;
  assert.equal(recorder.result()!.reasonSummary!.rows[0].eventsObserved, 3);
});

test('same-position reasons and check-wide weighted observations have separate bounded rows', () => {
  const recorder = new AnalysisGapRecorder();
  recorder.record('module_missing', 'flow', item().location, 2);
  recorder.record('module_ambiguous', 'flow', item().location, 3);
  recorder.record('parse_error', 'parse', undefined, 5);
  recorder.record('depth_limit', 'flow', undefined, 0);
  const gaps = recorder.result()!;
  assert.equal(gaps.items.length, 3); assert.equal(gaps.items[2].location, undefined);
  assert.deepEqual(gaps.reasonSummary?.rows, [
    { reason: 'module_missing', eventsObserved: 2, eventsDropped: 0 },
    { reason: 'module_ambiguous', eventsObserved: 3, eventsDropped: 0 },
    { reason: 'parse_error', eventsObserved: 5, eventsDropped: 0 },
  ]);
});

test('invalid records and overflow invalidate both accountings without fabricated reason zeros', () => {
  for (const invalid of ['outside_registry', 'overflow', 'negative', 'fraction', 'infinite']) {
    const recorder = new AnalysisGapRecorder();
    recorder.record('module_missing', 'flow', item().location);
    if (invalid === 'outside_registry') recorder.record(invalid, 'flow');
    else if (invalid === 'overflow') recorder.record('node_limit', 'index', undefined, Number.MAX_SAFE_INTEGER);
    else recorder.record('node_limit', 'index', undefined, invalid === 'negative' ? -1 : invalid === 'fraction' ? .5 : Infinity);
    const gaps = recorder.result()!;
    assert.equal(gaps.accounting, 'unknown'); assert.equal(gaps.eventsObserved, null);
    assert.deepEqual(gaps.reasonSummary, { accounting: 'unknown', rows: [] });
    assert.deepEqual(sanitiseAnalysisGaps(gaps, p => p), gaps);
  }
});

const exactReasonGap = (): AnalysisGaps => ({ ...envelope([item()]), reasonSummary: { accounting: 'exact', rows: [
  { reason: 'module_missing', eventsObserved: 1, eventsDropped: 0 },
] } });

test('malformed supplied reason metadata downgrades separately and cannot promote unknown global accounting', () => {
  const row = exactReasonGap().reasonSummary!.rows[0];
  const malformed = [null, [], {}, { accounting: 'exact', rows: 'bad' },
    { accounting: 'exact', rows: [row, row] },
    { accounting: 'exact', rows: Array.from({ length: 14 }, () => row) },
    ...['eventsObserved', 'eventsDropped'].flatMap(field => [-1, .5, Infinity, '1', [1], Number.MAX_SAFE_INTEGER + 1]
      .map(value => ({ accounting: 'exact', rows: [{ ...row, [field]: value }] }))),
    { accounting: 'exact', rows: [{ ...row, reason: 'run_command' }] },
    { accounting: 'exact', rows: [{ ...row, reason: ['module_missing'] }] },
    { accounting: 'exact', rows: [{ ...row, eventsObserved: 2 }] },
    { accounting: 'exact', rows: [{ ...row, eventsDropped: 1 }] },
    { accounting: 'exact', rows: [{ ...row, eventsObserved: 0 }] },
    { accounting: 'exact', rows: [{ ...row, reason: 'parse_error' }] },
  ];
  for (const reasonSummary of malformed) {
    const cleaned = sanitiseAnalysisGaps({ ...exactReasonGap(), reasonSummary }, p => p)!;
    assert.equal(cleaned.accounting, 'exact'); assert.equal(cleaned.eventsObserved, 1);
    assert.deepEqual(cleaned.items, [item()]);
    assert.deepEqual(cleaned.reasonSummary, { accounting: 'unknown', rows: [] });
    assert.deepEqual(sanitiseAnalysisGaps(cleaned, p => p), cleaned);
  }
  const globalUnknown = sanitiseAnalysisGaps({ ...exactReasonGap(), eventsObserved: 2 }, p => p)!;
  assert.equal(globalUnknown.accounting, 'unknown');
  assert.deepEqual(globalUnknown.reasonSummary, { accounting: 'unknown', rows: [] });
});

test('reason rows canonicalize order and zero omissions; legacy metadata remains absent', () => {
  const supplied = { ...exactReasonGap(), reasonSummary: { accounting: 'exact', rows: [
    { reason: 'parse_error', eventsObserved: 0, eventsDropped: 0 },
    { reason: 'module_missing', eventsObserved: 1, eventsDropped: 0 },
    { reason: 'module_export_unsupported', eventsObserved: 0, eventsDropped: 0 },
  ] } };
  const cleaned = sanitiseAnalysisGaps(supplied, p => p)!;
  assert.deepEqual(cleaned, exactReasonGap());
  supplied.reasonSummary.rows[1].eventsObserved = 20;
  assert.equal(cleaned.reasonSummary!.rows[0].eventsObserved, 1);
  for (const legacy of [envelope([item()]), { ...envelope([item()]), accounting: 'unknown', eventsObserved: null, eventsDropped: null, truncated: true }]) {
    const value = sanitiseAnalysisGaps(legacy, p => p)!;
    assert.equal(Object.hasOwn(value, 'reasonSummary'), false);
    assert.equal(Object.hasOwn(capAnalysisGaps(value, 0), 'reasonSummary'), false);
  }
});

test('report cap moves reason observations once and all four projections retain identical tables', async () => {
  const recorder = new AnalysisGapRecorder();
  for (let line = 1; line <= 32; line++) recorder.record('module_missing', 'flow', item(line).location);
  recorder.record('parse_error', 'parse', undefined, 4);
  const input = recorder.result()!;
  const checks = Array.from({ length: 9 }, (_, index) => ({ ...check(input), id: `bounded-${index}` }));
  const report = createReport(checks, 'source', started);
  const last = report.checks[8].analysisGaps!;
  assert.equal(last.items.length, 0); assert.equal(last.eventsObserved, 36); assert.equal(last.eventsDropped, 36);
  assert.deepEqual(last.reasonSummary, { accounting: 'exact', rows: [
    { reason: 'module_missing', eventsObserved: 32, eventsDropped: 32 },
    { reason: 'parse_error', eventsObserved: 4, eventsDropped: 4 },
  ] });
  assert.deepEqual(input.reasonSummary!.rows.map(row => row.eventsDropped), [0, 4]);
  assert.deepEqual(sanitiseReport(sanitiseReport(report)), report);
  assert.deepEqual(capAnalysisGaps(capAnalysisGaps(input, 0), 0), capAnalysisGaps(input, 0));
  const root = await mkdtemp(join(tmpdir(), 'wakeio-reason-projection-'));
  try {
    await writeReports(report, root, { failOn: 'none' });
    const bytes = await readFile(join(root, 'report.json'));
    const json = JSON.parse(bytes.toString()), agent = JSON.parse(await readFile(join(root, 'agent-report.json'), 'utf8'));
    const sarif = JSON.parse(await readFile(join(root, 'report.sarif'), 'utf8'));
    assert.deepEqual(json.checks[8].analysisGaps.reasonSummary, last.reasonSummary);
    assert.deepEqual(agent.checks[8].analysisGaps.reasonSummary, last.reasonSummary);
    assert.deepEqual(sarif.runs[0].properties.analysisGaps[8].analysisGaps.reasonSummary, last.reasonSummary);
    assert.deepEqual(agent.summary.incompleteChecks[0].analysisGaps.reasonSummary, input.reasonSummary);
    assert.equal(agent.reportArtifact.digest, createHash('sha256').update(bytes).digest('hex'));
    const markdown = await readFile(join(root, 'report.md'), 'utf8');
    assert.ok(markdown.includes('| module\\_missing | 32 | 32 |'));
    assert.ok(markdown.includes('| parse\\_error | 4 | 4 |'));
  } finally { await rm(root, { recursive: true, force: true }); }
});


test('Markdown reason tables follow nested gap lists and summary representatives', () => {
  const recorder = new AnalysisGapRecorder();
  for (let line = 1; line <= 5; line++) recorder.record('module_missing', 'flow', item(line).location);
  const markdown = toMarkdown(createReport([check(recorder.result())], 'source', started));
  const summary = markdown.split('## First read')[1].split('## Checks')[0];
  const detailed = markdown.split('## Checks')[1].split('## Findings')[0];
  assert.ok(summary.indexOf('| Reason | Observed | Dropped |') > summary.lastIndexOf('Representative gap:'));
  assert.ok(summary.indexOf('| Reason | Observed | Dropped |') > summary.indexOf('retained gap items omitted'));
  assert.ok(detailed.indexOf('| Reason | Observed | Dropped |') > detailed.lastIndexOf('next static review:'));
});
