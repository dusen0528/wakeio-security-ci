import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate, toAgentReport } from '../src/report.js';

const ENTRY = "import { search } from '@/lib/query';\nexport function route(req) { search(req.query.id); }";
const LEAF = "export function search(value) { db.query('SELECT ' + value); }";
const CONFIG = '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}';
const HTTP_CONTROL = "import client from 'axios'; export function route(req) { const p=new URLSearchParams({q:req.query.command}); const query=p.toString(); const url='https://owned.invalid/path?'+query; client.request({url,data:req.body}); }";

function scan(texts: Record<string, string>, complete = true, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text,
    bytes: Buffer.byteLength(text), sensitive: false,
    category: path.endsWith('.json') ? 'config' as const : 'code' as const }));
  const snapshot: SourceSnapshot = { root: '/owned-inert-configured-graph', files,
    issues: [], complete, ignoredFiles: 0, totalBytes: files.reduce((n, f) => n + f.bytes, 0) };
  return runBuiltinAst(snapshot, false, limits);
}
function connected(check: ReturnType<typeof scan>, entry = 'app.ts') {
  return check.findings.filter(f => f.staticFlow?.steps.some(s => s.role === 'source' && s.location.path === entry));
}
function configured(check: ReturnType<typeof scan>, target: string, entry = 'app.ts') {
  const rows = connected(check, entry).filter(f => f.location.path === target);
  assert.equal(rows.length, 1, 'the actual input must reach exactly the selected declaration');
  const row = rows[0];
  assert.equal(row.confidence, 'low');
  assert.equal(row.kind, 'candidate');
  assert.equal(row.staticContext?.authority, 'conditional');
  assert.ok(row.staticContext?.items.some(item => String(item.kind) === 'configured_module_resolution'));
  assert.equal(row.staticFlow?.truncated, true);
  const report = createReport([check], 'source', new Date(0)), agent = toAgentReport(report);
  assert.equal(evaluateGate(report, 'none').exitCode, 2, 'configured authority cannot become a complete clean scan');
  assert.ok(agent.findings.some(f => f.location.path === target && f.evidence.staticContext?.authority === 'conditional'));
  assert.equal(agent.findings.some(f => f.verification.vulnerabilityConfirmed), false);
  return row;
}

test('configured graph independent: snapshot JSONC alias resolves a declaration with conditional evidence', () => {
  const check = scan({ 'app.ts': ENTRY, 'src/lib/query.ts': LEAF,
    'tsconfig.json': '// snapshot data only\n{"compilerOptions":{"paths":{"@/*":["./src/*"],},},}' });
  configured(check, 'src/lib/query.ts');
  assert.equal(connected(scan({ 'app.ts': ENTRY, 'src/lib/query.ts': LEAF })).length, 0,
    'a missing collected configuration must not invent the alias');
});

test('configured graph independent: an empty capture cannot substitute a target star but accepts a literal target', () => {
  const files = { 'app.ts': ENTRY.replace('@/lib/query', '@/'), 'src/index.ts': LEAF };
  assert.equal(connected(scan({ ...files, 'tsconfig.json': CONFIG })).length, 0,
    'TypeScript leaves the target star unchanged when matchedStar is empty');
  configured(scan({ ...files,
    'tsconfig.json': '{"compilerOptions":{"paths":{"@/*":["./src/index"]}}}' }), 'src/index.ts');
});

test('configured graph independent: nearest config and tsconfig precedence choose one target', () => {
  const nestedEntry = ENTRY.replace('@/lib/query', '@/query');
  const texts = { 'nested/app.ts': nestedEntry, 'src/query.ts': LEAF, 'nested/local/query.ts': LEAF,
    'nested/js/query.ts': LEAF, 'tsconfig.json': CONFIG,
    'nested/tsconfig.json': '{"compilerOptions":{"paths":{"@/*":["./local/*"]}}}',
    'nested/jsconfig.json': '{"compilerOptions":{"paths":{"@/*":["./js/*"]}}}' };
  configured(scan(texts), 'nested/local/query.ts', 'nested/app.ts');
  const { 'nested/tsconfig.json': _omitted, ...jsOnly } = texts;
  configured(scan(jsOnly), 'nested/js/query.ts', 'nested/app.ts');
  const unsupported = scan({ ...texts,
    'nested/tsconfig.json': '{"extends":"../tsconfig.json","compilerOptions":{"paths":{"@/*":["./local/*"]}}}' });
  assert.equal(connected(unsupported, 'nested/app.ts').length, 0,
    'unsupported nearest config must not fall through to jsconfig or parent tsconfig');
});

test('configured graph independent: exact key and longest prefix beat broader patterns', () => {
  const paths = { '@/*': ['./broad/*'], '@/lib/*': ['./narrow/*'], '@/lib/query': ['./exact.ts'] };
  const texts = { 'app.ts': ENTRY, 'broad/lib/query.ts': LEAF, 'narrow/query.ts': LEAF,
    'exact.ts': LEAF, 'tsconfig.json': JSON.stringify({ compilerOptions: { paths } }) };
  configured(scan(texts), 'exact.ts');
  configured(scan({ ...texts, 'tsconfig.json': JSON.stringify({ compilerOptions: {
    paths: { '@/*': ['./broad/*'], '@/lib/*': ['./narrow/*'] } } }) }), 'narrow/query.ts');
});

test('configured graph independent: equal wildcard prefixes follow declaration order', () => {
  for (const reversed of [false, true]) {
    const entries: Array<[string, string[]]> = [['@/*/query', ['./first/*']], ['@/*', ['./second/*']]];
    if (reversed) entries.reverse();
    const check = scan({ 'app.ts': ENTRY, 'first/lib.ts': LEAF, 'second/lib/query.ts': LEAF,
      'tsconfig.json': JSON.stringify({ compilerOptions: { paths: Object.fromEntries(entries) } }) });
    configured(check, reversed ? 'second/lib/query.ts' : 'first/lib.ts');
  }
});

test('configured graph independent: fallback arrays, escape and extension ambiguity cannot select a body', () => {
  for (const targets of [['./src/*', './other/*'], ['../outside/*'], ['.\\src\\*']]) {
    const check = scan({ 'app.ts': ENTRY, 'src/lib/query.ts': LEAF, 'other/lib/query.ts': LEAF,
      'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { '@/*': targets } } }) });
    assert.equal(connected(check).length, 0, JSON.stringify(targets));
  }
  const ambiguous = scan({ 'app.ts': ENTRY, 'src/lib/query.ts': LEAF, 'src/lib/query.js': LEAF,
    'tsconfig.json': CONFIG });
  assert.equal(connected(ambiguous).length, 0, 'multiple collected extension matches do not establish one target');
});

test('configured graph independent: unique star and named re-export chains retain the actual target', () => {
  for (const barrel of ["export * from './leaf';", "export { search } from './leaf';"]) {
    const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
      'src/lib/query.ts': barrel, 'src/lib/leaf.ts': LEAF });
    configured(check, 'src/lib/leaf.ts');
  }
  const relative = scan({ 'app.ts': ENTRY.replace('@/lib/query', './barrel'),
    'barrel.ts': "export { search } from './leaf';", 'leaf.ts': LEAF });
  const rows = connected(relative).filter(f => f.location.path === 'leaf.ts');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].staticContext?.items.some(item => String(item.kind) === 'configured_module_resolution') ?? false, false);
});

test('configured graph independent: a supported star sibling without the requested name is not a conflict', () => {
  const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.ts': "export * from './other'; export * from './leaf';",
    'src/lib/other.ts': 'export function unrelated(value) { return value; }', 'src/lib/leaf.ts': LEAF });
  configured(check, 'src/lib/leaf.ts');
  const unknown = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.ts': "export * from './leaf'; export * from 'unreviewed-package';", 'src/lib/leaf.ts': LEAF });
  assert.equal(connected(unknown).length, 0, 'an external star may compete with the known runtime export');
  const nestedMissing = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.ts': "export * from './leaf'; export * from './nested';",
    'src/lib/nested.ts': "export * from './missing-file';", 'src/lib/leaf.ts': LEAF });
  assert.equal(connected(nestedMissing).length, 0,
    'a nested missing module is unresolved, not proof that the requested export is absent');
});

test('configured graph independent: conflicting exports and cycles do not inherit a convenient declaration', () => {
  const graphs: Array<Record<string, string>> = [
    { 'src/lib/query.ts': "export * from './one'; export * from './two';", 'src/lib/one.ts': LEAF, 'src/lib/two.ts': LEAF },
    { 'src/lib/query.ts': "export * from './cycle';", 'src/lib/cycle.ts': "export * from './query';" },
    { 'src/lib/query.ts': "export * from './default';", 'src/lib/default.ts': 'export default function search(value) { db.query(value); }' },
  ];
  for (const files of graphs) {
    assert.equal(connected(scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG, ...files })).length, 0);
  }
  const typeOnly = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.ts': "export type { search } from './types'; export * from './leaf';",
    'src/lib/types.ts': 'export type search = string;', 'src/lib/leaf.ts': LEAF });
  configured(typeOnly, 'src/lib/leaf.ts');
});

test('configured graph independent: runtime nonfunction exports conflict while erased types do not', () => {
  for (const runtime of [
    'export class search {}',
    'export enum search { Owned }',
    'export namespace search { export const value = 1; }',
  ]) {
    const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
      'src/lib/query.ts': "export * from './leaf'; export * from './other';",
      'src/lib/leaf.ts': LEAF, 'src/lib/other.ts': runtime });
    assert.equal(connected(check).length, 0, runtime);
  }
  const namespace = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.ts': "export * from './leaf'; export * as search from './other';",
    'src/lib/leaf.ts': LEAF, 'src/lib/other.ts': 'export const owned = 1;' });
  assert.equal(connected(namespace).length, 0, 'namespace re-export is an actual runtime binding');
  const erased = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.ts': "export * from './leaf'; export * from './other';",
    'src/lib/leaf.ts': LEAF, 'src/lib/other.ts': 'export type search = string;' });
  configured(erased, 'src/lib/leaf.ts');
});

test('configured graph independent: alias-to-CommonJS is not upgraded to a resolved scalar body', () => {
  const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.js': "const search = value => db.query('SELECT ' + value); module.exports = { search };" });
  assert.equal(connected(check).length, 0,
    'the configured ESM increment cannot silently authenticate an unsupported CommonJS target');
});

test('configured graph independent: an alias body cannot grant a native SQL values-only exclusion', () => {
  const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/lib/query.ts': "import { Pool } from 'pg'; const db = new Pool(); export function search(value) { db.query('SELECT $1', [value]); }" });
  const row = configured(check, 'src/lib/query.ts');
  assert.equal(row.ruleId, 'ast:sql-input-sink');
  assert.equal(check.metrics?.sqlValuesOnlyExcluded, 0,
    'conditional configured-module authority cannot certify a safe request/data origin');
});

test('configured graph independent: observed package overrides veto native negative certificates, not input', () => {
  // The frozen main4089839 and first graph draft both excluded the mapped PG
  // case. This is an existing certificate gap exposed by newly observed config,
  // not evidence that the alias increment introduced the behavior.
  const families = [
    { specifier: 'pg', text: "import { Pool } from 'pg'; const db = new Pool(); export function route(req) { db.query('SELECT $1', [req.query.command]); }",
      shim: 'export class Pool { query(_statement, values) { return backend.query(values[0]); } }',
      counter: 'sqlValuesOnlyExcluded', rules: ['ast:sql-input-sink'] },
    { specifier: 'axios', text: HTTP_CONTROL,
      shim: 'export default opaqueFactory;', counter: 'outboundEncodedQueryExcluded', rules: ['ast:server-request'] },
    { specifier: 'child_process', text: "import { spawn } from 'child_process'; export function route(req) { spawn('owned-tool', [req.query.command], {shell:false}); }",
      shim: 'export function spawn(_command, values) { return backend.exec(values[0]); }',
      counter: 'processArgvOnlyExcluded', rules: ['ast:process-executable', 'ast:shell-input-sink'] },
  ];
  for (const family of families) {
    const texts = { 'app.ts': family.text, 'shim.ts': family.shim, 'tsconfig.json': CONFIG };
    const normal = scan(texts);
    assert.equal(normal.status, 'completed', family.specifier);
    assert.equal(normal.findings.filter(f => family.rules.includes(f.ruleId)).length, 0);
    assert.equal(normal.metrics?.[family.counter], 1, 'unmapped native behavior remains an explicit control');
    const mapped = scan({ ...texts, 'tsconfig.json': JSON.stringify({ compilerOptions: {
      paths: { [family.specifier]: ['./shim.ts'] } } }) });
    assert.equal(mapped.metrics?.[family.counter], 0, family.specifier);
    const rows = connected(mapped).filter(f => family.rules.includes(f.ruleId));
    assert.ok(rows.length > 0, 'known input cannot disappear behind a contradictory native identity');
    assert.equal(mapped.status, 'partial');
    for (const row of rows) {
      assert.equal(row.confidence, 'low'); assert.equal(row.kind, 'candidate');
      assert.equal(row.staticContext?.authority, 'conditional');
      assert.ok(row.staticContext?.items.some(item => String(item.kind) === 'configured_module_resolution'));
    }
    assert.equal(evaluateGate(createReport([mapped], 'source', new Date(0)), 'none').exitCode, 2);
  }
});

test('configured graph independent: unknown nearest config cannot certify PG while erased mapped imports are harmless', () => {
  const pg = "import { Pool } from 'pg'; const db = new Pool(); export function route(req) { db.query('SELECT $1', [req.query.command]); }";
  const unknown = scan({ 'app.ts': pg, 'tsconfig.json': '{"extends":"./uncollected-config.json"}' });
  assert.equal(unknown.metrics?.sqlValuesOnlyExcluded, 0);
  assert.ok(connected(unknown).some(f => f.ruleId === 'ast:sql-input-sink' && f.confidence === 'low'));
  assert.equal(evaluateGate(createReport([unknown], 'source', new Date(0)), 'none').exitCode, 2);
  const erased = scan({
    'types.ts': "import type { Pool } from 'pg'; export type ImportedPool = Pool;",
    'shim.ts': 'export class Pool {}',
    'tsconfig.json': '{"compilerOptions":{"paths":{"pg":["./shim.ts"]}}}',
    'app.ts': HTTP_CONTROL,
  });
  assert.equal(erased.status, 'completed');
  assert.equal(erased.findings.length, 0);
  assert.equal(erased.metrics?.outboundEncodedQueryExcluded, 1, 'erased-only pg import cannot taint unrelated native authority');
});

test('configured graph independent: metadata and index boundaries preserve direct evidence without alias proof', () => {
  const entry = ENTRY + '\nexport function direct(req) { db.query(req.query.direct); }';
  const oversized = scan({ 'app.ts': entry, 'src/lib/query.ts': LEAF,
    'tsconfig.json': '/*' + 'x'.repeat(65_536) + '*/' + CONFIG });
  assert.ok(connected(oversized).some(f => f.location.path === 'app.ts'), 'existing direct evidence survives unsupported configuration');
  assert.equal(connected(oversized).some(f => f.location.path === 'src/lib/query.ts'), false);
  const capped = scan({ 'app.ts': entry, 'src/lib/query.ts': LEAF, 'tsconfig.json': CONFIG }, true,
    { ...FLOW_LIMITS, indexWork: 1 });
  assert.equal(capped.status, 'partial');
  assert.equal(capped.metrics?.indexComplete, false);
  assert.equal(connected(capped).some(f => f.location.path === 'src/lib/query.ts'), false);
  assert.equal(evaluateGate(createReport([capped], 'source', new Date(0)), 'none').exitCode, 2);
});
