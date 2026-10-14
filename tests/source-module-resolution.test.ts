import test from 'node:test';
import assert from 'node:assert/strict';
import { ModuleConfigurations } from '../src/source/module-config.js';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import type { CollectedFile, SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate, toAgentReport, toSarif } from '../src/report.js';
import { parseScanReport } from '../src/compare.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';

const CONFIG = '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}';
const ENTRY = "import { search } from '@/barrel'; export function route(req) { search(req.query.value); }";
const LEAF = "export function search(value) { db.query('SELECT '+value); }";
function files(texts: Record<string, string>): CollectedFile[] {
  return Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text),
    sensitive: false, category: path.endsWith('.json') ? 'config' : 'code' }));
}
function scan(texts: Record<string, string>, aliasSteps: number = FLOW_LIMITS.aliasSteps, overrides: Partial<FlowLimits> = {}) {
  const input = files(texts);
  const snapshot: SourceSnapshot = { root: '/owned-module-graph', files: input, issues: [], complete: true,
    ignoredFiles: 0, totalBytes: input.reduce((sum, file) => sum + file.bytes, 0) };
  return runBuiltinAst(snapshot, false, { ...FLOW_LIMITS, aliasSteps, ...overrides });
}
function actualRows(check: ReturnType<typeof scan>) {
  return check.findings.filter(f => f.location.path === 'src/leaf.ts'
    && f.staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'app.ts'));
}

test('configured graph owner: aggregate and configuration count bounds do not admit partial mappings', () => {
  const count = files(Object.fromEntries(Array.from({ length: 129 }, (_, index) =>
    [`p${index}/tsconfig.json`, CONFIG])));
  const capped = new ModuleConfigurations(count, () => true);
  assert.equal(capped.resolve('p0/app.ts', '@/barrel').kind, 'unsupported');
  assert.equal(capped.observed, 129); assert.equal(capped.supported, 0);
  const padded = CONFIG + ' '.repeat(65_000 - CONFIG.length);
  const aggregate = new ModuleConfigurations(files(Object.fromEntries(Array.from({ length: 17 }, (_, index) =>
    [`p${index}/tsconfig.json`, padded]))), () => true);
  assert.equal(aggregate.resolve('p16/app.ts', '@/barrel').kind, 'unsupported');
  assert.equal(aggregate.resolve('p0/app.ts', '@/barrel').kind, 'mapped', 'earlier complete configuration stays bounded and adopted');
});

test('configured graph owner: duplicate snapshot configuration cannot certify either copy', () => {
  const input = files({ 'tsconfig.json': CONFIG });
  const configurations = new ModuleConfigurations([...input, ...input], () => true);
  assert.equal(configurations.resolve('app.ts', '@/barrel').kind, 'unsupported');
  assert.equal(configurations.supported, 0); assert.equal(configurations.unsupported, 2);
});

test('configured graph owner: malformed compilerOptions cannot be treated as an absent mapping', () => {
  for (const compilerOptions of ['unknown', null, []]) {
    const configurations = new ModuleConfigurations(files({ 'tsconfig.json': JSON.stringify({ compilerOptions }) }), () => true);
    assert.equal(configurations.resolve('app.ts', 'pg').kind, 'unsupported');
    assert.equal(configurations.supported, 0);
  }
  const missing = new ModuleConfigurations(files({ 'tsconfig.json': '{}' }), () => true);
  assert.equal(missing.resolve('app.ts', 'pg').kind, 'external');
  assert.equal(missing.supported, 1);
});

test('configured graph owner: missing nested star target is not a proved absent export', () => {
  const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/leaf.ts': LEAF + ' export function ownSource(req) { db.query(req.query.statement); }',
    'src/barrel.ts': "export * from './leaf'; export * from './nested';",
    'src/nested.ts': "export * from './missing';" });
  assert.equal(actualRows(check).length, 0);
  assert.ok(check.findings.some(f => f.location.path === 'src/leaf.ts'), 'independent declared leaf root survives');
});

test('configured graph owner: unsupported runtime export namespaces cannot certify star absence', () => {
  for (const text of ["const obj={}; export = obj;", "export import other = require('./owned');",
    "export const { search } = opaque;", "export const [search] = opaque;"]) {
    const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG, 'src/leaf.ts': LEAF,
      'src/barrel.ts': "export * from './leaf'; export * from './other';", 'src/other.ts': text });
    assert.equal(actualRows(check).length, 0, text);
  }
});

test('configured graph owner: export binding collection cap refuses absence certification', () => {
  const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG, 'src/leaf.ts': LEAF,
    'src/barrel.ts': "export * from './leaf'; export * from './other';",
    'src/other.ts': 'export const {a:{b:{search}}}=opaque;' }, 2);
  assert.equal(actualRows(check).length, 0);
  assert.equal(check.status, 'partial');
});

test('configured graph owner: conditional alias body retains the independent exported root', () => {
  const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/barrel.ts': "export * from './leaf';", 'src/leaf.ts': LEAF });
  assert.equal(actualRows(check).length, 1);
  assert.ok(Number(check.metrics?.entryRootsDeclared) >= 2, 'alias resolution cannot replace the declared leaf entry');
  assert.equal(check.metrics?.configuredModuleCallSites, 1);
  assert.ok(Number(check.metrics?.configuredModuleCallContexts) >= 1);
});

test('configured graph owner: configured authority survives public report consumers and advice projection', () => {
  const check = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/barrel.ts': "export * from './leaf';", 'src/leaf.ts': LEAF });
  const report = createReport([check], 'source', new Date(0));
  const parsed = parseScanReport(JSON.parse(JSON.stringify(report)));
  assert.ok(parsed.checks[0].findings.some(f => f.staticContext?.items.some(item => item.kind === 'configured_module_resolution')));
  assert.equal(evaluateGate(parsed, 'none').exitCode, 2);
  const agent = toAgentReport(parsed);
  const row = agent.findings.find(f => f.evidence.staticContext?.items.some(item => item.kind === 'configured_module_resolution'))!;
  assert.equal(row.confidence, 'low'); assert.equal(row.verification.vulnerabilityConfirmed, false);
  assert.match(JSON.stringify(toSarif(parsed)), /configured_module_resolution/);
  const projected = projectAdviceContext(agent, false, { findingId: row.findingId, checkIndex: row.checkIndex });
  assert.equal(projected.input.projectionVersion, 13);
  assert.match(JSON.stringify(projected.input), /configured_module_resolution/);
});

test('configured graph owner: early costly aliases cannot preempt a later existing dangerous root', () => {
  const check = scan({ 'app.ts': ENTRY, 'late.ts': 'export function late(req){db.query(req.query.statement);}',
    'src/barrel.ts': 'export function search(value){'
      + Array.from({ length: 600 }, (_, index) => `\nconst owned${index}=1;`).join('') + 'db.query(value);}',
    'tsconfig.json': CONFIG }, FLOW_LIMITS.aliasSteps, { flowWork: 1_000 });
  assert.ok(check.findings.some(f => f.location.path === 'late.ts' && f.ruleId === 'ast:sql-input-sink'));
  assert.equal(check.status, 'partial');
  assert.ok(Number(check.metrics?.configuredBodyInspectionsQueued) > 0);
  assert.ok(Number(check.metrics?.configuredBodyInspectionsDropped) > 0);
  assert.equal(check.metrics?.maxFlowWork, 1_000);
});

test('configured graph owner: deferred actual properties are detached from later caller mutations', () => {
  const common = { 'tsconfig.json': CONFIG,
    'src/barrel.ts': 'export function search(box){db.query(box.value);}' };
  const captured = scan({ ...common, 'app.ts': "import {search} from '@/barrel';export function route(req){const box={value:req.query.id};search(box);box.value='fixed';}" });
  const row = captured.findings.find(f => f.location.path === 'src/barrel.ts'
    && f.staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'app.ts'));
  assert.ok(row); assert.equal(row.confidence, 'low');
  const later = scan({ ...common, 'app.ts': "import {search} from '@/barrel';export function route(req){const box={value:'fixed'};search(box);box.value=req.query.id;}" });
  assert.equal(later.findings.some(f => f.location.path === 'src/barrel.ts'
    && f.staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'app.ts')), false);
});

test('configured graph owner: deferred fixed return cannot retroactively grant caller safety', () => {
  const check = scan({ 'tsconfig.json': CONFIG, 'src/barrel.ts': "export function search(value){return 'fixed';}",
    'app.ts': "import {search} from '@/barrel';export function route(req){const result=search(req.query.id);db.query(result);}" });
  assert.ok(check.findings.some(f => f.location.path === 'app.ts' && f.ruleId === 'ast:sql-input-sink'));
  assert.ok(Number(check.metrics?.configuredBodyInspectionsStarted) > 0);
  assert.equal(check.status, 'partial');
});

test('configured graph owner: body snapshot argument cap cannot truncate caller input fallback', () => {
  const actuals = [...Array.from({ length: 30 }, () => '1'), 'req.query.last'].join(',');
  const check = scan({ 'tsconfig.json': CONFIG, 'src/barrel.ts': "export function search(){return 'fixed';}",
    'app.ts': `import {search} from '@/barrel';export function route(req){const result=search(${actuals});db.query(result);}` });
  assert.ok(check.findings.some(f => f.location.path === 'app.ts' && f.ruleId === 'ast:sql-input-sink'
    && f.staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'app.ts')));
  assert.ok(String(check.metrics?.incompleteReasons).includes('alias_limit'));
  assert.equal(check.status, 'partial');
});

test('configured graph owner: deferred queue, snapshot and ancestry caps remain explicit partial', () => {
  const repeated = ENTRY.replace('search(req.query.value);', 'search(req.query.value);search(req.query.other);search(req.query.third);');
  const queue = scan({ 'app.ts': repeated, 'tsconfig.json': CONFIG, 'src/barrel.ts': LEAF }, FLOW_LIMITS.aliasSteps, { functions: 2 });
  assert.ok(Number(queue.metrics?.configuredBodyInspectionsDropped) > 0); assert.equal(queue.status, 'partial');
  const copy = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG, 'src/barrel.ts': LEAF }, FLOW_LIMITS.aliasSteps, { summaryWork: 1 });
  assert.ok(Number(copy.metrics?.configuredBodyInspectionsDropped) > 0); assert.equal(copy.status, 'partial');
  const depth = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG, 'src/barrel.ts': LEAF }, FLOW_LIMITS.aliasSteps, { callDepth: 1 });
  assert.ok(String(depth.metrics?.incompleteReasons).includes('depth_limit'));
  const cyclic = scan({ 'app.ts': ENTRY, 'tsconfig.json': CONFIG,
    'src/barrel.ts': "import {other} from '@/other';export function search(value){other(value);}",
    'src/other.ts': "import {search} from '@/barrel';export function other(value){search(value);}" }, FLOW_LIMITS.aliasSteps, { functions: 20 });
  assert.ok(String(cyclic.metrics?.incompleteReasons).includes('summary_cycle'));
  assert.equal(cyclic.status, 'partial');
});
