import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { resolveAnalysisBudget } from '../src/source/analysis-budget.js';
import { createReport, RULESET_VERSION } from '../src/report.js';
import { compareReports, comparisonExitCode } from '../src/compare.js';
import type { SourceSnapshot } from '../src/source/types.js';

const EXEC = "import {exec} from 'node:child_process';\n";
function scan(text: string, limits: Partial<FlowLimits> = {}) {
  const file = { path: 'app.ts', text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false };
  const input: SourceSnapshot = { root: '/owned-rest-parameters', files: [file], complete: true,
    totalBytes: file.bytes, issues: [], ignoredFiles: 0 };
  return runBuiltinAst(input, false, { ...FLOW_LIMITS, ...limits }, resolveAnalysisBudget());
}
const shell = (check: ReturnType<typeof scan>) => check.findings.filter(f => f.ruleId === 'ast:shell-input-sink');

test('rest owner: dynamic identifier length is not the literal fresh-array length property', () => {
  const danger = scan(EXEC + 'function helper(length,...args){exec(args[length]);}export function route(req){helper(0,req.query.value);}');
  assert.equal(danger.status, 'partial'); assert.equal(shell(danger).length, 1);
  assert.ok(String(danger.metrics?.incompleteReasons).includes('module_export_unsupported'));
  for (const member of ["args['length']", 'args.length']) {
    const normal = scan(EXEC + `function helper(...args){exec(String(${member}));}export function route(req){helper(req.query.value);}`);
    assert.equal(normal.status, 'completed'); assert.equal(shell(normal).length, 0);
  }
});

test('rest owner: native command oracle fixes second-tail FN without unused/absent-slot FP', () => {
  const base = EXEC + 'function helper(...args){exec(args[1]);}\n';
  const danger = scan(base + "export function route(req){helper('fixed',req.query.value);}");
  assert.equal(shell(danger).length, 1); assert.equal(danger.status, 'completed');
  assert.ok(Number(danger.metrics?.restBindingsRecognized) >= 1);
  for (const actuals of ["req.query.value,'fixed'", 'req.query.value', '']) {
    const normal = scan(base + `export function route(req){helper(${actuals});}`);
    assert.equal(shell(normal).length, 0); assert.equal(normal.status, 'completed');
  }
});

test('rest owner: tail materialization cap preserves input instead of a false exact safe slot', () => {
  const actuals = [...Array.from({ length: 30 }, () => "'fixed'"), 'req.query.last'].join(',');
  const check = scan(EXEC + `function helper(...args){exec(args[0]);}export function route(req){helper(${actuals});}`);
  assert.equal(check.status, 'partial'); assert.equal(shell(check).length, 1);
  assert.ok(Number(check.metrics?.restBindingsUnsupported) >= 1);
  assert.ok(String(check.metrics?.incompleteReasons).includes('alias_limit'));
});

test('rest owner: wrapped and container compound escapes never certify a stale selected field', () => {
  for (const effect of [
    'const item=(args[0]);item.cmd=req.query.value;',
    'opaque((args[0]),req.query.value);',
    'const holder={item:args[0]};holder.item.cmd=req.query.value;',
    'opaque(args[0][key],req.query.value);',
  ]) {
    const check = scan(EXEC + `function helper(req,key,...args){${effect}exec(args[0].cmd);}
      export function route(req){helper(req,req.query.key,{cmd:'fixed'});}`);
    assert.equal(check.status, 'partial', effect);
    assert.ok(Number(check.metrics?.restBindingsUnsupported) >= 1);
  }
});

test('rest owner: branch writes retain added input without granting exact selected-slot safety', () => {
  const check = scan(EXEC + "function helper(req,...args){const same=args;if(flag){same[0]=req.query.value;}exec(args[0]);}export function route(req){helper(req,'fixed');}");
  assert.equal(check.status, 'partial'); assert.equal(shell(check).length, 1);
  assert.ok(shell(check)[0].staticFlow?.steps.some(step => step.role === 'source'));
});

test('rest owner: constructor rest remains explicit unsupported and old ruleset comparison unverified', () => {
  const check = scan(EXEC + "function Owned(...args){this.run=()=>exec(args[1]);}export function route(req){const item=new Owned('fixed',req.query.value);item.run();}");
  assert.equal(check.status, 'partial');
  assert.equal(RULESET_VERSION, '2026-10-14.4');
  const current = scan(EXEC + "function helper(...args){exec(args[1]);}export function route(req){helper('fixed',req.query.value);}");
  const after = createReport([current], 'source', new Date(0), {
    fingerprint: 'a'.repeat(64), ruleset: RULESET_VERSION, analysisBudget: current.analysisBudget,
  });
  assert.equal(compareReports(after, after).comparable, true, 'same completed current scope is comparable');
  const before = JSON.parse(JSON.stringify(after)); before.scope.ruleset = '2026-10-14.3';
  const comparison = compareReports(before, after);
  assert.equal(comparison.comparable, false);
  assert.ok(comparison.reasons.some(reason => /ruleset/i.test(reason)));
  assert.equal(comparisonExitCode(comparison, 'none'), 2);
});
