import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import type { CheckResult, Finding } from '../src/contracts.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';

// Independent review additions. The frozen process acceptance suite is untouched.
const ruleIds = new Set(['ast:shell-input-sink', 'ast:process-executable']);
const privateValue = 'owned-review-process-private-491f9e';
function scan(text: string, more: Record<string, string> = {}, limits: FlowLimits = FLOW_LIMITS) {
  const texts = { 'app.ts': text + `\n// ${privateValue}\n`, ...more };
  const files = Object.entries(texts).map(([path, value]) => ({ path, text: value, bytes: Buffer.byteLength(value), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/never-execute-review-source', files, issues: [], ignoredFiles: 0, totalBytes: files.reduce((n, file) => n + file.bytes, 0), complete: true };
  const ast = runBuiltinAst(snapshot, false, limits);
  const report = createReport([ast], 'source', '2026-10-13T00:00:00.000Z');
  const agent = toAgentReport(report, 'none');
  for (const output of [JSON.stringify(report), JSON.stringify(agent), toMarkdown(report), JSON.stringify(toSarif(report))]) {
    assert.equal(output.includes(privateValue), false);
    for (const value of Object.values(texts)) for (const line of value.split('\n').filter(line => /req\.(query|body)/.test(line))) {
      assert.equal(output.includes(line.trim()), false);
      assert.equal(output.includes(JSON.stringify(line.trim()).slice(1, -1)), false);
    }
  }
  return { ast, report, agent, findings: ast.findings.filter(finding => ruleIds.has(finding.ruleId)) };
}
function coordinate(text: string, needle: string) {
  const index = text.indexOf(needle); assert.ok(index >= 0);
  const before = text.slice(0, index).split('\n');
  return { path: 'app.ts', line: before.length, column: before.at(-1)!.length + 1 };
}
function hasSource(finding: Finding, text: string, needle: string) {
  return finding.staticFlow?.steps.some(step => step.role === 'source' && JSON.stringify(step.location) === JSON.stringify(coordinate(text, needle)));
}
function incomplete(result: ReturnType<typeof scan>) {
  assert.equal(result.ast.status, 'partial');
  assert.equal(evaluateGate(result.report, 'none').exitCode, 2);
  assert.equal(result.agent.scanGate.exitCode, 2);
  assert.ok(result.ast.analysisGaps?.items.length);
}
function retainedUnknown(result: ReturnType<typeof scan>) {
  assert.ok(result.findings.length || result.ast.status === 'partial', 'uncertain input role silently completed clean');
  for (const finding of result.findings) {
    assert.equal(finding.kind, 'candidate');
    assert.equal(finding.confidence, 'low');
    assert.equal(finding.staticFlow?.truncated, true);
    assert.match(`${finding.title} ${finding.description}`, /unresolved|unknown|possible|unverified/i);
  }
  if (result.ast.status === 'partial') incomplete(result);
}
function shellFieldInput(result: ReturnType<typeof scan>, text: string, needle: string) {
  assert.ok(result.findings.length || result.ast.status === 'partial', 'captured shell field input disappeared');
  if (result.ast.status === 'partial') incomplete(result);
  for (const finding of result.findings) {
    assert.equal(finding.ruleId, 'ast:process-executable');
    assert.equal(finding.severity, 'high');
    assert.equal(finding.kind, 'candidate');
    assert.ok(hasSource(finding, text, needle), 'shell selection borrowed a different input source');
    if (finding.confidence === 'low') assert.equal(finding.staticFlow?.truncated, true);
  }
}

test('process role work stays charged under dense native aliases and independent phase caps', () => {
  const aliases = Array.from({ length: 80 }, (_, index) => `const method${index}=cp.spawn;`).join('\n');
  const text = `const cp=require('node:child_process');\n${aliases}\nexport function route(req){method79('owned-fixed',[req.query.argument],{shell:false});}`;
  for (const limits of [{ ...FLOW_LIMITS, indexWork: 40 }, { ...FLOW_LIMITS, flowWork: 4 }, { ...FLOW_LIMITS, nodeVisits: 40 }]) {
    const result = scan(text, {}, limits); incomplete(result);
    const m = result.ast.metrics!;
    assert.equal(m.nodeVisits, Number(m.indexWork) + Number(m.flowWork));
    assert.ok(Number(m.nodeVisits) <= Number(m.maxNodeVisits));
    assert.ok(Number(m.indexWork) <= Number(m.maxIndexWork));
    assert.ok(Number(m.flowWork) <= Number(m.maxFlowWork));
    assert.ok(result.ast.analysisGaps!.items.length <= 32);
    assert.equal(result.ast.analysisGaps!.accounting, 'exact');
  }
});

test('namespace aliases and reflection writes across native package bindings revoke pristine exclusions', () => {
  const mutations = [
    "const alias=cp; alias.spawn=replacement;",
    "Object.defineProperty(cp,'spawn',{value:replacement});",
    "Reflect.set(cp,'spawn',replacement);",
    "delete cp.spawn; Object.getPrototypeOf(cp).spawn=replacement;",
    "const alias=require('child_process'); Object.assign(alias,{spawn:replacement});",
  ];
  for (const mutation of mutations) {
    retainedUnknown(scan(`const cp=require('node:child_process'); ${mutation} export function route(req){cp.spawn('owned-fixed',[req.query.argument],{shell:false});}`));
  }
  retainedUnknown(scan("import {spawn as launch} from 'node:child_process'; export function route(req){launch('owned-fixed',[req.query.argument],{shell:false});}", {
    'mutator.js': "const cp=require('child_process'); Object.defineProperty(cp,'spawn',{get(){return replacement;}});",
  }));
});

test('captured shell option value survives a later property assignment to its binding', () => {
  const text = `import {spawn as launch} from 'node:child_process';
export function route(req){
  let selected=req.query.shell;
  launch('owned-fixed',['fixed'],{shell:selected,cwd:(selected='fixed')});
}`;
  shellFieldInput(scan(text), text, 'req.query.shell');
});

test('later property input must not replace an earlier fixed shell field with authoritative selection taint', () => {
  const text = `import {spawn as launch} from 'node:child_process';
export function route(req){
  let selected='/bin/sh';
  launch('owned-fixed',['fixed'],{shell:selected,cwd:(selected=req.query.later)});
}`;
  const result = scan(text);
  // An unmodeled whole-options side effect may conservatively remain low/partial,
  // but the later cwd value is never a known selected-shell source.
  for (const finding of result.findings) {
    assert.equal(finding.confidence, 'low');
    assert.equal(finding.staticFlow?.truncated, true);
  }
  if (result.ast.status === 'partial') incomplete(result);
});

test('duplicate shell fields evaluate side effects then retain the last captured selection value', () => {
  const text = `import {spawn as launch} from 'child_process';
export function route(req){
  let selected='fixed';
  launch('owned-fixed',['fixed'],{shell:(selected=req.query.shell),shell:selected});
}`;
  shellFieldInput(scan(text), text, 'req.query.shell');
  const fixedLast = "import {spawn as launch} from 'child_process'; export function route(req){launch('owned-fixed',['fixed'],{shell:req.query.shell,shell:false});}";
  const result = scan(fixedLast);
  assert.equal(result.findings.length, 0);
  assert.equal(result.ast.status, 'completed');
});

test('undefined and null argv overloads preserve real shell selection in options argument two', () => {
  for (const method of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) for (const absent of ['undefined', 'null']) {
    const text = `import {${method} as launch} from 'node:child_process'; export function route(req){launch('owned-fixed',${absent},{shell:req.query.shell});}`;
    shellFieldInput(scan(text), text, 'req.query.shell');
  }
});

test('execFile callback overload ignores later options rather than manufacturing a selected-shell input', () => {
  const text = "import {execFile as launch} from 'node:child_process'; export function route(req){launch('owned-fixed',()=>req.body.unused,{shell:req.query.shell});}";
  const result = scan(text);
  // normalizeExecFileArgs sets options=null when argument one is the callback.
  // Evaluating the ignored argument expression does not make it an execution option.
  assert.equal(result.findings.length, 0);
  assert.equal(result.ast.status, 'completed');
});

test('opaque overload input remains unknown instead of being lost as neither argv nor options', () => {
  for (const method of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) {
    retainedUnknown(scan(`import {${method} as launch} from 'child_process'; export function route(req){launch('owned-fixed',identity(req.body.argvOrOptions));}`));
    retainedUnknown(scan(`import {${method} as launch} from 'child_process'; export function route(req){launch('owned-fixed',req.body.argvOrOptions,{shell:false});}`));
  }
});

test('local process-shaped call bodies suppress only when analysis finishes including throw-only bodies', () => {
  for (const method of ['exec', 'execFile', 'spawn']) {
    const text = `function ${method}(value){throw value;} export function route(req){${method}(req.query.argument);}`;
    const result = scan(text);
    assert.equal(result.ast.status, 'completed');
    assert.equal(result.findings.length, 0);
    for (const limits of [{ ...FLOW_LIMITS, flowWork: 1 }, { ...FLOW_LIMITS, callDepth: 1 }]) {
      const partial = scan(text, {}, limits);
      if (partial.ast.status === 'partial') incomplete(partial);
      else assert.equal(partial.findings.length, 0);
    }
  }
});

test('local wrapper interruption never certifies absence of nested native process input', () => {
  const text = "import {exec as nativeExec} from 'child_process'; function spawn(value){return nativeExec(value);} function wrapper(value){return spawn(value);} export function route(req){wrapper(req.query.command);}";
  const completed = scan(text);
  assert.ok(completed.findings.some(f => f.ruleId === 'ast:shell-input-sink'));
  const interrupted = scan(text, {}, { ...FLOW_LIMITS, callDepth: 1 });
  incomplete(interrupted);
  assert.equal(evaluateGate(interrupted.report, 'high').exitCode, 2);
});
