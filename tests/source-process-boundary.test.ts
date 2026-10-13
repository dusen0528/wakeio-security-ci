import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';

// Narrow independently reviewed boundary: Node clones options into null-prototype records.
// Existing frozen acceptance/review files are untouched; no target source executes.
const rules = new Set(['ast:shell-input-sink', 'ast:process-executable']);
const privateValue = 'owned-process-boundary-private-922e31';
function scan(text: string) {
  const source = text + `\n// ${privateValue}\n`;
  const snapshot: SourceSnapshot = { root: '/never-execute-boundary', complete: true, issues: [], ignoredFiles: 0, totalBytes: Buffer.byteLength(source),
    files: [{ path: 'app.ts', text: source, bytes: Buffer.byteLength(source), category: 'code', sensitive: false }] };
  const ast = runBuiltinAst(snapshot, false);
  const report = createReport([ast], 'source', '2026-10-13T00:00:00.000Z');
  const agent = toAgentReport(report, 'none');
  for (const output of [JSON.stringify(report), JSON.stringify(agent), toMarkdown(report), JSON.stringify(toSarif(report))]) {
    assert.equal(output.includes(privateValue), false);
    assert.equal(output.includes(text), false);
    assert.equal(output.includes(JSON.stringify(text).slice(1, -1)), false);
  }
  return { ast, report, agent, findings: ast.findings.filter(f => rules.has(f.ruleId)) };
}
function directControl(prefix: string, method = 'spawn') {
  return `${prefix}\nimport {${method} as launch} from 'node:child_process'; export function route(req){launch('owned-fixed',[req.query.argument],{shell:false});}`;
}
function closed(result: ReturnType<typeof scan>) {
  assert.equal(result.ast.status, 'completed');
  assert.equal(result.findings.length, 0);
  assert.equal(evaluateGate(result.report, 'high').exitCode, 0);
}
function unknown(result: ReturnType<typeof scan>) {
  assert.ok(result.findings.length || result.ast.status === 'partial', 'native mutation silently completed clean');
  for (const finding of result.findings) {
    assert.equal(finding.kind, 'candidate');
    assert.equal(finding.confidence, 'low');
    assert.equal(finding.staticFlow?.truncated, true);
    assert.match(`${finding.title} ${finding.description}`, /unknown|unresolved|possible|unverified/i);
  }
  if (result.ast.status === 'partial') { assert.equal(evaluateGate(result.report, 'none').exitCode, 2); assert.equal(result.agent.scanGate.exitCode, 2); }
}

test('unrelated plain record Object.assign does not revoke declared native direct argv exclusion', () => {
  for (const prefix of ["Object.assign({}, {x:1});", "const record={}; Object.assign(record,{shell:true});"]) {
    for (const method of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) closed(scan(directControl(prefix, method)));
  }
});

test('unrelated own-property reflection is distinct from process binding or options mutation', () => {
  for (const prefix of [
    "const record={}; Object.defineProperty(record,'shell',{value:true});",
    "const record={}; Object.defineProperties(record,{spawn:{value:replacement}});",
    "const record={}; Reflect.set(record,'shell',true);",
    "const record={}; Reflect.deleteProperty(record,'shell');",
    "const record={}; Object.setPrototypeOf(record,{shell:true});",
  ]) closed(scan(directControl(prefix)));
});

test('reading a built-in prototype or reflection method is not evidence of a native mutation', () => {
  for (const prefix of ["const prototype=Object.prototype;", "const assign=Object.assign;", "const set=Reflect.set;"]) closed(scan(directControl(prefix)));
});

test('inherited Object.prototype.shell cannot become an own execution option after null-prototype cloning', () => {
  for (const method of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) {
    for (const options of ['', ', {}', ', {shell:false}']) {
      const text = `Object.prototype.shell=true; import {${method} as launch} from 'child_process'; export function route(req){launch('owned-fixed',[req.query.argument]${options});}`;
      closed(scan(text));
    }
  }
});

test('deleting a native own method before inherited replacement invalidates the API binding', () => {
  unknown(scan("const cp=require('node:child_process'); delete cp.spawn; Object.prototype.spawn=replacement; export function route(req){cp.spawn('owned-fixed',[req.query.argument],{shell:false});}"));
});

test('an escaped native namespace with ambiguous reflective target retains mutation uncertainty', () => {
  unknown(scan("const cp=require('child_process'); const target=opaque(cp); Reflect.set(target,'spawn',replacement); export function route(req){cp.spawn('owned-fixed',[req.query.argument],{shell:false});}"));
  unknown(scan("const cp=require('child_process'); const options={shell:false}; Object.defineProperty(options,'shell',{get(){return mode;}}); export function route(req){cp.spawn('owned-fixed',[req.query.argument],options);}"));
});
