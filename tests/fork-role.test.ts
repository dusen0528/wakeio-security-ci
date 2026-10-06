import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, RULESET_VERSION } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function snapshot(texts:Record<string,string>, complete=true):SourceSnapshot {
  const files=Object.entries(texts).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));
  return {root:'/never-execute',files,issues:[],complete,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};
}
const run=(text:string,more:Record<string,string>={})=>runBuiltinAst(snapshot({'app.ts':text,...more}),false);
const fork=(check:ReturnType<typeof run>)=>check.findings.filter(f=>f.ruleId==='ast:fork-module-path');
const patterns=[
  ["const cp=require('child_process');",'cp.fork'],
  ["const cp=require('node:child_process');",'cp.fork'],
  ["const {fork:launch}=require('child_process');",'launch'],
  ["import {fork as launch} from 'node:child_process';",'launch'],
  ["import * as cp from 'child_process';",'cp.fork'],
  ['',"require('child_process').fork"],
];
test('lexical CJS/ESM/inline fork identifies only actual modulePath input',()=>{
  for(const [head,call] of patterns) {
    const text=head+`function route(req){${call}(req.query.module, [req.query.arg], {env:req.body})}`;
    const result=run(text);assert.equal(result.status,'completed');assert.equal(fork(result).length,1);
    const finding=fork(result)[0];assert.equal(finding.title,'Input reaches a Node fork module path');assert.equal(finding.severity,'high');assert.equal(finding.confidence,'medium');
    assert.equal(finding.staticFlow?.steps.find(s=>s.role==='source')?.location.column,text.indexOf('req.query.module')+1);
    assert.equal(result.findings.filter(f=>f.ruleId==='ast:shell-input-sink').length,0);
  }
});
test('fixed modulePath with input argv/options has no modulePath claim or whole-safe claim',()=>{
  for(const [head,call] of patterns) {
    const result=run(head+`function route(req){${call}('./worker.js',[req.query.arg],{execPath:req.query.exe,execArgv:req.body,cwd:req.query.cwd,env:req.body})}`);
    assert.equal(result.status,'completed');assert.equal(fork(result).length,0);assert.equal(result.findings.length,0);
    assert.match(result.notes.join('\n'),/execPath, execArgv, cwd and env are unmodeled/);
  }
});
test('recognized mutable or escaped package identity retains low unresolved arg0',()=>{
  for(const suffix of ['cp.fork=custom;', 'modify(cp);','const alias=cp;','const f=cp.fork;']) {
    const result=run("const cp=require('child_process');"+suffix+'function route(req){cp.fork(req.query.module)}');
    assert.equal(fork(result).length,1);assert.equal(fork(result)[0].confidence,'low');assert.equal(fork(result)[0].title,'Input reaches an unresolved fork-shaped call');
  }
  const result=run("const {fork:launch}=require('child_process'); launch=custom; function route(req){launch(req.query.module)}");
  assert.equal(fork(result)[0].confidence,'low');
});
test('same-package unsupported load/customization vetoes identity without claiming local shadowed fork',()=>{
  const source="import {fork as launch} from 'child_process';function route(req){launch(req.query.module)}";
  const result=run(source,{'other.ts':"require('child_process').fork=custom;"});assert.equal(fork(result)[0].confidence,'low');
  for(const head of ["function require(x){return {fork(x){}}}","const local={fork(x){}};"]) {
    const call=head.startsWith('function')?"require('child_process').fork":'local.fork';
    assert.equal(fork(run(head+`function route(req){${call}(req.query.module)}`)).length,0);
  }
  assert.equal(fork(run("import launch from 'child_process';function route(req){launch(req.query.module)}")).length,0);
});
test('bare legacy fork remains heuristic unless the new native role recognizes it',()=>{
  const legacy=run('function route(req){fork(req.query.module)}');assert.equal(fork(legacy).length,0);assert.equal(legacy.findings[0]?.ruleId,'ast:shell-input-sink');
  const native=run("const {fork}=require('child_process');function route(req){fork(req.query.module)}");assert.equal(fork(native).length,1);assert.equal(native.findings.length,1);
});
test('ordinary scalar helper actual-return and relative import preserve module evidence in both call orders',()=>{
  for(const reverse of [false,true]) {
    const calls=["send('./worker.js')",'send(req.query.module)'];if(reverse) calls.reverse();
    const result=run("const cp=require('child_process');import {pass} from './helper';function send(x){cp.fork(pass(x))}function route(req){"+calls.join(';')+'}',{'helper.ts':'export function pass(value){return value}'});
    assert.equal(fork(result).length,1);assert.equal(fork(result)[0].confidence,'medium');
    assert.ok(fork(result)[0].staticFlow?.steps.some(s=>s.role==='return' && s.location.path==='helper.ts'));
    assert.ok(fork(result)[0].staticFlow?.steps.some(s=>s.role==='source' && s.location.path==='app.ts'));
  }
});
test('unknown input and incomplete scope retain low role without invented source',()=>{
  const source="import {fork as launch} from 'child_process';function route(req){launch(opaque(req.query.module))}";
  const result=run(source);assert.equal(fork(result)[0].confidence,'low');assert.equal(fork(result)[0].title,'Input reaches a Node fork module path');
  const partial=runBuiltinAst(snapshot({'app.ts':"import {fork as launch} from 'child_process';function route(req){launch(req.query.module)}"},false),false);
  assert.equal(fork(partial)[0].confidence,'low');assert.equal(fork(partial)[0].title,'Input reaches an unresolved fork-shaped call');
});
test('scope parse failures and legacy aggregate caps remain incomplete gates',()=>{
  const text="const cp=require('child_process');function route(req){cp.fork(req.query.module)}";
  const parse=run(text,{'bad.ts':'function broken('});assert.equal(parse.status,'partial');assert.equal(fork(parse)[0].confidence,'low');
  for(const limits of [{...FLOW_LIMITS,nodeVisits:1},{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1}]) {
    const result=runBuiltinAst(snapshot({'app.ts':text}),false,limits);assert.equal(result.status,'partial');
    assert.equal(evaluateGate(createReport([result],'source','2026-10-05T00:00:00.000Z'),'none').exitCode,2);
  }
});
test('fork role does not change SQL HTTP HTML taint or first-argument source precedence',()=>{
  const result=run("const cp=require('child_process');function route(req){cp.fork('./worker.js',[req.query.x]);db.query(req.query.x);fetch(req.query.x);document.write(req.query.x)}");
  assert.equal(fork(result).length,0);for(const id of ['ast:sql-input-sink','ast:server-request','ast:html-input-sink'])assert.equal(result.findings.filter(f=>f.ruleId===id).length,1);
});
test('four projections retain the static candidate contract and new ruleset',()=>{
  const check=run("import {fork} from 'child_process';function route(req){fork(req.query.module)}");
  const report=createReport([check],'source','2026-10-05T00:00:00.000Z');assert.equal(RULESET_VERSION,'2026-10-06.1');
  assert.match(toMarkdown(report),/Input reaches a Node fork module path/);assert.match(JSON.stringify(toSarif(report)),/ast:fork-module-path/);
  const agent=toAgentReport(report);assert.equal(agent.findings[0].verification.vulnerabilityConfirmed,false);assert.equal(agent.findings[0].verification.remediationVerified,false);
  assert.equal(agent.findings[0].verification.state,'not_run');assert.match(JSON.stringify(report),/ast:fork-module-path/);
});

test('mixed named loads and mutable declarations recognize fork but retain unresolved identity',()=>{
  for(const head of ["import {fork as launch,spawn} from 'child_process';", "const {fork:launch,exec}=require('child_process');", "let {fork:launch}=require('child_process');"]) {
    const result=run(head+'function route(req){launch(req.query.module)}');assert.equal(fork(result).length,1);assert.equal(fork(result)[0].confidence,'low');assert.equal(fork(result)[0].title,'Input reaches an unresolved fork-shaped call');
  }
});
test('same-owner declaration-before-use is structural and deferred body is not runtime TDZ proof',()=>{
  const early=run("launch(req.query.module);const {fork:launch}=require('child_process');");assert.equal(fork(early)[0]?.confidence,'low');
  const deferred=run("function route(req){launch(req.query.module)}const {fork:launch}=require('child_process');");assert.equal(fork(deferred)[0]?.title,'Input reaches a Node fork module path');
});

test('recognized fork aliases override eval SQL HTTP HTML names without argv attribution',()=>{
  for(const alias of ['eval','query','fetch','exec','setTimeout']) for(const head of [
    `import {fork as ${alias}} from 'child_process';`,
    `const {fork:${alias}}=require('child_process');`
  ]) {
    const risky=run(head+`function route(req){${alias}(req.query.module,[req.query.arg])}`);
    assert.equal(risky.findings.length,1);assert.equal(fork(risky).length,1);
    const normal=run(head+`function route(req){${alias}('./worker.js',[req.query.arg],{env:req.body})}`);
    assert.equal(normal.findings.length,0);
  }
  const ordinary=run('function route(req){eval(req.query.module);db.query(req.query.module);fetch(req.query.module);document.write(req.query.module)}');
  for(const id of ['ast:dynamic-code','ast:sql-input-sink','ast:server-request','ast:html-input-sink'])assert.equal(ordinary.findings.filter(f=>f.ruleId===id).length,1);
});
test('many import/destructuring items consume index validation budget and partial cannot certify identity',()=>{
  for(const esm of [true,false]) {
    const items=Array.from({length:80},(_,n)=>esm?`fork as launch${n}`:`fork:launch${n}`).join(',');
    const text=(esm?`import {${items}} from 'child_process';`:`const {${items}}=require('child_process');`)+`function route(req){launch79(req.query.module)}`;
    const normal=run(text);assert.equal(normal.status,'completed');assert.equal(fork(normal)[0]?.confidence,'medium');
    const max=Number(normal.metrics?.indexWork);assert.ok(max>80);
    const partial=runBuiltinAst(snapshot({'app.ts':text}),false,{...FLOW_LIMITS,indexWork:max-1});
    assert.equal(partial.status,'partial');assert.equal(partial.metrics?.indexComplete,false);
    assert.equal(fork(partial)[0]?.title,'Input reaches an unresolved fork-shaped call');assert.equal(fork(partial)[0]?.confidence,'low');
  }
});
