import test from 'node:test';
import assert from 'node:assert/strict';
import {runBuiltinAst} from '../src/source/ast.js';
import {FLOW_LIMITS} from '../src/source/modules.js';
import {createReport,evaluateGate,toAgentReport,toMarkdown,toSarif,RULESET_VERSION} from '../src/report.js';
import type {SourceSnapshot} from '../src/source/types.js';
function snapshot(texts:Record<string,string>,complete=true):SourceSnapshot {
 const files=Object.entries(texts).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));
 return {root:'/never-execute',files,issues:[],complete,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};
}
const run=(text:string,more:Record<string,string>={})=>runBuiltinAst(snapshot({'app.ts':text,...more}),false);
const shell=(check:ReturnType<typeof run>)=>check.findings.filter(f=>f.ruleId==='ast:shell-input-sink');
const native=(check:ReturnType<typeof run>)=>check.findings.filter(f=>f.ruleId==='ast:fork-module-path');
test('immutable direct functions/const arrows/aliases are local identity, not native shell APIs',()=>{
 for(const head of ['function fork(value){return value}', 'const fork=value=>value;', 'function pass(value){return value}const fork=pass;']) {
  const result=run(head+'function route(req){fork(req.query.value)}');assert.equal(result.status,'completed');assert.equal(result.findings.length,0);assert.equal(evaluateGate(createReport([result],'source',new Date()),'high').exitCode,0);
 }
 const deferred=run('function route(req){fork(req.query.value)}const fork=value=>value;');assert.equal(deferred.findings.length,0);
});
test('supported named relative ESM/CJS scalar helpers keep the same local identity boundary',()=>{
 for(const head of ["import {pass as fork} from './helper';", "const {pass:fork}=require('./helper');"]) {
  const result=run(head+'function route(req){fork(req.query.value)}',{'helper.ts':'export function pass(value){return value}'});assert.equal(result.status,'completed');assert.equal(result.findings.length,0);assert.ok(Number(result.metrics?.resolvedCalls)>0);
 }
});
test('same-named local and relative wrappers retain their actual native modulePath sink and trace',()=>{
 for(const relative of [false,true])for(const reverse of [false,true]) {
  const calls=["fork('./worker.js')",'fork(req.query.module)'];if(reverse)calls.reverse();
  const helper="const cp=require('child_process');export function fork(value){cp.fork(value)}";
  const text=(relative?"import {fork} from './helper';":helper)+`function route(req){${calls.join(';')}}`;
  const result=run(text,relative?{'helper.ts':helper}:{});assert.equal(result.status,'completed');assert.equal(shell(result).length,0);assert.equal(native(result).length,1);assert.equal(native(result)[0].confidence,'medium');
  assert.equal(native(result)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.path,'app.ts');assert.equal(native(result)[0].location.path,relative?'helper.ts':'app.ts');
  assert.equal(native(result)[0].title,'Input reaches a Node fork module path');
 }
});
test('fixed native modulePath plus input argv inside local wrapper is not a path claim',()=>{
 const result=run("const cp=require('child_process');function fork(value){cp.fork('./worker.js',[value],{env:value})}function route(req){fork(req.query.arg)}");assert.equal(result.status,'completed');assert.equal(result.findings.length,0);
});
test('local callable proof never erases SQL/HTTP/HTML sinks or returned taint in either actual order',()=>{
 for(const sink of ['db.query','fetch','document.write'])for(const reverse of [false,true]) {
  const calls=["fork('fixed')",'fork(req.query.value)'];if(reverse)calls.reverse();
  const result=run(`function fork(value){${sink}(value);return value}function route(req){${calls.join(';')};${sink}(fork(req.query.value))}`);
  assert.equal(result.status,'completed');assert.equal(shell(result).length,0);assert.ok(result.findings.length>=1);assert.ok(result.findings.every(f=>f.ruleId!=='ast:fork-module-path'));
  assert.ok(result.findings.some(f=>f.staticFlow?.steps.some(s=>s.role==='source')));
 }
});
test('mutation, unsupported alias/escape, missing import and same-owner declaration-before-use keep legacy candidates',()=>{
 for(const text of [
  'let fork=value=>value;fork=custom;function route(req){fork(req.query.value)}',
  'function pass(value){return value}const fork=opaque(pass);function route(req){fork(req.query.value)}',
  'const box={method(value){return value}};const fork=box.method;function route(req){fork(req.query.value)}',
  "import {fork} from './missing';function route(req){fork(req.query.value)}",
  'fork(req.query.value);const fork=value=>value;'
 ]) {const result=run(text);assert.equal(shell(result).length,1);assert.equal(native(result).length,0);}
 const nativeEscaped=run("const cp=require('child_process');modify(cp);function fork(value){cp.fork(value)}function route(req){fork(req.query.value)}");assert.equal(shell(nativeEscaped).length,0);assert.equal(native(nativeEscaped).length,1);assert.equal(native(nativeEscaped)[0].confidence,'low');
});
test('a partial invocation cannot be overwritten by later successful summary/cache observations',()=>{
 for(const reverse of [false,true]) {
  const calls=["fork('fixed')",'fork(req.query.value)'];if(reverse)calls.reverse();
  const text=`function leaf(x){return x}function fork(x){return leaf(x)}function route(req){${calls.join(';')}}`;
  const check=runBuiltinAst(snapshot({'app.ts':text}),false,{...FLOW_LIMITS,callDepth:1});assert.equal(check.status,'partial');assert.equal(shell(check).length,1);assert.equal(evaluateGate(createReport([check],'source',new Date()),'none').exitCode,2);
 }
});
test('index/flow/summary caps and scope uncertainty do not certify a local fork exclusion',()=>{
 const text='function fork(value){return value}function route(req){fork(req.query.value)}';
 for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1},{...FLOW_LIMITS,summaryWork:0}]) {
  const check=runBuiltinAst(snapshot({'app.ts':text}),false,limits);assert.equal(check.status,'partial');assert.equal(evaluateGate(createReport([check],'source',new Date()),'none').exitCode,2);
  if(limits.summaryWork===0)assert.equal(shell(check).length,1);
 }
 assert.equal(shell(runBuiltinAst(snapshot({'app.ts':text},false),false)).length,1);
 assert.equal(shell(run(text,{'bad.ts':'function ('})).length,1);
});
test('ordinary native fork and non-fork shell calls retain their original rules and unverified projection',()=>{
 const check=run("const {fork}=require('child_process');function route(req){fork(req.query.module);exec(req.query.command)}");assert.equal(native(check).length,1);assert.equal(shell(check).length,1);
 const report=createReport([check],'source',new Date());assert.equal(RULESET_VERSION,'2026-10-05.18');assert.match(toMarkdown(report),/Node fork module path/);assert.match(JSON.stringify(toSarif(report)),/ast:fork-module-path/);
 const agent=toAgentReport(report);assert.ok(agent.findings.every(f=>f.verification.vulnerabilityConfirmed===false&&f.verification.remediationVerified===false));assert.equal(agent.scanGate.exitCode,1);
});

test('one completed context and one summary-budget failure at the same call position join conservatively in both orders',()=>{
 for(const reverse of [false,true]) {
  const calls=["send('fixed')",'send(req.query.value)'];if(reverse)calls.reverse();
  const text=`function fork(x){return x}function send(x){fork(x)}function route(req){${calls.join(';')}}`;
  const check=runBuiltinAst(snapshot({'app.ts':text}),false,{...FLOW_LIMITS,summaryWork:3});
  assert.equal(check.status,'partial');assert.ok(Number(check.metrics?.functionContextsCompleted)>0);assert.equal(shell(check).length,1);
  assert.equal(evaluateGate(createReport([check],'source',new Date()),'none').exitCode,2);
 }
});
