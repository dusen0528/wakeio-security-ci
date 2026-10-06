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
const producer="const cp=require('node:child_process');const jobs={run(value){cp.fork(value)},echo(value){return value}};module.exports={jobs};";
const route=(arg:string)=>`const api=require('./lib/api');function route(req){api.jobs.run(${arg})}`;
const files=(entry:string,api=producer,extra:Record<string,string>={})=>({'entry.js':entry,'lib/api.js':api,...extra});
const run=(texts:Record<string,string>,complete=true)=>runBuiltinAst(snapshot(texts,complete),false);
const fork=(check:ReturnType<typeof run>)=>check.findings.filter(f=>f.ruleId==='ast:fork-module-path');
function assertRedacted(check:ReturnType<typeof run>,input:string,fragments:readonly string[]):void {
 const report=createReport([check],'source',new Date());
 const outputs=[JSON.stringify(report),JSON.stringify(toAgentReport(report)),toMarkdown(report),JSON.stringify(toSarif(report))];
 for(const fragment of fragments){
  assert.ok(input.includes(fragment),'redaction control must exist in the actual source input');
  for(const output of outputs)assert.ok(!output.includes(fragment),'public projection must omit actual source text');
 }
}
test('required two-hop relative CJS wrapper/const child resolves actual modulePath with complete position evidence',()=>{
 for(const wrapped of [false,true]){
  const api=wrapped?producer.replace('module.exports={jobs};','const exported={jobs};module.exports=exported;'):producer;
  const riskyInput=route('req.query.modulePath');
  const risky=run(files(riskyInput,api));assert.equal(risky.status,'completed');assert.equal(fork(risky).length,1);assert.equal(fork(risky)[0].confidence,'medium');
  assertRedacted(risky,riskyInput,['req.query.modulePath','api.jobs.run(req.query.modulePath)']);
  assert.equal(fork(risky)[0].location.path,'lib/api.js');
  const steps=fork(risky)[0].staticFlow!.steps;for(const role of ['source','call','parameter','sink'])assert.ok(steps.some(s=>s.role===role));
  assert.equal(steps.find(s=>s.role==='source')?.location.path,'entry.js');assert.equal(evaluateGate(createReport([risky],'source',new Date()),'high').exitCode,1);
  const normalInput=route("'./owned-worker.js', [req.query.modulePath]");
  const normal=run(files(normalInput,api));assert.equal(normal.status,'completed');assert.equal(fork(normal).length,0);assert.equal(evaluateGate(createReport([normal],'source',new Date()),'high').exitCode,0);
  assertRedacted(normal,normalInput,['req.query.modulePath','./owned-worker.js']);
 }
});
test('method scalar returns/context cache and exported no-input roots preserve actual taint in both call orders',()=>{
 for(const reverse of [false,true]){
  const calls=["api.jobs.run('./fixed.js')",'api.jobs.run(req.body.value)'];if(reverse)calls.reverse();
  const check=run(files(`const api=require('./lib/api');function route(req){${calls.join(';')};db.query(api.jobs.echo(req.params.id));api.jobs.run(req.body.value)}`));
  assert.equal(check.status,'completed');assert.equal(fork(check).length,1);assert.equal(fork(check)[0].confidence,'medium');assert.ok(Number(check.metrics?.summaryWork)>0);
  assert.ok(check.findings.some(f=>f.ruleId==='ast:sql-input-sink'&&f.staticFlow?.steps.some(s=>s.role==='return')));
  assert.ok(Number(check.metrics?.externalEntryFunctions)>=2);assert.ok(Number(check.metrics?.entryRootsDeclared)>=2);
 }
});
test('actual formal paths reuse SQL HTTP HTML and relative scalar helpers without general safe suppression',()=>{
 for(const sink of ['db.query','fetch','document.write']){
  const api=`const jobs={run(value){${sink}(value);return value}};module.exports={jobs};`;
  const check=run(files(route('req.query.value'),api));assert.equal(check.status,'completed');assert.ok(check.findings.some(f=>f.confidence==='medium'&&f.location.path==='lib/api.js'));assert.ok(check.findings.some(f=>f.staticFlow?.steps.some(s=>s.role==='call')));
 }
 const api="const {forward}=require('./scalar');const jobs={run(value){return forward(value)}};module.exports={jobs};";
 const check=run(files("const api=require('./lib/api');function route(req){db.query(api.jobs.run(req.body.id))}",api,{'lib/scalar.js':'const forward=x=>x;module.exports={forward};'}));assert.equal(check.status,'completed');assert.ok(check.findings.some(f=>f.confidence==='medium'&&f.staticFlow?.steps.some(s=>s.role==='return'&&s.location.path==='lib/scalar.js')));
});
test('all observed importer writes/alias/storage/escape/reflection invalidate shared group identity',()=>{
 for(const use of [
  'api.jobs.run=custom;', 'api.jobs.deep.field=custom;', "api.jobs['run']=custom;", 'delete api.jobs.run;', 'api.jobs.count++;',
  'const other=api.jobs;', 'const box={api};', 'modify(api.jobs);', 'function expose(){return api.jobs}', 'Object.defineProperty(api.jobs,"run",{value:custom});'
 ]){
  const check=run(files(route('req.query.value'),producer,{'other.js':`const api=require('./lib/api');${use}`}));assert.equal(check.status,'partial');assert.equal(fork(check).length,0);assert.ok(Number(check.metrics?.unsupportedCalls)>0);assert.ok(Number(check.metrics?.externalEntryFunctions)>=2);
 }
 const plain=run(files(route('req.query.value'),producer,{'other.js':"const api=require('./lib/api');function other(req){api.jobs.run(req.body.value)}"}));assert.equal(fork(plain).length,1);
});
test('unsupported observed loaders target the same resolved file, not merely spelling or receiver name',()=>{
 for(const load of ["require('./lib/api').jobs.run('fixed');", "const {jobs}=require('./lib/api');", "import * as api from './lib/api';", "export {default} from './lib/api';", "import api=require('./lib/api');", "import('./lib/api');", "(require)('./lib/api');", "require(('./lib/api'));", "import(('./lib/api'));"]){
  const check=run(files(route('req.query.value'),producer,{'other.ts':load}));assert.equal(fork(check).length,0);assert.ok(Number(check.metrics?.unsupportedCalls)>0);
 }
 const unrelated=run(files(route('req.query.value'),producer,{'other.js':"const other=(require)(('./else'));",'else.js':'module.exports={nothing:1};'}));assert.equal(fork(unrelated).length,1);
 for(const text of ['const loader=require;','require(dynamicName);','require.cache.x=custom;'])assert.equal(fork(run(files(route('req.query.value'),producer,{'other.js':text}))).length,0);
});
test('opaque shapes, receiver-state, exports overwrite/shadow and initialization do not create resolved identity',()=>{
 for(const api of [
  producer.replace('module.exports={jobs};','module.exports={jobs};module.exports={jobs};'),
  producer.replace('module.exports={jobs};','module.exports={jobs};exports.x=custom;'),
  producer.replace('module.exports={jobs};','module.exports={...opaque,jobs};'),
  producer.replace('module.exports={jobs};','module.exports={jobs,jobs};'),
  producer.replace('module.exports={jobs};','module.exports={get jobs(){return jobs}};'),
  producer.replace('run(value){cp.fork(value)}','run(value){cp.fork(this.value)}'),
  producer.replace('run(value){cp.fork(value)}',"['run'](value){cp.fork(value)}"),
  "const module={};"+producer,
  producer.replace('module.exports={jobs};','modify(jobs);module.exports={jobs};'),
  producer.replace('module.exports={jobs};','const alias=jobs;module.exports={jobs};')
 ]) {const check=run(files(route('req.query.value'),api));assert.equal(fork(check).length,0);}
 for(const entry of ["function require(x){return fake};"+route('req.query.value'), 'api.jobs.run(req.query.value);const api=require("./lib/api");'])assert.equal(fork(run(files(entry))).length,0);
});
test('cycle/index/scope/flow/summary limits preserve partial gate and known exported roots',()=>{
 const cyc=run(files(route('req.query.value'),"const entry=require('../entry');"+producer));assert.equal(fork(cyc).length,0);
 for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1},{...FLOW_LIMITS,summaryWork:0},{...FLOW_LIMITS,callDepth:1},{...FLOW_LIMITS,moduleEdges:0}]){
  const check=runBuiltinAst(snapshot(files(route('req.query.value'))),false,limits);assert.equal(check.status,'partial');assert.equal(evaluateGate(createReport([check],'source',new Date()),'none').exitCode,2);
 }
 assert.equal(fork(run(files(route('req.query.value')),false)).length,0);
 assert.equal(fork(run(files(route('req.query.value'),producer,{'bad.ts':'function ('}))).length,0);
});
test('four projections retain unverified candidate, IDs and the current semantic version',()=>{
 const input=route('req.query.value');
 const check=run(files(input)),report=createReport([check],'source',new Date());assert.equal(RULESET_VERSION,'2026-10-05.18');assert.equal(fork(check).length,1);
 const agent=toAgentReport(report);assert.equal(agent.scanGate.exitCode,1);assert.ok(agent.findings.every(f=>f.verification.vulnerabilityConfirmed===false&&f.verification.remediationVerified===false));
 assert.match(toMarkdown(report),/Node fork module path/);assert.match(JSON.stringify(toSarif(report)),/ast:fork-module-path/);assert.equal(toSarif(report).runs[0].results?.[0].ruleId,report.checks[0].findings[0].ruleId);
 assertRedacted(check,input,['req.query.value','api.jobs.run(req.query.value)']);
});

test('observed ESM native loader and module.require boundary cannot certify an unchanged group',()=>{
 const normal=run(files(route('req.query.value')));assert.equal(fork(normal).length,1);
 const shadow=run(files(route('req.query.value'),producer,{'other.js':"const module={require(x){return x}};module.require('./lib/api');"}));assert.equal(fork(shadow).length,1);
 for(const load of [
  "import {createRequire} from 'node:module';const load=createRequire(import.meta.url);load('./lib/api');",
  "module.require('./lib/api').jobs.run('fixed');", "module['require']('./lib/api').jobs.run('fixed');",
  "import loader=require('node:module');", "export {createRequire} from 'node:module';", "import('node:module');"
 ]) {const check=run(files(route('req.query.value'),producer,{'other.js':load}));assert.equal(check.status,'partial');assert.equal(fork(check).length,0);}
});
