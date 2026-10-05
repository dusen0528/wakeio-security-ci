import test from 'node:test';
import assert from 'node:assert/strict';
import {runBuiltinAst} from '../src/source/ast.js';
import {FLOW_LIMITS,type FlowLimits} from '../src/source/modules.js';
import {createReport,evaluateGate,toAgentReport,toMarkdown,toSarif} from '../src/report.js';
import type {SourceSnapshot} from '../src/source/types.js';
const snap=(texts:Record<string,string>,complete=true):SourceSnapshot=>{const files=Object.entries(texts).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));return {root:'/never-execute',files,issues:[],complete,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};};
const run=(texts:Record<string,string>,complete=true,limits:FlowLimits=FLOW_LIMITS)=>runBuiltinAst(snap(texts,complete),false,limits);
const sql=(c:ReturnType<typeof run>)=>c.findings.filter(f=>f.ruleId==='ast:sql-input-sink');
const entry=(load="const {send:forward}=require('./util')",arg='req.query.ownedSourceMarker')=>`${load};function route(req){forward(${arg})}`;
const producer="module.exports.send = value => {db.query(value);return value};";
const files=(text=entry(),body=producer,extra:Record<string,string>={})=>({'entry.js':text,'util/index.js':body,...extra});
const gap=(c:ReturnType<typeof run>,reason='module_export_unsupported')=>c.analysisGaps?.items.find(g=>g.reason===reason);
function projections(c:ReturnType<typeof run>,source:string){const r=createReport([c],'source',new Date());for(const output of [JSON.stringify(r),JSON.stringify(toAgentReport(r)),toMarkdown(r),JSON.stringify(toSarif(r))]){assert.ok(!output.includes(source));assert.ok(!output.includes('ownedSourceMarker'));}return r;}

test('directory static member function connects real actuals and native sink with normal/redaction controls',()=>{
 for(const load of ["const {send:forward}=require('./util')","const forwardApi=require('./util');const ignored=0"]){
  const text=load.includes('forwardApi')?entry(load).replace('forward(req','forwardApi.send(req'):entry(load);
  const c=run(files(text));assert.equal(c.status,'completed');assert.equal(sql(c).length,1);assert.equal(sql(c)[0].confidence,'medium');assert.equal(sql(c)[0].kind,'candidate');assert.equal(sql(c)[0].severity,'high');
  assert.equal(sql(c)[0].location.path,'util/index.js');for(const role of ['source','call','parameter','sink'])assert.ok(sql(c)[0].staticFlow?.steps.some(s=>s.role===role));
  assert.equal(evaluateGate(projections(c,text),'high').exitCode,1);
  const normalText=text.replace('req.query.ownedSourceMarker',"'SELECT ownedSourceMarker'");const n=run(files(normalText));assert.equal(n.status,'completed');assert.equal(sql(n).length,0);assert.equal(evaluateGate(projections(n,normalText),'high').exitCode,0);
 }
});
test('scalar actual/returns and repeated contexts preserve taint independent of call order',()=>{
 for(const reverse of [false,true]){
  const calls=["forward('fixed')",'forward(req.body.ownedSourceMarker)'];if(reverse)calls.reverse();
  const text=`const {echo:forward}=require('./util');function route(req){${calls.join(';')};db.query(forward(req.params.ownedSourceMarker));db.query(forward(req.params.ownedSourceMarker))}`;
  const c=run(files(text,'function identity(value){return value};module.exports.echo=identity;'));assert.equal(c.status,'completed');assert.equal(sql(c).length,2);assert.ok(sql(c).every(f=>f.staticFlow?.steps.some(s=>s.role==='return'&&s.location.path==='util/index.js')));assert.ok(Number(c.metrics?.summaryWork)>0);
 }
});
test('file candidate priority, directory ambiguity, trailing separator and explicit extensions are deterministic',()=>{
 const fixed='module.exports.send=value=>{};';
 assert.equal(sql(run(files(entry(),producer,{'util.js':fixed}))).length,0);
 assert.ok(gap(run(files(entry(),producer,{'util.js':fixed,'util.ts':fixed})),'module_ambiguous'));
 assert.ok(gap(run(files(entry(),producer,{'util/index.ts':producer})),'module_ambiguous'));
 assert.equal(sql(run(files(entry("const {send:forward}=require('./util/')"),producer,{'util.js':fixed}))).length,1);
 const explicit=run({'entry.js':entry("const {send:forward}=require('./util.mts')"),'util.mts':producer});assert.equal(sql(explicit).length,1);
 const missing=run({'entry.js':entry(),'util/index.mts':producer});assert.ok(gap(missing,'module_missing'));assert.equal(missing.status,'partial');
 const directMissing=run(files(entry("const {send:forward}=require('./util.js')")));assert.ok(gap(directMissing,'module_missing'));
});
test('UMD, re-export, receiver/async/duplicate/whole exports and scope failures are unproved rather than missing',()=>{
 for(const body of ["(function(exports){exports.send=value=>db.query(value)})(module.exports)","module.exports.send=require('./other').send;",'module.exports.send=function(value){return this.value};','module.exports.send=function*(value){yield value};',producer+producer,producer+';module.exports={};','const module={exports:{}};'+producer]){
  const c=run(files(entry(),body));assert.equal(c.status,'partial');assert.ok(gap(c));assert.equal(gap(c)?.nextReview,'review_check_diagnostics');assert.equal(gap(c)?.location?.path,'entry.js');assert.ok(!gap(c,'module_missing'));
 }
 const c=run(files(),false);assert.equal(c.status,'partial');assert.ok(gap(c));
});
test('canonical file identity closes every observed importer deep-write/alias/escape/loader veto',()=>{
 for(const use of ['api.send=custom','api.deep.member=custom','delete api.send','api.send++','const alias=api','const box={api}','modify(api)','Object.defineProperty(api,"send",{value:custom})']){
  const c=run(files(entry(),producer,{'other.js':`const api=require('./util/index.js');${use}`}));assert.equal(c.status,'partial',use);assert.ok(gap(c),use);assert.equal(sql(c).length,0,use);assert.ok(Number(c.metrics?.externalEntryFunctions)>0);
 }
 for(const load of ["require('./util/index.js').send('x')","import * as api from './util/index.js'","export {send} from './util/index.js'","import('./util/index.js')","module.require('./util/index.js')","import {createRequire} from 'node:module'"]){
  const c=run(files(entry(),producer,{'other.ts':load}));assert.equal(c.status,'partial',load);assert.ok(gap(c));assert.equal(sql(c).length,0);
 }
 const normal=run(files(entry(),producer,{'other.js':"const api=require('./util/index.js');function second(req){api.send(req.body.ownedSourceMarker)}"}));assert.equal(normal.status,'completed');assert.equal(sql(normal).length,1);
});
test('relative named ESM and existing object export unsupported are actionable while unrelated calls remain limitations',()=>{
 const c=run({'entry.ts':"import {send} from './util';function route(req){db.query(send(req.query.value))}",'util/index.ts':'export default function send(v){return v}'});assert.equal(c.status,'partial');assert.ok(gap(c));assert.equal(sql(c)[0].confidence,'low');assert.equal(sql(c)[0].staticFlow?.truncated,true);
 const ext=run({'entry.js':"const {send}=require('external');function route(req){db.query(send(req.query.value))}"});assert.equal(ext.status,'completed');assert.equal(sql(ext)[0].confidence,'low');
 const shadow=run(files("function require(x){return fake};"+entry()));assert.equal(shadow.status,'completed');assert.equal(sql(shadow).length,0);
});
test('new gap preserves four projections, actual site, nextRead, gate2 and bounded accounting',()=>{
 const text=entry();const c=run(files(text,'module.exports.send=unknown;'));const r=projections(c,text);assert.equal(evaluateGate(r,'none').exitCode,2);
 assert.match(toMarkdown(r),/module_export_unsupported/);assert.match(JSON.stringify(toSarif(r)),/module_export_unsupported/);const agent=toAgentReport(r);assert.ok(agent.summary!.incompleteChecks.some(c=>c.analysisGaps?.representativeItems.some(g=>g.reason==='module_export_unsupported')));assert.equal(agent.summary!.nextRead.kind,'review_check_diagnostics');assert.equal(c.analysisGaps?.accounting,'exact');
});
test('existing budgets, cycles and cross-sinks retain partial and supported actual evidence',()=>{
 for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1},{...FLOW_LIMITS,moduleEdges:0},{...FLOW_LIMITS,summaryWork:0}]){const c=run(files(),true,limits);assert.equal(c.status,'partial');assert.equal(evaluateGate(createReport([c],'source',new Date()),'none').exitCode,2);}
 const cycle=run(files(entry(),"const e=require('../entry');"+producer));assert.equal(cycle.status,'partial');assert.ok(gap(cycle));
 for(const sink of ['fetch','document.write','exec']){const c=run(files(entry(),`module.exports.send=value=>${sink}(value)`));assert.equal(c.status,'completed');assert.ok(c.findings.some(f=>f.confidence==='medium'&&f.staticFlow?.steps.some(s=>s.role==='parameter')));}
});

test('ordinary function hoisting and immutable const aliases differ from export-before-const initialization',()=>{
 const good=run(files(entry(),'const original=value=>db.query(value);const alias=original;module.exports.send=alias;'));assert.equal(good.status,'completed');assert.equal(sql(good).length,1);
 const hoisted=run(files(entry(),'module.exports.send=helper;function helper(value){db.query(value)}'));assert.equal(hoisted.status,'completed');assert.equal(sql(hoisted).length,1);
 for(const body of ['module.exports.send=alias;function helper(value){return value};const alias=helper;','const alias=helper;const helper=value=>value;module.exports.send=alias;']){const c=run(files(entry(),body));assert.equal(c.status,'partial');assert.ok(gap(c));assert.equal(sql(c).length,0);}
});

test('isolated relative export failure counts one unsupported call and one actual site gap',()=>{
 const c=run({'entry.ts':"import {missing} from './helper.js';function route(req){missing(req.query.value)}",'helper.ts':'export default function helper(value){return value}'});
 assert.equal(c.status,'partial');assert.equal(c.metrics?.unsupportedCalls,1);assert.equal(c.analysisGaps?.eventsObserved,1);assert.equal(c.analysisGaps?.items.length,1);const item=gap(c)!;assert.equal(item.observations,1);assert.equal(item.extent,'site');assert.equal(item.location?.path,'entry.ts');assert.equal(item.nextReview,'review_check_diagnostics');assert.equal(evaluateGate(createReport([c],'source',new Date()),'none').exitCode,2);
});
test('legacy CJS scalar maps share certified normal and unproved canonical importer mutation or escape',()=>{
 for(const producer of ["const echo=value=>'fixed';module.exports={echo};","exports.echo=value=>'fixed';"]){
  const input="const {echo}=require('./util');function route(req){db.query(echo(req.query.ownedSourceMarker))}";
  for(const load of ["const api=require('./util/index.js');api.echo=value=>value;","const api=require('./util/index.js');modify(api);"]){
   const c=run({'entry.js':input,'util/index.js':producer,...(load?{'other.js':load}:{})});assert.equal(c.status,'partial');assert.ok(gap(c));assert.equal(sql(c).length,1);assert.equal(sql(c)[0].confidence,'low');assert.equal(sql(c)[0].staticFlow?.truncated,true);assert.ok(!sql(c)[0].staticFlow?.steps.some(s=>s.role==='parameter'&&s.location.path==='util/index.js'));assert.equal(evaluateGate(projections(c,input),'none').exitCode,2);
  }
  const trailing=run({'entry.js':input.replace("'./util'","'./util/'"),'util/index.js':producer});assert.equal(trailing.status,'completed');assert.equal(sql(trailing).length,0);
  const direct=run({'entry.js':input.replace("'./util'","'./util/index.js'"),'util/index.js':producer});assert.equal(direct.status,'completed');assert.equal(sql(direct).length,0); // The direct path now has the same closed importer identity as directory.
 }
});
