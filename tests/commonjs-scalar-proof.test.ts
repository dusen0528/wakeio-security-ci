import test from 'node:test';
import assert from 'node:assert/strict';
import {runBuiltinAst} from '../src/source/ast.js';
import {FLOW_LIMITS,type FlowLimits} from '../src/source/modules.js';
import {createReport,evaluateGate,toAgentReport,toMarkdown,toSarif} from '../src/report.js';
import type {SourceSnapshot} from '../src/source/types.js';
const snapshot=(texts:Record<string,string>,complete=true):SourceSnapshot=>{const files=Object.entries(texts).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));return {root:'/never-execute',files,issues:[],complete,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};};
const run=(texts:Record<string,string>,complete=true,limits:FlowLimits=FLOW_LIMITS)=>runBuiltinAst(snapshot(texts,complete),false,limits);
const sql=(c:ReturnType<typeof run>)=>c.findings.filter(f=>f.ruleId==='ast:sql-input-sink');
const gap=(c:ReturnType<typeof run>)=>c.analysisGaps?.items.some(g=>g.reason==='module_export_unsupported');
const producers=(body:string)=>[`exports.send=${body};`,`const send=${body};module.exports={send};`,`module.exports.send=${body};`];
const entry=(specifier:string,arg='req.query.ownedScalarMarker')=>`const {send:forward}=require('${specifier}');function route(req){db.query(forward(${arg}))}`;
const inputs=(source:string,producer:string,extra:Record<string,string>={})=>({'entry.js':source,'util/index.js':producer,...extra});
function publicEvidence(c:ReturnType<typeof run>,source:string){const report=createReport([c],'source',new Date());for(const text of [JSON.stringify(report),toMarkdown(report),JSON.stringify(toAgentReport(report)),JSON.stringify(toSarif(report))]){assert.ok(source.includes('ownedScalarMarker'));assert.ok(!text.includes(source));assert.ok(!text.includes('ownedScalarMarker'));}assert.ok(toAgentReport(report).findings.every(f=>!f.verification.vulnerabilityConfirmed&&!f.verification.remediationVerified));return report;}

test('all scalar producers support actual formal return and fixed normal across canonical direct and directory loads',()=>{
 for(const specifier of ['./util','./util/','./util/index.js','./unused/../util/index.js'])for(const body of producers('value=>value')){
  const source=entry(specifier),r=run(inputs(source,body));assert.equal(r.status,'completed',body+specifier);assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'medium');
  for(const role of ['source','call','parameter','return','sink'])assert.ok(sql(r)[0].staticFlow?.steps.some(s=>s.role===role),role);assert.equal(evaluateGate(publicEvidence(r,source),'high').exitCode,1);
  const normalBody=body.replace('value=>value',"value=>'fixed'"),n=run(inputs(source,normalBody));assert.equal(n.status,'completed');assert.equal(sql(n).length,0);assert.equal(evaluateGate(publicEvidence(n,source),'high').exitCode,0);
 }
});
test('namespace direct calls, supported inner sinks and mixed flat child returns use the same identity',()=>{
 for(const body of producers('value=>db.query(value)')){const r=run(inputs("const api=require('./util');function route(req){api.send(req.body.value)}",body));assert.equal(r.status,'completed');assert.equal(sql(r)[0].confidence,'medium');assert.equal(sql(r)[0].location.path,'util/index.js');}
 const body="const send=value=>value;const jobs={run(value){return send(value)}};module.exports={send,jobs,version:'fixed'};";
 const r=run(inputs("const api=require('./util');const {send}=require('./util/index.js');function route(req){db.query(api.jobs.run(req.query.id));db.query(api.send(req.body.id));db.query(send(req.params.id))}",body));assert.equal(r.status,'completed');assert.equal(sql(r).length,3);assert.ok(sql(r).every(f=>f.confidence==='medium'));
});
test('all canonical importers can veto stale fixed scalar targets by write, deep write, escape or unsupported loaders',()=>{
 for(const body of producers("value=>'fixed'"))for(const other of ['api.send=value=>value','delete api.send','api.deep.member=custom','const alias=api','const box={api}','modify(api)','Object.defineProperty(api,"send",{value:custom})','const fn=api.send','setImmediate(api.send)']){
  const source=entry('./util'),r=run(inputs(source,body,{'other.js':"const api=require('./util/index.js');"+other}));assert.equal(r.status,'partial',body+other);assert.ok(gap(r));assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');assert.equal(sql(r)[0].staticFlow?.truncated,true);assert.ok(!sql(r)[0].staticFlow?.steps.some(s=>s.role==='parameter'));assert.equal(evaluateGate(publicEvidence(r,source),'none').exitCode,2);
 }
 for(const other of ["require('./util/index.js').send('x')","import {send} from './util/index.js'","export {send} from './util/index.js'","import('./util/index.js')","import api=require('./util/index.js')","module.require('./util/index.js')"]){const r=run(inputs(entry('./util'),producers("value=>'fixed'")[0],{'other.ts':other}));assert.equal(r.status,'partial');assert.ok(gap(r));}
});
test('exact destructuring never confuses nested/default/computed/rest bindings with flat exports',()=>{
 const body="const send=value=>'fixed';const nested={send(value){return value}};module.exports={send,nested};";
 for(const load of ["const {nested:{send}}=require('./util')","const {send=custom}=require('./util')","const {['send']:send}=require('./util')","const {...send}=require('./util')","const [send]=require('./util')"]){const r=run(inputs(load+';function route(req){db.query(send(req.query.id))}',body));assert.equal(r.status,'partial',load);assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
});
test('producer whole replacement, duplicate/shadow/opaque export and target mutation never certify selected slots',()=>{
 for(const body of ["exports.send=value=>'fixed';exports.send=value=>value;","const send=value=>'fixed';module.exports={send};module.exports={send};","const send=value=>'fixed';module.exports={send};exports.extra=1;","const module={exports:{}};module.exports.send=value=>'fixed';","const exports={};exports.send=value=>'fixed';","const send=value=>'fixed';module.exports={...other,send};","const send=value=>'fixed';module.exports={get send(){return send}};","const send=value=>'fixed';module.exports={send,send};","function send(value){return 'fixed'}exports.send=send;send=value=>value;","const send=value=>'fixed';modify(send);module.exports={send};"]){const r=run(inputs(entry('./util/index.js'),body));assert.equal(r.status,'partial',body);assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
});
test('export discovery preserves known roots through pre-init, invalid aliases, receiver, generator and scope veto',()=>{
 for(const [body,complete] of [["module.exports={send};const send=req=>db.query(req.query.sql);send({query:{sql:'fixed'}});",true],["const send=req=>db.query(req.query.sql);module.exports={send};module.exports={};send({query:{sql:'fixed'}});",true],["exports.send=alias;const alias=send;function send(req){db.query(req.query.sql)}send({query:{sql:'fixed'}});",true],["const send=function(req){db.query(req.query.sql);return this.x};module.exports={send};send({query:{sql:'fixed'}});",true],["function* send(req){db.query(req.query.sql)}exports.send=send;send({query:{sql:'fixed'}});",true],["const send=req=>db.query(req.query.sql);module.exports={send};send({query:{sql:'fixed'}});",false]] as const){const r=run(inputs("const {send}=require('./util');function route(req){send(req.body)}",body),complete);assert.equal(r.status,'partial',body);assert.ok(gap(r));assert.ok(Number(r.metrics?.externalEntryFunctions)>0);assert.ok(sql(r).some(f=>f.confidence==='medium'&&f.location.path==='util/index.js'),body);}
});
test('ordinary hoisting and ordered immutable aliases work but export-before-const and alias-before-referent do not',()=>{
 for(const body of ['exports.send=send;function send(value){return value}', 'function first(value){return value};const second=first;const third=second;module.exports={send:third};']){const r=run(inputs(entry('./util'),body));assert.equal(r.status,'completed');assert.equal(sql(r)[0].confidence,'medium');}
 for(const body of ['exports.send=send;const send=value=>value;','const alias=send;const send=value=>value;module.exports={send:alias};']){const r=run(inputs(entry('./util'),body));assert.equal(r.status,'partial');assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
});
test('safe and tainted contexts retain actual origin in both orders with unchanged scalar cache behavior',()=>{
 for(const reversed of [false,true]){const calls=["db.query(forward('fixed'))",'db.query(forward(req.query.id))'];if(reversed)calls.reverse();const r=run(inputs("const {send:forward}=require('./util');function route(req){"+calls.join(';')+';db.query(forward(req.query.id))}',producers('value=>value')[1]));assert.equal(r.status,'completed');assert.equal(sql(r).length,2);assert.ok(sql(r).every(f=>f.confidence==='medium'));assert.ok(Number(r.metrics?.summariesCached)>0);}
});
test('receiverless async actual body remains supported while generators and async return qualifiers stay unavailable',()=>{
 for(const body of producers('async value=>db.query(value)')){const r=run(inputs("const {send}=require('./util');function route(req){send(req.query.id)}",body));assert.equal(r.status,'completed');assert.equal(sql(r)[0].confidence,'medium');const normal=run(inputs("const {send}=require('./util');function route(req){send('fixed')}",body));assert.equal(normal.status,'completed');assert.equal(sql(normal).length,0);}
 const pg="import {Pool} from 'pg';const db=new Pool();const {send}=require('./util');function route(req){db.query({text:'SELECT $1',values:send(req.query.id)})}";
 const r=run(inputs(pg,'exports.send=async value=>[value];'));assert.equal(r.status,'completed');assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');
 for(const body of ['exports.send=function*(value){return value};','exports.send=async function*(value){return value};']){const r=run(inputs(entry('./util'),body));assert.equal(r.status,'partial');assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
});
test('pure ESM and shadowed local require remain separate from CJS closed identity and interop is unproved',()=>{
 const esm=run({'entry.ts':"import {send} from './helper';function route(req){db.query(send(req.query.id))}",'helper.ts':"export const send=value=>value;"});assert.equal(esm.status,'completed');assert.equal(sql(esm)[0].confidence,'medium');
 const shadow=run(inputs("function require(x){return fake};const {send}=require('./util');function route(req){send(req.query.id)}",producers('value=>db.query(value)')[0]));assert.equal(shadow.status,'completed');assert.ok(!gap(shadow));
 const mixed=run(inputs(entry('./util'),"export function other(v){return v};exports.send=value=>'fixed';"));assert.equal(mixed.status,'partial');assert.ok(gap(mixed));
});
test('budget, recursion and all supported cross-sinks preserve partial and actual evidence without new limits',()=>{
 for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1},{...FLOW_LIMITS,moduleEdges:0},{...FLOW_LIMITS,summaryWork:0}]){const r=run(inputs(entry('./util'),producers('value=>value')[0]),true,limits);assert.equal(r.status,'partial');assert.equal(evaluateGate(createReport([r],'source',new Date()),'none').exitCode,2);}
 const cycle=run(inputs(entry('./util'),"const e=require('../entry');exports.send=value=>value;"));assert.equal(cycle.status,'partial');assert.ok(gap(cycle));
 for(const sink of ['fetch','document.write','exec']){const r=run(inputs("const {send}=require('./util');function route(req){send(req.query.id)}",producers(`value=>${sink}(value)`)[1]));assert.equal(r.status,'completed');assert.ok(r.findings.some(f=>f.confidence==='medium'&&f.staticFlow?.steps.some(s=>s.role==='parameter')));}
});

test('wrapper flat initialization uses construction time, with hoisting and discovered roots preserved',()=>{
 for(const body of ["const send=value=>value;const wrapper={send};module.exports=wrapper;","const first=value=>value;const send=first;const wrapper={send};module.exports=wrapper;","const wrapper={send};module.exports=wrapper;function send(value){return value}"]){const r=run(inputs(entry('./util'),body));assert.equal(r.status,'completed',body);assert.equal(sql(r)[0].confidence,'medium');const n=run(inputs(entry('./util'),body.replace('=>value',"=>'fixed'").replace('return value',"return 'fixed'")));assert.equal(n.status,'completed');assert.equal(sql(n).length,0);}
 for(const body of ["const wrapper={send};const send=value=>'fixed';module.exports=wrapper;","const wrapper={send};const send=first;const first=value=>'fixed';module.exports=wrapper;"]){const r=run(inputs(entry('./util'),body));assert.equal(r.status,'partial',body);assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
 const r=run(inputs("const {send}=require('./util');function route(req){send(req.body)}","const wrapper={send};const send=req=>db.query(req.query.sql);module.exports=wrapper;send({query:{sql:'fixed'}});"));assert.equal(r.status,'partial');assert.ok(sql(r).some(f=>f.confidence==='medium'&&f.location.path==='util/index.js'));
});
test('primitive property metadata is a non-callable sibling and mutation or use cannot certify it',()=>{
 for(const prefix of ['exports','module.exports'])for(const literal of ["'v1'",'42','true','false','null']){const body=`${prefix}.send=value=>value;${prefix}.version=${literal};`;const r=run(inputs(entry('./util'),body));assert.equal(r.status,'completed',body);assert.equal(sql(r)[0].confidence,'medium');const n=run(inputs(entry('./util'),body.replace('=>value',"=>'fixed'")));assert.equal(n.status,'completed');assert.equal(sql(n).length,0);}
 for(const extra of ['exports.version=42;','const api=require("./util");api.version=42;','const api=require("./util");consume(api.version);']){const producer="exports.send=value=>'fixed';exports.version='v1';";const r=extra.startsWith('exports')?run(inputs(entry('./util'),producer+extra)):run(inputs(entry('./util'),producer,{'other.js':extra}));assert.equal(r.status,'partial');assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
 const invoked=run(inputs("const {version}=require('./util');function route(req){db.query(version(req.query.id))}","exports.version='v1';"));assert.equal(invoked.status,'partial');assert.ok(gap(invoked));assert.equal(sql(invoked)[0].confidence,'low');
});
test('native CJS proof ignores unrelated nested names while actual top-level shadows remain unproved',()=>{
 for(const local of ['function unused(exports){return exports}','function unused(module){return module}','function unused(){const exports={};exports.x=1;return exports}','function unused(){var module={exports:{}};return module}','{const exports={};exports.other=1;}','function exports(){}']){
  const body=local+";exports.send=value=>value;";const r=run(inputs(entry('./util'),body));if(local==='function exports(){}'){assert.equal(r.status,'partial');assert.ok(gap(r));}else{assert.equal(r.status,'completed',local);assert.equal(sql(r)[0].confidence,'medium');const n=run(inputs(entry('./util'),body.replace('=>value',"=>'fixed'")));assert.equal(n.status,'completed');assert.equal(sql(n).length,0);}
 }
 for(const body of ['const exports={};exports.send=value=>value;','const module={exports:{}};module.exports.send=value=>value;']){const r=run(inputs(entry('./util'),body));assert.equal(r.status,'partial');assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
 for(const local of ["const exports={};exports.other=value=>'fixed';", "const module={exports:{}};module.exports.other=value=>'fixed';"]){const risky=local+'export function send(value){return value}',r=run({'entry.ts':"import {send} from './util';function route(req){db.query(send(req.query.id))}",'util.ts':risky});assert.equal(r.status,'completed',local);assert.equal(sql(r)[0].confidence,'medium');const n=run({'entry.ts':"import {send} from './util';function route(req){db.query(send(req.query.id))}",'util.ts':risky.replace('return value',"return 'fixed'")});assert.equal(n.status,'completed');assert.equal(sql(n).length,0);}
});
test('ESM default, empty-export and import markers veto genuine CJS independent of named-map size',()=>{
 for(const marker of ['export default function other(){};','export default 1;','export {};','export = other;','import external from "external";','import type {T} from "external";']){const r=run({'entry.ts':entry('./util'),'util.ts':marker+"exports.send=value=>'fixed';"});assert.equal(r.status,'partial',marker);assert.ok(gap(r));assert.equal(sql(r)[0].confidence,'low');}
});

test('catch bindings stay catch-local and do not shadow outside native CJS exports',()=>{
 for(const name of ['exports','module']){
  const local=name==='exports'?"exports.send=value=>'local';consume(exports)":"module.exports.send=value=>'local';consume(module)";
  const body=`try{}catch(${name}){${local}};exports.send=value=>value;`;
  const r=run(inputs(entry('./util'),body));assert.equal(r.status,'completed',name);assert.ok(!gap(r));assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'medium');
  const normal=run(inputs(entry('./util'),body.replace('exports.send=value=>value',"exports.send=value=>'fixed'")));assert.equal(normal.status,'completed');assert.ok(!gap(normal));assert.equal(sql(normal).length,0);
  const shadow=`const ${name}={${name==='module'?'exports:{}':''}};try{}catch(${name}){${local}};${name==='exports'?'exports':'module.exports'}.send=value=>'fixed';`;
  const blocked=run(inputs(entry('./util'),shadow));assert.equal(blocked.status,'partial');assert.ok(gap(blocked));assert.equal(sql(blocked)[0].confidence,'low');
 }
});
