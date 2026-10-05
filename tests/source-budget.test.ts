import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { createReport, evaluateGate, toAgentReport } from '../src/report.js';
const snapshot = (texts: Record<string,string>) => ({root:'/never-read',files:Object.entries(texts).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false})),issues:[],ignoredFiles:0,totalBytes:Object.values(texts).reduce((n,t)=>n+Buffer.byteLength(t),0),complete:true});
const scan=(text:string,limits:FlowLimits=FLOW_LIMITS)=>runBuiltinAst(snapshot({'app.ts':text}),false,limits);
const sql=(check:ReturnType<typeof scan>)=>check.findings.filter(f=>f.ruleId==='ast:sql-input-sink');
function counters(check:ReturnType<typeof scan>){
 const m=check.metrics!;
 assert.equal(m.nodeVisits,Number(m.indexWork)+Number(m.flowWork));
 assert.ok(Number(m.indexWork)<=Number(m.maxIndexWork));assert.ok(Number(m.flowWork)<=Number(m.maxFlowWork));assert.ok(Number(m.nodeVisits)<=Number(m.maxNodeVisits));
 for(const prefix of ['topLevel','entryRoots','functionContexts'])assert.equal(m[`${prefix}Started`],Number(m[`${prefix}Completed`])+Number(m[`${prefix}Partial`]));
 for(const prefix of ['topLevel','entryRoots'])assert.equal(m[`${prefix}Declared`],Number(m[`${prefix}Started`])+Number(m[`${prefix}Skipped`]));
}
test('separate phase accounting keeps complete helper binding and known structural root inventory',()=>{
 const check=scan("function helper(req){return db.query(req.query.sql)} helper({query:{sql:'fixed'}}); function ordinary(value){return value} export function route(req){db.query(req.query.sql)}");
 assert.equal(check.status,'completed');assert.equal(sql(check).length,1);counters(check);
 assert.equal(check.metrics?.indexComplete,true);assert.equal(check.metrics?.rootInventoryComplete,true);
 assert.equal(check.metrics?.functionsIndexed,3);assert.equal(check.metrics?.entryRootsDeclared,2);assert.equal(check.metrics?.entryRootsCompleted,2);
 assert.equal(check.metrics?.filesIndexed,1);assert.equal(check.metrics?.maxNodeVisits,500000);assert.equal(check.metrics?.maxIndexWork,300000);assert.equal(check.metrics?.maxFlowWork,200000);
});
test('index cap disables callee and native proof while retaining possible direct candidates and incomplete gate',()=>{
 const check=scan("function constant(x){return 'fixed'} function route(req){db.query(constant(req.query.x));fetch('https://fixed.example/p?'+new URLSearchParams({x:req.query.x}).toString())}",{...FLOW_LIMITS,indexWork:1});
 assert.equal(check.status,'partial');assert.match(String(check.metrics?.incompleteReasons),/index_work_limit/);
 assert.equal(check.metrics?.indexComplete,false);assert.equal(check.metrics?.rootInventoryComplete,false);assert.equal(check.metrics?.filesIndexed,0);
 assert.equal(check.metrics?.outboundFixedDestinationSuppressed,0);counters(check);
 const report=createReport([check],'source','2026-10-05T00:00:00.000Z');assert.equal(evaluateGate(report,'none').exitCode,2);assert.equal(toAgentReport(report,'none').scanGate.exitCode,2);
 // Index may have no function inventory at all: its known-root count is not a complete list.
 assert.equal(check.metrics?.entryRootsDeclared,0);
});
test('function inventory limit revokes safe summaries and does not hide known called roots',()=>{
 const check=scan("function helper(req){db.query(req.query.sql)} helper({query:{sql:'fixed'}}); function route(req){db.query(req.query.sql)}",{...FLOW_LIMITS,functions:1});
 assert.equal(check.status,'partial');assert.match(String(check.metrics?.incompleteReasons),/function_limit/);assert.equal(check.metrics?.indexComplete,false);
 assert.equal(check.metrics?.entryRootsDeclared,1);assert.equal(check.metrics?.entryRootsStarted,1);assert.equal(sql(check).length,1);counters(check);
});
test('flow-only limit preserves complete index inventory and separately accounts unfinished tasks',()=>{
 const check=scan("function route(req){db.query(req.query.sql)} function later(req){fetch(req.query.url)}",{...FLOW_LIMITS,flowWork:1});
 assert.equal(check.status,'partial');assert.match(String(check.metrics?.incompleteReasons),/flow_work_limit/);assert.equal(check.metrics?.indexComplete,true);assert.equal(check.metrics?.rootInventoryComplete,true);assert.equal(check.metrics?.entryRootsSkipped,2);counters(check);
});
test('legacy aggregate override and optional phase fields retain exact node_limit semantics',()=>{
 const {indexWork:unusedIndex,flowWork:unusedFlow,...legacy}=FLOW_LIMITS;
 const check=scan("function route(req){db.query(req.query.sql)}",{...legacy,nodeVisits:1});
 assert.equal(check.status,'partial');assert.equal(check.metrics?.nodeVisits,1);assert.match(String(check.metrics?.incompleteReasons),/node_limit/);assert.equal(check.metrics?.maxIndexWork,300000);assert.equal(check.metrics?.maxFlowWork,200000);counters(check);
});
test('parse-attempt counters include malformed files while index input includes only parse-valid files',()=>{
 const check=runBuiltinAst(snapshot({'good.ts':"function route(req){db.query(req.query.sql)}",'broken.ts':'function {'}),false);
 assert.equal(check.status,'partial');assert.equal(check.metrics?.filesParsed,2);assert.equal(check.metrics?.filesAnalyzed,2);assert.equal(check.metrics?.filesParseValid,1);assert.equal(check.metrics?.filesIndexInput,1);assert.equal(check.metrics?.filesIndexed,1);assert.equal(check.metrics?.parseErrorCount,1);assert.equal(check.metrics?.indexComplete,true);assert.equal(check.metrics?.rootInventoryComplete,false);counters(check);
});

test('partial summaries are not cached as completed evidence for a later equal safe context',()=>{
 const check=scan("function leaf(x){db.query(x);return x} function wrap(x){return leaf(x)} function routeA(req){wrap('fixed')} function routeB(req){wrap('fixed')}",{...FLOW_LIMITS,callDepth:2});
 assert.equal(check.status,'partial');assert.match(String(check.metrics?.incompleteReasons),/depth_limit/);assert.equal(check.metrics?.entryRootsDeclared,2);assert.equal(check.metrics?.entryRootsPartial,2);assert.equal(check.metrics?.entryRootsCompleted,0);assert.equal(check.metrics?.summariesCached,0);assert.equal(sql(check).length,0);counters(check);
});
