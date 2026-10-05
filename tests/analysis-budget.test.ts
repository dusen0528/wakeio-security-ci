import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { resolveAnalysisBudget, sanitiseAnalysisBudget } from '../src/source/analysis-budget.js';
import { runSource } from '../src/source.js';
import { buildScanScope } from '../src/scan-scope.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, RULESET_VERSION } from '../src/report.js';
import { parseScanReport, compareReports, comparisonExitCode } from '../src/compare.js';
import { parseCliArgs } from '../src/cli.js';
import type { AnalysisProfile, CheckResult } from '../src/contracts.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import { runBuiltinAst } from '../src/source/ast.js';
const exec = promisify(execFile);
const cli = resolve('build/src/cli.js');
const metricNames = { indexWork:'maxIndexWork', flowWork:'maxFlowWork', nodeVisits:'maxNodeVisits', functions:'maxFunctions', summaryWork:'maxSummaryWork', moduleEdges:'maxModuleEdges', callDepth:'maxCallDepth', aliasSteps:'maxAliasSteps', traceSteps:'maxTraceSteps' } as const;
const ast = (checks: CheckResult[]) => checks.find(c => c.id === 'source.builtin-ast')!;
async function withSource(files: Record<string,string>, fn:(root:string)=>Promise<void>) {
 const root = await mkdtemp(join(tmpdir(),'wakeio-analysis-budget-'));
 try { for (const [name,text] of Object.entries(files)) await writeFile(join(root,name),text); await fn(root); }
 finally { await rm(root,{recursive:true,force:true}); }
}
function checkCaps(check:CheckResult, profile:AnalysisProfile) {
 const budget = resolveAnalysisBudget(profile); assert.deepEqual(check.analysisBudget,budget);
 for(const [name,value] of Object.entries(budget.limits)) assert.equal(check.metrics?.[metricNames[name as keyof typeof metricNames]],value);
}
test('closed registry exactly preserves default9 and changes six workload caps4x without changing depth/alias/trace',()=>{
 const d=resolveAnalysisBudget(), e=resolveAnalysisBudget('extended'); assert.deepEqual(d.limits,FLOW_LIMITS);
 assert.ok(Object.isFrozen(d)&&Object.isFrozen(d.limits));
 for(const key of Object.keys(d.limits) as Array<keyof typeof d.limits>) assert.equal(e.limits[key],d.limits[key]*(['callDepth','aliasSteps','traceSteps'].includes(key)?1:4));
 for(const x of [null,0,{},[],['default'],'','DEFAULT','other']) assert.throws(()=>resolveAnalysisBudget(x));
 for(const x of [{...d,extra:0},{...d,revision:'other'},{...d,effectiveProfile:'extended'},{...d,limits:{...d.limits,functions:2001}},{...d,limits:{...d.limits,extra:0}},{...d,requestedProfile:['default']}]) assert.equal(sanitiseAnalysisBudget(x),undefined);
});
test('public omitted and explicit default preserve risky/normal/cross-sink evidence while extended has exact actual caps',async()=>{
 for(const input of ['req.query.value',"'fixed'"]){
  await withSource({'app.js':`function helper(value){return value} function route(req){db.query(helper(${input}));fetch(helper(${input}));document.write(helper(${input}))}`},async root=>{
   const implicit=ast(await runSource({root,tools:[]})); const explicit=ast(await runSource({root,tools:[],analysisProfile:'default'}));const extended=ast(await runSource({root,tools:[],analysisProfile:'extended'}));
   checkCaps(implicit,'default');checkCaps(explicit,'default');checkCaps(extended,'extended');assert.equal(implicit.status,'completed');assert.deepEqual(explicit,implicit);assert.deepEqual(extended.findings,implicit.findings);
   assert.equal(implicit.findings.length,input.startsWith('req.')?3:0);
   const a=await buildScanScope({mode:'source',source:root,tools:[],ruleset:RULESET_VERSION});const b=await buildScanScope({mode:'source',source:root,tools:[],ruleset:RULESET_VERSION,analysisProfile:'default'});assert.deepEqual(a,b);
   const report=createReport([implicit],'source',new Date(),a);const agent=toAgentReport(report);const sarif:any=toSarif(report);const md=toMarkdown(report);
   assert.deepEqual(agent.scope?.analysisBudget,a.analysisBudget);assert.deepEqual(agent.checks[0].analysisBudget,implicit.analysisBudget);assert.equal(agent.summary!.scope.analysisProfile,'default');
   assert.deepEqual(sarif.runs[0].properties.analysisBudget,a.analysisBudget);assert.deepEqual(sarif.runs[0].properties.analysisBudgets,[{checkIndex:0,checkId:'source.builtin-ast',analysisBudget:implicit.analysisBudget}]);assert.match(md,/default \(ast-work-v1/);
   for(const text of [JSON.stringify(report),JSON.stringify(agent),JSON.stringify(sarif),md])assert.ok(!text.includes('req.query.value'));
  });
 }
 const custom=runBuiltinAst({root:'/never-run',files:[{path:'a.js',text:'function route(req){fetch(req.query.value)}',bytes:42,category:'code',sensitive:false}],issues:[],complete:true,ignoredFiles:0,totalBytes:42},false,{...FLOW_LIMITS,indexWork:1},resolveAnalysisBudget()); assert.equal(custom.analysisBudget,undefined);assert.equal(custom.status,'partial');
});
test('invalid SDK selection rejects before collection; CLI missing/duplicate/source-less selectors reject',async()=>{
 const checks=await runSource({root:'/never-collect',tools:[],analysisProfile:'invalid' as AnalysisProfile});assert.equal(checks[0].id,'source.options');assert.equal(evaluateGate(createReport(checks,'source',new Date()),'none').exitCode,2);
 for(const args of [['scan','--source','x','--analysis-profile'],['scan','--source','x','--analysis-profile='],['scan','--source','x','--analysis-profile','other'],['scan','--source','x','--analysis-profile','default','--analysis-profile=extended'],['scan','--url','https://example.invalid','--analysis-profile','default']])assert.throws(()=>parseCliArgs(args));
 assert.equal((parseCliArgs(['scan','--source','x','--analysis-profile','extended']) as any).analysisProfile,'extended');
});
test('source and mixed scope budget identity is mandatory for comparison; malformed rejects before sanitization',async()=>{
 await withSource({'a.js':'function route(req){fetch(req.query.value)}'},async root=>{
  const check=ast(await runSource({root,tools:[]}));
  for(const mode of ['source','both','combined'] as const){
   const scope=await buildScanScope({mode,source:root,tools:[],ruleset:RULESET_VERSION});const before=createReport([check],mode,new Date(),scope);const after=createReport([{...check,findings:[]}],mode,new Date(),scope);
   assert.equal(compareReports(before,after).comparable,true);
   const legacy=structuredClone(after);delete legacy.scope!.analysisBudget;delete legacy.checks[0].analysisBudget;assert.equal(comparisonExitCode(compareReports(before,legacy),'none'),2);
   const forged=structuredClone(after);forged.scope!.analysisBudget=resolveAnalysisBudget('extended');forged.checks[0].analysisBudget=resolveAnalysisBudget('extended');assert.equal(forged.scope!.fingerprint,scope.fingerprint);assert.equal(compareReports(before,forged).comparable,false);
   const inconsistent=structuredClone(after);inconsistent.checks[0].analysisBudget=resolveAnalysisBudget('extended');assert.equal(compareReports(before,inconsistent).comparable,false);
   for(const location of ['scope','check']) { const bad:any=structuredClone(after);const target=location==='scope'?bad.scope:bad.checks[0];target.analysisBudget={...resolveAnalysisBudget(),limits:{...resolveAnalysisBudget().limits,functions:NaN}};delete bad.scope.provenance;assert.throws(()=>parseScanReport(bad)); }
  }
  const url=await buildScanScope({mode:'url',url:'https://example.invalid',tools:[],ruleset:RULESET_VERSION});assert.equal(url.analysisBudget,undefined);
 });
});
// These two corpus shapes and counts are fixed before the first execution; no per-result calibration.
const functionCorpus=Object.fromEntries(Array.from({length:21},(_,i)=>[`f${i}.js`,Array.from({length:100},(_,j)=>`function f${i}_${j}(){return 0}`).join('\n')]));
const indexCorpus=Object.fromEntries(Array.from({length:120},(_,i)=>[`i${i}.js`,Array.from({length:500},(_,j)=>`const v${i}_${j}=0;`).join('\n')]));
test('public SDK and CLI actual presets on pre-fixed function and index workload corpus', {timeout:120_000},async()=>{
 for(const [files,cap] of [[functionCorpus,'function_limit'],[indexCorpus,'index_work_limit']] as const) await withSource(files,async root=>{
  for(const profile of ['default','extended'] as const){
   const check=ast(await runSource({root,tools:[],analysisProfile:profile}));checkCaps(check,profile);
   assert.equal(check.status,profile==='default'?'partial':'completed');if(profile==='default')assert.ok(check.notes.some(n=>n.includes(cap)));
   const out=await mkdtemp(join(tmpdir(),`wakeio-analysis-reports-${profile}-`));let status=0;try{await exec(process.execPath,[cli,'scan','--source',root,'--tools','none','--analysis-profile',profile,'--fail-on','none','--out',out],{timeout:30_000,maxBuffer:8*1024*1024});}catch(e:any){status=e.code;}assert.equal(status,profile==='default'?2:0);
   try { const report=JSON.parse(await readFile(join(out,'report.json'),'utf8'));checkCaps(ast(report.checks),profile);assert.deepEqual(report.scope.analysisBudget,resolveAnalysisBudget(profile)); } finally { await rm(out,{recursive:true,force:true}); }
  }
 });
});
test('Action invalid selectors fail before setup/install and source-required profile is checked before setup-node',async()=>{
 const runner=resolve('scripts/action-run.mjs');
 for(const [profile,source] of [['invalid','x'],['','x'],['extended','']] as const){
  let result:any;try{await exec(process.execPath,[runner],{env:{...process.env,WAKEIO_ANALYSIS_PROFILE:profile,WAKEIO_SOURCE:source,WAKEIO_ACTION_PATH:'/absent-action'},timeout:5_000});assert.fail('must reject');}catch(e:any){result=e;}
  assert.equal(result.code,2);assert.match(result.stderr,/analysis-profile/);assert.ok(!result.stderr.includes('setup failed'));
 }
 const action=await readFile('action.yml','utf8');assert.ok(action.indexOf('Validate AST analysis profile')<action.indexOf('Set up Node.js 22'));
});
