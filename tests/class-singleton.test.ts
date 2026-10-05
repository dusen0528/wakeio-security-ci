import test from 'node:test';
import assert from 'node:assert/strict';
import * as ts from 'typescript';
import {runBuiltinAst} from '../src/source/ast.js';
import {findSnapshotInputFlows} from '../src/source/dataflow.js';
import {FLOW_LIMITS,type FlowLimits} from '../src/source/modules.js';
import {createReport,evaluateGate,toAgentReport,toMarkdown,toSarif,RULESET_VERSION} from '../src/report.js';
import type {SourceSnapshot} from '../src/source/types.js';
const snapshot=(texts:Record<string,string>,complete=true):SourceSnapshot=>{const files=Object.entries(texts).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));return {root:'/never-execute',files,issues:[],complete,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};};
const run=(texts:Record<string,string>,complete=true,limits:FlowLimits=FLOW_LIMITS)=>runBuiltinAst(snapshot(texts,complete),false,limits);
const entry="const finder=require('./finder');function route(req){finder.save('fixed-id',req.body.ownedReceiverMarker)}";
const producer=(sink='fetch(url)',async=true)=>`class Helper{constructor(){this.base='fixed'}}class Finder{constructor(){this.helper=new Helper()}${async?'async ':''}save(id,url){return this.download(url)}${async?'async ':''}download(url){${sink};return 'fixed'}}module.exports=new Finder();`;
const files=(body=producer(),extra:Record<string,string>={},source=entry)=>({'entry.js':source,'finder/index.js':body,...extra});
const outbound=(c:ReturnType<typeof run>)=>c.findings.filter(f=>f.ruleId==='ast:server-request');
const gap=(c:ReturnType<typeof run>)=>c.analysisGaps?.items.some(g=>g.reason==='module_export_unsupported');
function projections(c:ReturnType<typeof run>,source=entry){const report=createReport([c],'source',new Date());for(const text of [JSON.stringify(report),toMarkdown(report),JSON.stringify(toAgentReport(report)),JSON.stringify(toSarif(report))]){assert.ok(source.includes('ownedReceiverMarker'));assert.ok(!text.includes('ownedReceiverMarker'));assert.ok(!text.includes(source));}assert.ok(toAgentReport(report).findings.every(f=>!f.verification.vulnerabilityConfirmed&&!f.verification.remediationVerified));return report;}

test('canonical singleton carries actual argument1 through same receiver body despite fixed return, with matching fixed URL normal',()=>{
 assert.equal(RULESET_VERSION,'2026-10-05.17');
 for(const async of [false,true])for(const spec of ['./finder','./finder/index.js']){
  const source=entry.replace('./finder',spec),r=run(files(producer('fetch(url)',async),{},source));assert.equal(r.status,'completed');assert.equal(outbound(r).length,1);assert.equal(outbound(r)[0].confidence,'medium');assert.equal(outbound(r)[0].location.path,'finder/index.js');
  const trace=outbound(r)[0].staticFlow!;assert.equal(trace.truncated,false);assert.equal(trace.steps.filter(s=>s.role==='parameter').length,2);assert.ok(trace.steps.some(s=>s.role==='call'&&s.location.path==='entry.js'));assert.equal(evaluateGate(projections(r,source),'high').exitCode,1);
  const n=run(files(producer("fetch('https://owned.invalid/fixed')",async),{},source));assert.equal(n.status,'completed');assert.equal(outbound(n).length,0);assert.equal(evaluateGate(projections(n,source),'high').exitCode,0);
 }
});
test('relative CJS helper constructor uses independent closed own fields and does not poison selected method',()=>{
 const body="const Helper=require('./helper');class Finder{constructor(){this.helper=new Helper()}save(id,url){return this.download(url)}download(url){fetch(url);return 'fixed'}other(value){return this.helper.other(value)}}module.exports=new Finder();";
 const r=run(files(body,{'finder/helper.js':"class Helper{constructor(){this.base='fixed'}other(value){return this.base}}module.exports=Helper;"}));assert.equal(r.status,'completed');assert.equal(outbound(r)[0].confidence,'medium');assert.equal(outbound(r)[0].staticFlow?.steps.filter(s=>s.role==='parameter').length,2);
});
test('opaque loader permits only conditional body input, complete trace stays nontruncated and normal remains unproved',()=>{
 for(const extra of ["require(dynamicPath)","if(typeof require==='function'&&typeof module==='object'&&module){require(dynamicPath)}"]){
  const r=run(files(producer(),{'loader.js':extra}));assert.equal(r.status,'partial');assert.ok(gap(r));assert.equal(outbound(r).length,1);assert.equal(outbound(r)[0].confidence,'low');assert.equal(outbound(r)[0].staticFlow?.truncated,false);assert.equal(Number(r.metrics?.resolvedCalls),0);assert.equal(Number(r.metrics?.summariesCached),0);assert.equal(evaluateGate(projections(r),'none').exitCode,2);
  const n=run(files(producer("fetch('https://owned.invalid/fixed')"),{'loader.js':extra}));assert.equal(n.status,'partial');assert.ok(gap(n));assert.equal(outbound(n).length,0);projections(n);
 }
});
test('primitive UMD feature detection is closed only in approved use shapes',()=>{
 for(const guard of ["if(typeof require==='function'){}", "if(typeof module==='object'&&module){}", "if((module||false)){}", "const primitive=typeof module;"]){const r=run(files(producer(),{'guard.js':guard}));assert.equal(r.status,'completed',guard);assert.equal(outbound(r)[0].confidence,'medium');}
 for(const guard of ['consume(module)','const alias=module','const alias=require','module.require(dynamicPath)','require.cache.x=custom',"require('node:module')",'const x=module&&false']){const r=run(files(producer(),{'guard.js':guard}));assert.equal(r.status,'partial',guard);assert.ok(gap(r));assert.equal(outbound(r).length,0);}
});
test('conditional fixed return does not sanitize caller and rooted methods do not acquire conditional receiver',()=>{
 const source=entry.replace("finder.save('fixed-id',req.body.ownedReceiverMarker)","fetch(finder.save('fixed-id',req.body.ownedReceiverMarker))");
 const r=run(files(producer("fetch('https://owned.invalid/fixed')"),{'loader.js':'require(dynamicPath)'},source));assert.equal(r.status,'partial');assert.ok(outbound(r).some(f=>f.location.path==='entry.js'&&f.confidence==='low'));projections(r,source);
 const rooted=run({'finder.js':"class Finder{save(req){this.download(req.body.value)}download(url){fetch(url)}}module.exports=new Finder();",'loader.js':'require(dynamicPath)'});assert.equal(rooted.status,'partial');assert.equal(outbound(rooted).length,0);assert.ok(Number(rooted.metrics?.entryRootsDeclared)>=2);
});
test('observed importer mutation, escape or unsupported exact loader blocks closed and declared dispatch',()=>{
 for(const use of ['finder.save=custom','delete finder.download','finder.deep.value=custom','const alias=finder','const box={finder}','modify(finder)','Object.defineProperty(finder,"download",{value:custom})','const f=finder.save'])for(const opaque of [false,true]){
  const r=run(files(producer(),{'other.js':"const finder=require('./finder/index.js');"+use,...(opaque?{'loader.js':'require(dynamicPath)'}:{})}));assert.equal(r.status,'partial',use);assert.ok(gap(r));assert.equal(outbound(r).length,0);assert.ok(Number(r.metrics?.externalEntryFunctions)>=2);
 }
 for(const load of ["require('./finder/index.js')", "const {save}=require('./finder/index.js')", "import finder from './finder/index.js'", "import('./finder/index.js')"]){const r=run(files(producer(),{'other.js':load}));assert.equal(r.status,'partial');assert.equal(outbound(r).length,0);}
});
test('constructor, class, receiver and nested-this vetoes preserve discovery without possible-body escape',()=>{
 for(const body of [producer().replace('this.helper=new Helper()','this.download=custom'),producer().replace('new Helper()','new Helper(this)'),producer().replace('this.helper=new Helper()','return {}'),producer().replace('class Finder{','class Finder extends Helper{'),producer().replace('download(url){','*download(url){'),producer().replace('fetch(url)',"(()=>this.download(url))()"),producer().replace('fetch(url)',"function inner(){return this.download(url)};inner()"),producer().replace('fetch(url)','modify(this)'),producer().replace('fetch(url)','this.deep.value=custom'),producer().replace('module.exports=new Finder();','Finder.prototype.download=custom;module.exports=new Finder();'),producer().replace('module.exports=new Finder();','module.exports=new Finder();module.exports={};'),"module.exports=new Finder();class Finder{save(id,url){fetch(url)}}"]){const r=run(files(body,{'loader.js':'require(dynamicPath)'}));assert.equal(r.status,'partial',body);assert.equal(outbound(r).length,0);assert.ok(Number(r.metrics?.externalEntryFunctions)>0);}
});
test('shadowed local bindings, detached calls and different canonical same-name receivers never share body identity',()=>{
 const blocked=run(files(producer().replace('class Finder{','const module={exports:{}};class Finder{')));assert.equal(blocked.status,'partial');assert.equal(outbound(blocked).length,0);
 const source="function require(x){return fake};const finder=require('./finder');function route(req){finder.save('fixed-id',req.body.ownedReceiverMarker)}";const shadow=run(files(producer(),{},source));assert.equal(outbound(shadow).length,0);
 for(const reversed of [false,true]){const calls=["finder.save('id',req.body.ownedReceiverMarker)","normal.save('id',req.body.ownedReceiverMarker)"];if(reversed)calls.reverse();const source="const finder=require('./finder');const normal=require('./normal');function route(req){"+calls.join(';')+";finder.save('id',req.body.ownedReceiverMarker)}";const r=run(files(producer(),{'normal.js':producer("fetch('https://owned.invalid/fixed')")},source));assert.equal(r.status,'completed');assert.equal(outbound(r).length,1);assert.equal(outbound(r)[0].location.path,'finder/index.js');assert.ok(Number(r.metrics?.summariesCached)>0);projections(r,source);}
});
test('actual argument traces expose both method formals without a public security sink or new telemetry',()=>{
 const texts=files(producer('ordinaryHelper(url)'));
 const ast=Object.entries(texts).map(([path,text])=>ts.createSourceFile(path,text,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS));const result=findSnapshotInputFlows(ast);
 const helper=result.uses.find(u=>ts.isCallExpression(u.node)&&u.node.expression.getText()==='ordinaryHelper'&&u.argumentFlows?.[0]?.certainty==='tainted');assert.ok(helper);assert.equal(helper.argumentFlows![0].staticFlow?.steps.filter(s=>s.role==='parameter').length,2);assert.equal(run(texts).findings.length,0);
});
test('class budgets/scope/cycle and receiver return qualifiers remain bounded while other supported sinks survive',()=>{
 for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1},{...FLOW_LIMITS,moduleEdges:0},{...FLOW_LIMITS,summaryWork:0},{...FLOW_LIMITS,callDepth:1}]){const r=run(files(),true,limits);assert.equal(r.status,'partial');assert.equal(evaluateGate(createReport([r],'source',new Date()),'none').exitCode,2);}
 const incomplete=run(files(),false);assert.equal(incomplete.status,'partial');assert.equal(outbound(incomplete).length,0);
 const cycle=run(files(producer().replace('this.download(url)','this.save(id,url)')));assert.equal(cycle.status,'partial');assert.ok(String(cycle.metrics?.incompleteReasons).includes('summary_cycle'));
 for(const sink of ['db.query(url)','document.write(url)','exec(url)']){const r=run(files(producer(sink,false)));assert.equal(r.status,'completed');assert.ok(r.findings.some(f=>f.confidence==='medium'&&f.staticFlow?.steps.filter(s=>s.role==='parameter').length===2));}
});

test('declared provenance crosses ordinary scalar helper bodies without consuming a closed summary or washing fixed returns',()=>{
 const body="function forward(value){fetch(value);return 'fixed'}class Finder{save(id,url){return this.download(url)}download(url){return forward(url)}}module.exports=new Finder();";
 const r=run(files(body,{'loader.js':'require(dynamicPath)'}));assert.equal(r.status,'partial');assert.equal(outbound(r).length,1);assert.equal(outbound(r)[0].confidence,'low');assert.equal(outbound(r)[0].staticFlow?.truncated,false);assert.equal(outbound(r)[0].staticFlow?.steps.filter(s=>s.role==='parameter').length,3);
 const source=entry.replace("finder.save('fixed-id',req.body.ownedReceiverMarker)","fetch(finder.save('fixed-id',req.body.ownedReceiverMarker))");const outer=run(files(body,{'loader.js':'require(dynamicPath)'},source));assert.ok(outbound(outer).some(f=>f.location.path==='entry.js'&&f.confidence==='low'));projections(outer,source);
});
test('receiver-bound array and fixed target returns never automatically grant SQL or HTTP exclusion proof',()=>{
 const array="class Finder{save(value){return [value]}}module.exports=new Finder();";
 const sql=run({'entry.js':"import {Pool} from 'pg';const db=new Pool();const finder=require('./finder');function route(req){db.query({text:'SELECT $1',values:finder.save(req.body.value)})}",'finder.js':array});assert.equal(sql.status,'completed');assert.ok(sql.findings.some(f=>f.ruleId==='ast:sql-input-sink'&&f.confidence==='low'));
 const fixed="class Finder{save(value){return 'https://owned.invalid/fixed'}}module.exports=new Finder();";
 const http=run({'entry.js':"import axios from 'axios';const finder=require('./finder');function route(req){axios.request({url:finder.save(req.body.value),data:req.body.value})}",'finder.js':fixed});assert.equal(http.status,'completed');assert.ok(http.findings.some(f=>f.ruleId==='ast:server-request'&&f.confidence==='low'));
});
test('helper class constructor cannot hide static, accessor, argument, mutation or export-order effects',()=>{
 for(const helper of ["class Helper{static field=opaque();constructor(){this.base='fixed'}}module.exports=Helper;","class Helper{get base(){return custom}constructor(){this.base='fixed'}}module.exports=Helper;","class Helper{constructor(){consume(this)}}module.exports=Helper;","class Deep{constructor(){this.base='fixed'}}class Helper{constructor(){this.base=new Deep()}}module.exports=Helper;","class Helper{constructor(){this.base='fixed'}}Helper.prototype.base=custom;module.exports=Helper;","module.exports=Helper;class Helper{constructor(){this.base='fixed'}}"]){const body="const Helper=require('./helper');class Finder{constructor(){this.helper=new Helper()}save(id,url){fetch(url)}}module.exports=new Finder();";const r=run(files(body,{'finder/helper.js':helper}));assert.equal(r.status,'partial');assert.equal(outbound(r).length,0);}
});


test('R2 helper binding is initialized at singleton construction, not constructor syntax position',()=>{
 const helper="class Helper{constructor(){this.base='fixed'}}module.exports=Helper;";
 const core="class Finder{constructor(){this.helper=new Helper()}save(id,url){fetch(url)}}";
 for(const opaque of [false,true]){
  const extra={'finder/helper.js':helper,...(opaque?{'loader.js':'require(dynamicPath)'}:{})};
  const early=run(files("const Helper=require('./helper');"+core+"module.exports=new Finder();",extra));assert.equal(outbound(early).length,1);assert.equal(outbound(early)[0].confidence,opaque?'low':'medium');
  const late=run(files(core+"module.exports=new Finder();const Helper=require('./helper');",extra));assert.equal(late.status,'partial');assert.ok(gap(late));assert.equal(outbound(late).length,0);assert.ok(Number(late.metrics?.externalEntryFunctions)>0);
 }
 const local=run(files("class Finder{constructor(){this.helper=new Helper()}save(id,url){fetch(url)}}class Helper{constructor(){this.base='fixed'}}module.exports=new Finder();"));assert.equal(local.status,'completed');assert.equal(outbound(local).length,1);
});
test('R2 extra selected or helper instances cannot escape canonical prototype closure',()=>{
 for(const opaque of [false,true])for(const extra of ["const other=new Finder();Object.getPrototypeOf(other).save=custom;","const other=new Finder();modify(other);","const other=new Helper();other.base=custom;"]){
  const r=run(files(producer().replace('module.exports=new Finder();',extra+'module.exports=new Finder();'),opaque?{'loader.js':'require(dynamicPath)'}:{}));assert.equal(r.status,'partial');assert.ok(gap(r));assert.equal(outbound(r).length,0);
 }
 const body="const Helper=require('./helper');const other=new Helper();modify(other);class Finder{constructor(){this.helper=new Helper()}save(id,url){fetch(url)}}module.exports=new Finder();";
 const r=run(files(body,{'finder/helper.js':"class Helper{constructor(){this.base='fixed'}}module.exports=Helper;"}));assert.equal(r.status,'partial');assert.equal(outbound(r).length,0);
 const consumerEscape=run(files("const Helper=require('./helper');class Finder{constructor(){this.helper=new Helper()}save(id,url){fetch(url)}}module.exports=new Finder();",{'finder/helper.js':"class Helper{constructor(){this.base='fixed'}}module.exports=Helper;",'other.js':"const Helper=require('./finder/helper');class Other{constructor(){this.helper=new Helper()}save(v){return v}}module.exports=new Other();",'escape.js':"const other=require('./other');modify(other);"}));assert.equal(consumerEscape.status,'partial');assert.equal(outbound(consumerEscape).length,0);
 const indirect=run(files("const Helper=require('./helper');class Finder{constructor(){this.helper=new Helper()}save(id,url){fetch(url)}}module.exports=new Finder();",{'finder/helper.js':"class Helper{constructor(){this.base='fixed'}}module.exports=Helper;",'other.js':"const Helper=require('./finder/helper');const Broken=require('./broken');class Other{constructor(){this.helper=new Helper();this.broken=new Broken()}save(v){return v}}module.exports=new Other();",'broken.js':"class Broken{constructor(){this.base='fixed'}}module.exports=Broken;",'poison.js':"const Broken=require('./broken');const extra=new Broken();modify(extra);"}));assert.equal(indirect.status,'partial');assert.equal(outbound(indirect).length,1);assert.equal(outbound(indirect)[0].confidence,'low');assert.ok(gap(indirect));
 assert.equal(run(files(producer()+"class Unrelated{method(){return 'fixed'}}")).status,'completed');
});
test('R2 declared ordinary helper chain retains independent request roots while closed scalar summaries stay closed',()=>{
 const body="function forward(req){return deeper(req)}function deeper(req){fetch(req.body.value);return 'fixed'}class Finder{save(value){return forward(value)}}module.exports=new Finder();";
 const r=run({'entry.js':"const finder=require('./finder');finder.save('fixed');",'finder.js':body,'loader.js':'require(dynamicPath)'});assert.equal(r.status,'partial');assert.ok(outbound(r).some(f=>f.location.path==='finder.js'&&f.confidence==='medium'));assert.ok(Number(r.metrics?.entryRootsDeclared)>=3);
 const scalar=run({'entry.js':"function forward(value){return deeper(value)}function deeper(value){return 'fixed'}function route(req){fetch(forward(req.query.value));fetch(forward(req.query.value))}"});assert.equal(scalar.status,'completed');assert.equal(outbound(scalar).length,0);assert.ok(Number(scalar.metrics?.summariesCached)>0);
});
test('R2 declared returned input retains body formal and real return omission, fixed return uses actual fallback only',()=>{
 const source=entry.replace("finder.save('fixed-id',req.body.ownedReceiverMarker)","fetch(finder.save('fixed-id',req.body.ownedReceiverMarker))");
 const returning="class Finder{save(id,url){return this.download(url)}download(url){return url}}module.exports=new Finder();";
 const r=run(files(returning,{'loader.js':'require(dynamicPath)'},source));const f=outbound(r).find(f=>f.location.path==='entry.js')!;assert.ok(f);assert.equal(f.confidence,'low');assert.equal(f.staticFlow?.truncated,false);assert.equal(f.staticFlow?.steps.filter(s=>s.role==='parameter').length,2);assert.ok(f.staticFlow?.steps.some(s=>s.role==='return'&&s.location.path==='finder/index.js'));
 const deep="function a(v){return b(v)}function b(v){return c(v)}function c(v){return d(v)}function d(v){return e(v)}function e(v){return f(v)}function f(v){return v}"+returning.replace('download(url){return url}', 'download(url){return a(url)}');
 const truncated=run(files(deep,{'loader.js':'require(dynamicPath)'},source));assert.equal(outbound(truncated).find(f=>f.location.path==='entry.js')?.staticFlow?.truncated,true);
 const fixed=run(files("class Finder{save(id,url){return 'fixed'}}module.exports=new Finder();",{'loader.js':'require(dynamicPath)'},source));const fallback=outbound(fixed).find(f=>f.location.path==='entry.js')!;assert.ok(fallback);assert.equal(fallback.staticFlow?.steps.filter(s=>s.role==='parameter').length,0);assert.equal(fallback.staticFlow?.truncated,false);
 const noninput=run({'entry.js':"const finder=require('./finder');fetch(finder.save('id','fixed'))",'finder.js':returning,'loader.js':'require(dynamicPath)'});assert.equal(outbound(noninput).length,0);assert.equal(noninput.status,'partial');
});

const sharedHelper="class Helper{constructor(){this.base='fixed'}read(v){return this.base}}module.exports=Helper;";
const sharedFinder="const Helper=require('./helper');class Finder{constructor(){this.helper=new Helper()}save(id,url){return this.download(url)}download(url){return forward(url)}}function forward(value){fetch(value);return 'fixed'}module.exports=new Finder();";
function sharedFiles(other:string,helper=sharedHelper,sink=sharedFinder,extra:Record<string,string>={}){return files(sink,{'finder/helper.js':helper,'other.js':other,...extra});}
const softOther="const Helper=require('./finder/helper');class Other{constructor(){this.helper=new Helper();this.providers=['one','two'];this.verbose=false}read(v){return this.helper.read(v)}search(items){return items.map(v=>this.read(v))}}module.exports=new Other();";
test('conditional shared consumer effects propagate actuals through receiver and ordinary helper without safe/root/cache certificates',()=>{
 for(const opaque of [false,true]){
  const r=run(sharedFiles(softOther,sharedHelper,sharedFinder,opaque?{'loader.js':'require(dynamicPath)'}:{}));assert.equal(r.status,'partial');assert.ok(gap(r));assert.equal(outbound(r).length,1);assert.equal(outbound(r)[0].confidence,'low');assert.equal(outbound(r)[0].staticFlow?.truncated,false);assert.equal(outbound(r)[0].staticFlow?.steps.filter(s=>s.role==='parameter').length,3);/* The independent readonly arrow remains a closed scalar context. */assert.equal(Number(r.metrics?.summariesCached),1);assert.equal(evaluateGate(projections(r),'none').exitCode,2);
  const repeated=run({...sharedFiles(softOther,sharedHelper,sharedFinder,opaque?{'loader.js':'require(dynamicPath)'}:{}),'entry.js':entry.replace("finder.save('fixed-id',req.body.ownedReceiverMarker)","finder.save('fixed-id',req.body.ownedReceiverMarker);finder.save('fixed-id',req.body.ownedReceiverMarker)")});assert.equal(Number(repeated.metrics?.summariesCached),Number(r.metrics?.summariesCached));
  const n=run(sharedFiles(softOther,sharedHelper,sharedFinder.replace('fetch(value)',"fetch('https://owned.invalid/fixed')"),opaque?{'loader.js':'require(dynamicPath)'}:{}));assert.equal(n.status,'partial');assert.equal(outbound(n).length,0);projections(n);
 }
 const body=sharedFinder.replace("function forward(value){fetch(value);return 'fixed'}","function forward(req){return deeper(req)}function deeper(req){fetch(req.body.value);return 'fixed'}");
 const rooted=run(sharedFiles(softOther,sharedHelper,body,{}));assert.ok(outbound(rooted).some(f=>f.confidence==='medium'));assert.ok(Number(rooted.metrics?.entryRootsDeclared)>=4);
});
test('common producer guard rejects known capability on closed and conditional same-file and relative helper paths',()=>{
 for(const method of ['leak(){return this}','leak(){return this.constructor}','leak(){return Object.getPrototypeOf(this)}','leak(){const alias=this;return alias}','leak(){return this.read}','leak(){this.read=custom}'])for(const soft of [false,true])for(const local of [false,true]){
  const helper=sharedHelper.replace('read(v){return this.base}',`read(v){return this.base}${method}`);
  const r=local?run(files(producer().replace("class Helper{constructor(){this.base='fixed'}}",helper.replace('module.exports=Helper;','')),soft?{'loader.js':'require(dynamicPath)'}:{})):
   run(sharedFiles(soft?softOther:"const Helper=require('./finder/helper');class Other{constructor(){this.helper=new Helper()}read(v){return this.helper.read(v)}}module.exports=new Other();",helper));
  assert.equal(r.status,'partial',method);assert.ok(gap(r));assert.equal(outbound(r).length,0,method);assert.ok(Number(r.metrics?.externalEntryFunctions)>0);
 }
 const normal=run(files(producer()));assert.equal(normal.status,'completed');assert.equal(outbound(normal)[0].confidence,'medium');
});
test('conditional consumer keeps selected capability escape, initialization, unknown effects and hard loader vetoes',()=>{
 for(const other of [softOther.replace('return this.helper.read(v)','return this.helper'),softOther.replace('return this.helper.read(v)','consume(this.helper);return v'),softOther.replace('return this.helper.read(v)','modify(this);return v'),softOther.replace("this.providers=['one','two']",'this.providers=unknown()'),softOther.replace("this.providers=['one','two']",'this.providers=[this.helper]'),softOther.replace('new Helper()','new Helper(this)'),softOther.replace('return this.helper.read(v)','this.helper.read=custom;return v'),softOther.replace("this.providers=['one','two']",'this.providers={...unknown}'),softOther.replace("const Helper=require('./finder/helper');",'').replace('module.exports=new Other();',"module.exports=new Other();const Helper=require('./finder/helper');")]){
  const r=run(sharedFiles(other));assert.equal(r.status,'partial');assert.equal(outbound(r).length,0,other);assert.ok(gap(r));
 }
 for(const loader of ["require('node:module')","const alias=require","consume(module)"]){const r=run(sharedFiles(softOther,sharedHelper,sharedFinder,{'loader.js':loader}));assert.equal(r.status,'partial');assert.equal(outbound(r).length,0);}
 for(const brokenUse of ['new Broken(this.helper)','this.broken.use(this.helper)']){
  const other=softOther.replace("this.providers=['one','two']",brokenUse.startsWith('new')?'this.broken='+brokenUse:'this.broken=new Broken()').replace('return this.helper.read(v)',brokenUse.startsWith('this')?brokenUse+';return v':'return v').replace('const Helper=',"const Broken=require('./broken');const Helper=");
  const r=run(sharedFiles(other,sharedHelper,sharedFinder,{'broken.js':"class Broken{use(v){return v}}module.exports=Broken;"}));assert.equal(outbound(r).length,0,brokenUse);
 }
});
test('conditional eligibility cannot turn actual work/scope/cycle failure into body proof',()=>{
 for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,summaryWork:0},{...FLOW_LIMITS,moduleEdges:0}]){const r=run(sharedFiles(softOther),true,limits);assert.equal(r.status,'partial');assert.equal(evaluateGate(createReport([r],'source',new Date()),'none').exitCode,2);}
 const scope=run(sharedFiles(softOther),false);assert.equal(scope.status,'partial');assert.equal(outbound(scope).length,0);
 const cycle=run(sharedFiles(softOther,sharedHelper,sharedFinder.replace("return forward(url)","return this.save(id,url)")));assert.equal(cycle.status,'partial');assert.ok(String(cycle.metrics?.incompleteReasons).includes('summary_cycle'));
});
test('historical selected receiver rejection is not softened by unrelated shared consumer effects',()=>{
 const selected=sharedFinder.replace('this.helper=new Helper()','this.helper=new Helper();this.verbose=false').replace('return forward(url)','if(!this.verbose){return forward(url)}');
 for(const opaque of [false,true]){const r=run(sharedFiles(softOther,sharedHelper,selected,opaque?{'loader.js':'require(dynamicPath)'}:{}));assert.equal(r.status,'partial');assert.equal(outbound(r).length,0);assert.ok(gap(r));}
});
