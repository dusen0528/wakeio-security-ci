import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import { createReport,evaluateGate,toAgentReport,toSarif,toMarkdown,RULESET_VERSION } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';
function snapshot(texts:Record<string,string>):SourceSnapshot {
 const files=Object.entries(texts).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));
 return {root:'/not-read',files,complete:true,issues:[],ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};
}
const run=(code:string,more:Record<string,string>={})=>runBuiltinAst(snapshot({'app.ts':code,...more}),false);
const sql=(check:ReturnType<typeof run>)=>check.findings.filter(f=>f.ruleId==='ast:sql-input-sink');
const fixed="'SELECT id FROM widgets WHERE name=$1'";
const prefix="import {Pool} from 'pg';const db=new Pool();";

test('pg Client and Pool named/default/CJS identity separate supported text and values in JS/TS',()=>{
 for(const path of ['app.ts','app.js']) for(const [decl,ctor] of [
 ["import {Pool as Database} from 'pg';",'Database'],["import {Client as Database} from 'pg';",'Database'],
 ["const {Pool:Database}=require('pg');",'Database'],["const {Client:Database}=require('pg');",'Database'],
 ["import pg from 'pg';",'pg.Pool'],["import pg from 'pg';const {Pool:Database}=pg;",'Database']]){
 const pre=decl+`const db=new ${ctor}({connectionString:process.env.DATABASE_URL});`;
 const safe=runBuiltinAst(snapshot({[path]:pre+`function route(req){db.query({text:${fixed},values:[req.query.name]})}`}),false);
 const risk=runBuiltinAst(snapshot({[path]:pre+'function route(req){db.query({values:[req.query.name],text:req.query.statement})}'}),false);
 assert.equal(safe.status,'completed');assert.equal(sql(safe).length,0);assert.equal(safe.metrics?.sqlValuesOnlyExcluded,1);
 assert.equal(sql(risk).length,1);assert.equal(sql(risk)[0].confidence,'medium');assert.equal(sql(risk)[0].title,'Request input reaches a SQL statement text argument');
 }
});

test('positional SQL injection including dynamic identifier keeps the actual first argument trace',()=>{
 for(const statement of ['req.query.sql',"'SELECT * FROM '+req.query.table"]){
 const code=prefix+`function route(req){db.query(${statement},[req.query.value])}`;const result=run(code);const f=sql(result)[0];
 assert.equal(sql(result).length,1);assert.equal(f.confidence,'medium');assert.equal(f.staticFlow?.steps.find(s=>s.role==='source')?.location.column,code.indexOf('req.query.')+1);
 }
 const safe=run(prefix+`function route(req){db.query(${fixed},[req.query.value])}`);assert.equal(sql(safe).length,0);assert.equal(safe.metrics?.sqlValuesOnlyExcluded,1);
});

test('no-input inventory and generic unbound config do not become parameterization proof',()=>{
 const inventory=run(prefix+`db.query({text:${fixed},values:['constant']})`);
 assert.equal(inventory.metrics?.sqlRoleBoundUses,1);assert.equal(inventory.metrics?.sqlValuesOnlyExcluded,0);assert.equal(sql(inventory).length,0);
 const generic=run(`function route(req){db.query({text:${fixed},values:[req.query.name]})}`);
 assert.equal(sql(generic).length,1);assert.equal(generic.metrics?.sqlRoleBoundUses,0);
});

test('text snapshot and shorthand select text evidence without borrowing the earlier values source',()=>{
 for(const initialRisk of [false,true]){
 const code=prefix+`function route(req){let text=${initialRisk?'req.query.sql':fixed};const values=[req.query.value];const config={values,text};text=${initialRisk?fixed:'req.query.sql'};db.query(config)}`;
 const result=run(code);assert.equal(sql(result).length,initialRisk?1:0);
 if(initialRisk)assert.equal(sql(result)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.column,code.indexOf('req.query.sql')+1);
 }
});

test('const array mutation, alias and opaque escape strip only qualification and retain input',()=>{
 for(const mutation of ["const alias=values;","values[0]='constant';","values.push('constant');","opaque(values);","const box={values};"]){
 const r=run(prefix+`function route(req){const values=[req.query.value];${mutation}db.query({text:${fixed},values})}`);
 assert.equal(sql(r).length,1,mutation);assert.equal(sql(r)[0].confidence,'low',mutation);assert.equal(sql(r)[0].staticFlow?.truncated,true);
 }
 const safe=run(prefix+`function route(req){const values=[req.query.value];db.query({text:${fixed},values})}`);assert.equal(sql(safe).length,0);
});

test('readonly relative array actual and return wrappers preserve provenance in both module orders',()=>{
 const helper="export function arrayOf(item){return [item]} export function forward(items){return items}";
 const entry=prefix+`import {arrayOf,forward} from './helper';function route(req){const values=forward(arrayOf(req.query.value));db.query({text:${fixed},values})}`;
 for(const reverse of [false,true]){
 const result=runBuiltinAst(snapshot(reverse?{'helper.ts':helper,'entry.ts':entry}:{'entry.ts':entry,'helper.ts':helper}),false);
 assert.equal(result.status,'completed');assert.equal(sql(result).length,0);assert.equal(result.metrics?.sqlValuesOnlyExcluded,1);
 }
 const opaque=run(prefix+`import {forward} from './helper';function route(req){const values=forward([req.query.value]);db.query({text:${fixed},values})}`,{'helper.ts':'export function forward(items){opaque(items);return items}'});
 assert.equal(sql(opaque).length,1);assert.equal(sql(opaque)[0].confidence,'low');
});

test('module-local Pool exported scalar wrapper retains roots and actual text context priority',()=>{
 for(const reverse of [false,true]){
 const calls=[`send(${fixed},req.query.name)`,'send(req.query.sql,req.query.name)'];if(reverse)calls.reverse();
 const more={'db.ts':prefix+'export function send(text,value){db.query({text,values:[value]})}'};
 const r=run(`import {send} from './db';export function route(req){${calls.join(';')}}`,more);
 assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'medium');assert.equal(sql(r)[0].location.path,'db.ts');
 assert.ok(sql(r)[0].staticFlow?.steps.some(s=>s.role==='source'&&s.location.path==='app.ts'));
 assert.equal(r.metrics?.externalEntryFunctions,2);
 }
 const normal=run(`import {send} from './db';export function route(req){send(${fixed},req.query.name)}`,{'db.ts':prefix+'export function send(text,value){db.query({text,values:[value]})}'});
 assert.equal(sql(normal).length,0);assert.equal(normal.metrics?.sqlValuesOnlyExcluded,1);
});

test('dispatch veto cannot label config text as proven statement input',()=>{
 for(const change of ["Object.prototype.submit=function(){};","String.prototype.submit=function(){};","Object.defineProperty(Object.prototype,'submit',{get(){return custom}});","const proto=Object.prototype;proto.submit=custom;","const alias=db;", "db.query=custom;", "db.on('connect',custom);", "const other=await db.connect();"]){
 const r=run(prefix+`async function route(req){${change}db.query({text:req.query.sql,values:[req.query.value]})}`);
 assert.equal(sql(r).length,1,change);assert.equal(sql(r)[0].confidence,'low',change);assert.equal(sql(r)[0].title,'Input-related SQL API argument roles are unresolved',change);
 }
 const proto=run(prefix+'function route(req){String.prototype.submit=custom;db.query(req.query.sql)}');assert.equal(sql(proto)[0].confidence,'low');
});

test('Client discarded lifecycle and pure Object reads are allowed, consumed lifecycle is unknown',()=>{
 for(const lifecycle of ['db.connect();','await db.connect();','await db.end();']){
 const r=run("import {Client} from 'pg';const db=new Client();"+`async function route(req){Object.keys(Object.prototype);Object.entries(String.prototype);${lifecycle}db.query({text:${fixed},values:[req.query.name]})}`);
 assert.equal(sql(r).length,0,lifecycle);assert.equal(r.metrics?.sqlValuesOnlyExcluded,1);
 }
 const r=run("import {Client} from 'pg';const db=new Client();"+`async function route(req){const other=await db.connect();other.query=custom;db.query({text:${fixed},values:[req.query.name]})}`);
 assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');
});

test('custom Pool constructors, family customization and unsupported exact loads remain unknown',()=>{
 for(const option of ['{Client:custom}','{onConnect:custom}','{verify:custom}','{Promise:custom}','{connection:custom}','{...options}','options']){
 const r=run(`import {Pool} from 'pg';const db=new Pool(${option});function route(req){db.query({text:${fixed},values:[req.query.value]})}`);
 assert.equal(sql(r).length,1,option);assert.equal(sql(r)[0].confidence,'low');
 }
 for(const extra of ["require('pg').Client.prototype.query=custom","import pg from 'pg';pg.defaults.query=custom", "import('pg')","import native from 'pg-native'","process.env.NODE_PG_FORCE_NATIVE='1'"]){
 const r=run(prefix+`function route(req){db.query({text:${fixed},values:[req.query.value]})}`,{'other.ts':extra});assert.equal(sql(r).length,1,extra);assert.equal(sql(r)[0].confidence,'low');
 }
});

test('config shape/custom submit veto and explicit serializers preserve unknown candidate rather than false SQL-text claim',()=>{
 for(const config of [`{text:req.query.sql,values:[],submit:custom}`,`{get text(){return req.query.sql},values:[req.query.value]}`,`{text:${fixed},values:[{value:req.query.value,toPostgres(){return this.value}}]}`,`{text:${fixed},values:[req.query.value],...opaque}`]){
 const r=run(prefix+`function route(req){db.query(${config})}`);assert.equal(sql(r).length,1,config);assert.equal(sql(r)[0].confidence,'low');
 }
 const data=run(prefix+`function route(req){db.query({text:${fixed},values:[{name:req.query.value},[req.query.name]]})}`);assert.equal(sql(data).length,0);
});

test('async/generator returns never supply SQL literal or array exclusion while actual parameters inside async remain supported',()=>{
 for(const declaration of ['async function pack(x){return [x]}','function* pack(x){return [x]}']){
 const r=run(prefix+declaration+`async function route(req){const values=await pack(req.query.value);db.query({text:${fixed},values})}`);
 assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');
 }
 const r=run(prefix+`async function text(){return ${fixed}} function route(req){db.query({text:text(),values:[req.query.value]})}`);assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');
 const body=run(prefix+`async function send(items){db.query({text:${fixed},values:items})}function route(req){send([req.query.value])}`);assert.equal(sql(body).length,0);
});

test('different array origins and opaque input contexts veto exclusion without changing roots or safe controls',()=>{
 const r=run(prefix+`function route(req){let values;if(req.query.flag){values=[req.query.x]}else{values=[req.query.y]}db.query({text:${fixed},values})}`);assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');
 for(const reversed of [false,true]){
 const calls=[`send(${fixed},[req.query.value])`,'send(opaque(),opaque(req.query.value))'];if(reversed)calls.reverse();
 const r=run(prefix+`function send(text,values){db.query({text,values})}function route(req){${calls.join(';')}}`);assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');
 }
});

test('SQL qualification retains shell HTML outbound taint and applies scope/budget fail-closed',()=>{
 const code=prefix+`function route(req){const value=req.query.value;db.query({text:${fixed},values:[value]});exec(value);el.innerHTML=value;fetch(value)}`;
 const r=run(code);assert.equal(sql(r).length,0);for(const id of ['ast:shell-input-sink','ast:html-input-sink','ast:server-request'])assert.ok(r.findings.some(f=>f.ruleId===id));
 for(const cap of [{indexWork:1},{flowWork:1},{nodeVisits:1}]){const limited=runBuiltinAst(snapshot({'app.ts':code}),false,{...FLOW_LIMITS,...cap});assert.equal(limited.status,'partial');assert.equal(limited.metrics?.sqlValuesOnlyExcluded,0);assert.equal(evaluateGate(createReport([limited],'source','2026-10-05T00:00:00.000Z'),'none').exitCode,2);}
 const incomplete=snapshot({'app.ts':code});incomplete.complete=false;const failed=runBuiltinAst(incomplete,false);assert.equal(sql(failed).length,1);assert.equal(sql(failed)[0].confidence,'low');
});

test('four public projections keep actual text evidence, fixed titles, unverified status and redaction',()=>{
 const r=run(prefix+"function route(req){db.query({values:[req.query.payload],text:req.query.sql})}");const report=createReport([r],'source','2026-10-05T00:00:00.000Z');const agent=toAgentReport(report,'high');
 assert.equal(RULESET_VERSION,'2026-10-05.17');assert.equal(evaluateGate(report,'high').exitCode,1);
 assert.equal(agent.findings[0].verification.vulnerabilityConfirmed,false);assert.equal(agent.findings[0].verification.state,'not_run');
 for(const output of [JSON.stringify(report),JSON.stringify(agent),JSON.stringify(toSarif(report)),toMarkdown(report)]){
 assert.match(output,/Request input reaches a SQL statement text argument/);assert.doesNotMatch(output,/req\.query\.sql|SELECT id FROM/);
 }
});


test('shadowed Object pure-looking calls cannot grant inherited dispatch proof',()=>{
 for(const method of ['keys','entries','getOwnPropertyNames']){
  const r=run(prefix+`const Object={${method}(proto){proto.submit=custom;return []}};function route(req){Object.${method}(String.prototype);db.query({text:${fixed},values:[req.query.value]})}`);
  assert.equal(sql(r).length,1,method);assert.equal(sql(r)[0].confidence,'low');
  const normal=run(prefix+`function route(req){Object.${method}(String.prototype);db.query({text:${fixed},values:[req.query.value]})}`);assert.equal(sql(normal).length,0,method);
 }
});

test('explicit named bind-data serializers are unresolved without globally sanitizing their input',()=>{
 for(const declaration of ["const item={value:req.query.value,toPostgres(){return this.value}};","const item={value:req.query.value};item.toPostgres=custom;"]){
  const r=run(prefix+`function route(req){${declaration}db.query({text:${fixed},values:[item]})}`);
  assert.equal(sql(r).length,1,declaration);assert.equal(sql(r)[0].confidence,'low');
 }
 const normal=run(prefix+`function route(req){const item={value:req.query.value};db.query({text:${fixed},values:[item]})}`);assert.equal(sql(normal).length,0);
});

test('unshadowed globalThis native prototype writes and escapes revoke dispatch proof',()=>{
 for(const change of ["globalThis.String.prototype.submit=custom;","globalThis['Object'].prototype.submit=custom;","const proto=globalThis.Array.prototype;opaque(proto);","const native=globalThis.String;native.prototype.submit=custom;"]){
  const r=run(prefix+`function route(req){${change}db.query({text:${fixed},values:[req.query.value]})}`);assert.equal(sql(r).length,1,change);assert.equal(sql(r)[0].confidence,'low');
 }
 const normal=run(prefix+`const globalThis={String:{prototype:{}}};function route(req){globalThis.String.prototype.submit=custom;db.query({text:${fixed},values:[req.query.value]})}`);assert.equal(sql(normal).length,0);
});


test('named data reassignment, nested writes and computed/function fields fail only data qualification',()=>{
 for(const setup of [
  "let item={value:req.query.value};item={value:req.query.value,toPostgres(){return this.value}};",
  "const item={nested:{value:req.query.value}};item.nested.toPostgres=custom;",
  "const item={value:req.query.value,['toPostgres']:encode};",
  "const item={value:req.query.value,serialize:encode};",
  "const item={value:req.query.value};opaque(item);",
  "const item={value:req.query.value};const box={item};box.item.toPostgres=custom;",
  "const item={value:req.query.value};Object.defineProperty(item,'toPostgres',{value:custom});"
 ]){const r=run(prefix+`function encode(v){return v}function route(req){${setup}db.query({text:${fixed},values:[item]})}`);assert.equal(sql(r).length,1,setup);assert.equal(sql(r)[0].confidence,'low');}
 const normal=run(prefix+`function route(req){const item={nested:{value:req.query.value}};db.query({text:${fixed},values:[item.nested]})}`);assert.equal(sql(normal).length,0);
 const scalar=run(prefix+`function route(req){let statement=${fixed};const config={text:statement,values:[req.query.value]};statement=req.query.sql;db.query(config)}`);assert.equal(sql(scalar).length,0);
});

test('named and actual callback overloads remain unknown without erasing known text input',()=>{
 for(const call of ['db.query(req.query.sql,cb)','send(req.query.sql,cb)','send(req.query.sql,()=>{})']){
  const r=run(prefix+`function cb(){}function send(text,values){db.query(text,values)}function route(req){${call}}`);assert.equal(sql(r).length,1,call);assert.equal(sql(r)[0].confidence,'low');assert.equal(sql(r)[0].title,'Input-related SQL API argument roles are unresolved');
 }
 const risk=run(prefix+'function route(req){db.query(req.query.sql,[req.query.value])}');assert.equal(sql(risk)[0].confidence,'medium');
 const reassigned=run(prefix+'function source(){}function route(req){source=req.query.sql;db.query(source);exec(source)}');assert.equal(sql(reassigned).length,1);assert.equal(sql(reassigned)[0].confidence,'medium');assert.ok(reassigned.findings.some(f=>f.ruleId==='ast:shell-input-sink'));
});


test('array-only proof failure never downgrades an actual supported text input role',()=>{
 for(const values of ['opaque(req.query.value)', '['+Array.from({length:65},()=>"req.query.value").join(',')+']']){
  const risky=run(prefix+`function route(req){db.query({text:req.query.sql,values:${values}})}`);assert.equal(sql(risky).length,1);assert.equal(sql(risky)[0].confidence,'medium');assert.equal(sql(risky)[0].title,'Request input reaches a SQL statement text argument');
  const unqualified=run(prefix+`function route(req){db.query({text:${fixed},values:${values}})}`);assert.equal(sql(unqualified).length,1);assert.equal(sql(unqualified)[0].confidence,'low');assert.equal(unqualified.status,'completed');
 }
});


test('explicit object serializer evidence survives scalar actuals and array-return contexts without contaminating normal data',()=>{
 for(const reverse of [false,true]){
  const calls=[`db.query({text:${fixed},values:pack({value:input})})`,`db.query({text:${fixed},values:pack({value:input,toPostgres(){return this.value}})})`];if(reverse)calls.reverse();
  const r=run(prefix+`function pack(item){return [item]}function route(req){const input=req.query.value;${calls.join(';')}}`);assert.equal(sql(r).length,1);assert.equal(sql(r)[0].confidence,'low');assert.equal(r.metrics?.sqlValuesOnlyExcluded,1);
 }
});

for(const projection of ['item.nested','item[key]'])test(`nested SQL data-unavailable state survives ${projection} projection with a normal control`,()=>{
 const code=(mutation:string)=>prefix+`function pack(item,key){return [${projection}]}function route(req){const item={nested:{value:req.query.value}};${mutation}db.query({text:${fixed},values:pack(item,'nested')})}`;
 const normal=run(code(''));assert.equal(sql(normal).length,0);assert.equal(normal.metrics?.sqlValuesOnlyExcluded,1);
 const risky=run(code('item.nested.toPostgres=custom;'));assert.equal(sql(risky).length,1);assert.equal(sql(risky)[0].confidence,'low');assert.ok(sql(risky)[0].staticFlow?.steps.some(s=>s.role==='source'));
});
