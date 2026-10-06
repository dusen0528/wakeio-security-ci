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
const prefix="import {Pool} from 'pg';const db=new Pool();";
const choice="req.query.mode==='a'?'SELECT a WHERE id=$1':'SELECT b WHERE id=$1'";
const run=(code:string,more:Record<string,string>={})=>runBuiltinAst(snapshot({'entry.ts':code,...more}),false);
const sql=(check:ReturnType<typeof run>)=>check.findings.filter(f=>f.ruleId==='ast:sql-input-sink');
function excluded(code:string,more:Record<string,string>={}) {
 const result=run(code,more);assert.equal(result.status,'completed');assert.equal(sql(result).length,0);assert.equal(result.metrics?.sqlValuesOnlyExcluded,1);return result;
}
function unknown(code:string) {
 const result=run(code);assert.equal(result.status,'completed');assert.equal(sql(result).length,1);assert.equal(sql(result)[0].confidence,'low');assert.equal(sql(result)[0].title,'Input-related SQL API argument roles are unresolved');assert.equal(sql(result)[0].staticFlow?.truncated,true);return result;
}

test('request selector chooses fixed statements in positional/config JS and TS queries',()=>{
 for(const path of ['entry.js','entry.ts']) for(const config of [false,true]) {
 const text=prefix+`function route(req){const text=${choice};db.query(${config?'{text,values:[req.body.id]}':'text,[req.body.id]'})}`;
 const result=runBuiltinAst(snapshot({[path]:text}),false);assert.equal(result.status,'completed');assert.equal(sql(result).length,0);assert.equal(result.metrics?.sqlValuesOnlyExcluded,1);
 }
});

test('if branch merge and many literal selections keep a bounded maximum without enumerating strings',()=>{
 excluded(prefix+`function route(req){let text;if(req.query.mode){text='SELECT a WHERE id=$1'}else{text='SELECT b WHERE id=$1'}db.query(text,[req.body.id])}`);
 const branches=Array.from({length:30},(_,i)=>`text=req.query.flag${i}?'SELECT ${i} WHERE id=$1':text;`).join('');
 excluded(prefix+`function route(req){let text='SELECT start WHERE id=$1';${branches}db.query(text,[req.body.id])}`);
});

test('all-proven string concat and template preserve fixed choices; actual input concat does not',()=>{
 for(const text of [`(${choice})+' ORDER BY id'`,`\`prefix \${${choice}} suffix\``]) excluded(prefix+`function route(req){db.query(${text},[req.body.id])}`);
 const code=prefix+`function route(req){const text=(${choice})+req.query.tail;db.query(text,[req.body.id])}`;
 const result=run(code);assert.equal(sql(result).length,1);assert.equal(sql(result)[0].confidence,'medium');assert.equal(sql(result)[0].title,'Request input reaches a SQL statement text argument');assert.equal(sql(result)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.column,code.indexOf('req.query.tail')+1);
});

test('a risky branch retains the actual SQL input rather than selector or values trace in either order',()=>{
 for(const expression of ["req.query.mode?'SELECT a WHERE id=$1':req.query.statement","req.query.mode?req.query.statement:'SELECT b WHERE id=$1'"]) {
 const code=prefix+`function route(req){db.query({values:[req.body.id],text:${expression}})}`;
 const result=run(code);assert.equal(sql(result).length,1);assert.equal(sql(result)[0].confidence,'low');assert.equal(sql(result)[0].title,'Request input reaches a SQL statement text argument');assert.equal(sql(result)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.column,code.indexOf('req.query.statement')+1);
 }
});

test('opaque and general safe nonstring branches do not receive a literal qualifier',()=>{
 for(const branch of ['opaque()','42','false','null','new URLSearchParams().toString()']) unknown(prefix+`function route(req){const text=req.query.mode?'SELECT a WHERE id=$1':${branch};db.query(text,[req.body.id])}`);
});

test('scalar ordinary local and relative actual-return carries literal choices',()=>{
 excluded(prefix+`function choose(mode){return mode?'SELECT a WHERE id=$1':'SELECT b WHERE id=$1'}function pass(text){return text}function route(req){db.query(pass(choose(req.query.mode)),[req.body.id])}`);
 for(const reverse of [false,true]) {
 const entry=prefix+`import {choose,pass} from './helper';function route(req){db.query(pass(choose(req.query.mode)),[req.body.id])}`;
 const helper="export function choose(mode){return mode?'SELECT a WHERE id=$1':'SELECT b WHERE id=$1'}export function pass(text){return text}";
 const result=runBuiltinAst(snapshot(reverse?{'helper.ts':helper,'entry.ts':entry}:{'entry.ts':entry,'helper.ts':helper}),false);assert.equal(result.status,'completed');assert.equal(sql(result).length,0);assert.equal(result.metrics?.sqlValuesOnlyExcluded,1);assert.ok(Number(result.metrics?.resolvedCalls)>0);
 }
});

test('async and generator calls cannot restore fixed text via await or a literal join',()=>{
 for(const declaration of ["async function pack(){return 'SELECT a WHERE id=$1'}","function* pack(){return 'SELECT a WHERE id=$1'}"]) for(const call of ['pack()','await pack()']) unknown(prefix+declaration+`async function route(req){const text=req.query.mode?'SELECT b WHERE id=$1':${call};db.query(text,[req.body.id])}`);
 excluded(prefix+`async function send(text,value){db.query(text,[value])}function route(req){send(${choice},req.body.id)}`);
});

test('closed config captures fixed text before subsequent scalar reassignment',()=>{
 excluded(prefix+`function route(req){let text=${choice};const config={text,values:[req.body.id]};text=req.query.statement;db.query(config)}`);
 const code=prefix+`function route(req){let text=req.query.statement;const config={text,values:[req.body.id]};text=${choice};db.query(config)}`;
 const result=run(code);assert.equal(sql(result).length,1);assert.equal(sql(result)[0].confidence,'medium');assert.equal(sql(result)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.column,code.indexOf('req.query.statement')+1);
});

test('general container storage and member assignment cannot carry stale fixed-text proof',()=>{
 for(const setup of [`const box={text:${choice}};`,`const box={};box.text=${choice};`,`const box=[${choice}];`]) unknown(prefix+`function route(req){${setup}db.query(${setup.includes('box=[')?'box[0]':'box.text'},[req.body.id])}`);
 unknown(prefix+`function route(req){const box={text:${choice}};const alias=box;alias.text=req.query.statement;db.query(box.text,[req.body.id])}`);
});

test('length 0 and 2048 are qualified, any 2049 branch or concatenated upper bound is unknown',()=>{
 for(const text of ["''",JSON.stringify('a'.repeat(2048)),JSON.stringify('😀'.repeat(1024))]) excluded(prefix+`function route(req){db.query(textChoice(req.query.mode),[req.body.id])}function textChoice(mode){return mode?${text}:${text}}`);
 for(const expression of [`req.query.mode?'SELECT a':${JSON.stringify('a'.repeat(2049))}`,`(${JSON.stringify('a'.repeat(2048))})+'b'`,`\`a\${${JSON.stringify('a'.repeat(2048))}}\``]) unknown(prefix+`function route(req){db.query(${expression},[req.body.id])}`);
 excluded(prefix+`function route(req){db.query((${JSON.stringify('a'.repeat(2047))})+'b',[req.body.id])}`);
});

test('cache and context merging distinguish fixed opaque and actual input callers in either order',()=>{
 for(const reverse of [false,true]) for(const other of ['opaque()','req.query.statement']) {
 const calls=[`send(${choice},req.body.id)`,`send(${other},req.body.id)`];if(reverse)calls.reverse();
 const code=prefix+`function send(text,value){db.query({text,values:[value]})}function route(req){${calls.join(';')}}`;
 const result=run(code);assert.equal(result.status,'completed');assert.equal(sql(result).length,1);
 if(other==='req.query.statement'){assert.equal(sql(result)[0].confidence,'medium');assert.equal(sql(result)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.column,code.indexOf(other)+1);}else{assert.equal(sql(result)[0].confidence,'low');assert.equal(sql(result)[0].title,'Input-related SQL API argument roles are unresolved');}
 }
});

test('known dispatch, values and unbound API vetoes remain necessary despite fixed literal alternatives',()=>{
 unknown(prefix+`Object.prototype.submit=custom;function route(req){db.query(${choice},[req.body.id])}`);
 unknown(prefix+`function route(req){const values=[req.body.id];opaque(values);db.query(${choice},values)}`);
 const generic=run(`function route(req){db.query({text:${choice},values:[req.body.id]})}`);assert.equal(sql(generic).length,1);assert.equal(generic.metrics?.sqlRoleBoundUses,0);
});

test('bind-data remains tainted for shell HTML and outbound; URL query qualification does not inherit SQL facet',()=>{
 const result=excluded(prefix+`function route(req){const value=req.body.id;db.query(${choice},[value]);exec(value);el.innerHTML=value;fetch(value)}`);
 for(const rule of ['ast:shell-input-sink','ast:html-input-sink','ast:server-request'])assert.ok(result.findings.some(f=>f.ruleId===rule));
 const url=run(prefix+`function route(req){const q=new URLSearchParams({id:req.body.id});const prefix=req.query.mode?'https://a.example/p?':'https://b.example/p?';fetch(prefix+q.toString())}`);assert.equal(url.findings.filter(f=>f.ruleId==='ast:server-request').length,1);
});

test('phase caps and incomplete scope remain fail-closed and public output never exposes private qualifier',()=>{
 const code=prefix+`function route(req){db.query(${choice},[req.body.id])}`;
 for(const cap of [{indexWork:1},{flowWork:1},{nodeVisits:1}]){const limited=runBuiltinAst(snapshot({'entry.ts':code}),false,{...FLOW_LIMITS,...cap});assert.equal(limited.status,'partial');assert.equal(limited.metrics?.sqlValuesOnlyExcluded,0);assert.equal(evaluateGate(createReport([limited],'source','2026-10-05T00:00:00.000Z'),'none').exitCode,2);}
 const incomplete=snapshot({'entry.ts':code});incomplete.complete=false;const failed=runBuiltinAst(incomplete,false);assert.equal(sql(failed).length,1);assert.equal(sql(failed)[0].confidence,'low');
 const risk=run(prefix+`function route(req){db.query(req.query.statement,[req.body.id])}`);const report=createReport([risk],'source','2026-10-05T00:00:00.000Z');const agent=toAgentReport(report,'high');
 assert.equal(RULESET_VERSION,'2026-10-06.2');assert.equal(agent.scanGate.exitCode,1);assert.equal(agent.findings[0].verification.vulnerabilityConfirmed,false);
 for(const output of [JSON.stringify(report),JSON.stringify(agent),JSON.stringify(toSarif(report)),toMarkdown(report)]){assert.doesNotMatch(output,/sqlFixedText|maxCharacters|req\.query\.statement|SELECT a WHERE/);assert.match(output,/Request input reaches a SQL statement text argument/);}
});
