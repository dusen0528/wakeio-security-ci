import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runBuiltinAst} from '../src/source/ast.js';
import {FLOW_LIMITS,type FlowLimits} from '../src/source/modules.js';
import {runSource} from '../src/source.js';
import {createReport,evaluateGate,toAgentReport,toMarkdown,toSarif,RULESET_VERSION} from '../src/report.js';
import type {SourceSnapshot} from '../src/source/types.js';

const marker='OWNED_CODE_SIGNAL_MARKER';
function run(text:string,more:Record<string,string>={},complete=true,limits:FlowLimits=FLOW_LIMITS){
  const files=Object.entries({'app.ts':text,...more}).map(([path,text])=>({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));
  const snapshot:SourceSnapshot={root:'/never-execute-owned-source',files,issues:[],complete,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};
  return runBuiltinAst(snapshot,false,limits);
}
const dynamic=(c:ReturnType<typeof run>)=>c.findings.filter(f=>f.ruleId==='ast:dynamic-code');
function projections(c:ReturnType<typeof run>,source:string){
  const report=createReport([c],'source','2026-10-06T00:00:00.000Z');
  assert.ok(source.includes(marker));
  for(const output of [JSON.stringify(report),toMarkdown(report),JSON.stringify(toSarif(report)),JSON.stringify(toAgentReport(report))]){
    assert.ok(!output.includes(marker));assert.ok(!output.includes(source));
  }
  const agent=toAgentReport(report);assert.ok(agent.findings.every(f=>!f.verification.vulnerabilityConfirmed&&!f.verification.remediationVerified));
  return report;
}

test('direct literal call/new operands are syntax observations, input pair keeps actual evidence in four projections',()=>{
  assert.equal(RULESET_VERSION,'2026-10-06.1');
  for(const name of ['eval','window.eval','Function','window.Function','new Function','new window.Function']){
    const risk=`function route(req){${name}(req.body.${marker})}`;
    const r=run(risk),f=dynamic(r)[0];assert.equal(r.status,'completed');assert.equal(dynamic(r).length,1);
    assert.equal(f.kind,'candidate');assert.equal(f.severity,'high');assert.equal(f.confidence,'medium');
    assert.equal(f.location.path,'app.ts');assert.equal(f.location.line,1);assert.equal(f.location.column,risk.indexOf(name)+1);
    assert.equal(f.staticFlow?.truncated,false);assert.ok(f.staticFlow?.steps.some(s=>s.role==='source'));assert.match(f.title,/Input reaches an evaluation-shaped/);
    assert.equal(evaluateGate(projections(r,risk),'high').exitCode,1);
    const normal=`function route(req){${name}('return "${marker}"')}`;
    const n=run(normal),nf=dynamic(n)[0];assert.equal(n.status,'completed');assert.equal(dynamic(n).length,1);
    assert.equal(nf.kind,'observation');assert.equal(nf.severity,'info');assert.equal(nf.staticFlow,undefined);
    assert.match(nf.description,/Callee identity, generated-code safety and runtime execution are unverified/);
    const report=projections(n,normal);assert.equal(evaluateGate(report,'high').exitCode,0);assert.equal(evaluateGate(report,'info').exitCode,1);
    assert.equal(toAgentReport(report).summary!.counts.candidates,0);
  }
});

test('Function checks every parameter/body operand and selects actual later argument source, including new',()=>{
  for(const name of ['Function','window.Function','new Function','new window.Function'])for(const index of [0,1,2]){
    const args=["'x'","'y'",`'return "${marker}"'`];args[index]=`req.query.${marker}`;
    const text=`function route(req){${name}(${args.join(',')})}`,r=run(text),f=dynamic(r)[0];
    assert.equal(f.kind,'candidate');assert.equal(f.confidence,'medium');
    assert.ok(f.description.includes(`syntactic argument ${index+1} (${index===2?'body':'parameter-source'} under the API convention)`));
    assert.ok(f.staticFlow?.steps.some(s=>s.role==='source'&&s.location.column===text.indexOf(`req.query.${marker}`)+1));
    assert.ok(f.staticFlow?.steps.some(s=>s.role==='sink'&&s.location.column===text.indexOf(name)+1));projections(r,text);
  }
});

test('tainted relevant operands precede unknown, then lowest original index wins',()=>{
  for(const name of ['Function','new Function']){
    const text=`function route(req){${name}(opaque(req.query.first),req.body.${marker},req.params.last)}`;
    const f=dynamic(run(text))[0];assert.equal(f.confidence,'medium');
    assert.ok(f.staticFlow?.steps.some(s=>s.role==='source'&&s.location.column===text.indexOf(`req.body.${marker}`)+1));
    const first=`function route(req){${name}(req.query.${marker},req.body.other)}`;
    assert.ok(dynamic(run(first))[0].staticFlow?.steps.some(s=>s.role==='source'&&s.location.column===first.indexOf(`req.query.${marker}`)+1));
    const unknown=`function route(req){${name}(opaque(req.body.${marker}))}`;
    const u=dynamic(run(unknown))[0];assert.equal(u.confidence,'low');assert.ok(u.staticFlow?.steps.some(s=>s.role==='source'));projections(run(unknown),unknown);
  }
});

test('eval first argument excludes unrelated trailing input and nested real sink remains independent',()=>{
  const source=`function route(req){eval('return "${marker}"',req.body.ignored);eval('fixed',db.query(req.body.${marker}))}`;
  const r=run(source);assert.equal(dynamic(r).length,2);assert.ok(dynamic(r).every(f=>f.kind==='observation'&&!f.staticFlow));
  assert.equal(r.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,1);assert.equal(evaluateGate(projections(r,source),'high').exitCode,1);
});

test('nonliteral operands and all spread positions stay conservative without manufactured input trace',()=>{
  for(const operand of ['code','42','true','{}',"'a'+'b'",'`${value}`','String(code)']){
    const r=run(`const code='fixed';function route(req){Function(${operand})}`),f=dynamic(r)[0];
    assert.equal(f.severity,'high');assert.equal(f.kind,'candidate');assert.equal(f.confidence,'low');assert.equal(f.staticFlow,undefined);
  }
  for(const name of ['eval','Function','new Function'])for(const args of ["...['fixed']","'fixed',...['ignored']","...args,'fixed'"]){
    const f=dynamic(run(`${name}(${args})`))[0];assert.equal(f.kind,'candidate');assert.equal(f.severity,'high');assert.equal(f.confidence,'low');assert.equal(f.staticFlow,undefined);
  }
  const text=`function route(req){Function(...req.body.${marker})}`,r=run(text),f=dynamic(r)[0];assert.equal(f.confidence,'low');assert.match(f.title,/Unresolved/);assert.ok(f.staticFlow);projections(r,text);
});

test('no-substitution template qualifies without content allowlist or generated-code safety claim',()=>{
  for(const text of ["eval(`anything here`)","Function(`x`,`return x`)","new Function(`arbitrary fixed body`)",`eval('eval(req.body.${marker})')`]){
    const f=dynamic(run(text))[0];assert.equal(f.severity,'info');assert.equal(f.kind,'observation');assert.equal(f.staticFlow,undefined);
    assert.match(f.description,/generated-code safety.*unverified/);
  }
});

test('legacy computed name fallbacks keep low unresolved candidates and only syntactic input evidence',()=>{
  for(const callee of ['eval[key]','Function[key]','window[key].Function',"window['eval'][key]"]){
    const literal=`function route(req){${callee}('return "${marker}"')}`;
    const l=run(literal),lf=dynamic(l)[0];assert.equal(dynamic(l).length,1);assert.equal(lf.kind,'candidate');assert.equal(lf.severity,'high');assert.equal(lf.confidence,'low');assert.equal(lf.staticFlow,undefined);assert.match(lf.description,/unresolved computed dispatch/);projections(l,literal);
    const input=`function route(req){${callee}('fixed',req.body.${marker})}`;
    const r=run(input),f=dynamic(r)[0];assert.equal(f.kind,'candidate');assert.equal(f.confidence,'low');assert.match(f.title,/Unresolved/);assert.match(f.description,/syntactic argument 2; code role is unresolved/);
    assert.ok(!f.description.includes('under the API convention'));assert.ok(f.staticFlow?.steps.some(s=>s.role==='source'&&s.location.column===input.indexOf(`req.body.${marker}`)+1));projections(r,input);
  }
});

test('literal window member call spellings retain exact operand convention while identifier keys are unmodeled',()=>{
  for(const callee of ["window['eval']","window[`eval`]","window['Function']","window[`Function`]"]){
    const evalShape=callee.includes('eval');
    const input=`function route(req){${callee}(${evalShape?`req.body.${marker}`:`'x',req.body.${marker}`})}`;
    const r=run(input),f=dynamic(r)[0];assert.equal(f.confidence,'medium');assert.equal(f.kind,'candidate');assert.ok(f.description.includes(evalShape?'syntactic argument 1 (code operand':'syntactic argument 2 (body'));assert.ok(f.staticFlow);projections(r,input);
    const literal=`function route(req){${callee}('return "${marker}"')}`;const l=run(literal);assert.equal(dynamic(l)[0].kind,'observation');assert.equal(dynamic(l)[0].severity,'info');projections(l,literal);
  }
  // These were never statically named evaluation calls; no new computed-callee detection is added.
  assert.equal(dynamic(run("window[eval]('fixed');window[Function]('fixed');")).length,0);
});

test('lexical local shadow and replaced names retain shape semantics and supported local body sinks',()=>{
  for(const name of ['eval','Function']){
    const source=`function ${name}(value){db.query(value);return value}function route(req){${name}(req.query.${marker});${name}('fixed')}`;
    const r=run(source);assert.equal(dynamic(r).length,2);assert.equal(dynamic(r).filter(f=>f.kind==='candidate').length,1);assert.equal(dynamic(r).filter(f=>f.kind==='observation').length,1);
    assert.equal(r.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,1);projections(r,source);
    assert.equal(dynamic(run(`let ${name}=custom;${name}=other;${name}('fixed')`))[0].kind,'observation');
  }
});

test('ordinary call bodies and actual traces remain present for SQL HTTP HTML fork and timer',()=>{
  const source=`const {fork}=require('child_process');function route(req){Function('x',req.body.${marker});db.query(req.body.${marker});fetch(req.body.${marker});document.write(req.body.${marker});fork(req.body.${marker});setTimeout(req.body.${marker},1)}`;
  const r=run(source);for(const id of ['ast:sql-input-sink','ast:server-request','ast:html-input-sink','ast:fork-module-path'])assert.equal(r.findings.filter(f=>f.ruleId===id).length,1);
  const timer=r.findings.find(f=>f.title==='Request input reaches a timer code argument');assert.ok(timer?.staticFlow?.steps.some(s=>s.role==='source'));projections(r,source);
});

test('scope parse and budget incompletion keep gate2 and zero-argument behavior is unchanged',()=>{
  const text=`function pass(v){return v}function route(req){new Function(pass(req.body.${marker}));eval('fixed')}`;
  for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1},{...FLOW_LIMITS,summaryWork:0}]){
    const r=run(text,{},true,limits);assert.equal(r.status,'partial');assert.equal(evaluateGate(projections(r,text),'none').exitCode,2);
  }
  // Collection completeness is carried by source.inventory, not invented by this AST-only helper.
  const incomplete=run(text,{},false);assert.ok(dynamic(incomplete).some(f=>f.kind==='candidate'));projections(incomplete,text);
  const collectionReport=createReport([{id:'source.inventory',status:'partial',findings:[],notes:[]},incomplete],'source','2026-10-06T00:00:00.000Z');
  assert.equal(evaluateGate(collectionReport,'high').exitCode,2);
  const malformed=run(`eval('fixed');function broken(`);assert.equal(malformed.status,'partial');assert.equal(dynamic(malformed).length,1);assert.equal(dynamic(malformed)[0].kind,'candidate');
  assert.equal(dynamic(run('eval();Function();new Function();new window.Function;')).length,0);
});

test('declared uncertainty and physical omitted trace preserve their existing independent dimensions',()=>{
  const source=`const finder=require('./finder');function route(req){finder.send(req.body.${marker})}`;
  const r=run(source,{'finder.js':'class Finder{send(value){new Function(value)}}module.exports=new Finder();','loader.js':'require(dynamicPath)'}),f=dynamic(r)[0];
  assert.equal(r.status,'partial');assert.equal(f.confidence,'low');assert.equal(f.staticFlow?.truncated,false);assert.ok(f.staticFlow?.steps.some(s=>s.role==='parameter'));projections(r,source);
  const chain='function a(v){return b(v)}function b(v){return c(v)}function c(v){return d(v)}function d(v){return e(v)}function e(v){return f(v)}function f(v){return g(v)}function g(v){return h(v)}function h(v){return v}';
  const long=run(`${chain}function route(req){new Function(a(req.body.${marker}))}`);assert.equal(dynamic(long)[0].staticFlow?.truncated,true);
});

test('later operand writes do not replace earlier actuals in call/new, including initializer re-evaluation',()=>{
  for(const name of ['Function','new Function'])for(const initialize of [false,true]){
    const assigned=initialize?'const result=':'';
    const source=`function route(req){let x='fixed';${assigned}${name}(x,(x=req.body.${marker}))}`;
    const r=run(source),f=dynamic(r)[0];assert.equal(f.confidence,'medium');
    // The first value was fixed; only the later assignment is input-related.
    assert.ok(f.staticFlow?.steps.some(s=>s.role==='source'&&s.location.column===source.indexOf(`req.body.${marker}`)+1));
    assert.match(f.description,/syntactic argument 2 \(body under the API convention\)/);projections(r,source);
    const before=`function route(req){let x=req.body.${marker};${assigned}${name}(x,(x='fixed'))}`;
    const b=run(before),bf=dynamic(b)[0];assert.equal(bf.confidence,'medium');assert.ok(bf.staticFlow?.steps.some(s=>s.role==='source'));assert.match(bf.description,/syntactic argument 1 \(parameter-source under the API convention\)/);projections(b,before);
  }
  for(const initialize of [false,true]){
    const assigned=initialize?'const result=':'';
    const fixed=`function route(req){let x='fixed';${assigned}eval(x,(x=req.body.${marker}))}`;
    const f=dynamic(run(fixed))[0];assert.equal(f.confidence,'low');assert.equal(f.staticFlow,undefined);
    const input=`function route(req){let x=req.body.${marker};${assigned}eval(x,(x='fixed'))}`;
    const f2=dynamic(run(input))[0];assert.equal(f2.confidence,'medium');assert.ok(f2.staticFlow?.steps.some(s=>s.role==='source'));projections(run(input),input);
  }
  for(const name of ['Function','eval']){
    const body=`function ${name}(first,ignored){db.query(first);return first}`;
    const fixed=`${body}function route(req){let x='fixed';const result=${name}(x,(x=req.body.${marker}))}`;
    assert.equal(run(fixed).findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,0);
    const risky=`${body}function route(req){let x=req.body.${marker};const result=${name}(x,(x='fixed'))}`;
    assert.equal(run(risky).findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,1);projections(run(risky),risky);
  }
});

test('public source SDK risky/literal pair uses existing report contract with no target execution',async()=>{
  const root=await mkdtemp(join(tmpdir(),'wakeio-owned-dynamic-code-'));
  try{
    for(const code of [`function route(req){new Function('x',req.body.${marker})}`,`function route(req){new Function('x','return "${marker}"')}`]){
      await writeFile(join(root,'app.js'),code);const checks=await runSource({root,tools:[]});const c=checks.find(c=>c.id==='source.builtin-ast')!;
      const report=projections(c,code);assert.equal(evaluateGate(report,'high').exitCode,code.includes('req.body.')?1:0);
    }
  }finally{await rm(root,{recursive:true,force:true});}
});
