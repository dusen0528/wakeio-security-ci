import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runSource } from "../src/source.js";
import { runBuiltinAst } from "../src/source/ast.js";
import { FLOW_LIMITS } from "../src/source/modules.js";
import { createReport, sanitiseReport, toAgentReport, toSarif, toMarkdown, writeReports, RULESET_VERSION } from "../src/report.js";
import type { CheckResult, ScanReport } from "../src/contracts.js";

const exec = promisify(execFile);
const repo = resolve(fileURLToPath(new URL("../..", import.meta.url)));
async function withFiles<T>(files: Record<string, string>, fn: (root: string, parent: string) => Promise<T>): Promise<T> {
  const parent = await mkdtemp(join(tmpdir(), "wakeio-interprocedural-dev-"));
  const root = join(parent, "source");
  await mkdir(root);
  try {
    for (const [path, text] of Object.entries(files)) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await writeFile(join(root, path), text);
    }
    return await fn(root, parent);
  } finally { await rm(parent, { recursive: true, force: true }); }
}
async function scan(files: Record<string, string | undefined>) {
  const selected = Object.fromEntries(Object.entries(files).map(([path, text]) => {
    assert.equal(typeof text, "string"); return [path, text as string];
  }));
  return withFiles(selected, async (root) => (await runSource({ root, tools: [] })).find((check) => check.id === "source.builtin-ast")!);
}
const sql = (check: CheckResult) => check.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink");

// Development cases are inspectable regressions, not a statistical blind holdout.
test("existing two known misses resolve at their original sink without helper-name rules", async () => {
  for (const [fixture, path] of [["sql-cross-function-known-miss", "app.ts"], ["sql-cross-file-known-miss", "sink.ts"]]) {
    const check = (await runSource({ root: join(repo, "benchmarks/fixtures", fixture), tools: [] })).find((item) => item.id === "source.builtin-ast")!;
    assert.equal(check.status, "completed");
    const findings = sql(check);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].location.path, path);
    assert.equal(findings[0].location.line, 2);
    assert.equal(findings[0].kind, "candidate");
    assert.equal(findings[0].confidence, "medium");
    assert.ok(findings[0].staticFlow?.steps.some((step) => step.role === "call"));
    assert.ok(findings[0].staticFlow?.steps.some((step) => step.role === "parameter"));
    assert.equal(findings[0].staticFlow?.steps.at(-1)?.role, "sink");
  }
});

test("named relative ESM alias composes returns and sink arguments with a parameterized safe pair", async () => {
  for (const [statement, count] of [["`SELECT * FROM t WHERE id='${id}'`", 1], ["'SELECT * FROM t WHERE id=?'", 0]] as const) {
    const check = await scan({
      "main.ts": `import { build as renamed } from './lib.js'; function dispatch(statement, values, db){ return db.execute(statement, values); } export function route(req,db){return dispatch(renamed(req.query.id),[req.query.id],db);}`,
      "lib.ts": `export const build = (id) => ${statement};`,
    });
    assert.equal(check.status, "completed");
    assert.equal(sql(check).length, count);
    if (count) assert.ok(sql(check)[0].staticFlow?.steps.some((step) => step.role === "return" && step.location.path === "lib.ts"));
  }
});

test("constant static CommonJS destructuring alias supports risky and parameterized safe pairs", async () => {
  for (const [expression, count] of [["'select '+id", 1], ["'select ?'", 0]] as const) {
    const check = await scan({
      "entry.js": `const { make: rename } = require('./builder'); function dispatch(statement,values,db){return db.query(statement,values)} function route(req,db){return dispatch(rename(req.query.id),[req.query.id],db)} module.exports={route};`,
      "builder.js": `const make = id => ${expression}; module.exports = {make};`,
    });
    assert.equal(check.status, "completed");
    assert.equal(sql(check).length, count);
    if (count) assert.equal(sql(check)[0].confidence, "medium");
  }
  const property = await scan({"a.js": `const {build} = require('./b'); function route(req){ db.query(build(req.query.id)); }`, "b.js": `function build(value){return 'select '+value;} exports.build=build;`});
  assert.equal(sql(property).length, 1);
  assert.equal(sql(property)[0].confidence, "medium");
});

test("unused tainted arguments, constant returns and req-named safe actuals do not seed helper sources", async () => {
  const check = await scan({ "app.ts": `
    function constant(unused){return 'select 1'}
    function takeFirst(statement,unused){return statement}
    function helper(req){return db.query(req.query.sql)}
    function wrapper(statement,values){return db.query(statement,values)}
    function route(req){
      db.query(constant(req.query.id));
      db.query(takeFirst('select 1',req.query.id));
      helper({query:{sql:'select 1'}});
      wrapper('select ?',[req.query.id]);
    }
  `});
  assert.equal(check.status, "completed");
  assert.equal(sql(check).length, 0);
});

test("same helper safe and tainted contexts retain only the actual risky origin", async () => {
  const check = await scan({"app.ts": `function carry(value){return value} function consume(statement){db.query(statement)} function route(req){consume(carry('select 1'));consume(carry(req.query.sql));}`});
  assert.equal(sql(check).length, 1);
  assert.equal(sql(check)[0].confidence, "medium");
  const trace = sql(check)[0].staticFlow!;
  assert.equal(trace.steps[0].role, "source");
  assert.ok(trace.steps[0].location.column > 100);
  assert.ok(trace.steps.every((step) => step.location.path === "app.ts"));
  assert.deepEqual(check, await scan({"app.ts": `function carry(value){return value} function consume(statement){db.query(statement)} function route(req){consume(carry('select 1'));consume(carry(req.query.sql));}`}));
});

test("lexical request and SQL-shaped local shadows remain clean", async () => {
  const check = await scan({"app.ts": `
    function query(value){return value}
    function helper(req){const db={query(x){return x}};db.query(req.query.sql);return query(req.query.sql)}
    function route(request){
      const req={query:{sql:'fixed'}}; helper(req);
      { const request={query:{sql:'fixed'}}; db.query(request.query.sql); }
      query(request.query.sql);
    }
  `});
  assert.equal(check.status, "completed");
  assert.equal(sql(check).length, 0);
});

test("statement order and early return preserve risky sinks and reject unreachable ones", async () => {
  const check = await scan({"app.ts": `
    function risky(statement){db.query(statement);statement='fixed';return 'fixed'}
    function safe(statement){statement='fixed';return db.query(statement)}
    function unreachable(statement){return 'fixed';db.query(statement)}
    function conditional(statement,flag){if(flag)return 'fixed';return statement}
    function route(req){risky(req.query.sql);safe(req.query.sql);unreachable(req.query.sql);db.query(conditional(req.query.sql,req.query.flag))}
  `});
  assert.equal(sql(check).length, 2);
  assert.ok(sql(check).some((finding) => finding.location.line === 2));
  assert.equal(sql(check).some((finding) => finding.location.line === 4), false);
});

test("deferred const arrow calls work while direct pre-initialization CJS calls are not resolved", async () => {
  for (const [body, count] of [["db.query(value)",1],["db.query('select 1')",0]] as const) {
    const check = await scan({"app.ts": `function route(req){late(req.query.sql)} const late=value=>${body};`});
    assert.equal(sql(check).length, count);
  }
  const early = await scan({"a.js": `fn(req.query.sql); const {fn}=require('./b');`,"b.js": `const fn=x=>db.query(x);module.exports={fn};`});
  assert.equal(sql(early).length, 0);
});

test("mutated ES exports and overwritten CJS maps never reuse stale safe summaries", async () => {
  for (const files of [
    {"a.ts": `import {f} from './b.js';function route(req){db.query(f(req.query.sql))}`,"b.ts": `export function f(x){return 'fixed'};f=x=>x;`},
    {"a.js": `const {f}=require('./b');function route(req){db.query(f(req.query.sql))}`,"b.js": `const safe=x=>'fixed'; const unsafe=x=>x; module.exports={f:safe};module.exports={};module.exports.f=unsafe;`},
    {"a.js": `const {f}=require('./b');function route(req){db.query(f(req.query.sql))}`,"b.js": `const safe=x=>'fixed';const unsafe=x=>x;exports.f=safe;exports.f=unsafe;`},
  ]) {
    const check = await scan(files);
    assert.equal(sql(check).length, 1);
    assert.equal(sql(check)[0].confidence, "low");
  }
});

test("plain script globals and default exports do not create implicit named cross-file summaries", async () => {
  for (const files of [
    {"a.ts": `function route(req){db.query(f(req.query.sql))}`,"b.ts": `function f(x){return 'fixed'}`},
    {"a.ts": `import {helper} from './b.js';function route(req){db.query(helper(req.query.sql))}`,"b.ts": `export default function helper(x){return 'fixed'}`},
  ]) {
    const check = await scan(files);
    assert.equal(sql(check).length, 1);
    assert.equal(sql(check)[0].confidence, "low");
    assert.equal(sql(check)[0].staticFlow?.steps.some((step) => step.location.path.startsWith('b.')), false);
  }
});

test("required relative resolution failures are partial while external package calls are limitations", async () => {
  for (const files of [
    {"a.ts": `import {f} from './missing.js';function route(req){db.query(f(req.query.sql))}`},
    {"a.ts": `import {f} from './b.js';function route(req){db.query(f(req.query.sql))}`,"b.ts": `export function f(x){return x}`,"b.js": `export function f(x){return x}`},
  ]) assert.equal((await scan(files)).status, "partial");
  const external = await scan({"a.ts": `import {f} from 'external-package';function route(req){db.query(f(req.query.sql))}`});
  assert.equal(external.status, "completed");
  assert.equal(sql(external)[0].confidence, "low");
  assert.ok(Number(external.metrics?.unsupportedCalls) > 0);
});

test("supported recursion and low deterministic analysis budgets are incomplete", async () => {
  assert.equal((await scan({"app.ts": `function loop(x){return loop(x)}function route(req){db.query(loop(req.query.sql))}`})).status,"partial");
  const snapshot = {root:"/not-read", files:[{path:"a.ts",text:`function f(x){return x}function route(req){db.query(f(f(req.query.sql)))}`,bytes:100,category:"code" as const,sensitive:false}],issues:[],ignoredFiles:0,totalBytes:100,complete:true};
  for (const [key, reason] of [["nodeVisits","node_limit"],["functions","function_limit"],["summaryWork","summary_limit"],["callDepth","depth_limit"]] as const) {
    const check = runBuiltinAst(snapshot,false,{...FLOW_LIMITS,[key]:1});
    assert.equal(check.status,"partial",key);
    assert.match(String(check.metrics?.incompleteReasons),new RegExp(reason));
  }
  const alias = Array.from({length:70},(_,i)=>`const f${i+1}=f${i};`).join('');
  const chain = await scan({"app.ts": `const f0=x=>x;${alias}function route(req){db.query(f70(req.query.sql))}`});
  assert.equal(chain.status,"partial");
  assert.match(String(chain.metrics?.incompleteReasons),/alias_limit/);
});

test("all four report projections preserve position-only static evidence and unverified semantics", async () => {
  const files={"app.ts": `function carry(value){return value} function route(req){db.query(carry(req.query.sql))}`};
  await withFiles(files,async(root,parent)=>{
    const checks=await runSource({root,tools:[]});
    const report=createReport(checks,'source','2026-10-05T00:00:00.000Z');
    report.finishedAt=report.startedAt;
    const safe=sanitiseReport(report);
    assert.deepEqual(sanitiseReport(safe),safe);
    const agent=toAgentReport(safe);
    assert.equal(agent.findings[0].evidence.traceStatus,'static_provided');
    assert.equal(agent.findings[0].verification.vulnerabilityConfirmed,false);
    assert.equal(agent.findings[0].verification.remediationVerified,false);
    assert.equal(agent.findings[0].verification.state,'not_run');
    assert.equal(agent.findings[0].remediation.state,'not_verified');
    assert.match(toMarkdown(safe),/Static source flow/);
    assert.match(JSON.stringify(toSarif(safe)),/codeFlows/);
    assert.equal(JSON.stringify(agent).includes('req.query.sql'),false);
    assert.equal(RULESET_VERSION,'2026-10-05.17');
    const out=join(parent,'out');
    await writeReports(safe,out);
    const persisted=JSON.parse(await readFile(join(out,'agent-report.json'),'utf8'));
    assert.deepEqual(persisted,agent);
  });
});

test("trace cap and malicious trace paths are explicit without invented security confirmation", async () => {
  const expression=Array.from({length:30}).reduce<string>((value)=>`unknown(${value})`,'req.query.sql');
  const check=await scan({"a.ts": `function route(req){db.query(${expression})}`});
  assert.equal(check.status,'completed');
  const flow=sql(check)[0].staticFlow!;
  assert.equal(flow.truncated,true);
  assert.equal(flow.steps.length,24);
  assert.equal(flow.steps.at(-1)?.role,'sink');
  const report=createReport([check],'source','2026-10-05T00:00:00.000Z');
  const injected=structuredClone(report) as ScanReport;
  injected.checks[0].findings[0].staticFlow!.steps.unshift({role:'source',location:{path:'/private/secret.txt',line:1,column:1}});
  const serialised=JSON.stringify(toAgentReport(injected));
  assert.equal(serialised.includes('/private/secret.txt'),false);
  assert.match(serialised,/static_truncated/);
});

test("actual CLI distinguishes risky fixed normal and supported incomplete even with fail-on none", async () => {
  for (const [body,code] of [["db.query(carry(req.query.sql))",1],["db.query(carry('select 1'))",0],["db.query('select ?',[req.query.id])",0],["db.query(loop(req.query.sql))",2]] as const) {
    await withFiles({"app.ts": `function carry(value){return value} function loop(x){return loop(x)}function route(req){${body}}`},async(root,parent)=>{
      const out=join(parent,'out');
      let actual=0;
      try {await exec(process.execPath,[join(repo,'dist-action/wakeio-security-ci.mjs'),'scan','--source',root,'--tools','none','--fail-on',code===2?'none':'high','--out',out],{cwd:repo});}
      catch(error){actual=Number((error as {code:number}).code)}
      assert.equal(actual,code,body);
      const agent=JSON.parse(await readFile(join(out,'agent-report.json'),'utf8'));
      assert.equal(agent.scanGate.exitCode,code);
      assert.equal(agent.scanGate.outcome,code===2?'incomplete':code===1?'findings':'pass');
    });
  }
});

test("opaque Database clients retain SQL candidates while proven local query methods do not", async () => {
  const risky=await scan({"app.ts":`const db=new Database();function route(req){db.query(req.query.sql)}`});
  assert.equal(sql(risky).length,1);
  assert.equal(sql(risky)[0].confidence,'medium');
  const safe=await scan({"app.ts":`function route(req){const db={query(value){return value}};db.query(req.query.sql)}`});
  assert.equal(sql(safe).length,0);
  const rebound=await scan({"app.ts":`function route(req){const db={query(value){return value}};db.query=externalQuery;db.query(req.query.sql)}`});
  assert.equal(sql(rebound).length,1);
});

test("request source methods and dynamic projections retain actual source positions", async () => {
  const check=await scan({"app.ts":`async function route(req,formData,searchParams){db.query((await req.json()).sql);db.query(formData.get('sql'));db.query(searchParams.get('sql'));db.query(req.query[unknownKey]);}`});
  assert.equal(sql(check).length,4);
  for(const finding of sql(check)) {
    assert.ok(finding.staticFlow?.steps.some((item)=>item.role==='source'));
    assert.equal(finding.staticFlow?.steps.at(-1)?.role,'sink');
  }
  const constant=await scan({"app.ts":`function route(req){const p=new URLSearchParams('sql=fixed');db.query(p.get('sql'))}`});
  assert.equal(sql(constant).length,0);
});

test("sink-only supplied traces are explicitly incomplete in the sanitized agent projection", async()=>{
  const check=await scan({"app.ts":`function route(req){db.query(req.query.sql)}`});
  check.findings[0].staticFlow={kind:'static_flow',truncated:false,steps:[{role:'sink',location:{path:'app.ts',line:1,column:1}}]};
  const agent=toAgentReport(createReport([check],'source','2026-10-05T00:00:00.000Z'));
  assert.equal(agent.findings[0].evidence.traceStatus,'static_truncated');
  assert.equal(agent.findings[0].verification.vulnerabilityConfirmed,false);
});


test("finally overrides return summaries and always evaluates its direct sink", async()=>{
  for(const [body,count] of [["try{return 'fixed'}catch(e){return 'fixed'}finally{return x}",1],["try{return x}catch(e){return x}finally{return 'fixed'}",0]] as const){
    const check=await scan({"app.ts":`function pass(x){${body}}function route(req){db.query(pass(req.query.sql))}`});
    assert.equal(check.status,'completed');assert.equal(sql(check).length,count);
  }
  const direct=await scan({"app.ts":`function route(req){try{return 1}catch(e){return 2}finally{db.query(req.query.sql)}}`});
  assert.equal(sql(direct).length,1);
});


test("explicit exports and external callback escapes retain request-shaped entries after safe local calls",async()=>{
  for(const source of [
    `export function route(req){db.query(req.query.sql)}route({query:{sql:'fixed'}});`,
    `function route(req){db.query(req.query.sql)}route({query:{sql:'fixed'}});app.get('/r',route);`,
  ]) {const check=await scan({"app.ts":source});assert.equal(check.status,'completed');assert.equal(sql(check).length,1);}
  const ordinary=await scan({"app.ts":`function helper(req){db.query(req.query.sql)}helper({query:{sql:'fixed'}});`});
  assert.equal(sql(ordinary).length,0);
});

test("unsupported closure returns preserve prior low input candidates without tainting constant returns",async()=>{
  const risky=await scan({"app.ts":`function route(req){const statement=req.query.sql;function helper(x){return statement}db.query(helper(req.query.sql))}`});
  assert.equal(sql(risky).length,1);assert.equal(sql(risky)[0].confidence,'low');assert.equal(sql(risky)[0].staticFlow?.truncated,true);
  const safe=await scan({"app.ts":`function route(req){const statement=req.query.sql;function helper(x){return 'fixed'}db.query(helper(req.query.sql))}`});
  assert.equal(sql(safe).length,0);
});

// Revision2 R03 development regressions: source strings are analyzed, never executed.
test("destructuring binding writes invalidate safe exported summaries including rest and defaults", async () => {
  const writes = [
    "[f]=[x=>x];",
    "({key:f}={key:x=>x});",
    "[f=x=>x]=[];",
    "({f=x=>x}={});",
    "[...f]=[x=>x];",
    "({...f}={key:x=>x});",
    "({nested:[f]}={nested:[x=>x]});",
  ];
  for (const write of writes) {
    const check = await scan({
      "entry.ts": "import {f as transformed} from './helper.js'; export function route(req){db.query(transformed(req.query.sql));}",
      "helper.ts": `export function f(value){return 'fixed'}; ${write}`,
    });
    assert.equal(check.status, "partial", write);
    assert.equal(sql(check).length, 1, write);
    assert.equal(sql(check)[0].confidence, "low", write);
    assert.equal(sql(check)[0].staticFlow?.truncated, true, write);
  }
});

test("for-in and for-of initializer writes invalidate exported safe bindings", async () => {
  for (const write of [
    "for(f of [x=>x]){}",
    "for([f] of [[x=>x]]){}",
    "for({key:f} of [{key:x=>x}]){}",
    "for(f in object){}",
    "for(var f of [x=>x]){}",
  ]) {
    const check = await scan({
      "entry.ts": "import {f} from './helper.js'; function route(req){db.query(f(req.query.sql));}",
      "helper.ts": `export function f(value){return 'fixed'}; ${write}`,
    });
    assert.equal(check.status, "partial", write);
    assert.equal(sql(check).length, 1, write);
    assert.equal(sql(check)[0].confidence, "low", write);
    assert.equal(sql(check)[0].staticFlow?.truncated, true, write);
  }
});

test("destructuring property keys and default expression reads do not mutate a safe export", async () => {
  const reads = [
    "let other; ({f:other}={f:1});",
    "let other; ([other=f]=[1]);",
    "let other; ({other=f}={other:1});",
    "let other; ({[f('unused')]:other}={'fixed':1});",
    "for(let other of [f]){}",
    "for({f:other} of [{f:1}]){}",
  ];
  for (const read of reads) {
    const check = await scan({
      "entry.ts": "import {f} from './helper.js'; function route(req){db.query(f(req.query.sql));}",
      "helper.ts": `export function f(value){return 'fixed'}; ${read}`,
    });
    assert.equal(check.status, "completed", read);
    assert.equal(sql(check).length, 0, read);
    assert.ok(Number(check.metrics?.resolvedCalls) > 0, read);
  }
});

test("destructuring writes invalidate immutable aliases and static CommonJS export targets", async () => {
  const check = await scan({
    "entry.js": "const {apply} = require('./helper'); function route(req){db.query(apply(req.query.sql));}",
    "helper.js": "function target(value){return 'fixed'} const alias=target; module.exports={apply:alias}; [target]=[x=>x];",
  });
  assert.equal(check.status, "partial");
  assert.equal(sql(check).length, 1);
  assert.equal(sql(check)[0].confidence, "low");
  assert.equal(sql(check)[0].staticFlow?.truncated, true);
  const safe = await scan({
    "entry.js": "const {apply} = require('./helper'); function route(req){db.query(apply(req.query.sql));}",
    "helper.js": "function target(value){return 'fixed'} const alias=target; module.exports={apply:alias}; let other; ({target:other}={target:1});",
  });
  assert.equal(safe.status, "completed");
  assert.equal(sql(safe).length, 0);
});
