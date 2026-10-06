import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, RULESET_VERSION } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';
const fixed = "'https://fixed.example/path'";
function snapshot(texts: Record<string, string>): SourceSnapshot {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  return { root: '/never-read', files, issues: [], ignoredFiles: 0, totalBytes: files.reduce((n, f) => n + f.bytes, 0), complete: true };
}
const run = (text: string, more: Record<string,string> = {}) => runBuiltinAst(snapshot({ 'app.ts': text, ...more }), false);
const outbound = (check: ReturnType<typeof run>) => check.findings.filter(f => f.ruleId === 'ast:server-request');
const prefix = "import client from 'axios';";

test('bound ESM aliases/default-as and CJS request config distinguish URL input from payload input', () => {
  for (const [path, declaration] of [['app.ts',prefix],['app.ts',"import {default as client} from 'axios';"],['app.js',"const client=require('axios');"]]) {
    for (const local of [false,true]) {
      const call = local ? 'const config=VALUE;client.request(config)' : 'client.request(VALUE)';
      const safe = runBuiltinAst(snapshot({[path]: declaration+`function route(req){${call.replace('VALUE',`{url:${fixed},data:req.body,method:'POST',headers:{Accept:'application/json'}}`)}}`}),false);
      const risky = runBuiltinAst(snapshot({[path]: declaration+`function route(req){${call.replace('VALUE',"{data:'fixed',url:req.query.url}")}}`}),false);
      assert.equal(safe.status,'completed');assert.equal(outbound(safe).length,0);assert.equal(safe.metrics?.outboundPayloadOnlyExcluded,1);
      assert.equal(risky.status,'completed');assert.equal(outbound(risky).length,1);assert.equal(outbound(risky)[0].confidence,'medium');assert.match(outbound(risky)[0].title,/destination field/);
      assert.equal(risky.metrics?.outboundTargetInputUses,1);assert.equal(safe.metrics?.outboundRoleBoundUses,1);
    }
  }
});

test('normal no-input bound calls are inventoried but never credited as excluded input findings',()=>{
  const result=run(prefix+`client.request({url:${fixed},data:'fixed'})`);
  assert.equal(outbound(result).length,0);assert.equal(result.metrics?.outboundRoleBoundUses,1);
  assert.equal(result.metrics?.outboundPayloadOnlyExcluded,0);assert.equal(result.metrics?.outboundTargetInputUses,0);assert.equal(result.metrics?.outboundRoleUnknownUses,0);
});

test('opaque config roles and legacy name-only API preserve low unverified config evidence',()=>{
  for(const text of [prefix+'function route(req){client.request(req.body)}',prefix+'function route(req){client.request({url:opaque(),data:req.body})}',`function route(req){axios.request({url:${fixed},data:req.body})}`]){
    const result=run(text);const found=outbound(result);assert.equal(found.length,1);assert.equal(found[0].confidence,'low');
    assert.match(found[0].title,/configuration/);assert.match(found[0].description,/unresolved/);assert.equal(found[0].staticFlow?.truncated,true);
    assert.equal(result.metrics?.outboundRoleUnknownUses,1);
  }
});

test('URL-specific trace comes from URL input even when body input is evaluated first',()=>{
  const text=prefix+'function route(req){client.request({data:req.body,url:req.query.target})}';
  const result=run(text);const found=outbound(result)[0];assert.ok(found.staticFlow);
  const source=found.staticFlow.steps.find(s=>s.role==='source')!;
  assert.equal(source.location.column,text.indexOf('req.query.target')+1);
  assert.notEqual(source.location.column,text.indexOf('req.body')+1);
});

test('construction-time target snapshot survives later scalar reassignment in both directions',()=>{
  const safe=run(prefix+`function route(req){let url=${fixed};const config={url:url,data:req.body};url=req.query.url;client.request(config)}`);
  const risky=run(prefix+`function route(req){let url=req.query.url;const config={url:url,data:req.body};url=${fixed};client.request(config)}`);
  assert.equal(outbound(safe).length,0);assert.equal(safe.metrics?.outboundPayloadOnlyExcluded,1);
  assert.equal(outbound(risky).length,1);assert.equal(outbound(risky)[0].confidence,'medium');
});

test('shorthand URL and data preserve lexical construction-time values and URL source trace',()=>{
  for(const direct of [false,true]){
    const call=direct?'client.request({url,data})':'const config={url,data};REASSIGN;client.request(config)';
    const safe=run(prefix+`function route(req){let url=${fixed};const data=req.body;${call.replace('REASSIGN','url=req.query.url')}}`);
    const riskyText=prefix+`function route(req){let url=req.query.url;const data=req.body;${call.replace('REASSIGN',`url=${fixed}`)}}`;
    const risky=run(riskyText);assert.equal(outbound(safe).length,0);assert.equal(safe.metrics?.outboundPayloadOnlyExcluded,1);
    assert.equal(outbound(risky).length,1);assert.equal(outbound(risky)[0].confidence,'medium');
    assert.equal(outbound(risky)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.column,riskyText.indexOf('req.query.url')+1);
  }
  const duplicate=run(prefix+`function route(req){const url=${fixed};const data=req.body;client.request({url,url:req.query.url,data})}`);
  assert.equal(outbound(duplicate).length,1);assert.equal(outbound(duplicate)[0].confidence,'low');
});

test('general captured shorthand keeps the pre-existing request-shaped fallback outside HTTP roles',()=>{
  const result=run('function route(req){function captured(){const x={req};db.query(x.req.query.term);exec(x.req.query.term);element.innerHTML=x.req.query.term}captured()}');
  for(const id of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink'])assert.ok(result.findings.some(f=>f.ruleId===id),id);
  assert.equal(result.metrics?.outboundRoleBoundUses,0);
});

test('scalar local and relative-module wrappers retain target/body roles across contexts and call order',()=>{
  for(const reverse of [false,true]){
    const calls=[`send(${fixed},req.body)`,`send(req.query.url,'fixed')`];if(reverse)calls.reverse();
    const helper="import api from 'axios';export function send(url,payload){api.request({url:url,data:payload})}";
    const result=run(`import {send} from './helper';function route(req){${calls.join(';')}}`,{'helper.ts':helper});
    const found=outbound(result);assert.equal(found.length,1);assert.equal(found[0].confidence,'medium');assert.equal(found[0].location.path,'helper.ts');
    assert.ok(found[0].staticFlow?.steps.some(s=>s.role==='source'&&s.location.path==='app.ts'));
    assert.equal(result.metrics?.outboundTargetInputUses,1);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,0);
  }
});

test('exported helper no-input root contributes inventory without replacing actual payload-only context',()=>{
  for(const helperFirst of [false,true]){
    const entry="import {send} from './helper.js';export function endpoint(req){send('https://fixed.example/path',req.body)}";
    const helper="import client from 'axios';export function send(destination,payload){client.request({url:destination,data:payload,method:'POST'})}";
    const result=runBuiltinAst(snapshot(helperFirst?{'helper.ts':helper,'entry.ts':entry}:{'entry.ts':entry,'helper.ts':helper}),false);
    assert.equal(result.status,'completed');assert.equal(outbound(result).length,0);
    assert.equal(result.metrics?.outboundRoleBoundUses,1);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,1);
    assert.equal(result.metrics?.outboundRoleUnknownUses,0);
    assert.equal(result.metrics?.externalEntryFunctions,2);assert.equal(result.metrics?.entryRootsStarted,2);
    assert.equal(result.metrics?.functionContextsStarted,3);assert.equal(result.metrics?.resolvedCalls,1);assert.equal(result.metrics?.summaryWork,1);
  }
});

test('exported no-input root cannot replace actual URL trace in either actual-call order',()=>{
  for(const reverse of [false,true]){
    const calls=[`send(${fixed},req.body)`,'send(req.query.target,req.body)'];if(reverse)calls.reverse();
    const entry=`import {send} from './helper.js';export function endpoint(req){${calls.join(';')}}`;
    const helper="import client from 'axios';export function send(destination,payload){client.request({data:payload,url:destination})}";
    const result=runBuiltinAst(snapshot({'entry.ts':entry,'helper.ts':helper}),false);const found=outbound(result);
    assert.equal(found.length,1);assert.equal(found[0].confidence,'medium');assert.match(found[0].title,/destination field/);
    const source=found[0].staticFlow?.steps.find(s=>s.role==='source');assert.equal(source?.location.path,'entry.ts');
    assert.equal(source?.location.column,entry.indexOf('req.query.target')+1);
    assert.equal(result.metrics?.outboundTargetInputUses,1);assert.equal(result.metrics?.outboundRoleUnknownUses,0);
    assert.equal(result.metrics?.entryRootsStarted,2);assert.equal(result.metrics?.functionContextsStarted,4);assert.equal(result.metrics?.resolvedCalls,2);
  }
});

test('genuine input-related unknown context still vetoes payload-only exclusion in both orders',()=>{
  for(const reverse of [false,true]){
    const calls=[`send(${fixed},req.body)`,'send(opaque(),unknownHelper(req.body))'];if(reverse)calls.reverse();
    const entry=`import {send} from './helper.js';export function endpoint(req){${calls.join(';')}}`;
    const helper="import client from 'axios';export function send(destination,payload){client.request({url:destination,data:payload})}";
    const result=runBuiltinAst(snapshot({'entry.ts':entry,'helper.ts':helper}),false);const found=outbound(result);
    assert.equal(found.length,1);assert.equal(found[0].confidence,'low');assert.match(found[0].title,/configuration/);
    assert.equal(found[0].staticFlow?.truncated,true);assert.ok(found[0].staticFlow?.steps.some(s=>s.role==='source'&&s.location.path==='entry.ts'));
    assert.equal(result.metrics?.outboundRoleUnknownUses,1);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,0);
    assert.equal(result.metrics?.entryRootsStarted,2);assert.equal(result.metrics?.functionContextsStarted,4);assert.equal(result.metrics?.resolvedCalls,2);
  }
});

test('unknown context veto is conservative in branches and helper contexts',()=>{
  for(const reverse of [false,true]){
    const calls=[`send(${fixed},req.body)`,`send(opaque(),req.body)`];if(reverse)calls.reverse();
    const result=run(prefix+`function send(url,payload){client.request({url:url,data:payload})}function route(req){${calls.join(';')}}`);
    assert.equal(outbound(result).length,1);assert.equal(outbound(result)[0].confidence,'low');assert.equal(outbound(result)[0].staticFlow?.truncated,true);
  }
  const result=run(prefix+`function route(req){const config={url:flag?${fixed}:req.query.url,data:req.body};client.request(config)}`);
  assert.equal(outbound(result).length,1);
});

test('config aliases/mutations/containers/spreads/escapes never remove observed input',()=>{
  const cases=[
    `const config={url:${fixed},data:req.body};const alias=config;alias.url=req.query.url;client.request(config)`,
    `const config={url:${fixed},data:req.body};config.url=req.query.url;client.request(config)`,
    `const config={url:${fixed},data:req.body};const box={config};client.request(box.config)`,
    `const config={url:${fixed},data:req.body};external(config);client.request(config)`,
    `client.request({url:${fixed},data:req.body,...req.query})`,
    `client.request({get url(){return ${fixed}},data:req.body})`,
    `const config={url:${fixed},data:req.body};return helper(config)`,
  ];
  for(const body of cases.slice(0,6)) {const result=run(prefix+`function route(req){${body}}`);assert.equal(outbound(result).length,1,body);assert.equal(outbound(result)[0].confidence,'low',body);}
  const escaped=run(prefix+`function helper(c){client.request(c)}function route(req){${cases[6]}}`);
  assert.equal(outbound(escaped).length,1);assert.equal(outbound(escaped)[0].confidence,'low');
});

test('cross-file customization/defaults/interceptors and unsupported transport revoke family qualification',()=>{
  for(const customization of ["import changed from 'axios';changed.defaults.baseURL='https://other.example/';","const changed=require('axios');changed.interceptors.request.use(fn);","import changed from 'axios';changed['request']=other;","import * as changed from 'axios';changed.default.request(other)"]){
    const result=run(prefix+`function route(req){client.request({url:${fixed},data:req.body})}`,{'setup.js':customization});
    assert.equal(outbound(result).length,1,customization);assert.equal(outbound(result)[0].confidence,'low');
  }
  for(const option of ["baseURL:'https://base.example/'","allowAbsoluteUrls:false","socketPath:'/private/socket'","adapter:custom","proxy:req.body.proxy","params:req.query","headers:{Host:'other.example'}"]){
    const result=run(prefix+`function route(req){client.request({url:${fixed},data:req.body,${option}})}`);
    assert.equal(outbound(result).length,1,option);assert.equal(outbound(result)[0].confidence,'low');
  }
});

test('unsupported exact-package loads veto qualification without introducing new API coverage',()=>{
  for(const load of [
    "require('axios').defaults.adapter=custom;",
    "const changed=require('axios').default;changed.defaults.baseURL='https://other.example/';",
    "import changed=require('axios');changed.defaults.adapter=custom;",
    "const changed=import('axios');",
    "const changed=import('axios',{with:{type:'custom'}});",
    "require('axios',extra).defaults.adapter=custom;",
    "(require)('axios').defaults.adapter=custom;",
    "require(('axios')).defaults.adapter=custom;",
    "(require as any)(('axios' as string)).defaults.adapter=custom;",
    "require!('axios').defaults.adapter=custom;",
    "export {default as changed} from 'axios';",
  ]) {
    const result=run(prefix+`function route(req){client.request({url:${fixed},data:req.body})}`,{'setup.ts':load});
    assert.equal(result.status,'completed',load);assert.equal(outbound(result).length,1,load);
    assert.equal(outbound(result)[0].confidence,'low',load);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,0,load);
  }
  const normal=run(prefix+`function route(req){client.request({url:${fixed},data:req.body})}`,{'setup.ts':"const unrelated=import('other-package');"});
  assert.equal(outbound(normal).length,0);assert.equal(normal.metrics?.outboundPayloadOnlyExcluded,1);
});

test('lexical shadows are not new alias coverage, and require shadow never grants payload qualification',()=>{
  const shadow=run(prefix+`function route(req,client){client.request({url:${fixed},data:req.body})}`);
  assert.equal(outbound(shadow).length,0);assert.equal(shadow.metrics?.outboundRoleBoundUses,0);
  const shadowRequire=run(`const require=x=>other;const axios=require('axios');function route(req){axios.request({url:${fixed},data:req.body})}`);
  assert.equal(outbound(shadowRequire).length,1);assert.equal(outbound(shadowRequire)[0].confidence,'low');assert.equal(shadowRequire.metrics?.outboundRoleBoundUses,0);
});

test('CJS script-global merging cannot authenticate another file same-name receiver',()=>{
  for(const extension of ['js','ts']){
    const result=runBuiltinAst(snapshot({
      ['api.'+extension]:`const client=require('axios');function first(req){client.request({url:${fixed},data:req.body})}`,
      ['other.'+extension]:`const client={request:other};function second(req){client.request({url:req.query.url,data:req.body})}`,
    }),false);
    // JS's CommonJS binder isolates these files already; TS script binding can
    // resolve the second receiver to the first declaration. Neither grants
    // new API coverage in the non-package file.
    assert.equal(outbound(result).length,0,extension);
    assert.equal(result.metrics?.outboundRoleBoundUses,1,extension);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,1,extension);
  }
  const isolated=runBuiltinAst(snapshot({'api.js':`const client=require('axios');function route(req){client.request({url:${fixed},data:req.body})}`}),false);
  assert.equal(outbound(isolated).length,0);assert.equal(isolated.metrics?.outboundPayloadOnlyExcluded,1);
});

test('parse/sensitive/collection scope and reduced index/flow budgets never grant payload-only proof',()=>{
  const text=prefix+`function route(req){client.request({url:${fixed},data:req.body})}`;
  for(const mode of ['parse','sensitive','collection']){
    const input=snapshot({'app.ts':text,...(mode==='parse'?{'broken.ts':'function {'}:mode==='sensitive'?{'secret.ts':'private_source'}:{})});
    if(mode==='sensitive')input.files[1].sensitive=true;if(mode==='collection')input.complete=false;
    const result=runBuiltinAst(input,false);assert.equal(result.metrics?.roleProofScopeComplete,false);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,0);
    assert.equal(outbound(result).length,1);assert.equal(outbound(result)[0].confidence,'low');
  }
  for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1}]){
    const result=runBuiltinAst(snapshot({'app.ts':text}),false,limits);assert.equal(result.status,'partial');assert.equal(result.metrics?.outboundPayloadOnlyExcluded,0);
    assert.equal(evaluateGate(createReport([result],'source','2026-10-05T00:00:00.000Z'),'none').exitCode,2);
  }
});

test('payload role never sanitizes SQL/shell/HTML and public projections retain unverified semantics',()=>{
  const text=prefix+`function route(req){const payload=req.body;client.request({url:${fixed},data:payload});db.query(payload);exec(payload);element.innerHTML=payload}`;
  const result=run(text);assert.equal(outbound(result).length,0);
  for(const id of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink'])assert.ok(result.findings.some(f=>f.ruleId===id),id);
  const report=createReport([result],'source','2026-10-05T00:00:00.000Z');const agent=toAgentReport(report,'high');
  assert.equal(RULESET_VERSION,'2026-10-06.2');assert.equal(agent.scanGate.exitCode,1);
  assert.ok(agent.findings.every(f=>f.verification.state==='not_run'&&!f.verification.vulnerabilityConfirmed));
  for(const output of [JSON.stringify(report),JSON.stringify(agent),JSON.stringify(toSarif(report)),toMarkdown(report)])assert.equal(output.includes('https://fixed.example/path'),false);
  const safe=run(prefix+`function route(req){client.request({url:${fixed},data:req.body})}`);
  assert.equal(evaluateGate(createReport([safe],'source','2026-10-05T00:00:00.000Z'),'high').exitCode,0);
});

test('repeated scans and opaque helper input never reuse a safe role result',()=>{
  const safe=prefix+`function route(req){client.request({url:${fixed},data:req.body})}`;
  const risky=prefix+'function route(req){client.request({url:req.query.url,data:req.body})}';
  for(const text of [safe,risky,safe,risky])assert.equal(outbound(run(text)).length,text===safe?0:1);
  const opaque=run(prefix+'function pass(value){const captured=()=>value;return captured()}function route(req){client.request({url:pass(req.query.url),data:req.body})}');
  assert.equal(outbound(opaque).length,1);assert.equal(outbound(opaque)[0].confidence,'low');
});
