import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, RULESET_VERSION } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function snapshot(texts: Record<string, string>): SourceSnapshot {
  const files = Object.entries(texts).map(([path,text]) => ({path,text,bytes:Buffer.byteLength(text),category:'code' as const,sensitive:false}));
  return {root:'/never-execute',files,issues:[],complete:true,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)};
}
const prefix = "import client from 'axios';";
const encoded = "const p=new URLSearchParams({q:req.query.term});const query=p.toString();";
const fixed = "'https://fixed.example/path?'";
const run = (text:string,more:Record<string,string>={}) => runBuiltinAst(snapshot({'app.ts':text,...more}),false);
const outbound = (check:ReturnType<typeof run>) => check.findings.filter(f=>f.ruleId==='ast:server-request');
function excluded(text:string,more:Record<string,string>={}) {
  const result=run(text,more);assert.equal(result.status,'completed');assert.equal(outbound(result).length,0);
  assert.equal(result.metrics?.outboundEncodedQueryExcluded,1);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,0);return result;
}
function candidate(text:string, unknown=false) {
  const result=run(text);assert.equal(result.status,'completed');assert.equal(outbound(result).length,1);
  assert.equal(result.metrics?.outboundEncodedQueryExcluded,0);
  if(unknown){assert.equal(outbound(result)[0].confidence,'low');assert.match(outbound(result)[0].title,/configuration/);assert.equal(outbound(result)[0].staticFlow?.truncated,true);}
  return result;
}

test('bound JS/TS config excludes encoded initial URL field even with body input',()=>{
  for(const [path,head] of [['app.js',"const client=require('axios');"],['app.ts',prefix]]) for(const shorthand of [true,false]) {
    const text=head+`function route(req){${encoded}const url=${fixed}+query;client.request(${shorthand?'{url,data:req.body}':'{data:req.body,url:url,method:"POST",headers:{Accept:"application/json"}}'})}`;
    const result=runBuiltinAst(snapshot({[path]:text}),false);assert.equal(result.status,'completed');assert.equal(outbound(result).length,0);assert.equal(result.metrics?.outboundEncodedQueryExcluded,1);assert.equal(result.metrics?.outboundRoleBoundUses,1);
  }
});

test('request URL source remains actual authority/path/raw suffix rather than body or query',()=>{
  for(const url of ['req.query.url+query',"'https://'+req.query.host+'/path?'+query",fixed+'+query+req.query.tail']) {
    const text=prefix+`function route(req){${encoded}const url=${url};client.request({data:req.body,url})}`;
    const result=candidate(text);assert.equal(outbound(result)[0].confidence,'medium');assert.match(outbound(result)[0].title,/destination field/);
    const source=outbound(result)[0].staticFlow?.steps.find(s=>s.role==='source');assert.ok(source);
    assert.notEqual(source.location.column,text.indexOf('req.body')+1);assert.equal(result.metrics?.outboundTargetInputUses,1);
  }
});

test('exact-shape value joins retain proof; different URL alternatives do not gain a union proof',()=>{
  excluded(prefix+`function route(req){${encoded}const url=req.query.mode?${fixed}+query:${fixed}+query;client.request({url,data:req.body})}`);
  for(const expression of [`req.query.mode?${fixed}+query:'https://other.example/path?'+query`,`req.query.mode?'https://other.example/path?'+query:${fixed}+query`]) {
    candidate(prefix+`function route(req){${encoded}const url=${expression};client.request({url,data:req.body})}`);
  }
});

test('ordinary local/relative scalar actual-return preserves encoded URL and construction snapshot',()=>{
  excluded(prefix+`function pass(x){return x}function route(req){${encoded}let url=pass(${fixed}+query);const config={url,data:req.body};url=req.query.url;client.request(config)}`);
  excluded(prefix+`import {pass} from './helper';function route(req){${encoded}const url=pass(${fixed}+query);client.request({url,data:req.body})}`,{'helper.ts':'export function pass(x){return x}'});
  candidate(prefix+`function route(req){${encoded}let url=req.query.url;const config={url,data:req.body};url=${fixed}+query;client.request(config)}`);
});

test('per-sink contexts rank target then unknown then encoded then payload in either order',()=>{
  const declarations=prefix+`function send(url,data){client.request({url,data})}`;
  for(const reverse of [false,true]) {
    const safeCalls=[`send(${fixed}+query,req.body)`,`send('https://fixed.example/path',req.body)`];
    excluded(declarations+`function route(req){${encoded}${(reverse?safeCalls.reverse():safeCalls).join(';')}}`);
    for(const bad of ['req.query.url','opaque()']) {
      const calls=[`send(${fixed}+query,req.body)`,`send(${bad},req.body)`];
      const text=declarations+`function route(req){${encoded}${(reverse?calls.reverse():calls).join(';')}}`;
      const result=candidate(text,bad==='opaque()');
      if(bad!=='opaque()') assert.equal(outbound(result)[0].staticFlow?.steps.find(s=>s.role==='source')?.location.column,text.indexOf('req.query.url')+1);
    }
  }
});

test('exported no-input root cannot overwrite known encoded caller; no-input is inventory only',()=>{
  excluded(prefix+`export function send(url,data){client.request({url,data})}function route(req){${encoded}send(${fixed}+query,req.body)}`);
  const result=run(prefix+`function route(){const p=new URLSearchParams({q:'fixed'});const url=${fixed}+p.toString();client.request({url})}`);
  assert.equal(outbound(result).length,0);assert.equal(result.metrics?.outboundRoleBoundUses,1);assert.equal(result.metrics?.outboundEncodedQueryExcluded,0);
});

test('async/generator call-return and await remain HTTP unavailable, while direct scalar behavior stays unchanged',()=>{
  for(const declaration of ['async function pass(x){return x}','function* pass(x){return x}','async function* pass(x){return x}']) for(const awaitCall of [false,true]) {
    const text=prefix+declaration+`async function route(req){${encoded}const url=${awaitCall?'await ':''}pass(${fixed}+query);client.request({url,data:req.body});fetch(url)}`;
    const result=candidate(text,true);assert.equal(result.metrics?.outboundQueryQualifiedUses,1);
  }
  excluded(prefix+`async function send(url,data){client.request({url,data})}function route(req){${encoded}send(${fixed}+query,req.body)}`);
});

test('wrapper/cell invalidation survives constructor, append/set and immutable toString snapshot',()=>{
  for(const change of ["const p=new URLSearchParams({q:bad});","const p=new URLSearchParams();p.append('q',bad);","const p=new URLSearchParams();p.set('q',bad);"]) {
    const text=prefix+`async function pass(x){return x}function route(req){const bad=pass(req.query.term);${change}const url=${fixed}+p.toString();client.request({url,data:req.body});fetch(url)}`;
    const result=candidate(text,true);assert.equal(result.metrics?.outboundQueryQualifiedUses,1);
  }
  excluded(prefix+`async function pass(x){return x}function route(req){const p=new URLSearchParams({q:req.query.term});const url=${fixed}+p.toString();p.append('q',pass(req.query.other));client.request({url,data:req.body})}`);
});

test('negative marker survives resolved UNKNOWN and receiver/argument opaque fallback before new serialization',()=>{
  for(const opaque of ['read(bad)','bad.opaque()','opaque(bad)',"pass('fixed').opaque(req.query.term)"]) {
    const text=prefix+`async function pass(x){return x}function read(x){return captured}function route(req){const bad=pass(req.query.term);const value=${opaque};const p=new URLSearchParams({q:value});const url=${fixed}+p.toString();client.request({url,data:req.body})}`;
    candidate(text,true);
  }
});

test('container and static/dynamic projection cannot forget invalidation and requalify native content',()=>{
  for(const projection of ['box.value','box["value"]','box[req.query.key]','array[0]']) {
    candidate(prefix+`async function pass(x){return x}function route(req){const bad=pass(req.query.term);const box={value:bad};const array=[bad];const p=new URLSearchParams({q:${projection}});const url=${fixed}+p.toString();client.request({url,data:req.body})}`,true);
  }
});

test('body invalidation never contaminates a separately captured known URL',()=>{
  excluded(prefix+`async function pass(x){return x}function route(req){${encoded}const url=${fixed}+query;const data=pass(req.body);client.request({data,url})}`);
  const result=run(prefix+`async function pass(x){return x}function route(req){const data=pass(req.body);client.request({url:'https://fixed.example/path',data})}`);
  assert.equal(outbound(result).length,0);assert.equal(result.metrics?.outboundPayloadOnlyExcluded,1);
});

test('negative scalar joins/concat/member writes cannot restore HTTP proof with identical URL fragments',()=>{
  for(const expression of ['req.query.mode?good:bad','req.query.mode?bad:good',"bad+''",'`${bad}`']) {
    candidate(prefix+`async function pass(x){return x}function route(req){${encoded}const good=${fixed}+query;const bad=pass(good);const url=${expression};client.request({url,data:req.body})}`,true);
  }
  candidate(prefix+`async function pass(x){return x}function route(req){const box={};box.value=pass(req.query.term);const p=new URLSearchParams({q:box.value});const url=${fixed}+p.toString();client.request({url,data:req.body})}`,true);
});

test('cache distinguishes safe content from unavailable same-kind content in either order and across scans',()=>{
  for(const reverse of [false,true]) {
    const declarations=prefix+`async function opaque(){return 'fixed'}function encode(value){const p=new URLSearchParams({q:value});return p.toString()}function send(url,data){client.request({url,data})}`;
    const calls=[`send(${fixed}+encode('fixed'),req.body)`,`send(${fixed}+encode(opaque()),req.body)`];
    const text=declarations+`function route(req){${(reverse?calls.reverse():calls).join(';')}}`;
    candidate(text,true);
    excluded(prefix+`function encode(value){const p=new URLSearchParams({q:value});return p.toString()}function route(req){const url=${fixed}+encode('fixed');client.request({url,data:req.body})}`);
  }
});

test('native identity, scope, options and config inline effects retain candidates',()=>{
  for(const extra of ["const alias=p;","unknown(p);","URLSearchParams.prototype.toString=custom;"]) {
    const result=run(prefix+`function route(req){${encoded}${extra}const url=${fixed}+p.toString();client.request({url,data:req.body})}`);assert.equal(outbound(result).length,1);assert.equal(result.metrics?.outboundEncodedQueryExcluded,0);
  }
  for(const config of [`{url:${fixed}+new URLSearchParams({q:req.query.term}).toString(),data:req.body}`,`{url,data:req.body,baseURL:'https://other.example'}`,`{url,data:req.body,adapter:custom}`]) {
    candidate(prefix+`function route(req){${encoded}const url=${fixed}+query;client.request(${config})}`,true);
  }
  const text=prefix+`function route(req){${encoded}const url=${fixed}+query;client.request({url,data:req.body})}`;
  const scope=snapshot({'app.ts':text});scope.complete=false;
  const result=runBuiltinAst(scope,false);assert.equal(outbound(result).length,1);assert.equal(result.metrics?.outboundEncodedQueryExcluded,0);
});

test('query encoding leaves SQL/shell/HTML/redirect and direct URL model evidence intact',()=>{
  const text=prefix+`function route(req,res){${encoded}const url=${fixed}+query;client.request({url,data:req.body});fetch(url);db.query(url);exec(url);element.innerHTML=url;res.redirect(url)}`;
  const result=excluded(text);assert.equal(result.metrics?.outboundQueryQualifiedUses,1);
  for(const rule of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink','ast:open-redirect']) {
    const found=result.findings.find(f=>f.ruleId===rule);assert.ok(found,rule);assert.ok(found.staticFlow?.steps.some(s=>s.role==='source'),rule);
  }
});

test('shape bounds and flow/index budgets never become qualification success',()=>{
  const prefixLong="'https://fixed.example/"+'x'.repeat(2048)+"?'";
  candidate(prefix+`function route(req){${encoded}const url=${prefixLong}+query;client.request({url,data:req.body})}`);
  const many=[fixed,...Array(17).fill('query')].join('+');candidate(prefix+`function route(req){${encoded}const url=${many};client.request({url,data:req.body})}`);
  const text=prefix+`function route(req){${encoded}const url=${fixed}+query;client.request({url,data:req.body})}`;
  for(const limits of [{...FLOW_LIMITS,indexWork:1},{...FLOW_LIMITS,flowWork:1}]) {
    const result=runBuiltinAst(snapshot({'app.ts':text}),false,limits);assert.equal(result.status,'partial');assert.equal(result.metrics?.outboundEncodedQueryExcluded,0);
    const report=createReport([result],'source','2026-10-05T00:00:00.000Z');assert.equal(evaluateGate(report,'none').exitCode,2);
  }
});

test('new check metric and residual actual trace project through four sanitized reports with unchanged verification',()=>{
  const text=prefix+`function route(req){${encoded}const url=${fixed}+query;client.request({url,data:req.body});client.request({data:req.body,url:req.query.host})}`;
  const check=run(text);assert.equal(outbound(check).length,1);
  const report=createReport([check],'source','2026-10-05T00:00:00.000Z');
  const agent=toAgentReport(report,'high'),sarif=toSarif(report),md=toMarkdown(report);
  assert.equal(RULESET_VERSION,'2026-10-06.2');assert.equal(evaluateGate(report,'high').exitCode,1);assert.equal(agent.scanGate.exitCode,1);
  assert.equal(agent.findings[0].verification.vulnerabilityConfirmed,false);assert.equal(agent.findings[0].verification.state,'not_run');
  for(const output of [JSON.stringify(report),JSON.stringify(sarif),md,JSON.stringify(agent)]) {
    assert.ok(!output.includes('fixed.example'));assert.ok(!output.includes('req.query.host'));
  }
  assert.equal(check.metrics?.outboundRoleModel,'axios-request-config-query-v2');assert.equal(check.metrics?.outboundEncodedQueryExcluded,1);
});

test('append/set retains constructor input trace priority for ordinary sinks and direct URL qualification',()=>{
  for(const method of ['append','set']) {
    const text=`function route(req){const p=new URLSearchParams({q:req.query.first});p.${method}('next',req.query.second);const value=p.toString();db.query(value);exec(value);element.innerHTML=value;fetch('https://fixed.example/path?'+value)}`;
    const result=run(text);assert.equal(result.status,'completed');assert.equal(outbound(result).length,0);
    assert.equal(result.metrics?.outboundQueryQualifiedUses,1);
    for(const rule of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink']) {
      const found=result.findings.find(f=>f.ruleId===rule);assert.ok(found,rule);
      const source=found.staticFlow?.steps.find(s=>s.role==='source');assert.ok(source,rule);
      assert.equal(source.location.column,text.indexOf('req.query.first')+1,method+':'+rule);
    }
    const normal=run(`function route(){const p=new URLSearchParams({q:'first'});p.${method}('next','second');db.query(p.toString());exec(p.toString());element.innerHTML=p.toString()}`);
    assert.equal(normal.status,'completed');assert.equal(normal.findings.length,0);
  }
});

test('append/set ORs HTTP negative proof from existing content and new arguments without changing scalar taint',()=>{
  for(const method of ['append','set']) for(const unavailableFirst of [true,false]) {
    const initial=unavailableFirst?'opaque':'req.query.first', added=unavailableFirst?'req.query.second':'opaque';
    const text=prefix+`async function pass(x){return x}function route(req){const opaque=pass(req.query.opaque);const p=new URLSearchParams({q:${initial}});p.${method}('next',${added});const scalar=p.toString();const url=${fixed}+scalar;client.request({url,data:req.body});db.query(scalar);exec(scalar);element.innerHTML=scalar;fetch(url)}`;
    const result=candidate(text,true);assert.equal(result.metrics?.outboundQueryQualifiedUses,1);
    for(const rule of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink']) {
      const found=result.findings.find(f=>f.ruleId===rule);assert.ok(found,rule);
      assert.ok(found.staticFlow?.steps.some(s=>s.role==='source'),rule);
    }
  }
});
