import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runSource } from '../src/source.js';
import { createReport, toAgentReport, toMarkdown, toSarif } from '../src/report.js';

async function scan(code: string) {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-url-dev-'));
  try {
    await writeFile(join(root, 'app.ts'), code);
    const checks = await runSource({ root, tools: [] });
    const ast = checks.find((check) => check.id === 'source.builtin-ast')!;
    assert.equal(ast.status, 'completed');
    return { ast, checks };
  } finally { await rm(root, { recursive: true, force: true }); }
}
const outbound = (ast: Awaited<ReturnType<typeof scan>>['ast']) => ast.findings.filter((item) => item.ruleId === 'ast:server-request');
const params = `const p=new URLSearchParams({q:req.query.q});`;

test('fixed HTTP(S) destinations with encoded record query suppress only outbound candidates', async () => {
  for (const prefix of ['https://service.invalid/fixed?', 'http://service.invalid/fixed?', 'https://service.invalid:443/fixed?', 'http://service.invalid:80/fixed?']) {
    const { ast } = await scan(`function route(req){${params}fetch('${prefix}'+p.toString());}`);
    assert.equal(outbound(ast).length, 0);
    assert.equal(ast.metrics?.outboundFixedDestinationSuppressed, 1);
  }
  const { ast } = await scan('function route(req){'+params+'fetch(`https://service.invalid/fixed?${p.toString()}`); axios.get("https://service.invalid/fixed?"+p.toString(),{});}');
  assert.equal(outbound(ast).length, 0);
  assert.equal(ast.metrics?.outboundFixedDestinationSuppressed, 2);
});

test('append/set input preserves query encoding and evidence in other sink projections', async () => {
  const { ast, checks } = await scan(`function route(req){const p=new URLSearchParams({a:'fixed'});if(req.query.flag)p.append('q',req.query.q);p.set('other',req.body.other);const u='https://service.invalid/fixed?'+p.toString();fetch(u);db.query(u);exec(u);document.write(u);redirect(u);}`);
  assert.equal(outbound(ast).length, 0);
  for (const rule of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink','ast:open-redirect']) {
    const finding = ast.findings.find((item) => item.ruleId === rule);
    assert.ok(finding, rule);
    assert.ok(finding.staticFlow?.steps.some((item) => item.role === 'source'));
  }
  const report = createReport(checks, 'source', '2026-10-05T00:00:00.000Z');
  const agent = toAgentReport(report);
  assert.ok(agent.findings.every((finding) => !finding.verification.vulnerabilityConfirmed && !finding.verification.remediationVerified));
  assert.ok(JSON.stringify(toSarif(report)).includes('ast:sql-input-sink'));
  assert.ok(toMarkdown(report).includes('Request input reaches a dynamic SQL call'));
  assert.ok(!JSON.stringify(agent).includes('service.invalid'));
});

test('raw authority/path/query and malformed prefix retain source candidates', async () => {
  for (const value of ["'https://'+req.query.host+'/fixed'", "'https://service.invalid/'+req.query.path", "'https://service.invalid/fixed?'+req.query.q", "'https://user@service.invalid/fixed?'+p.toString()", "'https://service.invalid/fixed#?'+p.toString()", "'https://service.invalid/fixed?'+p.toString()+req.query.q", "'https://service.invalid\\\\evil/fixed?'+p.toString()", "'https://service.invalid/fixed?'+p.toString()+ '/raw'"]) {
    const { ast } = await scan(`function route(req){${params}fetch(${value});}`);
    assert.equal(outbound(ast).length, 1, value);
    assert.ok(outbound(ast)[0].staticFlow?.steps.some((item) => item.role === 'source'));
  }
});

test('shadowed globals, aliases, escapes and member mutation revoke native proof for all uses', async () => {
  for (const change of ['const alias=p;alias.toString();', 'external(p);', 'p.toString=()=>req.query.q;', 'const obj={p};', 'p.delete("q");', 'URLSearchParams.prototype.toString=()=>req.query.q;']) {
    const { ast } = await scan(`function route(req){${params}const u='https://service.invalid/fixed?'+p.toString();${change}fetch(u);fetch('https://service.invalid/fixed?'+p.toString());}`);
    assert.equal(outbound(ast).length, 2, change);
  }
  const shadow = await scan(`class URLSearchParams{constructor(x){}toString(){return 'opaque'}} function route(req){${params}fetch('https://service.invalid/fixed?'+p.toString());}`);
  assert.equal(outbound(shadow.ast).length, 1);
});

test('opaque options and URL object/base construction never claim fixed effective destination', async () => {
  for (const suffix of [',opts', ',getOptions(req)', ',{baseURL:req.query.host}', ',{allowAbsoluteUrls:false}', ',{url:req.query.url}']) {
    const { ast } = await scan(`function route(req){${params}axios.get('https://service.invalid/fixed?'+p.toString()${suffix});}`);
    assert.equal(outbound(ast).length, 1);
    assert.equal(ast.metrics?.outboundFixedDestinationSuppressed, 0);
  }
  const { ast } = await scan(`function route(req){fetch(new URL(req.query.url,'https://service.invalid/'));}`);
  assert.equal(outbound(ast).length, 1);
});

test('scalar helper cache and sink joins preserve unsafe contexts in either observation order', async () => {
  for (const reverse of [false, true]) {
    const calls = ["sink(carry('https://service.invalid/fixed?'+p.toString()))", "sink(carry(req.query.url))"];
    if (reverse) calls.reverse();
    const { ast } = await scan(`function carry(x){return x} function sink(x){fetch(x)} function route(req){${params}${calls.join(';')};}`);
    assert.equal(outbound(ast).length, 1);
    const source = outbound(ast)[0].staticFlow?.steps.find((item) => item.role === 'source');
    assert.ok(source);
    assert.equal(ast.metrics?.outboundFixedDestinationSuppressed, 0);
  }
  const branch = await scan(`function route(req){${params}const u=req.query.flag?'https://service.invalid/fixed?'+p.toString():req.query.url;fetch(u);}`);
  assert.equal(outbound(branch.ast).length, 1);
});

test('bounded shape metadata drops proof without dropping input evidence', async () => {
  const { ast } = await scan(`function route(req){${params}fetch('https://service.invalid/${'x'.repeat(2100)}?'+p.toString());}`);
  assert.equal(outbound(ast).length, 1);
  assert.ok(outbound(ast)[0].staticFlow?.steps.some((item) => item.role === 'source'));
});


test('mutable scalar containers retain candidates after nested aliases and external mutation', async () => {
  for (const body of ["const box={url:u};const alias=box;alias.url=req.query.url;fetch(box.url)", "const box=[u];const alias=box;alias[0]=req.query.url;fetch(box[0])", "const box={inner:{url:u}};external(box);fetch(box.inner.url)", "const box={url:u};fetch(box.url)"]) {
    const {ast}=await scan(`function route(req){${params}const u='https://service.invalid/fixed?'+p.toString();${body};}`);
    assert.equal(outbound(ast).length,1,body);
    assert.ok(outbound(ast)[0].staticFlow?.steps.some(step=>step.role==='source'));
  }
});

test('narrow literal method/headers options exclude authority and transport changes', async () => {
  for (const [options,count] of [["{method:'POST',headers:{'Content-Type':'text/plain'}}",0],["{headers:{Host:'other.invalid'}}",1],["{headers:{':authority':'other.invalid'}}",1],["{headers:{x:req.query.q}}",1],["{...opts}",1],["{get method(){return 'GET'}}",1],["{adapter:custom}",1]] as const) {
    const {ast}=await scan(`function route(req){${params}fetch('https://service.invalid/fixed?'+p.toString(),${options});}`);
    assert.equal(outbound(ast).length,count,options);
  }
  const {ast}=await scan(`globalThis['URLSearchParams'].prototype.toString=custom;function route(req){${params}fetch('https://service.invalid/fixed?'+p.toString());}`);
  assert.equal(outbound(ast).length,1);
});


test('fragment count cap and conditional destination alternatives stay conservative', async () => {
  const value = "'https://service.invalid/fixed?'" + "+p.toString()".repeat(17);
  const {ast}=await scan(`function route(req){${params}fetch(${value});}`);
  assert.equal(outbound(ast).length,1);
  const {ast: both}=await scan(`function route(req){${params}const u=req.query.flag?'https://one.invalid/fixed?'+p.toString():'https://two.invalid/fixed?'+p.toString();fetch(u);}`);
  assert.equal(outbound(both).length,1); // Different branch shapes are outside this equality-based join proof.
});


// Syntax categories disclosed after frozen URL-v1 independent measurement: known-case regressions.
test('fresh immediate native record serialization supports scalar/template/helper paths', async () => {
  for (const body of [
    "const q=new URLSearchParams({q:req.query.term}).toString();fetch('https://service.invalid/fixed?'+q)",
    "fetch(`https://service.invalid/fixed?${new URLSearchParams({q:req.query.term}).toString()}`)",
    "fetch('https://service.invalid/fixed?'+encode(req.query.term))",
  ]) {
    const {ast}=await scan(`function encode(term){return new URLSearchParams({q:term}).toString()}function route(req){${body};}`);
    assert.equal(outbound(ast).length,0,body);
    assert.equal(ast.metrics?.outboundFixedDestinationSuppressed,1,body);
  }
  for (const expression of ["'https://'+req.query.host+'/fixed?'+new URLSearchParams({q:req.query.term}).toString()", "'https://service.invalid/fixed?'+new URLSearchParams({q:req.query.term}).toString()+req.query.raw"]) {
    const {ast}=await scan(`function route(req){fetch(${expression});}`);
    assert.equal(outbound(ast).length,1,expression);
    assert.ok(outbound(ast)[0].staticFlow?.steps.some(step=>step.role==='source'));
  }
});

test('empty direct const params append/set transfers taint to every relevant sink', async () => {
  for (const mutation of ["p.append('q',req.query.term)","p.set('q',req.query.term)"]) {
    const {ast}=await scan(`function route(req){const p=new URLSearchParams();${mutation};const q=p.toString();fetch('https://service.invalid/fixed?'+q);db.query(q);exec(q);document.write(q);redirect(q);}`);
    assert.equal(outbound(ast).length,0);
    assert.equal(ast.metrics?.outboundFixedDestinationSuppressed,1);
    for (const rule of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink','ast:open-redirect']) {
      const finding=ast.findings.find(finding=>finding.ruleId===rule);
      assert.ok(finding,mutation+' '+rule);
      assert.ok(finding.staticFlow?.steps.some(step=>step.role==='source'));
    }
  }
  const clean=await scan(`function route(req){const p=new URLSearchParams();p.append('q','fixed');const q=p.toString();db.query(q);exec(q);document.write(q);}`);
  assert.equal(clean.ast.findings.filter(f=>['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink'].includes(f.ruleId)).length,0);
  const raw=await scan(`function route(req){const p=new URLSearchParams();p.append('q',req.query.term);fetch(req.query.host+p.toString());}`);
  assert.equal(outbound(raw.ast).length,1);
});

test('fresh immediate serialization keeps other sinks tainted and rejects custom natives', async () => {
  const {ast}=await scan(`function route(req){const q=new URLSearchParams({q:req.query.term}).toString();db.query(q);exec(q);document.write(q);}`);
  for(const rule of ['ast:sql-input-sink','ast:shell-input-sink','ast:html-input-sink']) assert.ok(ast.findings.some(f=>f.ruleId===rule));
  const {ast:shadow}=await scan(`class URLSearchParams{constructor(x){}toString(){return 'opaque'}}function route(req){fetch('https://service.invalid/fixed?'+new URLSearchParams({q:req.query.term}).toString());}`);
  assert.equal(outbound(shadow).length,1);
  const {ast:modified}=await scan(`URLSearchParams.prototype.toString=custom;function route(req){fetch('https://service.invalid/fixed?'+new URLSearchParams({q:req.query.term}).toString());}`);
  assert.equal(outbound(modified).length,1);
});


// Reviewer source-derived failure disclosed after URL-v2 freeze; known development regression.
test('empty params direct aliases before/after append preserve source and unsafe outbound candidates', async () => {
  for (const order of ["const alias=p;p.append('q',req.query.term)","p.append('q',req.query.term);const alias=p"]) {
    for (const target of ['p','alias']) {
      const {ast}=await scan(`function route(req){const p=new URLSearchParams();${order};const q=${target}.toString();db.query(q);fetch('https://service.invalid/fixed?'+q);}`);
      assert.equal(outbound(ast).length,1,order+' '+target);
      const finding=ast.findings.find(f=>f.ruleId==='ast:sql-input-sink');
      assert.ok(finding);
      assert.ok(finding.staticFlow?.steps.some(step=>step.role==='source'));
      assert.equal(ast.metrics?.outboundFixedDestinationSuppressed,0);
    }
  }
  const {ast}=await scan(`function route(req){const p=new URLSearchParams();const alias=p;alias.set('q',req.query.term);exec(p.toString());document.write(alias.toString());}`);
  assert.ok(ast.findings.some(f=>f.ruleId==='ast:shell-input-sink'));
  assert.ok(ast.findings.some(f=>f.ruleId==='ast:html-input-sink'));
});

test('alias-safe constants stay clean and earlier serialized scalar stays immutable', async () => {
  for (const code of ["const alias=p;p.append('q','fixed');db.query(alias.toString())", "p.append('q','fixed');const alias=p;db.query(p.toString())", "const q=p.toString();const alias=p;alias.append('q',req.query.term);db.query(q)"]) {
    const {ast}=await scan(`function route(req){const p=new URLSearchParams();${code};}`);
    assert.equal(ast.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,0,code);
  }
});

test('mutable query helper calls never reuse cached side effects or returned identities', async () => {
  const {ast}=await scan(`function append(p,x){p.append('q',x);return p}function make(x){const p=new URLSearchParams();p.append('q',x);return p}function route(req){const a=new URLSearchParams();const b=new URLSearchParams();append(a,req.query.term);append(b,req.query.term);db.query(a.toString());db.query(b.toString());db.query(make('fixed').toString());db.query(make(req.query.term).toString());}`);
  assert.equal(ast.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,3);
  const safe=await scan(`function make(x){const p=new URLSearchParams();p.append('q',x);return p}function route(req){db.query(make('fixed').toString())}`);
  assert.equal(safe.ast.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,0);
});

test('conservative branch content union keeps actual source and independent scan state', async () => {
  const code=`function route(req){const p=new URLSearchParams();const alias=p;if(req.query.flag)alias.append('q',req.query.term);else p.append('q','fixed');db.query(p.toString());}`;
  const risky=await scan(code);
  assert.equal(risky.ast.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,1);
  assert.ok(risky.ast.findings.find(f=>f.ruleId==='ast:sql-input-sink')?.staticFlow?.steps.some(step=>step.role==='source'));
  const safe=await scan(`function route(req){const p=new URLSearchParams();const alias=p;if(req.query.flag)alias.append('q','one');else p.append('q','two');db.query(p.toString());}`);
  assert.equal(safe.ast.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,0);
  const again=await scan(code);
  assert.deepEqual(again.ast.findings,risky.ast.findings);
});


// Reviewer source-derived UNKNOWN-to-SAFE failure disclosed after URL-v3 freeze.
test('opaque query content retains unknown helper fallback with constant-return safe pair', async () => {
  for (const [returned,count] of [['value',1],["'fixed'",0]] as const) {
    for(const serialization of ['const p=new URLSearchParams({q:read()});return p.toString()', 'return new URLSearchParams({q:read()}).toString()']) {
      const {ast}=await scan(`function pack(value){const read=()=>${returned};${serialization}}function route(req){db.query(pack(req.query.term));}`);
      const sql=ast.findings.filter(f=>f.ruleId==='ast:sql-input-sink');
      assert.equal(sql.length,count,returned+' '+serialization);
      if(count) {
        assert.equal(sql[0].confidence,'low');
        assert.equal(sql[0].staticFlow?.truncated,true);
        assert.ok(sql[0].staticFlow?.steps.some(step=>step.role==='source'));
        assert.equal(sql[0].kind,'candidate');
      }
    }
  }
  const safeActual=await scan(`function pack(value){const read=()=>value;const p=new URLSearchParams({q:read()});return p.toString()}function route(req){db.query(pack('fixed'));}`);
  assert.equal(safeActual.ast.findings.filter(f=>f.ruleId==='ast:sql-input-sink').length,0);
});
