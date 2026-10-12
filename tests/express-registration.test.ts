import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { createReport, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';
import * as ts from 'typescript';
import { findSnapshotInputFlows } from '../src/source/dataflow.js';
import { FLOW_LIMITS } from '../src/source/modules.js';

function scan(text: string) {
  const snapshot: SourceSnapshot = { root: '/never-executed', files: [{ path: 'route.ts', text,
    bytes: Buffer.byteLength(text), category: 'code', sensitive: false }], issues: [], complete: true,
    ignoredFiles: 0, totalBytes: Buffer.byteLength(text) };
  return runBuiltinAst(snapshot, false);
}
const html = (text: string) => scan(text).findings.filter(f => f.ruleId === 'ast:html-input-sink');
const prefix = "import express from 'express';const router=express.Router();";
const handler = '(incoming,outgoing)=>outgoing.send(incoming.query.syntheticRegistrationMarker)';

test('registered Express callback positions recognize renamed ESM and CommonJS inputs', () => {
  for (const setup of [prefix,
    "import createServer from 'express';const router=createServer();",
    "import {default as createServer} from 'express';const router=createServer();",
    "import {Router as createRouter} from 'express';const router=createRouter();",
    "import * as framework from 'express';const router=framework.Router();",
    "const framework=require('express');const router=framework.Router();",
    "const {Router:createRouter}=require('express');const router=createRouter();",
    "const router=require('express')();",
  ]) {
    const check = scan(setup + `router.get('/x',${handler});`);
    const findings = check.findings.filter(f => f.ruleId === 'ast:html-input-sink');
    assert.equal(check.status, 'completed'); assert.equal(findings.length, 1, setup);
    assert.equal(findings[0].kind, 'candidate'); assert.equal(findings[0].confidence, 'medium');
    assert.equal(findings[0].location.path, 'route.ts'); assert.equal(findings[0].location.line, 1);
    assert.equal(findings[0].staticFlow?.steps.at(-1)?.role, 'sink');
    assert.ok(findings[0].staticFlow?.steps.some(s => s.role === 'source'));
    const report = createReport([check], 'source', new Date(0));
    for (const output of [JSON.stringify(report), JSON.stringify(toAgentReport(report)), toMarkdown(report), JSON.stringify(toSarif(report))]) {
      assert.ok(!output.includes('syntheticRegistrationMarker')); assert.ok(!output.includes(handler));
    }
  }
});

test('immutable factory/router aliases and named callbacks in literal arrays retain registered roots', () => {
  const setup = "import express from 'express';const make=express;const Router=make.Router;const original=Router();const router=original;";
  assert.equal(html(setup + `router.post('/x',${handler});`).length, 1);
  for (const declaration of [
    'function render(incoming,outgoing){outgoing.send(incoming.body.value)}',
    'const render=(incoming,outgoing)=>outgoing.send(incoming.body.value);',
  ]) {
    assert.equal(html(prefix + declaration + "const alias=render;render({body:{value:'fixed'}},{send(){}});router.get('/x',[alias]);").length, 1);
  }
});

test('directly default-exported routers retain same-file renamed-handler candidates', () => {
  const source = "import { Router } from 'express';\nconst router = Router();\nrouter.get('/welcome', (incoming, outgoing) => {\n  return outgoing.send(`<h2>Welcome ${incoming.query.name}</h2>`);\n});\nexport default router;\n";
  const found = html(source);
  assert.equal(found.length, 1); assert.equal(found[0].location.line, 4);
  assert.equal(found[0].kind, 'candidate'); assert.equal(found[0].confidence, 'medium');
  assert.equal(html(source.replace('outgoing.send(`<h2>Welcome ${incoming.query.name}</h2>`)', 'outgoing.json({name:incoming.query.name})')).length, 0);
  assert.equal(html(source.replace("from 'express'", "from 'custom'" )).length, 0);
  assert.equal(html(source.replace('export default router;', 'opaque(router);export default router;')).length, 0);
  assert.equal(html(source.replace('export default router;', 'export default {router};')).length, 0);
});

test('Express HTTP registrations, route chains and middleware use the correct argument positions', () => {
  for (const method of ['get','post','put','patch','delete','head','options','all']) {
    assert.equal(html(prefix + `router.${method}('/x',auth,${handler});`).length, 1, method);
    assert.equal(html(prefix + `router.route('/x').${method}(${handler});`).length, 1, method);
  }
  for (const call of [`router.use(${handler})`, `router.use('/x',[auth,[${handler}]])`,
    `router.get('/a',auth).post('/b',${handler})`, `router.route('/x').get(auth).post(${handler})`,
    `router.get(['/a','/b'],${handler})`, `router.get(/^\\/x$/,${handler})`]) {
    assert.equal(html(prefix + call).length, 1, call);
  }
  assert.equal(html(prefix + "router.use((failure,incoming,outgoing,next)=>outgoing.send(incoming.query.value))").length, 1);
  assert.equal(html(prefix + "router.get('/x',({query:input},outgoing)=>outgoing.send(input.value))").length, 1);
});

test('registered callback MIME and actual-argument safeguards are unchanged', () => {
  for (const body of ["outgoing.type('text/plain').send(incoming.query.value)", 'outgoing.json(incoming.query.value)',
    'outgoing.send({value:incoming.query.value})', "outgoing.send('fixed')", 'outgoing={send(){}};outgoing.send(incoming.query.value)']) {
    assert.equal(html(prefix + `router.get('/x',(incoming,outgoing)=>{${body}})`).length, 0, body);
  }
  for (const body of ["outgoing.type('html').json({value:incoming.query.value})",
    "outgoing.type('text/plain');opaque(outgoing);outgoing.send(incoming.query.value)",
    "const bag={reply:outgoing};outgoing.type('text/plain');opaque(bag);outgoing.send(incoming.query.value)"]) {
    assert.equal(html(prefix + `router.get('/x',(incoming,outgoing)=>{${body}})`).length, 1, body);
  }
  assert.equal(html(prefix + "function write(output,value){output.send(value)}router.get('/x',(incoming,outgoing)=>write(outgoing,incoming.query.value))").length, 1);
  assert.equal(html(prefix + "function write(output,value){output.send(value)}router.get('/x',(incoming,outgoing)=>write({send(){}},incoming.query.value))").length, 0);
});

test('arbitrary callbacks, fake packages, shadowed bindings and non-handler Express arguments stay unseeded', () => {
  for (const text of [
    `arbitrary(${handler})`, `const router={get(){}};router.get('/x',${handler})`,
    `import express from 'not-express';const router=express();router.get('/x',${handler})`,
    `import type express from 'express';const router=express();router.get('/x',${handler})`,
    `import {type Router} from 'express';const router=Router();router.get('/x',${handler})`,
    `function require(value){return fake};const express=require('express');const router=express();router.get('/x',${handler})`,
    prefix + `function configure(router){router.get('/x',${handler})}`,
    `import express from 'express';function configure(express){const router=express();router.get('/x',${handler})}`,
    prefix + `router.get(${handler})`, prefix + `router.set('handler',${handler})`,
    prefix + `router.listen(8080,${handler})`, prefix + `router.param('id',${handler})`,
    prefix + `router.engine('html',${handler})`, prefix + `router.on('event',${handler})`,
    prefix + `router.get('/x',factory(${handler}))`,
    prefix + `router.get()`, prefix + `router.use()`, prefix + `router.route('/x').get()`,
    prefix + `router.use({},${handler})`, prefix + `router.get('/x',null,${handler})`,
  ]) assert.equal(html(text).length, 0, text);
});

test('mutations and opaque escapes revoke positional registration identity through aliases', () => {
  for (const change of [
    'router.get=replacement;', 'const alias=router;alias.get=replacement;', 'Object.assign(router,{get:replacement});',
    'opaque(router);', 'const bag={router};opaque(bag);', 'express.Router=replacement;',
    'express.application.get=replacement;', 'const factory=express;factory.Router=replacement;',
    "const alias=router.get('/first',auth);alias.get=replacement;", "opaque(router.get('/first',auth));",
  ]) assert.equal(html(prefix + change + `router.get('/x',${handler})`).length, 0, change);
  assert.equal(html("import express from 'express';let router=express();router=fake;" + `router.get('/x',${handler})`).length, 0);
  assert.equal(html(prefix + "let render=" + handler + ";render=other;router.get('/x',render)").length, 0);
  assert.equal(html(prefix + "import * as ns from 'express';ns.default.application.get=fake;" + `router.get('/x',${handler})`).length, 0);
  assert.equal(html(prefix + "import {Router} from 'express';Router.prototype.get=fake;" + `router.get('/x',${handler})`).length, 0);
  assert.equal(html("import express from 'express';const router=express();const alias=router.set('x','y');alias.get=fake;" + `router.get('/x',${handler})`).length, 0);
  assert.equal(html(prefix + `const handlers=[${handler}];handlers.pop();router.get('/x',handlers)`).length, 0);
  assert.equal(html(prefix + `const render=${handler};Object.defineProperty(render,'length',{value:4});router.get('/x',render)`).length, 0);
  assert.equal(html(`require=()=>()=>({get(){}});const express=require('express');const router=express();router.get('/x',${handler})`).length, 0);
  assert.equal(html(prefix + "const rogue=express.Router();rogue.__proto__.get=fake;" + `router.get('/x',${handler})`).length, 0);
  assert.equal(html(prefix + "import('express').then(x=>x.default.application.get=fake);" + `router.get('/x',${handler})`).length, 0);
});

test('positional registration ignores error, next and unrelated parameter names as request inputs', () => {
  for (const declaration of [
    '(request,incoming,outgoing,next)=>outgoing.send(request.query.value)',
    '(incoming,outgoing,request)=>outgoing.send(request.query.value)',
    '(incoming,outgoing,...extra)=>outgoing.send(incoming.query.value)',
    '(failure,incoming,outgoing,next=()=>{})=>outgoing.send(incoming.query.value)',
    'function(this:any,incoming,outgoing){outgoing.send(incoming.query.value)}',
  ]) assert.equal(html(prefix + `router.use(${declaration})`).length, 0, declaration);
});

test('Express positional identity cannot cross file scope or const initialization order', () => {
  for (const code of [
    `import express from 'express';router.get('/x',${handler});const router=express();`,
    `const router=express();const express=require('express');router.get('/x',${handler});`,
    prefix + "router.get('/x',render);const render=" + handler,
    prefix + `router.get('/x',...handlers,${handler});`,
  ]) assert.equal(html(code).length, 0, code);
  const texts = { 'owner.js': "const express=require('express');const router=express();", 'other.js': `router.get('/x',${handler});` };
  const files = Object.entries(texts).map(([path,text]) => ({path,text,bytes:text.length,category:'code' as const,sensitive:false}));
  const check = runBuiltinAst({root:'/never-read',files,issues:[],complete:true,ignoredFiles:0,totalBytes:files.reduce((n,f)=>n+f.bytes,0)}, false);
  assert.equal(check.findings.filter(f=>f.ruleId==='ast:html-input-sink').length, 0);
});

test('early and late index exhaustion never reuse positional entry proof', () => {
  const text = prefix + `router.get('/x',${handler});`;
  const run = (indexWork: number) => findSnapshotInputFlows([ts.createSourceFile('route.ts',text,ts.ScriptTarget.Latest,true)], {...FLOW_LIMITS,indexWork});
  const full = run(FLOW_LIMITS.indexWork);
  assert.ok(full.uses.some(use => use.htmlResponse === 'express'));
  for (const budget of [1, Number(full.metrics.indexWork) - 1]) {
    const result = run(budget);
    assert.equal(result.metrics.indexComplete, false);
    assert.ok(result.reasons.includes('index_work_limit'));
    assert.equal(result.uses.some(use => use.htmlResponse === 'express'), false);
    assert.ok(Number(result.metrics.indexWork) <= budget);
  }
});
