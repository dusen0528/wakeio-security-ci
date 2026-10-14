import test from 'node:test';
import assert from 'node:assert/strict';
import * as ts from 'typescript';
import { findSnapshotInputFlows } from '../src/source/dataflow.js';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import type { SourceSnapshot } from '../src/source/types.js';

// Owned source data only: these snippets and Express are never executed.
const prefix = "import express from 'express';const app=express();";
function snapshot(text: string): SourceSnapshot {
  return { root: '/never-executed', files: [{ path: 'route.ts', text, bytes: Buffer.byteLength(text), category: 'code', sensitive: false }],
    issues: [], complete: true, ignoredFiles: 0, totalBytes: Buffer.byteLength(text) };
}
function uses(text: string) {
  const file = ts.createSourceFile('route.ts', text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  return findSnapshotInputFlows([file], FLOW_LIMITS).uses.filter(use => use.htmlResponse === 'express');
}
function responseFindings(text: string) {
  return runBuiltinAst(snapshot(text), false).findings.filter(finding => ['ast:html-input-sink', 'ast:response-input-sink'].includes(finding.ruleId));
}

test('entry authority records registration rather than parameter spelling', () => {
  for (const [text, authority] of [
    [prefix+"app.get('/owned',(incoming,outgoing)=>outgoing.send(incoming.query.value));", 'registered_express'],
    ["function route(req,res){res.send(req.query.value)}", 'unqualified_response'],
    ["const app={get(){}};app.get('/owned',(req,res)=>res.send(req.query.value));", 'unqualified_response'],
  ] as const) {
    const found = uses(text);
    assert.equal(new Set(found.map(use => use.node)).size, 1);
    assert.ok(found.every(use => use.htmlResponseAuthority === authority));
    assert.equal(found[0].argumentFlows?.[0].staticFlow?.steps.at(-1)?.role, 'sink');
  }
});

test('response aliases and actual helper calls retain their entry authority', () => {
  for (const registered of [true, false]) {
    const text = "function reply(output,input){const alias=output;alias.send(input)}" + (registered
      ? prefix+"app.get('/owned',(incoming,outgoing)=>reply(outgoing,incoming.query.value));"
      : "function route(req,res){reply(res,req.query.value)}");
    const found = responseFindings(text);
    assert.equal(found.length, 1);
    assert.equal(found[0].ruleId, registered ? 'ast:html-input-sink' : 'ast:response-input-sink');
  }
});

test('opaque and container effects lower registered authority without removing the candidate', () => {
  for (const effect of [
    'opaque(outgoing);', 'outgoing.customPolicy();',
    'const bag={reply:outgoing};opaque(bag);',
    'if(incoming.query.flag){opaque(outgoing)}else{outgoing.status(200)}',
    'const alias=outgoing;if(incoming.query.flag){opaque(alias)}else{outgoing.status(200)}',
  ]) {
    const text = prefix+`app.get('/owned',(incoming,outgoing)=>{${effect}outgoing.send(incoming.query.value)});`;
    const found = responseFindings(text);
    assert.equal(found.length, 1, effect);
    assert.equal(found[0].ruleId, 'ast:response-input-sink', effect);
    assert.equal(found[0].confidence, 'low');
    assert.equal(found[0].severity, 'high');
  }
});

test('mixed invocation authority is independent of helper context traversal order and cache reuse', () => {
  const registered = prefix+"app.get('/owned',(incoming,outgoing)=>reply(outgoing,incoming.query.value));";
  const named = "function route(req,res){reply(res,req.query.value)}";
  const helper = "function reply(output,input){output.send(input)}";
  for (const text of [helper+registered+named, helper+named+registered]) {
    for (let scan = 0; scan < 2; scan++) {
      const found = responseFindings(text);
      assert.equal(found.length, 1);
      assert.equal(found[0].ruleId, 'ast:response-input-sink');
      assert.equal(found[0].confidence, 'low');
      assert.equal(found[0].severity, 'high');
    }
  }
});

test('authority classification preserves existing MIME and non-response detection boundaries', () => {
  for (const registered of [true, false]) {
    const make = (body: string) => registered ? prefix+`app.get('/owned',(req,res)=>{${body}});` : `function route(req,res){${body}}`;
    assert.equal(responseFindings(make("res.type('text/plain');res.send(req.query.value)")).length, 0);
    assert.equal(responseFindings(make('res.send({message:req.query.value})')).length, 0);
    assert.equal(responseFindings(make("res.type('html');res.send(req.query.value)")).length, 1);
    const check = runBuiltinAst(snapshot(make('element.innerHTML=req.query.value;res.send(req.query.value)')), false);
    assert.equal(check.findings.filter(finding => finding.ruleId === 'ast:html-input-sink').length, registered ? 2 : 1);
  }
});
