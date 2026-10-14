import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import type { SourceSnapshot } from '../src/source/types.js';

const prefix = "const producer=require('send');\n";
function scan(text: string, limits: FlowLimits = FLOW_LIMITS) {
  const file = { path: 'owned.js', text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false };
  const snapshot: SourceSnapshot = { root: '/owned-html-callback', files: [file], totalBytes: file.bytes,
    complete: true, ignoredFiles: 0, issues: [] };
  return runBuiltinAst(snapshot, false, limits);
}
const urls = (check: ReturnType<typeof scan>) => check.findings.filter(row => row.ruleId === 'ast:html-url-input-sink');

test('HTML callback owner: generic returned handler retains factory-selected regular alternatives', () => {
  const check = scan(prefix + `module.exports=function mount(options){
    const listener=options.enabled ? positive() : empty();
    return function receive(message,reply){const stream=producer(message,message.url,{});stream.on('directory',listener);stream.pipe(reply)};
  };
  function positive(){return function event(out){const value=this.req.url;out.setHeader('Content-Type','text/html');out.end('<a href="'+value+'">go</a>')}}
  function empty(){return function event(out){out.setHeader('Content-Type','text/plain');out.end('fixed')}}`);
  assert.equal(check.status, 'partial'); assert.equal(urls(check).length, 1);
  assert.equal(urls(check)[0].confidence, 'low');
  assert.ok(urls(check)[0].staticFlow?.steps.some(step => step.role === 'source'));
  assert.equal(urls(check)[0].staticFlow?.steps.at(-1)?.role, 'sink');
  assert.ok(Number(check.metrics?.htmlCallbackInspectionsStarted) > 0);
  assert.equal(check.metrics?.entryRootsSkipped, 0);
});

test('HTML callback owner: opaque receiver effect revokes stale non-HTML classification', () => {
  const check = scan("import {createServer} from 'node:http';createServer((message,out)=>{out.setHeader('Content-Type','application/json');out.opaque();out.end(message.url)});");
  assert.equal(check.status, 'partial');
  assert.equal(urls(check).length, 0);
  assert.equal(check.findings.filter(row => row.ruleId === 'ast:html-output-context-unknown').length, 1);
});

test('HTML callback owner: exhausted residual callback allowance stays partial and preserves direct root', () => {
  const text = prefix + "module.exports=function mount(){return function receive(message,reply){const stream=producer(message);stream.on('directory',listener());stream.pipe(reply)}};function listener(){return function event(out){out.end(this.req.url)}};export function direct(req){eval(req.query.code)}";
  const check = scan(text, { ...FLOW_LIMITS, summaryWork: 1 });
  assert.equal(check.status, 'partial');
  assert.ok(check.findings.some(row => row.ruleId === 'ast:dynamic-code'));
  assert.equal(check.metrics?.entryRootsSkipped, 0);
  assert.ok(Number(check.metrics?.htmlCallbackInspectionsDropped) > 0);
});

test('HTML callback owner: response in a general container cannot retain branch MIME exclusion', () => {
  const check = scan("import {createServer} from 'node:http';createServer((message,out)=>{out.setHeader('Content-Type','application/json');const holder={out};if(flag){holder.out.setHeader('Content-Type','text/html')}out.end(message.url)});");
  assert.equal(check.status, 'partial');
  assert.equal(check.findings.filter(row => row.ruleId === 'ast:html-output-context-unknown').length, 1);
});

test('HTML callback owner: detached response captures preserve direct aliases and re-establish callback MIME', () => {
  const check = scan("import {createServer} from 'node:http';createServer((incoming,res)=>{res.setHeader('Content-Type','application/json');const alias=res;return function returned(){alias.setHeader('Content-Type','text/html');res.end('<a href=\"'+incoming.url+'\">x</a>')}});");
  assert.equal(check.status, 'partial'); assert.equal(urls(check).length, 1);
  assert.equal(urls(check)[0].confidence, 'low');
});

test('HTML callback owner: unverified event scheduling cannot reuse captured pre-event non-HTML headers', () => {
  const check = scan("import {createServer} from 'node:http';const send=require('send');createServer((incoming,res)=>{res.setHeader('Content-Type','application/json');const stream=send(incoming,incoming.url,{});stream.on('directory',function(){res.end('<a href=\"'+incoming.url+'\">x</a>')});stream.pipe(res);res.setHeader('Content-Type','text/html')});");
  assert.equal(check.status, 'partial'); assert.equal(urls(check).length, 0);
  assert.equal(check.findings.filter(row => row.ruleId === 'ast:html-output-context-unknown').length, 1);
});

test('HTML callback owner: unsupported Node role diagnostics preserve existing indexed interfile SQL flow', () => {
  const sources = {
    'app.ts': "import {Agent} from 'node:http';import {execute} from './db';export function route(req){execute(req.query.sql)}",
    'db.ts': "import {Pool} from 'pg';const db=new Pool();export function execute(value){db.query(value)}",
    'shim.ts': 'export class Agent {}',
    'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { 'node:http': ['./shim.ts'] } } }),
  };
  const files = Object.entries(sources).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text),
    category: path.endsWith('.json') ? 'config' as const : 'code' as const, sensitive: false }));
  const check = runBuiltinAst({ root: '/owned-node-local-diagnostic', files, totalBytes: files.reduce((sum, file) => sum + file.bytes, 0),
    complete: true, ignoredFiles: 0, issues: [] }, false);
  assert.equal(check.status, 'partial'); assert.equal(check.metrics?.indexComplete, true);
  assert.ok(Number(check.metrics?.resolvedCalls) > 0);
  assert.equal(check.findings.filter(row => row.ruleId === 'ast:sql-input-sink').length, 1);
  assert.equal(check.metrics?.entryRootsSkipped, 0);
  assert.ok(String(check.metrics?.incompleteReasons).includes('module_export_unsupported'));
});

test('HTML callback owner: the same returned function body retains distinct captured alternatives in either order', () => {
  const before = prefix + "module.exports=function route(req,res){const stream=producer(req,req.url,{});const callback=flag ? ";
  const after = ";stream.on('directory',callback);stream.pipe(res)};function listener(value){return function(res){res.setHeader('Content-Type','text/html');res.end('<a href=\"'+value+'\">go</a>')}}";
  for (const branches of ["listener(req.query.url):listener('fixed')", "listener('fixed'):listener(req.query.url)"]) {
    const check = scan(before + branches + after);
    assert.equal(check.status, 'partial'); assert.equal(urls(check).length, 1, branches);
    assert.equal(urls(check)[0].confidence, 'low');
    assert.ok(urls(check)[0].staticFlow?.steps.some(step => step.role === 'source'));
  }
  const normal = scan(before + "listener('first'):listener('second')" + after);
  assert.equal(normal.status, 'partial'); assert.equal(urls(normal).length, 0);
});
