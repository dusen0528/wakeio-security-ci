import test from 'node:test';
import assert from 'node:assert/strict';
import * as ts from 'typescript';
import { htmlConcat, htmlHole, htmlLiteral, inspectHtml, type HtmlBudget } from '../src/source/html-context.js';
import { consumeNodeResponse, type NodeResponseState } from '../src/source/node-response-role.js';
import { runBuiltinAst } from '../src/source/ast.js';
import { createReport, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function budget(maxParts = 24, maxCharacters = 2048) {
  let work = 0, gaps = 0;
  const value: HtmlBudget = { maxParts, maxCharacters, tick: () => { work++; return true; }, gap: () => { gaps++; } };
  return { value, work: () => work, gaps: () => gaps };
}
function fragments(prefix: string, suffix: string, limits = budget()) {
  return { limits, value: htmlConcat([htmlLiteral(prefix, limits.value), htmlHole(true, undefined, limits.value),
    htmlLiteral(suffix, limits.value)], { kind: 'hole', inputRelated: true }, limits.value) };
}
function scan(text: string) {
  const snapshot: SourceSnapshot = { root: '/never-executed', files: [{ path: 'route.ts', text,
    bytes: Buffer.byteLength(text), category: 'code', sensitive: false }], issues: [], complete: true,
    ignoredFiles: 0, totalBytes: Buffer.byteLength(text) };
  return runBuiltinAst(snapshot, false);
}
const urlRows = (text: string) => scan(text).findings.filter(finding => finding.ruleId === 'ast:html-url-input-sink');
const node = (body: string, header = "res.setHeader('Content-Type','text/html');") =>
  `import {createServer} from 'node:http';createServer((incoming,res)=>{${header}${body}});`;

// All fixture source is inert data; no handler or third-party code is executed.
test('HTML carrier distinguishes quoted URL holes, literal prefixes and text positions', () => {
  for (const [prefix, suffix, kind] of [
    ['<a href="', '">next</a>', 'whole_url'],
    ["<form action='", "'>submit</form>", 'whole_url'],
    ['<img src="https://owned.invalid/path/', '">', 'fixed_prefix'],
  ]) {
    const source = fragments(prefix, suffix);
    const result = inspectHtml(source.value, source.limits.value);
    assert.equal(result.urlAttributeInput, true);
    assert.deepEqual(result.urlAttributeKinds, [kind]);
    assert.equal(result.unknown, false);
  }
  const text = fragments('<p>', '</p>');
  assert.equal(inspectHtml(text.value, text.limits.value).urlAttributeInput, false);
  const fixed = budget();
  assert.equal(inspectHtml(htmlLiteral('<a href="https://owned.invalid/">fixed</a>', fixed.value), fixed.value).inputRelated, false);
});

test('HTML carrier never treats dynamic markup, raw-text, unquoted attributes or lost bounds as known URL context', () => {
  for (const [prefix, suffix] of [
    ['<', '>fixed</a>'], ['<a href=', '>fixed</a>'], ['<script>', '</script>'],
    ['<a title="', '">fixed</a>'], ['<!--', '-->'], ['<a href="', ''],
  ]) {
    const source = fragments(prefix, suffix);
    const result = inspectHtml(source.value, source.limits.value);
    assert.equal(result.urlAttributeInput, false, prefix);
    assert.equal(result.unknown, true, prefix);
    assert.ok(source.limits.gaps() > 0);
  }
  const limited = budget(1);
  const lost = fragments('<a href="', '">', limited);
  assert.equal(lost.value.complete, false);
  assert.equal(lost.value.inputRelated, true);
  assert.equal(limited.gaps(), 0, 'representation loss alone is not an unrelated HTML gap');
  assert.equal(inspectHtml(lost.value, limited.value).unknown, true);
  assert.ok(limited.gaps() > 0);
});

test('Node consumption keeps encoding and cross-write uncertainty separate from a URL-attribute claim', () => {
  const file = ts.createSourceFile('route.ts', 'res.write("prefix");res.end(value);', ts.ScriptTarget.Latest, true);
  const calls = file.statements.map(statement => (statement as ts.ExpressionStatement).expression as ts.CallExpression);
  const state: NodeResponseState = { identity: {}, valid: true, mime: 'html', authority: 'declared_node_response' };
  const text = fragments('<p>', '</p>');
  const textUse = consumeNodeResponse(calls[1], state, text.value, text.limits.value)!;
  assert.equal(textUse.outcome, 'html_context_unknown');
  assert.equal(textUse.uncertainty, 'encoding');
  assert.ok(text.limits.gaps() > 0);
  const stream = budget();
  consumeNodeResponse(calls[0], state, htmlLiteral('<a href="', stream.value), stream.value);
  const second = fragments('', '">next</a>', stream);
  const streamed = consumeNodeResponse(calls[1], state, second.value, stream.value)!;
  assert.equal(streamed.outcome, 'html_context_unknown');
  assert.equal(streamed.uncertainty, 'streaming');
});

test('qualified Node HTML output detects a URL hole without trusting an escape helper name', () => {
  for (const value of ['incoming.url', 'escapeHtml(incoming.url)', 'encodeURIComponent(incoming.url)']) {
    const check = scan(node(`res.end('<a href="'+${value}+'">next</a>');`));
    const findings = check.findings.filter(finding => finding.ruleId === 'ast:html-url-input-sink');
    assert.equal(findings.length, 1, value);
    assert.equal(findings[0].severity, 'medium');
    assert.equal(findings[0].kind, 'candidate');
    assert.equal(findings[0].confidence, 'low');
    assert.ok(findings[0].staticFlow?.steps.some(step => step.role === 'source'));
    assert.equal(findings[0].staticFlow?.steps.at(-1)?.role, 'sink');
  }
  const fixedPrefix = urlRows(node('res.end(`<a href="https://owned.invalid/path/${encodeURIComponent(incoming.url)}">next</a>`);'));
  assert.equal(fixedPrefix.length, 1);
  assert.match(fixedPrefix[0].description, /does not prove input control of the URL scheme/);
});

test('Node response controls preserve literal URLs, non-HTML output and text-versus-URL discrimination', () => {
  assert.equal(urlRows(node('res.end(\'<a href="https://owned.invalid/">fixed</a>\');')).length, 0);
  const data = scan(node('res.end(incoming.url);', "res.setHeader('Content-Type','application/json');"));
  assert.equal(data.findings.filter(finding => finding.ruleId?.startsWith('ast:html-')).length, 0);
  const text = scan(node("res.end('<p>'+escapeHtml(incoming.url)+'</p>');"));
  assert.equal(text.findings.filter(finding => finding.ruleId === 'ast:html-url-input-sink').length, 0);
  assert.equal(text.findings.filter(finding => finding.ruleId === 'ast:html-output-context-unknown').length, 1);
  assert.equal(text.status, 'partial');
});

test('core Node registrations support renamed runtime bindings and the two-argument HTTPS signature', () => {
  for (const source of [
    `import * as core from 'http';core.createServer((message,reply)=>{reply.setHeader('Content-Type','text/html');reply.end('<a href="'+message.url+'">next</a>')});`,
    `const core=require('node:http');function handler(message,reply){reply.setHeader('Content-Type','text/html');reply.end('<a href="'+message.url+'">next</a>')}core.createServer(handler);`,
    `import {createServer as start} from 'node:https';const handler=(message,reply)=>{reply.writeHead(200,{'Content-Type':'text/html'});reply.end('<a href="'+message.url+'">next</a>')};start({key:'owned-inert-key',cert:'owned-inert-cert'},handler);`,
  ]) assert.equal(urlRows(source).length, 1, source);
  for (const source of [
    `const core={createServer(fn){}};core.createServer((message,reply)=>{reply.setHeader('Content-Type','text/html');reply.end('<a href="'+message.url+'">next</a>')});`,
    `import {createServer as start} from 'custom';start((message,reply)=>{reply.setHeader('Content-Type','text/html');reply.end('<a href="'+message.url+'">next</a>')});`,
  ]) assert.equal(urlRows(source).length, 0);
});

test('Node unknown contexts retain candidates and report projections expose no raw template or marker', () => {
  for (const body of ['res.end(incoming.url);', `res.write('<a href="');res.end(incoming.url+'">next</a>');`]) {
    const result = scan(node(body, ''));
    assert.equal(result.status, 'partial');
    assert.equal(result.findings.filter(finding => finding.ruleId === 'ast:html-output-context-unknown').length, 1);
  }
  const check = scan(node(`res.end('<a href="'+incoming.url+'">ownedRawHtmlMarker</a>');`));
  const report = createReport([check], 'source', new Date(0));
  for (const output of [JSON.stringify(report), JSON.stringify(toAgentReport(report)), JSON.stringify(toSarif(report)), toMarkdown(report)]) {
    assert.ok(!output.includes('ownedRawHtmlMarker'));
    assert.ok(!output.includes('<a href'));
  }
});
