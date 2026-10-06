import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { createReport, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function scan(text: string) {
  const snapshot: SourceSnapshot = { root: '/never-executed', files: [{ path: 'route.ts', text,
    bytes: Buffer.byteLength(text), category: 'code', sensitive: false }], issues: [], complete: true,
    ignoredFiles: 0, totalBytes: Buffer.byteLength(text) };
  return runBuiltinAst(snapshot, false);
}
const html = (text: string) => scan(text).findings.filter(finding => finding.ruleId === 'ast:html-input-sink');

// These source strings are parsed, never imported or executed.
test('Express request/response-shaped handlers report direct, template, status and alias send bodies', () => {
  for (const body of [
    'res.send(req.query.syntheticHtmlMarker)',
    'res.send(`<h1>${req.query.syntheticHtmlMarker}</h1>`)',
    'res.status(200).send(req.query.syntheticHtmlMarker)',
    'const reply=res; reply.send(req.query.syntheticHtmlMarker)',
    'const value=req.query.syntheticHtmlMarker; res.send(value)',
  ]) {
    const check = scan(`app.get('/hello',(req,res)=>{${body}})`);
    assert.equal(check.status, 'completed');
    const findings = check.findings.filter(finding => finding.ruleId === 'ast:html-input-sink');
    assert.equal(findings.length, 1, body);
    assert.equal(findings[0].kind, 'candidate');
    assert.equal(findings[0].confidence, 'medium');
    assert.equal(findings[0].location.path, 'route.ts');
    assert.equal(findings[0].location.line, 1);
    assert.match(findings[0].title, /res.send.*encode HTML or set a non-HTML type/);
    assert.equal(findings[0].staticFlow?.steps.at(-1)?.role, 'sink');
    assert.equal(findings[0].staticFlow?.truncated, false);
    const report = createReport([check], 'source', new Date(0));
    for (const text of [JSON.stringify(report), JSON.stringify(toAgentReport(report)), toMarkdown(report), JSON.stringify(toSarif(report))]) {
      assert.ok(!text.includes('syntheticHtmlMarker'));
      assert.ok(!text.includes(body));
    }
    assert.ok(toAgentReport(report).findings.every(finding => !finding.verification.vulnerabilityConfirmed));
  }
  assert.equal(html('function route(request,response){response.send(request.body.name)}').length, 1);
  assert.equal(html('function route(req,res){let body={value:req.query.value};body=req.query.raw;res.send(body)}').length, 1);
  assert.equal(html('function route(req,res){const body=req.query.raw ? {value:req.query.value} : req.query.raw;res.send(body)}').length, 1);
});

test('Express JSON/object/array/static bodies and unrelated send APIs do not become HTML candidates', () => {
  for (const body of [
    'res.json(req.query.value)', 'res.status(200).json(req.query.value)',
    'res.send({value:req.query.value})', 'res.send([req.query.value])',
    'const body={value:req.query.value}; res.send(body)',
    'const body={};body.text=req.query.value;res.send(body)',
    'const body={text:req.query.value};body.extra="fixed";res.send(body)', 'const body=[req.query.value]; res.send(body)',
    'res.send(({value:req.query.value}))',
    "res.send('fixed')", 'queue.send(req.query.value)',
    'res={send(value){}};res.send(req.query.value)',
    '{const res={send(value){}};res.send(req.query.value)}',
    'res.type("text/plain").send(req.query.value)',
  ]) assert.equal(html(`function route(req,res){${body}}`).length, 0, body);
  assert.equal(html('function custom(res){res.send(req.query.value)}').length, 0);
  assert.equal(html('function custom(input,res){res.send(req.query.value)}').length, 0);
  assert.equal(html('function render(req,res){res.send(req.query.value)} render({query:{value:"fixed"}},{send(value){}})').length, 0);
});

test('response metadata propagates through an actual local helper without confusing summary contexts', () => {
  const source = 'function reply(output,value){output.send(value)} function route(req,res){reply({send(value){}},req.query.first);reply(res,req.query.second)}';
  assert.equal(html(source).length, 1);
  assert.equal(html(source.replace('reply(res,req.query.second)', 'reply({send(value){}},req.query.second)')).length, 0);
});

test('Next route HTML Response body gets a source-to-sink candidate with explicit MIME', () => {
  for (const constructor of ['Response', 'NextResponse', 'Reply']) {
    const prefix = constructor === 'Response' ? '' : `import {NextResponse${constructor === 'Reply' ? ' as Reply' : ''}} from 'next/server';`;
    const source = `${prefix}export function GET(request){const name=request.nextUrl.searchParams.get('syntheticHtmlMarker');return new ${constructor}(\`<h1>\${name}</h1>\`,{headers:{'Content-Type':'text/html; charset=utf-8'}})}`;
    const result = html(source);
    assert.equal(result.length, 1, source);
    assert.equal(result[0].confidence, 'medium');
    assert.equal(result[0].kind, 'candidate');
    assert.match(result[0].title, /HTML response.*encode text or return JSON/);
    assert.ok(result[0].staticFlow?.steps.some(step => step.role === 'source'));
    assert.equal(result[0].staticFlow?.steps.at(-1)?.role, 'sink');
  }
});

test('Web Response requires an input body, unshadowed/bound constructor and closed literal HTML headers', () => {
  for (const expression of [
    'Response.json({value:request.nextUrl.searchParams.get("q")})',
    'new Response(request.nextUrl.searchParams.get("q"))',
    'new Response(request.nextUrl.searchParams.get("q"),{headers:{"content-type":"application/json"}})',
    'new Response(request.nextUrl.searchParams.get("q"),{headers:{"content-type":"text/plain"}})',
    'new Response("fixed",{headers:{"content-type":"text/html"}})',
    'new Response(request.nextUrl.searchParams.get("q"),{headers:{"content-type":"text/html",...extra}})',
    'new Response(request.nextUrl.searchParams.get("q"),{headers:{"content-type":"text/html","Content-Type":"application/json"}})',
    'new Response(request.nextUrl.searchParams.get("q"),{headers:{"content-type":"text/html"},headers:{"content-type":"text/plain"}})',
    'new CustomResponse(request.nextUrl.searchParams.get("q"),{headers:{"content-type":"text/html"}})',
  ]) assert.equal(html(`export function GET(request){return ${expression}}`).length, 0, expression);
  assert.equal(html('function route(request,Response){return new Response(request.query.name,{headers:{"content-type":"text/html"}})}').length, 0);
  for (const prefix of ['import type {NextResponse} from "next/server";', 'import {type NextResponse} from "next/server";']) {
    assert.equal(html(prefix+'function route(request){return new NextResponse(request.query.name,{headers:{"content-type":"text/html"}})}').length, 0);
  }
  assert.equal(html('import {NextResponse} from "custom";function route(request){return new NextResponse(request.query.name,{headers:{"content-type":"text/html"}})}').length, 0);
});


test('HTML Response captures actual body before options-side reassignment', () => {
  const options = '{status:(body=REPLACEMENT,200),headers:{"Content-Type":"text/html"}}';
  assert.equal(html(`function GET(request){let body=request.query.value;return new Response(body,${options.replace('REPLACEMENT', '\'fixed\'')})}`).length, 1);
  assert.equal(html(`function GET(request){let body='fixed';return new Response(body,${options.replace('REPLACEMENT', 'request.query.value')})}`).length, 0);
  assert.equal(html('function route(req,res){res.send(res=req.query.value)}').length, 1);
});


test('documented response data writes retain HTML sinks while API replacement invalidates shape', () => {
  for (const prefix of ['res.statusCode=200;', 'res.statusMessage="OK";', 'res.locals.name="fixed";', 'res.locals={name:"fixed"};', 'const reply=res;reply.locals.name="fixed";']) {
    const sink = prefix.startsWith('const reply') ? 'reply' : 'res';
    assert.equal(html(`function route(req,res){${prefix}${sink}.send(req.query.value)}`).length, 1, prefix);
  }
  for (const prefix of ['res.send=replacement;', 'res.status=replacement;', 'res.__proto__=replacement;', 'res.unknown=replacement;']) {
    assert.equal(html(`function route(req,res){${prefix}res.send(req.query.value)}`).length, 0, prefix);
  }
});

test('literal Express MIME setters distinguish text data from JSON served as HTML', () => {
  for (const prefix of [
    "res.type('text/plain');res.set('X-Content-Type-Options','nosniff');",
    "res.set('Content-Type','text/plain; charset=utf-8');",
    "res.header({'Content-Type':'application/json'});",
    "res.setHeader('Content-Type','text/plain');",
    "res.type('html');res.type('json');",
  ]) assert.equal(html(`function route(req,res){${prefix}res.send(req.query.value)}`).length, 0, prefix);
  for (const prefix of ["res.type('text/html');", "res.set('Content-Type','text/html');", "res.header({'content-type':'text/html'});", "res.type('text/plain');res.type('html');"]) {
    const findings = html(`function route(req,res){${prefix}res.json({message:req.query.value})}`);
    assert.equal(findings.length, 1, prefix);
    assert.equal(findings[0].confidence, 'medium');
    assert.match(findings[0].title, /JSON.*set application\/json/);
    assert.match(findings[0].remediation, /explicitly set application\/json before res.json/);
  }
  assert.equal(html("function route(req,res){res.type('html').json({message:req.query.value})}").length, 1);
  assert.equal(html("function route(req,res){res.type('text/plain').set('X-Content-Type-Options','nosniff').send(req.query.value)}").length, 0);
});

test('MIME aliases, branch joins and actual helper side effects do not create stale safe contexts', () => {
  assert.equal(html("function route(req,res){const reply=res;reply.type('html');res.json({message:req.query.value})}").length, 1);
  assert.equal(html("function route(req,res){const reply=res;reply.type('text/plain');res.send(req.query.value)}").length, 0);
  for (const choices of [["html", "text/plain"], ["text/plain", "html"]]) {
    assert.equal(html(`function route(req,res){if(req.query.choice){res.type('${choices[0]}')}else{res.type('${choices[1]}')}res.send(req.query.value)}`).length, 1);
    assert.equal(html(`function route(req,res){if(req.query.choice){res.type('${choices[0]}')}else{res.type('${choices[1]}')}res.json({message:req.query.value})}`).length, 1);
  }
  assert.equal(html("function route(req,res){const reply=res;if(req.query.choice){reply.type('text/plain')}else{res.type('text/plain')}reply.type('html');res.json({message:req.query.value})}").length, 1);
  assert.equal(html("function configure(reply){reply.type('html')}function route(req,res){configure(res);res.json({message:req.query.value})}").length, 1);
  assert.equal(html("function configure(reply,input){if(input){reply.type('html')}else{reply.type('text/plain')}}function route(req,res){configure(res,req.query.choice);res.json({message:req.query.value})}").length, 1);
});

test('dynamic MIME and duplicate append stay uncertain, while explicit removal restores defaults', () => {
  for (const prefix of ["res.type(req.query.mime);", "res.set(req.query.header,'text/plain');", "res.append('content-type','text/plain');"]) {
    const findings=html(`function route(req,res){${prefix}res.json({message:req.query.value})}`);
    assert.equal(findings.length,1,prefix);assert.equal(findings[0].confidence,'low');
  }
  assert.equal(html("function route(req,res){res.type('text/plain');res.removeHeader('content-type');res.send(req.query.value)}").length,1);
  assert.equal(html("function route(req,res){res.type('text/html');res.removeHeader('content-type');res.json({message:req.query.value})}").length,0);
  assert.equal(html("function route(req,res){res.type('html');res.statusCode=200;res.locals.name='fixed';res.json({message:req.query.value})}").length,1);
  assert.equal(html("function route(req,res){const reply=res;reply.send=replacement;res.send(req.query.value)}").length,0);
});


test('opaque response consumers cannot preserve a stale non-HTML exclusion', () => {
  for (const statement of ['configureExternally(res);', 'res.customHeaderPolicy();']) {
    const findings=html(`function route(req,res){res.type('text/plain');${statement}res.send(req.query.value)}`);
    assert.equal(findings.length,1);assert.equal(findings[0].confidence,'low');
  }
});


test('contained response aliases never retain a non-HTML MIME exclusion', () => {
  for (const body of [
    "const bag={reply:res};res.type('text/plain');if(req.query.flag){bag.reply.type('html')}else{res.type('text/plain')}res.send(req.query.message)",
    "res.type('text/plain');configureExternally({reply:res});res.send(req.query.message)",
    "const bag={};bag.reply=res;res.type('text/plain');configureExternally(bag);res.send(req.query.message)",
    "const replies=[res];res.type('text/plain');configureExternally(replies);res.send(req.query.message)",
  ]) {
    const findings=html(`export function route(req,res){${body}}`);
    assert.equal(findings.length,1,body);assert.equal(findings[0].confidence,'low');
  }
  const local="function configure(bag){bag.reply.type('html')}const policy={configure};export function route(req,res){res.type('text/plain');policy.configure({reply:res});res.send(req.query.message)}";
  assert.equal(html(local).length,1);
  // Direct lexical aliases stay in the supported model and retain the safe pair.
  assert.equal(html("function route(req,res){const reply=res;reply.type('text/plain');res.send(req.query.message)}").length,0);
});
