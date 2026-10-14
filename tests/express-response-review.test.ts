import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, RULESET_VERSION } from '../src/report.js';
import { compareReports, comparisonExitCode } from '../src/compare.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';
import type { SourceSnapshot } from '../src/source/types.js';

// Owned inert source strings, parsed by the trusted analyzer; never imported or executed.
const SHAPED = 'ast:response-input-sink';
const REGISTERED = 'ast:html-input-sink';
const SETUP = "import express from 'express';const app=express();\n";
const rows = (check: ReturnType<typeof scan>) => check.findings.filter(row => [SHAPED, REGISTERED].includes(row.ruleId));
function scan(text: string, path = 'src/route.ts') {
  const files = [{ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }];
  const snapshot: SourceSnapshot = { root: '/owned-inert-response-authority', files,
    issues: [], ignoredFiles: 0, complete: true, totalBytes: files[0].bytes };
  return runBuiltinAst(snapshot, false);
}
function unqualified(check: ReturnType<typeof scan>) {
  const found = rows(check);
  assert.ok(found.length > 0, 'uncertain response-shaped use remains reviewable');
  for (const row of found) {
    assert.equal(row.ruleId, SHAPED);
    assert.equal(row.severity, 'high');
    assert.equal(row.kind, 'candidate');
    assert.equal(row.confidence, 'low');
    assert.equal(row.title, 'Input-related value reaches a response-shaped call; dispatch and MIME unresolved');
    assert.match(row.description, /receiver|response/i);
    assert.match(row.description, /payload/i);
    assert.match(row.description, /MIME/i);
    assert.match(row.description, /origin|caller/i);
    assert.match(row.remediation, /verify|review|confirm/i);
    assert.match(row.remediation, /header|MIME|Content-Type/i);
    assert.match(row.remediation, /HTML/i);
  }
  return found;
}

test('generic functions and callbacks keep response-shape evidence without certifying Express HTML dispatch', () => {
  for (const text of [
    'function route(req,res){res.send(req.query.ownedResponseMarker)}',
    'queue.on("owned",(req,res)=>res.send(req.query.ownedResponseMarker));',
    'function route(req,res){const reply=res;reply.send(req.query.ownedResponseMarker)}',
    'function route(req,res){res.send(req.xhr)}',
    'function route(request,response){response.send(request.body.ownedResponseMarker)}',
  ]) {
    const check = scan(text);
    assert.equal(check.status, 'completed');
    assert.equal(unqualified(check).length, 1, text);
    assert.equal(evaluateGate(createReport([check], 'source', new Date(0)), 'high').exitCode, 1);
    assert.equal(evaluateGate(createReport([check], 'source', new Date(0)), 'none').exitCode, 0);
  }
});

test('qualified Express registration retains the established input/string and non-HTML controls', () => {
  for (const body of ['outgoing.send(incoming.query.message)',
    'const reply=outgoing;reply.send(incoming.query.message)']) {
    const check = scan(SETUP + `app.get('/owned',(incoming,outgoing)=>{${body}});`);
    assert.equal(check.status, 'completed');
    assert.equal(rows(check).length, 1, body);
    assert.equal(rows(check)[0].ruleId, REGISTERED);
    assert.equal(rows(check)[0].confidence, 'medium');
    assert.equal(rows(check)[0].kind, 'candidate');
  }
  const serialized = scan(SETUP + "app.get('/owned',(incoming,outgoing)=>outgoing.send(JSON.stringify({message:incoming.query.message})));" );
  assert.equal(rows(serialized).length, 1);
  assert.equal(rows(serialized)[0].ruleId, REGISTERED);
  assert.equal(rows(serialized)[0].confidence, 'low', 'qualified receiver does not upgrade unknown serialization flow');
  for (const body of ['outgoing.json({message:incoming.query.message})',
    'outgoing.send({message:incoming.query.message})',
    "outgoing.type('text/plain').send(incoming.query.message)"] ) {
    const check = scan(SETUP + `app.get('/owned',(incoming,outgoing)=>{${body}});`);
    assert.equal(check.status, 'completed');
    assert.equal(rows(check).length, 0, body);
  }
});

test('mixed actual contexts at one helper site cannot upgrade generic authority by analysis order', () => {
  const helper = 'function reply(res,value){res.send(value)}\n';
  const generic = 'function generic(req,res){reply(res,req.query.message)}\n';
  const registered = "app.get('/owned',(incoming,outgoing)=>reply(outgoing,incoming.query.message));\n";
  for (const body of [generic + registered, registered + generic]) {
    const check = scan(SETUP + helper + body);
    assert.equal(check.status, 'completed');
    const found = unqualified(check);
    assert.equal(found.length, 1, 'the helper sink is one row with conservative authority');
    assert.equal(found[0].location.line, 2);
  }
});

test('opaque response effects remain unresolved while a MIME-only branch retains registered authority', () => {
  for (const body of [
    "outgoing.type('text/plain');configureExternally(outgoing);outgoing.send(incoming.query.message)",
    "const bag={reply:outgoing};configureExternally(bag);outgoing.send(incoming.query.message)",
  ]) {
    const check = scan(SETUP + `app.get('/owned',(incoming,outgoing)=>{${body}});`);
    unqualified(check);
  }
  const branch = scan(SETUP + "app.get('/owned',(incoming,outgoing)=>{if(incoming.query.choice){outgoing.type('html')}else{outgoing.type('text/plain')}outgoing.send(incoming.query.message)});");
  assert.equal(rows(branch).length, 1);
  assert.equal(rows(branch)[0].ruleId, REGISTERED, 'both branches retain the same registered response binding');
  assert.equal(rows(branch)[0].confidence, 'low', 'MIME ambiguity does not become receiver ambiguity');
});

test('response authority follows bindings and does not depend on test paths or property spelling', () => {
  for (const path of ['src/controller.ts', 'test/req.xhr.ts']) {
    unqualified(scan('function route(req,res){res.send(req.query.message)}', path));
    const check = scan(SETUP + "app.get('/owned',(req,res)=>res.send(req.query.message));", path);
    assert.equal(rows(check).length, 1);
    assert.equal(rows(check)[0].ruleId, REGISTERED);
  }
  const local = scan('function render(req,res){res.send(req.query.message)}render({query:{message:"fixed"}},{send(value){}});');
  assert.equal(local.status, 'completed');
  assert.equal(rows(local).length, 0, 'a resolved safe actual local object is not freshly seeded as an HTTP response');
});

test('raw, JSON, agent, SARIF and advice preserve the same response rule and static-only authority', () => {
  const text = 'function route(req,res){res.send(req.query.ownedResponseMarker)}';
  const check = scan(text), raw = unqualified(check)[0];
  const report = createReport([check], 'source', new Date(0));
  const json = JSON.parse(JSON.stringify(report));
  const agent = toAgentReport(report, 'high'), sarif = toSarif(report);
  assert.equal(json.checks[0].findings[0].ruleId, raw.ruleId);
  assert.equal(json.checks[0].findings[0].confidence, 'low');
  assert.equal(agent.findings.length, 1);
  const finding = agent.findings[0];
  assert.equal(finding.ruleId, SHAPED);
  assert.equal(finding.confidence, 'low');
  assert.equal(finding.evidence.kind, 'candidate');
  assert.equal(finding.verification.state, 'not_run');
  assert.equal(finding.verification.vulnerabilityConfirmed, false);
  assert.equal(finding.remediation.state, 'not_verified');
  assert.deepEqual(finding.evidence.staticFlow, raw.staticFlow);
  assert.equal(agent.scanGate.exitCode, 1);
  assert.equal(finding.reachesFailOn, true);
  assert.equal(sarif.runs[0].results[0].ruleId, SHAPED);
  assert.ok(sarif.runs[0].tool.driver.rules.some(rule => rule.id === SHAPED));
  const markdown = toMarkdown(report, 'high');
  assert.ok(markdown.includes('Input\\-related value reaches a response\\-shaped call; dispatch and MIME unresolved'),
    'Markdown presents the uncertainty title with its existing inline escaping');
  assert.match(markdown, /Confidence: low/);
  assert.match(markdown, /receiver|caller/i);
  assert.ok(markdown.includes('First verify the receiver binding and caller origin'), 'human remediation starts with verification');
  const pair = { findingId: finding.findingId, checkIndex: finding.checkIndex };
  for (const selection of [undefined, pair]) {
    const { input } = projectAdviceContext(agent, false, selection);
    assert.equal(input.findings.length, 1);
    const card = input.findings[0];
    assert.equal(card.ruleId, SHAPED);
    assert.equal(card.confidence, 'low');
    assert.equal(card.evidenceKind, 'candidate');
    assert.equal(card.verification, 'not_run');
    assert.equal(card.recheckRoute, 'review_static_flow_or_budget');
    assert.equal(card.replayAvailable, false);
    assert.deepEqual(card.staticFlow?.roles, raw.staticFlow?.steps.map(step => step.role));
    assert.equal(input.scanGate.exitCode, 1);
    assert.equal(JSON.stringify(input).includes('ownedResponseMarker'), false);
    assert.equal(JSON.stringify(input).includes('src/route.ts'), false);
  }
});

test('response ruleset migration leaves comparison unverified rather than certifying an old HTML warning as fixed', () => {
  const check = scan('function route(req,res){res.send(req.query.message)}');
  assert.equal(RULESET_VERSION, '2026-10-14.2');
  const scope = { fingerprint: 'a'.repeat(64), ruleset: RULESET_VERSION, analysisBudget: check.analysisBudget };
  const current = createReport([check], 'source', new Date(0), scope);
  const legacy = createReport([{ ...check, findings: check.findings.map(row => {
    const { id, comparisonKey, ...rest } = row;
    return { ...rest, ruleId: REGISTERED };
  }) }], 'source', new Date(0), { ...scope, ruleset: '2026-10-14.1' });
  const finding = current.checks[0].findings[0], previous = legacy.checks[0].findings[0];
  assert.notEqual(finding.id, previous.id, 'rule identity is part of the deterministic finding ID');
  const comparison = compareReports(legacy, current);
  assert.equal(comparison.comparable, false);
  assert.ok(comparison.reasons.some(reason => /ruleset/i.test(reason)));
  assert.equal(comparison.summary.not_observed, 0);
  assert.ok(comparison.summary.unverified > 0);
  assert.equal(comparisonExitCode(comparison, 'high'), 2);
  assert.equal(comparisonExitCode(comparison, 'none'), 2);
  assert.equal(toAgentReport(current).findings[0].remediation.state, 'not_verified');
});
