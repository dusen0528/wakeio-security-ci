import test from 'node:test';
import assert from 'node:assert/strict';
import type { SourceSnapshot } from '../src/source/types.js';
import { runBuiltinAst } from '../src/source/ast.js';
import { createReport, evaluateGate, toAgentReport } from '../src/report.js';

const SETUP = "import { Hono } from 'hono';\nconst app = new Hono();\n";
const HTTP = 'ast:server-request';
function scan(texts: Record<string, string>) {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text,
    bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/owned-inert-hono-review', files,
    issues: [], ignoredFiles: 0, complete: true, totalBytes: files.reduce((n, file) => n + file.bytes, 0) };
  return runBuiltinAst(snapshot, false);
}
const outbound = (check: ReturnType<typeof scan>) => check.findings.filter(row => row.ruleId === HTTP);
const APP = SETUP + "app.get('/proxy', ctx => fetch(ctx.req.query('target')));\nexport default app;";

test('Hono independent review: runtime request-class imports revoke shared accessor proof across files', () => {
  for (const mutation of [
    "import { HonoRequest } from 'hono/request'; HonoRequest.prototype.query = () => 'fixed';",
    "import * as shared from 'hono/request'; shared.HonoRequest.prototype.query = () => 'fixed';",
    "const shared = require('hono/request'); shared.HonoRequest.prototype.query = () => 'fixed';",
    "const shared = await import('hono/request'); shared.HonoRequest.prototype.query = () => 'fixed';",
  ]) {
    const cases: Record<string, string>[] = [{ 'app.ts': mutation + '\n' + APP }, { 'app.ts': APP, 'shared.ts': mutation }];
    for (const texts of cases) {
      assert.equal(outbound(scan(texts)).length, 0,
        'observed shared request mutation must not receive the lexical Hono source certificate');
    }
  }
  const typeOnly = scan({ 'app.ts': APP,
    'types.ts': "import type { HonoRequest } from 'hono/request'; export type RequestAlias = HonoRequest;" });
  assert.equal(typeOnly.status, 'completed');
  assert.equal(outbound(typeOnly).length, 1, 'erased type-only import has no runtime request effect');
});

test('Hono independent review: later alias method mutations cannot erase previously read scalar input', () => {
  for (const mutation of ["alias.query = () => 'fixed';", 'delete alias.query;', 'alias.query++;', '++alias.query;']) {
    const text = SETUP + "app.get('/proxy', ctx => {\n const target = ctx.req.query('target');\n const alias = ctx.req;\n "
      + mutation + "\n fetch(target);\n});\nexport default app;";
    const check = scan({ 'app.ts': text }), findings = outbound(check);
    assert.equal(findings.length, 1, mutation);
    assert.ok(findings[0].staticFlow?.steps.some(step => step.role === 'source' && step.location.line === 4),
      'trace keeps the pre-mutation query read');
    const report = createReport([check], 'source', new Date(0)), agent = toAgentReport(report);
    assert.notEqual(evaluateGate(report, 'high').exitCode, 0, 'copied input does not become a clean scan');
    assert.equal(agent.findings[0].verification.state, 'not_run');
    assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
    assert.equal(agent.findings[0].remediation.state, 'not_verified');
  }
  const opaque = scan({ 'app.ts': SETUP + "app.get('/proxy', ctx => {const target=ctx.req.query('target');"
    + "opaque(ctx.req);fetch(target)});export default app;" });
  assert.equal(outbound(opaque).length, 1);
  assert.equal(opaque.status, 'partial', 'opaque request effects remain unresolved alongside prior input');
  assert.equal(evaluateGate(createReport([opaque], 'source', new Date(0)), 'none').exitCode, 2);
});

test('Hono independent review: request helper uses actual argument roles and fixed sink controls stay negative', () => {
  const helper = "function read(input) { return input.query('target'); }\n";
  const unsafe = scan({ 'app.ts': SETUP + helper
    + "app.get('/proxy', ctx => {const alias=ctx.req;fetch(read(alias));});export default app;" });
  assert.equal(outbound(unsafe).length, 1);
  assert.ok(outbound(unsafe)[0].staticFlow?.steps.some(step => step.role === 'source' && step.location.line === 3),
    'request read inside the helper remains the actual source position');
  const fixed = scan({ 'app.ts': SETUP + helper
    + "app.get('/proxy', ctx => {const target=read(ctx.req);fetch('https://fixed.example/owned',{body:target});});export default app;" });
  assert.equal(fixed.status, 'completed');
  assert.equal(outbound(fixed).length, 0, 'request input in payload does not control the destination');
  const local = scan({ 'app.ts': SETUP + helper
    + "app.get('/proxy', ctx => {const local={query:()=> 'https://fixed.example/owned'};fetch(read(local));});export default app;" });
  assert.equal(local.status, 'completed');
  assert.equal(outbound(local).length, 0, 'safe actual object does not borrow the registered Context role');
});

test('Hono independent review: observed Request and JSON parser mutations block only the pg data exclusion', () => {
  const app = SETUP + "import { Pool } from 'pg';\nconst db = new Pool();\n"
    + "app.post('/search', async ctx => {const payload=await ctx.req.json();"
    + "db.query('SELECT id FROM items WHERE name=$1',[payload.name]);});export default app;";
  for (const receiver of ['Request.prototype.json', 'JSON.parse', 'globalThis.Request.prototype.json', 'globalThis.JSON.parse']) {
    const mutation = `${receiver} = () => ({name:{toPostgres(){return 'owned';}}});`;
    const cases: Record<string, string>[] = [{ 'app.ts': mutation + '\n' + app }, { 'app.ts': app, 'shared.ts': mutation }];
    for (const texts of cases) {
      const check = scan(texts), rows = check.findings.filter(row => row.ruleId === 'ast:sql-input-sink');
      assert.equal(rows.length, 1, receiver + ' must revoke plain-data exclusion without erasing input');
      assert.equal(rows[0].kind, 'candidate');
      assert.equal(rows[0].confidence, 'low', 'observed intrinsic effects remain unresolved rather than a proven SQL injection');
      assert.equal(check.metrics?.sqlValuesOnlyExcluded, 0);
      const agent = toAgentReport(createReport([check], 'source', new Date(0)));
      assert.equal(agent.findings[0].verification.state, 'not_run');
      assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
    }
  }
});
