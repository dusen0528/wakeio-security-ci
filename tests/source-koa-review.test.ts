import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import type { SourceSnapshot } from '../src/source/types.js';
import type { CheckResult } from '../src/contracts.js';

// Independently authored source-as-data only. These fixtures never import or
// execute Koa, a target module, a request handler, a database or a server.
function scan(files: Record<string, string>): CheckResult {
  const inputs = Object.entries(files).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/owned-koa-review-data', files: inputs, issues: [], complete: true, ignoredFiles: 0,
    totalBytes: inputs.reduce((size, input) => size + input.bytes, 0) };
  return runBuiltinAst(snapshot, false);
}
function koaSources(check: CheckResult) {
  // An old generic unresolved sink candidate is not evidence of newly bound
  // Koa HTTP input. All callback parameter names avoid req/request heuristics.
  return check.findings.filter(finding => finding.ruleId === 'ast:sql-input-sink'
    && finding.staticFlow?.steps.some(step => step.role === 'source'));
}

const originalNegatives: Array<{ id: string; files: Record<string, string> }> = [
  { id: 'esm-instance-escape-constructor-alias', files: {
    'entry.js': "import Koa from 'koa';\nimport { configure } from './plugin.js';\nconst Constructor = Koa;\nconst application = new Constructor();\nconfigure(application);\nconst middleware = c => database.query(c.request.query.term);\napplication.use(middleware);\n",
    'plugin.js': 'export function configure(value) { foreignCustomization(value); }\n',
  } },
  { id: 'prototype-context-customization', files: {
    'entry.js': "import Koa from 'koa';\nconst application = new Koa();\nObject.defineProperty(application.context, 'request', { get() { return { query: { term: 'fixed' } }; } });\napplication.use(c => database.query(c.request.query.term));\n",
  } },
  { id: 'second-use-argument-is-not-middleware', files: {
    'entry.js': "import Koa from 'koa';\nconst application = new Koa();\nconst first = async (c, next) => next();\nconst second = c => database.query(c.request.query.term);\napplication.use(first, second);\nsecond({ request: { query: { term: 'SELECT 1' } } });\n",
  } },
  { id: 'computed-registration-authority', files: {
    'entry.js': "import Koa from 'koa';\nconst application = new Koa();\nconst method = 'use';\nconst middleware = c => database.query(c.request.query.term);\napplication[method](middleware);\n",
  } },
  { id: 'unregistered-named-function-fixed-actual', files: {
    'entry.js': "import Koa from 'koa';\nconst application = new Koa();\nfunction middleware(c) { database.query(c.request.query.term); }\nmiddleware({ request: { query: { term: 'SELECT 1' } } });\n",
  } },
  { id: 'relative-unrelated-constructor', files: {
    'entry.js': "import Koa from './local-koa.js';\nconst application = new Koa();\napplication.use(c => database.query(c.request.query.term));\n",
    'local-koa.js': "export default class Koa { use(callback) { callback({ request: { query: { term: 'SELECT 1' } } }); } }\n",
  } },
];

test('Koa review: immutable constructor aliases and named registered middleware retain real query source evidence', () => {
  const text = "import Koa from 'koa';\nconst Constructor = Koa;\nconst application = new Constructor();\nconst middleware = c => database.query(c.request.query.term);\napplication.use(middleware);\n";
  const check = scan({ 'entry.js': text }), findings = koaSources(check);
  assert.equal(check.status, 'completed'); assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'candidate');
  assert.ok(findings[0].staticFlow!.steps.some(step => step.role === 'source' && step.location.path === 'entry.js' && step.location.line === 4));
  assert.equal(findings[0].staticFlow!.steps.at(-1)!.role, 'sink');
});

test('Koa review: six frozen unregistered mutated escaped and unrelated source fixtures never acquire HTTP query authority', () => {
  for (const fixture of originalNegatives) assert.equal(koaSources(scan(fixture.files)).length, 0, fixture.id);
});

test('Koa review: inline constructed instance escapes and prototype mutation revoke shared registration authority', () => {
  for (const change of ['opaque(new Koa());', 'Object.getPrototypeOf(new Koa()).use = () => {};']) {
    const text = `import Koa from 'koa';\n${change}\nconst app = new Koa();\napp.use(c => database.query(c.request.query.term));\n`;
    assert.equal(koaSources(scan({ 'entry.js': text })).length, 0, change);
  }
});

test('Koa review: escaped use return identities cannot authenticate a later middleware after shared prototype replacement', () => {
  for (const change of ['opaque(app.use(c => {}));', 'Object.getPrototypeOf(app.use(c => {})).use = () => {};']) {
    const text = `import Koa from 'koa';\nconst app = new Koa();\n${change}\napp.use(c => database.query(c.query.term));\n`;
    assert.equal(koaSources(scan({ 'entry.js': text })).length, 0, change);
  }
});

test('Koa review: unsupported runtime namespace imports revoke shared prototype authority in the collected snapshot', () => {
  const fixtures: Array<Record<string, string>> = [
    { 'entry.js': "import Koa from 'koa';\nimport * as other from 'koa';\nother.default.prototype.use = () => {};\nconst app = new Koa();\napp.use(c => database.query(c.query.term));\n" },
    { 'entry.js': "import Koa from 'koa';\nconst app = new Koa();\napp.use(c => database.query(c.query.term));\n",
      'customization.js': "import * as other from 'koa';\nother.default.prototype.use = () => {};\n" },
    { 'entry.js': "import Koa from 'koa';\nrequire(('koa')).prototype.use = () => {};\nconst app = new Koa();\napp.use(c => database.query(c.query.term));\n" },
    { 'entry.ts': "import Koa from 'koa';\nrequire(('koa' as string)).prototype.use = () => {};\nconst app = new Koa();\napp.use(c => database.query(c.query.term));\n" },
  ];
  for (const files of fixtures) assert.equal(koaSources(scan(files)).length, 0);
});
