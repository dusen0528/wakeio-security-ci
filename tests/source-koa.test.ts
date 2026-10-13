import test from 'node:test';
import assert from 'node:assert/strict';
import * as ts from 'typescript';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runBuiltinAst } from '../src/source/ast.js';
import { findSnapshotInputFlows } from '../src/source/dataflow.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import type { SourceSnapshot } from '../src/source/types.js';
import type { CheckResult, Finding } from '../src/contracts.js';
import { runSource } from '../src/source.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';

// Independently owned source bytes and semantic assertions. Root alone builds
// and executes these tests. No fixture/module/package/handler is ever executed.
const SQL = 'ast:sql-input-sink', HTTP = 'ast:server-request', CODE = 'ast:dynamic-code';
const MARKER = 'ownedKoaQueryMarker';
const SETUP = "import Application from 'koa';\nconst app = new Application();\n";
const fixtures = fileURLToPath(new URL('../../tests/fixtures/source-koa/', import.meta.url));
function scan(texts: string | Record<string, string>): CheckResult {
  const entries = typeof texts === 'string' ? { 'route.ts': texts } : texts;
  const files = Object.entries(entries).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/owned-data-only', files, issues: [], complete: true, ignoredFiles: 0,
    totalBytes: files.reduce((bytes, file) => bytes + file.bytes, 0) };
  return runBuiltinAst(snapshot, false);
}
function position(text: string, needle: string) {
  const index = text.indexOf(needle); assert.ok(index >= 0, 'Owned source location exists');
  const before = text.slice(0, index), lines = before.split('\n');
  return { line: lines.length, column: lines.at(-1)!.length + 1 };
}
function boundFinding(check: CheckResult, text: string, ruleId: string, sourceLine: number, sink: string, path = 'route.ts'): Finding {
  const findings = check.findings.filter(finding => finding.ruleId === ruleId);
  assert.equal(findings.length, 1, `${ruleId}: one actual owned source-to-sink observation`);
  const finding = findings[0], where = position(text, sink);
  assert.equal(finding.kind, 'candidate'); assert.equal(finding.location.path, path);
  assert.equal(finding.location.line, where.line); assert.equal(finding.location.column, where.column);
  assert.ok(finding.staticFlow, 'A generic unresolved sink-name candidate cannot substitute for Koa source authority');
  assert.equal(finding.staticFlow.sourceKind, undefined, 'Preserve existing HTTP trace convention; no filename/path origin invented');
  assert.ok(finding.staticFlow.steps.some(step => step.role === 'source' && step.location.path === path && step.location.line === sourceLine));
  const last = finding.staticFlow.steps.at(-1)!;
  assert.equal(last.role, 'sink'); assert.equal(last.location.line, where.line); assert.equal(last.location.column, where.column);
  return finding;
}
function withoutRequestAuthority(text: string, label = text) {
  const check = scan(text);
  assert.equal(check.findings.filter(finding => [SQL, HTTP].includes(finding.ruleId)).length, 0, label);
  // Existing generic unresolved eval syntax is allowed. It must not acquire a
  // fabricated Koa query trace from a body/state/next/plain-object name.
  assert.ok(check.findings.filter(finding => finding.ruleId === CODE).every(finding => !finding.staticFlow?.steps.some(step => step.role === 'source')), label);
}
const middleware = (body: string, parameter = 'incoming') => SETUP + `app.use((${parameter}, continuation) => {\n${body}\n});\n`;

test('Koa independent: exact ESM constructor registration recognizes renamed first parameters with completed SQL source evidence', () => {
  for (const factory of ["import Application from 'koa';", "import {default as Application} from 'koa';"]) {
    for (const name of ['incoming', 'scope', 'arbitrarilyRenamed']) {
      const text = `${factory}\nconst app = new Application();\napp.use((${name}, continuation) => {\n  db.query('SELECT ' + ${name}.request.query.${MARKER});\n});\n`;
      const check = scan(text); boundFinding(check, text, SQL, 4, 'db.query(');
      assert.equal(check.status, 'completed', 'A justified registration must not remain an unresolved external use gap');
      assert.equal(evaluateGate(createReport([check], 'source', new Date(0)), 'high').exitCode, 1);
    }
  }
});

test('Koa independent: registered query input reaches outbound fetch with actual property-read trace', () => {
  const text = middleware(`  fetch(incoming.query.${MARKER});`);
  const check = scan(text); boundFinding(check, text, HTTP, 4, 'fetch('); assert.equal(check.status, 'completed');
});

test('Koa independent: registered query input reaches eval without borrowing a generic unresolved candidate', () => {
  const text = middleware(`  eval(incoming.query.${MARKER});`);
  const check = scan(text); boundFinding(check, text, CODE, 4, 'eval('); assert.equal(check.status, 'completed');
});

test('Koa independent: verified query URL and incoming header aliases preserve source authority through immutable context and request aliases', () => {
  const reads = [`incoming.query.${MARKER}`, `incoming.request.query.${MARKER}`, `incoming.query['${MARKER}']`, `incoming['request']['query']['${MARKER}']`,
    'incoming.url', 'incoming.originalUrl', 'incoming.path', 'incoming.querystring',
    'incoming.request.url', 'incoming.request.originalUrl', 'incoming.request.path', 'incoming.request.querystring',
    "incoming.header['x-owned']", "incoming.headers['x-owned']", "incoming.request.header['x-owned']", "incoming.request.headers['x-owned']"];
  for (const read of reads) {
    const text = middleware(`  db.query('SELECT ' + ${read});`);
    boundFinding(scan(text), text, SQL, 4, 'db.query(');
  }
  for (const body of [`  const alias = incoming;\n  db.query('SELECT ' + alias.query.${MARKER});`,
    `  const wire = incoming.request;\n  db.query('SELECT ' + wire.query.${MARKER});`]) {
    const text = middleware(body); boundFinding(scan(text), text, SQL, 5, 'db.query(');
  }
});

test('Koa independent: local and middleware-parameter destructuring connect only approved context request properties', () => {
  for (const body of [`  const {query: terms} = incoming;\n  db.query('SELECT ' + terms.${MARKER});`,
    `  const {request: wire} = incoming;\n  const {query: terms} = wire;\n  db.query('SELECT ' + terms.${MARKER});`,
    `  const {request: {query: {${MARKER}: term}}} = incoming;\n  db.query('SELECT ' + term);`]) {
    const text = middleware(body), sourceLine = body.includes('const {query: terms} = wire') ? 5 : position(text, 'const {').line;
    boundFinding(scan(text), text, SQL, sourceLine, 'db.query(');
  }
  for (const binding of ['{query: terms}', '{request: {query: terms}}']) {
    const text = SETUP + `app.use((${binding}, continuation) => {\n  db.query('SELECT ' + terms.${MARKER});\n});\n`;
    boundFinding(scan(text), text, SQL, 3, 'db.query(');
  }
});

test('Koa independent: fixed statement values fixed URL and explicit input overwrites remain narrow negative controls', () => {
  for (const body of [`  db.query('SELECT id FROM products WHERE name = $1', [incoming.query.${MARKER}]);`,
    "  fetch('https://owned.invalid/resource');", "  db.query('SELECT 1');",
    `  let term = incoming.query.${MARKER};\n  term = 'fixed';\n  db.query('SELECT ' + term);`,
    `  const alias = incoming;\n  incoming = {query: {${MARKER}: 'fixed'}};\n  db.query('SELECT ' + incoming.query.${MARKER});`]) {
    const check = scan(middleware(body)); assert.equal(check.status, 'completed');
    assert.equal(check.findings.filter(finding => [SQL, HTTP].includes(finding.ruleId)).length, 0, body);
  }
});

test('Koa independent: plain ctx objects unrelated use methods and unbound context functions cannot create Koa request sources', () => {
  for (const text of [
    `export function handler(ctx: any) { db.query('SELECT ' + ctx.request.query.${MARKER}); }`,
    `export function handler(context: any) { fetch(context.query.${MARKER}); }`,
    `const app={use(value){}};app.use(incoming=>db.query('SELECT ' + incoming.query.${MARKER}));`,
    `const ctx={request:{query:{${MARKER}:'fixed'}}};db.query('SELECT ' + ctx.request.query.${MARKER});`,
    SETUP + `other.use(incoming=>fetch(incoming.query.${MARKER}));`,
    `import Application from 'not-koa';const app=new Application();app.use(incoming=>db.query('SELECT ' + incoming.query.${MARKER}));`,
  ]) withoutRequestAuthority(text);
});

test('Koa independent: type-only imports shadowed constructors and reassigned factory or application bindings revoke registration evidence', () => {
  const callback = `incoming=>db.query('SELECT ' + incoming.query.${MARKER})`;
  for (const text of [
    `import type Application from 'koa';const app=new Application();app.use(${callback});`,
    `import {type Application} from 'koa';const app=new Application();app.use(${callback});`,
    `import Application from 'koa';function setup(Application){const app=new Application();app.use(${callback});}`,
    SETUP + `function setup(app){app.use(${callback});}`,
    `import Application from 'koa';let Factory=Application;Factory=Other;const app=new Factory();app.use(${callback});`,
    `import Application from 'koa';let app=new Application();app=other;app.use(${callback});`,
    `import Application from 'koa';const app=Application();app.use(${callback});`,
  ]) withoutRequestAuthority(text);
});

test('Koa independent: use prototype request-context mutation and opaque escapes cannot retain stale source authority through aliases', () => {
  const callback = `incoming=>db.query('SELECT ' + incoming.query.${MARKER})`;
  for (const change of ['app.use = replacement;', 'const alias = app;alias.use = replacement;',
    'Application.prototype.use = replacement;', "Object.defineProperty(app,'use',{value:replacement});",
    'opaque(app);', 'const bag={app};opaque(bag);', 'const Factory=Application;Factory.prototype.use=replacement;',
    'app.context.query = fixed;', 'app.request.query = fixed;', "Object.defineProperty(app.context,'query',{get(){return fixed}});"]) {
    withoutRequestAuthority(SETUP + change + `app.use(${callback});`, change);
  }
});

test('Koa independent: immutable named middleware context aliases work while next and unrelated callbacks remain unseeded', () => {
  for (const declaration of [`function handler(incoming, continuation){db.query('SELECT ' + incoming.query.${MARKER})}`,
    `const handler=(incoming, continuation)=>db.query('SELECT ' + incoming.query.${MARKER});`,
    `const original=(incoming, continuation)=>db.query('SELECT ' + incoming.query.${MARKER});const handler=original;`]) {
    const text = SETUP + declaration + '\napp.use(handler);\n';
    boundFinding(scan(text), text, SQL, 3, 'db.query(');
  }
  for (const text of [middleware(`  db.query('SELECT ' + continuation.query.${MARKER});`),
    SETUP + `app.use((incoming, request)=>db.query('SELECT ' + request.query.${MARKER}));`,
    SETUP + `app.on('event', incoming=>db.query('SELECT ' + incoming.query.${MARKER}));`,
    SETUP + `arbitrary(incoming=>db.query('SELECT ' + incoming.query.${MARKER}));`,
    SETUP + `let handler=incoming=>db.query('SELECT ' + incoming.query.${MARKER});handler=other;app.use(handler);`,
    SETUP + `app.use(factory(incoming=>db.query('SELECT ' + incoming.query.${MARKER})));`,
  ]) withoutRequestAuthority(text);
  const helper = `function select(value){db.query('SELECT ' + value)}\n`;
  const text = SETUP + helper + `app.use(incoming=>select(incoming.query.${MARKER}));\n`;
  boundFinding(scan(text), text, SQL, 4, 'db.query(');
});

test('Koa independent: response body outgoing headers state params and unmodeled parsed body never become automatic request roots', () => {
  for (const read of ['incoming.body', 'incoming.response.body', 'incoming.response.header.secret', 'incoming.response.headers.secret',
    'incoming.state.secret', 'incoming.params.id', 'incoming.request.body.secret', 'incoming.request.params.id']) {
    withoutRequestAuthority(middleware(`  db.query('SELECT ' + ${read});\n  fetch(${read});\n  eval(${read});`), read);
  }
  for (const binding of ['{body: value}', '{state: {secret: value}}', '{response: {body: value}}']) {
    withoutRequestAuthority(SETUP + `app.use((${binding}, continuation)=>db.query('SELECT ' + value));`, binding);
  }
});

test('Koa independent: source-only public scan and four-format redaction retain paired fixture gates while incomplete indexing and real missing modules keep gaps', async () => {
  const vulnerableText = await readFile(join(fixtures, 'vulnerable/app.js'), 'utf8');
  const fixedText = await readFile(join(fixtures, 'fixed/app.js'), 'utf8');
  const positive = scan({ 'app.js': vulnerableText });
  for (const [rule, sink] of [[SQL, 'db.query('], [HTTP, 'fetch('], [CODE, 'eval(']]) boundFinding(positive, vulnerableText, rule, 4, sink, 'app.js');
  assert.equal(positive.status, 'completed'); assert.equal(scan({ 'app.js': fixedText }).findings.length, 0);
  const top = await mkdtemp(join(tmpdir(), 'wakeio-koa-reports-'));
  try {
    for (const mode of ['vulnerable', 'fixed'] as const) {
      const checks = await runSource({ root: join(fixtures, mode), tools: [] });
      const report = createReport(checks, 'source', new Date(0));
      assert.equal(evaluateGate(report, 'high').exitCode, mode === 'vulnerable' ? 1 : 0);
      const out = join(top, mode); await writeReports(report, out);
      for (const text of [JSON.stringify(report), JSON.stringify(toAgentReport(report)), toMarkdown(report), JSON.stringify(toSarif(report)),
        ...await Promise.all(['report.json', 'agent-report.json', 'report.md', 'report.sarif'].map(name => readFile(join(out, name), 'utf8')))]) {
        assert.equal(text.includes(MARKER), false); assert.equal(text.includes(vulnerableText), false);
      }
    }
  } finally { await rm(top, { recursive: true, force: true }); }
  const parsed = ts.createSourceFile('route.ts', middleware(`  db.query('SELECT ' + incoming.query.${MARKER});`), ts.ScriptTarget.Latest, true);
  const limited = findSnapshotInputFlows([parsed], { ...FLOW_LIMITS, indexWork: 1 });
  assert.equal(limited.metrics.indexComplete, false); assert.ok(limited.reasons.includes('index_work_limit'));
  assert.ok(limited.uses.every(use => !(use.argumentFlows ?? []).some(flow => flow.staticFlow?.steps.some(step => step.role === 'source'))));
  const broken = scan("import {read} from './missing.js';\n" + middleware(`  db.query('SELECT ' + read(incoming.query.${MARKER}));`));
  assert.equal(broken.status, 'partial'); assert.equal(evaluateGate(createReport([broken], 'source', new Date(0)), 'none').exitCode, 2);
  const crossFile = scan({ 'owner.ts': SETUP, 'other.ts': `app.use(incoming=>db.query('SELECT ' + incoming.query.${MARKER}));` });
  assert.equal(crossFile.findings.filter(finding => finding.ruleId === SQL).length, 0, 'Script-global app names cannot borrow another file binding');
});
