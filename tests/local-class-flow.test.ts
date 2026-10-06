import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function run(texts: Record<string, string>, complete = true, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries(texts).map(([path, text]) => ({
    path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false,
  }));
  const snapshot: SourceSnapshot = {
    root: '/never-execute', files, issues: [], complete, ignoredFiles: 0,
    totalBytes: files.reduce((sum, file) => sum + file.bytes, 0),
  };
  return runBuiltinAst(snapshot, false, limits);
}
const sql = (check: ReturnType<typeof run>) => check.findings.filter(finding => finding.ruleId === 'ast:sql-input-sink');
const source = (body = "return db.query('SELECT * FROM records WHERE term = ' + term)", extra = '', ctor = '') =>
  `class Repository { ${ctor} search(term) { ${body} } } const repository = new Repository(); ${extra}
   function route(req) { return repository.search(req.query.localClassInputMarker); }`;

test('closed local class instance carries actual request input to the original SQL sink', () => {
  for (const extension of ['js', 'ts']) for (const ctor of ['', 'constructor() {}']) {
    const check = run({ [`app.${extension}`]: source(undefined, '', ctor) });
    assert.equal(check.status, 'completed');
    const findings = sql(check);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].confidence, 'medium');
    assert.equal(findings[0].kind, 'candidate');
    assert.equal(findings[0].location.path, `app.${extension}`);
    assert.ok(findings[0].staticFlow?.steps.some(step => step.role === 'call'));
    assert.ok(findings[0].staticFlow?.steps.some(step => step.role === 'parameter'));
    assert.equal(findings[0].staticFlow?.steps.at(-1)?.role, 'sink');
    assert.equal(findings[0].staticFlow?.truncated, false);
    const report = createReport([check], 'source', new Date());
    assert.equal(evaluateGate(report, 'high').exitCode, 1);
    for (const rendered of [JSON.stringify(report), JSON.stringify(toAgentReport(report)), toMarkdown(report), JSON.stringify(toSarif(report))]) {
      assert.ok(!rendered.includes('localClassInputMarker'));
    }
  }
});

test('local class parameterized SQL, fixed actuals, and unused tainted actuals stay clean', () => {
  for (const text of [
    source("return db.query('SELECT * FROM records WHERE term = ?', [term])"),
    source("return db.query('SELECT 1')"),
    source().replace('req.query.localClassInputMarker', "'fixed'"),
    'class Repository { search(req) { return db.query(req.query.sql); } } const repository = new Repository(); function route(req) { repository.search({query: {sql: "SELECT 1"}}); }',
  ]) {
    const check = run({ 'app.js': text });
    assert.equal(check.status, 'completed');
    assert.equal(sql(check).length, 0);
    assert.ok(Number(check.metrics?.resolvedCalls) > 0);
  }
});

test('local class scalar returns and ordinary helper calls preserve argument and return traces', () => {
  const returned = run({ 'app.js': source('return term').replace('return repository.search(', 'return db.query(repository.search(').replace('InputMarker);', 'InputMarker));') });
  assert.equal(sql(returned).length, 1);
  assert.equal(sql(returned)[0].confidence, 'medium');
  assert.ok(sql(returned)[0].staticFlow?.steps.some(step => step.role === 'return'));
  const helper = run({ 'app.js': 'function execute(term) { db.query(term); }' + source('return execute(term)') });
  assert.equal(sql(helper).length, 1);
  assert.equal(sql(helper)[0].staticFlow?.steps.filter(step => step.role === 'parameter').length, 2);
});

test('SQL-shaped local class method names do not become security sinks', () => {
  for (const method of ['query', 'execute', 'raw']) {
    const check = run({ 'app.js': `class Repository { ${method}(term) { return term; } } const repository = new Repository(); function route(req) { repository.${method}(req.query.sql); }` });
    assert.equal(check.status, 'completed');
    assert.equal(sql(check).length, 0);
    assert.ok(Number(check.metrics?.resolvedCalls) > 0);
  }
});

test('async method bodies and independent closed instances retain precise input contexts', () => {
  const text = source().replace('search(term)', 'async search(term)').replace('function route(req)', 'const second = new Repository(); function route(req)')
    .replace('return repository.search(', "second.search('fixed'); repository.search(req.query.localClassInputMarker); return repository.search(");
  const check = run({ 'app.js': text });
  assert.equal(check.status, 'completed');
  assert.equal(sql(check).length, 1);
  assert.equal(sql(check)[0].confidence, 'medium');
  assert.ok(Number(check.metrics?.summariesCached) > 0);
  assert.deepEqual(run({ 'app.js': text }), check);
});

test('instance mutation, aliasing, escape, detached calls, and prototype access veto local dispatch', () => {
  for (const extra of [
    'repository.search = replacement;', 'delete repository.search;', 'repository.deep.value = replacement;',
    'const alias = repository;', 'const {search} = repository;', 'const detached = repository.search;',
    'consume(repository);', 'const container = {repository};', 'Object.setPrototypeOf(repository, replacement);',
    'Object.defineProperty(repository, "search", {value: replacement});', 'repository["search"](input);',
    'Repository.prototype.search = replacement;', 'consume(Repository);', 'const Alias = Repository;',
    'const second = new Repository(); consume(second);', 'new Repository();',
    'const second = new Repository(); Object.getPrototypeOf(second).search = replacement;',
    'export {repository};', 'export {Repository};', 'export {repository as exposed};', 'export {Repository as Exposed};',
    'eval(dynamicCode);', 'const dynamic = Function(dynamicCode);', 'with (unknownObject) { repository.search(input); }',
  ]) {
    const check = run({ 'app.js': source(undefined, extra) });
    assert.equal(sql(check).length, 0, extra);
    assert.equal(Number(check.metrics?.resolvedCalls), 0, extra);
    assert.ok(Number(check.metrics?.unsupportedCalls) > 0, extra);
  }
});

test('unsupported class shapes never manufacture local method identity', () => {
  for (const text of [
    source(undefined, '', 'constructor() { return replacement; }'),
    source(undefined, '', 'constructor() { this.search = replacement; }'),
    source(undefined, '', 'constructor() { this.label = "fixed"; }'),
    source().replace('class Repository {', 'class Repository extends Base {'),
    source().replace('class Repository {', 'class Repository { get value() { return replacement; }'),
    source().replace('class Repository {', 'class Repository { field = replacement;'),
    source().replace('class Repository {', 'class Repository { static {}'),
    source().replace('search(term)', '*search(term)'),
    source().replace('search(term)', 'static search(term)'),
    source().replace('search(term)', '["search"](term)'),
    source().replace('search(term)', 'search(this: Repository, term)'),
    source().replace('search(term)', 'search(@decorate term)'),
    source().replace('return db.query', 'this.hidden; return db.query'),
    source().replace('return db.query', '(() => this.hidden)(); return db.query'),
    source().replace('const repository', 'let repository'),
    source().replace('const repository', 'export const repository'),
    source().replace('class Repository', 'export class Repository'),
    source().replace('new Repository()', 'new Repository(argument)'),
    source().replace('repository.search(req', 'repository?.search(req'),
    source().replace('repository.search(req', 'repository.search?.(req'),
    source().replace('class Repository', 'const Repository = class').replace('} const repository', '}; const repository'),
  ]) {
    const check = run({ 'app.ts': text });
    assert.equal(sql(check).length, 0);
    assert.equal(Number(check.metrics?.resolvedCalls), 0);
  }
});

test('rejected class summaries cannot erase actual input at a downstream sink', () => {
  for (const extra of ['consume(repository);', 'repository.search = replacement;', 'Repository.prototype.search = replacement;', 'export {repository};']) {
    const text = source("return 'SELECT 1'", extra).replace('return repository.search(', 'return db.query(repository.search(').replace('InputMarker);', 'InputMarker));');
    const check = run({ 'app.js': text });
    assert.equal(sql(check).length, 1, extra);
    assert.equal(sql(check)[0].confidence, 'low', extra);
    assert.equal(sql(check)[0].staticFlow?.steps.some(step => step.role === 'parameter'), false, extra);
  }
});

test('local proof does not cross imports, global script files, nested declarations, or receiver shadowing', () => {
  const cases: Record<string, string>[] = [
    { 'entry.ts': "import { Repository } from './repository.js'; const repository = new Repository(); function route(req) { repository.search(req.query.sql); }", 'repository.ts': 'export class Repository { search(term) { db.query(term); } }' },
    { 'entry.js': 'const repository = new Repository(); function route(req) { repository.search(req.query.sql); }', 'repository.js': 'class Repository { search(term) { db.query(term); } }' },
    { 'entry.js': 'function route(req) { class Repository { search(term) { db.query(term); } } const repository = new Repository(); repository.search(req.query.sql); }' },
    { 'entry.js': source().replace('return repository.search(req.query.localClassInputMarker);', 'const repository = {search(term) { return term; }}; return repository.search(req.query.localClassInputMarker);') },
    { 'entry.js': 'const repository = new Repository(); class Repository { search(term) { db.query(term); } } function route(req) { repository.search(req.query.sql); }' },
  ];
  for (const texts of cases) {
    const check = run(texts);
    assert.equal(sql(check).length, 0);
    assert.equal(Number(check.metrics?.resolvedCalls), 0);
  }
});

test('local method dispatch remains bounded and unavailable for incomplete source snapshots', () => {
  for (const limits of [{...FLOW_LIMITS, indexWork: 1}, {...FLOW_LIMITS, flowWork: 1}, {...FLOW_LIMITS, functions: 1}, {...FLOW_LIMITS, summaryWork: 0}, {...FLOW_LIMITS, callDepth: 0}]) {
    const check = run({ 'app.js': source() }, true, limits);
    assert.equal(check.status, 'partial');
    assert.equal(sql(check).some(finding => finding.confidence === 'medium'), false);
    assert.equal(evaluateGate(createReport([check], 'source', new Date()), 'none').exitCode, 2);
  }
  const incomplete = run({ 'app.js': source() }, false);
  // Collection coverage is reported by the outer source check. Within this AST
  // check an unsupported local call stays a limitation, never a safe summary.
  assert.equal(sql(incomplete).length, 0);
  assert.equal(Number(incomplete.metrics?.resolvedCalls), 0);
  assert.ok(Number(incomplete.metrics?.unsupportedCalls) > 0);
});
