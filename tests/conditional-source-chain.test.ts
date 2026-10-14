import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { createReport, evaluateGate } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

type Files = Record<string, string>;
function run(texts: Files, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/owned-static-only', files, issues: [], complete: true, ignoredFiles: 0, totalBytes: files.reduce((sum, file) => sum + file.bytes, 0) };
  return runBuiltinAst(snapshot, false, limits);
}
function chain(): Files {
  return {
    'package.json': JSON.stringify({ dependencies: { mongodb: '^2.1.18' } }),
    'package-lock.json': JSON.stringify({ packages: { 'node_modules/mongodb': { version: '2.2.36' } } }),
    'entry.js': "const MC=require('mongodb').MongoClient;const setup=require('./setup');MC.connect('mongodb://owned-static-only',(err,db)=>setup(app,db));",
    'setup.js': "const Handler=require('./handler');function setup(app,db){const h=new Handler(db);app.get('/x',h.show)}module.exports=setup;",
    'handler.js': "const DAO=require('./dao').DAO;function Handler(db){const dao=new DAO(db);this.show=(req)=>{const term=req.query.term;dao.lookup(term)}}module.exports=Handler;",
    'dao.js': "function DAO(db){const col=db.collection('records');this.lookup=(term)=>{const selector=()=>({$where:`this.value > '${term}'`});col.find(selector())}}module.exports.DAO=DAO;",
    'loader.js': 'require(selectedExtension);',
  };
}
const noSql = (result: ReturnType<typeof run>) => result.findings.filter(f => f.ruleId === 'ast:nosql-input-sink');
const sql = (result: ReturnType<typeof run>) => result.findings.filter(f => f.ruleId === 'ast:sql-input-sink');
function partial(result: ReturnType<typeof run>) {
  assert.equal(result.status, 'partial');
  assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
}

test('conditional chain keeps bootstrap assumptions outside the actual input trace', () => {
  const result = run(chain()); partial(result);
  assert.equal(noSql(result).length, 1);
  const finding = noSql(result)[0];
  assert.equal(finding.confidence, 'low'); assert.equal(finding.kind, 'candidate');
  assert.equal(finding.staticFlow?.truncated, true);
  assert.ok(finding.staticContext?.items.some(item => item.kind === 'unresolved_cjs_dispatch' && item.location.path === 'entry.js'));
  assert.ok(finding.staticContext?.items.some(item => item.kind === 'constructor_continuation'));
  assert.ok(finding.staticContext?.items.some(item => item.kind === 'declared_callback_entry'));
  assert.ok(finding.staticContext?.items.some(item => item.kind === 'unqualified_mongo_origin'));
  const steps = finding.staticFlow!.steps;
  assert.equal(steps[0].role, 'source'); assert.equal(steps[0].location.path, 'handler.js');
  assert.ok(steps.some(step => step.role === 'parameter' && step.location.path === 'dao.js'));
  assert.ok(steps.some(step => step.role === 'return' && step.location.path === 'dao.js'));
  assert.equal(steps.at(-1)?.role, 'sink'); assert.equal(steps.at(-1)?.location.path, 'dao.js');
  assert.equal(steps.some(step => ['entry.js', 'setup.js'].includes(step.location.path)), false);
});

test('indexed ImportEquals producer and native loader mutations veto conditional discovery in both file orders', () => {
  for (const mutation of ["import ns = require('./dao');ns.DAO=replacement;", "import Module = require('node:module');Module._load=replacement;", "import mongo = require('mongodb');mongo.MongoClient.connect=replacement;"]) {
    for (const first of [false, true]) {
      const files = first ? { 'mutation.ts': mutation, ...chain() } : { ...chain(), 'mutation.ts': mutation };
      const result = run(files); partial(result); assert.equal(noSql(result).length, 0, mutation);
    }
  }
});

test('an exported alias cannot hide original constructor writes or escape', () => {
  for (const effect of ['DAO[Symbol.hasInstance]=custom;', 'DAO.prototype=custom;', 'opaque(DAO);']) {
    const files = chain(); files['dao.js'] = files['dao.js'].replace('module.exports.DAO=DAO;', `${effect}const Out=DAO;module.exports.DAO=Out;`);
    const result = run(files); partial(result); assert.equal(noSql(result).length, 0, effect);
  }
});

test('current conditional body can use the selected receiver snapshot but subsequent caller use is not closed', () => {
  const result = run({
    'app.js': "const inspect=require('./inspect');function Repo(){this.lookup=(term)=>db.query(term)}function route(req){const repo=new Repo();inspect(repo,req.query.first);repo.lookup(req.query.later)}",
    'inspect.js': 'function inspect(repo,term){repo.lookup(term)}module.exports=inspect;',
    'loader.js': 'require(selectedExtension);',
  });
  partial(result); assert.equal(sql(result).length, 1);
  const finding = sql(result)[0];
  assert.equal(finding.confidence, 'low'); assert.equal(finding.staticContext?.authority, 'conditional');
  assert.equal(finding.staticFlow?.truncated, true);
  assert.ok(finding.staticFlow!.steps.some(step => step.role === 'source' && step.location.path === 'app.js' && step.location.column === resultSourceColumn('req.query.first')));
  function resultSourceColumn(source: string) { return "const inspect=require('./inspect');function Repo(){this.lookup=(term)=>db.query(term)}function route(req){const repo=new Repo();inspect(repo,req.query.first);repo.lookup(req.query.later)}".indexOf(source) + 1; }
});

test('a benign possible body cannot certify the caller receiver still returns a fixed value', () => {
  const app = "const noop=require('./noop');function Repo(){this.get=(term)=>'fixed'}function route(req){const repo=new Repo();BOUNDARYdb.query(repo.get(req.query.term))}";
  const fixed = run({ 'app.js': app.replace('BOUNDARY', ''), 'noop.js': 'function noop(repo){}module.exports=noop;' });
  assert.equal(sql(fixed).length, 0);
  const unknown = run({ 'app.js': app.replace('BOUNDARY', 'noop(repo);'), 'noop.js': 'function noop(repo){}module.exports=noop;', 'loader.js': 'require(selectedExtension);' });
  partial(unknown); assert.equal(sql(unknown).length, 1);
  assert.equal(sql(unknown)[0].confidence, 'low'); assert.equal(sql(unknown)[0].staticFlow?.truncated, true);
});

test('opaque receiver effects reach owned callable captures instead of retaining a stale response MIME proof', () => {
  const app = "const noop=require('./noop');function Holder(res){this.leak=()=>res}function route(req,res){res.type('text/plain');const holder=new Holder(res);BOUNDARYres.send(req.query.message)}";
  const fixed = run({ 'app.js': app.replace('BOUNDARY', ''), 'noop.js': 'function noop(holder){}module.exports=noop;' });
  assert.equal(fixed.findings.filter(f => ['ast:html-input-sink', 'ast:response-input-sink'].includes(f.ruleId)).length, 0);
  const escaped = run({ 'app.js': app.replace('BOUNDARY', 'noop(holder);'), 'noop.js': 'function noop(holder){}module.exports=noop;', 'loader.js': 'require(selectedExtension);' });
  partial(escaped);
  assert.equal(escaped.findings.filter(f => f.ruleId === 'ast:response-input-sink').length, 1);
  const replaced = run({ 'app.js': app.replace('BOUNDARY', 'res.send=replacement;noop(holder);'), 'noop.js': 'function noop(holder){}module.exports=noop;', 'loader.js': 'require(selectedExtension);' });
  partial(replaced);
  assert.equal(replaced.findings.filter(f => ['ast:html-input-sink', 'ast:response-input-sink'].includes(f.ruleId)).length, 0); // Opaque exposure cannot revive a concrete response-member write.
});

test('context overflow retains conditional authority and a persistent incomplete gap without raising modeled limits', () => {
  const imports = Array.from({ length: 10 }, (_, index) => `const f${index}=require('./f${index}');`).join('');
  const calls = Array.from({ length: 10 }, (_, index) => `const v${index + 1}=f${index}(v${index});`).join('');
  const files: Files = { 'app.js': `${imports}function route(req){const v0=req.query.term;${calls}db.query(v10)}`, 'loader.js': 'require(selectedExtension);' };
  for (let index = 0; index < 10; index++) files[`f${index}.js`] = `function f${index}(value){return value}module.exports=f${index};`;
  const result = run(files); partial(result); assert.equal(sql(result).length, 1);
  const finding = sql(result)[0];
  assert.equal(finding.staticContext?.authority, 'conditional'); assert.equal(finding.staticContext?.items.length, 8);
  assert.equal(finding.staticContext?.truncated, true); assert.equal(finding.staticFlow?.truncated, true);
  assert.ok(result.analysisGaps?.reasonSummary?.rows.some(row => row.reason === 'module_export_unsupported' && Number(row.eventsObserved) > 0));
});

test('existing bounded flow cuts remain incomplete independently of conditional metadata', () => {
  for (const cap of [{ summaryWork: 0 }, { flowWork: 1 }, { callDepth: 0 }]) {
    const result = run(chain(), { ...FLOW_LIMITS, ...cap }); partial(result);
    assert.ok(result.analysisGaps?.reasonSummary?.rows.length);
  }
});
