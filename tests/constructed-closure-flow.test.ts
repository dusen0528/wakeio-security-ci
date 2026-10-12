import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { createReport, evaluateGate } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function run(texts: Record<string, string>, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/never-execute', files, issues: [], complete: true, ignoredFiles: 0, totalBytes: files.reduce((sum, file) => sum + file.bytes, 0) };
  return runBuiltinAst(snapshot, false, limits);
}
const sql = (result: ReturnType<typeof run>) => result.findings.filter(f => f.ruleId === 'ast:sql-input-sink');
const nosql = (result: ReturnType<typeof run>) => result.findings.filter(f => f.ruleId === 'ast:nosql-input-sink');
const dao = "const DAO=function(db){this.lookup=(term)=>{db.query(term)}};module.exports.DAO=DAO;";

test('actual local and canonical CJS constructor-owned arrows carry formal input to the real sink', () => {
  const cases: Record<string, string>[] = [
    { 'app.js': "function Repository(db){this.lookup=(term)=>{db.query(term)}}function route(req){const repo=new Repository(db);repo.lookup(req.query.term)}" },
    { 'app.js': "const DAO=require('./dao').DAO;function route(req){const repo=new DAO(db);repo.lookup(req.query.term)}", 'dao.js': dao },
  ];
  for (const texts of cases) {
    const result = run(texts);
    assert.equal(result.status, 'partial'); // Independently seeded owned root lacks the actual captured DB frame.
    assert.equal(sql(result).length, 1);
    assert.equal(sql(result)[0].confidence, 'medium');
    assert.ok(sql(result)[0].staticFlow?.steps.some(step => step.role === 'parameter'));
    assert.equal(sql(result)[0].staticFlow?.truncated, false);
  }
});

test('constructor actual capture is lexical rather than same-spelling caller input', () => {
  const result = run({ 'app.js': "function Repository(req){this.lookup=()=>{db.query(req.query.term)}}function route(req){const repo=new Repository({query:{term:'fixed'}});repo.lookup()}" });
  assert.equal(sql(result).length, 0);
  const omitted = run({ 'app.js': "function Repository(req){this.lookup=()=>{db.query(req.query.term)}}function route(req){const repo=new Repository();repo.lookup()}" });
  assert.equal(sql(omitted).length, 0);
  assert.equal(omitted.status, 'partial');
  assert.equal(evaluateGate(createReport([omitted], 'source', new Date()), 'none').exitCode, 2);
});

test('local nested closure return preserves actual source, operator origin and dispatch sink across branch joins', () => {
  const result = run({
    'app.js': "import * as MarsDB from 'marsdb';const col=new MarsDB.Collection('items');const DAO=require('./dao').DAO;function route(req){const repo=new DAO();col.find(repo.criteria('fixed',req.query.threshold))}",
    'dao.js': "const DAO=function(){this.criteria=(userId,threshold)=>{const criteria=()=>{if(threshold)return {$where:`this.value > '${threshold}'`};return {userId:userId}};return criteria()}};module.exports.DAO=DAO;",
  });
  assert.equal(result.status, 'completed');
  assert.equal(nosql(result).length, 1);
  assert.match(nosql(result)[0].title, /JavaScript selector/);
  assert.equal(nosql(result)[0].location.path, 'dao.js');
  assert.equal(nosql(result)[0].staticFlow?.steps[0].location.path, 'app.js');
  assert.equal(nosql(result)[0].staticFlow?.steps.at(-1)?.location.path, 'app.js');
  assert.equal(nosql(result)[0].staticFlow?.steps.at(-1)?.role, 'sink');
  assert.ok(nosql(result)[0].staticFlow?.steps.some(step => step.role === 'return'));
  assert.equal(nosql(result)[0].staticFlow?.truncated, false);
});

test('registered owned arrow carries its actual captured repository into a request-shaped entry', () => {
  const result = run({
    'app.js': "const Handler=require('./handler');function setup(app){const handler=new Handler();app.get('/lookup',handler.display)}setup(app)",
    'handler.js': "const DAO=require('./dao').DAO;function Handler(){const dao=new DAO(db);this.display=(req,res)=>{dao.lookup(req.query.term)}}module.exports=Handler;",
    'dao.js': dao,
  });
  assert.equal(result.status, 'partial'); // Actual callback has a frame; the independently inventoried owned root does not.
  assert.equal(sql(result).length, 1);
  assert.equal(sql(result)[0].location.path, 'dao.js');
  assert.ok(sql(result)[0].staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'handler.js'));
});

test('closed default CJS function call can allocate a handler without weakening ordinary constructor calls', () => {
  const result = run({
    'app.js': "const setup=require('./setup');setup(app)",
    'setup.js': "const Handler=require('./handler');const setup=(app)=>{const handler=new Handler();app.get('/lookup',handler.display)};module.exports=setup;",
    'handler.js': "function Handler(){this.display=(req)=>{db.query(req.query.term)}}module.exports=Handler;",
  });
  assert.equal(sql(result).length, 1);
  assert.equal(sql(result)[0].staticFlow?.truncated, false);
});

test('no-new guard runs in a certified allocation context, and constructor mutation/escape vetoes it', () => {
  const guarded = "function Repository(){if(false===(this instanceof Repository)){return new Repository()}this.lookup=(term)=>db.query(term)}";
  const positive = run({ 'app.js': guarded + "function route(req){const repo=new Repository();repo.lookup(req.query.term)}" });
  assert.equal(sql(positive).length, 1);
  assert.doesNotMatch(String(positive.metrics?.incompleteReasons), /summary_cycle/);
  for (const effect of ["Repository[Symbol.hasInstance]=custom;", "Repository.prototype=custom;", "opaque(Repository);", "Function.prototype[Symbol.hasInstance]=custom;"]) {
    const result = run({ 'app.js': guarded + effect + "function route(req){const repo=new Repository();repo.lookup(req.query.term)}" });
    assert.equal(sql(result).length, 0, effect);
    assert.equal(result.status, 'partial', effect);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2, effect);
  }
});

test('separate allocations and local captures do not reuse another context source', () => {
  const result = run({ 'app.js': "function Repository(term){this.lookup=()=>db.query(term)}function route(req){const safe=new Repository('fixed');const risky=new Repository(req.query.term);safe.lookup();risky.lookup()}" });
  assert.equal(sql(result).length, 1);
  assert.equal(sql(result)[0].staticFlow?.truncated, false);
});

test('actual constructor and closure analysis remains bounded', () => {
  const text = "function Repository(){this.lookup=(term)=>db.query(term)}function route(req){const repo=new Repository();repo.lookup(req.query.term)}";
  for (const cap of [{ callDepth: 0 }, { summaryWork: 0 }, { flowWork: 1 }]) {
    const result = run({ 'app.js': text }, { ...FLOW_LIMITS, ...cap });
    assert.equal(result.status, 'partial');
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('mutable captured closure cannot silently return a clean selector through fresh-name analysis', () => {
  const result = run({ 'app.js': "import * as MarsDB from 'marsdb';const col=new MarsDB.Collection('records');function route(req){let threshold=req.query.threshold;const criteria=()=>({$where:threshold});threshold+='';col.find(criteria())}" });
  assert.equal(result.status, 'partial');
  assert.equal(nosql(result).length, 1);
  assert.equal(nosql(result)[0].confidence, 'low');
  assert.equal(nosql(result)[0].staticFlow?.truncated, true);
  assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
});

test('owned callable and each actual are selected before later argument mutations', () => {
  for (const invocation of ["let term=req.query.term;repo.lookup(term,term='fixed')", "repo.lookup(req.query.term,(repo.lookup=safe))"]) {
    const result = run({ 'app.js': "function Repository(){this.lookup=(term)=>db.query(term)}function route(req){const repo=new Repository();" + invocation + '}' });
    assert.equal(sql(result).length, 1, invocation);
    assert.equal(sql(result)[0].staticFlow?.truncated, false);
  }
});

test('constructor changes through any imported consumer veto actual new-guard proof in both orders', () => {
  for (const key of ['', 'Ctor']) for (const reversed of [false, true]) for (const effect of ['Ctor[Symbol.hasInstance]=custom', 'Ctor.prototype=custom', 'opaque(Ctor)']) {
    const load = key ? "require('./ctor').Ctor" : "require('./ctor')";
    const entries: Array<[string, string]> = [
      ['app.js', `const Ctor=${load};function route(req){const object=new Ctor();object.lookup(req.query.term)}`],
      ['mutate.js', `const Ctor=${load};${effect};`],
      ['ctor.js', "function Ctor(){if(false===(this instanceof Ctor))return new Ctor();this.lookup=(term)=>db.query(term)}" + (key ? 'module.exports.Ctor=Ctor' : 'module.exports=Ctor')],
    ];
    if (reversed) entries.reverse();
    const result = run(Object.fromEntries(entries));
    assert.equal(result.status, 'partial', effect);
    assert.equal(sql(result).length, 0, effect);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('branch operator location stays paired with the selected input flow and spread overwrite is not executable-input proof', () => {
  const result = run({ 'app.js': "import * as MarsDB from 'marsdb';const col=new MarsDB.Collection('records');function route(req){const criteria=()=>{\nif(flag)return {$where:'fixed'};\nreturn {$where:req.query.term};\n};col.find(criteria())}" });
  assert.equal(nosql(result).length, 1);
  assert.equal(nosql(result)[0].location.line, 3);
  assert.ok(nosql(result)[0].staticFlow?.steps.some(step => step.role === 'intermediate' && step.location.line === 3));
  const overwritten = run({ 'app.js': "import * as MarsDB from 'marsdb';const col=new MarsDB.Collection('records');function route(req){col.find({$where:req.query.term,...{$where:'fixed'}})}" });
  assert.equal(overwritten.metrics?.nosqlWhereInputUses, 0);
  assert.ok(nosql(overwritten).every(finding => finding.confidence === 'low'));
});

test('computed native prototype lookup cannot justify a new instanceof fallback exclusion', () => {
  const result = run({ 'app.js': "Function['pro'+'totype'][Symbol.hasInstance]=custom;function Ctor(){if(false===(this instanceof Ctor))return new Ctor();this.lookup=(term)=>db.query(term)}function route(req){const object=new Ctor();object.lookup(req.query.term)}" });
  assert.equal(result.status, 'partial');
  assert.equal(sql(result).length, 0);
});

test('self-referential captured closure and escaped owned capabilities retain incomplete coverage', () => {
  for (const text of [
    "function route(req){const go=()=>{db.query(req.query.term);go()};go()}",
    "function Ctor(){this.lookup=(term)=>db.query(term)}function route(req){const repo=new Ctor();opaque({repo});repo.lookup(req.query.term)}",
    "function Ctor(){this.lookup=(term)=>db.query(term)}function route(req){const repo=new Ctor();repo.lookup=opaque;repo.lookup(req.query.term)}",
  ]) {
    const result = run({ 'app.js': text });
    assert.equal(result.status, 'partial', text);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('ordinary and closed CJS scalar helpers preserve each actual evaluation before later writes', () => {
  for (const wrapper of ['local', 'default', 'named']) {
    const prefix = "import * as MarsDB from 'marsdb';const col=new MarsDB.Collection('records');";
    const texts: Record<string, string> = wrapper === 'local'
      ? { 'app.js': prefix + "function criteria(term,ignored){return {$where:term}}function route(req){let term=req.query.term;col.find(criteria(term,term='fixed'))}" }
      : { 'app.js': prefix + `const criteria=require('./criteria')${wrapper === 'named' ? '.criteria' : ''};function route(req){let term=req.query.term;col.find(criteria(term,term='fixed'))}`,
        'criteria.js': "function criteria(term,ignored){return {$where:term}}module.exports" + (wrapper === 'named' ? '.criteria' : '') + '=criteria;' };
    const result = run(texts);
    assert.equal(nosql(result).length, 1, wrapper);
    assert.equal(nosql(result)[0].staticFlow?.truncated, false, wrapper);
  }
});

test('uncertified ESM and dynamic consumers cannot leave a CJS new guard qualified', () => {
  for (const consumer of ["import Ctor from './ctor';Ctor.prototype=custom", "import * as ns from './ctor';ns.default.prototype=custom", "export {default} from './ctor'", "import('./ctor').then(ns=>{ns.default.prototype=custom})"]) {
    const result = run({
      'app.js': "const Ctor=require('./ctor');function route(req){const repo=new Ctor();repo.lookup(req.query.term)}",
      'foreign.js': consumer,
      'ctor.js': "function Ctor(){if(false===(this instanceof Ctor))return new Ctor();this.lookup=(term)=>db.query(term)}module.exports=Ctor",
    });
    assert.equal(result.status, 'partial', consumer);
    assert.equal(sql(result).length, 0, consumer);
  }
});

test('ordinary factories retain actual constructed return slots and ignore unused risky arguments', () => {
  const ctor = "function Ctor(term){this.lookup=()=>db.query(term)}function make(term,ignored){return new Ctor(term)}";
  const risky = run({ 'app.js': ctor + "function route(req){let term=req.query.term;const repo=make(term,term='fixed');repo.lookup()}" });
  assert.equal(sql(risky).length, 1);
  assert.equal(sql(risky)[0].staticFlow?.truncated, false);
  assert.equal(risky.metrics?.summaryWork, 3); // make, actual new, actual owned invocation; no initializer replay.
  const safe = run({ 'app.js': ctor + "function route(req){const repo=make('fixed',req.query.term);repo.lookup()}" });
  assert.equal(sql(safe).length, 0);
});
