import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { createReport, evaluateGate } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function run(texts: Record<string, string>, complete = true, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: /\.json$/.test(path) ? 'dependency' as const : 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/never-execute', files, issues: [], complete, ignoredFiles: 0, totalBytes: files.reduce((sum, file) => sum + file.bytes, 0) };
  return runBuiltinAst(snapshot, false, limits);
}
const metadata = { 'package.json': JSON.stringify({ dependencies: { mongodb: '^2.1.18' } }), 'package-lock.json': JSON.stringify({ packages: { 'node_modules/mongodb': { version: '2.2.36' } }, dependencies: { mongodb: { version: '2.2.36' } } }) };
const start = "const MongoClient=require('mongodb').MongoClient;MongoClient.connect('mongodb://fixture',";
const findings = (result: ReturnType<typeof run>) => result.findings.filter(f => f.ruleId === 'ast:nosql-input-sink');

test('different observed Mongo capabilities retain unresolved markers on selector use', () => {
  for (const setup of [
    "const collection=flag?db.collection('a'):db.collection('b');",
    "const collection=flag?db.collection('a'):{find(){}};",
    "function choose(value){if(flag)return value;return {collection(){return {find(){}}}}}const collection=choose(db).collection('a');",
    "function choose(value){if(flag)return value;return {find(){}}}const collection=choose(db.collection('a'));",
  ]) for (const selector of ["{$where:req.query.code}", "{_id:'fixed'}"]) {
    const result = run({ ...metadata, 'app.js': start + `(err,db)=>{const route=(req)=>{${setup}collection.find(${selector})};register(route)})` });
    assert.equal(result.status, 'partial', setup);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2, setup);
    assert.equal(findings(result).length, selector.includes('$where') ? 1 : 0, setup);
    assert.ok(findings(result).every(finding => finding.confidence === 'low'), setup);
  }
});

test('legacy driver contract callback actual Db role qualifies a selector and JavaScript source', () => {
  for (const options of ['', '{},']) {
    const result = run({ ...metadata, 'app.js': start + options + "(err,database)=>{const collection=database.collection('records');const route=(req)=>{collection.find({$where:req.query.code})};register(route)})" });
    assert.equal(findings(result).length, 1);
    assert.equal(findings(result)[0].confidence, 'medium');
    assert.match(findings(result)[0].description, /legacy MongoDB 2\.x Collection/);
    assert.equal(findings(result)[0].staticFlow?.truncated, false);
  }
});

test('missing, 3.x, ambiguous and contradictory contract evidence never supplies a legacy Db', () => {
  for (const files of [
    {}, { 'package.json': '{}' }, { 'package.json': JSON.stringify({ dependencies: { mongodb: '^3.0.0' } }) },
    { 'package.json': JSON.stringify({ dependencies: { mongodb: '2.2.36 || 3.0.0' } }) },
    { ...metadata, 'package-lock.json': JSON.stringify({ dependencies: { mongodb: { version: '3.0.0' } } }) },
    { ...metadata, 'package-lock.json': JSON.stringify({ packages: { 'node_modules/mongodb': { version: '2.2.36' } }, dependencies: { mongodb: { version: '3.0.0' } } }) },
    { ...metadata, 'package-lock.json': JSON.stringify({ dependencies: { mongodb: { version: '2.0.0' } } }) },
    { ...metadata, 'package.json': '{broken' },
  ] as Record<string, string>[]) {
    const result = run({ ...files, 'app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>{collection.find({$where:req.query.code})};register(route)})" });
    assert.equal(findings(result).length, 0);
    assert.equal(result.status, 'partial');
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('nearest package of the native driver load controls contract even when sink is elsewhere', () => {
  const result = run({ ...metadata,
    'nested/package.json': JSON.stringify({ dependencies: { mongodb: '^3.0.0' } }),
    'nested/app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>{collection.find(req.body)};register(route)})",
  });
  assert.equal(findings(result).length, 0);
  assert.equal(result.status, 'partial');
});

test('driver/error/Db parameter spelling does not substitute for lexical package identity', () => {
  for (const text of [
    "function route(db,req){db.collection('records').find(req.body)}",
    "const MongoClient={connect(url,cb){cb(null,{collection(){return {find(){}}}})}};MongoClient.connect('fixture',(err,db)=>{db.collection('records').find(req.body)})",
    "function route(require,req){const MongoClient=require('mongodb').MongoClient;MongoClient.connect('fixture',(err,db)=>{db.collection('records').find(req.body)})}",
    start + "(db,error)=>{const collection=db.collection('records');const route=(req)=>{collection.find(req.body)};register(route)})",
  ]) assert.equal(findings(run({ ...metadata, 'app.js': text })).length, 0, text);
});

test('update selector, data and options keep distinct arguments', () => {
  for (const invocation of ["collection.update({_id:'fixed'},{$set:{message:req.body.message}})", "collection.update({_id:'fixed'},fixed,{multi:req.body.multi})", "collection.find({_id:'fixed'})"]) {
    const result = run({ ...metadata, 'app.js': start + `(err,db)=>{const collection=db.collection('records');const route=(req)=>{${invocation}};register(route)})` });
    assert.equal(findings(result).length, 0, invocation);
  }
  const result = run({ ...metadata, 'app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>{collection.update({_id:req.body.id},{$set:{message:'fixed'}})};register(route)})" });
  assert.equal(findings(result).length, 1);
});

test('collection options, Db and collection escape or mutation preserve unresolved input and partial gate', () => {
  for (const setup of ["opaque(db);const collection=db.collection('records');", "db.collection=custom;const collection=db.collection('records');", "const collection=db.collection('records',{strict:true});", "const collection=db.collection('records');opaque(collection);", "const collection=db.collection('records');collection.find=custom;"]) {
    const result = run({ ...metadata, 'app.js': start + `(err,db)=>{${setup}const route=(req)=>{collection.find({$where:req.query.code})};register(route)})` });
    if (setup.includes('collection.find=custom')) assert.equal(findings(result).length, 0, setup); // Captured mutable-member binding is an unsupported callback frame.
    else {
      assert.equal(findings(result).length, 1, setup);
      assert.equal(findings(result)[0].confidence, 'low', setup);
    }
    assert.equal(result.status, 'partial', setup);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2, setup);
  }
});

test('actual legacy Db and nested constructor closures preserve source/operator/find coordinates', () => {
  const result = run({ ...metadata,
    'app.js': "const setup=require('./setup');" + start + '(err,db)=>setup(app,db))',
    'setup.js': "const Handler=require('./handler');const setup=(app,db)=>{const handler=new Handler(db);app.get('/lookup',handler.display)};module.exports=setup;",
    'handler.js': "const DAO=require('./dao').DAO;function Handler(db){const dao=new DAO(db);this.display=(req,res)=>{const {threshold}=req.query;dao.lookup(threshold)}}module.exports=Handler;",
    'dao.js': "const DAO=function(db){const collection=db.collection('records');this.lookup=(threshold)=>{const criteria=()=>{\nif(threshold)return {$where:`this.value > '${threshold}'`};\nreturn {value:1};};\ncollection.find(criteria())}};module.exports.DAO=DAO;",
  });
  assert.equal(findings(result).length, 1);
  const finding = findings(result)[0];
  assert.equal(finding.location.path, 'dao.js');
  assert.equal(finding.location.line, 2);
  assert.ok(finding.staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'handler.js'));
  assert.ok(finding.staticFlow?.steps.some(step => step.role === 'intermediate' && step.location.path === 'dao.js' && step.location.line === 2));
  assert.equal(finding.staticFlow?.steps.at(-1)?.location.line, 4);
  assert.equal(finding.staticFlow?.truncated, false);
  assert.equal(result.status, 'partial'); // Unmaterialized owned roots remain separate incomplete contexts.
});

test('metadata and actual legacy callback role honor collection/index/flow boundaries', () => {
  const texts = { ...metadata, 'app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>{collection.find(req.body)};register(route)})" };
  const incomplete = run(texts, false);
  assert.equal(incomplete.status, 'partial');
  assert.ok(findings(incomplete).every(finding => finding.confidence === 'low'));
  for (const cap of [{ indexWork: 1 }, { flowWork: 1 }, { nodeVisits: 1 }]) {
    const result = run(texts, true, { ...FLOW_LIMITS, ...cap });
    assert.equal(result.status, 'partial');
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('shared native package mutations through other imports refuse closed Mongo dispatch in either order', () => {
  for (const effect of [
    "const Other=require('mongodb').MongoClient;Other.connect=custom",
    "const mongo=require('mongodb');mongo.MongoClient.connect=custom",
    "import {MongoClient as Other} from 'mongodb';Other.connect=custom",
    "const Other=require('mongodb').MongoClient;Other['connect']=custom",
    "const Other=require('mongodb').MongoClient;opaque(Other)",
    "const mongo=require('mongodb');mongo.Collection.prototype.find=custom",
  ]) for (const reversed of [false, true]) {
    const entries: Array<[string, string]> = Object.entries({ ...metadata, 'app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>{collection.find({$where:req.query.code})};register(route)})", 'other.js': effect });
    if (reversed) entries.reverse();
    const result = run(Object.fromEntries(entries));
    assert.equal(findings(result).length, 1, effect);
    assert.equal(findings(result)[0].confidence, 'low', effect);
    assert.equal(result.status, 'partial', effect);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('applicable lock root conflict, ancestor lock conflict and shrinkwrap cannot favor a 2.x package-lock', () => {
  for (const extra of [
    { 'package-lock.json': JSON.stringify({ packages: { '': { dependencies: { mongodb: '^3.0.0' } }, 'node_modules/mongodb': { version: '2.2.36' } } }) },
    { 'npm-shrinkwrap.json': JSON.stringify({ dependencies: { mongodb: { version: '2.2.36' } } }) },
  ] as Record<string, string>[]) {
    const result = run({ ...metadata, ...extra, 'app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>collection.find(req.body);register(route)})" });
    assert.equal(findings(result).length, 0);
    assert.equal(result.status, 'partial');
  }
  const nested = run({ ...metadata, 'package-lock.json': JSON.stringify({ dependencies: { mongodb: { version: '3.0.0' } } }),
    'nested/package.json': metadata['package.json'], 'nested/app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>collection.find(req.body);register(route)})" });
  assert.equal(findings(nested).length, 0);
  assert.equal(nested.status, 'partial');
});

test('unsupported legacy callback shape or opaque connect options retain partial coverage', () => {
  for (const suffix of ["callback)", "((err,db)=>{db.collection('records')}))", "{promiseLibrary:custom},(err,db)=>{db.collection('records')})"]) {
    const result = run({ ...metadata, 'app.js': start + suffix });
    assert.equal(result.status, 'partial', suffix);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('scalar Db/collection wrappers keep role provenance without smearing unused input arguments', () => {
  for (const invocation of ["const collection=identity(db,req.body.unused).collection('records')", "const collection=identity(db.collection('records'),req.body.unused)"]) {
    const result = run({ ...metadata, 'app.js': start + `(err,db)=>{function identity(value,unused){return value}const route=(req)=>{${invocation};collection.find({$where:req.query.code})};register(route)})` });
    assert.equal(findings(result).length, 1, invocation);
    assert.equal(findings(result)[0].confidence, 'medium', invocation);
    assert.equal(findings(result)[0].staticFlow?.truncated, false);
  }
});

test('Mongo selector arguments are snapshotted before later modifier or option assignments', () => {
  const result = run({ ...metadata, 'app.js': start + "(err,db)=>{const collection=db.collection('records');const route=(req)=>{let selector={_id:req.body.id};collection.update(selector,(selector={_id:'fixed'}))};register(route)})" });
  assert.equal(findings(result).length, 1);
  assert.equal(findings(result)[0].staticFlow?.truncated, false);
});

test('branch joins preserve the identical Db cell and its monotonic invalidation', () => {
  for (const condition of ["if(err){log(err)}", "if(flag){opaque(db)}"]) {
    const result = run({ ...metadata, 'app.js': start + `(err,db)=>{${condition};const collection=db.collection('records');const route=(req)=>collection.find({$where:req.query.code});register(route)})` });
    assert.equal(findings(result).length, 1, condition);
    assert.equal(findings(result)[0].confidence, condition.includes('opaque') ? 'low' : 'medium');
    if (condition.includes('opaque')) {
      assert.equal(result.status, 'partial');
      assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
    }
  }
});
