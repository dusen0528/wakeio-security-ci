import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

function run(text: string, more: Record<string, string> = {}, complete = true, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries({ 'app.ts': text, ...more }).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/never-execute', files, issues: [], complete, ignoredFiles: 0, totalBytes: files.reduce((sum, file) => sum + file.bytes, 0) };
  return runBuiltinAst(snapshot, false, limits);
}
const prefix = "import * as MarsDB from 'marsdb'; const col=new MarsDB.Collection('records');";
const findings = (result: ReturnType<typeof run>) => result.findings.filter(f => f.ruleId === 'ast:nosql-input-sink');
const guarded = "const id=req.body.id; if(typeof id !== 'string') return;";

test('declared MarsDB methods inspect selector rather than update data or options', () => {
  for (const method of ['find', 'findOne', 'update', 'remove', 'count', 'ids']) {
    const result = run(prefix + `function route(req){col.${method}({_id:req.body.id})}`);
    assert.equal(result.status, 'completed', method);
    assert.equal(findings(result).length, 1, method);
    assert.equal(findings(result)[0].confidence, 'medium', method);
    assert.match(findings(result)[0].title, /query selector/);
    assert.equal(findings(result)[0].staticFlow?.truncated, false);
  }
  for (const suffix of ["{$set:{message:req.body.message}}", "{}, {multi:req.body.multi}", "{message:req.body.message}, {multi:true}"]) {
    const result = run(prefix + `function route(req){col.update({_id:'fixed'},${suffix})}`);
    assert.equal(findings(result).length, 0, suffix);
  }
  for (const options of ['', ',{multi:false}', ',{multi:true}']) assert.equal(findings(run(prefix + `function route(req){col.update({_id:req.body.id},{$set:{message:'fixed'}}${options})}`)).length, 1);
});

test('namespace exporter and named relative import keep original selector source and sink', () => {
  const db = "import * as MarsDB from 'marsdb';export const reviewsCollection=new MarsDB.Collection('posts');";
  for (const load of ["import * as db from './db';", "import {reviewsCollection as collection} from './db';"]) {
    const receiver = load.includes('* as') ? 'db.reviewsCollection' : 'collection';
    const result = run(load + `export function route(req){${receiver}.update({_id:req.body.selectorMarker},{$set:{message:req.body.dataMarker}},{multi:true})}`, { 'db.ts': db });
    assert.equal(findings(result).length, 1);
    const finding = findings(result)[0];
    assert.equal(finding.confidence, 'medium');
    assert.equal(finding.location.path, 'app.ts');
    assert.equal(finding.staticFlow?.steps[0].location.path, 'app.ts');
    assert.equal(finding.staticFlow?.steps.at(-1)?.role, 'sink');
    assert.ok(!JSON.stringify(finding).includes('selectorMarker'));
  }
});

test('unknown receivers, arrays, shadowing and Mongo-only method spellings are not MarsDB', () => {
  for (const text of [
    "function route(req){const col=[];col.find(req.body.predicate)}",
    prefix + "function route(col,req){col.find({_id:req.body.id})}",
    "import * as MarsDB from 'marsdb';function route(MarsDB,req){const col=new MarsDB.Collection('x');col.find(req.body)}",
    "const col={find(x){return x}};function route(req){col.find(req.body)}",
    "function route(req){db.collection('x').find(req.body)}",
    prefix + "function route(req){col.updateOne(req.body);col.deleteMany(req.body)}",
    prefix.replace("'marsdb'", "'custom-db'") + "function route(req){col.find(req.body)}",
    "function route(require,req){const MarsDB=require('marsdb');const col=new MarsDB.Collection('x');col.find(req.body)}",
  ]) assert.equal(findings(run(text)).length, 0, text);
});

test('collection alias, receiver/prototype mutation and escape retain unresolved candidates', () => {
  for (const before of ["col.find=custom;", "opaque(col);", "MarsDB.Collection.prototype.find=custom;", "const alias=col;"]) {
    const result = run(prefix + `function route(req){${before}col.find({_id:req.body.id})}`);
    assert.equal(findings(result).length, 1, before);
    assert.equal(findings(result)[0].confidence, 'low', before);
  }
  assert.equal(findings(run(prefix + "function route(req){const alias=col;alias.find(req.body)}")).length, 1);
  const more = { 'db.ts': "import * as MarsDB from 'marsdb';export const col=new MarsDB.Collection('records');" };
  for (const effect of ['opaque(db)', 'opaque(db.col)', 'db.col.find=custom']) {
    const result = run(`import * as db from './db';function route(req){${effect};db.col.find(req.body)}`, more);
    assert.equal(findings(result).length, 1, effect);
    assert.equal(findings(result)[0].confidence, 'low', effect);
  }
});

test('const snapshot string guard excludes operator objects without erasing code or other taint', () => {
  const result = run(prefix + `function route(req){${guarded}col.find({_id:id});col.find({$where:id});eval(id);db.query(id)}`);
  assert.equal(findings(result).length, 1);
  assert.match(findings(result)[0].title, /JavaScript selector/);
  assert.equal(result.metrics?.nosqlStringSelectorExcluded, 1);
  assert.ok(result.findings.some(f => f.ruleId === 'ast:dynamic-code'));
  assert.ok(result.findings.some(f => f.ruleId === 'ast:sql-input-sink'));
});

test('string input interpolated into $where stays a code selector candidate', () => {
  const result = run(prefix + `function route(req){${guarded}col.find({$where:\`this.value == '\${id}'\`})}`);
  assert.equal(findings(result).length, 1);
  assert.match(findings(result)[0].title, /JavaScript selector/);
  assert.equal(findings(result)[0].confidence, 'medium');
});

test('nonterminating guards, reassignment, member getters and caught throws grant no exclusion', () => {
  for (const body of [
    "const id=req.body.id;if(typeof id!=='string'){log()}col.find({_id:id})",
    "const id=req.body.id;if(typeof id!=='string'){if(flag)return}col.find({_id:id})",
    "let id=req.body.id;if(typeof id!=='string')return;id=req.body.other;col.find({_id:id})",
    "const id=req.body.id;try{if(typeof id!=='string')throw 1}catch{}col.find({_id:id})",
    "if(typeof req.body.id!=='string')return;col.find({_id:req.body.id})",
    "Object.defineProperty(req.body,'id',{get(){return req.query.selector}});if(typeof req.body.id!=='string')return;col.find({_id:req.body.id})",
    guarded + "opaque(id);col.find({_id:id})",
  ]) {
    const result = run(prefix + `function route(req){${body}}`);
    assert.equal(findings(result).length, 1, body);
    assert.equal(result.metrics?.nosqlStringSelectorExcluded, 0, body);
  }
});

test('computed keys, spread and selector alias mutation do not become safe literals', () => {
  for (const body of [
    "col.find({[req.body.key]:'fixed'})",
    "col.find({...req.body,_id:'fixed'})",
    "col.find({__proto__:req.body.selector})",
    "const selector={_id:'fixed'};const alias=selector;alias._id=req.body.id;col.find(selector)",
    "const selector={_id:'fixed'};opaque(selector,req.body.id);col.find(selector)",
    "const selector={_id:'fixed'};const alias=selector;if(flag)alias._id=req.body.id;col.find(selector)",
    "const nested={x:'fixed'};const selector={a:nested};nested.x=req.body.id;col.find(selector)",
    "const selector={_id:'fixed'};const alias=selector;alias._id=req.body.id;col.find({...selector})",
    "const selector={_id:'fixed'};const alias=selector;let chosen=selector;if(flag){alias._id=req.body.id}else{chosen={_id:'fixed'}}col.find(chosen)",
    "const selector={_id:'fixed'};opaque({selector},req.body.id);col.find(selector)",
  ]) {
    const result = run(prefix + `function route(req){${body}}`);
    assert.equal(findings(result).length, 1, body);
    assert.equal(findings(result)[0].confidence, 'low', body);
  }
});

test('an imported collection mutation from another consumer prevents string exclusion', () => {
  const more = {
    'db.ts': "import * as MarsDB from 'marsdb';export const col=new MarsDB.Collection('records');",
    'mutate.ts': "import * as db from './db';db.col.find=custom;",
  };
  const result = run(`import * as db from './db';function route(req){${guarded}db.col.find({_id:id})}`, more);
  assert.equal(findings(result).length, 1);
  assert.equal(findings(result)[0].confidence, 'low');
  assert.equal(result.metrics?.nosqlStringSelectorExcluded, 0);
});

test('selector operand snapshot does not borrow taint from a later update operand', () => {
  const result = run(prefix + "function route(req){let id='fixed';col.update({_id:id},(id=req.body.id,{$set:{x:1}}))}");
  assert.equal(findings(result).length, 0);
  const internal = run(prefix + "function route(req){let id=req.body.id;col.find({_id:id,z:(id='fixed')})}");
  assert.equal(findings(internal).length, 1);
  assert.equal(findings(internal)[0].staticFlow?.truncated, false);
  const later = run(prefix + "function route(req){let id='fixed';col.find({_id:id,z:(id=req.body.id)})}");
  assert.equal(findings(later).length, 1);
  assert.equal(findings(later)[0].staticFlow?.steps[0].location.column, (prefix + "function route(req){let id='fixed';col.find({_id:id,z:(id=").length + 1);
});

test('primitive guard does not grant exclusions for operator/control fields', () => {
  for (const operator of ['$regex', '$in', '$expr']) {
    const result = run(prefix + `function route(req){${guarded}col.find({${operator}:id})}`);
    assert.equal(findings(result).length, 1, operator);
    assert.equal(findings(result)[0].confidence, 'low', operator);
    assert.equal(result.metrics?.nosqlStringSelectorExcluded, 0);
  }
});

test('mixed actual contexts keep the unsafe selector and actual source trace', () => {
  for (const reversed of [false, true]) {
    const calls = ["lookup('fixed')", "lookup(req.body.id)"]; if (reversed) calls.reverse();
    const result = run(prefix + `function lookup(id){col.find({_id:id})}function route(req){${calls.join(';')}}`);
    assert.equal(findings(result).length, 1);
    assert.ok(findings(result)[0].staticFlow?.steps.some(s => s.role === 'parameter'));
    assert.equal(findings(result)[0].staticFlow?.truncated, false);
  }
});

test('partial scope and budget keep exit 2 and disable string selector exclusions', () => {
  const text = prefix + `function route(req){${guarded}col.find({_id:id})}`;
  const incomplete = run(text, {}, false);
  assert.equal(findings(incomplete).length, 1);
  assert.equal(incomplete.metrics?.nosqlStringSelectorExcluded, 0);
  for (const cap of [{ indexWork: 1 }, { flowWork: 1 }, { nodeVisits: 1 }, { functions: 1 }]) {
    const result = run(text + 'function another(req){col.find(req.body)}', {}, true, { ...FLOW_LIMITS, ...cap });
    assert.equal(result.status, 'partial');
    assert.equal(result.metrics?.nosqlStringSelectorExcluded, 0);
    assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
  }
});

test('deep NoSQL alias content traversal reports a cap instead of false clean completion', () => {
  const deep = '{outer:'.repeat(10) + 'nested' + '}'.repeat(10);
  const result = run(prefix + `function route(req){const nested={value:'fixed'};const selector=${deep};nested.value=req.body.id;col.find(selector)}`);
  assert.equal(result.status, 'partial');
  assert.match(String(result.metrics?.incompleteReasons), /alias_limit/);
  assert.equal(evaluateGate(createReport([result], 'source', new Date()), 'none').exitCode, 2);
});

test('public projections preserve candidate status and redact source text', () => {
  const result = run(prefix + "function route(req){col.find({_id:req.body.privateMarker})}");
  const report = createReport([result], 'source', new Date());
  const agent = toAgentReport(report);
  assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
  for (const output of [JSON.stringify(report), JSON.stringify(agent), JSON.stringify(toSarif(report)), toMarkdown(report)]) {
    assert.match(output, /NoSQL query selector/);
    assert.ok(!output.includes('privateMarker'));
  }
});
