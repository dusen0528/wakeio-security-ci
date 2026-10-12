import test from 'node:test';
import assert from 'node:assert/strict';
import * as ts from 'typescript';
import { StaticModules, FLOW_LIMITS } from '../src/source/modules.js';
import { analyzeClosureShape, analyzeConstructedShape } from '../src/source/closure-shape.js';

function indexed(text: string) {
  const file = ts.createSourceFile('shape.js', text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const modules = new StaticModules([file], () => true, FLOW_LIMITS, () => {});
  modules.finishIndex(true);
  const target = modules.functions.find(fn => ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn));
  assert.ok(target);
  return { modules, target };
}
const analyze = (text: string) => {
  const { modules, target } = indexed(text);
  return analyzeConstructedShape(target, modules, () => true);
};

test('constructor own arrows retain actual capture symbols and initialization effects', () => {
  const result = analyze(`function Store(db) {
    const collection = db.collection('items');
    const other = new Helper(db);
    this.find = (input) => { const query = () => ({$where: input}); return collection.find(query(), other); };
  }`);
  assert.equal(result.kind, 'supported');
  if (result.kind !== 'supported') return;
  assert.equal(result.shape.initializers.length, 2);
  assert.deepEqual(result.shape.effects.map(node => ts.isNewExpression(node) ? 'new' : 'call'), ['call', 'new']);
  assert.deepEqual(result.shape.ownArrows.get('find')?.captures.map(symbol => symbol.name).sort(), ['collection', 'other']);
  assert.equal(result.shape.ownArrows.get('find')?.lexicalThis, false);
});

test('exact constructor guard is recorded without treating its calls as initializer effects', () => {
  for (const condition of ['false === (this instanceof Store)', '(this instanceof Store) === false', '!(this instanceof Store)']) {
    const result = analyze(`const Store = function(db) {
      if (${condition}) { console.log('fallback'); return new Store(db); }
      const collection = db.collection('items'); this.read = () => collection.find({});
    };`);
    assert.equal(result.kind, 'supported', condition);
    if (result.kind !== 'supported') continue;
    assert.equal(result.shape.guards.length, 1);
    assert.equal(result.shape.effects.length, 1);
  }
  for (const guard of ['if (false === (this instanceof Other)) return new Store(db);',
    'if (false === (this instanceof Store)) return new Other(db);',
    'if (db) return new Store(db);', 'if (false === (this instanceof Store)) return new Store(db); else mutate(db);',
    'if (false === (this instanceof Store)) { const Store = Other; return new Store(db); }']) {
    assert.equal(analyze(`function Store(db){${guard} this.read=()=>db;}`).kind, 'unsupported', guard);
  }
});

test('free captures respect shadowing, shorthand reads, and nested closure requirements', () => {
  const { modules } = indexed(`const outside = 'outer'; function Store(db) {
    this.read = (outside) => { const local = outside; return () => ({local, db}); };
  }`);
  const arrow = modules.functions.find(ts.isArrowFunction);
  assert.ok(arrow);
  const result = analyzeClosureShape(arrow, modules, () => true);
  assert.equal(result.kind, 'supported');
  if (result.kind !== 'supported') return;
  assert.deepEqual(result.shape.captures.map(symbol => symbol.name), ['db']);
  const db = modules.functions.find(ts.isFunctionDeclaration)?.parameters[0];
  assert.equal(result.shape.captures[0], db ? modules.symbol(db.name) : undefined);
});

test('mutable captures, member writes, ambiguity, and forward captures remain unsupported', () => {
  for (const code of [
    'function Store(db){let value=db;this.read=()=>value;value=other;}',
    'function Store(db){this.read=()=>db;db.collection=other;}',
    'function Store(db){var value=db;var value=other;this.read=()=>value;}',
    'function Store(db){this.read=()=>value;const value=db;}',
    'function Store(db){this.read=()=>value;const {value}=db;}',
  ]) assert.equal(analyze(code).kind, 'unsupported', code);
});

test('nested arrow reads retain lexical this while dynamic this and receiver escape do not certify', () => {
  const supported = analyze('function Store(){this.read=()=>()=>this.read();}');
  assert.equal(supported.kind, 'supported');
  if (supported.kind === 'supported') assert.equal(supported.shape.ownArrows.get('read')?.lexicalThis, true);
  for (const body of ['function inner(){return this.read()} return inner;',
    'this.read=other;', 'this.state.value=other;', 'delete this.read;', 'return this[key];', 'return this;', 'opaque(this);', 'return arguments;', 'eval(code);']) {
    assert.equal(analyze(`function Store(){this.read=()=>{${body}}}`).kind, 'unsupported', body);
  }
});

test('opaque effects stay explicit and opaque returns, slot mutations and nesting are rejected', () => {
  const effect = analyze('function Store(db){opaque(db);this.read=()=>db;}');
  assert.equal(effect.kind, 'supported');
  if (effect.kind === 'supported') assert.equal(effect.shape.effects.length, 1);
  for (const body of ['return replacement;', 'opaque(this);', 'this.read=()=>db;this.read=()=>other;',
    'this[key]=()=>db;', 'this.read=function(){return db};', 'this.__proto__=()=>db;',
    'function nested(){this.read=()=>db}', 'if(db){this.read=()=>db}', 'this.value=db;', 'this.read=()=>db;this.read=other;',
    'eval(code);this.read=()=>db;']) {
    assert.equal(analyze(`function Store(db){${body}}`).kind, 'unsupported', body);
  }
});

test('budget exhaustion never returns a complete or unsupported-safe shape', () => {
  const { target, modules } = indexed('function Store(db){const col=db.collection("items");this.read=()=>col.find({});}');
  assert.deepEqual(analyzeConstructedShape(target, modules, () => false), { kind: 'budget' });
  const arrow = modules.functions.find(ts.isArrowFunction);
  assert.ok(arrow);
  let left = 2;
  assert.deepEqual(analyzeClosureShape(arrow, modules, () => left-- > 0), { kind: 'budget' });
});
