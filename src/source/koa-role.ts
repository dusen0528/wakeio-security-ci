import * as ts from 'typescript';
import { FLOW_LIMITS, StaticModules } from './modules.js';

interface Identity { kind: 'constructor' | 'app'; valid: boolean; parent?: Identity }
interface Binding { declaration: ts.Declaration; identity: Identity }
/** Shared request capability, not the request's value or runtime authentication. */
export interface KoaRequestRole { stage: 'context' | 'request' | 'input' | 'next'; state: { valid: boolean } }

/** Declared same-file Koa API subset. No package imports, target reads or extra AST walk. */
export class KoaRoleModel {
  private readonly factory: Identity = { kind: 'constructor', valid: true };
  private readonly bindings = new Map<ts.Symbol, Binding>();
  private readonly expressions = new WeakMap<ts.Expression, Identity | undefined>();
  private readonly resolving = new Set<ts.Symbol>();
  private readonly entries = new Set<ts.FunctionLikeDeclaration>();
  private readonly registrations = new Map<ts.CallExpression, ts.FunctionLikeDeclaration>();
  private complete = true;

  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean, private readonly indexAvailable: boolean) {
    for (const declaration of modules.importDeclarations) {
      if (!this.work()) return;
      if (!ts.isStringLiteralLike(declaration.moduleSpecifier) || declaration.moduleSpecifier.text !== 'koa') continue;
      const clause = declaration.importClause;
      if (!clause || clause.isTypeOnly) continue;
      if (clause.name) this.bind(clause.name, clause, this.factory);
      const named = clause.namedBindings;
      if (named && ts.isNamespaceImport(named)) this.factory.valid = false;
      if (named && ts.isNamedImports(named)) for (const element of named.elements) {
        if (!this.work()) return;
        if (!element.isTypeOnly) {
          if ((element.propertyName ?? element.name).text === 'default') this.bind(element.name, element, this.factory);
          else this.factory.valid = false;
        }
      }
    }
    if (!this.bindings.size) return;
    if (modules.koaOpaqueLoads.length) this.factory.valid = false;
    // CJS is not positively modeled. A known other load may alter the shared constructor.
    for (const call of modules.calls) {
      if (!this.work()) return;
      const callee = this.unwrap(call.expression);
      const load = callee && ts.isIdentifier(callee) && callee.text === 'require' && call.arguments.length === 1
        ? this.unwrap(call.arguments[0]) : undefined;
      if (callee && ts.isIdentifier(callee) && callee.text === 'require' && modules.cjsGlobal(callee)
        && load && ts.isStringLiteralLike(load) && load.text === 'koa') this.factory.valid = false;
      const handler = this.handlerAt(call);
      if (handler) this.registrations.set(call, handler);
      const returned = this.identity(call);
      if (returned?.kind === 'app') {
        let use: ts.Node = call;
        while (use.parent && (ts.isParenthesizedExpression(use.parent) || ts.isAsExpression(use.parent)
          || ts.isTypeAssertionExpression(use.parent) || ts.isNonNullExpression(use.parent))) {
          if (!this.work()) return; use = use.parent;
        }
        if (!ts.isExpressionStatement(use.parent) && !this.allowedUse(call, returned, 0)) {
          returned.valid = false; this.factory.valid = false;
        }
      }
    }
    // Constructor references alone do not describe the allocated object's use.
    // Audit its result too, using the existing charged allocation index.
    for (const allocation of modules.newExpressions) {
      if (!this.work()) return;
      const identity = this.identity(allocation);
      if (identity?.kind === 'app' && !this.allowedUse(allocation, identity, 0)) {
        identity.valid = false; this.factory.valid = false;
      }
    }
    // Alias discovery can grow this map during the bounded reference audit.
    for (const [symbol, binding] of this.bindings) {
      if (!this.work()) return;
      if (modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol)) binding.identity.valid = false;
      for (const reference of modules.references.get(symbol) ?? []) {
        if (!this.work()) return;
        if (reference.parent === binding.declaration) continue;
        if (reference.getSourceFile() !== binding.declaration.getSourceFile() || !this.allowedUse(reference, binding.identity, 0)) {
          binding.identity.valid = false;
          // Escape can expose shared mutable prototypes, not merely the local app.
          this.factory.valid = false;
        }
      }
    }
    for (const [call, fn] of this.registrations) {
      if (!this.work()) return;
      if (!this.valid(this.appAt(call)) || !this.handlerPristine(fn)) { this.registrations.delete(call); continue; }
      this.entries.add(fn); modules.externalEntries.add(fn);
    }
  }
  private work(): boolean { if (!this.tick()) { this.complete = false; return false; } return true; }
  private unwrap(expression: ts.Expression): ts.Expression | undefined {
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)) {
      if (!this.work()) return undefined; expression = expression.expression;
    }
    return expression;
  }
  private bind(name: ts.Identifier, declaration: ts.Declaration, identity: Identity): Identity | undefined {
    const symbol = this.modules.symbol(name);
    if (!symbol || symbol.declarations?.length !== 1 || symbol.declarations[0] !== declaration) return undefined;
    this.bindings.set(symbol, { declaration, identity }); return identity;
  }
  private available(declaration: ts.Declaration, reference: ts.Node): boolean {
    return declaration.getSourceFile() === reference.getSourceFile()
      && (declaration.end <= reference.pos || this.modules.ownerOf(declaration) !== this.modules.ownerOf(reference));
  }
  private identity(expression: ts.Expression, depth = 0): Identity | undefined {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps) return undefined;
    const node = this.unwrap(expression); if (!node) return undefined;
    if (this.expressions.has(node)) return this.expressions.get(node);
    let result: Identity | undefined;
    if (ts.isIdentifier(node)) {
      const symbol = this.modules.symbol(node), known = symbol && this.bindings.get(symbol);
      const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (known && (!ts.isVariableDeclaration(known.declaration) || this.available(known.declaration, node))) result = known.identity;
      else if (symbol && declaration && !this.resolving.has(symbol) && !this.modules.mutated.has(symbol)
        && ts.isVariableDeclaration(declaration) && ts.isIdentifier(declaration.name) && declaration.initializer
        && declaration.parent.flags & ts.NodeFlags.Const && this.available(declaration, node)) {
        this.resolving.add(symbol);
        const identity = this.identity(declaration.initializer, depth + 1);
        if (identity) result = this.bind(declaration.name, declaration, identity);
        this.resolving.delete(symbol);
      }
    } else if (ts.isNewExpression(node) && !(node.arguments?.length)) {
      const parent = this.identity(node.expression, depth + 1);
      if (parent?.kind === 'constructor') result = { kind: 'app', valid: true, parent };
    } else if (ts.isCallExpression(node)) {
      const app = this.appAt(node, depth + 1);
      if (app && this.handlerAt(node, depth + 1)) result = app;
    }
    this.expressions.set(node, result); return result;
  }
  private appAt(call: ts.CallExpression, depth = 0): Identity | undefined {
    if (!this.work() || call.questionDotToken || call.arguments.some(ts.isSpreadElement)) return undefined;
    const callee = this.unwrap(call.expression);
    if (!callee || !ts.isPropertyAccessExpression(callee) || callee.questionDotToken || callee.name.text !== 'use') return undefined;
    const identity = this.identity(callee.expression, depth + 1); return identity?.kind === 'app' ? identity : undefined;
  }
  private handlerAt(call: ts.CallExpression, depth = 0): ts.FunctionLikeDeclaration | undefined {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps || call.arguments.length !== 1 || !this.appAt(call, depth + 1)) return undefined;
    return this.handler(call.arguments[0], depth + 1);
  }
  private handler(expression: ts.Expression, depth: number): ts.FunctionLikeDeclaration | undefined {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps) return undefined;
    const node = this.unwrap(expression); if (!node) return undefined;
    let fn: ts.FunctionLikeDeclaration | undefined;
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) fn = node;
    else if (ts.isIdentifier(node)) {
      const symbol = this.modules.symbol(node), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (!symbol || !declaration || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol) || declaration.getSourceFile() !== node.getSourceFile()) return undefined;
      if (ts.isFunctionDeclaration(declaration)) fn = declaration;
      else if (ts.isVariableDeclaration(declaration) && declaration.initializer && declaration.parent.flags & ts.NodeFlags.Const && this.available(declaration, node)) return this.handler(declaration.initializer, depth + 1);
    }
    return fn && this.modules.functionSet.has(fn) && fn.body && fn.parameters.length >= 1 && fn.parameters.length <= 2
      && !('asteriskToken' in fn && fn.asteriskToken)
      && fn.parameters.every(parameter => !parameter.dotDotDotToken && !parameter.initializer
        && !(ts.isIdentifier(parameter.name) && parameter.name.text === 'this')) ? fn : undefined;
  }
  private valid(identity?: Identity, depth = 0): boolean {
    return this.work() && depth <= FLOW_LIMITS.aliasSteps && !!identity?.valid && (!identity.parent || this.valid(identity.parent, depth + 1));
  }
  private allowedUse(expression: ts.Expression, identity: Identity, depth: number): boolean {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps) return false;
    let node: ts.Node = expression;
    while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent) || ts.isTypeAssertionExpression(node.parent) || ts.isNonNullExpression(node.parent))) {
      if (!this.work()) return false; node = node.parent;
    }
    const parent = node.parent;
    if (ts.isVariableDeclaration(parent) && parent.initializer === node && parent.parent.flags & ts.NodeFlags.Const && ts.isIdentifier(parent.name)) return !!this.bind(parent.name, parent, identity);
    if (identity.kind === 'constructor') return ts.isNewExpression(parent) && parent.expression === node && !(parent.arguments?.length);
    if (ts.isExportAssignment(parent) && !parent.isExportEquals && parent.expression === node) return true;
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node && !parent.questionDotToken
      && ts.isCallExpression(parent.parent) && parent.parent.expression === parent) {
      if (parent.name.text === 'use') return !!this.handlerAt(parent.parent, depth + 1);
      return parent.name.text === 'listen' || parent.name.text === 'callback';
    }
    return false;
  }
  private handlerPristine(fn: ts.FunctionLikeDeclaration): boolean {
    const queue: ts.Symbol[] = [], seen = new Set<ts.Symbol>();
    const add = (name: ts.Identifier): boolean => {
      const symbol = this.modules.symbol(name);
      if (!symbol || symbol.declarations?.length !== 1 || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
      if (!seen.has(symbol)) { seen.add(symbol); queue.push(symbol); } return true;
    };
    if (fn.name && ts.isIdentifier(fn.name) && !add(fn.name)) return false;
    let owner: ts.Node = fn;
    while (owner.parent && (ts.isParenthesizedExpression(owner.parent) || ts.isAsExpression(owner.parent) || ts.isTypeAssertionExpression(owner.parent) || ts.isNonNullExpression(owner.parent))) {
      if (!this.work()) return false; owner = owner.parent;
    }
    if (ts.isVariableDeclaration(owner.parent) && ts.isIdentifier(owner.parent.name) && !add(owner.parent.name)) return false;
    for (let index = 0; index < queue.length; index++) {
      if (!this.work() || index > FLOW_LIMITS.aliasSteps) return false;
      for (const reference of this.modules.references.get(queue[index]) ?? []) {
        if (!this.work()) return false;
        if (reference.parent === queue[index].declarations![0]) continue;
        let node: ts.Node = reference;
        while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent) || ts.isTypeAssertionExpression(node.parent) || ts.isNonNullExpression(node.parent))) {
          if (!this.work()) return false; node = node.parent;
        }
        const parent = node.parent;
        if (reference.getSourceFile() !== fn.getSourceFile()) return false;
        if (ts.isVariableDeclaration(parent) && parent.initializer === node && parent.parent.flags & ts.NodeFlags.Const && ts.isIdentifier(parent.name) && add(parent.name)) continue;
        if (ts.isCallExpression(parent) && parent.expression === node) continue;
        if (ts.isCallExpression(parent) && this.registrations.get(parent) === fn) continue;
        return false;
      }
    }
    return true;
  }
  entry(fn: ts.FunctionLikeDeclaration): boolean { return this.complete && this.indexAvailable && this.modules.indexComplete && this.entries.has(fn); }
  registration(call: ts.CallExpression): boolean { return this.complete && this.indexAvailable && this.modules.indexComplete && this.registrations.has(call); }
}
