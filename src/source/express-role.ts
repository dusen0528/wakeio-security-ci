import * as ts from 'typescript';
import { FLOW_LIMITS, StaticModules } from './modules.js';

type Role = 'factory' | 'namespace' | 'routerFactory' | 'app' | 'router' | 'route';
interface Identity { role: Role; valid: boolean; parent?: Identity }
interface Binding { identity: Identity; declaration: ts.Declaration; file: ts.SourceFile }
export interface ExpressEntry { request: number; response: number }
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all']);
const INSTANCE_CALLS = new Set([...HTTP_METHODS, 'use', 'route', 'param', 'listen', 'set', 'engine', 'enable', 'disable', 'enabled', 'disabled']);
const FACTORY_CALLS = new Set(['json', 'raw', 'text', 'urlencoded', 'static']);
const SELF_RETURNING = new Set(['set', 'engine', 'enable', 'disable', 'param']);

/** Positional entry hints for a deliberately narrow, lexical Express registration subset.
 * Uses the shared index only; no target imports, dependency reads or AST re-walks.
 * This adds candidates, never authenticates runtime packages or upstream middleware.
 */
export class ExpressRoleModel {
  private readonly factory: Identity = { role: 'factory', valid: true };
  private readonly namespace: Identity = { role: 'namespace', valid: true, parent: this.factory };
  private readonly routerFactory: Identity = { role: 'routerFactory', valid: true, parent: this.factory };
  private readonly bindings = new Map<ts.Symbol, Binding>();
  private readonly expressions = new WeakMap<ts.Expression, Identity | undefined>();
  private readonly resolving = new Set<ts.Symbol>();
  private readonly entries = new Map<ts.FunctionLikeDeclaration, ExpressEntry>();
  private readonly handlerProofs = new WeakMap<ts.FunctionLikeDeclaration, boolean>();
  private complete = true;
  private requirePristine = true;

  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly indexAvailable: boolean) {
    if (modules.expressOpaqueLoads.length) this.factory.valid = false;
    for (const reference of modules.requireReferences) {
      if (!this.work()) break;
      if (!modules.cjsGlobal(reference)) continue;
      let node: ts.Node = reference;
      while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent)
        || ts.isTypeAssertionExpression(node.parent) || ts.isNonNullExpression(node.parent))) {
        if (!this.work()) break;
        node = node.parent;
      }
      if (!ts.isCallExpression(node.parent) || node.parent.expression !== node) this.requirePristine = false;
    }
    for (const declaration of modules.importDeclarations) {
      if (!this.work()) break;
      if (!ts.isStringLiteralLike(declaration.moduleSpecifier) || declaration.moduleSpecifier.text !== 'express') continue;
      const clause = declaration.importClause;
      if (!clause || clause.isTypeOnly) continue;
      if (clause.name) this.bind(clause.name, clause, this.factory);
      const named = clause.namedBindings;
      if (named && ts.isNamespaceImport(named)) this.bind(named.name, named, this.namespace);
      else if (named) for (const element of named.elements) {
        if (!this.work()) break;
        if (element.isTypeOnly) continue;
        const name = (element.propertyName ?? element.name).text;
        if (name === 'default' || name === 'Router') this.bind(element.name, element, name === 'default' ? this.factory : this.routerFactory);
      }
    }
    const registrations: Array<{ identity: Identity; handlers: ts.Expression[] }> = [];
    for (const call of modules.calls) {
      if (!this.work()) break;
      // Audit even an inline require that is used only to change shared prototypes.
      if (this.expressLoad(call) && !this.allowedUse(call, this.factory, 0)) this.invalidate(this.factory);
      const registration = this.registration(call, 0);
      if (registration) registrations.push(registration);
      const returned = this.identity(call);
      if (returned && ['app', 'router', 'route'].includes(returned.role)) {
        let use: ts.Node = call;
        while (use.parent && (ts.isParenthesizedExpression(use.parent) || ts.isAsExpression(use.parent)
          || ts.isTypeAssertionExpression(use.parent) || ts.isNonNullExpression(use.parent))) {
          if (!this.work()) break;
          use = use.parent;
        }
        if (!ts.isExpressionStatement(use.parent) && !this.allowedUse(call, returned, 0)) this.invalidate(returned, true);
      }
    }
    // Map iteration also audits new aliases discovered through a binding's references.
    for (const [symbol, binding] of this.bindings) {
      if (!this.work()) break;
      if (modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol)) this.invalidate(binding.identity);
      for (const reference of modules.references.get(symbol) ?? []) {
        if (!this.work()) break;
        if (reference.parent === binding.declaration) continue;
        if (reference.getSourceFile() !== binding.file || !this.allowedUse(reference, binding.identity, 0)) this.invalidate(binding.identity, true);
      }
    }
    for (const registration of registrations) {
      if (!this.work()) break;
      if (!this.valid(registration.identity)) continue;
      for (const handler of registration.handlers) {
        if (!this.work()) break;
        this.addHandler(handler, 0);
      }
    }
  }

  private work(): boolean { if (!this.tick()) { this.complete = false; return false; } return true; }
  private invalidate(identity: Identity, opaque = false): void {
    identity.valid = false;
    // Module/default/named imports share the package's mutable prototypes.
    if (opaque || ['factory', 'namespace', 'routerFactory'].includes(identity.role)) this.factory.valid = false;
  }
  private unwrap(expression: ts.Expression): ts.Expression | undefined {
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)) {
      if (!this.work()) return undefined;
      expression = expression.expression;
    }
    return expression;
  }
  private bind(name: ts.Identifier, declaration: ts.Declaration, identity: Identity): Identity | undefined {
    const symbol = this.modules.symbol(name);
    if (!symbol || symbol.declarations?.length !== 1 || symbol.declarations[0] !== declaration) return undefined;
    this.bindings.set(symbol, { identity, declaration, file: name.getSourceFile() });
    return identity;
  }
  private expressLoad(call: ts.CallExpression): boolean {
    const callee = this.unwrap(call.expression);
    return this.requirePristine && !!callee && ts.isIdentifier(callee) && callee.text === 'require' && this.modules.cjsGlobal(callee)
      && !this.modules.mutated.has(this.modules.symbol(callee)!)
      && call.arguments.length === 1 && ts.isStringLiteralLike(call.arguments[0]) && call.arguments[0].text === 'express';
  }
  private available(declaration: ts.Declaration, reference: ts.Node): boolean {
    return declaration.getSourceFile() === reference.getSourceFile()
      && (declaration.end <= reference.pos || this.modules.ownerOf(declaration) !== this.modules.ownerOf(reference));
  }
  private identity(expression: ts.Expression, depth = 0): Identity | undefined {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps) return undefined;
    const node = this.unwrap(expression);
    if (!node) return undefined;
    if (this.expressions.has(node)) return this.expressions.get(node);
    let result: Identity | undefined;
    if (ts.isIdentifier(node)) {
      const symbol = this.modules.symbol(node);
      const binding = symbol && this.bindings.get(symbol);
      const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (binding && binding.file === node.getSourceFile()
        && (!ts.isVariableDeclaration(binding.declaration) || this.available(binding.declaration, node))) result = binding.identity;
      else if (symbol && declaration && !this.resolving.has(symbol) && !this.modules.mutated.has(symbol)
        && declaration.getSourceFile() === node.getSourceFile()) {
        this.resolving.add(symbol);
        if (ts.isVariableDeclaration(declaration) && declaration.initializer && ts.isIdentifier(declaration.name)
          && declaration.parent.flags & ts.NodeFlags.Const && this.available(declaration, node)) {
          const identity = this.identity(declaration.initializer, depth + 1);
          if (identity) result = this.bind(declaration.name, declaration, identity);
        } else if (ts.isBindingElement(declaration) && !declaration.dotDotDotToken && !declaration.initializer
          && ts.isIdentifier(declaration.name) && ts.isObjectBindingPattern(declaration.parent)
          && ts.isVariableDeclaration(declaration.parent.parent)) {
          const variable = declaration.parent.parent;
          const key = declaration.propertyName ?? declaration.name;
          if (variable.initializer && variable.parent.flags & ts.NodeFlags.Const && this.available(variable, node)
            && (ts.isIdentifier(key) || ts.isStringLiteralLike(key)) && key.text === 'Router') {
            const owner = this.identity(variable.initializer, depth + 1);
            if (owner?.role === 'factory' || owner?.role === 'namespace') result = this.bind(declaration.name, declaration, this.routerFactory);
          }
        }
        this.resolving.delete(symbol);
      }
    } else if (ts.isPropertyAccessExpression(node) && node.name.text === 'Router') {
      const owner = this.identity(node.expression, depth + 1);
      if (owner?.role === 'factory' || owner?.role === 'namespace') result = this.routerFactory;
    } else if (ts.isCallExpression(node) && !node.questionDotToken && !node.arguments.some(ts.isSpreadElement)) {
      if (this.expressLoad(node)) result = this.factory;
      else {
        const callee = this.identity(node.expression, depth + 1);
        if (callee?.role === 'factory' && node.arguments.length === 0) result = { role: 'app', valid: true, parent: callee };
        else if (callee?.role === 'routerFactory' && node.arguments.length <= 1) result = { role: 'router', valid: true, parent: callee };
        else {
          const member = this.unwrap(node.expression);
          if (member && ts.isPropertyAccessExpression(member) && !member.questionDotToken) {
            const owner = this.identity(member.expression, depth + 1);
            if (owner && ['app', 'router'].includes(owner.role) && member.name.text === 'route'
              && node.arguments.length === 1 && this.path(node.arguments[0], 0)) result = { role: 'route', valid: true, parent: owner };
            else if (this.registration(node, depth + 1)) result = owner;
            else if (owner && (owner.role === 'app' && SELF_RETURNING.has(member.name.text)
              || owner.role === 'router' && member.name.text === 'param')
              && node.arguments.length >= (['enable', 'disable'].includes(member.name.text) ? 1 : 2)) result = owner;
          }
        }
      }
    }
    this.expressions.set(node, result);
    return result;
  }
  private path(expression: ts.Expression | undefined, depth: number): boolean {
    if (!expression || !this.work() || depth > 8) return false;
    const node = this.unwrap(expression);
    if (!node) return false;
    if (ts.isStringLiteralLike(node) || ts.isRegularExpressionLiteral(node)) return true;
    return ts.isArrayLiteralExpression(node) && node.elements.length > 0 && node.elements.length <= 32
      && node.elements.every(element => this.path(element, depth + 1));
  }
  private registration(call: ts.CallExpression, depth: number): { identity: Identity; handlers: ts.Expression[] } | undefined {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps || call.questionDotToken || call.arguments.some(ts.isSpreadElement)) return undefined;
    const callee = this.unwrap(call.expression);
    if (!callee || !ts.isPropertyAccessExpression(callee) || callee.questionDotToken) return undefined;
    const method = callee.name.text;
    if (!HTTP_METHODS.has(method) && method !== 'use') return undefined;
    const identity = this.identity(callee.expression, depth + 1);
    if (!identity || !['app', 'router', 'route'].includes(identity.role) || identity.role === 'route' && method === 'use') return undefined;
    const start = identity.role === 'route' ? 0 : method === 'use' ? (call.arguments[0] && this.path(call.arguments[0], 0) ? 1 : 0) : 1;
    if (start === 1 && !this.path(call.arguments[0], 0) || call.arguments.length <= start
      || !call.arguments.slice(start).every(argument => this.handlerShape(argument, 0))) return undefined;
    return { identity, handlers: [...call.arguments.slice(start)] };
  }
  private handlerShape(expression: ts.Expression, depth: number): boolean {
    if (!this.work() || depth > 8) return false;
    const node = this.unwrap(expression);
    if (!node) return false;
    if (ts.isArrayLiteralExpression(node)) return node.elements.length <= 32 && node.elements.every(element => this.handlerShape(element, depth + 1));
    return ts.isIdentifier(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)
      || ts.isCallExpression(node) || ts.isPropertyAccessExpression(node);
  }
  private allowedUse(expression: ts.Expression, identity: Identity, depth: number): boolean {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps) return false;
    let node: ts.Node = expression;
    while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent)
      || ts.isTypeAssertionExpression(node.parent) || ts.isNonNullExpression(node.parent))) {
      if (!this.work()) return false;
      node = node.parent;
    }
    const parent = node.parent;
    // A direct ESM default export publishes this binding without invoking or
    // rewriting it. Keep same-file registration candidates; exported consumer
    // behavior and runtime package identity are not certified by this model.
    if (ts.isExportAssignment(parent) && !parent.isExportEquals && parent.expression === node
      && (identity.role === 'app' || identity.role === 'router')) return true;
    if (ts.isVariableDeclaration(parent) && parent.initializer === node && parent.parent.flags & ts.NodeFlags.Const) {
      if (ts.isIdentifier(parent.name)) return this.bind(parent.name, parent, identity) !== undefined;
      if (ts.isObjectBindingPattern(parent.name) && (identity.role === 'factory' || identity.role === 'namespace')) {
        return parent.name.elements.every(element => {
          if (!this.work()) return false;
          const key = element.propertyName ?? element.name;
          return !element.initializer && !element.dotDotDotToken && ts.isIdentifier(element.name)
            && (ts.isIdentifier(key) || ts.isStringLiteralLike(key)) && key.text === 'Router'
            && this.bind(element.name, element, this.routerFactory) !== undefined;
        });
      }
      return false;
    }
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node && !parent.questionDotToken) {
      if ((identity.role === 'factory' || identity.role === 'namespace') && parent.name.text === 'Router') return this.allowedUse(parent, this.routerFactory, depth + 1);
      const methods = identity.role === 'factory' || identity.role === 'namespace' ? FACTORY_CALLS : INSTANCE_CALLS;
      return methods.has(parent.name.text) && ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
    }
    if (ts.isCallExpression(parent) && parent.expression === node) return identity.role === 'factory' || identity.role === 'routerFactory';
    if (ts.isCallExpression(parent) && parent.arguments.includes(node as ts.Expression)
      && (identity.role === 'app' || identity.role === 'router')) {
      const callee = this.unwrap(parent.expression);
      return !!callee && ts.isPropertyAccessExpression(callee) && callee.name.text === 'use' && !!this.registration(parent, depth + 1);
    }
    return false;
  }
  private valid(identity: Identity, depth = 0): boolean {
    return this.work() && depth <= FLOW_LIMITS.aliasSteps && identity.valid && (!identity.parent || this.valid(identity.parent, depth + 1));
  }
  private addHandler(expression: ts.Expression, depth: number): void {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps) return;
    const node = this.unwrap(expression);
    if (!node) return;
    if (ts.isArrayLiteralExpression(node)) {
      if (node.elements.length > 32) return;
      for (const element of node.elements) { if (!this.work()) break; this.addHandler(element, depth + 1); }
      return;
    }
    if (ts.isIdentifier(node)) {
      const symbol = this.modules.symbol(node);
      const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (!symbol || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)
        || !declaration || declaration.getSourceFile() !== node.getSourceFile()) return;
      if (ts.isFunctionDeclaration(declaration)) this.addFunction(declaration);
      else if (ts.isVariableDeclaration(declaration) && declaration.initializer && declaration.parent.flags & ts.NodeFlags.Const
        && this.available(declaration, node)) {
        const initializer = this.unwrap(declaration.initializer);
        // Literal arrays are supported at registration sites only. A const array
        // binding does not make its elements immutable or establish heap closure.
        if (initializer && !ts.isArrayLiteralExpression(initializer)) this.addHandler(initializer, depth + 1);
      }
    } else if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) this.addFunction(node);
  }
  private addFunction(fn: ts.FunctionLikeDeclaration): void {
    if (!this.work() || !this.modules.functionSet.has(fn) || !fn.body || fn.parameters.length < 1 || fn.parameters.length > 4
      || 'asteriskToken' in fn && fn.asteriskToken) return;
    for (const parameter of fn.parameters) {
      if (!this.work() || parameter.dotDotDotToken || parameter.initializer || ts.isIdentifier(parameter.name) && parameter.name.text === 'this') return;
    }
    if (!this.handlerPristine(fn)) return;
    const request = fn.parameters.length === 4 ? 1 : 0;
    this.entries.set(fn, { request, response: request + 1 });
    this.modules.externalEntries.add(fn);
  }
  private handlerPristine(fn: ts.FunctionLikeDeclaration): boolean {
    const known = this.handlerProofs.get(fn);
    if (known !== undefined) return known;
    const queue: ts.Symbol[] = [];
    const seen = new Set<ts.Symbol>();
    const add = (name: ts.Identifier): boolean => {
      const symbol = this.modules.symbol(name);
      if (!symbol || symbol.declarations?.length !== 1 || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
      if (!seen.has(symbol)) { seen.add(symbol); queue.push(symbol); }
      return true;
    };
    if (fn.name && ts.isIdentifier(fn.name) && !add(fn.name)) return false;
    let owner: ts.Node = fn;
    while (owner.parent && (ts.isParenthesizedExpression(owner.parent) || ts.isAsExpression(owner.parent)
      || ts.isTypeAssertionExpression(owner.parent) || ts.isNonNullExpression(owner.parent))) {
      if (!this.work()) return false;
      owner = owner.parent;
    }
    if (ts.isVariableDeclaration(owner.parent) && ts.isIdentifier(owner.parent.name) && !add(owner.parent.name)) return false;
    let valid = true;
    for (let index = 0; index < queue.length && valid; index++) {
      if (!this.work() || index > FLOW_LIMITS.aliasSteps) { valid = false; break; }
      const symbol = queue[index];
      for (const reference of this.modules.references.get(symbol) ?? []) {
        if (!this.work()) { valid = false; break; }
        if (reference.parent === symbol.declarations![0]) continue;
        let node: ts.Node = reference;
        while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent)
          || ts.isTypeAssertionExpression(node.parent) || ts.isNonNullExpression(node.parent) || ts.isArrayLiteralExpression(node.parent))) {
          if (!this.work()) { valid = false; break; }
          node = node.parent;
        }
        const parent = node.parent;
        if (reference.getSourceFile() !== fn.getSourceFile()) { valid = false; break; }
        if (ts.isVariableDeclaration(parent) && parent.initializer === node && ts.isIdentifier(parent.name)
          && parent.parent.flags & ts.NodeFlags.Const && !ts.isArrayLiteralExpression(node) && add(parent.name)) continue;
        if (ts.isCallExpression(parent) && parent.expression === node) continue;
        if (ts.isCallExpression(parent)) {
          const registration = this.registration(parent, 0);
          if (registration?.handlers.includes(node as ts.Expression) && this.valid(registration.identity)) continue;
        }
        valid = false; break;
      }
    }
    this.handlerProofs.set(fn, valid);
    return valid;
  }
  entry(fn: ts.FunctionLikeDeclaration): ExpressEntry | undefined {
    return this.complete && this.indexAvailable && this.modules.indexComplete ? this.entries.get(fn) : undefined;
  }
}
