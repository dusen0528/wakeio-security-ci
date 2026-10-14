import * as ts from 'typescript';
import { FLOW_LIMITS, StaticModules } from './modules.js';

interface Identity { kind: 'constructor' | 'app'; valid: boolean; parent?: Identity }
interface Binding { declaration: ts.Declaration; identity: Identity }
interface RequestState { valid: boolean; jsonReads?: number; jsonDataValid?: boolean }
export interface HonoRequestRole { stage: 'context' | 'request' | 'promise' | 'next'; state: RequestState;
  origin?: ts.CallExpression; jsonSourceState?: RequestState }
const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all']);

/** Lexical same-file Hono registration subset, not runtime/package authenticity. */
export class HonoRoleModel {
  private readonly factory: Identity = { kind: 'constructor', valid: true };
  private readonly bindings = new Map<ts.Symbol, Binding>();
  private readonly expressions = new WeakMap<ts.Expression, Identity | undefined>();
  private readonly resolving = new Set<ts.Symbol>();
  private readonly registrations = new Map<ts.CallExpression, ts.FunctionLikeDeclaration>();
  private readonly entries = new Set<ts.FunctionLikeDeclaration>();
  private readonly jsonEntries = new Set<ts.FunctionLikeDeclaration>();
  private complete = true;

  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly indexAvailable: boolean, private readonly scopeComplete: boolean) {
    if (!indexAvailable || !scopeComplete) return;
    for (const declaration of modules.importDeclarations) {
      if (!this.work()) return;
      if (!ts.isStringLiteralLike(declaration.moduleSpecifier) || !/^hono(?:\/|$)/.test(declaration.moduleSpecifier.text)) continue;
      const clause = declaration.importClause;
      if (clause?.isTypeOnly) continue;
      const named = clause?.namedBindings;
      const runtime = !clause || !!clause.name || !!named && (ts.isNamespaceImport(named)
        || ts.isNamedImports(named) && named.elements.some(specifier => !specifier.isTypeOnly));
      if (declaration.moduleSpecifier.text !== 'hono') {
        if (runtime) this.factory.valid = false; // Subpaths can expose the shared HonoRequest class.
        continue;
      }
      if (!clause) { this.factory.valid = false; continue; }
      if (clause.name || named && ts.isNamespaceImport(named)) this.factory.valid = false;
      if (named && ts.isNamedImports(named)) for (const specifier of named.elements) {
        if (!this.work()) return;
        if (!specifier.isTypeOnly) {
          if ((specifier.propertyName ?? specifier.name).text === 'Hono') this.bind(specifier.name, specifier, this.factory);
          else this.factory.valid = false; // Other runtime exports may expose shared request/constructor state.
        }
      }
    }
    if (!this.bindings.size) return;
    for (const call of modules.calls) {
      if (!this.work()) return;
      const callee = this.unwrap(call.expression), load = call.arguments[0] && this.unwrap(call.arguments[0]);
      if (callee && (callee.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(callee) && callee.text === 'require')
        && load && ts.isStringLiteralLike(load) && /^hono(?:\/|$)/.test(load.text)) this.factory.valid = false;
      const handler = this.handlerAt(call);
      if (handler) this.registrations.set(call, handler);
      const returned = this.identity(call);
      if (returned?.kind === 'app') {
        let use: ts.Node = call;
        while (use.parent && (ts.isParenthesizedExpression(use.parent) || ts.isAsExpression(use.parent)
          || ts.isTypeAssertionExpression(use.parent) || ts.isNonNullExpression(use.parent))) {
          if (!this.work()) return; use = use.parent;
        }
        if (!ts.isExpressionStatement(use.parent) && !this.allowedUse(call, returned, 0)) this.factory.valid = returned.valid = false;
      }
    }
    for (const allocation of modules.newExpressions) {
      if (!this.work()) return;
      const identity = this.identity(allocation);
      if (identity?.kind === 'app' && !this.allowedUse(allocation, identity, 0)) this.factory.valid = identity.valid = false;
    }
    // Alias discovery grows the map during this charged symbol-reference audit.
    for (const [symbol, binding] of this.bindings) {
      if (!this.work()) return;
      if (modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol)) this.factory.valid = binding.identity.valid = false;
      for (const reference of modules.references.get(symbol) ?? []) {
        if (!this.work()) return;
        if (reference.parent === binding.declaration) continue;
        if (reference.getSourceFile() !== binding.declaration.getSourceFile() || !this.allowedUse(reference, binding.identity, 0)) {
          this.factory.valid = binding.identity.valid = false;
        }
      }
    }
    // A handler losing proof does not erase its observed app registration or effects.
    const registrationsObserved=this.registrations.size;
    for (const [call, fn] of this.registrations) {
      if (!this.work()) return;
      if (!this.valid(this.appAt(call)) || !this.handlerPristine(fn)) { this.registrations.delete(call); continue; }
      this.entries.add(fn); modules.externalEntries.add(fn);
    }
    let jsonReads=0;
    for (const call of modules.calls) {
      if (!this.work()) return;
      const callee=this.unwrap(call.expression);
      const method=callee && (ts.isPropertyAccessExpression(callee) ? callee.name.text
        : ts.isElementAccessExpression(callee) && ts.isStringLiteralLike(callee.argumentExpression) ? callee.argumentExpression.text : undefined);
      if (method!=='json') continue;
      const owner=modules.ownerOf(call);
      const parameter=!ts.isSourceFile(owner) && owner.parameters[0]?.name;
      // Context.json is response serialization, not a request body read.
      if (!ts.isSourceFile(owner) && this.entries.has(owner) && parameter && ts.isIdentifier(parameter)
        && callee && ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)
        && modules.symbol(callee.expression)===modules.symbol(parameter)) continue;
      if (++jsonReads>1) break;
    }
    if (jsonReads===1 && registrationsObserved===1 && this.jsonIntrinsicsPristine()) {
      for (const fn of this.entries) if (this.jsonContextPristine(fn)) this.jsonEntries.add(fn);
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
    } else if (ts.isCallExpression(node) && this.handlerAt(node, depth + 1)) result = this.appAt(node, depth + 1);
    this.expressions.set(node, result); return result;
  }
  private appAt(call: ts.CallExpression, depth = 0): Identity | undefined {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps || call.questionDotToken || call.arguments.some(ts.isSpreadElement)) return undefined;
    const callee = this.unwrap(call.expression);
    if (!callee || !ts.isPropertyAccessExpression(callee) || callee.questionDotToken || !METHODS.has(callee.name.text)) return undefined;
    const identity = this.identity(callee.expression, depth + 1); return identity?.kind === 'app' ? identity : undefined;
  }
  private handlerAt(call: ts.CallExpression, depth = 0): ts.FunctionLikeDeclaration | undefined {
    if (!this.work() || depth > FLOW_LIMITS.aliasSteps || call.arguments.length !== 2
      || !ts.isStringLiteralLike(call.arguments[0]) || !this.appAt(call, depth + 1)) return undefined;
    return this.handler(call.arguments[1], depth + 1);
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
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node && !parent.questionDotToken) {
      if (parent.name.text === 'fetch') {
        // Read-only serving callback exports expose no arbitrary callback Context.
        const use = parent.parent;
        return !(ts.isBinaryExpression(use) && use.left === parent || ts.isDeleteExpression(use)
          || ts.isPrefixUnaryExpression(use) || ts.isPostfixUnaryExpression(use));
      }
      return ts.isCallExpression(parent.parent) && parent.parent.expression === parent && !!this.handlerAt(parent.parent, depth + 1);
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
  private jsonContextPristine(fn: ts.FunctionLikeDeclaration): boolean {
    const name=fn.parameters[0]?.name;
    if (!name || !ts.isIdentifier(name)) return false;
    const symbol=this.modules.symbol(name);
    if (!symbol || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
    for (const ref of this.modules.references.get(symbol) ?? []) {
      if (!this.work()) return false;
      if (ref===name) continue;
      if (this.modules.ownerOf(ref)!==fn) return false;
      const property=ref.parent;
      if (!ts.isPropertyAccessExpression(property) || property.expression!==ref || property.questionDotToken) return false;
      let callee:ts.PropertyAccessExpression=property;
      if (property.name.text==='req') {
        const method=property.parent;
        if (!ts.isPropertyAccessExpression(method) || method.expression!==property || method.questionDotToken
          || !['query','param','json'].includes(method.name.text)) return false;
        callee=method;
      } else if (!['text','json','html','redirect','body','status','header','newResponse','set','get'].includes(property.name.text)) return false;
      const call=callee.parent;
      if (!ts.isCallExpression(call) || call.expression!==callee || call.questionDotToken || call.arguments.some(ts.isSpreadElement)) return false;
    }
    const next=fn.parameters[1]?.name;
    if (next) {
      if (!ts.isIdentifier(next)) return false;
      const symbol=this.modules.symbol(next);
      if (!symbol) return false;
      for (const ref of this.modules.references.get(symbol) ?? []) {
        if (!this.work() || ref!==next) return false;
      }
    }
    return true;
  }
  private jsonIntrinsicsPristine(): boolean {
    for (const node of this.modules.honoJsonBoundaryNodes) {
      if (!this.work()) return false;
      let parent:ts.Node|undefined=node.parent, typeOnly=false;
      for (let depth=0; parent && depth<16; depth++,parent=parent.parent) {
        if (!this.work()) return false;
        if (ts.isTypeNode(parent)) { typeOnly=true; break; }
        if (ts.isStatement(parent) || ts.isExpression(parent)) break;
      }
      if (typeOnly) continue;
      let root:ts.Expression|undefined, kind:string|undefined;
      if (ts.isIdentifier(node)) {
        if (node.text==='globalThis') {
          if (this.modules.symbol(node)?.declarations?.length) continue;
          const member=node.parent;
          if (ts.isPropertyAccessExpression(member) && member.expression===node && !member.questionDotToken
            && ['JSON','Request'].includes(member.name.text)) { root=member; kind=member.name.text; }
          else if (ts.isElementAccessExpression(member) && member.expression===node && ts.isStringLiteralLike(member.argumentExpression)
            && ['JSON','Request'].includes(member.argumentExpression.text)) { root=member; kind=member.argumentExpression.text; }
          else return false;
        } else if (ts.isPropertyAccessExpression(node.parent) && node.parent.name===node) continue;
        else {
          if (this.modules.symbol(node)?.declarations?.length) continue;
          root=node; kind=node.text;
        }
      } else if (ts.isElementAccessExpression(node)) {
        if (this.modules.symbol(node.expression)?.declarations?.length) continue;
        root=node; kind=(node.argumentExpression as ts.StringLiteralLike).text;
      }
      if (!root) return false;
      const use=root.parent;
      if (kind==='Request' && ts.isNewExpression(use) && use.expression===root && !use.arguments?.some(ts.isSpreadElement)) continue;
      if (kind==='JSON' && ts.isPropertyAccessExpression(use) && use.expression===root && !use.questionDotToken
        && ['parse','stringify'].includes(use.name.text) && ts.isCallExpression(use.parent) && use.parent.expression===use
        && !use.parent.questionDotToken) continue;
      return false;
    }
    return true;
  }
  entry(fn: ts.FunctionLikeDeclaration): boolean { return this.complete && this.indexAvailable && this.scopeComplete && this.modules.indexComplete && this.entries.has(fn); }
  /** No middleware scheduler or version-specific cached-body identity is proven. */
  isolatedJsonEntry(fn: ts.FunctionLikeDeclaration): boolean { return this.entry(fn) && this.jsonEntries.has(fn); }
  registration(call: ts.CallExpression): boolean { return this.complete && this.indexAvailable && this.scopeComplete && this.modules.indexComplete && this.registrations.has(call); }
}
