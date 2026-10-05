import * as ts from 'typescript';
import { URL } from 'node:url';
import type { StaticModules } from './modules.js';
import type { StaticFlow } from '../contracts.js';
import type { UrlFragment } from './url-destination.js';

export interface HttpRoleUse {
  bound: boolean;
  inputRelated: boolean;
  outcome: 'target_input' | 'unknown_role' | 'encoded_query_fixed_initial_url' | 'payload_only_fixed_initial_url';
  certainty?: 'tainted' | 'unknown';
  staticFlow?: StaticFlow;
}
export function mergeHttpRoles(left: HttpRoleUse | undefined, right: HttpRoleUse | undefined): HttpRoleUse | undefined {
  if (!left) return right; if (!right) return left;
  const rank = { target_input: 3, unknown_role: 2, encoded_query_fixed_initial_url: 1, payload_only_fixed_initial_url: 0 };
  // A no-input context contributes API inventory, not a candidate role or
  // source trace. Do not combine its unknown role with another context's input.
  const preferred = left.inputRelated !== right.inputRelated ? right.inputRelated ? right : left
    : rank[right.outcome] > rank[left.outcome]
    || rank[right.outcome] === rank[left.outcome] && left.certainty === 'unknown' && right.certainty === 'tainted' ? right : left;
  return { ...preferred, bound: left.bound || right.bound, inputRelated: left.inputRelated || right.inputRelated };
}

const METHODS = new Set(['request', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
function unwrapped(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node)) node = node.expression;
  return node;
}
function requestReceiver(call: ts.CallExpression): ts.Identifier | undefined {
  const callee = unwrapped(call.expression);
  if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'request' && ts.isIdentifier(callee.expression)) return callee.expression;
  // Element spellings are recognizable identity, but never qualification grammar.
  if (ts.isElementAccessExpression(callee) && ts.isIdentifier(callee.expression)
    && ts.isStringLiteralLike(callee.argumentExpression) && callee.argumentExpression.text === 'request') return callee.expression;
  return undefined;
}
export function legacyAxiosRequest(call: ts.CallExpression): boolean { return requestReceiver(call)?.text === 'axios'; }

/** Fixed INITIAL field only; not runtime HTTP/proxy/redirect safety. */
export function fixedInitialHttpUrl(parts: readonly UrlFragment[] | undefined): boolean {
  if (!parts || parts.length !== 1 || !('literal' in parts[0])) return false;
  const value = parts[0].literal;
  if (value.length > 2048 || /[\u0000-\u0020\u007f\\]/.test(value) || !/^https?:\/\//.test(value)) return false;
  try {
    const parsed = new URL(value);
    if (!parsed.hostname || parsed.username || parsed.password || parsed.hash || !['http:', 'https:'].includes(parsed.protocol)) return false;
    const canonical = value.replace(/^(https?:\/\/[^/:?#]+):(80|443)([/?]|$)/, (match, authority: string, port: string, tail: string) =>
      authority.startsWith('https:') && port === '443' || authority.startsWith('http:') && port === '80' ? authority + tail : match);
    return parsed.href === canonical;
  } catch { return false; }
}

/** Indexed snapshot proof, never a library import or target execution. */
export class HttpRoleModel {
  private readonly bindings = new Map<ts.Symbol, Set<ts.SourceFile>>();
  private pristine = true;
  private readonly shapes = new WeakMap<ts.ObjectLiteralExpression, boolean>();

  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly scopeComplete: boolean, indexAvailable: boolean) {
    if (!indexAvailable) this.pristine = false;
    for (const declaration of modules.importDeclarations) {
      if (!tick()) { this.pristine = false; break; }
      if (!ts.isStringLiteralLike(declaration.moduleSpecifier) || declaration.moduleSpecifier.text !== 'axios') continue;
      const clause = declaration.importClause;
      if (!clause || clause.isTypeOnly) { this.pristine = false; continue; }
      const names: ts.Identifier[] = [];
      if (clause.name) names.push(clause.name);
      if (clause.namedBindings) {
        if (ts.isNamedImports(clause.namedBindings)) {
          for (const specifier of clause.namedBindings.elements) {
            if (!specifier.isTypeOnly && (specifier.propertyName ?? specifier.name).text === 'default') names.push(specifier.name);
            else this.pristine = false;
          }
        } else this.pristine = false;
      }
      for (const name of names) this.addBinding(name);
    }
    const supportedRequires = new Set<ts.CallExpression>();
    for (const declaration of modules.requireDeclarations) {
      if (!tick()) { this.pristine = false; break; }
      const init = declaration.initializer as ts.CallExpression;
      if ((init.arguments[0] as ts.StringLiteral).text !== 'axios') continue;
      const list = declaration.parent;
      if (!ts.isIdentifier(declaration.name) || !ts.isVariableDeclarationList(list) || !(list.flags & ts.NodeFlags.Const)
        || !ts.isVariableStatement(list.parent) || !ts.isSourceFile(list.parent.parent)
        || !modules.cjsGlobal(init.expression as ts.Identifier)) { this.pristine = false; continue; }
      this.addBinding(declaration.name);
      supportedRequires.add(init);
    }
    // Other exact-package loads may customize the shared instance. Observe them
    // in the common index without granting new API coverage or executing a load.
    for (const load of modules.axiosLoads) {
      if (!tick()) { this.pristine = false; break; }
      if (!ts.isCallExpression(load) || !supportedRequires.has(load)) this.pristine = false;
    }
    // Validate every same-package collected binding, not only the selected call's file.
    for (const symbol of this.bindings.keys()) {
      const references = modules.references.get(symbol);
      if (!references?.length || modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol)) this.pristine = false;
      for (const reference of references ?? []) {
        if (!tick()) { this.pristine = false; break; }
        const parent = reference.parent;
        if (ts.isImportClause(parent) && parent.name === reference || ts.isImportSpecifier(parent) && parent.name === reference
          || ts.isVariableDeclaration(parent) && parent.name === reference) continue;
        if (ts.isPropertyAccessExpression(parent) && parent.expression === reference && METHODS.has(parent.name.text)
          && ts.isCallExpression(parent.parent) && parent.parent.expression === parent) continue;
        this.pristine = false;
      }
    }
  }

  private addBinding(name: ts.Identifier): void {
    const symbol = this.modules.symbol(name);
    if (!symbol) { this.pristine = false; return; }
    // TypeScript may merge script-file globals. A package declaration in one
    // Node module never authenticates the same spelling in another file.
    const files = this.bindings.get(symbol) ?? new Set<ts.SourceFile>();
    files.add(name.getSourceFile()); this.bindings.set(symbol, files);
    if ((symbol.declarations?.length ?? 0) !== 1) this.pristine = false;
  }

  bound(call: ts.CallExpression): boolean {
    const receiver = requestReceiver(call);
    return Boolean(receiver && this.bindings.get(this.modules.symbol(receiver)!)?.has(call.getSourceFile()));
  }

  canQualify(call: ts.CallExpression): boolean {
    return this.scopeComplete && this.pristine && this.modules.indexComplete && this.bound(call)
      && ts.isPropertyAccessExpression(unwrapped(call.expression)) && call.arguments.length === 1;
  }

  /** Syntax/reference validation memoized per construction; values are captured elsewhere. */
  closedShape(node: ts.ObjectLiteralExpression): boolean {
    if (this.bindings.size === 0) return false;
    const cached = this.shapes.get(node); if (cached !== undefined) return cached;
    const finish = (value: boolean) => { this.shapes.set(node, value); return value; };
    if (node.properties.length > 16) return finish(false);
    const keys = new Set<string>(); let hasUrl = false;
    for (const property of node.properties) {
      if (!this.tick()) return finish(false);
      if (ts.isShorthandPropertyAssignment(property)) {
        const key = property.name.text;
        if (property.objectAssignmentInitializer || !['url', 'data'].includes(key) || keys.has(key)) return finish(false);
        keys.add(key); if (key === 'url') hasUrl = true;
        continue;
      }
      if (!ts.isPropertyAssignment(property) || ts.isComputedPropertyName(property.name)
        || !(ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))) return finish(false);
      const key = property.name.text;
      if (keys.has(key)) return finish(false); keys.add(key);
      if (key === 'url') { hasUrl = true; if (!this.sideEffectFree(property.initializer)) return finish(false); }
      else if (key === 'data') { if (!this.sideEffectFree(property.initializer)) return finish(false); }
      else if (key === 'method') {
        if (!ts.isStringLiteralLike(property.initializer) || !/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/i.test(property.initializer.text)) return finish(false);
      } else if (key === 'headers') {
        if (!ts.isObjectLiteralExpression(property.initializer) || property.initializer.properties.length > 16) return finish(false);
        const headers = new Set<string>();
        for (const header of property.initializer.properties) {
          if (!this.tick()) return finish(false);
          if (!ts.isPropertyAssignment(header) || ts.isComputedPropertyName(header.name)
            || !(ts.isIdentifier(header.name) || ts.isStringLiteralLike(header.name))
            || /^(host|:authority)$/i.test(header.name.text) || headers.has(header.name.text.toLowerCase()) || !ts.isStringLiteralLike(header.initializer)) return finish(false);
          headers.add(header.name.text.toLowerCase());
        }
      } else return finish(false);
    }
    if (!hasUrl) return finish(false);
    let parent: ts.Node = node;
    while (parent.parent && (ts.isParenthesizedExpression(parent.parent) || ts.isAsExpression(parent.parent)
      || ts.isTypeAssertionExpression(parent.parent) || ts.isNonNullExpression(parent.parent))) parent = parent.parent;
    if (ts.isCallExpression(parent.parent) && parent.parent.arguments[0] === parent) return finish(this.bound(parent.parent));
    const declaration = parent.parent;
    if (!ts.isVariableDeclaration(declaration) || declaration.initializer !== parent || !ts.isIdentifier(declaration.name)
      || !ts.isVariableDeclarationList(declaration.parent) || !(declaration.parent.flags & ts.NodeFlags.Const)) return finish(false);
    const symbol = this.modules.symbol(declaration.name);
    const references = symbol && this.modules.references.get(symbol);
    if (!symbol || !references?.length || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return finish(false);
    for (const reference of references) {
      if (!this.tick()) return finish(false);
      if (reference === declaration.name) continue;
      const call = reference.parent;
      if (!ts.isCallExpression(call) || call.arguments[0] !== reference || !this.bound(call)
        || this.modules.ownerOf(call) !== this.modules.ownerOf(declaration)) return finish(false);
    }
    return finish(true);
  }

  private sideEffectFree(expression: ts.Expression): boolean {
    let work = 0;
    const visit = (node: ts.Node, depth: number): boolean => {
      if (++work > 128 || depth > 16 || !this.tick()) return false;
      if (ts.isCallExpression(node) || ts.isNewExpression(node) || ts.isAwaitExpression(node) || ts.isYieldExpression(node)
        || ts.isSpreadAssignment(node) || ts.isSpreadElement(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)
        || ts.isMethodDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
        || ts.isDeleteExpression(node) || ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
          && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
        || (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
          && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator)) return false;
      let valid = true; node.forEachChild(child => { if (valid) valid = visit(child, depth + 1); }); return valid;
    };
    return visit(expression, 0);
  }
}
