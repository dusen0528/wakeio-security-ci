import * as ts from 'typescript';
import type { StaticFlow } from '../contracts.js';
import type { StaticModules } from './modules.js';

export interface NoSqlRoleUse {
  api?: 'marsdb' | 'mongodb2';
  inputRelated: boolean;
  outcome: 'selector_input' | 'where_input' | 'string_selector' | 'unknown_role';
  certainty?: 'tainted' | 'unknown';
  staticFlow?: StaticFlow;
  operatorNode?: ts.Node;
}
export function mergeNoSqlRoles(a?: NoSqlRoleUse, b?: NoSqlRoleUse): NoSqlRoleUse | undefined {
  if (!a) return b; if (!b) return a;
  const rank = { string_selector: 0, unknown_role: 1, selector_input: 2, where_input: 3 };
  return a.inputRelated !== b.inputRelated ? a.inputRelated ? a : b
    : rank[a.outcome] < rank[b.outcome] || rank[a.outcome] === rank[b.outcome] && a.certainty === 'unknown' && b.certainty === 'tainted' ? b : a;
}
function unwrap(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node)) node = node.expression;
  return node;
}
function name(node: ts.PropertyName | ts.Expression): string | undefined {
  return ts.isIdentifier(node) || ts.isStringLiteralLike(node) ? node.text : undefined;
}
function constant(node: ts.VariableDeclaration): boolean {
  return ts.isVariableDeclarationList(node.parent) && !!(node.parent.flags & ts.NodeFlags.Const);
}
function path(node: ts.Expression): string[] {
  node = unwrap(node);
  if (ts.isIdentifier(node)) return [node.text];
  if (ts.isPropertyAccessExpression(node)) return [...path(node.expression), node.name.text];
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) return [...path(node.expression), node.argumentExpression.text];
  return [];
}
interface Witness { valid: boolean; }
// Declared MarsDB 0.6.11 query entry points, not a generic find/update heuristic.
const SELECTORS = new Set(['find', 'findOne', 'update', 'remove', 'count', 'ids']);

export class NoSqlRoleModel {
  private readonly calls = new WeakMap<ts.CallExpression, Witness | null>();
  private readonly exports = new Map<string, Witness | null>();
  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly scopeComplete: boolean) {}

  bound(call: ts.CallExpression): boolean { return this.witness(call) !== undefined; }
  qualified(call: ts.CallExpression): boolean { return this.modules.indexComplete && this.witness(call)?.valid === true; }
  negativeProof(call: ts.CallExpression): boolean { return this.scopeComplete && this.qualified(call); }

  private witness(call: ts.CallExpression): Witness | undefined {
    const cached = this.calls.get(call); if (cached !== undefined) return cached ?? undefined;
    this.calls.set(call, null);
    const callee = unwrap(call.expression);
    if (!ts.isPropertyAccessExpression(callee) || !SELECTORS.has(callee.name.text)) return undefined;
    const witness = this.collection(callee.expression, new Set(), 0);
    if (witness) this.calls.set(call, witness);
    return witness;
  }
  private collection(expression: ts.Expression, seen: Set<ts.Symbol>, depth: number): Witness | undefined {
    if (!this.tick() || depth > 8) return undefined;
    expression = unwrap(expression);
    if (ts.isPropertyAccessExpression(expression) && ts.isIdentifier(expression.expression)) {
      const symbol = this.modules.symbol(expression.expression);
      const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (declaration && ts.isNamespaceImport(declaration)) {
        const load = declaration.parent.parent;
        if (ts.isImportDeclaration(load) && ts.isStringLiteralLike(load.moduleSpecifier) && !load.importClause?.isTypeOnly) {
          const file = this.modules.resolveSourceModule(expression.getSourceFile(), load.moduleSpecifier.text);
          if (file.kind === 'file') {
            const witness = this.exported(file.file, expression.name.text, seen, depth + 1);
            if (witness) return { valid: witness.valid && this.referencesClosed(symbol!, true) };
          }
        }
      }
      return undefined;
    }
    if (!ts.isIdentifier(expression)) return undefined;
    const symbol = this.modules.symbol(expression);
    if (!symbol || seen.has(symbol) || symbol.declarations?.length !== 1) return undefined;
    seen.add(symbol);
    const declaration = symbol.declarations[0];
    if (ts.isImportSpecifier(declaration)) {
      const load = declaration.parent.parent.parent;
      if (ts.isImportDeclaration(load) && ts.isStringLiteralLike(load.moduleSpecifier) && !declaration.isTypeOnly && !load.importClause?.isTypeOnly) {
        const file = this.modules.resolveSourceModule(expression.getSourceFile(), load.moduleSpecifier.text);
        if (file.kind === 'file') {
          const witness = this.exported(file.file, (declaration.propertyName ?? declaration.name).text, seen, depth + 1);
          if (witness) return { valid: witness.valid && this.referencesClosed(symbol) };
        }
      }
      return undefined;
    }
    if (!ts.isVariableDeclaration(declaration) || !declaration.initializer || !constant(declaration)) return undefined;
    const initializer = unwrap(declaration.initializer);
    const base = ts.isNewExpression(initializer) ? this.constructorWitness(initializer) : this.collection(initializer, seen, depth + 1);
    return base ? { valid: base.valid && this.referencesClosed(symbol) } : undefined;
  }
  private exported(file: ts.SourceFile, key: string, seen: Set<ts.Symbol>, depth: number): Witness | undefined {
    const identity = `${file.fileName}\0${key}`;
    const cached = this.exports.get(identity); if (cached !== undefined) return cached ?? undefined;
    this.exports.set(identity, null);
    let selected: ts.VariableDeclaration | undefined;
    for (const statement of file.statements) {
      if (!this.tick()) return undefined;
      if (!ts.isVariableStatement(statement) || !statement.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!this.tick()) return undefined;
        if (ts.isIdentifier(declaration.name) && declaration.name.text === key) {
          if (selected) return undefined;
          selected = declaration;
        }
      }
    }
    const witness = selected && ts.isIdentifier(selected.name) ? this.collection(selected.name, seen, depth + 1) : undefined;
    if (!witness) return undefined;
    const result = { valid: witness.valid && this.consumersClosed(file, key) };
    this.exports.set(identity, result);
    return result;
  }
  private consumersClosed(file: ts.SourceFile, key: string): boolean {
    for (const load of this.modules.importDeclarations) {
      if (!this.tick()) return false;
      if (!ts.isStringLiteralLike(load.moduleSpecifier) || !load.moduleSpecifier.text.startsWith('.')) continue;
      const resolved = this.modules.resolveSourceModule(load.getSourceFile(), load.moduleSpecifier.text);
      if (resolved.kind !== 'file' || resolved.file !== file) continue;
      const clause = load.importClause;
      if (!clause || clause.name) return false;
      if (clause.isTypeOnly) continue;
      const bindings = clause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) {
        const symbol = this.modules.symbol(bindings.name);
        if (!symbol || !this.referencesClosed(symbol, true)) return false;
      } else if (bindings && ts.isNamedImports(bindings)) {
        for (const item of bindings.elements) {
          if (!this.tick()) return false;
          if (item.isTypeOnly || (item.propertyName ?? item.name).text !== key) continue;
          const symbol = this.modules.symbol(item.name);
          if (!symbol || !this.referencesClosed(symbol)) return false;
        }
      }
    }
    for (const load of this.modules.requireDeclarations) {
      if (!this.tick()) return false;
      const initializer = load.initializer;
      if (!initializer || !ts.isCallExpression(initializer) || initializer.arguments.length !== 1 || !ts.isStringLiteralLike(initializer.arguments[0]) || !initializer.arguments[0].text.startsWith('.')) continue;
      const resolved = this.modules.resolveSourceModule(load.getSourceFile(), initializer.arguments[0].text);
      if (resolved.kind === 'file' && resolved.file === file) return false; // This lane does not certify CJS consumer effects.
    }
    return true;
  }
  private constructorWitness(node: ts.NewExpression): Witness | undefined {
    const callee = unwrap(node.expression);
    let binding: ts.Identifier; let imported: string;
    if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'Collection' && ts.isIdentifier(callee.expression)) {
      binding = callee.expression; imported = 'namespace';
    } else if (ts.isIdentifier(callee)) { binding = callee; imported = 'Collection'; }
    else return undefined;
    const symbol = this.modules.symbol(binding);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    let load: ts.ImportDeclaration | undefined;
    if (declaration && ts.isNamespaceImport(declaration) && imported === 'namespace' && ts.isImportDeclaration(declaration.parent.parent)) load = declaration.parent.parent;
    else if (declaration && ts.isImportSpecifier(declaration) && imported === 'Collection'
      && (declaration.propertyName ?? declaration.name).text === 'Collection' && !declaration.isTypeOnly && ts.isImportDeclaration(declaration.parent.parent.parent)) load = declaration.parent.parent.parent;
    if (!load || !ts.isStringLiteralLike(load.moduleSpecifier) || load.moduleSpecifier.text !== 'marsdb' || load.importClause?.isTypeOnly) return undefined;
    let valid = !this.modules.mutated.has(symbol!) && !this.modules.mutatedMembers.has(symbol!);
    for (const reference of this.modules.references.get(symbol!) ?? []) {
      if (!this.tick()) return { valid: false };
      if (reference === binding || ts.isImportSpecifier(reference.parent) || ts.isNamespaceImport(reference.parent)) continue;
      const parent = reference.parent;
      if (imported === 'namespace' && ts.isPropertyAccessExpression(parent) && parent.expression === reference && parent.name.text === 'Collection'
        && ts.isNewExpression(parent.parent) && parent.parent.expression === parent) continue;
      if (imported === 'Collection' && ts.isNewExpression(parent) && parent.expression === reference) continue;
      valid = false;
    }
    return { valid: valid && node.arguments?.length === 1 && ts.isStringLiteralLike(node.arguments[0]) };
  }
  private referencesClosed(symbol: ts.Symbol, namespace = false): boolean {
    if (this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      if (ts.isVariableDeclaration(reference.parent) && reference.parent.name === reference) continue;
      if (ts.isImportSpecifier(reference.parent) || ts.isNamespaceImport(reference.parent)) continue;
      let member = reference.parent;
      if (namespace && ts.isPropertyAccessExpression(member) && member.expression === reference) member = member.parent;
      if (ts.isPropertyAccessExpression(member) && (namespace || member.expression === reference) && ts.isCallExpression(member.parent) && member.parent.expression === member) continue;
      return false;
    }
    return true;
  }

  /** NoSQL selector-only syntax qualification. It never changes general taint. */
  stringAt(expression: ts.Expression, sink: ts.CallExpression): boolean {
    if (!this.negativeProof(sink) || !this.tick()) return false;
    expression = unwrap(expression);
    if (ts.isStringLiteralLike(expression)) return true;
    const selectedPath = path(expression);
    // Repeated property reads may execute getters. Only a local const snapshot
    // can carry this exclusion; request-shaped roots do not prove plain data.
    if (selectedPath.length !== 1 || !ts.isIdentifier(expression)) return false;
    let root: ts.Expression = expression;
    while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) root = root.expression;
    const symbol = this.modules.symbol(root);
    if (!symbol || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
    const declaration = symbol.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration || !ts.isVariableDeclaration(declaration) || !constant(declaration)) return false;
    // Reject aliases/containers of the value/root; tracked member state is not a heap model.
    for (const ref of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      let use: ts.Node = ref;
      while ((ts.isPropertyAccessExpression(use.parent) || ts.isElementAccessExpression(use.parent)) && use.parent.expression === use) use = use.parent;
      if (ts.isVariableDeclaration(use.parent) && use.parent.initializer === use || ts.isShorthandPropertyAssignment(use.parent)) return false;
    }
    let statement: ts.Node = sink;
    while (statement.parent && !ts.isBlock(statement.parent) && !ts.isSourceFile(statement.parent)) statement = statement.parent;
    if (!statement.parent || !ts.isBlock(statement.parent)) return false;
    const siblings = statement.parent.statements;
    const index = siblings.indexOf(statement as ts.Statement);
    for (let i = index - 1; i >= 0; i--) {
      if (!this.tick()) return false;
      const prior = siblings[i];
      if (!ts.isIfStatement(prior) || prior.elseStatement) continue;
      const condition = unwrap(prior.expression);
      if (!ts.isBinaryExpression(condition) || condition.operatorToken.kind !== ts.SyntaxKind.ExclamationEqualsEqualsToken
        || !ts.isTypeOfExpression(condition.left) || !ts.isStringLiteralLike(condition.right) || condition.right.text !== 'string') continue;
      const guarded = unwrap(condition.left.expression);
      if (path(guarded).join('.') !== selectedPath.join('.')) continue;
      let guardedRoot = guarded;
      while (ts.isPropertyAccessExpression(guardedRoot) || ts.isElementAccessExpression(guardedRoot)) guardedRoot = guardedRoot.expression;
      if (this.modules.symbol(guardedRoot) !== symbol) continue;
      const last = ts.isBlock(prior.thenStatement) ? prior.thenStatement.statements.at(-1) : prior.thenStatement;
      if (!last || !(ts.isReturnStatement(last) || ts.isThrowStatement(last))) continue;
      let invalid = false;
      const visit = (node: ts.Node): void => {
        if (!this.tick()) { invalid = true; return; }
        if (node !== statement && (ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node))) return;
        if (ts.isCallExpression(node) && node !== sink || ts.isNewExpression(node) || ts.isDeleteExpression(node)
          || ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)
          || ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) invalid = true;
        node.forEachChild(visit);
      };
      for (let j = i + 1; j <= index; j++) visit(siblings[j]);
      return !invalid;
    }
    return false;
  }
}
