import * as ts from 'typescript';
import type { StaticModules } from './modules.js';

export type BrowserLocationRole = 'global_browser_shape' | 'closed_local_object' | 'unknown_receiver';

/** Only direct dot-spelled window.location; bracket and nested href have no proof here. */
export function directBrowserLocationReceiver(node: ts.BinaryExpression): ts.Identifier | undefined {
  const target = node.left;
  if (!ts.isPropertyAccessExpression(target)
    || !ts.isIdentifier(target.expression) || target.expression.text !== 'window') return undefined;
  return target.name.text === 'location' ? target.expression : undefined;
}

export function mergeBrowserLocationRoles(left: BrowserLocationRole | undefined,
  right: BrowserLocationRole | undefined): BrowserLocationRole | undefined {
  if (!left && !right) return undefined;
  // Missing or uncertain contexts cannot certify the negative receiver proof.
  if (!left || !right || left === 'unknown_receiver' || right === 'unknown_receiver') return 'unknown_receiver';
  return left === 'global_browser_shape' || right === 'global_browser_shape' ? 'global_browser_shape' : 'closed_local_object';
}

/** Collected private data-slot proof only; ambient callable/realm closure is not certified. */
export class BrowserLocationRoleModel {
  private readonly closed = new Map<ts.Symbol, boolean>();

  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly scopeComplete: boolean, private readonly maxDepth: number) {}

  role(node: ts.BinaryExpression): BrowserLocationRole | undefined {
    const root = directBrowserLocationReceiver(node);
    if (!root) return undefined;
    if (!this.scopeComplete || !this.modules.indexComplete || !this.tick()) return 'unknown_receiver';
    const symbol = this.modules.symbol(root);
    if (!symbol?.declarations?.length) return 'global_browser_shape'; // Shape, not runtime browser identity.
    if (!this.closed.has(symbol)) this.closed.set(symbol, this.closedBinding(symbol));
    return this.closed.get(symbol) ? 'closed_local_object' : 'unknown_receiver';
  }

  private closedBinding(symbol: ts.Symbol): boolean {
    if (symbol.declarations?.length !== 1 || this.modules.mutated.has(symbol)
      || this.modules.isLocalExportBinding(symbol)) return false;
    const declaration = symbol.declarations[0];
    if (!ts.isVariableDeclaration(declaration) || !ts.isIdentifier(declaration.name)
      || !ts.isVariableDeclarationList(declaration.parent) || !(declaration.parent.flags & ts.NodeFlags.Const)
      || !declaration.initializer || !ts.isObjectLiteralExpression(declaration.initializer)) return false;
    const statement = declaration.parent.parent;
    if (ts.isVariableStatement(statement) && statement.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword)) return false;
    // A script's global lexical binding is visible to absent ambient evaluators.
    // Function-owned or module-private bindings still require the collected audit.
    if (ts.isSourceFile(this.modules.ownerOf(declaration)) && !ts.isExternalModule(declaration.getSourceFile())) return false;
    // Modeled evaluation/mutation boundaries can alter descriptors without a
    // receiver reference; this veto does not authenticate other ambient callables.
    if (this.modules.browserLocationBoundaryNodes.length || this.modules.constructorBoundaryNodes.length
      || this.modules.archiveIntrinsicBoundaryNodes.length) return false;
    if (!this.dataLiteral(declaration.initializer, 0)) return false;
    const references = this.modules.references.get(symbol);
    if (!references?.length) return false;
    for (const reference of references) {
      if (!this.tick()) return false;
      if (reference === declaration.name) continue;
      const target = reference.parent;
      if (!ts.isPropertyAccessExpression(target)
        || target.expression !== reference) return false;
      const assignment = target.parent;
      if (!ts.isBinaryExpression(assignment) || assignment.left !== target
        || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken
        || directBrowserLocationReceiver(assignment) !== reference) return false;
    }
    return true;
  }

  private dataLiteral(node: ts.Expression, depth: number): boolean {
    if (!this.tick() || depth > this.maxDepth) return false;
    if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)
      || [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword].includes(node.kind)) return true;
    if (!ts.isObjectLiteralExpression(node)) return false;
    const names = new Set<string>();
    for (const property of node.properties) {
      if (!this.tick() || !ts.isPropertyAssignment(property)
        || !(ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))) return false;
      const name = property.name.text;
      if (names.has(name) || ['__proto__', 'prototype', 'constructor'].includes(name)) return false;
      names.add(name);
      if (!this.dataLiteral(property.initializer, depth + 1)) return false;
    }
    return depth > 0 || names.has('location');
  }
}
