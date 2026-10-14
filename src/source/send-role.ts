import * as ts from 'typescript';
import type { StaticModules } from './modules.js';

/** Positive, declared API shape only. Installed package identity is never certified. */
export interface SendStreamRole {
  readonly origin: ts.CallExpression;
  readonly identity: object;
  valid: boolean;
}

export class SendRoleModel {
  private readonly bindings = new Map<ts.Symbol, boolean>();
  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean) {}

  factory(call: ts.CallExpression): boolean {
    if (call.questionDotToken || call.arguments.some(ts.isSpreadElement) || call.arguments.length < 1
      || !ts.isIdentifier(call.expression)) return false;
    const symbol = this.modules.symbol(call.expression);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!symbol || !declaration) return false;
    let load: ts.Node | undefined;
    if (ts.isVariableDeclaration(declaration) && declaration.initializer && ts.isCallExpression(declaration.initializer)) {
      const init = declaration.initializer;
      if (ts.isIdentifier(init.expression) && init.expression.text === 'require' && this.modules.cjsGlobal(init.expression)
        && init.arguments.length === 1 && ts.isStringLiteralLike(init.arguments[0]) && init.arguments[0].text === 'send') load = init;
    } else if (ts.isImportClause(declaration) && declaration.name && !declaration.isTypeOnly
      && ts.isImportDeclaration(declaration.parent) && ts.isStringLiteralLike(declaration.parent.moduleSpecifier)
      && declaration.parent.moduleSpecifier.text === 'send') load = declaration.parent;
    if (!load) return false;
    const cached = this.bindings.get(symbol);
    if (cached !== undefined) return cached;
    let valid = this.modules.indexComplete && !this.modules.mutated.has(symbol) && !this.modules.mutatedMembers.has(symbol)
      && this.modules.moduleConfigurations.resolve(call.getSourceFile().fileName, 'send').kind === 'external';
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) { valid = false; break; }
      if (reference.parent === declaration) continue;
      const parent = reference.parent;
      if (ts.isCallExpression(parent) && parent.expression === reference) continue;
      if (ts.isPropertyAccessExpression(parent) && parent.expression === reference && parent.name.text === 'mime') continue;
      valid = false;
    }
    this.bindings.set(symbol, valid); return valid;
  }
}
