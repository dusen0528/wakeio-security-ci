import * as ts from 'typescript';
import { StaticModules } from './modules.js';

export interface ForkRoleUse { identity: 'native' | 'unresolved' }
interface Binding { namespace: boolean; file: ts.SourceFile; declaration: ts.Node; pristine: boolean }
const packageName = (name: string) => name === 'child_process' || name === 'node:child_process';

/** Narrow API identity over the already charged index, never a second AST walk. */
export class ForkRoleModel {
  private readonly bindings = new Map<ts.Symbol, Binding[]>();
  private readonly supportedLoads = new Set<ts.Node>();
  private familyPristine = true;
  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly scopeComplete: boolean, private readonly indexAvailable: boolean) {
    for (const declaration of modules.importDeclarations) {
      if (!tick()) break;
      if (!ts.isStringLiteralLike(declaration.moduleSpecifier) || !packageName(declaration.moduleSpecifier.text)) continue;
      const clause = declaration.importClause;
      const named = clause?.namedBindings;
      if (!clause?.isTypeOnly && named) {
        if (ts.isNamespaceImport(named)) {
          this.add(named.name, true, named);
          if (!clause?.name) this.supportedLoads.add(declaration);
        } else {
          let supported = !clause?.name;
          for (const element of named.elements) {
            if (!tick()) { supported = false; break; }
            const fork = !element.isTypeOnly && (element.propertyName ?? element.name).text === 'fork';
            if (fork) this.add(element.name, false, element);
            else supported = false;
          }
          if (supported) this.supportedLoads.add(declaration);
        }
      }
    }
    for (const declaration of modules.requireDeclarations) {
      if (!tick()) break;
      const initializer = declaration.initializer as ts.CallExpression;
      if (!packageName((initializer.arguments[0] as ts.StringLiteral).text) || !modules.cjsGlobal(initializer.expression as ts.Identifier)) continue;
      const immutable = Boolean(declaration.parent.flags & ts.NodeFlags.Const);
      if (ts.isIdentifier(declaration.name)) {
        this.add(declaration.name, true, declaration);
        if (immutable) this.supportedLoads.add(initializer);
      } else if (ts.isObjectBindingPattern(declaration.name)) {
        const forkElement = (element: ts.BindingElement) => !element.dotDotDotToken && !element.initializer
          && ts.isIdentifier(element.name) && (element.propertyName ? ts.isIdentifier(element.propertyName) || ts.isStringLiteralLike(element.propertyName) : true)
          && (element.propertyName ?? element.name).getText().replace(/^['"]|['"]$/g, '') === 'fork';
        let supported = immutable;
        for (const element of declaration.name.elements) {
          if (!tick()) { supported = false; break; }
          const fork = forkElement(element);
          if (fork) this.add(element.name as ts.Identifier, false, element);
          else supported = false;
        }
        if (supported) this.supportedLoads.add(initializer);
      }
    }
    for (const load of modules.forkLoads) {
      if (!tick()) break;
      if (ts.isCallExpression(load)) {
        const callee = this.unwrap(load.expression);
        // A lexical require is not evidence of a native package load.
        if (callee && ts.isIdentifier(callee) && callee.text === 'require' && !modules.cjsGlobal(callee)) continue;
        if (this.inlineLoad(load)) { this.supportedLoads.add(load); continue; }
      }
      if (!this.supportedLoads.has(load)) this.familyPristine = false;
    }
    for (const [symbol, entries] of this.bindings) {
      let pristine = !modules.mutated.has(symbol) && !modules.mutatedMembers.has(symbol) && symbol.declarations?.length === 1;
      for (const ref of modules.references.get(symbol) ?? []) {
        if (!tick()) { pristine = false; break; }
        const entry = entries.find(item => item.file === ref.getSourceFile());
        if (!entry || !this.allowedReference(ref, entry)) pristine = false;
      }
      for (const entry of entries) entry.pristine = pristine;
      if (!pristine) this.familyPristine = false;
    }
  }
  private unwrap(expression: ts.Expression): ts.Expression | undefined {
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)) {
      if (!this.tick()) return undefined;
      expression = expression.expression;
    }
    return expression;
  }
  private add(name: ts.Identifier, namespace: boolean, declaration: ts.Node): void {
    const symbol = this.modules.symbol(name);
    if (!symbol) return;
    const entries = this.bindings.get(symbol) ?? [];
    entries.push({ namespace, declaration, file: name.getSourceFile(), pristine: false }); this.bindings.set(symbol, entries);
  }
  private allowedReference(ref: ts.Identifier, entry: Binding): boolean {
    if (ref.parent === entry.declaration) return true;
    if (!entry.namespace) return ts.isCallExpression(ref.parent) && ref.parent.expression === ref;
    const member = ref.parent;
    return ts.isPropertyAccessExpression(member) && member.expression === ref && member.name.text === 'fork'
      && ts.isCallExpression(member.parent) && member.parent.expression === member;
  }
  private inlineLoad(load: ts.CallExpression): boolean {
    const callee = this.unwrap(load.expression);
    const specifier = load.arguments.length === 1 ? this.unwrap(load.arguments[0]) : undefined;
    return !!callee && ts.isIdentifier(callee) && callee.text === 'require' && this.modules.cjsGlobal(callee)
      && !!specifier && ts.isStringLiteralLike(specifier) && packageName(specifier.text)
      && ts.isPropertyAccessExpression(load.parent) && load.parent.expression === load && load.parent.name.text === 'fork'
      && ts.isCallExpression(load.parent.parent) && load.parent.parent.expression === load.parent;
  }
  role(call: ts.CallExpression): ForkRoleUse | undefined {
    if (!this.tick()) return undefined;
    const expression = this.unwrap(call.expression);
    if (!expression) return undefined;
    let entry: Binding | undefined;
    let recognized = false;
    if (ts.isIdentifier(expression)) entry = this.bindings.get(this.modules.symbol(expression)!)?.find(item => !item.namespace && item.file === call.getSourceFile());
    else if (ts.isPropertyAccessExpression(expression) && expression.name.text === 'fork') {
      const receiver = this.unwrap(expression.expression);
      if (receiver && ts.isIdentifier(receiver)) entry = this.bindings.get(this.modules.symbol(receiver)!)?.find(item => item.namespace && item.file === call.getSourceFile());
      else if (receiver && ts.isCallExpression(receiver)) recognized = this.inlineLoad(receiver);
    }
    if (!entry && !recognized) return undefined;
    const initialized = !entry || !ts.isVariableDeclaration(entry.declaration) && !ts.isBindingElement(entry.declaration)
      || this.modules.ownerOf(call) !== this.modules.ownerOf(entry.declaration) || entry.declaration.pos < call.pos;
    return { identity: this.scopeComplete && this.indexAvailable && this.modules.indexComplete && this.familyPristine
      && (!entry || entry.pristine) && initialized ? 'native' : 'unresolved' };
  }
}
