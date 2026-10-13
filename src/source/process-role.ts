import * as ts from 'typescript';
import type { StaticFlow } from '../contracts.js';
import { ChildProcessBindings, type ChildProcessBindingUse } from './fork-role.js';
import type { StaticModules } from './modules.js';

export const PROCESS_METHODS = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync']);
export interface ProcessRoleUse {
  api: string;
  identity: 'native' | 'unresolved';
  shell: 'enabled' | 'disabled' | 'unresolved';
  inputRelated: boolean;
  outcome: 'command_input' | 'executable_input' | 'argv_shell_input' | 'shell_executable_input' | 'unknown_role' | 'argv_only_fixed_executable' | 'no_input';
  operandIndex?: number;
  executable?: boolean;
  certainty?: 'tainted' | 'unknown';
  staticFlow?: StaticFlow;
}
export interface ProcessLayout {
  shell: ProcessRoleUse['shell'];
  qualified: boolean;
  argvIndex?: number;
  optionsIndex?: number;
  shellField: boolean;
}

/** A risky input context wins over inventory/exclusion; it keeps its own operand trace. */
export function mergeProcessRoles(left?: ProcessRoleUse, right?: ProcessRoleUse): ProcessRoleUse | undefined {
  if (!left) return right; if (!right) return left;
  const rank = { command_input: 6, executable_input: 5, argv_shell_input: 4, shell_executable_input: 3, unknown_role: 2, argv_only_fixed_executable: 1, no_input: 0 };
  const candidate = (use: ProcessRoleUse) => use.inputRelated && rank[use.outcome] >= 2;
  const preferred = candidate(left) !== candidate(right) ? candidate(right) ? right : left
    : left.inputRelated !== right.inputRelated ? right.inputRelated ? right : left
    : rank[right.outcome] > rank[left.outcome] || rank[right.outcome] === rank[left.outcome]
      && left.certainty === 'unknown' && right.certainty === 'tainted' ? right : left;
  return { ...preferred, inputRelated: left.inputRelated || right.inputRelated };
}

/** Exact-load lexical identity and bounded literal role proof; no target evaluation. */
export class ProcessRoleModel {
  private readonly bindings: ChildProcessBindings;
  private readonly literals = new WeakMap<ts.Expression, { node: ts.Expression; readonly: boolean }>();
  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly scopeComplete: boolean, private readonly indexAvailable: boolean) {
    this.bindings = new ChildProcessBindings(modules, tick, scopeComplete, indexAvailable, new Set([...PROCESS_METHODS, 'fork']), true);
  }
  binding(call: ts.CallExpression): ChildProcessBindingUse | undefined {
    const use = this.bindings.binding(call);
    return use && PROCESS_METHODS.has(use.method) ? use : undefined;
  }
  private unwrap(expression: ts.Expression): ts.Expression | undefined {
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)) {
      if (!this.tick()) return undefined;
      expression = expression.expression;
    }
    return expression;
  }
  private literal(expression: ts.Expression): { node: ts.Expression; readonly: boolean } | undefined {
    const unwrapped = this.unwrap(expression); if (!unwrapped) return undefined;
    const cached = this.literals.get(unwrapped); if (cached) return cached;
    if (!ts.isIdentifier(unwrapped)) return { node: unwrapped, readonly: true };
    const symbol = this.modules.symbol(unwrapped);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer || !ts.isIdentifier(declaration.name)) return undefined;
    const node = this.unwrap(declaration.initializer); if (!node) return undefined;
    let readonly = Boolean(declaration.parent.flags & ts.NodeFlags.Const)
      && !this.modules.mutated.has(symbol!) && !this.modules.mutatedMembers.has(symbol!);
    for (const reference of this.modules.references.get(symbol!) ?? []) {
      if (!this.tick()) { readonly = false; break; }
      if (reference === declaration.name) continue;
      const call = reference.parent;
      if (!ts.isCallExpression(call) || !this.binding(call)
        || ![1, 2].some(index => call.arguments[index] === reference)
        || this.modules.ownerOf(call) === this.modules.ownerOf(declaration) && call.pos < declaration.pos) readonly = false;
    }
    const result = { node, readonly }; this.literals.set(unwrapped, result); return result;
  }
  private callback(expression: ts.Expression | undefined): boolean {
    if (!expression) return false;
    const node = this.unwrap(expression);
    return !!node && (ts.isArrowFunction(node) || ts.isFunctionExpression(node));
  }
  private absent(expression: ts.Expression | undefined): boolean {
    if (!expression) return true;
    const node = this.unwrap(expression);
    return !!node && (node.kind === ts.SyntaxKind.NullKeyword || ts.isIdentifier(node) && node.text === 'undefined' && !this.modules.symbol(node)?.declarations?.length);
  }
  layout(call: ts.CallExpression, binding: ChildProcessBindingUse): ProcessLayout {
    const command = binding.method === 'exec' || binding.method === 'execSync';
    // Node 22 copies options into a null-prototype record. Native namespace
    // writes/escapes are covered by the lexical family, not unrelated Object use.
    let qualified = binding.identity === 'native' && this.scopeComplete && this.indexAvailable && this.modules.indexComplete;
    for (const argument of call.arguments) {
      if (!this.tick()) { qualified = false; break; }
      if (ts.isSpreadElement(argument)) qualified = false;
    }
    let argvIndex: number | undefined, optionsIndex: number | undefined;
    const second = call.arguments[1]; const literal = second ? this.literal(second) : undefined;
    if (command) {
      if (second && !(binding.method === 'exec' && this.callback(second)) && !this.absent(second)) optionsIndex = 1;
      if (call.arguments.length > (binding.method === 'exec' ? 3 : 2)) qualified = false;
    } else if (literal && ts.isArrayLiteralExpression(literal.node)) {
      argvIndex = 1; qualified &&= literal.readonly;
      for (const element of literal.node.elements) {
        if (!this.tick()) { qualified = false; break; }
        if (ts.isSpreadElement(element) || ts.isOmittedExpression(element)) qualified = false;
      }
      if (call.arguments[2] && !(binding.method === 'execFile' && this.callback(call.arguments[2])) && !this.absent(call.arguments[2])) optionsIndex = 2;
    } else if (this.absent(second)) {
      if (call.arguments[2] && !this.absent(call.arguments[2])) optionsIndex = 2;
    } else if (!(binding.method === 'execFile' && this.callback(second))) {
      optionsIndex = 1;
      if (!literal || !ts.isObjectLiteralExpression(literal.node)) { argvIndex = 1; qualified = false; }
    }
    if (!command && call.arguments.length > (binding.method === 'execFile' ? 4 : 3)) qualified = false;
    let shell: ProcessRoleUse['shell'] = command ? 'enabled' : 'disabled';
    let shellField = false;
    if (optionsIndex !== undefined) {
      const options = this.literal(call.arguments[optionsIndex]);
      if (!options || !ts.isObjectLiteralExpression(options.node)) qualified = false;
      else {
        qualified &&= options.readonly;
        if (options.node.properties.length > 32) qualified = false;
        for (const property of options.node.properties) {
          if (!this.tick()) { qualified = false; break; }
          if (!ts.isPropertyAssignment(property) || ts.isComputedPropertyName(property.name)
            || !(ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))
            || ['__proto__', 'constructor', 'prototype'].includes(property.name.text)) { qualified = false; continue; }
          if (!this.sideEffectFree(property.initializer)) qualified = false;
          if (property.name.text !== 'shell') continue;
          shellField = true;
          const value = this.unwrap(property.initializer);
          if (!value) { shell = 'unresolved'; qualified = false; continue; }
          if (ts.isStringLiteralLike(value)) shell = value.text.length ? 'enabled' : 'disabled';
          else if (command && (value.kind === ts.SyntaxKind.TrueKeyword || value.kind === ts.SyntaxKind.FalseKeyword
            || value.kind === ts.SyntaxKind.NullKeyword || ts.isNumericLiteral(value) || ts.isObjectLiteralExpression(value))) shell = 'enabled';
          else if (value.kind === ts.SyntaxKind.TrueKeyword) shell = 'enabled';
          else if (value.kind === ts.SyntaxKind.FalseKeyword || value.kind === ts.SyntaxKind.NullKeyword) shell = 'disabled';
          else shell = 'unresolved';
        }
      }
    }
    return { shell: qualified ? shell : 'unresolved', qualified, argvIndex, optionsIndex, shellField };
  }
  private sideEffectFree(expression: ts.Expression): boolean {
    let work = 0;
    const visit = (node: ts.Node, depth: number): boolean => {
      if (++work > 128 || depth > 16 || !this.tick()) return false;
      if (ts.isCallExpression(node) || ts.isNewExpression(node) || ts.isAwaitExpression(node) || ts.isYieldExpression(node)
        || ts.isSpreadAssignment(node) || ts.isSpreadElement(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)
        || ts.isMethodDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isDeleteExpression(node)
        || ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
        || (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator)) return false;
      let valid = true; node.forEachChild(child => { if (valid) valid = visit(child, depth + 1); }); return valid;
    };
    return visit(expression, 0);
  }
}
