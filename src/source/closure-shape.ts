import * as ts from 'typescript';
import type { StaticModules } from './modules.js';

export type ShapeResult<T> = { kind: 'supported'; shape: T }
  | { kind: 'unsupported'; reason: string } | { kind: 'budget' };

export interface ClosureShape {
  readonly target: ts.ArrowFunction;
  /** Binding identities, including outer bindings needed by nested closures. */
  readonly captures: readonly ts.Symbol[];
  readonly lexicalThis: boolean;
}

export interface RegularClosureShape {
  readonly target: ts.FunctionExpression | ts.FunctionDeclaration;
  readonly captures: readonly ts.Symbol[];
}

/** Conditional inspection only: mutable captures never confer callable or safety authority. */
export function analyzeRegularClosureShape(target: RegularClosureShape['target'], modules: StaticModules,
  tick: () => boolean): ShapeResult<RegularClosureShape> {
  const captures = new Set<ts.Symbol>();
  let failure: ShapeResult<never> | undefined;
  const visit = (node: ts.Node): void => {
    if (failure) return;
    if (!tick()) { failure = { kind: 'budget' }; return; }
    if (ts.isTypeNode(node)) return;
    if (node !== target && (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)
      || ts.isArrowFunction(node) || ts.isClassDeclaration(node))) return;
    if (ts.isWithStatement(node) || ts.isMetaProperty(node) || node.kind === ts.SyntaxKind.SuperKeyword) {
      failure = unsupported('dynamic_scope'); return;
    }
    if (ts.isIdentifier(node) && reference(node)) {
      const symbol = modules.symbol(node);
      if (!tick()) { failure = { kind: 'budget' }; return; }
      if (node.text === 'eval' || node.text === 'arguments') { failure = unsupported('dynamic_scope'); return; }
      if (symbol && !symbol.declarations?.every(declaration => inside(declaration, target))) captures.add(symbol);
    }
    node.forEachChild(visit);
  };
  visit(target);
  return failure ?? { kind: 'supported', shape: { target, captures: [...captures] } };
}

export interface ConstructorShape {
  readonly target: ts.FunctionDeclaration | ts.FunctionExpression;
  readonly ownArrows: ReadonlyMap<string, ClosureShape>;
  readonly initializers: readonly ts.VariableDeclaration[];
  /** Ordered evaluation remains the caller's responsibility; these are not pure. */
  readonly effects: readonly (ts.CallExpression | ts.NewExpression)[];
  /** Syntactic guards only. Exclusion also needs closed constructor/prototype/hasInstance identity. */
  readonly guards: readonly ts.IfStatement[];
}

const unsupported = (reason: string): ShapeResult<never> => ({ kind: 'unsupported', reason });
const inside = (node: ts.Node, target: ts.Node): boolean => node.getSourceFile() === target.getSourceFile()
  && node.pos >= target.pos && node.end <= target.end;

function reference(node: ts.Identifier): boolean {
  const parent = node.parent;
  if (ts.isPropertyAccessExpression(parent) && parent.name === node) return false;
  if ((ts.isPropertyAssignment(parent) || ts.isMethodDeclaration(parent)
    || ts.isPropertyDeclaration(parent)) && parent.name === node) return false;
  if ((ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isBindingElement(parent)
    || ts.isFunctionDeclaration(parent) || ts.isFunctionExpression(parent) || ts.isClassDeclaration(parent))
    && parent.name === node) return false;
  if (ts.isBindingElement(parent) && parent.propertyName === node) return false;
  if (ts.isLabeledStatement(parent) || ts.isBreakStatement(parent) || ts.isContinueStatement(parent)) return false;
  return true;
}

function immutable(symbol: ts.Symbol, modules: StaticModules, tick: () => boolean): 'yes' | 'no' | 'budget' {
  if (modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol) || symbol.declarations?.length !== 1) return 'no';
  let declaration: ts.Node = symbol.declarations[0];
  if (ts.isBindingElement(declaration)) {
    while (ts.isBindingElement(declaration) || ts.isObjectBindingPattern(declaration) || ts.isArrayBindingPattern(declaration)) {
      if (!tick()) return 'budget';
      declaration = declaration.parent;
    }
  }
  return (ts.isParameter(declaration) || ts.isFunctionDeclaration(declaration)
    || ts.isImportSpecifier(declaration) || ts.isNamespaceImport(declaration) || ts.isImportClause(declaration)
    || ts.isVariableDeclaration(declaration) && !!(declaration.parent.flags & ts.NodeFlags.Const)) ? 'yes' : 'no';
}

function writeUse(node: ts.Node): boolean {
  const parent = node.parent;
  return ts.isDeleteExpression(parent) || ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)
    || ts.isBinaryExpression(parent) && parent.left === node
      && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment;
}

/** Structure only. A supported result never proves safe captures or callable effects. */
export function analyzeClosureShape(target: ts.ArrowFunction, modules: StaticModules,
  tick: () => boolean): ShapeResult<ClosureShape> {
  const captures = new Set<ts.Symbol>();
  let lexicalThis = false, failure: ShapeResult<never> | undefined;
  const visit = (node: ts.Node, dynamicThis = false): void => {
    if (failure) return;
    if (!tick()) { failure = { kind: 'budget' }; return; }
    if (ts.isTypeNode(node)) return;
    if (node !== target && (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)
      || ts.isMethodDeclaration(node))) dynamicThis = true;
    if (ts.isWithStatement(node) || ts.isMetaProperty(node) || node.kind === ts.SyntaxKind.SuperKeyword) {
      failure = unsupported('dynamic_scope'); return;
    }
    if (node.kind === ts.SyntaxKind.ThisKeyword) {
      if (dynamicThis) { failure = unsupported('dynamic_this'); return; }
      lexicalThis = true;
      const member = node.parent;
      let selected: ts.Node = member;
      while (ts.isPropertyAccessExpression(selected.parent) && selected.parent.expression === selected) {
        if (!tick()) { failure = { kind: 'budget' }; return; }
        selected = selected.parent;
      }
      if (!ts.isPropertyAccessExpression(member) || member.expression !== node || writeUse(selected)
        || ts.isElementAccessExpression(selected.parent) && selected.parent.expression === selected) {
        failure = unsupported('receiver_escape_or_write'); return;
      }
    }
    if (ts.isIdentifier(node) && reference(node)) {
      const symbol = modules.symbol(node);
      // The shared symbol lookup can itself exhaust the index/flow budget.
      if (!tick()) { failure = { kind: 'budget' }; return; }
      const declarations = symbol?.declarations;
      const local = declarations?.length === 1 && inside(declarations[0], target);
      if (!local && (node.text === 'arguments' || node.text === 'eval')) {
        failure = unsupported('dynamic_scope'); return;
      }
      if (symbol && !local) {
        const binding = immutable(symbol, modules, tick);
        if (binding === 'budget') { failure = { kind: 'budget' }; return; }
        if (binding !== 'yes') { failure = unsupported('mutable_or_ambiguous_capture'); return; }
        const declaration = declarations![0];
        // No snapshot of an uninitialized outer const. The caller may later add live binding cells.
        if ((ts.isVariableDeclaration(declaration) || ts.isBindingElement(declaration)) && declaration.pos >= target.pos
          && modules.ownerOf(declaration) === modules.ownerOf(target)) {
          failure = unsupported('capture_before_initialization'); return;
        }
        captures.add(symbol);
      }
    }
    node.forEachChild(child => visit(child, dynamicThis));
  };
  visit(target);
  return failure ?? { kind: 'supported', shape: { target, captures: [...captures], lexicalThis } };
}

function unwrapped(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node)
    || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node)) node = node.expression;
  return node;
}

/** Recognize syntax, not intrinsic instanceof semantics or Symbol.hasInstance safety. */
function constructorGuard(statement: ts.IfStatement, symbol: ts.Symbol | undefined,
  modules: StaticModules): boolean {
  if (!symbol || statement.elseStatement) return false;
  const condition = unwrapped(statement.expression);
  let test: ts.Expression | undefined;
  if (ts.isBinaryExpression(condition) && condition.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken) {
    const left = unwrapped(condition.left), right = unwrapped(condition.right);
    if (left.kind === ts.SyntaxKind.FalseKeyword) test = right;
    else if (right.kind === ts.SyntaxKind.FalseKeyword) test = left;
  } else if (ts.isPrefixUnaryExpression(condition) && condition.operator === ts.SyntaxKind.ExclamationToken) {
    test = unwrapped(condition.operand);
  }
  if (!test || !ts.isBinaryExpression(test) || test.operatorToken.kind !== ts.SyntaxKind.InstanceOfKeyword
    || unwrapped(test.left).kind !== ts.SyntaxKind.ThisKeyword || !ts.isIdentifier(unwrapped(test.right))
    || modules.symbol(unwrapped(test.right)) !== symbol) return false;
  const statements = ts.isBlock(statement.thenStatement) ? statement.thenStatement.statements : [statement.thenStatement];
  const last = statements.at(-1);
  if (!last || !ts.isReturnStatement(last) || !last.expression) return false;
  const value = unwrapped(last.expression);
  return ts.isNewExpression(value) && ts.isIdentifier(value.expression) && modules.symbol(value.expression) === symbol
    && statements.slice(0, -1).every(item => ts.isExpressionStatement(item) && ts.isCallExpression(item.expression));
}

/** Own slots only, for an already resolved constructor. No import/receiver identity is inferred here. */
export function analyzeConstructedShape(target: ts.FunctionLikeDeclaration, modules: StaticModules,
  tick: () => boolean): ShapeResult<ConstructorShape> {
  if ((!ts.isFunctionDeclaration(target) && !ts.isFunctionExpression(target)) || !target.body
    || target.asteriskToken || target.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.AsyncKeyword)) {
    return unsupported('constructor_form');
  }
  const ownArrows = new Map<string, ClosureShape>();
  const initializers: ts.VariableDeclaration[] = [];
  const effects: (ts.CallExpression | ts.NewExpression)[] = [];
  const guards: ts.IfStatement[] = [];
  const binding = target.name ?? (ts.isVariableDeclaration(target.parent) && ts.isIdentifier(target.parent.name)
    ? target.parent.name : undefined);
  const symbol = binding ? modules.symbol(binding) : undefined;
  if (!tick()) return { kind: 'budget' };
  let failure: ShapeResult<never> | undefined;
  const inspectInitializer = (node: ts.Node): void => {
    if (failure) return;
    if (!tick()) { failure = { kind: 'budget' }; return; }
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) return;
    if (node.kind === ts.SyntaxKind.ThisKeyword || node.kind === ts.SyntaxKind.SuperKeyword
      || ts.isWithStatement(node) || ts.isMetaProperty(node)) { failure = unsupported('opaque_constructor_receiver'); return; }
    if (ts.isCallExpression(node) && ts.isIdentifier(unwrapped(node.expression))
      && (unwrapped(node.expression) as ts.Identifier).text === 'eval') {
      failure = unsupported('dynamic_scope'); return;
    }
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) effects.push(node);
    node.forEachChild(inspectInitializer);
  };
  for (const parameter of target.parameters) {
    if (!tick()) return { kind: 'budget' };
    if (parameter.initializer || parameter.dotDotDotToken || parameter.modifiers?.length) return unsupported('constructor_parameters');
  }
  for (const statement of target.body.statements) {
    if (!tick()) return { kind: 'budget' };
    if (ts.isExpressionStatement(statement) && ts.isStringLiteral(statement.expression)) continue;
    if (ts.isVariableStatement(statement) && !!(statement.declarationList.flags & ts.NodeFlags.Const)) {
      for (const declaration of statement.declarationList.declarations) {
        if (!tick()) return { kind: 'budget' };
        if (!declaration.initializer) return unsupported('constructor_initializer');
        initializers.push(declaration); inspectInitializer(declaration.initializer);
        if (failure) return failure;
      }
      continue;
    }
    if (ts.isIfStatement(statement)) {
      // Charge the complete guard syntax, even though its effects are not executed by a certified new.
      const charge = (node: ts.Node): void => {
        if (failure) return;
        if (!tick()) { failure = { kind: 'budget' }; return; }
        node.forEachChild(charge);
      };
      charge(statement);
      if (failure) return failure;
      const guard = constructorGuard(statement, symbol, modules);
      if (!tick()) return { kind: 'budget' };
      if (!guard) return unsupported('constructor_control_flow');
      guards.push(statement); continue;
    }
    if (!ts.isExpressionStatement(statement)) return unsupported('constructor_control_flow_or_return');
    const expression = unwrapped(statement.expression);
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isPropertyAccessExpression(expression.left) && expression.left.expression.kind === ts.SyntaxKind.ThisKeyword
      && ts.isArrowFunction(expression.right)) {
      const key = expression.left.name.text;
      if (['constructor', 'prototype', '__proto__'].includes(key) || ownArrows.has(key)) return unsupported('duplicate_or_reserved_slot');
      const shape = analyzeClosureShape(expression.right, modules, tick);
      if (shape.kind !== 'supported') return shape;
      ownArrows.set(key, shape.shape); continue;
    }
    if (!ts.isCallExpression(expression) && !ts.isNewExpression(expression)) return unsupported('constructor_slot_or_write');
    inspectInitializer(expression);
    if (failure) return failure;
  }
  return ownArrows.size ? { kind: 'supported', shape: { target, ownArrows, initializers, effects, guards } }
    : unsupported('no_own_arrows');
}
