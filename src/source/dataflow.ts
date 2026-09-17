import * as ts from "typescript";

/** A source-to-sink use found by the bounded, same-function analysis. */
export interface InputFlowUse {
  node: ts.Node;
  kind: "assignment" | "call" | "jsx";
  argumentFlows?: Array<{ index: number; certainty: "tainted" | "unknown" }>;
}

type RootKind =
  | "request"
  | "params"
  | "query"
  | "body"
  | "headers"
  | "location"
  | "window"
  | "event"
  | "formData"
  | "searchParams";

interface FlowValue {
  kind: "safe" | "unknown" | "tainted" | "root";
  root?: RootKind;
  inputRelated?: boolean;
  properties?: ReadonlyMap<string, FlowValue>;
}

const SAFE: FlowValue = { kind: "safe" };
const UNKNOWN: FlowValue = { kind: "unknown" };
const TAINTED: FlowValue = { kind: "tainted" };
const UNKNOWN_INPUT: FlowValue = { kind: "unknown", inputRelated: true };

const ASSIGNMENT_OPERATORS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken,
  ts.SyntaxKind.AsteriskAsteriskEqualsToken,
  ts.SyntaxKind.SlashEqualsToken,
  ts.SyntaxKind.PercentEqualsToken,
  ts.SyntaxKind.LessThanLessThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.AmpersandEqualsToken,
  ts.SyntaxKind.BarEqualsToken,
  ts.SyntaxKind.CaretEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
]);

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return ASSIGNMENT_OPERATORS.has(kind);
}

function isSimpleAssignment(kind: ts.SyntaxKind): boolean {
  return kind === ts.SyntaxKind.EqualsToken;
}

function sourceRootForName(name: string): RootKind | undefined {
  switch (name) {
    case "req":
    case "request":
      return "request";
    case "params":
      return "params";
    case "query":
      return "query";
    case "body":
      return "body";
    case "headers":
      return "headers";
    case "location":
      return "location";
    case "window":
      return "window";
    case "event":
      return "event";
    case "formData":
      return "formData";
    case "searchParams":
      return "searchParams";
    default:
      return undefined;
  }
}

function rootValue(root: RootKind): FlowValue {
  return { kind: "root", root };
}

function rootProperty(root: RootKind, property: string): FlowValue {
  switch (root) {
    case "request":
      return ["query", "body", "params", "url", "headers", "nextUrl"].includes(property)
        ? TAINTED
        : UNKNOWN_INPUT;
    case "params":
      return TAINTED;
    case "query":
    case "body":
    case "headers":
      return TAINTED;
    case "location":
      return ["search", "hash", "href"].includes(property) ? TAINTED : UNKNOWN_INPUT;
    case "window":
      return property === "name" ? TAINTED : UNKNOWN_INPUT;
    case "event":
      return property === "data" ? TAINTED : UNKNOWN_INPUT;
    case "formData":
    case "searchParams":
      return UNKNOWN_INPUT;
    default:
      return UNKNOWN_INPUT;
  }
}

function propertyName(node: ts.PropertyName | ts.Expression | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) return node.text;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isNumericLiteral(node)) return node.text;
  return undefined;
}

function staticMemberPath(expression: ts.Expression): string[] {
  if (ts.isIdentifier(expression)) return [expression.text];
  if (ts.isPropertyAccessExpression(expression)) return [...staticMemberPath(expression.expression), expression.name.text];
  if (ts.isElementAccessExpression(expression)) {
    const property = propertyName(expression.argumentExpression);
    return property === undefined ? [] : [...staticMemberPath(expression.expression), property];
  }
  return [];
}

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node)
    || ts.isMethodDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node)
    || ts.isConstructorDeclaration(node);
}

function joinValues(left: FlowValue, right: FlowValue): FlowValue {
  const propertyNames = new Set<string>([
    ...left.properties?.keys() ?? [],
    ...right.properties?.keys() ?? [],
  ]);
  const properties = propertyNames.size > 0
    ? new Map([...propertyNames].map((name) => [
        name,
        joinValues(left.properties?.get(name) ?? UNKNOWN, right.properties?.get(name) ?? UNKNOWN),
      ] as [string, FlowValue]))
    : undefined;
  const withProperties = (value: FlowValue): FlowValue => properties ? { ...value, properties } : value;
  if (left.kind === right.kind && (left.kind !== "root" || left.root === right.root)) {
    if (left.kind === "root") return withProperties(left);
    if (left.kind === "unknown" && (left.inputRelated || right.inputRelated)) return withProperties(UNKNOWN_INPUT);
    return withProperties({ kind: left.kind });
  }
  return withProperties(isInputRelated(left) || isInputRelated(right) ? UNKNOWN_INPUT : UNKNOWN);
}

function combineValues(values: readonly FlowValue[]): FlowValue {
  if (values.some((value) => value.kind === "tainted")) return TAINTED;
  if (values.some((value) => isInputRelated(value))) return UNKNOWN_INPUT;
  if (values.some((value) => value.kind === "root" || value.kind === "unknown")) return UNKNOWN;
  return SAFE;
}

function isInputRelated(value: FlowValue): boolean {
  return value.kind === "tainted" || value.kind === "root" || value.inputRelated === true;
}

function projectValue(base: FlowValue, property: string): FlowValue {
  const propertyValue = base.properties?.get(property);
  if (propertyValue) return propertyValue;
  if (base.kind === "root" && base.root) return rootProperty(base.root, property);
  if (base.kind === "tainted") return TAINTED;
  if (base.kind === "safe") return SAFE;
  if (base.inputRelated) return UNKNOWN_INPUT;
  return UNKNOWN;
}

function functionBody(functionLike: ts.FunctionLikeDeclaration): ts.Block | ts.Expression | undefined {
  const body = functionLike.body;
  return body;
}

class FlowEnv {
  private readonly scopes: Map<string, FlowValue>[];

  constructor(scopes?: Map<string, FlowValue>[]) {
    this.scopes = scopes ?? [new Map<string, FlowValue>()];
  }

  clone(): FlowEnv {
    return new FlowEnv(this.scopes.map((scope) => new Map(scope)));
  }

  push(): void {
    this.scopes.push(new Map<string, FlowValue>());
  }

  pop(): void {
    if (this.scopes.length > 1) this.scopes.pop();
  }

  declare(name: string, value: FlowValue, blockScoped: boolean): void {
    const index = blockScoped ? this.scopes.length - 1 : 0;
    this.scopes[index].set(name, value);
  }

  assign(name: string, value: FlowValue): void {
    for (let index = this.scopes.length - 1; index >= 0; index -= 1) {
      if (this.scopes[index].has(name)) {
        this.scopes[index].set(name, value);
        return;
      }
    }
    this.scopes[this.scopes.length - 1].set(name, value);
  }

  /** Preserve a bounded object property assignment for later sink checks. */
  assignProperty(path: readonly string[], value: FlowValue): void {
    if (path.length < 2) {
      if (path.length === 1) this.assign(path[0], value);
      return;
    }
    const update = (base: FlowValue, index: number): FlowValue => {
      const property = path[index];
      const properties = new Map(base.properties ?? []);
      if (index === path.length - 1) {
        properties.set(property, value);
      } else {
        properties.set(property, update(properties.get(property) ?? UNKNOWN, index + 1));
      }
      const combined = combineValues([base, value]);
      return { ...combined, properties };
    };
    this.assign(path[0], update(this.resolve(path[0]), 1));
  }

  resolve(name: string): FlowValue {
    for (let index = this.scopes.length - 1; index >= 0; index -= 1) {
      const value = this.scopes[index].get(name);
      if (value) return value;
    }
    const root = sourceRootForName(name);
    return root ? rootValue(root) : UNKNOWN;
  }

  merge(branches: readonly FlowEnv[]): void {
    for (let depth = 0; depth < this.scopes.length; depth += 1) {
      const names = new Set<string>(this.scopes[depth].keys());
      for (const branch of branches) {
        for (const name of branch.scopes[depth]?.keys() ?? []) names.add(name);
      }
      for (const name of names) {
        const values = branches.map((branch) => branch.scopes[depth]?.get(name) ?? this.scopes[depth].get(name) ?? UNKNOWN);
        this.scopes[depth].set(name, values.reduce(joinValues));
      }
    }
  }
}

function isBindingPattern(node: ts.Node): node is ts.ObjectBindingPattern | ts.ArrayBindingPattern {
  return ts.isObjectBindingPattern(node) || ts.isArrayBindingPattern(node);
}

function isAssignmentPattern(node: ts.Node): node is ts.ObjectLiteralExpression | ts.ArrayLiteralExpression {
  return ts.isObjectLiteralExpression(node) || ts.isArrayLiteralExpression(node);
}

function isSupportedBindingTarget(node: ts.Node): node is ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression {
  return ts.isIdentifier(node)
    || ts.isObjectBindingPattern(node)
    || ts.isArrayBindingPattern(node)
    || ts.isObjectLiteralExpression(node)
    || ts.isArrayLiteralExpression(node);
}

class DataflowAnalyzer {
  private readonly uses: InputFlowUse[] = [];

  constructor(private readonly sourceFile: ts.SourceFile) {}

  run(): InputFlowUse[] {
    this.analyzeStatements(this.sourceFile.statements, new FlowEnv());
    const functions: ts.FunctionLikeDeclaration[] = [];
    const collect = (node: ts.Node): void => {
      if (isFunctionLike(node)) functions.push(node);
      node.forEachChild(collect);
    };
    collect(this.sourceFile);
    for (const functionLike of functions) this.analyzeFunction(functionLike);
    return this.uses;
  }

  private analyzeFunction(functionLike: ts.FunctionLikeDeclaration): void {
    const env = new FlowEnv();
    for (const parameter of functionLike.parameters) {
      this.declareParameter(parameter, env);
    }
    const body = functionBody(functionLike);
    if (!body) return;
    if (ts.isBlock(body)) this.analyzeStatement(body, env);
    else this.analyzeExpression(body, env);
  }

  private declareParameter(parameter: ts.ParameterDeclaration, env: FlowEnv): void {
    if (ts.isIdentifier(parameter.name)) {
      const root = sourceRootForName(parameter.name.text);
      this.declareBinding(parameter.name, root ? rootValue(root) : UNKNOWN, env, true);
      return;
    }
    // Next route handlers commonly destructure the second context parameter
    // (`{ params }`, `{ searchParams }`) and Express-style handlers commonly
    // destructure request fields (`{ query }`, `{ body }`). The old generic
    // UNKNOWN value made these inputs disappear before reaching a sink.
    if (ts.isObjectBindingPattern(parameter.name)) {
      for (const element of parameter.name.elements) {
        if (ts.isOmittedExpression(element)) continue;
        const key = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
        const root = key ? sourceRootForName(key) : undefined;
        const value = element.dotDotDotToken
          ? UNKNOWN
          : root
            ? rootValue(root)
            : UNKNOWN;
        this.declareBinding(element.name, value, env, true);
      }
      return;
    }
    this.declareBinding(parameter.name, UNKNOWN, env, true);
  }

  private declareBinding(name: ts.BindingName, value: FlowValue, env: FlowEnv, blockScoped: boolean): void {
    if (ts.isIdentifier(name)) {
      env.declare(name.text, value, blockScoped);
      return;
    }
    if (ts.isObjectBindingPattern(name)) {
      for (const element of name.elements) {
        if (ts.isOmittedExpression(element)) continue;
        const key = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
        const elementValue = element.dotDotDotToken
          ? value
          : key === undefined
            ? UNKNOWN
            : projectValue(value, key);
        this.declareBinding(element.name, elementValue, env, blockScoped);
      }
      return;
    }
    for (let index = 0; index < name.elements.length; index += 1) {
      const element = name.elements[index];
      if (ts.isOmittedExpression(element)) continue;
      const elementValue = element.dotDotDotToken ? value : projectValue(value, String(index));
      this.declareBinding(element.name, elementValue, env, blockScoped);
    }
  }

  private assignBinding(name: ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression, value: FlowValue, env: FlowEnv): void {
    if (ts.isIdentifier(name)) {
      env.assign(name.text, value);
      return;
    }
    if (ts.isObjectBindingPattern(name)) {
      for (const element of name.elements) {
        const key = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
        this.assignBinding(element.name, element.dotDotDotToken ? value : key === undefined ? UNKNOWN : projectValue(value, key), env);
      }
      return;
    }
    if (ts.isArrayBindingPattern(name)) {
      for (let index = 0; index < name.elements.length; index += 1) {
        const element = name.elements[index];
        if (ts.isOmittedExpression(element)) continue;
        this.assignBinding(element.name, element.dotDotDotToken ? value : projectValue(value, String(index)), env);
      }
      return;
    }
    if (ts.isObjectLiteralExpression(name)) {
      for (const element of name.properties) {
        if (ts.isSpreadAssignment(element)) {
          if (isSupportedBindingTarget(element.expression)) this.assignBinding(element.expression, value, env);
        } else if (ts.isPropertyAssignment(element)) {
          const key = propertyName(element.name);
          if (key !== undefined && isSupportedBindingTarget(element.initializer)) this.assignBinding(element.initializer, projectValue(value, key), env);
        } else if (ts.isShorthandPropertyAssignment(element)) {
          this.assignBinding(element.name, projectValue(value, element.name.text), env);
        }
      }
      return;
    }
    for (const [index, element] of name.elements.entries()) {
      if (ts.isOmittedExpression(element)) continue;
      if (ts.isSpreadElement(element)) {
        if (isSupportedBindingTarget(element.expression)) this.assignBinding(element.expression, value, env);
      } else if (isSupportedBindingTarget(element)) {
        this.assignBinding(element, projectValue(value, String(index)), env);
      }
    }
  }

  private analyzeStatements(statements: readonly ts.Statement[], env: FlowEnv): void {
    for (const statement of statements) this.analyzeStatement(statement, env);
  }

  private analyzeStatement(statement: ts.Statement, env: FlowEnv): void {
    if (isFunctionLike(statement)) return;
    if (ts.isVariableStatement(statement)) {
      this.analyzeVariableList(statement.declarationList, env);
      return;
    }
    if (ts.isExpressionStatement(statement)) {
      this.analyzeExpression(statement.expression, env);
      return;
    }
    if (ts.isBlock(statement)) {
      env.push();
      this.analyzeStatements(statement.statements, env);
      env.pop();
      return;
    }
    if (ts.isIfStatement(statement)) {
      this.analyzeExpression(statement.expression, env);
      const whenTrue = env.clone();
      this.analyzeStatement(statement.thenStatement, whenTrue);
      const branches = [whenTrue];
      if (statement.elseStatement) {
        const whenFalse = env.clone();
        this.analyzeStatement(statement.elseStatement, whenFalse);
        branches.push(whenFalse);
      } else {
        branches.push(env.clone());
      }
      env.merge(branches);
      return;
    }
    if (ts.isForStatement(statement)) {
      const loop = env.clone();
      loop.push();
      if (statement.initializer) {
        if (ts.isVariableDeclarationList(statement.initializer)) this.analyzeVariableList(statement.initializer, loop);
        else this.analyzeExpression(statement.initializer, loop);
      }
      if (statement.condition) this.analyzeExpression(statement.condition, loop);
      this.analyzeStatement(statement.statement, loop);
      if (statement.incrementor) this.analyzeExpression(statement.incrementor, loop);
      loop.pop();
      env.merge([loop, env.clone()]);
      return;
    }
    if (ts.isForInStatement(statement) || ts.isForOfStatement(statement)) {
      const loop = env.clone();
      loop.push();
      this.analyzeExpression(statement.expression, loop);
      const iterable = this.evalExpression(statement.expression, loop);
      if (ts.isVariableDeclarationList(statement.initializer)) {
        const blockScoped = (statement.initializer.flags & ts.NodeFlags.BlockScoped) !== 0;
        for (const declaration of statement.initializer.declarations) {
          // A loop element inherits the taint of the iterable. For an object or
          // array with tracked fields, wildcard projection keeps the useful
          // property-independent input signal without inventing a value.
          const elementValue = projectValue(iterable, "*");
          if (declaration.initializer) this.analyzeExpression(declaration.initializer, loop);
          this.declareBinding(declaration.name, elementValue, loop, blockScoped);
        }
      } else {
        this.analyzeAssignmentTarget(statement.initializer, loop);
        const elementValue = projectValue(iterable, "*");
        if (ts.isIdentifier(statement.initializer)) loop.assign(statement.initializer.text, elementValue);
        else if (isAssignmentPattern(statement.initializer) || isBindingPattern(statement.initializer)) {
          this.assignBinding(statement.initializer as ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression, elementValue, loop);
        } else {
          this.assignMemberPath(statement.initializer, elementValue, loop);
        }
      }
      this.analyzeStatement(statement.statement, loop);
      loop.pop();
      env.merge([loop, env.clone()]);
      return;
    }
    if (ts.isWhileStatement(statement) || ts.isDoStatement(statement)) {
      if (ts.isWhileStatement(statement)) this.analyzeExpression(statement.expression, env);
      const body = env.clone();
      this.analyzeStatement(statement.statement, body);
      if (ts.isDoStatement(statement)) this.analyzeExpression(statement.expression, body);
      env.merge([body, env.clone()]);
      return;
    }
    if (ts.isSwitchStatement(statement)) {
      this.analyzeExpression(statement.expression, env);
      const branches: FlowEnv[] = [env.clone()];
      for (const clause of statement.caseBlock.clauses) {
        const branch = env.clone();
        if (ts.isCaseClause(clause)) this.analyzeExpression(clause.expression, branch);
        this.analyzeStatements(clause.statements, branch);
        branches.push(branch);
      }
      env.merge(branches);
      return;
    }
    if (ts.isTryStatement(statement)) {
      const tryEnv = env.clone();
      this.analyzeBlockLike(statement.tryBlock, tryEnv);
      const branches = [tryEnv];
      if (statement.catchClause) {
        const catchEnv = env.clone();
        if (statement.catchClause.variableDeclaration) {
          catchEnv.push();
          this.declareBinding(statement.catchClause.variableDeclaration.name, UNKNOWN, catchEnv, true);
        }
        this.analyzeBlockLike(statement.catchClause.block, catchEnv);
        if (statement.catchClause.variableDeclaration) catchEnv.pop();
        branches.push(catchEnv);
      } else {
        branches.push(env.clone());
      }
      env.merge(branches);
      if (statement.finallyBlock) this.analyzeBlockLike(statement.finallyBlock, env);
      return;
    }
    if (ts.isReturnStatement(statement) || ts.isThrowStatement(statement)) {
      if (statement.expression) this.analyzeExpression(statement.expression, env);
      return;
    }
    if (ts.isWithStatement(statement)) {
      this.analyzeExpression(statement.expression, env);
      this.analyzeStatement(statement.statement, env);
      return;
    }
    if (ts.isLabeledStatement(statement)) {
      this.analyzeStatement(statement.statement, env);
      return;
    }
    if (ts.isClassDeclaration(statement)) {
      for (const member of statement.members) {
        if (ts.isPropertyDeclaration(member) && member.initializer) this.analyzeExpression(member.initializer, env);
      }
      return;
    }
    statement.forEachChild((child) => {
      if (isFunctionLike(child)) return;
      if (ts.isStatement(child)) this.analyzeStatement(child, env);
      else if (ts.isExpression(child)) this.analyzeExpression(child, env);
    });
  }

  private analyzeBlockLike(block: ts.Block, env: FlowEnv): void {
    this.analyzeStatement(block, env);
  }

  private analyzeVariableList(list: ts.VariableDeclarationList, env: FlowEnv): void {
    const blockScoped = (list.flags & ts.NodeFlags.BlockScoped) !== 0;
    for (const declaration of list.declarations) {
      if (declaration.initializer) this.analyzeExpression(declaration.initializer, env);
      const value = declaration.initializer ? this.evalExpression(declaration.initializer, env) : UNKNOWN;
      if (ts.isIdentifier(declaration.name)) {
        env.declare(declaration.name.text, value, blockScoped);
      } else {
        this.declareBinding(declaration.name, value, env, blockScoped);
      }
    }
  }

  private analyzeExpression(expression: ts.Expression, env: FlowEnv): void {
    if (isFunctionLike(expression)) return;
    if (ts.isBinaryExpression(expression) && isAssignmentOperator(expression.operatorToken.kind)) {
      this.analyzeExpression(expression.right, env);
      this.analyzeAssignmentTarget(expression.left, env);
      const right = this.evalExpression(expression.right, env);
      if (isSimpleAssignment(expression.operatorToken.kind)) {
        this.recordAssignment(expression, right);
        if (ts.isIdentifier(expression.left) || isAssignmentPattern(expression.left) || isBindingPattern(expression.left)) {
          this.assignBinding(expression.left as ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression, right, env);
        } else {
          this.assignMemberPath(expression.left, right, env);
        }
      } else {
        const prior = ts.isIdentifier(expression.left) ? env.resolve(expression.left.text) : UNKNOWN;
        const value = combineValues([prior, right]);
        this.recordAssignment(expression, value);
        if (ts.isIdentifier(expression.left)) env.assign(expression.left.text, value);
        else this.assignMemberPath(expression.left, value, env);
      }
      return;
    }
    if (ts.isCallExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      for (const argument of expression.arguments) this.analyzeExpression(argument, env);
      const argumentFlows: Array<{ index: number; certainty: "tainted" | "unknown" }> = [];
      for (let index = 0; index < expression.arguments.length; index += 1) {
        const value = this.evalExpression(expression.arguments[index], env);
        if (isInputRelated(value)) argumentFlows.push({ index, certainty: value.kind === "tainted" ? "tainted" : "unknown" });
      }
      if (argumentFlows.length > 0) this.uses.push({ node: expression, kind: "call", argumentFlows });
      return;
    }
    if (ts.isNewExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      for (const argument of expression.arguments ?? []) this.analyzeExpression(argument, env);
      return;
    }
    if (ts.isPrefixUnaryExpression(expression)) {
      this.analyzeExpression(expression.operand, env);
      if (expression.operator === ts.SyntaxKind.PlusPlusToken || expression.operator === ts.SyntaxKind.MinusMinusToken) {
        if (ts.isIdentifier(expression.operand)) env.assign(expression.operand.text, UNKNOWN);
      }
      return;
    }
    if (ts.isPostfixUnaryExpression(expression)) {
      this.analyzeExpression(expression.operand, env);
      if (ts.isIdentifier(expression.operand)) env.assign(expression.operand.text, UNKNOWN);
      return;
    }
    if (ts.isConditionalExpression(expression)) {
      this.analyzeExpression(expression.condition, env);
      const whenTrue = env.clone();
      this.analyzeExpression(expression.whenTrue, whenTrue);
      const whenFalse = env.clone();
      this.analyzeExpression(expression.whenFalse, whenFalse);
      env.merge([whenTrue, whenFalse]);
      return;
    }
    if (ts.isBinaryExpression(expression) && [
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken,
    ].includes(expression.operatorToken.kind)) {
      this.analyzeExpression(expression.left, env);
      const right = env.clone();
      this.analyzeExpression(expression.right, right);
      env.merge([right, env.clone()]);
      return;
    }
    if (ts.isJsxElement(expression)) {
      this.analyzeJsxAttributes(expression.openingElement.attributes, env);
      for (const child of expression.children) {
        if (ts.isJsxExpression(child) && child.expression) this.analyzeExpression(child.expression, env);
        else if (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child)) this.analyzeExpression(child, env);
      }
      return;
    }
    if (ts.isJsxSelfClosingElement(expression)) {
      this.analyzeJsxAttributes(expression.attributes, env);
      return;
    }
    if (ts.isObjectLiteralExpression(expression)) {
      for (const property of expression.properties) {
        if (ts.isPropertyAssignment(property)) this.analyzeExpression(property.initializer, env);
        else if (ts.isShorthandPropertyAssignment(property) && property.objectAssignmentInitializer) this.analyzeExpression(property.objectAssignmentInitializer, env);
        else if (ts.isSpreadAssignment(property)) this.analyzeExpression(property.expression, env);
      }
      return;
    }
    if (ts.isArrayLiteralExpression(expression)) {
      for (const element of expression.elements) {
        if (!ts.isOmittedExpression(element)) this.analyzeExpression(element, env);
      }
      return;
    }
    if (ts.isPropertyAccessExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      return;
    }
    if (ts.isElementAccessExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      if (expression.argumentExpression) this.analyzeExpression(expression.argumentExpression, env);
      return;
    }
    if (ts.isTemplateExpression(expression)) {
      for (const span of expression.templateSpans) this.analyzeExpression(span.expression, env);
      return;
    }
    if (ts.isTaggedTemplateExpression(expression)) {
      this.analyzeExpression(expression.tag, env);
      this.analyzeExpression(expression.template, env);
      return;
    }
    if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression) || ts.isAwaitExpression(expression) || ts.isYieldExpression(expression)) {
      if (expression.expression) this.analyzeExpression(expression.expression, env);
      return;
    }
    expression.forEachChild((child) => {
      if (isFunctionLike(child)) return;
      if (ts.isExpression(child)) this.analyzeExpression(child, env);
    });
  }

  private analyzeAssignmentTarget(target: ts.Expression, env: FlowEnv): void {
    if (ts.isIdentifier(target)) return;
    if (isAssignmentPattern(target)) {
      target.forEachChild((child) => {
        if (ts.isExpression(child)) this.analyzeExpression(child, env);
      });
      return;
    }
    if (ts.isPropertyAccessExpression(target)) {
      this.analyzeExpression(target.expression, env);
      return;
    }
    if (ts.isElementAccessExpression(target)) {
      this.analyzeExpression(target.expression, env);
      if (target.argumentExpression) this.analyzeExpression(target.argumentExpression, env);
    }
  }

  private analyzeJsxAttributes(attributes: ts.JsxAttributes, env: FlowEnv): void {
    for (const attribute of attributes.properties) {
      if (ts.isJsxSpreadAttribute(attribute)) {
        this.analyzeExpression(attribute.expression, env);
        continue;
      }
      if (!ts.isJsxAttribute(attribute)) continue;
      const initializer = attribute.initializer;
      if (!initializer || ts.isStringLiteral(initializer)) continue;
      if (!ts.isJsxExpression(initializer) || !initializer.expression) continue;
      this.analyzeExpression(initializer.expression, env);
      if (ts.isIdentifier(attribute.name) && attribute.name.text.toLowerCase() === "dangerouslysetinnerhtml") {
        const value = this.evalExpression(initializer.expression, env);
        if (isInputRelated(value)) {
          this.uses.push({
            node: attribute,
            kind: "jsx",
            argumentFlows: [{ index: 0, certainty: value.kind === "tainted" ? "tainted" : "unknown" }],
          });
        }
      }
    }
  }

  private assignMemberPath(target: ts.Expression, value: FlowValue, env: FlowEnv): void {
    const path = staticMemberPath(target);
    if (path.length >= 2) env.assignProperty(path, value);
  }

  private recordAssignment(node: ts.BinaryExpression, value: FlowValue): void {
    if (isInputRelated(value)) this.uses.push({ node, kind: "assignment", argumentFlows: [{ index: 0, certainty: value.kind === "tainted" ? "tainted" : "unknown" }] });
  }

  private evalExpression(expression: ts.Expression, env: FlowEnv): FlowValue {
    if (ts.isIdentifier(expression)) return env.resolve(expression.text);
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression) || ts.isNumericLiteral(expression) || ts.isBigIntLiteral(expression) || ts.isRegularExpressionLiteral(expression)) return SAFE;
    if (expression.kind === ts.SyntaxKind.TrueKeyword || expression.kind === ts.SyntaxKind.FalseKeyword || expression.kind === ts.SyntaxKind.NullKeyword || expression.kind === ts.SyntaxKind.UndefinedKeyword) return SAFE;
    if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression) || ts.isAwaitExpression(expression)) return this.evalExpression(expression.expression, env);
    if (ts.isYieldExpression(expression)) return expression.expression ? this.evalExpression(expression.expression, env) : UNKNOWN;
    if (ts.isPropertyAccessExpression(expression)) return projectValue(this.evalExpression(expression.expression, env), expression.name.text);
    if (ts.isElementAccessExpression(expression)) {
      const key = propertyName(expression.argumentExpression);
      const base = this.evalExpression(expression.expression, env);
      if (key !== undefined) return projectValue(base, key);
      // Dynamic keys cannot be resolved in this bounded analysis, but a
      // tainted base still means the selected property is input-related.
      const keyValue = expression.argumentExpression
        ? this.evalExpression(expression.argumentExpression, env)
        : UNKNOWN;
      return isInputRelated(base) || isInputRelated(keyValue)
        ? base.kind === "tainted" ? TAINTED : UNKNOWN_INPUT
        : UNKNOWN;
    }
    if (ts.isArrayLiteralExpression(expression)) {
      const properties = new Map<string, FlowValue>();
      const values: FlowValue[] = [];
      expression.elements.forEach((element, index) => {
        if (ts.isOmittedExpression(element)) return;
        const value = this.evalExpression(element, env);
        properties.set(String(index), value);
        values.push(value);
      });
      const combined = combineValues(values);
      return { ...combined, properties };
    }
    if (ts.isObjectLiteralExpression(expression)) {
      const properties = new Map<string, FlowValue>();
      const values: FlowValue[] = [];
      for (const property of expression.properties) {
        if (ts.isPropertyAssignment(property)) {
          const key = propertyName(property.name);
          const value = this.evalExpression(property.initializer, env);
          values.push(value);
          if (key !== undefined) properties.set(key, value);
        } else if (ts.isShorthandPropertyAssignment(property)) {
          const value = env.resolve(property.name.text);
          values.push(value);
          properties.set(property.name.text, value);
        } else if (ts.isSpreadAssignment(property)) {
          const value = this.evalExpression(property.expression, env);
          values.push(value);
          for (const [key, propertyValue] of value.properties ?? []) properties.set(key, propertyValue);
        }
      }
      const combined = combineValues(values);
      return { ...combined, properties };
    }
    if (ts.isTemplateExpression(expression)) {
      return combineValues(expression.templateSpans.map((span) => this.evalExpression(span.expression, env)));
    }
    if (ts.isNoSubstitutionTemplateLiteral(expression)) return SAFE;
    if (ts.isConditionalExpression(expression)) return joinValues(this.evalExpression(expression.whenTrue, env), this.evalExpression(expression.whenFalse, env));
    if (ts.isBinaryExpression(expression)) {
      if (isAssignmentOperator(expression.operatorToken.kind)) {
        if (isSimpleAssignment(expression.operatorToken.kind)) return this.evalExpression(expression.right, env);
        return combineValues([ts.isIdentifier(expression.left) ? env.resolve(expression.left.text) : UNKNOWN, this.evalExpression(expression.right, env)]);
      }
      if (expression.operatorToken.kind === ts.SyntaxKind.PlusToken) return combineValues([this.evalExpression(expression.left, env), this.evalExpression(expression.right, env)]);
      if ([
        ts.SyntaxKind.AmpersandAmpersandToken,
        ts.SyntaxKind.BarBarToken,
        ts.SyntaxKind.QuestionQuestionToken,
      ].includes(expression.operatorToken.kind)) return joinValues(this.evalExpression(expression.left, env), this.evalExpression(expression.right, env));
      return UNKNOWN;
    }
    if (ts.isCallExpression(expression)) {
      const receiver = ts.isPropertyAccessExpression(expression.expression) ? this.evalExpression(expression.expression.expression, env) : undefined;
      const method = ts.isPropertyAccessExpression(expression.expression) ? expression.expression.name.text : undefined;
      if (ts.isIdentifier(expression.expression) && expression.expression.text === "URLSearchParams") return rootValue("searchParams");
      if (method === "json" && receiver?.kind === "root" && receiver.root === "request") return TAINTED;
      if (method === "get" && receiver?.kind === "root" && (receiver.root === "searchParams" || receiver.root === "formData")) return TAINTED;
      if (method === "get" && receiver?.kind === "tainted") return TAINTED;
      if (method === "get" && receiver && isInputRelated(receiver)) return UNKNOWN_INPUT;
      if (receiver && isInputRelated(receiver)) return UNKNOWN_INPUT;
      if (expression.arguments.some((argument) => isInputRelated(this.evalExpression(argument, env)))) return UNKNOWN_INPUT;
      return UNKNOWN;
    }
    if (ts.isNewExpression(expression)) {
      if (ts.isIdentifier(expression.expression) && expression.expression.text === "URLSearchParams") return rootValue("searchParams");
      if ((expression.arguments ?? []).some((argument) => isInputRelated(this.evalExpression(argument, env)))) return UNKNOWN_INPUT;
      return UNKNOWN;
    }
    if (ts.isPrefixUnaryExpression(expression) || ts.isPostfixUnaryExpression(expression)) return UNKNOWN;
    if (ts.isSpreadElement(expression)) return this.evalExpression(expression.expression, env);
    if (ts.isArrowFunction(expression) || ts.isFunctionExpression(expression) || ts.isClassExpression(expression)) return SAFE;
    return UNKNOWN;
  }
}

/**
 * Find direct and same-function input flows. Unknown function calls deliberately
 * stay unknown; this avoids claiming that an unrecognised sanitizer is safe or
 * that an arbitrary wrapper preserves taint.
 */
export function findInputFlows(sourceFile: ts.SourceFile): InputFlowUse[] {
  return new DataflowAnalyzer(sourceFile).run();
}
