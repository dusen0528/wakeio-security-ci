import * as ts from "typescript";
import { posix } from "node:path";

export const FLOW_LIMITS = Object.freeze({
  nodeVisits: 500_000, // Aggregate cap; legacy callers can override independently.
  indexWork: 300_000,
  flowWork: 200_000,
  functions: 2_000,
  summaryWork: 5_000,
  callDepth: 8,
  moduleEdges: 2_000,
  traceSteps: 24,
  aliasSteps: 64,
});
export type FlowLimits = { [K in Exclude<keyof typeof FLOW_LIMITS, 'indexWork' | 'flowWork'>]: number }
  & { indexWork?: number; flowWork?: number };

export function isFlowFunction(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node) || ts.isConstructorDeclaration(node);
}

export interface SingletonReceiver { readonly file: ts.SourceFile; readonly classNode: ts.ClassDeclaration; readonly exportNode: ts.NewExpression; }
export type CallResolution =
  | { kind: "resolved" | "declared"; target: ts.FunctionLikeDeclaration; receiver?: SingletonReceiver }
  | { kind: "missing" | "ambiguous" | "unsupported" | "external" | "module_budget" | "export_unsupported" };

function nameOf(node: ts.PropertyName | ts.Expression | undefined): string | undefined {
  return node && (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) ? node.text : undefined;
}

function variableOf(node: ts.Node): ts.VariableDeclaration | undefined {
  let current: ts.Node | undefined = node;
  while (current && !ts.isVariableDeclaration(current)) current = current.parent;
  return current && ts.isVariableDeclaration(current) ? current : undefined;
}

interface ObjectExport {
  file: ts.SourceFile;
  methods: Map<string, Map<string, ts.FunctionLikeDeclaration>>;
  allowed: Set<ts.Node>;
  symbols: ts.Symbol[];
  callableSymbols: Set<ts.Symbol>;
  valid: boolean;
  receiver?: SingletonReceiver;
  constructorClass?: ts.ClassDeclaration;
  declared?: boolean;
  receiverProof?: boolean;
  dependencies?: ObjectExport[];
  singletonProof?: { exportClosed: boolean; structureClosed: boolean; importersClosed: boolean; loaderHard: boolean; cycle: boolean };
}

/** Uses the TS binder only. The host cannot read libraries, configs, or target files. */
export class StaticModules {
  readonly functions: ts.FunctionLikeDeclaration[] = [];
  readonly functionSet = new Set<ts.FunctionLikeDeclaration>();
  readonly called = new Set<ts.FunctionLikeDeclaration>();
  readonly externalEntries = new Set<ts.FunctionLikeDeclaration>();
  readonly checker: ts.TypeChecker;
  readonly files: ReadonlyMap<string, ts.SourceFile>;
  readonly moduleEdges = new Set<string>();
  readonly mutated = new Set<ts.Symbol>();
  readonly mutatedMembers = new Set<ts.Symbol>();
  private readonly exports = new Map<string, Map<string, ts.FunctionLikeDeclaration | null>>();
  private readonly cjsExportFiles = new Set<ts.SourceFile>();
  private readonly esmFiles = new Set<ts.SourceFile>();
  private readonly cjsShadowScopes = new Map<ts.SourceFile, Map<string, Set<ts.Node>>>();
  readonly calls: ts.CallExpression[] = [];
  readonly callTargets = new Map<ts.FunctionLikeDeclaration, ts.CallExpression[]>();
  readonly references = new Map<ts.Symbol, ts.Identifier[]>();
  readonly nativeBoundaryNodes: ts.Node[] = [];
  readonly newExpressions: ts.NewExpression[] = [];
  readonly importDeclarations: ts.ImportDeclaration[] = [];
  readonly requireDeclarations: ts.VariableDeclaration[] = [];
  readonly sqlLoads: Array<{ specifier: string; node: ts.Node }> = [];
  readonly sqlBoundaryNodes: ts.Identifier[] = [];
  readonly forkLoads: ts.Node[] = [];
  readonly axiosLoads: Array<ts.CallExpression | ts.ImportEqualsDeclaration | ts.ExportDeclaration> = [];
  readonly cjsReferences = new Map<ts.SourceFile, ts.Identifier[]>();
  readonly requireReferences: ts.Identifier[] = [];
  readonly expressOpaqueLoads: ts.Node[] = [];
  readonly indexWalkFiles = new Set<ts.SourceFile>();
  indexedAstNodes = 0;
  symbolLookups = 0;
  identifierReferences = 0;
  private readonly symbols = new WeakMap<ts.Node, ts.Symbol | undefined>();
  private readonly owners = new WeakMap<ts.Node, ts.FunctionLikeDeclaration | ts.SourceFile>();
  private proofsReady = false;
  private readonly objectExports = new Map<ts.SourceFile, ObjectExport>();
  private readonly objectCalls = new Map<ts.CallExpression, ts.FunctionLikeDeclaration>();
  private readonly loaderReferences: ts.Identifier[] = [];
  private readonly unsupportedObjectLoads: Array<{node: ts.Node; specifier?: string}> = [];
  private readonly receiverDependent = new Set<ts.FunctionLikeDeclaration>();
  private readonly localClassCalls = new Map<ts.CallExpression, ts.FunctionLikeDeclaration>();
  private readonly localExportBindings = new Set<ts.Symbol>();
  private readonly opaqueClassScopeFiles = new Set<ts.SourceFile>();
  private objectValidationComplete = false;
  private readonly classes = new Set<ts.ClassDeclaration>();
  private readonly classThis = new Map<ts.ClassDeclaration, ts.Node[]>();
  private readonly methodReceivers = new Map<ts.FunctionLikeDeclaration, ObjectExport>();
  private readonly constructorProof = new Map<ts.ClassDeclaration, boolean>();
  private readonly constructorConsumers = new Map<ts.ClassDeclaration, Set<ObjectExport>>();
  private readonly helperWitnesses = new Map<ts.ClassDeclaration, ObjectExport>();
  private readonly singletonEligibility = new Map<ObjectExport, 'closed' | 'conditional' | 'rejected'>();
  private readonly singletonReasons = new Map<ObjectExport, Set<'export_identity' | 'receiver_capability' | 'helper_capability' | 'loader_hard' | 'unclassified' | 'opaque_loader' | 'other_consumer_container_effect' | 'other_consumer_ctor_effect' | 'other_consumer_readonly_arrow'>>();
  private singletonAuditComplete = true;

  finishIndex(complete: boolean): void { this.proofsReady = complete; }
  get indexComplete(): boolean { return this.proofsReady; }
  ownerOf(node: ts.Node): ts.FunctionLikeDeclaration | ts.SourceFile { return this.owners.get(node) ?? node.getSourceFile(); }

  constructor(files: readonly ts.SourceFile[], private readonly tick: () => boolean,
    private readonly limits: FlowLimits, private readonly incomplete: (reason: string) => void,
    private readonly objectScopeComplete = true) {
    this.files = new Map(files.map((file) => [file.fileName, file]));
    const lookup = (name: string) => this.files.get(name.replace(/^\//, ""));
    const host: ts.CompilerHost = {
      getSourceFile: (name) => lookup(name),
      getDefaultLibFileName: () => "", writeFile: () => {},
      getCurrentDirectory: () => "/", getDirectories: () => [],
      fileExists: (name) => lookup(name) !== undefined,
      readFile: (name) => lookup(name)?.text,
      getCanonicalFileName: (name) => name, useCaseSensitiveFileNames: () => true,
      getNewLine: () => "\n", directoryExists: () => false,
    };
    const program = ts.createProgram([...this.files.keys()], {
      allowJs: true, noLib: true, noResolve: true, noEmit: true,
      target: ts.ScriptTarget.Latest, module: ts.ModuleKind.ESNext,
    }, host);
    this.checker = program.getTypeChecker();
    // Assignment patterns contain reads (keys/default values) as well as writes.
    // Visit only actual binding targets, never every identifier in the pattern.
    const markWrite = (target: ts.Node): void => {
      if (!this.tick()) return;
      if (ts.isIdentifier(target)) {
        const symbol = this.symbol(target);
        if (symbol) {
          this.mutated.add(symbol);
          // An exported declaration and a var redeclaration can have distinct
          // local/export symbols while referring to the same mutable binding.
          this.mutated.add(this.checker.getExportSymbolOfSymbol(symbol));
        }
      } else if (ts.isParenthesizedExpression(target) || ts.isAsExpression(target)
        || ts.isTypeAssertionExpression(target) || ts.isNonNullExpression(target)) {
        markWrite(target.expression);
      } else if (ts.isBinaryExpression(target) && target.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        markWrite(target.left); // A destructuring default's right side is read-only.
      } else if (ts.isArrayLiteralExpression(target) || ts.isArrayBindingPattern(target)) {
        for (const element of target.elements) if (!ts.isOmittedExpression(element)) markWrite(element);
      } else if (ts.isObjectLiteralExpression(target) || ts.isObjectBindingPattern(target)) {
        for (const property of ts.isObjectLiteralExpression(target) ? target.properties : target.elements) {
          if (ts.isPropertyAssignment(property)) markWrite(property.initializer);
          else if (ts.isShorthandPropertyAssignment(property)) markWrite(property.name);
          else if (ts.isSpreadAssignment(property)) markWrite(property.expression);
          else if (ts.isBindingElement(property)) markWrite(property.name);
        }
      } else if (ts.isSpreadElement(target)) markWrite(target.expression);
      else if (ts.isBindingElement(target)) markWrite(target.name);
      else if (ts.isVariableDeclarationList(target)) {
        for (const declaration of target.declarations) markWrite(declaration.name);
      } else if ((ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target))
        && ts.isIdentifier(target.expression)) {
        const symbol = this.symbol(target.expression);
        if (symbol) this.mutatedMembers.add(symbol);
      }
    };
    const staticLoadExpression = (expression: ts.Expression): ts.Expression | undefined => {
      while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
        || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)) {
        if (!this.tick()) return undefined;
        expression = expression.expression;
      }
      return expression;
    };
    let walkComplete = true;
    const visit = (node: ts.Node, owner: ts.FunctionLikeDeclaration | ts.SourceFile): void => {
      if (!this.tick()) { walkComplete = false; return; }
      this.indexedAstNodes += 1;
      this.owners.set(node, owner);
      if (ts.isClassDeclaration(node) && ts.isSourceFile(node.parent)) this.classes.add(node);
      if (ts.isImportDeclaration(node)) {
        this.importDeclarations.push(node);
        if (ts.isStringLiteralLike(node.moduleSpecifier) && /^(?:node:)?child_process$/.test(node.moduleSpecifier.text)) this.forkLoads.push(node);
        if (ts.isStringLiteralLike(node.moduleSpecifier) && /^(pg(?:\/|$)|pg-native$|pg-pool$)/.test(node.moduleSpecifier.text)) this.sqlLoads.push({specifier:node.moduleSpecifier.text,node});
      }
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const specifier = node.arguments.length === 1 ? staticLoadExpression(node.arguments[0]) : undefined;
        if (specifier && ts.isStringLiteralLike(specifier) && specifier.text === 'express') this.expressOpaqueLoads.push(node);
        this.unsupportedObjectLoads.push({node, specifier: specifier
          && ts.isStringLiteralLike(specifier) ? specifier.text : undefined});
      }
      if (ts.isExportDeclaration(node) && node.moduleSpecifier) this.unsupportedObjectLoads.push({node,
        specifier: ts.isStringLiteralLike(node.moduleSpecifier) ? node.moduleSpecifier.text : undefined});
      if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
        const specifier = node.moduleReference.expression;
        if (specifier && ts.isStringLiteralLike(specifier) && specifier.text === 'express') this.expressOpaqueLoads.push(node);
        this.unsupportedObjectLoads.push({node, specifier: specifier && ts.isStringLiteralLike(specifier) ? specifier.text : undefined});
      }
      if (ts.isCallExpression(node) && node.arguments.length >= 1) {
        const callee = staticLoadExpression(node.expression);
        if (callee && (callee.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(callee) && callee.text === 'require')) {
          const specifier = staticLoadExpression(node.arguments[0]);
          if (specifier && ts.isStringLiteralLike(specifier)) {
            if (/^(?:node:)?child_process$/.test(specifier.text)) this.forkLoads.push(node);
            if (specifier.text === 'axios') this.axiosLoads.push(node);
            if (/^(pg(?:\/|$)|pg-native$|pg-pool$)/.test(specifier.text)) this.sqlLoads.push({specifier:specifier.text,node});
          }
        }
      }
      if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)
        && node.moduleReference.expression && ts.isStringLiteralLike(node.moduleReference.expression)
        && node.moduleReference.expression.text === 'axios') this.axiosLoads.push(node);
      if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)
        && node.moduleSpecifier.text === 'axios') this.axiosLoads.push(node);
      if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference) && node.moduleReference.expression && ts.isStringLiteralLike(node.moduleReference.expression) && /^(?:node:)?child_process$/.test(node.moduleReference.expression.text)) this.forkLoads.push(node);
      if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier) && /^(?:node:)?child_process$/.test(node.moduleSpecifier.text)) this.forkLoads.push(node);
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isCallExpression(node.initializer)
        && ts.isIdentifier(node.initializer.expression) && node.initializer.expression.text === 'require'
        && node.initializer.arguments.length === 1 && ts.isStringLiteralLike(node.initializer.arguments[0])) this.requireDeclarations.push(node);
      if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference) && node.moduleReference.expression && ts.isStringLiteralLike(node.moduleReference.expression) && /^(pg(?:\/|$)|pg-native$|pg-pool$)/.test(node.moduleReference.expression.text)) this.sqlLoads.push({specifier:node.moduleReference.expression.text,node});
      if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier) && /^(pg(?:\/|$)|pg-native$|pg-pool$)/.test(node.moduleSpecifier.text)) this.sqlLoads.push({specifier:node.moduleSpecifier.text,node});
      if (ts.isIdentifier(node)) {
        if (node.text === 'require' && !(ts.isPropertyAccessExpression(node.parent) && node.parent.name === node)) this.requireReferences.push(node);
        if (node.text === 'eval' || node.text === 'Function') this.opaqueClassScopeFiles.add(node.getSourceFile());
        const symbol = this.symbol(node);
        if (symbol) {
          const references = this.references.get(symbol) ?? [];
          references.push(node); this.references.set(symbol, references);
          this.identifierReferences += 1;
        }
        if (['module', 'exports'].includes(node.text) && !(ts.isPropertyAccessExpression(node.parent) && node.parent.name === node)) {
          const file = node.getSourceFile();
          const references = this.cjsReferences.get(file) ?? [];
          references.push(node); this.cjsReferences.set(file, references);
        }
        if (node.text === 'URLSearchParams') this.nativeBoundaryNodes.push(node);
        if (['Object','String','Array','Reflect','process','globalThis'].includes(node.text)) this.sqlBoundaryNodes.push(node);
        if (node.text === 'require') this.loaderReferences.push(node);
      }
      if (ts.isWithStatement(node)) this.opaqueClassScopeFiles.add(node.getSourceFile());
      if (node.kind === ts.SyntaxKind.ThisKeyword || node.kind === ts.SyntaxKind.SuperKeyword) {
        // Include lexical outer methods as well as nested bodies. No receiver
        // environment is added to the scalar summary/cache contract.
        let parent: ts.Node | undefined = node.parent;
        let classRecorded = false;
        for (let depth = 0; parent && !ts.isSourceFile(parent); depth += 1, parent = parent.parent) {
          if (!this.tick()) { walkComplete = false; break; }
          if (depth >= this.limits.aliasSteps) { this.incomplete('alias_limit'); break; }
          if (isFlowFunction(parent)) this.receiverDependent.add(parent);
          if (!classRecorded && ts.isClassDeclaration(parent)) {
            const refs = this.classThis.get(parent) ?? []; refs.push(node); this.classThis.set(parent,refs); classRecorded = true;
          }
        }
      }
      if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteralLike(node.argumentExpression)
        && node.argumentExpression.text === 'URLSearchParams') this.nativeBoundaryNodes.push(node);
      if (ts.isNewExpression(node)) this.newExpressions.push(node);
      if (isFlowFunction(node) && node.body) {
        if (this.functions.length < this.limits.functions) { this.functions.push(node); this.functionSet.add(node); }
        else this.incomplete("function_limit");
      }
      if (ts.isCallExpression(node)) this.calls.push(node);
      if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
        && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) markWrite(node.left);
      if (ts.isForInStatement(node) || ts.isForOfStatement(node)) markWrite(node.initializer);
      if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
        && (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)) {
        markWrite(node.operand);
      }
      node.forEachChild((child) => visit(child, isFlowFunction(node) ? node : owner));
    };
    for (const file of files) {
      walkComplete = true; visit(file, file);
      if (walkComplete) this.indexWalkFiles.add(file);
    }
    for (const file of files) this.collectExports(file);
    for (const exported of this.exports.values()) {
      for (const fn of exported.values()) if (fn) this.externalEntries.add(fn);
    }
    this.collectObjectExports(files);
    this.collectLocalClassCalls();
    // Pure binding pass: missing/unsupported calls are diagnosed only when analyzed.
    const helperEdges = new Map<ts.FunctionLikeDeclaration | ts.SourceFile, Set<ts.FunctionLikeDeclaration>>();
    for (const call of this.calls) {
      if (!this.tick()) break;
      const resolution = this.resolveCall(call, false);
      if (resolution.kind === "resolved") {
        const uses = this.callTargets.get(resolution.target) ?? []; uses.push(call); this.callTargets.set(resolution.target, uses);
        const owner = this.ownerOf(call);
        const edges = helperEdges.get(owner) ?? new Set(); edges.add(resolution.target); helperEdges.set(owner,edges);
        if (owner !== resolution.target) this.called.add(resolution.target);
      } else {
        for (const argument of call.arguments) {
          const escaped = this.functionOf(argument);
          if (escaped && escaped.getSourceFile() === call.getSourceFile()) this.externalEntries.add(escaped);
        }
      }
    }
    // Possible-body reachability cannot certify removal of an independently seeded root.
    const possible = new Set<ts.FunctionLikeDeclaration>();
    const queue: ts.FunctionLikeDeclaration[] = [];
    for (const group of this.objectExports.values()) {
      if (!this.tick()) break;
      if (!group.receiver || this.singletonEligibility.get(group) !== 'conditional') continue;
      for (const methods of group.methods.values()) for (const target of methods.values()) {
        if (!this.tick()) break;
        if (!possible.has(target)) { possible.add(target); queue.push(target); }
      }
    }
    for (let i=0;i<queue.length;i+=1) {
      if (!this.tick()) break;
      for (const target of helperEdges.get(queue[i]) ?? []) {
        if (!this.tick()) break;
        this.externalEntries.add(target);
        if (!possible.has(target)) { possible.add(target); queue.push(target); }
      }
    }
  }

  symbol(node: ts.Node): ts.Symbol | undefined {
    if (this.symbols.has(node)) return this.symbols.get(node);
    if (!this.tick()) return undefined;
    this.symbolLookups += 1;
    const symbol = ts.isIdentifier(node) && ts.isShorthandPropertyAssignment(node.parent) && node.parent.name === node
      ? this.checker.getShorthandAssignmentValueSymbol(node.parent) : this.checker.getSymbolAtLocation(node);
    this.symbols.set(node, symbol);
    return symbol;
  }

  cjsGlobal(node: ts.Identifier): boolean {
    const symbol = this.symbol(node);
    // The TS JS binder synthesizes module/exports symbols from CommonJS syntax.
    // Real local variables/parameters/imports have declarations of their own.
    return !symbol || !symbol.declarations?.length || symbol.declarations.every((declaration) =>
      ts.isSourceFile(declaration) || ts.isIdentifier(declaration)
        && ts.isPropertyAccessExpression(declaration.parent) && declaration.parent.expression === declaration
      || ts.isPropertyAccessExpression(declaration) && ts.isIdentifier(declaration.expression)
        && declaration.expression.text === node.text
      || ts.isBinaryExpression(declaration) && declaration.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && ts.isPropertyAccessExpression(declaration.left) && ts.isIdentifier(declaration.left.expression)
        && declaration.left.expression.text === node.text && declaration.left.name.text === "exports"
        && ts.isObjectLiteralExpression(declaration.right));
  }

  private functionOf(node: ts.Node | undefined, initializedBefore?: number): ts.FunctionLikeDeclaration | undefined {
    const seen = new Set<ts.Node>();
    for (let depth = 0; node && !seen.has(node); depth += 1) {
      if (!this.tick()) return undefined;
      if (depth >= this.limits.aliasSteps) { this.incomplete("alias_limit"); return undefined; }
      seen.add(node);
      if (isFlowFunction(node) && node.body) {
        const name = "name" in node ? node.name : undefined;
        const symbol = name && ts.isIdentifier(name) ? this.symbol(name) : undefined;
        if (symbol && this.mutated.has(symbol)) return undefined;
        return this.functionSet.has(node) ? node : undefined;
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer
        && (node.parent.flags & ts.NodeFlags.Const) !== 0) {
        if (initializedBefore !== undefined && node.pos >= initializedBefore) return undefined;
        if (initializedBefore !== undefined) initializedBefore = node.pos;
        const symbol = this.symbol(node.name);
        if (symbol && this.mutated.has(symbol)) return undefined;
        node = node.initializer;
        continue;
      }
      if (ts.isIdentifier(node)) {
        const symbol = this.symbol(node);
        if (symbol && !this.mutated.has(symbol) && symbol.declarations?.length === 1) {
          node = symbol.declarations[0];
          continue;
        }
      }
      return undefined;
    }
    return undefined;
  }

  // Pure ESM remains independent of the closed CommonJS object proof.
  private collectExports(file: ts.SourceFile): void {
    const output = new Map<string, ts.FunctionLikeDeclaration | null>();
    const put = (name: string | undefined, value: ts.Node | undefined) => {
      if (!name) return;
      const fn = this.functionOf(value);
      output.set(name, output.has(name) ? null : fn ?? null);
    };
    for (const statement of file.statements) {
      if (!this.tick()) break;
      const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
      if (ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement) || ts.isExportAssignment(statement)
        || ts.isImportEqualsDeclaration(statement) || modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
        this.esmFiles.add(file);
      }
      const exported = modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
        && !modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword);
      if (exported && ts.isFunctionDeclaration(statement)) put(statement.name?.text, statement);
      if (exported && ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!this.tick()) break;
          if (ts.isIdentifier(declaration.name)) put(declaration.name.text, declaration);
        }
      }
      if (ts.isExportDeclaration(statement) && !statement.moduleSpecifier && statement.exportClause
        && ts.isNamedExports(statement.exportClause)) {
        for (const specifier of statement.exportClause.elements) {
          if (!this.tick()) break;
          const local = this.checker.getExportSpecifierLocalTargetSymbol(specifier);
          if (local) this.localExportBindings.add(local);
          put(specifier.name.text, local?.declarations?.[0]);
        }
      }
    }
    this.exports.set(file.fileName, output);
  }

  private importedFile(file: ts.SourceFile, specifier: string, count: boolean):
    { kind: 'file'; file: ts.SourceFile; directory: boolean } | Exclude<CallResolution, { kind: 'resolved' }> {
    if (!specifier.startsWith("./") && !specifier.startsWith("../")) return { kind: "external" };
    const path = posix.normalize(posix.join(posix.dirname(file.fileName), specifier));
    if (path === ".." || path.startsWith("../") || path.startsWith("/") || path.includes("\\")) return { kind: "unsupported" };
    const edge = `${file.fileName}\0${specifier}`;
    if (count) {
      this.moduleEdges.add(edge);
      if (this.moduleEdges.size > this.limits.moduleEdges) return { kind: "module_budget" };
    }
    const directory = specifier.endsWith('/');
    let directoryLookup = directory;
    const extensions = [".js", ".ts", ".tsx", ".jsx", ".cjs", ".mjs"];
    let candidates: string[];
    if (directory) candidates = extensions.map((extension) => posix.join(path, 'index') + extension);
    else if (/\.js$/.test(path)) candidates = [path, path.slice(0, -3) + ".ts", path.slice(0, -3) + ".tsx"];
    else if (/\.(?:ts|tsx|jsx|mjs|cjs|mts|cts)$/.test(path)) candidates = [path];
    else if (posix.extname(path)) return { kind: "unsupported" };
    else candidates = extensions.map((extension) => path + extension);
    const select = (paths: string[]): ts.SourceFile[] | undefined => {
      const matched: ts.SourceFile[] = [];
      for (const candidate of paths) {
        if (!this.tick()) return undefined;
        const source = this.files.get(candidate); if (source) matched.push(source);
      }
      return matched;
    };
    let matched = select(candidates);
    if (!matched) return {kind:'unsupported'}; // The shared tick already records the actual cap.
    if (!directory && !posix.extname(path) && matched.length === 0) {
      directoryLookup = true;
      matched = select(extensions.map((extension) => posix.join(path, 'index') + extension));
      if (!matched) return {kind:'unsupported'};
    }
    if (matched.length === 0) return { kind: "missing" };
    if (matched.length !== 1) return { kind: "ambiguous" };
    return { kind: 'file', file: matched[0], directory: directoryLookup };
  }

  private imported(file: ts.SourceFile, specifier: string, name: string, count: boolean, unproved = false): CallResolution {
    const result = this.importedFile(file, specifier, count);
    if (result.kind !== 'file') return result;
    const group = this.objectExports.get(result.file);
    // Every CommonJS scalar uses the same canonical producer/importer proof.
    // A file match alone must never revive the old direct-file export map.
    const target = this.cjsExportFiles.has(result.file)
      ? group?.valid && (!group.singletonProof || this.singletonEligibility.get(group) === 'closed') && this.objectValidationComplete && this.objectScopeComplete
        && group.methods.get('')?.get(name)
      : this.exports.get(result.file.fileName)?.get(name);
    return !unproved && target && target.getSourceFile() === result.file
      ? { kind: "resolved", target } : { kind: "export_unsupported" };
  }

  /** All CJS own slots share closed file/binding provenance. Synthetic CJS declarations are not local
   * module/exports/require variable, parameter, or import declarations. */
  private objectGlobal(node: ts.Identifier): boolean {
    const scopes = this.cjsShadowScopes.get(node.getSourceFile())?.get(node.text);
    if (scopes?.size) {
      let ancestor: ts.Node | undefined = node;
      for (let depth = 0; ancestor; depth += 1, ancestor = ancestor.parent) {
        if (!this.tick()) return false;
        if (depth >= this.limits.aliasSteps) { this.incomplete('alias_limit'); return false; }
        if (scopes.has(ancestor)) return false;
      }
    }
    const symbol = this.symbol(node);
    for (const declaration of symbol?.declarations ?? []) {
      if (!this.tick()) return false;
      if (ts.isVariableDeclaration(declaration) || ts.isParameter(declaration)
        || ts.isBindingElement(declaration) || ts.isImportSpecifier(declaration)
        || ts.isImportClause(declaration) || ts.isNamespaceImport(declaration)
        || ts.isFunctionDeclaration(declaration)) return false;
      if (!ts.isSourceFile(declaration) && !ts.isBinaryExpression(declaration)
        && !ts.isPropertyAccessExpression(declaration) && !ts.isIdentifier(declaration)) return false;
    }
    return true;
  }

  private objectConst(node: ts.Node): ts.VariableDeclaration | undefined {
    if (!this.tick() || !ts.isIdentifier(node)) return undefined;
    const symbol = this.symbol(node);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    return symbol && !this.mutated.has(symbol) && declaration && ts.isVariableDeclaration(declaration)
      && ts.isIdentifier(declaration.name) && ts.isVariableDeclarationList(declaration.parent)
      && !!(declaration.parent.flags & ts.NodeFlags.Const)
      && ts.isVariableStatement(declaration.parent.parent)
      && ts.isSourceFile(declaration.parent.parent.parent)
      && declaration.getSourceFile() === node.getSourceFile() ? declaration : undefined;
  }

  private objectMethods(literal: ts.ObjectLiteralExpression): Map<string, ts.FunctionLikeDeclaration> | undefined {
    const methods = new Map<string, ts.FunctionLikeDeclaration>();
    let valid = true;
    for (const property of literal.properties) {
      if (!this.tick()) return undefined;
      const key = !ts.isSpreadAssignment(property) ? nameOf(property.name) : undefined;
      const method = ts.isMethodDeclaration(property) ? property
        : ts.isPropertyAssignment(property) && (ts.isFunctionExpression(property.initializer)
          || ts.isArrowFunction(property.initializer)) ? property.initializer : undefined;
      // Preserve exported roots even when an unsupported sibling/ref vetoes
      // the group's identity proof. A candidate is not a security safe fact.
      if (method && this.functionSet.has(method)) this.externalEntries.add(method);
      if (!key || key === '__proto__' || methods.has(key) || !method?.body
        || !this.functionSet.has(method) || this.receiverDependent.has(method)) valid = false;
      else methods.set(key, method);
    }
    return valid && methods.size ? methods : undefined;
  }

  private objectRefCall(ref: ts.Identifier, methods: Map<string, Map<string, ts.FunctionLikeDeclaration>>,
    childSlot?: string): { call: ts.CallExpression; target: ts.FunctionLikeDeclaration } | undefined {
    let node: ts.Expression = ref;
    const keys: string[] = [];
    while (ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node) {
      if (!this.tick() || keys.length >= 2) return undefined;
      keys.push(node.parent.name.text); node = node.parent;
    }
    const call = node.parent;
    if (!ts.isCallExpression(call) || call.expression !== node
      || childSlot !== undefined && keys.length !== 1
      || childSlot === undefined && keys.length !== 1 && keys.length !== 2) return undefined;
    const target = methods.get(childSlot ?? (keys.length === 1 ? '' : keys[0]))?.get(keys.at(-1)!);
    return target ? { call, target } : undefined;
  }

  private objectRefs(symbol: ts.Symbol, group: ObjectExport, childSlot?: string,
    declaration?: ts.VariableDeclaration): boolean {
    for (const ref of this.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      if (group.allowed.has(ref)) continue;
      const use = this.objectRefCall(ref, group.methods, childSlot);
      if (!use || group.receiver && ts.isPropertyAccessExpression(use.call.expression) && !ts.isIdentifier(use.call.expression.expression)
        || declaration && this.beforeInitialization(use.call, declaration)) return false;
      if (childSlot === undefined) this.objectCalls.set(use.call, use.target);
    }
    return true;
  }

  /** Discover an indexed export root even when its immutable certificate fails.
   * The same charged alias witness records exact producer declarations, not a
   * second AST walk or a runtime initialization/loader proof. */
  private exportCallable(value: ts.Node, group: ObjectExport, before: number):
    { target?: ts.FunctionLikeDeclaration; identity: boolean; callable: boolean } {
    let node: ts.Node | undefined = value, position = before, identity = true;
    const seen = new Set<ts.Node>();
    for (let depth = 0; node && !seen.has(node); depth += 1) {
      if (!this.tick()) return {identity:false,callable:false};
      if (depth >= this.limits.aliasSteps) { this.incomplete('alias_limit'); return {identity:false,callable:false}; }
      seen.add(node);
      if (node.getSourceFile() !== group.file) return {identity:false,callable:false};
      if (isFlowFunction(node) && node.body) {
        if (!this.functionSet.has(node)) return {identity:false,callable:false};
        this.externalEntries.add(node);
        const name = 'name' in node ? node.name : undefined;
        if (name && ts.isIdentifier(name)) {
          const symbol = this.symbol(name);
          if (symbol) { group.callableSymbols.add(symbol); group.allowed.add(name); identity &&= !this.mutated.has(symbol); }
        }
        const declaration = variableOf(node);
        const topLevel = node === value || ts.isFunctionDeclaration(node) && ts.isSourceFile(node.parent)
          || declaration && ts.isVariableStatement(declaration.parent.parent)
            && ts.isSourceFile(declaration.parent.parent.parent);
        return {target:node,identity:identity && !!topLevel,
          callable:!this.receiverDependent.has(node) && !node.asteriskToken};
      }
      if (ts.isIdentifier(node)) {
        group.allowed.add(node);
        const symbol = this.symbol(node);
        const declarations = symbol?.declarations;
        if (!symbol || declarations?.length !== 1) return {identity:false,callable:false};
        group.callableSymbols.add(symbol); identity &&= !this.mutated.has(symbol);
        node = declarations[0]; continue;
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const symbol = this.symbol(node.name); group.allowed.add(node.name);
        if (symbol) { group.callableSymbols.add(symbol); identity &&= !this.mutated.has(symbol); }
        identity &&= !!(node.parent.flags & ts.NodeFlags.Const)
          && ts.isVariableStatement(node.parent.parent) && ts.isSourceFile(node.parent.parent.parent)
          && node.pos < position;
        position = node.pos; node = node.initializer; continue;
      }
      return {identity:false,callable:false};
    }
    return {identity:false,callable:false};
  }

  private callableRefs(group: ObjectExport): boolean {
    for (const symbol of group.callableSymbols) {
      for (const ref of this.references.get(symbol) ?? []) {
        if (!this.tick()) return false;
        if (group.allowed.has(ref)) continue;
        if (ref.getSourceFile() !== group.file || !ts.isCallExpression(ref.parent)
          || ref.parent.expression !== ref) return false;
      }
    }
    return true;
  }

  private memberBindingRefs(element: ts.BindingElement, group: ObjectExport): boolean {
    if (!this.tick() || !ts.isObjectBindingPattern(element.parent)
      || !ts.isVariableDeclaration(element.parent.parent) || element.parent.parent.name !== element.parent
      || element.dotDotDotToken || element.initializer || !ts.isIdentifier(element.name)
      || element.propertyName && !ts.isIdentifier(element.propertyName)) return false;
    const key = element.propertyName?.text ?? element.name.text;
    const target = group.methods.get('')?.get(key);
    const symbol = this.symbol(element.name);
    if (!symbol || this.mutated.has(symbol) || symbol.declarations?.length !== 1 || !target) return false;
    for (const ref of this.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      if (ref === element.name) continue;
      if (!ts.isCallExpression(ref.parent) || ref.parent.expression !== ref) return false;
      this.objectCalls.set(ref.parent,target);
    }
    return true;
  }

  /** JS synthetic CJS property symbols can hide the lexical binding at an
   * access. Record only indexed declaration names and their bounded scope;
   * unrelated nested names are not evidence of a native producer mutation. */
  private collectCjsShadows(): boolean {
    let complete = true;
    for (const [file, refs] of this.cjsReferences) {
      const byName = new Map<string, Set<ts.Node>>(); this.cjsShadowScopes.set(file,byName);
      for (const ref of refs) {
        if (!this.tick()) return false;
        const parent = ref.parent;
        const binding = (ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isBindingElement(parent)
          || ts.isFunctionDeclaration(parent) || ts.isFunctionExpression(parent) || ts.isClassDeclaration(parent)
          || ts.isClassExpression(parent) || ts.isImportClause(parent) || ts.isImportSpecifier(parent)
          || ts.isNamespaceImport(parent)) && parent.name === ref;
        if (!binding) continue;
        const functionScoped = ts.isParameter(parent) || ts.isFunctionExpression(parent);
        let varScoped = false, ancestor: ts.Node | undefined = parent;
        for (let depth = 0; ancestor; depth += 1, ancestor = ancestor.parent) {
          if (!this.tick()) return false;
          if (depth >= this.limits.aliasSteps) { this.incomplete('alias_limit'); complete = false; break; }
          if (ts.isVariableDeclarationList(ancestor)) varScoped = !(ancestor.flags & ts.NodeFlags.BlockScoped);
          if (ts.isSourceFile(ancestor) || isFlowFunction(ancestor) && (ancestor !== parent || functionScoped)
            || ts.isClassExpression(parent) && ancestor === parent
            || !functionScoped && !varScoped && ancestor !== parent && (ts.isBlock(ancestor)
              || ts.isForStatement(ancestor) || ts.isForInStatement(ancestor) || ts.isForOfStatement(ancestor)
              || ts.isCaseBlock(ancestor) || ts.isCatchClause(ancestor))) {
            const scopes = byName.get(ref.text) ?? new Set(); scopes.add(ancestor); byName.set(ref.text,scopes); break;
          }
        }
      }
    }
    return complete;
  }

  private collectObjectExports(files: readonly ts.SourceFile[]): void {
    let workComplete = this.collectCjsShadows();
    // Normalize flat property assignments and literal scalar/child objects once.
    // Discovery runs even with incomplete scope; certification does not.
    for (const file of files) {
      const group: ObjectExport = {file,methods:new Map(),allowed:new Set(),symbols:[],callableSymbols:new Set(),valid:true};
      const flat = new Map<string,ts.FunctionLikeDeclaration>(); group.methods.set('',flat);
      const keys = new Set<string>();
      const wholes: ts.BinaryExpression[] = [];
      let properties = 0, observed = false;
      const put = (key: string | undefined, value: ts.Node | undefined, before: number): void => {
        if (!this.tick()) { workComplete = false; group.valid = false; return; }
        if (!key || key === '__proto__' || keys.has(key)) group.valid = false;
        if (key) keys.add(key);
        if (!value) { group.valid = false; return; }
        if (ts.isStringLiteralLike(value) || ts.isNumericLiteral(value)
          || [ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(value.kind)) return;
        const witness = this.exportCallable(value,group,before);
        if (!witness.identity) group.valid = false;
        if (key && witness.target && witness.identity && witness.callable) flat.set(key,witness.target);
      };
      for (const statement of file.statements) {
        if (!this.tick()) { workComplete = false; group.valid = false; break; }
        if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)
          || statement.expression.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
        const assignment = statement.expression, left = assignment.left;
        if (!ts.isPropertyAccessExpression(left)) continue;
        const root = ts.isIdentifier(left.expression) && left.expression.text === 'exports' ? left.expression
          : ts.isPropertyAccessExpression(left.expression) && left.expression.name.text === 'exports'
            && ts.isIdentifier(left.expression.expression) && left.expression.expression.text === 'module'
              ? left.expression.expression : undefined;
        if (root) {
          if (!this.objectGlobal(root)) continue;
          observed = true; properties += 1; group.allowed.add(root); group.valid &&= this.objectGlobal(root);
          put(left.name.text,assignment.right,statement.pos);
        } else if (ts.isIdentifier(left.expression) && left.expression.text === 'module' && left.name.text === 'exports') {
          if (!this.objectGlobal(left.expression)) continue;
          observed = true; group.allowed.add(left.expression); group.valid &&= this.objectGlobal(left.expression);
          if (wholes.length) group.valid = false;
          wholes.push(assignment);
        }
      }
      if (!observed) continue;
      this.cjsExportFiles.add(file);
      for (const whole of wholes) {
        if (!this.tick()) { workComplete = false; group.valid = false; break; }
        if (properties) group.valid = false;
        const wrapper = ts.isIdentifier(whole.right) ? this.objectConst(whole.right) : undefined;
        const literal = wrapper?.initializer ?? whole.right;
        if (wrapper) {
          group.allowed.add(wrapper.name); group.allowed.add(whole.right);
          const symbol = this.symbol(wrapper.name); if (symbol) group.symbols.push(symbol); else group.valid = false;
          if (wrapper.pos > whole.pos) group.valid = false;
        }
        if (!ts.isObjectLiteralExpression(literal)) group.valid = false;
        else for (const property of literal.properties) {
          if (!this.tick()) { workComplete = false; group.valid = false; break; }
          const key = !ts.isSpreadAssignment(property) ? nameOf(property.name) : undefined;
          const value = ts.isShorthandPropertyAssignment(property) ? property.name
            : ts.isPropertyAssignment(property) ? property.initializer : ts.isMethodDeclaration(property) ? property : undefined;
          if (!key || key === '__proto__' || keys.has(key)) group.valid = false;
          if (!value) { group.valid = false; continue; }
          if (ts.isStringLiteralLike(value) || ts.isNumericLiteral(value)
            || [ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(value.kind)) { if (key) keys.add(key); continue; }
          const child = ts.isIdentifier(value) ? this.objectConst(value) : undefined;
          if (child?.initializer && ts.isObjectLiteralExpression(child.initializer)) {
            if (key) keys.add(key);
            if (child.pos > literal.pos) group.valid = false;
            const methods = this.objectMethods(child.initializer);
            if (!methods || !key) group.valid = false;
            else group.methods.set(key,methods);
            group.allowed.add(child.name); group.allowed.add(value);
            const symbol = this.symbol(child.name);
            if (!symbol || !this.objectRefs(symbol,group,key,child)) group.valid = false;
          } else put(key,value,literal.pos);
        }
      }
      // ESM+CJS export interoperability is not a closed CJS producer.
      if (this.esmFiles.has(file)) group.valid = false;
      for (const node of this.cjsReferences.get(file) ?? []) {
        if (!this.tick()) { workComplete = false; group.valid = false; break; }
        // Local lexical objects/parameters are not native exports. The
        // declaration-scoped index above still closes synthetic shadow holes.
        if (this.objectGlobal(node) && !group.allowed.has(node)) group.valid = false;
      }
      for (const symbol of group.symbols) if (!this.objectRefs(symbol,group)) group.valid = false;
      if (!this.callableRefs(group)) group.valid = false;
      this.objectExports.set(file,group);
    }
    this.collectSingletons(files);
    if (!this.objectExports.size) { this.objectValidationComplete = workComplete; return; }
    const edges = new Map<ts.SourceFile, Set<ts.SourceFile>>();
    let loaderClosed = true;
    let singletonLoaderHard = false, singletonLoaderOpaque = false;
    // module.require/cache/opaque module escape can introduce an unobserved
    // importer. Ordinary module.exports in unrelated files is not a loader.
    for (const refs of this.cjsReferences.values()) {
      for (const ref of refs) {
        if (!this.tick()) { workComplete = false; break; }
        if (ref.text !== 'module' || !this.objectGlobal(ref)) continue;
        if (!ts.isPropertyAccessExpression(ref.parent) || ref.parent.expression !== ref
          || ref.parent.name.text !== 'exports') { loaderClosed = false; if (!this.loaderObservation(ref)) singletonLoaderHard = true; }
      }
    }
    for (const ref of this.loaderReferences) {
      if (!this.tick()) { workComplete = false; break; }
      if (ts.isPropertyAccessExpression(ref.parent) && ref.parent.name === ref || !this.objectGlobal(ref)) continue;
      let callee: ts.Expression = ref;
      for (let depth = 0; ts.isParenthesizedExpression(callee.parent) || ts.isAsExpression(callee.parent)
        || ts.isTypeAssertionExpression(callee.parent) || ts.isNonNullExpression(callee.parent); depth += 1) {
        if (!this.tick()) { workComplete = false; break; }
        if (depth >= this.limits.aliasSteps) { this.incomplete('alias_limit'); workComplete = false; break; }
        callee = callee.parent;
      }
      const call = callee.parent;
      if (!ts.isCallExpression(call) || call.expression !== callee || call.arguments.length !== 1) { loaderClosed = false; if (!this.loaderObservation(ref)) singletonLoaderHard = true; continue; }
      let specifier = call.arguments[0];
      for (let depth = 0; ts.isParenthesizedExpression(specifier) || ts.isAsExpression(specifier)
        || ts.isTypeAssertionExpression(specifier) || ts.isNonNullExpression(specifier); depth += 1) {
        if (!this.tick()) { workComplete = false; break; }
        if (depth >= this.limits.aliasSteps) { this.incomplete('alias_limit'); workComplete = false; break; }
        specifier = specifier.expression;
      }
      if (!ts.isStringLiteralLike(specifier)) { loaderClosed = false; singletonLoaderOpaque = true; continue; }
      if (['module','node:module'].includes(specifier.text)) { loaderClosed = false; singletonLoaderHard = true; }
      const resolution = this.importedFile(ref.getSourceFile(), specifier.text, true);
      if (resolution.kind === 'module_budget') { this.incomplete('module_module_budget'); workComplete = false; break; }
      if (resolution.kind !== 'file') continue;
      const outgoing = edges.get(ref.getSourceFile()) ?? new Set(); outgoing.add(resolution.file); edges.set(ref.getSourceFile(), outgoing);
      const group = this.objectExports.get(resolution.file);
      if (!group) continue;
      const declaration = call.parent;
      if (callee !== ref || specifier !== call.arguments[0] || !ts.isVariableDeclaration(declaration) || declaration.initializer !== call
        || !ts.isVariableDeclarationList(declaration.parent)
        || !(declaration.parent.flags & ts.NodeFlags.Const)) { group.valid = false; if (group.singletonProof) group.singletonProof.importersClosed=false; continue; }
      if (ts.isObjectBindingPattern(declaration.name)) {
        if (group.receiver || group.constructorClass) { group.valid = false; if (group.singletonProof) group.singletonProof.importersClosed=false; }
        else for (const element of declaration.name.elements) if (!this.memberBindingRefs(element,group)) group.valid = false;
      } else if (ts.isIdentifier(declaration.name)) {
        const symbol = this.symbol(declaration.name); group.allowed.add(declaration.name);
        if (!symbol || this.mutated.has(symbol) || !(group.constructorClass ? this.constructorRefs(symbol,group,declaration) : this.objectRefs(symbol, group, undefined, declaration))) { group.valid = false; if (group.singletonProof) group.singletonProof.importersClosed=false; }
      } else { group.valid = false; if (group.singletonProof) group.singletonProof.importersClosed=false; }
    }
    // ESM/re-export loaders are observed but are not the CJS receiver lane.
    for (const declaration of this.importDeclarations) {
      if (!this.tick()) { workComplete = false; break; }
      if (!ts.isStringLiteralLike(declaration.moduleSpecifier)) { loaderClosed = false; singletonLoaderHard = true; continue; }
      if (['module','node:module'].includes(declaration.moduleSpecifier.text)) { loaderClosed = false; singletonLoaderHard = true; }
      const result = this.importedFile(declaration.getSourceFile(), declaration.moduleSpecifier.text, true);
      if (result.kind === 'module_budget') { this.incomplete('module_module_budget'); workComplete = false; break; }
      if (result.kind === 'file') {
        const outgoing = edges.get(declaration.getSourceFile()) ?? new Set(); outgoing.add(result.file); edges.set(declaration.getSourceFile(), outgoing);
        const group = this.objectExports.get(result.file); if (group) { group.valid = false; if(group.singletonProof)group.singletonProof.importersClosed=false; }
      }
    }
    for (const load of this.unsupportedObjectLoads) {
      if (!this.tick()) { workComplete = false; break; }
      if (load.specifier === undefined) { loaderClosed = false; singletonLoaderHard = true; continue; }
      if (['module','node:module'].includes(load.specifier)) { loaderClosed = false; singletonLoaderHard = true; }
      const result = this.importedFile(load.node.getSourceFile(), load.specifier, true);
      if (result.kind === 'module_budget') { this.incomplete('module_module_budget'); workComplete = false; break; }
      if (result.kind === 'file') {
        const outgoing = edges.get(load.node.getSourceFile()) ?? new Set(); outgoing.add(result.file); edges.set(load.node.getSourceFile(), outgoing);
        const group = this.objectExports.get(result.file); if (group) { group.valid = false; if(group.singletonProof)group.singletonProof.importersClosed=false; }
      }
    }
    const cyclic = (file: ts.SourceFile, active: Set<ts.SourceFile>, done: Set<ts.SourceFile>): boolean => {
      if (!this.tick()) { workComplete = false; return true; }
      if (active.has(file)) return true;
      if (done.has(file)) return false;
      if (active.size >= this.limits.aliasSteps) { this.incomplete('alias_limit'); workComplete = false; return true; }
      active.add(file);
      for (const target of edges.get(file) ?? []) if (cyclic(target, active, done)) return true;
      active.delete(file); done.add(file); return false;
    };
    for (const group of this.objectExports.values()) {
      const cycle = cyclic(group.file, new Set(), new Set());
      if (group.receiver || group.constructorClass) {
        if (singletonLoaderHard || cycle) group.valid = false;
        group.declared = singletonLoaderOpaque;
        if(group.singletonProof) { group.singletonProof.loaderHard=singletonLoaderHard; group.singletonProof.cycle=cycle; }
      } else if (!loaderClosed || cycle) group.valid = false;
    }
    // Propagate failed constructor/consumer certificates over existing indexed group edges.
    // Each group is invalidated once; no AST/heap traversal or result-dependent retry.
    const dependents=new Map<ObjectExport,Set<ObjectExport>>();
    const link=(dependency:ObjectExport,consumer:ObjectExport):void=>{const next=dependents.get(dependency) ?? new Set();next.add(consumer);dependents.set(dependency,next);};
    for (const group of this.objectExports.values()) {
      if (!this.tick()) { workComplete=false; group.valid=false; break; }
      for (const dependency of group.dependencies ?? []) {
        if (!this.tick()) { workComplete=false; group.valid=false; break; }
        link(dependency,group); group.declared ||= dependency.declared;
      }
      const classNode=group.constructorClass ?? group.receiver?.classNode;
      if (classNode) for (const consumer of this.constructorConsumers.get(classNode) ?? []) {
        if (!this.tick()) { workComplete=false; group.valid=false; break; }
        link(consumer,group);
      }
    }
    const invalid=[...this.objectExports.values()].filter(group=>!group.valid);
    for (let i=0;i<invalid.length;i+=1) {
      if (!this.tick()) { workComplete=false; break; }
      for (const group of dependents.get(invalid[i]) ?? []) {
        if (!this.tick()) { workComplete=false; break; }
        if (group.valid) { group.valid=false; invalid.push(group); }
      }
    }
    this.auditSingletonEligibility();
    this.objectValidationComplete = workComplete && this.singletonAuditComplete;
  }

  private singletonTick(): boolean {
    if (this.tick()) return true;
    this.singletonAuditComplete=false; return false;
  }

  private primitive(node: ts.Expression): boolean {
    return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)
      || [ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(node.kind);
  }

  /** Initializer identity only: unrelated class effects are deliberately not certified. */
  private constructorIdentity(value: ts.NewExpression, consumer: ObjectExport): ts.ClassDeclaration | undefined {
    if (!this.singletonTick() || !consumer.receiver || value.arguments?.length || !ts.isIdentifier(value.expression)) return undefined;
    const symbol=this.symbol(value.expression), declaration=symbol?.declarations?.length===1 ? symbol.declarations[0] : undefined;
    if (!symbol || this.mutated.has(symbol) || !declaration || declaration.end>consumer.receiver.exportNode.pos
      || this.ownerOf(declaration)!==consumer.file) return undefined;
    if (ts.isClassDeclaration(declaration)) return this.classes.has(declaration) ? declaration : undefined;
    if (!ts.isVariableDeclaration(declaration) || !ts.isIdentifier(declaration.name)
      || !ts.isVariableDeclarationList(declaration.parent) || !(declaration.parent.flags&ts.NodeFlags.Const)) return undefined;
    const load=declaration.initializer;
    if (!load || !ts.isCallExpression(load) || !ts.isIdentifier(load.expression) || load.expression.text!=='require'
      || !this.objectGlobal(load.expression) || load.arguments.length!==1 || !ts.isStringLiteralLike(load.arguments[0])) return undefined;
    const result=this.importedFile(consumer.file,load.arguments[0].text,true);
    if (result.kind!=='file') return undefined;
    const producer=this.objectExports.get(result.file);
    return producer?.singletonProof?.exportClosed ? producer.constructorClass : undefined;
  }

  private literalContainer(value: ts.Expression): boolean {
    const keys=new Set<string>();
    if (ts.isArrayLiteralExpression(value)) {
      for (const item of value.elements) if (!this.singletonTick() || !this.primitive(item)) return false;
      return true;
    }
    if (!ts.isObjectLiteralExpression(value)) return false;
    for (const item of value.properties) {
      if (!this.singletonTick() || !ts.isPropertyAssignment(item) || ts.isComputedPropertyName(item.name)) return false;
      const key=nameOf(item.name);
      if (!key || keys.has(key) || ['constructor','prototype','__proto__'].includes(key) || !this.primitive(item.initializer)) return false;
      keys.add(key);
    }
    return true;
  }

  /** Checks indexed receiver capabilities, including helper producers with no exported receiver. */
  private receiverCapability(classNode: ts.ClassDeclaration, fields: Map<string,'primitive'|'container'|'instance'>,
    methods: Set<string>, allowArrow: boolean, instances=new Map<string,Set<string>>()): {ok:boolean; arrow:boolean} {
    let arrow=false;
    for (const node of this.classThis.get(classNode) ?? []) {
      if (!this.singletonTick()) return {ok:false,arrow};
      let owner=this.ownerOf(node);
      if (ts.isConstructorDeclaration(owner) && owner.parent===classNode) continue;
      for (let depth=0;ts.isArrowFunction(owner);depth+=1) {
        if (!allowArrow || !this.singletonTick()) return {ok:false,arrow};
        if (depth>=this.limits.aliasSteps) {this.incomplete('alias_limit');this.singletonAuditComplete=false;return {ok:false,arrow};}
        arrow=true;owner=this.ownerOf(owner.parent);
      }
      const property=node.parent;
      if (node.kind!==ts.SyntaxKind.ThisKeyword || !ts.isMethodDeclaration(owner) || owner.parent!==classNode
        || !ts.isPropertyAccessExpression(property) || property.expression!==node
        || ['constructor','prototype','__proto__'].includes(property.name.text)) return {ok:false,arrow};
      const use=property.parent;
      if (ts.isBinaryExpression(use) && use.left===property && use.operatorToken.kind>=ts.SyntaxKind.FirstAssignment && use.operatorToken.kind<=ts.SyntaxKind.LastAssignment
        || ts.isDeleteExpression(use) || ts.isPrefixUnaryExpression(use) && [ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(use.operator) || ts.isPostfixUnaryExpression(use)) return {ok:false,arrow};
      if (methods.has(property.name.text)) {
        if (!ts.isCallExpression(use) || use.expression!==property) return {ok:false,arrow};
        continue;
      }
      const kind=fields.get(property.name.text);
      if (kind==='primitive') {
        if (ts.isPropertyAccessExpression(use) || ts.isElementAccessExpression(use)) return {ok:false,arrow};
        continue;
      }
      if (kind==='container' && ts.isForOfStatement(use) && use.expression===property) continue;
      if (kind==='instance' && ts.isPropertyAccessExpression(use) && use.expression===property
        && !['constructor','prototype','__proto__'].includes(use.name.text) && instances.get(property.name.text)?.has(use.name.text)
        && ts.isCallExpression(use.parent) && use.parent.expression===use) continue;
      return {ok:false,arrow};
    }
    return {ok:true,arrow};
  }

  /** Complete local shape check; soft syntax never stops the remaining hard audit. */
  private consumerCapability(group: ObjectExport, selectedHelper?: ts.ClassDeclaration): {ok:boolean; soft:boolean} {
    const proof=group.singletonProof,classNode=group.receiver?.classNode;
    if (!proof?.exportClosed || !proof.structureClosed || !proof.importersClosed || proof.loaderHard || proof.cycle || !classNode) return {ok:false,soft:false};
    const methods=new Set<string>(),fields=new Map<string,'primitive'|'container'|'instance'>(),instances=new Map<string,Set<string>>();
    for(const key of group.methods.get('')?.keys() ?? []) {if(!this.singletonTick())return {ok:false,soft:false};methods.add(key);}
    let soft=false,selected=0;
    for (const member of classNode.members) {
      if (!this.singletonTick()) return {ok:false,soft};
      if (!ts.isConstructorDeclaration(member)) continue;
      if (!member.body || member.parameters.length || member.modifiers?.length) return {ok:false,soft};
      for (const statement of member.body.statements) {
        if (!this.singletonTick() || !ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)
          || statement.expression.operatorToken.kind!==ts.SyntaxKind.EqualsToken) return {ok:false,soft};
        const {left,right}=statement.expression;
        if (!ts.isPropertyAccessExpression(left) || left.expression.kind!==ts.SyntaxKind.ThisKeyword
          || ['constructor','prototype','__proto__'].includes(left.name.text) || methods.has(left.name.text) || fields.has(left.name.text)) return {ok:false,soft};
        if (this.primitive(right)) fields.set(left.name.text,'primitive');
        else if (this.literalContainer(right)) {fields.set(left.name.text,'container');soft=true;const reasons=this.singletonReasons.get(group) ?? new Set();reasons.add('other_consumer_container_effect');this.singletonReasons.set(group,reasons);}
        else if (ts.isNewExpression(right)) {
          const helper=this.constructorIdentity(right,group);
          if (!helper || helper===classNode) return {ok:false,soft};
          fields.set(left.name.text,'instance');
          const keys=new Set<string>();
          for(const member of helper.members) {if(!this.singletonTick())return {ok:false,soft};if(ts.isMethodDeclaration(member)){const key=nameOf(member.name);if(key && !ts.isComputedPropertyName(member.name))keys.add(key);}}
          instances.set(left.name.text,keys);
          if (selectedHelper===helper) selected+=1;
          else if (selectedHelper) {soft=true;const reasons=this.singletonReasons.get(group) ?? new Set();reasons.add('other_consumer_ctor_effect');this.singletonReasons.set(group,reasons);}
        } else return {ok:false,soft};
      }
    }
    if (selectedHelper && selected!==1) return {ok:false,soft};
    const capability=this.receiverCapability(classNode,fields,methods,!!selectedHelper,instances);
    if (capability.arrow) {soft=true;const reasons=this.singletonReasons.get(group) ?? new Set();reasons.add('other_consumer_readonly_arrow');this.singletonReasons.set(group,reasons);}
    return {ok:capability.ok,soft};
  }

  private auditSingletonEligibility(): void {
    const helperMemo=new Map<ts.ClassDeclaration,{ok:boolean;soft:boolean}>();
    const auditHelper=(classNode:ts.ClassDeclaration):{ok:boolean;soft:boolean}=>{
      const cached=helperMemo.get(classNode);if(cached)return cached;
      const rejected={ok:false,soft:false};helperMemo.set(classNode,rejected);
      if (!this.singletonTick()) return rejected;
      const group=this.helperWitnesses.get(classNode),proof=group?.singletonProof;
      if (!group || !this.constructorProof.get(classNode) || proof && (!proof.exportClosed || !proof.structureClosed || !proof.importersClosed || proof.loaderHard || proof.cycle)) return rejected;
      const fields=new Map<string,'primitive'|'container'|'instance'>(),methods=new Set<string>();
      for (const member of classNode.members) {
        if (!this.singletonTick()) return rejected;
        if(ts.isMethodDeclaration(member)){const key=nameOf(member.name);if(key)methods.add(key);}
        if(ts.isConstructorDeclaration(member))for(const statement of member.body?.statements ?? []) {
          if(!this.singletonTick() || !ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)
            || !ts.isPropertyAccessExpression(statement.expression.left) || !this.primitive(statement.expression.right)) return rejected;
          fields.set(statement.expression.left.name.text,'primitive');
        }
      }
      if(!this.receiverCapability(classNode,fields,methods,false).ok)return rejected;
      let soft=!!group.declared;
      for(const consumer of this.constructorConsumers.get(classNode) ?? []) {
        if(!this.singletonTick())return rejected;
        const result=this.consumerCapability(consumer,classNode);
        if(!result.ok)return rejected;
        soft ||= result.soft;
      }
      const result={ok:true,soft};helperMemo.set(classNode,result);return result;
    };
    // Reverse the already-indexed constructor edges once, not once per invocation.
    const helpers=new Map<ObjectExport,Set<ts.ClassDeclaration>>();
    for(const [classNode,consumers] of this.constructorConsumers) {
      if(!this.singletonTick())break;
      for(const consumer of consumers) {
        if(!this.singletonTick())break;
        const set=helpers.get(consumer) ?? new Set();set.add(classNode);helpers.set(consumer,set);
      }
    }
    for(const group of this.objectExports.values()) {
      if(!this.singletonTick())break;
      if(!group.singletonProof)continue;
      this.singletonEligibility.set(group,'rejected');
      const proof=group.singletonProof;
      if(!this.objectScopeComplete || !proof.exportClosed || !proof.structureClosed || !proof.importersClosed || proof.loaderHard || proof.cycle) {
        this.singletonReasons.set(group,new Set([proof.loaderHard?'loader_hard':!proof.exportClosed?'export_identity':'unclassified']));continue;
      }
      let ok=true,soft=!!group.declared;
      if(group.constructorClass){const result=auditHelper(group.constructorClass);ok=result.ok;soft ||= result.soft;}
      else {
        if(!group.receiver || group.receiverProof!==true || !this.constructorProof.get(group.receiver.classNode)) {this.singletonReasons.set(group,new Set(['receiver_capability']));continue;}
        const own=this.consumerCapability(group);ok=own.ok;
        for(const helper of helpers.get(group) ?? []) {
          if(!this.singletonTick()){ok=false;break;}
          const result=auditHelper(helper);ok &&= result.ok;soft ||= result.soft;
        }
      }
      if(!ok){this.singletonReasons.set(group,new Set(['helper_capability']));continue;}
      // Unknown historical failure cannot be inferred to be soft from valid=false alone.
      if(!group.valid && !soft){this.singletonReasons.set(group,new Set(['unclassified']));continue;}
      const mode=soft ? 'conditional':'closed';this.singletonEligibility.set(group,mode);
      const reasons=this.singletonReasons.get(group) ?? new Set();if(group.declared)reasons.add('opaque_loader');this.singletonReasons.set(group,reasons);
    }
  }

  /** Primitive UMD observations do not expose a loader capability. */
  private loaderObservation(ref: ts.Identifier): boolean {
    if (ts.isTypeOfExpression(ref.parent) && ref.parent.expression === ref) return this.tick();
    if (ref.text !== 'module') return false;
    let node: ts.Node = ref;
    for (let depth = 0; depth < this.limits.aliasSteps; depth += 1) {
      if (!this.tick()) return false;
      const parent = node.parent;
      if (ts.isParenthesizedExpression(parent) && parent.expression === node) { node = parent; continue; }
      if (ts.isBinaryExpression(parent) && [ts.SyntaxKind.AmpersandAmpersandToken,ts.SyntaxKind.BarBarToken].includes(parent.operatorToken.kind)) { node = parent; continue; }
      return ts.isIfStatement(parent) && parent.expression === node || ts.isConditionalExpression(parent) && parent.condition === node;
    }
    this.incomplete('alias_limit'); return false;
  }

  private constructorRefs(symbol: ts.Symbol, group: ObjectExport, declaration?: ts.VariableDeclaration): boolean {
    for (const ref of this.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      if (group.allowed.has(ref) || declaration?.name === ref) continue;
      const parent = ref.parent;
      if (!ts.isNewExpression(parent) || parent.expression !== ref || parent.arguments?.length
        || declaration && this.beforeInitialization(parent as unknown as ts.CallExpression,declaration)
        || group.constructorClass && this.ownerOf(parent) === this.ownerOf(group.constructorClass) && parent.pos < group.constructorClass.end) return false;
      if (group.receiver) return false; // Additional instances are not the certified singleton export.
      // Only an independently validated singleton's own constructor field may hold a helper instance.
      const assignment = parent.parent, statement = assignment?.parent;
      const owner = this.ownerOf(parent);
      const singleton = ts.isConstructorDeclaration(owner) && ts.isClassDeclaration(owner.parent)
        ? this.objectExports.get(owner.getSourceFile()) : undefined;
      if (!ts.isBinaryExpression(assignment) || assignment.right !== parent || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken
        || !ts.isPropertyAccessExpression(assignment.left) || assignment.left.expression.kind !== ts.SyntaxKind.ThisKeyword
        || !ts.isExpressionStatement(statement) || !singleton?.receiver || singleton.receiver.classNode !== owner.parent) return false;
      const helperClass = group.constructorClass ?? symbol.declarations?.find(ts.isClassDeclaration);
      if (helperClass) { const consumers=this.constructorConsumers.get(helperClass) ?? new Set(); consumers.add(singleton); this.constructorConsumers.set(helperClass,consumers); }
    }
    return !this.mutated.has(symbol) && !this.mutatedMembers.has(symbol);
  }

  /** Existing indexed class/this/ref witnesses, never a second full AST walk. */
  private collectSingletons(files: readonly ts.SourceFile[]): void {
    for (const file of files) {
      for (const statement of file.statements) {
        if (!this.tick()) return;
        if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)
          || statement.expression.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
        const assignment = statement.expression, left = assignment.left;
        if (!ts.isPropertyAccessExpression(left) || left.name.text !== 'exports'
          || !ts.isIdentifier(left.expression) || left.expression.text !== 'module' || !this.objectGlobal(left.expression)) continue;
        const value = assignment.right;
        const name = ts.isNewExpression(value) && ts.isIdentifier(value.expression) ? value.expression
          : ts.isIdentifier(value) ? value : undefined;
        const symbol = name ? this.symbol(name) : undefined;
        const classNode = symbol?.declarations?.length === 1 && ts.isClassDeclaration(symbol.declarations[0]) ? symbol.declarations[0] : undefined;
        if (!classNode || !this.classes.has(classNode) || classNode.getSourceFile() !== file) continue;
        const group: ObjectExport = {file,methods:new Map([['',new Map()]]),allowed:new Set([left.expression,name!,classNode.name!]),symbols:[],callableSymbols:new Set(),valid:true,dependencies:[]};
        if (ts.isNewExpression(value)) group.receiver = {file,classNode,exportNode:value};
        else group.constructorClass = classNode;
        group.valid &&= !this.esmFiles.has(file) && classNode.end <= value.pos && !this.mutated.has(symbol!);
        const previous = this.objectExports.get(file);
        // Exactly one whole export and no competing CJS use/property assignment.
        for (const ref of this.cjsReferences.get(file) ?? []) {
          if (!this.tick()) { group.valid = false; break; }
          if (this.objectGlobal(ref) && !group.allowed.has(ref)) group.valid = false;
        }
        if (previous?.receiver || previous?.constructorClass) group.valid = false;
        if (ts.isNewExpression(value) && value.arguments?.length) group.valid = false;
        const exportClosed=group.valid;
        const keys = new Set<string>();
        if (classNode.heritageClauses?.length || classNode.modifiers?.length) group.valid = false;
        for (const member of classNode.members) {
          if (!this.tick()) { group.valid = false; break; }
          if (ts.isConstructorDeclaration(member)) continue;
          if (ts.isMethodDeclaration(member) && this.functionSet.has(member)) this.externalEntries.add(member);
          const key = ts.isMethodDeclaration(member) ? nameOf(member.name) : undefined;
          if (!ts.isMethodDeclaration(member) || !member.body || !key || ts.isComputedPropertyName(member.name)
            || ['constructor','prototype','__proto__'].includes(key) || keys.has(key)
            || member.asteriskToken || member.modifiers?.some(m=>m.kind!==ts.SyntaxKind.AsyncKeyword)) { group.valid = false; continue; }
          keys.add(key); group.methods.get('')!.set(key,member);
          if (group.receiver) this.methodReceivers.set(member,group);
        }
        if (!this.constructorRefs(symbol!,group)) group.valid = false;
        group.singletonProof={exportClosed,structureClosed:group.valid,importersClosed:true,loaderHard:false,cycle:false};
        if (group.constructorClass) this.helperWitnesses.set(classNode,group);
        this.objectExports.set(file,group); this.cjsExportFiles.add(file);
      }
    }
    // All constructor export groups exist before dependency lookup; each proof is memoized.
    for (const group of this.objectExports.values()) {
      if (!group.receiver && !group.constructorClass) continue;
      const classNode = group.receiver?.classNode ?? group.constructorClass!;
      if (!this.constructorShape(classNode,group,0)) group.valid = false;
      if (group.receiver) {
        group.receiverProof=true;
        for (const node of this.classThis.get(classNode) ?? []) {
        if (!this.tick()) { group.valid = false; group.receiverProof=false; break; }
        const owner = this.ownerOf(node);
        if (ts.isConstructorDeclaration(owner)) continue;
        const property = node.parent;
        if (node.kind !== ts.SyntaxKind.ThisKeyword || !ts.isMethodDeclaration(owner) || owner.parent !== classNode
          || !ts.isPropertyAccessExpression(property) || property.expression !== node
          || ['constructor','prototype','__proto__'].includes(property.name.text)) { group.valid = false; group.receiverProof=false; continue; }
        const consumer = property.parent;
        // Only reads/direct own method calls; selected instance capability never escapes.
        if (ts.isBinaryExpression(consumer) && consumer.left === property && consumer.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && consumer.operatorToken.kind <= ts.SyntaxKind.LastAssignment
          || ts.isDeleteExpression(consumer) || ts.isPrefixUnaryExpression(consumer) || ts.isPostfixUnaryExpression(consumer)) { group.valid = false; group.receiverProof=false; }
        if (group.methods.get('')!.has(property.name.text)
          && (!ts.isCallExpression(consumer) || consumer.expression !== property)) { group.valid = false; group.receiverProof=false; }
        if (!group.methods.get('')!.has(property.name.text)) {
          // Unknown field reads stay opaque; storage/argument/return of the receiver's field can expose its capability.
          if (ts.isReturnStatement(consumer) || ts.isVariableDeclaration(consumer)
            || ts.isCallExpression(consumer) && consumer.expression !== property
            || ts.isBinaryExpression(consumer) && consumer.right === property) { group.valid = false; group.receiverProof=false; }
          let outer: ts.Node = property;
          for (let depth=0; ts.isPropertyAccessExpression(outer.parent) && outer.parent.expression===outer; depth+=1) {
            if (!this.tick() || depth>=this.limits.aliasSteps) { group.valid=false; group.receiverProof=false; break; } outer=outer.parent;
          }
          if (ts.isBinaryExpression(outer.parent) && outer.parent.left===outer
            || ts.isDeleteExpression(outer.parent)) { group.valid=false; group.receiverProof=false; }
        }
      }
      }
    }

  }

  private constructorShape(classNode: ts.ClassDeclaration, group: ObjectExport, depth: number): boolean {
    const cached = this.constructorProof.get(classNode); if (cached !== undefined) return cached;
    if (!this.tick() || depth >= this.limits.aliasSteps) { if (depth>=this.limits.aliasSteps) this.incomplete('alias_limit'); return false; }
    this.constructorProof.set(classNode,false); // Active dependency/cycle never certifies.
    const constructors: ts.ConstructorDeclaration[] = [];
    const names = new Set<string>();
    if (classNode.modifiers?.length) return false;
    for (const member of classNode.members) {
      if (!this.tick()) return false;
      if (ts.isConstructorDeclaration(member)) { constructors.push(member); continue; }
      const key=ts.isMethodDeclaration(member) ? nameOf(member.name) : undefined;
      if (!ts.isMethodDeclaration(member) || !key || ts.isComputedPropertyName(member.name) || names.has(key)
        || member.modifiers?.some(m=>m.kind!==ts.SyntaxKind.AsyncKeyword) || member.asteriskToken) return false;
      names.add(key);
    }
    if (constructors.length>1 || classNode.heritageClauses?.length) return false;
    const ctor=constructors[0];
    if (!ctor) { this.constructorProof.set(classNode,true); return true; }
    if (!ctor.body || ctor.parameters.length || ctor.modifiers?.length) return false;
    const fields=new Set<string>();
    for (const statement of ctor.body.statements) {
      if (!this.tick()) return false;
      if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)
        || statement.expression.operatorToken.kind!==ts.SyntaxKind.EqualsToken) return false;
      const {left,right}=statement.expression;
      if (!ts.isPropertyAccessExpression(left) || left.expression.kind!==ts.SyntaxKind.ThisKeyword
        || ['constructor','prototype','__proto__'].includes(left.name.text) || fields.has(left.name.text)
        || group.methods.get('')?.has(left.name.text)) return false;
      fields.add(left.name.text);
      if (ts.isStringLiteralLike(right) || ts.isNumericLiteral(right) || [ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(right.kind)) continue;
      // The independent helper constructor is literal own-data only; no recursive factory graph.
      if (!group.receiver || !ts.isNewExpression(right) || right.arguments?.length || !ts.isIdentifier(right.expression)) return false;
      const symbol=this.symbol(right.expression);
      const declaration=symbol?.declarations?.length===1 ? symbol.declarations[0] : undefined;
      let helper: ts.ClassDeclaration | undefined, dependency: ObjectExport | undefined;
      if (declaration && ts.isClassDeclaration(declaration) && declaration.getSourceFile()===classNode.getSourceFile() && declaration.end<=group.receiver!.exportNode.pos) helper=declaration;
      else if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer
        && ts.isVariableDeclarationList(declaration.parent) && (declaration.parent.flags & ts.NodeFlags.Const)
        && !this.mutated.has(symbol!) && this.ownerOf(declaration)===classNode.getSourceFile()
        && declaration.end<=group.receiver!.exportNode.pos) {
        const load=declaration.initializer;
        if (ts.isCallExpression(load) && ts.isIdentifier(load.expression) && load.expression.text==='require' && this.objectGlobal(load.expression)
          && load.arguments.length===1 && ts.isStringLiteralLike(load.arguments[0])) {
          const resolution=this.importedFile(classNode.getSourceFile(),load.arguments[0].text,true);
          if (resolution.kind==='file') { dependency=this.objectExports.get(resolution.file); helper=dependency?.constructorClass; }
        }
      }
      if (!helper || helper===classNode || !this.classes.has(helper)) return false;
      const consumers=this.constructorConsumers.get(helper) ?? new Set();consumers.add(group);this.constructorConsumers.set(helper,consumers);
      const helperGroup=dependency ?? {file:helper.getSourceFile(),methods:new Map([['',new Map<string,ts.FunctionLikeDeclaration>()]]),allowed:new Set<ts.Node>([helper.name!,right.expression]),symbols:[],callableSymbols:new Set<ts.Symbol>(),valid:true};
      if (!dependency && (!symbol || !this.constructorRefs(symbol,helperGroup))) return false;
      if (!dependency) this.helperWitnesses.set(helper,helperGroup);
      if (!this.constructorShape(helper,helperGroup,depth+1)) return false;
      if (dependency && !group.dependencies!.includes(dependency)) group.dependencies!.push(dependency);
    }
    this.constructorProof.set(classNode,true); return true;
  }

  rootReceiver(target: ts.FunctionLikeDeclaration): SingletonReceiver | undefined {
    const group=this.methodReceivers.get(target);
    return this.indexComplete && this.objectScopeComplete && this.objectValidationComplete && group?.valid && this.singletonEligibility.get(group)==='closed' ? group.receiver : undefined;
  }

  private objectCall(call: ts.CallExpression, count: boolean): CallResolution {
    const expression = call.expression;
    if (!ts.isPropertyAccessExpression(expression)) return {kind:'unsupported'};
    const receiver = ts.isIdentifier(expression.expression) ? expression.expression
      : ts.isPropertyAccessExpression(expression.expression) && ts.isIdentifier(expression.expression.expression)
        ? expression.expression.expression : undefined;
    if (!receiver) return {kind:'unsupported'};
    const symbol = this.symbol(receiver);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer) return {kind:'unsupported'};
    const load = declaration.initializer;
    if (!ts.isCallExpression(load) || !ts.isIdentifier(load.expression) || load.expression.text !== 'require'
      || !this.objectGlobal(load.expression) || load.arguments.length !== 1
      || !ts.isStringLiteralLike(load.arguments[0])) return {kind:'unsupported'};
    const result = this.importedFile(call.getSourceFile(), load.arguments[0].text, count);
    if (result.kind !== 'file') return result;
    const group = this.objectExports.get(result.file);
    const target = this.objectCalls.get(call);
    const keysMatch = ts.isIdentifier(expression.expression)
      ? group?.methods.get('')?.get(expression.name.text) === target
      : ts.isPropertyAccessExpression(expression.expression)
        && group?.methods.get(expression.expression.name.text)?.get(expression.name.text) === target;
    const mode=group?.singletonProof ? this.singletonEligibility.get(group) : group?.valid ? 'closed' : 'rejected';
    return this.objectScopeComplete && this.objectValidationComplete && (!count || this.proofsReady)
      && !this.mutated.has(symbol!) && !this.beforeInitialization(call,declaration)
      && group && mode!=='rejected' && mode!==undefined && target && keysMatch && target.getSourceFile() === result.file
      ? {kind:mode==='conditional' ? 'declared' : 'resolved',target,...(group.receiver ? {receiver:group.receiver} : {})} : {kind:'export_unsupported'};
  }

  private beforeInitialization(call: ts.CallExpression, declaration: ts.Node): boolean {
    // Function-body calls may run after module initialization. Their runtime entry is not proven.
    return call.pos < declaration.pos && this.ownerOf(call) === this.ownerOf(declaration);
  }

  /** Receiver-independent local methods use ordinary scalar summaries only after
   * a closed constructor/instance reference audit. No class or heap state is modeled. */
  private collectLocalClassCalls(): void {
    if (!this.objectScopeComplete) return;
    for (const classNode of this.classes) {
      if (!this.tick()) return;
      const file = classNode.getSourceFile();
      if (!classNode.name || classNode.modifiers?.length || classNode.heritageClauses?.length
        || this.opaqueClassScopeFiles.has(file)) continue;
      const classSymbol = this.symbol(classNode.name);
      if (!classSymbol || classSymbol.declarations?.length !== 1 || classSymbol.declarations[0] !== classNode
        || this.mutated.has(classSymbol) || this.mutatedMembers.has(classSymbol)
        || this.localExportBindings.has(classSymbol)) continue;

      const methods = new Map<string, ts.FunctionLikeDeclaration>();
      let valid = true, constructors = 0;
      for (const member of classNode.members) {
        if (!this.tick()) return;
        if (ts.isConstructorDeclaration(member)) {
          constructors += 1;
          // Even apparently harmless field initialization may override a method
          // or expose a receiver. Only the default/empty constructor is covered.
          if (constructors > 1 || !member.body || member.body.statements.length
            || member.parameters.length || member.modifiers?.length) valid = false;
          continue;
        }
        const key = ts.isMethodDeclaration(member) ? nameOf(member.name) : undefined;
        if (!ts.isMethodDeclaration(member) || !member.body || !this.functionSet.has(member)
          || !key || ts.isComputedPropertyName(member.name) || methods.has(key)
          || ['constructor', 'prototype', '__proto__'].includes(key) || member.asteriskToken || member.questionToken
          || member.modifiers?.some(modifier => modifier.kind !== ts.SyntaxKind.AsyncKeyword)
          || this.receiverDependent.has(member)) { valid = false; continue; }
        for (const parameter of member.parameters) {
          if (!this.tick()) return;
          if (parameter.modifiers?.length || ts.isIdentifier(parameter.name) && parameter.name.text === 'this') valid = false;
        }
        methods.set(key, member);
      }
      if (!valid || !methods.size) continue;

      const instances = new Map<ts.Symbol, ts.VariableDeclaration>();
      for (const ref of this.references.get(classSymbol) ?? []) {
        if (!this.tick()) return;
        if (ref === classNode.name) continue;
        const creation = ref.parent;
        const declaration = ts.isNewExpression(creation) ? creation.parent : undefined;
        if (ref.getSourceFile() !== file || !ts.isNewExpression(creation) || creation.expression !== ref
          || creation.arguments?.length || classNode.end > creation.pos
          || !declaration || !ts.isVariableDeclaration(declaration) || declaration.initializer !== creation
          || this.objectConst(declaration.name) !== declaration) { valid = false; break; }
        const symbol = this.symbol(declaration.name);
        const statement = declaration.parent.parent;
        if (!symbol || this.mutatedMembers.has(symbol) || this.localExportBindings.has(symbol)
          || !ts.isVariableStatement(statement) || statement.modifiers?.length) { valid = false; break; }
        instances.set(symbol, declaration);
      }
      if (!valid || !instances.size) continue;

      const calls = new Map<ts.CallExpression, ts.FunctionLikeDeclaration>();
      for (const [symbol, declaration] of instances) {
        for (const ref of this.references.get(symbol) ?? []) {
          if (!this.tick()) return;
          if (ref === declaration.name) continue;
          const access = ref.parent;
          const call = ts.isPropertyAccessExpression(access) ? access.parent : undefined;
          const target = ts.isPropertyAccessExpression(access) ? methods.get(access.name.text) : undefined;
          if (ref.getSourceFile() !== file || !ts.isPropertyAccessExpression(access) || access.expression !== ref
            || access.questionDotToken || !call || !ts.isCallExpression(call) || call.expression !== access
            || call.questionDotToken || !target || this.beforeInitialization(call, declaration)) { valid = false; break; }
          calls.set(call, target);
        }
        if (!valid) break;
      }
      if (valid) for (const [call, target] of calls) {
        if (!this.tick()) return;
        this.localClassCalls.set(call, target);
      }
    }
  }

  resolveCall(call: ts.CallExpression, count = true, receiver?: SingletonReceiver): CallResolution {
    // The constructor's binding pass (count=false) precedes final proof validation.
    if (count && !this.proofsReady) return { kind: 'unsupported' };
    if (count && !this.tick()) return { kind: "unsupported" };
    if (ts.isPropertyAccessExpression(call.expression) && call.expression.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const owner = this.ownerOf(call);
      const group = this.methodReceivers.get(owner as ts.FunctionLikeDeclaration);
      if (!group) return {kind:'unsupported'};
      const target = group.methods.get('')?.get(call.expression.name.text);
      const mode=this.singletonEligibility.get(group);
      return receiver && group.receiver === receiver && mode!==undefined && mode!=='rejected' && this.objectValidationComplete && this.objectScopeComplete && target
        ? {kind:mode==='conditional' ? 'declared' : 'resolved',target,receiver} : {kind:'export_unsupported'};
    }
    if (!ts.isIdentifier(call.expression)) {
      const target = this.localClassCalls.get(call);
      return target ? {kind: 'resolved', target} : this.objectCall(call, count);
    }
    const symbol = this.symbol(call.expression);
    if (!symbol) return { kind: "external" };
    if (symbol.declarations?.length !== 1) return { kind: "unsupported" };
    const unproved = this.mutated.has(symbol);
    const declaration = symbol.declarations[0];
    if (ts.isImportSpecifier(declaration)) {
      const importDeclaration = declaration.parent.parent.parent;
      if (!ts.isImportDeclaration(importDeclaration) || !ts.isStringLiteral(importDeclaration.moduleSpecifier)
        || declaration.isTypeOnly || importDeclaration.importClause?.isTypeOnly) return { kind: "unsupported" };
      return this.imported(call.getSourceFile(), importDeclaration.moduleSpecifier.text,
        (declaration.propertyName ?? declaration.name).text, count, unproved);
    }
    if (ts.isBindingElement(declaration)) {
      const variable = variableOf(declaration);
      const initializer = variable?.initializer;

      if (variable && (variable.parent.flags & ts.NodeFlags.Const) !== 0 && initializer
        && ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression)
        && initializer.expression.text === "require" && this.cjsGlobal(initializer.expression)
        && initializer.arguments.length === 1 && ts.isStringLiteral(initializer.arguments[0])) {
        return this.imported(call.getSourceFile(), initializer.arguments[0].text,
          nameOf(declaration.propertyName) ?? (ts.isIdentifier(declaration.name) ? declaration.name.text : ""), count,
          unproved || !ts.isObjectBindingPattern(declaration.parent) || declaration.parent !== variable.name
            || declaration.dotDotDotToken !== undefined || declaration.initializer !== undefined
            || !ts.isIdentifier(declaration.name) || declaration.propertyName !== undefined && !ts.isIdentifier(declaration.propertyName)
            || this.beforeInitialization(call,variable));
      }
    }
    if (unproved) return {kind:"unsupported"};
    const target = this.functionOf(declaration);
    if (!target || target.getSourceFile() !== call.getSourceFile()) return { kind: "unsupported" };
    if (ts.isVariableDeclaration(declaration) && this.beforeInitialization(call, declaration)) return { kind: "unsupported" };
    return { kind: "resolved", target };
  }

  /** A syntactically local callable must not be reclassified by its SQL-shaped name. */
  localCallable(call: ts.CallExpression): boolean {
    if (!this.proofsReady) return false;
    if (this.localClassCalls.has(call)) return true;
    if (ts.isIdentifier(call.expression)) {
      const declarations = this.symbol(call.expression)?.declarations;
      return declarations?.some((declaration) => ts.isFunctionDeclaration(declaration)
        || ts.isVariableDeclaration(declaration) && !!this.functionOf(declaration)
        || ts.isImportSpecifier(declaration) || ts.isBindingElement(declaration)) ?? false;
    }
    if (ts.isPropertyAccessExpression(call.expression) && ts.isIdentifier(call.expression.expression)) {
      const receiver = this.symbol(call.expression.expression);
      if (!receiver || this.mutated.has(receiver) || this.mutatedMembers.has(receiver)) return false;
      const declaration = receiver.declarations?.length === 1 ? receiver.declarations[0] : undefined;
      if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer
        || !ts.isObjectLiteralExpression(declaration.initializer)) return false;
      const member = declaration.initializer.properties.find((property) =>
        !ts.isSpreadAssignment(property) && nameOf(property.name) === (call.expression as ts.PropertyAccessExpression).name.text);
      return !!member && (ts.isMethodDeclaration(member) && !!member.body
        || ts.isPropertyAssignment(member) && (ts.isArrowFunction(member.initializer) || ts.isFunctionExpression(member.initializer)));
    }
    return false;
  }
}
