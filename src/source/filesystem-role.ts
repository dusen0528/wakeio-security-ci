import * as ts from 'typescript';
import { posix } from 'node:path';
import type { StaticModules } from './modules.js';
import type { CollectedFile } from './types.js';

export interface FilesystemStreamRole { origin: ts.CallExpression; provider?: ts.FunctionLikeDeclaration; valid: boolean; identity: object }
export interface FilesystemWrapperRole { qualified: boolean; shell: 'enabled' | 'disabled' | 'unresolved'; interpreter: boolean }
const object = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
const unwrap = (expression: ts.Expression): ts.Expression => {
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isNonNullExpression(expression)
    || ts.isTypeAssertionExpression(expression)) expression = expression.expression;
  return expression;
};

/** Source declarations and narrow reviewed package contracts only. No installed modules or target execution. */
export class FilesystemRoleModel {
  private readonly manifests = new Map<string, Record<string, any> | null>();
  private readonly locks = new Map<string, Record<string, any> | null>();
  private readonly shrinkwraps = new Set<string>();
  private readonly accumulatorShapes = new WeakMap<ts.Identifier, { node: ts.Node; closed: boolean; valid: boolean } | null>();
  streamsRecognized = 0; filenameCallbacks = 0; accumulatorWrites = 0; unsupportedUses = 0;
  constructor(private readonly modules: StaticModules, metadata: readonly CollectedFile[], private readonly tick: () => boolean,
    private readonly gap: (reason: string, node?: ts.Node) => void, private readonly scopeComplete: boolean, private readonly aliasSteps: number) {
    let entries = 0;
    for (const file of metadata) {
      if (!tick()) break;
      const name = posix.basename(file.path), directory = posix.dirname(file.path);
      if (name === 'npm-shrinkwrap.json') { this.shrinkwraps.add(directory); continue; }
      if (!['package.json', 'package-lock.json'].includes(name)) continue;
      const table = name === 'package.json' ? this.manifests : this.locks;
      if (++entries > 256 || file.sensitive || file.bytes > 1024 * 1024 || table.has(directory)) { table.set(directory, null); continue; }
      try {
        const value: unknown = JSON.parse(file.text);
        table.set(directory, object(value) ? value : null);
      } catch { table.set(directory, null); }
    }
  }
  private metadata(file: ts.SourceFile): { manifest: Record<string, any>; directory: string } | undefined {
    let directory = posix.dirname(file.fileName);
    for (let depth = 0; depth <= 64; depth++) {
      if (!this.tick()) return undefined;
      const manifest = this.manifests.get(directory);
      if (manifest === null) return undefined;
      if (manifest) return { manifest, directory };
      if (directory === '.') break;
      directory = posix.dirname(directory);
    }
    return undefined;
  }
  private version(file: ts.SourceFile, name: string, expected: string): boolean {
    const metadata = this.metadata(file);
    if (!metadata) return false;
    const declaration = metadata.manifest.dependencies?.[name];
    if (typeof declaration !== 'string' || !/^(?:\^|~)?\d+\.\d+\.\d+$/.test(declaration)) return false;
    const minimum = declaration.replace(/^[\^~]/, '').split('.').map(Number), actual = expected.split('.').map(Number);
    const coherent = minimum.every(Number.isSafeInteger) && actual.every(Number.isSafeInteger)
      && (declaration.startsWith('^') ? actual[0] === minimum[0] && (actual[1] > minimum[1] || actual[1] === minimum[1] && actual[2] >= minimum[2])
        : declaration.startsWith('~') ? actual[0] === minimum[0] && actual[1] === minimum[1] && actual[2] >= minimum[2] : declaration === expected);
    if (!coherent) return false;
    let directory = metadata.directory;
    for (let depth = 0; depth <= 64; depth++) {
      if (!this.tick() || this.shrinkwraps.has(directory)) return false;
      const lock = this.locks.get(directory);
      if (lock === null) return false;
      if (lock) {
        // Nested workspace/hoisted resolution is not established by a favorable root lock row.
        if (directory !== metadata.directory) return false;
        const node = lock.packages?.[`node_modules/${name}`];
        const old = lock.dependencies?.[name];
        const versions = [node?.version, old?.version].filter(version => version !== undefined);
        return versions.length > 0 && versions.every(version => version === expected)
          && (!lock.packages?.['']?.dependencies?.[name] || lock.packages[''].dependencies[name] === declaration);
      }
      if (directory === '.') break;
      directory = posix.dirname(directory);
    }
    return false;
  }
  private imported(call: ts.CallExpression, name: string): { specifier: string; valid: boolean } | undefined {
    const callee = unwrap(call.expression);
    if (!ts.isIdentifier(callee)) return undefined;
    const symbol = this.modules.symbol(callee);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration || !ts.isImportSpecifier(declaration) || declaration.isTypeOnly
      || (declaration.propertyName ?? declaration.name).text !== name) return undefined;
    const load = declaration.parent.parent.parent;
    if (!ts.isImportDeclaration(load) || load.importClause?.isTypeOnly || !ts.isStringLiteralLike(load.moduleSpecifier)) return undefined;
    let valid = this.modules.indexComplete && !this.modules.mutated.has(symbol!) && !this.modules.mutatedMembers.has(symbol!);
    for (const reference of this.modules.references.get(symbol!) ?? []) {
      if (!this.tick()) { valid = false; break; }
      if (reference === declaration.name) continue;
      if (!ts.isCallExpression(reference.parent) || reference.parent.expression !== reference) valid = false;
    }
    return { specifier: load.moduleSpecifier.text, valid };
  }
  private importedClass(identifier: ts.Identifier): ts.ClassDeclaration | undefined {
    const symbol = this.modules.symbol(identifier);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration || this.modules.mutated.has(symbol!) || this.modules.mutatedMembers.has(symbol!)) return undefined;
    for (const reference of this.modules.references.get(symbol!) ?? []) {
      if (!this.tick()) return undefined;
      if (reference === ('name' in declaration ? declaration.name : undefined) || this.typeReference(reference)
        || ts.isNewExpression(reference.parent) && reference.parent.expression === reference || this.declaredRecordExport(reference)) continue;
      return undefined;
    }
    if (ts.isClassDeclaration(declaration)) return this.classUnchanged(declaration) ? declaration : undefined;
    if (!ts.isImportSpecifier(declaration) || declaration.isTypeOnly) return undefined;
    const load = declaration.parent.parent.parent;
    if (!ts.isImportDeclaration(load) || load.importClause?.isTypeOnly || !ts.isStringLiteralLike(load.moduleSpecifier)) return undefined;
    const module = this.modules.resolveSourceModule(identifier.getSourceFile(), load.moduleSpecifier.text);
    if (module.kind !== 'file') return undefined;
    const name = (declaration.propertyName ?? declaration.name).text;
    const classes = module.file.statements.filter((statement): statement is ts.ClassDeclaration => ts.isClassDeclaration(statement)
      && statement.name?.text === name && ts.getModifiers(statement)?.some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword) === true);
    return classes.length === 1 && this.classUnchanged(classes[0]) ? classes[0] : undefined;
  }
  private classUnchanged(declaration: ts.ClassDeclaration): boolean {
    const symbol = declaration.name ? this.modules.symbol(declaration.name) : undefined;
    if (!symbol || symbol.declarations?.length !== 1 || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      if (reference === declaration.name || ts.isNewExpression(reference.parent) && reference.parent.expression === reference) continue;
      if (this.typeReference(reference) || this.declaredRecordExport(reference)) continue;
      return false;
    }
    return true;
  }
  /** A declared public data slot is a conditional package boundary, not a runtime identity proof. */
  private declaredRecordExport(reference: ts.Identifier): boolean {
    const property = reference.parent;
    if (!ts.isShorthandPropertyAssignment(property) || property.name !== reference || !ts.isObjectLiteralExpression(property.parent)) return false;
    const record = property.parent, call = record.parent;
    if (!ts.isCallExpression(call) || call.arguments[1] !== record || call.arguments.length !== 2
      || !ts.isPropertyAccessExpression(call.expression) || call.expression.name.text !== 'assign'
      || !ts.isIdentifier(call.expression.expression) || call.expression.expression.text !== 'Object'
      || this.modules.symbol(call.expression.expression)?.declarations?.some(declaration => this.modules.files.has(declaration.getSourceFile().fileName))) return false;
    for (const entry of record.properties) {
      if (!this.tick() || !ts.isShorthandPropertyAssignment(entry) && !ts.isPropertyAssignment(entry)
        || ts.isComputedPropertyName(entry.name)) return false;
    }
    const binding = call.parent;
    if (!ts.isVariableDeclaration(binding) || !ts.isIdentifier(binding.name) || !ts.isVariableDeclarationList(binding.parent)
      || !(binding.parent.flags & ts.NodeFlags.Const) || !ts.isVariableStatement(binding.parent.parent)
      || !ts.getModifiers(binding.parent.parent)?.some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword)) return false;
    const symbol = this.modules.symbol(binding.name);
    for (const use of this.modules.references.get(symbol!) ?? []) {
      if (!this.tick()) return false;
      // Access to the exposed constructor slot (including computed/alias escapes)
      // is unsupported. Ordinary other public slots do not replace this class.
      if (use === binding.name) continue;
      if (ts.isPropertyAccessExpression(use.parent) && use.parent.expression === use && use.parent.name.text !== reference.text) continue;
      if (ts.isBinaryExpression(use.parent) && use.parent.right === use && ts.isPropertyAccessExpression(use.parent.left)
        && use.parent.left.name.text !== reference.text) continue;
      return false;
    }
    return true;
  }
  private typeReference(reference: ts.Identifier): boolean {
    let node: ts.Node = reference;
    for (let depth = 0; node.parent && depth < 16; depth++, node = node.parent) {
      if (!this.tick()) return false;
      if (ts.isTypeNode(node.parent)) return true;
      if (ts.isExpression(node.parent) || ts.isStatement(node.parent)) return false;
    }
    return false;
  }
  private localProvider(call: ts.CallExpression): ts.FunctionLikeDeclaration | undefined {
    const result = this.modules.resolveCall(call);
    if (result.kind !== 'resolved' || !result.target.body || !ts.isBlock(result.target.body)) return undefined;
    const statements = result.target.body.statements;
    const returned = statements.length === 1 && ts.isReturnStatement(statements[0]) ? statements[0].expression : undefined;
    if (!returned || !ts.isCallExpression(returned) || returned.arguments.length || !ts.isPropertyAccessExpression(returned.expression)
      || returned.expression.name.text !== 'stream' || !ts.isNewExpression(returned.expression.expression)) return undefined;
    const constructor = returned.expression.expression.expression;
    if (!ts.isIdentifier(constructor)) return undefined;
    const declared = this.importedClass(constructor);
    if (!declared) return undefined;
    const methods = declared.members.filter((member): member is ts.MethodDeclaration => ts.isMethodDeclaration(member)
      && !!member.body && ts.isIdentifier(member.name) && member.name.text === 'stream');
    if (methods.length !== 1) return undefined;
    const methodBody = methods[0].body!;
    const expression = methodBody.statements.length === 1 && ts.isReturnStatement(methodBody.statements[0]) ? methodBody.statements[0].expression : undefined;
    if (!expression || !ts.isCallExpression(expression) || !ts.isPropertyAccessExpression(expression.expression)
      || expression.expression.name.text !== 'stream' || !ts.isNewExpression(expression.expression.expression)
      || !ts.isIdentifier(expression.expression.expression.expression)) return undefined;
    const streamClass = this.importedClass(expression.expression.expression.expression);
    if (!streamClass || !this.filesystemProviderGraph(streamClass)) return undefined;
    return result.target;
  }
  private exactPackageSymbol(identifier: ts.Identifier, name: string, specifier: string): boolean {
    const symbol = this.modules.symbol(identifier), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration || !ts.isImportSpecifier(declaration) || declaration.isTypeOnly
      || (declaration.propertyName ?? declaration.name).text !== name || this.modules.mutated.has(symbol!) || this.modules.mutatedMembers.has(symbol!)) return false;
    const load = declaration.parent.parent.parent;
    return ts.isImportDeclaration(load) && !load.importClause?.isTypeOnly && ts.isStringLiteralLike(load.moduleSpecifier) && load.moduleSpecifier.text === specifier;
  }
  private filesystemProviderGraph(streamClass: ts.ClassDeclaration): boolean {
    const baseName = streamClass.heritageClauses?.find(clause => clause.token === ts.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
    if (!baseName || !ts.isIdentifier(baseName)) return false;
    const base = this.importedClass(baseName); if (!base) return false;
    const inClass = (node: ts.Node, declaration: ts.ClassDeclaration) => node.getSourceFile() === declaration.getSourceFile() && node.pos >= declaration.pos && node.end <= declaration.end;
    const methods = new Map<string, ts.MethodDeclaration>();
    for (const declaration of [base, streamClass]) for (const member of declaration.members) {
      if (!this.tick()) return false;
      if (ts.isMethodDeclaration(member) && member.body && ts.isIdentifier(member.name)) methods.set(member.name.text, member);
    }
    const stream = methods.get('stream'); if (!stream) return false;
    const returned = stream.body!.statements.filter(ts.isReturnStatement);
    const result = returned.length === 1 ? returned[0].expression : undefined;
    if (!result || !ts.isPropertyAccessExpression(result) || result.expression.kind !== ts.SyntaxKind.ThisKeyword) return false;
    const resultField = result.name.text;
    let allocations = 0;
    for (const write of this.modules.instanceFieldWrites) {
      if (!this.tick()) return false;
      if (!inClass(write, base) && !inClass(write, streamClass)) continue;
      const target = ts.isPropertyDeclaration(write) ? write.name : ts.isBinaryExpression(write) ? write.left
        : ts.isForInStatement(write) || ts.isForOfStatement(write) ? write.initializer
        : ts.isDeleteExpression(write) ? write.expression : ts.isPrefixUnaryExpression(write) || ts.isPostfixUnaryExpression(write) ? write.operand : undefined;
      const touches = ts.isPropertyDeclaration(write) ? ts.isComputedPropertyName(write.name)
        ? !ts.isStringLiteralLike(unwrap(write.name.expression)) || (unwrap(write.name.expression) as ts.StringLiteralLike).text === resultField
        : (ts.isIdentifier(write.name) || ts.isStringLiteralLike(write.name)) && write.name.text === resultField
        : target && this.touchesInstanceField(target, resultField);
      if (!touches) continue;
      const initializer = ts.isPropertyDeclaration(write) ? write.initializer : ts.isBinaryExpression(write)
        && write.operatorToken.kind === ts.SyntaxKind.EqualsToken ? write.right : undefined;
      const node = initializer && unwrap(initializer);
      const direct = ts.isPropertyDeclaration(write)
        ? !ts.isComputedPropertyName(write.name) || ts.isStringLiteralLike(unwrap(write.name.expression))
        : target && ts.isPropertyAccessExpression(target) && target.expression.kind === ts.SyntaxKind.ThisKeyword && target.name.text === resultField;
      if (!direct || !node || !ts.isNewExpression(node) || !ts.isIdentifier(node.expression)
        || !this.exactPackageSymbol(node.expression, 'Minipass', 'minipass') || ++allocations !== 1) return false;
      if (ts.isBinaryExpression(write) && !ts.isConstructorDeclaration(this.modules.ownerOf(write))) return false;
    }
    if (allocations !== 1) return false;
    const calls = new Map<ts.MethodDeclaration, ts.CallExpression[]>();
    for (const node of this.modules.calls) {
      if (!this.tick()) return false;
      if (!inClass(node, base) && !inClass(node, streamClass)) continue;
      for (const method of methods.values()) {
        if (!this.tick()) return false;
        if (node.getSourceFile() !== method.getSourceFile() || node.pos < method.pos || node.end > method.end) continue;
        let nested: ts.Node = node;
        let eligible = true;
        while (nested.parent && nested.parent !== method) {
          if (!this.tick()) return false;
          if (ts.isFunctionDeclaration(nested) || ts.isFunctionExpression(nested)) { eligible = false; break; }
          if (ts.isArrowFunction(nested) && (!ts.isCallExpression(nested.parent) || !nested.parent.arguments.includes(nested))) { eligible = false; break; }
          nested = nested.parent;
        }
        if (eligible) { const list = calls.get(method) ?? []; list.push(node); calls.set(method, list); }
      }
    }
    const reachable = new Set<ts.MethodDeclaration>(), pending = [stream];
    while (pending.length) {
      if (!this.tick()) return false;
      const method = pending.pop()!; if (reachable.has(method)) continue; reachable.add(method);
      for (const call of calls.get(method) ?? []) if (ts.isPropertyAccessExpression(call.expression)
        && call.expression.expression.kind === ts.SyntaxKind.ThisKeyword) {
        const target = methods.get(call.expression.name.text); if (target) pending.push(target);
      }
    }
    const emitters = new Set<ts.MethodDeclaration>();
    let read = false;
    for (const method of reachable) for (const call of calls.get(method) ?? []) {
      if (!this.tick()) return false;
      if (!ts.isPropertyAccessExpression(call.expression)) continue;
      const receiver = call.expression.expression;
      if (call.expression.name.text === 'readdirCB' && call.arguments.some(ts.isArrowFunction)
        && this.pathReceiver(receiver, method, new Set())) read = true;
      if (call.expression.name.text === 'write' && call.arguments.length === 1 && ts.isIdentifier(call.arguments[0])
        && ts.isPropertyAccessExpression(receiver) && receiver.expression.kind === ts.SyntaxKind.ThisKeyword && receiver.name.text === resultField
        && method.parameters.length === 1 && ts.isIdentifier(method.parameters[0].name)
        && this.modules.symbol(method.parameters[0].name) === this.modules.symbol(call.arguments[0])) emitters.add(method);
    }
    let pathToEmitter = false;
    for (const method of reachable) for (const call of calls.get(method) ?? []) {
      if (!this.tick()) return false;
      if (ts.isPropertyAccessExpression(call.expression) && call.expression.expression.kind === ts.SyntaxKind.ThisKeyword
        && emitters.has(methods.get(call.expression.name.text)!) && call.arguments.length === 1
        && this.pathDerived(call.arguments[0], method, new Set())) pathToEmitter = true;
    }
    // No uncalled noise or literal output certificate: require a reachable read,
    // a path-derived actual into the emitter formal, and the returned stream field.
    return read && pathToEmitter && this.version(streamClass.getSourceFile(), 'minipass', '7.1.2')
      && this.version(streamClass.getSourceFile(), 'path-scurry', '1.11.1');
  }
  /** Normalize only an already-indexed write target; never rescan the target program. */
  private touchesInstanceField(target: ts.Node, field: string, depth = 0): boolean {
    if (!this.tick()) return true;
    if (depth > this.aliasSteps) { this.gap('alias_limit', target); return true; }
    const nested = (node: ts.Node) => this.touchesInstanceField(node, field, depth + 1);
    if (ts.isPropertyAccessExpression(target)) return target.expression.kind === ts.SyntaxKind.ThisKeyword
      ? target.name.text === field : nested(target.expression);
    if (ts.isElementAccessExpression(target)) return target.expression.kind === ts.SyntaxKind.ThisKeyword
      ? !ts.isStringLiteralLike(target.argumentExpression) || target.argumentExpression.text === field : nested(target.expression);
    if (ts.isParenthesizedExpression(target) || ts.isAsExpression(target) || ts.isNonNullExpression(target)
      || ts.isTypeAssertionExpression(target) || ts.isSpreadElement(target) || ts.isSpreadAssignment(target)) return nested(target.expression);
    if (ts.isBinaryExpression(target)) return nested(target.left); // A default's right-hand value is not a write target.
    if (ts.isArrayLiteralExpression(target) || ts.isArrayBindingPattern(target)) return target.elements.some(nested);
    if (ts.isObjectLiteralExpression(target)) return target.properties.some(property => ts.isPropertyAssignment(property)
      ? nested(property.initializer) : ts.isShorthandPropertyAssignment(property) ? nested(property.name)
        : ts.isSpreadAssignment(property) ? nested(property.expression) : true);
    if (ts.isObjectBindingPattern(target)) return target.elements.some(element => nested(element.name));
    if (ts.isBindingElement(target)) return nested(target.name);
    if (ts.isVariableDeclarationList(target)) return target.declarations.some(declaration => nested(declaration.name));
    return false;
  }
  private pathFormalUncontradicted(parameter: ts.ParameterDeclaration, method: ts.MethodDeclaration): boolean {
    if (!ts.isIdentifier(method.name)) return false;
    const index = method.parameters.indexOf(parameter);
    let incoming = false;
    for (const call of this.modules.calls) {
      if (!this.tick()) return false;
      if (!ts.isPropertyAccessExpression(call.expression) || call.expression.expression.kind !== ts.SyntaxKind.ThisKeyword
        || call.expression.name.text !== method.name.text || !call.arguments[index]) continue;
      incoming = true;
      if (this.constantPathContradiction(call.arguments[index], new Set())) return false;
    }
    return incoming;
  }
  /** Type annotations never override collected constant/object actuals. */
  private constantPathContradiction(expression: ts.Expression, seen: Set<ts.Symbol>, depth = 0): boolean {
    if (!this.tick()) return true;
    if (depth > this.aliasSteps) { this.gap('alias_limit', expression); return true; }
    expression = unwrap(expression);
    if (ts.isObjectLiteralExpression(expression) || ts.isArrayLiteralExpression(expression) || ts.isLiteralExpression(expression)
      || [ts.SyntaxKind.NullKeyword, ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword].includes(expression.kind)) return true;
    if (ts.isIdentifier(expression)) {
      const symbol = this.modules.symbol(expression), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (!symbol || seen.has(symbol) || !declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer) return false;
      return this.constantPathContradiction(declaration.initializer, new Set([...seen, symbol]), depth + 1);
    }
    if (ts.isConditionalExpression(expression)) return this.constantPathContradiction(expression.whenTrue, seen, depth + 1)
      || this.constantPathContradiction(expression.whenFalse, seen, depth + 1);
    return false;
  }
  private pathType(type: ts.TypeNode | undefined): boolean {
    return !!type && ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName)
      && this.exactPackageSymbol(type.typeName, 'Path', 'path-scurry');
  }
  /** Narrow declared Path/PathScurry receiver domain, not a method-name source heuristic. */
  private pathReceiver(expression: ts.Expression, method: ts.MethodDeclaration, seen: Set<ts.Symbol>, depth = 0): boolean {
    if (!this.tick()) return false;
    if (depth > this.aliasSteps) { this.gap('alias_limit', expression); return false; }
    expression = unwrap(expression);
    if (ts.isPropertyAccessExpression(expression) && expression.name.text === 'cwd') {
      const allocation = unwrap(expression.expression);
      return ts.isNewExpression(allocation) && ts.isIdentifier(allocation.expression)
        && ['PathScurry', 'PathScurryPosix', 'PathScurryDarwin', 'PathScurryWin32'].some(name => this.exactPackageSymbol(allocation.expression as ts.Identifier, name, 'path-scurry'));
    }
    if (!ts.isIdentifier(expression)) return false;
    const symbol = this.modules.symbol(expression), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!symbol || seen.has(symbol) || !declaration) return false;
    const next = new Set([...seen, symbol]);
    if (ts.isParameter(declaration) && ts.isMethodDeclaration(declaration.parent) && this.pathType(declaration.type))
      return this.pathFormalUncontradicted(declaration, declaration.parent);
    if (!ts.isVariableDeclaration(declaration)) return false;
    if (declaration.initializer) return this.pathReceiver(declaration.initializer, method, next, depth + 1);
    if (!ts.isVariableDeclarationList(declaration.parent) || !ts.isForOfStatement(declaration.parent.parent)) return false;
    const iterable = unwrap(declaration.parent.parent.expression);
    if (!ts.isCallExpression(iterable) || !ts.isPropertyAccessExpression(iterable.expression) || !ts.isIdentifier(iterable.expression.expression)) return false;
    const receiver = this.modules.symbol(iterable.expression.expression), parameter = receiver?.declarations?.length === 1 ? receiver.declarations[0] : undefined;
    if (!parameter || !ts.isParameter(parameter) || !parameter.type || !ts.isTypeReferenceNode(parameter.type)
      || !ts.isIdentifier(parameter.type.typeName)) return false;
    const declared = this.importedClass(parameter.type.typeName); if (!declared) return false;
    for (const member of declared.members) {
      if (!this.tick()) return false;
      if (ts.isMethodDeclaration(member) && member.body && ts.isIdentifier(member.name) && member.name.text === iterable.expression.name.text
        && member.type && ts.isArrayTypeNode(member.type) && this.pathType(member.type.elementType)) {
        // This is a declared API domain assumption. Visible constant returns revoke it.
        for (const statement of member.body.statements) if (ts.isReturnStatement(statement) && statement.expression
          && this.constantPathContradiction(statement.expression, new Set())) return false;
        return true;
      }
    }
    return false;
  }
  private pathDerived(expression: ts.Expression, method: ts.MethodDeclaration, seen: Set<ts.Symbol>, depth = 0): boolean {
    if (!this.tick()) return false;
    if (depth > this.aliasSteps) { this.gap('alias_limit', expression); return false; }
    expression = unwrap(expression);
    if (ts.isCallExpression(expression) && ts.isPropertyAccessExpression(expression.expression)
      && ['fullpath', 'fullpathPosix', 'relative', 'relativePosix'].includes(expression.expression.name.text)) {
      const receiver = expression.expression.expression;
      if (!ts.isIdentifier(receiver)) return false;
      const symbol = this.modules.symbol(receiver), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (!declaration) return false;
      if (ts.isParameter(declaration) && declaration.parent === method && declaration.type && ts.isTypeReferenceNode(declaration.type)
        && ts.isIdentifier(declaration.type.typeName) && this.exactPackageSymbol(declaration.type.typeName, 'Path', 'path-scurry')) return this.pathFormalUncontradicted(declaration, method);
      if (ts.isVariableDeclaration(declaration) && ts.isVariableDeclarationList(declaration.parent) && ts.isForOfStatement(declaration.parent.parent)) {
        const iterable = declaration.parent.parent.expression;
        if (!ts.isIdentifier(iterable)) return false;
        const entrySymbol = this.modules.symbol(iterable), entry = entrySymbol?.declarations?.length === 1 ? entrySymbol.declarations[0] : undefined;
        if (!entry || !ts.isParameter(entry) || !ts.isArrowFunction(entry.parent) || entry.parent.parameters[1] !== entry
          || !ts.isCallExpression(entry.parent.parent) || !ts.isPropertyAccessExpression(entry.parent.parent.expression)
          || entry.parent.parent.expression.name.text !== 'readdirCB') return false;
        return this.pathReceiver(entry.parent.parent.expression.expression, method, new Set());
      }
      return false;
    }
    if (ts.isIdentifier(expression)) {
      const symbol = this.modules.symbol(expression);
      if (!symbol || seen.has(symbol) || this.modules.mutated.has(symbol)) return false;
      const declaration = symbol.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer || !(declaration.parent.flags & ts.NodeFlags.Const)) return false;
      return this.pathDerived(declaration.initializer, method, new Set([...seen, symbol]), depth + 1);
    }
    if (ts.isConditionalExpression(expression)) return this.pathDerived(expression.whenTrue, method, seen, depth + 1)
      || this.pathDerived(expression.whenFalse, method, seen, depth + 1);
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) return this.pathDerived(expression.left, method, seen, depth + 1)
      || this.pathDerived(expression.right, method, seen, depth + 1);
    return false;
  }
  stream(call: ts.CallExpression): FilesystemStreamRole | undefined {
    const imported = this.imported(call, 'globStream');
    if (!imported) return undefined;
    const metadata = this.metadata(call.getSourceFile());
    const external = imported.specifier === 'glob';
    const provider = external ? undefined : this.localProvider(call);
    const known = external ? this.version(call.getSourceFile(), 'glob', '10.4.5')
      : !!provider && metadata?.manifest.name === 'glob' && metadata.manifest.version === '10.4.5';
    if (!known || !imported.valid) { this.unsupportedUses++; this.gap('module_export_unsupported', call); return undefined; }
    const options = call.arguments[1] ? unwrap(call.arguments[1]) : undefined;
    let filename = call.arguments.length >= 1 && call.arguments.length <= 2 && !call.arguments.some(ts.isSpreadElement);
    if (options && !ts.isObjectLiteralExpression(options)) filename = false;
    if (options && ts.isObjectLiteralExpression(options)) for (const property of options.properties) {
      if (!this.tick()) { filename = false; break; }
      if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) { filename = false; break; }
      if (ts.isComputedPropertyName(property.name)) { filename = false; break; }
      // Custom traversal providers do not establish the reviewed filesystem API domain.
      if ((ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) && ['fs', 'scurry'].includes(property.name.text)) filename = false;
      if ((ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) && property.name.text === 'withFileTypes'
        && (!ts.isPropertyAssignment(property) || unwrap(property.initializer).kind !== ts.SyntaxKind.FalseKeyword)) filename = false;
    }
    if (!filename) { this.unsupportedUses++; this.gap('module_export_unsupported', call); return undefined; }
    this.streamsRecognized++;
    return { origin: call, provider, valid: imported.valid, identity: {} };
  }
  accumulator(name: ts.Identifier): { node: ts.Node; closed: boolean; valid: boolean } | undefined {
    const cached = this.accumulatorShapes.get(name); if (cached !== undefined) return cached ?? undefined;
    const symbol = this.modules.symbol(name);
    const declarations = symbol?.declarations;
    let writes = false, valid = this.modules.indexComplete && !!symbol && declarations?.length === 1
      && !this.modules.mutated.has(symbol!) && !this.modules.mutatedMembers.has(symbol!);
    for (const reference of this.modules.references.get(symbol!) ?? []) {
      if (!this.tick()) { valid = false; break; }
      const member = reference.parent;
      if (ts.isPropertyAccessExpression(member) && member.expression === reference && ['push', 'unshift'].includes(member.name.text)
        && ts.isCallExpression(member.parent) && member.parent.expression === member) writes = true;
      else if (ts.isPropertyAccessExpression(member) && member.expression === reference
        && ts.isCallExpression(member.parent) && member.parent.expression === member) valid = false;
      if (ts.isCallExpression(reference.parent) && reference.parent.arguments.some(argument => argument === reference)) {
        const wrapper = this.imported(reference.parent, 'foregroundChild');
        if (!wrapper || wrapper.specifier !== 'foreground-child') valid = false;
      }
      if (ts.isVariableDeclaration(reference.parent) && reference.parent.initializer === reference) valid = false;
    }
    if (!writes) { this.accumulatorShapes.set(name, null); return undefined; }
    const declaration = declarations?.length === 1 ? declarations[0] : undefined;
    const initializer = declaration && ts.isVariableDeclaration(declaration) && declaration.initializer ? unwrap(declaration.initializer) : undefined;
    let closed = this.scopeComplete && !!initializer && ts.isArrayLiteralExpression(initializer) && !initializer.elements.some(ts.isSpreadElement);
    // Reuse the charged intrinsic-boundary index. Reflective Array/namespace use
    // revokes this narrow negative; no regex or second AST walk claims safety.
    for (const node of this.modules.sqlBoundaryNodes) {
      if (!this.tick()) { closed = false; break; }
      if (['Array', 'Object', 'Reflect', 'globalThis'].includes(node.text)) closed = false;
    }
    const result = writes ? { node: name, closed: closed && valid, valid } : null;
    this.accumulatorShapes.set(name, result); return result ?? undefined;
  }
  wrapper(call: ts.CallExpression): FilesystemWrapperRole | undefined {
    const imported = this.imported(call, 'foregroundChild');
    if (!imported || imported.specifier !== 'foreground-child') return undefined;
    const qualified = imported.valid && this.version(call.getSourceFile(), 'foreground-child', '3.2.1')
      && call.arguments.length >= 2 && call.arguments.length <= 3 && !call.arguments.some(ts.isSpreadElement);
    if (!qualified) { this.unsupportedUses++; this.gap('module_export_unsupported', call); }
    let shell: FilesystemWrapperRole['shell'] = 'disabled';
    const options = call.arguments[2] ? unwrap(call.arguments[2]) : undefined;
    if (options && !ts.isObjectLiteralExpression(options)) shell = 'unresolved';
    if (options && ts.isObjectLiteralExpression(options)) for (const property of options.properties) {
      if (!this.tick()) { shell = 'unresolved'; break; }
      if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property) || ts.isComputedPropertyName(property.name)) { shell = 'unresolved'; continue; }
      const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : undefined;
      if (name !== 'shell') continue;
      const value = ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
      shell = value?.kind === ts.SyntaxKind.TrueKeyword ? 'enabled' : value?.kind === ts.SyntaxKind.FalseKeyword ? 'disabled' : 'unresolved';
    }
    const program = call.arguments[0] ? unwrap(call.arguments[0]) : undefined;
    const interpreter = !program || !ts.isStringLiteralLike(program) || /(?:^|[\\/])(?:sh|bash|zsh|ksh|fish|cmd|powershell|node|python\d*)$/i.test(program.text);
    return { qualified, shell: qualified ? shell : 'unresolved', interpreter };
  }
}
