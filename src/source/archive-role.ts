import * as ts from 'typescript';
import { posix } from 'node:path';
import type { StaticModules } from './modules.js';
import type { CollectedFile } from './types.js';

export interface ArchiveRole {
  readonly stage: 'promise' | 'directory' | 'files' | 'entry';
  readonly origin: ts.CallExpression;
  readonly state: { valid: boolean };
}
type Binding = { module: 'unzipper' | 'fs' | 'path'; members: string[]; closed: boolean; state: { valid: boolean } };
interface SharedLoadAudit {
  closed: boolean;
  writes: Array<Array<string | undefined>>;
  aliases: Array<{ name: ts.BindingName; members: Array<string | undefined> }>;
}
const object = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
function unwrap(value: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value) || ts.isTypeAssertionExpression(value) || ts.isNonNullExpression(value)) value = value.expression;
  return value;
}
function member(value: ts.Expression): { base: ts.Expression; name: string } | undefined {
  value = unwrap(value);
  if (ts.isPropertyAccessExpression(value)) return { base: value.expression, name: value.name.text };
  if (ts.isElementAccessExpression(value) && value.argumentExpression && ts.isStringLiteralLike(value.argumentExpression)) return { base: value.expression, name: value.argumentExpression.text };
  return undefined;
}

/** Collected declarations plus reviewed API semantics, never installed/runtime authority. */
export class ArchiveRoleModel {
  private readonly manifests = new Map<string, Record<string, any> | null>();
  private readonly locks = new Map<string, Record<string, any> | null>();
  private readonly shrinkwraps = new Set<string>();
  private readonly bindings = new Map<ts.Symbol, Binding | null>();
  private readonly callBindings = new WeakMap<ts.CallExpression, Binding | null>();
  private readonly families = new Map<Binding['module'], boolean>();
  private readonly familyContradictions = new Set<Binding['module']>();
  private sharedLoads?: Map<Binding['module'], SharedLoadAudit>;
  private intrinsicClosed?: boolean;
  directoriesRecognized = 0; entryPaths = 0; writeCandidates = 0; lexicalExclusions = 0; unsupportedUses = 0;
  constructor(private readonly modules: StaticModules, metadata: readonly CollectedFile[], private readonly tick: () => boolean,
    private readonly gap: (reason: string, node?: ts.Node) => void, private readonly scopeComplete: boolean, private readonly aliasSteps: number) {
    let count = 0;
    for (const file of metadata) {
      if (!tick()) break;
      const name = posix.basename(file.path), directory = posix.dirname(file.path);
      if (name === 'npm-shrinkwrap.json') { this.shrinkwraps.add(directory); continue; }
      if (name !== 'package.json' && name !== 'package-lock.json') continue;
      const table = name === 'package.json' ? this.manifests : this.locks;
      if (++count > 256 || file.sensitive || file.bytes > 1024 * 1024 || table.has(directory)) { table.set(directory, null); continue; }
      try { const value: unknown = JSON.parse(file.text); table.set(directory, object(value) ? value : null); }
      catch { table.set(directory, null); }
    }
  }
  unsupported(node: ts.Node): void { this.unsupportedUses++; this.gap('module_export_unsupported', node); }
  /** The index marks loop initialization as a write; a const element is not a replacement. */
  bindingMutated(name: ts.Identifier): boolean {
    const symbol = this.modules.symbol(name);
    if (!symbol) return true;
    if (this.modules.mutatedMembers.has(symbol)) return true;
    if (!this.modules.mutated.has(symbol)) return false;
    const declaration = name.parent;
    if (!ts.isVariableDeclaration(declaration) || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const) || !ts.isForOfStatement(declaration.parent.parent)) return true;
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) return true;
      if (reference === name) continue;
      let target: ts.Node = reference;
      while (ts.isArrayLiteralExpression(target.parent) || ts.isObjectLiteralExpression(target.parent)
        || ts.isPropertyAssignment(target.parent) && target.parent.initializer === target
        || ts.isShorthandPropertyAssignment(target.parent) || ts.isSpreadElement(target.parent) || ts.isSpreadAssignment(target.parent)) {
        if (!this.tick()) return true; target = target.parent;
      }
      const parent = target.parent;
      if (ts.isBinaryExpression(parent) && parent.left === target && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
        && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment || (ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent))
          && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(parent.operator)
        || (ts.isForOfStatement(parent) || ts.isForInStatement(parent)) && parent.initializer === target) return true;
    }
    return false;
  }
  private metadata(file: ts.SourceFile): boolean {
    let directory = posix.dirname(file.fileName);
    for (let level = 0; level <= 64; level++) {
      if (!this.tick()) return false;
      if (this.manifests.has(directory)) {
        const manifest = this.manifests.get(directory);
        if (manifest?.name === 'unzipper' && manifest.exports !== undefined) return false;
        const declaration = manifest?.dependencies?.unzipper;
        if (declaration !== '0.12.3' && declaration !== '^0.12.3') return false;
        if (manifest?.workspaces !== undefined || this.shrinkwraps.has(directory)) return false;
        const lock = this.locks.get(directory);
        if (lock === null) return false;
        if (lock) {
          if (![1, 2, 3].includes(lock.lockfileVersion)) return false;
          if (lock.packages !== undefined && !object(lock.packages) || lock.dependencies !== undefined && !object(lock.dependencies)) return false;
          const modern = lock.packages?.['node_modules/unzipper'], old = lock.dependencies?.unzipper;
          if (modern !== undefined && !object(modern) || old !== undefined && !object(old)) return false;
          const versions = [modern?.version, old?.version].filter(value => value !== undefined);
          if (!versions.length || versions.some(value => value !== versions[0])
            || versions.some(value => value !== '0.12.3' && value !== '0.12.5')
            || declaration === '0.12.3' && versions[0] !== '0.12.3'
            || modern?.link || modern?.resolved !== undefined && (typeof modern.resolved !== 'string' || modern.resolved.startsWith('file:'))
            || lock.packages && lock.packages['']?.dependencies?.unzipper !== declaration) return false;
        }
        // A nested manifest without a local lock must not borrow a hoisted/workspace resolution.
        let ancestor = posix.dirname(directory), reachedRoot = directory === '.' || directory === '/';
        for (let depth = 0; ancestor !== directory && depth <= 64; depth++) {
          if (!this.tick()) return false;
          if (this.locks.has(ancestor) || this.shrinkwraps.has(ancestor)) return false;
          if (ancestor === '.' || ancestor === '/') { reachedRoot = true; break; }
          directory = ancestor; ancestor = posix.dirname(ancestor);
        }
        if (!reachedRoot) this.gap('alias_limit', file);
        return reachedRoot;
      }
      if (directory === '.') return false;
      directory = posix.dirname(directory);
    }
    return false;
  }
  private identifier(identifier: ts.Identifier, depth: number): Binding | undefined {
    if (!this.tick() || depth > this.aliasSteps) return undefined;
    const symbol = this.modules.symbol(identifier);
    if (!symbol || symbol.declarations?.length !== 1) return undefined;
    if (this.bindings.has(symbol)) { const cached = this.bindings.get(symbol); return cached?.state.valid ? cached : undefined; }
    this.bindings.set(symbol, null);
    const declaration = symbol.declarations[0]; let binding: Binding | undefined;
    let candidate: ts.Node | undefined;
    if (ts.isImportClause(declaration)) candidate = declaration.parent;
    else if (ts.isNamespaceImport(declaration)) candidate = declaration.parent.parent;
    else if (ts.isImportSpecifier(declaration) && !declaration.isTypeOnly) candidate = declaration.parent.parent.parent;
    const load = candidate && ts.isImportDeclaration(candidate) ? candidate : undefined;
    if (load && !load.importClause?.isTypeOnly && ts.isStringLiteralLike(load.moduleSpecifier)) {
      const name = load.moduleSpecifier.text.replace(/^node:/, '');
      if (['unzipper', 'fs', 'path'].includes(name) && (name !== 'unzipper' || load.moduleSpecifier.text === 'unzipper')) {
        binding = { module: name as Binding['module'], members: ts.isImportSpecifier(declaration) ? [(declaration.propertyName ?? declaration.name).text] : [], closed: true, state: { valid: true } };
      }
    } else if (ts.isVariableDeclaration(declaration) && ts.isIdentifier(declaration.name) && declaration.initializer
      && (declaration.parent.flags & ts.NodeFlags.Const)) binding = this.binding(declaration.initializer, depth + 1);
    if (!binding) return undefined;
    const refuse = (): undefined => { binding!.state.valid = false; this.bindings.set(symbol, null); return undefined; };
    if (this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return refuse();
    this.bindings.set(symbol, binding); // Permit bounded aliases to refer back to this observed declaration.
    // Inspect complete static member chains, including nested writes and escapes.
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) return refuse();
      if (reference === ('name' in declaration ? declaration.name : undefined)) continue;
      if (ts.isTypeReferenceNode(reference.parent) || ts.isTypeQueryNode(reference.parent)) continue;
      let end: ts.Node = reference;
      while ((ts.isPropertyAccessExpression(end.parent) || ts.isElementAccessExpression(end.parent)) && end.parent.expression === end) {
        if (!this.tick() || ts.isElementAccessExpression(end.parent) && (!end.parent.argumentExpression || !ts.isStringLiteralLike(end.parent.argumentExpression))) return refuse();
        end = end.parent;
      }
      const read = this.bindingMembers(reference, end);
      if (binding.module === 'path' && [...binding.members, ...read].join('.') === 'sep'
        && !this.writeOrEscape(end)) continue;
      if (ts.isCallExpression(end.parent) && end.parent.expression === end) continue;
      if (ts.isVariableDeclaration(end.parent) && end.parent.initializer === end && ts.isIdentifier(end.parent.name)
        && (end.parent.parent.flags & ts.NodeFlags.Const)) {
        const alias = this.identifier(end.parent.name, depth + 1);
        if (alias) continue;
      }
      return refuse();
    }
    binding = { ...binding, closed: binding.closed && this.modules.indexComplete && this.scopeComplete };
    this.bindings.set(symbol, binding); return binding;
  }
  private bindingMembers(start: ts.Node, end: ts.Node): string[] {
    const members: string[] = [];
    while (end !== start && (ts.isPropertyAccessExpression(end) || ts.isElementAccessExpression(end))) {
      members.unshift(ts.isPropertyAccessExpression(end) ? end.name.text : (end.argumentExpression as ts.StringLiteral).text);
      end = end.expression;
    }
    return members;
  }
  private writeOrEscape(node: ts.Node): boolean {
    const parent = node.parent;
    return ts.isBinaryExpression(parent) && parent.left === node && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment || ts.isDeleteExpression(parent)
      || ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)
      || ts.isCallExpression(parent) && parent.expression !== node || ts.isNewExpression(parent);
  }
  private binding(expression: ts.Expression, depth = 0): Binding | undefined {
    if (!this.tick() || depth > this.aliasSteps) return undefined;
    expression = unwrap(expression);
    if (ts.isIdentifier(expression)) return this.identifier(expression, depth + 1);
    const access = member(expression);
    if (access) { const base = this.binding(access.base, depth + 1); return base ? { ...base, members: [...base.members, access.name] } : undefined; }
    if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression) && expression.expression.text === 'require'
      && this.modules.cjsGlobal(expression.expression) && expression.arguments.length === 1 && ts.isStringLiteralLike(expression.arguments[0])) {
      const name = expression.arguments[0].text.replace(/^node:/, '');
      if (['unzipper', 'fs', 'path'].includes(name) && (name !== 'unzipper' || expression.arguments[0].text === 'unzipper'))
        return { module: name as Binding['module'], members: [], closed: this.modules.indexComplete && this.scopeComplete, state: { valid: true } };
    }
    return undefined;
  }
  private classify(call: ts.CallExpression): Binding | undefined {
    const cached = this.callBindings.get(call);
    if (cached !== undefined) return cached?.state.valid ? cached : undefined;
    const callee = unwrap(call.expression), access = member(callee);
    // Negative syntax filter only; every accepted role still requires symbol-bound authority.
    if (access && !['buffer', 'resolve', 'relative', 'isAbsolute', 'createWriteStream'].includes(access.name)) {
      this.callBindings.set(call, null); return undefined;
    }
    const result = this.binding(callee);
    if (result && !this.family(result.module)) {
      if (this.familyContradictions.has(result.module)) { result.state.valid = false; this.callBindings.set(call, null); return undefined; }
      result.closed = false; // Unrelated opaque imports leave only a conditional selected-declaration witness.
    }
    this.callBindings.set(call, result ?? null); return result?.state.valid ? result : undefined;
  }
  private family(name: Binding['module']): boolean {
    const cached = this.families.get(name); if (cached !== undefined) return cached;
    this.families.set(name, false);
    let closed = true;
    const relevant = name === 'fs' ? [['createWriteStream']] : name === 'unzipper' ? [['Open', 'buffer']]
      : [['resolve'], ['relative'], ['isAbsolute'], ['sep']];
    const visited = new Set<string>();
    const inspect = (identifier: ts.Identifier, prefix: Array<string | undefined> = [], depth = 0): void => {
      if (!this.tick() || depth > this.aliasSteps) { closed = false; return; }
      const symbol = this.modules.symbol(identifier);
      const identity = `${identifier.getSourceFile().fileName}:${symbol?.declarations?.[0]?.pos}:${prefix.join('.')}`;
      if (visited.has(identity)) return; visited.add(identity);
      if (symbol && (this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol))) closed = false;
      for (const reference of symbol ? this.modules.references.get(symbol) ?? [] : []) {
        if (!this.tick()) { closed = false; break; }
        let end: ts.Node = reference; const members: Array<string | undefined> = [...prefix];
        while ((ts.isPropertyAccessExpression(end.parent) || ts.isElementAccessExpression(end.parent)
          || ts.isParenthesizedExpression(end.parent) || ts.isAsExpression(end.parent)
          || ts.isTypeAssertionExpression(end.parent) || ts.isNonNullExpression(end.parent)) && end.parent.expression === end) {
          if (!this.tick()) { closed = false; break; }
          if (ts.isPropertyAccessExpression(end.parent)) members.push(end.parent.name.text);
          else if (ts.isElementAccessExpression(end.parent)) members.push(end.parent.argumentExpression && ts.isStringLiteralLike(end.parent.argumentExpression)
            ? end.parent.argumentExpression.text : undefined);
          end = end.parent;
        }
        const alias = end.parent;
        if (ts.isVariableDeclaration(alias) && alias.initializer === end && (alias.parent.flags & ts.NodeFlags.Const)) inspectPattern(alias.name, members, depth + 1);
        const memberTarget = end !== reference;
        if (this.written(end)) {
          closed = false;
          // A known unrelated member write cannot replace this API. Unknown keys/ancestors can.
          if (memberTarget && members.length && relevant.some(path => members.slice(0, Math.min(members.length, path.length))
            .every((value, index) => value === undefined || value === path[index]))) this.familyContradictions.add(name);
        }
      }
      if (!this.identifier(identifier, 0)) closed = false;
    };
    const inspectPattern = (pattern: ts.BindingName, prefix: Array<string | undefined>, depth: number): void => {
      if (!this.tick() || depth > this.aliasSteps) { closed = false; return; }
      if (ts.isIdentifier(pattern)) { inspect(pattern, prefix, depth); return; }
      closed = false; // Destructuring is negative evidence only, not a new positive API binding.
      if (!ts.isObjectBindingPattern(pattern)) return;
      for (const element of pattern.elements) {
        if (!this.tick()) return;
        const key = element.propertyName ?? (ts.isIdentifier(element.name) ? element.name : undefined);
        const name = key && (ts.isIdentifier(key) || ts.isStringLiteralLike(key)) ? key.text : undefined;
        inspectPattern(element.name, element.dotDotDotToken ? prefix : [...prefix, name], depth + 1);
      }
    };
    for (const load of this.modules.importDeclarations) {
      if (!this.tick()) return false;
      if (!ts.isStringLiteralLike(load.moduleSpecifier) || load.moduleSpecifier.text.replace(/^node:/, '') !== name || load.importClause?.isTypeOnly) continue;
      const clause = load.importClause;
      if (!clause) { closed = false; continue; }
      if (clause.name) inspect(clause.name);
      if (clause.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) inspect(clause.namedBindings.name);
        else for (const item of clause.namedBindings.elements) {
          if (!this.tick()) return false;
          if (!item.isTypeOnly) inspect(item.name, [(item.propertyName ?? item.name).text]);
        }
      }
    }
    const loads = this.auditSharedLoads().get(name)!;
    closed &&= loads.closed;
    for (const write of loads.writes) {
      if (!this.tick()) return false;
      if (write.length && relevant.some(path => write.slice(0, Math.min(write.length, path.length))
        .every((value, index) => value === undefined || value === path[index]))) this.familyContradictions.add(name);
    }
    for (const alias of loads.aliases) { if (!this.tick()) return false; inspectPattern(alias.name, alias.members, 0); }
    closed &&= !this.familyContradictions.has(name);
    this.families.set(name, closed); return closed;
  }
  private written(node: ts.Node): boolean {
    while (ts.isArrayLiteralExpression(node.parent) || ts.isObjectLiteralExpression(node.parent)
      || (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent)
        || ts.isTypeAssertionExpression(node.parent) || ts.isNonNullExpression(node.parent)) && node.parent.expression === node
      || ts.isPropertyAssignment(node.parent) && node.parent.initializer === node
      || ts.isShorthandPropertyAssignment(node.parent) || ts.isSpreadElement(node.parent) || ts.isSpreadAssignment(node.parent)) {
      if (!this.tick()) return true; node = node.parent;
    }
    const parent = node.parent;
    return ts.isBinaryExpression(parent) && parent.left === node && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment || ts.isDeleteExpression(parent)
      || (ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent))
        && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(parent.operator)
      || (ts.isForOfStatement(parent) || ts.isForInStatement(parent)) && parent.initializer === node;
  }
  /** One charged pass over already indexed require references, shared by all three families. */
  private auditSharedLoads(): Map<Binding['module'], SharedLoadAudit> {
    if (this.sharedLoads) return this.sharedLoads;
    const audits = new Map<Binding['module'], SharedLoadAudit>(['fs', 'path', 'unzipper'].map(name =>
      [name as Binding['module'], { closed: true, writes: [], aliases: [] }]));
    this.sharedLoads = audits;
    const unknown = () => { for (const value of audits.values()) value.closed = false; };
    for (const reference of this.modules.requireReferences) {
      if (!this.tick()) { unknown(); break; }
      if (!this.modules.cjsGlobal(reference)) continue;
      const load = reference.parent;
      if (!ts.isCallExpression(load) || load.expression !== reference || load.arguments.length !== 1 || !ts.isStringLiteralLike(load.arguments[0])) { unknown(); continue; }
      const specifier = load.arguments[0].text, name = specifier.replace(/^node:/, '') as Binding['module'];
      if (!audits.has(name) || name === 'unzipper' && specifier !== 'unzipper') continue;
      const audit = audits.get(name)!; let end: ts.Node = load;
      const members: Array<string | undefined> = [];
      while ((ts.isPropertyAccessExpression(end.parent) || ts.isElementAccessExpression(end.parent)
        || ts.isParenthesizedExpression(end.parent) || ts.isAsExpression(end.parent)
        || ts.isTypeAssertionExpression(end.parent) || ts.isNonNullExpression(end.parent)) && end.parent.expression === end) {
        if (!this.tick()) { unknown(); break; }
        if (ts.isPropertyAccessExpression(end.parent)) members.push(end.parent.name.text);
        else if (ts.isElementAccessExpression(end.parent)) members.push(end.parent.argumentExpression && ts.isStringLiteralLike(end.parent.argumentExpression)
          ? end.parent.argumentExpression.text : undefined);
        end = end.parent;
      }
      if (this.written(end)) { audit.closed = false; audit.writes.push(members); continue; }
      const parent = end.parent;
      if (ts.isVariableDeclaration(parent) && parent.initializer === end) {
        if (!(parent.parent.flags & ts.NodeFlags.Const)) audit.closed = false;
        audit.aliases.push({ name: parent.name, members });
      } else if (!(ts.isCallExpression(parent) && parent.expression === end) || members.some(value => value === undefined)) audit.closed = false;
    }
    return audits;
  }
  open(call: ts.CallExpression): ArchiveRole | undefined {
    const binding = this.classify(call);
    if (binding?.module !== 'unzipper' || binding.members.join('.') !== 'Open.buffer') {
      if (this.rejectedOpen(call)) this.unsupported(call);
      return undefined;
    }
    if (call.arguments.length !== 1 || ts.isSpreadElement(call.arguments[0]) || !this.metadata(call.getSourceFile())) { this.unsupported(call); return undefined; }
    this.directoriesRecognized++; this.gap('module_export_unsupported', call);
    return { stage: 'promise', origin: call, state: { valid: true } };
  }
  /** Rejected declaration hypotheses produce a gap, never an archive source. */
  private rejectedOpen(call: ts.CallExpression): boolean {
    const method = member(call.expression);
    if (method?.name !== 'buffer') {
      const callee = unwrap(call.expression);
      if (!ts.isIdentifier(callee)) return false;
      const symbol = this.modules.symbol(callee), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
      if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer || !(declaration.parent.flags & ts.NodeFlags.Const)) return false;
      const initializer = unwrap(declaration.initializer);
      if (!ts.isIdentifier(initializer) && member(initializer)?.name !== 'buffer') return false;
      return this.declaredUnzipper(callee)?.join('.') === 'Open.buffer';
    }
    if (this.declaredUnzipper(call.expression)?.join('.') === 'Open.buffer') return true;
    const open = member(method.base);
    const base = unwrap(open?.name === 'Open' ? open.base : method.base);
    if (!ts.isIdentifier(base)) return false;
    for (const load of this.modules.importDeclarations) {
      if (!this.tick()) return false;
      if (load.getSourceFile() !== call.getSourceFile() || !ts.isStringLiteralLike(load.moduleSpecifier)
        || load.moduleSpecifier.text !== 'unzipper' || !load.importClause || load.importClause.isTypeOnly) continue;
      const clause = load.importClause;
      if (open?.name === 'Open' && clause.name?.text === base.text) return true;
      if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings) && open?.name === 'Open' && clause.namedBindings.name.text === base.text) return true;
      if (clause.namedBindings && ts.isNamedImports(clause.namedBindings) && clause.namedBindings.elements.some(item => !item.isTypeOnly
        && (item.propertyName ?? item.name).text === 'Open' && item.name.text === base.text)) return true;
    }
    return false;
  }
  private declaredUnzipper(expression: ts.Expression, depth = 0): string[] | undefined {
    if (!this.tick() || depth > this.aliasSteps) return undefined;
    expression = unwrap(expression);
    const access = member(expression);
    if (access) { const base = this.declaredUnzipper(access.base, depth + 1); return base ? [...base, access.name] : undefined; }
    if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression) && expression.expression.text === 'require'
      && expression.arguments.length === 1 && ts.isStringLiteralLike(expression.arguments[0]) && expression.arguments[0].text === 'unzipper') return [];
    if (!ts.isIdentifier(expression)) return undefined;
    const symbol = this.modules.symbol(expression), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration) return undefined;
    let candidate: ts.Node | undefined;
    if (ts.isImportClause(declaration)) candidate = declaration.parent;
    else if (ts.isNamespaceImport(declaration)) candidate = declaration.parent.parent;
    else if (ts.isImportSpecifier(declaration) && !declaration.isTypeOnly) candidate = declaration.parent.parent.parent;
    if (candidate && ts.isImportDeclaration(candidate) && !candidate.importClause?.isTypeOnly
      && ts.isStringLiteralLike(candidate.moduleSpecifier) && candidate.moduleSpecifier.text === 'unzipper')
      return ts.isImportSpecifier(declaration) ? [(declaration.propertyName ?? declaration.name).text] : [];
    if (ts.isVariableDeclaration(declaration) && declaration.initializer && (declaration.parent.flags & ts.NodeFlags.Const))
      return this.declaredUnzipper(declaration.initializer, depth + 1);
    return undefined;
  }
  pathCall(call: ts.CallExpression): 'path' | 'predicate' | undefined {
    const binding = this.classify(call);
    if (binding?.module !== 'path' || binding.members.length !== 1) return undefined;
    return ['resolve', 'relative'].includes(binding.members[0]) ? 'path' : binding.members[0] === 'isAbsolute' ? 'predicate' : undefined;
  }
  writer(call: ts.CallExpression): { options: boolean; closed: boolean } | undefined {
    const binding = this.classify(call);
    if (binding?.module !== 'fs' || binding.members.join('.') !== 'createWriteStream') return undefined;
    let options = call.arguments.length === 1 && !ts.isSpreadElement(call.arguments[0]);
    if (call.arguments.length === 2) {
      const value = unwrap(call.arguments[1]);
      const keys = new Set<string>();
      options = ts.isObjectLiteralExpression(value) && value.properties.length <= 16 && value.properties.every(property => {
        if (!this.tick() || !ts.isPropertyAssignment(property) || !(ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))) return false;
        const name = property.name.text, initial = unwrap(property.initializer);
        if (keys.has(name)) return false; keys.add(name);
        if (name === 'flags') return ts.isStringLiteralLike(initial) && ['w', 'wx', 'w+', 'wx+', 'a', 'ax', 'a+', 'ax+'].includes(initial.text);
        if (name === 'encoding') return ts.isStringLiteralLike(initial);
        if (['mode', 'start', 'highWaterMark'].includes(name)) return ts.isNumericLiteral(initial);
        return ['autoClose', 'emitClose', 'flush'].includes(name) && (initial.kind === ts.SyntaxKind.TrueKeyword || initial.kind === ts.SyntaxKind.FalseKeyword);
      });
    }
    return { options, closed: binding.closed };
  }
  private constant(expression: ts.Expression, depth = 0): ts.Expression | undefined {
    if (!this.tick() || depth > this.aliasSteps) return undefined;
    expression = unwrap(expression);
    if (!ts.isIdentifier(expression)) return expression;
    const symbol = this.modules.symbol(expression), declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!declaration || !ts.isVariableDeclaration(declaration) || !ts.isIdentifier(declaration.name) || !declaration.initializer
      || !(declaration.parent.flags & ts.NodeFlags.Const) || this.modules.mutated.has(symbol!) || this.modules.mutatedMembers.has(symbol!)) return undefined;
    return this.constant(declaration.initializer, depth + 1);
  }
  private same(left: ts.Expression, right: ts.Expression): boolean {
    left = unwrap(left); right = unwrap(right);
    return ts.isIdentifier(left) && ts.isIdentifier(right) && this.modules.symbol(left) !== undefined
      && this.modules.symbol(left) === this.modules.symbol(right) && this.constant(left) !== undefined;
  }
  private native(call: ts.CallExpression, method: string): boolean {
    const binding = this.classify(call);
    return binding?.module === 'path' && binding.closed && binding.members.length === 1 && binding.members[0] === method;
  }
  /** Lexical containment only, not symlink, TOCTOU, runtime or extraction safety. */
  contained(call: ts.CallExpression): boolean {
    if (!this.modules.indexComplete || !this.scopeComplete || !call.arguments[0]) return false;
    if (this.intrinsicClosed === undefined) {
      this.intrinsicClosed = true;
      if (this.modules.archiveIntrinsicBoundaryNodes.length > 0) { this.tick(); this.intrinsicClosed = false; }
      for (const node of this.modules.sqlBoundaryNodes) {
        if (!this.tick() || ['String', 'Object', 'Reflect', 'globalThis'].includes(node.text)) { this.intrinsicClosed = false; break; }
      }
    }
    if (!this.intrinsicClosed) return false;
    const destination = unwrap(call.arguments[0]);
    if (!ts.isIdentifier(destination)) return false;
    const resolved = this.constant(destination);
    if (!resolved || !ts.isCallExpression(resolved) || !this.native(resolved, 'resolve') || resolved.arguments.length !== 2) return false;
    const base = resolved.arguments[0], fixedBase = this.constant(base);
    if (!ts.isIdentifier(unwrap(base)) || !fixedBase || !ts.isCallExpression(fixedBase) || !this.native(fixedBase, 'resolve')
      || !fixedBase.arguments.length || !fixedBase.arguments.every(value => ts.isStringLiteralLike(unwrap(value)))) return false;
    let statement: ts.Node = call;
    while (statement.parent && !ts.isBlock(statement.parent) && !ts.isSourceFile(statement.parent)) {
      if (!this.tick() || ts.isFunctionLike(statement.parent)) return false;
      statement = statement.parent;
    }
    if (!statement.parent || !ts.isBlock(statement.parent)) return false;
    // A direct synchronous consumer only. Await/opaque enclosing calls may change interpretation before this write.
    const direct = ts.isExpressionStatement(statement) && unwrap(statement.expression) === call
      || ts.isVariableStatement(statement) && (statement.declarationList.flags & ts.NodeFlags.Const) !== 0
        && statement.declarationList.declarations.length === 1 && statement.declarationList.declarations[0].initializer === call;
    if (!direct) return false;
    for (const prior of statement.parent.statements) {
      if (!this.tick() || prior === statement) break;
      if (!ts.isIfStatement(prior) || prior.elseStatement) continue;
      const body = ts.isBlock(prior.thenStatement) ? prior.thenStatement.statements : [prior.thenStatement];
      if (body.length !== 1 || !ts.isReturnStatement(body[0]) && !ts.isThrowStatement(body[0])) continue;
      const pieces: ts.Expression[] = [];
      const flatten = (value: ts.Expression): boolean => {
        if (!this.tick() || pieces.length > 3) return false;
        value = unwrap(value);
        if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.BarBarToken) return flatten(value.left) && flatten(value.right);
        pieces.push(value); return true;
      };
      if (!flatten(prior.expression) || pieces.length !== 3) continue;
      let relative: ts.Expression | undefined;
      const equality = pieces.find(value => ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
        && (ts.isStringLiteralLike(unwrap(value.right)) && (unwrap(value.right) as ts.StringLiteral).text === '..'
          || ts.isStringLiteralLike(unwrap(value.left)) && (unwrap(value.left) as ts.StringLiteral).text === '..')) as ts.BinaryExpression | undefined;
      if (!equality) continue;
      relative = ts.isStringLiteralLike(unwrap(equality.right)) ? equality.left : equality.right;
      const calculation = this.constant(relative);
      if (!calculation || !ts.isCallExpression(calculation) || !this.native(calculation, 'relative') || calculation.arguments.length !== 2
        || !this.same(calculation.arguments[0], base) || !this.same(calculation.arguments[1], destination)) continue;
      const prefix = pieces.some(value => {
        if (!ts.isCallExpression(value) || value.arguments.length !== 1) return false;
        const access = member(value.expression), argument = unwrap(value.arguments[0]);
        if (!access || access.name !== 'startsWith' || !this.same(access.base, relative!)) return false;
        if (!ts.isBinaryExpression(argument) || argument.operatorToken.kind !== ts.SyntaxKind.PlusToken
          || !ts.isStringLiteralLike(unwrap(argument.left)) || (unwrap(argument.left) as ts.StringLiteral).text !== '..') return false;
        const separator = this.binding(argument.right);
        return separator?.module === 'path' && separator.closed && separator.members.join('.') === 'sep';
      });
      const absolute = pieces.some(value => ts.isCallExpression(value) && this.native(value, 'isAbsolute')
        && value.arguments.length === 1 && this.same(value.arguments[0], relative!));
      if (prefix && absolute) {
        // Only the adjacent rejection is supported: no intervening await, consumer, or nested control can retain a stale exclusion.
        const statements = statement.parent.statements;
        if (statements.indexOf(prior) + 1 === statements.indexOf(statement as ts.Statement)) return true;
      }
    }
    return false;
  }
}
