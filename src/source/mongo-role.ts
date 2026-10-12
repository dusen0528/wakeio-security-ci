import * as ts from 'typescript';
import { posix } from 'node:path';
import type { CollectedFile } from './types.js';
import type { StaticModules } from './modules.js';

export type MongoInvalidReason = 'opaque' | 'write' | 'ambiguous' | 'unsupported';
export interface MongoDbRole { valid: boolean; invalidReason?: MongoInvalidReason; readonly conditionalOrigin?: boolean; readonly origin: ts.ParameterDeclaration; }
export interface MongoCollectionRole { valid: boolean; invalidReason?: MongoInvalidReason; readonly db: MongoDbRole; readonly origin: ts.CallExpression; }
const SELECTORS = new Set(['find', 'findOne', 'update', 'updateOne', 'updateMany', 'remove', 'deleteOne', 'deleteMany', 'count']);
function record(value: unknown): value is Record<string, unknown> { return !!value && typeof value === 'object' && !Array.isArray(value); }
const legacyRange = (value: unknown): boolean => typeof value === 'string' && /^(?:\^|~)?2\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(value);
const legacyVersion = (value: unknown): boolean => typeof value === 'string' && /^2\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(value);
function satisfies(range: string, version: string): boolean {
  const minimum = range.replace(/^[~^]/, '').split('.').map(Number), actual = version.split('.').map(Number);
  if (![...minimum, ...actual].every(Number.isSafeInteger)) return false;
  if (range.startsWith('^')) return actual[1] > minimum[1] || actual[1] === minimum[1] && actual[2] >= minimum[2];
  if (range.startsWith('~')) return actual[1] === minimum[1] && actual[2] >= minimum[2];
  return range === version;
}

/** Source-only driver contract. No installed package, connection or DB is read. */
export class MongoRoleModel {
  private readonly manifests = new Map<string, unknown>();
  private readonly locks = new Map<string, unknown>();
  private readonly shrinkwraps = new Set<string>();
  private readonly entries = new WeakMap<ts.FunctionLikeDeclaration, { legacy: boolean; qualified: boolean } | null>();
  private readonly clients = new Map<ts.Symbol, boolean>();
  private sharedPristine?: boolean;
  private originPristine?: boolean;
  constructor(private readonly modules: StaticModules, files: readonly CollectedFile[], private readonly tick: () => boolean,
    private readonly gap: (reason: string, node?: ts.Node) => void, private readonly scopeComplete: boolean, indexAvailable: boolean) {
    if (!indexAvailable) return;
    let parsed = 0;
    for (const file of files) {
      if (!tick()) break;
      const basename = posix.basename(file.path);
      if (basename === 'npm-shrinkwrap.json') { this.shrinkwraps.add(posix.dirname(file.path)); continue; }
      if (!['package.json', 'package-lock.json'].includes(basename)) continue;
      const table = basename === 'package.json' ? this.manifests : this.locks;
      const directory = posix.dirname(file.path);
      if (table.has(directory)) { table.set(directory, null); continue; }
      if (file.sensitive || Buffer.byteLength(file.text) > 1024 * 1024 || parsed >= 256) { table.set(directory, null); continue; }
      parsed++;
      try { table.set(directory, JSON.parse(file.text)); } catch { table.set(directory, null); }
    }
  }

  private legacy(file: ts.SourceFile): boolean {
    let directory = posix.dirname(file.fileName);
    for (let depth = 0; depth <= 64; depth++) {
      if (!this.tick()) return false;
      if (this.manifests.has(directory)) {
        const manifest = this.manifests.get(directory);
        if (!record(manifest) || !record(manifest.dependencies) || !legacyRange(manifest.dependencies.mongodb)) return false;
        const range = manifest.dependencies.mongodb as string;
        let lockDirectory = directory;
        for (let level = 0; level <= 64 && !this.locks.has(lockDirectory) && !this.shrinkwraps.has(lockDirectory); level++) {
          if (!this.tick()) return false;
          if (lockDirectory === '.' || lockDirectory === '/') break;
          lockDirectory = posix.dirname(lockDirectory);
        }
        if (this.shrinkwraps.has(lockDirectory)) return false; // Its precedence is not implemented; never prefer a favorable package-lock.
        if (!this.locks.has(lockDirectory)) return true;
        const lock = this.locks.get(lockDirectory);
        if (!record(lock)) return false;
        if (record(lock.packages) && record(lock.packages['']) && record(lock.packages[''].dependencies)
          && lock.packages[''].dependencies.mongodb !== undefined && lock.packages[''].dependencies.mongodb !== range) return false;
        const versions: unknown[] = [];
        if (record(lock.packages) && record(lock.packages['node_modules/mongodb'])) versions.push(lock.packages['node_modules/mongodb'].version);
        if (record(lock.dependencies) && record(lock.dependencies.mongodb)) versions.push(lock.dependencies.mongodb.version);
        return versions.length > 0 && versions.every(legacyVersion) && versions.every(version => version === versions[0])
          && versions.every(version => satisfies(range, version as string));
      }
      if (directory === '.' || directory === '/' || directory === '') return false;
      directory = posix.dirname(directory);
    }
    this.gap('alias_limit'); return false;
  }

  private client(identifier: ts.Identifier): boolean | undefined {
    const symbol = this.modules.symbol(identifier);
    if (!symbol || symbol.declarations?.length !== 1) return undefined;
    const cached = this.clients.get(symbol); if (cached !== undefined) return cached;
    const declaration = symbol.declarations[0]; let recognized = false;
    if (ts.isVariableDeclaration(declaration) && declaration.initializer && (declaration.parent.flags & ts.NodeFlags.Const)) {
      const initializer = declaration.initializer;
      if (ts.isPropertyAccessExpression(initializer) && initializer.name.text === 'MongoClient' && ts.isCallExpression(initializer.expression)) {
        const load = initializer.expression;
        recognized = ts.isIdentifier(load.expression) && load.expression.text === 'require' && this.modules.cjsGlobal(load.expression)
          && load.arguments.length === 1 && ts.isStringLiteralLike(load.arguments[0]) && load.arguments[0].text === 'mongodb';
      }
    } else if (ts.isImportSpecifier(declaration) && !declaration.isTypeOnly && (declaration.propertyName ?? declaration.name).text === 'MongoClient') {
      const load = declaration.parent.parent.parent;
      recognized = ts.isImportDeclaration(load) && !load.importClause?.isTypeOnly && ts.isStringLiteralLike(load.moduleSpecifier) && load.moduleSpecifier.text === 'mongodb';
    }
    if (!recognized) return undefined;
    let valid = this.sharedLoadsClosed() && !this.modules.mutated.has(symbol) && !this.modules.mutatedMembers.has(symbol);
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      if (ts.isVariableDeclaration(reference.parent) && reference.parent.name === reference || ts.isImportSpecifier(reference.parent)) continue;
      const member = reference.parent;
      if (ts.isPropertyAccessExpression(member) && member.expression === reference && member.name.text === 'connect'
        && ts.isCallExpression(member.parent) && member.parent.expression === member) continue;
      valid = false;
    }
    this.clients.set(symbol, valid); return valid;
  }

  private bindingClosed(identifier: ts.Identifier, namespace: boolean): boolean {
    const symbol = this.modules.symbol(identifier);
    if (!symbol || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.tick()) return false;
      if (ts.isVariableDeclaration(reference.parent) && reference.parent.name === reference || ts.isBindingElement(reference.parent) && reference.parent.name === reference || ts.isImportSpecifier(reference.parent) || ts.isNamespaceImport(reference.parent)) continue;
      let member = reference.parent;
      if (namespace) {
        if (!ts.isPropertyAccessExpression(member) || member.expression !== reference || member.name.text !== 'MongoClient') return false;
        member = member.parent;
      }
      if (!ts.isPropertyAccessExpression(member) || member.name.text !== 'connect' || !ts.isCallExpression(member.parent) || member.parent.expression !== member) return false;
    }
    return true;
  }

  private sharedLoadsClosed(): boolean {
    if (this.sharedPristine !== undefined) return this.sharedPristine;
    this.sharedPristine = false;
    for (const load of this.modules.importDeclarations) {
      if (!this.tick()) return false;
      if (!ts.isStringLiteralLike(load.moduleSpecifier) || load.moduleSpecifier.text !== 'mongodb' || load.importClause?.isTypeOnly) continue;
      const clause = load.importClause;
      if (!clause || clause.name || !clause.namedBindings) return false;
      if (ts.isNamespaceImport(clause.namedBindings)) {
        if (!this.bindingClosed(clause.namedBindings.name, true)) return false;
      } else for (const item of clause.namedBindings.elements) {
        if (!this.tick()) return false;
        if (item.isTypeOnly) continue;
        if ((item.propertyName ?? item.name).text !== 'MongoClient' || !this.bindingClosed(item.name, false)) return false;
      }
    }
    for (const load of this.modules.exportDeclarations) {
      if (!this.tick()) return false;
      if (!load.isTypeOnly && load.moduleSpecifier && ts.isStringLiteralLike(load.moduleSpecifier) && load.moduleSpecifier.text === 'mongodb') return false;
    }
    for (const reference of this.modules.requireReferences) {
      if (!this.tick()) return false;
      if (!this.modules.cjsGlobal(reference)) continue;
      const load = reference.parent;
      if (!ts.isCallExpression(load) || load.expression !== reference || load.arguments.length !== 1 || !ts.isStringLiteralLike(load.arguments[0])) return false;
      if (load.arguments[0].text !== 'mongodb') continue;
      let value: ts.Node = load; let namespace = true;
      if (ts.isPropertyAccessExpression(load.parent) && load.parent.expression === load) {
        if (load.parent.name.text !== 'MongoClient') return false;
        value = load.parent; namespace = false;
      }
      const declaration = value.parent;
      if (!ts.isVariableDeclaration(declaration) || declaration.initializer !== value || !(declaration.parent.flags & ts.NodeFlags.Const)
        || !ts.isIdentifier(declaration.name) || !this.bindingClosed(declaration.name, namespace)) return false;
    }
    for (const call of this.modules.calls) {
      if (!this.tick()) return false;
      if (call.expression.kind === ts.SyntaxKind.ImportKeyword && (call.arguments.length !== 1 || !ts.isStringLiteralLike(call.arguments[0]) || call.arguments[0].text === 'mongodb')) return false;
    }
    this.sharedPristine = true; return true;
  }

  /** Scan every known native consumer even when an earlier unknown loader vetoed strict proof. */
  private nativeOriginUnchanged(): boolean {
    if (this.originPristine !== undefined) return this.originPristine;
    this.originPristine = false;
    let unchanged = true;
    if (['mongodb', 'module', 'node:module'].some(name => this.modules.hasUnsupportedModuleLoad(name))) unchanged = false;
    for (const load of this.modules.importDeclarations) {
      if (!this.tick()) return false;
      if (ts.isStringLiteralLike(load.moduleSpecifier) && ['module', 'node:module'].includes(load.moduleSpecifier.text)) unchanged = false;
      if (!ts.isStringLiteralLike(load.moduleSpecifier) || load.moduleSpecifier.text !== 'mongodb' || load.importClause?.isTypeOnly) continue;
      const clause = load.importClause;
      if (!clause || clause.name || !clause.namedBindings) { unchanged = false; continue; }
      if (ts.isNamespaceImport(clause.namedBindings)) unchanged &&= this.bindingClosed(clause.namedBindings.name, true);
      else for (const item of clause.namedBindings.elements) {
        if (!this.tick()) return false;
        if (!item.isTypeOnly && ((item.propertyName ?? item.name).text !== 'MongoClient' || !this.bindingClosed(item.name, false))) unchanged = false;
      }
    }
    for (const ref of this.modules.requireReferences) {
      if (!this.tick()) return false;
      const load = ref.parent;
      if (this.modules.cjsGlobal(ref)) {
        if (ts.isCallExpression(load) && load.expression === ref && load.arguments.some(argument => ts.isStringLiteralLike(argument) && ['module', 'node:module'].includes(argument.text))) unchanged = false;
        else if (!(ts.isCallExpression(load) && load.expression === ref) && !(ts.isTypeOfExpression(load))
          && !(ts.isPropertyAccessExpression(load) && load.name.text === 'resolve' && ts.isCallExpression(load.parent) && load.parent.expression === load)) unchanged = false;
      }
      if (!this.modules.cjsGlobal(ref) || !ts.isCallExpression(load) || load.expression !== ref || load.arguments.length !== 1
        || !ts.isStringLiteralLike(load.arguments[0]) || load.arguments[0].text !== 'mongodb') continue;
      let selected: ts.Node = load; let namespace = true;
      if (ts.isPropertyAccessExpression(load.parent) && load.parent.expression === load) {
        if (load.parent.name.text !== 'MongoClient') { unchanged = false; continue; }
        selected = load.parent; namespace = false;
      }
      const declaration = selected.parent;
      if (!ts.isVariableDeclaration(declaration) || declaration.initializer !== selected || !(declaration.parent.flags & ts.NodeFlags.Const)) { unchanged = false; continue; }
      if (ts.isIdentifier(declaration.name)) {
        if (!this.bindingClosed(declaration.name, namespace)) unchanged = false;
      } else if (namespace && ts.isObjectBindingPattern(declaration.name)) {
        for (const item of declaration.name.elements) {
          if (!this.tick()) return false;
          if (item.dotDotDotToken || item.initializer || !ts.isIdentifier(item.name)
            || (item.propertyName && !ts.isIdentifier(item.propertyName))
            || (item.propertyName ?? item.name).getText() !== 'MongoClient' || !this.bindingClosed(item.name, false)) unchanged = false;
        }
      } else unchanged = false;
    }
    this.originPristine = unchanged; return unchanged;
  }

  entry(fn: ts.FunctionLikeDeclaration): MongoDbRole | undefined {
    let entry = this.entries.get(fn);
    if (entry === undefined) {
      entry = null;
      const call = fn.parent;
      if (this.modules.indexComplete && ts.isCallExpression(call) && [2, 3].includes(call.arguments.length)
        && call.arguments.at(-1) === fn && ts.isPropertyAccessExpression(call.expression) && call.expression.name.text === 'connect'
        && ts.isIdentifier(call.expression.expression) && fn.parameters.length >= 2) {
        const witness = this.client(call.expression.expression);
        if (witness !== undefined) entry = { legacy: this.legacy(call.getSourceFile()), qualified: witness && this.scopeComplete
          && (call.arguments.length === 2 || ts.isObjectLiteralExpression(call.arguments[1]) && call.arguments[1].properties.length === 0) };
      }
      this.entries.set(fn, entry);
    }
    if (!entry) return undefined;
    if (!entry.legacy || !entry.qualified) this.gap('module_export_unsupported', fn.parent);
    if (!entry.legacy) return undefined;
    const call = fn.parent;
    const supportedOptions = ts.isCallExpression(call) && (call.arguments.length === 2
      || ts.isObjectLiteralExpression(call.arguments[1]) && call.arguments[1].properties.length === 0);
    const conditionalOrigin = supportedOptions && this.nativeOriginUnchanged();
    return { valid: entry.qualified, conditionalOrigin, origin: fn.parameters[1], ...(!entry.qualified ? { invalidReason: conditionalOrigin ? 'opaque' as const : 'unsupported' as const } : {}) };
  }

  observe(call: ts.CallExpression): void {
    if (!this.modules.indexComplete || !ts.isPropertyAccessExpression(call.expression) || call.expression.name.text !== 'connect' || !ts.isIdentifier(call.expression.expression)) return;
    const witness = this.client(call.expression.expression);
    if (witness === undefined) return;
    const callback = call.arguments.at(-1);
    if (!witness || !this.legacy(call.getSourceFile()) || ![2, 3].includes(call.arguments.length)
      || !callback || !(ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) || callback.parameters.length < 2
      || call.arguments.length === 3 && !(ts.isObjectLiteralExpression(call.arguments[1]) && call.arguments[1].properties.length === 0)) this.gap('module_export_unsupported', call);
  }

  collection(call: ts.CallExpression, db?: MongoDbRole): MongoCollectionRole | undefined {
    if (!db || !ts.isPropertyAccessExpression(call.expression) || call.expression.name.text !== 'collection') return undefined;
    const supported = call.arguments.length === 1 && ts.isStringLiteralLike(call.arguments[0]);
    if (!supported || !db.valid) this.gap('module_export_unsupported', call);
    return { valid: db.valid && supported, db, origin: call, ...(!db.valid || !supported ? { invalidReason: db.invalidReason ?? 'unsupported' as const } : {}) };
  }

  selector(call: ts.CallExpression, role?: MongoCollectionRole): boolean {
    return !!role && ts.isPropertyAccessExpression(call.expression) && SELECTORS.has(call.expression.name.text);
  }
}
