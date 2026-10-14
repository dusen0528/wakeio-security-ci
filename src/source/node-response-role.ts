import * as ts from 'typescript';
import type { StaticFlow } from '../contracts.js';
import { inspectHtml, type HtmlBudget, type HtmlFragments, type HtmlUrlAttributeKind } from './html-context.js';
import type { StaticModules } from './modules.js';

/** Identity is supplied by the declared entry/callback adapter, never res spelling. */
export interface NodeResponseState {
  identity: object;
  valid: boolean;
  mime: 'html' | 'non_html' | 'unknown';
  authority: 'declared_node_response';
  /** A prior write means later standalone fragments cannot prove context. */
  streamed?: boolean;
}
export interface NodeResponseUse {
  bound: true;
  mime: NodeResponseState['mime'];
  inputRelated: boolean;
  outcome: 'url_attribute_input' | 'html_context_unknown' | 'text_only' | 'non_html';
  staticFlow?: StaticFlow;
  urlAttributeKinds: HtmlUrlAttributeKind[];
  uncertainty?: 'encoding' | 'mime' | 'markup' | 'streaming';
}
function method(call: ts.CallExpression): string | undefined {
  if (call.questionDotToken) return undefined;
  const expression = call.expression;
  if (ts.isPropertyAccessExpression(expression) && !expression.questionDotToken) return expression.name.text;
  return undefined;
}
function literal(node: ts.Expression | undefined): string | undefined {
  return node && ts.isStringLiteralLike(node) ? node.text : undefined;
}
function mime(value: string | undefined): NodeResponseState['mime'] {
  if (value === undefined) return 'unknown';
  const name = value.split(';')[0].trim().toLowerCase();
  return name === 'text/html' ? 'html' : ['text/plain', 'application/json', 'application/octet-stream'].includes(name) ? 'non_html' : 'unknown';
}

/** Returns whether the direct method is a modeled metadata operation. Caller
 * must invalidate role state for unknown receiver mutations/opaque consumers.
 */
export function updateNodeResponse(call: ts.CallExpression, state: NodeResponseState,
  tick: () => boolean, gap: (node?: ts.Node) => void): boolean {
  const name = method(call);
  if (!state.valid) return false;
  if (!['setHeader', 'removeHeader', 'writeHead', 'getHeader', 'hasHeader'].includes(name ?? '')) return false;
  if (!tick() || call.arguments.some(ts.isSpreadElement)) { state.mime = 'unknown'; gap(call); return true; }
  const uncertain = (): true => { state.mime = 'unknown'; gap(call); return true; };
  if (state.streamed && ['setHeader', 'removeHeader', 'writeHead'].includes(name ?? '')) return uncertain();
  if (name === 'setHeader') {
    if (call.arguments.length !== 2) return uncertain();
    const header = literal(call.arguments[0]);
    if (header === undefined) return uncertain();
    if (header.toLowerCase() === 'content-type') state.mime = mime(literal(call.arguments[1]));
  } else if (name === 'removeHeader') {
    if (call.arguments.length !== 1) return uncertain();
    const header = literal(call.arguments[0]);
    if (header === undefined) return uncertain();
    if (header.toLowerCase() === 'content-type') state.mime = 'unknown';
  } else if (name === 'writeHead') {
    if (call.arguments.length < 1 || call.arguments.length > 3) return uncertain();
    const headers = call.arguments[call.arguments.length === 3 ? 2 : 1];
    if (!headers) return true;
    if (!ts.isObjectLiteralExpression(headers)) return uncertain();
    const seen = new Set<string>();
    for (const property of headers.properties) {
      if (!tick()) return uncertain();
      if (!ts.isPropertyAssignment(property) || ts.isComputedPropertyName(property.name)
        || !ts.isIdentifier(property.name) && !ts.isStringLiteralLike(property.name)) return uncertain();
      const key = property.name.text.toLowerCase();
      if (seen.has(key)) return uncertain();
      seen.add(key);
      if (key === 'content-type') state.mime = mime(literal(property.initializer));
    }
  }
  return true;
}

export function consumeNodeResponse(call: ts.CallExpression, state: NodeResponseState,
  fragments: HtmlFragments | undefined, budget: HtmlBudget): NodeResponseUse | undefined {
  if (!['write', 'end'].includes(method(call) ?? '')) return undefined;
  const inputRelated = fragments?.inputRelated ?? false;
  const base = { bound: true as const, mime: state.mime, inputRelated, urlAttributeKinds: [] as HtmlUrlAttributeKind[] };
  const streamed = state.streamed;
  if (method(call) === 'write') state.streamed = true;
  if (!inputRelated || state.valid && !streamed && state.mime === 'non_html') return { ...base, outcome: state.mime === 'non_html' ? 'non_html' : 'text_only' };
  const fallbackFlow = fragments?.parts.find(part => part.kind === 'hole' && part.inputRelated && part.staticFlow);
  if (!state.valid || streamed || !fragments || state.mime !== 'html' || call.arguments.length !== 1 || call.arguments.some(ts.isSpreadElement)) {
    budget.gap(call);
    return { ...base, outcome: 'html_context_unknown', uncertainty: streamed ? 'streaming' : state.mime !== 'html' ? 'mime' : 'markup',
      staticFlow: fallbackFlow?.kind === 'hole' ? fallbackFlow.staticFlow : undefined };
  }
  const inspected = inspectHtml(fragments, budget);
  if (!inspected.urlAttributeInput && !inspected.unknown) budget.gap(call);
  return { ...base, outcome: inspected.urlAttributeInput ? 'url_attribute_input' : 'html_context_unknown',
    ...(inspected.urlAttributeInput ? {} : { uncertainty: inspected.unknown ? 'markup' as const : 'encoding' as const }),
    urlAttributeKinds: inspected.urlAttributeKinds,
    staticFlow: inspected.urlAttributeFlows[0] ?? (fallbackFlow?.kind === 'hole' ? fallbackFlow.staticFlow : undefined) };
}

export function mergeNodeResponseUses(left: NodeResponseUse | undefined, right: NodeResponseUse | undefined): NodeResponseUse | undefined {
  if (!left) return right; if (!right) return left;
  const rank = { url_attribute_input: 3, html_context_unknown: 2, text_only: 1, non_html: 0 };
  const chosen = rank[right.outcome] > rank[left.outcome] ? right : left;
  return { ...chosen, inputRelated: left.inputRelated || right.inputRelated,
    mime: left.mime === right.mime ? left.mime : 'unknown' };
}

interface NodeEntry { request: 0; response: 1; origin: ts.CallExpression }
interface FactoryBinding { name: ts.Identifier; declaration: ts.Declaration; namespace: boolean; valid: boolean }
const CORE_HTTP = new Set(['http', 'https', 'node:http', 'node:https']);

/** Bounded lexical Node registration subset. Native package identity and callback
 * scheduling remain declared assumptions; this never executes an import.
 */
export class NodeResponseRoleModel {
  private readonly factories = new Map<ts.Symbol, FactoryBinding>();
  private readonly entries = new Map<ts.FunctionLikeDeclaration, NodeEntry>();
  private readonly pendingDiagnostics = new Set<ts.Node | undefined>();
  private diagnosticsReported = false;
  semanticGapsObserved = 0;
  semanticGapLocationsOmitted = 0;
  private complete = true;
  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly reportGap: (node?: ts.Node) => void, indexAvailable: boolean) {
    if (!indexAvailable) { this.complete = false; return; }
    for (const declaration of modules.importDeclarations) {
      if (!this.work()) return;
      if (!ts.isStringLiteralLike(declaration.moduleSpecifier) || !CORE_HTTP.has(declaration.moduleSpecifier.text)) continue;
      const clause = declaration.importClause;
      if (!clause || clause.isTypeOnly) continue;
      const runtimeNames = clause.name || clause.namedBindings && (ts.isNamespaceImport(clause.namedBindings)
        || clause.namedBindings.elements.some(element => !element.isTypeOnly));
      if (!runtimeNames) continue;
      if (!this.native(declaration, declaration.moduleSpecifier.text)) continue;
      if (clause.name) this.bind(clause.name, clause, true);
      const named = clause.namedBindings;
      if (named && ts.isNamespaceImport(named)) this.bind(named.name, named, true);
      else if (named) for (const element of named.elements) {
        if (!this.work()) return;
        if (!element.isTypeOnly && (element.propertyName ?? element.name).text === 'createServer') this.bind(element.name, element, false);
        if (!element.isTypeOnly && (element.propertyName ?? element.name).text === 'default') this.bind(element.name, element, true);
      }
    }
    for (const declaration of modules.requireDeclarations) {
      if (!this.work()) return;
      const load = declaration.initializer;
      if (!load || !ts.isCallExpression(load) || !ts.isIdentifier(load.expression)
        || !modules.cjsGlobal(load.expression) || load.arguments.length !== 1 || !ts.isStringLiteralLike(load.arguments[0])
        || !CORE_HTTP.has(load.arguments[0].text) || !ts.isVariableDeclarationList(declaration.parent)
        || !(declaration.parent.flags & ts.NodeFlags.Const) || !ts.isVariableStatement(declaration.parent.parent)
        || !ts.isSourceFile(declaration.parent.parent.parent) || !this.native(load, load.arguments[0].text)) continue;
      if (ts.isIdentifier(declaration.name)) this.bind(declaration.name, declaration, true);
      else if (ts.isObjectBindingPattern(declaration.name)) for (const element of declaration.name.elements) {
        if (!this.work()) return;
        if (element.dotDotDotToken || element.initializer || !ts.isIdentifier(element.name)) continue;
        const key = element.propertyName ?? element.name;
        if ((ts.isIdentifier(key) || ts.isStringLiteralLike(key)) && key.text === 'createServer') this.bind(element.name, element, false);
      }
    }
    let factoriesPristine = true;
    for (const [symbol, binding] of this.factories) {
      if (!this.work()) return;
      if (modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol)) binding.valid = false;
      for (const reference of modules.references.get(symbol) ?? []) {
        if (!this.work()) return;
        if (reference === binding.name) continue;
        if (reference.getSourceFile() !== binding.declaration.getSourceFile()
          || !this.factoryCall(reference, binding)) binding.valid = false;
      }
      if (!binding.valid) { factoriesPristine = false; this.gap(binding.name); }
    }
    // Exact package aliases can expose the same mutable factory. A second
    // collected load's concrete escape/write cannot certify the first load.
    if (!factoriesPristine) for (const binding of this.factories.values()) binding.valid = false;
    for (const call of modules.calls) {
      if (!this.work()) return;
      let name: ts.Identifier | undefined;
      if (ts.isIdentifier(call.expression)) name = call.expression;
      else if (ts.isPropertyAccessExpression(call.expression) && call.expression.name.text === 'createServer'
        && !call.expression.questionDotToken && ts.isIdentifier(call.expression.expression)) name = call.expression.expression;
      const binding = name && this.factories.get(modules.symbol(name)!);
      if (!name || !binding?.valid || call.questionDotToken || !this.factoryCall(name, binding)
        || !this.registrationArguments(call)) continue;
      const target = this.handler(call.arguments[call.arguments.length - 1]);
      if (!target || target.parameters.length !== 2 || target.parameters.some(parameter => !ts.isIdentifier(parameter.name)
        || parameter.initializer || parameter.dotDotDotToken) || !target.body) { this.gap(call); continue; }
      this.entries.set(target, { request: 0, response: 1, origin: call });
      modules.externalEntries.add(target);
    }
  }
  private work(): boolean {
    if (this.tick()) return true;
    this.complete = false; this.gap(); return false;
  }
  private gap(node?: ts.Node): void {
    this.semanticGapsObserved++;
    if (this.pendingDiagnostics.has(node)) return;
    if (this.pendingDiagnostics.size < 24) this.pendingDiagnostics.add(node);
    else this.semanticGapLocationsOmitted++;
  }
  /** Emit local role limitations after common indexing has finished. A role's
   * unsupported options/configuration cannot invalidate unrelated graph proof.
   * Exhausted shared tick() still invalidates indexing through its own path.
   */
  reportDiagnostics(): void {
    if (this.diagnosticsReported) return;
    this.diagnosticsReported = true;
    for (const node of this.pendingDiagnostics) this.reportGap(node);
    if (this.semanticGapLocationsOmitted) this.reportGap();
    this.pendingDiagnostics.clear();
  }
  private native(node: ts.Node, specifier: string): boolean {
    if (!this.work()) return false;
    if (!this.modules.configuredNativeIdentityComplete
      || this.modules.moduleConfigurations.resolve(node.getSourceFile().fileName, specifier).kind !== 'external') {
      this.gap(node); return false;
    }
    return true;
  }
  private bind(name: ts.Identifier, declaration: ts.Declaration, namespace: boolean): void {
    const symbol = this.modules.symbol(name);
    if (symbol?.declarations?.length === 1 && symbol.declarations[0] === declaration)
      this.factories.set(symbol, {name, declaration, namespace, valid: true});
  }
  private factoryCall(reference: ts.Identifier, binding: FactoryBinding): boolean {
    if (reference.getSourceFile() !== binding.declaration.getSourceFile()) return false;
    const parent = reference.parent;
    return binding.namespace ? ts.isPropertyAccessExpression(parent) && parent.expression === reference
      && parent.name.text === 'createServer' && !parent.questionDotToken && ts.isCallExpression(parent.parent)
      && parent.parent.expression === parent : ts.isCallExpression(parent) && parent.expression === reference;
  }
  private registrationArguments(call: ts.CallExpression): boolean {
    if (call.arguments.some(ts.isSpreadElement) || call.arguments.length < 1 || call.arguments.length > 2) { this.gap(call); return false; }
    if (call.arguments.length === 1) return true;
    // Custom message/response classes or opaque option objects do not retain
    // the declared core callback operand roles. TLS material is inert data.
    const options = call.arguments[0];
    if (!ts.isObjectLiteralExpression(options)) { this.gap(call); return false; }
    for (const property of options.properties) {
      if (!this.work()) return false;
      if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) { this.gap(call); return false; }
      if (!ts.isIdentifier(property.name) && !ts.isStringLiteralLike(property.name)) { this.gap(call); return false; }
      if (['IncomingMessage', 'ServerResponse', '__proto__'].includes(property.name.text)
        || ts.isShorthandPropertyAssignment(property) && property.objectAssignmentInitializer) { this.gap(call); return false; }
    }
    return true;
  }
  private handler(node: ts.Expression): ts.FunctionLikeDeclaration | undefined {
    if (!this.work()) return undefined;
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) return this.modules.functionSet.has(node) ? node : undefined;
    if (!ts.isIdentifier(node)) return undefined;
    const symbol = this.modules.symbol(node);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    if (!symbol || !declaration || declaration.getSourceFile() !== node.getSourceFile()
      || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return undefined;
    let target: ts.FunctionLikeDeclaration | undefined;
    if (ts.isFunctionDeclaration(declaration)) target = declaration;
    else if (ts.isVariableDeclaration(declaration) && declaration.parent.flags & ts.NodeFlags.Const
      && declaration.initializer && declaration.end < node.pos
      && (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer))) target = declaration.initializer;
    if (!target || !this.modules.functionSet.has(target)) return undefined;
    for (const reference of this.modules.references.get(symbol) ?? []) {
      if (!this.work()) return undefined;
      if (reference === node || (ts.isFunctionDeclaration(reference.parent) || ts.isVariableDeclaration(reference.parent))
        && reference.parent.name === reference) continue;
      const call = reference.parent;
      if (!ts.isCallExpression(call) || !this.registrationArguments(call)
        || call.arguments[call.arguments.length - 1] !== reference) return undefined;
      const expression = call.expression;
      const factory = ts.isIdentifier(expression) ? expression
        : ts.isPropertyAccessExpression(expression) && ts.isIdentifier(expression.expression) ? expression.expression : undefined;
      const binding = factory && this.factories.get(this.modules.symbol(factory)!);
      if (!factory || !binding?.valid || !this.factoryCall(factory, binding)) return undefined;
    }
    return target;
  }
  entry(target: ts.FunctionLikeDeclaration): NodeEntry | undefined {
    return this.complete && this.modules.indexComplete ? this.entries.get(target) : undefined;
  }
}
