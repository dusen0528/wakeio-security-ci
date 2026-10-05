import * as ts from 'typescript';
import type { StaticFlow } from '../contracts.js';
import type { StaticModules } from './modules.js';

export interface SqlRoleUse {
  bound: boolean; inputRelated: boolean;
  outcome: 'statement_input' | 'unknown_role' | 'values_only_fixed_text';
  certainty?: 'tainted' | 'unknown'; staticFlow?: StaticFlow;
}
export function mergeSqlRoles(a: SqlRoleUse | undefined, b: SqlRoleUse | undefined): SqlRoleUse | undefined {
  if (!a) return b; if (!b) return a;
  const rank = { statement_input: 2, unknown_role: 1, values_only_fixed_text: 0 };
  const selected = a.inputRelated !== b.inputRelated ? b.inputRelated ? b : a
    : rank[b.outcome] > rank[a.outcome] || rank[b.outcome] === rank[a.outcome] && a.certainty === 'unknown' && b.certainty === 'tainted' ? b : a;
  return { ...selected, bound: a.bound || b.bound, inputRelated: a.inputRelated || b.inputRelated };
}
function unwrap(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node)) node = node.expression;
  return node;
}
function key(node: ts.PropertyName): string | undefined { return ts.isIdentifier(node) || ts.isStringLiteralLike(node) ? node.text : undefined; }
function topConst(node: ts.VariableDeclaration): boolean {
  return ts.isVariableDeclarationList(node.parent) && !!(node.parent.flags & ts.NodeFlags.Const)
    && ts.isVariableStatement(node.parent.parent) && ts.isSourceFile(node.parent.parent.parent);
}
function declarationName(node: ts.Node): boolean {
  return ts.isImportSpecifier(node.parent) || ts.isImportClause(node.parent)
    || ts.isBindingElement(node.parent) && node.parent.name === node
    || ts.isVariableDeclaration(node.parent) && node.parent.name === node
    || ts.isParameter(node.parent) && node.parent.name === node;
}
function discarded(call: ts.CallExpression): boolean {
  let node: ts.Node = call;
  while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent) || ts.isNonNullExpression(node.parent) || ts.isAwaitExpression(node.parent))) node = node.parent;
  return ts.isExpressionStatement(node.parent);
}
type Kind = 'Client' | 'Pool';
/** Witnesses a declared pg JS API in the collected snapshot, not installed/runtime package identity. */
export class SqlRoleModel {
  private readonly constructors = new Map<ts.Symbol, { kind: Kind; file: ts.SourceFile }>();
  private readonly namespaces = new Map<ts.Symbol, ts.SourceFile>();
  private readonly instances = new Map<ts.Symbol, { file: ts.SourceFile; kind: Kind; valid: boolean }>();
  private pristine = true;
  private readonly shapes = new WeakMap<ts.Node, boolean>();
  private readonly bindings = new Map<ts.Symbol, Partial<Record<'array'|'config', boolean>>>();
  private readonly returnShapes = new Map<ts.FunctionLikeDeclaration, boolean>();
  private readonly dataBindings = new Map<ts.Symbol, boolean>();
  constructor(private readonly modules: StaticModules, private readonly tick: () => boolean,
    private readonly scopeComplete: boolean, indexAvailable: boolean) {
    this.pristine = indexAvailable;
    const supported = new Set<ts.Node>();
    const add = (name: ts.Identifier, kind?: Kind) => {
      const symbol = modules.symbol(name);
      if (!symbol || symbol.declarations?.length !== 1) { this.pristine = false; return; }
      if (kind) this.constructors.set(symbol, { kind, file:name.getSourceFile() });
      else this.namespaces.set(symbol, name.getSourceFile());
    };
    const destructure = (node: ts.VariableDeclaration): boolean => {
      if (!topConst(node) || !ts.isObjectBindingPattern(node.name)) return false;
      for (const element of node.name.elements) {
        if (!tick()) return false;
        const name = element.propertyName ? key(element.propertyName) : ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (element.dotDotDotToken || element.initializer || !ts.isIdentifier(element.name) || !['Client','Pool'].includes(name ?? '')) return false;
        add(element.name, name as Kind);
      }
      return true;
    };
    for (const node of modules.importDeclarations) {
      if (!tick()) { this.pristine=false; break; }
      if (!ts.isStringLiteralLike(node.moduleSpecifier) || node.moduleSpecifier.text !== 'pg') continue;
      const clause=node.importClause;
      if (!clause || clause.isTypeOnly) { if (!clause) this.pristine=false; else supported.add(node); continue; }
      supported.add(node);
      if (clause.name) add(clause.name);
      if (clause.namedBindings) {
        if (!ts.isNamedImports(clause.namedBindings)) { this.pristine=false; continue; }
        for (const spec of clause.namedBindings.elements) {
          if (!tick()) { this.pristine=false; break; }
          if (spec.isTypeOnly) continue;
          const imported=(spec.propertyName ?? spec.name).text;
          if (['Client','Pool'].includes(imported)) add(spec.name,imported as Kind);
          else if (imported === 'default') add(spec.name); else this.pristine=false;
        }
      }
    }
    for (const node of modules.requireDeclarations) {
      if (!tick()) { this.pristine=false; break; }
      const call=node.initializer as ts.CallExpression;
      if ((call.arguments[0] as ts.StringLiteral).text !== 'pg') continue;
      if (!modules.cjsGlobal(call.expression as ts.Identifier) || !destructure(node)) this.pristine=false;
      else supported.add(call);
    }
    // One-hop default namespace destructuring is indexed via its actual references.
    for (const symbol of this.namespaces.keys()) {
      for (const reference of modules.references.get(symbol) ?? []) {
        if (!tick()) { this.pristine=false; break; }
        if (declarationName(reference)) continue;
        if (ts.isVariableDeclaration(reference.parent) && reference.parent.initializer === reference && destructure(reference.parent)) continue;
        const member=reference.parent;
        if (ts.isPropertyAccessExpression(member) && member.expression===reference && ['Client','Pool'].includes(member.name.text)
          && ts.isNewExpression(member.parent) && member.parent.expression===member) continue;
        this.pristine=false;
      }
      if (modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol)) this.pristine=false;
    }
    for (const load of modules.sqlLoads) {
      if (!tick()) { this.pristine=false; break; }
      if (load.specifier !== 'pg' || !supported.has(load.node)) this.pristine=false;
    }
    if (!this.constructors.size && !this.namespaces.size) return;
    for (const [symbol] of this.constructors) {
      const refs=modules.references.get(symbol);
      if (!refs?.length || modules.mutated.has(symbol) || modules.mutatedMembers.has(symbol)) this.pristine=false;
      for (const ref of refs ?? []) {
        if (!tick()) { this.pristine=false; break; }
        if (!declarationName(ref) && !(ts.isNewExpression(ref.parent) && ref.parent.expression===ref)) this.pristine=false;
      }
    }
    for (const node of modules.newExpressions) {
      if (!tick()) { this.pristine=false; break; }
      const kind=this.constructorKind(node.expression); if (!kind) continue;
      const parent=node.parent;
      if (!ts.isVariableDeclaration(parent) || !ts.isIdentifier(parent.name) || !ts.isVariableDeclarationList(parent.parent)
        || !(parent.parent.flags & ts.NodeFlags.Const)) { this.pristine=false; continue; }
      const symbol=modules.symbol(parent.name); if (!symbol) { this.pristine=false; continue; }
      const valid=this.options(node,kind) && this.instanceRefs(symbol,kind) && !(ts.isVariableStatement(parent.parent.parent)
        && parent.parent.parent.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword));
      this.instances.set(symbol,{file:node.getSourceFile(),kind,valid});
    }
    for (const node of modules.sqlBoundaryNodes) {
      if (!tick()) { this.pristine=false; break; }
      if (!this.boundary(node)) this.pristine=false;
    }
  }
  private constructorKind(expression: ts.Expression): Kind | undefined {
    expression=unwrap(expression);
    if (ts.isIdentifier(expression)) {
      const binding=this.constructors.get(this.modules.symbol(expression)!);
      return binding?.file === expression.getSourceFile() ? binding.kind : undefined;
    }
    if (ts.isPropertyAccessExpression(expression) && ts.isIdentifier(expression.expression)) {
      const file=this.namespaces.get(this.modules.symbol(expression.expression)!);
      if (file===expression.getSourceFile() && ['Client','Pool'].includes(expression.name.text)) return expression.name.text as Kind;
    }
    return undefined;
  }
  private instanceRefs(symbol: ts.Symbol, kind: Kind): boolean {
    const refs=this.modules.references.get(symbol);
    if (!refs?.length || symbol.declarations?.length !== 1 || this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol)) return false;
    for (const ref of refs) {
      if (!this.tick()) return false;
      if (declarationName(ref)) continue;
      const member=ref.parent, call=member.parent;
      if (!ts.isPropertyAccessExpression(member) || member.expression!==ref || !ts.isCallExpression(call) || call.expression!==member) return false;
      if (member.name.text==='query') continue;
      if (call.arguments.length===0 && discarded(call) && (member.name.text==='end' || kind==='Client' && member.name.text==='connect')) continue;
      return false;
    }
    return true;
  }
  bound(call: ts.CallExpression): boolean {
    const callee=unwrap(call.expression);
    if (!(ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) || !ts.isIdentifier(callee.expression)) return false;
    const name=ts.isPropertyAccessExpression(callee) ? callee.name.text : ts.isStringLiteralLike(callee.argumentExpression) ? callee.argumentExpression.text : undefined;
    return name==='query' && this.instances.get(this.modules.symbol(callee.expression)!)?.file===call.getSourceFile();
  }
  dispatch(call: ts.CallExpression): boolean {
    const callee=unwrap(call.expression);
    return this.scopeComplete && this.pristine && this.modules.indexComplete && this.bound(call)
      && ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)
      && this.instances.get(this.modules.symbol(callee.expression)!)?.valid === true;
  }
  private options(node: ts.NewExpression, kind: Kind): boolean {
    const args=node.arguments ?? []; if (!args.length) return true;
    if (args.length!==1 || !ts.isObjectLiteralExpression(args[0]) || args[0].properties.length>16) return false;
    const stringKeys=new Set(['connectionString','host','database','user','password','application_name']);
    const numbers=new Set(['port','connectionTimeoutMillis',...(kind==='Pool'?['max','min','idleTimeoutMillis','maxUses','maxLifetimeSeconds']:[])]);
    const booleans=new Set(['keepAlive','ssl',...(kind==='Pool'?['allowExitOnIdle']:[])]); const keys=new Set<string>();
    for (const property of args[0].properties) {
      if (!this.tick()) return false;
      if (!ts.isPropertyAssignment(property)) return false;
      const name=key(property.name); if (!name || keys.has(name)) return false; keys.add(name);
      const value=unwrap(property.initializer);
      if (stringKeys.has(name)) {
        if (ts.isStringLiteralLike(value)) continue;
        if ((ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) && ts.isPropertyAccessExpression(value.expression)
          && value.expression.name.text==='env' && ts.isIdentifier(value.expression.expression) && value.expression.expression.text==='process'
          && !this.modules.symbol(value.expression.expression)?.declarations?.length
          && (ts.isPropertyAccessExpression(value) || ts.isStringLiteralLike(value.argumentExpression))) continue;
        return false;
      }
      if (numbers.has(name) && ts.isNumericLiteral(value) && Number.isFinite(Number(value.text)) && Number(value.text)>=0) continue;
      if (booleans.has(name) && [ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword].includes(value.kind)) continue;
      return false;
    }
    return true;
  }
  private boundary(node: ts.Identifier): boolean {
    if (ts.isPropertyAccessExpression(node.parent) && node.parent.name===node || declarationName(node)) return true;
    if (this.modules.symbol(node)?.declarations?.length) return true; // Lexically local, not the native global.
    let expression: ts.Node=node;
    while ((ts.isPropertyAccessExpression(expression.parent) || ts.isElementAccessExpression(expression.parent)) && expression.parent.expression===expression) expression=expression.parent;
    if (node.text==='globalThis') {
      const first=node.parent;
      const native=(ts.isPropertyAccessExpression(first) && first.expression===node) ? first.name.text
        : ts.isElementAccessExpression(first) && first.expression===node && ts.isStringLiteralLike(first.argumentExpression) ? first.argumentExpression.text : undefined;
      if (!native) return false; // Unknown native lookup or global alias/escape.
      if (!['Object','String','Array','Reflect','process'].includes(native)) return true;
      if (ts.isVariableDeclaration(expression.parent) || ts.isReturnStatement(expression.parent)
        || ts.isCallExpression(expression.parent) && expression.parent.arguments.includes(expression as ts.Expression)) return false;
    }
    const text=expression.getText(); // Private syntax comparison; never emitted.
    if (node.text==='process') return !/NODE_PG_FORCE_NATIVE/.test(text);
    const pure=ts.isPropertyAccessExpression(node.parent) && ['keys','entries','getOwnPropertyNames'].includes(node.parent.name.text)
      && ts.isCallExpression(node.parent.parent) && node.parent.parent.expression===node.parent;
    if (pure) return true;
    if (text.includes('prototype')) {
      const parent=expression.parent;
      if (ts.isCallExpression(parent) && parent.arguments.includes(expression as ts.Expression) && ts.isPropertyAccessExpression(parent.expression)
        && ts.isIdentifier(parent.expression.expression) && parent.expression.expression.text==='Object'
        && !this.modules.symbol(parent.expression.expression)?.declarations?.length
        && ['keys','entries','getOwnPropertyNames'].includes(parent.expression.name.text)) return true;
      // Direct reads of primitive/prototype members are harmless; writes or escape are not.
      if (expression!==node && (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression))
        && expression.expression!==node && !(ts.isBinaryExpression(parent) && parent.left===expression)
        && !ts.isDeleteExpression(parent) && !ts.isPrefixUnaryExpression(parent) && !ts.isPostfixUnaryExpression(parent) && !ts.isVariableDeclaration(parent) && !ts.isCallExpression(parent) && !ts.isReturnStatement(parent)) return true;
      return false;
    }
    if (expression===node) return false; // Alias/opaque global escape.
    if (ts.isCallExpression(expression.parent) && expression.parent.expression===expression
      && ['Object','Reflect'].includes(node.text)) {
      const method=ts.isPropertyAccessExpression(expression) ? expression.name.text : undefined;
      // Reflection on unrelated objects is not blanket-vetoed. Related instance/config refs have their own escape checks.
      if (['defineProperty','defineProperties','setPrototypeOf','assign'].includes(method ?? '')) return true;
    }
    if (ts.isBinaryExpression(expression.parent) && expression.parent.left===expression || ts.isDeleteExpression(expression.parent)) return false;
    return true;
  }
  closedConfig(node: ts.ObjectLiteralExpression): boolean {
    const cached=this.shapes.get(node); if (cached!==undefined) return cached;
    this.shapes.set(node,false);
    if (!this.instances.size || node.properties.length>4) return false;
    const names=new Set<string>(); let text=false;
    for (const property of node.properties) {
      if (!this.tick()) return false;
      if (!(ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property))) return false;
      const name=key(property.name); if (!name || names.has(name)) return false; names.add(name);
      if (name==='text' || name==='values') {
        if (ts.isShorthandPropertyAssignment(property)) { if (property.objectAssignmentInitializer) return false; }
        else if (name==='text' && !this.dataExpression(property.initializer,false)) return false;
        if (name==='text') text=true;
      } else if (name==='name' && ts.isPropertyAssignment(property) && ts.isStringLiteralLike(property.initializer)) continue;
      else if (name==='rowMode' && ts.isPropertyAssignment(property) && ts.isStringLiteralLike(property.initializer) && property.initializer.text==='array') continue;
      else return false;
    }
    const valid=text && this.valueUse(node,'config',0,new Set()); this.shapes.set(node,valid); return valid;
  }
  closedArray(node: ts.ArrayLiteralExpression): boolean {
    const cached=this.shapes.get(node); if (cached!==undefined) return cached;
    this.shapes.set(node,false);
    if (!this.instances.size || node.elements.length>64 || !this.dataExpression(node)) return false;
    const valid=this.valueUse(node,'array',0,new Set()); this.shapes.set(node,valid); return valid;
  }
  arrayParameter(name: ts.BindingName): boolean {
    return ts.isIdentifier(name) && this.bindingUses(name,'array',0,new Set());
  }
  returnedArrayUse(expression: ts.CallExpression): boolean { return this.valueUse(expression,'array',0,new Set()); }
  private valueUse(expression: ts.Node, role: 'array'|'config', depth: number, seen: Set<ts.Symbol>): boolean {
    if (!this.tick() || depth>this.modulesLimitDepth) return false;
    let node=expression;
    while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAsExpression(node.parent) || ts.isNonNullExpression(node.parent) || ts.isAwaitExpression(node.parent))) { if (!this.tick()) return false; node=node.parent; }
    const parent=node.parent;
    if (ts.isVariableDeclaration(parent) && parent.initializer===node && ts.isIdentifier(parent.name)
      && ts.isVariableDeclarationList(parent.parent) && !!(parent.parent.flags & ts.NodeFlags.Const)
      && (ts.isArrayLiteralExpression(expression) || ts.isObjectLiteralExpression(expression) || ts.isCallExpression(expression))) {
      if (ts.isVariableStatement(parent.parent.parent) && parent.parent.parent.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword)) return false;
      return this.bindingUses(parent.name,role,depth+1,seen);
    }
    if (role==='array' && (ts.isPropertyAssignment(parent) && key(parent.name)==='values' && parent.initializer===node
      || ts.isShorthandPropertyAssignment(parent) && parent.name===node && parent.name.text==='values')) return this.closedConfig(parent.parent as ts.ObjectLiteralExpression);
    if (ts.isCallExpression(parent)) {
      const slot=parent.arguments.indexOf(node as ts.Expression);
      if (this.bound(parent)) return role==='config' ? slot===0 && parent.arguments.length===1 : slot===1 && parent.arguments.length===2;
      if (role==='array' && slot>=0) {
        const resolution=this.modules.resolveCall(parent);
        if (resolution.kind==='resolved' && slot<resolution.target.parameters.length) {
          const param=resolution.target.parameters[slot]; return ts.isIdentifier(param.name) && this.bindingUses(param.name,role,depth+1,seen);
        }
      }
    }
    if (role==='array' && (ts.isReturnStatement(parent) || ts.isArrowFunction(parent) && parent.body===node)) {
      const owner=this.modules.ownerOf(node);
      if (ts.isSourceFile(owner)) return false;
      const cached=this.returnShapes.get(owner); if (cached!==undefined) return cached;
      this.returnShapes.set(owner,false);
      const calls=this.modules.callTargets.get(owner);
      const valid=Boolean(calls?.length) && calls!.every(call=>this.valueUse(call,'array',depth+1,seen));
      this.returnShapes.set(owner,valid); return valid;
    }
    return false;
  }
  private readonly modulesLimitDepth=8;
  private bindingUses(name: ts.Identifier, role:'array'|'config', depth:number, seen:Set<ts.Symbol>): boolean {
    if (!this.tick() || depth>8) return false;
    const symbol=this.modules.symbol(name); if (!symbol || seen.has(symbol)) return false;
    // Cache only finished validations, never accept an in-progress/cyclic graph.
    const cached=this.bindings.get(symbol)?.[role]; if (cached!==undefined) return cached;
    if (this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol) || symbol.declarations?.length!==1) return false;
    const refs=this.modules.references.get(symbol); if (!refs?.length) return false;
    const next=new Set(seen); next.add(symbol);
    for (const ref of refs) {
      if (!this.tick()) return false;
      if (ref===name || declarationName(ref)) continue;
      if (!this.valueUse(ref,role,depth+1,next)) { this.bindings.set(symbol,{...this.bindings.get(symbol),[role]:false}); return false; }
    }
    this.bindings.set(symbol,{...this.bindings.get(symbol),[role]:true}); return true;
  }
  dataIdentifierUnavailable(expression:ts.Identifier):boolean {
    if(!this.instances.size)return false;
    const declarations=this.modules.symbol(expression)?.declarations;
    const declaration=declarations?.length===1 ? declarations[0] : undefined;
    if(!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer)return false;
    const origin=unwrap(declaration.initializer);
    if(!ts.isObjectLiteralExpression(origin))return false;
    return !this.dataBindingPristine(this.modules.symbol(expression)!);
  }
  callbackArgument(expression:ts.Expression):boolean {
    expression=unwrap(expression);
    if(ts.isFunctionExpression(expression) || ts.isArrowFunction(expression))return true;
    if(!ts.isIdentifier(expression))return false;
    const symbol=this.modules.symbol(expression);
    if(symbol && this.modules.mutated.has(symbol))return false;
    const declarations=symbol?.declarations;
    if(declarations?.length!==1)return false;
    const declaration=declarations[0];
    return ts.isFunctionDeclaration(declaration) || ts.isVariableDeclaration(declaration) && !!declaration.initializer
      && (ts.isFunctionExpression(unwrap(declaration.initializer)) || ts.isArrowFunction(unwrap(declaration.initializer)));
  }
  private dataBindingPristine(symbol: ts.Symbol, depth=0): boolean {
    if(depth>8 || !this.tick())return false;
    const cached=this.dataBindings.get(symbol); if(cached!==undefined)return cached;
    this.dataBindings.set(symbol,false);
    if(this.modules.mutated.has(symbol) || this.modules.mutatedMembers.has(symbol))return false;
    const refs=this.modules.references.get(symbol); if(!refs?.length)return false;
    for(const ref of refs){
      if(!this.tick())return false;
      if(declarationName(ref))continue;
      let expression:ts.Node=ref;
      while(expression.parent && (ts.isPropertyAccessExpression(expression.parent) || ts.isElementAccessExpression(expression.parent))
        && expression.parent.expression===expression){if(!this.tick())return false;expression=expression.parent;}
      const parent=expression.parent;
      if(ts.isArrayLiteralExpression(parent) || ts.isPropertyAssignment(parent) && parent.initializer===expression
        || ts.isShorthandPropertyAssignment(parent) && parent.name===expression){
        let container:ts.Node=ts.isArrayLiteralExpression(parent) ? parent : parent.parent;
        while(!ts.isArrayLiteralExpression(container)){
          if(!this.tick())return false;
          const holder=container.parent;
          if(ts.isArrayLiteralExpression(holder))container=holder;
          else if(ts.isPropertyAssignment(holder) && holder.initializer===container)container=holder.parent;
          else return false;
        }
        if(!this.valueUse(container,'array',0,new Set()))return false;
      }
      if(ts.isBinaryExpression(parent) && parent.left===expression && parent.operatorToken.kind>=ts.SyntaxKind.FirstAssignment && parent.operatorToken.kind<=ts.SyntaxKind.LastAssignment
        || ts.isDeleteExpression(parent) || ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)
        || ts.isVariableDeclaration(parent) && parent.initializer===expression || ts.isReturnStatement(parent))return false;
      if(ts.isCallExpression(parent)){
        const callee=parent.expression;
        const pure=parent.arguments.includes(expression as ts.Expression) && ts.isPropertyAccessExpression(callee)
          && ts.isIdentifier(callee.expression) && callee.expression.text==='Object'
          && !this.modules.symbol(callee.expression)?.declarations?.length && ['keys','entries','getOwnPropertyNames'].includes(callee.name.text);
        if(!pure){
          const slot=parent.arguments.indexOf(expression as ts.Expression);
          const target=slot>=0 ? this.modules.resolveCall(parent) : undefined;
          const formal=target?.kind==='resolved' ? target.target.parameters[slot]?.name : undefined;
          const symbol=formal && ts.isIdentifier(formal) ? this.modules.symbol(formal) : undefined;
          if(!symbol || !this.dataBindingPristine(symbol,depth+1))return false;
        }
      }
    }
    this.dataBindings.set(symbol,true);return true;
  }
  private dataExpression(expression: ts.Expression, inspectDataBindings=true): boolean {
    let work=0; const active=new Set<ts.FunctionLikeDeclaration>(); const activeBindings=new Set<ts.Symbol>();
    const visit=(node:ts.Node,depth:number):boolean=>{
      if (++work>128 || depth>16 || !this.tick()) return false;
      if (inspectDataBindings && ts.isIdentifier(node) && !(ts.isPropertyAccessExpression(node.parent) && node.parent.name===node)
        && !((ts.isPropertyAssignment(node.parent) || ts.isMethodDeclaration(node.parent)) && node.parent.name===node)) {
        const symbol=this.modules.symbol(node);
        const declaration=symbol?.declarations?.length===1 ? symbol.declarations[0] : undefined;
        if (declaration && (ts.isFunctionDeclaration(declaration) || ts.isFunctionExpression(declaration) || ts.isArrowFunction(declaration))) return false;
        if (symbol && declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
          const origin=unwrap(declaration.initializer);
          const objectOrigin=ts.isObjectLiteralExpression(origin) || ts.isArrayLiteralExpression(origin)
            || ts.isNewExpression(origin) || ts.isCallExpression(origin) || ts.isIdentifier(origin);
          if (activeBindings.has(symbol) || this.modules.mutated.has(symbol) || objectOrigin && !this.dataBindingPristine(symbol)) return false;
          activeBindings.add(symbol); const valid=visit(declaration.initializer,depth+1); activeBindings.delete(symbol); return valid;
        }
      }
      if (ts.isCallExpression(node)) {
        const resolution=this.modules.resolveCall(node);
        if (resolution.kind!=='resolved' || active.has(resolution.target) || !resolution.target.body) return false;
        active.add(resolution.target); const valid=visit(resolution.target.body,depth+1); active.delete(resolution.target);
        return valid && node.arguments.every(a=>visit(a,depth+1));
      }
      if (ts.isNewExpression(node) || ts.isSpreadElement(node) || ts.isSpreadAssignment(node) || ts.isMethodDeclaration(node)
        || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
        || ts.isDeleteExpression(node) || ts.isAwaitExpression(node) || ts.isYieldExpression(node)
        || ts.isBinaryExpression(node) && node.operatorToken.kind>=ts.SyntaxKind.FirstAssignment && node.operatorToken.kind<=ts.SyntaxKind.LastAssignment
        || (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) && [ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(node.operator)) return false;
      if ((ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node)) && (!key(node.name) || ['toPostgres','toString','__proto__'].includes(key(node.name)!))) return false;
      let valid=true; node.forEachChild(child=>{if(valid) valid=visit(child,depth+1);});
      return valid;
    };
    return visit(expression,0);
  }
}
