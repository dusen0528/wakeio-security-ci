import * as ts from 'typescript';
import { URL } from 'node:url';
import type { StaticModules } from './modules.js';

// Private bounded value metadata; literal contents never become report evidence.
export type UrlFragment = { literal: string } | { encodedQuery: true };
export const URL_SHAPE_LIMITS = { fragments: 16, literalCharacters: 2048 } as const;
export function boundedFragments(parts: readonly UrlFragment[]): UrlFragment[] | undefined {
  const result: UrlFragment[] = [];
  let characters = 0;
  for (const part of parts) {
    if ('literal' in part) {
      characters += part.literal.length;
      if (characters > URL_SHAPE_LIMITS.literalCharacters) return undefined;
      const previous = result.at(-1);
      if (previous && 'literal' in previous) previous.literal += part.literal;
      else result.push({ literal: part.literal });
    } else result.push({ encodedQuery: true });
    if (result.length > URL_SHAPE_LIMITS.fragments) return undefined;
  }
  return result;
}
export function fixedQueryDestination(parts: readonly UrlFragment[] | undefined): boolean {
  if (!parts || parts.length < 2 || !('literal' in parts[0])) return false;
  const prefix = parts[0].literal;
  if (!/^https?:\/\//.test(prefix) || !prefix.endsWith('?') || /[\x00-\x20\x7f\\#]/.test(prefix)) return false;
  try {
    const parsed = new URL(prefix);
    if (!parsed.hostname || parsed.username || parsed.password || parsed.hash || parsed.search || !['http:', 'https:'].includes(parsed.protocol)) return false;
    // Require canonical authority/path syntax; do not silently normalize malformed input.
    const canonicalPrefix = prefix.replace(/^(https?:\/\/[^/:?#]+):(80|443)(\/)/, (match, authority, port, slash) =>
      authority.startsWith('https:') && port === '443' || authority.startsWith('http:') && port === '80' ? authority + slash : match);
    if (parsed.href !== canonicalPrefix || prefix.slice(0, -1).includes('?')) return false;
  } catch { return false; }
  return parts.slice(1).every((part) => 'encodedQuery' in part || /^[&=A-Za-z0-9_.~%+-]*$/.test(part.literal));
}
function record(node: ts.Expression | undefined): boolean {
  return Boolean(node && ts.isObjectLiteralExpression(node) && node.properties.every((property) =>
    ts.isPropertyAssignment(property) && !ts.isComputedPropertyName(property.name)
    || ts.isShorthandPropertyAssignment(property) && !property.objectAssignmentInitializer));
}
/** Whole-snapshot proof: fresh immediate serialization or direct const receivers; aliases/escapes revoke support. */
export class NativeQueryModel {
  private readonly supported = new Set<ts.NewExpression>();
  constructor(private readonly modules: StaticModules, tick: () => boolean, indexAvailable = true) {
    if (!indexAvailable) return;
    let pristine = true;
    for (const node of modules.nativeBoundaryNodes) {
      if (!tick()) { pristine = false; break; }
      if (ts.isElementAccessExpression(node)) { pristine = false; continue; }
      if (ts.isIdentifier(node) && node.text === 'URLSearchParams') {
        if (!modules.symbol(node) && !(ts.isNewExpression(node.parent) && node.parent.expression === node
          && (node.parent.arguments?.length === 0 || node.parent.arguments?.length === 1 && record(node.parent.arguments[0])))) pristine = false;
        if (ts.isPropertyAccessExpression(node.parent)) pristine = false;
      }
    }
    if (!pristine) return;
    for (const node of modules.newExpressions) {
      if (!tick()) return;
      if (!ts.isIdentifier(node.expression) || node.expression.text !== 'URLSearchParams' || modules.symbol(node.expression)) continue;
      if (!(node.arguments?.length === 0 || node.arguments?.length === 1 && record(node.arguments[0]))) continue;
      const member = node.parent;
      if (ts.isPropertyAccessExpression(member) && member.expression === node && member.name.text === 'toString'
        && ts.isCallExpression(member.parent) && member.parent.expression === member && member.parent.arguments.length === 0) {
        // Fresh object is consumed immediately; there is no mutable receiver alias to prove.
        this.supported.add(node);
        continue;
      }
      const declaration = node.parent;
      if (!ts.isVariableDeclaration(declaration) || declaration.initializer !== node || !ts.isIdentifier(declaration.name)
        || !ts.isVariableDeclarationList(declaration.parent) || !(declaration.parent.flags & ts.NodeFlags.Const)
) continue;
      const symbol = modules.symbol(declaration.name);
      if (!symbol) continue;
      const references = modules.references.get(symbol);
      if (!references?.length) continue;
      let declared = false;
      const valid = references.every((reference) => {
        if (!tick()) return false;
        if (reference === declaration.name) { declared = true; return true; }
        if (modules.symbol(reference) !== symbol) return true;
        const member = reference.parent;
        if (modules.ownerOf(reference) !== modules.ownerOf(node) || !ts.isPropertyAccessExpression(member) || member.expression !== reference) return false;
        const call = member.parent;
        return ts.isCallExpression(call) && call.expression === member &&
          (member.name.text === 'toString' && call.arguments.length === 0
            || ['append', 'set'].includes(member.name.text) && call.arguments.length === 2 && !call.arguments.some(ts.isSpreadElement));
      });
      if (valid && declared) this.supported.add(node);
    }
  }
  supports(node: ts.NewExpression): boolean { return this.modules.indexComplete && this.supported.has(node); }
}
