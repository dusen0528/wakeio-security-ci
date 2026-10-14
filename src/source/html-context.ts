import { parseFragment, type DefaultTreeAdapterTypes } from 'parse5';
import type { StaticFlow } from '../contracts.js';
import type * as ts from 'typescript';

/** Private source data. Holes never contain source text or encoder certificates. */
export type HtmlPart = { kind: 'literal'; text: string }
  | { kind: 'hole'; inputRelated: boolean; staticFlow?: StaticFlow };
export interface HtmlFragments {
  parts: readonly HtmlPart[];
  complete: boolean;
  inputRelated: boolean;
}
export interface HtmlBudget {
  tick: () => boolean;
  gap: (node?: ts.Node) => void;
  maxParts: number;
  maxCharacters: number;
}
export type HtmlUrlAttributeKind = 'whole_url' | 'fixed_prefix' | 'unknown';
export interface HtmlInspection {
  urlAttributeFlows: StaticFlow[];
  urlAttributeInput: boolean;
  urlAttributeKinds: HtmlUrlAttributeKind[];
  unknown: boolean;
  inputRelated: boolean;
}

function incomplete(parts: readonly HtmlPart[], budget: HtmlBudget): HtmlFragments {
  // Representation loss is a deferred diagnostic: unrelated SQL/string values
  // must not create an HTML gap before an HTML output consumes this carrier.
  const holes = parts.filter((part): part is Extract<HtmlPart, {kind:'hole'}> => part.kind === 'hole');
  const inputRelated = holes.some(part => part.inputRelated);
  return { complete: false, inputRelated, parts: [{ kind: 'hole', inputRelated,
    staticFlow: holes.find(part => part.inputRelated && part.staticFlow)?.staticFlow }] };
}

export function htmlLiteral(text: string, budget: HtmlBudget): HtmlFragments {
  if (text.length > budget.maxCharacters) return incomplete([], budget);
  if (!budget.tick()) return incomplete([], budget);
  return { parts: [{ kind: 'literal', text }], complete: true, inputRelated: false };
}
export function htmlHole(inputRelated: boolean, staticFlow: StaticFlow | undefined, budget: HtmlBudget): HtmlFragments {
  if (!budget.tick()) return incomplete([{ kind: 'hole', inputRelated, staticFlow }], budget);
  return { parts: [{ kind: 'hole', inputRelated, staticFlow }], complete: true, inputRelated };
}
export function htmlConcat(values: readonly (HtmlFragments | undefined)[], fallback: HtmlPart, budget: HtmlBudget): HtmlFragments {
  const output: HtmlPart[] = [];
  let complete = true, characters = 0;
  // Keep input fallback even when the bounded literal representation is lost.
  const lost = (): HtmlFragments => incomplete([...output, fallback], budget);
  for (const value of values) {
    if (!budget.tick()) return lost();
    complete &&= value?.complete ?? false;
    for (const part of value?.parts ?? [fallback]) {
      if (!budget.tick()) return lost();
      if (part.kind === 'literal') {
        characters += part.text.length;
        if (characters > budget.maxCharacters) return lost();
        const last = output.at(-1);
        if (last?.kind === 'literal') output[output.length - 1] = { kind: 'literal', text: last.text + part.text };
        else output.push(part);
      } else output.push(part);
      if (output.length > budget.maxParts) return lost();
    }
  }
  return { parts: output, complete, inputRelated: output.some(part => part.kind === 'hole' && part.inputRelated) };
}

const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formaction', 'poster', 'xlink:href']);
const RAW_TEXT = new Set(['script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext']);

/** Parse bounded literals with inert markers, never attacker strings or target code.
 * A marker only witnesses the declared context. It cannot prove escaping, a safe
 * scheme, browser parsing of the actual hole, or exploitability.
 */
export function inspectHtml(fragments: HtmlFragments, budget: HtmlBudget): HtmlInspection {
  const result: HtmlInspection = { urlAttributeFlows: [], urlAttributeInput: false,
    urlAttributeKinds: [], unknown: !fragments.complete, inputRelated: fragments.inputRelated };
  if (!fragments.inputRelated) return result;
  if (fragments.parts.length > budget.maxParts) { result.unknown = true; budget.gap(); return result; }
  const literals = fragments.parts.filter((part): part is Extract<HtmlPart,{kind:'literal'}> => part.kind === 'literal');
  const literalCharacters = literals.reduce((sum, part) => sum + part.text.length, 0);
  if (literalCharacters > budget.maxCharacters) { result.unknown = true; budget.gap(); return result; }
  let marker = 'wakeiohtmlhole';
  // All literals are bounded; a disjoint marker prevents literal/hole confusion.
  while (literals.some(part => part.text.toLowerCase().includes(marker))) {
    if (!budget.tick()) { result.unknown = true; budget.gap(); return result; }
    marker += 'x';
  }
  const holes: Array<{part: Extract<HtmlPart,{kind:'hole'}>; start:number; end:number; recognized:boolean}> = [];
  let source = '';
  for (const part of fragments.parts) {
    if (!budget.tick()) { result.unknown = true; budget.gap(); return result; }
    if (part.kind === 'literal') source += part.text;
    else {
      const text = `${marker}${holes.length}z`;
      holes.push({ part, start: source.length, end: source.length + text.length, recognized: false });
      source += text;
    }
  }
  // Charge the parser's bounded source and then each visited node/attribute.
  for (let index = 0; index < source.length; index++) if (!budget.tick()) {
    result.unknown = true; budget.gap(); return result;
  }
  const tree = parseFragment(source, { sourceCodeLocationInfo: true,
    onParseError: () => { result.unknown = true; } });
  const pending: Array<{node:DefaultTreeAdapterTypes.Node; raw:boolean}> = [{ node: tree, raw: false }];
  while (pending.length) {
    if (!budget.tick()) { result.unknown = true; break; }
    const { node, raw } = pending.pop()!;
    if ('attrs' in node) {
      for (const attr of node.attrs) {
        if (!budget.tick()) { result.unknown = true; break; }
        const location = node.sourceCodeLocation?.attrs?.[attr.name];
        if (!location) continue;
        const spelling = source.slice(location.startOffset, location.endOffset);
        const quoted = /^[^=\s]+\s*=\s*(["'])([\s\S]*)\1$/.exec(spelling);
        const inside = holes.filter(hole => hole.start >= location.startOffset && hole.end <= location.endOffset);
        for (const hole of inside) {
          if (!budget.tick()) { result.unknown = true; break; }
          if (!quoted || !URL_ATTRIBUTES.has(attr.name.toLowerCase())) { result.unknown = true; continue; }
          const valueStart = location.startOffset + spelling.indexOf(quoted[1]) + 1;
          // Only a value hole, never an attribute-name hole, qualifies.
          if (hole.start < valueStart || hole.end > location.endOffset - 1) { result.unknown = true; continue; }
          hole.recognized = true;
          if (!hole.part.inputRelated) continue;
          result.urlAttributeInput = true;
          const prefix = source.slice(valueStart, hole.start);
          const earlierHole = holes.some(other => other !== hole && other.start >= valueStart && other.start < hole.start);
          result.urlAttributeKinds.push(!prefix ? 'whole_url' : earlierHole ? 'unknown' : 'fixed_prefix');
          if (hole.part.staticFlow) result.urlAttributeFlows.push(hole.part.staticFlow);
        }
      }
    }
    if (node.nodeName === '#text' && node.sourceCodeLocation && !raw) {
      const location = node.sourceCodeLocation;
      for (const hole of holes) {
        if (!budget.tick()) { result.unknown = true; break; }
        if (hole.start >= location.startOffset && hole.end <= location.endOffset) hole.recognized = true;
      }
    }
    const nestedRaw = raw || ('tagName' in node && RAW_TEXT.has(node.tagName));
    if ('childNodes' in node) for (const child of node.childNodes) pending.push({ node: child, raw: nestedRaw });
    if ('content' in node) pending.push({ node: node.content, raw: nestedRaw });
  }
  if (holes.some(hole => !hole.recognized)) result.unknown = true;
  // A dynamic hole could alter downstream markup. Retain a partial diagnostic
  // rather than treating the inert parse as a full document safety proof.
  if (result.unknown) budget.gap();
  return result;
}
