import { types } from 'node:util';
import type { StaticCandidateContext } from './contracts.js';
import { redactSecrets, safeRelativePath } from './report-path.js';

export const STATIC_CONTEXT_LIMIT = 8;
export const STATIC_CONTEXT_KINDS: readonly StaticCandidateContext['items'][number]['kind'][] = Object.freeze([
  'unresolved_cjs_dispatch', 'constructor_continuation', 'declared_callback_entry', 'unqualified_mongo_origin',
  'declared_filesystem_stream_origin', 'declared_stream_callback_schedule', 'conditional_array_accumulator', 'declared_process_wrapper',
]);

function dataObject(input: unknown, required: readonly string[], optional: readonly string[] = []): input is Record<string, unknown> {
  if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input)) return false;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Reflect.ownKeys(descriptors);
  return required.every(key => Object.hasOwn(descriptors, key)) && keys.every(key => typeof key === 'string'
    && (required.includes(key) || optional.includes(key)) && descriptors[key].enumerable && Object.hasOwn(descriptors[key], 'value'));
}

function position(input: unknown): StaticCandidateContext['items'][number]['location'] | undefined {
  if (!dataObject(input, ['path', 'line', 'column']) || typeof input.path !== 'string' || input.path.length > 4096
    || redactSecrets(input.path) !== input.path || !Number.isSafeInteger(input.line) || Number(input.line) < 1
    || !Number.isSafeInteger(input.column) || Number(input.column) < 1) return undefined;
  const path = safeRelativePath(input.path);
  return path ? { path, line: Number(input.line), column: Number(input.column) } : undefined;
}

/** Closed data-only schema validation and path sanitization; does not authenticate the observed body. */
export function sanitiseStaticContext(input: unknown): StaticCandidateContext | undefined {
  if (!dataObject(input, ['revision', 'authority', 'items', 'truncated']) || input.revision !== 'static-context-v1'
    || input.authority !== 'conditional' || typeof input.truncated !== 'boolean'
    || types.isProxy(input.items) || !Array.isArray(input.items) || input.items.length > STATIC_CONTEXT_LIMIT
    || input.items.length === 0 && !input.truncated) return undefined;
  const rows = Object.getOwnPropertyDescriptors(input.items) as unknown as Record<string, PropertyDescriptor>;
  if (Reflect.ownKeys(rows).length !== input.items.length + 1) return undefined;
  const items: StaticCandidateContext['items'] = [];
  for (let index = 0; index < input.items.length; index++) {
    const row = rows[String(index)];
    if (!row || !row.enumerable || !Object.hasOwn(row, 'value')) return undefined;
    const item: unknown = row.value;
    if (!dataObject(item, ['kind', 'location'], ['target']) || !STATIC_CONTEXT_KINDS.includes(item.kind as StaticCandidateContext['items'][number]['kind'])) return undefined;
    const location = position(item.location);
    const target = Object.hasOwn(item, 'target') ? position(item.target) : undefined;
    if (!location || Object.hasOwn(item, 'target') && !target) return undefined;
    items.push({ kind: item.kind as StaticCandidateContext['items'][number]['kind'], location, ...(target ? { target } : {}) });
  }
  return { revision: 'static-context-v1', authority: 'conditional', items: canonicalItems(items), truncated: input.truncated };
}

function canonicalItems(items: StaticCandidateContext['items']): StaticCandidateContext['items'] {
  return [...new Map(items.map(item => [JSON.stringify(item), item])).entries()]
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, item]) => item);
}

/** Bounded pairwise union. Overflow retains conditional authority; the engine separately records its persistent gap. */
export function mergeStaticContexts(left?: StaticCandidateContext, right?: StaticCandidateContext): StaticCandidateContext | undefined {
  if (!left && !right) return undefined;
  const items = new Map<string, StaticCandidateContext['items'][number]>();
  let truncated = false;
  for (const context of [left, right]) {
    if (!context) continue;
    const safe = sanitiseStaticContext(context);
    if (!safe) { truncated = true; continue; }
    truncated ||= safe.truncated;
    for (const item of safe.items) items.set(JSON.stringify(item), item);
  }
  const sorted = canonicalItems([...items.values()]);
  return { revision: 'static-context-v1', authority: 'conditional', items: sorted.slice(0, STATIC_CONTEXT_LIMIT), truncated: truncated || sorted.length > STATIC_CONTEXT_LIMIT };
}
