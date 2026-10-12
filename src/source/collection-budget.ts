import type { CollectionBudget, CollectionEvidence, CollectionIssueCode, SourceOptions } from '../contracts.js';
import { types } from 'node:util';

export const COLLECTION_DEFAULT_MAX_FILES = 1_000;
export const COLLECTION_DEFAULT_MAX_BYTES = 25 * 1024 * 1024;
export const COLLECTION_MAX_FILES = 10_000;
export const COLLECTION_MAX_BYTES = 128 * 1024 * 1024;
export const COLLECTION_MAX_FILE_BYTES = 2 * 1024 * 1024;
/** The existing independent directory-depth bound; increasing maxFiles does not change it. */
export const COLLECTION_MAX_DIRECTORY_DEPTH = 64;

const entriesFor = (files: number): number => Math.min(Math.max(files * 8, 1_000), 100_000);
function positiveBound(value: number | undefined, fallback: number, maximum: number): number {
  return value === undefined || !Number.isSafeInteger(value) || value <= 0 ? fallback : Math.min(value, maximum);
}
/** SDK behavior remains default-on-invalid and clamp-on-valid-above-maximum. */
export function resolveCollectionBudget(options: Pick<SourceOptions, 'maxFiles' | 'maxBytes'> = {}): CollectionBudget {
  const maxFiles = positiveBound(options.maxFiles, COLLECTION_DEFAULT_MAX_FILES, COLLECTION_MAX_FILES);
  const maxBytes = positiveBound(options.maxBytes, COLLECTION_DEFAULT_MAX_BYTES, COLLECTION_MAX_BYTES);
  return Object.freeze({ revision: 'collection-v1', limits: Object.freeze({ maxFiles, maxBytes,
    maxFileBytes: COLLECTION_MAX_FILE_BYTES, maxEntries: entriesFor(maxFiles) }) });
}

/** CLI/Action grammar is stricter than the existing SDK fallback. */
export function parseCollectionLimit(raw: string, maximum: number): number {
  if (typeof raw !== 'string' || !/^[1-9][0-9]*$/.test(raw) || !Number.isSafeInteger(maximum) || maximum <= 0) throw new Error('Collection limit must be a canonical positive integer within its maximum.');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value > maximum) throw new Error('Collection limit must be a canonical positive integer within its maximum.');
  return value;
}

const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return Reflect.ownKeys(descriptors).length === keys.length && keys.every(key => descriptors[key]?.enumerable === true && Object.hasOwn(descriptors[key], 'value'));
};
export const COLLECTION_ISSUE_CODES: readonly CollectionIssueCode[] = Object.freeze([
  'changed_file', 'file_limit', 'hardlink', 'path_error', 'read_error', 'root_error', 'size_limit', 'special_file', 'symlink', 'unsupported_file',
]);

/** Closed shape/normalization validation; does not authenticate an external collector. */
export function sanitiseCollectionBudget(input: unknown): CollectionBudget | undefined {
  if (!object(input) || !exactKeys(input, ['revision', 'limits']) || input.revision !== 'collection-v1' || !object(input.limits)
    || !exactKeys(input.limits, ['maxFiles', 'maxBytes', 'maxFileBytes', 'maxEntries'])) return undefined;
  const { maxFiles, maxBytes } = input.limits;
  if (!Number.isSafeInteger(maxFiles) || Number(maxFiles) <= 0 || Number(maxFiles) > COLLECTION_MAX_FILES
    || !Number.isSafeInteger(maxBytes) || Number(maxBytes) <= 0 || Number(maxBytes) > COLLECTION_MAX_BYTES) return undefined;
  const budget = resolveCollectionBudget({ maxFiles: Number(maxFiles), maxBytes: Number(maxBytes) });
  const limits = input.limits;
  return Object.entries(budget.limits).every(([key, value]) => limits[key] === value) ? budget : undefined;
}

export function sameCollectionBudget(a: CollectionBudget | undefined, b: CollectionBudget | undefined): boolean {
  return !!a && !!b && JSON.stringify(a) === JSON.stringify(b);
}

export function collectionEvidence(issues: readonly { code: CollectionIssueCode }[]): CollectionEvidence {
  const counts = new Map<CollectionIssueCode, number>();
  for (const issue of issues) counts.set(issue.code, (counts.get(issue.code) ?? 0) + 1);
  return { revision: 'collection-v1', issueCount: issues.length,
    issues: COLLECTION_ISSUE_CODES.filter(code => counts.has(code)).map(code => ({ code, count: counts.get(code)! })) };
}

export function sanitiseCollectionEvidence(input: unknown): CollectionEvidence | undefined {
  if (!object(input) || !exactKeys(input, ['revision', 'issueCount', 'issues']) || input.revision !== 'collection-v1'
    || !Number.isSafeInteger(input.issueCount) || Number(input.issueCount) < 0 || !Array.isArray(input.issues) || types.isProxy(input.issues) || input.issues.length > COLLECTION_ISSUE_CODES.length) return undefined;
  const rows = Object.getOwnPropertyDescriptors(input.issues) as unknown as Record<string, PropertyDescriptor>;
  if (Reflect.ownKeys(rows).length !== input.issues.length + 1 || !Object.hasOwn(rows.length, 'value')
    || Array.from({ length: input.issues.length }, (_, index) => rows[String(index)]).some(row => !row || !Object.hasOwn(row, 'value'))) return undefined;
  let count = 0, previous = -1;
  const issues: CollectionEvidence['issues'] = [];
  for (let rowIndex = 0; rowIndex < input.issues.length; rowIndex++) {
    const item: unknown = rows[String(rowIndex)].value;
    if (!object(item) || !exactKeys(item, ['code', 'count'])) return undefined;
    const index = COLLECTION_ISSUE_CODES.indexOf(item.code as CollectionIssueCode);
    if (index <= previous || !Number.isSafeInteger(item.count) || Number(item.count) <= 0) return undefined;
    count += Number(item.count);
    if (!Number.isSafeInteger(count)) return undefined;
    previous = index; issues.push({ code: COLLECTION_ISSUE_CODES[index], count: Number(item.count) });
  }
  return count === input.issueCount ? { revision: 'collection-v1', issueCount: count, issues } : undefined;
}
