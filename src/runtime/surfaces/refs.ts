import { snapshotJsonData, JSON_MAX_DEPTH, JSON_MAX_INPUT_NODES } from '../../json-snapshot.js';

export type DataObject = Record<string, unknown>;
export const SURFACE_MAX_REFS = 256;
export class SurfaceInputError extends Error {
  constructor(readonly code: string) { super(code); }
}
export function reject(code = 'invalid_openapi'): never { throw new SurfaceInputError(code); }
export function object(value: unknown): DataObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  return value as DataObject;
}
export const pointerPart = (part: string) => part.replace(/~/g, '~0').replace(/\//g, '~1');

/** Input is data, never a URL or filename; descriptors are inspected before any caller property is read. */
export function snapshotOpenApi(input: unknown): DataObject {
  const document = object(snapshotJsonData(input, () => reject(), () => reject('openapi_limit')));
  const pending: unknown[] = [document];
  while (pending.length) {
    const value = pending.pop();
    if (value && typeof value === 'object') { pending.push(...Object.values(value)); Object.freeze(value); }
  }
  return document;
}
function target(document: DataObject, ref: unknown): { value: DataObject; locator: string } {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) reject('external_ref_blocked');
  if (ref.length > 512 || ref.includes('%')) reject('invalid_local_ref');
  let value: unknown = document;
  const parts = ref.slice(2).split('/');
  if (parts.length > JSON_MAX_DEPTH) reject('openapi_limit');
  for (const encoded of parts) {
    if (/~(?![01])/.test(encoded)) reject('invalid_local_ref');
    const key = encoded.replace(/~1/g, '/').replace(/~0/g, '~');
    if (Array.isArray(value) && !/^(0|[1-9][0-9]*)$/.test(key)) reject('invalid_local_ref');
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, key)) reject('invalid_local_ref');
    value = (value as DataObject)[key];
  }
  return { value: object(value), locator: ref };
}
export interface LocalReferences {
  document: DataObject;
  issues: string[];
  resolve(locator: string): { value: DataObject; locator: string };
}
/** Snapshot first. Local aliases share targets without expanding or copying the referenced graph. */
export function localReferences(input: unknown): LocalReferences {
  const document = snapshotOpenApi(input);
  const issues = new Set<string>(), active = new Set<object>(), done = new Set<object>();
  let refs = 0, resolutions = 0;
  const resolve = (locator: string) => {
    if (++resolutions > JSON_MAX_INPUT_NODES) reject('openapi_limit');
    let value: DataObject;
    ({ value, locator } = target(document, locator));
    const seen = new Set<object>();
    while (Object.hasOwn(value, '$ref')) {
      if (seen.has(value)) reject('cyclic_ref');
      if (seen.size >= JSON_MAX_DEPTH) reject('openapi_limit');
      seen.add(value);
      if (Object.keys(value).length !== 1) reject('ambiguous_ref');
      ({ value, locator } = target(document, value.$ref));
    }
    return { value, locator };
  };
  const visit = (value: unknown, depth: number): void => {
    if (!value || typeof value !== 'object' || done.has(value)) return;
    if (depth > JSON_MAX_DEPTH) reject('openapi_limit');
    if (active.has(value)) reject('cyclic_ref');
    active.add(value);
    try {
      if (!Array.isArray(value) && Object.hasOwn(value, '$ref')) {
        if (++refs > SURFACE_MAX_REFS) reject('openapi_limit');
        const row = value as DataObject;
        if (Object.keys(row).length !== 1) reject('ambiguous_ref');
        visit(target(document, row.$ref).value, depth + 1);
      } else for (const child of Object.values(value)) visit(child, depth + 1);
    } catch (error) {
      if (!(error instanceof SurfaceInputError) || error.code === 'openapi_limit') throw error;
      issues.add(error.code);
    } finally { active.delete(value); done.add(value); }
  };
  visit(document, 0);
  return { document, issues: [...issues].sort(), resolve };
}
