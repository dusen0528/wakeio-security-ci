import { createHash } from 'node:crypto';
import { snapshotJsonData } from './json-snapshot.js';
import { normalizeUrl } from './url-network.js';

export type PropertyScalar = string | number | boolean;
export interface PropertyActor {
  authorizationEnv: string;
  identity: { path: string; pointer: string; equals: PropertyScalar };
}
export interface ApiPropertyPolicyV1 {
  version: 1;
  origin: string;
  declarations: { disposable: true; staging: true; sharedStrongEtag: true; normalNonceFormat: 'wakeio-property-v1' };
  actors: { owner: PropertyActor; verifier: PropertyActor };
  resource: { path: string; id: { pointer: string; equals: PropertyScalar }; ownerPointer: string; runMarker: { pointer: string; equals: string } };
  normal: { field: string; initial: string };
  protected: { field: string; initial: PropertyScalar; probe: PropertyScalar; control: PropertyScalar };
}
export class ApiPropertyPolicyError extends Error {
  constructor() { super('invalid_property_policy'); this.name = 'ApiPropertyPolicyError'; }
}
function invalid(): never { throw new ApiPropertyPolicyError(); }
/** Bounded JSON wire data with duplicate-key rejection before any assertions. */
export function parsePropertyJsonText(text: string): unknown {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 64 * 1024) invalid();
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { invalid(); }
  const stack: Array<Set<string> | null> = [];
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (char === '{') stack.push(new Set());
    else if (char === '[') stack.push(null);
    else if (char === '}' || char === ']') stack.pop();
    else if (char === '"') {
      const start = index++;
      for (; index < text.length; index++) { if (text[index] === '\\') index++; else if (text[index] === '"') break; }
      let after = index + 1; while (after < text.length && /\s/.test(text[after]!)) after++;
      if (text[after] === ':') {
        const keys = stack[stack.length - 1], key = JSON.parse(text.slice(start, index + 1)) as string;
        if (!keys || keys.has(key) || ['__proto__', 'prototype', 'constructor'].includes(key)) invalid();
        keys.add(key);
      }
    }
  }
  return snapshotJsonData(parsed, invalid, invalid);
}
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const data = value as Record<string, unknown>;
  if (Object.keys(data).length !== keys.length || keys.some(key => !Object.hasOwn(data, key))) invalid();
  return data;
}
function text(value: unknown, max = 1024): string {
  if (typeof value !== 'string' || !value.length || value.length > max || /[\x00-\x1f\x7f]/.test(value)) invalid();
  return value;
}
function scalar(value: unknown): PropertyScalar {
  if (!(typeof value === 'string' && value.length <= 1024 || typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value))) invalid();
  return value as PropertyScalar;
}
function path(value: unknown): string {
  const result = text(value, 2048);
  // No response-derived paths, query strings, normalization, encoded separators or dot segments.
  if (!/^\/(?:[A-Za-z0-9_~!$&'()+,;=:@.-]+\/?)*$/.test(result) || result.startsWith('//')
    || result.split('/').some(part => part === '.' || part === '..')) invalid();
  return result;
}
function pointer(value: unknown): string {
  const result = text(value, 512);
  if (!result.startsWith('/') || /~(?![01])/.test(result)) invalid();
  const parts = result.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'));
  if (parts.some(part => !part.length || ['__proto__', 'prototype', 'constructor'].includes(part))) invalid();
  return result;
}
function expectation(value: unknown): { pointer: string; equals: PropertyScalar } {
  const data = object(value, ['pointer', 'equals']);
  return { pointer: pointer(data.pointer), equals: scalar(data.equals) };
}
function actor(value: unknown): PropertyActor {
  const data = object(value, ['authorizationEnv', 'identity']);
  const identity = object(data.identity, ['path', 'pointer', 'equals']);
  const env = text(data.authorizationEnv, 128);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(env)) invalid();
  return { authorizationEnv: env, identity: { path: path(identity.path), pointer: pointer(identity.pointer), equals: scalar(identity.equals) } };
}
function field(value: unknown): string {
  const result = text(value, 64);
  if (!/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(result) || ['__proto__', 'prototype', 'constructor'].includes(result)) invalid();
  return result;
}
/** Closed JSON data only. Declarations authorize a bounded experiment; they are not ownership proof. */
export function parseApiPropertyPolicy(input: unknown): ApiPropertyPolicyV1 {
  const data = object(snapshotJsonData(input, invalid, invalid), ['version', 'origin', 'declarations', 'actors', 'resource', 'normal', 'protected']);
  if (data.version !== 1) invalid();
  const origin = text(data.origin, 2048), url = normalizeUrl(origin);
  if (origin !== url.origin) invalid();
  const declarations = object(data.declarations, ['disposable', 'staging', 'sharedStrongEtag', 'normalNonceFormat']);
  if (declarations.disposable !== true || declarations.staging !== true || declarations.sharedStrongEtag !== true || declarations.normalNonceFormat !== 'wakeio-property-v1') invalid();
  const actors = object(data.actors, ['owner', 'verifier']);
  const owner = actor(actors.owner), verifier = actor(actors.verifier);
  if (owner.authorizationEnv === verifier.authorizationEnv || owner.identity.equals === verifier.identity.equals) invalid();
  const resource = object(data.resource, ['path', 'id', 'ownerPointer', 'runMarker']);
  const id = expectation(resource.id), marker = expectation(resource.runMarker), ownerPointer = pointer(resource.ownerPointer);
  if (typeof marker.equals !== 'string' || marker.equals.length < 16) invalid();
  if (new Set([id.pointer, ownerPointer, marker.pointer]).size !== 3) invalid();
  const normal = object(data.normal, ['field', 'initial']), protectedField = object(data.protected, ['field', 'initial', 'probe', 'control']);
  const normalName = field(normal.field), protectedName = field(protectedField.field);
  if (typeof normal.initial !== 'string' || normal.initial.length > 1024 || normalName === protectedName) invalid();
  const initial = scalar(protectedField.initial), probe = scalar(protectedField.probe), control = scalar(protectedField.control);
  if (typeof initial !== typeof probe || typeof initial !== typeof control || initial === probe || initial === control) invalid();
  for (const assertion of [id.pointer, ownerPointer, marker.pointer]) {
    const root = assertion.slice(1).split('/')[0]!.replace(/~1/g, '/').replace(/~0/g, '~');
    if (root === normalName || root === protectedName) invalid();
  }
  const nonce = 'wakeio-property-v1-' + '0'.repeat(32);
  for (const body of [{ [normalName]: nonce }, { [protectedName]: probe }, { [protectedName]: control },
    { [normalName]: nonce, [protectedName]: control }, { [normalName]: nonce, [protectedName]: initial },
    { [normalName]: normal.initial, [protectedName]: initial }]) {
    if (Buffer.byteLength(JSON.stringify(body)) > 4096) invalid();
  }
  return { version: 1, origin, declarations: { disposable: true, staging: true, sharedStrongEtag: true, normalNonceFormat: 'wakeio-property-v1' },
    actors: { owner, verifier }, resource: { path: path(resource.path), id, ownerPointer, runMarker: { pointer: marker.pointer, equals: marker.equals } },
    normal: { field: normalName, initial: normal.initial }, protected: { field: protectedName, initial, probe, control } };
}

export function propertyPolicyDigest(policy: ApiPropertyPolicyV1): string {
  return createHash('sha256').update(JSON.stringify(policy)).digest('hex');
}

export function propertyPointer(data: unknown, pointer: string): unknown {
  let value = data;
  for (const part of pointer.slice(1).split('/').map(item => item.replace(/~1/g, '/').replace(/~0/g, '~'))) {
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, part)) return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}
