import { createHash } from 'node:crypto';
import type { ArtifactRef, RuntimeGap, RuntimeParameter, RuntimeSurface } from '../types.js';
import { localReferences, object, pointerPart, reject, snapshotOpenApi, SurfaceInputError } from './refs.js';
import type { DataObject, LocalReferences } from './refs.js';

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
export const SURFACE_MAX_PATHS = 1_000, SURFACE_MAX_PARAMETERS = 32, SURFACE_MAX_BODY_LEAVES = 32;
export interface OpenApiProvenance { rawInputSha256: string; sanitizedArtifact: ArtifactRef }
export interface OpenApiSurfaces {
  surfaces: RuntimeSurface[]; status: 'completed' | 'partial' | 'error';
  counts: { declared: number | null; enumerated: number }; gaps: RuntimeGap[];
}
type State = { refs: LocalReferences; modern: boolean; params: RuntimeParameter[]; reasons: Set<string> };
const scalars = new Set(['string', 'integer', 'number', 'boolean', 'null']);
const code = (error: unknown) => error instanceof SurfaceInputError ? error.code : 'invalid_openapi';
const gap = (value: string): RuntimeGap => ({ area: 'openapi', code: value });
const sorted = (values: Set<string>) => [...values].sort();
class OperationMetadataLimit extends SurfaceInputError {
  constructor() { super('openapi_limit'); }
}

/** Stable discovery identity, not a request or an authorization to execute it. */
export function runtimeSurfaceId(method: string, pathTemplate: string): string {
  return createHash('sha256').update(JSON.stringify(['wakeio.surface/v2', method, pathTemplate])).digest('hex');
}
function provenance(input: OpenApiProvenance): OpenApiProvenance {
  // The caller supplies both references. No claim is made that raw response bytes were persisted.
  const data = localReferences({ metadata: input }).document.metadata;
  const row = object(data), artifact = object(row.sanitizedArtifact);
  if (typeof row.rawInputSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(row.rawInputSha256)
    || typeof artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.sha256)
    || typeof artifact.path !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,119}$/.test(artifact.path)
    || !Number.isSafeInteger(artifact.bytes) || (artifact.bytes as number) < 0
    || (artifact.bytes as number) > 64 * 1024 * 1024) reject('invalid_provenance');
  return { rawInputSha256: row.rawInputSha256, sanitizedArtifact: {
    path: artifact.path, sha256: artifact.sha256, bytes: artifact.bytes as number } };
}
function schema(state: State, locator: string): { value: DataObject; locator: string; type: RuntimeParameter['type'] } {
  const resolved = state.refs.resolve(locator), value = resolved.value;
  const type = typeof value.type === 'string' && scalars.has(value.type) ? value.type : 'unknown';
  if (['allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else', '$dynamicRef', '$id'].some(k => k in value)
    || Array.isArray(value.type)) state.reasons.add('unsupported_schema');
  if (value.nullable === true || type === 'null') state.reasons.add('nullable_input_unsupported');
  if (!state.modern && (type === 'null' || Array.isArray(value.type))) state.reasons.add('openapi30_schema');
  return { ...resolved, type: type as RuntimeParameter['type'] };
}
function parameter(state: State, locator: string): RuntimeParameter {
  const resolved = state.refs.resolve(locator), { value } = resolved;
  if (typeof value.name !== 'string' || !value.name || value.name.length > 256
    || !['path', 'query', 'header', 'cookie'].includes(String(value.in))) reject('invalid_parameter');
  const location = value.in as RuntimeParameter['in'];
  if (value.required !== undefined && typeof value.required !== 'boolean') reject('invalid_parameter');
  if (location === 'path' && value.required !== true) state.reasons.add('path_required_missing');
  const info = 'schema' in value ? schema(state, resolved.locator + '/schema') : null;
  const style = value.style === undefined ? (location === 'path' || location === 'header' ? 'simple' : 'form')
    : typeof value.style === 'string' ? value.style : null;
  const explode = value.explode === undefined ? style === 'form'
    : typeof value.explode === 'boolean' ? value.explode : null;
  const allowReserved = value.allowReserved === undefined ? false
    : typeof value.allowReserved === 'boolean' ? value.allowReserved : null;
  if (!info || info.type === 'unknown' || 'content' in value) state.reasons.add('unsupported_parameter_schema');
  if (location !== 'path' && location !== 'query') state.reasons.add('unsupported_parameter_location');
  if (style !== (location === 'path' ? 'simple' : 'form') || explode === null || allowReserved !== false
    || (location === 'path' && explode !== false)) state.reasons.add('unsupported_serialization');
  return { name: value.name, in: location, required: value.required === true, mediaType: null, jsonPointer: null,
    schemaLocator: info?.locator ?? resolved.locator, type: info?.type ?? 'unknown',
    serialization: { style, explode, allowReserved } };
}
function parameters(state: State, item: string, operation: string): void {
  const merged = new Map<string, { row: RuntimeParameter; reasons: Set<string> }>();
  for (const locator of [item, operation]) {
    const value = state.refs.resolve(locator).value;
    if (value.parameters === undefined) continue;
    if (!Array.isArray(value.parameters)) reject('invalid_parameters');
    if (value.parameters.length > SURFACE_MAX_PARAMETERS) throw new OperationMetadataLimit();
    const unique = new Set<string>();
    for (let i = 0; i < value.parameters.length; i++) {
      const reasons = new Set<string>();
      const row = parameter({ ...state, reasons }, `${locator}/parameters/${i}`);
      const key = JSON.stringify([row.in, row.name]);
      if (unique.has(key)) reject('duplicate_parameter');
      unique.add(key); merged.set(key, { row, reasons });
    }
  }
  if (merged.size > SURFACE_MAX_PARAMETERS) throw new OperationMetadataLimit();
  for (const { row, reasons } of merged.values()) {
    state.params.push(row); for (const reason of reasons) state.reasons.add(reason);
  }
}
function bodyLeaf(state: State, locator: string, pointer: string, required: boolean, mediaType: string,
  active = new Set<string>()): void {
  const info = schema(state, locator);
  if (active.has(info.locator)) reject('cyclic_ref');
  if (active.size >= 40) reject('openapi_limit');
  const next = new Set(active).add(info.locator);
  if (info.value.type === 'object' && info.value.properties !== undefined) {
    const properties = object(info.value.properties), needs = info.value.required ?? [];
    if (!Array.isArray(needs) || needs.some(v => typeof v !== 'string') || new Set(needs).size !== needs.length)
      reject('invalid_required');
    for (const name of Object.keys(properties).sort()) bodyLeaf(state,
      `${info.locator}/properties/${pointerPart(name)}`, pointer + '/' + pointerPart(name),
      required && needs.includes(name), mediaType, next);
    if (!Object.keys(properties).length) state.reasons.add('empty_body_schema');
    if (info.value.additionalProperties && typeof info.value.additionalProperties === 'object')
      state.reasons.add('dynamic_body_properties');
    return;
  }
  if (state.params.filter(p => p.in === 'body').length >= SURFACE_MAX_BODY_LEAVES)
    throw new OperationMetadataLimit();
  if (info.type === 'unknown') state.reasons.add('unsupported_body_schema');
  const name = (pointer.split('/').at(-1) ?? '').replace(/~1/g, '/').replace(/~0/g, '~');
  state.params.push({ name, in: 'body', required, mediaType,
    jsonPointer: pointer, schemaLocator: info.locator, type: info.type,
    serialization: { style: null, explode: null, allowReserved: null } });
}
function body(state: State, operation: string): void {
  const value = state.refs.resolve(operation).value;
  if (value.requestBody === undefined) return;
  const resolved = state.refs.resolve(operation + '/requestBody'), row = resolved.value;
  if (row.required !== undefined && typeof row.required !== 'boolean') reject('invalid_request_body');
  const content = object(row.content), media = Object.keys(content).sort();
  if (media.length !== 1 || media[0] !== 'application/json') state.reasons.add('unsupported_media_type');
  for (const type of media) {
    const location = `${resolved.locator}/content/${pointerPart(type)}`;
    const item = object(content[type]);
    if (!('schema' in item)) { state.reasons.add('missing_body_schema'); continue; }
    bodyLeaf(state, location + '/schema', '', row.required === true, type);
  }
}
function operation(refs: LocalReferences, modern: boolean, item: string, locator: string,
  method: string, path: string, source: OpenApiProvenance, evidenceLocator: string): RuntimeSurface {
  const state: State = { refs, modern, params: [], reasons: new Set() };
  try {
    const row = refs.resolve(locator).value;
    parameters(state, item, locator); body(state, locator);
    const security = Object.hasOwn(row, 'security') ? row.security : refs.document.security;
    if (security !== undefined && (!Array.isArray(security) || security.length)) state.reasons.add('auth_unsupported');
    if ('callbacks' in row) state.reasons.add('callbacks_unsupported');
    if (!['GET', 'POST'].includes(method)) state.reasons.add('method_not_attack_supported');
    if (method === 'GET' && row.requestBody !== undefined) state.reasons.add('get_body_unsupported');
    const names = [...path.matchAll(/\{([^{}]+)\}/g)].map(match => match[1]);
    if (names.some(name => !state.params.some(p => p.in === 'path' && p.name === name))
      || state.params.some(p => p.in === 'path' && !names.includes(p.name)))
      state.reasons.add('path_parameter_mismatch');
    if (!state.params.length) state.reasons.add('no_supported_input');
    if (!/^\/(?!\/)/.test(path) || /[?#%\\\s]|\/\.{1,2}(?:\/|$)|\/\//.test(path)
      || path.replace(/\{[^{}]+\}/g, '').match(/[{}*]/)) state.reasons.add('ambiguous_path');
  } catch (error) {
    if (code(error) === 'openapi_limit' && !(error instanceof OperationMetadataLimit)) throw error;
    state.reasons.add(code(error));
  }
  const reasons = sorted(state.reasons);
  return { id: runtimeSurfaceId(method, path), method, pathTemplate: path,
    params: state.params, readiness: reasons.length ? 'unresolved' : 'ready', reasons,
    provenance: [{ provider: 'openapi', ...source, locator: evidenceLocator }] };
}
function enumerate(refs: LocalReferences, source: OpenApiProvenance): OpenApiSurfaces {
  const document = refs.document, version = document.openapi;
  if (typeof version !== 'string' || !/^3\.[01]\.\d+$/.test(version)) reject('unsupported_openapi_version');
  const paths = object(document.paths), names = Object.keys(paths).sort(), gaps = refs.issues.map(gap);
  if (names.length > SURFACE_MAX_PATHS) reject('openapi_limit');
  const surfaces: RuntimeSurface[] = [];
  for (const path of names) {
    const pointer = '#/paths/' + pointerPart(path);
    try {
      const item = refs.resolve(pointer);
      for (const key of Object.keys(item.value)) {
        if (!METHODS.includes(key) && !['summary', 'description', 'servers', 'parameters'].includes(key)
          && !key.startsWith('x-')) gaps.push(gap('unsupported_path_field'));
      }
      for (const method of METHODS.filter(key => Object.hasOwn(item.value, key))) {
        if (surfaces.length >= SURFACE_MAX_PATHS) reject('openapi_limit');
        surfaces.push(operation(refs, version.startsWith('3.1.'), item.locator,
          item.locator + '/' + method, method.toUpperCase(), path, source,
          item.locator === pointer ? pointer + '/' + method : pointer));
      }
    } catch (error) { if (code(error) === 'openapi_limit') throw error; gaps.push(gap(code(error))); }
  }
  for (const surface of surfaces) for (const reason of surface.reasons)
    gaps.push({ ...gap(reason), surfaceId: surface.id });
  const result: OpenApiSurfaces = { surfaces, status: gaps.length ? 'partial' : 'completed',
    counts: { declared: gaps.length ? null : surfaces.length, enumerated: surfaces.length }, gaps };
  snapshotOpenApi(result); // Bound ref-alias amplification in the serialized artifact, too.
  return result;
}
/** Pure OpenAPI 3.0/3.1 discovery. It neither chooses an origin nor obtains a request capability. */
export function enumerateOpenApiSurfaces(input: unknown, metadata: OpenApiProvenance): OpenApiSurfaces {
  try { return enumerate(localReferences(input), provenance(metadata)); }
  catch (error) { return { surfaces: [], status: 'error', counts: { declared: null, enumerated: 0 },
    gaps: [gap(code(error))] }; }
}
