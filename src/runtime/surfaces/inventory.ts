import type { ArtifactRef, InventoryV2, RuntimeGap, RuntimeParameter, RuntimeSurface,
  SurfaceProvenance } from '../types.js';
import { snapshotJsonData } from '../../json-snapshot.js';
import { runtimeSurfaceId, SURFACE_MAX_PATHS } from './openapi.js';
import type { OpenApiSurfaces } from './openapi.js';

export interface ActuatorConstraint { surfaceId: string; consumes: string[]; signature: string }
export interface DiscoveryInput {
  id: SurfaceProvenance['provider']; result: OpenApiSurfaces & { constraints?: ActuatorConstraint[] };
}
export interface InventoryBinding { sourceSha256: string; run: ArtifactRef }
type Row = Record<string, unknown>;
const statuses = ['completed', 'partial', 'error'] as const;
const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
function invalid(): never { throw new TypeError('invalid_surface_inventory'); }
function limit(): never { throw new TypeError('surface_inventory_limit'); }
function row(v: unknown): Row { if (!v || typeof v !== 'object' || Array.isArray(v)) invalid(); return v as Row; }
function keys(v: Row, required: string[], optional: string[] = []): void {
  if (required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => ![...required, ...optional].includes(k)))
    invalid();
}
function list(v: unknown, max: number): unknown[] { if (!Array.isArray(v) || v.length > max) invalid(); return v; }
function text(v: unknown, max = 2048): string {
  if (typeof v !== 'string' || v.length > max || /[\x00-\x1f\x7f]/.test(v)) invalid(); return v;
}
function strings(v: unknown, max: number): string[] { return list(v, max).map(s => text(s)); }
function artifact(v: unknown): ArtifactRef {
  const a = row(v); keys(a, ['path', 'bytes', 'sha256']);
  if (!/^[a-z0-9][a-z0-9._-]{0,119}$/.test(text(a.path)) || !hex(a.sha256)
    || !Number.isSafeInteger(a.bytes) || (a.bytes as number) < 0 || (a.bytes as number) > 64 * 1024 * 1024) invalid();
  return { path: a.path as string, bytes: a.bytes as number, sha256: a.sha256 };
}
/** Validate shape only; orchestration verifies actual raw-byte and source-location bindings. */
export function surfaceProvenance(v: unknown, provider: SurfaceProvenance['provider']): SurfaceProvenance {
  const p = row(snapshotJsonData(v, invalid, limit));
  keys(p, ['provider', 'rawInputSha256', 'sanitizedArtifact', 'locator'], ['handler']);
  if (p.provider !== provider || !hex(p.rawInputSha256) || !text(p.locator).startsWith('#/')) invalid();
  const result: SurfaceProvenance = { provider, rawInputSha256: p.rawInputSha256,
    sanitizedArtifact: artifact(p.sanitizedArtifact), locator: p.locator as string };
  if (p.handler !== undefined) {
    const h = row(p.handler); keys(h, ['path', 'className', 'methodName'], ['line']);
    const path = text(h.path);
    if (!path || /^(?:\/|[A-Za-z]:)|\\|(?:^|\/)\.{1,2}(?:\/|$)/.test(path)
      || (h.line !== undefined && (!Number.isSafeInteger(h.line) || (h.line as number) < 1))) invalid();
    result.handler = { path, className: text(h.className), methodName: text(h.methodName),
      ...(h.line === undefined ? {} : { line: h.line as number }) };
  }
  return result;
}
function parameter(v: unknown): RuntimeParameter {
  const p = row(v);
  keys(p, ['name', 'in', 'required', 'mediaType', 'jsonPointer', 'schemaLocator', 'type', 'serialization']);
  const s = row(p.serialization); keys(s, ['style', 'explode', 'allowReserved']);
  if (!['path', 'query', 'header', 'cookie', 'body'].includes(String(p.in)) || typeof p.required !== 'boolean'
    || !['string', 'integer', 'number', 'boolean', 'null', 'unknown'].includes(String(p.type))
    || !text(p.schemaLocator).startsWith('#/') || (p.mediaType !== null && typeof p.mediaType !== 'string')
    || (p.jsonPointer !== null && p.jsonPointer !== '' && !text(p.jsonPointer).startsWith('/'))
    || (s.style !== null && typeof s.style !== 'string')
    || [s.explode, s.allowReserved].some(value => value !== null && typeof value !== 'boolean')) invalid();
  return { name: text(p.name, 256), in: p.in as RuntimeParameter['in'], required: p.required,
    mediaType: p.mediaType === null ? null : text(p.mediaType), jsonPointer: p.jsonPointer as string | null,
    schemaLocator: p.schemaLocator as string, type: p.type as RuntimeParameter['type'],
    serialization: { style: s.style === null ? null : text(s.style), explode: s.explode as boolean | null,
      allowReserved: s.allowReserved as boolean | null } };
}
function surface(v: unknown, provider: SurfaceProvenance['provider']): RuntimeSurface {
  const s = row(v); keys(s, ['id', 'method', 'pathTemplate', 'params', 'provenance', 'readiness', 'reasons']);
  const method = text(s.method, 32), path = text(s.pathTemplate);
  if (!/^[!#$%&'*+.^_`|~A-Z0-9-]+$/.test(method) || !path.startsWith('/')
    || s.id !== runtimeSurfaceId(method, path) || !['ready', 'unresolved', 'excluded'].includes(String(s.readiness)))
    invalid();
  const reasons = strings(s.reasons, 64);
  if ((s.readiness === 'ready' && reasons.length) || (s.readiness === 'unresolved' && !reasons.length)) invalid();
  const provenance = list(s.provenance, 256).map(p => surfaceProvenance(p, provider));
  if (!provenance.length) invalid();
  return { id: s.id as string, method, pathTemplate: path, params: list(s.params, 64).map(parameter),
    provenance, readiness: s.readiness as RuntimeSurface['readiness'], reasons };
}
function runtimeGap(v: unknown): RuntimeGap {
  const g = row(v); keys(g, ['area', 'code'], ['surfaceId']);
  if (g.surfaceId !== undefined && !hex(g.surfaceId)) invalid();
  return { area: text(g.area, 120), code: text(g.code, 120),
    ...(g.surfaceId === undefined ? {} : { surfaceId: g.surfaceId as string }) };
}
function discovery(v: unknown): DiscoveryInput {
  const input = row(v); keys(input, ['id', 'result']);
  if (!['spring-actuator', 'openapi'].includes(String(input.id))) invalid();
  const id = input.id as DiscoveryInput['id'], r = row(input.result), counts = row(r.counts);
  keys(r, ['surfaces', 'status', 'counts', 'gaps'], id === 'spring-actuator' ? ['constraints'] : []);
  keys(counts, ['declared', 'enumerated']);
  const surfaces = list(r.surfaces, SURFACE_MAX_PATHS).map(s => surface(s, id));
  const gaps = list(r.gaps, 4096).map(runtimeGap);
  if (!statuses.includes(r.status as typeof statuses[number]) || counts.enumerated !== surfaces.length
    || (counts.declared !== null && counts.declared !== surfaces.length)
    || (r.status === 'completed' && (counts.declared === null || gaps.length
      || surfaces.some(s => s.readiness !== 'ready')))
    || (r.status !== 'completed' && counts.declared !== null)) invalid();
  const constraints = r.constraints === undefined ? [] : list(r.constraints, SURFACE_MAX_PATHS).map(v => {
    const c = row(v); keys(c, ['surfaceId', 'consumes', 'signature']);
    if (!hex(c.surfaceId) || !hex(c.signature) || !surfaces.some(s => s.id === c.surfaceId)) invalid();
    return { surfaceId: c.surfaceId, consumes: strings(c.consumes, 32), signature: c.signature };
  });
  if (id === 'spring-actuator' && (r.constraints === undefined
    || surfaces.some(s => !constraints.some(c => c.surfaceId === s.id)))) invalid();
  return { id, result: { surfaces, status: r.status as OpenApiSurfaces['status'],
    counts: { declared: counts.declared as number | null, enumerated: surfaces.length },
    gaps, constraints } };
}
const order = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
function canonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical((v as Row)[k])).join(',') + '}';
}
function unique<T>(values: T[]): T[] {
  return [...new Map(values.map(value => [canonical(value), value])).entries()]
    .sort(([a], [b]) => order(a, b)).map(([, value]) => value);
}
const parameterMeaning = ({ schemaLocator: _locator, ...semantic }: RuntimeParameter) => canonical(semantic);
function mergeRoute(rows: RuntimeSurface[], constraints: ActuatorConstraint[]): RuntimeSurface {
  const first = rows[0]!, reasons = new Set(rows.flatMap(s => s.reasons));
  if (first.method === '*') {
    reasons.add('actuator_all_methods_unknown'); reasons.add('method_not_attack_supported');
  }
  const schemas = rows.filter(s => s.provenance[0]!.provider === 'openapi');
  const ready = schemas.some(s => s.readiness === 'ready');
  if (unique(rows.flatMap(s => s.provenance.flatMap(p => p.handler ? [p.handler] : []))).length > 1)
    reasons.add('inventory_handler_conflict');
  const signatures = unique(schemas.map(s => s.params.map(parameterMeaning).sort()));
  if (signatures.length > 1) reasons.add('inventory_parameter_conflict');
  if (new Set(constraints.map(c => c.signature)).size > 1) reasons.add('actuator_conflicting_mapping');
  const params = [...new Map(unique(schemas.flatMap(s => s.params)).map(p => [parameterMeaning(p), p])).values()];
  if (constraints.some(c => c.consumes.length && (!params.some(p => p.in === 'body')
    || params.filter(p => p.in === 'body').some(p => !c.consumes.includes(p.mediaType ?? '')))))
    reasons.add('inventory_media_conflict');
  if (ready && signatures.length === 1) reasons.delete('actuator_input_schema_unknown');
  const excluded = rows.some(s => s.readiness === 'excluded');
  if (excluded) reasons.add('inventory_excluded');
  return { id: first.id, method: first.method, pathTemplate: first.pathTemplate, params,
    provenance: unique(rows.flatMap(s => s.provenance)), readiness: excluded ? 'excluded'
      : ready && !reasons.size ? 'ready' : 'unresolved', reasons: [...reasons].sort() };
}
/** Trusted binding is supplied by orchestration; this pure merge proves neither origin access nor authorization. */
export function mergeSurfaceInventory(binding: InventoryBinding, input: DiscoveryInput[]): InventoryV2 {
  const data = row(snapshotJsonData({ binding, input }, invalid, limit)), b = row(data.binding);
  keys(b, ['sourceSha256', 'run']); if (!hex(b.sourceSha256)) invalid();
  const run = artifact(b.run), providers = list(data.input, 16).map(discovery);
  if (!providers.length) invalid();
  const groups = new Map<string, RuntimeSurface[]>(), states = new Map<string, OpenApiSurfaces['status']>();
  for (const provider of providers) {
    const current = states.get(provider.id) ?? 'completed';
    states.set(provider.id, statuses[Math.max(statuses.indexOf(current), statuses.indexOf(provider.result.status))]);
    for (const surface of provider.result.surfaces) {
      const rows = groups.get(surface.id) ?? []; rows.push(surface); groups.set(surface.id, rows);
      if (groups.size > SURFACE_MAX_PATHS) limit();
    }
  }
  const constraints = providers.flatMap(p => p.result.constraints ?? []);
  const surfaces = [...groups.values()].map(rows =>
    mergeRoute(rows, constraints.filter(c => c.surfaceId === rows[0]!.id)))
    .sort((a, b) => order(a.pathTemplate, b.pathTemplate) || order(a.method, b.method));
  const gaps = unique([...providers.flatMap(p => p.result.gaps), ...surfaces.flatMap(s => s.reasons.map(code =>
    ({ area: 'inventory', code, surfaceId: s.id })))]);
  const complete = providers.every(p => p.result.status === 'completed' && p.result.counts.declared !== null);
  const result: InventoryV2 = { schema: 'wakeio.surface-inventory/v2', sourceSha256: b.sourceSha256, run, surfaces,
    providers: [...states].sort(([a], [b]) => order(a, b)).map(([id, status]) => ({ id, status })),
    counts: { declared: complete && !surfaces.some(s => s.readiness !== 'ready') ? surfaces.length : null,
      enumerated: surfaces.length }, gaps };
  snapshotJsonData(result, invalid, limit); return result;
}
