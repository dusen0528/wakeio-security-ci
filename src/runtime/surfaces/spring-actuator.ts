import { createHash } from 'node:crypto';
import { snapshotJsonData } from '../../json-snapshot.js';
import type { RuntimeGap, RuntimeSurface, SurfaceProvenance } from '../types.js';
import { runtimeSurfaceId, SURFACE_MAX_PATHS } from './openapi.js';
import type { OpenApiProvenance, OpenApiSurfaces } from './openapi.js';
import { pointerPart } from './refs.js';
import { surfaceProvenance } from './inventory.js';
import type { ActuatorConstraint } from './inventory.js';

export interface ActuatorSurfaces extends OpenApiSurfaces { constraints: ActuatorConstraint[] }
type Row = Record<string, unknown>;
type Entry = { value: Row; locator: string; reasons: string[] };
type State = { surfaces: Map<string, RuntimeSurface>; constraints: ActuatorConstraint[]; gaps: RuntimeGap[];
  expanded: number; source: OpenApiProvenance };
class MappingError extends Error { constructor(readonly code: string) { super(code); } }
function fail(code = 'invalid_actuator'): never { throw new MappingError(code); }
function limit(): never { fail('actuator_limit'); }
function row(value: unknown): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(); return value as Row;
}
function array(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value)) fail(); if (value.length > max) limit(); return value;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2048 || /[\x00-\x1f\x7f]/.test(value)) fail(); return value;
}
const gap = (code: string, surfaceId?: string): RuntimeGap => ({ area: 'spring-actuator', code,
  ...(surfaceId === undefined ? {} : { surfaceId }) });
const errorCode = (error: unknown) => error instanceof MappingError ? error.code : 'invalid_actuator';
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k =>
    JSON.stringify(k) + ':' + canonical((value as Row)[k])).join(',') + '}';
}
function conditionList(value: unknown): Row[] { return array(value, 32).map(row); }
function conditions(value: Row, reasons: Set<string>): string[] {
  const known = ['methods', 'patterns', 'params', 'headers', 'consumes', 'produces'];
  if (Object.keys(value).some(k => !known.includes(k))) reasons.add('actuator_condition_unsupported');
  for (const key of ['params', 'headers', 'produces']) {
    const entries = conditionList(value[key]);
    if (entries.length) reasons.add('actuator_condition_unsupported');
  }
  const consumes = conditionList(value.consumes);
  const media = consumes.map(entry => {
    if (typeof entry.negated !== 'boolean') fail();
    if (entry.negated || Object.keys(entry).some(k => !['mediaType', 'negated'].includes(k)))
      reasons.add('actuator_condition_unsupported');
    const type = text(entry.mediaType).toLowerCase();
    if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(type))
      reasons.add('actuator_media_unsupported');
    return type;
  });
  if (media.length > 1 || media.some(type => type !== 'application/json')) reasons.add('actuator_media_unsupported');
  return [...new Set(media.filter(type => type === 'application/json'))].sort();
}
function mapping(state: State, entry: Entry): void {
  const details = row(entry.value.details), conditionsRow = row(details.requestMappingConditions);
  const methods = array(conditionsRow.methods, 16).map(text), patterns = array(conditionsRow.patterns, 64).map(text);
  if (!methods.length || methods.includes('*')) { state.gaps.push(gap('actuator_all_methods_unknown')); return; }
  if (!patterns.length) { state.gaps.push(gap('actuator_patterns_unknown')); return; }
  if (methods.some(method => !/^[!#$%&'*+.^_`|~A-Z0-9-]{1,32}$/.test(method))) fail();
  const reasons = new Set([...entry.reasons, 'actuator_input_schema_unknown']);
  if (new Set(methods).size !== methods.length || new Set(patterns).size !== patterns.length)
    reasons.add('actuator_duplicate_condition');
  let consumes: string[] = [];
  try { consumes = conditions(conditionsRow, reasons); }
  catch (error) { reasons.add(errorCode(error)); }
  const normalized = Object.fromEntries(Object.entries(conditionsRow).filter(([key]) => !['methods', 'patterns']
    .includes(key)).map(([key, value]) => [key, Array.isArray(value)
    ? [...value].sort((a, b) => canonical(a) < canonical(b) ? -1 : canonical(a) > canonical(b) ? 1 : 0) : value]));
  const identity = { conditions: normalized, handler: details.handlerMethod ?? details.handlerFunction ?? null };
  const signature = createHash('sha256').update(canonical(identity)).digest('hex');
  for (const method of [...new Set(methods)].sort()) for (const path of [...new Set(patterns)].sort()) {
    if (++state.expanded > SURFACE_MAX_PATHS) limit();
    const local = new Set(reasons);
    if (!/^\/(?!\/)/.test(path) || /[?#%\\\s]|\/\.{1,2}(?:\/|$)|\/\//.test(path)
      || /[{}*:]/.test(path.replace(/\{[A-Za-z_][A-Za-z0-9_]*\}/g, '')))
      local.add('actuator_dynamic_path');
    if (!['GET', 'POST'].includes(method)) local.add('method_not_attack_supported');
    const id = runtimeSurfaceId(method, path), previous = state.surfaces.get(id);
    if (state.constraints.some(c => c.surfaceId === id && c.signature !== signature))
      local.add('actuator_conflicting_mapping');
    const provenance: SurfaceProvenance = { provider: 'spring-actuator', ...state.source, locator: entry.locator };
    const existing = previous?.provenance ?? [];
    if (!existing.some(p => p.locator === provenance.locator)) existing.push(provenance);
    state.surfaces.set(id, { id, method, pathTemplate: path, params: [], provenance: existing,
      readiness: 'unresolved', reasons: [...new Set([...(previous?.reasons ?? []), ...local])].sort() });
    if (!state.constraints.some(c => c.surfaceId === id && c.signature === signature))
      state.constraints.push({ surfaceId: id, consumes, signature });
  }
}
function baseReasons(mappings: Row, group: string, reactive: boolean): string[] {
  if (reactive) return ['actuator_base_path_unknown'];
  if (!Array.isArray(mappings.servlets)) return ['actuator_base_path_unknown'];
  const matching = array(mappings.servlets, 32).map(row).filter(s => s.name === group);
  return matching.length === 1 && canonical(matching[0]!.mappings) === '["/"]'
    ? [] : ['actuator_base_path_unsupported'];
}
function entries(document: Row, state: State): Entry[] {
  const contexts = row(document.contexts), ids = Object.keys(contexts).sort(), result: Entry[] = [];
  if (!ids.length) fail(); if (ids.length > 32) limit();
  for (const id of ids) {
    text(id);
    const context = row(contexts[id]), mappings = row(context.mappings);
    const ambiguous = ids.length > 1 || context.parentId !== undefined;
    if (Object.keys(mappings).some(k => !['dispatcherServlets', 'dispatcherHandlers', 'servlets', 'servletFilters']
      .includes(k))) state.gaps.push(gap('actuator_mapping_type_unknown'));
    let groups = 0;
    for (const type of ['dispatcherServlets', 'dispatcherHandlers']) {
      if (mappings[type] === undefined) continue;
      const dispatchers = row(mappings[type]), names = Object.keys(dispatchers).sort();
      if (names.length > 32) limit();
      for (const name of names) {
        text(name);
        groups++;
        const reasons = baseReasons(mappings, name, type === 'dispatcherHandlers');
        if (ambiguous) reasons.push('actuator_context_ambiguous');
        const locator = `#/contexts/${pointerPart(id)}/mappings/${type}/${pointerPart(name)}`;
        for (const [index, value] of array(dispatchers[name], SURFACE_MAX_PATHS).entries()) {
          result.push({ value: row(value), locator: locator + '/' + index, reasons });
          if (result.length > SURFACE_MAX_PATHS) limit();
        }
      }
    }
    if (!groups) state.gaps.push(gap('actuator_dispatcher_unknown'));
  }
  return result;
}
/** Structured Spring Boot 4.1 mappings only. No predicate parsing, handler-path inference or request port. */
export function enumerateActuatorSurfaces(input: unknown, metadata: OpenApiProvenance): ActuatorSurfaces {
  try {
    const data = row(snapshotJsonData({ input, metadata }, () => fail(), limit));
    const source = surfaceProvenance({ provider: 'spring-actuator', ...row(data.metadata), locator: '#/contexts' },
      'spring-actuator');
    const state: State = { source: { rawInputSha256: source.rawInputSha256,
      sanitizedArtifact: source.sanitizedArtifact }, surfaces: new Map(), constraints: [], gaps: [], expanded: 0 };
    for (const entry of entries(row(data.input), state)) {
      try { mapping(state, entry); }
      catch (error) { if (errorCode(error) === 'actuator_limit') throw error;
        state.gaps.push(gap('actuator_unstructured_mapping')); }
    }
    const surfaces = [...state.surfaces.values()].sort((a, b) => a.pathTemplate < b.pathTemplate ? -1
      : a.pathTemplate > b.pathTemplate ? 1 : a.method < b.method ? -1 : a.method > b.method ? 1 : 0);
    for (const surface of surfaces) {
      surface.provenance.sort((a, b) => a.locator < b.locator ? -1 : a.locator > b.locator ? 1 : 0);
      state.gaps.push(...surface.reasons.map(reason => gap(reason, surface.id)));
    }
    if (!surfaces.length) state.gaps.push(gap('actuator_no_structured_routes'));
    state.constraints.sort((a, b) => a.surfaceId + a.signature < b.surfaceId + b.signature ? -1
      : a.surfaceId + a.signature > b.surfaceId + b.signature ? 1 : 0);
    const result: ActuatorSurfaces = { surfaces, constraints: state.constraints, status: 'partial',
      counts: { declared: null, enumerated: surfaces.length }, gaps: state.gaps };
    snapshotJsonData(result, () => fail(), limit); return result;
  } catch (error) { return { surfaces: [], constraints: [], status: 'error',
    counts: { declared: null, enumerated: 0 }, gaps: [gap(errorCode(error))] }; }
}
