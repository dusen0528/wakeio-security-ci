import { createHash } from 'node:crypto';
import { snapshotJsonData } from './json-snapshot.js';
import { openApiReferences } from './openapi.js';

export type ZapJson = null | boolean | string | number | ZapJson[] | { [key: string]: ZapJson };
export type ZapRequest = { method: 'GET'; path: string } | { method: 'POST'; path: string; body: Record<string, string | number> };
export interface ZapCompiledRequest { method: 'GET' | 'POST'; path: string; body?: Record<string, string | number>;
  template?: ZapJson; fields?: Array<{ alias: string; pointer: string }> }
export interface ZapOpenApiInput { document: unknown; operations: Array<{ method: 'GET' | 'POST'; path: string;
  pathParameters?: Record<string, string | number>; query?: Record<string, string | number>; body?: ZapJson }> }
const obj = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
function bad(): never { throw new TypeError('invalid_zap_openapi'); }
function exact(v: unknown, required: string[], optional: string[] = []): asserts v is Record<string, any> {
  if (!obj(v) || required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) bad();
}
function name(v: unknown): string {
  if (typeof v !== 'string' || !/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(v) || ['__proto__', 'constructor', 'prototype'].includes(v)) bad(); return v;
}
function scalar(v: unknown): v is string | number { return typeof v === 'string' && v.length <= 512 && !/[\x00-\x1f\x7f]/.test(v) || typeof v === 'number' && Number.isFinite(v); }
/** Only same-document references are reused from the existing OpenAPI boundary. */
export function compileZapOpenApi(input: unknown): { openapi: ZapOpenApiInput; requests: ZapCompiledRequest[]; sourceSha256: string } {
  const value = snapshotJsonData(input, bad, bad); exact(value, ['document', 'operations']);
  const doc = value.document;
  if (!obj(doc) || !/^3\.(0|1)\.\d+$/.test(doc.openapi) || !obj(doc.paths) || Object.keys(doc.paths).length > 1000
    || !Array.isArray(value.operations) || !value.operations.length || value.operations.length > 16) bad();
  const ref = openApiReferences(doc), resolve = (v: unknown): Record<string, any> => ref(v), seen = new Set<string>();
  const seed = (schemaInput: unknown, supplied: unknown, provided: boolean, depth = 0): ZapJson => {
    if (depth > 6) bad(); const schema = resolve(schemaInput);
    if (['allOf', 'oneOf', 'anyOf', 'not'].some(k => Object.hasOwn(schema, k))) bad();
    if (!provided && Object.hasOwn(schema, 'example')) { supplied = schema.example; provided = true; }
    if (!provided && Object.hasOwn(schema, 'default')) { supplied = schema.default; provided = true; }
    if (!provided && Array.isArray(schema.enum) && schema.enum.length) { supplied = schema.enum[0]; provided = true; }
    if (schema.type === 'object') {
      if (!obj(schema.properties) || Object.keys(schema.properties).length > 32 || provided && !obj(supplied)) bad();
      const source = supplied as Record<string, unknown> | undefined;
      if (source && Object.keys(source).some(k => !Object.hasOwn(schema.properties, k))) bad();
      if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.some((k: unknown) => typeof k !== 'string' || !Object.hasOwn(schema.properties, k)))) bad();
      const result: Record<string, ZapJson> = {};
      for (const key of Object.keys(schema.properties)) {
        name(key); if (provided && !Object.hasOwn(source!, key)) { if (schema.required?.includes(key)) bad(); continue; }
        result[key] = seed(schema.properties[key], source?.[key], !!source && Object.hasOwn(source, key), depth + 1);
      }
      return result;
    }
    if (schema.type === 'array') {
      if (provided && !Array.isArray(supplied)) bad();
      if (schema.minItems !== undefined && (!Number.isSafeInteger(schema.minItems) || schema.minItems < 0 || schema.minItems > 8)) bad();
      const list = provided ? supplied as unknown[] : Array.from({ length: Math.max(1, Number(schema.minItems ?? 1)) }, () => undefined);
      if (!Number.isSafeInteger(list.length) || list.length > 8 || list.length < Number(schema.minItems ?? 0) || list.length > Number(schema.maxItems ?? 8)) bad();
      return list.map(item => seed(schema.items, item, provided, depth + 1));
    }
    let result = provided ? supplied : schema.type === 'string' ? 'wakeio' : schema.type === 'integer' || schema.type === 'number' ? Math.max(1, Number(schema.minimum ?? 1)) : schema.type === 'boolean' ? false : schema.type === 'null' ? null : bad();
    if (result === null && (schema.nullable === true || schema.type === 'null')) return null;
    if (schema.type === 'string' ? typeof result !== 'string' || !scalar(result) : schema.type === 'integer' ? !Number.isSafeInteger(result)
      : schema.type === 'number' ? typeof result !== 'number' || !Number.isFinite(result) : schema.type === 'boolean' ? typeof result !== 'boolean' : true) bad();
    if (schema.enum && (!Array.isArray(schema.enum) || !schema.enum.includes(result))) bad();
    if (typeof result === 'number' && (result < Number(schema.minimum ?? -Infinity) || result > Number(schema.maximum ?? Infinity))) bad();
    if (typeof result === 'string' && (result.length < Number(schema.minLength ?? 0) || result.length > Number(schema.maxLength ?? 512))) bad();
    return result as ZapJson;
  };
  const requests: ZapCompiledRequest[] = value.operations.map((item: unknown) => {
    exact(item, ['method', 'path'], ['pathParameters', 'query', 'body']);
    if (!['GET', 'POST'].includes(item.method) || typeof item.path !== 'string' || !Object.hasOwn(doc.paths, item.path) || !/^\/(?:[A-Za-z0-9_~.{}-]+\/?)*$/.test(item.path)) bad();
    const key = `${item.method}:${item.path}`; if (seen.has(key)) bad(); seen.add(key);
    const pathItem = resolve(doc.paths[item.path]), operation = resolve(pathItem[item.method.toLowerCase()]);
    if (operation.callbacks) bad();
    const params = new Map<string, Record<string, any>>();
    for (const container of [pathItem, operation]) {
      if (container.parameters !== undefined && (!Array.isArray(container.parameters) || container.parameters.length > 32)) bad();
      for (const raw of container.parameters ?? []) { const p = resolve(raw); name(p.name);
        if (!['path', 'query'].includes(p.in)) { if (p.required) bad(); continue; }
        if (p.style && !['simple', 'form'].includes(p.style)) bad(); params.set(`${p.in}:${p.name}`, p); }
    }
    for (const [location, supplied] of [['path', item.pathParameters], ['query', item.query]] as const) {
      if (supplied !== undefined && (!obj(supplied) || Object.keys(supplied).some(k => !params.has(`${location}:${k}`)))) bad();
    }
    let path = item.path; const query = new URLSearchParams();
    for (const p of params.values()) {
      const supplied = p.in === 'path' ? item.pathParameters : item.query;
      const result = seed(p.schema, supplied?.[p.name] ?? p.example, supplied && Object.hasOwn(supplied, p.name) || Object.hasOwn(p, 'example'));
      if (!scalar(result)) bad();
      if (p.in === 'path') { const text = String(result); if (!/^[A-Za-z0-9_~-]+$/.test(text)) bad(); path = path.replaceAll(`{${p.name}}`, text); }
      else query.set(p.name, String(result));
    }
    if (/[{}]/.test(path)) bad();
    if (item.method === 'GET') {
      if (Object.hasOwn(item, 'body') || operation.requestBody || !query.size) bad(); return { method: 'GET', path: path + '?' + query.toString() };
    }
    if (query.size) bad();
    const bodyDef = resolve(operation.requestBody);
    if (!obj(bodyDef.content) || !obj(bodyDef.content['application/json'])) bad();
    const media = bodyDef.content['application/json'];
    const template = seed(media.schema, Object.hasOwn(item, 'body') ? item.body : media.example, Object.hasOwn(item, 'body') || Object.hasOwn(media, 'example'));
    const fields: Array<{ alias: string; pointer: string }> = [], body: Record<string, string | number> = {};
    const walk = (v: ZapJson, pointer: string) => {
      if (typeof v === 'string' || typeof v === 'number') { const alias = `p${fields.length}`; fields.push({ alias, pointer }); body[alias] = v; }
      else if (v && typeof v === 'object') for (const [key, child] of Object.entries(v)) walk(child, pointer + '/' + key);
    };
    walk(template, '');
    if (!obj(template) || !fields.length || fields.length > 16 || Buffer.byteLength(JSON.stringify(template)) > 8192) bad();
    return { method: 'POST', path, body, template, fields };
  });
  if (new Set(requests.map(r => `${r.method}:${r.path.split('?')[0]}`)).size !== requests.length) bad();
  return { openapi: value as unknown as ZapOpenApiInput, requests, sourceSha256: createHash('sha256').update(JSON.stringify(doc)).digest('hex') };
}
/** Canonical flat virtual body -> the prevalidated actual object, preserving all unselected structure. */
export function reconstructZapBody(request: ZapCompiledRequest, body: Record<string, string | number>): ZapJson {
  if (!request.fields) return body;
  const result = structuredClone(request.template!);
  for (const { alias, pointer } of request.fields) {
    const parts = pointer.slice(1).split('/'); let parent: any = result;
    for (const part of parts.slice(0, -1)) parent = parent[part];
    parent[parts.at(-1)!] = body[alias];
  }
  return result;
}
/** Remove every document server, ref, extension and unselected operation before native import. */
export function projectedZapOpenApi(requests: ZapCompiledRequest[], origin: string): object {
  const paths: Record<string, any> = {};
  for (const request of requests) {
    const url = new URL(request.path, origin), operation: Record<string, any> = { responses: { '200': { description: 'Reviewed seed response' } } };
    if (request.method === 'GET') operation.parameters = [...url.searchParams].map(([name, value]) => ({ name, in: 'query', required: true, schema: { type: 'string', default: value }, example: value }));
    else operation.requestBody = { required: true, content: { 'application/json': { schema: { type: 'object', required: Object.keys(request.body!), properties:
      Object.fromEntries(Object.entries(request.body!).map(([key, value]) => [key, { type: typeof value === 'number' ? 'number' : 'string', default: value }])) }, example: request.body } } };
    (paths[url.pathname] ??= {})[request.method.toLowerCase()] = operation;
  }
  return { openapi: '3.0.3', info: { title: 'Reviewed WakeIO projection', version: '1' }, servers: [{ url: origin }], paths };
}
