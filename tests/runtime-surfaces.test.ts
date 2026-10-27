import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parse } from 'yaml';
import { enumerateOpenApiSurfaces, runtimeSurfaceId } from '../src/runtime/surfaces/openapi.js';
import { localReferences } from '../src/runtime/surfaces/refs.js';

const metadata = { rawInputSha256: 'a'.repeat(64),
  sanitizedArtifact: { path: 'surfaces-sanitized.json', bytes: 123, sha256: 'b'.repeat(64) } };
const scalar = (name = 'q', location = 'query') => ({ name, in: location,
  required: true, schema: { type: 'string' } });
const doc = (paths: Record<string, unknown> = { '/items': { get: { parameters: [scalar()] } } }) =>
  ({ openapi: '3.1.0', paths });
const run = (input: unknown) => enumerateOpenApiSurfaces(input, metadata);
const has = (input: unknown, reason: string) => assert.ok(run(input).gaps.some(g => g.code === reason), reason);

test('v2 preserves every declared method and exact path identity without creating implicit methods', () => {
  const methods = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
  const result = run(doc({ '/Case/': Object.fromEntries(methods.map(method => [method,
    { parameters: [scalar()] }])), '/Case': { get: { parameters: [scalar()] } } }));
  assert.equal(result.surfaces.length, 9);
  assert.deepEqual(result.surfaces.filter(s => s.pathTemplate === '/Case/').map(s => s.method),
    methods.map(m => m.toUpperCase()));
  assert.notEqual(runtimeSurfaceId('GET', '/Case'), runtimeSurfaceId('GET', '/Case/'));
  assert.notEqual(runtimeSurfaceId('GET', '/Case'), runtimeSurfaceId('GET', '/case'));
  assert.equal(result.surfaces.find(s => s.method === 'PUT')?.readiness, 'unresolved');
  assert.equal(result.counts.declared, null);
});

test('GET path/query and POST declared JSON scalar leaves retain locations, requiredness and provenance', () => {
  const input = doc({ '/items/{id}': { parameters: [scalar('id', 'path')], get: { parameters: [scalar()] },
    post: { requestBody: { required: true, content: { 'application/json': { schema: { type: 'object',
      required: ['name'], properties: { name: { type: 'string' }, 'a/b~': { type: 'integer' } } } } } } } } });
  const before = JSON.stringify(input), result = run(input);
  assert.equal(result.status, 'completed'); assert.equal(result.counts.declared, 2);
  assert.equal(JSON.stringify(input), before);
  const post = result.surfaces[1]!;
  assert.equal(post.readiness, 'ready');
  assert.deepEqual(post.params.map(p => [p.in, p.name, p.jsonPointer, p.required]),
    [['path', 'id', null, true], ['body', 'a/b~', '/a~1b~0', false], ['body', 'name', '/name', true]]);
  assert.equal(post.params[1]!.mediaType, 'application/json');
  assert.equal(post.params[1]!.schemaLocator,
    '#/paths/~1items~1{id}/post/requestBody/content/application~1json/schema/properties/a~1b~0');
  assert.deepEqual(result.surfaces[0]!.params[0]!.serialization,
    { style: 'simple', explode: false, allowReserved: false });
  assert.deepEqual(post.provenance[0], { provider: 'openapi', ...metadata, locator: '#/paths/~1items~1{id}/post' });
  metadata.sanitizedArtifact.bytes = 124;
  assert.equal(post.provenance[0]!.sanitizedArtifact.bytes, 123); metadata.sanitizedArtifact.bytes = 123;
  assert.equal('request' in result, false);
});

test('local aliases and operation override use own pointers and retain distinct paths deterministically', () => {
  const input = { ...doc({ '/a': { $ref: '#/components/pathItems/A' }, '/b': { $ref: '#/components/pathItems/A' } }),
    components: { pathItems: { A: { parameters: [{ ...scalar(), schema: { type: 'array' } }],
      get: { parameters: [{ ...scalar(), schema: { $ref: '#/components/schemas/ID~1with~0' } }] } } },
    schemas: { 'ID/with~': { type: 'integer' } } } };
  for (const version of ['3.0.3', '3.1.0']) {
    input.openapi = version;
    const result = run(input);
    assert.equal(result.status, 'completed'); assert.equal(result.surfaces.length, 2);
    assert.ok(result.surfaces.every(s => s.params[0]!.type === 'integer' && s.readiness === 'ready'));
    assert.deepEqual(result.surfaces.map(s => s.provenance[0]!.locator), ['#/paths/~1a', '#/paths/~1b']);
    assert.deepEqual(result, run(input));
  }
  const duplicate = doc(); duplicate.paths['/items'] = { get: { parameters: [scalar(), scalar()] } };
  has(duplicate, 'duplicate_parameter');
});

test('unsupported input semantics remain visible with unknown readiness and explicit reasons', () => {
  for (const [param, reason] of [
    [scalar('x', 'header'), 'unsupported_parameter_location'], [scalar('x', 'cookie'), 'unsupported_parameter_location'],
    [{ ...scalar(), style: 'deepObject' }, 'unsupported_serialization'],
    [{ ...scalar(), schema: { type: 'array' } }, 'unsupported_parameter_schema'],
    [{ ...scalar(), schema: { anyOf: [{ type: 'string' }, { type: 'number' }] } }, 'unsupported_schema'],
  ] as const) {
    const input = doc({ '/a': { get: { parameters: [param] } } });
    has(input, reason); assert.equal(run(input).surfaces[0]!.params.length, 1);
  }
  has({ ...doc(), security: [{ basic: [] }] }, 'auth_unsupported');
  const body = { required: true, content: { 'multipart/form-data': { schema: { type: 'string' } } } };
  const result = run(doc({ '/a': { post: { requestBody: body } } }));
  assert.equal(result.surfaces[0]!.params[0]!.mediaType, 'multipart/form-data');
  assert.ok(result.surfaces[0]!.reasons.includes('unsupported_media_type'));
  has(doc({ '/a': { get: { parameters: [{ ...scalar(), schema: { type: ['string', 'null'] } }] } } }),
    'unsupported_schema');
});

test('remote references, malformed escapes, cycles and ambiguous siblings never resolve externally', () => {
  for (const ref of ['https://example.invalid/schema', 'file:///secret', './a.json#/X', '#/toString',
    '#/paths/~2bad', '#/paths/%61', '#/paths/constructor']) {
    const result = run({ ...doc(), components: { schemas: { Remote: { $ref: ref } } } });
    assert.equal(result.counts.declared, null); assert.equal(result.status, 'partial');
  }
  const cyclic = { ...doc(), components: { schemas: { A: { type: 'object', properties: {
    child: { $ref: '#/components/schemas/A' } } } } } };
  has(cyclic, 'cyclic_ref');
  has(doc({ '/a': { $ref: '#/paths/~1a' } }), 'cyclic_ref');
  has(doc({ '/a': { $ref: '#/paths/~1b', summary: 'ambiguous' }, '/b': { get: {} } }), 'ambiguous_ref');
  assert.equal(run({ ...doc(), servers: [{ url: 'https://never-fetch.invalid/' }] }).status, 'completed');
});

test('byte, node, depth, reference, route and body leaf bounds cannot produce complete counts', () => {
  const inputs: unknown[] = [
    { ...doc(), huge: 'x'.repeat(1024 * 1024) }, { ...doc(), huge: Array(20_001).fill(null) },
    { ...doc(), refs: Array.from({ length: 257 }, () => ({ $ref: '#/paths/~1items' })) },
    doc(Object.fromEntries(Array.from({ length: 1001 }, (_, i) => ['/' + i, { get: {} }]))),
    doc({ '/a': { post: { requestBody: { content: { 'application/json': { schema: { type: 'object',
      properties: Object.fromEntries(Array.from({ length: 33 }, (_, i) => ['p' + i, { type: 'string' }])) } } } } } } }),
  ];
  const deep = doc() as Record<string, unknown>; let cursor = deep;
  for (let i = 0; i < 41; i++) { cursor.next = {}; cursor = cursor.next as Record<string, unknown>; } inputs.push(deep);
  for (const input of inputs) { const result = run(input); assert.equal(result.status, 'error');
    assert.equal(result.counts.declared, null); assert.equal(result.gaps[0]!.code, 'openapi_limit'); }
});

test('proxies, getters, inherited and cyclic data fail without running caller code', () => {
  let calls = 0;
  const accessor = Object.defineProperty(doc(), 'secret', { enumerable: true, get() { calls++; return 'secret'; } });
  const proxy = new Proxy({}, { ownKeys() { calls++; throw new Error('executed'); } });
  const cyclic = doc() as Record<string, unknown>; cyclic.self = cyclic;
  for (const input of [accessor, proxy, cyclic, Object.assign(Object.create({ openapi: '3.1.0' }), { paths: {} })]) {
    assert.equal(run(input).status, 'error'); assert.throws(() => localReferences(input));
  }
  assert.equal(calls, 0);
  const refs = localReferences(doc());
  assert.throws(() => Object.defineProperty(refs.document, 'paths', { get() { calls++; return {}; } }));
  assert.equal(calls, 0);
});

test('reference DAG expansion and aliased output amplification remain bounded', () => {
  const schemas: Record<string, unknown> = { S0: { type: 'object', properties: {} } };
  for (let i = 1; i < 16; i++) schemas['S' + i] = { type: 'object', properties: {
    left: { $ref: '#/components/schemas/S' + (i - 1) }, right: { $ref: '#/components/schemas/S' + (i - 1) } } };
  const source = { ...doc({ '/a': { post: { requestBody: { content: { 'application/json': {
    schema: { $ref: '#/components/schemas/S15' } } } } } } }), components: { schemas } };
  assert.equal(run(source).status, 'error'); has(source, 'openapi_limit');
  const paths = Object.fromEntries(Array.from({ length: 200 }, (_, i) => ['/' + i,
    { $ref: '#/components/pathItems/P' }]));
  const amplified = { ...doc(paths), components: { pathItems: { P: { get: {
    parameters: Array.from({ length: 20 }, (_, i) => scalar('p' + i)) } } } } };
  assert.equal(run(amplified).status, 'error'); has(amplified, 'openapi_limit');
});

test('R8 ground truth is consumed unchanged as a contract input, without claiming live discovery recall', async () => {
  const files = ['tests/fixtures/runtime-m1/primary-ground-truth.json'];
  if (process.env.WAKEIO_R8_SECONDARY_GROUND_TRUTH) files.push(process.env.WAKEIO_R8_SECONDARY_GROUND_TRUTH);
  for (const file of files) {
    const truth = JSON.parse(await readFile(file, 'utf8'));
    const paths: Record<string, any> = {};
    for (const route of truth.routes) {
      const row = paths[route.path] ??= {};
      row[route.method.toLowerCase()] = route.input?.startsWith('query:') ? { parameters: [scalar('name')] }
        : route.input?.startsWith('json:') ? { requestBody: { required: true, content: { 'application/json': {
          schema: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } } } } } } : {};
    }
    const result = run(doc(paths));
    assert.deepEqual(result.surfaces.map(s => `${s.method} ${s.pathTemplate}`).sort(),
      truth.routes.map((r: any) => `${r.method} ${r.path}`).sort());
    assert.equal(result.counts.enumerated, truth.declaredBusinessRoutes);
  }
});

test('Pack carries reserved binding/source-route hints rather than claiming compiler/Oracle support', async () => {
  const pack = parse(await readFile('packs/spring-boot.v1.yml', 'utf8'));
  assert.equal(pack.runtime.defaultPort, 8080); assert.equal(pack.runtime.health, '/actuator/health');
  assert.deepEqual(pack.surfaces[0], { provider: 'spring-actuator', paths: ['/actuator/mappings'] });
  assert.deepEqual(pack.surfaces[1], { provider: 'openapi', paths: ['/v3/api-docs'] });
  assert.ok(pack.sources.some((s: any) => s.annotation?.includes('RequestBody')));
  assert.equal(pack.sinks.sql[0].arg, 0); assert.equal(pack.sanitizers.sql[0].when.placeholders, true);
});
