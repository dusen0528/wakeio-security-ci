import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parse } from 'yaml';
import { enumerateOpenApiSurfaces, runtimeSurfaceId } from '../src/runtime/surfaces/openapi.js';
import { localReferences } from '../src/runtime/surfaces/refs.js';
import { enumerateActuatorSurfaces } from '../src/runtime/surfaces/spring-actuator.js';
import { mergeSurfaceInventory } from '../src/runtime/surfaces/inventory.js';
import type { DiscoveryInput } from '../src/runtime/surfaces/inventory.js';

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
    assert.equal(result.surfaces.length, 1); assert.equal(result.surfaces[0]!.readiness, 'ready');
  }
  const cyclic = { ...doc(), components: { schemas: { A: { type: 'object', properties: {
    child: { $ref: '#/components/schemas/A' } } } } } };
  has(cyclic, 'cyclic_ref');
  has(doc({ '/a': { $ref: '#/paths/~1a' } }), 'cyclic_ref');
  has(doc({ '/a': { $ref: '#/paths/~1b', summary: 'ambiguous' }, '/b': { get: {} } }), 'ambiguous_ref');
  assert.equal(run({ ...doc(), servers: [{ url: 'https://never-fetch.invalid/' }] }).status, 'completed');
});

test('global byte, node, depth, reference and route bounds reject the whole document', () => {
  const inputs: unknown[] = [
    { ...doc(), huge: 'x'.repeat(1024 * 1024) }, { ...doc(), huge: Array(20_001).fill(null) },
    { ...doc(), refs: Array.from({ length: 257 }, () => ({ $ref: '#/paths/~1items' })) },
    doc(Object.fromEntries(Array.from({ length: 1001 }, (_, i) => ['/' + i, { get: {} }]))),
  ];
  const deep = doc() as Record<string, unknown>; let cursor = deep;
  for (let i = 0; i < 41; i++) { cursor.next = {}; cursor = cursor.next as Record<string, unknown>; } inputs.push(deep);
  for (const input of inputs) { const result = run(input); assert.equal(result.status, 'error');
    assert.equal(result.counts.declared, null); assert.equal(result.gaps[0]!.code, 'openapi_limit'); }
});

test('32 metadata entries are ready; the 33rd preserves the unresolved surface and a normal GET', () => {
  for (const size of [32, 33]) for (const kind of ['body', 'parameters']) {
    const entries = Array.from({ length: size }, (_, i) => 'p' + i);
    const large = kind === 'body' ? { post: { requestBody: { required: true, content: { 'application/json': {
      schema: { type: 'object', properties: Object.fromEntries(entries.map(p => [p, { type: 'string' }])) },
    } } } } } : { get: { parameters: entries.map(p => scalar(p)) } };
    const result = run(doc({ '/normal': { get: { parameters: [scalar()] } }, '/large': large }));
    const normal = result.surfaces.find(s => s.pathTemplate === '/normal')!;
    const affected = result.surfaces.find(s => s.pathTemplate === '/large')!;
    assert.equal(result.counts.enumerated, 2); assert.equal(normal.readiness, 'ready');
    assert.equal(affected.method, kind === 'body' ? 'POST' : 'GET');
    assert.equal(affected.id, runtimeSurfaceId(affected.method, '/large'));
    if (size === 32) {
      assert.equal(result.status, 'completed'); assert.equal(result.counts.declared, 2);
      assert.equal(affected.readiness, 'ready'); assert.equal(affected.params.length, 32);
    } else {
      assert.equal(result.status, 'partial'); assert.equal(result.counts.declared, null);
      assert.equal(affected.readiness, 'unresolved'); assert.ok(affected.reasons.includes('openapi_limit'));
      assert.ok(result.gaps.some(g => g.code === 'openapi_limit' && g.surfaceId === affected.id));
      assert.ok(affected.params.length <= 32);
    }
  }
});

test('merged path-item and operation parameter overflow stays local', () => {
  const result = run(doc({ '/large': { parameters: Array.from({ length: 16 }, (_, i) => scalar('base' + i)),
    get: { parameters: Array.from({ length: 17 }, (_, i) => scalar('extra' + i)) } },
  '/normal': { get: { parameters: [scalar()] } } }));
  assert.equal(result.status, 'partial'); assert.equal(result.surfaces.length, 2);
  assert.equal(result.surfaces.find(s => s.pathTemplate === '/normal')!.readiness, 'ready');
  assert.deepEqual(result.surfaces.find(s => s.pathTemplate === '/large')!.reasons, ['openapi_limit']);
});

test('memoized aliases preserve locator identity and do not remove the global resolution work budget', () => {
  const refs = localReferences({ ...doc(), components: { schemas: { Alias: { $ref: '#/components/schemas/Value' },
    Value: { type: 'string' } } } });
  const first = refs.resolve('#/components/schemas/Alias');
  assert.equal(first.locator, '#/components/schemas/Value');
  assert.equal(first, refs.resolve('#/components/schemas/Alias'));
  assert.throws(() => Object.defineProperty(first, 'locator', { value: '#/bad' }));
  for (let i = 2; i < 20_000; i++) refs.resolve('#/components/schemas/Alias');
  assert.throws(() => refs.resolve('#/components/schemas/Alias'), /openapi_limit/);
});

test('global ref-node bound stays 256 even when all nodes alias the same target', () => {
  for (const size of [256, 257]) {
    const result = run({ ...doc(), refs: Array.from({ length: size }, () => ({ $ref: '#/paths/~1items' })) });
    assert.equal(result.status, size === 256 ? 'completed' : 'error');
    assert.equal(result.counts.declared, size === 256 ? 1 : null);
    assert.equal(result.counts.enumerated, size === 256 ? 1 : 0);
  }
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

// Inline contract inputs follow the official 4.1 structure; these are not captured Spring responses.
const actEntry = (methods = ['GET'], patterns = ['/route'], conditions: Record<string, unknown> = {}) => ({
  details: { handlerMethod: { className: 'fixtures.Controller', name: 'handle', descriptor: '()V' },
    requestMappingConditions: { methods, patterns, params: [], headers: [], consumes: [], produces: [], ...conditions } },
  predicate: 'RAW_SECRET https://never-request.invalid/GET', handler: 'RAW_SECRET',
});
const actDoc = (entries: unknown[]) => ({ contexts: { app: { mappings: {
  dispatcherServlets: { dispatcherServlet: entries },
  servlets: [{ name: 'dispatcherServlet', className: 'org.springframework.web.servlet.DispatcherServlet', mappings: ['/'] }],
} } } });
const act = (input: unknown) => enumerateActuatorSurfaces(input, metadata);
const inventoryBinding = { sourceSha256: 'c'.repeat(64),
  run: { path: 'run.json', bytes: 20, sha256: 'd'.repeat(64) } };
const discovery = (id: DiscoveryInput['id'], result: DiscoveryInput['result']): DiscoveryInput => ({ id, result });

test('Actuator structured methods and aliases retain case/slash without predicate or handler-path inference', () => {
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE'];
  const source = { ...actDoc([actEntry(methods, ['/Alias', '/Alias/', '/alias'])]),
    unrelated: { $ref: 'https://never-request.invalid/schema', value: 'RAW_SECRET' } };
  const result = act(source);
  assert.equal(result.surfaces.length, 24); assert.equal(new Set(result.surfaces.map(s => s.id)).size, 24);
  assert.deepEqual([...new Set(result.surfaces.map(s => s.method))].sort(), methods.sort());
  assert.equal(result.status, 'partial'); assert.equal(result.counts.declared, null);
  assert.ok(result.surfaces.every(s => s.readiness === 'unresolved' && !s.provenance[0]!.handler));
  assert.equal(result.surfaces[0]!.provenance[0]!.rawInputSha256, metadata.rawInputSha256);
  assert.deepEqual(result.surfaces[0]!.provenance[0]!.sanitizedArtifact, metadata.sanitizedArtifact);
  assert.ok(result.surfaces[0]!.provenance[0]!.locator.startsWith('#/contexts/app/mappings/dispatcherServlets/'));
  assert.equal(JSON.stringify(result).includes('RAW_SECRET'), false);
  assert.equal(JSON.stringify(result).includes('never-request.invalid'), false);
});

test('all-method, opaque, empty and malformed mappings report unknown instead of inventing GET or completeness', () => {
  for (const methods of [[], ['*'], ['*', 'GET']]) {
    const result = act(actDoc([actEntry(methods, ['/alias/', '/alias']), actEntry(['POST'], ['/known'])]));
    const unknown = result.surfaces.filter(s => s.method === '*');
    assert.equal(result.surfaces.length, 3); assert.equal(result.counts.enumerated, 3);
    assert.deepEqual(unknown.map(s => s.pathTemplate), ['/alias', '/alias/']);
    assert.equal(result.surfaces.find(s => s.pathTemplate === '/known')!.method, 'POST');
    assert.equal(result.surfaces.some(s => s.method === 'GET'), false);
    assert.ok(unknown.every(s => s.readiness === 'unresolved'
      && s.reasons.includes('actuator_all_methods_unknown') && s.reasons.includes('method_not_attack_supported')));
    assert.ok(unknown.every(s => s.provenance[0]!.locator.endsWith('/dispatcherServlet/0')));
    assert.ok(unknown.every(s => result.constraints.some(c => c.surfaceId === s.id && c.signature.length === 64)));
    assert.equal(result.status, 'partial'); assert.equal(result.counts.declared, null);
    assert.ok(result.gaps.some(g => g.code === 'actuator_all_methods_unknown'));
  }
  const opaque = act(actDoc([{ predicate: 'GET /guess', handler: 'ignored' }]));
  assert.equal(opaque.counts.enumerated, 0); assert.equal(opaque.counts.declared, null);
  assert.equal(opaque.status, 'partial'); assert.ok(opaque.gaps.some(g => g.code === 'actuator_unstructured_mapping'));
  assert.equal(act(actDoc([])).status, 'partial');
});

test('all-method path markers survive alias ordering and merge without absorbing a concrete GET', () => {
  const before = act(actDoc([actEntry([], ['/alias', '/alias/'])]));
  const reordered = act(actDoc([actEntry([], ['/alias/', '/alias'])]));
  assert.deepEqual(before, reordered);
  const openapi = run(doc({ '/alias': { get: { parameters: [scalar()] } } }));
  const inputs = [discovery('spring-actuator', before), discovery('openapi', openapi)];
  const result = mergeSurfaceInventory(inventoryBinding, inputs);
  assert.equal(result.counts.enumerated, 3); assert.equal(result.counts.declared, null);
  assert.equal(result.surfaces.find(s => s.method === 'GET')!.readiness, 'ready');
  for (const marker of result.surfaces.filter(s => s.method === '*')) {
    assert.equal(marker.id, runtimeSurfaceId('*', marker.pathTemplate));
    assert.equal(marker.readiness, 'unresolved'); assert.ok(marker.reasons.includes('actuator_all_methods_unknown'));
    assert.equal(marker.provenance[0]!.provider, 'spring-actuator');
    assert.equal(marker.provenance[0]!.rawInputSha256, metadata.rawInputSha256);
  }
  assert.deepEqual(result, mergeSurfaceInventory(inventoryBinding, [...inputs].reverse()));
  const claimed = structuredClone(openapi);
  claimed.surfaces[0]!.method = '*'; claimed.surfaces[0]!.id = runtimeSurfaceId('*', '/alias');
  const blocked = mergeSurfaceInventory(inventoryBinding, [discovery('openapi', claimed)]);
  assert.equal(blocked.surfaces[0]!.readiness, 'unresolved');
  assert.ok(blocked.surfaces[0]!.reasons.includes('method_not_attack_supported'));
  const missing = act(actDoc([actEntry([], [])]));
  assert.equal(missing.counts.enumerated, 0); assert.equal(missing.counts.declared, null);
  assert.ok(missing.gaps.some(g => g.code === 'actuator_patterns_unknown'));
});

test('Actuator conditions remain blocking and never preserve raw parameter/header values', () => {
  for (const condition of [
    { headers: [{ name: 'Authorization', negated: false, value: 'RAW_SECRET' }] },
    { params: [{ name: 'q', negated: true, value: 'RAW_SECRET' }] },
    { consumes: [{ mediaType: 'application/xml', negated: false }] },
    { consumes: [{ mediaType: 'RAW_SECRET', negated: false }] },
    { produces: [{ mediaType: 'application/json', negated: true }] },
    { apiVersion: 'future-condition' },
  ]) {
    const result = act(actDoc([actEntry(['GET'], ['/route'], condition)]));
    assert.equal(result.surfaces.length, 1);
    assert.ok(result.surfaces[0]!.reasons.some(r => ['actuator_condition_unsupported', 'actuator_media_unsupported']
      .includes(r))); assert.equal(JSON.stringify(result).toUpperCase().includes('RAW_SECRET'), false);
  }
  const overflow = act(actDoc([actEntry(['GET'], ['/route'], { headers: Array(33).fill({ name: 'x' }) })]));
  assert.equal(overflow.surfaces.length, 1); assert.ok(overflow.surfaces[0]!.reasons.includes('actuator_limit'));
  const duplicate = act(actDoc([actEntry(['GET', 'GET'], ['/route', '/route'])]));
  assert.equal(duplicate.surfaces.length, 1);
  assert.ok(duplicate.surfaces[0]!.reasons.includes('actuator_duplicate_condition'));
});

test('multiple contexts, non-root servlet mappings, dynamic routes and WebFlux retain explicit uncertainty', () => {
  const multiple = actDoc([actEntry()]) as any;
  multiple.contexts.other = actDoc([actEntry(['POST'], ['/other'])]).contexts.app;
  assert.ok(act(multiple).surfaces.every(s => s.reasons.includes('actuator_context_ambiguous')));
  const prefix = actDoc([actEntry()]); prefix.contexts.app.mappings.servlets[0]!.mappings = ['/prefix/*'];
  const result = act(prefix); assert.equal(result.surfaces[0]!.pathTemplate, '/route');
  assert.ok(result.surfaces[0]!.reasons.includes('actuator_base_path_unsupported'));
  const reactive = { contexts: { app: { mappings: { dispatcherHandlers: { webHandler: [actEntry()] } } } } };
  assert.ok(act(reactive).surfaces[0]!.reasons.includes('actuator_base_path_unknown'));
  assert.ok(act(actDoc([actEntry(['GET'], ['/a/{id:[0-9]+}'])])).surfaces[0]!.reasons
    .includes('actuator_dynamic_path'));
});

test('Actuator own-data, document and route expansion limits fail closed without caller code', () => {
  let calls = 0;
  const getter = Object.defineProperty(actDoc([]), 'hidden', { get() { calls++; return 1; }, enumerable: true });
  const proxy = new Proxy({}, { ownKeys() { calls++; throw new Error('must not run'); } });
  const cyclic: any = actDoc([]); cyclic.self = cyclic;
  const deep: any = actDoc([]); let cursor = deep;
  for (let i = 0; i < 41; i++) { cursor.child = {}; cursor = cursor.child; }
  const aliases = Array.from({ length: 64 }, (_, i) => '/a' + i);
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'];
  const huge = actDoc([actEntry(methods, aliases), actEntry(methods, aliases.map(p => '/b' + p))]);
  for (const input of [getter, proxy, cyclic, deep, huge, { ...actDoc([]), huge: 'x'.repeat(1024 * 1024) },
    { ...actDoc([]), nodes: Array(20_001).fill(null) }]) {
    const result = act(input); assert.equal(result.status, 'error');
    assert.equal(result.counts.declared, null); assert.equal(result.counts.enumerated, 0);
  }
  assert.equal(calls, 0);
});

test('pure Inventory complements schema-only uncertainty while keeping provider incompleteness and exact identities', () => {
  const parsed = act(actDoc([actEntry(['GET', 'POST'], ['/search'])]));
  const openapi = run(doc({ '/search': { get: { parameters: [scalar()] }, post: { requestBody: {
    required: true, content: { 'application/json': { schema: { type: 'object', properties: { q: { type: 'string' } } } } },
  } } }, '/search/': { get: { parameters: [scalar()] } } }));
  const inputs = [discovery('spring-actuator', parsed), discovery('openapi', openapi)];
  const result = mergeSurfaceInventory(inventoryBinding, inputs);
  assert.equal(result.surfaces.length, 3); assert.ok(result.surfaces.every(s => s.readiness === 'ready'));
  assert.equal(result.counts.declared, null); assert.equal(result.counts.enumerated, 3);
  assert.deepEqual(result.providers, [{ id: 'openapi', status: 'completed' }, { id: 'spring-actuator', status: 'partial' }]);
  assert.equal(result.surfaces.find(s => s.method === 'POST')!.params[0]!.jsonPointer, '/q');
  assert.ok(result.surfaces.filter(s => s.pathTemplate === '/search').every(s => s.provenance.length === 2));
  assert.equal(result.sourceSha256, inventoryBinding.sourceSha256); assert.deepEqual(result.run, inventoryBinding.run);
  assert.equal('request' in result, false);
  assert.deepEqual(result, mergeSurfaceInventory(inventoryBinding, [...inputs].reverse()));
});

test('Inventory keeps conditional/media/serialization contradictions unresolved and deduplicates provenance', () => {
  const plain = run(doc({ '/route': { get: { parameters: [scalar()] } } }));
  const alternate = run(doc({ '/route': { get: { parameters: [{ ...scalar(), explode: false }] } } }));
  const conflict = mergeSurfaceInventory(inventoryBinding, [discovery('openapi', plain), discovery('openapi', alternate)]);
  assert.ok(conflict.surfaces[0]!.reasons.includes('inventory_parameter_conflict'));
  assert.equal(conflict.surfaces[0]!.readiness, 'unresolved');
  for (const [condition, reason] of [
    [{ headers: [{ name: 'x', negated: false, value: 'RAW_SECRET' }] }, 'actuator_condition_unsupported'],
    [{ consumes: [{ mediaType: 'application/json', negated: false }] }, 'inventory_media_conflict'],
  ] as const) {
    const parsed = act(actDoc([actEntry(['GET'], ['/route'], condition)]));
    const result = mergeSurfaceInventory(inventoryBinding, [discovery('spring-actuator', parsed),
      discovery('openapi', plain), discovery('openapi', plain)]);
    assert.equal(result.surfaces[0]!.readiness, 'unresolved');
    assert.ok(result.surfaces[0]!.reasons.includes(reason)); assert.equal(result.surfaces[0]!.provenance.length, 2);
    assert.equal(JSON.stringify(result).includes('RAW_SECRET'), false);
  }
  const duplicate = mergeSurfaceInventory(inventoryBinding, [discovery('openapi', plain), discovery('openapi', plain)]);
  assert.equal(duplicate.surfaces.length, 1); assert.equal(duplicate.surfaces[0]!.provenance.length, 1);
  assert.equal(duplicate.surfaces[0]!.params.length, 1); assert.equal(duplicate.counts.declared, 1);
  const left = structuredClone(plain), right = structuredClone(plain);
  left.surfaces[0]!.provenance[0]!.handler = { path: 'src/A.java', className: 'A', methodName: 'handle' };
  right.surfaces[0]!.provenance[0]!.handler = { path: 'src/B.java', className: 'B', methodName: 'handle' };
  const handlers = mergeSurfaceInventory(inventoryBinding, [discovery('openapi', left), discovery('openapi', right)]);
  assert.ok(handlers.surfaces[0]!.reasons.includes('inventory_handler_conflict'));
  assert.equal(handlers.surfaces[0]!.readiness, 'unresolved');
});

test('declared JSON consumes can be complemented by the same POST body schema', () => {
  const actuator = act(actDoc([actEntry(['POST'], ['/route'], {
    consumes: [{ mediaType: 'application/json', negated: false }],
  })]));
  const openapi = run(doc({ '/route': { post: { requestBody: { required: true, content: { 'application/json': {
    schema: { type: 'object', required: ['q'], properties: { q: { type: 'string' } } },
  } } } } } }));
  const result = mergeSurfaceInventory(inventoryBinding,
    [discovery('spring-actuator', actuator), discovery('openapi', openapi)]);
  assert.equal(result.surfaces[0]!.readiness, 'ready'); assert.equal(result.surfaces[0]!.params[0]!.jsonPointer, '/q');
  assert.equal(result.counts.declared, null);
});

test('provider errors and null denominators propagate while preserving other known routes', () => {
  const result = mergeSurfaceInventory(inventoryBinding, [discovery('openapi', run({ openapi: 'invalid' })),
    discovery('spring-actuator', act(actDoc([actEntry()]))) ]);
  assert.equal(result.surfaces.length, 1); assert.equal(result.counts.declared, null);
  assert.equal(result.providers.find(p => p.id === 'openapi')!.status, 'error');
  assert.ok(result.gaps.some(g => g.area === 'openapi'));
});

test('Actuator conflicting handler mappings remain unresolved; reordered aliases share a semantic signature', () => {
  const a = actEntry(['GET'], ['/a', '/b']), b = actEntry(['GET'], ['/b', '/a']);
  const same = act(actDoc([a, b]));
  assert.ok(same.surfaces.every(s => !s.reasons.includes('actuator_conflicting_mapping')));
  b.details.handlerMethod.name = 'other';
  const different = act(actDoc([a, b]));
  assert.ok(different.surfaces.every(s => s.reasons.includes('actuator_conflicting_mapping')));
});

test('Inventory rejects malformed binding, producer masquerading, tampered identities and executable data', () => {
  const source = discovery('openapi', run(doc()));
  const forged: any = structuredClone(source); forged.result.surfaces[0].id = '0'.repeat(64);
  assert.throws(() => mergeSurfaceInventory(inventoryBinding, [forged]), /invalid_surface_inventory/);
  assert.throws(() => mergeSurfaceInventory({ ...inventoryBinding, sourceSha256: 'not-sha' }, [source]));
  assert.throws(() => mergeSurfaceInventory(inventoryBinding, [{ ...source, id: 'spring-actuator' }]));
  const falseComplete = discovery('spring-actuator', { ...act(actDoc([actEntry()])), status: 'completed' });
  assert.throws(() => mergeSurfaceInventory(inventoryBinding, [falseComplete]));
  let calls = 0;
  const accessor = Object.defineProperty({}, 'id', { enumerable: true, get() { calls++; return 'openapi'; } });
  assert.throws(() => mergeSurfaceInventory(inventoryBinding, [accessor as DiscoveryInput]));
  assert.equal(calls, 0);
});

test('both unchanged R8 business route lists match inline Actuator contracts, without live-response/recall claims', async () => {
  for (const file of ['primary-ground-truth.json', 'jdbc-ground-truth.json']) {
    const truth = JSON.parse(await readFile('tests/fixtures/runtime-m1/' + file, 'utf8'));
    const result = act(actDoc(truth.routes.map((r: any) => actEntry([r.method], [r.path]))));
    assert.equal(result.counts.enumerated, truth.declaredBusinessRoutes);
    assert.deepEqual(result.surfaces.map(s => `${s.method} ${s.pathTemplate}`).sort(),
      truth.routes.map((r: any) => `${r.method} ${r.path}`).sort());
    assert.ok(result.surfaces.every(s => s.params.length === 0 && !s.provenance[0]!.handler));
  }
});
