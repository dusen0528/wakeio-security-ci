import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import * as ts from 'typescript';
import type { CheckResult, Finding } from '../src/contracts.js';
import type { AdmissionSnapshot } from '../src/agent-dast/admission.js';
import { parseExecutionPlan, type ExecutionTask } from '../src/agent-dast/plan.js';
import { ATTACK_ENGINES, attackEngine } from '../src/runtime/registry.js';
import { EXECUTION_TASKS, taskDescriptor } from '../src/agent-dast/task-parsers.js';
import type { AttackContext } from '../src/runtime/types.js';
import { zapSurfaceKey } from '../src/zap-policy.js';

const tasks: ExecutionTask[] = [
  { id: 't-native', engine: 'native-dast', policy: 'native', maxRequests: 64 },
  { id: 't-schema', engine: 'schemathesis', schema: 'schema', authPolicy: 'auth',
    operations: ['/items/{id}'], seed: 1, maxRequests: 64 },
  { id: 't-nuclei', engine: 'nuclei', scopes: ['misconfiguration', 'exposures'], maxRequests: 20000 },
  { id: 't-zap', engine: 'zap', policy: 'zap', maxRequests: 2000 },
];
const plan = (selected: unknown[]) => ({
  version: 1, kind: 'wakeio.execution-plan', origin: 'http://127.0.0.1', tasks: selected,
});

test('runtime registry has exactly the four immutable v1 engine identities', () => {
  assert.deepEqual(ATTACK_ENGINES.map(engine => engine.id), ['native-dast', 'schemathesis', 'nuclei', 'zap']);
  assert.equal(new Set(ATTACK_ENGINES.map(engine => engine.id)).size, 4);
  assert.ok(Object.isFrozen(ATTACK_ENGINES));
  assert.ok(Object.isFrozen(EXECUTION_TASKS));
  assert.deepEqual(EXECUTION_TASKS.map(descriptor => descriptor.id), ATTACK_ENGINES.map(engine => engine.id));
  for (const engine of ATTACK_ENGINES) {
    assert.ok(Object.isFrozen(engine)); assert.equal(attackEngine(engine.id), engine);
    const descriptor = taskDescriptor(engine.id);
    assert.ok(Object.isFrozen(descriptor));
    assert.equal(engine.parseTask, descriptor.parseTask);
    assert.equal(engine.requiredInputs, descriptor.requiredInputs);
    assert.equal(engine.category, descriptor.category); assert.equal(engine.reportMode, descriptor.reportMode);
  }
  for (const id of ['browser', '__proto__', null, {}, ['zap']]) {
    assert.throws(() => attackEngine(id), /invalid_execution_plan/);
    assert.throws(() => taskDescriptor(id), /invalid_execution_plan/);
  }
});

test('emitted plan and provider recording imports exclude engine execution and network modules', async () => {
  for (const entry of ['plan', 'providers/record']) {
    const pending = [new URL(`../src/agent-dast/${entry}.js`, import.meta.url).href];
    const graph = new Set<string>();
    while (pending.length) {
      const url = pending.pop()!;
      if (graph.has(url)) continue;
      graph.add(url);
      const source = ts.createSourceFile(url, await readFile(new URL(url), 'utf8'), ts.ScriptTarget.ES2022);
      for (const statement of source.statements) {
        const specifier = ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)
          ? statement.moduleSpecifier : undefined;
        if (!specifier || !ts.isStringLiteral(specifier)) continue;
        if (specifier.text.startsWith('.')) pending.push(new URL(specifier.text, url).href);
        else graph.add(specifier.text);
      }
    }
    assert.ok([...graph].some(url => url.endsWith('/agent-dast/task-parsers.js')));
    for (const module of graph) {
      assert.doesNotMatch(module, /(?:engine-adapters|schemathesis(?:-live)?|runtime\/registry)\.js$/);
      assert.doesNotMatch(module, /^node:(?:child_process|net|https?|http2|tls|dgram)$/);
    }
  }
});

test('registry parsers preserve exact v1 task data, request bounds and input SHA grant aliases', () => {
  assert.deepEqual(parseExecutionPlan(plan(tasks)).tasks, tasks);
  assert.deepEqual(tasks.map(task => attackEngine(task.engine).requiredInputs(task)),
    [['native'], ['schema', 'auth'], [], ['zap']]);
  const schemaOnly = { ...tasks[1] } as Extract<ExecutionTask, { engine: 'schemathesis' }>;
  delete schemaOnly.authPolicy;
  assert.deepEqual(attackEngine('schemathesis').requiredInputs(schemaOnly), ['schema']);
  for (const task of tasks) {
    const invalidFields = [{ maxRequests: task.maxRequests + 1 }, { maxRequests: 0 },
      { provider: 'custom' }, { executable: '/caller' }];
    for (const change of invalidFields) {
      assert.throws(() => parseExecutionPlan(plan([{ ...task, ...change }])), /invalid_execution_plan/);
    }
    const missing = { ...task } as Record<string, unknown>; delete missing.maxRequests;
    assert.throws(() => parseExecutionPlan(plan([missing])), /invalid_execution_plan/);
  }
  for (const operations of [[], ['/same', '/same'], ['/items?q=1'], ['relative']]) {
    assert.throws(() => parseExecutionPlan(plan([{ ...tasks[1], operations }])), /invalid_execution_plan/);
  }
  for (const scopes of [[], ['unknown'], ['exposures', 'exposures']]) {
    assert.throws(() => parseExecutionPlan(plan([{ ...tasks[2], scopes }])), /invalid_execution_plan/);
  }
  assert.throws(() => parseExecutionPlan(plan([{ ...tasks[0], policy: '../file' }])), /invalid_execution_plan/);
  assert.throws(() => parseExecutionPlan(plan([{ ...tasks[1], authPolicy: '' }])), /invalid_execution_plan/);
});

const origin = 'http://127.0.0.1';
const identity = { path: '/whoami', status: 200, jsonPointer: '/id', equals: 'owner' };
const authentication = { authorizationEnv: 'OWNED_AUTH', identity };
const nativePolicy = { version: 1, kind: 'sql-boolean-differential', baseUrl: origin,
  url: `${origin}/items?id=1`, parameter: 'id', profile: 'numeric',
  oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
const schema = { openapi: '3.0.3', info: { title: 'Owned v1 mapping', version: '1' }, paths: {
  '/items/{id}': { get: { parameters: [{ name: 'id', in: 'path', required: true,
    schema: { type: 'integer', enum: [1, 2] } }], responses: { '200': { description: 'owned' } } } },
} };
const authPolicy = { version: 1, kind: 'schemathesis-get-auth', baseUrl: origin, ...authentication,
  operations: [{ path: '/items/{id}', normal: { path: '/items/1', status: 200, jsonPointer: '/id', equals: 1 } }] };
const zapPolicy = { version: 1, kind: 'zap-active', origin, ...{ authentication },
  requests: [{ method: 'GET', path: '/items?id=1' }] };
function prepare(task: ExecutionTask, data: Record<string, unknown>) {
  const context: AttackContext = { plan: parseExecutionPlan(plan([task])), allowPrivate: true,
    ratePerSecond: 10, nucleiTemplates: '/owned/templates', env: { OWNED_AUTH: 'Bearer owned-test-credential' } };
  return attackEngine(task.engine).prepare(task, new Map(Object.entries(data)), context);
}
function finding(url?: string): Finding {
  return { ruleId: 'owned', title: 'owned', description: 'owned', severity: 'medium', confidence: 'low',
    kind: 'candidate', location: url ? { url } : {}, remediation: 'review' };
}

test('opaque handles retain native and authenticated Schemathesis completion and template distinctions', () => {
  const observed = { requestCount: 8 } as AdmissionSnapshot;
  const check: CheckResult = { id: 'owned', status: 'completed', findings: [], notes: [],
    metrics: { operationsExercised: 1 } };
  const schemaOnly: ExecutionTask = { id: 't-schema', engine: 'schemathesis', schema: 'schema',
    operations: ['/items/{id}'], seed: 1, maxRequests: 64 };
  const anonymous = prepare(schemaOnly, { schema });
  assert.equal(anonymous.complete(check, observed), true);
  assert.equal(anonymous.complete({ ...check, metrics: {} }, observed), false);
  const authenticated = prepare(tasks[1], { schema, auth: authPolicy });
  assert.equal(authenticated.complete(check, observed), false);
  check.schemathesisAuth = { status: 'completed', requests: { attempted: 8 } } as CheckResult['schemathesisAuth'];
  assert.equal(authenticated.complete(check, observed), true);
  assert.equal(authenticated.complete(check, { ...observed, requestCount: 7 }), false);
  const native = prepare(tasks[0], { native: nativePolicy });
  assert.equal(native.complete(check, observed), false);
  check.dastExecution = { status: 'complete' } as CheckResult['dastExecution'];
  assert.equal(native.complete(check, observed), true);
  assert.equal(prepare(tasks[2], {}).complete(check, observed), true);
  assert.equal(prepare(tasks[3], { zap: zapPolicy }).complete(check, observed), true);
  assert.equal(authenticated.findingSurface(finding(`${origin}/items/%7Bid%7D`)).path, '/items/{id}');
  assert.equal(authenticated.findingSurface(finding(`${origin}/items/%7Bid%7D`)).authState, 'user');
  assert.equal(anonymous.findingSurface(finding(`${origin}/items/%7Bid%7D`)).authState, 'anonymous');
  assert.throws(() => authenticated.findingSurface(finding(`${origin}/other`)), /invalid_run_plan/);
  assert.throws(() => authenticated.findingSurface(finding()), /invalid_run_plan/);
  assert.deepEqual(Object.keys(authenticated), ['task', 'execute', 'complete', 'findingSurface']);
  assert.ok(Object.isFrozen(authenticated));
  assert.equal(JSON.stringify(authenticated).includes('owned-test-credential'), false);
});

test('adapter-owned surfaces preserve native GET/POST and ZAP query/nested pointer authentication', () => {
  const native = prepare(tasks[0], { native: nativePolicy });
  assert.deepEqual(native.findingSurface(finding()), { surfaceId: '', method: 'GET', path: '/items',
    param: 'id', location: 'query', authState: 'anonymous' });
  const postPolicy = { ...nativePolicy, version: 4, method: 'POST', url: `${origin}/items`,
    body: { id: '1' }, alternate: { value: '2', expected: 1 },
    oracle: { jsonPointer: '/count', expectedBaseline: 2, expectedTrue: 2, expectedFalse: 0 }, ...authentication };
  assert.deepEqual(prepare(tasks[0], { native: postPolicy }).findingSurface(finding()),
    { surfaceId: '', method: 'POST', path: '/items', param: 'id', location: 'body', authState: 'user' });
  const query = prepare(tasks[3], { zap: zapPolicy });
  const queryFinding = { ...finding(`${origin}/items?id=1`), ruleId: 'zap.40018',
    comparisonKey: zapSurfaceKey('40018', { method: 'GET', path: '/items?id=1' }, 'id') };
  assert.deepEqual(query.findingSurface(queryFinding), { surfaceId: '', method: 'GET', path: '/items',
    param: 'id', location: 'query', authState: 'user' });
  const nestedPolicy = { version: 2, kind: 'zap-active', origin, authentication,
    openapi: { document: { openapi: '3.0.3', info: { title: 'Owned nested mapping', version: '1' }, paths: {
      '/filter': { post: { requestBody: { required: true, content: { 'application/json': { schema: {
        type: 'object', required: ['filter', 'tags'], properties: {
          filter: { type: 'object', required: ['name'], properties: { name: { type: 'string', default: 'owned' } } },
          tags: { type: 'array', items: { type: 'string', default: 'daily' }, minItems: 1, maxItems: 1 },
        },
      } } } }, responses: { '200': { description: 'owned' } } } },
    } }, operations: [{ method: 'POST', path: '/filter' }] } };
  const nested = prepare(tasks[3], { zap: nestedPolicy });
  for (const pointer of ['/filter/name', '/tags/0']) {
    const nestedFinding = { ...finding(`${origin}/filter`), ruleId: 'zap.40018',
      comparisonKey: zapSurfaceKey('40018', { method: 'POST', path: '/filter' }, pointer) };
    assert.deepEqual(nested.findingSurface(nestedFinding), { surfaceId: '', method: 'POST', path: '/filter',
      param: pointer, location: 'body', authState: 'user' });
  }
  assert.throws(() => nested.findingSurface({ ...queryFinding, comparisonKey: 'unknown' }), /invalid_run_plan/);
  assert.throws(() => nested.findingSurface(finding()), /invalid_run_plan/);
  const nuclei = prepare(tasks[2], {});
  assert.deepEqual(nuclei.findingSurface(finding(`${origin}/config`)),
    { surfaceId: '', method: 'GET', path: '/config', authState: 'anonymous' });
  assert.throws(() => nuclei.findingSurface(finding()), /invalid_run_plan/);
});
