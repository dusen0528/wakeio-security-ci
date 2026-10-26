import assert from 'node:assert/strict';
import test from 'node:test';
import type { CheckResult } from '../src/contracts.js';
import type { AdmissionSnapshot } from '../src/agent-dast/admission.js';
import { parseExecutionPlan, type ExecutionTask } from '../src/agent-dast/plan.js';
import { ATTACK_ENGINES, attackEngine } from '../src/runtime/registry.js';
import type { PreparedAttackTask } from '../src/runtime/types.js';

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
  for (const engine of ATTACK_ENGINES) {
    assert.ok(Object.isFrozen(engine)); assert.equal(attackEngine(engine.id), engine);
  }
  for (const id of ['browser', '__proto__', null, {}, ['zap']]) {
    assert.throws(() => attackEngine(id), /invalid_execution_plan/);
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

test('engine completion and finding paths retain native and authenticated Schemathesis distinctions', () => {
  const observed = { requestCount: 8 } as AdmissionSnapshot;
  const check: CheckResult = { id: 'owned', status: 'completed', findings: [], notes: [],
    metrics: { operationsExercised: 1 } };
  const prepared: PreparedAttackTask = { task: tasks[1] };
  assert.equal(attackEngine('schemathesis').complete(prepared, check, observed), true);
  assert.equal(attackEngine('schemathesis').complete(prepared, { ...check, metrics: {} }, observed), false);
  prepared.authPolicy = {} as NonNullable<PreparedAttackTask['authPolicy']>;
  assert.equal(attackEngine('schemathesis').complete(prepared, check, observed), false);
  check.schemathesisAuth = { status: 'completed', requests: { attempted: 8 } } as CheckResult['schemathesisAuth'];
  assert.equal(attackEngine('schemathesis').complete(prepared, check, observed), true);
  assert.equal(attackEngine('schemathesis').complete(prepared, check, { ...observed, requestCount: 7 }), false);
  assert.equal(attackEngine('native-dast').complete({ task: tasks[0] }, check, observed), false);
  check.dastExecution = { status: 'complete' } as CheckResult['dastExecution'];
  assert.equal(attackEngine('native-dast').complete({ task: tasks[0] }, check, observed), true);
  for (const task of tasks.slice(2)) assert.equal(attackEngine(task.engine).complete({ task }, check, observed), true);
  assert.equal(attackEngine('schemathesis').findingPath(prepared,
    new URL('http://127.0.0.1/items/%7Bid%7D')), '/items/{id}');
  assert.throws(() => attackEngine('schemathesis').findingPath(prepared,
    new URL('http://127.0.0.1/other')), /invalid_run_plan/);
});
