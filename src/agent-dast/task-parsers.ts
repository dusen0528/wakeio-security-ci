import type { ExecutionTask } from './plan.js';
import { alias, count, fail, keys } from './plan-validation.js';

type Task<E extends ExecutionTask['engine']> = Extract<ExecutionTask, { engine: E }>;
export interface ExecutionTaskDescriptor<T extends ExecutionTask = ExecutionTask> {
  id: T['engine'];
  category: 'injection' | 'config';
  reportMode: 'url' | 'api';
  parseTask(raw: Record<string, unknown>): T;
  requiredInputs(task: T): readonly string[];
}

function policyTask<E extends 'native-dast' | 'zap'>(raw: Record<string, unknown>, engine: E, max: number) {
  if (raw.engine !== engine) fail();
  keys(raw, ['id', 'engine', 'policy', 'maxRequests']); alias(raw.policy); count(raw.maxRequests, max);
  return { id: raw.id as string, engine, policy: raw.policy, maxRequests: raw.maxRequests };
}

export const nativeDastTask = Object.freeze<ExecutionTaskDescriptor<Task<'native-dast'>>>({
  id: 'native-dast', category: 'injection', reportMode: 'url',
  parseTask: raw => policyTask(raw, 'native-dast', 64),
  requiredInputs: task => [task.policy],
});

export const schemathesisTask = Object.freeze<ExecutionTaskDescriptor<Task<'schemathesis'>>>({
  id: 'schemathesis', category: 'config', reportMode: 'api',
  parseTask(raw) {
    if (raw.engine !== 'schemathesis') fail();
    keys(raw, ['id', 'engine', 'schema', 'operations', 'seed', 'maxRequests'], ['authPolicy']);
    alias(raw.schema); if (Object.hasOwn(raw, 'authPolicy')) alias(raw.authPolicy);
    count(raw.seed, 2147483647); count(raw.maxRequests, 64);
    if (!Array.isArray(raw.operations) || !raw.operations.length || raw.operations.length > 16
      || new Set(raw.operations).size !== raw.operations.length
      || raw.operations.some(path => typeof path !== 'string' || !path.startsWith('/')
        || path.length > 2048 || /[\u0000-\u0020\u007f?#\\]/.test(path))) fail();
    return { id: raw.id as string, engine: 'schemathesis', schema: raw.schema,
      operations: raw.operations as string[], seed: raw.seed, maxRequests: raw.maxRequests,
      ...(typeof raw.authPolicy === 'string' ? { authPolicy: raw.authPolicy } : {}) };
  },
  requiredInputs: task => [task.schema, ...(task.authPolicy ? [task.authPolicy] : [])],
});

export const nucleiTask = Object.freeze<ExecutionTaskDescriptor<Task<'nuclei'>>>({
  id: 'nuclei', category: 'config', reportMode: 'url',
  parseTask(raw) {
    if (raw.engine !== 'nuclei') fail();
    keys(raw, ['id', 'engine', 'scopes', 'maxRequests']); count(raw.maxRequests, 20_000);
    if (!Array.isArray(raw.scopes) || !raw.scopes.length || raw.scopes.length > 2
      || new Set(raw.scopes).size !== raw.scopes.length
      || raw.scopes.some(scope => scope !== 'misconfiguration' && scope !== 'exposures')) fail();
    return { id: raw.id as string, engine: 'nuclei',
      scopes: raw.scopes as Array<'misconfiguration' | 'exposures'>, maxRequests: raw.maxRequests };
  },
  requiredInputs: () => [],
});

export const zapTask = Object.freeze<ExecutionTaskDescriptor<Task<'zap'>>>({
  id: 'zap', category: 'injection', reportMode: 'url',
  parseTask: raw => policyTask(raw, 'zap', 2000),
  requiredInputs: task => [task.policy],
});

/** Data-only v1 metadata; importing a plan never loads an execution adapter. */
export const EXECUTION_TASKS = Object.freeze([nativeDastTask, schemathesisTask, nucleiTask, zapTask]);
export type AttackEngineId = typeof EXECUTION_TASKS[number]['id'];

export function taskDescriptor(id: unknown): ExecutionTaskDescriptor {
  const descriptor = EXECUTION_TASKS.find(candidate => candidate.id === id);
  if (!descriptor) fail();
  return descriptor;
}
