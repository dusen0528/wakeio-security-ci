import {
  dastDefaultMaxRequests, parseDastPolicy, prepareDastPolicy, runDast, snapshotDastEnvironment,
} from '../dast.js';
import { runSchemathesisLive } from '../schemathesis-live.js';
import { parseSchemathesisAuthPolicy, snapshotSchemathesisCredential } from '../schemathesis-auth.js';
import { validateSchemathesisAuthSchema } from '../schemathesis-auth-run.js';
import { selectOpenApiLiveOperations } from '../openapi.js';
import { runNuclei } from '../nuclei.js';
import { runZap } from '../zap.js';
import { prepareZapPolicy } from '../zap-policy.js';
import type { ExecutionTask } from './plan.js';
import type { RegisteredAttackEngine } from '../runtime/types.js';

type Task<E extends ExecutionTask['engine']> = Extract<ExecutionTask, { engine: E }>;
function defineEngine<T extends ExecutionTask>(definition: RegisteredAttackEngine<T>) {
  return Object.freeze(definition);
}
function fail(): never { throw new TypeError('invalid_execution_plan'); }
function invalid(): never { throw new TypeError('invalid_run_plan'); }
function keys(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some(key => !Object.hasOwn(value, key))
    || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) fail();
}
function alias(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9_-]{0,39}$/.test(value)) fail();
}
function count(value: unknown, max: number): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > max) fail();
}
function policyTask<E extends 'native-dast' | 'zap'>(raw: Record<string, unknown>, engine: E, max: number) {
  if (raw.engine !== engine) fail();
  keys(raw, ['id', 'engine', 'policy', 'maxRequests']); alias(raw.policy); count(raw.maxRequests, max);
  return { id: raw.id as string, engine, policy: raw.policy, maxRequests: raw.maxRequests };
}

export const nativeDastEngine = defineEngine<Task<'native-dast'>>({
  id: 'native-dast', category: 'injection', reportMode: 'url',
  parseTask: raw => policyTask(raw, 'native-dast', 64),
  requiredInputs: task => [task.policy],
  prepare(task, data, options) {
    const parsed = parseDastPolicy(data.get(task.policy));
    const env = snapshotDastEnvironment(parsed.policy, options.env);
    const { policy } = prepareDastPolicy(parsed.policy, { allowPrivate: options.allowPrivate, env });
    if (new URL(policy.baseUrl).origin !== options.plan.origin
      || task.maxRequests < dastDefaultMaxRequests(policy)) invalid();
    return { task, policy, env };
  },
  execute(prepared, options, runtime, remaining) {
    return runDast({ policy: prepared.policy!, env: prepared.env, consent: true, allowPrivate: options.allowPrivate,
      maxRequests: prepared.task.maxRequests, timeoutMs: Math.min(remaining, 120_000),
      signal: options.signal }, runtime);
  },
  complete: (_prepared, check) => check.dastExecution?.status === 'complete',
  findingPath: (_prepared, url) => url.pathname,
});

export const schemathesisEngine = defineEngine<Task<'schemathesis'>>({
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
  prepare(task, data, options) {
    const selection = selectOpenApiLiveOperations(data.get(task.schema),
      task.operations.map(path => ({ method: 'GET' as const, path })));
    if (!task.authPolicy) {
      // The legacy CONNECT lane cannot attest a shared HTTPS HTTP request denominator.
      if (new URL(options.plan.origin).protocol === 'https:') invalid();
      return { task, document: selection.document };
    }
    const { policy } = parseSchemathesisAuthPolicy(data.get(task.authPolicy));
    if (new URL(policy.baseUrl).origin !== options.plan.origin || policy.operations.length !== task.operations.length
      || task.operations.some(path => !policy.operations.some(operation => operation.path === path))
      || task.maxRequests < 2 + 4 * task.operations.length) invalid();
    validateSchemathesisAuthSchema(selection);
    if (new URL(policy.baseUrl).protocol === 'http:' && (!options.allowPrivate
      || !['127.0.0.1', '[::1]'].includes(new URL(policy.baseUrl).hostname))) invalid();
    const credential = snapshotSchemathesisCredential(policy, options.env);
    return { task, document: selection.document, authPolicy: policy, env: { [policy.authorizationEnv]: credential } };
  },
  execute(prepared, options, runtime, remaining) {
    const task = prepared.task;
    return runSchemathesisLive({ document: prepared.document, baseUrl: `${options.plan.origin}/`,
      operations: task.operations.map(path => ({ method: 'GET' as const, path })),
      ...(prepared.authPolicy ? { authPolicy: prepared.authPolicy, env: prepared.env } : {}),
      consent: true, allowPrivate: options.allowPrivate, python: options.schemathesisPython,
      maxRequests: task.maxRequests, timeoutMs: Math.min(remaining, 120_000), seed: task.seed,
      signal: options.signal }, runtime);
  },
  complete(prepared, check, observed) {
    if (prepared.authPolicy) return check.schemathesisAuth?.status === 'completed'
      && check.schemathesisAuth.requests.attempted === observed.requestCount;
    return check.metrics?.operationsExercised === prepared.task.operations.length;
  },
  findingPath(prepared, url) {
    const template = prepared.task.operations.find(candidate => candidate === url.pathname
      || new URL(candidate, url.origin).pathname === url.pathname);
    if (!template) invalid(); return template;
  },
});

export const nucleiEngine = defineEngine<Task<'nuclei'>>({
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
  prepare(task, _data, options) {
    if (!options.nucleiTemplates || new URL(options.plan.origin).protocol === 'https:') invalid();
    return { task };
  },
  execute(prepared, options, runtime, remaining) {
    return runNuclei({ url: `${options.plan.origin}/`, executable: options.nucleiPath,
      templatesDir: options.nucleiTemplates!, scopes: prepared.task.scopes, consent: true,
      allowPrivate: options.allowPrivate, maxRequests: prepared.task.maxRequests, rateLimit: options.ratePerSecond,
      timeoutMs: Math.min(remaining, 600_000), signal: options.signal }, runtime);
  },
  complete: () => true,
  findingPath: (_prepared, url) => url.pathname,
});

export const zapEngine = defineEngine<Task<'zap'>>({
  id: 'zap', category: 'injection', reportMode: 'url',
  parseTask: raw => policyTask(raw, 'zap', 2000),
  requiredInputs: task => [task.policy],
  prepare(task, data, options) {
    const prepared = prepareZapPolicy(data.get(task.policy), options.allowPrivate, options.env);
    if (prepared.policy.origin !== options.plan.origin || options.ratePerSecond > 50
      || task.maxRequests < prepared.requests.length * (prepared.policy.version === 2 ? 2 : 1)
        + (prepared.policy.authentication ? 3 : 0) + (prepared.loginEnv ? 1 : 0) + 1) invalid();
    return { task, zapPolicy: prepared.policy, zapRequests: prepared.requests,
      env: prepared.loginEnv ?? (prepared.policy.authentication
        && 'authorizationEnv' in prepared.policy.authentication
        ? { [prepared.policy.authentication.authorizationEnv]: prepared.authorization } : {}) };
  },
  execute(prepared, options, runtime, remaining) {
    return runZap({ url: options.plan.origin, policy: prepared.zapPolicy!, env: prepared.env,
      executable: options.zapPath, consent: true, allowPrivate: options.allowPrivate,
      maxRequests: prepared.task.maxRequests, rateLimit: options.ratePerSecond,
      timeoutMs: Math.min(remaining, 600_000), signal: options.signal }, runtime);
  },
  complete: () => true,
  findingPath: (_prepared, url) => url.pathname,
});
