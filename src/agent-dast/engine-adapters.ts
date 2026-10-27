import {
  dastDefaultMaxRequests, hasDastAuthentication, parseDastPolicy, prepareDastPolicy, runDast,
  snapshotDastEnvironment, type DastPolicy,
} from '../dast.js';
import { runSchemathesisLive } from '../schemathesis-live.js';
import { parseSchemathesisAuthPolicy, snapshotSchemathesisCredential,
  type SchemathesisAuthPolicy } from '../schemathesis-auth.js';
import { validateSchemathesisAuthSchema } from '../schemathesis-auth-run.js';
import { selectOpenApiLiveOperations } from '../openapi.js';
import { runNuclei } from '../nuclei.js';
import { runZap } from '../zap.js';
import { prepareZapPolicy, zapSurfaceKey, type ZapPolicyInput } from '../zap-policy.js';
import type { ZapCompiledRequest } from '../zap-openapi.js';
import type { CheckResult, Finding } from '../contracts.js';
import type { AdmissionSnapshot, TaskAdmission } from './admission.js';
import type { NewSurface } from './store.js';
import type { ExecutionTask } from './plan.js';
import type { AttackContext, RegisteredAttackEngine } from '../runtime/types.js';
import { nativeDastTask, nucleiTask, schemathesisTask, zapTask } from './task-parsers.js';

type Task<E extends ExecutionTask['engine']> = Extract<ExecutionTask, { engine: E }>;
type NativeState = { task: Task<'native-dast'>; policy: DastPolicy; env?: NodeJS.ProcessEnv };
type SchemaState = { task: Task<'schemathesis'>; document: unknown;
  authPolicy?: SchemathesisAuthPolicy; env?: NodeJS.ProcessEnv };
type NucleiState = { task: Task<'nuclei'> };
type ZapState = { task: Task<'zap'>; zapPolicy: ZapPolicyInput;
  zapRequests: ZapCompiledRequest[]; env: NodeJS.ProcessEnv };
interface EngineDefinition<T extends ExecutionTask, State> extends Omit<RegisteredAttackEngine<T>, 'prepare'> {
  prepare(task: T, data: ReadonlyMap<string, unknown>, options: AttackContext): State;
  execute(state: State, options: AttackContext, runtime: TaskAdmission, remaining: number): Promise<CheckResult[]>;
  complete(state: State, check: CheckResult, observed: AdmissionSnapshot): boolean;
  findingSurface(state: State, finding: Finding): NewSurface;
}
function defineEngine<T extends ExecutionTask, State>(
  definition: EngineDefinition<T, State>,
): RegisteredAttackEngine<T> {
  Object.freeze(definition);
  const engine: RegisteredAttackEngine<T> = {
    id: definition.id, category: definition.category, reportMode: definition.reportMode,
    parseTask: definition.parseTask, requiredInputs: definition.requiredInputs,
    prepare(task, data, options) {
      const state = definition.prepare(task, data, options);
      return Object.freeze({ task,
        execute: (context: AttackContext, runtime: TaskAdmission, remaining: number) =>
          definition.execute(state, context, runtime, remaining),
        complete: (check: CheckResult, observed: AdmissionSnapshot) => definition.complete(state, check, observed),
        findingSurface: (finding: Finding) => definition.findingSurface(state, finding),
      });
    },
  };
  return Object.freeze(engine);
}
function invalid(): never { throw new TypeError('invalid_run_plan'); }
function findingUrl(finding: Finding): URL {
  if (!finding.location.url) invalid();
  return new URL(finding.location.url);
}
export const nativeDastEngine = defineEngine<Task<'native-dast'>, NativeState>({
  ...nativeDastTask,
  prepare(task, data, options) {
    const parsed = parseDastPolicy(data.get(task.policy));
    const env = snapshotDastEnvironment(parsed.policy, options.env);
    const { policy } = prepareDastPolicy(parsed.policy, { allowPrivate: options.allowPrivate, env });
    if (new URL(policy.baseUrl).origin !== options.plan.origin
      || task.maxRequests < dastDefaultMaxRequests(policy)) invalid();
    return { task, policy, env };
  },
  execute(prepared, options, runtime, remaining) {
    return runDast({ policy: prepared.policy, env: prepared.env, consent: true, allowPrivate: options.allowPrivate,
      maxRequests: prepared.task.maxRequests, timeoutMs: Math.min(remaining, 120_000),
      signal: options.signal }, runtime);
  },
  complete: (_prepared, check) => check.dastExecution?.status === 'complete',
  findingSurface(prepared) {
    const policy = prepared.policy;
    return { surfaceId: '', method: policy.version === 4 ? 'POST' : 'GET', path: new URL(policy.url).pathname,
      param: policy.parameter, location: policy.version === 4 ? 'body' : 'query',
      authState: hasDastAuthentication(policy) ? 'user' : 'anonymous' };
  },
});

export const schemathesisEngine = defineEngine<Task<'schemathesis'>, SchemaState>({
  ...schemathesisTask,
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
  findingSurface(prepared, finding) {
    const url = findingUrl(finding);
    const template = prepared.task.operations.find(candidate => candidate === url.pathname
      || new URL(candidate, url.origin).pathname === url.pathname);
    if (!template) invalid();
    return { surfaceId: '', method: 'GET', path: template, authState: prepared.authPolicy ? 'user' : 'anonymous' };
  },
});

export const nucleiEngine = defineEngine<Task<'nuclei'>, NucleiState>({
  ...nucleiTask,
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
  findingSurface: (_prepared, finding) =>
    ({ surfaceId: '', method: 'GET', path: findingUrl(finding).pathname, authState: 'anonymous' }),
});

export const zapEngine = defineEngine<Task<'zap'>, ZapState>({
  ...zapTask,
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
    return runZap({ url: options.plan.origin, policy: prepared.zapPolicy, env: prepared.env,
      executable: options.zapPath, consent: true, allowPrivate: options.allowPrivate,
      maxRequests: prepared.task.maxRequests, rateLimit: options.ratePerSecond,
      timeoutMs: Math.min(remaining, 600_000), signal: options.signal }, runtime);
  },
  complete: () => true,
  findingSurface(prepared, finding) {
    const url = findingUrl(finding);
    for (const request of prepared.zapRequests) {
      const selected = new URL(request.path, prepared.zapPolicy.origin);
      if (url.origin !== selected.origin || url.pathname !== selected.pathname) continue;
      const params = request.method === 'POST' ? Object.keys(request.body!) : [...selected.searchParams.keys()];
      const parameter = params.find(param => zapSurfaceKey(finding.ruleId.replace(/^zap\./, ''), request,
        request.fields?.find(field => field.alias === param)?.pointer ?? param) === finding.comparisonKey);
      if (parameter !== undefined) return { surfaceId: '', method: request.method, path: selected.pathname,
        param: request.fields?.find(field => field.alias === parameter)?.pointer ?? parameter,
        location: request.method === 'POST' ? 'body' : 'query',
        authState: prepared.zapPolicy.authentication ? 'user' : 'anonymous' };
    }
    invalid();
  },
});
