import { snapshotJsonData } from '../json-snapshot.js';

export const EXECUTION_PLAN_KIND = 'wakeio.execution-plan' as const;
export const EXECUTION_PLAN_MAX_TASKS = 16;
export const EXECUTION_INPUT_MAX_BYTES = 1024 * 1024;
export const EXECUTION_TASK_ID = /^t-[a-z0-9-]{1,40}$/;
const ALIAS = /^[a-z][a-z0-9_-]{0,39}$/;
export type ExecutionEngine = 'native-dast' | 'schemathesis' | 'nuclei';
export type ExecutionTask =
  | { id: string; engine: 'native-dast'; policy: string; maxRequests: number }
  | { id: string; engine: 'schemathesis'; schema: string; authPolicy?: string; operations: string[]; seed: number; maxRequests: number }
  | { id: string; engine: 'nuclei'; scopes: Array<'misconfiguration' | 'exposures'>; maxRequests: number };
export interface ExecutionPlan { version: 1; kind: typeof EXECUTION_PLAN_KIND; origin: string; tasks: ExecutionTask[] }
export interface ExecutionInput { id: string; path: string; sha256: string }
export interface ExecutionInputs { version: 1; inputs: ExecutionInput[] }
function fail(): never { throw new TypeError('invalid_execution_plan'); }
function object(value: unknown): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
}
function keys(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) fail();
}
function alias(value: unknown): asserts value is string { if (typeof value !== 'string' || !ALIAS.test(value)) fail(); }
function count(value: unknown, max: number): asserts value is number { if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > max) fail(); }
/** Exact origin only; no userinfo, query, fragments or request path authority. */
export function executionOrigin(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2048 || /[\u0000-\u0020\u007f]/.test(value)) fail();
  let url: URL; try { url = new URL(value); } catch { fail(); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) fail();
  return url.origin;
}
/** Agent data only: no code, provider, executable, credential or store authority. */
export function parseExecutionPlan(raw: unknown): ExecutionPlan {
  const value = snapshotJsonData(raw, fail, fail); object(value); keys(value, ['version', 'kind', 'origin', 'tasks']);
  if (value.version !== 1 || value.kind !== EXECUTION_PLAN_KIND || !Array.isArray(value.tasks) || !value.tasks.length || value.tasks.length > EXECUTION_PLAN_MAX_TASKS) fail();
  const origin = executionOrigin(value.origin), seen = new Set<string>();
  const tasks: ExecutionTask[] = value.tasks.map(item => {
    object(item);
    if (typeof item.id !== 'string' || !EXECUTION_TASK_ID.test(item.id) || seen.has(item.id)) fail();
    seen.add(item.id);
    if (item.engine === 'native-dast') {
      keys(item, ['id', 'engine', 'policy', 'maxRequests']); alias(item.policy); count(item.maxRequests, 64);
      return { id: item.id, engine: item.engine, policy: item.policy, maxRequests: item.maxRequests };
    }
    if (item.engine === 'schemathesis') {
      keys(item, ['id', 'engine', 'schema', 'operations', 'seed', 'maxRequests'], ['authPolicy']);
      alias(item.schema); if (Object.hasOwn(item, 'authPolicy')) alias(item.authPolicy);
      count(item.seed, 2147483647); count(item.maxRequests, 64);
      if (!Array.isArray(item.operations) || !item.operations.length || item.operations.length > 16 || new Set(item.operations).size !== item.operations.length
        || item.operations.some(path => typeof path !== 'string' || !path.startsWith('/') || path.length > 2048 || /[\u0000-\u0020\u007f?#\\]/.test(path))) fail();
      return { id: item.id, engine: item.engine, schema: item.schema, operations: item.operations as string[], seed: item.seed, maxRequests: item.maxRequests,
        ...(typeof item.authPolicy === 'string' ? { authPolicy: item.authPolicy } : {}) };
    }
    if (item.engine === 'nuclei') {
      keys(item, ['id', 'engine', 'scopes', 'maxRequests']); count(item.maxRequests, 20_000);
      if (!Array.isArray(item.scopes) || !item.scopes.length || item.scopes.length > 2 || new Set(item.scopes).size !== item.scopes.length
        || item.scopes.some(scope => scope !== 'misconfiguration' && scope !== 'exposures')) fail();
      return { id: item.id, engine: item.engine, scopes: item.scopes as Array<'misconfiguration' | 'exposures'>, maxRequests: item.maxRequests };
    }
    fail();
  });
  return { version: 1, kind: EXECUTION_PLAN_KIND, origin, tasks };
}
/** Owner file aliases. SHA256 binds raw file bytes, not a reserialized object. */
export function parseExecutionInputs(raw: unknown): ExecutionInputs {
  const value = snapshotJsonData(raw, fail, fail); object(value); keys(value, ['version', 'inputs']);
  if (value.version !== 1 || !Array.isArray(value.inputs) || value.inputs.length > 32) fail();
  const seen = new Set<string>();
  const inputs = value.inputs.map(item => {
    object(item); keys(item, ['id', 'path', 'sha256']); alias(item.id);
    if (seen.has(item.id) || typeof item.path !== 'string' || !item.path || item.path.length > 4096 || /[\u0000-\u001f\u007f]/.test(item.path)
      || typeof item.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(item.sha256)) fail();
    seen.add(item.id); return { id: item.id, path: item.path, sha256: item.sha256 };
  });
  return { version: 1, inputs };
}
