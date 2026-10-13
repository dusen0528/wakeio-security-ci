import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, unlink } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { types } from 'node:util';
import type { CheckResult, FailOn, ScanReport } from '../contracts.js';
import { createApiRunControl } from '../api.js';
import { dastDefaultMaxRequests, hasDastAuthentication, parseDastPolicy, prepareDastPolicy, runDast, snapshotDastEnvironment, type DastPolicy } from '../dast.js';
import { runSchemathesisLive } from '../schemathesis-live.js';
import { parseSchemathesisAuthPolicy, snapshotSchemathesisCredential, type SchemathesisAuthPolicy } from '../schemathesis-auth.js';
import { validateSchemathesisAuthSchema } from '../schemathesis-auth-run.js';
import { selectOpenApiLiveOperations } from '../openapi.js';
import { runNuclei } from '../nuclei.js';
import { normalizeUrl, validateStaticTarget } from '../url-network.js';
import { createReport, evaluateGate, RULESET_VERSION, writeArtifacts, writeReports } from '../report.js';
import { RunAdmission, type AdmissionSnapshot, type TaskAdmission } from './admission.js';
import { executionOrigin, EXECUTION_INPUT_MAX_BYTES, parseExecutionInputs, parseExecutionPlan, type ExecutionEngine, type ExecutionInputs, type ExecutionPlan, type ExecutionTask } from './plan.js';
import { openRunStore, type NewSurface, type RunStore } from './store.js';
import { failedWorkerResult, MAX_FINDING_IDS, SEVERITIES, WORKER_RESULT_SCHEMA, validateWorkerResult, type WorkerResultV1 } from './result.js';

export const EXECUTION_RUN_REVISION = 'built-in-plan-run-v1' as const;
export interface ExecutionRunOptions {
  plan: ExecutionPlan; inputs: ExecutionInputs; inputBaseDir?: string; outDir: string; consent: boolean; allowedOrigin: string;
  allowPrivate?: boolean; maxRequests?: number; timeoutMs?: number; ratePerSecond?: number; concurrency?: number; failOn?: FailOn;
  nucleiPath?: string; nucleiTemplates?: string; schemathesisPython?: string; env?: NodeJS.ProcessEnv; signal?: AbortSignal;
}
export interface TaskRunSummary {
  taskId: string; engine: ExecutionEngine; status: 'completed' | 'partial' | 'error'; exitCode: 0 | 1 | 2;
  reportPath: string | null; reportSha256: string | null; requests: AdmissionSnapshot;
}
export interface ExecutionRunResult {
  version: 1; runId: string; exitCode: 0 | 1 | 2; status: 'completed' | 'partial' | 'error'; delivery: 'published' | 'failed';
  outDir: string | null; manifestSha256: string | null; tasks: TaskRunSummary[]; requests: AdmissionSnapshot;
}
export interface RunArtifact { path: string; bytes: number; sha256: string }
const zero = (): AdmissionSnapshot => ({ requestCount: 0, bytes: 0, responseCompleted: 0, transportErrors: 0, pending: 0, refused: 0, attempts: [] });
const sha = (value: string | Buffer): string => createHash('sha256').update(value).digest('hex');
function invalid(): never { throw new TypeError('invalid_run_plan'); }
function bounded(value: unknown, fallback: number, max: number): number {
  const result = value ?? fallback; if (!Number.isSafeInteger(result) || Number(result) < 1 || Number(result) > max) invalid(); return Number(result);
}
function pathOption(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\u0000-\u001f\u007f]/.test(value)) invalid();
  return value;
}
/** Runtime options are own data. Neither getters nor proxy traps are invoked. */
function optionsSnapshot(raw: ExecutionRunOptions): Required<Pick<ExecutionRunOptions, 'maxRequests' | 'timeoutMs' | 'ratePerSecond' | 'concurrency' | 'failOn' | 'allowPrivate'>> & ExecutionRunOptions {
  if (!raw || typeof raw !== 'object' || types.isProxy(raw) || Array.isArray(raw)) invalid();
  const prototype = Object.getPrototypeOf(raw);
  if (prototype !== Object.prototype && prototype !== null || Object.getOwnPropertySymbols(raw).length) invalid();
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  const names = ['plan', 'inputs', 'inputBaseDir', 'outDir', 'consent', 'allowedOrigin', 'allowPrivate', 'maxRequests', 'timeoutMs', 'ratePerSecond', 'concurrency', 'failOn', 'nucleiPath', 'nucleiTemplates', 'schemathesisPython', 'env', 'signal'];
  if (Object.keys(descriptors).some(key => !names.includes(key) || !descriptors[key].enumerable || !('value' in descriptors[key]))
    || ['plan', 'inputs', 'outDir', 'consent', 'allowedOrigin'].some(key => !Object.hasOwn(descriptors, key))) invalid();
  const read = (key: string): unknown => descriptors[key]?.value;
  const plan = parseExecutionPlan(read('plan')), inputs = parseExecutionInputs(read('inputs'));
  if (read('consent') !== true || executionOrigin(read('allowedOrigin')) !== plan.origin
    || read('allowPrivate') !== undefined && typeof read('allowPrivate') !== 'boolean') invalid();
  const signal = read('signal'); if (signal !== undefined && (types.isProxy(signal) || !(signal instanceof AbortSignal))) invalid();
  const failOn = read('failOn') ?? 'high'; if (typeof failOn !== 'string' || !['critical', 'high', 'medium', 'low', 'info', 'none'].includes(failOn)) invalid();
  const sourceEnv = read('env') ?? process.env;
  if (!sourceEnv || typeof sourceEnv !== 'object' || types.isProxy(sourceEnv) || Array.isArray(sourceEnv)) invalid();
  const envPrototype = Object.getPrototypeOf(sourceEnv);
  if (sourceEnv !== process.env && envPrototype !== Object.prototype && envPrototype !== null) invalid();
  const outDir = pathOption(read('outDir')); if (!outDir) invalid();
  const allowPrivate = read('allowPrivate') === true;
  validateStaticTarget(normalizeUrl(plan.origin), allowPrivate);
  return { plan, inputs, outDir: resolve(outDir), consent: true, allowedOrigin: plan.origin, allowPrivate, env: sourceEnv as NodeJS.ProcessEnv, signal: signal as AbortSignal | undefined,
    inputBaseDir: pathOption(read('inputBaseDir')), nucleiPath: pathOption(read('nucleiPath')), nucleiTemplates: pathOption(read('nucleiTemplates')),
    schemathesisPython: pathOption(read('schemathesisPython')), maxRequests: bounded(read('maxRequests'), 64, 20_000),
    timeoutMs: bounded(read('timeoutMs'), 120_000, 600_000), ratePerSecond: bounded(read('ratePerSecond'), 10, 150), concurrency: bounded(read('concurrency'), 2, 4), failOn: failOn as FailOn };
}
/** Read each granted input once. Execution uses these bytes' parsed snapshot only. */
async function readStable(path: string, cap: number): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat(); if (!before.isFile() || before.size > cap) invalid();
    const bytes = Buffer.alloc(before.size + 1); let used = 0;
    while (used < bytes.length) { const read = await handle.read(bytes, used, bytes.length - used, used); if (!read.bytesRead) break; used += read.bytesRead; }
    const after = await handle.stat();
    if (used !== before.size || after.size !== before.size || after.ctimeMs !== before.ctimeMs || after.mtimeMs !== before.mtimeMs) invalid();
    return bytes.subarray(0, used);
  } finally { await handle.close(); }
}
type PreparedTask = { task: ExecutionTask; policy?: DastPolicy; document?: unknown; authPolicy?: SchemathesisAuthPolicy; env?: NodeJS.ProcessEnv };
async function prepareTasks(options: ReturnType<typeof optionsSnapshot>): Promise<PreparedTask[]> {
  const data = new Map<string, unknown>();
  const required = new Set(options.plan.tasks.flatMap(task => task.engine === 'native-dast' ? [task.policy] : task.engine === 'schemathesis' ? [task.schema, ...(task.authPolicy ? [task.authPolicy] : [])] : []));
  for (const id of required) {
    const input = options.inputs.inputs.find(item => item.id === id); if (!input) invalid();
    const bytes = await readStable(resolve(options.inputBaseDir ?? process.cwd(), input.path), EXECUTION_INPUT_MAX_BYTES);
    if (sha(bytes) !== input.sha256) invalid();
    data.set(id, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  }
  return options.plan.tasks.map(task => {
    if (task.engine === 'native-dast') {
      const parsed = parseDastPolicy(data.get(task.policy));
      const env = snapshotDastEnvironment(parsed.policy, options.env);
      const { policy } = prepareDastPolicy(parsed.policy, { allowPrivate: options.allowPrivate, env });
      if (new URL(policy.baseUrl).origin !== options.plan.origin || task.maxRequests < dastDefaultMaxRequests(policy)) invalid();
      return { task, policy, env };
    }
    if (task.engine === 'schemathesis') {
      const selection = selectOpenApiLiveOperations(data.get(task.schema), task.operations.map(path => ({ method: 'GET' as const, path })));
      if (!task.authPolicy) {
        // The legacy CONNECT lane cannot attest a shared HTTPS HTTP request denominator.
        if (new URL(options.plan.origin).protocol === 'https:') invalid();
        return { task, document: selection.document };
      }
      const { policy } = parseSchemathesisAuthPolicy(data.get(task.authPolicy));
      if (new URL(policy.baseUrl).origin !== options.plan.origin || policy.operations.length !== task.operations.length
        || task.operations.some(path => !policy.operations.some(operation => operation.path === path)) || task.maxRequests < 2 + 4 * task.operations.length) invalid();
      validateSchemathesisAuthSchema(selection);
      if (new URL(policy.baseUrl).protocol === 'http:' && (!options.allowPrivate || !['127.0.0.1', '[::1]'].includes(new URL(policy.baseUrl).hostname))) invalid();
      const credential = snapshotSchemathesisCredential(policy, options.env);
      return { task, document: selection.document, authPolicy: policy, env: { [policy.authorizationEnv]: credential } };
    }
    if (!options.nucleiTemplates || new URL(options.plan.origin).protocol === 'https:') invalid();
    return { task };
  });
}
async function safeParent(path: string, depth = 0): Promise<void> {
  if (depth > 128) invalid();
  const parent = dirname(path); if (parent !== path) await safeParent(parent, depth + 1);
  const stat = await lstat(path);
  if (stat.isSymbolicLink()) {
    // macOS system aliases only; an arbitrary caller symlink remains unsupported.
    if (process.platform !== 'darwin' || !['/var', '/tmp'].includes(path) || await realpath(path) !== `/private${path}`) invalid();
    const target = await lstat(`/private${path}`); if (!target.isDirectory() || target.isSymbolicLink()) invalid();
  } else if (!stat.isDirectory()) invalid();
}
function gapCheck(reason: 'not_started' | 'execution_incomplete' | 'store_error'): CheckResult {
  return { id: 'agent-dast.execution', status: 'partial', findings: [], notes: ['The assigned built-in engine group was not fully observed.'], metrics: { reason } };
}
async function execute(prepared: PreparedTask, options: ReturnType<typeof optionsSnapshot>, runtime: TaskAdmission): Promise<CheckResult[]> {
  const task = prepared.task, remaining = Math.max(1, runtime.deadlineAt - Date.now());
  if (runtime.signal.aborted || Date.now() >= runtime.deadlineAt) return [gapCheck('not_started')];
  if (task.engine === 'native-dast') return runDast({ policy: prepared.policy!, env: prepared.env, consent: true, allowPrivate: options.allowPrivate,
    maxRequests: task.maxRequests, timeoutMs: Math.min(remaining, 120_000), signal: options.signal }, runtime);
  if (task.engine === 'schemathesis') return runSchemathesisLive({ document: prepared.document, baseUrl: `${options.plan.origin}/`, operations: task.operations.map(path => ({ method: 'GET' as const, path })),
    ...(prepared.authPolicy ? { authPolicy: prepared.authPolicy, env: prepared.env } : {}), consent: true, allowPrivate: options.allowPrivate, python: options.schemathesisPython,
    maxRequests: task.maxRequests, timeoutMs: Math.min(remaining, 120_000), seed: task.seed, signal: options.signal }, runtime);
  return runNuclei({ url: `${options.plan.origin}/`, executable: options.nucleiPath, templatesDir: options.nucleiTemplates!, scopes: task.scopes, consent: true,
    allowPrivate: options.allowPrivate, maxRequests: task.maxRequests, rateLimit: options.ratePerSecond, timeoutMs: Math.min(remaining, 600_000), signal: options.signal }, runtime);
}
function observedGroup(prepared: PreparedTask, checks: CheckResult[], observed: AdmissionSnapshot): boolean {
  if (!observed.requestCount || observed.pending || observed.transportErrors || observed.refused || checks.length !== 1 || checks[0].status !== 'completed'
    || checks[0].metrics?.requestCount !== observed.requestCount) return false;
  const check = checks[0];
  if (prepared.task.engine === 'native-dast') return check.dastExecution?.status === 'complete';
  if (prepared.authPolicy) return check.schemathesisAuth?.status === 'completed' && check.schemathesisAuth.requests.attempted === observed.requestCount;
  // These are trusted adapter results, not arbitrary caller-supplied metrics. No per-endpoint coverage is inferred.
  return prepared.task.engine === 'nuclei' || check.metrics?.operationsExercised === prepared.task.operations.length;
}
function findingSurface(prepared: PreparedTask, findingUrl: string | undefined): NewSurface {
  if (prepared.policy) return { surfaceId: '', method: prepared.policy.version === 4 ? 'POST' : 'GET', path: new URL(prepared.policy.url).pathname,
    param: prepared.policy.parameter, location: prepared.policy.version === 4 ? 'body' : 'query', authState: hasDastAuthentication(prepared.policy) ? 'user' : 'anonymous' };
  if (!findingUrl) invalid();
  const url = new URL(findingUrl);
  let path = url.pathname;
  if (prepared.task.engine === 'schemathesis') {
    const template = prepared.task.operations.find(candidate => candidate === path || new URL(candidate, url.origin).pathname === path);
    if (!template) invalid(); path = template;
  }
  return { surfaceId: '', method: 'GET', path, authState: prepared.authPolicy ? 'user' : 'anonymous' };
}
/** Post-execution audit: group completion and registered observations are separate from endpoint coverage. */
async function storeTask(store: RunStore, runId: string, prepared: PreparedTask, report: ScanReport, complete: boolean, observed: AdmissionSnapshot, duration: number, out: string): Promise<void> {
  const task = prepared.task, groupSurfaceId = `s-${task.id.slice(2)}`, groupCheck = `group.${task.engine}`;
  const category = task.engine === 'native-dast' ? 'injection' : 'config';
  const rows = report.checks.flatMap(item => item.findings).map((finding, index) => {
    const surface = findingSurface(prepared, finding.location?.url);
    surface.surfaceId = `s-${sha(JSON.stringify(surface)).slice(0, 40)}`;
    return { finding, id: `f-${sha(`${task.id}:${index}`).slice(0, 32)}`, surface, check: `observation.${sha(finding.ruleId).slice(0, 24)}` };
  });
  const surfaces = new Map(rows.map(row => [row.surface.surfaceId, row.surface]));
  const assignments = new Map(rows.map(row => [`${row.surface.surfaceId}:${row.check}`, { surfaceId: row.surface.surfaceId, check: row.check }]));
  store.addSurfaces(runId, [{ surfaceId: groupSurfaceId, method: 'GET', path: '/', authState: 'anonymous' }, ...surfaces.values()]);
  const coveragePlan = [{ surfaceId: groupSurfaceId, check: groupCheck }, ...assignments.values()];
  store.createTask({ taskId: task.id, runId, category, surfaceIds: [groupSurfaceId, ...surfaces.keys()], coveragePlan, provider: 'fixed', scriptRef: `builtin:${task.engine}` });
  store.startTask(task.id);
  store.recordCoverage([{ taskId: task.id, surfaceId: groupSurfaceId, check: groupCheck, result: complete ? 'executed' : 'error', ...(complete ? {} : { reason: 'tool_error' as const }) },
    ...[...assignments.values()].map(assignment => ({ ...assignment, taskId: task.id, result: 'executed' as const }))]);
  const findingIds = new Map<string, typeof SEVERITIES[number]>();
  for (const { finding, id, surface, check } of rows) {
    await writeArtifacts(join(out, 'evidence'), [[`${id}.json`, JSON.stringify({ version: 1, taskId: task.id, reportPath: `tasks/${task.id}/report.json`, findingId: finding.id, ruleId: finding.ruleId, severity: finding.severity, kind: finding.kind }) + '\n']]);
    const recorded = store.recordFinding({ findingId: id, runId, taskId: task.id, surfaceId: surface.surfaceId, check, ruleId: finding.ruleId, severity: finding.severity });
    const prior = findingIds.get(recorded.findingId);
    if (!prior || SEVERITIES.indexOf(finding.severity) < SEVERITIES.indexOf(prior)) findingIds.set(recorded.findingId, finding.severity);
  }
  if (findingIds.size > MAX_FINDING_IDS) invalid();
  const bySeverity: WorkerResultV1['findings']['by_severity'] = {};
  for (const severity of findingIds.values()) bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
  const result = validateWorkerResult({ schema: WORKER_RESULT_SCHEMA, run_id: runId, task_id: task.id, category, status: complete ? 'completed' : 'partial',
    coverage: { planned: coveragePlan.length, executed: assignments.size + (complete ? 1 : 0), skipped: 0 }, findings: { candidate: findingIds.size, by_severity: bySeverity }, finding_ids: [...findingIds.keys()],
    gaps: complete ? [] : [{ reason: 'tool_error', count: 1 }], next_hint: 'none', duration_ms: Math.max(0, duration), truncated: false });
  const bytes = Buffer.byteLength(JSON.stringify(result));
  store.completeTask(result, { provider: 'fixed', requestCount: observed.requestCount, bytes: observed.bytes, exitCode: complete ? 0 : 2, stdoutBytes: bytes, truncated: false });
}
async function artifact(path: string, base: string): Promise<RunArtifact> {
  const bytes = await readStable(join(base, path), 16 * 1024 * 1024);
  return { path, bytes: bytes.byteLength, sha256: sha(bytes) };
}
/** Preserve already registered observations; placeholder counts are error-only, never a completion claim. */
function closeFailedTask(store: RunStore, runId: string, task: ExecutionTask, observed: AdmissionSnapshot, duration: number): boolean {
  const category = task.engine === 'native-dast' ? 'injection' : 'config', surfaceId = `s-${task.id.slice(2)}`, check = `group.${task.engine}`;
  try {
    store.addSurfaces(runId, [{ surfaceId, method: 'GET', path: '/', authState: 'anonymous' }]);
    try { store.createTask({ taskId: task.id, runId, category, surfaceIds: [surfaceId], coveragePlan: [{ surfaceId, check }], provider: 'fixed', scriptRef: `builtin:${task.engine}` }); } catch { /* May already be registered. */ }
    try { store.startTask(task.id); } catch { /* May already be running. */ }
    const failure = failedWorkerResult({ runId, taskId: task.id, category }, 'nonzero_exit', Math.max(0, duration));
    store.completeTask(failure, { provider: 'fixed', requestCount: observed.requestCount, bytes: observed.bytes, exitCode: 2,
      stdoutBytes: Buffer.byteLength(JSON.stringify(failure)), truncated: false });
    return true;
  } catch { return false; }
}
const note = 'Built-in engine groups only. The agent supplied a data plan; the trusted controller executed it. Group completion is not individual endpoint or whole-service coverage. Database assignments registered after execution audit observations; they are not a live scheduler, crash recovery or planned endpoint denominator. Publication does not attest the final caller process exit.';
/** Execute a reviewed data plan. No model, arbitrary worker code, installation or agent DB access. */
export async function runExecutionPlan(raw: ExecutionRunOptions): Promise<ExecutionRunResult> {
  const runId = `r-${randomUUID()}`;
  const refused = (): ExecutionRunResult => ({ version: 1, runId, exitCode: 2, status: 'error', delivery: 'failed', outDir: null, manifestSha256: null, tasks: [], requests: zero() });
  let options: ReturnType<typeof optionsSnapshot>, prepared: PreparedTask[];
  try { options = optionsSnapshot(raw); prepared = await prepareTasks(options); if (options.signal?.aborted) return refused(); await safeParent(dirname(options.outDir)); }
  catch { return refused(); }
  // Atomic claim, not atomic publication of an entire artifact tree. Never clobber an existing caller directory.
  try { await mkdir(options.outDir, { mode: 0o700 }); } catch { return refused(); }
  const out = options.outDir, startedAt = new Date().toISOString(), tasks: TaskRunSummary[] = [], artifacts: RunArtifact[] = [];
  let store: RunStore | undefined, admission: RunAdmission | undefined, deliveryFailed = false, receiptOwned = false;
  let control: ReturnType<typeof createApiRunControl> | undefined;
  const planSha256 = sha(JSON.stringify(options.plan));
  const inputBindings = options.inputs.inputs.map(({ id, sha256 }) => ({ id, sha256 })).sort((a, b) => a.id.localeCompare(b.id));
  const scopeHash = sha(JSON.stringify({ revision: EXECUTION_RUN_REVISION, planSha256, inputBindings, maxRequests: options.maxRequests, timeoutMs: options.timeoutMs,
    ratePerSecond: options.ratePerSecond, concurrency: options.concurrency, allowPrivate: options.allowPrivate, failOn: options.failOn, ruleset: RULESET_VERSION }));
  try {
    await mkdir(join(out, 'tasks'), { mode: 0o700 }); await mkdir(join(out, 'evidence'), { mode: 0o700 });
    for (const { task } of prepared) await mkdir(join(out, 'tasks', task.id), { mode: 0o700 });
    store = await openRunStore(join(out, 'run.db'));
    store.createRun({ runId, targetOrigin: options.plan.origin, scopeHash, provider: 'fixed', startedAt });
    await writeArtifacts(out, [['run-start.json', JSON.stringify({ version: 1, profileRevision: EXECUTION_RUN_REVISION, runId, planSha256, scopeHash, inputBindings,
      expectedTasks: prepared.map(({ task }) => ({ taskId: task.id, engine: task.engine })), limits: { maxRequests: options.maxRequests, timeoutMs: options.timeoutMs,
        ratePerSecond: options.ratePerSecond, concurrency: options.concurrency }, declarationOnly: true }, null, 2) + '\n']]);
    control = createApiRunControl(options.timeoutMs, options.signal, 600_000);
    admission = new RunAdmission({ maxRequests: options.maxRequests, ratePerSecond: options.ratePerSecond, deadlineAt: control.deadlineAt, signal: control.signal });
    let next = 0;
    const runtimes = new Map<string, TaskAdmission>();
    const worker = async () => {
      while (next < prepared.length) {
        const index = next++, item = prepared[index], task = item.task, start = Date.now(), runtime = admission!.bindTask(task.id);
        runtimes.set(task.id, runtime);
        let checks: CheckResult[];
        try { checks = await execute(item, options, runtime); } catch { checks = [gapCheck('execution_incomplete')]; }
        const observed = runtime.snapshot();
        let report = createReport(checks, task.engine === 'native-dast' ? 'url' : task.engine === 'schemathesis' ? 'api' : 'url', new Date(start).toISOString(), { fingerprint: sha(`${scopeHash}:${task.id}`), ruleset: RULESET_VERSION });
        const complete = observedGroup(item, report.checks, observed) && !runtime.signal.aborted;
        if (!complete && !report.checks.some(check => check.status === 'partial' || check.status === 'error' || check.status === 'skipped')) {
          report = createReport([...report.checks, gapCheck('execution_incomplete')], report.mode, report.startedAt, report.scope);
        }
        try { await storeTask(store!, runId, item, report, complete, observed, Date.now() - start, out); }
        catch {
          const closed = closeFailedTask(store!, runId, task, observed, Date.now() - start);
          const gap = gapCheck('store_error'); gap.metrics = { reason: 'store_error', storeTerminal: closed ? 'error' : 'unknown' };
          if (!closed) gap.notes.push('Storage could not be reconciled; task termination in the database is unknown.');
          report = createReport([...report.checks, gap], report.mode, report.startedAt, report.scope);
        }
        const taskSummary: TaskRunSummary = { taskId: task.id, engine: task.engine, status: evaluateGate(report, options.failOn).exitCode === 2 ? 'partial' : 'completed',
          exitCode: evaluateGate(report, options.failOn).exitCode, reportPath: null, reportSha256: null, requests: runtime.snapshot() };
        try {
          await writeReports(report, join(out, 'tasks', task.id), { failOn: options.failOn });
          for (const format of ['report.json', 'report.sarif', 'report.md', 'agent-report.json']) artifacts.push(await artifact(`tasks/${task.id}/${format}`, out));
          taskSummary.reportPath = `tasks/${task.id}/report.json`;
          taskSummary.reportSha256 = artifacts.find(file => file.path === taskSummary.reportPath)!.sha256;
        } catch { deliveryFailed = true; taskSummary.exitCode = 2; taskSummary.status = 'error'; }
        tasks[index] = taskSummary;
      }
    };
    // Wait for every engine's cleanup even if one controller task unexpectedly fails.
    await Promise.allSettled(Array.from({ length: Math.min(options.concurrency, prepared.length) }, worker));
    for (const [index, item] of prepared.entries()) {
      if (tasks[index]) continue;
      const observed = runtimes.get(item.task.id)?.snapshot() ?? zero();
      closeFailedTask(store, runId, item.task, observed, 0);
      tasks[index] = { taskId: item.task.id, engine: item.task.engine, status: 'error', exitCode: 2, reportPath: null, reportSha256: null, requests: observed };
      deliveryFailed = true;
    }
    const stopped = control.signal.aborted || Date.now() >= control.deadlineAt;
    const incomplete = stopped || tasks.length !== prepared.length || tasks.some(task => task.exitCode === 2);
    store.finishRun(runId, incomplete ? 'partial' : 'completed', new Date().toISOString());
    store.close(); store = undefined;
    const requests = admission.snapshot();
    const exitCode: 0 | 1 | 2 = incomplete || deliveryFailed || requests.pending ? 2 : tasks.some(task => task.exitCode === 1) ? 1 : 0;
    const status = exitCode === 2 ? 'partial' as const : 'completed' as const;
    const stopReason = options.signal?.aborted ? 'cancelled' : stopped ? 'deadline' : deliveryFailed ? 'delivery_error' : requests.refused && requests.requestCount >= options.maxRequests ? 'request_budget' : incomplete ? 'execution_incomplete' : 'complete';
    const runReport = { version: 1, profileRevision: EXECUTION_RUN_REVISION, runId, planSha256, inputBindings, scopeHash, status, exitCode, stopReason,
      failOn: options.failOn, limits: { maxRequests: options.maxRequests, timeoutMs: options.timeoutMs, ratePerSecond: options.ratePerSecond, concurrency: options.concurrency },
      tasks, requests, notes: [note] };
    const json = JSON.stringify(runReport, null, 2) + '\n';
    const markdown = `# Wakeio built-in plan run\n\n${note}\n\n- Revision: ${EXECUTION_RUN_REVISION}\n- Status: ${status}\n- Run gate: ${exitCode}\n- HTTP attempts: ${requests.requestCount}\n\n`
      + tasks.map(task => `- ${task.taskId}: ${task.engine}, ${task.status}, gate ${task.exitCode}, ${task.requests.requestCount} HTTP attempts; report ${task.reportPath ?? 'unavailable'}`).join('\n') + '\n';
    await writeArtifacts(out, [['run-report.json', json], ['run-report.md', markdown], ['agent-run.json', JSON.stringify({ ...runReport,
      reportArtifact: { name: 'run-report.json', algorithm: 'sha256', digest: sha(json) }, diagnosticOnly: true, replayAuthority: false }, null, 2) + '\n']]);
    for (const path of ['run-start.json', 'run-report.json', 'run-report.md', 'agent-run.json', 'run.db']) artifacts.push(await artifact(path, out));
    const evidence = await readdir(join(out, 'evidence'));
    for (const name of evidence.sort()) artifacts.push(await artifact(`evidence/${name}`, out));
    if (deliveryFailed) return { version: 1, runId, exitCode: 2, status: 'error', delivery: 'failed', outDir: out, manifestSha256: null, tasks, requests };
    if ((control.signal.aborted || Date.now() >= control.deadlineAt) && exitCode !== 2) invalid();
    const manifest = { version: 1, profileRevision: EXECUTION_RUN_REVISION, runId, planSha256, scopeHash, artifacts: artifacts.sort((a, b) => a.path.localeCompare(b.path)) };
    const manifestText = JSON.stringify(manifest, null, 2) + '\n';
    await writeArtifacts(out, [['run-manifest.json', manifestText]]);
    const manifestSha256 = sha(manifestText);
    // Final publication marker. It binds the complete artifact set, not final process/Action success.
    if ((control.signal.aborted || Date.now() >= control.deadlineAt) && exitCode !== 2) invalid();
    const receipt = await open(join(out, 'run-receipt.json'), 'wx', 0o600);
    receiptOwned = true;
    try { await receipt.writeFile(JSON.stringify({ version: 1, profileRevision: EXECUTION_RUN_REVISION, runId, status: 'publication_only',
      manifestSha256, runReportSha256: sha(json), exitCode, requiresCallerAcknowledgement: true, provesFinalProcessExit: false }, null, 2) + '\n'); }
    finally { await receipt.close(); }
    if ((control.signal.aborted || Date.now() >= control.deadlineAt) && exitCode !== 2) invalid();
    return { version: 1, runId, exitCode, status, delivery: 'published', outDir: out, manifestSha256, tasks, requests };
  } catch {
    if (receiptOwned) await unlink(join(out, 'run-receipt.json')).catch(() => undefined);
    return { version: 1, runId, exitCode: 2, status: 'error', delivery: 'failed', outDir: out, manifestSha256: null, tasks, requests: admission?.snapshot() ?? zero() };
  } finally { try { store?.close(); } catch { /* Result remains incomplete on store failure. */ } admission?.close(); control?.dispose(); }
}
