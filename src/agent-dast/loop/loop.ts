import { createHash, randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { parseExecutionPlan, executionOrigin, type ExecutionPlan, type ExecutionTask } from '../plan.js';
import { runExecutionPlan, type ExecutionRunOptions } from '../runner.js';
import { openRunStore, type RunStore } from '../store.js';
import { WORKER_RESULT_SCHEMA, type GapReason, type WorkerResultV1 } from '../result.js';
import { writeArtifacts } from '../../report.js';
import { parseSelection, summaryInput, type AgentPort } from './agent.js';

export interface LoopOptions {
  agent: AgentPort; reconStore: RunStore; reconRunId: string; origin: string; outDir: string;
  taskCatalog: Array<{ checkId: string; task: ExecutionTask }>;
  coverageCells: Array<{ surface: string; checkId: string }>;
  sharedRequestCap: number; maxRounds?: number;
  execution: Omit<ExecutionRunOptions, 'plan' | 'outDir' | 'maxRequests'>;
}
export interface LoopResult {
  runId: string; status: 'completed' | 'partial' | 'error'; reason: string; requestCount: number;
  rounds: Array<{ round: number; action: 'initial' | 'verify' | 'expand'; runId: string; requestCount: number; outDir: string; ledgerVerified: boolean }>;
}
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
class LoopError extends Error { constructor(readonly reason: string) { super(reason); } }
/** One retry for malformed JSON/data; policy violations never execute or acquire a new budget. */
async function decision<T>(request: () => Promise<unknown>, parse: (raw: unknown) => T): Promise<T> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try { return parse(await request()); } catch { /* Agent output/errors are untrusted; do not echo them. */ }
  }
  throw new LoopError('invalid_agent_output');
}

export async function runAgentLoop(input: LoopOptions): Promise<LoopResult> {
  const origin = executionOrigin(input.origin), cap = input.sharedRequestCap, maxRounds = input.maxRounds ?? 8;
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > 20_000 || !Number.isSafeInteger(maxRounds) || maxRounds < 1 || maxRounds > 64) throw new LoopError('invalid_loop_limits');
  if (input.execution.allowedOrigin !== origin || input.execution.consent !== true) throw new LoopError('invalid_loop_scope');
  const cells = structuredClone(input.coverageCells), catalog = new Map<string, { checkId: string; task: ExecutionTask }>();
  if (!cells.length || cells.length > 4096 || cells.some(c => !c.surface || !/^c-[a-z0-9-]{1,49}$/.test(c.checkId))
    || new Set(cells.map(c => JSON.stringify([c.surface,c.checkId]))).size !== cells.length) throw new LoopError('invalid_loop_scope');
  const allowed = new Set(cells.map(c => c.checkId));
  for (const item of input.taskCatalog) {
    const task = parseExecutionPlan({ version: 1, kind: 'wakeio.execution-plan', origin, tasks: [item.task] }).tasks[0];
    if (catalog.has(task.id) || !allowed.has(item.checkId)) throw new LoopError('invalid_loop_scope');
    catalog.set(task.id, { task, checkId: item.checkId });
  }
  if (!catalog.size || [...allowed].some(id => ![...catalog.values()].some(item => item.checkId === id))) throw new LoopError('invalid_loop_scope');
  const scope = (plan: ExecutionPlan) => {
    if (plan.origin !== origin || plan.tasks.some(task => !catalog.has(task.id) || hash(catalog.get(task.id)!.task) !== hash(task))) throw new LoopError('out_of_scope');
    return plan;
  };
  const recon = summaryInput(input.reconStore.roundSummary(input.reconRunId));
  const out = resolve(input.outDir), runId = `r-${randomUUID()}`, startedAt = new Date().toISOString();
  await mkdir(out, { mode: 0o700 }); // Claim a fresh directory; never overwrite a previous run.
  const declaration = { version: 1, runId, origin, sharedRequestCap: cap, maxRounds, coverageCells: cells, taskCatalog: [...catalog.values()], startedAt };
  await writeArtifacts(out, [['run-start.json', JSON.stringify(declaration) + '\n']]);
  const store = await openRunStore(join(out, 'run.db'));
  store.createRun({ runId, targetOrigin: origin, scopeHash: hash(declaration), provider: 'fixed', startedAt });
  const result: LoopResult = { runId, status: 'completed', reason: 'stopped', requestCount: 0, rounds: [] };
  let audit = 0;
  const record = (requests: number, gap?: GapReason) => {
    const taskId = `t-round-${++audit}`, surfaceId = `s-round-${audit}`;
    store.addSurfaces(runId, [{ surfaceId, method: 'GET', path: '/', authState: 'anonymous' }]);
    store.createTask({ taskId, runId, category: 'config', surfaceIds: [surfaceId], coveragePlan: [{ surfaceId, check: 'round.audit' }], provider: 'fixed', scriptRef: 'loop/round-audit' });
    store.startTask(taskId);
    store.recordCoverage([{ taskId, surfaceId, check: 'round.audit', result: gap ? 'error' : 'executed', ...(gap ? { reason: gap } : {}) }]);
    const value: WorkerResultV1 = { schema: WORKER_RESULT_SCHEMA, run_id: runId, task_id: taskId, category: 'config', status: gap ? 'partial' : 'completed',
      coverage: { planned: 1, executed: gap ? 0 : 1, skipped: gap ? 1 : 0 }, findings: { candidate: 0, by_severity: {} }, finding_ids: [],
      gaps: gap ? [{ reason: gap, count: 1 }] : [], next_hint: 'none', duration_ms: 0, truncated: false };
    store.completeTask(value, { provider: 'fixed', requestCount: requests, bytes: 0, exitCode: gap ? 2 : 0, stdoutBytes: Buffer.byteLength(JSON.stringify(value)), truncated: false });
  };
  try {
    let plan = scope(await decision(() => input.agent.planTasks(structuredClone(recon)), parseExecutionPlan));
    let action: 'initial' | 'verify' | 'expand' = 'initial';
    const summaries = new Set<string>();
    while (true) {
      const remaining = cap - result.requestCount;
      if (remaining <= 0) throw new LoopError('budget_exhausted');
      if (result.rounds.length >= maxRounds) throw new LoopError('round_limit');
      const round = result.rounds.length + 1, roundDir = join(out, `round-${round}`);
      const run = await runExecutionPlan({ ...input.execution, allowedOrigin: origin, plan, outDir: roundDir, maxRequests: remaining });
      if (run.outDir !== roundDir) throw new LoopError('execution_failed');
      const requests = run.requests.requestCount;
      if (!Number.isSafeInteger(requests) || requests < 0) throw new LoopError('ledger_mismatch');
      result.requestCount += requests;
      const attempted = { round, action, runId: run.runId, requestCount: requests, outDir: roundDir, ledgerVerified: false };
      result.rounds.push(attempted);
      try {
        const db = new DatabaseSync(join(roundDir, 'run.db'), { readOnly: true });
        try { attempted.ledgerVerified = Number(db.prepare('SELECT coalesce(sum(request_count),0) n FROM ledger').get()!.n) === requests && requests <= remaining; }
        finally { db.close(); }
      } catch { /* Preserve admissions even when the child ledger cannot be read. */ }
      const incomplete = run.exitCode === 2;
      record(requests, !attempted.ledgerVerified ? 'tool_error' : incomplete ? result.requestCount >= cap ? 'budget_exhausted' : 'tool_error' : undefined);
      if (!attempted.ledgerVerified) throw new LoopError('ledger_mismatch');
      if (incomplete) throw new LoopError(result.requestCount >= cap ? 'budget_exhausted' : 'execution_failed');
      const roundStore = await openRunStore(join(roundDir, 'run.db'));
      let summary;
      try { summary = summaryInput(roundStore.roundSummary(run.runId)); } finally { roundStore.close(); }
      const fingerprint = hash({ ...summary, run_id: '' });
      if (summaries.has(fingerprint)) throw new LoopError('repeated_summary');
      summaries.add(fingerprint);
      if (result.requestCount >= cap) throw new LoopError('budget_exhausted');
      const next = await decision(() => input.agent.selectNext(structuredClone(summary)), raw => parseSelection(raw, origin));
      if (next.action === 'stop') break;
      plan = scope(parseExecutionPlan({ version: 1, kind: 'wakeio.execution-plan', origin, tasks: next.tasks }));
      action = next.action;
    }
  } catch (error) {
    result.reason = error instanceof LoopError ? error.reason : 'execution_failed';
    result.status = ['invalid_agent_output','execution_failed','ledger_mismatch'].includes(result.reason) ? 'error' : 'partial';
    const gap: GapReason = result.reason === 'out_of_scope' ? 'out_of_scope' : ['budget_exhausted','round_limit'].includes(result.reason) ? 'budget_exhausted' : 'tool_error';
    record(0, gap);
  } finally {
    try { store.finishRun(runId, result.status, new Date().toISOString()); } finally { store.close(); }
  }
  await writeArtifacts(out, [['loop-report.json', JSON.stringify(result, null, 2) + '\n'], ['loop-report.md', `# Agent loop\n\nStatus: ${result.status}\nReason: ${result.reason}\nAdmitted requests: ${result.requestCount}\nRounds: ${result.rounds.length}\n\nPer-round runner bundles contain the original reports. This database audits rounds, not endpoint coverage.\n`]]);
  return result;
}
