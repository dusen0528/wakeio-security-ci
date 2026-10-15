import { parseExecutionPlan, type ExecutionPlan, type ExecutionTask } from '../plan.js';
import type { RoundSummary } from '../store.js';
import { GAP_REASONS, SEVERITIES } from '../result.js';
import { snapshotJsonData } from '../../json-snapshot.js';

export type ReconSummary = RoundSummary;
export type TaskSpec = ExecutionTask;
export type { RoundSummary } from '../store.js';
export interface NextSelection { action: 'verify' | 'expand' | 'stop'; tasks: TaskSpec[] }
/** Cooperative cancellation; custom ports that ignore it have no hard-termination guarantee. */
export interface AgentCallContext { signal?: AbortSignal }
export function throwIfAgentCancelled(context?: AgentCallContext): void {
  if (context?.signal?.aborted) throw Error('agent_cancelled');
}
export interface AgentPort {
  /** Settle only after this decision's transport cleanup, including on cancellation. */
  planTasks(recon: ReconSummary, context?: AgentCallContext): Promise<ExecutionPlan>;
  /** Settle only after this decision's transport cleanup, including on cancellation. */
  selectNext(summary: RoundSummary, context?: AgentCallContext): Promise<NextSelection>;
}
function invalid(): never { throw Error('invalid_agent_output'); }
export function parseSelection(raw: unknown, origin: string): NextSelection {
  const value = snapshotJsonData(raw, invalid, invalid) as Record<string, unknown>;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 2
    || !Object.hasOwn(value, 'action') || !Object.hasOwn(value, 'tasks') || !Array.isArray(value.tasks)) invalid();
  if (value.action === 'stop') { if (value.tasks.length) invalid(); return { action: 'stop', tasks: [] }; }
  if (value.action !== 'verify' && value.action !== 'expand') invalid();
  return { action: value.action, tasks: parseExecutionPlan({ version: 1, kind: 'wakeio.execution-plan', origin, tasks: value.tasks }).tasks };
}
/** Copy only the store's public counters. Never send report/evidence strings to a provider. */
export function summaryInput(summary: RoundSummary): RoundSummary {
  const count = (value: number) => { if (!Number.isSafeInteger(value) || value < 0) invalid(); return value; };
  const counters = <T extends string>(keys: readonly T[], values: Record<T, number>) => Object.fromEntries(keys.map(k => [k, count(values[k])])) as Record<T, number>;
  if (!/^r-[a-z0-9-]{1,40}$/.test(summary.run_id)) invalid();
  return { run_id: summary.run_id,
    tasks: counters(['queued','running','completed','partial','error','skipped'], summary.tasks),
    findings: counters(['candidate','confirmed','rejected'], summary.findings),
    open_by_severity: counters(SEVERITIES, summary.open_by_severity),
    gaps: Object.fromEntries(GAP_REASONS.filter(k => summary.gaps[k] !== undefined).map(k => [k, count(summary.gaps[k]!)])),
    needs_verify: count(summary.needs_verify), needs_retry: count(summary.needs_retry) };
}
/** Deterministic script for offline work; reset by constructing a new instance. */
export class FakeAgent implements AgentPort {
  private next = 0;
  private readonly plan: ExecutionPlan;
  private readonly selections: NextSelection[];
  constructor(plan: ExecutionPlan, selections: NextSelection[] = []) {
    this.plan = parseExecutionPlan(plan);
    this.selections = selections.map(value => parseSelection(value, this.plan.origin));
  }
  async planTasks(_recon: ReconSummary): Promise<ExecutionPlan> { return structuredClone(this.plan); }
  async selectNext(_summary: RoundSummary): Promise<NextSelection> {
    return structuredClone(this.selections[this.next++] ?? { action: 'stop', tasks: [] });
  }
}
