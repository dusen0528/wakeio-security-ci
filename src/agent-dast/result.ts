/**
 * Worker result contract (wakeio.worker-result/v1).
 *
 * A worker script prints exactly one JSON object to stdout and nothing else.
 * That object is the only thing an agent ever sees about a task: counts,
 * finding IDs and gap reasons. Raw requests, responses and evidence stay in
 * run.db and evidence/, never here.
 *
 * schemas/worker-result.v1.json is the reference schema for docs and tests.
 * This file is the runtime validator. It also enforces cross-field rules the
 * JSON Schema cannot express (identity binding, count consistency).
 */

export const WORKER_RESULT_SCHEMA = 'wakeio.worker-result/v1';
export const WORKER_RESULT_MAX_BYTES = 2048;

export const WORKER_CATEGORIES = ['recon', 'injection', 'authz', 'config', 'verify'] as const;
export const WORKER_STATUSES = ['completed', 'partial', 'error', 'skipped'] as const;
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const GAP_REASONS = ['auth_required', 'timeout', 'budget_exhausted', 'out_of_scope', 'tool_error', 'unsupported'] as const;
export const NEXT_HINTS = ['verify', 'retry', 'none'] as const;

export const MAX_FINDING_IDS = 20;
export const MAX_GAPS = 10;

export type WorkerCategory = typeof WORKER_CATEGORIES[number];
export type WorkerStatus = typeof WORKER_STATUSES[number];
export type Severity = typeof SEVERITIES[number];
export type GapReason = typeof GAP_REASONS[number];
export type NextHint = typeof NEXT_HINTS[number];

export const RUN_ID = /^r-[0-9a-z-]{1,40}$/;
export const TASK_ID = /^t-[0-9a-z-]{1,60}$/;
export const FINDING_ID = /^f-[0-9a-z-]{1,40}$/;

export interface WorkerResultV1 {
  schema: typeof WORKER_RESULT_SCHEMA;
  run_id: string;
  task_id: string;
  category: WorkerCategory;
  status: WorkerStatus;
  coverage: { planned: number; executed: number; skipped: number };
  findings: { candidate: number; by_severity: Partial<Record<Severity, number>> };
  finding_ids: string[];
  gaps: { reason: GapReason; count: number }[];
  next_hint: NextHint;
  duration_ms: number;
  /** Set only by the runner when it had to replace an unusable worker output. */
  truncated: boolean;
}

/** What the runner assigned to the task. A worker cannot report for another task. */
export interface WorkerIdentity {
  runId: string;
  taskId: string;
  category: WorkerCategory;
}

export type WorkerResultRejection = 'output_too_large' | 'not_json' | 'schema_invalid' | 'identity_mismatch';

export type ParsedWorkerResult =
  | { ok: true; result: WorkerResultV1 }
  /** `path` names the offending field only. Worker output is never echoed back. */
  | { ok: false; reason: WorkerResultRejection; path?: string };

class Invalid extends Error {
  constructor(readonly path: string) { super('schema_invalid'); }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], path: string): void {
  for (const key of required) if (!Object.hasOwn(value, key)) throw new Invalid(`${path}.${key}`);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new Invalid(`${path}.${key}`);
}

function count(value: unknown, path: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new Invalid(path);
  return value as number;
}

function oneOf<T extends string>(value: unknown, options: readonly T[], path: string): T {
  if (typeof value !== 'string' || !(options as readonly string[]).includes(value)) throw new Invalid(path);
  return value as T;
}

function matching(value: unknown, pattern: RegExp, path: string): string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Invalid(path);
  return value;
}

const TOP_LEVEL = ['schema', 'run_id', 'task_id', 'category', 'status', 'coverage', 'findings', 'finding_ids', 'gaps', 'next_hint', 'duration_ms', 'truncated'] as const;

/** Validate an already-parsed value. Returns a fresh object with no shared references. */
export function validateWorkerResult(raw: unknown): WorkerResultV1 {
  if (!record(raw)) throw new Invalid('$');
  exactKeys(raw, TOP_LEVEL, [], '$');
  if (raw.schema !== WORKER_RESULT_SCHEMA) throw new Invalid('$.schema');

  const run_id = matching(raw.run_id, RUN_ID, '$.run_id');
  const task_id = matching(raw.task_id, TASK_ID, '$.task_id');
  const category = oneOf(raw.category, WORKER_CATEGORIES, '$.category');
  const status = oneOf(raw.status, WORKER_STATUSES, '$.status');

  if (!record(raw.coverage)) throw new Invalid('$.coverage');
  exactKeys(raw.coverage, ['planned', 'executed', 'skipped'], [], '$.coverage');
  const coverage = {
    planned: count(raw.coverage.planned, '$.coverage.planned'),
    executed: count(raw.coverage.executed, '$.coverage.executed'),
    skipped: count(raw.coverage.skipped, '$.coverage.skipped'),
  };
  if (coverage.executed + coverage.skipped > coverage.planned) throw new Invalid('$.coverage');

  if (!record(raw.findings)) throw new Invalid('$.findings');
  exactKeys(raw.findings, ['candidate', 'by_severity'], [], '$.findings');
  const candidate = count(raw.findings.candidate, '$.findings.candidate');
  if (!record(raw.findings.by_severity)) throw new Invalid('$.findings.by_severity');
  exactKeys(raw.findings.by_severity, [], SEVERITIES, '$.findings.by_severity');
  const by_severity: Partial<Record<Severity, number>> = {};
  let severityTotal = 0;
  for (const severity of SEVERITIES) {
    if (!Object.hasOwn(raw.findings.by_severity, severity)) continue;
    const n = count(raw.findings.by_severity[severity], `$.findings.by_severity.${severity}`);
    by_severity[severity] = n;
    severityTotal += n;
  }
  if (severityTotal !== candidate) throw new Invalid('$.findings.by_severity');

  if (!Array.isArray(raw.finding_ids) || raw.finding_ids.length > MAX_FINDING_IDS) throw new Invalid('$.finding_ids');
  const finding_ids = raw.finding_ids.map((id, i) => matching(id, FINDING_ID, `$.finding_ids[${i}]`));
  if (new Set(finding_ids).size !== finding_ids.length) throw new Invalid('$.finding_ids');
  if (finding_ids.length > candidate) throw new Invalid('$.finding_ids');

  if (!Array.isArray(raw.gaps) || raw.gaps.length > MAX_GAPS) throw new Invalid('$.gaps');
  const seen = new Set<GapReason>();
  const gaps = raw.gaps.map((gap, i) => {
    const path = `$.gaps[${i}]`;
    if (!record(gap)) throw new Invalid(path);
    exactKeys(gap, ['reason', 'count'], [], path);
    const reason = oneOf(gap.reason, GAP_REASONS, `${path}.reason`);
    if (seen.has(reason)) throw new Invalid(`${path}.reason`);
    seen.add(reason);
    return { reason, count: count(gap.count, `${path}.count`, 1) };
  });

  // An incomplete task must say why, or the report would read it as clean.
  if (status === 'partial' && gaps.length === 0) throw new Invalid('$.gaps');
  if (status === 'skipped' && coverage.executed !== 0) throw new Invalid('$.coverage.executed');

  const next_hint = oneOf(raw.next_hint, NEXT_HINTS, '$.next_hint');
  const duration_ms = count(raw.duration_ms, '$.duration_ms');
  if (typeof raw.truncated !== 'boolean') throw new Invalid('$.truncated');

  return {
    schema: WORKER_RESULT_SCHEMA, run_id, task_id, category, status, coverage,
    findings: { candidate, by_severity }, finding_ids, gaps, next_hint, duration_ms, truncated: raw.truncated,
  };
}

/**
 * Parse a worker's stdout. Rejects anything over the byte budget before
 * parsing, anything that is not exactly one JSON object, a result a worker
 * marked `truncated` itself, and a result for a task it was not given.
 */
export function parseWorkerResult(stdout: string, expected: WorkerIdentity): ParsedWorkerResult {
  if (Buffer.byteLength(stdout, 'utf8') > WORKER_RESULT_MAX_BYTES) return { ok: false, reason: 'output_too_large' };
  let raw: unknown;
  try { raw = JSON.parse(stdout.trim()); } catch { return { ok: false, reason: 'not_json' }; }
  let result: WorkerResultV1;
  try { result = validateWorkerResult(raw); } catch (error) {
    return { ok: false, reason: 'schema_invalid', path: error instanceof Invalid ? error.path : '$' };
  }
  if (result.truncated) return { ok: false, reason: 'schema_invalid', path: '$.truncated' };
  if (result.run_id !== expected.runId) return { ok: false, reason: 'identity_mismatch', path: '$.run_id' };
  if (result.task_id !== expected.taskId) return { ok: false, reason: 'identity_mismatch', path: '$.task_id' };
  if (result.category !== expected.category) return { ok: false, reason: 'identity_mismatch', path: '$.category' };
  return { ok: true, result };
}

export type WorkerFailure = WorkerResultRejection | 'timeout' | 'budget_exhausted' | 'spawn_error' | 'nonzero_exit';

/**
 * The result the runner records when a worker's own output cannot be used.
 * It reports nothing the worker claimed; findings already written to run.db
 * stay there and are counted from the database, not from this object.
 */
export function failedWorkerResult(identity: WorkerIdentity, failure: WorkerFailure, durationMs: number): WorkerResultV1 {
  const reason: GapReason = failure === 'timeout' ? 'timeout' : failure === 'budget_exhausted' ? 'budget_exhausted' : 'tool_error';
  return {
    schema: WORKER_RESULT_SCHEMA,
    run_id: identity.runId,
    task_id: identity.taskId,
    category: identity.category,
    status: 'error',
    coverage: { planned: 0, executed: 0, skipped: 0 },
    findings: { candidate: 0, by_severity: {} },
    finding_ids: [],
    gaps: [{ reason, count: 1 }],
    next_hint: failure === 'timeout' || failure === 'spawn_error' ? 'retry' : 'none',
    duration_ms: Number.isSafeInteger(durationMs) && durationMs >= 0 ? durationMs : 0,
    truncated: failure !== 'timeout' && failure !== 'budget_exhausted' && failure !== 'spawn_error' && failure !== 'nonzero_exit',
  };
}
