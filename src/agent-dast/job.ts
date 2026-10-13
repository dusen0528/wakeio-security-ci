/**
 * Worker job (wakeio.worker-job/v1): what the runner hands a template on stdin.
 *
 * The job travels on stdin, not in argv or the environment, because it carries
 * the task's proxy credential: argv is visible to other processes and
 * runProcess deliberately forwards no proxy variables.
 */
import { FINDING_ID, RUN_ID, TASK_ID, WORKER_CATEGORIES, type WorkerCategory } from './result.js';
import { AUTH_STATES, PARAM_LOCATIONS, SURFACE_ID, type AuthState, type ParamLocation } from './store.js';

export const WORKER_JOB_SCHEMA = 'wakeio.worker-job/v1';
export const WORKER_JOB_MAX_BYTES = 256 * 1024;

export interface JobSurface {
  surface_id: string;
  method: string;
  path: string;
  param: string | null;
  location: ParamLocation | null;
  auth_state: AuthState;
}

export interface WorkerJobV1 {
  schema: typeof WORKER_JOB_SCHEMA;
  run_id: string;
  task_id: string;
  category: WorkerCategory;
  template: string;
  /** Absolute path of run.db. */
  run_db: string;
  /** Absolute directory for `<finding_id>.json` evidence files. */
  evidence_dir: string;
  target_origin: string;
  /** This task's run-gate proxy URL, credential included. Never log or persist it. */
  proxy: string;
  /** Epoch milliseconds. The runner kills the worker shortly after. */
  deadline_at: number;
  surfaces: JobSurface[];
  /** Template parameters chosen by the agent, already validated by the template's own schema. */
  params: Record<string, unknown>;
  /** Prefix the worker must use for finding IDs it creates, so IDs never collide across tasks. */
  finding_prefix: string;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function parseWorkerJob(text: string): WorkerJobV1 {
  if (Buffer.byteLength(text) > WORKER_JOB_MAX_BYTES) throw new Error('job_too_large');
  const raw: unknown = JSON.parse(text);
  if (!record(raw) || raw.schema !== WORKER_JOB_SCHEMA) throw new Error('job_invalid');
  const str = (key: string, pattern?: RegExp) => {
    const value = raw[key];
    if (typeof value !== 'string' || (pattern && !pattern.test(value))) throw new Error(`job_invalid:${key}`);
    return value;
  };
  const category = str('category');
  if (!(WORKER_CATEGORIES as readonly string[]).includes(category)) throw new Error('job_invalid:category');
  if (!Array.isArray(raw.surfaces) || !record(raw.params) || !Number.isSafeInteger(raw.deadline_at)) throw new Error('job_invalid');
  const surfaces = raw.surfaces.map((s): JobSurface => {
    if (!record(s) || typeof s.surface_id !== 'string' || !SURFACE_ID.test(s.surface_id) || typeof s.method !== 'string'
      || typeof s.path !== 'string' || !s.path.startsWith('/') || !(AUTH_STATES as readonly string[]).includes(String(s.auth_state))
      || (s.location !== null && !(PARAM_LOCATIONS as readonly string[]).includes(String(s.location)))
      || (s.param !== null && typeof s.param !== 'string')) throw new Error('job_invalid:surfaces');
    return { surface_id: s.surface_id, method: s.method, path: s.path, param: s.param as string | null, location: s.location as ParamLocation | null, auth_state: s.auth_state as AuthState };
  });
  const finding_prefix = str('finding_prefix', /^f-[0-9a-z-]{1,24}$/);
  if (!FINDING_ID.test(`${finding_prefix}-1`)) throw new Error('job_invalid:finding_prefix');
  return {
    schema: WORKER_JOB_SCHEMA,
    run_id: str('run_id', RUN_ID),
    task_id: str('task_id', TASK_ID),
    category: category as WorkerCategory,
    template: str('template'),
    run_db: str('run_db', /^\//),
    evidence_dir: str('evidence_dir', /^\//),
    target_origin: str('target_origin'),
    proxy: str('proxy', /^http:\/\/[^@\s]+@127\.0\.0\.1:\d+$/),
    deadline_at: raw.deadline_at as number,
    surfaces,
    params: raw.params,
    finding_prefix,
  };
}
