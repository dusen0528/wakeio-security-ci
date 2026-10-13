import { setTimeout as delay } from 'node:timers/promises';
import { TASK_ID } from './result.js';

export type AdmissionMethod = 'GET' | 'HEAD' | 'POST';
export interface AdmissionMetadata { method: AdmissionMethod; kind: 'probe' | 'control'; operationIndex?: number }
export interface AdmissionAttempt {
  ordinal: number; method: AdmissionMethod; kind: 'probe' | 'control'; operationIndex: number | null;
  outcome: 'pending' | 'response' | 'transport_error';
}
export interface AdmissionSnapshot {
  requestCount: number; bytes: number; responseCompleted: number; transportErrors: number; pending: number; refused: number;
  attempts: AdmissionAttempt[];
}
export interface AttemptPermit { addBytes(bytes: number): void; finish(outcome: 'response' | 'transport_error'): void }
/** Internal authority only. Never serialize this capability into an agent job. */
export interface TaskAdmission {
  readonly signal: AbortSignal; readonly deadlineAt: number;
  reserve(metadata: AdmissionMetadata, signal?: AbortSignal): Promise<AttemptPermit>;
  snapshot(): AdmissionSnapshot;
}
export class DastAdmissionError extends Error {
  constructor(readonly code: 'request_limit' | 'timeout' | 'invalid_admission') { super(code); this.name = 'DastAdmissionError'; }
}
export function admissionSignal(runtime: TaskAdmission | undefined, signal?: AbortSignal): AbortSignal | undefined {
  return runtime ? signal ? AbortSignal.any([runtime.signal, signal]) : runtime.signal : signal;
}

/** One serialized admission queue, not one queue per engine or per task. */
export class RunAdmission {
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
  private readonly controller = new AbortController();
  private readonly tasks = new Map<string, AdmissionSnapshot>();
  private count = 0;
  private nextAt = 0;
  private tail: Promise<void> = Promise.resolve();
  private readonly timer: NodeJS.Timeout;
  private readonly onAbort = () => this.close();

  constructor(private readonly options: { maxRequests: number; ratePerSecond: number; deadlineAt: number; signal?: AbortSignal }) {
    if (!Number.isSafeInteger(options.maxRequests) || options.maxRequests < 1 || options.maxRequests > 20_000
      || !Number.isFinite(options.ratePerSecond) || options.ratePerSecond <= 0 || options.ratePerSecond > 1000
      || !Number.isSafeInteger(options.deadlineAt) || options.deadlineAt < 1
      || options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new DastAdmissionError('invalid_admission');
    // Keep caller mutation from changing the cap or pacing after construction.
    this.options = { ...options };
    this.deadlineAt = options.deadlineAt;
    this.signal = this.controller.signal;
    this.timer = setTimeout(this.onAbort, Math.max(1, Math.min(2_147_483_647, options.deadlineAt - Date.now())));
    this.timer.unref();
    options.signal?.addEventListener('abort', this.onAbort, { once: true });
    if (options.signal?.aborted || Date.now() >= this.deadlineAt) this.close();
  }

  bindTask(taskId: string): TaskAdmission {
    if (typeof taskId !== 'string' || !TASK_ID.test(taskId) || this.tasks.has(taskId)) throw new DastAdmissionError('invalid_admission');
    const state: AdmissionSnapshot = { requestCount: 0, bytes: 0, responseCompleted: 0, transportErrors: 0, pending: 0, refused: 0, attempts: [] };
    this.tasks.set(taskId, state);
    const snapshot = (): AdmissionSnapshot => ({ ...state, attempts: state.attempts.map(attempt => ({ ...attempt })) });
    return Object.freeze({ signal: this.signal, deadlineAt: this.deadlineAt, snapshot,
      reserve: (metadata: AdmissionMetadata, signal?: AbortSignal) => {
        if (!metadata || !['GET', 'HEAD', 'POST'].includes(metadata.method) || !['probe', 'control'].includes(metadata.kind)
          || metadata.operationIndex !== undefined && (!Number.isSafeInteger(metadata.operationIndex) || metadata.operationIndex < 0)) {
          return Promise.reject(new DastAdmissionError('invalid_admission'));
        }
        const meta = { method: metadata.method, kind: metadata.kind, operationIndex: metadata.operationIndex ?? null };
        const combined = signal ? AbortSignal.any([signal, this.signal]) : this.signal;
        const request = this.tail.then(async () => {
          const check = () => {
            if (combined.aborted || Date.now() >= this.deadlineAt) throw new DastAdmissionError('timeout');
            if (this.count >= this.options.maxRequests) throw new DastAdmissionError('request_limit');
          };
          try {
            check();
            const wait = Math.max(0, this.nextAt - Date.now());
            if (wait) await delay(wait, undefined, { signal: combined });
            check();
          } catch (error) {
            state.refused++;
            throw error instanceof DastAdmissionError ? error : new DastAdmissionError('timeout');
          }
          this.count++;
          this.nextAt = Date.now() + 1000 / this.options.ratePerSecond;
          const attempt: AdmissionAttempt = { ordinal: state.requestCount + 1, ...meta, outcome: 'pending' };
          state.requestCount++; state.pending++; state.attempts.push(attempt);
          const finish = (outcome: 'response' | 'transport_error') => {
            if (outcome !== 'response' && outcome !== 'transport_error') throw new DastAdmissionError('invalid_admission');
            if (attempt.outcome !== 'pending') return;
            attempt.outcome = outcome; state.pending--;
            if (outcome === 'response') state.responseCompleted++; else state.transportErrors++;
            combined.removeEventListener('abort', aborted);
          };
          const aborted = () => finish('transport_error');
          combined.addEventListener('abort', aborted, { once: true });
          if (combined.aborted) aborted();
          return Object.freeze({ finish, addBytes: (bytes: number) => {
            if (!Number.isSafeInteger(bytes) || bytes < 0 || !Number.isSafeInteger(state.bytes + bytes)) throw new DastAdmissionError('invalid_admission');
            if (attempt.outcome === 'pending') state.bytes += bytes;
          } });
        });
        this.tail = request.then(() => undefined, () => undefined);
        return request;
      },
    });
  }

  snapshot(): AdmissionSnapshot {
    const total: AdmissionSnapshot = { requestCount: 0, bytes: 0, responseCompleted: 0, transportErrors: 0, pending: 0, refused: 0, attempts: [] };
    for (const task of this.tasks.values()) for (const key of ['requestCount', 'bytes', 'responseCompleted', 'transportErrors', 'pending', 'refused'] as const) total[key] += task[key];
    return total;
  }
  close(): void {
    clearTimeout(this.timer);
    this.options.signal?.removeEventListener('abort', this.onAbort);
    this.controller.abort();
  }
}
