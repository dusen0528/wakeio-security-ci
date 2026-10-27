import { isAbsolute } from 'node:path';
import { MAX_PROCESS_OUTPUT_BYTES, MAX_TOOL_TIMEOUT_MS, runProcess } from '../source/process.js';
import type { ProcessResult } from '../source/types.js';

export const MAX_RUNTIME_INPUT_BYTES = 64 * 1024;
const MAX_ARG_BYTES = 64 * 1024;

export interface RuntimeProcessOptions {
  cwd: string;
  home: string;
  timeoutMs: number;
  deadlineAt: number;
  maxOutputBytes: number;
  input?: string;
  signal?: AbortSignal;
}
export type RuntimeProcessResult = ProcessResult & { completed: boolean };

function notStarted(reason: 'spawn_error' | 'cancelled' | 'timeout'): RuntimeProcessResult {
  return { exitCode: null, signal: null, stdout: '', stderr: '', timedOut: reason === 'timeout',
    outputLimitExceeded: false, cancelled: reason === 'cancelled', stopReason: reason,
    ...(reason === 'spawn_error' ? { spawnError: 'invalid runtime process profile' } : {}),
    cleanupState: 'not_started', cleanupConfirmed: true, closeConfirmed: true, completed: false };
}

function validProfile(executable: string, args: readonly string[], options: RuntimeProcessOptions): boolean {
  const path = (value: unknown): value is string =>
    typeof value === 'string' && isAbsolute(value) && !/[\0\r\n]/.test(value);
  return ['darwin', 'linux'].includes(process.platform) && path(executable) && path(options.cwd)
    && path(options.home) && Array.isArray(args) && args.length <= 256
    && args.every(arg => typeof arg === 'string' && !arg.includes('\0'))
    && args.reduce((bytes, arg) => bytes + Buffer.byteLength(arg) + 1, 0) <= MAX_ARG_BYTES
    && Number.isSafeInteger(options.timeoutMs) && options.timeoutMs > 0
    && options.timeoutMs <= MAX_TOOL_TIMEOUT_MS && Number.isSafeInteger(options.deadlineAt)
    && Number.isSafeInteger(options.maxOutputBytes) && options.maxOutputBytes > 0
    && options.maxOutputBytes <= MAX_PROCESS_OUTPUT_BYTES
    && (options.input === undefined || typeof options.input === 'string'
      && Buffer.byteLength(options.input) <= MAX_RUNTIME_INPUT_BYTES);
}

function checkedResult(result: ProcessResult, stop: 'cancelled' | 'timeout' | undefined,
  maxOutputBytes: number): RuntimeProcessResult {
  const reason = stop && (!result.stopReason || result.stopReason === 'cancelled') ? stop : result.stopReason;
  // Invalid UTF-8 replacement can expand the helper's raw byte buffer. Never return more than the caller's cap.
  const expanded = Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) > maxOutputBytes;
  const stopped = reason ?? (expanded ? 'output_limit' : undefined);
  const cleanup = result.cleanupConfirmed === true && result.closeConfirmed === true
    && ['terminated', 'terminated_zombies', 'not_started'].includes(result.cleanupState ?? '');
  return { ...result, stdout: cleanup && !expanded ? result.stdout : '',
    stderr: cleanup && !expanded ? result.stderr : '', stopReason: stopped ?? (!cleanup ? 'close_unknown' : undefined),
    timedOut: stopped === 'timeout', cancelled: stopped === 'cancelled',
    outputLimitExceeded: result.outputLimitExceeded || expanded,
    completed: result.exitCode === 0 && result.signal === null && !stopped && !result.spawnError
      && !result.timedOut && !result.cancelled && !result.outputLimitExceeded && cleanup };
}

/** Trusted tools only: caller owns executable/argv/cwd/home. Never run source scripts on the host.
 * Reuses argv-only minimal-env supervision without exposing its authentication or environment additions.
 * Group cleanup covers descendants remaining in the owned PGID; this is not a sandbox or container cleanup.
 */
export async function runRuntimeProcess(executable: string, args: readonly string[],
  configuration: RuntimeProcessOptions): Promise<RuntimeProcessResult> {
  const options = { ...configuration };
  if (!validProfile(executable, args, options)) return notStarted('spawn_error');
  if (options.signal?.aborted) return notStarted('cancelled');
  const timeoutMs = Math.min(options.timeoutMs, options.deadlineAt - Date.now());
  if (timeoutMs <= 0) return notStarted('timeout');
  const controller = new AbortController();
  let stopped: 'timeout' | 'cancelled' | undefined;
  const stop = (reason: 'timeout' | 'cancelled') => { stopped ??= reason; controller.abort(); };
  const onAbort = () => stop('cancelled');
  options.signal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => stop('timeout'), timeoutMs);
  try {
    if (options.signal?.aborted) onAbort();
    const result = await runProcess(executable, [...args], { cwd: options.cwd, home: options.home,
      timeoutMs, maxOutputBytes: options.maxOutputBytes, input: options.input,
      signal: controller.signal, supervision: 'agent' });
    return checkedResult(result, stopped, options.maxOutputBytes);
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  }
}
