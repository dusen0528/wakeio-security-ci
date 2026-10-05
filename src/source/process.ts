import { spawn, execFileSync } from "node:child_process";
import { access, constants, lstat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { ProcessResult } from "./types.js";

export const DEFAULT_TOOL_TIMEOUT_MS = 120_000;
export const MAX_TOOL_TIMEOUT_MS = 600_000;
export const MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024;

export interface ProcessOptions {
  cwd: string;
  timeoutMs: number;
  maxOutputBytes?: number;
  /** A private temporary home prevents user scanner configuration loading. */
  home?: string;
  /** Narrow, explicit additions for a scanner's prepared local database. */
  environment?: Record<string, string>;
  /** Bounded protocol input, never a shell command. */
  input?: string;
  /** Explicit provider-only authentication; never pass this to target/scanner processes. */
  authentication?: { variable: 'CODEX_API_KEY' | 'ANTHROPIC_API_KEY'; value: string };
  signal?: AbortSignal;
  tmpdir?: string;
  /** Narrow offline-native lane: confirmed group cleanup and sampled RSS. */
  supervision?: 'native-offline';
}

function safeTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) return DEFAULT_TOOL_TIMEOUT_MS;
  return Math.min(value, MAX_TOOL_TIMEOUT_MS);
}

function minimalEnvironment(home: string | undefined, additions: Record<string, string> | undefined, authentication: ProcessOptions['authentication']): NodeJS.ProcessEnv {
  // Keep only paths needed by the binary itself and by a shebang in test
  // adapters. In particular, do not forward proxy, cloud credential, npm, or
  // scanner-specific environment variables from the caller.
  const nodeBin = dirname(process.execPath);
  const path = [nodeBin, "/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    .filter((entry, index, all) => all.indexOf(entry) === index)
    .join(":");
  const allowedAdditions = Object.entries(additions ?? {}).filter(([key, value]) => key === "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" && typeof value === "string" && value.length > 0);
  const auth = authentication && ['CODEX_API_KEY', 'ANTHROPIC_API_KEY'].includes(authentication.variable) &&
    typeof authentication.value === 'string' && authentication.value.length > 0 && authentication.value.length <= 16384
    ? { [authentication.variable]: authentication.value } : {};
  return {
    PATH: path,
    HOME: home ?? "/tmp",
    LC_ALL: "C",
    LANG: "C",
    TMPDIR: "/tmp",
    ...Object.fromEntries(allowedAdditions),
    ...auth,
  };
}

/**
 * Runs a scanner with argv-array semantics, no shell, a bounded output
 * buffer, and a supervisor timeout. Scanner stdout/stderr are returned to a
 * parser and are never copied into reports verbatim.
 */
export function runProcess(executable: string, args: readonly string[], options: ProcessOptions): Promise<ProcessResult> {
  if (options.supervision === 'native-offline') return runStrictProcess(executable, args, options);
  if (options.signal?.aborted) return Promise.resolve({ exitCode: null, signal: null, stdout: '', stderr: '', timedOut: false, outputLimitExceeded: false, cancelled: true });
  const timeoutMs = safeTimeout(options.timeoutMs);
  const maxOutputBytes = Number.isSafeInteger(options.maxOutputBytes) && (options.maxOutputBytes ?? 0) > 0
    ? Math.min(options.maxOutputBytes!, MAX_PROCESS_OUTPUT_BYTES)
    : MAX_PROCESS_OUTPUT_BYTES;
  return new Promise((resolveResult) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(executable, [...args], {
        cwd: options.cwd,
        env: minimalEnvironment(options.home, options.environment, options.authentication),
        shell: false,
        detached: process.platform !== "win32",
        windowsHide: true,
        stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      });
    } catch {
      resolveResult({ exitCode: null, signal: null, stdout: "", stderr: "", timedOut: false, outputLimitExceeded: false, spawnError: "scanner could not be started" });
      return;
    }

    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let outputLimitExceeded = false;
    let outputBytes = 0;
    let timer: NodeJS.Timeout | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    let settleTimer: NodeJS.Timeout | undefined;

    const signalProcessGroup = (signal: NodeJS.Signals): void => {
      try {
        if (process.platform !== "win32" && child.pid) {
          try { process.kill(-child.pid, signal); }
          catch { child.kill(signal); }
        } else child.kill(signal);
      } catch {
        // The process may have exited between the timeout and this signal.
      }
    };
    const stop = (): void => {
      signalProcessGroup("SIGTERM");
      killTimer = setTimeout(() => signalProcessGroup("SIGKILL"), 250);
      killTimer.unref();
      // A descendant that inherited stdio can otherwise keep the close event
      // open. Group termination is attempted above, and this final deadline
      // keeps the promise bounded even if the operating system refuses it.
      settleTimer = setTimeout(() => finish({ exitCode: null, signal: "SIGKILL", stdout, stderr, timedOut, outputLimitExceeded }), 2_000);
      settleTimer.unref();
    };
    const finish = (result: ProcessResult): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      if (settleTimer) clearTimeout(settleTimer);
      options.signal?.removeEventListener('abort', onAbort);
      resolveResult({ ...result, ...(options.signal?.aborted ? { cancelled: true } : {}) });
    };
    const append = (target: "stdout" | "stderr", chunk: Buffer): void => {
      if (settled) return;
      if (outputBytes + chunk.byteLength > maxOutputBytes) {
        outputLimitExceeded = true;
        stop();
        return;
      }
      outputBytes += chunk.byteLength;
      const text = chunk.toString("utf8");
      if (target === "stdout") stdout += text;
      else stderr += text;
    };
    child.stdout?.on("data", (chunk: Buffer) => append("stdout", chunk));
    child.stderr?.on("data", (chunk: Buffer) => append("stderr", chunk));
    child.once("error", () => {
      finish({ exitCode: null, signal: null, stdout, stderr: "", timedOut, outputLimitExceeded, spawnError: "scanner could not be started" });
    });
    child.once("close", (exitCode, signal) => {
      finish({ exitCode, signal, stdout, stderr, timedOut, outputLimitExceeded });
    });
    const onAbort = (): void => stop();
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, timeoutMs);
    timer.unref();
    child.stdin?.on('error', () => { /* Close/error is the authoritative result. */ });
    if (options.input !== undefined) child.stdin?.end(options.input);
  });
}

const STRICT_PS_ENV = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };
const STRICT_RSS_CAP = 512 * 1024 * 1024;

/** Owned PGID only. Sampled observation is not hard memory isolation. */
function strictRows(): Array<{ pid: number; pgid: number; rss: number; state: string }> {
  const output = execFileSync('/bin/ps', ['-eo', 'pid=,pgid=,rss=,stat='], {
    env: STRICT_PS_ENV, encoding: 'utf8', timeout: 250, maxBuffer: 2 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return parseStrictRows(output);
}

/** Internal bounded ps protocol parser; no process discovery by argv. */
export function parseStrictRows(output: string): Array<{ pid: number; pgid: number; rss: number; state: string }> {
  if (!output.trim()) throw new Error('empty ps observation');
  const rows = output.trim().split('\n').map((line) => {
    const fields = line.trim().split(/\s+/);
    if (fields.length !== 4 || !fields.slice(0, 3).every((part) => /^\d+$/.test(part))) throw new Error('ps protocol');
    if (!/^[?HIDRSTUWZXtKP][<NLSsl+>EVWXA]*$/.test(fields[3])) throw new Error('ps state');
    const [pid, pgid, rss] = fields.slice(0, 3).map(Number);
    if (![pid, pgid, rss].every(Number.isSafeInteger)) throw new Error('ps range');
    return { pid, pgid, rss, state: fields[3] };
  });
  return rows;
}

export function observeOwnedGroup(pid: number): NonNullable<ProcessResult['cleanupState']> {
  if (!Number.isSafeInteger(pid) || pid < 1) return 'unknown';
  try { process.kill(-pid, 0); }
  catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ESRCH') return 'terminated';
    return 'unknown';
  }
  try {
    const members = strictRows().filter((row) => row.pgid === pid);
    if (members.length === 0) return 'terminated';
    if (members.some((row) => row.state.startsWith('?'))) return 'unknown';
    return members.every((row) => row.state.startsWith('Z')) ? 'terminated_zombies' : 'running';
  } catch { return 'unknown'; }
}

async function runStrictProcess(executable: string, args: readonly string[], options: ProcessOptions): Promise<ProcessResult> {
  const empty = { exitCode: null, signal: null, stdout: '', stderr: '', timedOut: false, outputLimitExceeded: false };
  if (options.signal?.aborted) return { ...empty, cancelled: true, stopReason: 'cancelled', exited: false, closeConfirmed: false, cleanupState: 'not_started', cleanupConfirmed: true };
  if (!['darwin', 'linux'].includes(process.platform) || !options.home || !options.tmpdir || options.authentication || options.environment || options.input !== undefined) {
    return { ...empty, spawnError: 'invalid strict process profile', stopReason: 'spawn_error', cleanupState: 'not_started', cleanupConfirmed: true };
  }
  const started = Date.now();
  const timeoutMs = Math.min(safeTimeout(options.timeoutMs), 10_000);
  const maxOutputBytes = Math.min(options.maxOutputBytes ?? MAX_PROCESS_OUTPUT_BYTES, MAX_PROCESS_OUTPUT_BYTES);
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) return { ...empty, spawnError: 'invalid output budget', stopReason: 'spawn_error' };
  const rss: NonNullable<ProcessResult['rss']> = { assessment: 'unassessed', samples: 0, failedSamples: 0, peakBytes: 0, capBytes: STRICT_RSS_CAP };
  let child: ReturnType<typeof spawn>;
  try {
    child = spawn(executable, [...args], { cwd: options.cwd, shell: false, detached: true,
      env: { ...STRICT_PS_ENV, HOME: options.home, TMPDIR: options.tmpdir }, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch { return { ...empty, spawnError: 'scanner could not be started', stopReason: 'spawn_error', cleanupState: 'not_started', cleanupConfirmed: true, rss }; }
  let exitCode: number | null = null, exitSignal: NodeJS.Signals | null = null;
  let exited = false, closed = false, finished = false, stopping = false;
  let reason: ProcessResult['stopReason'], outputBytes = 0, spawnError: string | undefined;
  const stdout: Buffer[] = [], stderr: Buffer[] = [];
  let deadlineTimer: NodeJS.Timeout | undefined, sampleTimer: NodeJS.Timeout | undefined;
  let escalationTimer: NodeJS.Timeout | undefined, settlementTimer: NodeJS.Timeout | undefined;
  const signalGroup = (signal: NodeJS.Signals): void => {
    if (!child.pid) return;
    try { process.kill(-child.pid, signal); } catch { /* Observation, not delivery, decides cleanup. */ }
  };
  // No timer is unref'd: cleanup must keep the command alive after root/stdio close.
  return new Promise<ProcessResult>((resolveResult) => {
    const finish = (): void => {
      if (finished) return;
      finished = true;
      clearTimeout(deadlineTimer); clearInterval(sampleTimer); clearTimeout(escalationTimer); clearTimeout(settlementTimer);
      options.signal?.removeEventListener('abort', onAbort);
      const cleanupState = child.pid ? observeOwnedGroup(child.pid) : 'not_started';
      const cleanupConfirmed = ['terminated', 'terminated_zombies', 'not_started'].includes(cleanupState) && (closed || !child.pid);
      rss.assessment = rss.samples > 0 && rss.failedSamples === 0 ? 'measured' : 'unassessed';
      if (!reason && rss.assessment !== 'measured') reason = 'observer_unknown';
      if (!closed && child.pid && !reason) reason = 'close_unknown';
      child.stdout?.destroy(); child.stderr?.destroy(); child.unref();
      resolveResult({ exitCode, signal: exitSignal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'),
        timedOut: reason === 'timeout', outputLimitExceeded: reason === 'output_limit', cancelled: reason === 'cancelled',
        ...(reason ? { stopReason: reason } : {}), ...(spawnError ? { spawnError } : {}),
        exited, closeConfirmed: closed, cleanupState, cleanupConfirmed, rss });
    };
    const maybeFinish = (): void => {
      if (!closed || !child.pid) { if (closed) finish(); return; }
      const state = observeOwnedGroup(child.pid);
      if (state === 'terminated' || state === 'terminated_zombies') finish();
    };
    const stop = (value?: ProcessResult['stopReason']): void => {
      if (value) reason ??= value;
      if (stopping || finished) return;
      stopping = true;
      signalGroup('SIGTERM');
      escalationTimer = setTimeout(() => { signalGroup('SIGKILL'); maybeFinish(); }, 250);
      settlementTimer = setTimeout(() => { signalGroup('SIGKILL'); finish(); }, 2_000);
    };
    const onAbort = (): void => stop('cancelled');
    const sample = (): void => {
      if (finished || exited || !child.pid) return;
      try {
        const members = strictRows().filter((row) => row.pgid === child.pid && !row.state.startsWith('Z'));
        if (members.some((row) => row.state.startsWith('?'))) throw new Error('owned state unknown');
        if (members.length > 4096) throw new Error('owned group cap');
        if (members.length > 0) {
          const bytes = members.reduce((total, row) => total + row.rss * 1024, 0);
          if (!Number.isSafeInteger(bytes)) throw new Error('rss overflow');
          rss.samples++; rss.peakBytes = Math.max(rss.peakBytes, bytes);
          if (bytes > rss.capBytes) stop('rss_limit');
        }
      } catch { rss.failedSamples++; stop('observer_unknown'); }
      if (!exited && Date.now() - started >= timeoutMs) stop('timeout');
    };
    const collect = (chunk: Buffer, output: Buffer[]): void => {
      if (finished) return;
      const room = Math.max(0, maxOutputBytes - outputBytes);
      if (room) output.push(chunk.subarray(0, room));
      outputBytes += chunk.length;
      if (outputBytes > maxOutputBytes) stop('output_limit');
    };
    child.stdout?.on('data', (chunk: Buffer) => collect(chunk, stdout));
    child.stderr?.on('data', (chunk: Buffer) => collect(chunk, stderr));
    child.once('error', () => { spawnError = 'scanner could not be started'; reason ??= 'spawn_error'; stop('spawn_error'); });
    child.once('exit', (code, signal) => { exited = true; exitCode = code; exitSignal = signal; stop(); });
    child.once('close', () => { closed = true; stop(); maybeFinish(); });
    options.signal?.addEventListener('abort', onAbort, { once: true });
    deadlineTimer = setTimeout(() => stop('timeout'), timeoutMs);
    sampleTimer = setInterval(() => { sample(); if (exited) maybeFinish(); }, 100);
    sample();
    if (options.signal?.aborted) onAbort();
  });
}

function executableCandidates(command: string): string[] {
  if (isAbsolute(command) || command.includes("/") || command.includes("\\")) return [resolve(command)];
  const pathEntries = [
    dirname(process.execPath),
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    ...(process.env.PATH ?? "").split(":").filter(Boolean),
  ];
  return pathEntries.filter((entry, index, all) => all.indexOf(entry) === index).map((entry) => join(entry, command));
}

export async function findExecutable(command: string | undefined): Promise<string | undefined> {
  if (!command || command.includes("\0")) return undefined;
  for (const candidate of executableCandidates(command)) {
    try {
      const stat = await lstat(candidate);
      if (!stat.isFile()) continue;
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Continue through the deterministic candidate list.
    }
  }
  return undefined;
}
