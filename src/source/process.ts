import { spawn } from "node:child_process";
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
}

function safeTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) return DEFAULT_TOOL_TIMEOUT_MS;
  return Math.min(value, MAX_TOOL_TIMEOUT_MS);
}

function minimalEnvironment(home: string | undefined, additions: Record<string, string> | undefined): NodeJS.ProcessEnv {
  // Keep only paths needed by the binary itself and by a shebang in test
  // adapters. In particular, do not forward proxy, cloud credential, npm, or
  // scanner-specific environment variables from the caller.
  const nodeBin = dirname(process.execPath);
  const path = [nodeBin, "/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    .filter((entry, index, all) => all.indexOf(entry) === index)
    .join(":");
  const allowedAdditions = Object.entries(additions ?? {}).filter(([key, value]) => key === "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" && typeof value === "string" && value.length > 0);
  return {
    PATH: path,
    HOME: home ?? "/tmp",
    LC_ALL: "C",
    LANG: "C",
    TMPDIR: "/tmp",
    ...Object.fromEntries(allowedAdditions),
  };
}

/**
 * Runs a scanner with argv-array semantics, no shell, a bounded output
 * buffer, and a supervisor timeout. Scanner stdout/stderr are returned to a
 * parser and are never copied into reports verbatim.
 */
export function runProcess(executable: string, args: readonly string[], options: ProcessOptions): Promise<ProcessResult> {
  const timeoutMs = safeTimeout(options.timeoutMs);
  const maxOutputBytes = Number.isSafeInteger(options.maxOutputBytes) && (options.maxOutputBytes ?? 0) > 0
    ? Math.min(options.maxOutputBytes!, MAX_PROCESS_OUTPUT_BYTES)
    : MAX_PROCESS_OUTPUT_BYTES;
  return new Promise((resolveResult) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(executable, [...args], {
        cwd: options.cwd,
        env: minimalEnvironment(options.home, options.environment),
        shell: false,
        detached: process.platform !== "win32",
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
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
      resolveResult(result);
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
    timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, timeoutMs);
    timer.unref();
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
