import { spawn } from 'node:child_process';
import { redactArtifact } from './artifacts.mjs';

function groupGone(pid) {
  if (!pid) return true;
  try { process.kill(-pid, 0); return false; }
  catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ESRCH') return true;
    return false;
  }
}

/** Trusted QA commands only, POSIX process groups; not an untrusted-code sandbox. */
export async function captureProcess(command, args, options = {}) {
  const { signal, timeoutMs = 5000, maxOutputBytes = 65536, onStdout } = options;
  if (process.platform === 'win32' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1
    || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) throw new TypeError('invalid_process_budget');
  if (signal?.aborted) return { command, args, reason: 'cancelled', exitCode: null,
    signal: null, stdout: '', stderr: '', outputBytes: 0, truncated: false,
    cleanup: { confirmed: true, pid: null, closeConfirmed: true, groupGone: true } };
  const stdout = [], stderr = [];
  let reason = null, outputBytes = 0, exitCode = null, exitSignal = null, closeConfirmed = false;
  let finish, grace;
  const child = spawn(command, args, { detached: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
  const kill = () => {
    if (!child.pid) return;
    try { process.kill(-child.pid, 'SIGKILL'); }
    catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ESRCH')) reason ??= 'cleanup_signal_failed';
    }
  };
  const stop = value => {
    reason ??= value;
    kill();
    grace ??= setTimeout(() => {
      child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish();
    }, 2000);
  };
  const cancel = () => stop('cancelled');
  const collect = (chunk, buffers) => {
    const room = Math.max(0, maxOutputBytes - outputBytes);
    buffers.push(chunk.subarray(0, room));
    outputBytes += chunk.length;
    if (outputBytes > maxOutputBytes) stop('output_limit');
  };
  const completion = new Promise(resolve => {
    finish = resolve;
    child.once('error', () => stop('spawn_error'));
    child.once('exit', (code, sig) => {
      exitCode = code; exitSignal = sig; kill();
      grace ??= setTimeout(() => stop('close_unconfirmed'), 2000);
    });
    child.once('close', () => { closeConfirmed = true; resolve(); });
    child.stdout.on('data', chunk => {
      collect(chunk, stdout);
      try { onStdout?.(Buffer.concat(stdout).toString('utf8')); }
      catch (error) {
        if (!(error instanceof Error)) reason ??= 'handler_non_error';
        stop('handler_error');
      }
    });
    child.stderr.on('data', chunk => collect(chunk, stderr));
  });
  signal?.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(() => stop('timeout'), timeoutMs);
  try {
    if (signal?.aborted) cancel();
    await completion;
  } finally {
    clearTimeout(timer); clearTimeout(grace); signal?.removeEventListener('abort', cancel); kill();
  }
  const gone = groupGone(child.pid);
  const truncated = outputBytes > maxOutputBytes;
  return redactArtifact({ command, args, reason, exitCode, signal: exitSignal,
    // A cap can cut a PEM or credential before its delimiter; never persist that fragment.
    stdout: truncated ? '[TRUNCATED_CAPTURE_DISCARDED]' : Buffer.concat(stdout).toString('utf8'),
    stderr: truncated ? '[TRUNCATED_CAPTURE_DISCARDED]' : Buffer.concat(stderr).toString('utf8'),
    outputBytes, truncated,
    cleanup: { confirmed: closeConfirmed && gone, pid: child.pid ?? null, closeConfirmed, groupGone: gone } });
}
