import { spawn, execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

/** Cooperative shutdown of the trusted CLI and observed owned detached engine
 * groups. Process observation is not an arbitrary-code or hostile-process sandbox. */
export async function superviseCli(command, args, { cwd, env, timeoutMs, maxOutputBytes, signal }) {
  if (process.platform === 'win32' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) {
    throw Error('unsupported_cli_supervision');
  }
  if (signal.aborted) return { exitCode: null, signal: null, reason: 'cancelled', stdout: '', cleanupConfirmed: true, closeConfirmed: false };
  const child = spawn(command, args, { cwd, env, shell: false, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const pids = new Set(child.pid ? [child.pid] : []), groups = new Set(child.pid ? [child.pid] : []);
  let observationFailed = false, exitCode = null, exitSignal = null, closeConfirmed = false, reason = null, size = 0;
  const output = []; let settle, settled = false, graceTimer, settlementTimer, closeTimer;
  const rows = () => {
    try {
      return execFileSync('ps', ['-eo', 'pid=,ppid=,pgid=,stat='], { encoding: 'utf8', timeout: 250, maxBuffer: 4 * 1024 * 1024 })
        .trim().split('\n').filter(Boolean).map(row => { const [pid, ppid, pgid, stat] = row.trim().split(/\s+/); return { pid: Number(pid), ppid: Number(ppid), pgid: Number(pgid), stat }; });
    } catch { observationFailed = true; return []; }
  };
  const observe = () => {
    const current = rows(); let changed = true;
    while (changed) {
      changed = false;
      for (const row of current) if (pids.has(row.ppid) && !pids.has(row.pid)) { pids.add(row.pid); changed = true; }
    }
    // A detached group's leader must itself have been observed as our child.
    for (const row of current) if (pids.has(row.pid) && pids.has(row.pgid)) groups.add(row.pgid);
    return current;
  };
  const active = current => current.filter(row => (pids.has(row.pid) || groups.has(row.pgid)) && !row.stat?.startsWith('Z'));
  const send = (pid, sig, group = false) => {
    try { process.kill(group ? -pid : pid, sig); } catch { /* Observation determines cleanup. */ }
  };
  const killOwned = () => {
    const current = observe();
    for (const group of groups) send(group, 'SIGKILL', true);
    // Include an observed descendant whose group leader was outside our tree;
    // we may kill this PID, but must never claim authority over that group.
    for (const row of current) if (pids.has(row.pid) && !groups.has(row.pgid)) send(row.pid, 'SIGKILL');
  };
  const finish = () => { if (!settled) { settled = true; settle?.(); } };
  const stop = value => {
    if (reason) return; reason = value; observe();
    if (child.pid) send(child.pid, 'SIGTERM', true);
    // Native DAST closes sockets, Schemathesis kills/awaits its own isolated
    // Python group, and Nuclei forwards TERM/KILL before the CLI is escalated.
    graceTimer = setTimeout(killOwned, 1500);
    settlementTimer = setTimeout(() => {
      killOwned(); child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish();
    }, 4000);
  };
  const abort = () => stop('cancelled'); signal.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => stop('timeout'), timeoutMs);
  const poll = setInterval(observe, 25);
  const collect = (chunk, retain) => {
    const room = Math.max(0, maxOutputBytes - size);
    if (retain && room) output.push(chunk.subarray(0, room));
    size += chunk.length; if (size > maxOutputBytes) stop('output_limit');
  };
  child.stdout.on('data', chunk => collect(chunk, true));
  child.stderr.on('data', chunk => collect(chunk, false));
  await new Promise(resolve => {
    settle = resolve;
    child.once('error', () => { reason ??= 'spawn_error'; finish(); });
    child.once('exit', (code, sig) => {
      exitCode = code; exitSignal = sig; observe();
      closeTimer = setTimeout(() => {
        reason ??= 'close_unknown'; killOwned(); child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish();
      }, 2000);
    });
    child.once('close', () => { closeConfirmed = true; finish(); });
    if (signal.aborted) abort();
  });
  clearTimeout(timer); clearTimeout(graceTimer); clearTimeout(settlementTimer); clearTimeout(closeTimer); clearInterval(poll);
  signal.removeEventListener('abort', abort);
  let remaining = active(observe());
  if (remaining.length) {
    reason ??= 'owned_descendants_remaining'; killOwned();
    const deadline = Date.now() + 2000;
    while (remaining.length && Date.now() < deadline) { await delay(25); remaining = active(observe()); }
  }
  return { exitCode, signal: exitSignal, reason, stdout: Buffer.concat(output).toString('utf8'),
    cleanupConfirmed: closeConfirmed && !observationFailed && remaining.length === 0, closeConfirmed };
}
