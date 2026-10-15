import { constants } from 'node:fs';
import { access, lstat, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { runProcess } from '../../source/process.js';
import { ProviderFailure } from './record.js';

/** Preserve execFile's caller PATH order and ordinary npm executable symlinks. */
async function executable(): Promise<string> {
  for (const directory of (process.env.PATH ?? '/usr/bin:/bin').split(':').filter(Boolean)) {
    try {
      const path = await realpath(join(directory, 'codex'));
      if (!(await lstat(path)).isFile()) continue;
      await access(path, constants.X_OK);
      return path;
    } catch { /* Try the next caller-approved PATH entry. */ }
  }
  throw new ProviderFailure('sdk_failure');
}

/** Help is not an SDK turn: own its process group and require actual close/cleanup before accepting output. */
export async function codexHelp(directory: string, signal: AbortSignal): Promise<{ executable: string; stdout: string }> {
  if (signal.aborted) throw Error('agent_cancelled');
  const binary = await executable();
  if (signal.aborted) throw Error('agent_cancelled');
  const result = await runProcess(binary, ['exec', '--help'], { cwd: directory, home: directory,
    timeoutMs: 5000, maxOutputBytes: 65536, supervision: 'agent', signal });
  if (result.cleanupConfirmed !== true || result.cleanupState !== 'not_started' && result.closeConfirmed !== true) throw new ProviderFailure('cleanup_error');
  if (signal.aborted || result.cancelled) throw Error('agent_cancelled');
  if (result.timedOut) throw new ProviderFailure('timeout');
  if (result.closeConfirmed !== true || result.cleanupState === 'not_started' || result.exitCode !== 0 || result.signal || result.stopReason || result.spawnError || result.outputLimitExceeded) throw new ProviderFailure('sdk_failure');
  return { executable: binary, stdout: result.stdout };
}
