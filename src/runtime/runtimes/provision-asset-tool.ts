import { spawn } from 'node:child_process';
import type { Readable } from 'node:stream';
import { lstat } from 'node:fs/promises';
import { assetGuard, assetRemaining, ProvisionAssetError } from './provision-asset-error.js';

type PlatformTool = '/usr/bin/bsdtar' | '/usr/bin/codesign';
export interface AssetToolOptions {
  readonly cwd: string;
  readonly signal: AbortSignal;
  readonly inputFd?: number;
}

/** Fixed platform tools only. Never invokes a vendor binary, shell, user argv, PATH, or inherited environment. */
export async function assetTool<T>(invocation: {
  readonly tool: PlatformTool; readonly args: readonly string[];
}, options: AssetToolOptions, consume: (stdout: Readable) => Promise<T>): Promise<T> {
  assetRemaining(options.signal);
  const before = await lstat(invocation.tool);
  assetGuard(before.isFile() && before.uid === 0 && (before.mode & 0o022) === 0, 'platform_unavailable');
  const child = spawn(invocation.tool, [...invocation.args], {
    cwd: options.cwd, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', TZ: 'UTC',
      HOME: options.cwd, TMPDIR: options.cwd }, signal: options.signal, killSignal: 'SIGKILL',
    stdio: ['ignore', 'pipe', 'pipe', options.inputFd ?? 'ignore'],
  });
  // Node's extra-FD overload does not retain the pipe-specific stdout/stderr types.
  assetGuard(child.stdout && child.stderr, 'tool_failed');
  const stdout = child.stdout, stderr = child.stderr;
  const completion = new Promise<void>((resolve, reject) => {
    let failure: Error | undefined, stderrBytes = 0;
    child.on('error', error => { failure = error; });
    stderr.on('data', (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 16384) { failure = new ProvisionAssetError('tool_failed'); child.kill('SIGKILL'); }
    });
    child.once('close', (code, signal) => {
      if (failure) reject(failure);
      else if (code !== 0 || signal !== null) reject(new ProvisionAssetError('tool_failed'));
      else resolve();
    });
  });
  // Subscribe to close/error before consuming. Always reap, including when a stream guard rejects.
  const consumed = consume(stdout).catch(error => { child.kill('SIGKILL'); throw error; });
  const results = await Promise.allSettled([consumed, completion]);
  const after = await lstat(invocation.tool);
  assetGuard(before.dev === after.dev && before.ino === after.ino && before.size === after.size
    && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'identity_changed');
  const [body, exit] = results;
  if (body.status === 'rejected') throw body.reason;
  if (exit.status === 'rejected') throw exit.reason;
  assetRemaining(options.signal);
  return body.value;
}

export async function toolText(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of stream) {
    assetGuard(Buffer.isBuffer(chunk), 'tool_failed');
    bytes += chunk.length;
    assetGuard(bytes <= 1024 * 1024, 'tool_failed');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}
