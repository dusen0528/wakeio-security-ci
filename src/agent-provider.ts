import { constants } from 'node:fs';
import { access, lstat, open, realpath, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { runProcess } from './source/process.js';
import { readJsonInput } from './json-input.js';

export type AdviceAuthMode = 'cli-login' | 'api-key';

export interface ProviderAdviceResult {
  advice: unknown;
  version: string;
  executableSha256: string;
  eventCount: number;
}

const requiredFlags = ['--ignore-user-config', '--ignore-rules', '--strict-config', '--skip-git-repo-check',
  '--ephemeral', '--sandbox', '--disable', '--output-schema', '--output-last-message', '--json'];
// Keep this list aligned with the installed CLI's known feature flags. A later CLI must fail closed when a flag disappears.
const disabledFeatures = ['shell_tool', 'unified_exec', 'shell_snapshot', 'code_mode', 'multi_agent', 'multi_agent_v2',
  'apps', 'plugins', 'hooks', 'browser_use', 'browser_use_external', 'computer_use', 'view_image',
  'image_generation', 'memories', 'in_app_browser', 'skill_mcp_dependency_install'];

async function executable(command: string): Promise<string> {
  const candidates = isAbsolute(command) || command.includes('/') ? [command] :
    (process.env.PATH ?? '').split(':').filter(Boolean).map(path => join(path, command));
  for (const candidate of candidates) {
    try {
      const path = await realpath(candidate);
      if (!(await lstat(path)).isFile()) continue;
      await access(path, constants.X_OK);
      return path;
    } catch { /* Search the next executable path. */ }
  }
  throw new Error('agent_unavailable');
}

async function binaryDigest(path: string, deadline: number, signal: AbortSignal): Promise<string> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > 512 * 1024 * 1024) throw new Error('agent_policy_unsupported');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(64 * 1024);
    let offset = 0;
    while (offset < before.size) {
      if (signal.aborted) throw new Error('agent_cancelled');
      if (Date.now() >= deadline) throw new Error('agent_budget_exhausted');
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, before.size - offset), offset);
      if (!bytesRead) throw new Error('agent_policy_unsupported');
      hash.update(buffer.subarray(0, bytesRead)); offset += bytesRead;
    }
    const after = await handle.stat();
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error('agent_policy_unsupported');
    return hash.digest('hex');
  } finally { await handle.close(); }
}

function parseEvents(stdout: string): number {
  if (!stdout || stdout.length > 1024 * 1024) throw new Error('agent_protocol_invalid');
  const lines = stdout.trim().split('\n');
  if (lines.length > 128) throw new Error('agent_protocol_invalid');
  let thread = 0, turn = 0, completed = 0, finalMessages = 0;
  for (const line of lines) {
    if (line.length > 64 * 1024) throw new Error('agent_protocol_invalid');
    let value: unknown;
    try { value = JSON.parse(line); } catch { throw new Error('agent_protocol_invalid'); }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('agent_protocol_invalid');
    const event = value as Record<string, unknown>;
    if (event.type === 'thread.started' && thread === 0 && turn === 0) { thread++; continue; }
    if (event.type === 'turn.started' && thread === 1 && turn === 0) { turn++; continue; }
    if (event.type === 'turn.completed' && turn === 1 && completed === 0) { completed++; continue; }
    if (['item.started', 'item.updated', 'item.completed'].includes(String(event.type)) && turn === 1 && completed === 0) {
      const item = event.item;
      if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('agent_protocol_invalid');
      const kind = (item as Record<string, unknown>).type;
      if (kind !== 'reasoning' && kind !== 'agent_message') throw new Error('agent_tools_not_allowed');
      if (kind === 'agent_message' && event.type === 'item.completed') finalMessages++;
      continue;
    }
    throw new Error(event.type === 'error' || event.type === 'turn.failed' ? 'agent_execution_failed' : 'agent_protocol_invalid');
  }
  if (thread !== 1 || turn !== 1 || completed !== 1 || finalMessages < 1) throw new Error('agent_protocol_invalid');
  return lines.length;
}

/** Run a no-tool, data-only Codex turn; supplied report content is the only task input. */
export async function codexAdvice(command: string | undefined, authMode: AdviceAuthMode, directory: string,
  deadline: number, prompt: string, schema: unknown, signal: AbortSignal): Promise<ProviderAdviceResult> {
  if (signal.aborted || Date.now() >= deadline) throw new Error('agent_cancelled');
  const key = authMode === 'api-key' ? process.env.CODEX_API_KEY : undefined;
  if (authMode === 'api-key' && (!key || key.length > 16384)) throw new Error('agent_authentication_missing');
  const codexHome = authMode === 'cli-login' ? (process.env.CODEX_HOME || join(homedir(), '.codex')) : undefined;
  if (codexHome) {
    try { if (!isAbsolute(codexHome) || !(await lstat(codexHome)).isDirectory()) throw new Error('invalid'); }
    catch { throw new Error('agent_authentication_missing'); }
  }
  const binary = await executable(command ?? 'codex');
  const settings = { cwd: directory, home: directory, timeoutMs: Math.min(5000, Math.max(1, deadline - Date.now())), maxOutputBytes: 64 * 1024,
    supervision: 'agent' as const, signal };
  const [help, version] = await Promise.all([
    runProcess(binary, ['exec', '--help'], settings), runProcess(binary, ['--version'], settings),
  ]);
  if (signal.aborted || help.cancelled || version.cancelled) throw new Error('agent_cancelled');
  if (Date.now() >= deadline || help.timedOut || version.timedOut) throw new Error('agent_budget_exhausted');
  if (help.exitCode !== 0 || !help.cleanupConfirmed || help.outputLimitExceeded ||
      requiredFlags.some(flag => !help.stdout.includes(flag)) || version.exitCode !== 0 ||
      !version.cleanupConfirmed ||
      !/^codex-cli [a-zA-Z0-9_.+()-]{1,80}$/.test(version.stdout.trim())) throw new Error('agent_policy_unsupported');
  const executableSha256 = await binaryDigest(binary, deadline, signal);
  if (signal.aborted) throw new Error('agent_cancelled');
  if (Date.now() >= deadline) throw new Error('agent_budget_exhausted');
  const schemaPath = join(directory, 'schema.json');
  const responsePath = join(directory, 'response.json');
  await writeFile(schemaPath, JSON.stringify(schema), { mode: 0o600, flag: 'wx' });
  const args = ['exec', '--ignore-user-config', '--ignore-rules', '--strict-config', '--skip-git-repo-check', '--ephemeral',
    '--sandbox', 'read-only', '-c', 'approval_policy="never"', '-c', 'web_search="disabled"',
    ...disabledFeatures.flatMap(feature => ['--disable', feature]), '--output-schema', schemaPath,
    '--output-last-message', responsePath, '--json', '-'];
  const result = await runProcess(binary, args, { ...settings, timeoutMs: Math.max(1, deadline - Date.now()),
    maxOutputBytes: 1024 * 1024, input: prompt,
    ...(authMode === 'api-key' ? { authentication: { variable: 'CODEX_API_KEY' as const, value: key! } } : { codexHome }),
  });
  if (result.cancelled || signal.aborted) throw new Error('agent_cancelled');
  if (result.timedOut) throw new Error('agent_budget_exhausted');
  if (result.outputLimitExceeded) throw new Error('agent_output_limit');
  if (!result.cleanupConfirmed) throw new Error('agent_cleanup_unverified');
  if (result.exitCode !== 0 || result.spawnError || result.signal) throw new Error('agent_execution_failed');
  const eventCount = parseEvents(result.stdout);
  let advice: unknown;
  try { advice = await readJsonInput(responsePath, 64 * 1024); }
  catch { throw new Error('agent_protocol_invalid'); }
  if (signal.aborted) throw new Error('agent_cancelled');
  if (Date.now() >= deadline) throw new Error('agent_budget_exhausted');
  return { advice, version: version.stdout.trim(), executableSha256, eventCount };
}
