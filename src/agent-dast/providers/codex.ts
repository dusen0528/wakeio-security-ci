import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { credentialEnvironment, optionalSdk, recordedAgent, requireLive, type ProviderOptions, type Reply } from './record.js';

// Same fail-closed feature policy as agent-provider.ts; that module keeps its list private.
const disabledFeatures = ['shell_tool','unified_exec','shell_snapshot','code_mode','multi_agent','multi_agent_v2',
  'apps','plugins','hooks','browser_use','browser_use_external','computer_use','view_image',
  'image_generation','memories','in_app_browser','skill_mcp_dependency_install'];
export async function createAgent(options: ProviderOptions & { authMode?: 'api-key' | 'cli-login' }) {
  requireLive(options);
  const sdk = options.replay === undefined ? await optionalSdk('@openai/codex-sdk') : undefined;
  return recordedAgent('codex', options, async (prompt, schema) => {
    const directory = await mkdtemp(join(tmpdir(), 'wakeio-codex-'));
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 60_000);
    try {
      const env = options.authMode === 'cli-login'
        ? { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: directory, TMPDIR: directory, CODEX_HOME: process.env.CODEX_HOME || join(homedir(), '.codex') }
        : { ...credentialEnvironment('CODEX_API_KEY', directory), CODEX_HOME: directory };
      const help = await promisify(execFile)('codex', ['exec','--help'], { env, timeout: 5000, maxBuffer: 65536 });
      const flags = ['--ignore-user-config','--ignore-rules','--strict-config','--ephemeral','--disable'];
      if (flags.some(flag => !help.stdout.includes(flag))) throw new Error('agent_policy_unsupported');
      // The SDK does not expose isolation flags. Its executable adapter inserts the existing CLI policy before exec arguments.
      const executable = join(directory, 'sdk-exec');
      await writeFile(executable, `#!/bin/sh\n[ "$1" = exec ] || exit 64\nshift\nexec codex exec ${flags.slice(0,4).join(' ')} ${disabledFeatures.map(name => '--disable ' + name).join(' ')} "$@"\n`, { mode: 0o700, flag: 'wx' });
      const codex = new sdk.Codex({ codexPathOverride: executable, env, config: { approval_policy: 'never', web_search: 'disabled' } });
      const thread = codex.startThread({ workingDirectory: directory, sandboxMode: 'read-only', skipGitRepoCheck: true, approvalPolicy: 'never', networkAccessEnabled: false, webSearchMode: 'disabled' });
      const { events } = await thread.runStreamed(prompt, { outputSchema: schema, signal: abort.signal });
      let count = 0, completed = false; const reply: Reply = {};
      for await (const event of events) {
        if (++count > 256) throw new Error('agent_output_invalid');
        if (['item.started','item.updated','item.completed'].includes(event.type)) {
          if (!['reasoning','agent_message'].includes(event.item?.type)) { abort.abort(); return { toolAttempt: true }; }
          if (event.type === 'item.completed' && event.item.type === 'agent_message') reply.json = event.item.text;
        } else if (event.type === 'turn.completed') {
          completed = true; reply.inputTokens = event.usage?.input_tokens; reply.outputTokens = event.usage?.output_tokens;
        } else if (!['thread.started','turn.started'].includes(event.type)) throw new Error('agent_output_invalid');
      }
      if (!completed) throw new Error('agent_output_invalid');
      return reply;
    // The SDK iterator kills its child on close; aborting after it removes listeners emits an unhandled error.
    } finally { clearTimeout(timer); await rm(directory, { recursive: true, force: true }); }
  });
}
