import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { credentialEnvironment, optionalSdk, recordedAgent, requireLive, type ProviderOptions, type Reply } from './record.js';

export async function createAgent(options: ProviderOptions) {
  requireLive(options);
  const sdk = options.replay === undefined ? await optionalSdk('@anthropic-ai/claude-agent-sdk') : undefined;
  return recordedAgent('claude', options, async (prompt, schema) => {
    const directory = await mkdtemp(join(tmpdir(), 'wakeio-claude-'));
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 60_000);
    let stream: any;
    try {
      stream = sdk.query({ prompt: JSON.stringify({ request: prompt, schema }), options: { cwd: directory, env: { ...credentialEnvironment('ANTHROPIC_API_KEY', directory), CLAUDE_CONFIG_DIR: directory },
        tools: [], allowedTools: [], mcpServers: {}, strictMcpConfig: true, plugins: [], skills: [], settingSources: [],
        settings: { disableAllHooks: true }, permissionMode: 'dontAsk',
        canUseTool: async () => ({ behavior: 'deny', message: 'Tools disabled' }),
        hooks: { PreToolUse: [{ hooks: [async () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'Tools disabled' } })] }] },
        persistSession: false, maxTurns: 2, abortController: abort, stderr: () => {},
        // JSON schema in the prompt avoids the SDK's StructuredOutput tool; the shared parser enforces it.
        systemPrompt: 'Return only JSON matching the supplied schema. No tools are permitted.',
      } });
      let count = 0; const reply: Reply = {};
      for await (const event of stream) {
        if (++count > 256) throw new Error('agent_output_invalid');
        if (event.type === 'assistant' && event.message?.content?.some((block: any) => block.type === 'tool_use')) { abort.abort(); return { toolAttempt: true }; }
        if (event.type === 'result') {
          if (event.subtype !== 'success' || event.is_error || event.permission_denials?.length) throw new Error('agent_output_invalid');
          reply.json = event.structured_output === undefined ? event.result : JSON.stringify(event.structured_output);
          reply.inputTokens = event.usage?.input_tokens; reply.outputTokens = event.usage?.output_tokens;
          return reply;
        }
      }
      throw new Error('agent_output_invalid');
    } finally { clearTimeout(timer); abort.abort(); stream?.close(); await rm(directory, { recursive: true, force: true }); }
  });
}
