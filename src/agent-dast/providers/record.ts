import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseExecutionPlan, type ExecutionPlan } from '../plan.js';
import { parseSelection, summaryInput, type AgentPort, type RoundSummary } from '../loop/agent.js';

export interface Reply { json?: string; toolAttempt?: boolean; inputTokens?: number; outputTokens?: number; purpose?: Purpose; inputDigest?: string; durationMs?: number; provider?: string }
export interface ProviderOptions { template: ExecutionPlan; recordDir: string; replay?: Reply[]; live?: boolean }
export type Purpose = 'plan' | 'select';
export type Transport = (prompt: string, schema: unknown) => Promise<Reply>;
const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const invalid = () => new Error('agent_output_invalid');
const safe = (value: unknown) => {
  const text = JSON.stringify(value);
  if (['CODEX_API_KEY','ANTHROPIC_API_KEY'].some(name => process.env[name] && text.includes(process.env[name]!))) throw invalid();
};
/** SDKs are optional. Never resolve or start them on the replay path. */
export async function optionalSdk(name: string): Promise<any> {
  try { return await import(name); } catch { throw new Error(`optional_sdk_unavailable: ${name}`); }
}
export function requireLive(options: ProviderOptions): void {
  if (options.replay === undefined && (options.live !== true || process.env.WAKEIO_AGENT_LIVE !== '1')) throw new Error('agent_live_disabled');
}
export function credentialEnvironment(name: 'CODEX_API_KEY' | 'ANTHROPIC_API_KEY', directory: string): Record<string,string> {
  const key = process.env[name];
  if (!key || key.length > 16384) throw new Error('agent_authentication_missing');
  return { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: directory, TMPDIR: directory, [name]: key };
}
/** Only validated decisions and bounded usage survive; SDK prose/errors are never recorded. */
export async function recordedAgent(provider: 'codex' | 'claude', options: ProviderOptions, transport: Transport): Promise<AgentPort> {
  requireLive(options);
  const template = parseExecutionPlan(options.template); safe(template);
  const catalog = new Set(template.tasks.map(digest));
  const replies = options.replay === undefined ? undefined : structuredClone(options.replay);
  let cursor = 0, failed = false;
  await mkdir(options.recordDir, { mode: 0o700 });
  for (const name of ['ledger.jsonl','transcript.jsonl']) await writeFile(join(options.recordDir, name), '', { flag: 'wx', mode: 0o600 });
  async function decide(purpose: Purpose, input: RoundSummary): Promise<any> {
    if (failed) throw invalid(); // A provider exhausted its one retry; the outer loop must not acquire more attempts.
    const summary = summaryInput(input);
    const inputDigest = digest({ summary: { ...summary, run_id: '' }, template, purpose }); // Run IDs change across offline replay executions.
    const taskSchema = { enum: template.tasks };
    const schema = purpose === 'plan' ? { type: 'object', additionalProperties: false, required: ['version','kind','origin','tasks'], properties: {
      version: { const: 1 }, kind: { const: template.kind }, origin: { const: template.origin }, tasks: { type: 'array', minItems: 1, maxItems: template.tasks.length, items: taskSchema },
    } } : { type: 'object', additionalProperties: false, required: ['action','tasks'], properties: { action: { enum: ['verify','expand','stop'] }, tasks: { type: 'array', maxItems: template.tasks.length, items: taskSchema } } };
    const prompt = JSON.stringify({ instruction: 'Return only one JSON decision. Use no tools. Choose only from the approved task catalog; stop with empty tasks when no further work is needed.', purpose, summary, template });
    safe(prompt);
    for (let attempt = 0; attempt < 2; attempt++) {
      const start = Date.now(); let reply: Reply = {}, output: unknown, error: 'invalid_output' | 'tools_forbidden' | undefined;
      try {
        reply = replies ? replies[cursor++] ?? {} : await transport(prompt, schema);
        if (reply.provider !== undefined && reply.provider !== provider) throw invalid();
        if (reply.purpose !== undefined && reply.purpose !== purpose || reply.inputDigest !== undefined && reply.inputDigest !== inputDigest) throw invalid();
        if (reply.toolAttempt) { error = 'tools_forbidden'; throw invalid(); }
        if (typeof reply.json !== 'string' || Buffer.byteLength(reply.json) > 65536) throw invalid();
        const value = JSON.parse(reply.json);
        output = purpose === 'plan' ? parseExecutionPlan(value) : parseSelection(value, template.origin);
        const decision = output as ExecutionPlan;
        if (purpose === 'plan' && decision.origin !== template.origin || decision.tasks.some(task => !catalog.has(digest(task)))) throw invalid();
        safe(output);
      } catch { error ??= 'invalid_output'; output = undefined; }
      const token = (value: unknown) => Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null;
      const usage = { provider, purpose, mode: replies ? 'replay' : 'live', attempt: attempt + 1, inputTokens: token(reply.inputTokens), outputTokens: token(reply.outputTokens), durationMs: replies && token(reply.durationMs) !== null ? reply.durationMs : Date.now() - start, status: error ?? 'ok' };
      try {
        await appendFile(join(options.recordDir, 'ledger.jsonl'), JSON.stringify(usage) + '\n');
        await appendFile(join(options.recordDir, 'transcript.jsonl'), JSON.stringify({ version: 1, inputDigest, ...usage, ...(error ? { error } : { output }) }) + '\n');
      } catch { failed = true; throw new Error('agent_recording_failed'); }
      if (!error) return output;
    }
    failed = true; throw invalid();
  }
  return { planTasks: summary => decide('plan', summary), selectNext: summary => decide('select', summary) };
}
export async function replayRecording(path: string): Promise<Reply[]> {
  const text = await readFile(path, 'utf8');
  if (Buffer.byteLength(text) > 1024 * 1024) throw invalid();
  return text.trim().split('\n').map(line => {
    const value = JSON.parse(line);
    if (value.version !== 1 || !['codex','claude'].includes(value.provider) || !['plan','select'].includes(value.purpose)) throw invalid();
    return { ...(value.error ? { toolAttempt: value.error === 'tools_forbidden' } : { json: JSON.stringify(value.output) }), inputTokens: value.inputTokens, outputTokens: value.outputTokens, durationMs: value.durationMs, purpose: value.purpose, provider: value.provider, inputDigest: value.inputDigest };
  });
}
