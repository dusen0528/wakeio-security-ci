import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { openRunStore } from '../src/agent-dast/store.js';
import { runAgentLoop } from '../src/agent-dast/loop/loop.js';

const template = { version: 1 as const, kind: 'wakeio.execution-plan' as const, origin: 'http://127.0.0.1', tasks: [{ id: 't-exposure', engine: 'nuclei' as const, scopes: ['exposures' as const], maxRequests: 8 }] };
const summary = { run_id: 'r-recon', tasks: { queued: 0, running: 0, completed: 0, partial: 0, error: 0, skipped: 0 }, findings: { candidate: 0, confirmed: 0, rejected: 0 }, open_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, gaps: {}, needs_verify: 0, needs_retry: 0 };
for (const provider of ['codex','claude'] as const) {
  test(`${provider}: offline plan, selection and sanitized recording`, async () => {
    const root = await mkdtemp(join(tmpdir(), 'wakeio-provider-'));
    try {
      const { createAgent } = await import(`../src/agent-dast/providers/${provider}.js`);
      const { replayRecording } = await import('../src/agent-dast/providers/record.js');
      const agent = await createAgent({ template, recordDir: join(root, 'record'), replay: [
        { json: JSON.stringify(template), inputTokens: 10, outputTokens: 5 },
        { json: JSON.stringify({ action: 'stop', tasks: [] }), inputTokens: 12, outputTokens: 3 },
      ] });
      assert.deepEqual(await agent.planTasks({ ...summary, raw: 'RAW_RESPONSE_CANARY' }), template);
      assert.deepEqual(await agent.selectNext(summary), { action: 'stop', tasks: [] });
      const transcript = await readFile(join(root, 'record/transcript.jsonl'), 'utf8');
      const ledger = await readFile(join(root, 'record/ledger.jsonl'), 'utf8');
      assert.ok(!transcript.includes('RAW_RESPONSE_CANARY'));
      assert.ok(!transcript.includes('API_KEY')); assert.ok(!ledger.includes('API_KEY'));
      const rows = ledger.trim().split('\n').map(s => JSON.parse(s));
      assert.equal(rows.length, 2); assert.equal(rows[0].provider, provider); assert.equal(rows[0].inputTokens, 10); assert.ok(rows[0].durationMs >= 0);
      const repeated = await createAgent({ template, recordDir: join(root, 'replay'), replay: await replayRecording(join(root, 'record/transcript.jsonl')) });
      assert.deepEqual(await repeated.planTasks(summary), template);
      assert.deepEqual(await repeated.selectNext({ ...summary, run_id: 'r-new-round' }), { action: 'stop', tasks: [] });
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  for (const failure of ['json','tool','secret'] as const) test(`${provider}: ${failure} rejected after one retry`, async () => {
    const root = await mkdtemp(join(tmpdir(), 'wakeio-provider-'));
    try {
      const { createAgent } = await import(`../src/agent-dast/providers/${provider}.js`);
      const reply = failure === 'json' ? { json: 'RAW_RESPONSE_CANARY not JSON' } : failure === 'tool' ? { json: JSON.stringify(template), toolAttempt: true } : { json: JSON.stringify({ ...template, secret: 'KEY_CANARY' }) };
      const agent = await createAgent({ template, recordDir: join(root, 'record'), replay: [reply,reply,{ json: JSON.stringify(template) }] });
      const store = await openRunStore(':memory:');
      store.createRun({ runId: 'r-recon', targetOrigin: template.origin, scopeHash: 'a'.repeat(64), provider: 'fixed', startedAt: new Date().toISOString() });
      const result = await runAgentLoop({ agent, reconStore: store, reconRunId: 'r-recon', origin: template.origin, outDir: join(root, 'loop'), taskCatalog: [{ checkId: 'c-exposure', task: template.tasks[0] }], coverageCells: [{ surface: 'GET /', checkId: 'c-exposure' }], sharedRequestCap: 8, execution: { consent: true, allowedOrigin: template.origin, inputs: { version: 1, inputs: [] } } });
      store.close(); assert.equal(result.status, 'error'); assert.equal(result.rounds.length, 0);
      await assert.rejects(agent.planTasks(summary), /agent_output_invalid/);
      const ledger = await readFile(join(root, 'record/ledger.jsonl'), 'utf8');
      assert.equal(ledger.trim().split('\n').length, 2);
      const transcript = await readFile(join(root, 'record/transcript.jsonl'), 'utf8');
      assert.ok(!transcript.includes('RAW_RESPONSE_CANARY')); assert.ok(!transcript.includes('KEY_CANARY'));
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  test(`${provider}: live calls disabled without explicit flag`, async () => {
    const { createAgent } = await import(`../src/agent-dast/providers/${provider}.js`);
    await assert.rejects(createAgent({ template, recordDir: '/unused', live: false }), /agent_live_disabled/);
  });
  // The required-engine receipt forbids skipped tests; live smoke belongs only to the opt-in provider suite.
  if (process.env.WAKEIO_REQUIRE_SCHEMATHESIS !== '1') test(`${provider}: optional live schema smoke`, { skip: process.env.WAKEIO_AGENT_LIVE !== '1' }, async () => {
    const root = await mkdtemp(join(tmpdir(), 'wakeio-provider-live-'));
    try {
      const { createAgent } = await import(`../src/agent-dast/providers/${provider}.js`);
      const agent = await createAgent({ template, recordDir: join(root, 'record'), live: true });
      assert.equal((await agent.planTasks(summary)).kind, template.kind);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}

const sdkScript = `
import {mock} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {promisify} from 'node:util';
import net from 'node:net';
let sockets=0;mock.method(net.Socket.prototype,'connect',()=>{sockets++;throw Error('network_forbidden')});
const provider=process.argv[1], attack=process.argv[2]==='tool';
const template=${JSON.stringify(template)}, summary=${JSON.stringify(summary)};
process.env.WAKEIO_AGENT_LIVE='1';process.env.CODEX_API_KEY='KEY_CANARY_123';process.env.ANTHROPIC_API_KEY='KEY_CANARY_456';process.env.PRIVATE_CANARY='PRIVATE';
let calls=0, constructorOptions, threadOptions, queryOptions, executableText;
const fakeExec=()=>{};fakeExec[promisify.custom]=async()=>({stdout:'--ignore-user-config --ignore-rules --strict-config --ephemeral --disable',stderr:''});
mock.module('node:child_process',{namedExports:{execFile:fakeExec}});
const record=await import('./build/src/agent-dast/providers/record.js');
const sdk = {
 Codex: class {
  constructor(options) { constructorOptions = options; }
  startThread(options) {
   threadOptions = options;
   return { runStreamed: async (_prompt, options) => {
    if (process.argv[2] === 'cleanup') options.signal.addEventListener('abort', () => { throw Error('abort_after_sdk_cleanup'); });
    calls++; executableText = await readFile(constructorOptions.codexPathOverride, 'utf8');
    return { events: (async function* () {
     yield { type: 'thread.started' }; yield { type: 'turn.started' };
     if (process.argv[2] === 'rate-limit') { yield {type:'turn.failed',error:{message:'429 rate limit SECRET_CANARY'}}; return; }
     yield { type: 'item.completed', item: { type: attack ? 'command_execution' : 'agent_message', text: JSON.stringify(template) } };
     yield { type: 'turn.completed', usage: { input_tokens: 4, output_tokens: 3 } };
    })() };
   } };
  }
 },
 query: options => {
  calls++; queryOptions = options;
  const stream = (async function* () {
   if (attack) yield { type: 'assistant', message: { content: [{ type: 'tool_use', name: 'Bash' }] } };
   yield { type: 'result', subtype: 'success', is_error: false, result: JSON.stringify(template), usage: { input_tokens: 4, output_tokens: 3 } };
  })();
  stream.close = () => {}; return stream;
 }
};
mock.module('./build/src/agent-dast/providers/record.js',{namedExports:{...record,optionalSdk:async()=>sdk}});
const {createAgent}=await import('./build/src/agent-dast/providers/'+provider+'.js');
const root=await mkdtemp(join(tmpdir(),'wakeio-sdk-test-'));
try{
 const agent=await createAgent({template,recordDir:join(root,'record'),live:true,...(process.argv[2]==='cli-login'?{authMode:'cli-login'}:{})});
 if(attack || process.argv[2]==='rate-limit'){await assert.rejects(agent.planTasks(summary),/agent_output_invalid/);assert.equal(calls,2)}else{assert.deepEqual(await agent.planTasks(summary),template);assert.equal(calls,1)}
 const env=provider==='codex'?constructorOptions.env:queryOptions.options.env;
 assert.equal(env.PRIVATE_CANARY,undefined);assert.equal(env[provider==='codex'?'ANTHROPIC_API_KEY':'CODEX_API_KEY'],undefined);
 if(process.argv[2]==='cli-login'){assert.equal(env.CODEX_API_KEY,undefined);assert.notEqual(env.CODEX_HOME,env.HOME);}
 if(provider==='codex'){assert.ok(executableText.includes('--ignore-user-config'));assert.ok(executableText.includes('--disable shell_tool'));assert.ok(executableText.includes('--disable unified_exec'));assert.equal(threadOptions.networkAccessEnabled,false);assert.equal(threadOptions.webSearchMode,'disabled');assert.equal(threadOptions.approvalPolicy,'never')}
 else{assert.deepEqual(queryOptions.options.tools,[]);assert.deepEqual(queryOptions.options.settingSources,[]);assert.equal(queryOptions.options.strictMcpConfig,true);assert.deepEqual(queryOptions.options.mcpServers,{});assert.equal((await queryOptions.options.canUseTool()).behavior,'deny');assert.equal(queryOptions.options.persistSession,false)}
 const data=(await readFile(join(root,'record/transcript.jsonl'),'utf8'))+(await readFile(join(root,'record/ledger.jsonl'),'utf8'));
 assert.ok(!data.includes('KEY_CANARY'));assert.ok(!data.includes('PRIVATE'));assert.ok(!data.includes('SECRET_CANARY'));assert.equal(sockets,0);
 if(process.argv[2]==='rate-limit') assert.ok(data.includes('rate_limit'));
}finally{await rm(root,{recursive:true,force:true})}
`;
for (const provider of ['codex','claude']) for (const scenario of (provider === 'codex' ? ['valid','tool','cli-login','cleanup','rate-limit'] : ['valid','tool'])) {
  test(`${provider}: SDK configuration and ${scenario} events without network`, () => {
    assert.doesNotThrow(() => execFileSync(process.execPath, ['--experimental-test-module-mocks','--input-type=module','-e',sdkScript,provider,scenario], { stdio: 'pipe' }));
  });
}


test('missing optional SDK has a named error without loading a provider', async () => {
  const { optionalSdk } = await import('../src/agent-dast/providers/record.js');
  await assert.rejects(optionalSdk('node:wakeio-missing-sdk'), /optional_sdk_unavailable: node:wakeio-missing-sdk/);
});

test('provider diagnostics distinguish transport and parse failures without retaining messages', async () => {
  const { recordedAgent, providerFailure } = await import('../src/agent-dast/providers/record.js');
  const root = await mkdtemp(join(tmpdir(), 'wakeio-diagnostics-'));
  const previous = process.env.WAKEIO_AGENT_LIVE; process.env.WAKEIO_AGENT_LIVE = '1';
  try {
    for (const [label, failure, expected] of [
      ['rate', '429 rate limit SECRET_CANARY', 'rate_limit'],
      ['auth', '401 unauthorized SECRET_CANARY', 'authentication'],
      ['schema', 'invalid response_format schema SECRET_CANARY', 'output_schema'],
      ['network', 'ECONNRESET SECRET_CANARY', 'transport'],
    ]) {
      const recordDir = join(root, label);
      const agent = await recordedAgent('codex', { template, recordDir, live: true }, async () => { throw providerFailure(failure); });
      await assert.rejects(agent.selectNext(summary));
      const text = await readFile(join(recordDir, 'ledger.jsonl'), 'utf8');
      const rows = text.trim().split('\n').map(line => JSON.parse(line));
      assert.equal(rows.length, 2); assert.ok(rows.every(row => row.diagnostic === expected));
      assert.ok(!text.includes('SECRET_CANARY'));
    }
    const recordDir = join(root, 'parse');
    const agent = await recordedAgent('codex', { template, recordDir, replay: [{ json: 'broken' }, { json: 'broken' }] }, async () => ({}));
    await assert.rejects(agent.selectNext(summary));
    assert.ok((await readFile(join(recordDir, 'ledger.jsonl'), 'utf8')).includes('json_parse'));
  } finally {
    if (previous === undefined) delete process.env.WAKEIO_AGENT_LIVE; else process.env.WAKEIO_AGENT_LIVE = previous;
    await rm(root, { recursive: true, force: true });
  }
});
