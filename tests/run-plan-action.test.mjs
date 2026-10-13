import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, copyFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { startNativeDastSqlite } from '../examples/native-dast-sqlite.mjs';

async function fixture(bundle) {
  const root = await mkdtemp(join(tmpdir(), 'owned-plan-action-'));
  await mkdir(join(root, 'actions/run-plan'), { recursive: true }); await mkdir(join(root, 'dist-action'));
  for (const name of ['run.mjs', 'supervise.mjs']) await copyFile(new URL(`../actions/run-plan/${name}`, import.meta.url), join(root, 'actions/run-plan', name));
  await writeFile(join(root, 'dist-action/wakeio-security-ci.mjs'), bundle);
  await writeFile(join(root, 'plan.json'), '{}'); await writeFile(join(root, 'inputs.json'), '{}');
  await writeFile(join(root, 'outputs'), ''); await writeFile(join(root, 'summary'), '');
  return { root, env: { ...process.env, GITHUB_WORKSPACE: root, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_EVENT_PATH: '',
    GITHUB_OUTPUT: join(root, 'outputs'), GITHUB_STEP_SUMMARY: join(root, 'summary'), WAKEIO_ACTION_PATH: join(root, 'actions/run-plan'),
    WAKEIO_PLAN: 'plan.json', WAKEIO_PLAN_INPUTS: 'inputs.json', WAKEIO_PLAN_ACTIVE_CONSENT: 'true',
    WAKEIO_PLAN_ALLOWED_ORIGIN: 'http://127.0.0.1:1', WAKEIO_PLAN_OUT: 'result', WAKEIO_PLAN_TIMEOUT_MS: '1000',
    WAKEIO_PLAN_MAX_REQUESTS: '64', WAKEIO_PLAN_RATE: '10', WAKEIO_PLAN_CONCURRENCY: '2', WAKEIO_PLAN_FAIL_ON: 'high', WAKEIO_PLAN_ALLOW_PRIVATE: 'true' },
    close: () => rm(root, { recursive: true, force: true }) };
}
function launch(f) {
  const child = spawn(process.execPath, [join(f.root, 'actions/run-plan/run.mjs')], { cwd: f.root, env: f.env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(Error('owned_wrapper_timeout')); }, 12000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
  return { child, done };
}
async function exists(path) { try { await access(path); return true; } catch { return false; } }
async function outputs(f) { return Object.fromEntries((await readFile(join(f.root, 'outputs'), 'utf8')).trim().split('\n').filter(Boolean).map(line => { const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)]; })); }
const started = `import { writeFileSync } from 'node:fs'; writeFileSync('child-started','yes'); `;

test('consent, pull_request_target and fork refusals happen before reading inputs or starting the CLI', async () => {
  for (const mode of ['consent', 'pull_request_target', 'fork']) {
    const f = await fixture(started + 'process.exitCode=0;');
    try {
      f.env.WAKEIO_PLAN = 'missing-plan.json'; f.env.WAKEIO_PLAN_INPUTS = 'missing-inputs.json';
      if (mode === 'consent') f.env.WAKEIO_PLAN_ACTIVE_CONSENT = 'false';
      if (mode === 'pull_request_target') f.env.GITHUB_EVENT_NAME = 'pull_request_target';
      if (mode === 'fork') {
        f.env.GITHUB_EVENT_NAME = 'pull_request'; f.env.GITHUB_EVENT_PATH = join(f.root, 'event.json');
        await writeFile(f.env.GITHUB_EVENT_PATH, JSON.stringify({ pull_request: { head: { repo: { full_name: 'owned-fork/repo' } }, base: { repo: { full_name: 'owned-base/repo' } } } }));
      }
      const result = await launch(f).done, values = await outputs(f);
      assert.equal(result.code, 2, mode); assert.equal(values['exit-code'], '2'); assert.equal(values['setup-status'], 'refused');
      assert.equal(values['report-dir'], ''); assert.equal(await exists(join(f.root, 'child-started')), false);
      assert.equal(await exists(join(f.root, 'result')), false);
    } finally { await f.close(); }
  }
});

const counterfeit = `
import { mkdirSync, writeFileSync } from 'node:fs';
const out = process.argv[process.argv.indexOf('--out')+1];
writeFileSync('child-started','yes'); mkdirSync(out);
const runId='r-00000000-0000-4000-8000-000000000001', hash='a'.repeat(64);
const command={version:1,runId,exitCode:0,status:'completed',delivery:'published',outDir:out,manifestSha256:hash,tasks:[{taskId:'t-owned'}],requests:{}};
`;
test('exit-zero without a current receipt, tampered hashes, child/JSON disagreement and stale outputs all fail closed', async () => {
  for (const mode of ['missing-receipt', 'tampered', 'exit-disagreement', 'stale']) {
    const tamper = `writeFileSync(out+'/run-receipt.json',JSON.stringify({version:1,profileRevision:'built-in-plan-run-v1',runId,status:'publication_only',exitCode:0,manifestSha256:hash,runReportSha256:hash,requiresCallerAcknowledgement:true,provesFinalProcessExit:false}));writeFileSync(out+'/run-manifest.json','{}');`;
    const f = await fixture(counterfeit + (mode === 'tampered' ? tamper : '') + `console.log(JSON.stringify(command));process.stderr.write('owned-raw-output-canary');process.exitCode=${mode === 'exit-disagreement' ? 1 : 0};`);
    try {
      if (mode === 'stale') { await mkdir(join(f.root, 'result')); await writeFile(join(f.root, 'result/run-receipt.json'), 'owned-previous-marker'); }
      const result = await launch(f).done, values = await outputs(f);
      assert.equal(result.code, 2, mode); assert.equal(values['exit-code'], '2'); assert.equal(values['delivery-status'], 'failed');
      assert.equal(values['report-dir'], ''); assert.equal(values.receipt, ''); assert.equal(result.stderr.includes('owned-raw-output-canary'), false);
      if (mode === 'stale') {
        assert.equal(await exists(join(f.root, 'child-started')), false);
        assert.equal(await readFile(join(f.root, 'result/run-receipt.json'), 'utf8'), 'owned-previous-marker');
      }
    } finally { await f.close(); }
  }
});

test('Action cancellation terminates a trusted CLI, its detached ignoring engine and that engine descendant', async () => {
  const f = await fixture(`
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const engine = spawn(process.execPath, ['-e', ${JSON.stringify(`
const {spawn}=require('node:child_process'),{writeFileSync}=require('node:fs');
process.on('SIGTERM',()=>{});
const leaf=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{stdio:'ignore'});
writeFileSync('engine-pids.json',JSON.stringify({engine:process.pid,leaf:leaf.pid}));setInterval(()=>{},1000);
`)}], { detached:true, stdio:'ignore' });
process.on('SIGTERM',()=>{});writeFileSync('cli-pid.json',JSON.stringify({pid:process.pid}));setInterval(()=>{},1000);
`);
  let execution;
  try {
    f.env.WAKEIO_PLAN_TIMEOUT_MS = '10000'; execution = launch(f);
    const deadline = Date.now() + 5000;
    while (!await exists(join(f.root, 'engine-pids.json')) && Date.now() < deadline) await delay(25);
    assert.equal(await exists(join(f.root, 'engine-pids.json')), true);
    // Give the observer two sampling periods to discover the owned subtree.
    await delay(100); execution.child.kill('SIGTERM');
    const result = await execution.done, values = await outputs(f);
    assert.equal(result.code, 2); assert.equal(values['exit-code'], '2'); assert.equal(values['scan-status'], 'cancelled');
    assert.equal(values['report-dir'], ''); assert.equal(values.receipt, '');
    const cli = JSON.parse(await readFile(join(f.root, 'cli-pid.json'), 'utf8')), engine = JSON.parse(await readFile(join(f.root, 'engine-pids.json'), 'utf8'));
    for (const pid of [cli.pid, engine.engine, engine.leaf]) {
      let state = ''; try { state = execFileSync('ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8', timeout: 1000 }).trim(); } catch (error) { assert.equal(error.status, 1); }
      assert.ok(!state || state.startsWith('Z'), `owned PID ${pid} remains running: ${state}`);
    }
  } finally {
    if (execution && execution.child.exitCode === null) execution.child.kill('SIGKILL');
    for (const name of ['cli-pid.json', 'engine-pids.json']) {
      try {
        const known = JSON.parse(await readFile(join(f.root, name), 'utf8'));
        for (const [key, pid] of Object.entries(known)) if (Number.isSafeInteger(pid) && pid > 0) {
          try { process.kill(key === 'leaf' ? pid : -pid, 'SIGKILL'); } catch { /* Owned fixture may already be gone. */ }
        }
      } catch { /* The fixture may not have reached its PID publication. */ }
    }
    await f.close();
  }
});

test('an existing unowned Action receipt is preserved on collision after a real completed native run', async () => {
  const bundle = await readFile(new URL('../dist-action/wakeio-security-ci.mjs', import.meta.url));
  const f = await fixture(bundle), target = await startNativeDastSqlite('bound');
  try {
    const policy = JSON.stringify({ version: 1, kind: 'sql-boolean-differential', baseUrl: `${target.origin}/`, url: target.url, parameter: 'id', profile: 'numeric',
      oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } }) + '\n';
    await writeFile(join(f.root, 'policy.json'), policy);
    await writeFile(join(f.root, 'inputs.json'), JSON.stringify({ version: 1, inputs: [{ id: 'policy', path: 'policy.json', sha256: createHash('sha256').update(policy).digest('hex') }] }));
    await writeFile(join(f.root, 'plan.json'), JSON.stringify({ version: 1, kind: 'wakeio.execution-plan', origin: target.origin,
      tasks: [{ id: 't-owned', engine: 'native-dast', policy: 'policy', maxRequests: 8 }] }));
    f.env.WAKEIO_PLAN_ALLOWED_ORIGIN = target.origin; f.env.WAKEIO_PLAN_TIMEOUT_MS = '5000';
    const execution = launch(f), deadline = Date.now() + 5000;
    while (!await exists(join(f.root, 'result')) && Date.now() < deadline) await delay(10);
    assert.equal(await exists(join(f.root, 'result')), true);
    const receipt = join(f.root, 'result/run-action-receipt.json');
    await writeFile(receipt, 'owned-other-writer-sentinel', { flag: 'wx' });
    const result = await execution.done, values = await outputs(f);
    assert.equal(target.requests.length, 8, 'the original native engine completed before Action receipt refusal');
    assert.equal(result.code, 2); assert.equal(values['exit-code'], '2'); assert.equal(values.receipt, '');
    assert.equal(values['delivery-status'], 'failed');
    assert.equal(await readFile(receipt, 'utf8'), 'owned-other-writer-sentinel');
  } finally { await target.close(); await f.close(); }
});

test('the bounded Action protocol accepts a published partial ledger with 20000 attempt records', async () => {
  // Protocol-size control only: synthetic metadata, no engine or target execution.
  const f = await fixture(`
import {createHash} from 'node:crypto';import {mkdirSync,writeFileSync} from 'node:fs';
const out=process.argv[process.argv.indexOf('--out')+1], sha=x=>createHash('sha256').update(x).digest('hex');
mkdirSync(out);mkdirSync(out+'/tasks');mkdirSync(out+'/tasks/t-owned');
const revision='built-in-plan-run-v1',runId='r-00000000-0000-4000-8000-000000000001',hash='a'.repeat(64);
const taskReport='{}\\n',reportSha256=sha(taskReport);
const attempts=Array.from({length:20000},(_,i)=>({ordinal:i+1,method:'GET',kind:'probe',operationIndex:null,outcome:'transport_error'}));
const requests={requestCount:20000,bytes:0,responseCompleted:0,transportErrors:20000,pending:0,refused:0,attempts:[]};
const task={taskId:'t-owned',engine:'nuclei',status:'partial',exitCode:2,reportPath:'tasks/t-owned/report.json',reportSha256,requests:{...requests,attempts}};
const report={version:1,profileRevision:revision,runId,planSha256:hash,scopeHash:hash,status:'partial',exitCode:2,stopReason:'execution_incomplete',tasks:[task],requests};
const json=JSON.stringify(report)+'\\n';
const contents={
 'run-start.json':JSON.stringify({runId,declarationOnly:true,expectedTasks:[{taskId:'t-owned',engine:'nuclei'}]}),
 'run-report.json':json,'run-report.md':'Owned synthetic partial metadata control.','run.db':'Owned synthetic artifact bytes; not a database attestation.',
 'agent-run.json':JSON.stringify({...report,diagnosticOnly:true,replayAuthority:false,reportArtifact:{name:'run-report.json',algorithm:'sha256',digest:sha(json)}}),
 'tasks/t-owned/report.json':taskReport,'tasks/t-owned/report.md':'Owned partial control.','tasks/t-owned/report.sarif':'{}',
 'tasks/t-owned/agent-report.json':JSON.stringify({reportArtifact:{name:'report.json',algorithm:'sha256',digest:reportSha256},scanGate:{exitCode:2}})
};
const artifacts=Object.entries(contents).map(([path,text])=>{writeFileSync(out+'/'+path,text);return{path,bytes:Buffer.byteLength(text),sha256:sha(text)};});
const manifest=JSON.stringify({version:1,profileRevision:revision,runId,planSha256:hash,scopeHash:hash,artifacts}),manifestSha256=sha(manifest);
writeFileSync(out+'/run-manifest.json',manifest);
writeFileSync(out+'/run-receipt.json',JSON.stringify({version:1,profileRevision:revision,runId,status:'publication_only',exitCode:2,manifestSha256,runReportSha256:sha(json),requiresCallerAcknowledgement:true,provesFinalProcessExit:false}));
const command=JSON.stringify({version:1,runId,exitCode:2,status:'partial',delivery:'published',outDir:out,manifestSha256,tasks:[task],requests});
writeFileSync('protocol-bytes.json',JSON.stringify({bytes:Buffer.byteLength(command)}));console.log(command);process.exitCode=2;
`);
  try {
    f.env.WAKEIO_PLAN_MAX_REQUESTS = '20000';
    const result = await launch(f).done, values = await outputs(f);
    const size = JSON.parse(await readFile(join(f.root, 'protocol-bytes.json'), 'utf8')).bytes;
    assert.ok(size > 1024 * 1024 && size < 4 * 1024 * 1024);
    assert.equal(result.code, 2); assert.equal(values['exit-code'], '2');
    assert.equal(values['delivery-status'], 'delivered', 'a current published partial result survives the supported maximum ledger size');
    assert.ok(values.receipt); assert.equal(values['scan-status'], 'incomplete');
  } finally { await f.close(); }
});
