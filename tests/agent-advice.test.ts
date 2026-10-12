import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createReport, toAgentReport, writeReports } from '../src/report.js';
import { adviseMain } from '../src/agent-advice.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';
import { runProcess } from '../src/source/process.js';
import { runDast, type DastPolicy } from '../src/dast.js';

const testFinding = {
  ruleId: 'fixture:sql', title: 'Potential SQL injection', description: 'Synthetic owned fixture only.',
  severity: 'high' as const, confidence: 'medium' as const, kind: 'candidate' as const,
  location: { path: 'fixture.py', line: 1 }, remediation: 'Review query parameter binding.',
};

async function fixture() {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-advice-test-'));
  const reports = join(top, 'reports');
  const report = createReport([{ id: 'source.sql', status: 'completed', findings: [testFinding], notes: [] }],
    'source', '2026-10-13T00:00:00.000Z');
  await writeReports(report, reports);
  return { top, reports };
}

async function fakeCodex(top: string, behavior: 'ok' | 'capture' | 'tool' | 'unknown-id' | 'wrong-route' | 'malformed' | 'slow' | 'slow-help' | 'overflow' | 'descendant') {
  const path = join(top, `codex-${behavior}`);
  const script = `#!/usr/bin/env node
const fs = require('fs');
const cp = require('child_process');
const args = process.argv.slice(2);
if (args.includes('--version')) { process.stdout.write('codex-cli 0.162.0-alpha.17.2\\n'); process.exit(0); }
if (args.includes('--help')) { if (${JSON.stringify(behavior)} === 'slow-help') return setTimeout(() => {}, 100000); process.stdout.write('--ignore-user-config --ignore-rules --strict-config --skip-git-repo-check --ephemeral --sandbox --disable --output-schema --output-last-message --json'); process.exit(0); }
const mode = ${JSON.stringify(behavior)};
if (!args.includes('exec') || !args.includes('read-only') || !args.includes('--ephemeral') || !args.includes('--ignore-user-config') || !args.includes('--ignore-rules') || !args.includes('--json') || !args.includes('--output-schema') || !args.includes('--output-last-message') || !args.includes('shell_tool') || !args.includes('shell_snapshot') || !args.includes('code_mode') || args.includes('code_mode_host') || !args.includes('approval_policy="never"') || !args.includes('web_search="disabled"')) process.exit(80);
if (process.env.WAKEIO_SECRET_CANARY || !process.env.HOME || process.env.HOME === process.env.CODEX_HOME) process.exit(81);
const auth = process.env.CODEX_API_KEY ? 'api-key' : process.env.CODEX_HOME ? 'cli-login' : 'missing';
if (auth === 'missing') process.exit(82);
let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  if (input.includes('secret-canary-do-not-upload') || input.includes('fixture.py')) process.exit(83);
  if (mode === 'slow') { fs.writeFileSync(${JSON.stringify(join(top, 'slow.started'))}, '1'); return setTimeout(() => {}, 100000); }
  if (mode === 'overflow') { process.stdout.write('x'.repeat(1200000)); return; }
  if (mode === 'descendant') {
    const child = cp.spawn(process.execPath, ['-e', 'process.on("SIGTERM",()=>{}); setInterval(()=>{},1000)'], {detached:false,stdio:'ignore'});
    fs.writeFileSync(${JSON.stringify(join(top, 'descendant.pid'))}, String(child.pid));
    child.unref();
  }
  const job = JSON.parse(input); const finding = job.report.findings[0];
  if (mode === 'capture') fs.writeFileSync(${JSON.stringify(join(top, 'captured-projection.json'))}, JSON.stringify(job.report));
  const answer = { version: 1, overview: auth + ' synthetic advice only', recommendations: job.report.scanGate.outcome === 'pass' && job.report.counts.findings === 0 ? [] : [{ referenceId: mode === 'unknown-id' ? 'invented-id' : finding?.referenceId ?? 'scope', recheckRoute: mode === 'wrong-route' ? 'review_scope' : finding?.recheckRoute ?? 'review_scope', priority: 1, reason: 'Review the candidate.', nextStep: 'Inspect the bounded evidence.', recheck: 'Run an independent control.' }] };
  fs.writeFileSync(args[args.indexOf('--output-last-message') + 1], mode === 'malformed' ? '{' : JSON.stringify(answer));
  process.stdout.write(JSON.stringify({type:'thread.started',thread_id:'synthetic'})+'\\n');
  process.stdout.write(JSON.stringify({type:'turn.started'})+'\\n');
  process.stdout.write(JSON.stringify({type:'item.completed',item:{type:mode === 'tool' ? 'command_execution' : 'agent_message',text:'done'}})+'\\n');
  process.stdout.write(JSON.stringify({type:'turn.completed'})+'\\n');
});

`;
  await writeFile(path, script, { mode: 0o700 });
  return path;
}

async function receipt(path: string) { return JSON.parse(await readFile(join(path, 'agent-advice.json'), 'utf8')); }
const args = (reports: string, out: string, executable: string, auth: string, timeout = '5000') =>
  ['advise', '--report', reports, '--agent', 'codex', '--auth', auth, '--allow-report-upload', '--out', out,
    '--agent-path', executable, '--timeout-ms', timeout];

test('fake CLI receives the owned native SQLite evidence and a clean bound control needs no invented recommendation', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-native-advice-'));
  const previousKey = process.env.CODEX_API_KEY;
  try {
    process.env.CODEX_API_KEY = 'test-only-key';
    const fake = await fakeCodex(top, 'capture');
    const fixtureModule = new URL('../../examples/native-dast-sqlite.mjs', import.meta.url).href;
    for (const [mode, expected] of [['vulnerable', 'observed'], ['bound', 'not_observed']] as const) {
      const owned = await (await import(fixtureModule)).startNativeDastSqlite(mode) as {
        origin: string; url: string; close(): Promise<void> };
      try {
        const policy: DastPolicy = { version: 1, kind: 'sql-boolean-differential', baseUrl: `${owned.origin}/`,
          url: owned.url, parameter: 'id', profile: 'numeric',
          oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
        const [check] = await runDast({ policy, consent: true, allowPrivate: true });
        assert.ok(check);
        const reports = join(top, `reports-${mode}`);
        const scan = createReport([check], 'url', '2026-10-13T00:00:00.000Z');
        await writeReports(scan, reports);
        const out = join(top, `advice-${mode}`);
        assert.equal(await adviseMain(args(reports, out, fake, 'api-key')), 0);
        const projection = JSON.parse(await readFile(join(top, 'captured-projection.json'), 'utf8'));
        assert.equal(projection.projectionVersion, 2);
        assert.equal(projection.checks[0].engine, 'native_sql_boolean');
        assert.equal(projection.checks[0].nativeDast.outcome, expected);
        assert.equal(projection.checks[0].nativeDast.steps.length, 8);
        assert.equal(projection.checks[0].nativeDast.counts.httpAttempts, 8);
        assert.equal(Object.hasOwn(projection.scope, 'sourceToolSelection'), false);
        assert.equal(JSON.stringify(projection).includes(owned.url), false);
        const produced = await receipt(out);
        assert.equal(produced.policyVersion, 2);
        assert.equal(produced.advice.recommendations.length, mode === 'bound' ? 0 : 1);
        if (mode === 'vulnerable') {
          assert.equal(projection.findings[0].recheckRoute, 'replay_native_finding_same_policy');
          assert.equal(produced.advice.recommendations[0].recheckRoute, 'replay_native_finding_same_policy');
          const agent = toAgentReport(scan);
          const reportOnlyCases = [
            (copy: typeof agent) => { copy.checks[0].status = 'error'; },
            (copy: typeof agent) => { copy.checks[0].metrics = { requestCount: 7 }; },
            (copy: typeof agent) => { copy.findings[0].ruleId = 'other.rule'; },
            (copy: typeof agent) => { copy.findings[0].title = 'Other title'; },
            (copy: typeof agent) => { copy.findings[0].confidence = 'low'; },
            (copy: typeof agent) => { copy.findings[0].severity = 'medium'; },
            (copy: typeof agent) => { delete copy.findings[0].location.url; },
            (copy: typeof agent) => { copy.findings[0].location.url = 'javascript:invalid'; },
            (copy: typeof agent) => { copy.findings.push(structuredClone(copy.findings[0]));
              copy.checks[0].findingIds.push(copy.findings[0].findingId); },
            (copy: typeof agent) => { copy.checks.push({ ...structuredClone(copy.checks[0]), checkIndex: 1 }); },
          ];
          for (const mutate of reportOnlyCases) {
            const copy = structuredClone(agent); mutate(copy);
            const context = projectAdviceContext(copy, true).input;
            assert.equal(context.findings[0].replayAvailable, false);
            assert.notEqual(context.findings[0].recheckRoute, 'replay_native_finding_same_policy');
            if (copy.checks[0].status === 'error' || copy.checks[0].metrics?.requestCount === 7) {
              assert.equal(context.checks[0].recheckRoute, 'review_check_diagnostics');
            }
          }
          // Advice accepts a larger digest-bound pair than native replay's 1 MiB
          // source snapshot. Such a report still gets advice, but no replay claim.
          const extra = Array.from({ length: 70 }, (_, index) => ({ id: `url.extra-${index}`,
            status: 'completed' as const, findings: [], notes: ['x'.repeat(16000)] }));
          const largeReports = join(top, 'large-native-reports');
          await writeReports(createReport([check, ...extra], 'url', '2026-10-13T00:00:00.000Z'), largeReports);
          assert.ok((await readFile(join(largeReports, 'report.json'))).length > 1024 * 1024);
          const largeOut = join(top, 'large-native-advice');
          assert.equal(await adviseMain(args(largeReports, largeOut, fake, 'api-key')), 0);
          const largeProjection = JSON.parse(await readFile(join(top, 'captured-projection.json'), 'utf8'));
          assert.equal(largeProjection.findings[0].replayAvailable, false);
          assert.notEqual(largeProjection.findings[0].recheckRoute, 'replay_native_finding_same_policy');
        }
      } finally { await owned.close(); }
    }
  } finally {
    if (previousKey === undefined) delete process.env.CODEX_API_KEY; else process.env.CODEX_API_KEY = previousKey;
    await rm(top, { recursive: true, force: true });
  }
});

test('explicit auth modes, bounded projection, and original report unchanged', async () => {
  const { top, reports } = await fixture();
  const previousKey = process.env.CODEX_API_KEY, previousHome = process.env.CODEX_HOME;
  try {
    const fake = await fakeCodex(top, 'ok');
    const original = await readFile(join(reports, 'agent-report.json'));
    process.env.CODEX_API_KEY = 'test-only-key';
    process.env.WAKEIO_SECRET_CANARY = 'must-not-forward';
    const apiOut = join(top, 'api');
    assert.equal(await adviseMain(args(reports, apiOut, fake, 'api-key')), 0);
    const api = await receipt(apiOut);
    assert.equal(api.status, 'advice_produced'); assert.equal(api.verified, false);
    assert.equal(api.authMode, 'api-key'); assert.match(api.advice.overview, /^api-key/);
    const loginHome = join(top, 'codex-state'); await mkdir(loginHome);
    process.env.CODEX_HOME = loginHome;
    const loginOut = join(top, 'login');
    assert.equal(await adviseMain(args(reports, loginOut, fake, 'cli-login')), 0);
    const login = await receipt(loginOut);
    assert.equal(login.authMode, 'cli-login'); assert.match(login.advice.overview, /^cli-login/);
    assert.deepEqual(await readFile(join(reports, 'agent-report.json')), original);
    assert.equal((await readFile(join(apiOut, 'agent-advice.json'), 'utf8')).includes('test-only-key'), false);
  } finally {
    if (previousKey === undefined) delete process.env.CODEX_API_KEY; else process.env.CODEX_API_KEY = previousKey;
    if (previousHome === undefined) delete process.env.CODEX_HOME; else process.env.CODEX_HOME = previousHome;
    delete process.env.WAKEIO_SECRET_CANARY;
    await rm(top, { recursive: true, force: true });
  }
});

test('rejects mismatched report digest and missing outbound consent before model call', async () => {
  const { top, reports } = await fixture();
  try {
    const fake = await fakeCodex(top, 'ok');
    await writeFile(join(reports, 'report.json'), '{}');
    const out = join(top, 'bad');
    assert.equal(await adviseMain(args(reports, out, fake, 'api-key')), 2);
    assert.equal((await receipt(out)).reason, 'invalid_report');
    assert.equal(await adviseMain(args(reports, join(top, 'no-consent'), fake, 'api-key').filter(x => x !== '--allow-report-upload')), 2);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('rejects linked sibling and canonical agent-report mismatch', async () => {
  const { top, reports } = await fixture();
  try {
    const fake = await fakeCodex(top, 'ok');
    const original = join(reports, 'report.json'), moved = join(top, 'saved-report.json');
    const bytes = await readFile(original); await rm(original); await writeFile(moved, bytes);
    await symlink(moved, original);
    const linkedOut = join(top, 'linked');
    assert.equal(await adviseMain(args(reports, linkedOut, fake, 'api-key')), 2);
    assert.equal((await receipt(linkedOut)).reason, 'invalid_report');
    await rm(original); await writeFile(original, bytes);
    const agent = JSON.parse(await readFile(join(reports, 'agent-report.json'), 'utf8'));
    agent.findings[0].title = 'forged';
    await writeFile(join(reports, 'agent-report.json'), JSON.stringify(agent));
    const forgedOut = join(top, 'forged');
    assert.equal(await adviseMain(args(reports, forgedOut, fake, 'api-key')), 2);
    assert.equal((await receipt(forgedOut)).reason, 'invalid_report');
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('same output directory permits one advice artifact only', async () => {
  const { top, reports } = await fixture();
  const previousKey = process.env.CODEX_API_KEY;
  try {
    process.env.CODEX_API_KEY = 'test-only-key';
    const fake = await fakeCodex(top, 'ok'); const out = join(top, 'same');
    const outcomes = await Promise.all([adviseMain(args(reports, out, fake, 'api-key')),
      adviseMain(args(reports, out, fake, 'api-key'))]);
    assert.deepEqual(outcomes.sort(), [0, 2]);
    assert.equal((await receipt(out)).status, 'advice_produced');
  } finally {
    if (previousKey === undefined) delete process.env.CODEX_API_KEY; else process.env.CODEX_API_KEY = previousKey;
    await rm(top, { recursive: true, force: true });
  }
});

test('owned process group kills TERM-ignoring descendant after normal agent exit', async () => {
  const { top, reports } = await fixture();
  const previousKey = process.env.CODEX_API_KEY;
  try {
    process.env.CODEX_API_KEY = 'test-only-key';
    const fake = await fakeCodex(top, 'descendant'); const out = join(top, 'descendant-advice');
    assert.equal(await adviseMain(args(reports, out, fake, 'api-key')), 0);
    const pid = Number(await readFile(join(top, 'descendant.pid'), 'utf8'));
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    let state = '';
    try { state = (await import('node:child_process')).execFileSync('/bin/ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8' }).trim(); }
    catch { /* No process remains. */ }
    assert.ok(!state || state.startsWith('Z'), `descendant still alive: ${state}`);
  } finally {
    if (previousKey === undefined) delete process.env.CODEX_API_KEY; else process.env.CODEX_API_KEY = previousKey;
    await rm(top, { recursive: true, force: true });
  }
});

test('agent cancellation sends TERM then KILL to an owned descendant group', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-advice-cancel-'));
  try {
    const pidPath = join(top, 'child.pid');
    const parent = join(top, 'parent');
    await writeFile(parent, `#!/usr/bin/env node
const cp=require('child_process'), fs=require('fs');
const child=cp.spawn(process.execPath,['-e','process.on("SIGTERM",()=>{}); setInterval(()=>{},1000)'],{detached:false,stdio:'ignore'});
fs.writeFileSync(${JSON.stringify(pidPath)},String(child.pid));
setInterval(()=>{},1000);
`, { mode: 0o700 });
    const controller = new AbortController();
    const pending = runProcess(parent, [], { cwd: top, home: top, timeoutMs: 4000, maxOutputBytes: 1024,
      supervision: 'agent', signal: controller.signal });
    let pid = 0;
    for (let attempt = 0; attempt < 50; attempt++) {
      try { pid = Number(await readFile(pidPath, 'utf8')); if (pid > 0) break; }
      catch { await new Promise(resolve => setTimeout(resolve, 20)); }
    }
    assert.ok(pid > 0);
    controller.abort();
    const outcome = await pending;
    assert.equal(outcome.cancelled, true);
    assert.equal(outcome.cleanupConfirmed, true);
    let state = '';
    try { state = (await import('node:child_process')).execFileSync('/bin/ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8' }).trim(); }
    catch { /* No process remains. */ }
    assert.ok(!state || state.startsWith('Z'), `descendant still alive: ${state}`);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('SIGTERM during a response publishes an incomplete cancellation receipt', async () => {
  const { top, reports } = await fixture();
  const previousKey = process.env.CODEX_API_KEY;
  try {
    process.env.CODEX_API_KEY = 'test-only-key';
    const fake = await fakeCodex(top, 'slow'); const out = join(top, 'cancelled-advice');
    const pending = adviseMain(args(reports, out, fake, 'api-key', '4000'));
    let started = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      try { await readFile(join(top, 'slow.started')); started = true; break; }
      catch { await new Promise(resolve => setTimeout(resolve, 20)); }
    }
    assert.equal(started, true);
    process.emit('SIGTERM');
    assert.equal(await pending, 2);
    const result = await receipt(out);
    assert.equal(result.status, 'incomplete'); assert.equal(result.reason, 'agent_cancelled');
    assert.equal(result.verified, false); assert.equal(Object.hasOwn(result, 'advice'), false);
  } finally {
    if (previousKey === undefined) delete process.env.CODEX_API_KEY; else process.env.CODEX_API_KEY = previousKey;
    await rm(top, { recursive: true, force: true });
  }
});

test('rejects tool events, unknown finding references/routes, malformed output, preflight/runtime timeout and output overflow', async () => {
  const { top, reports } = await fixture();
  const previousKey = process.env.CODEX_API_KEY;
  try {
    process.env.CODEX_API_KEY = 'test-only-key';
    for (const behavior of ['tool', 'unknown-id', 'wrong-route', 'malformed', 'slow', 'slow-help', 'overflow'] as const) {
      const fake = await fakeCodex(top, behavior); const out = join(top, `out-${behavior}`);
      assert.equal(await adviseMain(args(reports, out, fake, 'api-key', behavior === 'slow' || behavior === 'slow-help' ? '150' : '5000')), 2, behavior);
      const report = await receipt(out);
      assert.equal(report.status, 'incomplete'); assert.equal(report.verified, false);
      assert.ok(['agent_tools_not_allowed', 'agent_protocol_invalid', 'agent_budget_exhausted', 'agent_output_limit'].includes(report.reason), behavior);
      if (behavior === 'slow-help') assert.equal(report.reason, 'agent_budget_exhausted');
    }
  } finally {
    if (previousKey === undefined) delete process.env.CODEX_API_KEY; else process.env.CODEX_API_KEY = previousKey;
    await rm(top, { recursive: true, force: true });
  }
});
