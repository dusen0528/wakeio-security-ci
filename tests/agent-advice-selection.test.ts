import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { AgentReport, CheckResult, Finding } from '../src/contracts.js';
import { createReport, toAgentReport, writeReports } from '../src/report.js';
import { adviseMain } from '../src/agent-advice.js';
import { ADVICE_PROJECTION_POLICY_VERSION, projectAdviceContext } from '../src/agent-advice-context.js';

type Selection = { findingId: string; checkIndex: number };
const project = projectAdviceContext;
const NOW = '2026-10-14T00:00:00.000Z';
const PRIVATE = 'private-selection-detail-never-upload';
const finding = (index = 0, extra: Partial<Finding> = {}): Finding => ({
  ruleId: 'owned:selection', title: `Owned selection ${index}`, description: PRIVATE,
  severity: 'high', confidence: 'medium', kind: 'candidate', location: { path: 'private-selection-path.ts', line: index + 1 },
  remediation: PRIVATE, ...extra,
});
const report = (checks: CheckResult[]) => createReport(checks, 'source', NOW);
const check = (findings: Finding[], id = 'source.owned'): CheckResult => ({ id, status: 'completed', findings, notes: [PRIVATE] });
const select = (agent: AgentReport, checkIndex: number, rowIndex = 0): Selection => ({
  checkIndex, findingId: agent.findings.filter(row => row.checkIndex === checkIndex)[rowIndex].findingId,
});
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');

test('selected advice: explicit selection preserves a late row and parent beyond both default caps', () => {
  const checks = Array.from({ length: 30 }, (_, index) => check([finding(index)], `source.owned-${index}`));
  checks[29] = check(Array.from({ length: 30 }, (_, index) => finding(100 + index, { severity: 'low' })), 'source.selected');
  checks[0].status = 'partial';
  const agent = toAgentReport(report(checks)), selection = select(agent, 29, 29);
  const { input, referenceRoutes } = project(agent, false, selection);
  assert.equal(ADVICE_PROJECTION_POLICY_VERSION, 12);
  assert.equal(input.projectionVersion, 12);
  assert.deepEqual(input.selection, selection);
  assert.equal(input.checks.length, 1);
  assert.equal(input.checks[0].checkIndex, 29);
  assert.equal(input.checks[0].findingRows, 30);
  assert.equal(input.findings.length, 1);
  assert.deepEqual({ findingId: input.findings[0].findingId, checkIndex: input.findings[0].checkIndex }, selection);
  assert.equal(input.findings[0].severity, 'low');
  assert.equal(input.findings[0].reachesFailOn, false);
  assert.equal(input.scanGate.outcome, 'incomplete');
  assert.equal(input.scanGate.exitCode, agent.scanGate.exitCode);
  assert.deepEqual(input.counts, agent.summary!.counts);
  assert.equal(input.omittedChecks, 29);
  assert.equal(input.omittedFindings, 58);
  assert.equal(input.ambiguousFindingRows, 0);
  assert.equal(referenceRoutes.get(input.findings[0].referenceId), input.findings[0].recheckRoute);
  for (const forbidden of [PRIVATE, 'private-selection-path.ts', '"path":', '"url":']) {
    assert.equal(JSON.stringify(input).includes(forbidden), false, forbidden);
  }
});

test('selected advice: full-report ambiguity is counted before caps and all colliding cards are omitted', () => {
  const duplicate = finding(0);
  const rows = [duplicate, ...Array.from({ length: 28 }, (_, index) => finding(index + 1)),
    { ...duplicate, severity: 'low' as const }];
  const agent = toAgentReport(report([check(rows)]));
  assert.equal(agent.findings[0].findingId, agent.findings[29].findingId);
  const { input, referenceRoutes } = project(agent, false);
  assert.equal(input.ambiguousFindingRows, 2);
  assert.equal(input.findings.some(row => row.findingId === agent.findings[0].findingId), false);
  assert.equal(referenceRoutes.has(`finding:0:${agent.findings[0].findingId}`), false);
  assert.deepEqual(input.counts, agent.summary!.counts);
  assert.equal(input.omittedFindings, agent.findings.length - input.findings.length);
  assert.ok(input.checks.some(row => row.checkIndex === 0));
  assert.throws(() => project(agent, false, select(agent, 0)), /ambiguous_finding/);
});

test('selected advice: same IDs in different duplicate-named checks remain distinct selections', () => {
  const agent = toAgentReport(report([check([finding()], 'source.same'), check([finding()], 'source.same')]));
  assert.equal(agent.findings[0].findingId, agent.findings[1].findingId);
  const normal = project(agent, false).input;
  assert.equal(normal.ambiguousFindingRows, 0);
  assert.equal(normal.findings.length, 2);
  assert.equal(new Set(normal.findings.map(row => row.referenceId)).size, 2);
  for (const index of [0, 1]) {
    const selection = select(agent, index), input = project(agent, false, selection).input;
    assert.deepEqual(input.selection, selection);
    assert.equal(input.findings.length, 1);
    assert.equal(input.findings[0].checkIndex, index);
  }
});

async function workspace(t: TestContext) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-advice-selection-'));
  const previousKey = process.env.CODEX_API_KEY, previousHome = process.env.CODEX_HOME;
  const home = join(top, 'fake-login'); await mkdir(home);
  process.env.CODEX_API_KEY = 'owned-selection-fake-key'; process.env.CODEX_HOME = home;
  t.after(async () => {
    if (previousKey === undefined) delete process.env.CODEX_API_KEY; else process.env.CODEX_API_KEY = previousKey;
    if (previousHome === undefined) delete process.env.CODEX_HOME; else process.env.CODEX_HOME = previousHome;
    await rm(top, { recursive: true, force: true });
  });
  return top;
}

async function pair(top: string, checks: CheckResult[]) {
  const directory = join(top, 'reports'); await writeReports(report(checks), directory);
  const reportBytes = await readFile(join(directory, 'report.json'));
  const agentBytes = await readFile(join(directory, 'agent-report.json'));
  return { directory, reportBytes, agentBytes, agent: JSON.parse(agentBytes.toString()) as AgentReport };
}

async function fakeProvider(top: string, mode: 'ok' | 'omitted-check' | 'wrong-route' = 'ok') {
  const executable = join(top, `fake-codex-${mode}`), calls = join(top, `${mode}-calls`);
  const capture = join(top, `${mode}-capture.json`);
  const script = `#!/usr/bin/env node
const fs=require('node:fs');const args=process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(calls)},'called\\n',{mode:0o600});
if(args.includes('--version')){process.stdout.write('codex-cli 0.162.0-alpha.17.2\\n');process.exit(0)}
if(args.includes('--help')){process.stdout.write('--ignore-user-config --ignore-rules --strict-config --skip-git-repo-check --ephemeral --sandbox --disable --output-schema --output-last-message --json');process.exit(0)}
if(!args.includes('exec')||!args.includes('read-only')||!args.includes('--ephemeral')||!args.includes('web_search="disabled"'))process.exit(80);
let text='';process.stdin.on('data',chunk=>text+=chunk);process.stdin.on('end',()=>{
const job=JSON.parse(text);const card=job.report.findings[0];if(!card)process.exit(81);
const schema=JSON.parse(fs.readFileSync(args[args.indexOf('--output-schema')+1],'utf8'));
const auth=process.env.CODEX_API_KEY?'api-key':process.env.CODEX_HOME?'cli-login':'missing';
fs.writeFileSync(${JSON.stringify(capture)},JSON.stringify({projection:job.report,schema,auth}),{mode:0o600});
const referenceId=${JSON.stringify(mode)}==='omitted-check'?'check:'+job.report.scope.nextRead.checkIndex:card.referenceId;
const recheckRoute=${JSON.stringify(mode)}==='wrong-route'?'review_scope':card.recheckRoute;
const answer={version:1,overview:'Owned fake selection advice only.',recommendations:[{referenceId,recheckRoute,priority:1,reason:'Review selected evidence.',nextStep:'Inspect the declared source pattern.',recheck:'Use independently authorized controls.'}]};
fs.writeFileSync(args[args.indexOf('--output-last-message')+1],JSON.stringify(answer));
for(const event of [{type:'thread.started',thread_id:'owned-selection'},{type:'turn.started'},{type:'item.completed',item:{type:'agent_message',text:'done'}},{type:'turn.completed'}])process.stdout.write(JSON.stringify(event)+'\\n');
});
`;
  await writeFile(executable, script, { mode: 0o700 });
  return { executable, calls, capture };
}
const argumentsFor = (directory: string, out: string, executable: string, auth = 'api-key', selection?: Selection) =>
  ['advise', '--report', directory, '--agent', 'codex', '--auth', auth, '--allow-report-upload', '--out', out,
    '--agent-path', executable, '--timeout-ms', '10000',
    ...(selection ? ['--finding', selection.findingId, '--check-index', String(selection.checkIndex)] : [])];
const receipt = async (out: string) => JSON.parse(await readFile(join(out, 'agent-advice.json'), 'utf8'));

test('selected advice: fake CLI in both auth modes binds receipt hashes and exact selected reference without replacing the global gate', async t => {
  const top = await workspace(t), partial = check([finding(0)], 'source.before'); partial.status = 'partial';
  const p = await pair(top, [partial, check([finding(1, { severity: 'low' })], 'source.chosen')]);
  const selected = select(p.agent, 1), fake = await fakeProvider(top);
  for (const auth of ['api-key', 'cli-login']) {
    const out = join(top, auth);
    assert.equal(await adviseMain(argumentsFor(p.directory, out, fake.executable, auth, selected)), 0);
    const r = await receipt(out), captured = JSON.parse(await readFile(fake.capture, 'utf8'));
    assert.equal(r.policyVersion, 12); assert.equal(r.status, 'advice_produced'); assert.equal(r.verified, false);
    assert.equal(r.authMode, auth); assert.equal(captured.auth, auth);
    assert.deepEqual(r.input.selection, selected); assert.deepEqual(captured.projection.selection, selected);
    assert.equal(r.input.reportSha256, sha(p.reportBytes)); assert.equal(r.input.agentReportSha256, sha(p.agentBytes));
    assert.deepEqual(r.input.scanGate, p.agent.scanGate);
    assert.equal(r.input.scanGate.exitCode, 2, 'advice success is not scan success');
    assert.deepEqual(captured.projection.counts, p.agent.summary!.counts);
    assert.equal(captured.projection.checks.length, 1); assert.equal(captured.projection.findings.length, 1);
    assert.equal(captured.projection.scope.nextRead.checkIndex, 0, 'global next-read metadata remains honest');
    assert.equal(captured.projection.omittedChecks, 1); assert.equal(captured.projection.omittedFindings, 1);
    assert.equal(captured.projection.findings[0].reachesFailOn, false);
    const card = captured.projection.findings[0];
    assert.equal(r.advice.recommendations[0].referenceId, `finding:1:${selected.findingId}`);
    assert.equal(r.advice.recommendations[0].recheckRoute, card.recheckRoute);
    const refs = captured.schema.properties.recommendations.items.properties.referenceId.enum;
    assert.ok(refs.includes(card.referenceId)); assert.equal(refs.includes('check:0'), false);
    for (const forbidden of [PRIVATE, 'private-selection-path.ts', '"path":', '"url":']) {
      assert.equal(JSON.stringify(captured.projection).includes(forbidden), false, forbidden);
    }
    assert.deepEqual(await readFile(join(p.directory, 'report.json')), p.reportBytes);
    assert.deepEqual(await readFile(join(p.directory, 'agent-report.json')), p.agentBytes);
  }
});

test('selected advice: malformed paired selectors fail before every provider invocation', async t => {
  const top = await workspace(t), p = await pair(top, [check([finding()])]), fake = await fakeProvider(top);
  const selected = select(p.agent, 0);
  const invalid = [
    ['--finding', selected.findingId], ['--check-index', '0'],
    ['--finding', selected.findingId.toUpperCase(), '--check-index', '0'],
    ['--finding', 'short', '--check-index', '0'],
    ...['00', '+0', '-1', '0.0', '1e0', '9007199254740992'].map(index => ['--finding', selected.findingId, '--check-index', index]),
  ];
  for (const [index, flags] of invalid.entries()) {
    assert.equal(await adviseMain([...argumentsFor(p.directory, join(top, `bad-${index}`), fake.executable), ...flags]), 2);
    await assert.rejects(readFile(fake.calls), { code: 'ENOENT' });
  }
});

test('selected advice: absent or same-check ambiguous rows and a noncanonical sibling are refused before provider probes', async t => {
  const top = await workspace(t);
  const p = await pair(top, [check([finding(), finding()], 'source.ambiguous'), check([finding(1)], 'source.unique')]);
  const fake = await fakeProvider(top), duplicate = select(p.agent, 0);
  const cases: Array<[Selection, string]> = [
    [duplicate, 'ambiguous_finding'], [{ ...duplicate, findingId: 'f'.repeat(64) }, 'invalid_finding'],
    [{ ...duplicate, checkIndex: 99 }, 'invalid_finding'],
    [{ ...select(p.agent, 1), checkIndex: 0 }, 'invalid_finding'],
  ];
  for (const [index, [selected, reason]] of cases.entries()) {
    const out = join(top, `refused-${index}`);
    assert.equal(await adviseMain(argumentsFor(p.directory, out, fake.executable, 'api-key', selected)), 2);
    assert.equal((await receipt(out)).reason, reason);
    await assert.rejects(readFile(fake.calls), { code: 'ENOENT' });
  }
  const changed = JSON.parse(p.agentBytes.toString()); changed.checks[0].status = 'error';
  await writeFile(join(p.directory, 'agent-report.json'), JSON.stringify(changed));
  const out = join(top, 'noncanonical');
  assert.equal(await adviseMain(argumentsFor(p.directory, out, fake.executable, 'api-key', select(p.agent, 1))), 2);
  assert.equal((await receipt(out)).reason, 'invalid_report');
  await assert.rejects(readFile(fake.calls), { code: 'ENOENT' });
});

test('selected advice: provider cannot recommend an omitted next-read check or the wrong route for the selected reference', async t => {
  const top = await workspace(t), partial = check([finding(0)], 'source.partial'); partial.status = 'partial';
  const p = await pair(top, [partial, check([finding(1)], 'source.selected')]), selected = select(p.agent, 1);
  for (const mode of ['omitted-check', 'wrong-route'] as const) {
    const fake = await fakeProvider(top, mode), out = join(top, mode);
    assert.equal(await adviseMain(argumentsFor(p.directory, out, fake.executable, 'api-key', selected)), 2);
    const r = await receipt(out); assert.equal(r.reason, 'agent_protocol_invalid');
    assert.equal(r.status, 'incomplete'); assert.equal(Object.hasOwn(r, 'advice'), false);
    assert.deepEqual(r.input.selection, selected);
    const captured = JSON.parse(await readFile(fake.capture, 'utf8'));
    assert.equal(captured.projection.scope.nextRead.checkIndex, 0);
    assert.equal(captured.projection.checks[0].checkIndex, 1);
  }
});

test('selected advice: observation selection is supported and never silently replaced by a candidate', () => {
  const agent = toAgentReport(report([check([finding(), finding(1, { kind: 'observation', severity: 'info' })])]));
  const selected = select(agent, 0, 1), input = project(agent, false, selected).input;
  assert.equal(input.findings.length, 1); assert.equal(input.findings[0].findingId, selected.findingId);
  assert.equal(input.findings[0].evidenceKind, 'observation'); assert.equal(input.scanGate.exitCode, 1);
});

test('selected advice: an oversized typed parent card fails the projection budget rather than dropping the selection', () => {
  const agent = toAgentReport(report([check([finding()], 'api.authorization')]));
  // Deliberate SDK boundary stress, not a claimed canonical producer ledger:
  // current canonical ledgers cap requests at 64. Future or manufactured typed
  // inputs must still fail the 32 KiB projection cap without substituting a row.
  agent.checks[0].apiExecution = { version: 1, basis: 'declared-api-execution', status: 'partial', policyVersion: 2,
    planSha256: 'a'.repeat(64), plan: null, steps: Array.from({ length: 1000 }, (_, ordinal) => ({ ordinal, outcome: 'not_attempted',
      reason: 'not_reached', attemptStart: 0, httpAttempts: 0, httpStatus: null })),
    counts: { planned: 1000, evaluated: 0, inconclusive: 0, notAttempted: 1000, httpAttempts: 0 },
    reasons: ['run_incomplete', 'incomplete_steps'] };
  assert.throws(() => project(agent, false, select(agent, 0)), /report_projection_too_large/);
});
