import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { main } from '../src/cli.js';
import { toAgentReport } from '../src/report.js';
import { compareReports, comparisonExitCode } from '../src/compare.js';

// The trusted scanner reads these owned strings. No fixture code/dependency is executed.
const BROKEN = 'function { /* OWNED_PRIVATE_DIAGNOSTIC_CONTENT */\n';
const CLEAN = 'const declared = 1;\n';
const HIGH = 'function route(req){eval(req.query.command)}\n';
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
type Workspace = { top: string; source: string; app: string };
type Pair = { dir: string; report: any; agent: any; code: number };
async function cli(args: string[]) {
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try { return await main(args); }
  finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
async function workspace(t: TestContext, text = BROKEN): Promise<Workspace> {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-diagnostic-handoff-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'), app = join(source, 'app.ts');
  await mkdir(source); await writeFile(app, text);
  return { top, source, app };
}
async function pairAt(dir: string, code = 0): Promise<Pair> {
  return { dir, code, report: JSON.parse(await readFile(join(dir, 'report.json'), 'utf8')),
    agent: JSON.parse(await readFile(join(dir, 'agent-report.json'), 'utf8')) };
}
async function scan(w: Workspace, name: string, flags: string[] = []): Promise<Pair> {
  const dir = join(w.top, name);
  const code = await cli(['scan', '--source', w.source, '--tools', 'none', '--project-id', 'owned/diagnostic-handoff',
    '--analysis-profile', 'default', '--source-max-files', '1000', '--source-max-bytes', '26214400',
    '--timeout-ms', '30000', '--out', dir, ...flags]);
  return pairAt(dir, code);
}
async function resign(pair: Pair, change: (report: any) => void) {
  const report = JSON.parse(JSON.stringify(pair.report)); change(report);
  await writeFile(join(pair.dir, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  await writeFile(join(pair.dir, 'agent-report.json'), JSON.stringify(toAgentReport(report, pair.agent.scanGate.failOn), null, 2) + '\n');
  return pairAt(pair.dir, pair.code);
}
async function create(w: Workspace, pair: Pair, name: string, checkId = 'source.builtin-ast') {
  const checkIndex = pair.report.checks.findIndex((check: any) => check.id === checkId);
  assert.ok(checkIndex >= 0);
  const out = join(w.top, name);
  const code = await cli(['handoff', 'create', '--report', pair.dir, '--source', w.source,
    '--check-index', String(checkIndex), '--out', out]);
  return { out, code };
}
async function finish(w: Workspace, handoff: string, pair: Pair, name: string) {
  const out = join(w.top, name);
  const code = await cli(['handoff', 'finish', '--handoff', handoff, '--report', pair.dir, '--source', w.source, '--out', out]);
  return { out, code };
}
const receipt = async (out: string) => JSON.parse(await readFile(join(out, 'handoff.json'), 'utf8'));
function unverified(r: any) {
  assert.deepEqual(r.verification, { vulnerabilityConfirmed: false, remediationVerified: false,
    securityControl: 'not_run', normalControl: 'not_run' });
}

test('diagnostic handoff: zero-finding partial scan produces a private snapshot-bound check packet', async t => {
  const w = await workspace(t), before = await scan(w, 'before');
  assert.equal(before.code, 2); assert.equal(before.agent.findings.length, 0);
  const oldReport = await readFile(join(before.dir, 'report.json'));
  const oldAgent = await readFile(join(before.dir, 'agent-report.json'));
  const sourceHash = sha(await readFile(w.app));
  const result = await create(w, before, 'review'); assert.equal(result.code, 0);
  const r = await receipt(result.out), original = before.report.checks[r.selected.checkIndex];
  assert.equal(r.version, 2); assert.deepEqual(r.selected, { kind: 'diagnostic_check', checkIndex: r.selected.checkIndex, checkId: 'source.builtin-ast' });
  assert.equal(r.originalScanGate.exitCode, 2); assert.equal(r.diagnostic.status, 'partial');
  assert.deepEqual(r.diagnostic.analysisGaps, original.analysisGaps);
  assert.deepEqual(r.diagnostic.analysisBudget, original.analysisBudget);
  assert.equal(r.sourceBinding.complete, true); assert.equal(r.sourceBinding.digest, before.report.checks[0].sourceSnapshot.digest);
  assert.equal(r.input.reportSha256, sha(oldReport)); assert.equal(r.input.agentReportSha256, sha(oldAgent));
  assert.deepEqual(await readFile(join(result.out, 'report.json')), oldReport);
  assert.deepEqual(await readFile(join(result.out, 'agent-report.json')), oldAgent);
  assert.equal(sha(await readFile(w.app)), sourceHash);
  assert.equal((await lstat(result.out)).mode & 0o777, 0o700);
  for (const name of ['handoff.json', 'handoff.md', 'report.json', 'agent-report.json']) assert.equal((await lstat(join(result.out, name))).mode & 0o777, 0o600);
  const markdown = await readFile(join(result.out, 'handoff.md'), 'utf8');
  assert.match(markdown, /Selected diagnostic check/); assert.match(markdown, /Original scan gate: incomplete; exit 2/);
  assert.match(markdown, /dropped locations.*cannot be reconstructed/);
  assert.equal(JSON.stringify(r).includes('OWNED_PRIVATE_DIAGNOSTIC_CONTENT'), false);
  assert.equal(markdown.includes('OWNED_PRIVATE_DIAGNOSTIC_CONTENT'), false);
  assert.equal('selectedState' in r, false); unverified(r);
});

test('diagnostic handoff: selected-check progress is separate from strict comparison and the full after gate', async t => {
  for (const [name, afterText, exit, state] of [['partial', BROKEN, 2, 'still_incomplete'],
    ['completed', CLEAN, 0, 'reported_completed'], ['other-high', CLEAN + HIGH, 1, 'reported_completed']] as const) {
    const w = await workspace(t), before = await scan(w, 'before'), handoff = await create(w, before, 'review');
    assert.equal(handoff.code, 0); await writeFile(w.app, afterText);
    const after = await scan(w, 'after'); assert.equal(after.code, exit);
    const result = await finish(w, handoff.out, after, 'recheck'); assert.equal(result.code, exit);
    const r = await receipt(result.out);
    assert.equal(r.scopeComparison.basis, 'declared_source_scope'); assert.equal(r.scopeComparison.compatible, true);
    assert.equal(r.selectedCheckProgress.state, state); assert.equal(r.selectedCheckProgress.beforeStatus, 'partial');
    assert.equal(r.after.scanGate.exitCode, exit); assert.equal(r.originalScanGate.exitCode, 2);
    assert.equal(r.comparison.comparable, false); assert.equal(comparisonExitCode(compareReports(before.report, after.report), 'none'), 2);
    assert.equal('selectedState' in r, false); unverified(r);
    assert.match(await readFile(join(result.out, 'handoff.md'), 'utf8'), /Check completion is a reported analysis status, not a fix/);
    assert.deepEqual(await readFile(join(handoff.out, 'report.json')), await readFile(join(before.dir, 'report.json')));
  }
});

test('diagnostic handoff: incomplete strict code coverage can be selected without inventing a finding', async t => {
  const w = await workspace(t), before = await scan(w, 'before', ['--require-code-analysis']);
  const check = before.report.checks.find((check: any) => check.id === 'source.code-coverage');
  assert.equal(check.status, 'partial'); assert.equal(before.agent.findings.length, 0);
  const result = await create(w, before, 'review', 'source.code-coverage'); assert.equal(result.code, 0);
  assert.deepEqual((await receipt(result.out)).diagnostic.codeCoverage, check.codeCoverage);
});

test('diagnostic handoff: incomplete framework check is explicit and excludes inventory or completed checks', async t => {
  const w = await workspace(t, CLEAN), original = await scan(w, 'before');
  const before = await resign(original, report => { const check = report.checks.find((c: any) => c.id === 'source.framework'); check.status = 'error'; check.notes = ['Owned diagnostic framework error; no source contents.']; });
  const result = await create(w, before, 'framework', 'source.framework'); assert.equal(result.code, 0);
  assert.equal((await receipt(result.out)).diagnostic.status, 'error');
  assert.equal((await create(w, before, 'inventory', 'source.inventory')).code, 2);
  assert.equal((await create(w, before, 'completed', 'source.builtin-ast')).code, 2);
});

test('diagnostic handoff: source drift, inconsistent pairs and uncollected reported positions fail closed', async t => {
  for (const kind of ['drift', 'pair', 'position', 'legacy'] as const) {
    const w = await workspace(t); let before = await scan(w, 'before');
    if (kind === 'drift') await writeFile(w.app, BROKEN + '// changed');
    if (kind === 'pair') await writeFile(join(before.dir, 'agent-report.json'), '{}');
    if (kind === 'position') before = await resign(before, report => { report.checks.find((c: any) => c.id === 'source.builtin-ast').analysisGaps.items[0].location.path = 'not-collected.ts'; });
    if (kind === 'legacy') before = await resign(before, report => { report.scope.ruleset = '2026-10-14.2'; });
    const result = await create(w, before, 'review'); assert.equal(result.code, 2, kind);
    assert.equal((await receipt(result.out)).status, 'incomplete');
  }
});

test('diagnostic handoff: check-only grammar remains canonical and malformed selectors cannot choose a row', async t => {
  const w = await workspace(t), before = await scan(w, 'before');
  for (const [index, value] of ['01', '+1', '-1', '1.0', '1e0', '999', '9007199254740992'].entries()) {
    assert.equal(await cli(['handoff', 'create', '--report', before.dir, '--source', w.source,
      '--check-index', value, '--out', join(w.top, 'invalid-' + index)]), 2);
  }
  assert.equal(await cli(['handoff', 'create', '--report', before.dir, '--source', w.source, '--out', join(w.top, 'missing')]), 2);
});

test('diagnostic handoff: finding packets keep v1 and strict incomplete comparison behavior', async t => {
  const w = await workspace(t, HIGH); await writeFile(join(w.source, 'broken.ts'), BROKEN);
  const before = await scan(w, 'before'), finding = before.agent.findings[0]; assert.ok(finding);
  const out = join(w.top, 'review');
  assert.equal(await cli(['handoff', 'create', '--report', before.dir, '--source', w.source,
    '--finding', finding.findingId, '--check-index', String(finding.checkIndex), '--out', out]), 0);
  const r = await receipt(out); assert.equal(r.version, 1); assert.equal('kind' in r.selected, false); assert.equal('diagnostic' in r, false);
  const after = await scan(w, 'after'); assert.equal((await finish(w, out, after, 'recheck')).code, 2);
});

test('diagnostic handoff: configured alias candidate context still binds through the unchanged finding path', async t => {
  const w = await workspace(t, "import {execute} from '@owned/helper'; export function route(req){execute(req.query.command)}\n");
  await mkdir(join(w.source, 'src'));
  await writeFile(join(w.source, 'src/helper.ts'), 'export function execute(value){eval(value)}\n');
  await writeFile(join(w.source, 'tsconfig.json'), JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@owned/*': ['src/*'] } } }));
  const before = await scan(w, 'before');
  const finding = before.agent.findings.find((row: any) => row.evidence.staticContext?.items.some((item: any) => item.kind === 'configured_module_resolution'));
  assert.ok(finding, 'new configured graph context must appear in the canonical finding');
  const out = join(w.top, 'review');
  assert.equal(await cli(['handoff', 'create', '--report', before.dir, '--source', w.source,
    '--finding', finding.findingId, '--check-index', String(finding.checkIndex), '--out', out]), 0);
  assert.equal((await receipt(out)).version, 1);
  const copied = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
  assert.deepEqual(copied.findings, before.agent.findings);
});
