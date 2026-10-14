import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { main } from '../src/cli.js';
import { toAgentReport } from '../src/report.js';
import { compareDeclaredSourceScope, compareReports, comparisonExitCode } from '../src/compare.js';
import type { AgentReport, ScanReport } from '../src/contracts.js';

const BROKEN = 'function { /* owned inert parse failure */\n';
const CLEAN = 'export const owned = 1;\n';
type Workspace = { top: string; source: string; app: string };
type Pair = { dir: string; report: ScanReport; agent: AgentReport; code: number };
async function cli(args: string[]) {
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try { return await main(args); }
  finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
async function workspace(t: TestContext, text = BROKEN): Promise<Workspace> {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-independent-diagnostic-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'), app = join(source, 'app.ts');
  await mkdir(source); await writeFile(app, text);
  return { top, source, app };
}
async function pair(dir: string, code = 0): Promise<Pair> {
  return { dir, code, report: JSON.parse(await readFile(join(dir, 'report.json'), 'utf8')),
    agent: JSON.parse(await readFile(join(dir, 'agent-report.json'), 'utf8')) };
}
async function scan(w: Workspace, name: string, projectId = 'owned/independent-diagnostic') {
  const dir = join(w.top, name);
  const code = await cli(['scan', '--source', w.source, '--tools', 'none', '--project-id', projectId,
    '--out', dir]);
  return pair(dir, code);
}
async function resign(original: Pair, change: (report: ScanReport) => void) {
  const report: ScanReport = JSON.parse(JSON.stringify(original.report)); change(report);
  await writeFile(join(original.dir, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  await writeFile(join(original.dir, 'agent-report.json'), JSON.stringify(toAgentReport(report, 'high'), null, 2) + '\n');
  return pair(original.dir, original.code);
}
async function create(w: Workspace, before: Pair, id = 'source.builtin-ast') {
  const index = before.report.checks.findIndex(c => c.id === id); assert.ok(index >= 0);
  const out = join(w.top, 'handoff');
  const code = await cli(['handoff', 'create', '--report', before.dir, '--source', w.source,
    '--check-index', String(index), '--out', out]);
  return { code, out };
}
async function finish(w: Workspace, handoff: string, after: Pair, name = 'finished') {
  const out = join(w.top, name);
  const code = await cli(['handoff', 'finish', '--handoff', handoff, '--report', after.dir,
    '--source', w.source, '--out', out]);
  return { code, out };
}
const receipt = async (out: string) => JSON.parse(await readFile(join(out, 'handoff.json'), 'utf8'));

test('diagnostic independent: zero-finding partial review preserves strict comparison and the complete after gate', async t => {
  for (const high of [false, true]) {
    const w = await workspace(t), before = await scan(w, 'before');
    assert.equal(before.code, 2); assert.equal(before.agent.findings.length, 0);
    const handoff = await create(w, before); assert.equal(handoff.code, 0);
    await writeFile(w.app, CLEAN + (high ? 'export function route(req) { eval(req.query.code); }\n' : ''));
    const after = await scan(w, 'after'); assert.equal(after.code, high ? 1 : 0);
    const result = await finish(w, handoff.out, after); assert.equal(result.code, after.code);
    const r = await receipt(result.out);
    assert.equal(r.scopeComparison.compatible, true);
    assert.equal(r.selectedCheckProgress.state, 'reported_completed');
    assert.equal(r.comparison.comparable, false);
    assert.equal(comparisonExitCode(compareReports(before.report, after.report), 'none'), 2);
    assert.equal(r.after.scanGate.exitCode, after.code);
    assert.equal(r.originalScanGate.exitCode, 2);
    assert.equal(r.verification.vulnerabilityConfirmed, false);
    assert.equal(r.verification.remediationVerified, false);
    assert.equal('selectedState' in r, false, 'diagnostics must not acquire finding disappearance states');
    if (high) assert.ok(r.after.scanGate.blockingFindingIds.length > 0);
  }
});

test('diagnostic independent: selected check becoming not-applicable remains unverified even with a clean after gate', async t => {
  const w = await workspace(t, CLEAN), original = await scan(w, 'before');
  assert.equal(original.code, 0);
  const before = await resign(original, report => {
    const framework = report.checks.find(c => c.id === 'source.framework'); assert.ok(framework);
    framework.status = 'error'; framework.notes = ['Owned reported framework diagnostic; no target execution.'];
  });
  const handoff = await create(w, before, 'source.framework'); assert.equal(handoff.code, 0);
  const after = await scan(w, 'after'); assert.equal(after.code, 0);
  assert.equal(after.report.checks.find(c => c.id === 'source.framework')?.status, 'not_applicable');
  const result = await finish(w, handoff.out, after); assert.equal(result.code, 2);
  const r = await receipt(result.out);
  assert.equal(r.scopeComparison.compatible, true, 'declared scope is distinct from selected applicability');
  assert.equal(r.selectedCheckProgress.afterStatus, 'not_applicable');
  assert.equal(r.selectedCheckProgress.state, 'unverified');
  assert.equal(r.after.scanGate.exitCode, 0, 'preserve the actual global gate without using it to erase uncertainty');
  assert.equal(r.verification.remediationVerified, false);
});

test('diagnostic independent: changed declared project scope cannot pass on completed clean source', async t => {
  const w = await workspace(t), before = await scan(w, 'before');
  const handoff = await create(w, before); assert.equal(handoff.code, 0);
  await writeFile(w.app, CLEAN);
  const after = await scan(w, 'after', 'owned/different-project'); assert.equal(after.code, 0);
  const result = await finish(w, handoff.out, after); assert.equal(result.code, 2);
  const r = await receipt(result.out);
  assert.equal(r.scopeComparison.compatible, false);
  assert.ok(r.scopeComparison.reasons.length > 0);
  assert.equal(r.selectedCheckProgress.state, 'unverified');
  assert.equal(r.after.scanGate.exitCode, 0);
  assert.equal(r.comparison.comparable, false);
});

test('diagnostic independent: scope helper ignores completion/content changes without ignoring unknown identities', async t => {
  const w = await workspace(t), before = await scan(w, 'before');
  await writeFile(w.app, CLEAN); const after = await scan(w, 'after');
  assert.equal(compareDeclaredSourceScope(before.report, after.report).compatible, true);
  assert.equal(compareReports(before.report, after.report).comparable, false);
  const variants: Array<(report: ScanReport) => void> = [
    report => { delete report.scope!.analysisBudget; },
    report => { report.scope!.provenance!.engines = [{ name: 'owned', status: 'unknown' }]; },
    report => { report.scope!.provenance!.dataSources = { ownedRules: 'unknown' }; },
    report => { delete report.checks.find(c => c.id === 'source.inventory')!.collectionEvidence; },
  ];
  for (const mutate of variants) {
    const changed: ScanReport = JSON.parse(JSON.stringify(after.report)); mutate(changed);
    const result = compareDeclaredSourceScope(before.report, changed);
    assert.equal(result.compatible, false); assert.ok(result.reasons.length > 0);
  }
});

test('diagnostic independent: changing packet mode or reported diagnostic cannot grant a successful finish', async t => {
  for (const [reason, mutate] of [
    ['invalid_finding', (r: any) => { r.version = 1; r.selected.kind = 'finding'; r.selected.findingId = 'f'.repeat(64); }],
    ['invalid_handoff', (r: any) => { r.selected.kind = 'finding'; }],
    ['invalid_handoff', (r: any) => { r.diagnostic.status = 'completed'; }],
  ] as const) {
    const w = await workspace(t), before = await scan(w, 'before');
    const handoff = await create(w, before); assert.equal(handoff.code, 0);
    const changed = await receipt(handoff.out); mutate(changed);
    await writeFile(join(handoff.out, 'handoff.json'), JSON.stringify(changed, null, 2) + '\n');
    await writeFile(w.app, CLEAN); const after = await scan(w, 'after');
    const result = await finish(w, handoff.out, after); assert.equal(result.code, 2);
    const r = await receipt(result.out); assert.equal(r.status, 'incomplete');
    assert.equal(r.reason, reason);
    assert.equal(r.exitCode, 2); assert.equal('selectedCheckProgress' in r, false);
    assert.equal('after' in r, false);
    assert.equal(r.verification.vulnerabilityConfirmed, false);
    assert.equal(r.verification.remediationVerified, false);
  }
});
