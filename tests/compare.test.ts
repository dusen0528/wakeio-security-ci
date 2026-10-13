import { resolveAnalysisBudget } from '../src/source/analysis-budget.js';
import { collectionEvidence, resolveCollectionBudget } from '../src/source/collection-budget.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createReport } from '../src/report.js';
import { compareReports, comparisonExitCode, parseScanReport, readScanReport } from '../src/compare.js';
import { main } from '../src/cli.js';
import { buildScanScope } from '../src/scan-scope.js';
import { runSource } from '../src/source.js';
import type { Finding, CheckResult, ScanProvenance } from '../src/contracts.js';

const finding = (line = 1): Finding => ({ ruleId: 'fixture:sql', title: 'Input reaches SQL', description: 'Candidate',
  severity: 'high', confidence: 'medium', kind: 'candidate', location: { path: 'app.ts', line }, remediation: 'Use parameters.' });
const check = (findings: Finding[], status: CheckResult['status'] = 'completed'): CheckResult => ({ id: 'source.builtin-ast', findings, status, notes: [], analysisBudget: resolveAnalysisBudget() });
const scope = { fingerprint: 'a'.repeat(64), ruleset: 'test.1', analysisBudget: resolveAnalysisBudget() };
const report = (findings: Finding[], status: CheckResult['status'] = 'completed') => createReport([check(findings, status)], 'source', new Date(), scope);

const collectedReport = (findings: Finding[], maxFiles = 1000, exclusions = 0) => {
  const collectionBudget = resolveCollectionBudget({ maxFiles });
  const inventory: CheckResult = { id: 'source.inventory', status: 'completed', findings: [], notes: [], collectionBudget,
    collectionEvidence: collectionEvidence(Array.from({ length: exclusions }, () => ({ code: 'unsupported_file' as const }))) };
  return createReport([inventory, check(findings)], 'source', new Date(), { ...scope, collectionBudget });
};

test('report comparison preserves counts, stable IDs, new and changed finding gates', () => {
  const before = report([finding(1), finding(2), finding(3)]);
  const after = report([finding(1), { ...finding(2), severity: 'critical' }, finding(4)]);
  const comparison = compareReports(before, after);
  assert.deepEqual(comparison.summary, { new: 1, changed: 1, unchanged: 1, not_observed: 1, unverified: 0 });
  assert.equal(comparisonExitCode(comparison, 'critical'), 1);
  assert.equal(comparisonExitCode(comparison, 'none'), 0);
  assert.equal(before.checks[0].findings[0].id, after.checks[0].findings[0].id);
  assert.equal(before.checks[0].findings.length, 3);
  const unchanged = compareReports(before, report([finding(1), finding(2), finding(3)]));
  assert.equal(comparisonExitCode(unchanged, 'high'), 0);
});

test('missing scope, changed versions, missing checks, or incomplete scans never imply a fix', () => {
  const before = report([finding()]);
  const mutations = [
    () => ({ ...report([]), scope: undefined }),
    () => ({ ...report([]), scope: { ...scope, fingerprint: 'b'.repeat(64) } }),
    () => ({ ...report([]), toolVersion: 'different' }),
    () => ({ ...report([]), checks: [] }),
    () => report([], 'partial'),
    () => report([], 'not_applicable'),
  ];
  for (const mutate of mutations) {
    const comparison = compareReports(before, mutate());
    assert.equal(comparison.comparable, false);
    assert.equal(comparison.summary.not_observed, 0);
    assert.equal(comparison.summary.unverified, 1);
    assert.equal(comparisonExitCode(comparison, 'none'), 2);
  }
});

test('line movement and duplicate findings remain visible without claiming remediation', () => {
  const moved = compareReports(report([finding(1)]), report([finding(2)]));
  assert.equal(moved.summary.new, 1);
  assert.equal(moved.summary.not_observed, 1);
  assert.ok(moved.limitations.some((line) => /not proof of a security fix/.test(line)));
  const duplicates = compareReports(report([finding(), finding()]), report([finding()]));
  assert.equal(duplicates.comparable, false);
  assert.deepEqual(duplicates.summary, { new: 0, changed: 0, unchanged: 0, not_observed: 0, unverified: 3 });
  assert.equal(comparisonExitCode(duplicates, 'none'), 2);
});

test('semantic comparison keys survive line movement and duplicate keys remain unverified', () => {
  const key = 'b'.repeat(64);
  const anchored = (line: number): Finding => ({ ...finding(line), comparisonKey: key });
  const moved = compareReports(report([anchored(1)]), report([anchored(9)]));
  assert.deepEqual(moved.summary, { new: 0, changed: 0, unchanged: 1, not_observed: 0, unverified: 0 });
  const duplicate = compareReports(report([anchored(1), anchored(2)]), report([anchored(3)]));
  assert.equal(duplicate.comparable, false);
  assert.equal(comparisonExitCode(duplicate, 'none'), 2);
  assert.ok(duplicate.reasons.some((reason) => /comparison key.*more than once/i.test(reason)));
  assert.equal(duplicate.summary.unverified, 3);
});

test('project identity makes different checkout paths stable while content hash remains provenance', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-scope-'));
  const left = join(root, 'left');
  const right = join(root, 'right');
  await mkdir(left);
  await mkdir(right);
  try {
    await writeFile(join(left, 'app.ts'), 'export const value = 1;\n');
    await writeFile(join(right, 'app.ts'), 'export const value = 1;\n');
    const common = { mode: 'source' as const, projectId: 'acme/example', tools: [], ruleset: 'test.1' };
    const leftScope = await buildScanScope({ ...common, source: left });
    const rightScope = await buildScanScope({ ...common, source: right });
    assert.equal(leftScope.fingerprint, rightScope.fingerprint);
    assert.equal(leftScope.provenance?.sourceContentHash, rightScope.provenance?.sourceContentHash);
    await writeFile(join(right, 'app.ts'), 'export const value = 2;\n');
    const changedScope = await buildScanScope({ ...common, source: right });
    assert.equal(changedScope.fingerprint, rightScope.fingerprint);
    assert.notEqual(changedScope.provenance?.sourceContentHash, rightScope.provenance?.sourceContentHash);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('same-byte engines at different paths remain comparable, while an engine change is provenance drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-engine-scope-'));
  const left = join(root, 'left');
  const right = join(root, 'right');
  const leftEngine = join(root, 'engine-left');
  const rightEngine = join(root, 'engine-right');
  await mkdir(left);
  await mkdir(right);
  try {
    await writeFile(join(left, 'app.ts'), 'export const value = 1;\n');
    await writeFile(join(right, 'app.ts'), 'export const value = 1;\n');
    await writeFile(leftEngine, '#!/bin/sh\nexit 0\n');
    await writeFile(rightEngine, '#!/bin/sh\nexit 0\n');
    await chmod(leftEngine, 0o755);
    await chmod(rightEngine, 0o755);
    const base = { mode: 'source' as const, projectId: 'acme/example', tools: ['gitleaks' as const], ruleset: 'test.1' };
    const leftScope = await buildScanScope({ ...base, source: left, toolPaths: { gitleaks: leftEngine } });
    const rightScope = await buildScanScope({ ...base, source: right, toolPaths: { gitleaks: rightEngine } });
    assert.equal(leftScope.fingerprint, rightScope.fingerprint);
    assert.deepEqual(leftScope.provenance?.engines, rightScope.provenance?.engines);
    const leftInventory = (await runSource({ root: left, tools: [] })).find(check => check.id === 'source.inventory')!;
    const rightInventory = (await runSource({ root: right, tools: [] })).find(check => check.id === 'source.inventory')!;
    const before = createReport([check([finding()]), leftInventory], 'source', new Date(), leftScope);
    const after = createReport([check([finding()]), rightInventory], 'source', new Date(), rightScope);
    assert.equal(compareReports(before, after).comparable, true);
    await writeFile(rightEngine, '#!/bin/sh\nexit 1\n');
    const changedScope = await buildScanScope({ ...base, source: right, toolPaths: { gitleaks: rightEngine } });
    const changed = compareReports(before, createReport([check([finding()]), rightInventory], 'source', new Date(), changedScope));
    assert.equal(changed.comparable, false);
    assert.ok(changed.reasons.some((reason) => /engine provenance changed/i.test(reason)));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('unknown data and incomplete engine provenance cannot claim comparable reports', () => {
  const base = { fingerprint: 'c'.repeat(64), ruleset: 'test.1' };
  const unknown = {
    ...base,
    provenance: {
      engines: [{ name: 'osv', status: 'unreadable' as const }],
      dataSources: { osvDatabase: 'online-unknown' },
    },
  };
  const before = createReport([check([finding()])], 'source', new Date(), unknown);
  const after = createReport([check([finding()])], 'source', new Date(), unknown);
  const result = compareReports(before, after);
  assert.equal(result.comparable, false);
  assert.equal(comparisonExitCode(result, 'none'), 2);
  assert.ok(result.reasons.some((reason) => /unknown/i.test(reason)));
  assert.ok(result.reasons.some((reason) => /incomplete/i.test(reason)));
  assert.throws(() => parseScanReport({ ...before, scope: {
    ...base,
    provenance: { engines: [{ name: 'osv', status: 'available' }] },
  } }));
});

test('external checks without provenance cannot be presented as comparable', () => {
  const external: CheckResult = { id: 'source.gitleaks', status: 'completed', findings: [], notes: [] };
  const base = createReport([external], 'source', new Date(), scope);
  const result = compareReports(base, base);
  assert.equal(result.comparable, false);
  assert.equal(comparisonExitCode(result, 'none'), 2);
  assert.ok(result.reasons.some((reason) => /external scanner checks.*provenance is missing/i.test(reason)));
});

test('each applicable external check requires its own engine and required data-source evidence', () => {
  const completed = (id: CheckResult['id']): CheckResult => ({ id, status: 'completed', findings: [], notes: [] });
  const engine = (name: string) => ({ name, status: 'available' as const, sha256: 'a'.repeat(64) });
  const withScope = (checkId: CheckResult['id'], provenance: ScanProvenance) =>
    createReport([completed(checkId)], 'source', new Date(), { ...scope, provenance });

  const sourceOnly = withScope('source.gitleaks', { sourceContentHash: 'b'.repeat(64) });
  const sourceOnlyResult = compareReports(sourceOnly, sourceOnly);
  assert.equal(sourceOnlyResult.comparable, false);
  assert.ok(sourceOnlyResult.reasons.some((reason) => /source\.gitleaks lacks available engine/i.test(reason)));

  const gitleaks = withScope('source.gitleaks', { engines: [engine('gitleaks')] });
  assert.equal(compareReports(gitleaks, gitleaks).comparable, true);

  const osvMissingSource = withScope('source.osv', { engines: [engine('osv')] });
  const osvMissingSourceResult = compareReports(osvMissingSource, osvMissingSource);
  assert.equal(osvMissingSourceResult.comparable, false);
  assert.ok(osvMissingSourceResult.reasons.some((reason) => /source\.osv lacks osvDatabase/i.test(reason)));

  const osvUnknownSource = withScope('source.osv', {
    engines: [engine('osv')], dataSources: { osvDatabase: 'online-unknown' },
  });
  const osvUnknownSourceResult = compareReports(osvUnknownSource, osvUnknownSource);
  assert.equal(osvUnknownSourceResult.comparable, false);
  assert.ok(osvUnknownSourceResult.reasons.some((reason) => /source\.osv has unknown osvDatabase/i.test(reason)));

  const trivyMissingBundle = withScope('source.trivy', {
    engines: [engine('trivy')], dataSources: { trivyDatabase: 'db-2026-09-16' },
  });
  const trivyMissingBundleResult = compareReports(trivyMissingBundle, trivyMissingBundle);
  assert.equal(trivyMissingBundleResult.comparable, false);
  assert.ok(trivyMissingBundleResult.reasons.some((reason) => /source\.trivy lacks trivyChecksBundle/i.test(reason)));

  const banditMissingEngine = withScope('source.bandit', {
    dataSources: { banditRuntime: 'python-3.12-bandit-1' },
  });
  const banditMissingEngineResult = compareReports(banditMissingEngine, banditMissingEngine);
  assert.equal(banditMissingEngineResult.comparable, false);
  assert.ok(banditMissingEngineResult.reasons.some((reason) => /source\.bandit lacks available engine/i.test(reason)));
});

test('untrusted report IDs are recomputed and malformed input is rejected', () => {
  const input = report([finding()]);
  input.checks[0].findings[0].id = 'forged';
  const parsed = parseScanReport(input);
  assert.match(parsed.checks[0].findings[0].id!, /^[a-f0-9]{64}$/);
  assert.throws(() => parseScanReport({ ...input, checks: [{ id: 'x', status: 'completed' }] }));
  assert.throws(() => parseScanReport({ ...input, checks: [input.checks[0], input.checks[0]] }));
  assert.throws(() => parseScanReport({ ...input, scope: { fingerprint: 'invalid', ruleset: 'v1' } }));
  assert.throws(() => parseScanReport({ ...input, scope: {
    ...scope,
    provenance: {
      engines: [
        { name: 'gitleaks', status: 'missing' },
        { name: 'gitleaks', status: 'available', sha256: 'a'.repeat(64) },
      ],
    },
  } }));
});

test('CLI comparison reads real scan artifacts, writes results, and rejects linked input', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-compare-'));
  try {
    const before = join(root, 'before.json');
    const after = join(root, 'after.json');
    const out = join(root, 'comparison');
    await writeFile(before, JSON.stringify(report([finding()])));
    await writeFile(after, JSON.stringify(report([])));
    assert.equal(await main(['compare', '--before', before, '--after', after, '--out', out]), 0);
    const comparison = JSON.parse(await readFile(join(out, 'comparison.json'), 'utf8'));
    assert.equal(comparison.summary.not_observed, 1);
    assert.match(await readFile(join(out, 'comparison.md'), 'utf8'), /not proof/);
    await symlink(before, join(root, 'linked.json'));
    await assert.rejects(readScanReport(join(root, 'linked.json')));
    await writeFile(after, '{"checks": []}');
    assert.equal(await main(['compare', '--before', before, '--after', after, '--out', out]), 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('collection comparison binds effective limits independently of a supplied unchanged scope fingerprint', () => {
  const before = collectedReport([finding()]);
  const same = compareReports(before, collectedReport([]));
  assert.equal(same.comparable, true);
  assert.equal(same.summary.not_observed, 1);
  const changed = collectedReport([], 2000);
  assert.equal(before.scope!.fingerprint, changed.scope!.fingerprint);
  const inconsistent = collectedReport([]);
  inconsistent.scope!.collectionBudget = resolveCollectionBudget({ maxFiles: 2000 });
  const missingScopeBudget = collectedReport([]);
  delete missingScopeBudget.scope!.collectionBudget;
  const missingInventoryBudget = collectedReport([]);
  delete missingInventoryBudget.checks[0].collectionBudget;
  const missingEvidence = collectedReport([]);
  delete missingEvidence.checks[0].collectionEvidence;
  for (const after of [changed, inconsistent, missingScopeBudget, missingInventoryBudget, missingEvidence, collectedReport([], 1000, 1)]) {
    const comparison = compareReports(before, after);
    assert.equal(comparison.comparable, false);
    assert.equal(comparison.summary.not_observed, 0);
    assert.equal(comparison.summary.unverified, 1);
    assert.ok(comparison.reasons.some(reason => /collection/.test(reason)));
  }
});

test('legacy inventory reports remain readable but missing collection identity stays unverified', () => {
  const before = collectedReport([finding()]);
  const after = collectedReport([]);
  for (const report of [before, after]) {
    delete report.scope!.collectionBudget;
    delete report.checks[0].collectionBudget;
    delete report.checks[0].collectionEvidence;
    assert.equal(parseScanReport(report).checks[0].status, 'completed');
  }
  assert.equal(compareReports(before, after).comparable, false);
  assert.equal(compareReports(before, after).summary.not_observed, 0);
  assert.equal(parseScanReport(report([])).scope!.collectionBudget, undefined);
});

test('comparison rejects malformed typed collection records before sanitization can drop them', () => {
  for (const mutation of [
    (report: ReturnType<typeof collectedReport>) => { report.scope!.collectionBudget = { revision: 'bad' } as any; },
    (report: ReturnType<typeof collectedReport>) => { report.checks[0].collectionBudget = { ...resolveCollectionBudget(), extra: true } as any; },
    (report: ReturnType<typeof collectedReport>) => { report.checks[0].collectionEvidence = { revision: 'collection-v1', issueCount: 1, issues: [] }; },
    (report: ReturnType<typeof collectedReport>) => { report.checks[0].collectionEvidence = collectionEvidence([{ code: 'file_limit' }]); },
    (report: ReturnType<typeof collectedReport>) => { report.checks[0].collectionEvidence = collectionEvidence([{ code: 'root_error' }]); report.checks[0].status = 'partial'; },
    (report: ReturnType<typeof collectedReport>) => { report.checks[1].collectionBudget = resolveCollectionBudget(); },
  ]) {
    const after = collectedReport([]);
    mutation(after);
    assert.throws(() => parseScanReport(after), /Invalid scan report/);
    assert.throws(() => compareReports(collectedReport([finding()]), after), /Invalid scan report/);
  }
  let reads = 0;
  for (const destination of ['scope', 'inventory'] as const) {
    const after = collectedReport([]);
    Object.defineProperty(destination === 'scope' ? after.scope! : after.checks[0], 'collectionBudget', { get: () => { reads++; throw new Error('must not run'); } });
    assert.throws(() => parseScanReport(after), /Invalid scan report/);
  }
  assert.equal(reads, 0);
});

test('SDK sanitization cannot turn malformed collection scope into comparable legacy identity', () => {
  const malformedScope = { ...scope, collectionBudget: { revision: 'collection-v1', limits: {} } as any };
  const before = createReport([check([finding()])], 'source', new Date(), malformedScope);
  const after = createReport([check([])], 'source', new Date(), malformedScope);
  assert.equal(before.scope, undefined);
  assert.equal(after.scope, undefined);
  assert.equal(before.checks[0].status, 'completed');
  assert.equal(after.checks[0].status, 'completed');
  const comparison = compareReports(before, after);
  assert.equal(comparison.comparable, false);
  assert.equal(comparison.summary.not_observed, 0);
  assert.equal(comparison.summary.unverified, 1);
  let reads = 0;
  const accessorScope = { ...scope };
  Object.defineProperty(accessorScope, 'collectionBudget', { get: () => { reads++; throw new Error('must not run'); } });
  assert.equal(createReport([check([])], 'source', new Date(), accessorScope).scope, undefined);
  assert.equal(reads, 0);
});
