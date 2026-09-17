import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createReport, exitCode, toMarkdown, toSarif, writeReports } from '../src/report.js';
import type { CheckResult } from '../src/contracts.js';

const startedAt = '2026-09-15T00:00:00.000Z';

function finding(overrides: Partial<CheckResult['findings'][number]> = {}) {
  return {
    ruleId: 'fixture-rule',
    title: 'Fixture package 1.2.3',
    description: 'password="a value that must not be copied" ghp_A1b2C3d4E5f6G7h8I9j0',
    severity: 'high' as const,
    confidence: 'medium' as const,
    kind: 'candidate' as const,
    location: { path: 'src/unsafe name #?.ts', line: 7, column: 3 },
    remediation: 'Rotate the credential and review the configuration.',
    references: ['https://example.com/advisory?id=private'],
    ...overrides,
  };
}

test('report projection redacts secrets and query strings', () => {
  const report = createReport(
    [{ id: 'fixture', status: 'completed', findings: [finding()], notes: [] }],
    'source',
    startedAt,
  );
  const serialised = JSON.stringify(report);
  assert.equal(serialised.includes('ghp_A1b2C3d4E5f6G7h8I9j0'), false);
  assert.equal(serialised.includes('a value that must not be copied'), false);
  assert.equal(serialised.includes('?id=private'), false);
  assert.equal(report.checks[0].findings[0].kind, 'candidate');

  const sarif = toSarif(report) as any;
  const result = sarif.runs[0].results[0];
  assert.equal(result.kind, undefined);
  assert.match(result.locations[0].physicalLocation.artifactLocation.uri, /%20|%23|%3F/);
  assert.match(result.fingerprints['wakeio-security-ci/v1'], /^[a-f0-9]{64}$/);
  assert.match(result.partialFingerprints['wakeio-security-ci/v1'], /^[a-f0-9]{64}$/);
  assert.equal(sarif.runs[0].automationDetails.id, 'wakeio-security-ci/source');
  assert.equal(sarif.runs[0].properties.category, 'wakeio-security-ci/source');
  assert.equal(result.helpUri, undefined);
  assert.equal(sarif.runs[0].tool.driver.rules[0].helpUri, 'https://example.com/advisory');
});

test('semantic anchors and bounded provenance survive report projections without paths or secrets', () => {
  const comparisonKey = 'd'.repeat(64);
  const report = createReport(
    [{ id: 'fixture', status: 'completed', findings: [finding({ comparisonKey })], notes: [] }],
    'source',
    startedAt,
    {
      fingerprint: 'e'.repeat(64),
      ruleset: 'test.1',
      projectId: 'acme/example',
      provenance: {
        sourceContentHash: 'f'.repeat(64),
        engines: [{ name: 'gitleaks', status: 'available', sha256: '1'.repeat(64) }],
        dataSources: { osvDatabase: 'online-unknown' },
      },
    },
  );
  assert.equal(report.scope?.projectId, 'acme/example');
  assert.equal(report.scope?.provenance?.sourceContentHash, 'f'.repeat(64));
  assert.equal(report.checks[0].findings[0].comparisonKey, comparisonKey);
  const sarif = toSarif(report) as any;
  const result = sarif.runs[0].results[0];
  assert.equal(result.partialFingerprints['wakeio-security-ci/comparison-key'], comparisonKey);
  assert.equal(result.primaryLocationLineHash, undefined);
  const markdown = toMarkdown(report);
  assert.match(markdown, /Project ID/);
  assert.match(markdown, /Source content hash/);
  assert.match(markdown, /online-unknown/);
});

test('exitCode gives incomplete work priority and does not treat not_applicable alone as clean', () => {
  const complete: CheckResult = { id: 'complete', status: 'completed', findings: [], notes: [] };
  const findingCheck: CheckResult = { id: 'finding', status: 'completed', findings: [finding()], notes: [] };
  const error: CheckResult = { id: 'error', status: 'error', findings: [finding({ severity: 'critical' })], notes: [] };
  const notApplicable: CheckResult = { id: 'na', status: 'not_applicable', findings: [], notes: [] };
  assert.equal(exitCode(createReport([complete], 'source', startedAt), 'high'), 0);
  assert.equal(exitCode(createReport([findingCheck], 'source', startedAt), 'high'), 1);
  assert.equal(exitCode(createReport([findingCheck], 'source', startedAt), 'critical'), 0);
  assert.equal(exitCode(createReport([findingCheck], 'source', startedAt), 'none'), 0);
  assert.equal(exitCode(createReport([error], 'source', startedAt), 'none'), 2);
  assert.equal(exitCode(createReport([notApplicable], 'source', startedAt), 'none'), 2);
  assert.equal(exitCode(createReport([], 'source', startedAt), 'none'), 2);
});

test('writeReports writes the standard three artifacts and rejects symlink ancestors and targets', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-report-test-'));
  const outside = await mkdtemp(join(tmpdir(), 'wakeio-report-outside-'));
  const report = createReport(
    [{ id: 'fixture', status: 'completed', findings: [], notes: [] }],
    'source',
    startedAt,
  );
  try {
    await writeReports(report, root);
    for (const name of ['report.json', 'report.sarif', 'report.md']) {
      const contents = await readFile(join(root, name), 'utf8');
      assert.ok(contents.length > 0);
    }

    const target = join(root, 'preserved.txt');
    await writeFile(target, 'keep');
    await symlink(target, join(root, 'report.json.new'));
    await assert.rejects(
      writeReports(report, join(root, 'report.json.new')),
      /not a directory|symlink|output path/i,
    );

    const link = join(root, 'link');
    await symlink(outside, link);
    await assert.rejects(writeReports(report, join(link, 'reports')), /symlink/i);
    assert.equal(await readFile(target, 'utf8'), 'keep');
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
