import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseReport, parseScanReport, readReport, readScanReport } from '../src/compare.js';
import { parseRuntimeReport, sanitiseRuntimeReport, sanitiseReport, toAgentReport } from '../src/report.js';
import type { Report, RuntimeReport, ScanReport } from '../src/contracts.js';
import type { EvidenceGrade, Reach, RuntimeCheckId, RuntimeFinding } from '../src/runtime/types.js';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const ref = (name: string) => ({ path: name + '.json', bytes: 0, sha256: sha(name) });
const clone = <T>(data: T): T => JSON.parse(JSON.stringify(data));
function part(report: RuntimeReport, id: RuntimeCheckId): any { return report.checks.find(row => row.id === id)!; }
function fixture(): RuntimeReport {
  const surface = { id: 'fixture-route', method: 'GET', pathTemplate: '/api/items/search' };
  const row = () => ({ status: 'completed' as const, findings: [], notes: [] });
  return { schemaVersion: '1.0.0', toolVersion: '0.5.0', mode: 'runtime',
    startedAt: '2026-10-28T00:00:00.000Z', finishedAt: '2026-10-28T00:00:01.000Z',
    checks: [
      { ...row(), id: 'runtime.build', runtime: { builder: 'compose', imageDigest: 'sha256:' + sha('image'),
        cacheKey: sha('cache'), durationMs: 1, reasons: [], isolation: {
          requested: 'rootless-docker', applied: 'rootless-docker', daemonRootless: true, backend: 'linux-rootless',
          daemonVersion: '28.0.0', runtimeVersion: 'runc-1.2.5', targetUid: 1000, capDropAll: true,
          readOnlyRootfs: true, seccomp: 'default', cgroup: { version: 2, driver: 'systemd', systemd: true,
            delegatedUnit: 'wakeio.service', controllers: ['cpu', 'memory', 'pids'] },
          resources: { requested: { cpu: 1, memoryBytes: 1048576, pids: 64 },
            measured: { cpuQuota: 100000, memoryMax: 1048576, pidsMax: 64 }, probe: ref('isolation'), enforced: true },
          buildNetwork: 'registry-allowlist', runNetwork: 'internal', verified: true, gaps: [] } } },
      { ...row(), id: 'runtime.start', runtime: { lease: ref('lease'), health: 'passed', durationMs: 1,
        instrumentation: ref('instrumentation'), reasons: [] } },
      { ...row(), id: 'runtime.surface', runtime: { declared: 1, enumerated: 1, reasons: [], routes: [{ surface,
        attacked: true, reasons: [], provenance: [{ provider: 'openapi', rawInputSha256: sha('raw'),
          sanitizedArtifact: ref('inventory'), locator: '#/paths/~1api~1items~1search/get' }] }] } },
      { ...row(), id: 'runtime.coverage', runtime: { method: 'jacoco', reasons: [], dumpRefs: [ref('coverage')],
        routes: [{ surface: { ...surface }, files: [{ path: 'src/Fixture.java', sha256: sha('source'),
          coveredLines: [1],
          executableLines: [1, 2] }], coveredFiles: 1, coveredLines: 1, executableLines: 2, ratio: 0.5,
          accounting: 'exact', reasons: [] }] } },
      { ...row(), id: 'runtime.oracle.sql', runtime: { method: 'pg-ast-token-differential', reasons: [],
        cases: [{ surfaceId: surface.id, state: 'not_triggered', reasons: ['bound_parameter'] }],
        markerLedger: ref('markers'), parserRevision: 'libpg-query-18.2.1', verdictRefs: [] } },
    ], runtime: { revision: 'verify-m1-v1', scope: { requestedVulnClasses: ['sql'],
      unsupportedVulnClasses: ['command', 'ssrf', 'path', 'xss', 'redirect', 'authz'], gaps: [] },
      inputArtifacts: [ref('source')], stages: [ref('stage')], verifyGate: {
        outcome: 'pass', exitCode: 0, failOnGrade: 'strong', blockingFindingIds: [], reasons: [] },
      cleanup: { status: 'confirmed', lease: ref('lease'), processGroupExitConfirmed: true,
        resources: [{ kind: 'container', id: 'owned-target', absenceConfirmed: true }],
        remainingOwnedIds: [], reasons: [] } } };
}
function finding(grade: EvidenceGrade, reach: Reach = grade === 'confirmed' ? 'triggered' : 'reached_not_triggered') {
  return { id: sha('finding-' + grade), ruleId: 'runtime.sql', title: 'SQL observation',
    description: 'Recorded evidence',
    severity: 'high', confidence: 'medium', kind: 'candidate', location: { path: 'src/Fixture.java', line: 1 },
    remediation: 'Review code', evidence: { basis: 'runtime-observation-ledger', grade, reach,
      markers: [sha('m1'), sha('m2')], controlPairId: 'pair-1', oracleRevision: 'sql-projection/v1',
      refs: [ref('control'), ref('probe')] } } as RuntimeFinding;
}
function withFinding(grade: 'confirmed' | 'strong' = 'confirmed'): RuntimeReport {
  const report = fixture(), sql = part(report, 'runtime.oracle.sql'), item = finding(grade);
  sql.findings = [item]; sql.runtime.cases[0].state = 'triggered';
  sql.runtime.verdictRefs = [ref('verdicts')];
  report.runtime.verifyGate = { outcome: 'findings', exitCode: 1, failOnGrade: 'strong',
    blockingFindingIds: [item.id!], reasons: [] }; return report;
}
function incomplete(report: RuntimeReport): void {
  report.runtime.verifyGate = { outcome: 'incomplete', exitCode: 2, failOnGrade: 'strong', blockingFindingIds: [],
    reasons: [{ area: 'oracle.sql', code: 'not_completed' }] };
}

test('common/runtime readers retain evidence without legacy proof or independent verification claims', () => {
  const report = withFinding(), before = JSON.stringify(report), safe = parseReport(report);
  assert.equal(safe.mode, 'runtime');
  if (safe.mode !== 'runtime') throw Error('wrong branch');
  assert.equal(part(safe, 'runtime.oracle.sql').findings[0].evidence.grade, 'confirmed');
  assert.equal(part(safe, 'runtime.oracle.sql').findings[0].evidence.basis, 'runtime-observation-ledger');
  assert.equal(JSON.stringify(sanitiseRuntimeReport(safe)), JSON.stringify(safe));
  assert.equal(JSON.stringify(report), before);
  report.runtime.verifyGate.blockingFindingIds.length = 0;
  assert.equal(safe.runtime.verifyGate.blockingFindingIds.length, 1);
  assert.throws(() => parseScanReport(safe));
  assert.equal('verification' in safe, false);
});

test('report contract copies R8 V/F/N grade expectations without executing or deriving SQL verdicts', async () => {
  const raw = await readFile('tests/fixtures/runtime-m1/sql-cases.json');
  const corpus = JSON.parse(raw.toString('utf8'));
  for (const item of corpus.cases) {
    const expected = item.expected, report = expected.confirmed ? withFinding('confirmed')
      : expected.strong ? withFinding('strong') : fixture();
    const surface = clone(item.surface), sql = part(report, 'runtime.oracle.sql');
    part(report, 'runtime.surface').runtime.routes[0].surface = surface;
    part(report, 'runtime.coverage').runtime.routes[0].surface = clone(surface);
    sql.runtime.cases[0] = { surfaceId: surface.id, state: sql.runtime.cases[0].state, reasons: [expected.reason] };
    if (expected.unknown) {
      sql.status = 'partial'; sql.runtime.reasons = [expected.reason];
      sql.runtime.cases = [{ surfaceId: surface.id, state: 'unknown', reasons: [expected.reason] }];
      if (sql.findings.length) {
        sql.runtime.cases.push({ surfaceId: surface.id, state: 'triggered', reasons: [expected.reason] });
        sql.findings[0].evidence.reach = 'unknown';
      } else incomplete(report);
    }
    const safe = parseRuntimeReport(report);
    assert.equal(safe.runtime.verifyGate.exitCode, expected.exit, item.id);
    const findings = part(safe, 'runtime.oracle.sql').findings as RuntimeFinding[];
    assert.equal(findings.filter(row => row.evidence.grade === 'confirmed').length, expected.confirmed, item.id);
    assert.equal(findings.filter(row => row.evidence.grade === 'strong').length, expected.strong, item.id);
  }
  assert.deepEqual(await readFile('tests/fixtures/runtime-m1/sql-cases.json'), raw);
});

test('free prose, URL credentials/query and raw wire markers are not replayed', async () => {
  const corpus = JSON.parse(await readFile('tests/fixtures/runtime-m1/sql-cases.json', 'utf8'));
  const report = withFinding(), sql = part(report, 'runtime.oracle.sql');
  const body = corpus.rawTemplates.promotion.statement, marker = corpus.cases[0].requests[0].marker;
  sql.findings[0].description = `${body} ${marker} password="private-password"`;
  sql.notes = [sql.findings[0].description];
  sql.findings[0].references = ['https://user:private-password@example.test/advice?token=private-query#fragment'];
  const before = JSON.stringify(report), safe = parseRuntimeReport(report), output = JSON.stringify(safe);
  for (const text of [body, marker, 'private-password', 'private-query', 'user:']) {
    assert.ok(!output.includes(text));
  }
  assert.equal(part(safe, 'runtime.oracle.sql').findings[0].references[0], 'https://example.test/advice');
  assert.equal(JSON.stringify(report), before);
  for (const key of ['rawSql', 'payload', 'response', 'credentials']) {
    const bad: any = clone(report); bad.checks[4].runtime[key] = body;
    assert.throws(() => parseRuntimeReport(bad), { message: 'invalid_runtime_report' });
  }
});

test('mixed branches, invalid schema, required checks, empty plans and missing SQL metadata are rejected', () => {
  const mutations: Array<(r: any) => void> = [
    r => { r.mode = 'source'; }, r => { r.runtime.revision = 'verify-m2-v1'; }, r => { r.scope = {}; },
    r => { r.checks.pop(); }, r => { r.checks[1] = clone(r.checks[0]); },
    r => { r.checks[0].status = 'not_applicable'; r.checks[0].runtime.reasons = ['not_implemented']; },
    r => { r.checks[4].runtime.cases = []; }, r => { r.checks[4].runtime.parserRevision = null;
      r.checks[4].runtime.reasons = ['parser_missing']; },
    r => { r.checks[4].runtime.markerLedger = null; r.checks[4].runtime.reasons = ['markers_missing']; },
    r => { r.checks[4].findings[0].evidence.markers = []; }, r => { r.checks[4].findings[0].evidence.refs = []; },
    r => { delete r.checks[4].findings[0].id; }, r => { r.checks[4].findings.push(clone(r.checks[4].findings[0])); },
    r => { r.checks[4].findings[0].evidence.grade = 'strong'; },
    r => { r.checks[4].findings[0].evidence.reach = 'reached_not_triggered'; },
    r => { r.startedAt = 'not-a-date'; }, r => { r.finishedAt = '2025-01-01T00:00:00Z'; },
    r => { r.startedAt = '2026-02-30T00:00:00Z'; },
    r => { r.toolVersion = 'unknown'; }, r => { r.checks[0].runtime.imageDigest = 'not-a-digest'; },
    r => { r.checks[0].runtime.isolation.resources.enforced = false; },
    r => { r.checks[1].runtime.health = 'unknown'; r.checks[1].runtime.reasons = ['health_unknown']; },
    r => { r.checks[2].runtime.enumerated = 2; },
    r => { r.checks[2].runtime.routes.push(clone(r.checks[2].runtime.routes[0])); r.checks[2].runtime.enumerated = 2; },
    r => { r.runtime.cleanup.processGroupExitConfirmed = false; }, r => { r.runtime.cleanup.resources = []; },
    r => { r.runtime.cleanup.reasons = ['cleanup_unknown']; },
    r => { r.runtime.cleanup.lease.sha256 = sha('different'); },
  ];
  for (const mutate of mutations) {
    const report = withFinding(); mutate(report); assert.throws(() => parseReport(report));
  }
  const legacy: any = JSON.parse(JSON.stringify(fixture())); delete legacy.runtime; legacy.mode = 'source';
  assert.throws(() => parseReport(legacy));
});

test('coverage arithmetic, unique files, route identities, null and unknown accounting remain honest', () => {
  const mutations: Array<(r: any) => void> = [
    r => { r.files.push(clone(r.files[0])); }, r => { r.files[0].coveredLines = [3]; },
    r => { r.files[0].coveredLines = [1, 1]; }, r => { r.coveredFiles = 0; },
    r => { r.coveredLines = 0; }, r => { r.executableLines = 1; }, r => { r.ratio = 1; },
    r => { r.surface.method = 'POST'; }, r => { r.files[0].path = '../escape'; },
  ];
  for (const mutate of mutations) {
    const report = fixture(); mutate(part(report, 'runtime.coverage').runtime.routes[0]);
    assert.throws(() => parseRuntimeReport(report));
  }
  const report = fixture(), coverage = part(report, 'runtime.coverage');
  coverage.status = 'partial'; coverage.runtime.reasons = ['coverage_unknown'];
  Object.assign(coverage.runtime.routes[0], { files: null, coveredFiles: null, coveredLines: null,
    executableLines: null, ratio: null, accounting: 'unknown', reasons: ['coverage_unknown'] });
  incomplete(report);
  assert.equal(part(parseRuntimeReport(report), 'runtime.coverage').runtime.routes[0].ratio, null);
  coverage.runtime.routes[0].ratio = 0; assert.throws(() => parseRuntimeReport(report));
  const both = fixture(), discovery = part(both, 'runtime.surface'), covered = part(both, 'runtime.coverage');
  const second = clone(discovery.runtime.routes[0]); second.surface = {
    id: 'second-route', method: 'GET', pathTemplate: '/api/second' };
  discovery.runtime.routes.push(second); discovery.runtime.enumerated = discovery.runtime.declared = 2;
  const mapping = clone(covered.runtime.routes[0]); mapping.surface = clone(second.surface);
  covered.runtime.routes.push(mapping);
  part(both, 'runtime.oracle.sql').runtime.cases.push({
    surfaceId: 'second-route', state: 'not_triggered', reasons: [],
  });
  assert.doesNotThrow(() => parseRuntimeReport(both));
  second.surface.pathTemplate = mapping.surface.pathTemplate = '/api/items/search';
  assert.throws(() => parseRuntimeReport(both));
  second.surface.pathTemplate = mapping.surface.pathTemplate = '/api/second';
  mapping.files[0].sha256 = sha('different-source'); assert.throws(() => parseRuntimeReport(both));
});

test('null SQL metadata remains unknown; zero line denominators never become invented percentages', () => {
  const report = fixture(), sql = part(report, 'runtime.oracle.sql');
  sql.status = 'partial'; sql.runtime.reasons = ['metadata_unknown'];
  sql.runtime.markerLedger = sql.runtime.parserRevision = null;
  sql.runtime.cases[0] = { surfaceId: 'fixture-route', state: 'unknown', reasons: ['metadata_unknown'] };
  incomplete(report);
  const parsed = parseRuntimeReport(report);
  assert.equal(part(parsed, 'runtime.oracle.sql').runtime.parserRevision, null);
  assert.equal(parsed.runtime.verifyGate.exitCode, 2);
  const zero = fixture(), coverage = part(zero, 'runtime.coverage');
  Object.assign(coverage.runtime.routes[0], { files: [], coveredFiles: 0, coveredLines: 0,
    executableLines: 0, ratio: null, reasons: ['no_executable_lines'] });
  assert.equal(part(parseRuntimeReport(zero), 'runtime.coverage').runtime.routes[0].ratio, null);
  coverage.status = 'not_applicable'; coverage.runtime.reasons = ['no_executable_lines'];
  assert.throws(() => parseRuntimeReport(zero));
});

test('gate recomputation keeps finding priority, exact blocking IDs and recorded unknowns', () => {
  const found = withFinding(); found.runtime.cleanup.status = 'error';
  found.runtime.cleanup.reasons = ['cleanup_unknown']; found.runtime.cleanup.processGroupExitConfirmed = false;
  assert.equal(parseRuntimeReport(found).runtime.verifyGate.exitCode, 1);
  for (const bad of [[], [sha('other')]]) {
    const next = clone(found); next.runtime.verifyGate.blockingFindingIds = bad;
    assert.throws(() => parseRuntimeReport(next));
  }
  const strong = withFinding('strong');
  strong.runtime.verifyGate.failOnGrade = 'confirmed';
  assert.throws(() => parseRuntimeReport(strong));
  Object.assign(strong.runtime.verifyGate, { exitCode: 0, outcome: 'pass', blockingFindingIds: [] });
  assert.equal(parseRuntimeReport(strong).checks[4].findings[0].evidence.grade, 'strong');
  const unknown = fixture(); unknown.runtime.scope.gaps.push({ area: 'oracle.sql', code: 'unknown' });
  assert.throws(() => parseRuntimeReport(unknown)); incomplete(unknown);
  assert.equal(parseRuntimeReport(unknown).runtime.scope.gaps[0].code, 'unknown');
});

test('new boundaries reject caller hooks and byte/node/depth overflows without calls', () => {
  let calls = 0;
  const getter = Object.defineProperty(fixture(), 'runtime', {
    get() { calls++; throw Error('must not run'); },
  });
  const inherited = Object.create({ get mode() { calls++; throw Error('must not run'); } });
  const custom = Object.assign(fixture(), { toJSON() { calls++; return {}; } });
  const proxy = new Proxy(fixture(), { get() { calls++; throw Error('must not run'); } });
  const huge: any = fixture(); huge.checks[0].notes = ['x'.repeat(1024 * 1024 + 1)];
  const many: any = fixture(); many.checks[0].notes = Array(20001).fill('x');
  const deep: any = fixture(); let cursor = deep; for (let i = 0; i < 42; i++) cursor = cursor.extra = {};
  for (const raw of [getter, inherited, custom, proxy, huge, many, deep]) {
    for (const parse of [parseReport, parseRuntimeReport, sanitiseRuntimeReport]) assert.throws(() => parse(raw));
  }
  assert.equal(calls, 0);
});

test('bounded/common and historical scan readers keep distinct limits and legacy projections', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-runtime-reader-'));
  try {
    const path = join(top, 'report.json'); await writeFile(path, JSON.stringify(withFinding()), { mode: 0o600 });
    assert.equal((await readReport(path)).mode, 'runtime');
    await symlink(path, join(top, 'link')); await assert.rejects(readReport(join(top, 'link')));
    await assert.rejects(readReport(join(top, 'password=private-path')), { message: 'invalid_report' });
    const legacy = JSON.parse(await readFile('tests/fixtures/compat-0.5/findings/reports/report.json', 'utf8'));
    assert.deepEqual(parseReport(legacy), parseScanReport(legacy));
    assert.deepEqual(sanitiseReport(legacy), parseScanReport(legacy));
    assert.equal(toAgentReport(legacy).findings[0].verification.vulnerabilityConfirmed, false);
    legacy.checks[0].notes.push('x'.repeat(1024 * 1024 + 1));
    assert.doesNotThrow(() => parseScanReport(legacy)); assert.throws(() => parseReport(legacy));
    await writeFile(path, JSON.stringify(legacy));
    assert.equal((await readScanReport(path)).mode, legacy.mode); await assert.rejects(readReport(path));
  } finally { await rm(top, { recursive: true, force: true }); }
});

// Compile-time compatibility: broad common data never widens the old scan-only contracts.
function types(runtime: RuntimeReport, scan: ScanReport): Report {
  const unchanged: ScanReport = sanitiseReport(scan); void unchanged;
  // @ts-expect-error RuntimeReport is not a legacy ScanReport.
  sanitiseReport(runtime);
  return parseReport(runtime);
}
void types;
