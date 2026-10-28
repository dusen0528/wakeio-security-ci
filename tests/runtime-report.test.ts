import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { isBuiltin } from 'node:module';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseReport, parseScanReport, readReport, readScanReport } from '../src/compare.js';
import { parseRuntimeReport, sanitiseRuntimeReport, sanitiseCommonReport, sanitiseScanReport,
  toCommonAgentReport, toCommonReportSummary,
  toCommonMarkdown, toCommonSarif, writeCommonReports, evaluateGate, sanitiseReport,
  toAgentReport, toReportSummary, toMarkdown, toSarif, writeReports } from '../src/report.js';
import type { AgentReport, Report, RuntimeAgentReport, RuntimeReport, ScanReport } from '../src/contracts.js';
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

test('isolated legacy entries never load Ajv; runtime loads and compiles once on first use', async () => {
  const legacy = JSON.parse(await readFile('tests/fixtures/compat-0.5/findings/reports/report.json', 'utf8'));
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { readFileSync } from 'node:fs';
    import Module from 'node:module';
    const load = Module._load;
    let loads = 0, count = 0, allowed = false, calls = 0;
    Module._load = function (id, ...args) {
      if (id !== 'ajv/dist/2020.js') return Reflect.apply(load, this, [id, ...args]);
      loads++; assert.ok(allowed, 'runtime_ajv_loaded_for_legacy');
      const loaded = Reflect.apply(load, this, [id, ...args]), compile = loaded.Ajv2020.prototype.compile;
      loaded.Ajv2020.prototype.compile = function (...args) {
        count++; return Reflect.apply(compile, this, args);
      };
      return loaded;
    };
    const { parseReport, parseScanReport } = await import(
      ${JSON.stringify(new URL('../src/compare.js', import.meta.url).href)});
    const { parseRuntimeReport, sanitiseRuntimeReport, sanitiseCommonReport } = await import(
      ${JSON.stringify(new URL('../src/report.js', import.meta.url).href)});
    const { legacy, runtime } = JSON.parse(readFileSync(0, 'utf8'));
    assert.equal(loads, 0); assert.equal(count, 0);
    assert.deepEqual(parseReport(legacy), parseScanReport(legacy));
    assert.deepEqual(sanitiseCommonReport(legacy), parseScanReport(legacy));
    const getter = Object.defineProperty({}, 'mode', { get() { calls++; throw Error('must_not_run'); } });
    const proxy = new Proxy({}, { get() { calls++; throw Error('must_not_run'); } });
    const custom = { toJSON() { calls++; throw Error('must_not_run'); } };
    for (const raw of [getter, proxy, custom]) {
      assert.throws(() => parseReport(raw)); assert.throws(() => parseRuntimeReport(raw));
    }
    assert.equal(calls, 0); assert.equal(loads, 0); assert.equal(count, 0);
    allowed = true;
    assert.equal(parseReport(runtime).mode, 'runtime'); assert.equal(count, 1);
    assert.deepEqual(sanitiseRuntimeReport(runtime), parseRuntimeReport(runtime));
    const wrongSchema = structuredClone(runtime); wrongSchema.runtime.revision = 'unknown';
    assert.throws(() => parseRuntimeReport(wrongSchema), { message: 'invalid_runtime_report' });
    const wrongCount = structuredClone(runtime); wrongCount.checks[3].runtime.routes[0].ratio = 1;
    assert.throws(() => parseRuntimeReport(wrongCount), { message: 'invalid_runtime_report' });
    assert.equal(loads, 1); assert.equal(count, 1);
  `], { input: JSON.stringify({ legacy, runtime: withFinding() }), encoding: 'utf8', timeout: 30000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null);
  assert.equal(child.status, 0, child.stderr); assert.equal(child.stdout, '');
});

test('static bundled runtime reader validates without any Ajv resolution outside its module', async () => {
  const { build } = await import('esbuild');
  const top = await mkdtemp(join(tmpdir(), 'wakeio-runtime-reader-bundle-'));
  try {
    const bundled = await build({
      entryPoints: ['build/src/runtime-report.js'], bundle: true, platform: 'node', format: 'esm', target: 'node22',
      write: false, metafile: true, logLevel: 'silent',
    });
    assert.ok(Object.keys(bundled.metafile.inputs).some(path => path.includes('ajv/dist/2020')));
    for (const output of Object.values(bundled.metafile.outputs)) {
      assert.ok(output.imports.every(item => item.external && isBuiltin(item.path)));
    }
    const path = join(top, 'reader.mjs'); await writeFile(path, bundled.outputFiles[0].contents);
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import Module, { createRequire } from 'node:module';
      import { readFileSync } from 'node:fs';
      import { pathToFileURL } from 'node:url';
      const path = process.argv[1], require = createRequire(path), load = Module._load;
      assert.throws(() => require.resolve('ajv/dist/2020.js'), { code: 'MODULE_NOT_FOUND' });
      Module._load = function (id, ...args) {
        assert.ok(!['ajv', 'fast-uri', 'fast-deep-equal', 'json-schema-traverse'].includes(id.split('/')[0]));
        return Reflect.apply(load, this, [id, ...args]);
      };
      const { parseRuntimeReport } = await import(pathToFileURL(path).href);
      const runtime = JSON.parse(readFileSync(0, 'utf8'));
      assert.equal(parseRuntimeReport(runtime).runtime.verifyGate.exitCode, 1);
      runtime.runtime.revision = 'unknown';
      assert.throws(() => parseRuntimeReport(runtime), { message: 'invalid_runtime_report' });
    `, path], { input: JSON.stringify(withFinding()), encoding: 'utf8', timeout: 30000 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null);
    assert.equal(child.status, 0, child.stderr); assert.equal(child.stdout, '');
  } finally { await rm(top, { recursive: true, force: true }); }
});

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
    const agent = toCommonAgentReport(report), navigation = toCommonReportSummary(report);
    assert.equal(navigation.findings.confirmedIds.length, expected.confirmed, item.id);
    assert.equal(navigation.findings.strongIds.length, expected.strong, item.id);
    assert.equal(agent.runtime.verifyGate.exitCode, expected.exit, item.id);
    assert.deepEqual(agent.summary, navigation);
    assert.deepEqual(toCommonSarif(report).runs[0].properties.runtime, safe.runtime);
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
  assert.deepEqual(toCommonReportSummary(both).coverage.lines.map(row => row.executableLines), [2, 2]);
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
    assert.deepEqual(sanitiseCommonReport(legacy), parseScanReport(legacy));
    assert.equal(toCommonAgentReport(legacy).findings[0].verification.vulnerabilityConfirmed, false);
    legacy.checks[0].notes.push('x'.repeat(1024 * 1024 + 1));
    assert.doesNotThrow(() => parseScanReport(legacy)); assert.throws(() => parseReport(legacy));
    await writeFile(path, JSON.stringify(legacy));
    assert.equal((await readScanReport(path)).mode, legacy.mode); await assert.rejects(readReport(path));
  } finally { await rm(top, { recursive: true, force: true }); }
});

// Compile-time compatibility: broad common data never widens the old scan-only contracts.
function types(runtime: RuntimeReport, scan: ScanReport): Report {
  const unchanged: ScanReport = sanitiseReport(scan); void unchanged;
  const legacyAgent: AgentReport = toAgentReport(scan); void legacyAgent;
  const runtimeAgent: RuntimeAgentReport = toCommonAgentReport(runtime); void runtimeAgent;
  const runtimeSafe: RuntimeReport = sanitiseCommonReport(runtime); void runtimeSafe;
  return parseReport(runtime);
}
void types;

test('legacy source/API readers, projections and writer preserve ID-only namespaces', async () => {
  const base = JSON.parse(await readFile('tests/fixtures/compat-0.5/pass/reports/report.json', 'utf8'));
  const top = await mkdtemp(join(tmpdir(), 'wakeio-legacy-report-id-'));
  try {
    for (const mode of ['source', 'api'] as const) {
      const legacy: ScanReport = { ...base, mode, checks: [
        { id: 'runtime.legacy-extension', status: 'partial', findings: [], notes: [] },
      ] };
      delete legacy.scope;
      const old = parseScanReport(legacy), id = legacy.checks[0].id;
      assert.equal(old.checks[0].id, id);
      assert.deepEqual(sanitiseScanReport(legacy), old); assert.deepEqual(sanitiseReport(legacy), old);
      assert.deepEqual(sanitiseCommonReport(legacy), old);
      assert.deepEqual(toCommonAgentReport(legacy), toAgentReport(legacy));
      const agent = toAgentReport(legacy), navigation = toReportSummary(legacy);
      assert.equal(agent.mode, mode); assert.equal(agent.checks[0].checkId, id);
      assert.deepEqual(agent.scanGate, evaluateGate(old)); assert.deepEqual(agent.summary, navigation);
      assert.equal(navigation.incompleteChecks[0].checkId, id);
      // Historical Markdown escapes punctuation; its displayed check ID is unchanged.
      assert.ok(toMarkdown(legacy).replaceAll('\\', '').includes(id));
      assert.ok(JSON.stringify(toSarif(legacy)).includes(id));
      assert.deepEqual(parseReport(legacy), old);
      const out = join(top, mode); await writeReports(legacy, out);
      const stored = JSON.parse(await readFile(join(out, 'report.json'), 'utf8'));
      const commonOut = join(top, mode + '-common'); await writeCommonReports(legacy, commonOut);
      assert.deepEqual(JSON.parse(await readFile(join(commonOut, 'report.json'), 'utf8')), stored);
      const storedAgent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
      assert.equal(stored.checks[0].id, id); assert.equal(storedAgent.checks[0].checkId, id);
      assert.equal((await readScanReport(join(out, 'report.json'))).checks[0].id, id);
      assert.deepEqual(await readReport(join(out, 'report.json')), await readScanReport(join(out, 'report.json')));
      assert.equal(await readFile(join(out, 'report.md'), 'utf8'), toMarkdown(legacy));
      assert.deepEqual(JSON.parse(await readFile(join(out, 'report.sarif'), 'utf8')), toSarif(legacy));
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('common runtime projections retain grades, refs and verification limits with matching raw SHA', async () => {
  const report = withFinding(), sql = part(report, 'runtime.oracle.sql');
  const corpus = JSON.parse(await readFile('tests/fixtures/runtime-m1/sql-cases.json', 'utf8'));
  const secret = 'private-password', marker = corpus.cases[0].requests[0].marker;
  sql.findings[0].location.path = 'src/Fixture #%.java';
  sql.findings[0].description = corpus.rawTemplates.promotion.statement + ' ' + marker + ' password="' + secret + '"';
  const before = JSON.stringify(report), safe = sanitiseCommonReport(report), agent = toCommonAgentReport(report);
  const summary = toCommonReportSummary(report), sarif = toCommonSarif(report), markdown = toCommonMarkdown(report);
  assert.deepEqual(agent.runtime, safe.runtime); assert.deepEqual(agent.summary, summary);
  assert.equal(agent.reportArtifact.digest, sha(JSON.stringify(safe, null, 2) + '\n'));
  assert.equal(agent.checks.length, 5); assert.equal(agent.findings[0].checkId, 'runtime.oracle.sql');
  assert.equal(agent.findings[0].checkIndex, 4); assert.equal(agent.findings[0].reachesFailOnGrade, true);
  assert.deepEqual(agent.findings[0].evidence, part(safe, 'runtime.oracle.sql').findings[0].evidence);
  assert.deepEqual(clone(agent.findings[0].verification),
    { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
  assert.equal(agent.findings[0].remediation.state, 'not_verified');
  assert.equal(agent.consumerRequirements.findingsGrantActionAuthorization, false);
  assert.equal(agent.deliveryContract.finalProcessExitRequiresSeparateReceipt, true);
  assert.equal('scanGate' in agent, false); assert.equal('scope' in summary, false);
  assert.equal(sarif.runs[0].results[0].properties.findingId, agent.findings[0].findingId);
  assert.equal(sarif.runs[0].results[0].locations![0].physicalLocation!.artifactLocation!.uri,
    'src/Fixture%20%23%25.java');
  assert.deepEqual(sarif.runs[0].properties.checks, safe.checks);
  for (const text of [JSON.stringify(safe), JSON.stringify(agent), JSON.stringify(sarif), markdown]) {
    for (const raw of [secret, marker, corpus.rawTemplates.promotion.statement]) assert.ok(!text.includes(raw));
  }
  assert.ok(markdown.indexOf('## Findings by grade') < markdown.indexOf('## Verify gate'));
  assert.ok(markdown.indexOf('## Verify gate') < markdown.indexOf('## Reach, unknown and coverage'));
  assert.ok(markdown.indexOf('## Reach, unknown and coverage') < markdown.indexOf('## Limitations'));
  assert.equal(JSON.stringify(report), before);
  agent.runtime.cleanup.reasons.push('caller_mutation');
  assert.deepEqual(toCommonAgentReport(report).summary, summary);
});

test('runtime summary keeps unknown routes, per-route line denominators and finding priority distinct', () => {
  const report = fixture(), surface = part(report, 'runtime.surface'), sql = part(report, 'runtime.oracle.sql');
  const coverage = part(report, 'runtime.coverage');
  surface.status = 'partial'; surface.runtime.reasons = ['surface_unknown']; surface.runtime.declared = null;
  surface.runtime.routes[0].attacked = null;
  surface.runtime.routes[0].reasons = ['attack_accounting_unknown'];
  sql.status = 'partial'; sql.runtime.reasons = ['oracle_unknown'];
  sql.runtime.cases[0] = { surfaceId: 'fixture-route', state: 'unknown', reasons: ['oracle_unknown'] };
  coverage.status = 'partial'; coverage.runtime.reasons = ['coverage_unknown'];
  Object.assign(coverage.runtime.routes[0], { files: null, coveredFiles: null, coveredLines: null,
    executableLines: null, ratio: null, accounting: 'unknown', reasons: ['coverage_unknown'] });
  incomplete(report);
  const navigation = toCommonReportSummary(report);
  assert.equal(navigation.coverage.declaredRoutes, null); assert.equal(navigation.coverage.unknownRoutes, 1);
  assert.equal(navigation.coverage.attackedRoutes, null); assert.equal(navigation.coverage.unattackedRoutes, null);
  assert.equal(navigation.coverage.routeRatio, null); assert.equal(navigation.coverage.lines[0].executableLines, null);
  assert.equal(navigation.coverage.lines[0].ratio, null); assert.equal(navigation.unknownCases.length, 1);
  assert.equal(navigation.reach.unknown, 0); assert.equal(navigation.verifyGate.exitCode, 2);
  const found = withFinding(); found.runtime.cleanup.status = 'error';
  found.runtime.cleanup.reasons = ['cleanup_unknown']; found.runtime.cleanup.processGroupExitConfirmed = false;
  part(found, 'runtime.oracle.sql').findings[0].evidence.reach = 'unknown';
  assert.equal(toCommonReportSummary(found).verifyGate.exitCode, 1);
  assert.equal(toCommonAgentReport(found).runtime.cleanup.status, 'error');
  assert.equal(toCommonReportSummary(found).reach.unknown, 1);
});

test('common projection dispatch rejects mixed branches, caller hooks and severity policy on runtime', () => {
  let calls = 0;
  const getter = Object.defineProperty(withFinding(), 'mode', { get() { calls++; throw Error('must_not_run'); } });
  const proxy = new Proxy(withFinding(), { get() { calls++; throw Error('must_not_run'); } });
  const mixed: any = withFinding(); mixed.mode = 'source'; delete mixed.runtime;
  const bad: any = withFinding(); bad.checks[4].findings[0].evidence.tokenHashes = [sha('not_public')];
  for (const raw of [getter, proxy, mixed, bad]) {
    const projects = [sanitiseCommonReport, toCommonAgentReport, toCommonReportSummary,
      toCommonSarif, toCommonMarkdown];
    for (const project of projects) {
      assert.throws(() => project(raw as RuntimeReport));
    }
  }
  assert.equal(calls, 0);
  assert.throws(() => (toCommonAgentReport as any)(withFinding(), 'none'));
  assert.throws(() => (toCommonMarkdown as any)(withFinding(), 'none'));
});

test('runtime common writer creates a new private source-external directory and binds actual JSON bytes', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-runtime-writer-'));
  try {
    const source = join(top, 'source'), out = join(top, 'reports'); await mkdir(source);
    await writeFile(join(source, 'owned.txt'), 'source_canary');
    await assert.rejects((writeCommonReports as any)(withFinding(), out));
    await assert.rejects(lstat(out), { code: 'ENOENT' });
    await assert.rejects((writeCommonReports as any)(withFinding(), out, { sourceRoot: source, failOn: 'none' }));
    await assert.rejects(writeCommonReports(withFinding(), join(source, 'reports'), { sourceRoot: source }));
    await writeCommonReports(withFinding(), out, { sourceRoot: source });
    assert.equal((await lstat(out)).mode & 0o777, 0o700);
    assert.deepEqual((await readdir(out)).sort(), ['agent-report.json', 'report.json', 'report.md', 'report.sarif']);
    const reportJson = await readFile(join(out, 'report.json'), 'utf8');
    const agent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
    assert.equal(agent.reportArtifact.digest, sha(reportJson));
    assert.deepEqual(agent.runtime, JSON.parse(reportJson).runtime);
    assert.equal(await readFile(join(out, 'report.md'), 'utf8'), toCommonMarkdown(withFinding()));
    for (const name of await readdir(out)) assert.equal((await lstat(join(out, name))).mode & 0o777, 0o600);
    await assert.rejects(writeCommonReports(withFinding(), out, { sourceRoot: source }));
    assert.equal(await readFile(join(source, 'owned.txt'), 'utf8'), 'source_canary');
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('runtime publication interruption leaves partial files and never publishes the bound agent early', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-runtime-writer-fault-'));
  try {
    const source = join(top, 'source'), out = join(top, 'reports'); await mkdir(source);
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import fs from 'node:fs/promises';
      import { readFileSync } from 'node:fs';
      import { syncBuiltinESMExports } from 'node:module';
      const link = fs.link;
      fs.link = async (from, to) => {
        if (to.endsWith('/report.md')) throw Error('owned_publication_interruption');
        return link(from, to);
      };
      syncBuiltinESMExports();
      const { writeCommonReports } = await import(${JSON.stringify(new URL('../src/report.js', import.meta.url).href)});
      await assert.rejects(writeCommonReports(JSON.parse(readFileSync(0, 'utf8')), process.argv[2],
        { sourceRoot: process.argv[1] }));
    `, source, out], { input: JSON.stringify(withFinding()), encoding: 'utf8', timeout: 30000 });
    assert.equal(child.error, undefined); assert.equal(child.status, 0, child.stderr);
    assert.deepEqual((await readdir(out)).sort(), ['report.json', 'report.sarif']);
    assert.equal(JSON.parse(await readFile(join(out, 'report.json'), 'utf8')).runtime.verifyGate.exitCode, 1);
    assert.deepEqual(await readdir(source), []);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('legacy class and nested Proxy/accessor metadata retain Scan sanitation without added caller hooks', async () => {
  const base: ScanReport = JSON.parse(await readFile('tests/fixtures/compat-0.5/findings/reports/report.json', 'utf8'));
  const wrapped = Object.assign(new class LegacyReport {}, clone(base));
  assert.deepEqual(sanitiseReport(wrapped), sanitiseScanReport(wrapped));
  assert.deepEqual(sanitiseCommonReport(wrapped), sanitiseReport(base));
  assert.deepEqual(toAgentReport(wrapped), toAgentReport(base));
  assert.equal(toMarkdown(wrapped), toMarkdown(base)); assert.deepEqual(toSarif(wrapped), toSarif(base));
  let calls = 0;
  const trap = () => { calls++; throw Error('must_not_run'); };
  const raw = clone(base), row = raw.checks.find(item => item.findings.length > 0)!;
  row.findings[0] = new Proxy(row.findings[0], { get: trap, ownKeys: trap,
    getOwnPropertyDescriptor: trap, getPrototypeOf: trap });
  const safe = sanitiseScanReport(raw), projected = sanitiseReport(raw);
  assert.deepEqual(projected, safe);
  assert.deepEqual(sanitiseCommonReport(raw), safe);
  assert.equal(projected.checks.find(item => item.id === row.id)!.status, 'partial');
  assert.equal(projected.checks.find(item => item.id === row.id)!.findings[0].confidence, 'low');
  assert.deepEqual(toAgentReport(raw), toAgentReport(safe));
  for (const metadata of [Object.create({ get basis() { return trap(); } }),
    new Proxy({}, { get: trap, ownKeys: trap, getOwnPropertyDescriptor: trap })]) {
    const input = clone(base), finding = input.checks.find(item => item.findings.length > 0)!.findings[0];
    Object.assign(finding, { evidence: metadata });
    assert.deepEqual(sanitiseReport(input), sanitiseScanReport(input));
  }
  const accessor = clone(base), finding = accessor.checks.find(item => item.findings.length > 0)!.findings[0];
  Object.defineProperty(finding, 'evidence', { enumerable: true, get: trap });
  assert.deepEqual(sanitiseReport(accessor), sanitiseScanReport(accessor));
  assert.equal(calls, 0);
  const forwarding = new Proxy(base, {});
  assert.deepEqual(sanitiseScanReport(forwarding), sanitiseScanReport(base));
  assert.deepEqual(sanitiseReport(forwarding), sanitiseReport(base));
  assert.throws(() => sanitiseCommonReport(forwarding), { message: 'invalid_runtime_report' });
});

test('explicit runtime signals keep class, nested Proxy and accessor inputs strict without invoking hooks', () => {
  let calls = 0;
  const trap = () => { calls++; throw Error('must_not_run'); };
  const nested = withFinding();
  part(nested, 'runtime.oracle.sql').findings[0] = new Proxy(finding('confirmed'), { get: trap, ownKeys: trap });
  const accessor = withFinding(); Object.defineProperty(accessor, 'runtime', { get: trap });
  const wrapped = Object.assign(new class RuntimeReportClass {}, withFinding());
  for (const raw of [nested, accessor, wrapped]) {
    const projects = [sanitiseCommonReport, toCommonAgentReport, toCommonReportSummary,
      toCommonSarif, toCommonMarkdown];
    for (const project of projects) {
      assert.throws(() => project(raw));
    }
  }
  assert.equal(calls, 0);
});

test('historical Scan names retain baseline whole Proxy, class and nested Proxy behavior', async () => {
  const base: ScanReport = JSON.parse(await readFile('tests/fixtures/compat-0.5/findings/reports/report.json', 'utf8'));
  const top = await mkdtemp(join(tmpdir(), 'wakeio-report-public-'));
  try {
    for (const variant of ['whole', 'class', 'nested']) {
      let calls = 0;
      const unexpected = () => { throw Error('new_shape_inspection'); };
      const instrument = (data: ScanReport | ScanReport['checks'][number]['findings'][number]) => new Proxy(data, {
        get(target, key, receiver) { calls++; return Reflect.get(target, key, receiver); },
        ownKeys: unexpected, getOwnPropertyDescriptor: unexpected, getPrototypeOf: unexpected, has: unexpected,
      });
      let raw = clone(base);
      if (variant === 'whole') raw = instrument(raw) as ScanReport;
      if (variant === 'class') raw = Object.assign(new class LegacyReport {}, raw);
      if (variant === 'nested') {
        const row = raw.checks.find(item => item.findings.length > 0)!;
        row.findings[0] = instrument(row.findings[0]) as typeof row.findings[number];
      }
      const safe = sanitiseScanReport(variant === 'whole' ? base : raw);
      const projects = [sanitiseReport, toAgentReport, toReportSummary, toMarkdown, toSarif];
      for (const project of projects) {
        calls = 0; assert.deepEqual(project(raw), project(safe));
        // Baseline672 source with current compiled dependencies: each public function reads the wrapper eight times.
        assert.equal(calls, variant === 'whole' ? 8 : 0);
      }
      const out = join(top, variant); calls = 0; await writeReports(raw, out);
      assert.equal(calls, variant === 'whole' ? 8 : 0);
      assert.deepEqual(JSON.parse(await readFile(join(out, 'report.json'), 'utf8')), safe);
      assert.deepEqual(JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8')), toAgentReport(safe));
      assert.deepEqual(JSON.parse(await readFile(join(out, 'report.sarif'), 'utf8')), toSarif(safe));
      assert.equal(await readFile(join(out, 'report.md'), 'utf8'), toMarkdown(safe));
    }
    let calls = 0;
    const trap = () => { calls++; throw Error('must_not_run'); };
    const common = [sanitiseCommonReport, toCommonAgentReport, toCommonReportSummary, toCommonSarif,
      toCommonMarkdown, parseRuntimeReport, sanitiseRuntimeReport, parseReport];
    for (const target of [base, withFinding()]) {
      const opaque = new Proxy(target, { get: trap, ownKeys: trap, getOwnPropertyDescriptor: trap });
      for (const project of common) assert.throws(() => project(opaque as never));
      await assert.rejects(writeCommonReports(opaque as RuntimeReport, join(top, 'rejected'), { sourceRoot: top }));
    }
    assert.equal(calls, 0); await assert.rejects(lstat(join(top, 'rejected')), { code: 'ENOENT' });
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('runtime SARIF execution completion is independent of finding-only and finding-plus-incomplete gates', () => {
  const findingOnly = withFinding(), incompleteOnly = fixture(), findingPartial = withFinding();
  const coverage = part(incompleteOnly, 'runtime.coverage');
  coverage.status = 'partial'; coverage.runtime.reasons = ['contract_incomplete']; incomplete(incompleteOnly);
  const partial = part(findingPartial, 'runtime.coverage');
  partial.status = 'partial'; partial.runtime.reasons = ['contract_incomplete'];
  const cleanupFailure = withFinding(); cleanupFailure.runtime.cleanup.status = 'error';
  cleanupFailure.runtime.cleanup.processGroupExitConfirmed = false;
  cleanupFailure.runtime.cleanup.reasons = ['cleanup_unknown'];
  const cases: Array<[RuntimeReport, boolean, 0 | 1 | 2]> = [[fixture(), true, 0], [findingOnly, true, 1],
    [incompleteOnly, false, 2], [findingPartial, false, 1], [cleanupFailure, false, 1]];
  for (const [report, complete, exit] of cases) {
    assert.equal(toCommonSarif(report).runs[0].invocations[0].executionSuccessful, complete);
    assert.equal(toCommonReportSummary(report).verifyGate.exitCode, exit);
  }
});
