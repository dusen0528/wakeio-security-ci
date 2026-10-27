import { Ajv2020 } from 'ajv/dist/2020.js';
import schema from '../schemas/verify-artifact.v1.json' with { type: 'json' };
import { snapshotJsonData } from './json-snapshot.js';
import { redactSecrets, safeHttpUrl, safeRelativePath } from './report-path.js';
import { sanitiseStaticContext } from './static-context.js';
import type { RuntimeReport } from './contracts.js';
import type { RuntimeCheck, RuntimeCheckId, RuntimeFinding, SurfaceRef } from './runtime/types.js';

type Check<K extends RuntimeCheckId> = Extract<RuntimeCheck, { id: K }>;
const SHA = /^[a-f0-9]{64}$/, IMAGE = /^sha256:[a-f0-9]{64}$/;
const MARKER = /\bwk[a-z0-9]{12}\b/gi; // PLAN 6's wire marker, never an SQL classifier.
function invalid(): never { throw new TypeError('invalid_runtime_report'); }
function requireData(ok: unknown): asserts ok { if (!ok) invalid(); }
const ajv = new Ajv2020({ strict: true, allErrors: false, $data: false, coerceTypes: false,
  useDefaults: false, removeAdditional: false, ownProperties: true, validateSchema: true, logger: false });
const validate = ajv.compile<RuntimeReport>(schema);
const omitted = '[runtime text omitted]';
const prose = new Set(['title', 'description', 'remediation', 'notes']);
function publicIdentity(value: string): boolean {
  MARKER.lastIndex = 0;
  return !/[\x00-\x1f\x7f]/.test(value) && redactSecrets(value) === value && !MARKER.test(value);
}
function token(value: string, empty = false): void {
  requireData((empty || value.length > 0) && value.length <= 120 && publicIdentity(value)
    && /^[A-Za-z0-9_.:/@+$<>*-]*$/.test(value));
}
function path(value: string): void {
  requireData(publicIdentity(value) && safeRelativePath(value) === value);
}
/** Free prose has no bounded privacy contract: omit it instead of guessing which text is SQL or a response. */
function publicData(value: unknown, key = '', owner?: Record<string, unknown>): unknown {
  if (typeof value === 'string') {
    if (prose.has(key)) return value ? omitted : '';
    if (key === 'url' || key === 'references') {
      const url = safeHttpUrl(redactSecrets(value).replace(MARKER, 'redacted-marker'));
      requireData(url); return url;
    }
    if (key === 'path') path(value);
    else if (key === 'pathTemplate') requireData(publicIdentity(value));
    else if (key === 'surfaceId') requireData(value.length > 0 && value.length <= 120 && publicIdentity(value)
      && (/^[A-Za-z0-9_.:-]+$/.test(value) || /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]* \//.test(value)));
    else if (key === 'locator') requireData(publicIdentity(value) && /^#(?:\/|$)/.test(value));
    else if (key === 'id' && owner && 'method' in owner) {
      requireData(value.length <= 120 && publicIdentity(value)
        && (/^[A-Za-z0-9_.:-]+$/.test(value) || value === `${owner.method} ${owner.pathTemplate}`));
    } else token(value, true);
    return value;
  }
  if (Array.isArray(value)) return value.map(child => publicData(child, key, owner));
  if (value && typeof value === 'object') {
    const row = value as Record<string, unknown>;
    for (const [name, child] of Object.entries(row)) row[name] = publicData(child, name, row);
  }
  return value;
}
function unique(values: readonly (string | number)[]): void { requireData(new Set(values).size === values.length); }
function check<K extends RuntimeCheckId>(report: RuntimeReport, id: K): Check<K> {
  return report.checks.find(row => row.id === id) as Check<K>;
}
function surfaceKey(surface: SurfaceRef): string {
  requireData(surface.method === surface.method.toUpperCase());
  return JSON.stringify([surface.method, surface.pathTemplate]);
}
function references(value: unknown, known = new Map<string, string>()): void {
  if (!value || typeof value !== 'object') return;
  const row = value as Record<string, unknown>;
  if (!Array.isArray(value) && 'path' in row && 'bytes' in row && 'sha256' in row) {
    const identity = JSON.stringify([row.bytes, row.sha256]), name = row.path as string;
    requireData(!known.has(name) || known.get(name) === identity); known.set(name, identity);
  }
  for (const child of Object.values(value)) references(child, known);
}
function build(row: Check<'runtime.build'>): void {
  const data = row.runtime, isolation = data.isolation;
  if (data.builder !== null) token(data.builder);
  if (data.imageDigest !== null) requireData(IMAGE.test(data.imageDigest));
  if (data.cacheKey !== null) requireData(SHA.test(data.cacheKey));
  if (isolation) {
    if (!isolation.verified) requireData(isolation.gaps.length > 0);
    else {
      const cgroup = isolation.cgroup, resources = isolation.resources, measured = resources.measured;
      requireData(isolation.applied === isolation.requested && isolation.daemonRootless
        && isolation.targetUid !== null && isolation.targetUid > 0 && isolation.capDropAll && isolation.readOnlyRootfs
        && isolation.seccomp && isolation.backend && isolation.daemonVersion && isolation.runtimeVersion
        && cgroup.version === 2 && cgroup.driver === 'systemd' && cgroup.systemd && cgroup.delegatedUnit
        && ['cpu', 'memory', 'pids'].every(name => cgroup.controllers.includes(name))
        && resources.enforced && measured.cpuQuota !== null && measured.cpuQuota > 0
        && measured.memoryMax === resources.requested.memoryBytes && measured.pidsMax === resources.requested.pids
        && isolation.gaps.length === 0);
    }
  }
  if (row.status === 'completed') requireData(data.builder && data.imageDigest && data.cacheKey
    && data.durationMs !== null && isolation?.verified);
}
function surfaces(row: Check<'runtime.surface'>): Map<string, SurfaceRef> {
  const data = row.runtime;
  unique(data.routes.map(route => route.surface.id)); unique(data.routes.map(route => surfaceKey(route.surface)));
  requireData(data.enumerated === data.routes.length && (data.declared === null || data.declared >= data.enumerated));
  for (const route of data.routes) requireData(route.provenance.length > 0);
  if (row.status === 'completed') requireData(data.routes.length > 0 && data.declared === data.enumerated
    && data.routes.every(route => route.attacked !== null));
  return new Map(data.routes.map(route => [route.surface.id, route.surface]));
}
function coverageRoute(route: Check<'runtime.coverage'>['runtime']['routes'][number]): void {
  if (route.files === null) {
    requireData(route.accounting === 'unknown' && route.coveredFiles === null && route.coveredLines === null
      && route.executableLines === null && route.ratio === null); return;
  }
  unique(route.files.map(file => file.path));
  let covered = 0, executable = 0, reachedFiles = 0;
  for (const file of route.files) {
    const lines = new Set(file.executableLines);
    requireData(file.coveredLines.every(line => lines.has(line)));
    covered += file.coveredLines.length; executable += lines.size;
    if (file.coveredLines.length) reachedFiles++;
  }
  for (const [recorded, actual] of [[route.coveredFiles, reachedFiles], [route.coveredLines, covered],
    [route.executableLines, executable]]) if (recorded !== null) requireData(recorded === actual);
  if (route.accounting === 'exact') requireData(route.coveredFiles !== null && route.coveredLines !== null
    && route.executableLines !== null && route.ratio === (executable ? covered / executable : null)
    && (executable > 0 || route.reasons.length > 0));
}
function coverage(row: Check<'runtime.coverage'>, routes: Map<string, SurfaceRef>): void {
  unique(row.runtime.routes.map(route => route.surface.id));
  const files = new Map<string, string>();
  for (const route of row.runtime.routes) {
    requireData(routes.has(route.surface.id)
      && surfaceKey(routes.get(route.surface.id)!) === surfaceKey(route.surface));
    coverageRoute(route);
    for (const file of route.files ?? []) {
      requireData(!files.has(file.path) || files.get(file.path) === file.sha256); files.set(file.path, file.sha256);
    }
  }
  if (row.status === 'completed') requireData(row.runtime.routes.length > 0
    && row.runtime.routes.length === routes.size && row.runtime.dumpRefs.length > 0
    && row.runtime.routes.every(route => route.accounting === 'exact' && route.files !== null));
}
function finding(row: RuntimeFinding): void {
  requireData(typeof row.id === 'string'); token(row.id);
  token(row.ruleId); token(row.evidence.controlPairId); token(row.evidence.oracleRevision);
  if (row.comparisonKey !== undefined) requireData(SHA.test(row.comparisonKey));
  const evidence = row.evidence;
  unique(evidence.markers); requireData(evidence.markers.length > 0 && evidence.refs.length > 0);
  if (evidence.grade === 'confirmed' || evidence.grade === 'strong') requireData(evidence.markers.length >= 2);
  if (evidence.reach === 'triggered') requireData(evidence.grade === 'confirmed');
  if (evidence.grade === 'confirmed') requireData(evidence.reach !== 'reached_not_triggered');
  if (row.staticContext) {
    const context = sanitiseStaticContext(row.staticContext);
    requireData(context && row.kind === 'candidate' && row.confidence === 'low'
      && (!row.staticFlow || row.staticFlow.truncated)); row.staticContext = context;
  }
}
function sql(row: Check<'runtime.oracle.sql'>, surface: Check<'runtime.surface'>): void {
  const data = row.runtime, routes = new Map(surface.runtime.routes.map(route => [route.surface.id, route]));
  for (const item of data.cases) {
    requireData(routes.has(item.surfaceId));
    if (item.state !== 'unknown') requireData(routes.get(item.surfaceId)!.attacked === true);
  }
  row.findings.forEach(finding);
  const graded = row.findings.some(item => ['strong', 'confirmed'].includes(item.evidence.grade));
  requireData(data.cases.some(item => item.state === 'triggered') === graded);
  if (row.findings.length) requireData(data.markerLedger && data.parserRevision);
  if (data.parserRevision !== null) token(data.parserRevision);
  if (graded) requireData(data.verdictRefs.length > 0);
  if (row.status === 'completed') requireData(data.cases.length > 0 && data.markerLedger && data.parserRevision
    && data.cases.every(item => item.state !== 'unknown')
    && surface.runtime.routes.filter(route => route.attacked === true)
      .every(route => data.cases.some(item => item.surfaceId === route.surface.id)));
}
function gate(report: RuntimeReport): void {
  const findings = report.checks.flatMap(row => row.findings), gate = report.runtime.verifyGate;
  unique(findings.map(item => item.id!));
  const blocking = findings.filter(item => item.evidence.grade === 'confirmed'
    || gate.failOnGrade === 'strong' && item.evidence.grade === 'strong').map(item => item.id!).sort();
  requireData(JSON.stringify([...gate.blockingFindingIds].sort()) === JSON.stringify(blocking));
  const incomplete = report.checks.some(row => row.status !== 'completed')
    || report.runtime.cleanup.status !== 'confirmed' || report.runtime.scope.gaps.length > 0
    || report.runtime.inputArtifacts.length === 0 || report.runtime.stages.length === 0
    || findings.some(item => item.evidence.reach === 'unknown');
  const code = blocking.length ? 1 : incomplete ? 2 : 0;
  requireData(gate.exitCode === code && gate.outcome === ['pass', 'findings', 'incomplete'][code]);
}
function timestamp(value: string): number {
  requireData(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value));
  const time = Date.parse(value), normalized = value.includes('.') ? value : value.replace('Z', '.000Z');
  requireData(Number.isFinite(time) && new Date(time).toISOString() === normalized); return time;
}
function semantics(report: RuntimeReport): void {
  requireData(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(report.toolVersion));
  requireData(timestamp(report.startedAt) <= timestamp(report.finishedAt));
  references(report);
  for (const row of report.checks) {
    requireData(row.status !== 'not_applicable');
    if (row.id !== 'runtime.oracle.sql') requireData(row.findings.length === 0);
  }
  build(check(report, 'runtime.build'));
  const start = check(report, 'runtime.start');
  if (start.status === 'completed') requireData(start.runtime.health === 'passed'
    && start.runtime.lease && start.runtime.instrumentation && start.runtime.durationMs !== null);
  const surface = check(report, 'runtime.surface'), routes = surfaces(surface);
  coverage(check(report, 'runtime.coverage'), routes); sql(check(report, 'runtime.oracle.sql'), surface);
  const cleanup = report.runtime.cleanup;
  for (const resource of cleanup.resources) { token(resource.kind); token(resource.id); }
  for (const id of cleanup.remainingOwnedIds) token(id);
  unique(cleanup.resources.map(resource => JSON.stringify([resource.kind, resource.id])));
  unique(cleanup.remainingOwnedIds);
  if (cleanup.status === 'confirmed') requireData(cleanup.reasons.length === 0);
  if (start.status === 'completed' && cleanup.status === 'confirmed') requireData(cleanup.resources.length > 0);
  gate(report);
}

/** Self-consistent report data only: no vault/file-chain, provenance authentication or Oracle execution. */
export function parseRuntimeReport(raw: unknown): RuntimeReport {
  const snapshot = snapshotJsonData(raw, invalid, invalid);
  // Ajv uniqueItems needs ordinary JSON objects; snapshot before this copy can invoke no caller code.
  if (!validate(JSON.parse(JSON.stringify(snapshot)))) invalid();
  const report = publicData(snapshot) as RuntimeReport;
  semantics(report);
  return snapshotJsonData(report, invalid, invalid) as RuntimeReport;
}
export function sanitiseRuntimeReport(raw: unknown): RuntimeReport { return parseRuntimeReport(raw); }
