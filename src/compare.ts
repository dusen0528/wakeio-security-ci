import { sanitiseAnalysisBudget, sameAnalysisBudget } from './source/analysis-budget.js';
import { sanitiseCollectionBudget, sanitiseCollectionEvidence, sameCollectionBudget } from './source/collection-budget.js';
import { sanitiseSourceSnapshotEvidence } from './source/snapshot-evidence.js';
import { parseApiWriteStateEvidence } from './api-write-observer.js';
import { types as utilTypes } from 'node:util';
import { sanitiseStaticContext } from './static-context.js';
import { sanitizeDastExecution, isDastObservedEvidence, isLegacyDastExecution } from './dast-execution.js';
import type { Finding, ScanProvenance, ScanReport, Severity } from './contracts.js';
import { exitCode, sanitiseReport, writeArtifacts } from './report.js';
import { readJsonInput } from './json-input.js';

export type ComparisonState = 'new' | 'changed' | 'unchanged' | 'not_observed' | 'unverified';
export interface ComparisonEntry {
  state: ComparisonState;
  checkId: string;
  finding: Finding;
  previousSeverity?: Severity;
}
export interface ReportComparison {
  schemaVersion: '1.0.0';
  comparable: boolean;
  reasons: string[];
  summary: Record<ComparisonState, number>;
  entries: ComparisonEntry[];
  limitations: string[];
}

const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const record = (x: unknown): x is Record<string, any> => !!x && typeof x === 'object' && !Array.isArray(x);
const text = (x: unknown): x is string => typeof x === 'string';

/** Validate before sanitising: malformed external data must not become an empty clean report. */
export function parseScanReport(input: unknown): ScanReport {
  const invalid = () => { throw new Error('Invalid scan report'); };
  if (!record(input)) return invalid();
  if (input.schemaVersion !== '1.0.0' || !text(input.toolVersion) || !input.toolVersion
    || !['source', 'url', 'both', 'api', 'combined'].includes(input.mode)
    || !text(input.startedAt) || !Number.isFinite(Date.parse(input.startedAt))
    || !text(input.finishedAt) || !Number.isFinite(Date.parse(input.finishedAt))
    || !Array.isArray(input.checks) || input.checks.length > 1000) return invalid();
  const checkIds = new Set<string>();
  let count = 0;
  for (const check of input.checks) {
    if (!record(check) || !text(check.id) || !check.id || checkIds.has(check.id)
      || !['completed', 'partial', 'error', 'skipped', 'not_applicable'].includes(check.status)
      || !Array.isArray(check.findings) || !Array.isArray(check.notes) || !check.notes.every(text)) return invalid();
    if (check.analysisBudget !== undefined && !sanitiseAnalysisBudget(check.analysisBudget)) return invalid();
    const collectionBudget = collectionField(check, 'collectionBudget');
    const collectionEvidence = collectionField(check, 'collectionEvidence');
    const snapshotField = collectionField(check, 'sourceSnapshot');
    const sourceSnapshot = snapshotField.present ? sanitiseSourceSnapshotEvidence(snapshotField.value) : undefined;
    const snapshotBudget = sanitiseCollectionBudget(collectionBudget.value);
    if (!snapshotField.valid || snapshotField.present && (!sourceSnapshot || check.id !== 'source.inventory' || !snapshotBudget
      || sourceSnapshot.filesSelected > snapshotBudget.limits.maxFiles || sourceSnapshot.bytesSelected > snapshotBudget.limits.maxBytes
      || check.metrics?.filesSelected !== sourceSnapshot.filesSelected || check.metrics?.bytesSelected !== sourceSnapshot.bytesSelected
      || !sourceSnapshot.complete && ['completed', 'not_applicable'].includes(check.status))) return invalid();
    if (!collectionBudget.valid || !collectionEvidence.valid
      || (collectionBudget.present && !sanitiseCollectionBudget(collectionBudget.value))
      || (collectionEvidence.present && !sanitiseCollectionEvidence(collectionEvidence.value))
      || ((collectionBudget.present || collectionEvidence.present) && check.id !== 'source.inventory')) return invalid();
    const evidence = collectionEvidence.present ? sanitiseCollectionEvidence(collectionEvidence.value) : undefined;
    if (evidence?.issues.some(issue => issue.code === 'root_error') && check.status !== 'error'
      || evidence?.issues.some(issue => issue.code !== 'unsupported_file') && ['completed', 'not_applicable'].includes(check.status)) return invalid();
    const nativeField = collectionField(check, 'dastExecution');
    // Keep historical v1 normalization readable; newer evidence must be valid
    // before sanitation can preserve a candidate or a completed result.
    const nativeVersion = nativeField.valid && nativeField.value && typeof nativeField.value === 'object'
      && !utilTypes.isProxy(nativeField.value) ? Object.getOwnPropertyDescriptor(nativeField.value, 'version') : undefined;
    const nativeV1 = nativeVersion && 'value' in nativeVersion && nativeVersion.value === 1;
    if (nativeField.present && !nativeField.valid) return invalid();
    let nativeExecution: ReturnType<typeof sanitizeDastExecution> = null;
    if (nativeField.present && !nativeV1) {
      const execution = sanitizeDastExecution(nativeField.value);
      if (!execution || isLegacyDastExecution(execution) || check.id !== 'url.sql-boolean' || check.metrics?.requestCount !== execution.counts.httpAttempts
        || execution.status !== 'complete' && ['completed', 'not_applicable'].includes(check.status)
        || isDastObservedEvidence(execution) && check.findings.length !== 1 && ['completed', 'not_applicable'].includes(check.status)
        || check.findings.length > 0 && !isDastObservedEvidence(execution)) return invalid();
      nativeExecution = execution;
    }
    checkIds.add(check.id);
    const writeEvidence = collectionField(check, 'apiWriteStateEvidence');
    if (writeEvidence.present && (!writeEvidence.valid || check.id !== 'api.owned-write-state-oracle'
      || !parseApiWriteStateEvidence(writeEvidence.value))) return invalid();
    count += check.findings.length;
    if (count > 50_000 || (check.status === 'not_applicable' && check.findings.length)) return invalid();
    for (const finding of check.findings) {
      if (finding && typeof finding === 'object' && utilTypes.isProxy(finding)) return invalid();
      if (!record(finding) || !text(finding.ruleId) || !finding.ruleId || !text(finding.title)
        || !text(finding.description) || !text(finding.remediation) || !severities.includes(finding.severity)
        || !['low', 'medium', 'high'].includes(finding.confidence)
        || !['observation', 'candidate', 'advisory'].includes(finding.kind) || !record(finding.location)) return invalid();
      if (nativeExecution && !isLegacyDastExecution(nativeExecution) && (finding.kind !== 'candidate' || finding.confidence === 'high'
        || (nativeExecution.status !== 'complete' || check.status !== 'completed') && finding.confidence !== 'low')) return invalid();
      const context = collectionField(finding, 'staticContext');
      if (!context.valid || context.present && (!sanitiseStaticContext(context.value)
        || finding.confidence !== 'low' || finding.kind !== 'candidate'
        || ['completed', 'not_applicable'].includes(check.status)
        || finding.staticFlow !== undefined && finding.staticFlow.truncated !== true)) return invalid();
      if (finding.comparisonKey !== undefined
        && (!text(finding.comparisonKey) || !/^[a-f0-9]{64}$/.test(finding.comparisonKey))) return invalid();
      if (finding.staticFlow?.sourceKind !== undefined && finding.staticFlow.sourceKind !== 'filesystem_filename') return invalid();
      for (const key of ['path', 'url']) if (finding.location[key] !== undefined && !text(finding.location[key])) return invalid();
      for (const key of ['line', 'column']) if (finding.location[key] !== undefined
        && (!Number.isSafeInteger(finding.location[key]) || finding.location[key] < 1)) return invalid();
    }
  }
  if (input.scope !== undefined && !validScope(input.scope)) return invalid();
  const safe = sanitiseReport(input as ScanReport);
  if (new Set(safe.checks.map((check) => check.id)).size !== safe.checks.length) return invalid();
  return safe;
}

export async function readScanReport(path: string): Promise<ScanReport> {
  return parseScanReport(await readJsonInput(path));
}

interface IndexedFinding {
  checkId: string;
  finding: Finding;
  matchKey: string;
}

interface FindingIndex {
  findings: Map<string, IndexedFinding>;
  ambiguous: Set<string>;
}

function indexed(report: ScanReport): FindingIndex {
  const occurrences = new Map<string, number>();
  const output = new Map<string, IndexedFinding>();
  const anchoredOccurrences = new Map<string, number>();
  const ambiguous = new Set<string>();
  for (const check of report.checks) for (const finding of check.findings) {
    if (finding.comparisonKey) {
      // A key is only meaningful within the check that emitted it. Keeping
      // the check in the index avoids merging two detectors that happen to
      // choose the same semantic anchor.
      const key = `semantic:${check.id}:${finding.comparisonKey}`;
      const count = anchoredOccurrences.get(key) ?? 0;
      anchoredOccurrences.set(key, count + 1);
      if (count > 0) ambiguous.add(key);
      output.set(`${key}:${count}`, { checkId: check.id, finding, matchKey: key });
      continue;
    }
    const key = `legacy:${check.id}:${finding.id!}`;
    const count = occurrences.get(key) ?? 0;
    occurrences.set(key, count + 1);
    output.set(`${key}:${count}`, { checkId: check.id, finding, matchKey: key });
  }
  return { findings: output, ambiguous };
}

export function compareReports(beforeInput: ScanReport, afterInput: ScanReport): ReportComparison {
  const before = parseScanReport(beforeInput);
  const after = parseScanReport(afterInput);
  const reasons: string[] = [];
  for (const id of new Set([...before.checks, ...after.checks].map(check => check.id))) {
    const oldWrite = before.checks.find(check => check.id === id)?.apiWriteStateEvidence;
    const newWrite = after.checks.find(check => check.id === id)?.apiWriteStateEvidence;
    if ((oldWrite || newWrite) && JSON.stringify(oldWrite) !== JSON.stringify(newWrite)) reasons.push('Owned write evidence, execution plan or persisted-state scope changed or is missing; independent observer comparison is required.');
  }
  if (!before.scope || !after.scope) reasons.push('Declared scan scope is missing; older reports cannot establish comparable scope.');
  else {
    if (before.scope.projectId !== after.scope.projectId) {
      reasons.push('Logical project identity changed or is missing from one report.');
    }
    if (before.scope.fingerprint !== after.scope.fingerprint || before.scope.ruleset !== after.scope.ruleset) {
      reasons.push('Declared target, options, or ruleset changed.');
    }
    compareProvenance(before.scope.provenance, after.scope.provenance, reasons);
  }
  if (before.scope && after.scope && !before.scope.provenance && !after.scope.provenance
    && (externalCheckNeedsProvenance(before) || externalCheckNeedsProvenance(after))) {
    reasons.push('External scanner checks are present but engine and data-source provenance is missing.');
  }
  requireExternalProvenance(before, 'Before', reasons);
  requireExternalProvenance(after, 'After', reasons);
  if (before.mode !== after.mode || before.toolVersion !== after.toolVersion) reasons.push('Scan mode or Wakeio tool version changed.');
  const beforeChecks = before.checks.map((check) => check.id).sort();
  const afterChecks = after.checks.map((check) => check.id).sort();
  if (JSON.stringify(beforeChecks) !== JSON.stringify(afterChecks)) reasons.push('The set of executed checks changed.');
  if (exitCode(before, 'none') === 2 || exitCode(after, 'none') === 2) reasons.push('At least one scan is incomplete or has no applicable checks.');
  for (const check of before.checks) {
    if (after.checks.find((next) => next.id === check.id)?.status !== check.status) {
      reasons.push('Check applicability or completion changed.');
      break;
    }
  }
  for (const [report, label] of [[before, 'Before'], [after, 'After']] as const) {
    const ast = report.checks.find(check => check.id === 'source.builtin-ast' && check.status !== 'not_applicable');
    if (ast && !sameAnalysisBudget(report.scope?.analysisBudget, ast.analysisBudget)) reasons.push(`${label} AST analysis budget identity is missing or inconsistent.`);
  }
  if ((before.checks.some(c => c.id === 'source.builtin-ast' && c.status !== 'not_applicable') || after.checks.some(c => c.id === 'source.builtin-ast' && c.status !== 'not_applicable'))
    && !sameAnalysisBudget(before.scope?.analysisBudget, after.scope?.analysisBudget)) reasons.push('AST analysis budget changed or is unknown.');
  compareCollection(before, after, reasons);
  for (const check of before.checks) {
    const previous = check.apiExecution;
    const next = after.checks.find(candidate => candidate.id === check.id)?.apiExecution;
    if (!previous && !next) continue;
    if (!previous || !next || previous.status !== 'complete' || next.status !== 'complete'
      || previous.policyVersion !== next.policyVersion || previous.planSha256 !== next.planSha256) {
      reasons.push('Declared API execution plan is missing, incomplete, or changed.');
    }
  }
  for (const check of before.checks) {
    const previous = check.dastExecution;
    const next = after.checks.find(candidate => candidate.id === check.id)?.dastExecution;
    if (!previous && !next) continue;
    if (!previous || !next || previous.status !== 'complete' || next.status !== 'complete'
      || previous.version !== next.version || previous.plannedRequests !== next.plannedRequests
      || previous.policySha256 !== next.policySha256 || previous.profile !== next.profile
      || previous.profileRevision !== next.profileRevision || previous.maxRequests !== next.maxRequests
      || previous.timeoutMs !== next.timeoutMs || previous.allowPrivate !== next.allowPrivate) {
      reasons.push('Native DAST policy or execution is missing, incomplete, or changed.');
    }
  }
  const oldIndex = indexed(before);
  const currentIndex = indexed(after);
  for (const id of new Set([...oldIndex.findings.keys(), ...currentIndex.findings.keys()])) {
    const previous = oldIndex.findings.get(id)?.finding.staticContext;
    const next = currentIndex.findings.get(id)?.finding.staticContext;
    const previousOrigin = oldIndex.findings.get(id)?.finding.staticFlow?.sourceKind;
    const nextOrigin = currentIndex.findings.get(id)?.finding.staticFlow?.sourceKind;
    if ((previousOrigin || nextOrigin) && previousOrigin !== nextOrigin) {
      reasons.push('Static filename source origin changed or is missing; this cannot establish disappearance or a fix.');
      break;
    }
    if ((previous || next) && JSON.stringify(previous) !== JSON.stringify(next)) {
      reasons.push('Conditional static context changed or is missing from a corresponding finding; body hypotheses cannot establish disappearance or a fix.');
      break;
    }
  }
  if (oldIndex.ambiguous.size > 0 || currentIndex.ambiguous.size > 0) {
    reasons.push('A semantic comparison key occurs more than once in a check; matching is ambiguous.');
  }
  const comparable = reasons.length === 0;
  const old = oldIndex.findings;
  const current = currentIndex.findings;
  const entries: ComparisonEntry[] = [];
  for (const [id, item] of current) {
    const ambiguous = oldIndex.ambiguous.has(item.matchKey) || currentIndex.ambiguous.has(item.matchKey);
    const previous = ambiguous ? undefined : old.get(id);
    const changed = previous && (previous.finding.severity !== item.finding.severity || previous.finding.confidence !== item.finding.confidence);
    entries.push({ checkId: item.checkId, finding: item.finding, state: !comparable ? 'unverified' : !previous ? 'new' : changed ? 'changed' : 'unchanged',
      ...(previous && changed ? { previousSeverity: previous.finding.severity } : {}) });
    if (previous) old.delete(id);
  }
  for (const item of old.values()) entries.push({ checkId: item.checkId, finding: item.finding, state: comparable ? 'not_observed' : 'unverified' });
  const summary: ReportComparison['summary'] = { new: 0, changed: 0, unchanged: 0, not_observed: 0, unverified: 0 };
  for (const entry of entries) summary[entry.state]++;
  return { schemaVersion: '1.0.0', comparable, reasons, summary, entries, limitations: [
    'Comparable means the declared target/options, logical project identity, Wakeio version/ruleset, completed check set, and known engine/data provenance match. It is not proof that an unknown advisory database or rule bundle stayed identical.',
    'Not observed means that finding is absent from the later report. Code deletion, line movement, changed data, or detector limitations may explain it; it is not proof of a security fix.',
    'Semantic comparison keys can survive line movement. Findings without a key retain location-based IDs, so moving them appears as new plus not observed. Duplicate semantic keys are left unverified instead of being matched arbitrarily.',
    'Source content hashes are provenance evidence and do not establish scope identity. Unknown scanner databases or rule bundles make the comparison unverified.',
    'Source inventory comparisons require known matching effective collection budgets and recorded exclusion reasons independently of the supplied scope fingerprint. Changed or unknown collection selection remains unverified.',
    'Comparisons do not suppress findings in the scan reports and do not certify the whole service.',
  ] };
}

function validScope(scope: unknown): boolean {
  if (!record(scope) || !/^[a-f0-9]{64}$/.test(scope.fingerprint)
    || !/^[A-Za-z0-9._-]{1,80}$/.test(scope.ruleset)) return false;
  if (scope.projectId !== undefined
    && (typeof scope.projectId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(scope.projectId))) return false;
  if (scope.analysisBudget !== undefined && !sanitiseAnalysisBudget(scope.analysisBudget)) return false;
  const budget = collectionField(scope, 'collectionBudget');
  if (!budget.valid || budget.present && !sanitiseCollectionBudget(budget.value)) return false;
  const provenance = scope.provenance;
  if (provenance === undefined) return true;
  if (!record(provenance)) return false;
  if (provenance.sourceContentHash !== undefined
    && (typeof provenance.sourceContentHash !== 'string' || !/^[a-f0-9]{64}$/.test(provenance.sourceContentHash))) return false;
  if (provenance.engines !== undefined) {
    if (!Array.isArray(provenance.engines) || provenance.engines.length > 16) return false;
    const engineNames = new Set<string>();
    for (const engine of provenance.engines) {
      if (!record(engine) || typeof engine.name !== 'string' || !/^[A-Za-z0-9._:-]{1,80}$/.test(engine.name)
        || !['available', 'missing', 'unreadable', 'unknown'].includes(engine.status as string)) return false;
      if (engineNames.has(engine.name)) return false;
      engineNames.add(engine.name);
      if (engine.sha256 !== undefined && (typeof engine.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(engine.sha256))) return false;
      if (engine.status === 'available' && engine.sha256 === undefined) return false;
    }
  }
  if (provenance.dataSources !== undefined) {
    if (!record(provenance.dataSources) || Object.keys(provenance.dataSources).length > 16) return false;
    for (const [name, value] of Object.entries(provenance.dataSources)) {
      if (!safeMetadataKey(name) || typeof value !== 'string' || value.length > 160) return false;
    }
  }
  return true;
}

function collectionField(input: object, key: string): { present: boolean; valid: boolean; value?: unknown } {
  if (utilTypes.isProxy(input)) return { present: true, valid: false };
  const descriptor = Object.getOwnPropertyDescriptor(input, key);
  return descriptor ? { present: true, valid: 'value' in descriptor, ...('value' in descriptor ? { value: descriptor.value } : {}) } : { present: false, valid: true };
}

function compareCollection(before: ScanReport, after: ScanReport, reasons: string[]): void {
  const previous = before.checks.find(check => check.id === 'source.inventory');
  const next = after.checks.find(check => check.id === 'source.inventory');
  if (!previous && !next && !before.scope?.collectionBudget && !after.scope?.collectionBudget) return;
  for (const [report, inventory, label] of [[before, previous, 'Before'], [after, next, 'After']] as const) {
    if (!inventory || inventory.status === 'not_applicable'
      || !sameCollectionBudget(report.scope?.collectionBudget, inventory.collectionBudget)
      || !inventory.collectionEvidence) reasons.push(`${label} source collection identity or diagnostics are missing or inconsistent.`);
  }
  if (!sameCollectionBudget(previous?.collectionBudget, next?.collectionBudget)
    || !sameCollectionBudget(before.scope?.collectionBudget, after.scope?.collectionBudget)) reasons.push('Effective source collection budget changed or is unknown.');
  if (!previous?.collectionEvidence || !next?.collectionEvidence
    || JSON.stringify(previous.collectionEvidence) !== JSON.stringify(next.collectionEvidence)) reasons.push('Recorded source collection exclusions changed or are unknown.');
}

function safeMetadataKey(value: string): boolean {
  return /^[A-Za-z0-9._:-]{1,80}$/.test(value)
    && value !== '__proto__' && value !== 'constructor' && value !== 'prototype';
}

function externalCheckNeedsProvenance(report: ScanReport): boolean {
  return report.checks.some((check) =>
    ['source.gitleaks', 'source.osv', 'source.trivy', 'source.bandit'].includes(check.id)
      && check.status !== 'not_applicable',
  );
}

/**
 * A provenance object containing only a source hash (or unrelated engines) is
 * not evidence that a completed external check used the expected scanner.
 * Keep this requirement tied to the checks actually present in the report so
 * a deliberately not-applicable external check remains compatible.
 */
function requireExternalProvenance(report: ScanReport, label: string, reasons: string[]): void {
  const provenance = report.scope?.provenance;
  if (!provenance) return;
  const engines = new Map((provenance.engines ?? []).map((engine) => [engine.name, engine]));
  const dataSources = provenance.dataSources ?? {};
  const requirements: Record<string, { sourceNames?: string[] }> = {
    'source.gitleaks': {},
    'source.osv': { sourceNames: ['osvDatabase'] },
    'source.trivy': { sourceNames: ['trivyDatabase', 'trivyChecksBundle'] },
    'source.bandit': { sourceNames: ['banditRuntime'] },
  };
  for (const check of report.checks) {
    if (check.status === 'not_applicable') continue;
    const requirement = requirements[check.id];
    if (!requirement) continue;
    const engine = engines.get(check.id.slice('source.'.length));
    if (!engine || engine.status !== 'available' || !/^[a-f0-9]{64}$/.test(engine.sha256 ?? '')) {
      reasons.push(`${label} ${check.id} lacks available engine SHA-256 provenance.`);
    }
    for (const sourceName of requirement.sourceNames ?? []) {
      const value = dataSources[sourceName];
      if (typeof value !== 'string' || value.length === 0) {
        reasons.push(`${label} ${check.id} lacks ${sourceName} provenance.`);
      } else if (/unknown/i.test(value)) {
        reasons.push(`${label} ${check.id} has unknown ${sourceName} provenance.`);
      }
    }
  }
}

function compareProvenance(
  before: ScanProvenance | undefined,
  after: ScanProvenance | undefined,
  reasons: string[],
): void {
  if (!before && !after) return;
  if (!before || !after) {
    reasons.push('Engine or data-source provenance is missing from one report.');
    return;
  }
  const beforeEngines = JSON.stringify(before.engines ?? []);
  const afterEngines = JSON.stringify(after.engines ?? []);
  if (beforeEngines !== afterEngines) reasons.push('External engine provenance changed.');
  const incompleteEngine = [...(before.engines ?? []), ...(after.engines ?? [])]
    .some((engine) => engine.status !== 'available' || !engine.sha256);
  if (incompleteEngine) reasons.push('External engine provenance is incomplete; missing, unreadable, or unknown engines cannot establish a comparable run.');
  const beforeSources = before.dataSources ?? {};
  const afterSources = after.dataSources ?? {};
  const unknown = [...Object.entries(beforeSources), ...Object.entries(afterSources)]
    .some(([, value]) => /unknown/i.test(value));
  if (unknown) reasons.push('Advisory database or rule-bundle provenance is unknown; the reports cannot claim identical external data.');
  if (!unknown && JSON.stringify(beforeSources) !== JSON.stringify(afterSources)) reasons.push('External data-source provenance changed.');
}

export function comparisonExitCode(result: ReportComparison, failOn: Severity | 'none'): 0 | 1 | 2 {
  if (!result.comparable) return 2;
  if (failOn === 'none') return 0;
  const threshold = severities.indexOf(failOn);
  if (threshold < 0) return 2;
  return result.entries.some((entry) => ['new', 'changed'].includes(entry.state) && severities.indexOf(entry.finding.severity) >= threshold) ? 1 : 0;
}

export async function writeComparison(result: ReportComparison, outDir: string): Promise<void> {
  const escape = (value: string) => value.replace(/[\r\n\t]+/g, ' ').replace(/[\\`*_[\]{}()<>#+.!|\-]/g, '\\$&');
  const lines = ['# Wakeio report comparison', '', `Comparable declared scope: ${result.comparable}`, '',
    ...result.reasons.map((reason) => `- ${reason}`), '', '## Counts', '',
    ...Object.entries(result.summary).map(([state, count]) => `- ${state}: ${count}`), '', '## Findings', '',
    ...result.entries.map((entry) => `- **${entry.state}** [${entry.finding.severity}] ${escape(entry.finding.title)} (${entry.finding.id})`),
    '', '## Limits', '', ...result.limitations.map((limit) => `- ${limit}`), ''];
  await writeArtifacts(outDir, [['comparison.json', JSON.stringify(result, null, 2) + '\n'], ['comparison.md', lines.join('\n')]]);
}
