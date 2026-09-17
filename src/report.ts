import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import { dirname, posix, resolve, sep } from 'node:path';
import type {
  CheckResult,
  Finding,
  Mode,
  ScanProvenance,
  ScanReport,
  Severity,
} from './contracts.js';

/** The version of the report shape emitted by this package. */
export const REPORT_SCHEMA_VERSION = '1.0.0' as const;

/** The version advertised to SARIF consumers when the package is built. */
export const REPORT_TOOL_VERSION = '0.4.0-dev.1';
export const RULESET_VERSION = '2026-09-16.2';

const SEVERITIES: readonly Severity[] = [
  'info',
  'low',
  'medium',
  'high',
  'critical',
];

const STATUSES: readonly CheckResult['status'][] = [
  'completed',
  'partial',
  'error',
  'not_applicable',
  'skipped',
];

const KINDS: readonly Finding['kind'][] = [
  'observation',
  'candidate',
  'advisory',
];

const CONFIDENCES: readonly Finding['confidence'][] = [
  'low',
  'medium',
  'high',
];

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const SAFE_TEXT_MAX = 16_384;
const SAFE_ID_MAX = 512;

/**
 * Create a report without retaining source snippets, scanner output, or
 * caller-owned object references. The report is deliberately a small data
 * contract so that it can be written to CI artifacts safely.
 */
export function createReport(
  checks: CheckResult[],
  mode: Mode,
  startedAt: string | Date,
  scope?: ScanReport['scope'],
): ScanReport {
  const start = timestamp(startedAt);
  const finished = new Date().toISOString();

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    toolVersion: REPORT_TOOL_VERSION,
    mode: validMode(mode),
    startedAt: start,
    finishedAt: finished,
    checks: Array.isArray(checks) ? checks.map(sanitiseCheck) : [],
    ...safeScope(scope),
  };
}

/**
 * Write the three public report formats using atomic replacement.
 *
 * The output directory and all of its ancestors are checked with lstat. A
 * symlink is rejected at every level, including an existing report target.
 * This prevents a report path from being redirected outside the requested
 * directory. Temporary files are created in the checked directory and then
 * renamed into place.
 */
export async function writeReports(
  report: ScanReport,
  outDir: string,
): Promise<void> {
  if (typeof outDir !== 'string' || outDir.trim().length === 0) {
    throw new Error('Report output directory must be a non-empty path');
  }

  const targetDir = resolve(outDir);
  await ensureSafeDirectory(targetDir);

  const safeReport = sanitiseReport(report);
  const outputs: ReadonlyArray<readonly [string, string]> = [
    ['report.json', `${JSON.stringify(safeReport, null, 2)}\n`],
    ['report.sarif', `${JSON.stringify(toSarif(safeReport), null, 2)}\n`],
    ['report.md', toMarkdown(safeReport)],
  ];

  const destinations = outputs.map(([filename, contents]) => ({
    destination: resolve(targetDir, filename),
    contents,
  }));
  for (const { destination } of destinations) {
    await ensureSafeReportTarget(destination, targetDir);
  }
  for (const { destination, contents } of destinations) {
    await atomicWrite(destination, contents);
  }
}

/**
 * Return the CI exit code for the report.
 *
 * Incomplete requested work is an error even when --fail-on none is selected.
 * Error status takes precedence over severity findings so that a partial
 * scan can never be presented as a clean result.
 */
export function exitCode(
  report: ScanReport,
  failOn: Severity | 'none',
): 0 | 1 | 2 {
  const checks = Array.isArray(report?.checks) ? report.checks : [];
  if (checks.length === 0 || checks.every((check) => check.status === 'not_applicable')) {
    return 2;
  }
  if (checks.some((check) => check.status !== 'completed' && check.status !== 'not_applicable')) {
    return 2;
  }

  if (failOn === 'none') {
    return 0;
  }

  const threshold = SEVERITY_RANK[failOn];
  if (threshold === undefined) {
    // Invalid configuration is an execution error. TypeScript callers cannot
    // reach this branch, but CLI input is untrusted at runtime.
    return 2;
  }

  for (const check of checks) {
    for (const finding of Array.isArray(check.findings) ? check.findings : []) {
      if (SEVERITY_RANK[finding.severity] >= threshold) {
        return 1;
      }
    }
  }
  return 0;
}

/** Exposed for the CLI and tests that need to inspect the SARIF projection. */
export function toSarif(report: ScanReport): SarifLog {
  const safeReport = sanitiseReport(report);
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const check of safeReport.checks) {
    for (const finding of check.findings) {
      const ruleId = safeId(finding.ruleId, 'wakeio-finding');
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: safeText(finding.title, 'Finding'),
          shortDescription: { text: safeText(finding.title, 'Finding') },
          fullDescription: {
            text: safeText(finding.description, finding.title || 'Security finding'),
          },
          properties: {
            kind: finding.kind,
            confidence: finding.confidence,
            severity: finding.severity,
          },
          ...(finding.references && finding.references.length > 0
            ? { helpUri: finding.references[0] }
            : {}),
        });
      }

      const result: SarifResult = {
        ruleId,
        level: sarifLevel(finding.severity),
        message: {
          text: safeText(
            [finding.title, finding.description].filter(Boolean).join(': '),
            'Security finding',
          ),
        },
        fingerprints: {
          'wakeio-security-ci/v1': fingerprint(check.id, finding),
          'wakeio-security-ci/v2': finding.id!,
        },
        // `comparisonKey` is the semantic anchor supplied by a detector. A
        // location fingerprint remains useful for findings that do not yet
        // have an anchor, but is deliberately kept separate from the report
        // comparison contract.
        partialFingerprints: {
          'wakeio-security-ci/v1': finding.comparisonKey ?? fingerprint(check.id, finding),
          ...(finding.comparisonKey
            ? { 'wakeio-security-ci/comparison-key': finding.comparisonKey }
            : {}),
        },
        properties: {
          checkId: safeId(check.id, 'check'),
          kind: finding.kind,
          confidence: finding.confidence,
          severity: finding.severity,
          remediation: safeText(finding.remediation, 'Review the finding and verify the affected scope.'),
        },
      };

      const location = sarifLocation(finding.location);
      if (location) {
        result.locations = [location];
      }
      if (finding.references && finding.references.length > 0) {
        result.properties.references = finding.references;
      }
      results.push(result);
    }
  }

  const incomplete = safeReport.checks.some(
    (check) => check.status !== 'completed' && check.status !== 'not_applicable',
  );
  const noWork =
    safeReport.checks.length === 0 ||
    safeReport.checks.every((check) => check.status === 'not_applicable');

  const invocationProperties: Record<string, unknown> = {
    mode: safeReport.mode,
    category: `wakeio-security-ci/${safeReport.mode}`,
    statuses: Object.fromEntries(
      safeReport.checks.map((check) => [safeId(check.id, 'check'), check.status]),
    ),
  };

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        automationDetails: { id: `wakeio-security-ci/${safeReport.mode}` },
        tool: {
          driver: {
            name: 'wakeio-security-ci',
            version: safeReport.toolVersion,
            rules: [...rules.values()],
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: !incomplete && !noWork,
            startTimeUtc: safeReport.startedAt,
            endTimeUtc: safeReport.finishedAt,
            properties: invocationProperties,
          },
        ],
        properties: {
          mode: safeReport.mode,
          category: `wakeio-security-ci/${safeReport.mode}`,
          schemaVersion: safeReport.schemaVersion,
        },
      },
    ],
  };
}

/** Exposed for tests and consumers that want the human-readable projection. */
export function toMarkdown(report: ScanReport): string {
  const safeReport = sanitiseReport(report);
  const lines: string[] = [
    '# Wakeio Security CI report',
    '',
    `- Mode: ${markdownInline(safeReport.mode)}`,
    `- Started: ${markdownInline(safeReport.startedAt)}`,
    `- Finished: ${markdownInline(safeReport.finishedAt)}`,
    '',
    '## Checks',
    '',
  ];

  if (safeReport.scope) {
    lines.push(
      `- Scope fingerprint: ${markdownInline(safeReport.scope.fingerprint)}`,
      `- Ruleset: ${markdownInline(safeReport.scope.ruleset)}`,
      ...(safeReport.scope.projectId ? [`- Project ID: ${markdownInline(safeReport.scope.projectId)}`] : []),
    );
    if (safeReport.scope.provenance) {
      const provenance = safeReport.scope.provenance;
      if (provenance.sourceContentHash) lines.push('- Source content hash: recorded as provenance; it does not define comparison scope.');
      if (provenance.engines && provenance.engines.length > 0) {
        lines.push(`- Engine provenance: ${provenance.engines.map((engine) => `${engine.name}=${engine.status}${engine.sha256 ? ` (${engine.sha256.slice(0, 12)}…)` : ''}`).join(', ')}`);
      }
      if (provenance.dataSources && Object.keys(provenance.dataSources).length > 0) {
        lines.push(`- Data source provenance: ${Object.entries(provenance.dataSources).map(([name, value]) => `${name}=${value}`).join(', ')}`);
      }
    }
    lines.push('');
  }

  if (safeReport.checks.length === 0) {
    lines.push('No checks were requested.');
  } else {
    for (const check of safeReport.checks) {
      lines.push(`- **${markdownInline(check.id)}**: ${markdownInline(check.status)}`);
      for (const note of check.notes) {
        lines.push(`  - Note: ${markdownInline(note)}`);
      }
    }
  }

  lines.push('', '## Findings', '');
  const findingRows = safeReport.checks.flatMap((check) =>
    check.findings.map((finding) => ({ check, finding })),
  );
  if (findingRows.length === 0) {
    lines.push('No findings were reported.');
  } else {
    for (const { check, finding } of findingRows) {
      const where = markdownLocation(finding.location);
      const prefix = `[${finding.severity.toUpperCase()}] [${finding.kind}]`;
      lines.push(
        `- ${prefix} ${markdownInline(finding.title)} — ${markdownInline(finding.description)}`,
      );
      lines.push(`  - Check: ${markdownInline(check.id)}`);
      lines.push(`  - ID: ${finding.id}`);
      lines.push(`  - Confidence: ${markdownInline(finding.confidence)}`);
      if (where) {
        lines.push(`  - Location: ${markdownInline(where)}`);
      }
      lines.push(`  - Remediation: ${markdownInline(finding.remediation)}`);
      if (finding.references && finding.references.length > 0) {
        lines.push(
          `  - References: ${finding.references.map((reference) => markdownInline(reference)).join(', ')}`,
        );
      }
    }
  }

  lines.push('', '_Generated locally by wakeio-security-ci._', '');
  return lines.join('\n');
}

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

interface SarifRun {
  automationDetails?: { id: string };
  tool: { driver: { name: string; version: string; rules: SarifRule[] } };
  results: SarifResult[];
  invocations: Array<{
    executionSuccessful: boolean;
    startTimeUtc: string;
    endTimeUtc: string;
    properties: Record<string, unknown>;
  }>;
  properties: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  properties: Record<string, unknown>;
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  level: 'none' | 'note' | 'warning' | 'error';
  message: { text: string };
  locations?: SarifLocation[];
  fingerprints: Record<string, string>;
  partialFingerprints?: Record<string, string>;
  properties: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: { uri: string; uriBaseId?: string };
    region?: { startLine?: number; startColumn?: number };
  };
  logicalLocations?: Array<{ fullyQualifiedName: string }>;
}

export function sanitiseReport(report: ScanReport): ScanReport {
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    toolVersion: safeId(report?.toolVersion, REPORT_TOOL_VERSION),
    mode: validMode(report?.mode),
    startedAt: timestamp(report?.startedAt),
    finishedAt: timestamp(report?.finishedAt),
    checks: Array.isArray(report?.checks) ? report.checks.map(sanitiseCheck) : [],
    ...safeScope(report?.scope),
  };
}

function sanitiseCheck(input: CheckResult): CheckResult {
  const status = STATUSES.includes(input?.status) ? input.status : 'error';
  const findings = Array.isArray(input?.findings)
    ? input.findings.map(sanitiseFinding)
    : [];
  const notes = Array.isArray(input?.notes)
    ? input.notes.map((note) => safeText(note)).filter(Boolean)
    : [];

  const metrics: Record<string, number | string | boolean> = {};
  if (input?.metrics && typeof input.metrics === 'object') {
    for (const [key, value] of Object.entries(input.metrics)) {
      if (
        typeof value === 'number' ||
        typeof value === 'boolean' ||
        typeof value === 'string'
      ) {
        metrics[safeId(key, 'metric')] =
          typeof value === 'string' ? safeText(value) : value;
      }
    }
  }

  return {
    id: safeId(input?.id, 'check'),
    status,
    findings: findings.map((finding) => ({ ...finding, id: findingIdentity(safeId(input?.id, 'check'), finding) })),
    notes,
    ...(Object.keys(metrics).length > 0 ? { metrics } : {}),
  };
}

function safeScope(scope: ScanReport['scope']): { scope?: ScanReport['scope'] } {
  if (!scope || !/^[a-f0-9]{64}$/.test(scope.fingerprint) || !/^[A-Za-z0-9._-]{1,80}$/.test(scope.ruleset)) return {};
  const projectId = scope.projectId && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(scope.projectId)
    ? scope.projectId
    : undefined;
  const provenance = sanitiseProvenance(scope.provenance);
  return {
    scope: {
      fingerprint: scope.fingerprint,
      ruleset: scope.ruleset,
      ...(projectId ? { projectId } : {}),
      ...(provenance ? { provenance } : {}),
    },
  };
}

function sanitiseProvenance(provenance: ScanProvenance | undefined): ScanProvenance | undefined {
  if (!provenance || typeof provenance !== 'object') return undefined;
  const engines = Array.isArray(provenance.engines)
    ? provenance.engines
        .filter((engine) => engine && typeof engine === 'object')
        .slice(0, 16)
        .map((engine) => {
          const name = typeof engine.name === 'string' && /^[A-Za-z0-9._:-]{1,80}$/.test(engine.name)
            ? engine.name
            : undefined;
          const status = engine.status === 'available' || engine.status === 'missing'
            || engine.status === 'unreadable' || engine.status === 'unknown'
            ? engine.status
            : undefined;
          if (!name || !status) return undefined;
          const sha256 = typeof engine.sha256 === 'string' && /^[a-f0-9]{64}$/.test(engine.sha256)
            ? engine.sha256
            : undefined;
          return { name, status, ...(sha256 ? { sha256 } : {}) };
        })
        .filter((engine): engine is NonNullable<typeof engine> => engine !== undefined)
        .sort((a, b) => a.name.localeCompare(b.name))
    : undefined;
  const dataSources: Record<string, string> = {};
  if (provenance.dataSources && typeof provenance.dataSources === 'object' && !Array.isArray(provenance.dataSources)) {
    for (const [name, value] of Object.entries(provenance.dataSources).sort(([a], [b]) => a.localeCompare(b)).slice(0, 16)) {
      if (safeMetadataKey(name) && typeof value === 'string' && value.length <= 160) {
        dataSources[name] = safeText(value);
      }
    }
  }
  const sourceContentHash = typeof provenance.sourceContentHash === 'string'
    && /^[a-f0-9]{64}$/.test(provenance.sourceContentHash)
    ? provenance.sourceContentHash
    : undefined;
  if (!sourceContentHash && !engines?.length && !Object.keys(dataSources).length) return undefined;
  return {
    ...(sourceContentHash ? { sourceContentHash } : {}),
    ...(engines?.length ? { engines } : {}),
    ...(Object.keys(dataSources).length ? { dataSources } : {}),
  };
}

function safeMetadataKey(value: string): boolean {
  return /^[A-Za-z0-9._:-]{1,80}$/.test(value)
    && value !== '__proto__' && value !== 'constructor' && value !== 'prototype';
}

function findingIdentity(checkId: string, finding: Finding): string {
  return createHash('sha256').update(JSON.stringify([
    checkId, finding.ruleId, finding.kind, finding.title,
    finding.location.path ?? null, finding.location.url ?? null,
    finding.location.line ?? null, finding.location.column ?? null,
  ])).digest('hex');
}

/** Bounded callers choose fixed artifact names; all outputs retain report path protections. */
export async function writeArtifacts(outDir: string, artifacts: ReadonlyArray<readonly [string, string]>): Promise<void> {
  const targetDir = resolve(outDir);
  await ensureSafeDirectory(targetDir);
  for (const [name] of artifacts) {
    if (!/^[a-z][a-z0-9-]*\.(json|md)$/.test(name)) throw new Error('Invalid artifact name');
    await ensureSafeReportTarget(resolve(targetDir, name), targetDir);
  }
  for (const [name, contents] of artifacts) await atomicWrite(resolve(targetDir, name), contents);
}

function sanitiseFinding(input: Finding): Finding {
  const severity = SEVERITIES.includes(input?.severity) ? input.severity : 'info';
  const confidence = CONFIDENCES.includes(input?.confidence)
    ? input.confidence
    : 'low';
  const kind = KINDS.includes(input?.kind) ? input.kind : 'candidate';
  const references = Array.isArray(input?.references)
    ? input.references
        .map((reference) => safeHttpUrl(reference))
        .filter((reference): reference is string => reference !== undefined)
    : undefined;
  const location = sanitiseLocation(input?.location);
  const comparisonKey = typeof input?.comparisonKey === 'string' && /^[a-f0-9]{64}$/.test(input.comparisonKey)
    ? input.comparisonKey
    : undefined;

  return {
    ruleId: safeId(input?.ruleId, 'wakeio-finding'),
    title: safeText(input?.title, 'Security finding'),
    description: safeText(input?.description, 'The scanner reported a security finding.'),
    severity,
    confidence,
    kind,
    location,
    remediation: safeText(
      input?.remediation,
      'Review the finding and verify the affected scope.',
    ),
    ...(comparisonKey ? { comparisonKey } : {}),
    ...(references && references.length > 0 ? { references } : {}),
  };
}

function sanitiseLocation(
  location: Finding['location'] | undefined,
): Finding['location'] {
  const safe: Finding['location'] = {};
  if (location && typeof location.path === 'string') {
    const path = safeRelativePath(location.path);
    if (path) safe.path = path;
  }
  if (location && typeof location.url === 'string') {
    const url = safeHttpUrl(location.url);
    if (url) safe.url = url;
  }
  if (location && Number.isInteger(location.line) && (location.line as number) > 0) {
    safe.line = location.line;
  }
  if (location && Number.isInteger(location.column) && (location.column as number) > 0) {
    safe.column = location.column;
  }
  return safe;
}

function sarifLocation(location: Finding['location']): SarifLocation | undefined {
  const result: SarifLocation = {};
  if (location.path) {
    result.physicalLocation = {
      artifactLocation: { uri: sarifPathUri(location.path) },
    };
  } else if (location.url) {
    result.logicalLocations = [{ fullyQualifiedName: location.url }];
  }

  if (location.line || location.column) {
    result.physicalLocation ??= {};
    result.physicalLocation.region = {};
    if (location.line) result.physicalLocation.region.startLine = location.line;
    if (location.column) result.physicalLocation.region.startColumn = location.column;
  }

  return Object.keys(result).length > 0 ? result : undefined;
}

function fingerprint(checkId: string, finding: Finding): string {
  const location = finding.location.path
    ? `path:${finding.location.path}`
    : finding.location.url
      ? `url:${finding.location.url}`
      : 'location:unknown';
  const canonical = [
    safeId(checkId, 'check'),
    finding.ruleId,
    finding.kind,
    safeText(finding.title, 'Security finding'),
    location,
    finding.location.line ?? '',
    finding.location.column ?? '',
  ].join('|');
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function sarifLevel(severity: Severity): SarifResult['level'] {
  if (severity === 'info') return 'note';
  if (severity === 'low' || severity === 'medium') return 'warning';
  return 'error';
}

function markdownLocation(location: Finding['location']): string | undefined {
  if (location.path) {
    return `${location.path}${location.line ? `:${location.line}` : ''}`;
  }
  if (location.url) return location.url;
  return undefined;
}

function sarifPathUri(path: string): string {
  // Encode each segment so spaces, #, ?, and percent signs cannot change the
  // meaning of the relative artifact URI. The slash separators remain URI
  // path separators.
  return path.split('/').map((segment) => encodeURIComponent(segment)).join('/');
}

function markdownInline(value: unknown): string {
  return safeText(value)
    .replace(/[\t\r\n]+/g, ' ')
    .replaceAll('\\', '\\\\')
    .replace(/[\\`*_[\]{}()<>#+\-.!|]/g, '\\$&')
    .replaceAll('\n', ' ');
}

function safeText(value: unknown, fallback = ''): string {
  const text = typeof value === 'string' ? value : value == null ? fallback : String(value);
  return redactSecrets(stripControl(text)).slice(0, SAFE_TEXT_MAX);
}

function safeId(value: unknown, fallback: string): string {
  const valueText = safeText(value, fallback)
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim();
  return (valueText || fallback).slice(0, SAFE_ID_MAX);
}

function stripControl(value: string): string {
  return [...value]
    .filter((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code === 9 || code === 10 || code === 13 || code >= 32;
    })
    .join('');
}

/** Redact common credential forms before any text reaches an artifact. */
function redactSecrets(value: string): string {
  let result = value;

  // URL query strings are never needed in a report and frequently contain
  // tokens. This also strips credentials embedded in an URL authority.
  result = result.replace(/https?:\/\/[^\s<>"'`]+/gi, (candidate) => {
    const safe = safeHttpUrl(candidate);
    return safe ?? '[REDACTED_URL]';
  });

  // PEM bodies and common bearer/API-token forms.
  result = result.replace(
    /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/gi,
    '[REDACTED_KEY]',
  );
  result = result.replace(
    /(authorization\s*[:=]\s*(?:bearer\s+)?|bearer\s+)([^\s,;]+)/gi,
    '$1[REDACTED]',
  );
  result = result.replace(
    /((?:api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret|session|cookie|refresh[_-]?token)\s*[:=]\s*)(["'])(?:\\.|(?!\2)[\s\S])*?\2/gi,
    '$1$2[REDACTED]$2',
  );
  result = result.replace(
    /\b[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_-]*\s*=\s*(["'])(?:\\.|(?!\1)[\s\S])*?\1/gi,
    '[REDACTED_ASSIGNMENT]',
  );
  result = result.replace(
    /((?:api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret|session|cookie|refresh[_-]?token)\s*[:=]\s*["']?)([^\s"',;]+)/gi,
    '$1[REDACTED]',
  );
  result = result.replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]+\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bgithub_pat_[A-Za-z0-9_]+\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bxox[baprs]-[A-Za-z0-9-]+\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bASIA[0-9A-Z]{16}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bAIza[0-9A-Za-z_-]{20,}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED_JWT]');

  return result;
}

function safeRelativePath(value: string): string | undefined {
  let path = value.replaceAll('\\', '/').trim();
  if (!path || path.includes('\u0000') || /[\u0000-\u001f\u007f]/.test(path)) {
    return undefined;
  }
  // Reject both absolute and drive-relative Windows spellings. A value such
  // as `C:report.txt` is not an absolute filesystem path on Windows, but it is
  // still interpreted as a URI scheme by some SARIF consumers.
  if (path.startsWith('/') || path.startsWith('//') || /^[A-Za-z]:/.test(path)) {
    return undefined;
  }

  const parts = path.split('/');
  const safeParts: string[] = [];
  for (const part of parts) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (safeParts.length === 0) return undefined;
      safeParts.pop();
      continue;
    }
    safeParts.push(part);
  }
  path = posix.normalize(safeParts.join('/'));
  if (!path || path === '..' || path.startsWith('../') || path.startsWith('/')) {
    return undefined;
  }
  return path;
}

function safeHttpUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return undefined;
  }
}

function timestamp(value: unknown): string {
  if (value instanceof Date) {
    return Number.isNaN(value.valueOf()) ? new Date().toISOString() : value.toISOString();
  }
  if (typeof value === 'string') {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.valueOf())) return parsed.toISOString();
  }
  return new Date().toISOString();
}

function validMode(value: unknown): Mode {
  return value === 'source' || value === 'url' || value === 'both' || value === 'api' || value === 'combined' ? value : 'source';
}

async function ensureSafeDirectory(directory: string): Promise<void> {
  const absolute = resolve(directory);
  const root = resolve(absolute, sep);
  const relative = absolute.slice(root.length).split(sep).filter(Boolean);
  let current = root;

  for (const component of relative) {
    current = resolve(current, component);
    let stats;
    try {
      stats = await lstat(current);
    } catch (error: unknown) {
      if (!isMissing(error)) throw error;
      await mkdir(current);
      stats = await lstat(current);
    }
    if (stats.isSymbolicLink()) {
      // macOS exposes /tmp and /var as stable system aliases (usually to
      // /private/tmp and /private/var). Resolve only these exact aliases; a
      // user-created link anywhere below them remains rejected.
      if (isStableSystemAlias(current)) {
        current = await realpath(current);
        continue;
      }
      throw new Error(`Refusing symlink in report output path: ${current}`);
    }
    if (!stats.isDirectory()) {
      throw new Error(`Report output path is not a directory: ${current}`);
    }
  }
}

function isStableSystemAlias(path: string): boolean {
  return path === '/tmp' || path === '/var';
}

async function ensureSafeReportTarget(
  destination: string,
  directory: string,
): Promise<void> {
  if (dirname(destination) !== directory) {
    throw new Error('Report target escaped the output directory');
  }
  try {
    const stats = await lstat(destination);
    if (stats.isSymbolicLink()) {
      throw new Error(`Refusing symlink report target: ${destination}`);
    }
    if (!stats.isFile()) {
      throw new Error(`Report target is not a regular file: ${destination}`);
    }
  } catch (error: unknown) {
    if (!isMissing(error)) throw error;
  }
}

async function atomicWrite(destination: string, contents: string): Promise<void> {
  const temporary = `${destination}.tmp-${process.pid}-${Date.now()}-${Math.random()
    .toString(16)
    .slice(2)}`;
  let handle;
  try {
    handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
    await handle.close();
    await rename(temporary, destination);
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

function isMissing(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT');
}
