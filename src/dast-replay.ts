import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { parseScanReport } from './compare.js';
import { DAST_CHECK_ID, dastProfileRevision, parseDastPolicy, runDast, type DastPolicy } from './dast.js';
import { sanitizeDastExecution, isDastReplayableExecution } from './dast-execution.js';
import { snapshotJsonData } from './json-snapshot.js';
import { createReport, REPORT_TOOL_VERSION } from './report.js';
import { safeHttpUrl } from './report-path.js';
import type { CheckResult } from './contracts.js';

export type DastReplayOutcome = 'reproduced' | 'not_reproduced' | 'inconclusive' | 'refused';
export type DastReplayRefusal = 'invalid_options' | 'consent_required' | 'invalid_report' | 'finding_not_found'
  | 'not_replayable' | 'invalid_policy' | 'policy_mismatch' | 'execution_mismatch' | 'private_consent_required';

export interface DastReplayOptions {
  report: unknown;
  policy: unknown;
  findingId: string;
  consent: boolean;
  allowPrivate?: boolean;
  signal?: AbortSignal;
  env?: NodeJS.ProcessEnv;
}

export interface DastReplayResult {
  version: 1;
  kind: 'native-dast-finding-replay';
  outcome: DastReplayOutcome;
  findingId: string;
  reason?: DastReplayRefusal;
  /** Digest of JSON serialization of a bounded own-data snapshot, not the report file's byte digest. */
  sourceReportSha256?: string;
  sourceToolVersion?: string;
  replayToolVersion?: string;
  policySha256?: string;
  profileRevision?: string;
  sourceExecutionSha256?: string;
  freshExecutionSha256?: string;
  /** New fixed-plan check; the normal report writer sanitizes it for public output. */
  check?: CheckResult;
}

const ID = /^[0-9a-f]{64}$/;
const RULE = 'dast.sql-boolean-differential';
const TITLE = 'SQL boolean response differential observed';
const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);

function refused(findingId: string, reason: DastReplayRefusal, metadata: Partial<DastReplayResult> = {}): DastReplayResult {
  return { version: 1, kind: 'native-dast-finding-replay', outcome: 'refused', findingId, reason, ...metadata };
}

/** Read only own data properties before any await; signal remains a checked live cancellation capability. */
function snapshotOptions(raw: DastReplayOptions): DastReplayOptions | undefined {
  if (!raw || typeof raw !== 'object' || types.isProxy(raw)) return undefined;
  const prototype = Object.getPrototypeOf(raw);
  if (prototype !== Object.prototype && prototype !== null || Object.getOwnPropertySymbols(raw).length) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  const permitted = new Set(['report', 'policy', 'findingId', 'consent', 'allowPrivate', 'signal', 'env']);
  if (Object.entries(descriptors).some(([key, descriptor]) => !permitted.has(key) || !descriptor.enumerable || !('value' in descriptor))) return undefined;
  const value = (key: keyof DastReplayOptions) => descriptors[key]?.value;
  if (typeof value('findingId') !== 'string' || !ID.test(value('findingId') as string)
    || typeof value('consent') !== 'boolean'
    || value('allowPrivate') !== undefined && typeof value('allowPrivate') !== 'boolean'
    || value('signal') !== undefined && (types.isProxy(value('signal')) || !(value('signal') instanceof AbortSignal))) return undefined;
  return { report: value('report'), policy: value('policy'), findingId: value('findingId') as string,
    consent: value('consent') as boolean, allowPrivate: value('allowPrivate') as boolean | undefined,
    signal: value('signal') as AbortSignal | undefined, env: value('env') as NodeJS.ProcessEnv | undefined };
}

/**
 * Re-execute exactly the selected prior numeric SQL candidate's policy. A complete
 * baseline-preserving negative is not_reproduced; every incomplete/ambiguous run
 * is inconclusive. Neither outcome proves exploitability or a security fix.
 */
export async function replayDastFinding(rawOptions: DastReplayOptions): Promise<DastReplayResult> {
  let options: DastReplayOptions | undefined;
  try { options = snapshotOptions(rawOptions); } catch { return refused('', 'invalid_options'); }
  if (!options) return refused('', 'invalid_options');
  const { findingId } = options;
  if (!options.consent) return refused(findingId, 'consent_required');

  let policy: DastPolicy, policySha256: string;
  try {
    const parsed = parseDastPolicy(options.policy);
    policy = parsed.policy; policySha256 = parsed.policySha256;
  } catch { return refused(findingId, 'invalid_policy'); }

  let rawReport: unknown, report: ReturnType<typeof parseScanReport>;
  try {
    rawReport = snapshotJsonData(options.report);
    report = parseScanReport(rawReport);
  } catch { return refused(findingId, 'invalid_report'); }
  const metadata: Partial<DastReplayResult> = { sourceReportSha256: digest(rawReport),
    sourceToolVersion: report.toolVersion === REPORT_TOOL_VERSION ? REPORT_TOOL_VERSION : 'other',
    replayToolVersion: REPORT_TOOL_VERSION,
    policySha256, profileRevision: dastProfileRevision(policy) };
  const rawChecks = object(rawReport) && Array.isArray(rawReport.checks) ? rawReport.checks : [];
  const rawNative = rawChecks.filter(item => object(item) && item.id === DAST_CHECK_ID);
  if (rawNative.length !== 1 || !object(rawNative[0]) || !Array.isArray(rawNative[0].findings)) {
    return refused(findingId, 'not_replayable', metadata);
  }
  const rawSelected = rawNative[0].findings.filter(item => object(item) && item.id === findingId);
  if (rawSelected.length === 0) return refused(findingId, 'finding_not_found', metadata);
  if (rawSelected.length !== 1 || rawNative[0].findings.length !== 1) return refused(findingId, 'not_replayable', metadata);
  const native = report.checks.filter(check => check.id === DAST_CHECK_ID);
  if (native.length !== 1) return refused(findingId, 'not_replayable', metadata);
  const check = native[0]!;
  const selected = check.findings.filter(finding => finding.id === findingId);
  if (selected.length !== 1) return refused(findingId, 'not_replayable', metadata);
  if (check.findings.length !== 1 || check.status !== 'completed'
    || !check.dastExecution || check.dastExecution.status !== 'complete' || check.dastExecution.outcome !== 'observed'
    || check.metrics?.requestCount !== check.dastExecution.counts.httpAttempts
    || check.dastExecution.counts.evaluated !== check.dastExecution.plannedRequests || check.dastExecution.counts.httpAttempts < check.dastExecution.plannedRequests) {
    return refused(findingId, 'not_replayable', metadata);
  }
  const original = sanitizeDastExecution(check.dastExecution);
  if (!original || !isDastReplayableExecution(original)) return refused(findingId, 'not_replayable', metadata);
  metadata.sourceExecutionSha256 = digest(original);
  const finding = selected[0]!;
  if (original.policySha256 !== policySha256 || original.profile !== policy.profile
    || original.profileRevision !== dastProfileRevision(policy) || original.version !== policy.version) return refused(findingId, 'policy_mismatch', metadata);
  if (finding.ruleId !== RULE || finding.title !== TITLE || finding.kind !== 'candidate'
    || finding.severity !== 'high' || finding.confidence !== 'medium'
    || finding.location.url !== safeHttpUrl(policy.url)) return refused(findingId, 'not_replayable', metadata);
  if (original.allowPrivate !== (options.allowPrivate === true)) {
    return refused(findingId, original.allowPrivate ? 'private_consent_required' : 'execution_mismatch', metadata);
  }

  let fresh: CheckResult | undefined;
  try {
    const [rawFresh] = await runDast({ policy, consent: true, allowPrivate: options.allowPrivate,
      maxRequests: original.maxRequests, timeoutMs: original.timeoutMs, signal: options.signal, env: options.env });
    if (rawFresh) fresh = createReport([rawFresh], 'url', new Date()).checks[0];
  } catch {
    return { version: 1, kind: 'native-dast-finding-replay', outcome: 'inconclusive', findingId, ...metadata };
  }
  const execution = fresh?.dastExecution ? sanitizeDastExecution(fresh.dastExecution) : null;
  if (execution) metadata.freshExecutionSha256 = digest(execution);
  const sameSettings = execution?.policySha256 === original.policySha256
    && execution.profileRevision === original.profileRevision && execution.maxRequests === original.maxRequests
    && execution.timeoutMs === original.timeoutMs && execution.allowPrivate === original.allowPrivate;
  const completed = fresh?.id === DAST_CHECK_ID && fresh.status === 'completed' && execution?.status === 'complete'
    && execution.counts.evaluated === execution.plannedRequests && fresh.metrics?.requestCount === execution.counts.httpAttempts && sameSettings;
  const outcome: DastReplayOutcome = !completed ? 'inconclusive'
    : execution?.outcome === 'observed' && fresh?.findings.length === 1 && fresh.findings[0]?.id === findingId ? 'reproduced'
      : execution?.outcome === 'not_observed' && fresh?.findings.length === 0 ? 'not_reproduced'
        : 'inconclusive';
  return { version: 1, kind: 'native-dast-finding-replay', outcome, findingId, ...metadata, ...(fresh ? { check: fresh } : {}) };
}

/** Exit 0 is only a complete scoped non-reproduction, never a verified fix. */
export function dastReplayExitCode(result: DastReplayResult): number {
  return result.outcome === 'reproduced' ? 1 : result.outcome === 'not_reproduced' ? 0 : 2;
}
