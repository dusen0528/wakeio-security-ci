import type { AnalysisGap, ReportSummary, ScanGate, ScanReport } from './contracts.js';
import { nextGapReview } from './analysis-gaps.js';

const SUMMARY_CHECK_LIMIT = 6;
const SUMMARY_GAP_LIMIT = 3;

function selectedTools(report: ScanReport): ReportSummary['scope']['toolSelection'] {
  const inventories = report.checks.filter(check => check.id === 'source.inventory');
  if (inventories.length !== 1) return 'unknown';
  const metrics = inventories[0].metrics;
  if (!metrics || typeof metrics.nativePreviewSelected !== 'boolean') return 'unknown';
  if (metrics.requestedTools === 'none') return metrics.nativePreviewSelected ? 'native_preview_selected' : 'built_in_only';
  if (typeof metrics.requestedTools !== 'string') return 'unknown';
  const tools = metrics.requestedTools.split(',');
  return tools.length > 0 && tools.every(tool => ['gitleaks', 'osv', 'trivy', 'bandit'].includes(tool))
    ? 'external_tools_selected' : 'unknown';
}

/** Internal pure projection. Callers supply the public sanitised report and its existing gate. */
export function projectReportSummary(report: ScanReport, gate: ScanGate): ReportSummary {
  const blocking = new Set(gate.blockingFindingIds);
  const candidateIds = new Set<string>();
  let findings = 0, candidates = 0, completedChecks = 0, notApplicableChecks = 0;
  const incomplete: ReportSummary['incompleteChecks'] = [];
  let incompleteCount = 0;
  for (const [checkIndex, check] of report.checks.entries()) {
    findings += check.findings.length;
    for (const finding of check.findings) {
      if (finding.kind === 'candidate') { candidates++; candidateIds.add(finding.id!); }
    }
    if (check.status === 'completed') completedChecks++;
    else if (check.status === 'not_applicable') notApplicableChecks++;
    else {
      incompleteCount++;
      if (incomplete.length >= SUMMARY_CHECK_LIMIT) continue;
      const gaps = check.analysisGaps;
      incomplete.push({ checkIndex, checkId: check.id, status: check.status,
        diagnosticBasis: gaps ? 'typed_analysis_gaps' : 'check_status_only',
        ...(gaps ? { analysisGaps: {
          accounting: gaps.accounting, eventsObserved: gaps.eventsObserved, eventsDropped: gaps.eventsDropped,
          truncated: gaps.truncated,
          ...(gaps.reasonSummary ? { reasonSummary: { accounting: gaps.reasonSummary.accounting,
            rows: gaps.reasonSummary.rows.map(row => ({ ...row })) } } : {}),
          representativeItems: gaps.items.slice(0, SUMMARY_GAP_LIMIT).map(copyGap),
          omittedRetainedItems: Math.max(0, gaps.items.length - SUMMARY_GAP_LIMIT),
        } } : {}),
      });
    }
  }
  const first = incomplete[0], firstGap = first?.analysisGaps?.representativeItems[0];
  const gap = firstGap?.reason === 'parse_error' && !firstGap.location
    ? first.analysisGaps!.representativeItems.find(item => item.reason === 'parse_error' && item.location) ?? firstGap
    : firstGap;
  const summary = first?.analysisGaps?.reasonSummary;
  const reason = summary?.accounting === 'exact' ? summary.rows.find(row => row.eventsObserved! > 0)?.reason : undefined;
  const nextRead: ReportSummary['nextRead'] = first
    ? { kind: gap?.nextReview ?? (reason ? nextGapReview(reason) : 'review_check_diagnostics'), checkIndex: first.checkIndex, checkId: first.checkId,
      ...(gap?.location ? { location: { ...gap.location } } : {}) }
    : { kind: gate.outcome === 'incomplete' ? 'review_check_diagnostics'
      : findings > 0 ? 'review_finding_evidence' : 'review_scope_limitations' };
  return {
    version: 1, basis: 'sanitised_report',
    scanGate: { outcome: gate.outcome, exitCode: gate.exitCode, failOn: gate.failOn,
      reasonCodes: [...new Set(gate.reasons.map(reason => reason.code))].slice(0, 5) },
    counts: { findings, candidates, blockingFindings: blocking.size,
      blockingCandidates: [...candidateIds].filter(id => blocking.has(id)).length,
      completedChecks, incompleteChecks: incompleteCount, notApplicableChecks },
    incompleteChecks: incomplete, omittedIncompleteChecks: incompleteCount - incomplete.length,
    scope: { mode: report.mode,
      ...(report.scope ? { fingerprint: report.scope.fingerprint, ruleset: report.scope.ruleset, ...(report.scope.analysisBudget ? { analysisProfile: report.scope.analysisBudget.effectiveProfile, analysisBudgetRevision: report.scope.analysisBudget.revision } : {}) } : {}),
      toolSelection: selectedTools(report), wholeProjectCoverage: 'not_established' },
    nextRead,
  };
}

function copyGap(gap: AnalysisGap): AnalysisGap {
  return { ...gap, ...(gap.location ? { location: { ...gap.location } } : {}) };
}
