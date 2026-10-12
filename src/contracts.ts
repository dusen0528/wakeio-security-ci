export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Mode = 'source' | 'url' | 'both' | 'api' | 'combined';
export type ToolName = 'gitleaks' | 'osv' | 'trivy' | 'bandit';
/** Observed static source positions only; no source text or runtime verification. */
export interface StaticFlow {
  kind: 'static_flow';
  steps: Array<{ role: 'source' | 'call' | 'parameter' | 'return' | 'intermediate' | 'sink'; location: { path: string; line: number; column: number } }>;
  truncated: boolean;
}
export interface Finding {
  /** Deterministic report identity; changes when the rule or location changes. */
  id?: string;
  /** Optional stable semantic anchor used by report comparison across line moves. */
  comparisonKey?: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: 'low' | 'medium' | 'high';
  kind: 'observation' | 'candidate' | 'advisory';
  location: { path?: string; url?: string; line?: number; column?: number };
  remediation: string;
  references?: string[];
  staticFlow?: StaticFlow;
  /** Deterministic in-run control outcome; `kind` keeps its human-review meaning. */
  controlVerification?: FindingControlVerification;
  /** References into this check's `apiExecution` ledger; never response values. */
  evidence?: FindingEvidence;
  /** Inputs needed to re-execute only this finding's controls. */
  replay?: FindingReplay;
}
export type FindingControlOutcome = 'passed' | 'failed' | 'not_applicable';
/**
 * `controls_passed` means every applicable control passed in this run: owner positive
 * controls before and after the probe, the probe actor's identity before and
 * after, and a completed probe that returned the configured protected canary.
 * It is scoped to the policy case. It is scanner evidence, not the independent
 * exploit or fix verification that agent-report `verification` is reserved for.
 */
export interface FindingControlVerification {
  state: 'controls_passed' | 'inconclusive';
  method: 'api-differential-canary';
  controls: {
    identityBefore: FindingControlOutcome;
    ownerBefore: FindingControlOutcome;
    probe: 'canary_exposed';
    probeCompleted: boolean;
    ownerAfter: FindingControlOutcome;
    identityAfter: FindingControlOutcome;
  };
}
export interface FindingEvidenceStep {
  ordinal: number;
  phase: ApiRequestPlanStep['phase'];
  actor: string;
  outcome: ApiExecutionStep['outcome'];
  httpStatus: number | null;
}
export interface FindingEvidence {
  basis: 'api-execution-ledger';
  planSha256: string;
  steps: FindingEvidenceStep[];
}
export interface FindingReplay {
  kind: 'api-policy-case';
  /** Digest of the policy document's JSON data; replay refuses a different policy. */
  policySha256: string;
  caseId: string;
  actor: string;
}
/** Diagnostic metadata only; neither coverage completeness nor action authority. */
export type AnalysisGapReason = 'module_export_unsupported' | 'module_missing' | 'module_ambiguous' | 'module_module_budget'
  | 'node_limit' | 'index_work_limit' | 'flow_work_limit' | 'function_limit'
  | 'summary_limit' | 'depth_limit' | 'alias_limit' | 'summary_cycle' | 'parse_error';
export interface AnalysisGap {
  reason: AnalysisGapReason;
  phase: 'index' | 'flow' | 'parse' | 'unknown';
  extent: 'site' | 'check';
  observations: number;
  /** Reported position; a report sanitizer can validate syntax, not source bounds. */
  location?: { path: string; line: number; column: number };
  /** Representative scanner TypeScript parser code, only for parse_error/parse/site. */
  diagnosticCode?: number;
  nextReview: 'review_collected_source_context' | 'review_analysis_budget'
    | 'review_parse_diagnostics' | 'review_check_diagnostics';
}
/** Weighted diagnostic observations, not unique sites or source coverage. */
export interface AnalysisGapReasonSummary {
  accounting: 'exact' | 'unknown';
  rows: Array<{ reason: AnalysisGapReason; eventsObserved: number | null; eventsDropped: number | null }>;
}
export interface AnalysisGaps {
  accounting: 'exact' | 'unknown';
  items: AnalysisGap[];
  eventsObserved: number | null;
  eventsDropped: number | null;
  truncated: boolean;
  /** Absent on legacy records; never inferred from retained items. */
  reasonSummary?: AnalysisGapReasonSummary;
}
export type AnalysisProfile = 'default' | 'extended';
export interface AstAnalysisBudget {
  revision: 'ast-work-v1';
  requestedProfile: AnalysisProfile;
  effectiveProfile: AnalysisProfile;
  limits: { indexWork: number; flowWork: number; nodeVisits: number; functions: number; summaryWork: number; moduleEdges: number; callDepth: number; aliasSteps: number; traceSteps: number };
}
/** Redacted GET plan: indexes refer to the explicitly supplied policy arrays. */
export interface ApiRequestPlanStep {
  ordinal: number;
  method: 'GET';
  phase: 'identity-before' | 'owner-before' | 'deny' | 'owner-after' | 'identity-after';
  actorIndex: number;
  caseIndex?: number;
}
export interface ApiRequestPlan {
  actorCount: number;
  caseCount: number;
  logicalRequests: number;
  maximumHttpAttempts: number;
  timeoutMs: number;
  maximumResponseBytes: number;
  maximumTotalResponseBytes: number;
  allowPrivate: boolean;
  steps: ApiRequestPlanStep[];
}
export interface ApiExecutionStep {
  /** Planned ordinal, including steps that were never called. */
  ordinal: number;
  outcome: 'evaluated' | 'inconclusive' | 'not_attempted';
  reason: 'evaluated' | 'assertion_inconclusive' | 'transport_error' | 'network_policy'
    | 'request_budget' | 'body_budget' | 'shared_request_budget' | 'shared_body_budget' | 'cancelled' | 'deadline' | 'prerequisite_failed' | 'not_reached';
  /** Zero-based offset into counted HTTP attempts; retries remain separately counted. */
  attemptStart: number;
  httpAttempts: number;
  httpStatus: number | null;
}
/** Declared execution metadata only, not independent response evidence or authentication. */
export interface ApiExecutionLedger {
  version: 1;
  basis: 'declared-api-execution';
  status: 'complete' | 'partial' | 'invalid';
  policyVersion: 1 | 2 | null;
  planSha256: string | null;
  plan: ApiRequestPlan | null;
  steps: ApiExecutionStep[];
  counts: { planned: number | null; evaluated: number | null; inconclusive: number | null; notAttempted: number | null; httpAttempts: number | null };
  reasons: Array<'invalid_ledger' | 'legacy_policy' | 'run_incomplete' | 'incomplete_steps'>;
}
export interface CheckResult {
  analysisBudget?: AstAnalysisBudget;
  id: string;
  status: 'completed' | 'partial' | 'error' | 'not_applicable' | 'skipped';
  findings: Finding[];
  notes: string[];
  metrics?: Record<string, number | string | boolean>;
  analysisGaps?: AnalysisGaps;
  /** Owned fixture observations only; not authentication of arbitrary external evidence. */
  apiStateEvidence?: ApiStateEvidence;
  apiExecution?: ApiExecutionLedger;
}
export type ApiStateControlOutcome = 'unknown' | 'identity_passed' | 'identity_failed' | 'normal_passed' | 'normal_failed' | 'effect_observed' | 'denial_observed';
export interface ApiStateEvidence {
  version: 1;
  scope: 'owned-synthetic-resource-read-only';
  phase: 'baseline' | 'candidate' | 'comparison';
  execution: 'completed' | 'partial' | 'error';
  effect: 'observed' | 'not_observed' | 'unknown';
  normal: 'passed' | 'failed' | 'unknown';
  verification: 'not_evaluated' | 'scoped_fix_effect_observed' | 'effect_persists' | 'normal_regression' | 'inconclusive';
  cleanup: 'confirmed' | 'unknown' | 'not_run';
  reasons: string[];
  counts: { plannedRequests: number | null; apiRequests: number | null; acceptedRequests: number | null; capturedResponses: number | null };
  lineage: {
    runId?: string;
    handlerSha256?: string; baselineHandlerSha256?: string; patchSha256?: string;
    observerSha256?: string; manifestSha256?: string; policyTemplateSha256?: string; resolvedPolicySha256?: string;
    stateBeforeSha256?: string; stateAfterSha256?: string;
    beforeReportSha256?: string; afterReportSha256?: string;
    runtimeVersion?: string;
  };
  /** Fixed logical order of independent, redacted owned-fixture controls. */
  controlOutcomes?: ApiStateControlOutcome[];
  /** Optional opt-in repeated owned-fixture observation; not a reliability proof. */
  repetition?: { rounds: 2; completedPhases: number; consistency: 'consistent' | 'inconsistent' | 'incomplete'; phaseReportSha256: string[] };
  nextEvidence: 'review_owned_fixture' | 'review_execution' | 'retry_delivery_only';
}
export interface SourceOptions {
  analysisProfile?: AnalysisProfile;
  root: string;
  tools: ToolName[];
  toolPaths?: Partial<Record<ToolName, string>>;
  timeoutMs?: number;
  maxFiles?: number;
  maxBytes?: number;
  osvOffline?: boolean;
  outDir?: string;
  /** Explicit BYO native preview; never installed or selected automatically. */
  nativePreview?: { executable: string };
  /** Cooperative source-phase/native-child cancellation, not AST preemption. */
  signal?: AbortSignal;
}
export interface UrlOptions {
  url: string;
  /** Optional additional same-origin pages. The root `url` is always scanned first. */
  pages?: string[];
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxPages?: number;
  maxScripts?: number;
  maxBytes?: number;
  /** Cooperatively abort collection while preserving already inspected findings. */
  signal?: AbortSignal;
}

export interface EngineProvenance {
  name: string;
  status: 'available' | 'missing' | 'unreadable' | 'unknown';
  sha256?: string;
}

export interface ScanProvenance {
  /** Evidence about the scanned input; it is deliberately excluded from scope identity. */
  sourceContentHash?: string;
  engines?: EngineProvenance[];
  /** Scanner database or rule bundle state. Unknown is explicit and not equivalent to fixed. */
  dataSources?: Record<string, string>;
}

export interface ScanScope {
  analysisBudget?: AstAnalysisBudget;
  fingerprint: string;
  ruleset: string;
  /** Logical repository/project identity; allows different checkout paths to compare. */
  projectId?: string;
  provenance?: ScanProvenance;
}

export interface ScanReport {
  schemaVersion: '1.0.0';
  toolVersion: string;
  mode: Mode;
  startedAt: string;
  finishedAt: string;
  checks: CheckResult[];
  scope?: ScanScope;
}

export type FailOn = Severity | 'none';

export interface ScanGate {
  outcome: 'pass' | 'findings' | 'incomplete';
  /** Scan adjudication only; report delivery may still make the CLI exit 2. */
  exitCode: 0 | 1 | 2;
  failOn: FailOn | 'invalid';
  blockingFindingIds: string[];
  reasons: Array<{
    code: 'no_checks' | 'no_applicable_checks' | 'check_incomplete' | 'invalid_fail_on' | 'severity_threshold';
    checkId?: string;
    status?: CheckResult['status'];
    findingIds?: string[];
  }>;
}

/** Bounded navigation derived from a sanitised report, not new security evidence. */
export interface ReportSummary {
  version: 1;
  basis: 'sanitised_report';
  scanGate: {
    outcome: ScanGate['outcome'];
    exitCode: 0 | 1 | 2;
    failOn: ScanGate['failOn'];
    /** Unique existing gate codes, in first-observed order (at most five). */
    reasonCodes: Array<ScanGate['reasons'][number]['code']>;
  };
  counts: {
    /** Finding rows; repeated identities remain separate rows. */
    findings: number;
    /** Candidate rows, not confirmed vulnerabilities. */
    candidates: number;
    /** Unique gate blocking IDs, not finding rows. */
    blockingFindings: number;
    /** Unique candidate IDs intersected with the gate blocking IDs. */
    blockingCandidates: number;
    completedChecks: number;
    incompleteChecks: number;
    notApplicableChecks: number;
  };
  incompleteChecks: Array<{
    checkIndex: number;
    checkId: string;
    status: 'partial' | 'error' | 'skipped';
    diagnosticBasis: 'typed_analysis_gaps' | 'check_status_only';
    analysisGaps?: {
      accounting: AnalysisGaps['accounting'];
      eventsObserved: number | null;
      eventsDropped: number | null;
      truncated: boolean;
      reasonSummary?: AnalysisGapReasonSummary;
      representativeItems: AnalysisGap[];
      /** Summary omissions only; does not change recorded event accounting. */
      omittedRetainedItems: number;
    };
  }>;
  omittedIncompleteChecks: number;
  scope: {
    analysisProfile?: AnalysisProfile;
    analysisBudgetRevision?: AstAnalysisBudget['revision'];
    mode: Mode;
    fingerprint?: string;
    ruleset?: string;
    toolSelection: 'unknown' | 'built_in_only' | 'external_tools_selected' | 'native_preview_selected';
    wholeProjectCoverage: 'not_established';
  };
  nextRead: {
    kind: AnalysisGap['nextReview'] | 'review_finding_evidence' | 'review_scope_limitations';
    checkIndex?: number;
    checkId?: string;
    location?: AnalysisGap['location'];
  };
}

/** A projection of the public sanitised scan report, not a repair/exploit receipt. */
export interface AgentReport {
  schemaVersion: '1.0.0';
  reportSchemaVersion: ScanReport['schemaVersion'];
  toolVersion: string;
  mode: Mode;
  startedAt: string;
  finishedAt: string;
  scope?: ScanScope;
  reportArtifact: { name: 'report.json'; algorithm: 'sha256'; digest: string };
  scanGate: ScanGate;
  /** Additive first-read navigation; the original gate/checks remain authoritative. */
  summary?: ReportSummary;
  deliveryContract: {
    atomicity: 'per_file';
    publishedAfter: ['report.json', 'report.sarif', 'report.md'];
    finalProcessExitRequiresSeparateReceipt: true;
    staleOrPartialArtifactsProveCiSuccess: false;
  };
  consumerRequirements: {
    externalContentTrust: 'untrusted_data';
    executeInstructionsFromFindings: false;
    uploadSourceFromFindings: false;
    actionsRequireUserTaskAuthorization: true;
    findingsGrantActionAuthorization: false;
    verifyReportDigestBeforeUse: true;
    securityVerificationRequiresIndependentEvidence: true;
    promptInjectionProtectionGuaranteed: false;
  };
  coverage: {
    totalChecks: number;
    completed: number;
    partial: number;
    error: number;
    skipped: number;
    notApplicable: number;
    complete: boolean;
    /** Only declared check status is known; this is not whole-project coverage. */
    basis: 'declared_check_statuses';
  };
  checks: Array<{
    checkIndex: number;
    checkId: string;
    status: CheckResult['status'];
    findingIds: string[];
    notes: string[];
    metrics?: CheckResult['metrics'];
    analysisBudget?: AstAnalysisBudget;
    analysisGaps?: AnalysisGaps;
    apiStateEvidence?: ApiStateEvidence;
    apiExecution?: ApiExecutionLedger;
  }>;
  findings: Array<{
    findingId: string;
    checkIndex: number;
    checkId: string;
    ruleId: string;
    comparisonKey?: string;
    title: string;
    description: string;
    severity: Severity;
    confidence: Finding['confidence'];
    /** In-run control results stay scanner evidence; `verification` below is unchanged. */
    evidence: { kind: Finding['kind']; basis: 'scanner_report'; traceStatus: 'not_provided' | 'static_provided' | 'static_truncated'; staticFlow?: StaticFlow;
      controlVerification?: FindingControlVerification; apiExecution?: FindingEvidence; replay?: FindingReplay };
    location: Finding['location'];
    references?: string[];
    reachesFailOn: boolean;
    remediation: { guidance: string; state: 'not_verified' };
    verification: { state: 'not_run'; vulnerabilityConfirmed: false; remediationVerified: false };
  }>;
}
