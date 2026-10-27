import type { CheckResult, CodeLanguage, Finding, SourceOptions, ToolName } from '../contracts.js';
import type { AdmissionSnapshot, TaskAdmission } from '../agent-dast/admission.js';
import type { ExecutionPlan, ExecutionTask } from '../agent-dast/plan.js';
import type { ExecutionTaskDescriptor } from '../agent-dast/task-parsers.js';
import type { NewSurface } from '../agent-dast/store.js';
import type { CollectedFile, SourceSnapshot } from '../source/types.js';

// M0 vocabulary only. Target execution and marker-aware ports arrive in later milestones.
export type VulnClass = 'sql' | 'command' | 'ssrf' | 'path' | 'xss' | 'redirect';
export type EvidenceGrade = 'confirmed' | 'strong' | 'observed' | 'candidate';
export type Reach = 'triggered' | 'reached_not_triggered' | 'not_reached' | 'unknown';

// Later milestones bind these type parameters to reviewed file-artifact contracts.
export interface BuiltTarget<Isolation> {
  imageDigest: string;
  builder: string;
  cacheKey: string;
  isolation: Isolation;
}
export interface Builder<Spec, Context, Target, Detection> {
  id: string;
  detect(snapshot: SourceSnapshot, spec: Spec): Detection;
  build(spec: Spec, context: Context): Promise<Target>;
}
export interface RuntimeProfile<Target, Detection, Instrumentation, Context, Coverage> {
  id: 'jvm' | 'node' | 'python' | 'go' | 'php' | 'dotnet';
  detect(target: Target, snapshot: SourceSnapshot): Detection;
  instrument(): Instrumentation;
  collectCoverage(context: Context): Promise<Coverage>;
}
export interface SurfaceProvider<Context, Result> {
  id: string;
  discover(context: Context): Promise<Result>;
}
export interface AttackEngine<Surface, Budget, Task, Markers, Context, Log> {
  id: string;
  plan(surfaces: Surface[], budget: Budget): Task[];
  run(task: Task, markers: Markers, context: Context): Promise<Log>;
}
export interface Observer<Context, Handle, Observation> {
  id: string;
  covers: VulnClass[];
  attach(context: Context): Promise<Handle>;
  drain(handle: Handle): Promise<Observation[]>;
}
/** Implementations must remain pure; this port supplies no execution context. */
export interface Oracle<Log, Observation, Coverage, Result> {
  vulnClass: VulnClass;
  judge(log: Log, observations: Observation[], coverage?: Coverage): Result[];
}
export interface Verdict<SurfaceRef, EvidenceRef> {
  surface: SurfaceRef;
  vulnClass: VulnClass;
  grade: EvidenceGrade;
  reach: Reach;
  markers: string[];
  evidence: EvidenceRef[];
}

export interface AnalyzerSelection {
  tools: readonly ToolName[];
  nativePreview: boolean;
}

export interface AnalyzerProvider<Context> {
  id: string;
  checkId: string;
  selection: 'always' | 'native-preview' | 'tool';
  selected(options: AnalyzerSelection): boolean;
  applicable(snapshot: SourceSnapshot): boolean;
  executable?(options: SourceOptions): string;
  stage?: 'shared' | 'python' | 'safe-config';
  notApplicable?(snapshot: SourceSnapshot): CheckResult;
  run(context: Context): Promise<CheckResult> | CheckResult;
  codeCoverage?: {
    languages: readonly CodeLanguage[];
    inputs(snapshot: SourceSnapshot): readonly CollectedFile[];
    complete(check: CheckResult, inputCount: number): boolean;
  };
}

/** Trusted callbacks capture private adapter state; none of it is serialized or caller-supplied. */
export interface PreparedAttackTask<T extends ExecutionTask = ExecutionTask> {
  task: T;
  execute(options: AttackContext, runtime: TaskAdmission, remaining: number): Promise<CheckResult[]>;
  complete(check: CheckResult, observed: AdmissionSnapshot): boolean;
  findingSurface(finding: Finding): NewSurface;
}

export interface AttackContext {
  plan: ExecutionPlan;
  allowPrivate: boolean;
  ratePerSecond: number;
  nucleiPath?: string;
  nucleiTemplates?: string;
  schemathesisPython?: string;
  zapPath?: string;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}

/** Internal v1 adapter port; it grants no caller-supplied code or execution authority. */
export interface RegisteredAttackEngine<T extends ExecutionTask = ExecutionTask> extends ExecutionTaskDescriptor<T> {
  prepare(task: T, data: ReadonlyMap<string, unknown>, options: AttackContext): PreparedAttackTask<T>;
}

// M1 data contracts. These declarations load no execution adapters or filesystem capabilities.
export type Sha256 = string;
export type PathRef = string;
export interface ArtifactRef { path: PathRef; bytes: number; sha256: Sha256 }
export interface RuntimeGap { area: string; code: string; surfaceId?: string }
export interface TargetSpec {
  version: 1; project: string; source: PathRef;
  build: { kind: 'compose'; file: PathRef; service: string };
  pack: { id: string; version: number };
  entry: { port: number; health: string; startupTimeoutSec: number };
  dependencies: { service: string; observer: 'pg-log' }[];
  seed: { sql: PathRef[]; snapshot: 'per-request' };
  scope: { include: string[]; exclude: string[] };
  budget: { maxRequests: number; maxMinutes: number; ratePerSecond: number };
}
export interface SourceManifest {
  files: { path: PathRef; mode: number; bytes: number; sha256: Sha256 }[]; complete: boolean;
}
export interface Stage<T> {
  schema: 'wakeio.verify-stage/v1'; stage: string; runId: string; epoch: string; runNonce: string;
  inputs: ArtifactRef[]; output: T; status: 'completed' | 'partial' | 'error'; gaps: RuntimeGap[];
}
export type StageBinding = Pick<Stage<unknown>, 'stage' | 'runId' | 'epoch' | 'runNonce' | 'inputs'>;
export interface ArtifactVault {
  readonly root: string;
  writeBytes(path: string, bytes: Uint8Array): Promise<ArtifactRef>;
  readBytes(ref: ArtifactRef): Promise<Buffer>;
  writeStage(path: string, stage: Stage<unknown>): Promise<ArtifactRef>;
  readStage(ref: ArtifactRef, binding: StageBinding): Promise<Stage<unknown>>;
}
export interface SurfaceRef { id: string; method: string; pathTemplate: string }
export interface SurfaceProvenance {
  provider: 'spring-actuator' | 'openapi'; rawInputSha256: Sha256; sanitizedArtifact: ArtifactRef; locator: string;
  handler?: { path: PathRef; className: string; methodName: string; line?: number };
}
export interface RuntimeParameter {
  name: string; in: 'path' | 'query' | 'header' | 'cookie' | 'body'; required: boolean;
  mediaType: string | null; jsonPointer: string | null; schemaLocator: string;
  type: 'string' | 'integer' | 'number' | 'boolean' | 'null' | 'unknown';
  serialization: { style: string | null; explode: boolean | null; allowReserved: boolean | null };
}
export interface RuntimeSurface extends SurfaceRef {
  params: RuntimeParameter[]; provenance: SurfaceProvenance[];
  readiness: 'ready' | 'unresolved' | 'excluded'; reasons: string[];
}
export interface InventoryV2 {
  schema: 'wakeio.surface-inventory/v2'; sourceSha256: Sha256; run: ArtifactRef; surfaces: RuntimeSurface[];
  providers: { id: string; status: 'completed' | 'partial' | 'error' }[];
  counts: { declared: number | null; enumerated: number }; gaps: RuntimeGap[];
}
export interface MarkerRow {
  markerHash: Sha256; surfaceId: string; method: string;
  param: { in: string; name: string; jsonPointer: string | null; schemaLocator: string };
  payload: 'benign' | 'sql-quote' | 'sql-boolean'; requestOrdinal: number; controlPairId: string;
}
export interface MarkerLedger { reproductionKey: Sha256; seed: string; rows: readonly MarkerRow[] }
export interface AttackAttempt {
  ordinal: number; surfaceId: string; markerHash: Sha256; payloadHash: Sha256; requestHash: Sha256;
  phase: 'control' | 'probe'; snapshotHash: Sha256;
  outcome: 'response' | 'transport_error' | 'not_started'; httpStatus: number | null;
}
export interface AttackLog { plan: ArtifactRef; markers: ArtifactRef; attempts: readonly AttackAttempt[] }
export interface PgCursor { dbLeaseId: string; logIdentity: string; rotation: number; byteOffset: number }
export interface Observation {
  id: string; runId: string; epoch: string; runNonce: string; observerSession: string; sequence: number;
  requestOrdinal: number; markerHash: Sha256; sourceContainerId: string; pgSessionId: string; pgSessionLine: number;
  cursor: PgCursor; requestWindow: { begin: PgCursor; end: PgCursor; closed: boolean };
  sql: {
    channel: 'statement' | 'bind'; dialect: 'postgres'; rawStatementSha256: Sha256; rawEventSha256: Sha256;
    parser: { version: string; pgMajor: number; lockSha256: Sha256; wasmSha256: Sha256 };
    ast: { id: number; kind: string; parent: number | null; span: [number, number] }[];
    tokens: { kind: string; span: [number, number];
      role: 'literal' | 'identifier' | 'operator' | 'syntax' | 'comment' | 'parameter' }[];
    insertions: { payloadHash: Sha256; span: [number, number]; tokenIndexes: number[]; nodeIds: number[] }[];
    error: { sqlState: string | null; pgCharPosition1Based: number | null; parserByteOffset0Based: number | null;
      kind: 'none' | 'quote_imbalance' | 'other_syntax' | 'unsupported' | 'invalid' };
    controlContextHash: Sha256; outsidePayloadTokenHash: Sha256;
  };
  evidence: ArtifactRef;
}
export interface CoverageFiles {
  path: PathRef; sha256: Sha256; coveredLines: number[]; executableLines: number[];
}
export interface CoverageDump { exec: ArtifactRef; xml: ArtifactRef; resetAck: ArtifactRef }
/** One request between the before/reset acknowledgement and the after/reset acknowledgement. */
export interface RequestCoverage {
  surfaceId: string; taskId: string; requestOrdinal: number; jacocoSessionId: string; classTree: ArtifactRef;
  before: CoverageDump; after: CoverageDump; files: CoverageFiles[];
  accounting: 'exact' | 'unknown'; reasons: string[];
}
export interface CoverageMap {
  basis: 'jacoco'; imageDigest: string; sourceSha256: Sha256; dump: ArtifactRef;
  agentVersion: string; agentSha256: Sha256; requests: RequestCoverage[];
}
export interface RuntimeVerdict extends Verdict<SurfaceRef, ArtifactRef> {
  vulnClass: 'sql'; ruleRevision: string; controlPairId: string;
}
export interface CaseOutcome {
  surfaceId: string; state: 'triggered' | 'not_triggered' | 'unknown'; reasons: string[];
}
export interface IsolationReport {
  requested: 'gvisor' | 'rootless-docker'; applied: 'gvisor' | 'rootless-docker' | 'unavailable';
  daemonRootless: boolean; backend: string; daemonVersion: string; runtimeVersion: string; targetUid: number | null;
  capDropAll: boolean; readOnlyRootfs: boolean; seccomp: string;
  cgroup: { version: number | null; driver: string; systemd: boolean;
    delegatedUnit: string | null; controllers: string[] };
  resources: { requested: { cpu: number; memoryBytes: number; pids: number };
    measured: { cpuQuota: number | null; memoryMax: number | null; pidsMax: number | null };
    probe: ArtifactRef; enforced: boolean };
  buildNetwork: 'registry-allowlist'; runNetwork: 'internal'; verified: boolean; gaps: RuntimeGap[];
}
export type JsonScalar = null | boolean | number | string;
export type JsonData = JsonScalar | { readonly [key: string]: JsonData };
export interface RuntimeResponse {
  ordinal: number; outcome: 'response' | 'transport_error' | 'cancelled' | 'limit';
  sent: 'confirmed' | 'not_sent' | 'unknown'; status: number | null;
  bodyBytes: Uint8Array; rawBodySha256: Sha256 | null; truncated: boolean;
}
export interface RuntimeRequestPort {
  readonly transport: 'stdio-relay'; readonly leaseId: string; readonly origin: string;
  readonly deadlineAt: number; readonly maxRequests: number;
  request(input: { taskId: string; phase: 'health' | 'discover' | 'control' | 'probe';
    method: 'GET' | 'HEAD' | 'POST'; path: string; query: readonly [string, string][];
    body: null | { mediaType: 'application/json'; data: JsonData };
    deadlineAt: number; maxResponseBytes: number; signal: AbortSignal }): Promise<RuntimeResponse>;
}
export interface RunContext {
  runId: string; epoch: string; runNonce: string;
  dbLease: { id: string; containerId: string; seedCursor: PgCursor };
  target: Readonly<TargetSpec>; source: ArtifactRef; built: ArtifactRef; signal: AbortSignal; deadlineAt: number;
  handles: { target: object; observer: object; admission: TaskAdmission; snapshots: object; artifacts: ArtifactVault };
  request: RuntimeRequestPort;
}
export interface CleanupReport {
  status: 'confirmed' | 'error'; lease: ArtifactRef; processGroupExitConfirmed: boolean;
  resources: { kind: string; id: string; absenceConfirmed: boolean }[];
  remainingOwnedIds: string[]; reasons: string[];
}
export interface VerifyGate {
  outcome: 'pass' | 'findings' | 'incomplete'; exitCode: 0 | 1 | 2; failOnGrade: 'strong' | 'confirmed';
  blockingFindingIds: string[]; reasons: RuntimeGap[];
}
export interface RuntimeFindingEvidence {
  basis: 'runtime-observation-ledger'; grade: EvidenceGrade; reach: Reach; markers: Sha256[];
  controlPairId: string; refs: ArtifactRef[]; oracleRevision: string;
}
export type RuntimeFinding = Omit<Finding, 'evidence'> & { evidence: RuntimeFindingEvidence };
export interface RuntimeCheckPayloads {
  'runtime.build': { builder: string | null; imageDigest: string | null; cacheKey: string | null;
    isolation: IsolationReport | null; durationMs: number | null };
  'runtime.start': { lease: ArtifactRef | null; health: 'passed' | 'failed' | 'unknown';
    durationMs: number | null; instrumentation: ArtifactRef | null };
  'runtime.surface': { routes: { surface: SurfaceRef; provenance: SurfaceProvenance[];
    attacked: boolean | null; reasons: string[] }[]; declared: number | null; enumerated: number };
  'runtime.coverage': { method: 'jacoco'; routes: { surface: SurfaceRef; files: CoverageFiles[] | null;
    coveredFiles: number | null; coveredLines: number | null; executableLines: number | null;
    ratio: number | null; accounting: 'exact' | 'unknown'; reasons: string[] }[]; dumpRefs: ArtifactRef[] };
  'runtime.oracle.sql': { method: 'pg-ast-token-differential'; cases: CaseOutcome[];
    verdictRefs: ArtifactRef[]; markerLedger: ArtifactRef | null; parserRevision: string | null };
}
export type RuntimeCheckId = keyof RuntimeCheckPayloads;
export type RuntimeCheck = { [K in RuntimeCheckId]: {
  id: K; status: CheckResult['status']; findings: RuntimeFinding[]; notes: string[];
  runtime: RuntimeCheckPayloads[K] & { reasons: string[] };
} }[RuntimeCheckId];
export interface RuntimeScope {
  requestedVulnClasses: ['sql']; unsupportedVulnClasses: Array<Exclude<VulnClass, 'sql'> | 'authz'>; gaps: RuntimeGap[];
}
export interface RuntimeReportData {
  revision: 'verify-m1-v1'; verifyGate: VerifyGate; scope: RuntimeScope;
  inputArtifacts: ArtifactRef[]; stages: ArtifactRef[]; cleanup: CleanupReport;
}

/** Navigation from sanitised data; copied gates/counts never establish execution or producer trust. */
export interface RuntimeReportSummary {
  version: 1; basis: 'sanitised_runtime_report'; mode: 'runtime'; revision: 'verify-m1-v1';
  scope?: never; scanGate?: never;
  findings: { confirmedIds: string[]; strongIds: string[]; observedIds: string[]; candidateIds: string[] };
  verifyGate: VerifyGate;
  /** Finding rows by recorded reach, not all route/case outcomes. */
  reach: { triggered: number; reachedNotTriggered: number; notReached: number; unknown: number };
  unknownCases: Array<CaseOutcome & { state: 'unknown' }>;
  coverage: {
    declaredRoutes: number | null; enumeratedRoutes: number; attackedRoutes: number | null;
    unattackedRoutes: number | null; unknownRoutes: number; routeRatio: number | null;
    /** Per-route denominators; never sum overlapping source lines into project coverage. */
    lines: Array<Pick<RuntimeCheckPayloads['runtime.coverage']['routes'][number],
      'surface' | 'coveredFiles' | 'coveredLines' | 'executableLines' | 'ratio' | 'accounting' | 'reasons'>>;
  };
  limitations: RuntimeGap[];
}
export type RuntimeAgentCheck = { [K in RuntimeCheckId]: {
  checkIndex: number; checkId: K; status: CheckResult['status']; findingIds: string[]; notes: string[];
  runtime: RuntimeCheckPayloads[K] & { reasons: string[] };
} }[RuntimeCheckId];
