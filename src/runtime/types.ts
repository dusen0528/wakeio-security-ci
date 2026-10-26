import type { CheckResult, CodeLanguage, CodeProvider, SourceOptions } from '../contracts.js';
import type { DastPolicy } from '../dast.js';
import type { SchemathesisAuthPolicy } from '../schemathesis-auth.js';
import type { ZapCompiledRequest } from '../zap-openapi.js';
import type { ZapPolicyInput } from '../zap-policy.js';
import type { AdmissionSnapshot, TaskAdmission } from '../agent-dast/admission.js';
import type { ExecutionPlan, ExecutionTask } from '../agent-dast/plan.js';
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

export interface AnalyzerProvider<Context> {
  id: string;
  checkId: string;
  selection: 'always' | 'native-preview' | 'tool';
  selected(options: SourceOptions): boolean;
  applicable(snapshot: SourceSnapshot): boolean;
  executable?(options: SourceOptions): string;
  stage?: 'shared' | 'python' | 'safe-config';
  notApplicable?(snapshot: SourceSnapshot): CheckResult;
  run(context: Context): Promise<CheckResult> | CheckResult;
  codeCoverage?: {
    publicId: CodeProvider;
    languages: readonly CodeLanguage[];
    inputs(snapshot: SourceSnapshot): readonly CollectedFile[];
    complete(check: CheckResult, inputCount: number): boolean;
  };
}

export interface PreparedAttackTask<T extends ExecutionTask = ExecutionTask> {
  task: T;
  policy?: DastPolicy;
  zapPolicy?: ZapPolicyInput;
  zapRequests?: ZapCompiledRequest[];
  document?: unknown;
  authPolicy?: SchemathesisAuthPolicy;
  env?: NodeJS.ProcessEnv;
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
export interface RegisteredAttackEngine<T extends ExecutionTask = ExecutionTask> {
  id: T['engine'];
  category: 'injection' | 'config';
  reportMode: 'url' | 'api';
  parseTask(raw: Record<string, unknown>): T;
  requiredInputs(task: T): readonly string[];
  prepare(task: T, data: ReadonlyMap<string, unknown>, options: AttackContext): PreparedAttackTask<T>;
  execute(prepared: PreparedAttackTask<T>, options: AttackContext,
    runtime: TaskAdmission, remaining: number): Promise<CheckResult[]>;
  complete(prepared: PreparedAttackTask<T>, check: CheckResult, observed: AdmissionSnapshot): boolean;
  findingPath(prepared: PreparedAttackTask<T>, url: URL): string;
}
