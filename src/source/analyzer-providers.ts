import type { CheckResult, CodeProvider, SourceOptions, ToolName } from '../contracts.js';
import type { AnalyzerProvider, AnalyzerSelection } from '../runtime/types.js';
import { builtinAstFiles } from './ast.js';
import { nativeFiles, runNativePreview } from './opengrep.js';
import { pythonFiles, runBandit } from './python.js';
import { semgrepFiles, runSemgrep } from './semgrep.js';
import { frameworkHasApplicableInput, runFrameworkRules } from './framework.js';
import { govulncheckHasApplicableInput, runGovulncheck } from './govulncheck.js';
import { runTrivyVulnerabilities } from '../trivy-vuln.js';
import { osvHasApplicableInput, trivyInputCandidate } from './analyzer-inputs.js';
import type { SourceSnapshot } from './types.js';

interface ToolInput {
  snapshot: SourceSnapshot; stageDir: string; timeoutMs: number; toolPath: string;
  signal?: AbortSignal; osvOffline?: boolean; blockedConfigCount?: number;
}
export interface AnalyzerRunContext extends ToolInput {
  options: SourceOptions;
  builtinAst?: () => CheckResult;
  legacy: Record<'gitleaks' | 'osv' | 'trivy', (context: ToolInput) => Promise<CheckResult>>;
}
export interface SourceAnalyzer extends AnalyzerProvider<AnalyzerRunContext> {
  tool?: ToolName;
  /** The adapter owns input, cancellation and missing-executable classification. */
  adapterOwnsPreflight?: boolean;
  stageFailure?: string;
  failureMessage?: string;
}
export interface ToolAnalyzer extends SourceAnalyzer {
  tool: ToolName;
  executable(options: SourceOptions): string;
  notApplicable(snapshot: SourceSnapshot): CheckResult;
}
export interface SyncAnalyzer extends SourceAnalyzer {
  selection: 'always';
  run(context: AnalyzerRunContext): CheckResult;
}

type CoverageMetadata = NonNullable<AnalyzerProvider<never>['codeCoverage']>;
export interface CodeAnalyzerMetadata extends SourceAnalyzer {
  id: CodeProvider;
  codeCoverage: CoverageMetadata & {
    inputCount(check: CheckResult): unknown;
  };
}

function provider(value: CodeAnalyzerMetadata): CodeAnalyzerMetadata {
  return Object.freeze({ ...value, codeCoverage: Object.freeze({ ...value.codeCoverage,
    languages: Object.freeze([...value.codeCoverage.languages]) }) });
}

const parsedFilesComplete = (check: CheckResult, n: number) =>
  check.metrics?.filesRequested === n && check.metrics?.filesAnalyzed === n && check.metrics?.errorCount === 0;
const requestedFiles = (check: CheckResult) => check.metrics?.filesRequested ?? check.metrics?.files;

export const builtinAstMetadata = provider({
  id: 'builtin_ast', checkId: 'source.builtin-ast', selection: 'always', selected: () => true,
  applicable: snapshot => builtinAstFiles(snapshot).length > 0,
  run: context => context.builtinAst!(),
  codeCoverage: {
    languages: ['javascript', 'typescript'], inputs: builtinAstFiles,
    complete: (check, n) => check.metrics?.filesAnalyzed === n && check.metrics?.filesParseValid === n,
    inputCount: check => check.metrics?.filesAnalyzed,
  },
});

export const banditMetadata = provider({
  id: 'bandit', checkId: 'source.bandit', selection: 'tool', tool: 'bandit',
  selected: options => options.tools.includes('bandit'), applicable: snapshot => pythonFiles(snapshot).length > 0,
  executable: options => options.toolPaths?.bandit ?? 'bandit', stage: 'python',
  stageFailure: 'The bounded Python snapshot could not be staged for Bandit.',
  failureMessage: 'Bandit scanning could not be completed.',
  notApplicable: () => empty('bandit', 'No allowlisted Python file was available for Bandit.', { files: 0 }),
  run: context => runBandit(toolInput(context)),
  codeCoverage: { languages: ['python'], inputs: pythonFiles,
    complete: parsedFilesComplete, inputCount: requestedFiles },
});

export const nativePreviewMetadata = provider({
  id: 'opengrep_native', checkId: 'source.opengrep.preview', selection: 'native-preview',
  selected: options => options.nativePreview, applicable: snapshot => nativeFiles(snapshot).length > 0,
  run: context => runNativePreview(context.snapshot, context.options),
  codeCoverage: {
    languages: ['javascript', 'typescript', 'python'], inputs: nativeFiles,
    complete: (check, n) => check.metrics?.filesDeclared === n && check.metrics?.filesScanned === n
      && check.metrics?.identityUnchanged === true && check.metrics?.closeConfirmed === true
      && check.metrics?.stageCleanupConfirmed === true,
    inputCount: check => check.metrics?.filesDeclared,
  },
});

export const semgrepMetadata = provider({
  id: 'semgrep', checkId: 'source.semgrep', selection: 'tool', tool: 'semgrep',
  selected: options => options.tools.includes('semgrep'), applicable: snapshot => semgrepFiles(snapshot).length > 0,
  executable: options => options.toolPaths?.semgrep ?? 'semgrep', adapterOwnsPreflight: true,
  notApplicable: () => empty('semgrep', 'No applicable source input was collected.', { files: 0 }),
  run: context => runSemgrep(toolInput(context)),
  codeCoverage: { languages: ['go'], inputs: semgrepFiles,
    complete: parsedFilesComplete, inputCount: requestedFiles },
});

function toolInput(context: AnalyzerRunContext): ToolInput {
  const { snapshot, stageDir, toolPath, timeoutMs, options } = context;
  return { snapshot, stageDir, toolPath, timeoutMs, signal: options.signal };
}
function empty(tool: ToolName, message: string, metrics: Record<string, number | boolean>): CheckResult {
  return { id: `source.${tool}`, status: 'not_applicable', findings: [], notes: [message], metrics };
}
function tool(value: Omit<ToolAnalyzer, 'id' | 'checkId' | 'selection' | 'selected'>): ToolAnalyzer {
  return Object.freeze({ ...value, id: value.tool, checkId: `source.${value.tool}`, selection: 'tool',
    selected: (options: AnalyzerSelection) => options.tools.includes(value.tool) });
}

export const frameworkAnalyzer: SyncAnalyzer = Object.freeze({
  id: 'framework', checkId: 'source.framework', selection: 'always', selected: () => true,
  applicable: frameworkHasApplicableInput, run: (context: AnalyzerRunContext) => runFrameworkRules(context.snapshot),
});
export const gitleaksAnalyzer = tool({
  tool: 'gitleaks', applicable: snapshot => snapshot.files.length > 0,
  executable: options => options.toolPaths?.gitleaks ?? 'gitleaks',
  notApplicable: () => empty('gitleaks', 'No allowlisted source file was available for Gitleaks.', { files: 0 }),
  run: context => context.legacy.gitleaks(toolInput(context)),
});
export const osvAnalyzer = tool({
  tool: 'osv', applicable: osvHasApplicableInput,
  executable: options => options.toolPaths?.osv ?? 'osv-scanner',
  notApplicable: () => empty('osv',
    'No allowlisted dependency manifest or supported lockfile was available for OSV-Scanner.',
    { lockfiles: 0, dependencyManifest: false }),
  run: context => context.legacy.osv({ ...toolInput(context),
    ...(context.options.osvOffline ? { osvOffline: true } : {}) }),
});
export const trivyAnalyzer = tool({
  tool: 'trivy', stage: 'safe-config',
  applicable: snapshot => snapshot.files.some(file => file.category === 'config'
    && trivyInputCandidate(file.path, file.text)),
  executable: options => options.toolPaths?.trivy ?? 'trivy',
  stageFailure: 'The bounded Trivy snapshot could not be staged for Trivy.',
  failureMessage: 'Trivy scanning could not be completed.',
  notApplicable: () => empty('trivy',
    'No supported Dockerfile, Kubernetes manifest, or Terraform configuration was available for Trivy config scanning.',
    { configFiles: 0, blockedConfigFiles: 0 }),
  run: context => context.legacy.trivy({ ...toolInput(context), blockedConfigCount: context.blockedConfigCount }),
});
export const govulncheckAnalyzer = tool({
  tool: 'govulncheck', applicable: govulncheckHasApplicableInput, adapterOwnsPreflight: true,
  executable: options => options.toolPaths?.govulncheck ?? 'govulncheck',
  notApplicable: () => empty('govulncheck', 'No applicable source input was collected.', { files: 0 }),
  run: context => runGovulncheck({ ...toolInput(context), goPath: context.options.goPath,
    moduleCache: context.options.goModuleCache, database: context.options.govulnDatabase,
    buildTags: context.options.goBuildTags }),
});
export const trivyVulnerabilityAnalyzer = tool({
  tool: 'trivy-vuln', applicable: snapshot => snapshot.files.some(file => file.category === 'dependency'),
  adapterOwnsPreflight: true,
  executable: options => options.toolPaths?.['trivy-vuln'] ?? options.toolPaths?.trivy ?? 'trivy',
  notApplicable: () => empty('trivy-vuln', 'No applicable source input was collected.', { files: 0 }),
  run: context => runTrivyVulnerabilities({ ...toolInput(context), cacheDir: context.options.trivyCache,
    offline: context.options.trivyOffline }),
});
