import type { CheckResult, CodeProvider, ToolName } from '../contracts.js';
import type { AnalyzerProvider } from '../runtime/types.js';
import { builtinAstFiles } from './ast.js';
import { nativeFiles } from './opengrep.js';
import { pythonFiles } from './python.js';
import { semgrepFiles } from './semgrep.js';

type CoverageMetadata = NonNullable<AnalyzerProvider<never>['codeCoverage']>;
export interface CodeAnalyzerMetadata extends Pick<AnalyzerProvider<never>,
  'id' | 'checkId' | 'selection' | 'selected' | 'applicable'> {
  tool?: ToolName;
  codeCoverage: CoverageMetadata & {
    publicId: CodeProvider;
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
  codeCoverage: {
    publicId: 'builtin_ast', languages: ['javascript', 'typescript'], inputs: builtinAstFiles,
    complete: (check, n) => check.metrics?.filesAnalyzed === n && check.metrics?.filesParseValid === n,
    inputCount: check => check.metrics?.filesAnalyzed,
  },
});

export const banditMetadata = provider({
  id: 'bandit', checkId: 'source.bandit', selection: 'tool', tool: 'bandit',
  selected: options => options.tools.includes('bandit'), applicable: snapshot => pythonFiles(snapshot).length > 0,
  codeCoverage: { publicId: 'bandit', languages: ['python'], inputs: pythonFiles,
    complete: parsedFilesComplete, inputCount: requestedFiles },
});

export const nativePreviewMetadata = provider({
  id: 'opengrep_native', checkId: 'source.opengrep.preview', selection: 'native-preview',
  selected: options => !!options.nativePreview, applicable: snapshot => nativeFiles(snapshot).length > 0,
  codeCoverage: {
    publicId: 'opengrep_native', languages: ['javascript', 'typescript', 'python'], inputs: nativeFiles,
    complete: (check, n) => check.metrics?.filesDeclared === n && check.metrics?.filesScanned === n
      && check.metrics?.identityUnchanged === true && check.metrics?.closeConfirmed === true
      && check.metrics?.stageCleanupConfirmed === true,
    inputCount: check => check.metrics?.filesDeclared,
  },
});

export const semgrepMetadata = provider({
  id: 'semgrep', checkId: 'source.semgrep', selection: 'tool', tool: 'semgrep',
  selected: options => options.tools.includes('semgrep'), applicable: snapshot => semgrepFiles(snapshot).length > 0,
  codeCoverage: { publicId: 'semgrep', languages: ['go'], inputs: semgrepFiles,
    complete: parsedFilesComplete, inputCount: requestedFiles },
});
