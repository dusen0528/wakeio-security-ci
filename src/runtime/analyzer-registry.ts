import { banditMetadata, builtinAstMetadata, nativePreviewMetadata, semgrepMetadata,
  frameworkAnalyzer, gitleaksAnalyzer, osvAnalyzer, trivyAnalyzer, govulncheckAnalyzer, trivyVulnerabilityAnalyzer,
  type CodeAnalyzerMetadata, type SourceAnalyzer, type ToolAnalyzer, type SyncAnalyzer,
} from '../source/analyzer-providers.js';
import type { CodeProvider, ToolName } from '../contracts.js';

/** Coverage metadata is shared by generation, strict v1 parsing and consistency checks. */
export const CODE_ANALYZERS = Object.freeze([
  builtinAstMetadata, banditMetadata, nativePreviewMetadata, semgrepMetadata,
]);

export function codeAnalyzer(id: CodeProvider): CodeAnalyzerMetadata {
  const analyzer = CODE_ANALYZERS.find(candidate => candidate.id === id);
  if (!analyzer) throw new TypeError('invalid_code_provider');
  return analyzer;
}

/** Registration is static; source options only select these trusted descriptors. */
export const ANALYZERS: readonly SourceAnalyzer[] = Object.freeze([
  builtinAstMetadata, frameworkAnalyzer, nativePreviewMetadata, gitleaksAnalyzer, osvAnalyzer,
  trivyAnalyzer, banditMetadata, semgrepMetadata, govulncheckAnalyzer, trivyVulnerabilityAnalyzer,
]);
export const SYNC_ANALYZERS = Object.freeze(ANALYZERS.filter(
  (analyzer): analyzer is SyncAnalyzer => analyzer.selection === 'always',
));
export function sourceAnalyzer(id: unknown): SourceAnalyzer {
  const analyzer = ANALYZERS.find(candidate => candidate.id === id);
  if (!analyzer) throw new TypeError('invalid_source_analyzer');
  return analyzer;
}
export function isSourceTool(id: unknown): id is ToolName {
  return ANALYZERS.some(analyzer => analyzer.selection === 'tool' && analyzer.tool === id);
}
export function toolAnalyzer(id: ToolName): ToolAnalyzer {
  const analyzer = sourceAnalyzer(id);
  if (analyzer.selection !== 'tool') throw new TypeError('invalid_source_tool');
  return analyzer as ToolAnalyzer;
}
