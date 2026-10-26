import { nativeDastEngine, nucleiEngine, schemathesisEngine, zapEngine } from '../agent-dast/engine-adapters.js';
import type { RegisteredAttackEngine } from './types.js';
import { banditMetadata, builtinAstMetadata, nativePreviewMetadata, semgrepMetadata,
  type CodeAnalyzerMetadata } from '../source/analyzer-providers.js';
import type { CodeProvider } from '../contracts.js';

/** Static trusted adapters only; plans cannot register or load executable modules. */
export const ATTACK_ENGINES = Object.freeze([
  nativeDastEngine, schemathesisEngine, nucleiEngine, zapEngine,
]);
export type AttackEngineId = typeof ATTACK_ENGINES[number]['id'];

export function attackEngine(id: unknown): RegisteredAttackEngine {
  const engine = ATTACK_ENGINES.find(candidate => candidate.id === id);
  if (!engine) throw new TypeError('invalid_execution_plan');
  return engine;
}

/** Coverage metadata is shared by generation, strict v1 parsing and consistency checks. */
export const CODE_ANALYZERS = Object.freeze([
  builtinAstMetadata, banditMetadata, nativePreviewMetadata, semgrepMetadata,
]);

export function codeAnalyzer(id: CodeProvider): CodeAnalyzerMetadata {
  const analyzer = CODE_ANALYZERS.find(candidate => candidate.codeCoverage.publicId === id);
  if (!analyzer) throw new TypeError('invalid_code_provider');
  return analyzer;
}
