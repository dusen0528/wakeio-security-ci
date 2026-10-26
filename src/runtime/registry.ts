import { nativeDastEngine, nucleiEngine, schemathesisEngine, zapEngine } from '../agent-dast/engine-adapters.js';
import type { RegisteredAttackEngine } from './types.js';

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
