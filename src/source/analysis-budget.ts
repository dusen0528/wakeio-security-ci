import type { AstAnalysisBudget } from '../contracts.js';

const DEFAULT = Object.freeze({ indexWork: 300_000, flowWork: 200_000, nodeVisits: 500_000, functions: 2_000, summaryWork: 5_000, moduleEdges: 2_000, callDepth: 8, aliasSteps: 64, traceSteps: 24 });
const EXTENDED = Object.freeze({ indexWork: 1_200_000, flowWork: 800_000, nodeVisits: 2_000_000, functions: 8_000, summaryWork: 20_000, moduleEdges: 8_000, callDepth: 8, aliasSteps: 64, traceSteps: 24 });
/** Closed, versioned workload selection; no automatic fallback or numeric override. */
export function resolveAnalysisBudget(profile: unknown = 'default'): AstAnalysisBudget {
  if (profile !== 'default' && profile !== 'extended') throw new Error('Analysis profile must be default or extended.');
  return Object.freeze({ revision: 'ast-work-v1', requestedProfile: profile, effectiveProfile: profile, limits: profile === 'default' ? DEFAULT : EXTENDED });
}
const object = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const exactKeys = (x: Record<string, unknown>, keys: string[]) => Object.keys(x).length === keys.length && keys.every(k => Object.hasOwn(x, k));
/** Shape/registry validation only; does not authenticate an external execution. */
export function sanitiseAnalysisBudget(input: unknown): AstAnalysisBudget | undefined {
  if (!object(input) || !exactKeys(input, ['revision', 'requestedProfile', 'effectiveProfile', 'limits']) || input.revision !== 'ast-work-v1'
    || !['default', 'extended'].includes(input.requestedProfile as string) || input.effectiveProfile !== input.requestedProfile || !object(input.limits)) return undefined;
  const expected = resolveAnalysisBudget(input.requestedProfile);
  const limits = input.limits;
  if (!exactKeys(input.limits, Object.keys(expected.limits)) || !Object.entries(expected.limits).every(([k, v]) => Number.isSafeInteger(limits[k]) && limits[k] === v)) return undefined;
  return resolveAnalysisBudget(expected.requestedProfile);
}
export function sameAnalysisBudget(a: AstAnalysisBudget | undefined, b: AstAnalysisBudget | undefined): boolean {
  return !!a && !!b && JSON.stringify(a) === JSON.stringify(b);
}
