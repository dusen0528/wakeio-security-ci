import { snapshotJsonData } from '../json-snapshot.js';
import { assertNever, fail } from './sequence-domain.js';
import type { RuntimeSequencePlan, SequenceScope } from './sequence-domain.js';
import { identities, structure } from './sequence-structure.js';
import { cycles, dependencies, order } from './sequence-graph.js';
import { membership, references, slots } from './sequence-authority.js';
import { extractScalar, typedScalar } from './sequence-values.js';

export type {
  RuntimeSequencePlan, SequenceScope, SequenceStep, RequestBinding, ExtractionDeclaration, SequenceScalar,
  SequenceEdge, SequenceObservationRef, PlannedCell, SequenceContractIssue,
} from './sequence-domain.js';
export { SequenceContractError } from './sequence-domain.js';
export const RUNTIME_SEQUENCE_KIND = 'wakeio.runtime-sequence' as const;
export const RUNTIME_SEQUENCE_VERSION = 1 as const;

function freeze(value: unknown): void {
  if (value === null || typeof value !== 'object') return;
  for (const child of Object.values(value)) freeze(child);
  Object.freeze(value);
}
/** All candidate stages complete globally before the next stage begins. No execution capability. */
export function parseRuntimeSequencePlan(raw: unknown, scope: SequenceScope): RuntimeSequencePlan {
  const location = { field: 'plan' } as const;
  const snapshot = snapshotJsonData(raw, () => fail('invalid_shape', location), () => fail('input_limit', location));
  const plan = structure(snapshot);
  identities(plan);
  const resolved = membership(plan, scope);
  dependencies(plan);
  cycles(plan);
  order(plan);
  slots(resolved, scope);
  references(resolved, scope);
  const cells = plan.sequences.reduce((sum, sequence) =>
    sum + sequence.steps.reduce((count, step) => count + step.checks.length, 0), 0);
  if (cells > plan.limits.maxPlannedCells || cells > 4096) fail('cell_limit', location);
  const accepted: RuntimeSequencePlan = { ...plan, sequences: plan.sequences.map(sequence => ({
    ...sequence, steps: sequence.steps.map(step => ({ ...step, bindings: step.bindings.map(binding => {
      switch (binding.kind) {
        case 'literal': return { ...binding, ...typedScalar(binding.value, binding.scalarType,
          { field: 'binding' }) };
        case 'extracted': case 'actor': return binding;
        default: return assertNever(binding);
      }
    }) })),
  })) };
  freeze(accepted);
  return accepted;
}
export const parseSequenceExtraction = extractScalar;
