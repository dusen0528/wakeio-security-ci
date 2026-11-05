import { assertNever, fail } from './sequence-domain.js';
import type { SequenceCandidate, CandidateSequence } from './sequence-domain.js';
import { steps } from './sequence-structure.js';

export function dependencies(plan: SequenceCandidate): void {
  for (const { sequence, step, location } of steps(plan)) {
    for (const ordinal of step.dependsOn) {
      if (!sequence.steps.some(candidate => candidate.ordinal === ordinal)) fail('missing_producer', location);
    }
    for (const [bindingIndex, binding] of step.bindings.entries()) {
      switch (binding.kind) {
        case 'literal': case 'actor': break;
        case 'extracted': {
          const producer = sequence.steps.find(candidate => candidate.ordinal === binding.producerOrdinal);
          if (!producer?.extract.some(declaration => declaration.id === binding.extractionRef)) {
            fail('missing_producer', { ...location, field: 'binding', bindingIndex });
          }
          break;
        }
        default: assertNever(binding);
      }
    }
  }
}
export function cycles(plan: SequenceCandidate): void {
  for (const [sequenceIndex, sequence] of plan.sequences.entries()) {
    const active = new Set<number>(), visited = new Set<number>();
    const visit = (ordinal: number): void => {
      if (active.has(ordinal)) fail('cycle', { field: 'sequence', sequenceIndex });
      if (visited.has(ordinal)) return;
      active.add(ordinal);
      const step = sequence.steps.find(candidate => candidate.ordinal === ordinal);
      for (const dependency of step?.dependsOn ?? []) visit(dependency);
      active.delete(ordinal); visited.add(ordinal);
    };
    for (const step of sequence.steps) visit(step.ordinal);
  }
}
function ancestors(sequence: CandidateSequence, ordinal: number): ReadonlySet<number> {
  const result = new Set<number>();
  const visit = (current: number): void => {
    const step = sequence.steps.find(candidate => candidate.ordinal === current);
    for (const dependency of step?.dependsOn ?? []) {
      if (!result.has(dependency)) { result.add(dependency); visit(dependency); }
    }
  };
  visit(ordinal);
  return result;
}
export function order(plan: SequenceCandidate): void {
  for (const { sequence, step, location } of steps(plan)) {
    if (step.ordinal !== location.stepIndex || step.dependsOn.some((ordinal, index) =>
      ordinal >= step.ordinal || index > 0 && ordinal <= (step.dependsOn[index - 1] ?? -1))) {
      fail('dependency_order', location);
    }
    const prior = ancestors(sequence, step.ordinal);
    for (const [bindingIndex, binding] of step.bindings.entries()) {
      switch (binding.kind) {
        case 'literal': case 'actor': break;
        case 'extracted':
          if (!prior.has(binding.producerOrdinal)) {
            fail('dependency_order', { ...location, field: 'binding', bindingIndex });
          }
          break;
        default: assertNever(binding);
      }
    }
  }
}
