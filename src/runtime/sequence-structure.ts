import { binding, closed, extraction, integer, list, object, text } from './sequence-binding.js';
import { assertNever, fail } from './sequence-domain.js';
import type {
  CandidateSequence, CandidateStep, Identity, IssueCode, IssueLocation, Method, SequenceCandidate,
} from './sequence-domain.js';

function boundedList(raw: unknown, bounds: { readonly min: number; readonly max: number;
  readonly code?: IssueCode }, location: IssueLocation): readonly unknown[] {
  const values = list(raw, location);
  if (values.length < bounds.min) fail('invalid_shape', location);
  if (values.length > bounds.max) fail(bounds.code ?? 'invalid_shape', location);
  return values;
}
function refs<Tag extends string>(raw: unknown, minimum: number, location: IssueLocation): readonly Identity<Tag>[] {
  const values = boundedList(raw, { min: minimum, max: 16 }, location).map(value => text<Tag>(value, location));
  if (new Set(values).size !== values.length) fail('invalid_shape', location);
  return values;
}
function method(raw: unknown, location: IssueLocation): Method {
  switch (raw) {
    case 'GET': case 'HEAD': case 'POST': case 'PUT': case 'PATCH': case 'DELETE': return raw;
    default: return fail('invalid_shape', location);
  }
}
function step(raw: unknown, location: IssueLocation): CandidateStep {
  const value = object(raw, location);
  closed(value, ['ordinal', 'dependsOn', 'operationRef', 'method', 'actorRef', 'checks',
    'bindings', 'extract', 'controlRefs', 'observationRefs'], { code: 'invalid_shape', location });
  const dependencies = boundedList(value.dependsOn, { min: 0, max: 15 }, location)
    .map(item => integer<'ordinal'>(item, location));
  if (new Set(dependencies).size !== dependencies.length) fail('invalid_shape', location);
  return {
    ordinal: integer(value.ordinal, location), dependsOn: dependencies,
    operationRef: text(value.operationRef, location), method: method(value.method, location),
    actorRef: text(value.actorRef, location), checks: refs(value.checks, 1, location),
    bindings: boundedList(value.bindings, { min: 0, max: 16 }, location).map((item, bindingIndex) =>
      binding(item, { ...location, field: 'binding', bindingIndex })),
    extract: boundedList(value.extract, { min: 0, max: 16 }, location).map((item, bindingIndex) =>
      extraction(item, { ...location, field: 'extraction', bindingIndex })),
    controlRefs: refs(value.controlRefs, 0, { ...location, field: 'control' }),
    observationRefs: refs(value.observationRefs, 0, { ...location, field: 'observation' }),
  };
}
function sequence(raw: unknown, sequenceIndex: number): CandidateSequence {
  const location = { field: 'sequence', sequenceIndex } as const;
  const value = object(raw, location);
  closed(value, ['id', 'stateScope', 'steps'], { code: 'invalid_shape', location });
  return { id: text(value.id, location), stateScope: text(value.stateScope, location),
    steps: boundedList(value.steps, { min: 1, max: 16, code: 'step_limit' }, location)
      .map((item, stepIndex) => step(item, { field: 'step', sequenceIndex, stepIndex })) };
}
export function structure(raw: unknown): SequenceCandidate {
  const location = { field: 'plan' } as const, value = object(raw, location);
  if (value.kind !== 'wakeio.runtime-sequence' || typeof value.version !== 'number') {
    fail('invalid_shape', location);
  }
  if (value.version !== 1) fail('unsupported_version', location);
  closed(value, ['version', 'kind', 'scopeRef', 'limits', 'sequences'], { code: 'invalid_shape', location });
  const limits = object(value.limits, location);
  closed(limits, ['maxPlannedCells', 'maxIterations'], { code: 'invalid_shape', location });
  const maxPlannedCells = integer<'cells'>(limits.maxPlannedCells, location);
  const maxIterations = integer<'iterations'>(limits.maxIterations, location);
  if (maxPlannedCells < 1 || maxPlannedCells > 4096) fail('cell_limit', location);
  if (maxIterations < 1 || maxIterations > 64) fail('iteration_limit', location);
  return { version: 1, kind: 'wakeio.runtime-sequence', scopeRef: text(value.scopeRef, location),
    limits: { maxPlannedCells, maxIterations },
    sequences: boundedList(value.sequences, { min: 1, max: 256 }, location).map(sequence) };
}
export function alias(value: string, location: IssueLocation): void {
  if (!/^[a-z][a-z0-9_-]{0,39}(?![\s\S])/.test(value)
    || ['__proto__', 'prototype', 'constructor'].includes(value)) fail('invalid_shape', location);
}
export function* steps(plan: SequenceCandidate) {
  for (const [sequenceIndex, sequence] of plan.sequences.entries()) {
    for (const [stepIndex, step] of sequence.steps.entries()) {
      yield { sequence, step, location: { field: 'step', sequenceIndex, stepIndex } as const };
    }
  }
}
export function identities(plan: SequenceCandidate): void {
  alias(plan.scopeRef, { field: 'plan' });
  const sequenceIds = new Set<string>();
  for (const [sequenceIndex, sequence] of plan.sequences.entries()) {
    const location = { field: 'sequence', sequenceIndex } as const;
    alias(sequence.id, location); alias(sequence.stateScope, location);
    if (sequenceIds.has(sequence.id)) fail('duplicate_id', location);
    sequenceIds.add(sequence.id);
    const ordinals = new Set<number>();
    for (const [stepIndex, step] of sequence.steps.entries()) {
      if (ordinals.has(step.ordinal) || step.ordinal < 0 || step.ordinal >= sequence.steps.length) {
        fail('invalid_ordinal', { field: 'sequence', sequenceIndex });
      }
      ordinals.add(step.ordinal);
      const location = { field: 'step', sequenceIndex, stepIndex } as const;
      alias(step.operationRef, location); alias(step.actorRef, location);
      for (const ref of step.checks) alias(ref, location);
      for (const ref of step.controlRefs) alias(ref, { ...location, field: 'control' });
      for (const ref of step.observationRefs) alias(ref, { ...location, field: 'observation' });
      for (const [bindingIndex, binding] of step.bindings.entries()) {
        const at = { ...location, field: 'binding', bindingIndex } as const;
        alias(binding.valueType, at);
        switch (binding.destination.location) {
          case 'body': break;
          case 'path': case 'query': case 'header': case 'cookie': alias(binding.destination.name, at); break;
          default: assertNever(binding.destination);
        }
        switch (binding.kind) {
          case 'actor': alias(binding.credentialRef, at); break;
          case 'extracted': alias(binding.extractionRef, at); break;
          case 'literal': break;
          default: assertNever(binding);
        }
      }
      const ids = new Set<string>();
      for (const [bindingIndex, declaration] of step.extract.entries()) {
        const at = { ...location, field: 'extraction', bindingIndex } as const;
        alias(declaration.id, at); alias(declaration.valueType, at);
        if (ids.has(declaration.id)) fail('duplicate_id', at);
        ids.add(declaration.id);
      }
    }
  }
}
