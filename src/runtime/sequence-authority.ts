import { assertNever, fail } from './sequence-domain.js';
import type {
  CandidateBinding, CandidateSequence, CandidateStep, IssueLocation, ScopeOperation, SequenceCandidate, SequenceScope,
} from './sequence-domain.js';
import { destinationIdentity, overlap, pointerSegments, scalarBytes, typedScalar } from './sequence-values.js';

interface ResolvedStep {
  readonly sequence: CandidateSequence;
  readonly step: CandidateStep;
  readonly operation: ScopeOperation;
  readonly location: IssueLocation;
}
export function membership(plan: SequenceCandidate, scope: SequenceScope): readonly ResolvedStep[] {
  if (plan.scopeRef !== scope.scopeRef) fail('scope_mismatch', { field: 'plan' });
  const resolved: ResolvedStep[] = [];
  for (const [sequenceIndex, sequence] of plan.sequences.entries()) {
    if (!scope.stateScopes.includes(sequence.stateScope)) {
      fail('scope_mismatch', { field: 'sequence', sequenceIndex });
    }
    for (const [stepIndex, step] of sequence.steps.entries()) {
      const location = { field: 'step', sequenceIndex, stepIndex } as const;
      const actor = scope.actors.find(actor => actor.id === step.actorRef);
      if (!actor?.stateScopes.includes(sequence.stateScope)) fail('actor_scope', location);
      const operation = scope.operations.find(operation => operation.id === step.operationRef);
      if (!operation || operation.method !== step.method) fail('operation_scope', location);
      if (!operation.actorRefs.includes(step.actorRef) || !operation.stateScopes.includes(sequence.stateScope)) {
        fail('actor_scope', location);
      }
      resolved.push({ sequence, step, operation, location });
    }
  }
  return resolved;
}
function bindingSource(binding: CandidateBinding, context: ResolvedStep, scope: SequenceScope): void {
  const location = context.location;
  switch (binding.kind) {
    case 'literal':
      scalarBytes(typedScalar(binding.value, binding.scalarType, location), 4096, location);
      return;
    case 'actor': {
      const actor = scope.actors.find(actor => actor.id === context.step.actorRef);
      const credential = actor?.credentials.find(credential => credential.id === binding.credentialRef);
      if (!credential) fail('actor_scope', location);
      if (credential.valueType !== binding.valueType || credential.scalarType !== binding.scalarType) {
        fail('type_mismatch', location);
      }
      return;
    }
    case 'extracted': {
      const producer = context.sequence.steps.find(step => step.ordinal === binding.producerOrdinal);
      const declaration = producer?.extract.find(item => item.id === binding.extractionRef);
      if (!producer || !declaration) fail('missing_producer', location);
      if (declaration.valueType !== binding.valueType || declaration.scalarType !== binding.scalarType) {
        fail('type_mismatch', location);
      }
      if (producer.actorRef !== context.step.actorRef) {
        const operation = scope.operations.find(operation => operation.id === producer.operationRef);
        const exported = operation?.exports.find(item => item.id === declaration.id);
        if (exported?.transfer !== 'resource-id' || scope.actors.some(actor =>
          actor.credentials.some(credential => credential.valueType === binding.valueType))
          || !scope.transfers.some(grant =>
          grant.producerActorRef === producer.actorRef && grant.consumerActorRef === context.step.actorRef
          && grant.stateScope === context.sequence.stateScope && grant.valueType === binding.valueType)) {
          fail('actor_scope', location);
        }
      }
      return;
    }
    default: return assertNever(binding);
  }
}
export function slots(resolved: readonly ResolvedStep[], scope: SequenceScope): void {
  for (const context of resolved) {
    const identities = new Set<string>(), destinations = [];
    for (const [bindingIndex, binding] of context.step.bindings.entries()) {
      const location = { ...context.location, field: 'binding', bindingIndex } as const;
      const identity = destinationIdentity(binding.destination, location);
      if (identities.has(identity)) fail('binding_forbidden', location);
      identities.add(identity); destinations.push(binding.destination); overlap(destinations, location);
      const slot = context.operation.slots.find(slot => destinationIdentity(slot.destination, location) === identity);
      if (!slot || !slot.sourceKinds.includes(binding.kind)
        || slot.sourceKinds.includes('actor') && binding.kind !== 'actor') fail('binding_forbidden', location);
      if (slot.valueType !== binding.valueType || slot.scalarType !== binding.scalarType) {
        fail('type_mismatch', location);
      }
      bindingSource(binding, { ...context, location }, scope);
    }
    for (const slot of context.operation.slots) {
      if (slot.required && !identities.has(destinationIdentity(slot.destination, context.location))) {
        fail('binding_forbidden', { ...context.location, field: 'binding' });
      }
    }
    for (const [bindingIndex, declaration] of context.step.extract.entries()) {
      const location = { ...context.location, field: 'extraction', bindingIndex } as const;
      const pointer = JSON.stringify(pointerSegments(declaration.pointer, location));
      const exported = context.operation.exports.find(item => item.id === declaration.id);
      if (!exported || JSON.stringify(pointerSegments(exported.pointer, location)) !== pointer) {
        fail('binding_forbidden', location);
      }
      if (exported.valueType !== declaration.valueType || exported.scalarType !== declaration.scalarType) {
        fail('type_mismatch', location);
      }
      if (declaration.maxBytes > exported.maxBytes) fail('extraction_limit', location);
    }
  }
}
export function references(resolved: readonly ResolvedStep[], scope: SequenceScope): void {
  for (const context of resolved) {
    const { step, sequence, operation } = context;
    if (step.checks.some(check => !operation.checks.includes(check))) fail('reference_scope', context.location);
    for (const ref of step.controlRefs) {
      const location = { ...context.location, field: 'control' } as const;
      const control = scope.controls.find(control => control.id === ref);
      if (!control || control.operationRef !== step.operationRef || control.actorRef !== step.actorRef
        || control.stateScope !== sequence.stateScope || !control.cells.length) fail('reference_scope', location);
      for (const cell of control.cells) {
        const target = resolved.find(item => item.sequence.id === cell.sequenceId
          && item.step.ordinal === cell.ordinal && item.step.checks.some(check => check === cell.checkRef));
        if (!target || target.step.operationRef !== control.operationRef
          || target.step.actorRef !== control.actorRef || target.sequence.stateScope !== control.stateScope) {
          fail('reference_scope', location);
        }
        switch (control.kind) {
          case 'normal': case 'fixed': break;
          case 'interrupted-edge': {
            const consumer = target.sequence.steps.find(item => item.ordinal === control.consumerOrdinal);
            if (!consumer?.dependsOn.some(ordinal => ordinal === control.producerOrdinal)) {
              fail('reference_scope', location);
            }
            break;
          }
          default: assertNever(control);
        }
      }
    }
    for (const ref of step.observationRefs) {
      const channel = scope.observationChannels.find(channel => channel.id === ref);
      if (!channel || !channel.operationRefs.includes(step.operationRef)
        || !channel.actorRefs.includes(step.actorRef) || !channel.stateScopes.includes(sequence.stateScope)) {
        fail('reference_scope', { ...context.location, field: 'observation' });
      }
    }
  }
}
