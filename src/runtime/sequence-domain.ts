export type Identity<Tag extends string> = string & { readonly __sequenceIdentity: Tag };
export type Count<Tag extends string> = number & { readonly __sequenceCount: Tag };
export type ScalarType = 'string' | 'number' | 'boolean' | 'null';
export type ScalarValue = string | number | boolean | null;
export type Method = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type SourceKind = 'literal' | 'extracted' | 'actor';
export type Destination =
  | { readonly location: 'body'; readonly pointer: string }
  | { readonly location: 'path' | 'query' | 'header' | 'cookie'; readonly name: string };
export type SequenceScalar =
  | { readonly scalarType: 'string'; readonly value: string }
  | { readonly scalarType: 'number'; readonly value: number }
  | { readonly scalarType: 'boolean'; readonly value: boolean }
  | { readonly scalarType: 'null'; readonly value: null };
export interface ExtractionDeclaration {
  readonly id: Identity<'extraction'>;
  readonly pointer: string;
  readonly scalarType: ScalarType;
  readonly valueType: Identity<'value-type'>;
  readonly maxBytes: Count<'scalar-bytes'>;
}
interface BindingType {
  readonly destination: Destination;
  readonly valueType: Identity<'value-type'>;
  readonly scalarType: ScalarType;
}
export type CandidateBinding = BindingType & (
  | { readonly kind: 'literal'; readonly value: ScalarValue }
  | { readonly kind: 'extracted'; readonly producerOrdinal: number; readonly extractionRef: Identity<'extraction'> }
  | { readonly kind: 'actor'; readonly credentialRef: Identity<'credential'> }
);
export type RequestBinding = Exclude<CandidateBinding, { readonly kind: 'literal' }>
  | (Omit<BindingType, 'scalarType'> & { readonly kind: 'literal' } & SequenceScalar);
export interface SequenceStep {
  readonly ordinal: Count<'ordinal'>;
  readonly dependsOn: readonly Count<'ordinal'>[];
  readonly operationRef: Identity<'operation'>;
  readonly method: Method;
  readonly actorRef: Identity<'actor'>;
  readonly checks: readonly Identity<'check'>[];
  readonly bindings: readonly RequestBinding[];
  readonly extract: readonly ExtractionDeclaration[];
  readonly controlRefs: readonly Identity<'control'>[];
  readonly observationRefs: readonly Identity<'channel'>[];
}
export interface Sequence {
  readonly id: Identity<'sequence'>;
  readonly stateScope: Identity<'state'>;
  readonly steps: readonly SequenceStep[];
}
export interface RuntimeSequencePlan {
  readonly version: 1;
  readonly kind: 'wakeio.runtime-sequence';
  readonly scopeRef: Identity<'scope'>;
  readonly limits: {
    readonly maxPlannedCells: Count<'cells'>;
    readonly maxIterations: Count<'iterations'>;
  };
  readonly sequences: readonly Sequence[];
}
export type CandidateStep = Omit<SequenceStep, 'bindings'> & { readonly bindings: readonly CandidateBinding[] };
export type CandidateSequence = Omit<Sequence, 'steps'> & { readonly steps: readonly CandidateStep[] };
export type SequenceCandidate = Omit<RuntimeSequencePlan, 'sequences'> & {
  readonly sequences: readonly CandidateSequence[];
};
export interface ScopeSlot {
  readonly destination: Destination;
  readonly valueType: string;
  readonly scalarType: ScalarType;
  readonly sourceKinds: readonly SourceKind[];
  readonly required: boolean;
}
export interface ScopeExport {
  readonly id: string;
  readonly pointer: string;
  readonly valueType: string;
  readonly scalarType: ScalarType;
  readonly maxBytes: number;
  readonly transfer: 'same-actor' | 'resource-id';
}
export interface ScopeOperation {
  readonly id: string;
  readonly surfaceRef: string;
  readonly method: Method;
  readonly actorRefs: readonly string[];
  readonly stateScopes: readonly string[];
  readonly checks: readonly string[];
  readonly slots: readonly ScopeSlot[];
  readonly exports: readonly ScopeExport[];
}
export interface ControlCell {
  readonly sequenceId: string;
  readonly ordinal: number;
  readonly checkRef: string;
}
interface ControlScope {
  readonly id: string;
  readonly operationRef: string;
  readonly actorRef: string;
  readonly stateScope: string;
  readonly cells: readonly ControlCell[];
}
export type ScopeControl = ControlScope & (
  | { readonly kind: 'normal' | 'fixed' }
  | { readonly kind: 'interrupted-edge'; readonly producerOrdinal: number; readonly consumerOrdinal: number }
);
/** Trusted owner declarations, never planner authority or credential bodies. */
export interface SequenceScope {
  readonly scopeRef: string;
  readonly stateScopes: readonly string[];
  readonly actors: readonly {
    readonly id: string;
    readonly stateScopes: readonly string[];
    readonly credentials: readonly {
      readonly id: string; readonly valueType: string; readonly scalarType: ScalarType;
    }[];
  }[];
  readonly operations: readonly ScopeOperation[];
  readonly controls: readonly ScopeControl[];
  readonly observationChannels: readonly {
    readonly id: string; readonly operationRefs: readonly string[];
    readonly actorRefs: readonly string[]; readonly stateScopes: readonly string[];
  }[];
  readonly transfers: readonly {
    readonly producerActorRef: string; readonly consumerActorRef: string;
    readonly stateScope: string; readonly valueType: string;
  }[];
}
export interface PlannedCell {
  readonly sequenceId: Identity<'sequence'>;
  readonly ordinal: Count<'ordinal'>;
  readonly surfaceRef: string;
  readonly checkRef: Identity<'check'>;
  readonly actorRef: Identity<'actor'>;
}
export interface SequenceObservationRef {
  readonly runId: string; readonly sequenceId: Identity<'sequence'>;
  readonly stateScope: Identity<'state'>; readonly resetGeneration: Count<'generation'>;
  readonly surfaceRef: string; readonly checkRef: Identity<'check'>; readonly ordinal: Count<'ordinal'>;
  readonly actorRef: Identity<'actor'>; readonly admissionId: string; readonly channelRef: Identity<'channel'>;
  readonly observationId: string; readonly logicalOrdinal: Count<'observation'>;
  readonly evidenceRef: string; readonly contentHash: string;
}
export type SequenceEdge =
  | { readonly kind: 'prerequisite'; readonly producerOrdinal: number; readonly consumerOrdinal: number;
      readonly provenance: 'declared' }
  | { readonly kind: 'binding'; readonly producerOrdinal: number; readonly consumerOrdinal: number;
      readonly extractionRef: Identity<'extraction'>; readonly destination: Destination;
      readonly scalarType: ScalarType; readonly valueType: Identity<'value-type'>;
      readonly provenance: 'declared' | 'inferred'; readonly producerObservation: null;
      readonly consumerObservation: null }
  | { readonly kind: 'binding'; readonly producerOrdinal: number; readonly consumerOrdinal: number;
      readonly extractionRef: Identity<'extraction'>; readonly destination: Destination;
      readonly scalarType: ScalarType; readonly valueType: Identity<'value-type'>;
      readonly provenance: 'observed'; readonly producerObservation: SequenceObservationRef;
      readonly consumerObservation: SequenceObservationRef };
export type IssueCode = 'invalid_shape' | 'input_limit' | 'unsupported_version' | 'duplicate_id'
  | 'invalid_ordinal' | 'step_limit' | 'iteration_limit' | 'cell_limit' | 'scope_mismatch' | 'actor_scope'
  | 'operation_scope' | 'missing_producer' | 'cycle' | 'dependency_order' | 'type_mismatch'
  | 'reference_scope' | 'binding_forbidden' | 'invalid_pointer' | 'extraction_missing' | 'extraction_limit';
export interface IssueLocation {
  readonly field: 'plan' | 'sequence' | 'step' | 'binding' | 'extraction' | 'control' | 'observation';
  readonly sequenceIndex?: number;
  readonly stepIndex?: number;
  readonly bindingIndex?: number;
}
export interface SequenceContractIssue {
  readonly code: IssueCode;
  readonly location: IssueLocation;
}
export class SequenceContractError extends Error implements SequenceContractIssue {
  readonly code: IssueCode;
  readonly location: IssueLocation;
  constructor(code: IssueCode, location: IssueLocation) {
    super(code);
    this.name = 'SequenceContractError';
    this.code = code;
    this.location = Object.freeze({ ...location });
  }
}
export function fail(code: IssueCode, location: IssueLocation): never {
  throw new SequenceContractError(code, location);
}
export function assertNever(value: never): never {
  throw new TypeError('unreachable_sequence_variant');
}
