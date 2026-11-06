import type { DatabaseSync, SQLOutputValue } from 'node:sqlite';
import { DatabaseArtifactError } from '../agent-dast/store-contract.js';
import { RUN_ID, TASK_ID } from '../agent-dast/result.js';
import { SURFACE_ID } from '../agent-dast/store.js';
import { alias as proposalAlias } from './sequence-structure.js';
import { destinationIdentity } from './sequence-values.js';
import { SequenceContractError, assertNever } from './sequence-domain.js';
import type {
  Destination, RuntimeSequencePlan, Sequence, SequenceStep, SequenceObservationRef, SequenceEdge,
} from './sequence-domain.js';
export type SqlRow = Readonly<Record<string, SQLOutputValue>>;
export function invalid(): never { throw new DatabaseArtifactError('invalid_record', 'inspect'); }
function text(value: unknown, maximum: number, pattern?: RegExp): string {
  if (typeof value !== 'string' || Buffer.byteLength(value) < 1 || Buffer.byteLength(value) > maximum
    || /[\x00-\x1f\x7f]/.test(value) || pattern && !pattern.test(value)) return invalid();
  return value;
}
function alias(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try { proposalAlias(value, { field: 'observation' }); return true; }
  catch (error) { if (error instanceof SequenceContractError) return false; throw error; }
}
const sequence = (v: unknown): v is Sequence['id'] => alias(v);
const scope = (v: unknown): v is Sequence['stateScope'] => alias(v);
const actor = (v: unknown): v is SequenceStep['actorRef'] => alias(v);
const operation = (v: unknown): v is SequenceStep['operationRef'] => alias(v);
const check = (v: unknown): v is SequenceObservationRef['checkRef'] => alias(v);
const channel = (v: unknown): v is SequenceObservationRef['channelRef'] => alias(v);
const extraction = (v: unknown): v is Extract<SequenceEdge, {kind:'binding'}>['extractionRef'] => alias(v);
const valueType = (v: unknown): v is Extract<SequenceEdge, {kind:'binding'}>['valueType'] => alias(v);
export function range(value: unknown, minimum: number, maximum: number): boolean {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
const ordinal = (v: unknown): v is SequenceStep['ordinal'] => range(v, 0, 15);
const generation = (v: unknown): v is SequenceObservationRef['resetGeneration'] =>
  range(v, 1, Number.MAX_SAFE_INTEGER);
const logical = (v: unknown): v is SequenceObservationRef['logicalOrdinal'] => range(v, 1, Number.MAX_SAFE_INTEGER);
const iteration = (v: unknown): v is RuntimeSequencePlan['limits']['maxIterations'] => range(v, 1, 64);
function parsed<T>(value: unknown, accepts: (value: unknown) => value is T): T {
  if (!accepts(value)) return invalid();
  return value;
}
export function sqlNumber(value: SQLOutputValue | undefined): SQLOutputValue | undefined {
  return typeof value === 'bigint' ? Number(value) : value;
}
export function member<T extends string>(value: unknown, choices: readonly T[]): T {
  return choices.find(choice => choice === value) ?? invalid();
}
function common(row: SqlRow) {
  return {
    runId: text(row.run_id, 42, RUN_ID),
    sequenceId: parsed(row.sequence_id, sequence),
    resetGeneration: parsed(sqlNumber(row.reset_generation), generation),
    ordinal: parsed(sqlNumber(row.ordinal), ordinal),
    surfaceRef: text(row.surface_id, 62, SURFACE_ID),
    actorRef: parsed(row.actor_ref, actor),
  };
}
export function decodeStep(row: SqlRow) {
  return Object.freeze({
    ...common(row),
    stateScope: parsed(row.state_scope, scope),
    operationRef: parsed(row.operation_ref, operation),
    method: member(row.method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] as const),
    planDigest: text(row.plan_digest, 64, /^[0-9a-f]{64}$/),
  });
}
const reasons = ['cancelled', 'tool_error', 'policy_denied', 'observer_unavailable', 'reset_failed',
  'budget_exhausted', 'iteration_limit', 'no_progress', 'dependency_failed', 'extraction_missing',
  'extraction_limit', 'type_mismatch', 'stale_generation', 'private_value_limit', 'not_applicable',
  'not_observed', 'interrupted'] as const;
export function decodeCell(row: SqlRow) {
  return Object.freeze({
    ...common(row),
    checkRef: parsed(row.check_id, check),
    firstIteration: parsed(sqlNumber(row.first_iteration), iteration),
    planDigest: text(row.plan_digest, 64, /^[0-9a-f]{64}$/),
    executionState: member(row.execution_state,
      ['queued', 'running', 'completed', 'partial', 'error', 'not_applicable', 'skipped'] as const),
    observationOutcome: member(row.observation_outcome, ['observed', 'not_observed', 'unverified'] as const),
    taskId: row.task_id === null ? null : text(row.task_id, 62, TASK_ID),
    reasonCode: row.reason_code === null ? null : member(row.reason_code, reasons),
  });
}
export function decodeObservation(row: SqlRow): SequenceObservationRef {
  return Object.freeze({
    ...common(row),
    checkRef: parsed(row.check_id, check),
    stateScope: parsed(row.state_scope, scope),
    admissionId: text(row.admission_id, 200),
    observationId: text(row.observation_id, 200),
    channelRef: parsed(row.channel_ref, channel),
    logicalOrdinal: parsed(sqlNumber(row.logical_ordinal), logical),
    evidenceRef: text(row.evidence_ref, 200,
      /^evidence\/[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*\.json$/),
    contentHash: text(row.content_hash, 64, /^[0-9a-f]{64}$/),
  });
}
function destination(row: SqlRow): Destination {
  switch (row.destination_location) {
    case 'body': {
      const encoded = text(row.destination_ref, 4096);
      let raw: unknown;
      try { raw = JSON.parse(encoded); }
      catch (error) { if (error instanceof SyntaxError) return invalid(); throw error; }
      if (!Array.isArray(raw) || raw.length !== 2 || raw[0] !== 'body' || !Array.isArray(raw[1])) return invalid();
      const segments: readonly unknown[] = raw[1];
      if (!segments.every((segment): segment is string => typeof segment === 'string')) return invalid();
      const pointer = segments.length ? '/' + segments.map(s =>
        s.replace(/~/g, '~0').replace(/\//g, '~1')).join('/') : '';
      const result = { location: 'body', pointer } as const;
      try { if (destinationIdentity(result, { field: 'binding' }) !== encoded) return invalid(); }
      catch (error) { if (error instanceof SequenceContractError) return invalid(); throw error; }
      return Object.freeze(result);
    }
    case 'path': case 'query': case 'header': case 'cookie': {
      if (!alias(row.destination_ref)) return invalid();
      return Object.freeze({ location: row.destination_location, name: row.destination_ref });
    }
    default: return invalid();
  }
}
function observationById(db: DatabaseSync, runId: string, id: string): SequenceObservationRef {
  const statement = db.prepare('SELECT o.*,s.state_scope FROM observation_refs o LEFT JOIN sequence_steps s'
    + ' ON s.run_id=o.run_id AND s.sequence_id=o.sequence_id AND s.reset_generation=o.reset_generation'
    + ' AND s.ordinal=o.ordinal WHERE o.run_id=? AND o.observation_id=?');
  statement.setReadBigInts(true);
  const row = statement.get(runId, id);
  return row ? decodeObservation(row) : invalid();
}
export function decodeEdge(row: SqlRow, db: DatabaseSync) {
  const runId = text(row.run_id, 42, RUN_ID), sequenceId = parsed(row.sequence_id, sequence);
  const resetGeneration = parsed(sqlNumber(row.reset_generation), generation);
  const producerOrdinal = parsed(sqlNumber(row.producer_ordinal), ordinal);
  const consumerOrdinal = parsed(sqlNumber(row.consumer_ordinal), ordinal);
  if (producerOrdinal >= consumerOrdinal) return invalid();
  const identity = { runId, sequenceId, resetGeneration };
  switch (row.kind) {
    case 'prerequisite':
      if (row.provenance !== 'declared' || row.extraction_ref !== '' || row.destination_location !== ''
        || row.destination_ref !== '' || row.scalar_type !== null || row.value_type !== null
        || row.producer_observation_id !== null || row.consumer_observation_id !== null) return invalid();
      return Object.freeze({ ...identity, kind: 'prerequisite', producerOrdinal, consumerOrdinal,
        provenance: 'declared' } as const);
    case 'binding': {
      const base = { ...identity, kind: 'binding', producerOrdinal, consumerOrdinal,
        extractionRef: parsed(row.extraction_ref, extraction), destination: destination(row),
        valueType: parsed(row.value_type, valueType),
        scalarType: member(row.scalar_type, ['string', 'number', 'boolean', 'null'] as const) } as const;
      const provenance = member(row.provenance, ['declared', 'inferred', 'observed'] as const);
      switch (provenance) {
        case 'declared': case 'inferred':
          if (row.producer_observation_id !== null || row.consumer_observation_id !== null) return invalid();
          return Object.freeze({ ...base, provenance, producerObservation: null, consumerObservation: null });
        case 'observed': {
          const producerObservation = observationById(db, runId, text(row.producer_observation_id, 200));
          const consumerObservation = observationById(db, runId, text(row.consumer_observation_id, 200));
          if ([producerObservation, consumerObservation].some(o => o.sequenceId !== sequenceId
            || o.resetGeneration !== resetGeneration) || producerObservation.ordinal !== producerOrdinal
            || consumerObservation.ordinal !== consumerOrdinal) return invalid();
          return Object.freeze({ ...base, provenance, producerObservation, consumerObservation });
        }
        default: return assertNever(provenance);
      }
    }
    default: return invalid();
  }
}
