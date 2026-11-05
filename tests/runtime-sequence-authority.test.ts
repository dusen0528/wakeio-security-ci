import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  parseRuntimeSequencePlan, SequenceContractError, type SequenceScope, type SequenceContractIssue,
} from '../src/runtime/sequence-contract.js';

type Mutable<T> = T extends readonly (infer U)[] ? Mutable<U>[]
  : T extends object ? { -readonly [K in keyof T]: Mutable<T[K]> } : T;
interface Proposal {
  limits: { maxPlannedCells: number };
  sequences: { steps: {
    actorRef: string; bindings: Record<string, unknown>[]; controlRefs: string[];
  }[] }[];
}
const qa: { fixture(): { plan: Proposal; scope: Mutable<SequenceScope> } } =
  await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/sequence-contract.mjs')).href);
function step(plan: Proposal, index: number) {
  const result = plan.sequences[0]?.steps[index]; assert.ok(result); return result;
}
const consumer = { field: 'binding', sequenceIndex: 0, stepIndex: 1, bindingIndex: 0 } as const;
function rejects(issue: SequenceContractIssue, action: () => unknown): void {
  assert.throws(action, error => {
    assert.ok(error instanceof SequenceContractError);
    assert.deepEqual({ code: error.code, location: error.location }, issue);
    assert.equal(error.message, issue.code);
    return true;
  });
}
function transferred() {
  const { plan, scope } = qa.fixture();
  scope.actors.push({ id: 'bob', stateScopes: ['shop-reset'], credentials: [] });
  const read = scope.operations[1], channel = scope.observationChannels[0], control = scope.controls[1];
  assert.ok(read && channel && control);
  read.actorRefs.push('bob'); channel.actorRefs.push('bob'); control.actorRef = 'bob';
  step(plan, 1).actorRef = 'bob';
  const exported = scope.operations[0]?.exports[0]; assert.ok(exported); exported.transfer = 'resource-id';
  scope.transfers.push({ producerActorRef: 'alice', consumerActorRef: 'bob',
    stateScope: 'shop-reset', valueType: 'order-id' });
  return { plan, scope, exported };
}
test('owner resource-ID export and exact actor grant admit cross-actor consumption', () => {
  const { plan, scope } = transferred();
  const accepted = parseRuntimeSequencePlan(plan, scope);
  assert.equal(accepted.sequences[0]?.steps[1]?.actorRef, 'bob');
  assert.deepEqual(accepted.sequences[0]?.steps[1]?.dependsOn, [0]);
});
for (const mode of ['missing-grant', 'same-actor-export', 'wrong-state', 'credential-type'] as const) {
  test(`actor transfer rejects ${mode} even with valid dependency and scalar tags`, () => {
    const { plan, scope, exported } = transferred();
    const grant = scope.transfers[0]; assert.ok(grant);
    switch (mode) {
      case 'missing-grant': scope.transfers = []; break;
      case 'same-actor-export': exported.transfer = 'same-actor'; break;
      case 'wrong-state': grant.stateScope = 'other-state'; break;
      case 'credential-type': {
        const actor = scope.actors[0]; assert.ok(actor);
        actor.credentials.push({ id: 'opaque-session', valueType: 'order-id', scalarType: 'string' });
        break;
      }
      default: assert.fail(mode satisfies never);
    }
    rejects({ code: 'actor_scope', location: consumer }, () => parseRuntimeSequencePlan(plan, scope));
  });
}
function credential() {
  const { plan, scope } = qa.fixture(), actor = scope.actors[0], read = scope.operations[1];
  assert.ok(actor && read);
  actor.credentials.push({ id: 'opaque-session', valueType: 'session', scalarType: 'string' });
  const destination = { location: 'header', name: 'session-slot' } as const;
  read.slots = [{ destination, valueType: 'session', scalarType: 'string',
    sourceKinds: ['actor'], required: true }];
  step(plan, 1).bindings = [{ destination, kind: 'actor', valueType: 'session',
    scalarType: 'string', credentialRef: 'opaque-session' }];
  return { plan, scope, read, destination };
}
test('current actor may bind only its opaque typed credential declaration', () => {
  const { plan, scope } = credential();
  const binding = parseRuntimeSequencePlan(plan, scope).sequences[0]?.steps[1]?.bindings[0];
  assert.ok(binding);
  switch (binding.kind) {
    case 'actor': assert.equal(binding.credentialRef, 'opaque-session'); break;
    default: assert.fail('expected actor binding');
  }
});
for (const mode of ['other-actor', 'literal'] as const) test(`credential slot rejects ${mode} authority`, () => {
  const { plan, scope, read, destination } = credential();
  switch (mode) {
    case 'other-actor':
      Object.assign(step(plan, 1).bindings[0], { credentialRef: 'bob-session' });
      scope.actors.push({ id: 'bob', stateScopes: ['shop-reset'],
        credentials: [{ id: 'bob-session', valueType: 'session', scalarType: 'string' }] });
      rejects({ code: 'actor_scope', location: consumer }, () => parseRuntimeSequencePlan(plan, scope));
      break;
    case 'literal': {
      const slot = read.slots[0]; assert.ok(slot); slot.sourceKinds.push('literal');
      step(plan, 1).bindings = [{ destination, kind: 'literal', valueType: 'session',
        scalarType: 'string', value: 'public-synthetic-not-a-credential' }];
      rejects({ code: 'binding_forbidden', location: consumer }, () => parseRuntimeSequencePlan(plan, scope));
      break;
    }
    default: assert.fail(mode satisfies never);
  }
});
for (const row of [
  { first: '/a~1b', second: '/a/b', accepted: true },
  { first: '/a~1b', second: '/a~1b/c', accepted: false },
  { first: '', second: '/leaf', accepted: false },
  { first: '/a~0b', second: '/a~0b/c', accepted: false },
]) test(`decoded body destinations ${JSON.stringify(row)} use segment identity and prefix overlap`, () => {
  const { plan, scope } = qa.fixture(), operation = scope.operations[0]; assert.ok(operation);
  const slot = operation.slots[0], binding = step(plan, 0).bindings[0]; assert.ok(slot && binding);
  const destinations = [row.first, row.second].map(pointer => ({ location: 'body', pointer } as const));
  operation.slots = destinations.map(destination => ({ ...slot, destination }));
  step(plan, 0).bindings = destinations.map(destination => ({ ...binding, destination }));
  if (row.accepted) assert.equal(parseRuntimeSequencePlan(plan, scope).sequences[0]?.steps[0]?.bindings.length, 2);
  else rejects({ code: 'binding_forbidden',
    location: { field: 'binding', sequenceIndex: 0, stepIndex: 0, bindingIndex: 1 } },
  () => parseRuntimeSequencePlan(plan, scope));
});
for (const valid of [true, false]) test(`interrupted-edge control requires an actual dependency: ${valid}`, () => {
  const { plan, scope } = qa.fixture(), control = scope.controls[1]; assert.ok(control);
  Object.assign(control, { kind: 'interrupted-edge', producerOrdinal: valid ? 0 : 1, consumerOrdinal: 1 });
  if (valid) assert.equal(parseRuntimeSequencePlan(plan, scope).sequences[0]?.steps.length, 2);
  else rejects({ code: 'reference_scope', location: { field: 'control', sequenceIndex: 0, stepIndex: 1 } },
    () => parseRuntimeSequencePlan(plan, scope));
});
test('all slot semantics precede an earlier control reference and candidate capacity', () => {
  const { plan, scope } = qa.fixture(); plan.limits.maxPlannedCells = 1;
  step(plan, 0).controlRefs = ['forged'];
  Object.assign(step(plan, 1).bindings[0], { valueType: 'user-id' });
  rejects({ code: 'type_mismatch', location: consumer }, () => parseRuntimeSequencePlan(plan, scope));
});
test('resolved control scope precedes the final candidate capacity check', () => {
  const { plan, scope } = qa.fixture(); plan.limits.maxPlannedCells = 1;
  step(plan, 0).controlRefs = ['forged'];
  rejects({ code: 'reference_scope', location: { field: 'control', sequenceIndex: 0, stepIndex: 0 } },
    () => parseRuntimeSequencePlan(plan, scope));
});
test('observation channel membership is scoped to the exact actor operation and state', () => {
  const { plan, scope } = qa.fixture(), channel = scope.observationChannels[0]; assert.ok(channel);
  channel.stateScopes = ['other-state'];
  rejects({ code: 'reference_scope', location: { field: 'observation', sequenceIndex: 0, stepIndex: 0 } },
    () => parseRuntimeSequencePlan(plan, scope));
});
