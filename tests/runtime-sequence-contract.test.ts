import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import {
  parseRuntimeSequencePlan, parseSequenceExtraction, SequenceContractError,
  type SequenceScope, type SequenceContractIssue, type ExtractionDeclaration,
} from '../src/runtime/sequence-contract.js';

type Mutable<T> = T extends readonly (infer U)[] ? Mutable<U>[]
  : T extends object ? { -readonly [K in keyof T]: Mutable<T[K]> } : T;
interface InputStep {
  ordinal: number; dependsOn: number[]; operationRef: string; method: string; actorRef: string;
  checks: string[]; bindings: Record<string, unknown>[]; extract: {
    id: string; pointer: string; scalarType: ExtractionDeclaration['scalarType']; valueType: string; maxBytes: number;
  }[]; controlRefs: string[]; observationRefs: string[];
}
interface InputPlan {
  version: number; kind: string; scopeRef: string; limits: { maxPlannedCells: number; maxIterations: number };
  sequences: { id: string; stateScope: string; steps: InputStep[] }[];
}
const qa: { fixture(): { plan: InputPlan; scope: Mutable<SequenceScope> } } =
  await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/sequence-contract.mjs')).href);
const fixture = qa.fixture;
function step(plan: InputPlan, index = 0) {
  const sequence = plan.sequences[0]; assert.ok(sequence);
  const result = sequence.steps[index]; assert.ok(result); return result;
}
function rejection(issue: SequenceContractIssue, action: () => unknown): void {
  assert.throws(action, error => {
    assert.ok(error instanceof SequenceContractError);
    assert.deepEqual({ code: error.code, location: error.location }, issue);
    assert.equal(error.message, issue.code);
    assert.equal(Object.hasOwn(error, 'cause'), false);
    assert.equal(JSON.stringify(error).includes('HOSTILE_DO_NOT_ECHO'), false);
    return true;
  });
}
const at = { field: 'binding', sequenceIndex: 0, stepIndex: 1, bindingIndex: 0 } as const;
const cases: readonly { name: string; code: SequenceContractIssue['code'];
  location: SequenceContractIssue['location']; mutate(p: InputPlan, s: Mutable<SequenceScope>): void }[] = [
  { name: 'cycle before forward order', code: 'cycle', location: { field: 'sequence', sequenceIndex: 0 },
    mutate: p => { step(p).dependsOn = [1]; } },
  { name: 'executable authority', code: 'binding_forbidden', location: { ...at, stepIndex: 0 },
    mutate: p => { step(p).bindings[0] = { kind: 'javascript', expression: '1+1' }; } },
  { name: 'absent dependency', code: 'missing_producer', location: { field: 'step', sequenceIndex: 0, stepIndex: 1 },
    mutate: p => { step(p, 1).dependsOn = [2]; } },
  { name: 'absent extraction', code: 'missing_producer', location: at,
    mutate: p => { Object.assign(step(p, 1).bindings[0], { extractionRef: 'missing' }); } },
  { name: 'nonancestor producer', code: 'dependency_order', location: at,
    mutate: p => { step(p, 1).dependsOn = []; } },
  { name: 'semantic type swap', code: 'type_mismatch', location: at,
    mutate: p => { Object.assign(step(p, 1).bindings[0], { valueType: 'user-id' }); } },
  { name: 'unknown actor', code: 'actor_scope', location: { field: 'step', sequenceIndex: 0, stepIndex: 1 },
    mutate: p => { step(p, 1).actorRef = 'bob'; } },
  { name: 'wrong method', code: 'operation_scope', location: { field: 'step', sequenceIndex: 0, stepIndex: 1 },
    mutate: p => { step(p, 1).method = 'DELETE'; } },
  { name: 'unknown channel', code: 'reference_scope',
    location: { field: 'observation', sequenceIndex: 0, stepIndex: 1 },
    mutate: p => { step(p, 1).observationRefs = ['forged']; } },
  { name: 'pointer syntax', code: 'invalid_pointer',
    location: { field: 'extraction', sequenceIndex: 0, stepIndex: 0, bindingIndex: 0 },
    mutate: p => { Object.assign(step(p).extract[0], { pointer: '/a~2b' }); } },
  { name: 'iteration bound', code: 'iteration_limit', location: { field: 'plan' },
    mutate: p => { p.limits.maxIterations = 65; } },
  { name: 'declared cell cap', code: 'cell_limit', location: { field: 'plan' },
    mutate: p => { p.limits.maxPlannedCells = 1; } },
  { name: 'required slot', code: 'binding_forbidden', location: { field: 'binding', sequenceIndex: 0, stepIndex: 0 },
    mutate: p => { step(p).bindings = []; } },
  { name: 'duplicate destination', code: 'binding_forbidden', location: { ...at, stepIndex: 0, bindingIndex: 1 },
    mutate: p => { step(p).bindings.push(structuredClone(step(p).bindings[0] ?? {})); } },
  { name: 'closed binding keys', code: 'binding_forbidden', location: { ...at, stepIndex: 0 },
    mutate: p => { Object.assign(step(p).bindings[0], { env: 'HOSTILE_DO_NOT_ECHO' }); } },
  { name: 'true alias end', code: 'invalid_shape', location: { field: 'plan' },
    mutate: p => { p.scopeRef += '\n'; } },
  { name: 'unsupported version', code: 'unsupported_version', location: { field: 'plan' },
    mutate: p => { p.version = 2; } },
  { name: 'scope mismatch', code: 'scope_mismatch', location: { field: 'plan' },
    mutate: p => { p.scopeRef = 'other'; } },
  { name: 'duplicate ordinal', code: 'invalid_ordinal', location: { field: 'sequence', sequenceIndex: 0 },
    mutate: p => { step(p, 1).ordinal = 0; } },
  { name: 'duplicate extraction', code: 'duplicate_id',
    location: { field: 'extraction', sequenceIndex: 0, stepIndex: 0, bindingIndex: 1 },
    mutate: p => { const d = step(p).extract[0]; assert.ok(d); step(p).extract.push({ ...d }); } },
  { name: 'control cell membership', code: 'reference_scope',
    location: { field: 'control', sequenceIndex: 0, stepIndex: 0 },
    mutate: (_p, s) => {
      s.controls[0]?.cells.push({ sequenceId: 'absent', ordinal: 0, checkRef: 'normal-create' });
    } },
];
for (const row of cases) test(`sequence rejects ${row.name} at exact safe location`, () => {
  const { plan, scope } = fixture(); row.mutate(plan, scope);
  rejection({ code: row.code, location: row.location }, () => parseRuntimeSequencePlan(plan, scope));
});
test('sequence detaches and deeply freezes accepted data including inert attack literals', () => {
  const { plan, scope } = fixture();
  const operation = scope.operations[0]; assert.ok(operation);
  const slot = operation.slots[0]; assert.ok(slot); slot.scalarType = 'string';
  Object.assign(step(plan).bindings[0], { scalarType: 'string', value: '${process.env.SECRET}; eval(x)' });
  const parsed = parseRuntimeSequencePlan(plan, scope);
  assert.equal(parsed.sequences.length, 1); assert.equal(parsed.sequences[0]?.steps.length, 2);
  Object.assign(step(plan).bindings[0], { value: 'changed' }); step(plan).dependsOn.push(1);
  const binding = parsed.sequences[0]?.steps[0]?.bindings[0]; assert.ok(binding);
  assert.equal(binding.kind, 'literal');
  assert.ok(Object.isFrozen(parsed) && Object.isFrozen(parsed.sequences[0]?.steps[0]?.bindings[0]?.destination));
  const pending: unknown[] = [parsed];
  while (pending.length) {
    const value = pending.pop();
    if (value !== null && typeof value === 'object') {
      assert.ok(Object.isFrozen(value)); pending.push(...Object.values(value));
    }
  }
  assert.equal(Reflect.set(binding, 'value', 'tamper'), false);
  switch (binding.kind) {
    case 'literal': assert.equal(binding.value, '${process.env.SECRET}; eval(x)'); break;
    default: assert.fail('expected literal');
  }
});
function declaration(pointer = '/id', maxBytes = 4096): ExtractionDeclaration {
  const { plan, scope } = fixture();
  Object.assign(step(plan).extract[0], { pointer, maxBytes });
  const operation = scope.operations[0]; assert.ok(operation);
  Object.assign(operation.exports[0] ?? {}, { pointer, maxBytes });
  const result = parseRuntimeSequencePlan(plan, scope).sequences[0]?.steps[0]?.extract[0];
  assert.ok(result); return result;
}
test('extraction honors escaped segments, scalar roots, canonical array indices and encoded UTF8 limits', () => {
  const dec = declaration();
  for (const [raw, pointer, expected] of [
    ['root', '', 'root'], [{ 'a/b': { '~': 'ok' } }, '/a~1b/~0', 'ok'],
    [['first'], '/0', 'first'], [{ '01': 'object-key' }, '/01', 'object-key'],
  ] as const) assert.deepEqual(parseSequenceExtraction(raw, { ...dec, pointer }),
    { scalarType: 'string', value: expected });
  for (const value of ['a'.repeat(4094), '\u00e9'.repeat(2047)]) {
    assert.equal(parseSequenceExtraction({ id: value }, dec).value, value);
  }
  for (const [raw, pointer, code] of [
    [{}, '/id', 'extraction_missing'], [{ id: 17 }, '/id', 'type_mismatch'],
    [{ id: [] }, '/id', 'type_mismatch'], [['x'], '/01', 'invalid_pointer'],
    [['x'], '/-', 'invalid_pointer'], [['x'], '/9007199254740992', 'invalid_pointer'],
    [{ id: 'a'.repeat(4095) }, '/id', 'extraction_limit'],
    [{ id: '\u00e9'.repeat(2048) }, '/id', 'extraction_limit'],
    [{}, '/constructor', 'invalid_pointer'],
    [{}, '/x'.repeat(17), 'invalid_pointer'], [{}, '/' + 'x'.repeat(512), 'invalid_pointer'],
  ] as const) rejection({ code, location: { field: 'extraction' } },
    () => parseSequenceExtraction(raw, { ...dec, pointer }));
  assert.deepEqual(parseSequenceExtraction(null, { ...dec, pointer: '', scalarType: 'null' }),
    { scalarType: 'null', value: null });
});
test('active and oversized inputs refuse without invoking caller getters or proxy traps', () => {
  const { plan, scope } = fixture(); let fired = 0;
  const active = { ...plan, get sequences() { fired++; return plan.sequences; } };
  const proxy = new Proxy(plan, { ownKeys() { fired++; return []; } });
  for (const raw of [active, proxy, { ...plan, sequences: new Array(1) }, Object.create({ inherited: 1 }),
    { ...plan, version: Infinity }]) rejection({ code: 'invalid_shape', location: { field: 'plan' } },
    () => parseRuntimeSequencePlan(raw, scope));
  assert.equal(fired, 0);
  rejection({ code: 'input_limit', location: { field: 'plan' } },
    () => parseRuntimeSequencePlan({ ...plan, padding: 'x'.repeat(1048576) }, scope));
});
function compact(count: number, stepCount: number, checks: number) {
  const { plan, scope } = fixture(), operation = scope.operations[0]; assert.ok(operation);
  operation.id = 'probe'; operation.method = 'GET'; operation.slots = []; operation.exports = [];
  operation.checks = Array.from({ length: checks }, (_, i) => `check-${i}`); scope.operations = [operation];
  plan.sequences = Array.from({ length: count }, (_, i) => ({ id: `sequence-${i}`, stateScope: 'shop-reset',
    steps: Array.from({ length: stepCount }, (_, ordinal) => ({ ordinal, dependsOn: [], operationRef: 'probe',
      method: 'GET', actorRef: 'alice', checks: [...operation.checks], bindings: [], extract: [],
      controlRefs: [], observationRefs: [] })) }));
  return { plan, scope };
}
test('sequence accepts exact16steps64iterations4096cells and refuses each next boundary', () => {
  const { plan, scope } = compact(16, 16, 16);
  const parsed = parseRuntimeSequencePlan(plan, scope);
  const cells = parsed.sequences.reduce((sum, s) => sum + s.steps.reduce((n, x) => n + x.checks.length, 0), 0);
  assert.equal(cells, 4096);
  const extra = compact(1, 1, 1).plan.sequences[0]; assert.ok(extra); extra.id = 'extra'; plan.sequences.push(extra);
  rejection({ code: 'cell_limit', location: { field: 'plan' } }, () => parseRuntimeSequencePlan(plan, scope));
  const seventeen = compact(1, 17, 1);
  rejection({ code: 'step_limit', location: { field: 'sequence', sequenceIndex: 0 } },
    () => parseRuntimeSequencePlan(seventeen.plan, seventeen.scope));
});
for (const mode of ['membership', 'cycle'] as const) test(
  `whole candidate ${mode} precedence rejects later sequence before earlier pointer semantics`, () => {
  const { plan, scope } = fixture(); Object.assign(step(plan).extract[0], { pointer: '/bad~2' });
  const next = structuredClone(plan.sequences[0]); assert.ok(next); next.id = 'other';
  const nextStep = next.steps[0]; assert.ok(nextStep); plan.sequences.push(next);
  switch (mode) {
    case 'membership':
      nextStep.actorRef = 'absent';
      rejection({ code: 'actor_scope', location: { field: 'step', sequenceIndex: 1, stepIndex: 0 } },
        () => parseRuntimeSequencePlan(plan, scope));
      break;
    case 'cycle':
      nextStep.dependsOn = [0];
      rejection({ code: 'cycle', location: { field: 'sequence', sequenceIndex: 1 } },
        () => parseRuntimeSequencePlan(plan, scope));
      break;
    default: assert.fail(mode satisfies never);
  }
});
const exec = promisify(execFile);
test('identity diagnostics follow step order before later duplicate ordinals', () => {
  const { plan, scope } = fixture(); step(plan).actorRef = 'alice\n'; step(plan, 1).ordinal = 0;
  rejection({ code: 'invalid_shape', location: { field: 'step', sequenceIndex: 0, stepIndex: 0 } },
    () => parseRuntimeSequencePlan(plan, scope));
});
test('real shared driver proves calibrated parser rejection and compiled bindings', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sequence-driver-'));
  try {
    for (const mutate of [undefined, 'cycle', 'executable-binding', 'unknown']) {
      const out = join(directory, mutate ?? 'happy'), args = ['scripts/qa/roadmap.mjs', '--case',
        'sequence-contract', '--out', out, ...(mutate ? ['--mutate', mutate] : [])];
      let code = 0;
      try { await exec(process.execPath, args, { timeout: 20000 }); }
      catch (error) {
        if (!(error instanceof Error && 'code' in error && typeof error.code === 'number')) throw error;
        code = error.code;
      }
      assert.equal(code, mutate ? 2 : 0);
      const read = async (name: string): Promise<Record<string, unknown>> =>
        JSON.parse(await readFile(join(out, name + '.json'), 'utf8'));
      const cleanup = await read('cleanup'); assert.equal(cleanup.confirmed, true);
      if (mutate === 'unknown') { assert.equal(cleanup.scope, 'not_started'); continue; }
      const contract = await read('contract'), wire = await read('wire'), modules = await read('module-bindings');
      assert.equal(contract.expectationMet, true); assert.equal(contract.productionRejected, !!mutate);
      assert.equal(wire.calibration, 1); assert.equal(wire.attempted, mutate ? 0 : 1);
      assert.equal(wire.arrivals, mutate ? 0 : 1); assert.equal(cleanup.portReleased, true);
      assert.ok(Array.isArray(modules.modules)); assert.equal(modules.modules.length, 11);
      for (const entry of modules.modules) {
        assert.equal(entry.sha256, createHash('sha256').update(await readFile(entry.path)).digest('hex'));
      }
    }
  } finally { await rm(directory, { recursive: true }); }
});
