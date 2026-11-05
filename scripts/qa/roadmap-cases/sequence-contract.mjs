import assert from 'node:assert/strict';
import { createServer, get } from 'node:http';
import { createServer as portProbe } from 'node:net';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { captureProcess } from './process.mjs';
import { sha256, writeArtifact } from './artifacts.mjs';

const SELF = fileURLToPath(import.meta.url), ROOT = new URL('../../../', import.meta.url);
const privateModules = ['sequence-contract', 'sequence-domain', 'sequence-structure', 'sequence-binding',
  'sequence-graph', 'sequence-authority', 'sequence-values'];
const compiled = [...privateModules.map(name => `runtime/${name}`), 'json-snapshot',
  'agent-dast/plan', 'agent-dast/task-parsers', 'agent-dast/plan-validation'];

/** Public synthetic declarations; used by the real parser child, never evaluator truth. */
export function fixture() {
  const exported = { id: 'order-id', pointer: '/id', scalarType: 'string', valueType: 'order-id', maxBytes: 128 };
  const body = { location: 'body', pointer: '/quantity' }, path = { location: 'path', name: 'id' };
  const create = { id: 'create-order', surfaceRef: 's-create-order', method: 'POST', actorRefs: ['alice'],
    stateScopes: ['shop-reset'], checks: ['normal-create'], slots: [{ destination: body, valueType: 'quantity',
      scalarType: 'number', sourceKinds: ['literal'], required: true }],
    exports: [{ ...exported, transfer: 'same-actor' }] };
  const read = { id: 'read-order', surfaceRef: 's-read-order', method: 'GET', actorRefs: ['alice'],
    stateScopes: ['shop-reset'], checks: ['normal-read'], slots: [{ destination: path, valueType: 'order-id',
      scalarType: 'string', sourceKinds: ['extracted'], required: true }], exports: [] };
  const scope = { scopeRef: 'shop-owner-scope', stateScopes: ['shop-reset'],
    actors: [{ id: 'alice', stateScopes: ['shop-reset'], credentials: [] }], operations: [create, read],
    controls: [create, read].map((op, ordinal) => ({ id: ordinal === 0 ? 'create-live' : 'read-live',
      operationRef: op.id, actorRef: 'alice', stateScope: 'shop-reset', kind: 'normal',
      cells: [{ sequenceId: 'order-read', ordinal, checkRef: op.checks[0] }] })),
    observationChannels: [{ id: 'http-response', operationRefs: [create.id, read.id],
      actorRefs: ['alice'], stateScopes: ['shop-reset'] }], transfers: [] };
  const common = { actorRef: 'alice', observationRefs: ['http-response'] };
  const plan = { version: 1, kind: 'wakeio.runtime-sequence', scopeRef: scope.scopeRef,
    limits: { maxPlannedCells: 4096, maxIterations: 64 }, sequences: [{ id: 'order-read',
      stateScope: 'shop-reset', steps: [
        { ...common, ordinal: 0, dependsOn: [], operationRef: create.id, method: 'POST', checks: create.checks,
          bindings: [{ destination: body, kind: 'literal', valueType: 'quantity', scalarType: 'number', value: 1 }],
          extract: [exported], controlRefs: ['create-live'] },
        { ...common, ordinal: 1, dependsOn: [0], operationRef: read.id, method: 'GET', checks: read.checks,
          bindings: [{ destination: path, kind: 'extracted', valueType: 'order-id', scalarType: 'string',
            producerOrdinal: 0, extractionRef: 'order-id' }], extract: [], controlRefs: ['read-live'] },
      ] }] };
  return { plan: structuredClone(plan), scope: structuredClone(scope) };
}
function request(url) {
  return new Promise((resolve, reject) => {
    const req = get(url, { agent: false, signal: AbortSignal.timeout(5000) }, response => {
      response.on('error', reject);
      response.resume();
      response.once('end', () => response.complete && response.statusCode === 200
        ? resolve() : reject(new Error('witness_response_incomplete')));
    });
    req.once('error', reject);
  });
}
async function child(mutate, origin) {
  if (!['happy', 'cycle', 'executable-binding'].includes(mutate)
    || !/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(origin)) throw new TypeError('invalid_child_arguments');
  const runtime = await import('../../../build/src/runtime/sequence-contract.js');
  const legacy = await import('../../../build/src/agent-dast/plan.js');
  const { plan, scope } = fixture();
  if (mutate === 'cycle') plan.sequences[0].steps[0].dependsOn = [1];
  if (mutate === 'executable-binding') plan.sequences[0].steps[0].bindings = [{
    destination: { location: 'body', pointer: '/quantity' }, kind: 'javascript',
    expression: '1+1', valueType: 'quantity', scalarType: 'number',
  }];
  let attempted = 0;
  try {
    const parsed = runtime.parseRuntimeSequencePlan(plan, scope);
    const old = { version: 1, kind: 'wakeio.execution-plan', origin: 'https://owned.invalid',
      tasks: [{ id: 't-owned', engine: 'native-dast', policy: 'policy', maxRequests: 8 }] };
    assert.deepEqual(legacy.parseExecutionPlan(old), old);
    assert.deepEqual(legacy.parseExecutionInputs({ version: 1, inputs: [] }), { version: 1, inputs: [] });
    assert.throws(() => legacy.parseExecutionPlan(plan), { message: 'invalid_execution_plan' });
    assert.throws(() => runtime.parseRuntimeSequencePlan(old, scope), { code: 'invalid_shape' });
    const secret = randomUUID(), declaration = parsed.sequences[0].steps[0].extract[0];
    const selected = runtime.parseSequenceExtraction({ id: secret }, declaration);
    assert.equal(selected.scalarType, 'string'); assert.equal(selected.value, secret);
    const summary = { sequences: parsed.sequences.length, steps: parsed.sequences[0].steps.length,
      cells: parsed.sequences[0].steps.reduce((sum, step) => sum + step.checks.length, 0) };
    assert.deepEqual(summary, { sequences: 1, steps: 2, cells: 2 });
    attempted++;
    await request(`${origin}/after-parse`);
    const result = { accepted: true, summary, legacyAccepted: true, extractionMatched: true,
      extractionBytes: Buffer.byteLength(JSON.stringify(selected.value)), attempted };
    assert.equal(JSON.stringify(result).includes(secret), false);
    console.log(JSON.stringify(result));
    return 0;
  } catch (error) {
    if (!(error instanceof runtime.SequenceContractError)) throw error;
    console.log(JSON.stringify({ accepted: false, issue: { code: error.code, location: error.location }, attempted }));
    return 2;
  }
}
async function witness() {
  let calibration = 0, arrivals = 0;
  const server = createServer((req, res) => {
    if (req.url === '/calibrate') calibration++;
    else if (req.url === '/after-parse') arrivals++;
    res.writeHead(200); res.end();
  });
  const ready = once(server, 'listening', { signal: AbortSignal.timeout(5000) });
  server.listen(0, '127.0.0.1'); await ready;
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return { origin: `http://127.0.0.1:${address.port}`, port: address.port,
    counts: () => ({ calibration, arrivals }),
    async close() {
      const closed = once(server, 'close', { signal: AbortSignal.timeout(5000) });
      server.close(); server.closeAllConnections(); await closed;
      const probe = portProbe(), listening = once(probe, 'listening', { signal: AbortSignal.timeout(5000) });
      probe.listen(address.port, '127.0.0.1'); await listening;
      const released = once(probe, 'close', { signal: AbortSignal.timeout(5000) });
      probe.close(); await released;
      return true;
    } };
}
async function moduleBindings() {
  const modules = [];
  for (const name of compiled) {
    const path = `build/src/${name}.js`, source = `src/${name}.ts`;
    modules.push({ path, sha256: sha256(await readFile(new URL(path, ROOT))),
      source, sourceSha256: sha256(await readFile(new URL(source, ROOT))) });
  }
  const compiler = JSON.parse(await readFile(new URL('node_modules/typescript/package.json', ROOT), 'utf8'));
  return { modules, compiler: { name: compiler.name, version: compiler.version },
    provenance: 'Actual compiled bytes of fixed child imports and their complete static local dependency graph.' };
}
function expectation(mutate, capture, data, wire) {
  if (capture.reason || capture.truncated || capture.signal || !capture.cleanup.confirmed) return false;
  if (!mutate) return capture.exitCode === 0 && data.accepted === true && data.attempted === 1
    && data.legacyAccepted === true && data.extractionMatched === true && wire.arrivals === 1
    && JSON.stringify(data.summary) === JSON.stringify({ sequences: 1, steps: 2, cells: 2 });
  const issue = mutate === 'cycle' ? { code: 'cycle', location: { field: 'sequence', sequenceIndex: 0 } }
    : { code: 'binding_forbidden', location: { field: 'binding', sequenceIndex: 0, stepIndex: 0, bindingIndex: 0 } };
  return capture.exitCode === 2 && data.accepted === false && data.attempted === 0 && wire.arrivals === 0
    && JSON.stringify(data.issue) === JSON.stringify(issue);
}
export async function runCase({ out, mutate }) {
  if (mutate && !['cycle', 'executable-binding'].includes(mutate)) {
    const cleanup = { confirmed: true, scope: 'not_started', children: [] };
    await writeArtifact(out, 'cleanup.json', cleanup);
    return { status: 'unavailable', artifacts: ['cleanup.json'], cleanup };
  }
  let target, capture, modules, data, failure = null, portReleased = false;
  try {
    modules = await moduleBindings();
    target = await witness();
    await request(`${target.origin}/calibrate`);
    assert.equal(target.counts().calibration, 1);
    capture = await captureProcess(process.execPath, [SELF, '--sequence-child', mutate ?? 'happy', target.origin],
      { timeoutMs: 10000 });
    if (!capture.truncated) data = JSON.parse(capture.stdout);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    failure = error.name;
  } finally {
    if (target) {
      try { portReleased = await target.close(); }
      catch (error) { if (!(error instanceof Error)) throw error; failure = 'cleanup_unconfirmed'; }
    }
  }
  const wire = { ...target?.counts(), attempted: data?.attempted ?? null, scope: 'isolated_qa_continuation_only' };
  const cleanup = { confirmed: (!target || portReleased) && (capture?.cleanup.confirmed ?? true),
    portReleased, port: target?.port ?? null, children: capture ? [capture.cleanup] : [] };
  const expectationMet = !failure && wire.calibration === 1 && cleanup.confirmed
    && !!capture && !!data && expectation(mutate, capture, data, wire);
  const contract = { ...data, productionRejected: expectationMet && !!mutate, expectationMet, failure };
  const status = expectationMet ? mutate ? 'unavailable' : 'pass'
    : failure || !capture || capture.reason || capture.truncated || data?.unavailable || !cleanup.confirmed
      ? 'unavailable' : 'fail';
  const artifacts = [];
  for (const [name, value] of [['process', capture ?? { notStarted: true }], ['contract', contract],
    ['wire', wire], ['module-bindings', modules ?? { unavailable: true }], ['cleanup', cleanup]]) {
    artifacts.push(await writeArtifact(out, `${name}.json`, value));
  }
  return { status, artifacts, cleanup };
}
if (process.argv[1] === SELF && process.argv[2] === '--sequence-child') {
  try { process.exitCode = await child(process.argv[3], process.argv[4]); }
  catch (error) {
    // Private child CLI boundary: never echo exceptions or selected response values.
    console.log(JSON.stringify({ unavailable: true, attempted: 0 }));
    process.exitCode = 2;
  }
}
