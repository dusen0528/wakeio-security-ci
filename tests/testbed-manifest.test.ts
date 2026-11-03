import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import fixture from '../benchmarks/testbeds/manifest.json' with { type: 'json' };

const root = fileURLToPath(new URL('../../', import.meta.url));
const validator = await import(new URL('../../scripts/testbed-manifest.mjs', import.meta.url).href);
const exec = promisify(execFile);
const fresh = () => structuredClone(fixture);

test('evaluator resolves real local and immutable Git pins without promoting unavailable prerequisites', async () => {
  const loaded = await validator.loadManifest();
  assert.equal(loaded.data.schema, 'wakeio.testbed/v1');
  assert.equal(loaded.data.scope, 'partial-not-representative-accuracy');
  assert.equal(loaded.data.prerequisites.every((p: { readonly status: string }) => p.status === 'unavailable'), true);
  assert.match(loaded.sha256, /^[a-f0-9]{64}$/);
});

const invalid = [
  { name: 'empty truth', change: (data: typeof fixture) => ({ ...data, targets: [{ ...data.targets[0], truth: [] }] }), reason: /schema_array/ },
  { name: 'duplicate unit despite different metadata', change: (data: typeof fixture) => {
    const target = data.targets[0];
    return { ...data, targets: [{ ...target, truth: [...target.truth, { ...target.truth[0], knownMiss: 'different explanation' }] }] };
  }, reason: /duplicate_truth_unit/ },
  { name: 'unpinned image', change: (data: typeof fixture) => ({ ...data, targets: [{ ...data.targets[0], image: 'node:latest' }] }), reason: /schema_string/ },
  { name: 'missing pin reference', change: (data: typeof fixture) => ({ ...data, privateFiles: data.privateFiles.slice(1) }), reason: /missing_pin/ },
  { name: 'undeclared actor', change: (data: typeof fixture) => {
    const target = data.targets[0];
    return { ...data, targets: [{ ...target, truth: [{ ...target.truth[0], actor: 'unknown' }] }] };
  }, reason: /unknown_actor/ },
  { name: 'missing paired variant expectation', change: (data: typeof fixture) => {
    const target = data.targets[0];
    return { ...data, targets: [{ ...target, truth: [{ ...target.truth[0], singleSite: { vulnerable: true, other: false } }] }] };
  }, reason: /variant_expectations/ },
  { name: 'extra nested field', change: (data: typeof fixture) => {
    const target = data.targets[0];
    return { ...data, targets: [{ ...target, seed: { ...target.seed, payload: 'private' } }] };
  }, reason: /schema_unknown/ },
  { name: 'escaping pin path', change: (data: typeof fixture) => ({ ...data, privateFiles: [{ ...data.privateFiles[0], path: 'benchmarks/../manifest.json' }] }), reason: /invalid_pin_path/ },
];
for (const row of invalid) test(`manifest rejects ${row.name}`, () => {
  assert.throws(() => validator.parseManifest(row.change(fresh())), row.reason);
});

for (const field of ['cwe', 'input', 'actor', 'operation', 'chain'] as const) {
  test(`truth identity distinguishes ${field} without changing the other identity fields`, () => {
    const data = fresh(), target = data.targets[0], original = target.truth[0];
    const changed = {
      ...original,
      ...(field === 'cwe' ? { cwe: 'CWE-90' } : {}),
      ...(field === 'input' ? { input: 'query:other' } : {}),
      ...(field === 'actor' ? { actor: 'other-user' } : {}),
      ...(field === 'operation' ? { operation: 'POST /rest/products/search' } : {}),
      ...(field === 'chain' ? { chain: { id: 'causal-chain', expected: { vulnerable: true, fixed: false }, steps: ['POST /stored', 'GET /rendered'],
        edges: [{ producer: 0, consumer: 1, binding: 'stored-object-id', interruptedControl: 'GET /fixed-rendered' }] } } : {}),
    };
    const candidate = { ...data, targets: [{ ...target, actors: [...target.actors, 'other-user'],
      operations: [...target.operations, 'POST /rest/products/search'], truth: [...target.truth, changed] }] };
    assert.doesNotThrow(() => validator.parseManifest(candidate));
  });
}

for (const edges of [
  [{ producer: 1, consumer: 1, binding: 'same-state', interruptedControl: 'GET /fixed' }],
  [{ producer: 0, consumer: 2, binding: 'same-state', interruptedControl: 'GET /fixed' }],
  [{ producer: 0, consumer: 1, binding: 'same-state' }],
]) test(`chain rejects invalid causal edge ${JSON.stringify(edges)}`, () => {
  const data = fresh(), target = data.targets[0];
  const truth = { ...target.truth[0], chain: { id: 'chain', expected: { vulnerable: true, fixed: false }, steps: ['POST /producer', 'GET /consumer'], edges } };
  assert.throws(() => validator.parseManifest({ ...data, targets: [{ ...target, truth: [truth] }] }), /invalid_causal_edge|schema_required/);
});

test('scanner projection excludes evaluator payloads and takes operations from public inventory, not truth', () => {
  const data = fresh(), target = data.targets[0];
  const privateTruth = { ...target.truth[0], knownMiss: 'synthetic-private-miss',
    input: 'synthetic-private-payload', normalControl: { ...target.truth[0].normalControl, input: 'synthetic-private-control' } };
  const candidate = validator.parseManifest({ ...data, targets: [{ ...target,
    operations: [...target.operations, 'GET /public-unscored-operation'], truth: [privateTruth] }] });
  const projected = validator.scannerInput(candidate);
  assert.deepEqual(projected, { schema: 'wakeio.testbed-input/v1', targets: [{
    id: target.id, version: target.version, image: target.image, service: target.service, actors: target.actors,
    operations: ['GET /rest/products/search', 'GET /public-unscored-operation'],
  }] });
  assert.equal(JSON.stringify(projected).includes('synthetic-private'), false);
});

test('CLI fails closed for malformed JSON, stale bytes, bad flags and symlink inputs', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'testbed-contract-'));
  const script = join(root, 'scripts/testbed-manifest.mjs');
  const rejects = async (argv: readonly string[], reason: RegExp) => {
    await assert.rejects(exec(process.execPath, [script, ...argv], { cwd: root }), error => {
      assert.ok(error instanceof Error && 'code' in error && 'stderr' in error);
      assert.equal(error.code, 2);
      assert.match(String(error.stderr), reason);
      return true;
    });
  };
  try {
    const malformed = join(temporary, 'malformed.json');
    await writeFile(malformed, '{');
    await rejects(['--manifest', malformed], /"status":"fail"/);
    const data = fresh();
    data.privateFiles[0].sha256 = '0'.repeat(64);
    const stale = join(temporary, 'stale.json');
    await writeFile(stale, JSON.stringify(data));
    await rejects(['--manifest', stale], /stale_pin/);
    await rejects(['--dry-run', 'success'], /invalid_arguments/);
    const alias = join(temporary, 'alias.json');
    await symlink(join(root, 'benchmarks/testbeds/manifest.json'), alias);
    await rejects(['--manifest', alias], /unsafe_file/);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test('CLI creates only the public input while evaluator metadata stays separately readable', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'testbed-input-'));
  try {
    const input = join(temporary, 'input.mjs');
    const { stdout } = await exec(process.execPath, [join(root, 'scripts/testbed-manifest.mjs'), '--scanner-out', input], { cwd: root });
    assert.equal(JSON.parse(stdout).status, 'pass');
    const bytes = await readFile(input, 'utf8');
    assert.equal((await import(pathToFileURL(input).href)).inventory.schema, 'wakeio.testbed-input/v1');
    assert.equal(bytes.includes('privateFiles'), false);
    assert.equal(bytes.includes('CWE-'), false);
    assert.equal(JSON.parse(await readFile(join(root, 'benchmarks/testbeds/manifest.json'), 'utf8')).targets[0].truth[0].cwe, 'CWE-89');
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
