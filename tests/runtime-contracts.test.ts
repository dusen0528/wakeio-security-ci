import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile }
  from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertRuntimeScopeLocation, createArtifactVault } from '../src/runtime/artifacts.js';
import type { Report, RuntimeReport } from '../src/contracts.js';
import type { ArtifactRef, ArtifactVault, RequestCoverage, Stage, StageBinding } from '../src/runtime/types.js';

const digest = (value: string) => createHash('sha256').update(value).digest('hex');
async function fixture(run: (base: string, source: string, vault: ArtifactVault) => Promise<void>) {
  const base = await mkdtemp(join(tmpdir(), 'wakeio-runtime-contract-')), source = join(base, 'source');
  try {
    await mkdir(source); await run(base, source, await createArtifactVault(source, join(base, 'vault')));
  } finally { await rm(base, { recursive: true, force: true }); }
}
const stage = (inputs: ArtifactRef[] = []): Stage<unknown> => ({
  schema: 'wakeio.verify-stage/v1', stage: 'prepare', runId: 'r-owned', epoch: 'e-owned', runNonce: 'n-owned',
  inputs, output: { retained: true }, status: 'completed', gaps: [],
});
const binding = (value: Stage<unknown>): StageBinding => ({ stage: value.stage, runId: value.runId,
  epoch: value.epoch, runNonce: value.runNonce, inputs: value.inputs });

test('artifact vault creates private immutable files and verifies raw bytes', async () => fixture(async (_, __, v) => {
  assert.equal((await lstat(v.root)).mode & 0o777, 0o700);
  const bytes = Buffer.from('owned\n'), ref = await v.writeBytes('01-input.json', bytes);
  assert.equal((await lstat(join(v.root, ref.path))).mode & 0o777, 0o600);
  assert.equal(ref.bytes, 6); assert.equal(ref.sha256, digest('owned\n'));
  assert.deepEqual(await v.readBytes(ref), bytes);
  await assert.rejects(v.writeBytes(ref.path, Buffer.from('replacement')), /invalid_runtime_artifact/);
  assert.equal((await v.readBytes(ref)).toString(), 'owned\n');
  assert.deepEqual(await readdir(v.root), [ref.path]);
}));

test('vault refuses source-contained, existing and linked output ancestors before publication', async () => {
  await fixture(async (base, source, v) => {
    await assert.rejects(createArtifactVault(source, join(source, 'inside')), /invalid_runtime_artifact/);
    await assert.rejects(createArtifactVault(source, source), /invalid_runtime_artifact/);
    await assert.rejects(createArtifactVault(source, v.root), /invalid_runtime_artifact/);
    await symlink(base, join(base, 'alias'));
    await assert.rejects(createArtifactVault(source, join(base, 'alias', 'escape')), /invalid_runtime_artifact/);
    await symlink(source, join(base, 'source-alias'));
    await assert.rejects(createArtifactVault(join(base, 'source-alias'), join(base, 'new')),
      /invalid_runtime_artifact/);
    assert.deepEqual(await readdir(source), []);
  });
});

test('artifact paths, keys, getters and proxies grant no file authority', async () => fixture(async (_, __, v) => {
  const ref = await v.writeBytes('owned.json', Buffer.from('x')); let calls = 0;
  for (const path of ['../escape', '/absolute', 'nested/file', './owned.json', 'a\\b', 'C:drive', ' white', '.']) {
    await assert.rejects(v.readBytes({ ...ref, path }), /invalid_runtime_artifact/);
    await assert.rejects(v.writeBytes(path, Buffer.from('x')), /invalid_runtime_artifact/);
  }
  await assert.rejects(v.readBytes(Object.assign({}, ref, { executable: 'unapproved' })), /invalid_runtime_artifact/);
  const accessor = Object.defineProperty({ ...ref }, 'sha256', { get() { calls++; return ref.sha256; } });
  await assert.rejects(v.readBytes(accessor));
  await assert.rejects(v.readBytes(new Proxy(ref, { get() { calls++; throw Error('must_not_run'); } })));
  const bytes = new Uint8Array([1, 2]);
  Object.defineProperty(bytes, 'byteLength', { get() { calls++; throw Error('must_not_run'); } });
  Object.defineProperty(bytes, 'length', { get() { calls++; throw Error('must_not_run'); } });
  assert.equal((await v.writeBytes('intrinsic-bytes', bytes)).bytes, 2);
  await assert.rejects(v.writeBytes('proxy-bytes', new Proxy(bytes, {})));
  assert.equal(calls, 0);
}));

test('links, directories and FIFOs cannot be read as artifacts', async () => fixture(async (base, _, v) => {
  const outside = join(base, 'outside'); await writeFile(outside, 'owned', { mode: 0o600 });
  await symlink(outside, join(v.root, 'symlink'));
  await link(outside, join(v.root, 'hardlink'));
  await mkdir(join(v.root, 'directory'));
  execFileSync('mkfifo', [join(v.root, 'fifo')]);
  for (const path of ['symlink', 'hardlink', 'directory', 'fifo']) {
    await assert.rejects(v.readBytes({ path, bytes: path === 'fifo' ? 0 : 5, sha256: digest('owned') }),
      /invalid_runtime_artifact/);
  }
  assert.equal(await readFile(outside, 'utf8'), 'owned');
}));

test('size, digest, mode and replaced root mismatches are refused', async () => fixture(async (base, _, v) => {
  const ref = await v.writeBytes('data', Buffer.from('old'));
  await assert.rejects(v.readBytes({ ...ref, bytes: 2 }), /invalid_runtime_artifact/);
  await assert.rejects(v.readBytes({ ...ref, bytes: 64 * 1024 * 1024 + 1 }), /invalid_runtime_artifact/);
  await assert.rejects(v.readBytes({ ...ref, sha256: 'a'.repeat(64) }), /invalid_runtime_artifact/);
  await writeFile(join(v.root, 'data'), 'new');
  await assert.rejects(v.readBytes(ref), /invalid_runtime_artifact/);
  await chmod(join(v.root, 'data'), 0o644);
  await assert.rejects(v.readBytes({ ...ref, sha256: digest('new') }), /invalid_runtime_artifact/);
  await rename(v.root, v.root + '-saved'); await symlink(base, v.root);
  await assert.rejects(v.writeBytes('escape', Buffer.from('x')), /invalid_runtime_artifact/);
  assert.equal((await readdir(base)).includes('escape'), false);
}));

test('stage reads bind identity and ordered inputs and verify transitive raw input hashes', async () => {
  await fixture(async (_, __, v) => {
    const seed = await v.writeBytes('seed', Buffer.from('old'));
    const prepare = stage([seed]), prepareRef = await v.writeStage('01-prepare.json', prepare);
    const build = { ...stage([prepareRef]), stage: 'build' }, buildRef = await v.writeStage('02-build.json', build);
    assert.equal(JSON.stringify((await v.readStage(buildRef, binding(build))).output), '{"retained":true}');
    await assert.rejects(v.readStage(buildRef, { ...binding(build), runNonce: 'another-run' }));
    await assert.rejects(v.readStage(buildRef, { ...binding(build), inputs: [] }));
    await assert.rejects(v.writeStage('foreign.json', { ...stage([prepareRef]), epoch: 'another-epoch' }));
    await assert.rejects(v.writeStage('duplicate.json', stage([seed, seed])));
    await writeFile(join(v.root, 'seed'), 'new');
    await assert.rejects(v.readStage(buildRef, binding(build)), /invalid_runtime_artifact/);
  });
});

test('stage publication snapshots own bounded JSON before asynchronous work', async () => fixture(async (_, __, v) => {
  const original = stage(), promise = v.writeStage('snapshot.json', original);
  original.output = { mutated: true };
  const ref = await promise;
  assert.equal(JSON.stringify((await v.readStage(ref, binding(original))).output), '{"retained":true}');
  await assert.rejects(v.writeStage('oversize.json', { ...stage(), output: 'x'.repeat(1024 * 1024 + 1) }));
  const atLimit = { ...stage(), output: '' };
  atLimit.output = 'x'.repeat(1024 * 1024 - Buffer.byteLength(JSON.stringify(atLimit)));
  await assert.rejects(v.writeStage('newline-over-limit.json', atLimit));
  await assert.rejects(v.writeStage('keys.json', Object.assign(stage(), { provider: 'unapproved' })));
  await assert.rejects(v.writeStage('stage.ndjson', stage()));
  let calls = 0;
  const accessor = Object.defineProperty(stage(), 'output', { get() { calls++; return {}; } });
  await assert.rejects(v.writeStage('getter.json', accessor)); assert.equal(calls, 0);
}));

test('runtime report scope placement rejects mixed input without claiming full report parsing', () => {
  const envelope = { mode: 'runtime', runtime: { revision: 'verify-m1-v1', scope: {} } };
  assert.doesNotThrow(() => assertRuntimeScopeLocation(envelope));
  for (const scope of [{}, null, undefined]) assert.throws(() => assertRuntimeScopeLocation({ ...envelope, scope }));
  assert.throws(() => assertRuntimeScopeLocation({ ...envelope, mode: 'source' }));
  assert.throws(() => assertRuntimeScopeLocation({ mode: 'runtime', runtime: { revision: 'verify-m1-v1' } }));
  let calls = 0;
  assert.throws(() => assertRuntimeScopeLocation(Object.defineProperty({ ...envelope }, 'scope', {
    get() { calls++; return {}; },
  })));
  assert.equal(calls, 0);
});

// Compile-time public union and single-request coverage contracts; never executed.
function concreteTypes(report: RuntimeReport, coverage: RequestCoverage): Report {
  const ordinal: number = coverage.requestOrdinal; void ordinal;
  // @ts-expect-error RuntimeReport has only runtime.scope.
  report.scope = {};
  // @ts-expect-error A coverage barrier never spans several requests.
  coverage.requestOrdinals = [1, 2];
  return report;
}
void concreteTypes;
