import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile }
  from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertRuntimeScopeLocation, createArtifactVault } from '../src/runtime/artifacts.js';
import { parseRuntimeYaml, parseTargetSpec, parseTargetYaml } from '../src/runtime/target.js';
import targetSchema from '../schemas/target.v1.json' with { type: 'json' };
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

const target = () => ({
  version: 1, project: 'owned-project', source: '.',
  build: { kind: 'compose', file: 'compose.json', service: 'app' }, pack: { id: 'spring-boot', version: 1 },
  entry: { port: 8080, health: '/actuator/health', startupTimeoutSec: 180 },
  dependencies: [{ service: 'db', observer: 'pg-log' }], seed: { sql: ['seed/data.sql'], snapshot: 'per-request' },
  scope: { include: ['/api/**'], exclude: [] as string[] },
  budget: { maxRequests: 2000, maxMinutes: 15, ratePerSecond: 1 },
});

test('target parsers accept own data and YAML, preserving scalar types without granting execution', async () => {
  const original = target(), parsed = parseTargetSpec(original);
  assert.equal(JSON.stringify(parsed), JSON.stringify(original));
  original.build.service = 'mutated'; assert.equal(parsed.build.service, 'app');
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(parseTargetYaml(JSON.stringify(target())).source, '.');
  assert.equal(parseTargetSpec({ ...target(), source: 'services/app' }).source, 'services/app');
  for (const variant of ['vulnerable', 'fixed']) {
    const draft = await readFile(`examples/runtime/spring-sqli/${variant}/wakeio.target.draft.yml`, 'utf8');
    assert.equal(parseTargetYaml(draft).seed.snapshot, 'per-request');
  }
  const yaml = 'version: 1\nproject: owned\nsource: .\n';
  assert.equal(JSON.stringify(parseRuntimeYaml(yaml)), '{"version":1,"project":"owned","source":"."}');
  assert.equal(JSON.stringify(parseRuntimeYaml('value: No')), '{"value":"No"}');
});

test('distinct Target dependencies retain uniqueness and snapshot isolation', () => {
  const original = { ...target(), dependencies: [
    { service: 'db', observer: 'pg-log' }, { service: 'audit-db', observer: 'pg-log' },
  ] };
  const parsed = parseTargetSpec(original);
  assert.deepEqual(parsed.dependencies.map(value => value.service), ['db', 'audit-db']);
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(Object.getPrototypeOf(parsed.dependencies[0]), null);
  assert.notEqual(parsed.dependencies, original.dependencies);
  assert.notEqual(parsed.dependencies[0], original.dependencies[0]);
  assert.equal(parseTargetYaml(JSON.stringify(original)).dependencies.length, 2);
  original.dependencies[0].service = 'changed'; original.dependencies.push({ service: 'later', observer: 'pg-log' });
  assert.deepEqual(parsed.dependencies.map(value => value.service), ['db', 'audit-db']);
  assert.throws(() => parseTargetSpec({ ...target(), dependencies: [
    { service: 'db', observer: 'pg-log' }, { observer: 'pg-log', service: 'db' },
  ] }), /invalid_runtime_target/);
  assert.throws(() => parseTargetSpec({ ...target(), dependencies: [
    { service: 'db', observer: 'pg-log' }, { service: 'app', observer: 'pg-log' },
  ] }), /invalid_runtime_target/);
});

test('ordinary JSON validation bridge cannot bypass own-data rejection or invoke caller hooks', () => {
  let calls = 0;
  const getter = Object.defineProperty(target(), 'toJSON', { get() { calls++; throw Error('must_not_run'); } });
  const nested = Object.defineProperty({ service: 'db', observer: 'pg-log' }, 'toJSON', {
    get() { calls++; throw Error('must_not_run'); },
  });
  const proxy = new Proxy(target(), { ownKeys() { calls++; throw Error('must_not_run'); } });
  for (const input of [getter, proxy, { ...target(), dependencies: [nested] },
    Object.assign(Object.create({ inherited: true }), target()),
    Object.defineProperty(target(), 'hidden', { value: true, enumerable: false }),
    { ...target(), [Symbol('hidden')]: true },
    { ...target(), dependencies: [{ service: 'db', observer: 'pg-log', constructor: 'untrusted' }] },
    JSON.parse(JSON.stringify(target()).replace('"project":', '"__proto__":{},"project":')),
  ]) assert.throws(() => parseTargetSpec(input), /invalid_runtime_target/);
  assert.equal(calls, 0);
});

test('YAML nodes reject duplicate keys, tags, anchors, aliases, merges and multiple documents', () => {
  for (const text of [
    'x: 1\nx: 2', 'x: 1\n"x": 2', 'x: !!str 1', 'x: ! value', 'x: !custom value',
    '!!map {x: 1}', '!!str x: value', 'x: &unused 1', 'x: &a 1\ny: *a', 'x: *missing',
    'x: {<<: {a: 1}}', '"<<": value', 'x: 1\n---\ny: 2', 'x: 1\n...\n---\ny: 2',
    '%YAML 1.1\n---\nx: yes', '%TAG !custom! tag:example.test,2026:\n---\nx: 1',
    '%TAG !! tag:yaml.org,2002:\n---\nx: 1',
    '? [complex, key]\n: value', 'x: [1,', '', '---',
  ]) assert.throws(() => parseRuntimeYaml(text), /invalid_runtime_target/, text);
});

test('YAML rejects interpolation, non-JSON numbers and input byte/depth/node overflows before conversion', () => {
  for (const value of ['${HOME}', '$HOME', '$$${HOME}', '$(command)', '%HOME%']) {
    assert.throws(() => parseRuntimeYaml(JSON.stringify({ value })), /invalid_runtime_target/);
  }
  assert.throws(() => parseRuntimeYaml('value: "\\u0024{HOME}"'));
  for (const text of ['x: .inf', 'x: .nan', 'x: 9007199254740993', '\ud800', '#'.repeat(1024 * 1024 + 1)]) {
    assert.throws(() => parseRuntimeYaml(text), /invalid_runtime_target/);
  }
  assert.throws(() => parseRuntimeYaml('x: ' + 'あ'.repeat(400000)), /invalid_runtime_target/);
  assert.throws(() => parseRuntimeYaml('['.repeat(41) + '0' + ']'.repeat(41)), /invalid_runtime_target/);
  assert.throws(() => parseRuntimeYaml('- 0\n'.repeat(20000)), /invalid_runtime_target/);
  assert.doesNotThrow(() => parseRuntimeYaml('['.repeat(40) + '0' + ']'.repeat(40)));
  // The existing own-data snapshot also bounds the array's own length descriptor.
  assert.throws(() => parseRuntimeYaml('- 0\n'.repeat(19999)));
  assert.equal(Array.isArray(parseRuntimeYaml('- 0\n'.repeat(19998))), true);
});

test('target schema rejects unknown keys, mutation options, implicit defaults and unsupported M1 shapes', () => {
  const valid = target();
  for (const extra of ['accounts', 'login', '$ref', '$async', '$data', 'loadSchema', '__proto__']) {
    assert.throws(() => parseTargetSpec({ ...valid, [extra]: 'untrusted' }), /invalid_runtime_target/);
  }
  for (const key of Object.keys(valid)) {
    const missing: Record<string, unknown> = { ...valid }; delete missing[key];
    assert.throws(() => parseTargetSpec(missing));
  }
  for (const key of ['build', 'pack', 'entry', 'seed', 'scope', 'budget'] as const) {
    assert.throws(() => parseTargetSpec({ ...valid, [key]: { ...valid[key], unknown: true } }));
  }
  for (const input of [
    { ...valid, version: '1' }, { ...valid, build: { ...valid.build, kind: 'dockerfile' } },
    { ...valid, pack: 'spring-boot' }, { ...valid, seed: { ...valid.seed, snapshot: 'per-surface' } },
    { ...valid, dependencies: [{ service: 'db', observer: 'shell', command: 'untrusted' }] },
    { ...valid, dependencies: [valid.dependencies[0], valid.dependencies[0]] },
    { ...valid, dependencies: [{ service: 'app', observer: 'pg-log' }] },
  ]) assert.throws(() => parseTargetSpec(input));
  assert.equal(JSON.stringify(valid), JSON.stringify(target()));
  const pending: unknown[] = [targetSchema];
  while (pending.length) {
    const value = pending.pop(); if (!value || typeof value !== 'object') continue;
    for (const [key, child] of Object.entries(value)) {
      assert.equal(['$async', '$data', 'default'].includes(key), false);
      if (key === '$ref') assert.match(String(child), /^#\//);
      pending.push(child);
    }
  }
});

test('source root dot differs from file paths; paths, IDs and request origins have no escape syntax', () => {
  for (const path of ['.', '..', '../escape', 'a/../b', 'a/./b', '/absolute', '//host', 'C:drive',
    'a\\b', 'a//b', 'a/', '~/file', 'a%2fb', 'a\0b', 'a\nb', 'a\n', '$HOME/file', '-option']) {
    assert.throws(() => parseTargetSpec({ ...target(), build: { ...target().build, file: path } }),
      /invalid_runtime_target/, path);
    assert.throws(() => parseTargetSpec({ ...target(), seed: { ...target().seed, sql: [path] } }),
      /invalid_runtime_target/, path);
    if (path !== '.') assert.throws(() => parseTargetSpec({ ...target(), source: path }),
      /invalid_runtime_target/, path);
  }
  for (const path of ['https://host/path', '//host/path', '/a/../b', '/%2e%2e', '/x?q=1', '/x#f', '/x\n']) {
    assert.throws(() => parseTargetSpec({ ...target(), entry: { ...target().entry, health: path } }));
    assert.throws(() => parseTargetSpec({ ...target(), scope: { include: [path], exclude: [] } }));
  }
  for (const id of ['../module', 'file:///module', 'x\n', '${PACK}', '']) {
    assert.throws(() => parseTargetSpec({ ...target(), pack: { id, version: 1 } }));
  }
  assert.equal(parseTargetSpec({ ...target(), build: { ...target().build, file: '.compose/config.json' } })
    .build.file, '.compose/config.json');
});

test('budget, collection and own-data caps reject overflow, getters and proxies without invoking user code', () => {
  for (const [key, values] of Object.entries({ maxRequests: [0, 2001, 1.5, '1'], maxMinutes: [0, 16],
    ratePerSecond: [0, -1, 1001, Infinity, NaN] })) {
    for (const value of values) assert.throws(() => parseTargetSpec({ ...target(),
      budget: { ...target().budget, [key]: value } }));
  }
  for (const entry of [{ port: 0 }, { port: 65536 }, { startupTimeoutSec: 901 }]) {
    assert.throws(() => parseTargetSpec({ ...target(), entry: { ...target().entry, ...entry } }));
  }
  assert.throws(() => parseTargetSpec({ ...target(), scope: { include: [], exclude: [] } }));
  assert.throws(() => parseTargetSpec({ ...target(), scope: { include: ['/x', '/x'], exclude: [] } }));
  assert.throws(() => parseTargetSpec({ ...target(), seed: { ...target().seed, sql: Array(33).fill('a.sql') } }));
  assert.throws(() => parseTargetSpec({ ...target(), extra: 'x'.repeat(1024 * 1024) }));
  let deep: unknown = 0; for (let i = 0; i < 41; i++) deep = [deep];
  assert.throws(() => parseTargetSpec({ ...target(), extra: deep }));
  assert.throws(() => parseTargetSpec({ ...target(), extra: Array(20000).fill(0) }));
  let calls = 0;
  const getter = Object.defineProperty(target(), 'build', { get() { calls++; return target().build; } });
  const proxy = new Proxy(target(), { get() { calls++; throw Error('must_not_run'); } });
  assert.throws(() => parseTargetSpec(getter)); assert.throws(() => parseTargetSpec(proxy));
  assert.throws(() => parseTargetSpec({ ...target(), build: new Proxy(target().build, {}) }));
  assert.throws(() => parseTargetSpec({ ...target(), build: { ...target().build, toJSON() { calls++; } } }));
  assert.equal(calls, 0);
});

test('raw-named Stage-shaped inputs remain opaque leaves; only .json inputs are interpreted as Stages', async () => {
  await fixture(async (_, __, v) => {
    const foreign = { ...stage([{ path: 'absent', bytes: 1, sha256: digest('x') }]), runNonce: 'foreign' };
    const bytes = Buffer.from(JSON.stringify(foreign));
    const raw = await v.writeBytes('raw-envelope', bytes), json = await v.writeBytes('envelope.json', bytes);
    const root = stage([raw]), ref = await v.writeStage('raw-input.json', root);
    assert.equal((await v.readStage(ref, binding(root))).inputs[0].sha256, raw.sha256);
    await assert.rejects(v.writeStage('json-input.json', stage([json])), /invalid_runtime_artifact/);
  });
});

test('failed vault creation under excessive umask removes only its own empty directory', async () => {
  await fixture(async (base, source) => {
    const destination = join(base, 'umask-vault');
    execFileSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      const { createArtifactVault } = await import(
        ${JSON.stringify(new URL('../src/runtime/artifacts.js', import.meta.url).href)});
      const old = process.umask(0o777);
      try { await assert.rejects(createArtifactVault(process.argv[1], process.argv[2])); }
      finally { process.umask(old); }
    `, source, destination]);
    await assert.rejects(lstat(destination), { code: 'ENOENT' });
  });
});

test('failed vault creation does not remove a racing replacement directory', async () => {
  await fixture(async (base, source) => {
    const destination = join(base, 'race-vault');
    execFileSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import fs from 'node:fs/promises';
      import { syncBuiltinESMExports } from 'node:module';
      import { dirname, basename, join } from 'node:path';
      const path = join(await fs.realpath(dirname(process.argv[2])), basename(process.argv[2]));
      const original = fs.lstat; let count = 0;
      fs.lstat = async (...args) => {
        if (args[0] === path && ++count === 2) {
          await fs.rename(path, path + '-owned'); await fs.mkdir(path, {mode: 0o700});
        }
        return original(...args);
      };
      syncBuiltinESMExports();
      const { createArtifactVault } = await import(
        ${JSON.stringify(new URL('../src/runtime/artifacts.js', import.meta.url).href)});
      await assert.rejects(createArtifactVault(process.argv[1], path));
      assert.ok((await original(path)).isDirectory());
      assert.notEqual((await original(path)).ino, (await original(path + '-owned')).ino);
    `, source, destination]);
    assert.deepEqual(await readdir(destination), []);
    assert.ok((await lstat(destination + '-owned')).isDirectory());
  });
});
