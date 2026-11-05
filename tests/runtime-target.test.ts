import assert from 'node:assert/strict';
import test from 'node:test';
import { parseRuntimeYaml, parseTargetSpec, parseTargetYaml } from '../src/runtime/target.js';

const target = () => ({
  version: 1, project: 'owned-project', source: '.',
  build: { kind: 'compose', file: 'compose.json', service: 'app' }, pack: { id: 'spring-boot', version: 1 },
  entry: { port: 8080, health: '/actuator/health', startupTimeoutSec: 180 },
  dependencies: [{ service: 'db', observer: 'pg-log' }], seed: { sql: ['seed/data.sql'], snapshot: 'per-request' },
  scope: { include: ['/api/**'], exclude: [] },
  budget: { maxRequests: 2000, maxMinutes: 15, ratePerSecond: 1 },
});

test('target parsers accept own data and YAML, preserving scalar types without granting execution', () => {
  const original = target(), parsed = parseTargetSpec(original);
  assert.equal(JSON.stringify(parsed), JSON.stringify(original));
  original.build.service = 'mutated'; assert.equal(parsed.build.service, 'app');
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(parseTargetYaml(JSON.stringify(target())).source, '.');
  assert.equal(parseTargetSpec({ ...target(), source: 'services/app' }).source, 'services/app');
  const text = [
    'version: 1', 'project: owned-project', 'source: .',
    'build: {kind: compose, file: compose.json, service: app}',
    'pack: {id: spring-boot, version: 1}',
    'entry: {port: 8080, health: /actuator/health, startupTimeoutSec: 180}',
    'dependencies: [{service: db, observer: pg-log}]',
    'seed: {sql: [seed/data.sql], snapshot: per-request}',
    'scope: {include: [/api/**], exclude: []}',
    'budget: {maxRequests: 2000, maxMinutes: 15, ratePerSecond: 1}',
  ].join('\n');
  assert.equal(JSON.stringify(parseTargetYaml(text)), JSON.stringify(target()));
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
  assert.throws(() => parseRuntimeYaml('x: ' + '\u3042'.repeat(400000)), /invalid_runtime_target/);
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
