import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { compileFrameworkPack, PACK_COMPILER_REVISION } from '../src/runtime/packs/compile-opengrep.js';
import { parseFrameworkPack, parseFrameworkPackYaml } from '../src/runtime/packs/schema.js';
import packSchema from '../schemas/framework-pack.v1.json' with { type: 'json' };

const pack = () => ({
  id: 'custom-framework', version: 1, languages: ['java', 'kotlin'],
  detect: { anyFile: ['pom.xml', 'module/build.gradle.kts'], contains: ['org.example.framework'] },
  runtime: { profile: 'jvm', env: { FEATURE_ENABLED: 'true' }, defaultPort: 8080, health: '/health' },
  surfaces: [{ provider: 'openapi', paths: ['/api-docs'] }],
  sources: [{ annotation: ['QueryInput', 'BodyInput'] }, { call: ['InputContext.getParameter'] }],
  sinks: { sql: [{ call: ['SqlClient.query', 'SqlClient.execute*'], arg: 0 }] },
  sanitizers: { sql: [] },
});
const encode = (input: unknown) => JSON.stringify(input);
const digest = (text: string) => createHash('sha256').update(text).digest('hex');

test('Pack parser accepts bounded data, snapshots callers and preserves the PLAN field structure', () => {
  const original = pack(), parsed = parseFrameworkPack(original);
  assert.equal(encode(parsed), encode(original)); assert.notEqual(parsed, original);
  original.runtime.env.FEATURE_ENABLED = 'false'; assert.equal(parsed.runtime.env.FEATURE_ENABLED, 'true');
  assert.equal(parseFrameworkPackYaml(encode(pack())).languages[1], 'kotlin');
  assert.doesNotThrow(() => parseFrameworkPack({ ...pack(), surfaces: [{ provider: 'spring-actuator' }] }));
  assert.doesNotThrow(() => parseFrameworkPack({ ...pack(), runtime: { ...pack().runtime, env: {
    MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: 'health,mappings', SPRINGDOC_API_DOCS_ENABLED: 'true',
  } } }));
});

test('actuator paths are bounded explicit local metadata with no default insertion', () => {
  const legacy = parseFrameworkPack({ ...pack(), surfaces: [{ provider: 'spring-actuator' }] });
  assert.equal(Object.hasOwn(legacy.surfaces[0], 'paths'), false);
  const paths = ['/internal/route-map', '/manage/routes'];
  const parsed = parseFrameworkPack({ ...pack(), surfaces: [{ provider: 'spring-actuator', paths }] });
  const surface = parsed.surfaces[0];
  assert.equal(surface.provider, 'spring-actuator');
  if (surface.provider !== 'spring-actuator') assert.fail('actuator variant expected');
  assert.deepEqual(surface.paths, paths); paths.push('/later'); assert.equal(surface.paths?.length, 2);
  for (const paths of [[], ['/same', '/same'], Array.from({ length: 17 }, (_, i) => '/map/' + i),
    ['https://host/maps'], ['//host/maps'], ['/maps?q=1'], ['/maps#fragment'], ['/a/../maps'],
    ['/a/./maps'], ['/a//maps'], ['/a\\maps'], ['/%2e%2e/maps'], ['/maps\n'], ['/' + 'x'.repeat(512)]]) {
    for (const provider of ['spring-actuator', 'openapi']) {
      assert.throws(() => parseFrameworkPack({ ...pack(), surfaces: [{ provider, paths }] }),
        /invalid_framework_pack/);
    }
  }
  assert.doesNotThrow(() => parseFrameworkPack({ ...pack(), surfaces: [{ provider: 'spring-actuator',
    paths: Array.from({ length: 16 }, (_, i) => '/map/' + i),
  }] }));
});

test('prior compiled hashes remain fixed and actuator metadata changes only bound IDs in taint rules', () => {
  // Measured before this additive schema edit at 0b28c95; these are compiler regression hashes, not Oracle verdicts.
  const prior = compileFrameworkPack(encode(pack()));
  assert.equal(prior.rawPackSha256, 'a83ddd299708855f8a5a31f72ffde9671c3671154970c7f2791fa4553b237abc');
  assert.equal(prior.semanticPackSha256, 'bba7228cf5fd4067429aec73c0e3bb5de24aeca9eb302b3276fab49ada6f9496');
  assert.equal(prior.rulesSha256, '110c09cf93c4691580d9747540ca2850e41fc2977b08035dccdb6ca4e85c2ec1');
  assert.deepEqual(prior.diagnostics, []); assert.equal(prior.diagnosticsSha256, digest('[]'));
  const before = compileFrameworkPack(encode({ ...pack(), surfaces: [{ provider: 'spring-actuator' }] }));
  const after = compileFrameworkPack(encode({ ...pack(), surfaces: [
    { provider: 'spring-actuator', paths: ['/internal/route-map'] },
  ] }));
  assert.notEqual(after.rawPackSha256, before.rawPackSha256);
  assert.notEqual(after.semanticPackSha256, before.semanticPackSha256);
  assert.notEqual(after.rulesSha256, before.rulesSha256);
  const formulas = (json: string) => JSON.parse(json).rules.map(({ id, ...rule }: Record<string, unknown>) => rule);
  assert.deepEqual(formulas(after.rulesJson), formulas(before.rulesJson));
  assert.equal(after.verification, 'not_run');
});

test('unknown DSL, executable modules, raw patterns, unsupported sink classes and languages are rejected', () => {
  for (const key of ['module', 'script', 'command', 'pattern', 'pattern-sources', 'loadSchema', '$ref', '$async']) {
    assert.throws(() => parseFrameworkPack({ ...pack(), [key]: 'untrusted' }), /invalid_framework_pack/);
  }
  for (const input of [
    { ...pack(), sources: [{ annotation: ['Input'], call: ['Ctx.read'] }] },
    { ...pack(), sources: [{ pattern: 'untrusted(...)' }] },
    { ...pack(), sinks: { ...pack().sinks, command: [{ call: ['Runtime.exec'], arg: 0 }] } },
    { ...pack(), runtime: { ...pack().runtime, profile: 'node' } },
    { ...pack(), languages: ['python'] }, { ...pack(), languages: ['java', 'java'] },
    { ...pack(), detect: { ...pack().detect, execute: 'build' } },
    { ...pack(), surfaces: [{ provider: 'openapi', paths: ['/docs'], fetch: 'https://host' }] },
  ]) assert.throws(() => parseFrameworkPack(input), /invalid_framework_pack/);
  const missing: Record<string, unknown> = pack(); delete missing.sanitizers;
  assert.throws(() => parseFrameworkPack(missing));
});

test('DSL symbols and paths cannot inject patterns, regexes, URLs, interpolation or path traversal', () => {
  for (const value of ['a/b', 'https://host', '../module', '$METHOD', 'Client.query(...); evil()',
    'Client.(.*)', 'Client.get*Value', 'Client.<init>', 'Client.query\n', 'Client.query|anything', 'class.return']) {
    assert.throws(() => parseFrameworkPack({ ...pack(), sources: [{ call: [value] }] }));
    assert.throws(() => parseFrameworkPack({ ...pack(), sources: [{ annotation: [value] }] }));
  }
  for (const value of ['../pom.xml', '/tmp/a', 'a\\b', 'a/./b', 'C:drive', '${HOME}', './pom.xml', 'a\n']) {
    assert.throws(() => parseFrameworkPack({ ...pack(), detect: { ...pack().detect, anyFile: [value] } }));
  }
  for (const value of ['//host', 'https://host/docs', '/a/../b', '/%2e%2e', '/docs?q=1']) {
    assert.throws(() => parseFrameworkPack({ ...pack(), surfaces: [{ provider: 'openapi', paths: [value] }] }));
  }
  for (const value of ['', 'Not-Normal', 'x\n', '../pack', 'x'.repeat(65)]) {
    assert.throws(() => parseFrameworkPack({ ...pack(), id: value }));
  }
  assert.throws(() => parseFrameworkPack({ ...pack(), detect: { ...pack().detect, contains: ['$HOME'] } }));
});

test('reserved process environment and executable-looking values carry no loader or credential authority', () => {
  for (const key of ['PATH', 'NODE_OPTIONS', 'JAVA_TOOL_OPTIONS', 'LD_PRELOAD', 'HTTPS_PROXY', 'CI_TOKEN']) {
    assert.throws(() => parseFrameworkPack({ ...pack(), runtime: { ...pack().runtime, env: { [key]: 'x' } } }));
  }
  for (const value of ['${HOME}', '$(command)', 'http://host', '-javaagent:/tmp/a.jar', 'import fs;']) {
    assert.throws(() => parseFrameworkPack({ ...pack(), runtime: { ...pack().runtime,
      env: { FEATURE_ENABLED: value } } }));
  }
});

test('arrays, integer arguments and own-data bounds are enforced before generation', () => {
  for (const arg of [-1, 0.5, 8, '0', Infinity, NaN]) {
    assert.throws(() => parseFrameworkPack({ ...pack(), sinks: { sql: [{ call: ['Db.query'], arg }] } }));
  }
  for (const version of [0, 1000001, 1.5, '1']) assert.throws(() => parseFrameworkPack({ ...pack(), version }));
  for (const input of [
    { ...pack(), sources: [] }, { ...pack(), sinks: { sql: [] } },
    { ...pack(), sources: [{ annotation: Array(17).fill('Input') }] },
    { ...pack(), sources: [pack().sources[0], pack().sources[0]] },
    { ...pack(), detect: { anyFile: ['a', 'a'], contains: ['needle'] } },
    { ...pack(), extra: 'x'.repeat(1024 * 1024) }, { ...pack(), extra: Array(20000).fill(0) },
  ]) assert.throws(() => parseFrameworkPack(input));
  let deep: unknown = 0; for (let i = 0; i < 41; i++) deep = [deep];
  assert.throws(() => parseFrameworkPack({ ...pack(), extra: deep }));
});

test('getters, proxies, custom prototypes and toJSON are rejected without invoking caller code', () => {
  let calls = 0;
  const input = Object.defineProperty(pack(), 'sources', { get() { calls++; return []; } });
  assert.throws(() => parseFrameworkPack(input));
  assert.throws(() => parseFrameworkPack(new Proxy(pack(), { get() { calls++; throw Error('must_not_run'); } })));
  assert.throws(() => parseFrameworkPack({ ...pack(), sources: new Proxy([], {}) }));
  assert.throws(() => parseFrameworkPack({ ...pack(), toJSON() { calls++; return pack(); } }));
  assert.throws(() => parseFrameworkPack(Object.assign(Object.create({ hidden: true }), pack())));
  assert.equal(calls, 0);
});

test('Pack YAML reuses strict duplicate/tag/anchor/alias/merge/multi-document and size rejection', () => {
  for (const text of ['id: x\nid: y', 'id: !!str x', 'id: &a x', 'id: *a', '<<: {}',
    'id: x\n---\nid: y', 'id: ${HOME}', '#'.repeat(1024 * 1024 + 1)]) {
    assert.throws(() => parseFrameworkPackYaml(text), /invalid_framework_pack/);
  }
});

test('argCount and placeholder hints never suppress SQL taint without actual overload evidence', () => {
  const baseline = compileFrameworkPack(encode(pack()));
  const formulas = (json: string) => JSON.parse(json).rules.map(({ id, ...rule }: Record<string, unknown>) => rule);
  for (const argCount of ['>=2', '>=3']) {
    const input = { ...pack(), sanitizers: { sql: [{ call: ['SqlClient.*'],
      when: { argCount, placeholders: true } }] } };
    assert.doesNotThrow(() => parseFrameworkPack(input));
    const compiled = compileFrameworkPack(encode(input));
    assert.deepEqual(formulas(compiled.rulesJson), formulas(baseline.rulesJson));
    assert.notEqual(compiled.semanticPackSha256, baseline.semanticPackSha256);
    assert.deepEqual(compiled.diagnostics, [{ kind: 'sanitizer', index: 0, vulnClass: 'sql',
      disposition: 'not-applied', reason: 'binding-literal-overload-argument-unproven',
      call: ['SqlClient.*'], when: { argCount, placeholders: true } }]);
    assert.notEqual(compiled.diagnosticsSha256, baseline.diagnosticsSha256);
    for (const rule of JSON.parse(compiled.rulesJson).rules) {
      assert.equal(Object.hasOwn(rule, 'pattern-sanitizers'), false);
      assert.ok(encode(rule['pattern-sinks']).includes('$SQL'));
    }
  }
  assert.throws(() => parseFrameworkPack({ ...pack(), sanitizers: { sql: [{ call: ['Db.query'],
    when: { argCount: '>=2', placeholders: true, promoted: true } }] } }));
  const reserved = compileFrameworkPack(encode({ ...pack(), surfaces: [
    { provider: 'source-routes', annotations: ['Route'] },
  ] }));
  assert.deepEqual(reserved.diagnostics, [{ kind: 'surface', index: 0, provider: 'source-routes',
    disposition: 'unsupported', reason: 'discovery-not-implemented', annotations: ['Route'] }]);
  assert.deepEqual(formulas(reserved.rulesJson), formulas(baseline.rulesJson));
});

test('original builtin Pack compiles SQL rules and preserves unsupported discovery and unproven hints', async () => {
  const raw = await readFile('packs/spring-boot.v1.yml', 'utf8');
  const original = parseFrameworkPackYaml(raw), compiled = compileFrameworkPack(raw);
  assert.equal(compiled.rawPackSha256, digest(raw)); assert.equal(compiled.verification, 'not_run');
  assert.deepEqual(compiled, compileFrameworkPack(raw));
  assert.equal(compiled.rulesSha256, digest(compiled.rulesJson));
  const rules = JSON.parse(compiled.rulesJson).rules;
  assert.deepEqual(rules.map((rule: { languages: string[] }) => rule.languages[0]), ['java', 'kotlin']);
  for (const rule of rules) {
    assert.equal(rule.mode, 'taint'); assert.equal(Object.hasOwn(rule, 'pattern-sanitizers'), false);
    assert.equal(rule['pattern-sources'].length, 7); assert.equal(rule['pattern-sinks'].length, 6);
    assert.ok(encode(rule['pattern-sinks']).includes('"focus-metavariable":"$SQL"'));
  }
  assert.equal(compiled.diagnostics.length, 2);
  const surface = original.surfaces[2];
  if (surface.provider !== 'source-routes') assert.fail('builtin source-routes entry expected');
  assert.deepEqual(compiled.diagnostics[0], { kind: 'surface', index: 2, provider: 'source-routes',
    disposition: 'unsupported', reason: 'discovery-not-implemented', annotations: surface.annotations });
  assert.deepEqual(compiled.diagnostics[1], { kind: 'sanitizer', index: 0, vulnClass: 'sql',
    disposition: 'not-applied', reason: 'binding-literal-overload-argument-unproven',
    call: original.sanitizers.sql[0].call, when: original.sanitizers.sql[0].when });
  assert.equal(await readFile('packs/spring-boot.v1.yml', 'utf8'), raw);
});

test('diagnostics are immutable bounded closed metadata and hashes bind their exact configuration', () => {
  const input = { ...pack(), sanitizers: { sql: [{ call: ['SqlClient.*'],
    when: { argCount: '>=2', placeholders: true } }] } };
  const first = compileFrameworkPack(encode(input));
  assert.ok(Object.isFrozen(first.diagnostics));
  assert.ok(Object.isFrozen(first.diagnostics[0]));
  const row = first.diagnostics[0];
  if (row.kind !== 'sanitizer') assert.fail('sanitizer diagnostic expected');
  assert.ok(Object.isFrozen(row.call)); assert.ok(Object.isFrozen(row.when));
  assert.deepEqual(Object.keys(row).sort(), ['call', 'disposition', 'index', 'kind', 'reason', 'vulnClass', 'when']);
  assert.throws(() => Object.assign(row.when, { placeholders: false }), TypeError);
  input.sanitizers.sql[0].when.argCount = '>=3';
  const next = compileFrameworkPack(encode(input));
  assert.notEqual(next.rawPackSha256, first.rawPackSha256);
  assert.notEqual(next.semanticPackSha256, first.semanticPackSha256);
  assert.notEqual(next.diagnosticsSha256, first.diagnosticsSha256);
  assert.equal(row.when.argCount, '>=2');
  assert.throws(() => compileFrameworkPack(encode({ ...input, sanitizers: { sql: [{
    ...input.sanitizers.sql[0], reason: 'trust-me', pattern: 'sanitize(...)',
  }] } })), /invalid_framework_pack/);
});

test('diagnostic counts and indices obey the original Pack limits without truncation', () => {
  const input = { ...pack(),
    surfaces: Array.from({ length: 16 }, (_, i) => ({ provider: 'source-routes', annotations: ['Route' + i] })),
    sanitizers: { sql: Array.from({ length: 32 }, (_, i) => ({ call: ['SqlClient' + i + '.*'],
      when: { argCount: '>=2', placeholders: true } })) },
  };
  const compiled = compileFrameworkPack(encode(input));
  assert.equal(compiled.diagnostics.length, 48);
  assert.deepEqual(compiled.diagnostics.slice(0, 16).map(row => row.index), Array.from({ length: 16 }, (_, i) => i));
  assert.deepEqual(compiled.diagnostics.slice(16).map(row => row.index), Array.from({ length: 32 }, (_, i) => i));
  input.sanitizers.sql.push({ call: ['ExtraClient.*'], when: { argCount: '>=2', placeholders: true } });
  assert.throws(() => compileFrameworkPack(encode(input)), /invalid_framework_pack/);
});

test('deterministic data-only generation binds raw YAML, canonical Pack, revision and exact JSON bytes', () => {
  const raw = encode(pack()), compiled = compileFrameworkPack(raw), again = compileFrameworkPack(raw);
  assert.deepEqual(compiled, again); assert.ok(Object.isFrozen(compiled));
  assert.equal(compiled.generationRevision, PACK_COMPILER_REVISION);
  assert.equal(compiled.rawPackSha256, digest(raw)); assert.equal(compiled.rulesSha256, digest(compiled.rulesJson));
  const reversed = Object.fromEntries(Object.entries(pack()).reverse());
  const formatted = compileFrameworkPack(JSON.stringify(reversed, null, 2));
  assert.notEqual(formatted.rawPackSha256, compiled.rawPackSha256);
  assert.equal(formatted.semanticPackSha256, compiled.semanticPackSha256);
  assert.equal(formatted.rulesJson, compiled.rulesJson);
  const changed = compileFrameworkPack(encode({ ...pack(), sinks: { sql: [{ call: ['SqlClient.query'], arg: 1 }] } }));
  assert.notEqual(changed.semanticPackSha256, compiled.semanticPackSha256);
  assert.notEqual(changed.rulesSha256, compiled.rulesSha256);
});

test('standard source/sink focus rules preserve call ownership, argument position and language syntax', () => {
  const compiled = compileFrameworkPack(encode(pack())), document = JSON.parse(compiled.rulesJson);
  assert.equal(compiled.verification, 'not_run'); assert.equal(document.rules.length, 2);
  assert.equal(compiled.executionProtocol, 'core-rules-targets-intrafile');
  for (const rule of document.rules) {
    assert.equal(rule.mode, 'taint'); assert.match(rule.id, /^[a-z0-9.-]+$/);
    assert.equal(rule['pattern-sanitizers'], undefined);
    assert.ok(rule['pattern-sources'].every((source: { exact: boolean }) => source.exact === true));
    assert.ok(rule['pattern-sinks'].every((sink: { patterns: unknown[] }) =>
      encode(sink.patterns).includes('"focus-metavariable":"$SQL"')));
    assert.ok(encode(rule).includes('"metavariable-type":{"metavariable":"$RECEIVER","type":"SqlClient"}'));
    const source = rule['pattern-sources'][0];
    assert.ok(encode(source).includes('"focus-metavariable":"$SOURCE"'));
    assert.equal(encode(source).includes('fun $METHOD'), rule.languages[0] === 'kotlin');
  }
  const arg2 = compileFrameworkPack(encode({ ...pack(), sinks: { sql: [{ call: ['SqlClient.query'], arg: 2 }] } }));
  assert.ok(arg2.rulesJson.includes('$_, $_, $SQL, ...'));
  const other = compileFrameworkPack(encode({ ...pack(), id: 'different-pack',
    sources: [{ annotation: ['OtherInput'] }, { call: ['OtherContext.read'] }],
  }));
  assert.ok(other.rulesJson.includes('@OtherInput')); assert.ok(other.rulesJson.includes('OtherContext'));
  assert.equal(other.rulesJson.includes('QueryInput'), false);
});

test('static schemas use local refs and pure modules exclude execution imports', async () => {
  const pending: unknown[] = [packSchema];
  while (pending.length) {
    const value = pending.pop(); if (!value || typeof value !== 'object') continue;
    for (const [key, child] of Object.entries(value)) {
      assert.equal(['$async', '$data', 'default'].includes(key), false);
      if (key === '$ref') assert.match(String(child), /^#\//);
      pending.push(child);
    }
  }
  for (const name of ['schema', 'compile-opengrep']) {
    const code = await readFile(new URL(`../src/runtime/packs/${name}.js`, import.meta.url), 'utf8');
    assert.doesNotMatch(code, /node:(?:fs|child_process|net|http|https)|Date\.|Math\.random|import\(/);
  }
});
