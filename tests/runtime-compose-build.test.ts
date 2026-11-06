import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import test from 'node:test';
import {
  FixedComposeProfileError, selectFixedComposeProfile,
} from '../src/runtime/builders/compose.js';
import { parseRuntimeYaml } from '../src/runtime/target.js';

const profiles = [
  { id: 'f01', root: 'examples/runtime/spring-sqli/vulnerable' },
  { id: 'f02', root: 'examples/runtime/spring-sqli/fixed' },
  { id: 'f03', root: 'examples/runtime/spring-sqli-jdbc/vulnerable' },
  { id: 'f04', root: 'examples/runtime/spring-sqli-jdbc/fixed' },
] as const;

async function inputFor(profile: typeof profiles[number]) {
  return {
    profileId: profile.id,
    sourceRoot: profile.root,
    targetText: await readFile(`${profile.root}/wakeio.target.yml`, 'utf8'),
    composeText: await readFile(`${profile.root}/compose.json`, 'utf8'),
    pinsText: await readFile(`${dirname(profile.root)}/pins.json`, 'utf8'),
  };
}

for (const profile of profiles) {
  test(`${profile.id} selects exact physical BUILD and SCANNER inputs with controller exclusion`, async () => {
    const input = await inputFor(profile);
    const physical = (await readdir(profile.root, { recursive: true, withFileTypes: true }))
      .filter(entry => entry.isFile())
      .map(entry => `${entry.parentPath}/${entry.name}`.slice(profile.root.length + 1));
    const source = physical.filter(path => path === 'pom.xml' || path.startsWith('src/')).sort();
    const build = physical.filter(path => path !== 'compose.json'
      && path !== 'wakeio.target.yml' && path !== 'seed.sql').sort();

    const selected = selectFixedComposeProfile(input);

    assert.equal(selected.sourceRoot, profile.root);
    assert.equal(selected.profileId, profile.id);
    assert.equal(selected.build.length, 5);
    assert.equal(selected.scanner.length, 3);
    assert.deepEqual(selected.build.map(file => file.path).sort(), build);
    assert.deepEqual(selected.scanner.map(file => file.path).sort(), source);
    assert.notEqual(selected.build, selected.scanner);
    for (const file of [...selected.build, ...selected.scanner, ...selected.controllerOnly]) {
      const bytes = await readFile(file.repositoryPath);
      assert.equal(bytes.length, file.bytes, file.repositoryPath);
      assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.repositoryPath);
    }
    const controllers = selected.controllerOnly.map(file => file.repositoryPath);
    assert.equal(new Set(controllers).size, 4);
    assert.ok([...selected.build, ...selected.scanner].every(file => !controllers.includes(file.repositoryPath)));
    const pins = parseRuntimeYaml(input.pinsText);
    assert.ok(pins !== null && typeof pins === 'object' && 'baseImages' in pins);
    assert.equal(JSON.stringify(selected.pins.baseImages), JSON.stringify(pins.baseImages));
    assert.equal(selected.compose.postgres.declaredImage,
      `${selected.pins.baseImages.postgres.repository}@${selected.pins.baseImages.postgres.indexDigest}`);
    assert.equal(selected.compose.app.command, null);
    assert.equal(selected.compose.app.entrypoint, null);
    assert.deepEqual(selected.compose.app.build, { context: '.', dockerfile: 'Dockerfile' });
    assert.deepEqual(selected.compose.app.environment.map(item => item.field).sort(), ['password', 'url', 'username']);
  });
}

test('selection is deeply immutable detached DATA and retains unfulfilled canonical prerequisites', async () => {
  const input = await inputFor(profiles[0]);
  const selected = selectFixedComposeProfile(input);
  input.sourceRoot = profiles[1].root;

  assert.equal(selected.sourceRoot, profiles[0].root);
  assert.equal(selected.kind, 'DATA');
  assert.equal(selected.executable, false);
  assert.equal(selected.restrictions.platform, 'linux/arm64');
  assert.deepEqual(selected.compose.requires, ['source-snapshot', 'trusted-postgres-pin', 'verified-isolation']);
  assert.equal(selected.compose.inheritEnvironment, false);
  assert.deepEqual(selected.compose.hostPorts, []);
  for (const value of [selected, selected.build, selected.build[0], selected.target.seed.sql,
    selected.compose.app.environment, selected.pins.baseImages.build.platforms, selected.commands.maven]) {
    assert.ok(Object.isFrozen(value));
    assert.throws(() => Object.defineProperty(value, 'changed', { value: true }), TypeError);
  }
});

test('unknown profiles and nonexact roots refuse rather than normalize caller authority', async () => {
  const input = await inputFor(profiles[0]);
  for (const profileId of ['f00', 'f05', '__proto__', '', null, 1]) {
    assert.throws(() => selectFixedComposeProfile({ ...input, profileId }), FixedComposeProfileError);
  }
  for (const sourceRoot of [profiles[1].root, '.', `${input.sourceRoot}/`, `./${input.sourceRoot}`,
    `${input.sourceRoot}/../vulnerable`, `/${input.sourceRoot}`, null]) {
    assert.throws(() => selectFixedComposeProfile({ ...input, sourceRoot }), FixedComposeProfileError);
  }
});

test('changed commands entrypoint environment images services and Compose extras refuse', async () => {
  const input = await inputFor(profiles[2]);
  const changes = [
    input.composeText.replace('"app": {', '"app": {"command": ["java", "-version"],'),
    input.composeText.replace('"app": {', '"app": {"entrypoint": ["java"],'),
    input.composeText.replace('wakeio:postgres.url', 'jdbc:postgresql://foreign/db'),
    input.composeText.replace('"environment": {', '"environment": {"HOME": "/tmp",'),
    input.composeText.replace('"environment": {', '"environment": {"JAVA_TOOL_OPTIONS": "-javaagent:foreign",'),
    input.composeText.replace('"db": {', '"other": {}, "db": {'),
    input.composeText.replace('"app": {', '"renamed": {'),
    input.composeText.replace('"services": {', '"extra": true, "services": {'),
    input.composeText.replace('"app": {', '"app": {"ports": ["8080:8080"],'),
    input.composeText.replace('"context": "."', '"context": "../foreign"'),
    input.composeText.replace('"dockerfile": "Dockerfile"', '"dockerfile": "other"'),
    input.composeText.replace('postgres@sha256:', 'foreign@sha256:'),
    input.composeText.replace('edb0c08d', 'adb0c08d'),
  ];
  for (const composeText of changes) {
    assert.notEqual(composeText, input.composeText);
    assert.throws(() => selectFixedComposeProfile({ ...input, composeText }), FixedComposeProfileError);
  }
});

test('all three controller texts require exact bytes including digest and terminal LF', async () => {
  const input = await inputFor(profiles[3]);
  for (const key of ['targetText', 'composeText', 'pinsText'] as const) {
    for (const text of [input[key].slice(0, -1), `${input[key]} `, input[key].replace(/\n/g, '\r\n'),
      input[key].replace(/[a-z]/, 'X'), '\ud800', 'x'.repeat(1024 * 1024 + 1), null, {}]) {
      assert.throws(() => selectFixedComposeProfile({ ...input, [key]: text }), FixedComposeProfileError);
    }
  }
  const other = await inputFor(profiles[0]);
  assert.throws(() => selectFixedComposeProfile({ ...input, targetText: other.targetText }), FixedComposeProfileError);
});

test('own-data boundary rejects hooks proxies inherited hidden symbol missing and extra fields', async () => {
  const input = await inputFor(profiles[0]);
  let calls = 0;
  const getter = Object.defineProperty({ ...input }, 'composeText', {
    enumerable: true, get() { calls++; throw new Error('caller_hook'); },
  });
  const proxy = new Proxy(input, { ownKeys() { calls++; throw new Error('caller_proxy'); } });
  const missing: Record<string, unknown> = { ...input };
  delete missing['pinsText'];
  for (const value of [getter, proxy, Object.assign(Object.create(input), input),
    Object.defineProperty({ ...input }, 'hidden', { value: true }),
    { ...input, [Symbol('hidden')]: true }, { ...input, command: ['foreign'] },
    { ...input, toJSON() { calls++; return input; } }, missing, null, [input]]) {
    assert.throws(() => selectFixedComposeProfile(value), FixedComposeProfileError);
  }
  assert.equal(calls, 0);
});
