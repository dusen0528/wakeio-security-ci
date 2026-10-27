import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFile, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { writeInitTargetDraft } from '../src/init-target.js';
import { parseTargetYaml } from '../src/runtime/target.js';
import { parseFrameworkPackYaml } from '../src/runtime/packs/schema.js';

const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const packFile = resolve('packs/spring-boot.v1.yml');
const canary = 'private-source-and-environment-canary';
async function fixture(top: string, name = 'service') {
  const source = join(top, name); await mkdir(source);
  await writeFile(join(source, 'pom.xml'), `org.springframework.boot\n${canary}`);
  return source;
}

test('Pack-driven Maven/Gradle detection writes only a private schema-valid draft with hashes', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-target-'));
  try {
    const rawPack = await readFile(packFile), pack = parseFrameworkPackYaml(rawPack.toString('utf8'));
    for (const [index, file] of pack.detect.anyFile.entries()) {
      const source = join(top, `service-${index}`); await mkdir(source);
      const bytes = Buffer.from(pack.detect.contains[0] + '\n' + canary);
      await writeFile(join(source, file), bytes);
      const output = join(top, `target-${index}.yml`);
      const result = await writeInitTargetDraft(source, output), yaml = await readFile(output, 'utf8');
      const target = parseTargetYaml(yaml);
      assert.equal(target.source, `service-${index}`); assert.equal(target.entry.port, pack.runtime.defaultPort);
      assert.equal(target.entry.health, pack.runtime.health);
      assert.deepEqual(target.pack, Object.assign(Object.create(null),
        { id: pack.id, version: pack.version }));
      assert.equal(result.status, 'draft'); assert.equal(result.pack.sha256, digest(rawPack));
      assert.deepEqual(result.detection, [{ file, sha256: digest(bytes), reason: 'pack_detect_match' }]);
      assert.ok(result.missing.includes('compose_file')); assert.ok(result.missing.includes('seed_sql'));
      assert.match(yaml, /Draft only/); assert.match(yaml, /not source-routes/); assert.ok(!yaml.includes(canary));
      assert.equal((await lstat(output)).mode & 0o777, 0o600); assert.equal((await lstat(output)).nlink, 1);
      assert.deepEqual(await readFile(join(source, file)), bytes); assert.deepEqual(await readdir(source), [file]);
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('owned fixture POM is read as data; target scripts and original fixture bytes remain untouched', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-owned-'));
  const original = resolve('examples/runtime/spring-sqli/vulnerable/pom.xml');
  try {
    const before = await readFile(original), source = join(top, 'owned');
    await mkdir(source);
    await copyFile(original, join(source, 'pom.xml'));
    await writeFile(join(source, 'package.json'), JSON.stringify({
      scripts: { prepare: 'exit 99', postinstall: 'exit 99' },
    }));
    await writeInitTargetDraft(source, join(top, 'draft.yml'));
    assert.deepEqual(await readFile(original), before);
    assert.deepEqual(await readFile(join(source, 'pom.xml')), before);
    assert.deepEqual((await readdir(source)).sort(), ['package.json', 'pom.xml']);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('unsupported, oversized, non-UTF8, linked and hardlinked detection inputs fail without publication', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-inputs-'));
  try {
    const source = await fixture(top), output = join(top, 'draft.yml'), pom = join(source, 'pom.xml');
    for (const bytes of [Buffer.from('ordinary project'), Buffer.alloc(256 * 1024 + 1), Buffer.from([0xff])]) {
      await writeFile(pom, bytes); await assert.rejects(writeInitTargetDraft(source, output));
      await assert.rejects(lstat(output), { code: 'ENOENT' });
    }
    await rm(pom); await assert.rejects(writeInitTargetDraft(source, output), /unsupported_runtime_source/);
    await writeFile(join(top, 'original'), 'org.springframework.boot');
    await symlink(join(top, 'original'), pom); await assert.rejects(writeInitTargetDraft(source, output));
    await rm(pom); await link(join(top, 'original'), pom); await assert.rejects(writeInitTargetDraft(source, output));
    assert.deepEqual((await readdir(top)).sort(), ['original', 'service']);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('source/output links, existing leaves, missing parents and unrepresentable references are refused', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-paths-'));
  try {
    const source = await fixture(top), before = await readFile(join(source, 'pom.xml'));
    const existing = join(top, 'existing'); await writeFile(existing, 'preserve');
    await symlink(existing, join(top, 'leaf-link')); await link(existing, join(top, 'hard-leaf'));
    await symlink(source, join(top, 'source-link')); await symlink(top, join(top, 'parent-link'));
    await mkdir(join(top, 'other')); const spaced = await fixture(top, 'not representable');
    for (const [input, output] of [
      [source, join(source, 'inside.yml')], [source, existing], [source, join(top, 'leaf-link')],
      [source, join(top, 'hard-leaf')], [source, join(top, 'absent', 'draft')],
      [source, join(top, 'other', 'draft')], [source, join(top, 'parent-link', 'draft')],
      [join(top, 'source-link'), join(top, 'draft')], [spaced, join(top, 'draft')],
      [source, '/dev/null'],
    ]) await assert.rejects(writeInitTargetDraft(input, output));
    assert.equal(await readFile(existing, 'utf8'), 'preserve');
    assert.deepEqual(await readFile(join(source, 'pom.xml')), before);
    assert.deepEqual(await readdir(source), ['pom.xml']);
    assert.ok((await readdir(top)).every(name => !name.startsWith('.wakeio-target-')));
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('racing writers publish exactly one draft without replacement or temporary leftovers', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-race-'));
  try {
    const source = await fixture(top), output = join(top, 'draft.yml');
    const runs = await Promise.allSettled(Array.from({ length: 4 }, () => writeInitTargetDraft(source, output)));
    assert.equal(runs.filter(run => run.status === 'fulfilled').length, 1);
    const bytes = await readFile(output); parseTargetYaml(bytes.toString('utf8'));
    await assert.rejects(writeInitTargetDraft(source, output), /init_target_output_exists/);
    assert.deepEqual(await readFile(output), bytes); assert.equal((await lstat(output)).nlink, 1);
    assert.deepEqual((await readdir(top)).sort(), ['draft.yml', 'service']);
  } finally { await rm(top, { recursive: true, force: true }); }
});
