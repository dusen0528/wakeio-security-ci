import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import type { TestContext } from 'node:test';
import {
  observeSourceSnapshot, readSourceSnapshot, SourceSnapshotError, withSourceSnapshot,
} from '../src/runtime/snapshots.js';
import type { SourceSnapshotHandle } from '../src/runtime/snapshots.js';

const java = 'src/main/java/io/wakeio/fixtures/Application.java';
const sourceFiles = new Map([
  ['pom.xml', '<project>owned</project>\n'], [java, 'class Application {}\n'],
  ['src/main/resources/application.properties', 'server.port=8080\n'],
  ['Dockerfile', 'FROM scratch\n'], ['.dockerignore', '.git\n'],
]);
const scanner = ['pom.xml', java, 'src/main/resources/application.properties'];
const sha = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');

async function fixture(t: TestContext) {
  const top = await fs.realpath(await fs.mkdtemp(join(tmpdir(), 'source-capture-test-')));
  t.after(() => fs.rm(top, { recursive: true }));
  const sourceRoot = join(top, 'source');
  for (const [path, data] of sourceFiles) {
    await fs.mkdir(dirname(join(sourceRoot, path)), { recursive: true });
    await fs.writeFile(join(sourceRoot, path), data);
  }
  await fs.writeFile(join(sourceRoot, 'truth.json'), 'controller only');
  const input = { executeTargetConsent: true, sourceRoot, build: [...sourceFiles.keys()], scanner };
  return { top, input };
}

test('consent denial performs zero source access, allocation, or process creation', async t => {
  let touches = 0;
  const deny = () => { touches++; throw new Error('unexpected operation'); };
  for (const name of ['open', 'readFile', 'mkdir', 'mkdtemp'] as const) t.mock.method(fs, name, deny);
  t.mock.method(childProcess, 'spawn', deny);
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  const accessor = Object.defineProperty({}, 'executeTargetConsent', { get: deny });
  const hostile = new Proxy({}, { get: deny, ownKeys: deny, getOwnPropertyDescriptor: deny });
  for (const consent of [undefined, false, 'true', 1]) {
    const input = Object.defineProperty({ executeTargetConsent: consent }, 'sourceRoot', { get: deny });
    await assert.rejects(withSourceSnapshot(input, deny), { code: 'consent' });
  }
  for (const input of [accessor, hostile, Object.create({ executeTargetConsent: true })]) {
    await assert.rejects(withSourceSnapshot(input, deny), { code: 'consent' });
  }
  assert.equal(touches, 0);
});

test('capture delivers separate neutral projections and revokes original identity before CLOSE settlement', async t => {
  const { input } = await fixture(t);
  const children: ReturnType<typeof childProcess.spawn>[] = [];
  const closes: number[] = [];
  const closeRevocations: Promise<unknown>[] = [];
  const original = childProcess.spawn;
  t.mock.method(childProcess, 'spawn', (...args: Parameters<typeof childProcess.spawn>) => {
    const child = original(...args);
    children.push(child);
    child.once('close', () => {
      closes.push(1);
      closeRevocations.push(assert.rejects(observeSourceSnapshot(retained), { code: 'revoked' }));
    });
    return child;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  let retained: SourceSnapshotHandle | undefined;
  let root = '';
  await withSourceSnapshot(input, async handle => {
    retained = handle;
    const observed = await observeSourceSnapshot(handle);
    root = observed.root;
    assert.deepEqual((await fs.readdir(root)).sort(), ['build', 'scanner']);
    assert.deepEqual(observed.files.filter(r => r.role === 'scanner').map(r => r.path).sort(), [...scanner].sort());
    for (const row of observed.files) {
      const expected = sourceFiles.get(row.path);
      assert.ok(expected);
      assert.equal(row.sha256, sha(expected));
      assert.equal((await fs.readFile(join(root, row.role, row.path))).toString(), expected);
      assert.equal((await readSourceSnapshot(handle, row)).toString(), expected);
    }
    for (const forged of [{ ...handle }, new Proxy(handle, {}), JSON.parse(JSON.stringify(handle)), observed]) {
      await assert.rejects(observeSourceSnapshot(forged), { code: 'revoked' });
    }
  });
  await assert.rejects(readSourceSnapshot(retained, { role: 'build', path: 'pom.xml' }), { code: 'revoked' });
  await assert.rejects(fs.stat(root), { code: 'ENOENT' });
  assert.equal(children.length, 1);
  assert.equal(closes.length, 1);
  await Promise.all(closeRevocations);
  const child = children[0];
  assert.ok(child?.pid);
  assert.equal(child.stdout?.closed, true);
  assert.equal(child.stderr?.closed, true);
  assert.throws(() => process.kill(child.pid ?? 0, 0), { code: 'ESRCH' });
  for (const [path, data] of sourceFiles) assert.equal(await fs.readFile(join(input.sourceRoot, path), 'utf8'), data);
});

test('aggregate bound counts both physical projections rather than unique source files', async t => {
  const { input } = await fixture(t);
  const extra = 'src/main/java/io/wakeio/jdbcfixtures/Application.java';
  for (const path of [...sourceFiles.keys(), extra]) {
    await fs.mkdir(dirname(join(input.sourceRoot, path)), { recursive: true });
    await fs.writeFile(join(input.sourceRoot, path), Buffer.alloc(1024 * 1024));
  }
  await assert.rejects(withSourceSnapshot({ ...input, scanner: [...scanner, extra] },
    async () => assert.fail('published')), SourceSnapshotError);
});

test('callback failure preserves its error after original resources close and handle revocation', async t => {
  const { input } = await fixture(t);
  const failure = new Error('callback failed');
  let handle: SourceSnapshotHandle | undefined;
  let root = '';
  await assert.rejects(withSourceSnapshot(input, async original => {
    handle = original;
    root = (await observeSourceSnapshot(original)).root;
    throw failure;
  }), error => error === failure);
  await assert.rejects(observeSourceSnapshot(handle), { code: 'revoked' });
  await assert.rejects(fs.stat(root), { code: 'ENOENT' });
});

for (const attack of ['file-symlink', 'directory-symlink', 'root-symlink', 'hardlink', 'oversize'] as const) {
  test(`physical capture refuses ${attack} without publishing a handle`, async t => {
    const { top, input } = await fixture(t);
    const pom = join(input.sourceRoot, 'pom.xml');
    switch (attack) {
      case 'file-symlink':
        await fs.rename(pom, join(top, 'original'));
        await fs.symlink(join(top, 'original'), pom);
        break;
      case 'directory-symlink':
        await fs.rename(join(input.sourceRoot, 'src'), join(top, 'original'));
        await fs.symlink(join(top, 'original'), join(input.sourceRoot, 'src'));
        break;
      case 'root-symlink':
        await fs.rename(input.sourceRoot, join(top, 'original'));
        await fs.symlink(join(top, 'original'), input.sourceRoot);
        break;
      case 'hardlink':
        await fs.link(pom, join(top, 'linked'));
        break;
      case 'oversize':
        await fs.writeFile(pom, Buffer.alloc(1024 * 1024 + 1));
        break;
      default: {
        const exhaustive: never = attack;
        assert.fail(exhaustive);
      }
    }
    let published = false;
    await assert.rejects(withSourceSnapshot(input, async () => { published = true; }), SourceSnapshotError);
    assert.equal(published, false);
  });
}

for (const path of ['../pom.xml', '/pom.xml', './pom.xml', '.omo/data', '.git/config',
  '.handoff/data', 'truth.json', 'compose.json', 'seed.sql', 'wakeio.target.yml', 'Dockerfile']) {
  test(`scanner rejects unapproved relative file ${path}`, async t => {
    const { input } = await fixture(t);
    await assert.rejects(withSourceSnapshot({ ...input, scanner: [path] }, async () => assert.fail('published')),
      SourceSnapshotError);
  });
}

for (const parent of ['.omo', '.handoff', '.git', '.OMO', '.HANDOFF', '.GIT',
  'private', 'evaluator-provenance', 'truth', 'cases']) {
  test(`private source ancestor ${parent} is refused`, async t => {
    const { top, input } = await fixture(t);
    const destination = join(top, parent);
    await fs.mkdir(destination);
    await fs.rename(input.sourceRoot, join(destination, 'source'));
    await assert.rejects(withSourceSnapshot({ ...input, sourceRoot: join(destination, 'source') },
      async () => assert.fail('published')), SourceSnapshotError);
  });
}

test('source replacement cannot redirect retained descriptors into a private replacement', async t => {
  const { top, input } = await fixture(t);
  let root = '';
  await assert.rejects(withSourceSnapshot(input, async handle => {
    root = (await observeSourceSnapshot(handle)).root;
    await fs.rename(input.sourceRoot, join(top, 'original'));
    await fs.mkdir(input.sourceRoot);
    await fs.writeFile(join(input.sourceRoot, 'pom.xml'), 'private replacement');
    await readSourceSnapshot(handle, { role: 'build', path: 'pom.xml' });
  }), SourceSnapshotError);
  assert.equal(await fs.readFile(join(input.sourceRoot, 'pom.xml'), 'utf8'), 'private replacement');
  assert.equal(await fs.readFile(join(top, 'original/pom.xml'), 'utf8'), sourceFiles.get('pom.xml'));
  await assert.rejects(fs.stat(root), { code: 'ENOENT' });
});

test('cleanup preserves a foreign projection replacement and reports unknown instead of success', async t => {
  const { top, input } = await fixture(t);
  let root = '';
  await assert.rejects(withSourceSnapshot(input, async handle => {
    root = (await observeSourceSnapshot(handle)).root;
    await fs.rename(join(root, 'build/pom.xml'), join(top, 'original-output'));
    await fs.writeFile(join(root, 'build/pom.xml'), 'foreign replacement');
  }), error => {
    assert.ok(error instanceof SourceSnapshotError);
    assert.equal(error.code, 'cleanup_unknown');
    const recovery = error.cleanup;
    assert.ok(recovery);
    const directory = recovery.directory;
    assert.ok(directory);
    assert.equal(recovery.uncertain, true);
    assert.ok(recovery.pending.some(entry => entry.name === 'pom.xml'));
    t.after(() => fs.rm(directory, { recursive: true }));
    return true;
  });
  assert.equal(await fs.readFile(join(root, 'build/pom.xml'), 'utf8'), 'foreign replacement');
  assert.equal(await fs.readFile(join(top, 'original-output'), 'utf8'), sourceFiles.get('pom.xml'));
  // The test owns this injected drift; production deliberately retained it.
  await fs.rm(root, { recursive: true });
});

test('unexpected original helper CLOSE revokes authority before the callback settles', async t => {
  const { input } = await fixture(t);
  const original = childProcess.spawn;
  let child: ReturnType<typeof childProcess.spawn> | undefined;
  t.mock.method(childProcess, 'spawn', (...args: Parameters<typeof childProcess.spawn>) => {
    child = original(...args);
    return child;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  let root = '';
  let actualClose = false;
  await assert.rejects(withSourceSnapshot(input, async handle => {
    root = (await observeSourceSnapshot(handle)).root;
    assert.ok(child);
    const closed = once(child, 'close', { signal: AbortSignal.timeout(5000) });
    child.kill('SIGTERM');
    await closed;
    actualClose = true;
    await assert.rejects(observeSourceSnapshot(handle), { code: 'revoked' });
  }), error => {
    assert.ok(error instanceof SourceSnapshotError);
    assert.equal(error.code, 'cleanup_unknown');
    const recovery = error.cleanup;
    assert.ok(recovery);
    assert.equal(recovery.directory, null);
    assert.equal(recovery.uncertain, false);
    assert.deepEqual(recovery.pending, []);
    return true;
  });
  assert.equal(actualClose, true);
  await assert.rejects(fs.stat(root), { code: 'ENOENT' });
});
