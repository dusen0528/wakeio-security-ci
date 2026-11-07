import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, realpath, rename, rm, writeFile, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ProvisionOwner } from '../src/runtime/runtimes/provision-controller-owner.js';
import { ProvisionFile } from '../src/runtime/runtimes/provision-controller-files.js';
import { ProvisionProcess } from '../src/runtime/runtimes/provision-controller-process.js';
import { provisionOptions } from '../src/runtime/runtimes/provision-types.js';

function deferred() {
  let resolve = () => {};
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

test('consent refuses proxy inherited and accessor inputs without invoking them', () => {
  let reads = 0;
  const getter = { get executeTargetConsent() { reads++; return true; } };
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { reads++; return undefined; } });
  const inputs = [undefined, {}, { executeTargetConsent: false },
    Object.create({ executeTargetConsent: true }), getter, proxy];
  for (const input of inputs) assert.throws(() => provisionOptions(input), { code: 'consent_required' });
  assert.equal(reads, 0);
});

test('consented options snapshot refuses a nested accessor before startup', () => {
  let reads = 0;
  assert.throws(() => provisionOptions({
    executeTargetConsent: true, deadlineAt: Date.now() + 1000, acquisitionDeadlineAt: Date.now() + 500,
    requiredGrade: 'rootless-docker', catalog: { get secret() { reads++; return 'value'; } },
  }), { code: 'options_invalid' });
  assert.equal(reads, 0);
});

test('revocation rejects new borrowers and waits for the existing borrower before removal', async () => {
  const owner = new ProvisionOwner(Date.now() + 10000);
  const started = deferred();
  const release = deferred();
  let removed = false;
  owner.own({ identity: 'owned', stop() {}, drained: Promise.resolve(),
    async remove() { removed = true; return true; } });
  const borrowed = owner.borrow(async () => { started.resolve(); await release.promise; });
  await started.promise;
  const closing = owner.close();
  assert.throws(() => owner.borrow(async () => undefined), { code: 'owner_closed' });
  await Promise.resolve();
  assert.equal(removed, false);
  release.resolve();
  await borrowed;
  assert.deepEqual(await closing, { confirmed: true, retained: [], failures: [] });
  assert.equal(removed, true);
});

test('an unconfirmed process drain preserves its resource and prevents outer removal', async () => {
  const owner = new ProvisionOwner(Date.now() + 10000);
  let removed = false;
  owner.own({ identity: 'vm', stop() {}, drained: Promise.resolve(),
    async remove() { removed = true; return true; } });
  owner.own({ identity: 'installer', stop() {}, drained: Promise.reject(new Error('lost-close')),
    async remove() { throw new Error('must retain'); } });
  const cleanup = await owner.close();
  assert.equal(cleanup.confirmed, false);
  assert.deepEqual(cleanup.retained, ['vm', 'installer']);
  assert.equal(removed, false);
});

test('cleanup includes resources acquired by a borrower while revocation is in flight',
  { timeout: 5000 }, async () => {
    const owner = new ProvisionOwner(Date.now() + 10000);
    const started = deferred(), resume = deferred();
    const drained = Promise.reject(new Error('late-close-unconfirmed'));
    void drained.catch(() => undefined);
    let removed = false;
    const borrowed = owner.borrow(async () => {
      started.resolve();
      await resume.promise;
      owner.own({ identity: 'late-process', drained,
        async remove() { removed = true; return true; } });
    });
    const rejected = assert.rejects(borrowed, { code: 'owner_closed' });
    await started.promise;
    const closing = owner.close();
    resume.resolve();
    await rejected;
    assert.deepEqual(await closing,
      { confirmed: false, retained: ['late-process'], failures: ['drain_unconfirmed'] });
    assert.equal(removed, false);
  });

test('same-byte inode replacement cannot preserve a bound descriptor identity', async () => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'backend-fd-'));
  const path = join(root, 'helper');
  await writeFile(path, 'fixed', { mode: 0o600 });
  const file = await ProvisionFile.open(path);
  try {
    await writeFile(join(root, 'replacement'), 'fixed', { mode: 0o600 });
    await rename(join(root, 'replacement'), path);
    await assert.rejects(file.check(), { code: 'file_identity_changed' });
  } finally {
    await file.close();
    await rm(root, { recursive: true });
  }
});

test('controller rejects substitution between producer descriptor capture and controller adoption', async () => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'backend-adopt-'));
  const path = join(root, 'asset');
  await writeFile(path, 'fixed', { mode: 0o600 });
  const original = await open(path, 'r');
  try {
    const adopted = await ProvisionFile.borrow(path, original.fd);
    await adopted.close();
    await writeFile(join(root, 'replacement'), 'fixed', { mode: 0o600 });
    await rename(join(root, 'replacement'), path);
    await assert.rejects(ProvisionFile.borrow(path, original.fd), { code: 'file_identity_changed' });
  } finally {
    await original.close();
    await rm(root, { recursive: true });
  }
});

test('abort requests termination but cannot resolve process close before real exit', async () => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'backend-process-'));
  const abort = new AbortController();
  const owned = new ProvisionProcess({
    executable: process.execPath, home: root, limaHome: root, temporary: root,
    argv: ['-e', "process.on('SIGINT',()=>process.stdout.write('signal\\n'));"
      + "process.stdin.resume();process.stdout.write('ready\\n');"
      + "process.stdin.on('data',()=>process.exit(0));"],
  }, abort.signal);
  const ready = once(owned.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
  let closed = false;
  void owned.closed.then(() => { closed = true; });
  try {
    await ready;
    const acknowledged = once(owned.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
    abort.abort();
    await acknowledged;
    assert.equal(closed, false);
    owned.child.stdin.end('exit');
    const result = await owned.closed;
    assert.equal(result.groupAbsent, true);
    assert.equal(closed, true);
  } finally {
    owned.stop();
    await owned.closed;
    await rm(root, { recursive: true });
  }
});
