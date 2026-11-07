import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { consumeInstallOperation } from '../src/runtime/runtimes/provision-install.js';

async function withChild(script: string, use: (child: ChildProcessWithoutNullStreams) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'install-wire-'));
  const child = spawn(process.execPath, ['-e', script], { stdio: ['pipe', 'pipe', 'pipe'],
    env: { RUN_TMP: root, TMPDIR: root, NODE_COMPILE_CACHE: join(root, 'node'),
      BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun') } });
  const closed = once(child, 'close', { signal: AbortSignal.timeout(10000) });
  try { await use(child); }
  finally {
    child.kill('SIGKILL');
    await closed;
    await rm(root, { recursive: true, force: true });
  }
}

test('a detached success wire cannot restore a supervisor operation', async () => {
  await withChild(`process.stdout.write('INSTALLED '+('a'.repeat(64)+' ').repeat(2)+'a'.repeat(64)+'\\n')`,
    async child => {
      const operation = consumeInstallOperation(child, new AbortController().signal);
      await assert.rejects(operation.result, { code: 'protocol_order_or_binding' });
      assert.deepEqual(await operation.drained, { transportClosed: true, guestCleanupConfirmed: false });
    });
});

test('replacement receipt is rejected after the real synthetic child preparation handshake', async () => {
  await withChild(`
    process.stdin.once('data', () => {
      process.stdout.write('INSTALLED '+('b'.repeat(64)+' ').repeat(2)+'b'.repeat(64)+'\\n');
      process.stdin.destroy();
    });
    process.stdout.write('PREPARED '+'a'.repeat(64)+'\\n');
  `, async child => {
    const operation = consumeInstallOperation(child, new AbortController().signal);
    await assert.rejects(operation.result, { code: 'protocol_order_or_binding' });
    await operation.drained;
  });
});

test('abort revokes outcome while drain waits for the actual close event', async () => {
  await withChild(`
    process.on('SIGTERM', () => {});
    process.stdin.resume();
    process.stderr.write('ready\\n');
  `, async child => {
    const ready = once(child.stderr, 'data', { signal: AbortSignal.timeout(5000) });
    const controller = new AbortController();
    const operation = consumeInstallOperation(child, controller.signal);
    let drained = false;
    void operation.drained.then(() => { drained = true; });
    const rejected = assert.rejects(operation.result, { code: 'operation_aborted' });
    await ready;
    controller.abort();
    await rejected;
    assert.equal(drained, false);
    child.kill('SIGKILL');
    await operation.drained;
    assert.equal(drained, true);
  });
});

test('deadline and kill grace expiry never manufacture process drain', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  await withChild(`
    process.on('SIGTERM', () => {});
    process.stdin.resume();
    process.stderr.write('ready\\n');
  `, async child => {
    const ready = once(child.stderr, 'data', { signal: AbortSignal.timeout(5000) });
    const operation = consumeInstallOperation(child, new AbortController().signal);
    let drained = false;
    void operation.drained.then(() => { drained = true; });
    const rejected = assert.rejects(operation.result, { code: 'operation_deadline' });
    await ready;
    t.mock.timers.tick(900_000);
    await rejected;
    t.mock.timers.tick(5000);
    await Promise.resolve();
    assert.equal(drained, false);
    await operation.drained;
    assert.equal(drained, true);
  });
  t.mock.timers.reset();
});

test('concurrent reuse revokes the original exchange and remains drainable', async () => {
  await withChild('process.stdin.resume()', async child => {
    const signal = new AbortController().signal;
    const operation = consumeInstallOperation(child, signal);
    const rejected = assert.rejects(operation.result);
    assert.throws(() => consumeInstallOperation(child, signal), { code: 'operation_replay' });
    await rejected;
    await operation.drained;
  });
});
