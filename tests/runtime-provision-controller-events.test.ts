import assert from 'node:assert/strict';
import { getEventListeners, once } from 'node:events';
import { appendFile, link, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { LimaEvents } from '../src/runtime/runtimes/provision-controller-events.js';

async function withDirectory(initial: string, use: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'lima-events-'));
  try {
    await writeFile(join(directory, 'ha.stdout.log'), initial, { mode: 0o600 });
    await use(directory);
  } finally {
    await rm(directory, { recursive: true });
  }
}

for (const alreadyAborted of [false, true]) {
  test(`public cancellation leaves fixture delivery alive when already aborted is ${alreadyAborted}`,
    { timeout: 5000 }, async () => {
      await withDirectory('', async directory => {
        const observer = new AbortController();
        const caller = new AbortController();
        const events = new LimaEvents(directory, observer.signal);
        try {
          if (alreadyAborted) caller.abort();
          const rejected = assert.rejects(events.waitRunning(caller.signal), { code: 'boot_aborted' });
          const ready = events.waitRunning(new AbortController().signal);
          if (!alreadyAborted) caller.abort();
          await rejected;
          assert.equal(events.failureSignal.aborted, false);
          assert.equal(getEventListeners(observer.signal, 'abort').length, 1);
          await appendFile(join(directory, 'ha.stdout.log'), '{"status":{"running":true}}\n');
          await ready;
          await appendFile(join(directory, 'ha.stdout.log'), '{"status":{"exiting":true}}\n');
          await events.exiting;
        } finally {
          await events.close();
        }
        assert.equal(getEventListeners(observer.signal, 'abort').length, 0);
      });
    });
}

test('settled readiness removes only its own public abort listener', { timeout: 5000 }, async () => {
  await withDirectory('', async directory => {
    const observer = new AbortController();
    const caller = new AbortController();
    let cancellations = 0;
    const external = () => { cancellations++; };
    caller.signal.addEventListener('abort', external);
    const events = new LimaEvents(directory, observer.signal);
    try {
      const ready = events.waitRunning(caller.signal);
      await appendFile(join(directory, 'ha.stdout.log'), '{"status":{"running":true}}\n');
      await ready;
      assert.deepEqual(getEventListeners(caller.signal, 'abort'), [external]);
      caller.abort();
      assert.equal(cancellations, 1);
      await events.running;
      await appendFile(join(directory, 'ha.stdout.log'), '{"status":{"exiting":true}}\n');
      await events.exiting;
    } finally {
      await events.close();
      caller.signal.removeEventListener('abort', external);
    }
  });
});

test('settled readiness retains a later real fixture read failure epoch', { timeout: 5000 }, async () => {
  await withDirectory('{"status":{"running":true}}\n', async directory => {
    const events = new LimaEvents(directory, new AbortController().signal);
    try {
      await events.running;
      let announced = false;
      events.failureSignal.addEventListener('abort', () => { announced = true; }, { once: true });
      const notified = once(events.failureSignal, 'abort', { signal: AbortSignal.timeout(4000) });
      const exited = assert.rejects(events.exiting, error => {
        assert.equal(announced, true);
        assert.ok(error instanceof SyntaxError);
        assert.equal(error, events.failureSignal.reason);
        return true;
      });
      await appendFile(join(directory, 'ha.stdout.log'), 'not-json\n');
      await Promise.all([notified, exited]);
    } finally {
      await assert.rejects(events.close(), SyntaxError);
    }
  });
});

test('reconciliation retains a partial fixture frame for actual watcher delivery',
  { timeout: 5000 }, async () => {
    await withDirectory('{"status":{"running":true}}\n{"status":', async directory => {
      const events = new LimaEvents(directory, new AbortController().signal);
      try {
        await events.running;
        const delivered = events.exiting;
        await appendFile(join(directory, 'ha.stdout.log'), '{"exiting":true}}\n');
        await delivered;
      } finally {
        await events.close();
      }
    });
  });

test('idempotent close joins initial queued fixture reconciliation', { timeout: 5000 }, async () => {
  await withDirectory('{"status":{"running":true}}\n{"status":{"exiting":true}}\n', async directory => {
    const events = new LimaEvents(directory, new AbortController().signal);
    let runningDelivered = false;
    let exitingDelivered = false;
    void events.running.then(() => { runningDelivered = true; });
    void events.exiting.then(() => { exitingDelivered = true; });
    const closing = events.close();
    assert.equal(events.close(), closing);
    await closing;
    assert.equal(runningDelivered, true);
    assert.equal(exitingDelivered, true);
  });
});

for (const alreadyAborted of [false, true]) {
  test(`private observer cancellation remains a failure when already aborted is ${alreadyAborted}`,
    { timeout: 5000 }, async () => {
      await withDirectory('', async directory => {
        const observer = new AbortController();
        if (alreadyAborted) observer.abort();
        const events = new LimaEvents(directory, observer.signal);
        const running = assert.rejects(events.running, { code: 'boot_aborted' });
        const exiting = assert.rejects(events.exiting, { code: 'boot_aborted' });
        const waiter = assert.rejects(events.waitRunning(new AbortController().signal), { code: 'boot_aborted' });
        try {
          if (!alreadyAborted) observer.abort();
          await Promise.all([running, exiting, waiter]);
        } finally {
          await assert.rejects(events.close(), { code: 'boot_aborted' });
        }
        assert.equal(getEventListeners(observer.signal, 'abort').length, 0);
      });
    });
}

const invalidFixtures = [
  { text: '{"status":{"degraded":true}}\n', code: 'boot_failed' },
  { text: '{"status":{"errors":[]}}\n', code: 'boot_failed' },
  { text: '{"status":{"exiting":true}}\n', code: 'boot_exited' },
  { text: 'x'.repeat(16385), code: 'boot_event_bound' },
  { text: '{"status":{"padding":"' + 'x'.repeat(16385) + '"}}\n', code: 'boot_event_bound' },
] as const;

for (const fixture of invalidFixtures) {
  test(`invalid fixture rejects readiness and closure: ${fixture.code} (${fixture.text.length} bytes)`,
    { timeout: 5000 }, async () => {
      await withDirectory(fixture.text, async directory => {
        const events = new LimaEvents(directory, new AbortController().signal);
        try {
          await assert.rejects(events.waitRunning(new AbortController().signal), { code: fixture.code });
        } finally {
          const closing = events.close();
          assert.equal(events.close(), closing);
          await assert.rejects(closing, { code: fixture.code });
        }
      });
    });
}

test('malformed JSON retains its genuine read failure through close', { timeout: 5000 }, async () => {
  await withDirectory('not-json\n', async directory => {
    const events = new LimaEvents(directory, new AbortController().signal);
    let failure: Error | undefined;
    try {
      await assert.rejects(events.running, error => {
        assert.ok(error instanceof SyntaxError);
        failure = error;
        return true;
      });
    } finally {
      await assert.rejects(events.close(), error => {
        assert.equal(error, failure);
        return true;
      });
    }
  });
});

test('a hard-linked fixture is rejected by the real descriptor identity check',
  { timeout: 5000 }, async () => {
    await withDirectory('{"status":{"running":true}}\n', async directory => {
      await link(join(directory, 'ha.stdout.log'), join(directory, 'alias'));
      const events = new LimaEvents(directory, new AbortController().signal);
      try {
        await assert.rejects(events.running, { code: 'boot_event_identity' });
      } finally {
        await assert.rejects(events.close(), { code: 'boot_event_identity' });
      }
    });
  });
