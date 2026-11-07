import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ProvisionProcess } from '../src/runtime/runtimes/provision-controller-process.js';

const python = process.env['T6P_TEST_PYTHON'];
if (!python) throw new Error('T6P_TEST_PYTHON is required');
const interpreter = python;
const probe = `import os,signal
os.set_blocking(0,False)
def check(signum,frame):
    try:
        os.read(0,1)
        os._exit(125)
    except BlockingIOError:
        os.write(1,b'silent-open\\n')
        os.write(2,b'observed-error-stream\\n')
        os._exit(19)
signal.signal(signal.SIGUSR1,check)
os.write(1,b'ready\\n')
signal.pause()
`;

async function withProcess(script: string,
  use: (owned: ProvisionProcess, abort: AbortController) => Promise<void>,
  drainFailure?: 'process_pipe_unconfirmed') {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'native-process-'));
  const abort = new AbortController();
  const owned = new ProvisionProcess({ executable: interpreter, argv: ['-I', '-B', '-c', script],
    home: root, limaHome: root, temporary: root }, abort.signal);
  owned.failureSignal.addEventListener('abort', () => owned.stop(), { once: true });
  if (owned.failureSignal.aborted) owned.stop();
  try { await use(owned, abort); }
  finally {
    owned.stop();
    try {
      if (drainFailure) await assert.rejects(owned.drain(), { code: drainFailure });
      else await owned.drain();
    } finally { await rm(root, { recursive: true }); }
  }
}

function trigger(owned: ProvisionProcess) {
  assert.ok(owned.child.pid);
  process.kill(owned.child.pid, 'SIGUSR1');
}

test('open observation preserves a live silent kernel pipe and both streams on nonzero CLOSE',
  { timeout: 10000 }, async () => {
    await withProcess(probe, async owned => {
      const ready = once(owned.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
      const observation = owned.observeOpenInput();
      await ready;
      trigger(owned);
      const result = await observation;
      assert.deepEqual(result, { code: 19, signal: null, groupAbsent: true,
        stdout: 'ready\nsilent-open\n', stderr: 'observed-error-stream\n' });
      assert.equal((await owned.closed).code, 19);
    });
  });

test('one process capture cannot be replayed through either public observation method',
  { timeout: 10000 }, async () => {
    await withProcess(probe, async owned => {
      const ready = once(owned.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
      const original = owned.observeOpenInput();
      await assert.rejects(owned.observeOpenInput(), { code: 'command_output_replay' });
      await assert.rejects(owned.output('forbidden'), { code: 'command_output_replay' });
      await ready;
      trigger(owned);
      assert.equal((await original).code, 19);
    });
  });

test('aborted open observation rejects before actual CLOSE without manufacturing drainage',
  { timeout: 10000 }, async () => {
    await withProcess(`import os,signal
signal.signal(signal.SIGINT,lambda signum,frame:os.write(1,b'ack\\n'))
signal.signal(signal.SIGUSR1,lambda signum,frame:os._exit(0))
os.write(1,b'ready\\n')
while True: signal.pause()
`, async (owned, abort) => {
      const ready = once(owned.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
      let closed = false;
      void owned.closed.then(() => { closed = true; });
      const rejected = assert.rejects(owned.observeOpenInput(), { code: 'command_aborted' });
      await ready;
      const acknowledged = once(owned.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
      abort.abort();
      await acknowledged;
      await rejected;
      assert.equal(closed, false);
      trigger(owned);
      await owned.drain();
      assert.equal(closed, true);
    });
  });

test('combined stdout and stderr overflow refuses a result and retains real drain',
  { timeout: 10000 }, async () => {
    await withProcess('import sys;sys.stdout.buffer.write(b"x"*600000);sys.stdout.flush();'
      + 'sys.stderr.buffer.write(b"y"*600000);sys.stderr.flush()', async owned => {
      await assert.rejects(owned.observeOpenInput(), { code: 'command_failed' });
      await owned.drain();
      assert.equal((await owned.closed).groupAbsent, true);
    });
  });

test('ordinary output still supplies bytes then EOF and rejects nonzero child exit',
  { timeout: 10000 }, async () => {
    for (const code of [0, 19]) {
      await withProcess('import sys;sys.stdout.write(sys.stdin.read());sys.exit(' + code + ')', async owned => {
        const result = owned.output('ordinary-input');
        if (code === 0) assert.equal(await result, 'ordinary-input');
        else await assert.rejects(result, { code: 'command_failed' });
      });
    }
  });

test('drain retains both original EOF orders before releasing the captured result',
  { timeout: 15000 }, async () => {
    for (const first of ['stdout', 'stderr'] as const) {
      const fd = first === 'stdout' ? 1 : 2;
      await withProcess(`import os,signal
signal.signal(signal.SIGUSR1,lambda signum,frame:os._exit(0))
os.write(1,b'ordinary-out')
os.write(2,b'ordinary-err')
os.close(${fd})
signal.pause()
`, async owned => {
        const eof = once(owned.child[first], 'end', { signal: AbortSignal.timeout(5000) });
        let drained = false;
        const draining = owned.drain().then(() => { drained = true; });
        const captured = owned.observeOpenInput();
        await eof;
        assert.equal(drained, false);
        trigger(owned);
        assert.deepEqual(await captured, { code: 0, signal: null, groupAbsent: true,
          stdout: 'ordinary-out', stderr: 'ordinary-err' });
        await draining;
        assert.equal(drained, true);
      });
    }
  });

test('destroying either original pipe retains failure and still joins the other pipe and child',
  { timeout: 15000 }, async () => {
    for (const pipe of ['stdout', 'stderr'] as const) {
      const damaged = pipe === 'stdout' ? 1 : 2;
      const other = pipe === 'stdout' ? 'stderr' : 'stdout';
      const intact = damaged === 1 ? 2 : 1;
      await withProcess(`import os,signal
signal.signal(signal.SIGINT,lambda signum,frame:os.write(${intact},b'ack'))
signal.signal(signal.SIGUSR1,lambda signum,frame:os._exit(0))
os.write(${damaged},b'ready')
while True: signal.pause()
`, async owned => {
        const ready = once(owned.child[pipe], 'data', { signal: AbortSignal.timeout(5000) });
        const captured = assert.rejects(owned.observeOpenInput(), { code: 'command_failed' });
        await ready;
        let settled = false;
        const draining = owned.drain().finally(() => { settled = true; });
        const refused = assert.rejects(draining, pipe === 'stderr'
          ? { code: 'process_pipe_unconfirmed', retained: ['original-pipe-error'] }
          : { code: 'process_pipe_unconfirmed' });
        const acknowledged = once(owned.child[other], 'data', { signal: AbortSignal.timeout(5000) });
        const closed = new Promise<void>(resolve => owned.child[pipe].once('close', resolve));
        owned.child[pipe].destroy(pipe === 'stderr' ? new Error('original-pipe-error') : undefined);
        await closed;
        await acknowledged;
        assert.equal(owned.child[pipe].readableEnded, false);
        assert.equal(owned.child[other].readableEnded, false);
        assert.equal(settled, false);
        trigger(owned);
        await captured;
        await refused;
        assert.equal((await owned.closed).code, 0);
        assert.equal(settled, true);
      }, 'process_pipe_unconfirmed');
    }
  });

test('passive drain registration preserves buffered ordinary bytes until capture attaches',
  { timeout: 15000 }, async () => {
    for (const pipe of ['stdout', 'stderr'] as const) {
      const fd = pipe === 'stdout' ? 1 : 2;
      const other = pipe === 'stdout' ? 'stderr' : 'stdout';
      const ack = fd === 1 ? 2 : 1;
      await withProcess(`import os
os.write(${fd},b'buffered-prefix')
os.read(0,1)
os.write(${ack},b'ack')
while os.read(0,4096): pass
os.write(${fd},b'-suffix')
`, async owned => {
        await once(owned.child[pipe], 'readable', { signal: AbortSignal.timeout(5000) });
        const acknowledged = once(owned.child[other], 'data', { signal: AbortSignal.timeout(5000) });
        const draining = owned.drain();
        owned.child.stdin.write('g');
        await acknowledged;
        const captured = owned.observeOpenInput();
        owned.child.stdin.end();
        const result = await captured;
        assert.equal(result[pipe], 'buffered-prefix-suffix');
        await draining;
        assert.equal((await owned.closed).groupAbsent, true);
      });
    }
  });

test('drain retains an inherited open pipe until its writer exits and the original child reaps it',
  { timeout: 10000 }, async () => {
    await withProcess(`import os,signal
reader,writer=os.pipe()
signal.signal(signal.SIGUSR1,lambda signum,frame:os.write(writer,b'g'))
pid=os.fork()
if pid == 0:
    os.close(writer)
    os.write(1,b'inherited-ready')
    os.read(reader,1)
    os.write(1,b'-final')
    os._exit(0)
os.close(reader)
os.close(1)
os.close(2)
os.waitpid(pid,0)
`, async owned => {
      const ready = once(owned.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
      let drained = false;
      const draining = owned.drain().then(() => { drained = true; });
      const captured = owned.observeOpenInput();
      await ready;
      assert.equal(drained, false);
      trigger(owned);
      assert.deepEqual(await captured, { code: 0, signal: null, groupAbsent: true,
        stdout: 'inherited-ready-final', stderr: '' });
      await draining;
      assert.equal(drained, true);
    });
  });
