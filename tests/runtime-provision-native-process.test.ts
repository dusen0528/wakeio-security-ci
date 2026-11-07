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
  use: (owned: ProvisionProcess, abort: AbortController) => Promise<void>) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'native-process-'));
  const abort = new AbortController();
  const owned = new ProvisionProcess({ executable: interpreter, argv: ['-I', '-B', '-c', script],
    home: root, limaHome: root, temporary: root }, abort.signal);
  try { await use(owned, abort); }
  finally { owned.stop(); await owned.drain(); await rm(root, { recursive: true }); }
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
