import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProvisionOwner } from '../src/runtime/runtimes/provision-controller-owner.js';
import { ProvisionProcess } from '../src/runtime/runtimes/provision-controller-process.js';
import { sshArgv } from '../src/runtime/runtimes/provision-controller-auth.js';
import { relayServiceArgv } from '../src/runtime/runtimes/provision-relay.js';

const python = process.env['T6P_TEST_PYTHON'];
if (!python) throw new Error('T6P_TEST_PYTHON is required');
const interpreter = python;
const probe = `import os,signal
signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT})
os.write(2,b'ready\\n')
for index in range(2):
    os.read(0,1)
    pending=int(signal.SIGINT in signal.sigpending())
    os.write(2,('pending='+str(pending)+'\\n').encode())
os.read(0,1)
os._exit(0)
`;

async function withProbe(use: (owned: ProvisionProcess, owner: ProvisionOwner) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'private-process-'));
  const owner = new ProvisionOwner(Date.now() + 15_000);
  const privateSignal = new AbortController();
  const owned = new ProvisionProcess({ executable: interpreter, argv: ['-I', '-B', '-c', probe],
    home: root, limaHome: root, temporary: root }, privateSignal.signal);
  owner.own({ identity: 'probe:' + owner.run, stop: () => owned.stop(), drained: owned.drain(),
    remove: async () => (await owned.closed).groupAbsent });
  try {
    const [ready] = await once(owned.child.stderr, 'data', { signal: AbortSignal.timeout(5000) });
    assert.equal(String(ready), 'ready\n');
    await use(owned, owner);
  } finally {
    owned.stop();
    if (!owned.child.stdin.writableEnded && !owned.child.stdin.destroyed) owned.child.stdin.end('ggg');
    try {
      await assert.rejects(owned.drain(), { code: 'process_pipe_unconfirmed' });
      assert.equal((await owned.closed).code, 0);
      const cleanup = await owner.close();
      assert.equal(cleanup.confirmed, false);
      assert.deepEqual(cleanup.retained, ['probe:' + owner.run]);
    } finally { await rm(root, { recursive: true }); }
  }
}

async function pendingSignal(owned: ProvisionProcess): Promise<number> {
  const reply = once(owned.child.stderr, 'data', { signal: AbortSignal.timeout(5000) });
  owned.child.stdin.write('g');
  const [bytes] = await reply;
  const frame = String(bytes);
  assert.match(frame, /^pending=[01]\n$/);
  return Number(frame.slice(8, 9));
}

async function damagePipe(owned: ProvisionProcess): Promise<void> {
  const closed = once(owned.child.stdout, 'close', { signal: AbortSignal.timeout(5000) });
  owned.child.stdout.destroy();
  await closed;
  assert.equal(owned.child.stdout.readableEnded, false);
}

test('protected process remains live after observer failure until its original owner explicitly stops it',
  { timeout: 15000 }, async () => {
    await withProbe(async (owned, owner) => {
      await damagePipe(owned);
      assert.equal(await pendingSignal(owned), 0);
      const closing = owner.close();
      assert.equal(await pendingSignal(owned), 1);
      owned.child.stdin.end('g');
      assert.equal((await closing).confirmed, false);
    });
  });

test('protected failure revokes public eligibility without stopping the retained private child',
  { timeout: 15000 }, async () => {
    await withProbe(async (owned, owner) => {
      owned.failureSignal.addEventListener('abort', () => owner.revoke('process_failed'), { once: true });
      await damagePipe(owned);
      assert.equal(owned.failureSignal.aborted, true);
      assert.throws(() => owner.check(), { code: 'process_failed' });
      assert.equal(await pendingSignal(owned), 0);
      const closing = owner.close();
      assert.equal(await pendingSignal(owned), 1);
      owned.child.stdin.end('g');
      assert.equal((await closing).confirmed, false);
    });
  });

test('ordinary manager latches owner failure and immediately stops its actual child',
  { timeout: 15000 }, async () => {
    await withProbe(async (owned, owner) => {
      let notifications = 0;
      owned.failureSignal.addEventListener('abort', () => {
        notifications++;
        owner.revoke('process_failed');
        owned.stop();
      }, { once: true });
      await damagePipe(owned);
      assert.equal(owned.failureSignal.reason.code, 'process_failed');
      assert.throws(() => owner.check(), { code: 'process_failed' });
      assert.equal(await pendingSignal(owned), 1);
      assert.equal(notifications, 1);
    });
  });

test('already-revoked owner cannot replace direct stop of a later separate-signal cleanup child',
  { timeout: 15000 }, async () => {
    await withProbe(async (owned, owner) => {
      owner.revoke('earlier_failure');
      assert.equal(await pendingSignal(owned), 0);
      owned.failureSignal.addEventListener('abort', () => {
        owner.revoke('process_failed');
        owned.stop();
      }, { once: true });
      await damagePipe(owned);
      assert.equal(owned.failureSignal.aborted, true);
      assert.throws(() => owner.check(), { code: 'earlier_failure' });
      assert.equal(await pendingSignal(owned), 1);
    });
  });

test('registration handles a retained process failure that preceded its listener',
  { timeout: 15000 }, async () => {
    await withProbe(async (owned, owner) => {
      await damagePipe(owned);
      assert.equal(owned.failureSignal.aborted, true);
      assert.equal(await pendingSignal(owned), 0);
      const failed = () => {
        owner.revoke('process_failed');
        owned.stop();
      };
      owned.failureSignal.addEventListener('abort', failed, { once: true });
      if (owned.failureSignal.aborted) failed();
      assert.throws(() => owner.check(), { code: 'process_failed' });
      assert.equal(await pendingSignal(owned), 1);
    });
  });

test('strict SSH and fixed relay service formatters preserve security flags and scalar operand boundaries', () => {
  const guest = { knownHosts: '/private/tmp/known hosts', name: 'wk-123', key: '/private/tmp/key file', port: 2222 };
  const argv = sshArgv(guest, ['/usr/bin/true', '--flag']);
  for (const option of ['BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes',
    'UserKnownHostsFile=' + guest.knownHosts, 'HostKeyAlias=' + guest.name,
    'ForwardAgent=no', 'ClearAllForwardings=yes']) {
    const index = argv.indexOf(option);
    assert.ok(index > 0);
    assert.equal(argv[index - 1], '-o');
  }
  assert.deepEqual(argv.slice(0, 4), ['-F', '/dev/null', '-T', '-o']);
  assert.equal(argv[argv.indexOf('-i') + 1], guest.key);
  assert.deepEqual(argv.slice(argv.indexOf('-p'), argv.indexOf('-p') + 3),
    ['-p', '2222', 'wakeio-admin@127.0.0.1']);
  assert.deepEqual(argv.slice(-8), ['/usr/bin/sudo', '-n', '/usr/bin/env', '-i',
    'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C', '/usr/bin/true', '--flag']);
  const run = 'a'.repeat(32), service = relayServiceArgv(run);
  assert.deepEqual(service.slice(0, 6), ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
    '--service-type=exec']);
  assert.equal(service[6], '--unit=wakeio-backend-' + run + '.service');
  assert.deepEqual(service.filter(arg => arg.startsWith('--property=')), [
    '--property=CPUQuota=50%', '--property=MemoryMax=268435456', '--property=TasksMax=64',
    '--property=RuntimeMaxSec=900', '--property=TimeoutStopSec=30', '--property=KillMode=control-group',
  ]);
  assert.deepEqual(service.slice(-5), ['/usr/bin/python3', '-I', '-B',
    '/usr/local/lib/wakeio-controller/relay.py', run]);
});
