import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { authenticateGuest } from '../src/runtime/runtimes/provision-controller-auth.js';
import { ProvisionRelayWire } from '../src/runtime/runtimes/provision-relay-wire.js';
import { ProvisionOwner } from '../src/runtime/runtimes/provision-controller-owner.js';

test('bootstrap host-key authentication rejects substitution and challenge replay', () => {
  const nonce = '12'.repeat(32), challenge = '34'.repeat(32), helper = '56'.repeat(32);
  const payload = { boot: '12345678-1234-1234-1234-123456789abc', challenge, helper,
    key: 'ssh-ed25519 ' + 'A'.repeat(68) };
  const mac = createHmac('sha256', Buffer.from(nonce, 'hex')).update(JSON.stringify(payload)).digest('hex');
  assert.deepEqual(authenticateGuest(JSON.stringify({ payload, mac }), { nonce, challenge, helper }),
    { boot: payload.boot, helper, key: payload.key });
  assert.throws(() => authenticateGuest(JSON.stringify({ payload: { ...payload, key: 'ssh-ed25519 '
    + 'B'.repeat(68) }, mac }), { nonce, challenge, helper }), { code: 'guest_identity_mac' });
  assert.throws(() => authenticateGuest(JSON.stringify({ payload, mac }),
    { nonce, challenge: '78'.repeat(32), helper }), { code: 'guest_identity_binding' });
});

async function withPeer(change: string, use: (wire: ProvisionRelayWire) => Promise<void>) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'backend-wire-'));
  // A synthetic wire peer tests framing/authentication only; it cannot issue a production backend.
  const child = spawn(process.execPath, ['-e', `
    const {createHmac}=require('node:crypto');
    let pending=Buffer.alloc(0);
    process.stdin.on('data',chunk=>{
      pending=Buffer.concat([pending,chunk]);
      if(pending.length<4||pending.length<4+pending.readUInt32BE(0))return;
      const request=JSON.parse(pending.subarray(4));
      const response={version:1,sequence:request.sequence,run:request.run,
        challenge:request.challenge,result:{observed:'wire-only'}};
      let mac=createHmac('sha256',Buffer.from('12'.repeat(32),'hex'))
        .update('response:'+JSON.stringify(response)).digest('hex');
      ${change}
      const body=Buffer.from(JSON.stringify({...response,mac}));
      const header=Buffer.alloc(4);header.writeUInt32BE(body.length);
      process.stdout.write(header.subarray(0,2));
      process.stdout.write(Buffer.concat([header.subarray(2),body]));
    });
  `], { stdio: ['pipe', 'pipe', 'pipe'], env: { RUN_TMP: root, TMPDIR: root,
    NODE_COMPILE_CACHE: join(root, 'node'), BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun') } });
  const closed = once(child, 'close', { signal: AbortSignal.timeout(10000) });
  const signal = new AbortController();
  const wire = new ProvisionRelayWire(child, { nonce: '12'.repeat(32), run: 'ab'.repeat(16) }, signal.signal);
  try { await use(wire); }
  finally {
    wire.close();
    child.kill('SIGKILL');
    await closed;
    await rm(root, { recursive: true });
  }
}

test('authenticated wire reassembles fragmented frames without granting backend authority', async () => {
  await withPeer('', async wire => {
    const response = await wire.request({ operation: 'identity' });
    assert.equal(response.observed, 'wire-only');
  });
});

test('wire rejects incorrect MAC and reflected or substituted response bindings', async () => {
  for (const change of [
    "mac='00'.repeat(32);",
    'response.sequence++;',
    "response.run='cd'.repeat(16);",
    "response.challenge='ef'.repeat(32);",
  ]) {
    await withPeer(change, async wire => {
      let notifications = 0;
      wire.failureSignal.addEventListener('abort', () => { notifications++; }, { once: true });
      const refused = wire.request({ operation: 'identity' }).catch((error: unknown) => {
        assert.equal(notifications, 1);
        assert.equal(error, wire.failureSignal.reason);
        throw error;
      });
      await assert.rejects(refused, { code: 'relay_frame_invalid' });
      await assert.rejects(wire.request({ operation: 'identity' }), { code: 'relay_frame_invalid' });
      assert.equal(notifications, 1);
    });
  }
});

test('closing idle admission preserves one authenticated wire-only shutdown', async () => {
  await withPeer('', async wire => {
    assert.equal(wire.beginClose(), true);
    await assert.rejects(wire.request({ operation: 'identity' }), { code: 'relay_closed' });
    assert.deepEqual(await wire.shutdown(), { observed: 'wire-only' });
    await assert.rejects(wire.shutdown(), { code: 'relay_closed' });
    assert.equal(wire.beginClose(), false);
  });
});

test('closing active admission rejects the original request without concurrent cleanup', async () => {
  await withPeer('', async wire => {
    const pending = wire.request({ operation: 'identity' });
    const rejected = assert.rejects(pending, { code: 'relay_closed' });
    assert.equal(wire.beginClose(), false);
    await rejected;
    await assert.rejects(wire.shutdown(), { code: 'relay_closed' });
    await assert.rejects(wire.request({ operation: 'identity' }), { code: 'relay_closed' });
  });
});

test('cleanup deadline reports retention and never treats elapsed grace as a drain event', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const owner = new ProvisionOwner(Date.now() + 10000);
  let removed = false;
  owner.own({ identity: 'unclosed-vm', stop() {}, drained: new Promise<void>(() => {}),
    async remove() { removed = true; return true; } });
  const closing = owner.close();
  t.mock.timers.tick(120000);
  const cleanup = await closing;
  assert.deepEqual(cleanup, { confirmed: false, retained: ['unclosed-vm'], failures: ['drain_unconfirmed'] });
  assert.equal(removed, false);
  t.mock.timers.reset();
});
