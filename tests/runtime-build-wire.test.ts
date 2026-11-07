import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { buildRequest, buildResult, type BuildRequest } from '../src/runtime/runtimes/provision-build-wire.js';
import { ProvisionRelayWire } from '../src/runtime/runtimes/provision-relay-wire.js';

const token = '34'.repeat(32), digest = '56'.repeat(32);
const begin = { operation: 'build-begin', build: null, body: { profile: 'f01' } } as const;
const interpreter = process.env['T6P_TEST_PYTHON'];
if (!interpreter) throw new Error('T6P_TEST_PYTHON is required');
const python = interpreter;
const peer = join(process.env.BUILD_WIRE_TREE ?? process.cwd(), 'tests/native/fixtures/runtime_build_wire_peer.py');

async function withPeer(mode: string,
  use: (wire: ProvisionRelayWire, child: ChildProcessWithoutNullStreams) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'build-wire-'));
  const child = spawn(python, ['-I', '-B', peer, mode], {
    stdio: ['pipe', 'pipe', 'pipe'], env: { RUN_TMP: root, TMPDIR: root,
      NODE_COMPILE_CACHE: join(root, 'node'), BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun') },
  });
  const closed = once(child, 'close', { signal: AbortSignal.timeout(10000) });
  const wire = new ProvisionRelayWire(child, { nonce: '12'.repeat(32), run: 'ab'.repeat(16) },
    AbortSignal.timeout(10000));
  try { await use(wire, child); }
  finally {
    wire.close();
    child.stdin.end();
    child.kill('SIGTERM');
    await closed;
    await rm(root, { recursive: true });
  }
}

test('Python and host share v1 sequence and fragmented authenticated build observations', async () => {
  await withPeer('normal', async wire => {
    assert.deepEqual(await wire.request({ operation: 'identity' }), { observed: 'wire-only' });
    assert.deepEqual(await wire.build(begin), { build: token, result: { kind: 'allocated', generation: 1 } });
    for (let file = 0; file < 5; file++) {
      assert.deepEqual(await wire.build({ operation: 'build-input', build: token,
        body: { file, offset: 0, data: 'YWJj' } }),
      { build: token, result: { kind: 'input-accepted', file, nextOffset: 3 } });
    }
    assert.equal((await wire.build({ operation: 'build-seal', build: token,
      body: { files: Array.from({ length: 5 }, (_, file) => ({ file, bytes: 3, sha256: digest })) } }))
      .result.kind, 'sealed');
    for (const [operation, kind] of [
      ['build-prepare', 'preparation-closed'], ['build-offline', 'offline-closed'],
      ['build-assemble', 'assembled'],
    ] as const) {
      assert.equal((await wire.build({ operation, build: token, body: {} })).result.kind, kind);
      assert.deepEqual(await wire.request({ operation: 'identity' }), { observed: 'wire-only' });
    }
    assert.deepEqual(await wire.build({ operation: 'build-stop', build: token, body: { reason: 'completed' } }),
      { build: token, result: { kind: 'stop-requested' } });
    assert.deepEqual(await wire.build({ operation: 'build-close', build: token, body: {} }),
      { build: token, result: { kind: 'cleanup-state', state: 'confirmed', reason: null } });
  });
});

test('host waits for the body after an observed two byte header fragment', async () => {
  await withPeer('fragment', async (wire, child) => {
    const fragment = once(child.stdout, 'data', { signal: AbortSignal.timeout(10000) });
    const reply = wire.build(begin);
    const [chunk] = await fragment;
    assert.equal(Buffer.byteLength(chunk), 2);
    child.kill('SIGUSR1');
    assert.deepEqual(await reply, { build: token, result: { kind: 'allocated', generation: 1 } });
  });
});

test('host refuses reordered files offsets phases references and repeat begin before transmission', async () => {
  await withPeer('normal', async wire => {
    await wire.build(begin);
    await assert.rejects(wire.build(begin), { code: 'build_reservation' });
    await assert.rejects(wire.build({ operation: 'build-prepare', build: token, body: {} }),
      { code: 'build_phase' });
    await assert.rejects(wire.build({ operation: 'build-close', build: digest, body: {} }),
      { code: 'build_reference' });
    await wire.build({ operation: 'build-input', build: token, body: { file: 1, offset: 0, data: 'YQ==' } });
    for (const [file, offset] of [[0, 0], [1, 0], [1, 2]]) {
      await assert.rejects(wire.build({ operation: 'build-input', build: token,
        body: { file: file ?? -1, offset: offset ?? -1, data: 'YQ==' } }), { code: 'build_input_order' });
    }
    await assert.rejects(wire.build({ operation: 'build-seal', build: token,
      body: { files: Array.from({ length: 5 }, (_, file) => ({ file, bytes: 0, sha256: digest })) } }),
    { code: 'build_seal_order' });
    await wire.build({ operation: 'build-close', build: token, body: {} });
    await assert.rejects(wire.build({ operation: 'build-close', build: token, body: {} }),
      { code: 'build_reference' });
  });
});

test('an acknowledgement commits its offset before another data listener can replay the write', async () => {
  await withPeer('normal', async (wire, child) => {
    await wire.build(begin);
    const request = { operation: 'build-input', build: token,
      body: { file: 0, offset: 0, data: 'YQ==' } } as const;
    let received = Buffer.alloc(0);
    let replay: Promise<void> | undefined;
    const observe = (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (received.length < 4 || received.length < received.readUInt32BE(0) + 4) return;
      child.stdout.removeListener('data', observe);
      replay = assert.rejects(wire.build(request), { code: 'build_input_order' });
    };
    child.stdout.on('data', observe);
    await wire.build(request);
    assert.ok(replay);
    await replay;
  });
});

for (const [label, mode, send] of [
  ['v1 BOM', 'bom', (wire: ProvisionRelayWire) => wire.request({ operation: 'identity' })],
  ['build-v2 BOM', 'bom', (wire: ProvisionRelayWire) => wire.build(begin)],
  ['v1 invalid UTF8 with valid MAC', 'utf8-valid-mac',
    (wire: ProvisionRelayWire) => wire.request({ operation: 'identity' })],
] as const) {
  test(`canonical wire rejects authenticated ${label} bytes`, async () => {
    await withPeer(mode, async wire => {
      await assert.rejects(send(wire), { code: 'relay_frame_invalid' });
      await assert.rejects(wire.request({ operation: 'identity' }), { code: 'relay_frame_invalid' });
    });
  });
}

for (const mode of ['mac', 'sequence', 'challenge', 'run', 'operation', 'variant', 'extra', 'domain', 'order',
  'utf8', 'duplicate', 'whitespace']) {
  test(`authenticated host rejects ${mode} frame and permanently refuses reuse`, async () => {
    await withPeer(mode, async wire => {
      await assert.rejects(wire.build(begin), { code: 'relay_frame_invalid' });
      await assert.rejects(wire.request({ operation: 'identity' }), { code: 'relay_frame_invalid' });
    });
  });
}

test('later response must echo its build reference and cannot replay a begin response', async () => {
  for (const mode of ['build', 'replay']) {
    await withPeer(mode, async wire => {
      const reply = await wire.build(begin);
      assert.equal(reply.build, token);
      await assert.rejects(wire.build({ operation: 'build-input', build: reply.build ?? '',
        body: { file: 0, offset: 0, data: 'YQ==' } }), { code: 'relay_frame_invalid' });
    });
  }
});

test('truncation requires child CLOSE and oversized headers refuse without waiting for body', async () => {
  for (const [mode, code] of [['truncated', 'relay_closed'], ['overflow', 'relay_frame_bound']]) {
    await withPeer(mode ?? '', async wire => {
      await assert.rejects(wire.build(begin), { code });
      await assert.rejects(wire.build(begin), { code });
    });
  }
});

test('failed begin retains null correlation and consumes the original one use slot', async () => {
  await withPeer('failed', async wire => {
    assert.deepEqual(await wire.build(begin),
      { build: null, result: { kind: 'failed', reason: 'allocation_unknown' } });
    await assert.rejects(wire.build(begin), { code: 'build_reservation' });
  });
});

test('reservation charges all checkpoints and retains two closure plus thirty two teardown frames', async () => {
  await withPeer('normal', async wire => {
    for (let i = 0; i < 736; i++) await wire.request({ operation: 'identity' });
    await wire.build(begin);
    for (let i = 0; i < 253; i++) await wire.request({ operation: 'identity' });
    await assert.rejects(wire.request({ operation: 'identity' }), { code: 'build_budget' });
    await assert.rejects(wire.build({ operation: 'build-input', build: token,
      body: { file: 0, offset: 0, data: 'YQ==' } }), { code: 'build_budget' });
    await wire.build({ operation: 'build-stop', build: token, body: { reason: 'failure' } });
    await wire.build({ operation: 'build-close', build: token, body: {} });
    for (let i = 0; i < 32; i++) await wire.request({ operation: 'identity' });
    await assert.rejects(wire.request({ operation: 'identity' }), { code: 'relay_concurrent_or_exhausted' });
  });
  await withPeer('normal', async wire => {
    for (let i = 0; i < 737; i++) await wire.request({ operation: 'identity' });
    await assert.rejects(wire.build(begin), { code: 'build_reservation' });
    assert.deepEqual(await wire.request({ operation: 'identity' }), { observed: 'wire-only' });
  });
});

test('five maximum source files fit the charged reservation without enlarging a frame', async () => {
  await withPeer('normal', async wire => {
    await wire.build(begin);
    for (let file = 0; file < 5; file++) {
      for (let offset = 0; offset < 1048576; offset += 24576) {
        const length = Math.min(24576, 1048576 - offset);
        const reply = await wire.build({ operation: 'build-input', build: token,
          body: { file, offset, data: Buffer.alloc(length, file).toString('base64') } });
        assert.deepEqual(reply.result, { kind: 'input-accepted', file, nextOffset: offset + length });
      }
    }
    assert.equal((await wire.build({ operation: 'build-seal', build: token,
      body: { files: Array.from({ length: 5 }, (_, file) => ({ file, bytes: 1048576, sha256: digest })) } }))
      .result.kind, 'sealed');
  });
});

test('own data grammar refuses hooks proxies unknown keys noncanonical chunks and unsafe counts', () => {
  let invoked = false;
  const hooked = { operation: 'build-begin', build: null, get body() { invoked = true; return {}; } };
  for (const raw of [hooked, new Proxy(begin, {}), { ...begin, extra: true },
    { ...begin, body: { profile: 'f05' } },
    ...['YQ', 'YR==', 'YQ==\n', '', Buffer.alloc(24577).toString('base64')].map(data =>
      ({ operation: 'build-input', build: token, body: { file: 0, offset: 0, data } })),
    ...[-1, 5, 0.5, Number.MAX_SAFE_INTEGER + 1].map(file =>
      ({ operation: 'build-input', build: token, body: { file, offset: 0, data: 'YQ==' } })),
    { operation: 'build-input', build: token, body: { file: 0, offset: 1048576, data: 'YQ==' } },
  ]) assert.throws(() => buildRequest(raw));
  assert.equal(invoked, false);
});

test('phase result schemas enforce bounds platform reasons and the exact input acknowledgement', () => {
  const cases: readonly (readonly [BuildRequest, unknown])[] = [
    [begin, { kind: 'allocated', generation: 0 }],
    [begin, { kind: 'allocated', generation: Number.MAX_SAFE_INTEGER + 1 }],
    [begin, { kind: 'failed', reason: 'arbitrary' }],
    [{ operation: 'build-input', build: token, body: { file: 0, offset: 0, data: 'YQ==' } },
      { kind: 'input-accepted', file: 0, nextOffset: 2 }],
    [{ operation: 'build-prepare', build: token, body: {} }, { kind: 'preparation-closed',
      cache: { sha256: digest, bytes: 1073741825, entries: 1 }, closureSha256: digest }],
    [{ operation: 'build-prepare', build: token, body: {} }, { kind: 'preparation-closed',
      cache: { sha256: digest, bytes: 0, entries: 16385 }, closureSha256: digest }],
    [{ operation: 'build-offline', build: token, body: {} }, { kind: 'offline-closed',
      jar: { bytes: 67108865, sha256: digest }, classes: { sha256: digest, bytes: 0, entries: 0 } }],
    [{ operation: 'build-offline', build: token, body: {} }, { kind: 'offline-closed',
      jar: { bytes: 0, sha256: digest }, classes: { sha256: digest, bytes: 134217729, entries: 0 } }],
    [{ operation: 'build-offline', build: token, body: {} }, { kind: 'offline-closed',
      jar: { bytes: 0, sha256: digest }, classes: { sha256: digest, bytes: 0, entries: 4097 } }],
    [{ operation: 'build-assemble', build: token, body: {} }, { kind: 'assembled',
      image: { id: 'sha256:' + digest, configSha256: digest, os: 'linux',
        architecture: 'amd64', layersSha256: digest }, recipeSha256: digest, gateSha256: digest }],
    [{ operation: 'build-close', build: token, body: {} },
      { kind: 'cleanup-state', state: 'confirmed', reason: 'aborted' }],
  ];
  for (const [request, result] of cases) assert.throws(() => buildResult(result, request));
  let invoked = false;
  assert.throws(() => buildResult({ get kind() { invoked = true; return 'allocated'; }, generation: 1 }, begin));
  assert.equal(invoked, false);
});
