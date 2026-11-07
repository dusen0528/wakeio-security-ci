import type { TestContext } from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { ProvisionOwner } from '../src/runtime/runtimes/provision-controller-owner.js';
import { AssetDirectory, type BoundAssetFile } from '../src/runtime/runtimes/provision-paths.js';
import { writeAssetStream } from '../src/runtime/runtimes/provision-asset-transfer.js';
import { withAssetBorrow, type ProvisionAssetRetention } from '../src/runtime/runtimes/provision-asset-borrow.js';
import { startAssetUse, finishAssetDirectory } from '../src/runtime/runtimes/provision-asset-lifetime.js';
import type { ProvisionAssetFiles, VerifiedProvisionAssets } from '../src/runtime/runtimes/provision-assets.js';

function event() {
  let resolve = () => {};
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

function fileChild(fd: number, root: string) {
  const child = spawn(process.execPath, ['-e', "process.on('SIGINT',()=>{});process.stdin.resume();"
    + "process.stdin.on('end',()=>process.exit(0));require('node:fs').readFileSync(3);process.stdout.write('ready');"],
  { stdio: ['pipe', 'pipe', 'pipe', fd], env: { RUN_TMP: root, TMPDIR: root,
    NODE_COMPILE_CACHE: join(root, 'node'), BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun') } });
  const ready = new Promise<void>((resolve, reject) => {
    child.once('error', reject);
    child.stdout?.once('data', () => resolve());
  });
  const closed = new Promise<void>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => code === 0 ? resolve() : reject(new Error('child_exit')));
  });
  return { child, ready, closed };
}

interface ControllerPeer {
  fd: number;
  releaseOnShutdown: boolean;
  readonly draining: Promise<void>;
  readonly settled: Promise<void>;
  finish(): void;
}
type BackendModule = typeof import('../src/runtime/runtimes/provision-backend.js');

interface AssetPeerState {
  readonly directory: AssetDirectory;
  readonly bound: BoundAssetFile;
  readonly signal: AbortSignal;
  readonly peer: ControllerPeer;
  readonly settled: () => void;
  token?: ProvisionAssetRetention;
}
function assetProducer(state: AssetPeerState) {
  return {
    async withProvisionAssets<T>(_input: unknown, use: (assets: VerifiedProvisionAssets) => Promise<T>) {
      const active = startAssetUse(() => use({ kind: 'verified-asset-prefix' }), state.signal);
      try { return await active.result; }
      finally { await finishAssetDirectory(state.directory, [active]).finally(state.settled); }
    },
    async withProvisionAssetFiles<T>(_handle: VerifiedProvisionAssets,
      use: (files: ProvisionAssetFiles) => Promise<T>) {
      return withAssetBorrow({ directory: state.directory, files: [state.bound], signal: state.signal,
        revoke() {} }, async view => {
        state.peer.fd = view.files[0].fd;
        return use({ limactl: view.files[0], guestagent: view.files[0], rootfs: view.files[0],
          signal: state.signal, retentionOwner: view.owner,
          retainForDrain() { state.token = view.retainForDrain(); return state.token; },
          authentication: { publisherTlsAndExpectedDigests: true, vendorCodeSignatureVerified: true,
            detachedSignatureVerified: false, notarizationVerified: false,
            currentHostVzCompatibilityVerified: false, backendVerified: false } });
      });
    },
  };
}

export async function withControllerPeer(t: TestContext,
  check: (api: BackendModule, peer: ControllerPeer) => Promise<void>) {
  const base = await mkdtemp(join(await realpath(tmpdir()), 't6p005-lifetime-'));
  const directory = await AssetDirectory.create(base);
  const lifetime = new AbortController(), shutting = event();
  const settled = event();
  const bound = await writeAssetStream(Readable.from([Buffer.from('original owned file')]),
    { directory, relative: 'asset', limit: 64, signal: lifetime.signal });
  let child: ReturnType<typeof fileChild> | undefined;
  let owner: ProvisionOwner | undefined;
  const peer: ControllerPeer = { fd: -1, releaseOnShutdown: true,
    draining: shutting.promise, settled: settled.promise,
    finish() { child?.child.stdin?.end(); } };
  const state: AssetPeerState = { directory, bound, signal: lifetime.signal, peer, settled: settled.resolve };
  const realAssets = await import('../src/runtime/runtimes/provision-assets.js');
  const realController = await import('../src/runtime/runtimes/provision-controller.js');
  t.mock.module(new URL('../src/runtime/runtimes/provision-assets.js', import.meta.url), { namedExports: {
    ...realAssets, ...assetProducer(state),
  } });
  t.mock.module(new URL('../src/runtime/runtimes/provision-controller.js', import.meta.url), { namedExports: {
    ...realController,
    async prepareOwnedController(actualOwner: ProvisionOwner) {
      owner = actualOwner;
      const drain = owner.cleanupAfterDrain.bind(owner);
      t.mock.method(owner, 'cleanupAfterDrain', () => {
        shutting.resolve();
        return drain();
      });
      child = fileChild(peer.fd, base);
      const current = child;
      owner.own({ identity: 'actual-child', stop() { current.child.kill('SIGINT'); },
        drained: current.closed, async remove() { return true; } });
      await child.ready;
      return { kind: 'prepared-provision-controller' };
    },
    async qualifyOwnedController() {
      return { kind: 'refused', refusal: {
        kind: 'refused', phase: 'qualification', code: 'delegation_missing', missing: ['cpu'] } };
    },
    async shutdownOwnedController() {
      if (peer.releaseOnShutdown) peer.finish();
    },
  } });
  try {
    const capability = await import(new URL(
      '../src/runtime/runtimes/provision-backend-capability.js?lifetime=' + randomUUID(), import.meta.url).href);
    t.mock.module(new URL('../src/runtime/runtimes/provision-backend-capability.js', import.meta.url),
      { namedExports: capability });
    const api: BackendModule = await import(new URL(
      '../src/runtime/runtimes/provision-backend.js?lifetime=' + randomUUID(), import.meta.url).href);
    await check(api, peer);
  } finally {
    peer.finish();
    await child?.closed;
    await owner?.close();
    if (state.token) { await state.token.release(); await state.token.disposed; }
    await directory.cleanup();
    await rm(base, { recursive: true });
  }
}
