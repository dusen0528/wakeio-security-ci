import { request } from 'node:https';
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import type { IncomingMessage } from 'node:http';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createHash } from 'node:crypto';
import type { AssetPin } from './provision-asset-catalog.js';
import { assetGuard, assetRemaining, ProvisionAssetError } from './provision-asset-error.js';
import { AssetDirectory, hashAsset, type BoundAssetFile } from './provision-paths.js';
import { runAssetUse } from './provision-asset-lifetime.js';

const PRIVATE = new BlockList();
for (const [address, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
  ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
  ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 3]] satisfies readonly (readonly [string, number])[]) PRIVATE.addSubnet(address, prefix, 'ipv4');
PRIVATE.addSubnet('2001:db8::', 32, 'ipv6');
PRIVATE.addSubnet('2001::', 32, 'ipv6');
PRIVATE.addSubnet('2002::', 16, 'ipv6');
PRIVATE.addSubnet('3fff::', 20, 'ipv6');

function publicAddress(address: string): boolean {
  const family = isIP(address);
  return family === 4 ? !PRIVATE.check(address, 'ipv4')
    : family === 6 && /^[23]/i.test(address) && !PRIVATE.check(address, 'ipv6');
}

export interface AssetWrite {
  readonly directory: AssetDirectory;
  readonly relative: string;
  readonly limit: number;
  readonly signal: AbortSignal;
}

/** Real stream/FD boundary shared by HTTPS, bounded decompression, and native tar output. */
export async function writeAssetStream(source: Readable, output: AssetWrite,
  expected?: Pick<AssetPin, 'bytes' | 'sha256'>): Promise<BoundAssetFile> {
  assetRemaining(output.signal);
  const allocation = output.directory.createFile(output.relative), hash = createHash('sha256');
  let bytes = 0;
  // Attach the sink synchronously, before allocation awaits. Child stdio may flush immediately at exit.
  const sink = new Writable({ highWaterMark: 65536, write(chunk: unknown, _encoding, complete) {
    const writing = async () => {
      assetRemaining(output.signal);
      assetGuard(Buffer.isBuffer(chunk), 'asset_transfer');
      bytes += chunk.length;
      assetGuard(bytes <= output.limit && (!expected || bytes <= expected.bytes), 'asset_integrity');
      hash.update(chunk);
      await (await allocation).fd.writeFile(chunk);
    };
    writing().then(() => complete(), error => complete(error instanceof Error
      ? error : new ProvisionAssetError('asset_transfer')));
  } });
  allocation.catch(error => sink.destroy(error instanceof Error ? error : new ProvisionAssetError('asset_transfer')));
  try {
    await pipeline(source, sink, { signal: output.signal });
    const target = await allocation;
    assetRemaining(output.signal);
    assetGuard(bytes > 0 && (!expected || bytes === expected.bytes && hash.digest('hex') === expected.sha256),
      'asset_integrity');
    await target.fd.sync();
    await target.fd.chmod(0o400);
    return await hashAsset(target.path, output.signal);
  } catch (error) {
    if (output.signal.aborted) throw new ProvisionAssetError('asset_expired');
    throw error;
  } finally {
    const target = await allocation;
    await target.fd.close();
    source.destroy();
  }
}

/** Header policy runs before any response body is persisted. Compression and redirect bodies are not assets. */
export function verifyAssetResponse(response: IncomingMessage, pin: AssetPin): void {
  const counts = (name: string) => response.rawHeaders.filter((v, i) => i % 2 === 0
    && v.toLowerCase() === name).length;
  assetGuard(response.statusCode === 200 && counts('content-length') === 1
    && response.headers['content-length'] === String(pin.bytes)
    && counts('content-encoding') === 0 && counts('transfer-encoding') === 0, 'asset_transfer');
}

async function responseFor(url: URL, signal: AbortSignal): Promise<IncomingMessage> {
  assetRemaining(signal);
  const addresses = await runAssetUse(() => lookup(url.hostname, { all: true, verbatim: true }), signal);
  assetRemaining(signal);
  assetGuard(addresses.length > 0 && addresses.every(a => publicAddress(a.address)), 'asset_transfer');
  const selected = addresses[0];
  assetGuard(selected, 'asset_transfer');
  return new Promise((resolve, reject) => {
    const outgoing = request(url, { method: 'GET', agent: false, signal, maxHeaderSize: 16384,
      rejectUnauthorized: true, headers: { 'Accept-Encoding': 'identity', 'User-Agent': 'wakeio-t6p-assets/1' },
      lookup: (_host, options, callback) => {
        if (options.all) callback(null, [selected]);
        else callback(null, selected.address, selected.family);
      } }, resolve);
    const closed = new Promise<void>(finished => outgoing.once('close', finished));
    outgoing.once('error', () => {
      void closed.then(() => reject(new ProvisionAssetError(signal.aborted ? 'asset_expired' : 'asset_transfer')));
    });
    outgoing.end();
  });
}

async function closeAssetResponse(response: IncomingMessage): Promise<void> {
  const closed = response.closed ? Promise.resolve()
    : new Promise<void>(resolve => response.once('close', resolve));
  response.destroy();
  await closed;
}

/** Only the two exact publisher origins plus GitHub's release-asset delivery origin are reachable. */
export async function downloadAsset(pin: AssetPin, output: AssetWrite): Promise<BoundAssetFile> {
  let url = new URL(pin.url);
  assetGuard(url.protocol === 'https:' && !url.username && !url.password && !url.port
    && ['github.com', 'cloud-images.ubuntu.com'].includes(url.hostname), 'asset_transfer');
  for (let redirects = 0; ; redirects++) {
    const response = await responseFor(url, output.signal);
    if (response.statusCode === 302) {
      await closeAssetResponse(response);
      const location = response.headers.location;
      assetGuard(redirects < 2 && url.hostname === 'github.com' && typeof location === 'string',
        'asset_transfer');
      let next: URL;
      try { next = new URL(location); }
      catch (error) {
        if (error instanceof TypeError) throw new ProvisionAssetError('asset_transfer');
        throw error;
      }
      assetGuard(next.protocol === 'https:' && next.hostname === 'release-assets.githubusercontent.com'
        && !next.username && !next.password && !next.port && !next.hash, 'asset_transfer');
      url = next;
      continue;
    }
    try {
      verifyAssetResponse(response, pin);
      return await writeAssetStream(response, output, pin);
    } finally { await closeAssetResponse(response); }
  }
}
