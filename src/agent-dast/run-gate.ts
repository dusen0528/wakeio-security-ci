/**
 * Run gate: one loopback forward proxy shared by every worker in a run.
 *
 * It sits in front of the existing DAST egress gate (src/dast-egress.ts) and
 * adds what that gate does not have and what parallel workers need:
 *
 *   - one request budget for the whole run, not one per engine;
 *   - a token-bucket rate limit on the target origin, so N workers never
 *     multiply the load on the target;
 *   - a separate credential per task, so request counts in the ledger come
 *     from the wire instead of from what a worker claims.
 *
 * Origin pinning, private/metadata address rules, method allowlists and byte
 * budgets stay in the inner egress gate. This gate also refuses other origins
 * itself, before a token is spent. Workers only ever see this gate's per-task
 * proxy URL; the inner gate credential stays in the runner process.
 *
 * The inner gate is used unchanged, so this file can evolve without touching
 * the shared dast-egress.ts.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from 'node:http';
import { connect, type Socket } from 'node:net';

export type RunGateRefusal = 'unauthorized' | 'origin' | 'run_budget' | 'closed' | 'upstream';

export interface RunGateOptions {
  /** Target origin, e.g. `http://127.0.0.1:3000`. Requests for any other origin are refused here. */
  targetOrigin: string;
  /** Inner egress gate proxy URL including its credential (`EgressGate.proxyUrl`). Never given to workers. */
  upstreamProxyUrl: string;
  /** Requests (and HTTPS tunnels) allowed for the whole run, across all tasks. */
  maxRequests: number;
  /** Sustained requests per second to the target, across all tasks. */
  ratePerSecond: number;
  /** Tokens available at once; defaults to `ratePerSecond`, minimum 1. */
  burst?: number;
  signal?: AbortSignal;
}

export interface TaskCounters {
  /** Requests and tunnels admitted and forwarded upstream for this task. */
  requests: number;
  /** Response bytes relayed back to the worker (tunnel bytes for HTTPS). */
  bytes: number;
  refused: Record<RunGateRefusal, number>;
}

export interface TaskLease {
  /** Proxy URL with this task's credential. Give it to one worker only; never persist it. */
  proxyUrl: string;
  counters: TaskCounters;
  /** Stop admitting this task's requests. Requests already in flight finish. */
  revoke(): void;
}

export interface RunGate {
  port: number;
  /** Admitted requests across all tasks. */
  admitted(): number;
  lease(taskId: string): TaskLease;
  close(): Promise<void>;
}

const emptyRefused = (): Record<RunGateRefusal, number> => ({ unauthorized: 0, origin: 0, run_budget: 0, closed: 0, upstream: 0 });

/** Token bucket. `take` resolves when a token is available, or false if the gate closes first. */
class TokenBucket {
  private tokens: number;
  private last = Date.now();
  private readonly waiters: Array<{ resolve: (ok: boolean) => void }> = [];
  private timer: NodeJS.Timeout | undefined;
  private closed = false;

  constructor(private readonly ratePerMs: number, private readonly capacity: number) { this.tokens = capacity; }

  private refill(): void {
    const now = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + (now - this.last) * this.ratePerMs);
    this.last = now;
  }

  private drain(): void {
    this.timer = undefined;
    this.refill();
    while (this.waiters.length && this.tokens >= 1) { this.tokens -= 1; this.waiters.shift()!.resolve(true); }
    if (this.waiters.length && !this.closed) {
      this.timer = setTimeout(() => this.drain(), Math.max(1, Math.ceil((1 - this.tokens) / this.ratePerMs)));
    }
  }

  take(): Promise<boolean> {
    if (this.closed) return Promise.resolve(false);
    return new Promise(resolve => { this.waiters.push({ resolve }); if (!this.timer) this.drain(); });
  }

  close(): void {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    for (const waiter of this.waiters.splice(0)) waiter.resolve(false);
  }
}

function proxyAuthorization(url: URL): string {
  const user = decodeURIComponent(url.username), pass = decodeURIComponent(url.password);
  return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
}

function sameBytes(a: Buffer, b: Buffer): boolean { return a.length === b.length && timingSafeEqual(a, b); }

export async function startRunGate(options: RunGateOptions): Promise<RunGate> {
  const target = new URL(options.targetOrigin);
  if (!['http:', 'https:'].includes(target.protocol) || target.origin !== options.targetOrigin) throw new Error('run_gate_origin_invalid');
  const upstream = new URL(options.upstreamProxyUrl);
  if (upstream.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(upstream.hostname)) throw new Error('run_gate_upstream_invalid');
  if (!Number.isSafeInteger(options.maxRequests) || options.maxRequests < 1) throw new Error('run_gate_budget_invalid');
  if (!(options.ratePerSecond > 0) || options.ratePerSecond > 1000) throw new Error('run_gate_rate_invalid');
  const burst = Math.max(1, Math.floor(options.burst ?? options.ratePerSecond));
  const upstreamAuth = proxyAuthorization(upstream);
  const targetPort = target.port || (target.protocol === 'https:' ? '443' : '80');
  const targetAuthority = `${target.hostname}:${targetPort}`;

  const bucket = new TokenBucket(options.ratePerSecond / 1000, burst);
  const leases = new Map<string, { expected: Buffer; counters: TaskCounters; revoked: boolean }>();
  const sockets = new Set<Socket>();
  let admitted = 0;
  let closing = false;

  const lookup = (header: string | undefined) => {
    if (!header) return undefined;
    const given = Buffer.from(header);
    for (const lease of leases.values()) if (sameBytes(given, lease.expected)) return lease;
    return undefined;
  };

  /** Reserve one unit of the run budget, then wait for a rate token. */
  const admit = async (counters: TaskCounters): Promise<RunGateRefusal | undefined> => {
    if (closing || options.signal?.aborted) return 'closed';
    if (admitted >= options.maxRequests) return 'run_budget';
    admitted += 1;
    if (!(await bucket.take()) || closing || options.signal?.aborted) return 'closed';
    counters.requests += 1;
    return undefined;
  };

  const refuse = (response: ServerResponse, status: number, reason: RunGateRefusal, counters?: TaskCounters) => {
    if (counters) counters.refused[reason] += 1;
    if (response.headersSent) { response.destroy(); return; }
    response.writeHead(status, { 'content-length': '0', connection: 'close', 'x-wakeio-run-gate': reason });
    response.end();
  };

  const server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
    const lease = lookup(request.headers['proxy-authorization']);
    if (!lease || lease.revoked) {
      request.resume();
      response.writeHead(407, { 'proxy-authenticate': 'Basic', 'content-length': '0', connection: 'close' });
      response.end();
      return;
    }
    let url: URL;
    try { url = new URL(request.url ?? ''); } catch { request.resume(); refuse(response, 502, 'origin', lease.counters); return; }
    if (url.origin !== target.origin || target.protocol !== 'http:') { request.resume(); refuse(response, 502, 'origin', lease.counters); return; }
    const refusal = await admit(lease.counters);
    if (refusal) { request.resume(); refuse(response, refusal === 'run_budget' ? 429 : 503, refusal, lease.counters); return; }

    const headers = { ...request.headers, 'proxy-authorization': upstreamAuth, connection: 'close' };
    const forward = httpRequest({ host: upstream.hostname, port: upstream.port, method: request.method, path: url.href, headers }, incoming => {
      response.writeHead(incoming.statusCode ?? 502, incoming.headers);
      incoming.on('data', (chunk: Buffer) => { lease.counters.bytes += chunk.byteLength; });
      incoming.pipe(response);
    });
    forward.on('error', () => refuse(response, 502, 'upstream', lease.counters));
    request.pipe(forward);
  });

  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); if (closing) socket.destroy(); });

  server.on('connect', async (request: IncomingMessage, client: Socket, head: Buffer) => {
    const reject = (line: string, reason: RunGateRefusal, counters?: TaskCounters) => {
      if (counters) counters.refused[reason] += 1;
      client.end(`HTTP/1.1 ${line}\r\nx-wakeio-run-gate: ${reason}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n`);
    };
    const lease = lookup(request.headers['proxy-authorization']);
    if (!lease || lease.revoked) { client.end('HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic\r\ncontent-length: 0\r\n\r\n'); return; }
    if (target.protocol !== 'https:' || request.url !== targetAuthority) { reject('502 Bad Gateway', 'origin', lease.counters); return; }
    const refusal = await admit(lease.counters);
    if (refusal) { reject(refusal === 'run_budget' ? '429 Too Many Requests' : '503 Service Unavailable', refusal, lease.counters); return; }

    const tunnel = connect(Number(upstream.port), upstream.hostname);
    sockets.add(tunnel); tunnel.once('close', () => sockets.delete(tunnel));
    tunnel.once('error', () => { lease.counters.refused.upstream += 1; client.destroy(); });
    client.once('error', () => tunnel.destroy());
    tunnel.write(`CONNECT ${targetAuthority} HTTP/1.1\r\nhost: ${targetAuthority}\r\nproxy-authorization: ${upstreamAuth}\r\n\r\n`);
    // Relay the inner gate's answer (including a refusal) and then the tunnel, unchanged.
    if (head.byteLength) tunnel.write(head);
    tunnel.on('data', (chunk: Buffer) => { lease.counters.bytes += chunk.byteLength; });
    tunnel.pipe(client);
    client.pipe(tunnel);
  });

  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve()); });
  const address = server.address();
  if (!address || typeof address !== 'object') throw new Error('run_gate_listen_failed');
  const port = address.port;

  let closePromise: Promise<void> | undefined;
  const close = () => closePromise ??= (async () => {
    closing = true;
    bucket.close();
    for (const lease of leases.values()) lease.revoked = true;
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  })();
  options.signal?.addEventListener('abort', () => { void close(); }, { once: true });

  return {
    port,
    admitted: () => admitted,
    lease(taskId: string): TaskLease {
      if (closing) throw new Error('run_gate_closed');
      if (leases.has(taskId)) throw new Error('run_gate_lease_exists');
      const token = randomBytes(18).toString('base64url');
      const user = 'task';
      const counters: TaskCounters = { requests: 0, bytes: 0, refused: emptyRefused() };
      const entry = { expected: Buffer.from(`Basic ${Buffer.from(`${user}:${token}`).toString('base64')}`), counters, revoked: false };
      leases.set(taskId, entry);
      return { proxyUrl: `http://${user}:${token}@127.0.0.1:${port}`, counters, revoke: () => { entry.revoked = true; } };
    },
    close,
  };
}
