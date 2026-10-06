import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import { connect, isIP, type Socket } from "node:net";
import { normalizeUrl, resolveAddresses, type DnsAddress, type NormalizedUrl } from "./url-network.js";

/**
 * Loopback forward proxy that every active DAST engine must use. It inherits
 * the URL-network policy (metadata/private address rules, one validated and
 * pinned peer, one approved origin) and enforces request and response-byte
 * budgets on the wire, so an engine cannot widen scope by template choice.
 */
export const EGRESS_MAX_REQUEST_BODY_BYTES = 64 * 1024;

export type EgressStopReason = "request_limit" | "body_limit" | "peer_mismatch";

export interface EgressPolicy {
  origin: NormalizedUrl;
  address: DnsAddress;
  /** Methods forwarded for plain-HTTP origins. HTTPS tunnels cannot inspect methods. */
  methods: ReadonlySet<string>;
  maxRequests: number;
  maxSingleBodyBytes: number;
  maxTotalBytes: number;
  signal: AbortSignal;
  deadlineAt: number;
}

export interface EgressCounters {
  /** Requests forwarded to the approved origin (plain HTTP only). */
  forwarded: number;
  /** HTTPS CONNECT tunnels opened to the approved origin. */
  tunnels: number;
  blockedOrigin: number;
  blockedMethod: number;
  blockedBudget: number;
  upstreamErrors: number;
  rejectedEncoding: number;
  /** Bytes relayed from the target: bodies for HTTP, tunnel bytes for HTTPS. */
  responseBytes: number;
}

export interface EgressGate {
  /** Proxy URL including a per-run credential; never persist it. */
  proxyUrl: string;
  port: number;
  counters: EgressCounters;
  /** First budget stop, if any. The caller must stop its engine. */
  stopReason(): EgressStopReason | undefined;
  onStop(listener: (reason: EgressStopReason) => void): void;
  close(): Promise<void>;
}

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authorization", "proxy-authenticate", "proxy-connection",
  "te", "trailer", "transfer-encoding", "upgrade", "accept-encoding", "host",
]);

/** Validate a DAST origin with the URL-network policy and pin the first allowed answer. */
export async function resolveDastOrigin(raw: string, allowPrivate: boolean, signal: AbortSignal): Promise<{ origin: NormalizedUrl; address: DnsAddress }> {
  const origin = normalizeUrl(raw);
  const parsed = new URL(origin.href);
  if (parsed.pathname !== "/" || parsed.search) throw new Error("dast_origin_required");
  const addresses = await resolveAddresses(origin, signal, allowPrivate);
  return { origin, address: addresses[0]! };
}

function defaultPort(origin: NormalizedUrl): string {
  return origin.port || (origin.protocol === "https:" ? "443" : "80");
}

function authority(origin: NormalizedUrl): string {
  const host = isIP(origin.hostname) === 6 ? `[${origin.hostname}]` : origin.hostname;
  return `${host}:${defaultPort(origin)}`;
}

function sameOrigin(raw: string | undefined, origin: NormalizedUrl): URL | undefined {
  if (!raw || !/^http:\/\//i.test(raw)) return undefined;
  try {
    const normalized = normalizeUrl(raw);
    return normalized.origin === origin.origin ? new URL(normalized.href) : undefined;
  } catch {
    return undefined;
  }
}

function sameAddress(left: string | undefined, right: string): boolean {
  if (!left) return false;
  const canonical = (value: string) => value.toLowerCase().replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, "$1");
  return canonical(left) === canonical(right);
}

function forwardHeaders(headers: IncomingHttpHeaders, host: string): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || HOP_BY_HOP.has(name.toLowerCase())) continue;
    result[name] = value;
  }
  // Decompression is never delegated to an engine: identity keeps byte caps exact.
  result["accept-encoding"] = "identity";
  result.host = host;
  result.connection = "close";
  return result;
}

export async function startEgressGate(policy: EgressPolicy): Promise<EgressGate> {
  const token = randomBytes(18).toString("base64url");
  const expected = Buffer.from(`Basic ${Buffer.from(`wakeio:${token}`).toString("base64")}`);
  const counters: EgressCounters = { forwarded: 0, tunnels: 0, blockedOrigin: 0, blockedMethod: 0, blockedBudget: 0, upstreamErrors: 0, rejectedEncoding: 0, responseBytes: 0 };
  const sockets = new Set<Socket>();
  const listeners: Array<(reason: EgressStopReason) => void> = [];
  let stopped: EgressStopReason | undefined;
  const stop = (reason: EgressStopReason) => {
    if (stopped) return;
    stopped = reason;
    for (const listener of listeners) listener(reason);
  };
  const authorized = (headers: IncomingHttpHeaders) => {
    const value = Buffer.from(String(headers["proxy-authorization"] ?? ""));
    return value.length === expected.length && timingSafeEqual(value, expected);
  };
  const remaining = () => Math.max(1, policy.deadlineAt - Date.now());
  const countBytes = (bytes: number, single: number): boolean => {
    counters.responseBytes += bytes;
    if (single > policy.maxSingleBodyBytes || counters.responseBytes > policy.maxTotalBytes) {
      stop("body_limit");
      return false;
    }
    return true;
  };
  const refuse = (response: ServerResponse, status: number) => {
    // Fixed, empty reply so a refused request cannot satisfy a template matcher by content.
    response.writeHead(status, { "content-length": "0", connection: "close", "x-wakeio-egress": "refused" });
    response.end();
  };

  const onRequest = (request: IncomingMessage, response: ServerResponse) => {
    if (!authorized(request.headers)) { response.writeHead(407, { "proxy-authenticate": "Basic", "content-length": "0", connection: "close" }); response.end(); return; }
    const target = policy.origin.protocol === "http:" ? sameOrigin(request.url, policy.origin) : undefined;
    if (!target) { counters.blockedOrigin += 1; request.resume(); refuse(response, 502); return; }
    if (!policy.methods.has(request.method ?? "")) { counters.blockedMethod += 1; request.resume(); refuse(response, 405); return; }
    if (stopped || policy.signal.aborted || counters.forwarded >= policy.maxRequests) {
      counters.blockedBudget += 1;
      if (counters.forwarded >= policy.maxRequests) stop("request_limit");
      request.resume(); refuse(response, 503); return;
    }
    counters.forwarded += 1;
    // Sockets can emit more than one error; count one failure per request and never leave an error unhandled.
    let failed = false;
    const fail = () => { if (!failed) { failed = true; counters.upstreamErrors += 1; } response.destroy(); };
    const upstream = httpRequest({
      host: policy.address.address, port: defaultPort(policy.origin), family: policy.address.family,
      method: request.method, path: `${target.pathname}${target.search}`,
      headers: forwardHeaders(request.headers, new URL(policy.origin.href).host),
      agent: false, timeout: remaining(),
    }, (incoming) => {
      if (!sameAddress(incoming.socket?.remoteAddress, policy.address.address)) {
        incoming.destroy(); counters.upstreamErrors += 1; stop("peer_mismatch"); response.destroy(); return;
      }
      const encoding = String(incoming.headers["content-encoding"] ?? "identity").trim().toLowerCase();
      if (encoding !== "identity" && encoding !== "") {
        incoming.destroy(); counters.rejectedEncoding += 1; refuse(response, 502); return;
      }
      const declared = Number.parseInt(String(incoming.headers["content-length"] ?? ""), 10);
      if (Number.isFinite(declared) && declared > policy.maxSingleBodyBytes) {
        incoming.destroy(); stop("body_limit"); response.destroy(); return;
      }
      const headers: Record<string, string | string[]> = {};
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value !== undefined && !HOP_BY_HOP.has(name.toLowerCase()) && name.toLowerCase() !== "content-length") headers[name] = value;
      }
      const chunks: Buffer[] = [];
      let single = 0;
      incoming.on("data", (chunk: Buffer) => {
        single += chunk.byteLength;
        if (!countBytes(chunk.byteLength, single)) { incoming.destroy(); response.destroy(); return; }
        chunks.push(chunk);
      });
      incoming.once("end", () => {
        if (response.destroyed) return;
        const body = Buffer.concat(chunks);
        response.writeHead(incoming.statusCode ?? 502, { ...headers, "content-length": String(body.byteLength), connection: "close" });
        response.end(body);
      });
      incoming.on("error", fail);
    });
    upstream.once("timeout", () => upstream.destroy(new Error("timeout")));
    upstream.on("error", fail);
    request.on("error", () => upstream.destroy());
    let sent = 0;
    request.on("data", (chunk: Buffer) => {
      sent += chunk.byteLength;
      if (sent > EGRESS_MAX_REQUEST_BODY_BYTES) { upstream.destroy(); response.destroy(); return; }
      upstream.write(chunk);
    });
    request.once("end", () => upstream.end());
  };

  const server = createServer({ maxHeaderSize: 16 * 1024 }, onRequest);
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.on("connect", (request: IncomingMessage, client: Socket) => {
    const reject = (status: string) => { client.end(`HTTP/1.1 ${status}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`); };
    if (!authorized(request.headers)) { reject("407 Proxy Authentication Required"); return; }
    if (policy.origin.protocol !== "https:" || (request.url ?? "").toLowerCase() !== authority(policy.origin)) {
      counters.blockedOrigin += 1; reject("502 Bad Gateway"); return;
    }
    if (stopped || policy.signal.aborted) { counters.blockedBudget += 1; reject("503 Service Unavailable"); return; }
    counters.tunnels += 1;
    const upstream = connect({ host: policy.address.address, port: Number(defaultPort(policy.origin)), family: policy.address.family, timeout: remaining() });
    sockets.add(upstream);
    upstream.once("close", () => sockets.delete(upstream));
    upstream.once("connect", () => {
      if (!sameAddress(upstream.remoteAddress, policy.address.address)) { counters.upstreamErrors += 1; stop("peer_mismatch"); upstream.destroy(); client.destroy(); return; }
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.on("data", (chunk: Buffer) => {
        if (!countBytes(chunk.byteLength, 0)) { upstream.destroy(); client.destroy(); return; }
        client.write(chunk);
      });
      client.on("data", (chunk: Buffer) => upstream.write(chunk));
    });
    let tunnelFailed = false;
    upstream.once("timeout", () => upstream.destroy());
    upstream.on("error", () => { if (!tunnelFailed) { tunnelFailed = true; counters.upstreamErrors += 1; } client.destroy(); });
    upstream.once("end", () => client.end());
    client.on("error", () => upstream.destroy());
    client.once("close", () => upstream.destroy());
  });

  const closeAll = () => { for (const socket of sockets) socket.destroy(); };
  policy.signal.addEventListener("abort", closeAll, { once: true });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return {
    proxyUrl: `http://wakeio:${token}@127.0.0.1:${port}`,
    port,
    counters,
    stopReason: () => stopped,
    onStop(listener) { listeners.push(listener); if (stopped) listener(stopped); },
    close() {
      policy.signal.removeEventListener("abort", closeAll);
      closeAll();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
