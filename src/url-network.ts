import { lookup as nodeLookup } from "node:dns/promises";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import type { Duplex } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

/** The network policy is deliberately stricter than a normal HTTP client. */
export const MAX_REDIRECTS = 3;
export const MAX_DNS_ANSWERS = 32;
export const MAX_REQUESTS = 64;
export const MAX_COMPRESSED_BODY_BYTES = 2 * 1024 * 1024;
export const MAX_SINGLE_BODY_BYTES = 2 * 1024 * 1024;

const MAX_URL_LENGTH = 8192;
const INTERNAL_HOSTNAMES = new Set([
  "metadata",
  "metadata.google.internal",
  "metadata.azure.internal",
  "instance-data.ec2.internal",
  "host.docker.internal",
  "kubernetes.default.svc",
  "100.100.100.200",
]);
const AWS_IPV6_METADATA = "fd00:ec2::254";

export type UrlProtocol = "http:" | "https:";

export interface NormalizedUrl {
  href: string;
  origin: string;
  protocol: UrlProtocol;
  hostname: string;
  port: string;
}

export interface DnsAddress {
  address: string;
  family: 4 | 6;
}

export interface RequestBudget {
  count: number;
  max: number;
}

export interface UrlNetworkContext {
  allowPrivate: boolean;
  signal: AbortSignal;
  budget: RequestBudget;
  deadlineAt: number;
  /** Optional Authorization value for a single explicitly authorized request. */
  authorization?: string;
  /** Refuse redirects instead of making a follow-up request. */
  rejectRedirects?: boolean;
  /** Prefer JSON in the request's Accept header. */
  acceptJson?: boolean;
}

export interface RedirectHop {
  status: number;
  from: NormalizedUrl;
  to: NormalizedUrl;
}

export interface FetchedResource {
  requestedUrl: NormalizedUrl;
  finalUrl: NormalizedUrl;
  status: number;
  headers: Record<string, string | string[]>;
  body: Uint8Array;
  compressedBytes: number;
  redirects: RedirectHop[];
}

export class UrlNetworkError extends Error {
  readonly code: string;

  constructor(code: string, message = code) {
    super(message);
    this.name = "UrlNetworkError";
    this.code = code;
  }
}

function fail(code: string, message = code): never {
  throw new UrlNetworkError(code, message);
}

function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

const MAX_AUTHORIZATION_LENGTH = 8192;

function validateAuthorization(value: string): void {
  if (value.length === 0 || value.length > MAX_AUTHORIZATION_LENGTH || hasControlCharacters(value)) {
    fail("invalid_authorization", "authorization value is empty, too long, or contains control characters");
  }
}

function rawAuthorityHost(raw: string): string | undefined {
  const authority = raw.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i)?.[1];
  if (authority === undefined) return undefined;
  const withoutUserinfo = authority.includes("@") ? authority.slice(authority.lastIndexOf("@") + 1) : authority;
  if (withoutUserinfo.startsWith("[")) {
    const end = withoutUserinfo.indexOf("]");
    if (end < 0) return withoutUserinfo;
    return withoutUserinfo.slice(1, end);
  }
  // An unbracketed IPv6 authority is invalid, but retaining the whole value
  // makes the later hostname validation reject it without guessing a port.
  const colon = withoutUserinfo.lastIndexOf(":");
  if (colon > -1 && /^\d+$/.test(withoutUserinfo.slice(colon + 1))) return withoutUserinfo.slice(0, colon);
  return withoutUserinfo;
}

function rejectAmbiguousRawHost(raw: string): void {
  const host = rawAuthorityHost(raw);
  if (!host) return;
  if (host.includes("%")) fail("ambiguous_host", "hostname is ambiguous or invalid");
  const lower = host.toLowerCase();
  // WHATWG URL accepts decimal, hexadecimal and some non-canonical dotted
  // IPv4 forms. Reject these before URL has a chance to normalize them to an
  // internal address.
  if (/^\d+$/.test(lower) || /^0x[0-9a-f]+$/i.test(lower)) fail("ambiguous_host", "hostname is ambiguous or invalid");
  const numericDotted = /^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){1,3}$/i.test(lower);
  if (numericDotted && (!/^\d+(?:\.\d+){3}$/.test(lower) || lower.includes("0x"))) fail("ambiguous_host", "hostname is ambiguous or invalid");
  if (/^[0-9.]+$/.test(lower)) {
    const parts = lower.split(".");
    if (
      parts.length !== 4 ||
      parts.some((part) => !/^(?:0|[1-9]\d*)$/.test(part) || Number(part) > 255)
    ) fail("ambiguous_host", "hostname is ambiguous or invalid");
  }
  if (/[\s\\]/.test(host)) fail("ambiguous_host", "hostname is ambiguous or invalid");
}

function isValidDnsName(hostname: string): boolean {
  if (!hostname || hostname.length > 253 || hostname.endsWith(".") || hostname.includes("..")) return false;
  if (hostname.includes("%")) return false;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(hostname);
}

export function normalizeUrl(raw: string): NormalizedUrl {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH || hasControlCharacters(raw)) {
    fail("invalid_url", "URL is empty, too long, or contains control characters");
  }
  rejectAmbiguousRawHost(raw);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    fail("invalid_url", "URL could not be parsed");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") fail("unsupported_scheme", "only HTTP and HTTPS are allowed");
  if (parsed.username || parsed.password) fail("userinfo_not_allowed", "URL userinfo is not allowed");
  if (parsed.hash) fail("fragment_not_allowed", "URL fragments are not allowed");
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isIP(hostname) === 0 && !isValidDnsName(hostname)) fail("ambiguous_host", "hostname is ambiguous or invalid");
  if (isIP(hostname) === 6 && hostname.includes("%")) fail("ambiguous_host", "IPv6 zone identifiers are not allowed");
  // URL.port is empty for a default port and a decimal string otherwise. The
  // parser itself rejects out-of-range ports, but this explicit check keeps the
  // contract stable if a different URL implementation is used in tests.
  if (parsed.port && (!/^\d+$/.test(parsed.port) || Number(parsed.port) < 1 || Number(parsed.port) > 65535)) {
    fail("invalid_port", "port is invalid");
  }
  parsed.hostname = hostname;
  return {
    href: parsed.toString(),
    origin: parsed.origin,
    protocol: parsed.protocol,
    hostname,
    port: parsed.port,
  };
}

/** A display URL with query values removed. It is safe for findings/notes. */
export function safeUrl(url: string | URL | NormalizedUrl): string {
  let parsed: URL;
  try {
    parsed = new URL(typeof url === "string" ? url : url.href);
  } catch {
    return "[invalid-url]";
  }
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  if (parsed.search) parsed.search = "?[REDACTED]";
  return parsed.toString();
}

function parseIPv4(address: string): number[] | null {
  const pieces = address.split(".");
  if (pieces.length !== 4) return null;
  const numbers = pieces.map((piece) => (/^(?:0|[1-9]\d*)$/.test(piece) ? Number(piece) : Number.NaN));
  if (numbers.some((number) => !Number.isInteger(number) || number < 0 || number > 255)) return null;
  return numbers;
}

function inIPv4(address: string, base: number[], bits: number): boolean {
  const numbers = parseIPv4(address);
  if (!numbers) return false;
  const value = numbers[0] * 0x1000000 + numbers[1] * 0x10000 + numbers[2] * 0x100 + numbers[3];
  const network = base[0] * 0x1000000 + base[1] * 0x10000 + base[2] * 0x100 + base[3];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((value >>> 0) & mask) === ((network >>> 0) & mask);
}

function expandIPv6(address: string): number[] | null {
  let value = address.toLowerCase();
  const zone = value.indexOf("%");
  if (zone >= 0) value = value.slice(0, zone);
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4 = parseIPv4(value.slice(lastColon + 1));
    if (!ipv4) return null;
    value = `${value.slice(0, lastColon)}:${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (left.some((part) => !/^[0-9a-f]{1,4}$/.test(part)) || right.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;
  return [...left, ...Array.from({ length: Math.max(0, missing) }, () => "0"), ...right].map((part) => parseInt(part, 16));
}

function inIPv6(address: string, base: number[], bits: number): boolean {
  const words = expandIPv6(address);
  if (!words || words.length !== 8) return false;
  const fullWords = Math.floor(bits / 16);
  const remainder = bits % 16;
  for (let index = 0; index < fullWords; index += 1) if (words[index] !== base[index]) return false;
  if (remainder > 0) {
    const mask = (0xffff << (16 - remainder)) & 0xffff;
    if ((words[fullWords] & mask) !== (base[fullWords] & mask)) return false;
  }
  return true;
}

function embeddedIpv4(words: number[]): string {
  return `${words[6] >>> 8}.${words[6] & 255}.${words[7] >>> 8}.${words[7] & 255}`;
}

/**
 * RFC1918/loopback/link-local and special-use address policy. The caller uses
 * the two classes separately because --allow-private permits a self-hosted
 * loopback/RFC1918 fixture while metadata and link-local endpoints remain
 * forbidden in every mode.
 */
export function isPrivateAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    return [
      [[0, 0, 0, 0], 8],
      [[10, 0, 0, 0], 8],
      [[100, 64, 0, 0], 10],
      [[127, 0, 0, 0], 8],
      [[169, 254, 0, 0], 16],
      [[172, 16, 0, 0], 12],
      [[192, 0, 0, 0], 24],
      [[192, 168, 0, 0], 16],
    ].some(([base, bits]) => inIPv4(address, base as number[], bits as number));
  }
  if (family === 6) {
    const words = expandIPv6(address);
    if (!words) return true;
    const mapped = words.slice(0, 6).every((word, index) => word === (index === 5 ? 0xffff : 0));
    if (mapped) return isPrivateAddress(embeddedIpv4(words));
    const compatible = words.slice(0, 6).every((word) => word === 0);
    if (compatible) return isPrivateAddress(embeddedIpv4(words));
    const nat64 = words[0] === 0x0064 && words[1] === 0xff9b && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0;
    if (nat64 && isPrivateAddress(embeddedIpv4(words))) return true;
    const sixToFour = words[0] === 0x2002 && isPrivateAddress(`${words[1] >>> 8}.${words[1] & 255}.${words[2] >>> 8}.${words[2] & 255}`);
    if (sixToFour) return true;
    const teredo = words[0] === 0x2001 && words[1] === 0;
    if (teredo) {
      const decoded = `${(~(words[6] >>> 8)) & 255}.${(~words[6]) & 255}.${(~(words[7] >>> 8)) & 255}.${(~words[7]) & 255}`;
      if (isPrivateAddress(decoded)) return true;
    }
    return inIPv6(address, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7) || inIPv6(address, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10);
  }
  return true;
}

function isAlwaysForbiddenAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    if (address === "169.254.169.254" || address === "100.100.100.200") return true;
    return [
      [[169, 254, 0, 0], 16], // link-local and IPv4 metadata fabric
      [[192, 0, 0, 0], 24],
      [[192, 0, 2, 0], 24],
      [[192, 88, 99, 0], 24],
      [[198, 18, 0, 0], 15],
      [[198, 51, 100, 0], 24],
      [[203, 0, 113, 0], 24],
      [[224, 0, 0, 0], 4],
      [[240, 0, 0, 0], 4],
    ].some(([base, bits]) => inIPv4(address, base as number[], bits as number));
  }
  if (family === 6) {
    const words = expandIPv6(address);
    if (!words) return true;
    const mapped = words.slice(0, 6).every((word, index) => word === (index === 5 ? 0xffff : 0));
    if (mapped) return isAlwaysForbiddenAddress(embeddedIpv4(words));
    const compatible = words.slice(0, 6).every((word) => word === 0);
    if (compatible && isAlwaysForbiddenAddress(embeddedIpv4(words))) return true;
    const nat64 = words[0] === 0x0064 && words[1] === 0xff9b && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0;
    if (nat64 && isAlwaysForbiddenAddress(embeddedIpv4(words))) return true;
    const sixToFour = words[0] === 0x2002 && isAlwaysForbiddenAddress(`${words[1] >>> 8}.${words[1] & 255}.${words[2] >>> 8}.${words[2] & 255}`);
    if (sixToFour) return true;
    if (words[0] === 0x2001 && words[1] === 0) {
      const decoded = `${(~(words[6] >>> 8)) & 255}.${(~words[6]) & 255}.${(~(words[7] >>> 8)) & 255}.${(~words[7]) & 255}`;
      if (isAlwaysForbiddenAddress(decoded)) return true;
    }
    return (
      inIPv6(address, [0, 0, 0, 0, 0, 0, 0, 0], 128) ||
      inIPv6(address, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10) ||
      inIPv6(address, [0xff00, 0, 0, 0, 0, 0, 0, 0], 8) ||
      inIPv6(address, [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32) ||
      inIPv6(address, [0x2001, 0x0002, 0, 0, 0, 0, 0, 0], 48) ||
      inIPv6(address, [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0], 128) ||
      address.toLowerCase() === AWS_IPV6_METADATA
    );
  }
  return true;
}

function hostAlwaysForbidden(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return INTERNAL_HOSTNAMES.has(lower) || lower === AWS_IPV6_METADATA || lower.endsWith(".internal") || lower.endsWith(".svc") || lower.endsWith(".cluster.local");
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal, code = "timeout"): Promise<T> {
  if (signal.aborted) fail(code, "collection deadline exceeded");
  let onAbort: (() => void) | undefined;
  const cancellation = new Promise<never>((_, reject) => {
    onAbort = () => reject(new UrlNetworkError(code, "collection deadline exceeded"));
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([promise, cancellation]);
  } finally {
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}

async function lookupAddresses(hostname: string, signal: AbortSignal, allowPrivate: boolean): Promise<DnsAddress[]> {
  const lower = hostname.toLowerCase();
  if (hostAlwaysForbidden(lower)) fail("metadata_host", "metadata and internal hostnames are not allowed");
  let answers: Array<{ address: string; family: number }>;
  try {
    answers = await raceAbort(nodeLookup(lower, { all: true, verbatim: true }), signal, "dns_timeout");
  } catch (error) {
    if (error instanceof UrlNetworkError) throw error;
    fail("dns_error", "DNS lookup failed");
  }
  if (!Array.isArray(answers) || answers.length === 0) fail("dns_empty", "hostname has no A/AAAA answers");
  if (answers.length > MAX_DNS_ANSWERS) fail("dns_answer_limit", "hostname returned too many addresses");
  const seen = new Set<string>();
  const validated: DnsAddress[] = [];
  for (const entry of answers) {
    if (!entry || (entry.family !== 4 && entry.family !== 6) || typeof entry.address !== "string" || isIP(entry.address) !== entry.family) {
      fail("dns_invalid", "DNS returned an invalid address");
    }
    const normalizedAddress = entry.address.toLowerCase().replace(/^\[|\]$/g, "");
    const key = `${entry.family}:${normalizedAddress}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (isAlwaysForbiddenAddress(normalizedAddress) || (!allowPrivate && isPrivateAddress(normalizedAddress))) {
      fail("blocked_address", "hostname resolves to a blocked address");
    }
    validated.push({ address: normalizedAddress, family: entry.family });
  }
  if (validated.length === 0) fail("dns_empty", "hostname has no usable A/AAAA answers");
  return validated;
}

export async function resolveAddresses(url: NormalizedUrl, signal: AbortSignal, allowPrivate: boolean): Promise<DnsAddress[]> {
  if (isIP(url.hostname) !== 0) {
    if (isAlwaysForbiddenAddress(url.hostname) || (!allowPrivate && isPrivateAddress(url.hostname))) fail("blocked_address", "target address is not allowed");
    return [{ address: url.hostname, family: isIP(url.hostname) as 4 | 6 }];
  }
  if (!allowPrivate && (url.hostname === "localhost" || url.hostname.endsWith(".local"))) fail("private_hostname", "private hostname is not allowed");
  return lookupAddresses(url.hostname, signal, allowPrivate);
}

function headerValues(headers: Record<string, string | string[]>, name: string): string[] {
  const found = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  if (found === undefined) return [];
  return Array.isArray(found) ? found.map(String) : [String(found)];
}

function responseHeaders(response: IncomingMessage): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(response.headers)) {
    if (value !== undefined) result[name] = Array.isArray(value) ? value.map(String) : String(value);
  }
  return result;
}

function closeResponse(response: IncomingMessage): void {
  response.removeAllListeners("data");
  response.resume();
  response.destroy();
}

function consumeRequestBudget(budget: RequestBudget): void {
  if (budget.count >= budget.max) fail("request_limit", "request budget exhausted");
  budget.count += 1;
}

function sameAddress(left: string | undefined, right: string): boolean {
  if (!left) return false;
  const canonical = (value: string): string => {
    const lower = value.toLowerCase().replace(/^\[|\]$/g, "");
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped?.[1] ?? lower;
  };
  return canonical(left) === canonical(right);
}

async function requestPinned(url: NormalizedUrl, address: DnsAddress, context: UrlNetworkContext): Promise<IncomingMessage> {
  if (context.signal.aborted || Date.now() >= context.deadlineAt) fail("timeout", "collection deadline exceeded");
  if (context.authorization !== undefined) validateAuthorization(context.authorization);
  consumeRequestBudget(context.budget);
  const isHttps = url.protocol === "https:";
  const requestFn = isHttps ? httpsRequest : httpRequest;
  const hostHeader = new URL(url.href).host;
  const port = url.port || (isHttps ? "443" : "80");
  return await new Promise<IncomingMessage>((resolve, reject) => {
    let settled = false;
    let response: IncomingMessage | undefined;
    const finishError = (error: UrlNetworkError) => {
      if (settled) return;
      settled = true;
      response?.destroy();
      reject(error);
    };
    const req = requestFn({
      protocol: url.protocol,
      hostname: url.hostname,
      port,
      path: `${new URL(url.href).pathname}${new URL(url.href).search}` || "/",
      method: "GET",
      headers: {
        accept: context.acceptJson
          ? "application/json,application/*+json;q=0.9"
          : "text/html,application/xhtml+xml,application/javascript,text/javascript;q=0.9,*/*;q=0.1",
        "accept-encoding": "gzip, br, deflate",
        connection: "close",
        host: hostHeader,
        ...(context.authorization === undefined ? {} : { authorization: context.authorization }),
      },
      // The DNS answer was checked before this call. Returning only the
      // selected answer pins the socket to the value that is peer-checked.
      lookup: ((_: string, _options: { all?: boolean } | undefined, callback: (error: Error | null, address?: string, family?: number) => void) => {
        callback(null, address.address, address.family);
      }) as never,
      agent: false,
      autoSelectFamily: false,
      ...(isHttps ? { servername: isIP(url.hostname) === 0 ? url.hostname : undefined, rejectUnauthorized: true } : {}),
    } as never, (incoming: IncomingMessage) => {
      response = incoming;
      const peer = incoming.socket?.remoteAddress;
      if (!sameAddress(peer, address.address)) {
        closeResponse(incoming);
        finishError(new UrlNetworkError("dns_rebinding", "connection peer is outside the validated DNS answers"));
        return;
      }
      if (isHttps) {
        const tlsSocket = incoming.socket as typeof incoming.socket & { authorized?: boolean };
        if (tlsSocket.authorized !== true) {
          closeResponse(incoming);
          finishError(new UrlNetworkError("tls_verification_failed", "TLS certificate verification failed"));
          return;
        }
      }
      if (settled) {
        closeResponse(incoming);
        return;
      }
      settled = true;
      resolve(incoming);
    });
    const onAbort = () => {
      req.destroy();
      finishError(new UrlNetworkError("timeout", "collection deadline exceeded"));
    };
    context.signal.addEventListener("abort", onAbort, { once: true });
    const cleanup = () => context.signal.removeEventListener("abort", onAbort);
    req.once("error", (error: Error) => {
      cleanup();
      if (context.signal.aborted) finishError(new UrlNetworkError("timeout", "collection deadline exceeded"));
      else finishError(new UrlNetworkError("request_error", "HTTP request failed"));
      void error;
    });
    req.once("response", cleanup);
    req.setTimeout(Math.max(1, context.deadlineAt - Date.now()), () => {
      req.destroy();
      finishError(new UrlNetworkError("timeout", "request deadline exceeded"));
    });
    req.end();
  });
}

async function requestWithAddresses(url: NormalizedUrl, addresses: DnsAddress[], context: UrlNetworkContext): Promise<IncomingMessage> {
  let lastError: unknown;
  for (const address of addresses) {
    try {
      return await requestPinned(url, address, context);
    } catch (error) {
      lastError = error;
      const code = error instanceof UrlNetworkError ? error.code : "request_error";
      // A peer mismatch or TLS failure is a policy failure, rather than a
      // transient unreachable address. Never hide it by trying another answer.
      if (code === "dns_rebinding" || code === "tls_verification_failed" || code === "blocked_address" || code === "metadata_host" || code === "timeout" || code === "request_limit") throw error;
    }
  }
  if (lastError instanceof UrlNetworkError) throw lastError;
  fail("request_error", "HTTP request failed");
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function decodeContentEncoding(headers: Record<string, string | string[]>): string {
  return headerValues(headers, "content-encoding").join(",").trim().toLowerCase();
}

function decompress(input: Buffer, encoding: string, maximum: number, signal: AbortSignal): Promise<Buffer> {
  const encodings = encoding.split(",").map((entry) => entry.trim()).filter(Boolean).filter((entry) => entry !== "identity");
  if (encodings.length > 1) return Promise.reject(new UrlNetworkError("decompression_failed", "multiple content encodings are not supported"));
  if (encodings.length === 0) {
    if (input.byteLength > maximum) return Promise.reject(new UrlNetworkError("body_limit", "decompressed body budget exceeded"));
    return Promise.resolve(input);
  }
  const factory: (() => Duplex) | undefined = encodings[0] === "br"
    ? createBrotliDecompress
    : encodings[0] === "gzip" || encodings[0] === "x-gzip"
      ? createGunzip
      : encodings[0] === "deflate"
        ? createInflate
        : undefined;
  if (!factory) return Promise.reject(new UrlNetworkError("decompression_failed", "unsupported content encoding"));
  return new Promise<Buffer>((resolve, reject) => {
    const stream = factory();
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    const finishError = (error: UrlNetworkError) => {
      if (settled) return;
      settled = true;
      cleanup();
      stream.destroy();
      reject(error);
    };
    const onAbort = () => finishError(new UrlNetworkError("timeout", "collection deadline exceeded"));
    stream.on("data", (chunk: Buffer) => {
      bytes += chunk.byteLength;
      if (bytes > maximum) finishError(new UrlNetworkError("body_limit", "decompressed body budget exceeded"));
      else chunks.push(chunk);
    });
    stream.on("error", (error: Error) => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new UrlNetworkError("decompression_failed", "response decompression failed"));
      }
      void error;
    });
    stream.on("end", () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks));
    });
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    else stream.end(input);
  });
}

export async function readResponseBody(
  response: IncomingMessage,
  signal: AbortSignal,
  maxCompressedBytes: number,
  maxDecompressedBytes: number,
): Promise<{ bytes: Uint8Array; compressedBytes: number }> {
  const declared = Number.parseInt(response.headers["content-length"] ?? "", 10);
  if (Number.isFinite(declared) && declared > maxCompressedBytes) {
    closeResponse(response);
    fail("body_limit", "compressed body budget exceeded");
  }
  const chunks: Buffer[] = [];
  let compressedBytes = 0;
  const onAbort = () => response.destroy();
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    for await (const chunk of response) {
      if (signal.aborted) fail("timeout", "collection deadline exceeded");
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      compressedBytes += value.byteLength;
      if (compressedBytes > maxCompressedBytes) {
        closeResponse(response);
        fail("body_limit", "compressed body budget exceeded");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof UrlNetworkError) throw error;
    if (signal.aborted) fail("timeout", "collection deadline exceeded");
    fail("body_read_error", "response body could not be read");
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  const compressed = Buffer.concat(chunks);
  const bytes = await decompress(compressed, decodeContentEncoding(responseHeaders(response)), maxDecompressedBytes, signal);
  return { bytes: new Uint8Array(bytes), compressedBytes };
}

function locationHeader(headers: Record<string, string | string[]>): string | undefined {
  return headerValues(headers, "location")[0];
}

export async function fetchResource(
  start: NormalizedUrl,
  context: UrlNetworkContext,
  allowedOrigin: string,
  maxCompressedBytes: number,
  maxDecompressedBytes: number,
): Promise<FetchedResource> {
  if (context.authorization !== undefined) validateAuthorization(context.authorization);
  let current = start;
  const redirects: RedirectHop[] = [];
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    if (context.signal.aborted || Date.now() >= context.deadlineAt) fail("timeout", "collection deadline exceeded");
    if (current.origin !== allowedOrigin) fail("cross_origin_redirect", "resource left the approved origin");
    const addresses = await resolveAddresses(current, context.signal, context.allowPrivate);
    // An authenticated caller may explicitly permit same-origin redirects for
    // another profile, but credentials are only ever sent on the initial hop.
    // API mode additionally sets rejectRedirects so it does not follow one.
    const hopContext = hop === 0 || context.authorization === undefined
      ? context
      : { ...context, authorization: undefined };
    const response = await requestWithAddresses(current, addresses, hopContext);
    const headers = responseHeaders(response);
    if (isRedirect(response.statusCode ?? 0)) {
      if (context.rejectRedirects) {
        closeResponse(response);
        fail("redirect_rejected", "redirects are not allowed for this request");
      }
      const location = locationHeader(headers);
      closeResponse(response);
      if (!location) fail("redirect_without_location", "redirect did not include a location");
      if (hop >= MAX_REDIRECTS) fail("redirect_limit", "redirect budget exhausted");
      let next: NormalizedUrl;
      try {
        next = normalizeUrl(new URL(location, current.href).toString());
      } catch (error) {
        if (error instanceof UrlNetworkError) throw error;
        fail("invalid_redirect", "redirect location is invalid");
      }
      if (next.origin !== allowedOrigin) fail("cross_origin_redirect", "redirect left the approved origin");
      redirects.push({ status: response.statusCode ?? 0, from: current, to: next });
      current = next;
      continue;
    }
    const body = await readResponseBody(response, context.signal, maxCompressedBytes, maxDecompressedBytes);
    return {
      requestedUrl: start,
      finalUrl: current,
      status: response.statusCode ?? 0,
      headers,
      body: body.bytes,
      compressedBytes: body.compressedBytes,
      redirects,
    };
  }
  fail("redirect_limit", "redirect budget exhausted");
}
