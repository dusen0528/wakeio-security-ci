import { randomBytes } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import { parseAuthAssertion, type SchemathesisAuthAssertion } from './schemathesis-auth.js';
import { parsePropertyJsonText, propertyPointer } from './api-property-policy.js';
import { zapRequestUrl } from './zap-policy.js';

export const ZAP_SESSION_PATH = '/__wakeio_session';
export interface ZapSessionPolicy {
  login: { path: string; format: 'json' | 'form'; fields: Record<string, string> };
  session: { type: 'bearer'; tokenPointer: string; refreshPointer?: string } | { type: 'cookie'; name: string };
  refresh?: { path: string; field: string };
  identity: SchemathesisAuthAssertion;
  maxAttempts: number;
}
function bad(): never { throw new TypeError('invalid_zap_session'); }
function exact(v: unknown, required: string[], optional: string[] = []): asserts v is Record<string, any> {
  if (!v || typeof v !== 'object' || Array.isArray(v) || required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) bad();
}
function field(v: unknown): string { if (typeof v !== 'string' || !/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(v) || ['__proto__', 'prototype', 'constructor'].includes(v)) bad(); return v; }
function pointer(v: unknown): string { if (typeof v !== 'string' || !/^\/(?:[A-Za-z0-9_-]+\/?)+$/.test(v) || v.length > 256 || v.split('/').some(p => ['__proto__', 'prototype', 'constructor'].includes(p))) bad(); return v; }
export function parseZapSessionPolicy(v: unknown, origin: string): ZapSessionPolicy {
  exact(v, ['login', 'session', 'identity', 'maxAttempts'], ['refresh']); exact(v.login, ['path', 'format', 'fields']);
  const path = (p: unknown): string => { if (typeof p !== 'string' || new URL(zapRequestUrl(origin, p)).search || p === ZAP_SESSION_PATH) bad(); return p; };
  if (!['json', 'form'].includes(v.login.format)) bad();
  if (!v.login.fields || typeof v.login.fields !== 'object' || Array.isArray(v.login.fields) || !Object.keys(v.login.fields).length || Object.keys(v.login.fields).length > 8) bad();
  for (const [key, env] of Object.entries(v.login.fields)) { field(key); if (typeof env !== 'string' || !/^[A-Z][A-Z0-9_]{0,127}$/.test(env)) bad(); }
  let session: ZapSessionPolicy['session'];
  if (v.session?.type === 'bearer') { exact(v.session, ['type', 'tokenPointer'], ['refreshPointer']); session = { type: 'bearer', tokenPointer: pointer(v.session.tokenPointer),
    ...(v.session.refreshPointer !== undefined ? { refreshPointer: pointer(v.session.refreshPointer) } : {}) }; }
  else { exact(v.session, ['type', 'name']); if (v.session.type !== 'cookie') bad(); session = { type: 'cookie', name: field(v.session.name) }; }
  let refresh: ZapSessionPolicy['refresh'];
  if (v.refresh !== undefined) { exact(v.refresh, ['path', 'field']); if (session.type !== 'bearer' || !session.refreshPointer) bad(); refresh = { path: path(v.refresh.path), field: field(v.refresh.field) }; }
  const identity = parseAuthAssertion(v.identity, false); path(identity.path);
  if (identity.path === v.login.path || identity.path === refresh?.path || !Number.isSafeInteger(v.maxAttempts) || v.maxAttempts < 1 || v.maxAttempts > 8) bad();
  return { login: { path: path(v.login.path), format: v.login.format, fields: { ...v.login.fields } }, session, identity, maxAttempts: v.maxAttempts, ...(refresh ? { refresh } : {}) };
}
/** Own data values only, selected synchronously. Never hand these values to ZAP. */
export function snapshotZapLogin(policy: ZapSessionPolicy, env: NodeJS.ProcessEnv): Record<string, string> {
  const result: Record<string, string> = {};
  for (const variable of Object.values(policy.login.fields)) {
    const d = Object.getOwnPropertyDescriptor(env, variable), value = d && 'value' in d ? d.value : undefined;
    if (typeof value !== 'string' || !value.length || value.length > 2048 || /[\x00-\x1f\x7f]/.test(value)) bad(); result[variable] = value;
  }
  const values = Object.fromEntries(Object.entries(policy.login.fields).map(([key, variable]) => [key, result[variable]]));
  if (Buffer.byteLength(policy.login.format === 'json' ? JSON.stringify(values) : new URLSearchParams(values).toString()) > 4096) bad();
  return result;
}
/** Trusted Node session capability. The native authentication context sees an opaque cookie only. */
export class ZapSessionBridge {
  readonly virtualOrigin = `http://${randomBytes(24).toString('hex')}.wakeio-zap.invalid`;
  readonly engineCookie = `wakeio_session=${randomBytes(24).toString('hex')}`;
  readonly metrics = { loginRequests: 0, refreshRequests: 0, challenges: 0, exchanges: 0 };
  failed = false;
  private credential: string | undefined;
  private refreshToken: string | undefined;
  private valid = false;
  private verifying = false;
  private pending: 'login' | 'refresh' | undefined;
  onRenewed?: () => Promise<boolean>;
  constructor(readonly policy: ZapSessionPolicy, private readonly env: Record<string, string>) {}
  get ready(): boolean { return this.valid && !this.verifying && !!this.credential && !this.failed; }
  accepts(cookie: string | undefined): boolean { return !!cookie?.split(/;\s*/).includes(this.engineCookie); }
  headers(controller = false): Record<string, string> { return !(this.valid && !!this.credential && !this.failed && (controller || !this.verifying)) ? {} : this.policy.session.type === 'bearer' ? { authorization: 'Bearer ' + this.credential! } : { cookie: `${this.policy.session.name}=${this.credential!}` }; }
  prepare(body: Buffer): { cached: true } | { path: string; body: Buffer; contentType: string } {
    if (++this.metrics.exchanges > 32 || this.failed) bad();
    if (this.policy.login.format === 'form' && [...new URLSearchParams(body.toString()).keys()].length !== 2) bad();
    const supplied = this.policy.login.format === 'json' ? parsePropertyJsonText(body.toString()) : Object.fromEntries(new URLSearchParams(body.toString()));
    exact(supplied, ['username', 'password']); if (supplied.username !== 'wakeio-user' || supplied.password !== 'wakeio-password') bad();
    if (this.ready) return { cached: true };
    if (this.pending || this.metrics.loginRequests + this.metrics.refreshRequests >= this.policy.maxAttempts) { this.failed = true; bad(); }
    const renew = !!this.refreshToken && !!this.policy.refresh;
    this.pending = renew ? 'refresh' : 'login';
    const values = renew ? { [this.policy.refresh!.field]: this.refreshToken! }
      : Object.fromEntries(Object.entries(this.policy.login.fields).map(([field, variable]) => [field, this.env[variable]]));
    if (renew) this.metrics.refreshRequests++; else this.metrics.loginRequests++;
    const json = renew || this.policy.login.format === 'json';
    return { path: renew ? this.policy.refresh!.path : this.policy.login.path, body: Buffer.from(json ? JSON.stringify(values) : new URLSearchParams(values).toString()),
      contentType: json ? 'application/json' : 'application/x-www-form-urlencoded' };
  }
  async receive(status: number, headers: IncomingHttpHeaders, body: Buffer): Promise<boolean> {
    const renewed = this.pending === 'refresh' || this.metrics.loginRequests > 1;
    try {
      if (status < 200 || status > 299) bad();
      if (this.policy.session.type === 'bearer') {
        const json = parsePropertyJsonText(new TextDecoder('utf-8', { fatal: true }).decode(body));
        const token = propertyPointer(json, this.policy.session.tokenPointer);
        if (typeof token !== 'string' || !/^[\x21-\x7e]{1,8192}$/.test(token)) bad(); this.credential = token;
        if (this.policy.session.refreshPointer) {
          const refresh = propertyPointer(json, this.policy.session.refreshPointer);
          if (refresh !== undefined) { if (typeof refresh !== 'string' || !/^[\x21-\x7e]{1,8192}$/.test(refresh)) bad(); this.refreshToken = refresh; }
          if (this.policy.refresh && !this.refreshToken) bad();
        }
      } else {
        const name = this.policy.session.name;
        const cookie = (headers['set-cookie'] ?? []).find(c => c.startsWith(name + '='))?.split(';')[0].slice(name.length + 1);
        if (!cookie || !/^[\x21-\x7e]{1,4096}$/.test(cookie) || /[;,]/.test(cookie)) bad(); this.credential = cookie;
      }
      this.valid = true;
      if (renewed && this.onRenewed) { this.verifying = true; try { if (!await this.onRenewed()) bad(); } finally { this.verifying = false; } }
      return true;
    } catch { this.failed = true; this.valid = false; this.credential = undefined; return false; } finally { this.pending = undefined; }
  }
  observe(status: number): void { if (status === 401) { this.metrics.challenges++; this.valid = false; } else if (status === 403) this.failed = true; }
}
