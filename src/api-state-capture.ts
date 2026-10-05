import type { NormalizedUrl, FetchedResource } from './url-network.js';

/** Internal owned-pilot lane. No root SDK export or user supplied callbacks. */
export interface ApiStateCaptureRecord {
  ordinal: number; path: string; actor: 'owner' | 'other' | 'anonymous' | 'unknown';
  status?: number; body?: Uint8Array; error?: boolean;
}
export interface ApiStateCaptureSession {
  start(url: NormalizedUrl, authorization: string | undefined): number | undefined;
  finish(ordinal: number | undefined, resource?: FetchedResource): void;
  seal(): { records: ApiStateCaptureRecord[]; incomplete: boolean };
  dispose(): void;
}
const sessions = new WeakMap<AbortSignal, ApiStateCaptureSession>();
export function ownedApiCapture(signal?: AbortSignal): ApiStateCaptureSession | undefined {
  return signal ? sessions.get(signal) : undefined;
}
export function openOwnedApiCapture(signal: AbortSignal, origin: string,
  credentials: ReadonlyMap<string, 'owner' | 'other'>): ApiStateCaptureSession {
  if (sessions.has(signal)) throw new Error('capture_session_conflict');
  const records: ApiStateCaptureRecord[] = [];
  let bytes = 0, sealed = false, incomplete = false;
  const session: ApiStateCaptureSession = {
    start(url, authorization) {
      if (sealed || records.length >= 32 || url.origin !== origin) { incomplete = true; return undefined; }
      const actor = authorization === undefined ? 'anonymous' : credentials.get(authorization) ?? 'unknown';
      const ordinal = records.length;
      records.push({ ordinal, path: new URL(url.href).pathname, actor });
      if (actor === 'unknown') incomplete = true;
      return ordinal;
    },
    finish(ordinal, resource) {
      const record = ordinal === undefined ? undefined : records[ordinal];
      if (sealed || !record || record.body || record.error) { incomplete = true; return; }
      if (!resource || resource.body.byteLength > 65536 || bytes + resource.body.byteLength > 1048576) {
        incomplete = true; record.error = true; return;
      }
      bytes += resource.body.byteLength;
      record.status = resource.status;
      // fetchResource's content-decoded body; neither raw HTTP wire nor server submission bytes.
      record.body = resource.body.slice();
    },
    seal() { sealed = true; return { records: records.map(r => ({ ...r, ...(r.body ? { body: r.body.slice() } : {}) })), incomplete }; },
    dispose() {
      sealed = true; sessions.delete(signal);
      for (const record of records) record.body?.fill(0);
      records.length = 0;
    },
  };
  sessions.set(signal, session);
  return session;
}
