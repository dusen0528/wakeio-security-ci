import { randomBytes, randomUUID } from 'node:crypto';
import { constants, fstatSync, fsyncSync, ftruncateSync, lstatSync, readSync, writeSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, rename, rm } from 'node:fs/promises';
import { createServer, request, type ServerResponse } from 'node:http';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import { createApiRunControl } from './api.js';
import { WRITE_SCOPE, writeDigest, ownedWriteSteps, parseWriteStore, observeWriteWindow, unknownWriteEvidence, type WriteStore } from './api-write-observer.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toSarif, writeArtifacts } from './report.js';
import type { ApiWriteStateEvidence, ScanReport, ScanGate } from './contracts.js';
import type { SharedArtifactStorage } from './schemathesis.js';

export type ApiWriteStateCandidate = 'fixed' | 'ineffective' | 'all-deny' | 'normal-regression' | 'status-only' | 'wrong-object';
export interface ApiWriteStatePilotOptions { candidate: ApiWriteStateCandidate; activeConsent: true; timeoutMs?: number; signal?: AbortSignal }
export interface ApiWriteStatePhaseResult { report: ScanReport; scanGate: ScanGate; evidence: ApiWriteStateEvidence }
export interface ApiWriteStatePilotResult {
  version: 1; scope: typeof WRITE_SCOPE; runId: string; before: ApiWriteStatePhaseResult | null; after: ApiWriteStatePhaseResult | null;
  verification: ScanReport; verificationGate: ScanGate;
  execution: { httpAttempts: number; patchAttempts: number; bytesInspected: number; stateObservations: number; cleanup: ApiWriteStateEvidence['cleanup'] };
}
export interface ApiWriteStateDeliveryOptions { outDir?: string; storage?: SharedArtifactStorage }
export interface ApiWriteStateDeliveryReceipt {
  version: 1; runId: string; deliveryAttemptId: string; outputRelativePath: string; status: 'delivered' | 'unknown';
  reason: 'complete' | 'delivery_failed' | 'delivery_timeout'; verificationExitCode: 0 | 1 | 2; finalExitCode: 0 | 1 | 2;
  artifactSha256: string; reportDigests: { before?: string; after?: string; verification: string }; apiReexecuted: false;
}
const CANDIDATES: readonly ApiWriteStateCandidate[] = ['fixed', 'ineffective', 'all-deny', 'normal-regression', 'status-only', 'wrong-object'];
const BUNDLED = basename(fileURLToPath(import.meta.url)) === 'wakeio-security-ci.mjs';
const ROOT = new URL(BUNDLED ? '../workers/api-write-state/' : '../../workers/api-write-state/', import.meta.url);
const MANIFEST_PIN = 'f57e973dc2db977f5eab683a5a84be8a09d8fdbf2ad9dc1eb5ebd6b1f97071b6';
const serialise = (value: unknown) => JSON.stringify(value, null, 2) + '\n';
const retained = new WeakMap<ApiWriteStatePilotResult, { bytes: Uint8Array; artifacts: Array<[string, Array<[string, string]>]>; digests: ApiWriteStateDeliveryReceipt['reportDigests'] }>();
function freeze<T>(value: T): T { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
async function regularBytes(path: string, cap: number): Promise<Buffer> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > cap) throw new Error('fixture_unavailable');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const actual = await fd.stat(), bytes = await fd.readFile();
    if (!actual.isFile() || actual.dev !== stat.dev || actual.ino !== stat.ino || bytes.length !== actual.size || bytes.length > cap) throw new Error('source_mismatch');
    return bytes;
  } finally { await fd.close(); }
}
interface HandlerRequest { actor: 0 | 1 | 2; resourceId: string; title: string }
interface StoreView { read(id: string): WriteStore['resources'][number] | undefined; write(id: string, fields: { title?: string; contents?: string }): void }
type Handler = (request: HandlerRequest, view: StoreView) => { status: number; body: unknown };
async function inputs(candidate: ApiWriteStateCandidate) {
  const manifestBytes = await regularBytes(fileURLToPath(new URL('manifest.json', ROOT)), 65536);
  if (writeDigest(manifestBytes) !== MANIFEST_PIN) throw new Error('source_mismatch');
  const manifest = JSON.parse(manifestBytes.toString()) as { version: number; files: Record<string, string> };
  const sources = [];
  for (const name of ['vulnerable', candidate]) {
    const url = new URL(`${name}.mjs`, ROOT), bytes = await regularBytes(fileURLToPath(url), 65536);
    if (manifest.version !== 1 || writeDigest(bytes) !== manifest.files[`${name}.mjs`]) throw new Error('source_mismatch');
    const module = await import(url.href) as { handle: Handler };
    if (typeof module.handle !== 'function') throw new Error('fixture_unavailable');
    sources.push({ url, sha256: writeDigest(bytes), handle: module.handle });
  }
  const observerUrl = BUNDLED ? new URL(import.meta.url) : new URL('./api-write-observer.js', import.meta.url);
  const observerSha256 = writeDigest(await regularBytes(fileURLToPath(observerUrl), 32 * 1024 * 1024));
  return { sources, observerUrl, observerSha256, manifestSha256: writeDigest(manifestBytes),
    patchSha256: writeDigest(serialise({ before: sources[0].sha256, after: sources[1].sha256 })) };
}
interface RunBudget { http: number; patch: number; bytes: number; observations: number }
/** Single attempt, same owned loopback peer, no DNS/address/redirect/retry policy. */
async function requestOwned(port: number, path: string, method: 'GET' | 'PATCH', authorization: string | undefined, body: Buffer | undefined,
  control: ReturnType<typeof createApiRunControl>, budget: RunBudget) {
  if (control.signal.aborted) throw new Error(Date.now() >= control.deadlineAt ? 'timeout' : 'cancelled');
  if (budget.http >= 36 || method === 'PATCH' && budget.patch >= 12) throw new Error('request_budget');
  if (body && body.length > 4096) throw new Error('body_budget');
  budget.http++; if (method === 'PATCH') budget.patch++;
  return await new Promise<{ status: number; body: Buffer }>((resolve, reject) => {
    let settled = false;
    const fail = (reason: string) => { if (!settled) { settled = true; reject(new Error(reason)); } };
    const req = request({ hostname: '127.0.0.1', port, path, method, agent: false, signal: control.signal,
      headers: { accept: 'application/json', 'accept-encoding': 'identity', connection: 'close',
        ...(authorization ? { authorization } : {}), ...(body ? { 'content-type': 'application/json', 'content-length': body.length } : {}) } }, async res => {
      const chunks: Buffer[] = []; let bytes = 0;
      try {
        if (res.socket.remoteAddress !== '127.0.0.1' && res.socket.remoteAddress !== '::ffff:127.0.0.1') throw new Error('transport_error');
        if ((res.statusCode ?? 500) >= 300 && (res.statusCode ?? 500) < 400 || res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') throw new Error('transport_error');
        for await (const chunk of res) {
          const value = Buffer.from(chunk); bytes += value.length; budget.bytes += value.length;
          if (bytes > 65536 || budget.bytes > 1048576) throw new Error('body_budget');
          chunks.push(value);
        }
        if (!settled) { settled = true; resolve({ status: res.statusCode ?? 500, body: Buffer.concat(chunks) }); }
      } catch (error) { res.destroy(); fail(error instanceof Error && error.message === 'body_budget' ? 'body_budget' : 'transport_error'); }
      finally { chunks.forEach(chunk => chunk.fill(0)); }
    });
    req.on('error', () => fail(control.signal.aborted ? Date.now() >= control.deadlineAt ? 'timeout' : 'cancelled' : 'transport_error'));
    req.end(body);
  });
}
function failure(reason: 'effect_persists' | 'normal_regression') {
  return { ruleId: `api.owned-write-state-${reason}`, title: reason === 'effect_persists' ? 'Owned unauthorized PATCH changed persisted state' : 'Owned normal PATCH control failed',
    description: 'Independent stored-state observation of fixed author-owned synthetic resources. HTTP status alone is not the effect oracle; external services and production fixes remain unverified.',
    severity: 'high' as const, confidence: 'high' as const, kind: 'observation' as const, location: {},
    remediation: 'Review ownership and the intended resource/field mutation; preserve legitimate owner writes and independently inspect persisted state.' };
}
async function phase(name: 'baseline' | 'candidate', source: Awaited<ReturnType<typeof inputs>>['sources'][number], input: Awaited<ReturnType<typeof inputs>>,
  initial: WriteStore, tokens: readonly string[], control: ReturnType<typeof createApiRunControl>, budget: RunBudget): Promise<ApiWriteStatePhaseResult> {
  const started = new Date(), startHttp = budget.http, startPatch = budget.patch, startObs = budget.observations;
  const steps = ownedWriteSteps(), reasons = new Set<string>();
  let folder: string | undefined, store: Awaited<ReturnType<typeof open>> | undefined, observer: Awaited<ReturnType<typeof open>> | undefined;
  let storePath: string | undefined, server: ReturnType<typeof createServer> | undefined;
  let beforeSha: string | undefined, afterSha: string | undefined, cleanup: ApiWriteStateEvidence['cleanup'] = 'not_run';
  let effect = false, normalFailed = false, normalUnknown = true, currentOrdinal = -1, captured = 0;
  const pending = new Set<Promise<void>>(), arrivals: Array<{ ordinal: number; method: string; actor: number; resourceId: string | null; finished: boolean }> = [];
  const writes: Array<{ ordinal: number; actor: number; resourceId: string; before: string; after: string }> = [];
  const actorOf = (auth?: string): 0 | 1 | 2 => auth === tokens[0] ? 0 : auth === tokens[1] ? 1 : 2;
  const readBytes = (observed = false) => {
    const handle = observed ? observer : store;
    if (!handle || !storePath) throw new Error('state_mismatch');
    const stat = fstatSync(handle.fd), pathStat = lstatSync(storePath);
    if (!stat.isFile() || stat.size > 65536 || (stat.mode & 0o777) !== 0o600 || process.getuid && stat.uid !== process.getuid()) throw new Error('state_mismatch');
    if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.dev !== stat.dev || pathStat.ino !== stat.ino) throw new Error('state_mismatch');
    const bytes = Buffer.alloc(stat.size);
    if (readSync(handle.fd, bytes, 0, bytes.length, 0) !== bytes.length) throw new Error('state_mismatch');
    const after = fstatSync(handle.fd), afterPath = lstatSync(storePath);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size || afterPath.isSymbolicLink()
      || afterPath.dev !== stat.dev || afterPath.ino !== stat.ino) throw new Error('state_mismatch');
    return bytes;
  };
  const readState = (observed = false) => { const bytes = readBytes(observed); try { return parseWriteStore(bytes, initial.runId); } finally { bytes.fill(0); } };
  const digestState = () => { const bytes = readBytes(true); try { return writeDigest(bytes); } finally { bytes.fill(0); } };
  const snapshot = () => { const state = readState(true); budget.observations++; return state; };
  try {
    if (control.signal.aborted) throw new Error('cancelled');
    folder = await mkdtemp(join(tmpdir(), 'wakeio-api-write-'));
    storePath = join(folder, 'state.json');
    store = await open(storePath, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    await store.writeFile(serialise(initial)); await store.sync();
    observer = await open(storePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const writerStat = await store.stat(), observerStat = await observer.stat();
    if (writerStat.dev !== observerStat.dev || writerStat.ino !== observerStat.ino) throw new Error('state_mismatch');
    beforeSha = digestState();
    const view: StoreView = { read(id) { return readState().resources.find(row => row.id === id); }, write(id, fields) {
      // This primitive validates storage shape but deliberately does NOT enforce actor ownership.
      if (control.signal.aborted || !fields || Object.keys(fields).some(key => !['title', 'contents'].includes(key))
        || Object.values(fields).some(value => typeof value !== 'string' || value.length > 1024)) throw new Error('write_mismatch');
      const state = readState(), row = state.resources.find(row => row.id === id); if (!row || !store) throw new Error('write_mismatch');
      const before = writeDigest(serialise(state)); Object.assign(row, fields); const bytes = Buffer.from(serialise(state));
      if (bytes.length > 65536) throw new Error('state_budget');
      if (writeSync(store.fd, bytes, 0, bytes.length, 0) !== bytes.length) throw new Error('write_mismatch');
      ftruncateSync(store.fd, bytes.length); fsyncSync(store.fd); bytes.fill(0);
      writes.push({ ordinal: currentOrdinal, actor: arrivals[currentOrdinal]?.actor ?? 2, resourceId: id, before, after: writeDigest(serialise(readState())) });
    } };
    const json = (res: ServerResponse, status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
    server = createServer((req, res) => {
      const task = (async () => {
        const actor = actorOf(req.headers.authorization), id = /^\/resources\/(resource-[01])$/.exec(req.url ?? '')?.[1] ?? null;
        const ordinal = arrivals.length; arrivals.push({ ordinal, method: req.method ?? '', actor, resourceId: id, finished: false });
        res.once('finish', () => { arrivals[ordinal].finished = true; });
        if (arrivals.length > 18 || control.signal.aborted) { json(res, 503, { stopped: true }); return; }
        if (req.method === 'GET' && req.url === '/whoami') { json(res, actor === 2 ? 401 : 200, { principal: actor, organization: 'owned-org' }); return; }
        if (!id) { json(res, 404, { missing: true }); return; }
        if (req.method === 'GET') { json(res, actor === view.read(id)?.owner ? 200 : 403, actor === view.read(id)?.owner ? view.read(id) : { denied: true }); return; }
        if (req.method !== 'PATCH') { json(res, 405, { denied: true }); return; }
        const chunks: Buffer[] = []; let size = 0;
        try {
          for await (const chunk of req) { size += chunk.length; if (size > 4096) throw new Error('body_budget'); chunks.push(Buffer.from(chunk)); }
          const bytes = Buffer.concat(chunks); let payload;
          try { payload = JSON.parse(bytes.toString()); } finally { bytes.fill(0); }
          if (!payload || Object.keys(payload).length !== 1 || typeof payload.title !== 'string' || payload.title.length > 1024) throw new Error('write_mismatch');
          currentOrdinal = ordinal; const result = source.handle({ actor, resourceId: id, title: payload.title }, view); json(res, result.status, result.body);
        } finally { chunks.forEach(chunk => chunk.fill(0)); }
      })().catch(() => { if (!res.headersSent) json(res, 500, { failed: true }); else res.destroy(); });
      pending.add(task); void task.finally(() => pending.delete(task));
    });
    await new Promise<void>((resolve, reject) => server!.listen(0, '127.0.0.1', resolve).once('error', reject));
    const address = server.address(); if (!address || typeof address === 'string' || address.address !== '127.0.0.1') throw new Error('fixture_unavailable');
    for (const step of steps) {
      if (control.signal.aborted) throw new Error(Date.now() >= control.deadlineAt ? 'timeout' : 'cancelled');
      const id = step.resourceIndex === undefined ? undefined : `resource-${step.resourceIndex}`;
      const title = `owned-change-${randomBytes(16).toString('hex')}`, body = step.method === 'PATCH' ? Buffer.from(JSON.stringify({ title })) : undefined;
      const before = step.method === 'PATCH' ? snapshot() : undefined, writeOffset = writes.length;
      let response: Awaited<ReturnType<typeof requestOwned>> | undefined, transportFailure: unknown;
      const attemptStart = budget.http; step.attempted = true; step.outcome = 'inconclusive';
      try { response = await requestOwned(address.port, id ? `/resources/${id}` : '/whoami', step.method, tokens[step.actorIndex], body, control, budget); }
      catch (error) { transportFailure = error; }
      finally { body?.fill(0); }
      if (budget.http === attemptStart) { step.attempted = false; step.outcome = 'not_attempted'; }
      if (response) { captured++; step.httpStatus = response.status; }
      if (before && step.resourceIndex !== undefined) {
        const after = snapshot(), observed = observeWriteWindow(before, after, step.actorIndex, step.resourceIndex, title);
        effect ||= observed.effect;
        if (observed.unexpectedMutation) { reasons.add('write_mismatch'); normalFailed = true; }
        if (!observed.integrity) reasons.add('state_mismatch');
        const ownWrites = writes.slice(writeOffset), changed = writeDigest(serialise(before)) !== writeDigest(serialise(after));
        if (ownWrites.length > 1 || ownWrites.some(write => write.ordinal !== step.ordinal || write.actor !== step.actorIndex)
          || changed !== (ownWrites.length === 1) || ownWrites[0] && (ownWrites[0].before !== writeDigest(serialise(before)) || ownWrites[0].after !== writeDigest(serialise(after)))) reasons.add('write_mismatch');
        if (step.action === 'owner-write' && (!observed.normal || !response || response.status < 200 || response.status >= 300)) { normalFailed = true; reasons.add('normal_prerequisite_failed'); }
      }
      try {
        if (transportFailure) throw transportFailure;
        if (!response) throw new Error('capture_incomplete');
        if (response.status === 429 || response.status >= 500) throw new Error('capture_incomplete');
        const arrived = arrivals[step.ordinal];
        if (!arrived || !arrived.finished || arrived.method !== step.method || arrived.actor !== step.actorIndex || arrived.resourceId !== (id ?? null)) throw new Error('dispatch_mismatch');
        const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(response.body));
        if (step.resourceIndex === undefined) {
          if (response.status !== 200 || value.principal !== step.actorIndex || value.organization !== 'owned-org') throw new Error('identity_failed');
        } else if (step.method === 'GET') {
          const actual = readState(true).resources[step.resourceIndex];
          if (response.status !== 200 || JSON.stringify(value) !== JSON.stringify(actual)) { normalFailed = true; throw new Error('normal_prerequisite_failed'); }
        }
        step.outcome = reasons.size ? 'inconclusive' : 'evaluated';
      } finally { response?.body.fill(0); }
      if (reasons.size) break;
    }
    normalUnknown = steps.some(step => step.action.startsWith('identity') || step.action === 'read-normal' ? step.outcome !== 'evaluated' : false);
    afterSha = digestState();
    for (const record of [source, ...input.sources]) if (writeDigest(await regularBytes(fileURLToPath(record.url), 65536)) !== record.sha256) reasons.add('source_mismatch');
    if (writeDigest(await regularBytes(fileURLToPath(new URL('manifest.json', ROOT)), 65536)) !== input.manifestSha256
      || writeDigest(await regularBytes(fileURLToPath(input.observerUrl), 32 * 1024 * 1024)) !== input.observerSha256) reasons.add('source_mismatch');
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'fixture_unavailable';
    reasons.add(['cancelled', 'timeout', 'state_mismatch', 'state_budget', 'write_mismatch', 'normal_prerequisite_failed', 'identity_failed', 'capture_incomplete', 'dispatch_mismatch', 'request_budget', 'body_budget', 'transport_error'].includes(reason) ? reason : 'fixture_unavailable');
    try { afterSha = digestState(); } catch { reasons.add('state_mismatch'); }
  } finally {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try { await Promise.race([(async () => {
      server?.closeAllConnections();
      if (server) await new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve()));
      await Promise.allSettled([...pending]); await observer?.close(); await store?.close(); if (folder) await rm(folder, { recursive: true, force: true });
    })(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('cleanup_unknown')), 2000); })]); cleanup = folder ? 'confirmed' : 'not_run'; }
    catch { cleanup = 'unknown'; reasons.add('cleanup_unknown'); }
    finally { if (timer) clearTimeout(timer); }
  }
  if (control.signal.aborted) reasons.add(Date.now() >= control.deadlineAt ? 'timeout' : 'cancelled');
  if (steps.some(step => step.outcome !== 'evaluated') && !reasons.size) reasons.add('capture_incomplete');
  const evidence: ApiWriteStateEvidence = { version: 1, scope: WRITE_SCOPE, phase: name, execution: reasons.size ? 'partial' : 'completed',
    effect: effect ? 'observed' : reasons.size ? 'unknown' : 'not_observed', normal: normalFailed ? 'failed' : normalUnknown ? 'unknown' : 'passed',
    verification: 'not_evaluated', cleanup, reasons: [...reasons], counts: { plannedRequests: 18, httpAttempts: budget.http - startHttp, patchAttempts: budget.patch - startPatch,
      capturedResponses: captured, stateObservations: budget.observations - startObs },
    lineage: { runId: initial.runId, handlerSha256: source.sha256, baselineHandlerSha256: input.sources[0].sha256, patchSha256: input.patchSha256,
      observerSha256: input.observerSha256, observerBasis: BUNDLED ? 'bundled-runtime' : 'compiled-observer-module', manifestSha256: input.manifestSha256,
      ...(beforeSha ? { stateBeforeSha256: beforeSha } : {}), ...(afterSha ? { stateAfterSha256: afterSha } : {}), runtimeVersion: process.versions.node },
    ledger: { version: 1, basis: 'declared-owned-write-execution', status: reasons.size ? 'partial' : 'complete', maximumHttpAttempts: 36, maximumPatchAttempts: 12, steps },
    nextEvidence: reasons.size ? 'review_execution' : 'review_owned_fixture' };
  const report = createReport([{ id: 'api.owned-write-state-oracle', status: reasons.size ? 'partial' : 'completed',
    findings: [...(effect ? [failure('effect_persists')] : []), ...(normalFailed ? [failure('normal_regression')] : [])],
    notes: ['Owned synthetic PATCH state only; no external service or production fix is verified. State effects are independent of HTTP acknowledgement.'], apiWriteStateEvidence: evidence }], 'api', started);
  return { report, scanGate: evaluateGate(report), evidence };
}
export async function runOwnedApiWriteStatePilot(options: ApiWriteStatePilotOptions): Promise<ApiWriteStatePilotResult> {
  if (!options || types.isProxy(options) || Object.keys(options).some(key => !['candidate', 'activeConsent', 'timeoutMs', 'signal'].includes(key))
    || ![Object.prototype, null].includes(Object.getPrototypeOf(options)) || !Object.hasOwn(options, 'candidate') || !Object.hasOwn(options, 'activeConsent')
    || Object.values(Object.getOwnPropertyDescriptors(options)).some(descriptor => !('value' in descriptor)) || options.activeConsent !== true || !CANDIDATES.includes(options.candidate)) throw new TypeError('invalid_owned_write_options');
  const { candidate, timeoutMs = 30000, signal } = options;
  const control = createApiRunControl(timeoutMs, signal, 30000), started = new Date(), runId = randomUUID();
  const budget: RunBudget = { http: 0, patch: 0, bytes: 0, observations: 0 }, reasons = new Set<string>();
  let before: ApiWriteStatePhaseResult | null = null, after: ApiWriteStatePhaseResult | null = null;
  try {
    if (control.signal.aborted) throw new Error('cancelled');
    const input = await inputs(candidate);
    const initial: WriteStore = { version: 1, runId, resources: ([0, 1] as const).map(owner => ({ id: `resource-${owner}`, owner,
      canary: `owned-canary-${randomBytes(16).toString('hex')}`, title: `Owned initial title ${owner}`, contents: `Owned normal contents ${owner}` })) };
    const tokens = [0, 1].map(() => `Bearer ${randomBytes(24).toString('hex')}`);
    before = await phase('baseline', input.sources[0], input, initial, tokens, control, budget);
    if (before.evidence.execution !== 'completed' || before.evidence.effect !== 'observed' || before.evidence.normal !== 'passed') reasons.add('baseline_unconfirmed');
    if (!reasons.size && !control.signal.aborted) after = await phase('candidate', input.sources[1], input, initial, tokens, control, budget);
  } catch (error) { reasons.add(error instanceof Error && ['cancelled', 'source_mismatch'].includes(error.message) ? error.message : 'fixture_unavailable'); }
  finally { control.dispose(); }
  if (control.signal.aborted || signal?.aborted) reasons.add(Date.now() >= control.deadlineAt ? 'timeout' : 'cancelled');
  for (const p of [before, after]) for (const reason of p?.evidence.reasons ?? []) reasons.add(reason);
  if ((!before || !after) && !reasons.size) reasons.add('baseline_unconfirmed');
  const effect = after?.evidence.effect ?? 'unknown', normal = after?.evidence.normal ?? 'unknown';
  const complete = !reasons.size && before?.evidence.execution === 'completed' && after?.evidence.execution === 'completed' && normal === 'passed';
  const verdict = complete ? effect === 'observed' ? 'effect_persists' : 'scoped_fix_effect_observed' : 'inconclusive';
  const steps = [...(before?.evidence.ledger?.steps ?? ownedWriteSteps()), ...(after?.evidence.ledger?.steps ?? ownedWriteSteps())].map((step, ordinal) => ({ ...step, ordinal }));
  const evidence: ApiWriteStateEvidence = { ...unknownWriteEvidence('comparison', runId), execution: complete ? 'completed' : 'partial', effect, normal,
    verification: verdict, cleanup: [before, after].some(p => p?.evidence.cleanup === 'unknown') ? 'unknown' : [before, after].some(p => p?.evidence.cleanup === 'confirmed') ? 'confirmed' : 'not_run',
    reasons: [...reasons], counts: { plannedRequests: 36, httpAttempts: budget.http, patchAttempts: budget.patch,
      capturedResponses: (before?.evidence.counts.capturedResponses ?? 0) + (after?.evidence.counts.capturedResponses ?? 0), stateObservations: budget.observations },
    lineage: { ...(after?.evidence.lineage ?? before?.evidence.lineage ?? { runId }), ...(before ? { beforeReportSha256: writeDigest(serialise(before.report)) } : {}),
      ...(after ? { afterReportSha256: writeDigest(serialise(after.report)) } : {}) },
    ledger: { version: 1, basis: 'declared-owned-write-execution', status: complete ? 'complete' : 'partial', maximumHttpAttempts: 36, maximumPatchAttempts: 12, steps },
    nextEvidence: complete ? 'review_owned_fixture' : 'review_execution' };
  const verification = createReport([{ id: 'api.owned-write-state-oracle', status: complete ? 'completed' : 'partial', apiWriteStateEvidence: evidence,
    findings: [...(effect === 'observed' ? [failure('effect_persists')] : []), ...(normal === 'failed' ? [failure('normal_regression')] : [])],
    notes: ['Baseline must reproduce unauthorized persisted mutation and legitimate owner functionality. Candidate unmet normal/identity/state controls remain incomplete.',
      'A 200 acknowledgement with unchanged protected state proves no unauthorized mutation in these windows; it does not verify HTTP denial semantics.'] }], 'api', started);
  const result: ApiWriteStatePilotResult = freeze({ version: 1, scope: WRITE_SCOPE, runId, before, after, verification, verificationGate: evaluateGate(verification),
    execution: { httpAttempts: budget.http, patchAttempts: budget.patch, bytesInspected: budget.bytes, stateObservations: budget.observations, cleanup: evidence.cleanup } });
  const artifacts: Array<[string, Array<[string, string]>]> = [], digests: ApiWriteStateDeliveryReceipt['reportDigests'] = { verification: writeDigest(serialise(verification)) };
  for (const [name, report] of [['before', before?.report], ['after', after?.report], ['verification', verification]] as const) if (report) {
    const safe = sanitiseReport(report), json = serialise(safe); digests[name] = writeDigest(json);
    artifacts.push([name, [['report.json', json], ['agent-report.json', serialise(toAgentReport(safe))], ['report.md', toMarkdown(safe)], ['report.sarif', serialise(toSarif(safe))]]]);
  }
  retained.set(result, { bytes: Buffer.from(serialise(result)), artifacts, digests }); return result;
}
/** Retries publish retained redacted bytes only. Directory publication is not a cross-storage transaction. */
export async function deliverOwnedApiWriteStatePilot(result: ApiWriteStatePilotResult, options: ApiWriteStateDeliveryOptions): Promise<ApiWriteStateDeliveryReceipt> {
  const saved = retained.get(result);
  if (!saved || !options || types.isProxy(options) || Object.keys(options).some(key => !['outDir', 'storage'].includes(key))
    || ![Object.prototype, null].includes(Object.getPrototypeOf(options))
    || Object.values(Object.getOwnPropertyDescriptors(options)).some(descriptor => !('value' in descriptor)) || !options.outDir && !options.storage
    || options.outDir !== undefined && (typeof options.outDir !== 'string' || !options.outDir.trim()) || options.storage !== undefined && typeof options.storage.put !== 'function') throw new TypeError('invalid_owned_write_delivery');
  const outDir = Object.hasOwn(options, 'outDir') ? options.outDir : undefined;
  const storage = Object.hasOwn(options, 'storage') ? options.storage : undefined, put = storage?.put;
  const deliveryAttemptId = randomUUID(), outputRelativePath = `${result.runId}/${deliveryAttemptId}`;
  const receipt: ApiWriteStateDeliveryReceipt = { version: 1, runId: result.runId, deliveryAttemptId, outputRelativePath, status: 'delivered', reason: 'complete',
    verificationExitCode: result.verificationGate.exitCode, finalExitCode: result.verificationGate.exitCode, artifactSha256: writeDigest(saved.bytes), reportDigests: { ...saved.digests }, apiReexecuted: false };
  let expired = false, staged = false, published = false, timer: ReturnType<typeof setTimeout> | undefined, stage: string | undefined, final: string | undefined;
  const work = async () => {
    if (put) await put.call(storage, result.runId, Uint8Array.from(saved.bytes));
    if (expired) throw new Error('delivery_timeout');
    if (outDir) {
      const base = resolve(outDir); await writeArtifacts(dirname(base), []);
      try { await mkdir(base, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      await writeArtifacts(base, []); // Validate existing caller roots without changing their permissions.
      const parent = join(base, result.runId);
      try { await mkdir(parent, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      const runStat = await lstat(parent);
      if (!runStat.isDirectory() || runStat.isSymbolicLink() || (runStat.mode & 0o777) !== 0o700
        || process.getuid && runStat.uid !== process.getuid()) throw new Error('delivery_failed');
      await writeArtifacts(parent, []);
      stage = join(parent, `.${deliveryAttemptId}.staging`); final = join(parent, deliveryAttemptId);
      await mkdir(stage, { mode: 0o700 }); staged = true;
      for (const [name, artifacts] of saved.artifacts) {
        if (expired) throw new Error('delivery_timeout');
        const phaseDirectory = join(stage, name); await mkdir(phaseDirectory, { mode: 0o700 });
        await writeArtifacts(phaseDirectory, artifacts);
      }
      if (expired) throw new Error('delivery_timeout');
      const manifest = serialise({ version: 1, scope: WRITE_SCOPE, runId: result.runId, deliveryAttemptId,
        artifacts: saved.artifacts.flatMap(([phase, artifacts]) => artifacts.map(([name, bytes]) => ({ path: `${phase}/${name}`,
          bytes: Buffer.byteLength(bytes, 'utf8'), sha256: writeDigest(bytes) }))) });
      await writeArtifacts(stage, [['api-write-manifest.json', manifest]]);
      if (expired) throw new Error('delivery_timeout');
      await writeArtifacts(stage, [['api-write-delivery.json', serialise({ version: 1, runId: result.runId, deliveryAttemptId, status: 'publication_only',
        requiresCallerAcknowledgement: true, provesFinalProcessExit: false, artifactSha256: receipt.artifactSha256, reportDigests: receipt.reportDigests,
        manifestSha256: writeDigest(manifest), apiReexecuted: false })]]);
      if (expired) throw new Error('delivery_timeout');
      try { await lstat(final); throw new Error('delivery_failed'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      await rename(stage, final); published = true; if (expired) throw new Error('delivery_timeout');
    }
  };
  const operation = work();
  try { await Promise.race([operation, new Promise<never>((_, reject) => { timer = setTimeout(() => { expired = true; reject(new Error('delivery_timeout')); }, 5000); })]); }
  catch (error) { expired = true; receipt.status = 'unknown'; receipt.reason = error instanceof Error && error.message === 'delivery_timeout' ? 'delivery_timeout' : 'delivery_failed'; receipt.finalExitCode = 2;
    void operation.catch(() => {}).finally(async () => { if (staged && stage) await rm(stage, { recursive: true, force: true }).catch(() => {}); if (published && final) await rm(final, { recursive: true, force: true }).catch(() => {}); }); }
  finally { if (timer) clearTimeout(timer); }
  return freeze(receipt);
}
