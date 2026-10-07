import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { constants, readSync } from 'node:fs';
import { lstat, mkdtemp, open, readFile, rm } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createApiRunControl, runApiPolicy, API_DEFAULT_TIMEOUT_MS, API_MAX_REQUESTS, API_MAX_TOTAL_BODY_BYTES } from './api.js';
import { openOwnedApiCapture, type OwnedApiBudget } from './api-state-capture.js';
import { observeOwnedPhase, parseOwnedState, resourceDigest, stateDigest, unknownApiStateEvidence,
  type OwnedActor, type OwnedArrival, type OwnedRead, type OwnedState } from './api-state-observer.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toSarif, writeArtifacts } from './report.js';
import type { ApiStateEvidence, CheckResult, ScanReport, ScanGate } from './contracts.js';
import type { SharedArtifactStorage } from './schemathesis.js';

export type ApiStateCandidate = 'fixed' | 'ineffective' | 'all-deny' | 'normal-regression';
export interface ApiStatePilotOptions { candidate: ApiStateCandidate; timeoutMs?: number; signal?: AbortSignal; verificationRounds?: 1 | 2 }
export interface ApiStatePhaseResult { report: ScanReport; scanGate: ScanGate; evidence: ApiStateEvidence }
export interface ApiStatePilotResult {
  version: 1; scope: 'owned-synthetic-resource-read-only'; runId: string;
  verificationRounds: 1 | 2;
  before: ApiStatePhaseResult | null; after: ApiStatePhaseResult | null;
  beforeRepeat?: ApiStatePhaseResult | null; afterRepeat?: ApiStatePhaseResult | null;
  verification: ScanReport; verificationGate: ScanGate;
  execution: { phaseInvocations: number; apiRequests: number; acceptedRequests: number; bytesInspected: number; cleanup: 'confirmed' | 'unknown' | 'not_run' };
}
export interface ApiStateDeliveryOptions { outDir?: string; storage?: SharedArtifactStorage }
export interface ApiStateDeliveryReceipt {
  version: 1; runId: string; deliveryAttemptId: string; outputRelativePath: string; status: 'delivered' | 'unknown'; reason: 'complete' | 'delivery_failed' | 'delivery_timeout';
  verificationExitCode: 0 | 1 | 2; finalExitCode: 0 | 1 | 2; artifactSha256: string;
  reportDigests: { before?: string; after?: string; beforeRepeat?: string; afterRepeat?: string; verification: string };
  apiReexecuted: false;
}
const ROOT = new URL('../../workers/api-state/', import.meta.url);
const CANDIDATES: readonly ApiStateCandidate[] = ['fixed', 'ineffective', 'all-deny', 'normal-regression'];
// Fixed author-owned files only. This pin is generated before any runtime measurement.
const MANIFEST_PIN = '756014d94c2ae95de9cf40ad1323ca9e5636ab9d99c47a08919eb4a2ac1727e3';
const retained = new WeakMap<ApiStatePilotResult, { artifacts: Array<[string, Array<[string, string]>]>; bytes: Uint8Array; digests: ApiStateDeliveryReceipt['reportDigests'] }>();
const hash = (text: string | Uint8Array) => createHash('sha256').update(text).digest('hex');
const serialise = (value: unknown) => JSON.stringify(value, null, 2) + '\n';
function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); }
  return value;
}
async function regularBytes(path: string, cap: number): Promise<Buffer> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > cap) throw new Error('fixture_unavailable');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const actual = await fd.stat();
    if (!actual.isFile() || actual.size > cap || actual.dev !== stat.dev || actual.ino !== stat.ino) throw new Error('source_mismatch');
    const bytes = await fd.readFile();
    if (bytes.length !== actual.size) throw new Error('source_mismatch');
    return bytes;
  } finally { await fd.close(); }
}
interface FixtureView {
  actor(auth: string | undefined): OwnedActor;
  identity(req: IncomingMessage, res: ServerResponse): boolean;
  readResource(path: string | undefined, actor: OwnedActor): OwnedState['resources'][number] | undefined;
  json(res: ServerResponse, status: number, value: unknown): void;
}
type Handler = (request: IncomingMessage, response: ServerResponse, view: FixtureView) => void;
async function fixtureInputs(candidate: ApiStateCandidate) {
  const manifestBytes = await regularBytes(fileURLToPath(new URL('manifest.json', ROOT)), 65536);
  if (hash(manifestBytes) !== MANIFEST_PIN) throw new Error('source_mismatch');
  const manifest = JSON.parse(manifestBytes.toString()) as { version: number; files: Record<string, string> };
  if (manifest.version !== 1) throw new Error('source_mismatch');
  const names = ['vulnerable', candidate] as const;
  const sources = await Promise.all(names.map(async name => {
    const url = new URL(`${name}.mjs`, ROOT), bytes = await regularBytes(fileURLToPath(url), 65536);
    if (hash(bytes) !== manifest.files[`${name}.mjs`]) throw new Error('source_mismatch');
    const module = await import(url.href) as { handle: Handler };
    if (typeof module.handle !== 'function') throw new Error('fixture_unavailable');
    return { name, url, bytes, sha256: hash(bytes), handle: module.handle };
  }));
  const observerBytes = await regularBytes(fileURLToPath(new URL('./api-state-observer.js', import.meta.url)), 262144);
  const patch = serialise({ format: 'owned-module-replacement-v1', before: sources[0].bytes.toString('utf8'), after: sources[1].bytes.toString('utf8') });
  return { sources, manifestSha256: hash(manifestBytes), observerSha256: hash(observerBytes), patchSha256: hash(patch) };
}
function policy(state: OwnedState, baseUrl: string) {
  return { version: 2 as const, baseUrl,
    actors: [
      { id: 'owner', authorizationEnv: 'OWNED_OWNER_AUTH', identity: { path: '/whoami', status: 200, jsonPointer: '/userId', equals: 'principal-owner', organization: { jsonPointer: '/orgId', equals: 'owned-org' } } },
      { id: 'other', authorizationEnv: 'OWNED_OTHER_AUTH', identity: { path: '/whoami', status: 200, jsonPointer: '/userId', equals: 'principal-other', organization: { jsonPointer: '/orgId', equals: 'owned-org' } } },
      { id: 'anonymous' } ],
    cases: state.resources.map(row => ({ id: `read-${row.owner}`, path: `/resources/${row.id}`,
      allow: { actor: row.owner, status: 200, resource: { jsonPointer: '/id', equals: row.id }, protected: { jsonPointer: '/canary', equals: row.canary } },
      deny: [{ actor: row.owner === 'owner' ? 'other' : 'owner', statuses: [401, 403, 404] }, { actor: 'anonymous', statuses: [401, 403, 404] }] })) };
}
function phaseFailure(reason: string): CheckResult {
  return { id: 'api.authorization', status: 'partial', findings: [], notes: ['Owned fixture phase did not complete.'], metrics: { requestCount: 0, reason } };
}
async function phase(name: 'baseline' | 'candidate', source: Awaited<ReturnType<typeof fixtureInputs>>['sources'][number],
  input: Awaited<ReturnType<typeof fixtureInputs>>, stateBytes: Buffer, state: OwnedState,
  env: NodeJS.ProcessEnv, control: ReturnType<typeof createApiRunControl>, budget: OwnedApiBudget): Promise<ApiStatePhaseResult> {
  const started = new Date(), phaseControl = new AbortController();
  const abort = () => phaseControl.abort();
  control.signal.addEventListener('abort', abort, { once: true });
  if (control.signal.aborted) abort();
  let folder: string | undefined, store: Awaited<ReturnType<typeof open>> | undefined;
  let server: ReturnType<typeof createServer> | undefined, capture: ReturnType<typeof openOwnedApiCapture> | undefined;
  let checks = [phaseFailure('fixture_unavailable')], cleanup: ApiStateEvidence['cleanup'] = 'not_run';
  const arrivals: OwnedArrival[] = [], reads: OwnedRead[] = [];
  let captureResult: ReturnType<ReturnType<typeof openOwnedApiCapture>['seal']> | undefined;
  const reasons = new Set<string>();
  const beforeHash = hash(stateBytes);
  let afterHash: string | undefined, resolvedPolicySha256: string | undefined, policyTemplateSha256 = hash(serialise(policy(state, 'http://owned.invalid')));
  try {
    if (phaseControl.signal.aborted || Date.now() >= control.deadlineAt) throw new Error('cancelled');
    folder = await mkdtemp(join(tmpdir(), 'wakeio-api-state-'));
    const storePath = join(folder, 'resource-state.json');
    const initial = await open(storePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { await initial.writeFile(stateBytes); await initial.sync(); } finally { await initial.close(); }
    store = await open(storePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const storeStat = await store.stat();
    if (!storeStat.isFile() || (storeStat.mode & 0o777) !== 0o600 || storeStat.size !== stateBytes.length
      || (process.getuid && storeStat.uid !== process.getuid())) throw new Error('state_unavailable');
    const observerState = parseOwnedState(await regularBytes(storePath, 65536), state.runId);
    if (stateDigest(serialise(observerState)) !== beforeHash) throw new Error('state_mismatch');
    const actors = new Map<string, 'owner' | 'other'>([[env.OWNED_OWNER_AUTH!, 'owner'], [env.OWNED_OTHER_AUTH!, 'other']]);
    const actor = (authorization: string | undefined): OwnedActor => authorization === undefined ? 'anonymous' : actors.get(authorization) ?? 'anonymous';
    const json = (res: ServerResponse, status: number, value: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(value));
    };
    let ordinal = -1;
    const view: FixtureView = {
      actor, json,
      identity(req, res) {
        if (req.url !== '/whoami') return false;
        const principal = actor(req.headers.authorization);
        json(res, principal === 'anonymous' ? 401 : 200, principal === 'anonymous' ? { error: 'denied' } : { userId: `principal-${principal}`, orgId: 'owned-org' });
        return true;
      },
      readResource(path, principal) {
        // Handler reads the actual persisted bytes, not the observer's expected object.
        const bytes = Buffer.alloc(stateBytes.length);
        if (!store || readSync(store.fd, bytes, 0, bytes.length, 0) !== bytes.length) throw new Error('state_unavailable');
        const current = JSON.parse(bytes.toString('utf8')) as OwnedState;
        const row = current.resources.find(row => path === `/resources/${row.id}`);
        if (row) reads.push({ ordinal, actor: principal, resourceId: row.id, rowSha256: resourceDigest(row) });
        return row;
      },
    };
    server = createServer((req, res) => {
      ordinal = arrivals.length;
      const arrived: OwnedArrival = { path: req.url ?? '', actor: actor(req.headers.authorization), finished: false };
      if (arrivals.length >= 32 || req.method !== 'GET' || phaseControl.signal.aborted) {
        reasons.add('dispatch_mismatch'); json(res, 503, { error: 'stopped' }); return;
      }
      arrivals.push(arrived); res.once('finish', () => { arrived.finished = true; });
      try { source.handle(req, res, view); } catch { json(res, 500, { error: 'fixture-failed' }); }
    });
    await new Promise<void>((resolve, reject) => server!.listen(0, '127.0.0.1', resolve).once('error', reject));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('fixture_unavailable');
    const origin = `http://127.0.0.1:${address.port}`;
    capture = openOwnedApiCapture(phaseControl.signal, origin, actors, budget);
    if (phaseControl.signal.aborted || Date.now() >= control.deadlineAt) throw new Error('cancelled');
    const remaining = Math.max(1, control.deadlineAt - Date.now());
    const resolvedPolicy = policy(state, origin);
    resolvedPolicySha256 = hash(serialise(resolvedPolicy));
    checks = await runApiPolicy({ policy: resolvedPolicy, allowPrivate: true, env, timeoutMs: remaining, signal: phaseControl.signal });
    captureResult = capture.seal();
    afterHash = hash(await regularBytes(storePath, 65536));
    if (afterHash !== beforeHash) reasons.add('state_mismatch');
    if (hash(await regularBytes(fileURLToPath(source.url), 65536)) !== source.sha256) reasons.add('source_mismatch');
    if (hash(await regularBytes(fileURLToPath(new URL('manifest.json', ROOT)), 65536)) !== input.manifestSha256) reasons.add('source_mismatch');
    if (hash(await regularBytes(fileURLToPath(new URL('./api-state-observer.js', import.meta.url)), 262144)) !== input.observerSha256) reasons.add('source_mismatch');
  } catch (error) {
    const known = error instanceof Error && ['state_mismatch', 'state_unavailable', 'source_mismatch', 'cancelled'].includes(error.message) ? error.message : 'fixture_unavailable';
    reasons.add(control.signal.aborted ? 'cancelled' : Date.now() >= control.deadlineAt ? 'timeout' : known);
    captureResult ??= capture?.seal();
  } finally {
    // No raw capture survives a phase. Close work has its own bounded wait.
    capture?.dispose();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([(async () => {
        if (server) await new Promise<void>((resolve, reject) => {
          server!.closeAllConnections(); server!.close(error => error ? reject(error) : resolve());
        });
        await store?.close();
        if (folder) await rm(folder, { recursive: true, force: true });
      })(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('cleanup_unknown')), 2000); })]);
      cleanup = folder || server ? 'confirmed' : 'not_run';
    } catch { cleanup = 'unknown'; reasons.add('cleanup_unknown'); }
    finally { if (timer) clearTimeout(timer); }
    control.signal.removeEventListener('abort', abort);
  }
  if (control.signal.aborted) reasons.add('cancelled');
  else if (Date.now() >= control.deadlineAt) reasons.add('timeout');
  const observation = observeOwnedPhase(state, captureResult?.records ?? [], arrivals, reads, captureResult?.incomplete ?? true);
  for (const reason of observation.reasons) reasons.add(reason);
  for (const record of captureResult?.records ?? []) record.body?.fill(0);
  if (checks.some(check => check.status !== 'completed')) reasons.add('api_incomplete');
  const apiRequests = Number(checks[0]?.metrics?.requestCount ?? 0);
  if (apiRequests !== arrivals.length || apiRequests !== observation.capturedResponses) reasons.add('dispatch_mismatch');
  const apiEffect = checks.some(check => check.findings.some(finding => finding.ruleId === 'api.authorization-data-exposure'));
  if (apiEffect !== (observation.effect === 'observed')) reasons.add('observer_mismatch');
  const evidence: ApiStateEvidence = { version: 1, scope: 'owned-synthetic-resource-read-only', phase: name,
    execution: reasons.size ? 'partial' : 'completed', effect: observation.effect, normal: observation.normal,
    controlOutcomes: observation.controlOutcomes, verification: 'not_evaluated', cleanup, reasons: [...reasons],
    counts: { plannedRequests: 12, apiRequests, acceptedRequests: arrivals.length, capturedResponses: observation.capturedResponses },
    lineage: { runId: state.runId, handlerSha256: source.sha256, baselineHandlerSha256: input.sources[0].sha256,
      patchSha256: input.patchSha256, observerSha256: input.observerSha256, manifestSha256: input.manifestSha256,
      policyTemplateSha256, ...(resolvedPolicySha256 ? { resolvedPolicySha256 } : {}), stateBeforeSha256: beforeHash, ...(afterHash ? { stateAfterSha256: afterHash } : {}), runtimeVersion: process.versions.node },
    nextEvidence: reasons.size ? 'review_execution' : 'review_owned_fixture' };
  // Phase evidence is passive metadata. API status/findings/gate remain the original adjudication.
  const report = createReport(checks.map(check => ({ ...check, apiStateEvidence: evidence })), 'api', started);
  return { report, scanGate: evaluateGate(report), evidence };
}
function oracleFinding(reason: 'effect_persists' | 'normal_regression') {
  return { ruleId: `api.owned-state-${reason}`, title: reason === 'effect_persists' ? 'Owned fixture protected data still reaches another actor' : 'Owned fixture normal data regressed',
    description: 'The declared owned synthetic resource comparison failed. This finding does not verify arbitrary services or OSS vulnerabilities.',
    severity: 'high' as const, confidence: 'high' as const, kind: 'observation' as const, location: {},
    remediation: 'Review the owned handler patch and independent stored-resource evidence; preserve normal owner reads.' };
}
/** Executes only fixed author-owned resource fixtures. No target, worker or observer injection. */
export async function runOwnedApiStatePilot(options: ApiStatePilotOptions): Promise<ApiStatePilotResult> {
  if (!options || typeof options !== 'object' || Object.keys(options).some(key => !['candidate', 'timeoutMs', 'signal', 'verificationRounds'].includes(key))
    || !CANDIDATES.includes(options.candidate) || (options.verificationRounds !== undefined && ![1, 2].includes(options.verificationRounds))) throw new TypeError('invalid_owned_pilot_options');
  // Snapshot permissions before any await. Repetition never accepts an external target.
  const { candidate, timeoutMs, signal } = options;
  const verificationRounds = options.verificationRounds ?? 1;
  const control = createApiRunControl(timeoutMs ?? API_DEFAULT_TIMEOUT_MS, signal);
  const budget: OwnedApiBudget = { requests: { count: 0, max: API_MAX_REQUESTS }, bytes: 0, bodyExhausted: false, bodyReadIncomplete: false };
  const started = new Date(), runId = randomUUID();
  let before: ApiStatePhaseResult | null = null, after: ApiStatePhaseResult | null = null;
  let beforeRepeat: ApiStatePhaseResult | null = null, afterRepeat: ApiStatePhaseResult | null = null;
  let input: Awaited<ReturnType<typeof fixtureInputs>> | undefined, stateBytes: Buffer | undefined;
  const reasons = new Set<string>();
  const runnable = () => !control.signal.aborted && Date.now() < control.deadlineAt
    && budget.requests.count < API_MAX_REQUESTS && !budget.bodyExhausted;
  const baselineValid = (p: ApiStatePhaseResult) => p.evidence.execution === 'completed'
    && p.evidence.effect === 'observed' && p.evidence.normal === 'passed';
  try {
    if (control.signal.aborted) throw new Error('cancelled');
    input = await fixtureInputs(candidate);
    const state: OwnedState = { version: 1, runId, resources: (['owner', 'other'] as const).map(owner => ({
      id: `resource-${owner}`, owner, canary: `owned-canary-${randomBytes(16).toString('hex')}`,
      title: `Title for ${owner}`, contents: `Stored normal contents for ${owner}` })) };
    stateBytes = Buffer.from(serialise(state));
    const env = { OWNED_OWNER_AUTH: `Bearer ${randomBytes(24).toString('hex')}`, OWNED_OTHER_AUTH: `Bearer ${randomBytes(24).toString('hex')}` };
    before = await phase('baseline', input.sources[0], input, stateBytes, state, env, control, budget);
    if (!baselineValid(before)) reasons.add('baseline_unconfirmed');
    if (!reasons.size && runnable()) after = await phase('candidate', input.sources[1], input, stateBytes, state, env, control, budget);
    if (verificationRounds === 2 && after?.evidence.execution === 'completed' && runnable()) {
      beforeRepeat = await phase('baseline', input.sources[0], input, stateBytes, state, env, control, budget);
      if (!baselineValid(beforeRepeat)) reasons.add('baseline_unconfirmed');
      if (!reasons.size && runnable()) afterRepeat = await phase('candidate', input.sources[1], input, stateBytes, state, env, control, budget);
    }
  } catch (error) {
    reasons.add(error instanceof Error && error.message === 'cancelled' ? 'cancelled' : error instanceof Error && error.message === 'source_mismatch' ? 'source_mismatch' : 'fixture_unavailable');
  } finally { stateBytes?.fill(0); control.dispose(); }
  const phases = verificationRounds === 2 ? [before, after, beforeRepeat, afterRepeat] : [before, after];
  if (signal?.aborted) reasons.add('cancelled');
  else if (Date.now() >= control.deadlineAt) reasons.add('timeout');
  if (budget.requests.count >= API_MAX_REQUESTS && phases.some(p => !p || p.evidence.execution !== 'completed')) reasons.add('request_budget');
  if (budget.bodyExhausted) reasons.add('body_budget');
  for (const p of phases) for (const reason of p?.evidence.reasons ?? []) reasons.add(reason);
  if (phases.some(p => !p || p.evidence.execution !== 'completed') && !reasons.size) reasons.add('repeat_incomplete');
  const differs = (a: ApiStatePhaseResult | null, b: ApiStatePhaseResult | null) => !!a && !!b
    && a.evidence.execution === 'completed' && b.evidence.execution === 'completed'
    && (a.evidence.effect !== b.evidence.effect || a.evidence.normal !== b.evidence.normal
      || JSON.stringify(a.evidence.controlOutcomes) !== JSON.stringify(b.evidence.controlOutcomes));
  const inconsistent = verificationRounds === 2 && (differs(before, beforeRepeat) || differs(after, afterRepeat));
  if (inconsistent) reasons.add('repeat_inconsistent');
  const candidates = verificationRounds === 2 ? [after, afterRepeat] : [after];
  // A later clean response, error or skipped repeat cannot erase an observed leak or regression.
  const effect = candidates.some(p => p?.evidence.effect === 'observed') ? 'observed'
    : candidates.every(p => p?.evidence.effect === 'not_observed') ? 'not_observed' : 'unknown';
  const normal = candidates.some(p => p?.evidence.normal === 'failed') ? 'failed'
    : candidates.every(p => p?.evidence.normal === 'passed') ? 'passed' : 'unknown';
  const verdict: ApiStateEvidence['verification'] = reasons.size ? 'inconclusive' : normal === 'failed' ? 'normal_regression' : effect === 'observed' ? 'effect_persists'
    : effect === 'not_observed' && normal === 'passed' ? 'scoped_fix_effect_observed' : 'inconclusive';
  if (verdict === 'inconclusive' && !reasons.size) reasons.add('observer_mismatch');
  const apiRequests = phases.reduce((n, p) => n + (p?.evidence.counts.apiRequests ?? 0), 0);
  const acceptedRequests = phases.reduce((n, p) => n + (p?.evidence.counts.acceptedRequests ?? 0), 0);
  if (apiRequests !== budget.requests.count) reasons.add('dispatch_mismatch');
  const beforeDigest = before ? hash(serialise(before.report)) : undefined, afterDigest = after ? hash(serialise(after.report)) : undefined;
  const repetition: ApiStateEvidence['repetition'] = verificationRounds === 2 ? { rounds: 2,
    completedPhases: phases.filter(p => p?.evidence.execution === 'completed').length,
    consistency: inconsistent ? 'inconsistent' : phases.every(p => p?.evidence.execution === 'completed') ? 'consistent' : 'incomplete',
    phaseReportSha256: phases.filter((p): p is ApiStatePhaseResult => !!p).map(p => hash(serialise(p.report))) } : undefined;
  const evidence: ApiStateEvidence = { ...unknownApiStateEvidence(), phase: 'comparison', execution: reasons.size ? 'partial' : 'completed',
    effect, normal, verification: reasons.size ? 'inconclusive' : verdict, cleanup: phases.some(p => p?.evidence.cleanup === 'unknown') ? 'unknown'
      : phases.some(p => p?.evidence.cleanup === 'confirmed') ? 'confirmed' : 'not_run',
    reasons: [...reasons], counts: { plannedRequests: 24 * verificationRounds, apiRequests, acceptedRequests,
      capturedResponses: phases.reduce((n, p) => n + (p?.evidence.counts.capturedResponses ?? 0), 0) },
    lineage: { ...(after?.evidence.lineage ?? before?.evidence.lineage ?? { runId }),
      ...(beforeDigest ? { beforeReportSha256: beforeDigest } : {}), ...(afterDigest ? { afterReportSha256: afterDigest } : {}) },
    ...(repetition ? { repetition } : {}), nextEvidence: reasons.size ? 'review_execution' : 'review_owned_fixture' };
  const observedFailures = verificationRounds === 2
    ? [...(effect === 'observed' ? [oracleFinding('effect_persists')] : []), ...(normal === 'failed' ? [oracleFinding('normal_regression')] : [])]
    : verdict === 'effect_persists' || verdict === 'normal_regression' ? [oracleFinding(verdict)] : [];
  const verification = createReport([{ id: 'api.owned-state-oracle', status: reasons.size ? 'partial' : 'completed', findings: observedFailures,
    notes: ['Fixture-scoped comparison only. Every phase retains its original API findings/gate in a separate document.',
      'Repeated observations are bounded controls, not statistical reliability, production verification or proof that a fix is permanent.',
      'Finding verification flags are unchanged. Independent review is required to interpret this owned fixture evidence.'], apiStateEvidence: evidence }], 'api', started);
  const result: ApiStatePilotResult = deepFreeze({ version: 1, scope: 'owned-synthetic-resource-read-only', runId, verificationRounds,
    before, after, ...(verificationRounds === 2 ? { beforeRepeat, afterRepeat } : {}), verification,
    verificationGate: evaluateGate(verification), execution: { phaseInvocations: phases.filter(Boolean).length, apiRequests, acceptedRequests,
      bytesInspected: budget.bytes, cleanup: evidence.cleanup } });
  const artifacts: Array<[string, Array<[string, string]>]> = [];
  const digests: ApiStateDeliveryReceipt['reportDigests'] = { verification: hash(serialise(verification)) };
  for (const [name, report] of [['before', before?.report], ['after', after?.report], ['beforeRepeat', beforeRepeat?.report], ['afterRepeat', afterRepeat?.report], ['verification', verification]] as const) {
    if (!report) continue;
    const safe = sanitiseReport(report), json = serialise(safe);
    digests[name] = hash(json);
    artifacts.push([name, [['report.json', json], ['report.sarif', serialise(toSarif(safe))], ['report.md', toMarkdown(safe)], ['agent-report.json', serialise(toAgentReport(safe))]]]);
  }
  retained.set(result, { artifacts, bytes: Buffer.from(serialise(result)), digests });
  return result;
}
/** Delivery-only retry consumes retained redacted bytes; it never starts HTTP or handlers. */
export async function deliverOwnedApiStatePilot(result: ApiStatePilotResult, options: ApiStateDeliveryOptions): Promise<ApiStateDeliveryReceipt> {
  const frozen = retained.get(result);
  if (!frozen || !options || (!options.outDir && !options.storage) || Object.keys(options).some(key => !['outDir', 'storage'].includes(key))
    || (options.outDir !== undefined && (typeof options.outDir !== 'string' || !options.outDir.trim()))
    || (options.storage !== undefined && typeof options.storage.put !== 'function')) throw new TypeError('invalid_owned_delivery');
  let timer: ReturnType<typeof setTimeout> | undefined, expired = false;
  const deliveryAttemptId = randomUUID();
  const outputRelativePath = `${result.runId}/${deliveryAttemptId}`;
  const receipt: ApiStateDeliveryReceipt = { version: 1, runId: result.runId, deliveryAttemptId, outputRelativePath, status: 'delivered', reason: 'complete',
    verificationExitCode: result.verificationGate.exitCode, finalExitCode: result.verificationGate.exitCode,
    artifactSha256: hash(frozen.bytes), reportDigests: { ...frozen.digests }, apiReexecuted: false };
  try {
    await Promise.race([(async () => {
      if (options.storage) await options.storage.put(result.runId, Uint8Array.from(frozen.bytes));
      if (expired) throw new Error('delivery_timeout');
      if (options.outDir) {
        const output = resolve(options.outDir, result.runId, deliveryAttemptId);
        for (const [name, artifacts] of frozen.artifacts) {
          if (expired) throw new Error('delivery_timeout');
          await writeArtifacts(join(output, name), artifacts);
        }
        // Delivery receipt is published last. These are per-file atomic outputs, not a transaction.
        if (expired) throw new Error('delivery_timeout');
        await writeArtifacts(output, [['api-state-delivery.json', serialise({ version: 1, runId: result.runId, deliveryAttemptId,
          status: 'publication_only', requiresCallerAcknowledgement: true, provesFinalProcessExit: false,
          artifactSha256: receipt.artifactSha256, reportDigests: receipt.reportDigests, apiReexecuted: false })]]);
      }
    })(), new Promise<never>((_, reject) => { timer = setTimeout(() => { expired = true; reject(new Error('delivery_timeout')); }, 5000); })]);
  } catch (error) {
    receipt.status = 'unknown'; receipt.reason = error instanceof Error && error.message === 'delivery_timeout' ? 'delivery_timeout' : 'delivery_failed'; receipt.finalExitCode = 2;
  } finally { if (timer) clearTimeout(timer); }
  return deepFreeze(receipt);
}
