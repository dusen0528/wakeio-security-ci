import { createHash } from 'node:crypto';
import type { ApiStateCaptureRecord } from './api-state-capture.js';

export type OwnedActor = 'owner' | 'other' | 'anonymous';
export interface OwnedResource { id: string; owner: 'owner' | 'other'; canary: string; title: string; contents: string }
export interface OwnedState { version: 1; runId: string; resources: OwnedResource[] }
export interface OwnedArrival { path: string; actor: OwnedActor; finished: boolean }
export interface OwnedRead { ordinal: number; actor: OwnedActor; resourceId: string; rowSha256: string }
export function stateDigest(bytes: Uint8Array | string): string { return createHash('sha256').update(bytes).digest('hex'); }
export function resourceDigest(row: OwnedResource): string { return stateDigest(JSON.stringify(row)); }

/** Separate observer schema; never uses policy assertions or scanner verdicts as truth. */
export function parseOwnedState(bytes: Uint8Array, runId: string): OwnedState {
  if (bytes.byteLength > 65536) throw new Error('state_limit');
  const state = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as OwnedState;
  if (!state || state.version !== 1 || state.runId !== runId || !Array.isArray(state.resources) || state.resources.length !== 2) throw new Error('invalid_state');
  const owners = new Set<string>(), ids = new Set<string>(), canaries = new Set<string>();
  for (const row of state.resources) {
    if (!row || !['owner', 'other'].includes(row.owner) || row.id !== `resource-${row.owner}`
      || typeof row.canary !== 'string' || !/^owned-canary-[a-f0-9]{32}$/.test(row.canary)
      || typeof row.title !== 'string' || row.title !== `Title for ${row.owner}`
      || typeof row.contents !== 'string' || row.contents !== `Stored normal contents for ${row.owner}`) throw new Error('invalid_state');
    owners.add(row.owner); ids.add(row.id); canaries.add(row.canary);
  }
  if (owners.size !== 2 || ids.size !== 2 || canaries.size !== 2) throw new Error('invalid_state');
  return state;
}
export interface OwnedObservation {
  effect: 'observed' | 'not_observed' | 'unknown'; normal: 'passed' | 'failed' | 'unknown';
  incomplete: boolean; reasons: string[]; capturedResponses: number;
}
/** Facts come from readonly store + client-consumed body + trusted arrival/read ledgers. */
export function observeOwnedPhase(state: OwnedState, records: readonly ApiStateCaptureRecord[],
  arrivals: readonly OwnedArrival[], reads: readonly OwnedRead[], captureIncomplete: boolean): OwnedObservation {
  const reasons = new Set<string>();
  const expected: Array<[string, OwnedActor]> = [['/whoami', 'owner'], ['/whoami', 'other']];
  for (const row of state.resources) {
    const peer = row.owner === 'owner' ? 'other' : 'owner';
    expected.push([`/resources/${row.id}`, row.owner], [`/resources/${row.id}`, peer],
      [`/resources/${row.id}`, 'anonymous'], [`/resources/${row.id}`, row.owner]);
  }
  expected.push(['/whoami', 'owner'], ['/whoami', 'other']);
  if (new Set(reads.map(read => read.ordinal)).size !== reads.length || reads.length > 8
    || reads.some(read => !Number.isSafeInteger(read.ordinal) || read.ordinal < 0 || records[read.ordinal]?.path === '/whoami'
      || !records[read.ordinal])) reasons.add('read_mismatch');
  if (captureIncomplete) reasons.add('capture_incomplete');
  if (records.length !== 12 || arrivals.length !== 12) reasons.add('dispatch_mismatch');
  let exposed = false, normalFailed = false, ownerControls = 0, capturedResponses = 0;
  const rowById = new Map(state.resources.map(row => [row.id, row]));
  records.forEach((record, ordinal) => {
    const plan = expected[ordinal], arrived = arrivals[ordinal];
    if (!plan || record.ordinal !== ordinal || record.path !== plan[0] || record.actor !== plan[1]
      || !arrived || arrived.path !== record.path || arrived.actor !== record.actor || !arrived.finished) reasons.add('dispatch_mismatch');
    if (!record.body || record.status === undefined || record.error) { reasons.add('capture_incomplete'); return; }
    capturedResponses++;
    if (record.status === 429 || record.status >= 500) reasons.add('response_incomplete');
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(record.body));
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('body');
    } catch { reasons.add('capture_incomplete'); return; }
    if (record.path === '/whoami') {
      if (record.status !== 200 || body.userId !== `principal-${record.actor}` || body.orgId !== 'owned-org') reasons.add('identity_mismatch');
      return;
    }
    const row = rowById.get(record.path.replace(/^\/resources\//, ''));
    if (!row) { reasons.add('state_mismatch'); return; }
    const read = reads.find(item => item.ordinal === ordinal);
    if (!read || read.resourceId !== row.id || read.actor !== record.actor || read.rowSha256 !== resourceDigest(row)) reasons.add('read_mismatch');
    if (record.actor === row.owner) {
      ownerControls++;
      if (record.status !== 200 || body.id !== row.id || body.canary !== row.canary || body.title !== row.title || body.contents !== row.contents) normalFailed = true;
    } else if (body.canary === row.canary && body.id === row.id) exposed = true;
    else if (![401, 403, 404].includes(record.status)) reasons.add('denial_unknown');
  });
  if (ownerControls !== 4) reasons.add('normal_unobserved');
  const incomplete = reasons.size > 0;
  return { effect: exposed ? 'observed' : incomplete ? 'unknown' : 'not_observed',
    normal: normalFailed ? 'failed' : incomplete ? 'unknown' : 'passed', incomplete,
    reasons: [...reasons], capturedResponses };
}

import type { ApiStateEvidence } from './contracts.js';
const EVIDENCE_REASONS = new Set(['invalid_evidence', 'capture_incomplete', 'dispatch_mismatch', 'identity_mismatch',
  'response_incomplete', 'state_mismatch', 'read_mismatch', 'normal_unobserved', 'denial_unknown', 'api_incomplete',
  'observer_mismatch', 'baseline_unconfirmed', 'identity_unavailable', 'source_mismatch', 'cancelled', 'timeout',
  'cleanup_unknown', 'state_unavailable', 'fixture_unavailable', 'normal_regression', 'effect_persists']);
export function unknownApiStateEvidence(phase: ApiStateEvidence['phase'] = 'comparison'): ApiStateEvidence {
  return { version: 1, scope: 'owned-synthetic-resource-read-only', phase, execution: 'partial', effect: 'unknown',
    normal: 'unknown', verification: 'inconclusive', cleanup: 'unknown', reasons: ['invalid_evidence'],
    counts: { plannedRequests: null, apiRequests: null, acceptedRequests: null, capturedResponses: null },
    lineage: {}, nextEvidence: 'review_execution' };
}
/** Syntactic fail-closed projection. It is not a facts/signature verifier. */
export function sanitiseApiStateEvidence(input: unknown): ApiStateEvidence {
  try {
    if (!input || typeof input !== 'object') throw new Error('shape');
    if (Array.isArray(input)) throw new Error('shape');
    const value = input as ApiStateEvidence;
    if (value.version !== 1 || value.scope !== 'owned-synthetic-resource-read-only'
      || !['baseline', 'candidate', 'comparison'].includes(value.phase)
      || !['completed', 'partial', 'error'].includes(value.execution)
      || !['observed', 'not_observed', 'unknown'].includes(value.effect)
      || !['passed', 'failed', 'unknown'].includes(value.normal)
      || !['not_evaluated', 'scoped_fix_effect_observed', 'effect_persists', 'normal_regression', 'inconclusive'].includes(value.verification)
      || !['confirmed', 'unknown', 'not_run'].includes(value.cleanup)
      || !['review_owned_fixture', 'review_execution', 'retry_delivery_only'].includes(value.nextEvidence)
      || !Array.isArray(value.reasons) || value.reasons.length > 24 || value.reasons.some(reason => !EVIDENCE_REASONS.has(reason))) throw new Error('enum');
    if (!value.counts || typeof value.counts !== 'object' || Array.isArray(value.counts)) throw new Error('counts');
    const counts = {} as ApiStateEvidence['counts'];
    for (const key of ['plannedRequests', 'apiRequests', 'acceptedRequests', 'capturedResponses'] as const) {
      const number = value.counts?.[key];
      if (number !== null && (!Number.isSafeInteger(number) || number! < 0 || number! > 64)) throw new Error('count');
      counts[key] = number;
    }
    const lineage: ApiStateEvidence['lineage'] = {};
    if (!value.lineage || typeof value.lineage !== 'object' || Array.isArray(value.lineage)) throw new Error('lineage');
    for (const key of ['handlerSha256', 'baselineHandlerSha256', 'patchSha256', 'observerSha256', 'manifestSha256',
      'policyTemplateSha256', 'resolvedPolicySha256', 'stateBeforeSha256', 'stateAfterSha256', 'beforeReportSha256', 'afterReportSha256'] as const) {
      const hash = value.lineage[key];
      if (hash !== undefined) { if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) throw new Error('digest'); lineage[key] = hash; }
    }
    if (value.lineage.runId !== undefined) {
      if (typeof value.lineage.runId !== 'string' || !/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.lineage.runId)) throw new Error('run');
      lineage.runId = value.lineage.runId;
    }
    if (value.lineage.runtimeVersion !== undefined) {
      if (typeof value.lineage.runtimeVersion !== 'string' || !/^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(value.lineage.runtimeVersion)) throw new Error('runtime');
      lineage.runtimeVersion = value.lineage.runtimeVersion;
    }
    if (counts.plannedRequests !== null && counts.plannedRequests !== (value.phase === 'comparison' ? 24 : 12)) throw new Error('planned');
    if (value.phase !== 'comparison' && value.verification !== 'not_evaluated' && value.verification !== 'inconclusive') throw new Error('phase');
    if (value.verification !== 'not_evaluated' && value.verification !== 'inconclusive' && value.execution !== 'completed') throw new Error('execution');
    if (value.execution === 'completed' && (value.effect === 'unknown' || value.normal === 'unknown')) throw new Error('unknown_complete');
    if (value.execution === 'completed' && (value.cleanup !== 'confirmed' || counts.plannedRequests === null
      || counts.apiRequests !== counts.plannedRequests || counts.acceptedRequests !== counts.apiRequests
      || counts.capturedResponses !== counts.apiRequests || !lineage.runId || !lineage.handlerSha256
      || !lineage.observerSha256 || !lineage.manifestSha256 || !lineage.policyTemplateSha256
      || (value.phase !== 'comparison' && !lineage.resolvedPolicySha256) || !lineage.stateBeforeSha256 || lineage.stateBeforeSha256 !== lineage.stateAfterSha256)) throw new Error('complete');
    if (value.verification === 'scoped_fix_effect_observed' && (value.phase !== 'comparison' || value.execution !== 'completed'
      || value.effect !== 'not_observed' || value.normal !== 'passed' || value.reasons.length
      || !lineage.beforeReportSha256 || !lineage.afterReportSha256 || !lineage.patchSha256 || !lineage.baselineHandlerSha256)) throw new Error('verification');
    if (value.phase === 'comparison' && value.execution === 'completed' && !['scoped_fix_effect_observed', 'effect_persists', 'normal_regression'].includes(value.verification)) throw new Error('verdict');
    if (value.verification === 'effect_persists' && value.effect !== 'observed') throw new Error('effect');
    if (value.verification === 'normal_regression' && value.normal !== 'failed') throw new Error('normal');
    return { version: 1, scope: value.scope, phase: value.phase, execution: value.execution, effect: value.effect,
      normal: value.normal, verification: value.verification, cleanup: value.cleanup, reasons: [...new Set(value.reasons)],
      counts, lineage, nextEvidence: value.nextEvidence };
  } catch { return unknownApiStateEvidence(); }
}
