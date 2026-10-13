import { createHash } from 'node:crypto';
import { snapshotJsonData } from './json-snapshot.js';
import type { ApiWriteStateEvidence, ApiWriteExecutionLedger } from './contracts.js';

export const WRITE_SCOPE = 'owned-synthetic-resource-patch-write' as const;
export const writeDigest = (bytes: string | Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
export interface WriteResource { id: string; owner: 0 | 1; canary: string; title: string; contents: string }
export interface WriteStore { version: 1; runId: string; resources: WriteResource[] }
const serialise = (value: unknown) => JSON.stringify(value);
const same = (a: unknown, b: unknown) => serialise(a) === serialise(b);
const exactKeys = (value: object, allowed: readonly string[]) => Object.keys(value).every(key => allowed.includes(key));
export function parseWriteStore(bytes: Uint8Array, runId: string): WriteStore {
  if (bytes.byteLength > 65536) throw new Error('state_budget');
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as WriteStore;
  if (!value || value.version !== 1 || value.runId !== runId || Object.keys(value).length !== 3
    || !Array.isArray(value.resources) || value.resources.length !== 2) throw new Error('state_mismatch');
  for (const [index, row] of value.resources.entries()) if (!row || Object.keys(row).length !== 5
    || row.id !== `resource-${index}` || row.owner !== index || !/^owned-canary-[a-f0-9]{32}$/.test(row.canary)
    || typeof row.title !== 'string' || row.title.length > 1024 || typeof row.contents !== 'string' || row.contents.length > 1024) throw new Error('state_mismatch');
  return value;
}
/** Persisted facts only. HTTP status and handler candidate names are not oracle inputs. */
export function observeWriteWindow(before: WriteStore, after: WriteStore, actor: number, target: number, title: string) {
  const stableIdentity = before.resources.every((row, index) => {
    const next = after.resources[index]; return row.id === next.id && row.owner === next.owner && row.canary === next.canary;
  });
  const changed = !same(before, after);
  const otherChanged = !same(before.resources[1 - target], after.resources[1 - target]);
  const unexpectedMutation = !stableIdentity || otherChanged || after.resources[target].contents !== before.resources[target].contents
    || changed && after.resources[target].title !== title;
  const normal = actor === target && !unexpectedMutation && after.resources[target].title === title
    && after.resources[target].contents === before.resources[target].contents;
  return { integrity: stableIdentity, effect: changed && (actor !== target || otherChanged), normal, unexpectedMutation };
}
export function ownedWriteSteps(): ApiWriteExecutionLedger['steps'] {
  const steps: ApiWriteExecutionLedger['steps'] = [];
  const add = (action: ApiWriteExecutionLedger['steps'][number]['action'], actorIndex: 0 | 1 | 2, resourceIndex?: 0 | 1) => {
    steps.push({ ordinal: steps.length, action, method: action.endsWith('write') ? 'PATCH' : 'GET', actorIndex,
      ...(resourceIndex === undefined ? {} : { resourceIndex }), attempted: false, outcome: 'not_attempted', httpStatus: null });
  };
  add('identity-before', 0); add('identity-before', 1);
  for (const resource of [0, 1] as const) {
    add('read-before', resource, resource); add('owner-write', resource, resource); add('read-normal', resource, resource);
    add('peer-write', resource === 0 ? 1 : 0, resource); add('read-peer', resource, resource);
    add('anonymous-write', 2, resource); add('read-anonymous', resource, resource);
  }
  add('identity-after', 0); add('identity-after', 1); return steps;
}
const REASONS = new Set(['invalid_evidence', 'fixture_unavailable', 'source_mismatch', 'state_mismatch', 'state_budget',
  'identity_failed', 'normal_prerequisite_failed', 'capture_incomplete', 'dispatch_mismatch', 'write_mismatch', 'baseline_unconfirmed',
  'request_budget', 'body_budget', 'transport_error', 'cancelled', 'timeout', 'cleanup_unknown', 'delivery_failed']);
export function unknownWriteEvidence(phase: ApiWriteStateEvidence['phase'] = 'comparison', runId = 'unknown'): ApiWriteStateEvidence {
  return { version: 1, scope: WRITE_SCOPE, phase, execution: 'partial', effect: 'unknown', normal: 'unknown', verification: 'inconclusive',
    cleanup: 'unknown', reasons: ['invalid_evidence'], counts: { plannedRequests: phase === 'comparison' ? 36 : 18, httpAttempts: 0,
      patchAttempts: 0, capturedResponses: 0, stateObservations: 0 }, lineage: { runId }, nextEvidence: 'review_execution' };
}
/** Strict bounded projection; syntax and digest binding do not authenticate remote state. */
export function parseApiWriteStateEvidence(input: unknown): ApiWriteStateEvidence | undefined {
  try {
    const e = snapshotJsonData(input) as ApiWriteStateEvidence;
    if (!e || !exactKeys(e, ['version', 'scope', 'phase', 'execution', 'effect', 'normal', 'verification', 'cleanup', 'reasons', 'counts', 'lineage', 'ledger', 'nextEvidence'])
      || e.version !== 1 || e.scope !== WRITE_SCOPE || !['baseline', 'candidate', 'comparison'].includes(e.phase)
      || !['completed', 'partial', 'error'].includes(e.execution) || !['observed', 'not_observed', 'unknown'].includes(e.effect)
      || !['passed', 'failed', 'unknown'].includes(e.normal) || !['not_evaluated', 'scoped_fix_effect_observed', 'effect_persists', 'normal_regression', 'inconclusive'].includes(e.verification)
      || !['confirmed', 'unknown', 'not_run'].includes(e.cleanup) || !['review_owned_fixture', 'review_execution', 'retry_delivery_only'].includes(e.nextEvidence)
      || !Array.isArray(e.reasons) || e.reasons.length > REASONS.size || e.reasons.some(reason => !REASONS.has(reason))) throw new Error('shape');
    const planned = e.phase === 'comparison' ? 36 : 18;
    if (!e.counts || Object.keys(e.counts).length !== 5 || !exactKeys(e.counts, ['plannedRequests', 'httpAttempts', 'patchAttempts', 'capturedResponses', 'stateObservations']) || e.counts.plannedRequests !== planned
      || !Object.values(e.counts).every(value => Number.isSafeInteger(value) && value >= 0)
      || e.counts.httpAttempts > planned || e.counts.patchAttempts > planned / 3 || e.counts.capturedResponses > e.counts.httpAttempts
      || e.counts.stateObservations > planned / 3 * 2) throw new Error('counts');
    const hashes = ['handlerSha256', 'baselineHandlerSha256', 'patchSha256', 'observerSha256', 'manifestSha256', 'stateBeforeSha256', 'stateAfterSha256', 'beforeReportSha256', 'afterReportSha256'];
    if (!e.lineage || !exactKeys(e.lineage, ['runId', 'runtimeVersion', 'observerBasis', ...hashes])
      || typeof e.lineage.runId !== 'string' || !/^(?:unknown|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/.test(e.lineage.runId)) throw new Error('lineage');
    for (const [key, value] of Object.entries(e.lineage)) {
      if (hashes.includes(key) ? typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)
        : key === 'runtimeVersion' ? typeof value !== 'string' || !/^\d+\.\d+\.\d+$/.test(value)
          : key === 'observerBasis' ? !['compiled-observer-module', 'bundled-runtime'].includes(value as string) : key !== 'runId') throw new Error('lineage');
    }
    const ledger = e.ledger;
    if (ledger) {
      if (!exactKeys(ledger, ['version', 'basis', 'status', 'maximumHttpAttempts', 'maximumPatchAttempts', 'steps'])
        || ledger.version !== 1 || ledger.basis !== 'declared-owned-write-execution' || ledger.maximumHttpAttempts !== 36
        || ledger.maximumPatchAttempts !== 12 || !['complete', 'partial'].includes(ledger.status) || !Array.isArray(ledger.steps) || ledger.steps.length !== planned) throw new Error('ledger');
      const plan = ownedWriteSteps(); let attempts = 0, patches = 0, captured = 0, stopped = false;
      for (const [index, step] of ledger.steps.entries()) {
        const expected = plan[index % 18];
        if (!step || !exactKeys(step, ['ordinal', 'method', 'action', 'actorIndex', 'resourceIndex', 'attempted', 'outcome', 'httpStatus'])
          || step.ordinal !== index || step.method !== expected.method || step.action !== expected.action || step.actorIndex !== expected.actorIndex
          || step.resourceIndex !== expected.resourceIndex || typeof step.attempted !== 'boolean'
          || !['evaluated', 'inconclusive', 'not_attempted'].includes(step.outcome)
          || step.httpStatus !== null && (!Number.isSafeInteger(step.httpStatus) || step.httpStatus < 100 || step.httpStatus > 599)
          || !step.attempted && (step.outcome !== 'not_attempted' || step.httpStatus !== null) || step.attempted && (stopped || step.outcome === 'not_attempted')) throw new Error('step');
        if (step.attempted) { attempts++; if (step.method === 'PATCH') patches++; if (step.httpStatus !== null) captured++; }
        else stopped = true;
        if (step.outcome === 'evaluated') {
          const status = step.httpStatus;
          if (status === null || step.method === 'GET' && status !== 200
            || step.action === 'owner-write' && (status < 200 || status >= 300)
            || step.method === 'PATCH' && (status < 200 || status >= 500 || status >= 300 && status < 400 || status === 429)) throw new Error('status');
        }
      }
      if (attempts !== e.counts.httpAttempts || patches !== e.counts.patchAttempts || captured !== e.counts.capturedResponses
        || ledger.status === 'complete' && ledger.steps.some(step => step.outcome !== 'evaluated')) throw new Error('ledger_counts');
    }
    if (e.execution === 'completed' && (e.reasons.length || e.normal !== 'passed' || e.effect === 'unknown' || e.cleanup !== 'confirmed'
      || e.counts.httpAttempts !== planned || e.counts.capturedResponses !== planned || e.counts.patchAttempts !== planned / 3
      || e.counts.stateObservations !== planned / 3 * 2 || !ledger || ledger.status !== 'complete'
      || !e.lineage.handlerSha256 || !e.lineage.manifestSha256 || !e.lineage.observerSha256 || !e.lineage.observerBasis || !e.lineage.stateBeforeSha256 || !e.lineage.stateAfterSha256)) throw new Error('complete');
    if (e.phase !== 'comparison' && !['not_evaluated', 'inconclusive'].includes(e.verification)) throw new Error('phase');
    if (e.phase === 'comparison' && e.execution === 'completed'
      && e.verification !== (e.effect === 'observed' ? 'effect_persists' : 'scoped_fix_effect_observed')) throw new Error('comparison');
    if (e.verification === 'scoped_fix_effect_observed' && (e.execution !== 'completed' || e.effect !== 'not_observed' || e.normal !== 'passed'
      || !e.lineage.beforeReportSha256 || !e.lineage.afterReportSha256 || !e.lineage.patchSha256 || !e.lineage.baselineHandlerSha256)) throw new Error('verification');
    if (e.verification === 'effect_persists' && (e.execution !== 'completed' || e.effect !== 'observed')) throw new Error('effect');
    if (e.execution !== 'completed' && !['not_evaluated', 'inconclusive'].includes(e.verification)) throw new Error('partial');
    return e;
  } catch { return undefined; }
}
export function sanitiseApiWriteStateEvidence(input: unknown): ApiWriteStateEvidence {
  return parseApiWriteStateEvidence(input) ?? unknownWriteEvidence();
}
