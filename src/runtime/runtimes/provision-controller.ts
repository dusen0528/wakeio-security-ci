import { createHash } from 'node:crypto';
import type { ProvisionAssetFiles } from './provision-assets.js';
import type { ProvisionOwner } from './provision-controller-owner.js';
import type { ProvisionHelper } from './provision-controller-config.js';
import { prepareControllerConnection, type ControllerContext } from './provision-controller-guest.js';
import { parseProvisionProbe, type ProvisionQualification } from './provision-probe.js';
import { ProvisionError, provisionRecord, requireProvision, unreachable } from './provision-types.js';
import { snapshotJsonData } from '../../json-snapshot.js';

export interface LiveProvisionController extends ControllerContext {
  readonly qualification: ProvisionQualification;
}
export interface PreparedProvisionController { readonly kind: 'prepared-provision-controller' }
export interface DelegationRefusal {
  readonly kind: 'refused';
  readonly phase: 'qualification';
  readonly code: 'delegation_missing';
  readonly missing: readonly ('cpu' | 'memory' | 'pids')[];
}
export interface FixtureObservation {
  readonly json: string;
  readonly sha256: string;
  readonly helperSha256: string;
  readonly argv: readonly string[];
  readonly unitAbsent: true;
  readonly transportClosed: true;
}
export type ControllerAttempt = Readonly<{ kind: 'qualified'; controller: LiveProvisionController }>
  | Readonly<{ kind: 'refused'; refusal: DelegationRefusal }>;
interface PreparedState {
  readonly context: ControllerContext;
  readonly helpers: readonly ProvisionHelper[];
  readonly snapshot: string;
  phase: 'ready' | 'fixture' | 'observed' | 'consumed' | 'revoked';
}
const PREPARED = new WeakMap<PreparedProvisionController, PreparedState>();

function preparedState(handle: PreparedProvisionController): PreparedState {
  const state = PREPARED.get(handle);
  requireProvision(state, 'prepared_handle_invalid');
  state.context.owner.check();
  return state;
}

/** Controller-internal preparation preserves the normal installation continuation. */
export async function prepareOwnedController(owner: ProvisionOwner, files: ProvisionAssetFiles):
Promise<PreparedProvisionController> {
  const { context, helpers, snapshot } = await prepareControllerConnection(owner, files);
  const handle: PreparedProvisionController = Object.freeze({ kind: 'prepared-provision-controller',
    toJSON(): never { throw new ProvisionError('prepared_handle_invalid'); } });
  PREPARED.set(handle, { context, helpers, snapshot, phase: 'ready' });
  return handle;
}

export async function qualifyOwnedController(handle: PreparedProvisionController): Promise<ControllerAttempt> {
  const state = preparedState(handle);
  requireProvision(state.phase === 'ready' || state.phase === 'observed', 'qualification_consumed');
  state.phase = 'consumed';
  const { context, helpers } = state;
  await context.checkpoint();
  const data = await context.relay.request({ operation: 'qualify' });
  if (Object.hasOwn(data, 'kind')) {
    requireProvision(Object.keys(data).sort().join(',') === 'code,kind,missing,phase'
      && data.kind === 'refused' && data.phase === 'qualification' && data.code === 'delegation_missing'
      && Array.isArray(data.missing), 'qualification_refusal_invalid');
    const required = ['cpu', 'memory', 'pids'] as const;
    const reported: readonly unknown[] = data.missing;
    const missing = required.filter(name => reported.includes(name));
    requireProvision(missing.length > 0 && JSON.stringify(missing) === JSON.stringify(data.missing),
      'qualification_refusal_invalid');
    return Object.freeze({ kind: 'refused', refusal: Object.freeze({
      kind: 'refused', phase: 'qualification', code: 'delegation_missing', missing: Object.freeze(missing) }) });
  }
  const collector = helpers.find(helper => helper.name === 'collector.mjs');
  requireProvision(collector, 'collector_helper_missing');
  const qualification = parseProvisionProbe(data,
    { run: context.owner.run, endpoint: 'unix://' + context.vm.endpoint, collectorSha256: collector.sha256 });
  await context.checkpoint();
  return Object.freeze({ kind: 'qualified', controller: Object.freeze({ ...context, qualification }) });
}

/** One fixed action, not a caller-supplied script/argv/hook. */
export async function runOwnedCpuWithdrawal(handle: PreparedProvisionController): Promise<FixtureObservation> {
  const state = preparedState(handle);
  requireProvision(state.phase === 'ready', 'prequalification_scope_closed');
  state.phase = 'fixture';
  const { context } = state;
  try {
    await context.checkpoint();
    const selected = state.helpers.filter(item => item.name === 'prequalification.py'
      && item.installation === 'controller');
    const helper = selected[0];
    requireProvision(selected.length === 1 && helper
      && createHash('sha256').update(helper.body).digest('hex') === helper.sha256,
    'prequalification_helper_binding');
    requireProvision(context.owner.deadlineAt - Date.now() >= 35000, 'fixture_deadline_insufficient');
    const unit = 'wakeio-delegation-' + context.owner.run + '.service';
    const listing = ['/usr/bin/systemctl', 'list-units', '--all', '--full', '--plain', '--no-legend', unit];
    requireProvision((await (await context.vm.admin(listing)).output()).trim() === '', 'fixture_unit_exists');
    const argv = ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect', '--service-type=exec',
      '--unit=' + unit, '--property=CPUQuota=50%', '--property=MemoryMax=67108864', '--property=TasksMax=16',
      '--property=RuntimeMaxSec=30', '--property=TimeoutStopSec=5', '--property=KillMode=control-group',
      '--property=UMask=0077', '--property=IPAddressDeny=any', '/usr/bin/python3', '-I', '-B', '-',
      Buffer.from(state.snapshot).toString('base64')];
    const process = await context.vm.admin(argv);
    let diagnostics = '';
    const capture = (chunk: Buffer) => { diagnostics = (diagnostics + chunk.toString('utf8')).slice(0, 4096); };
    process.child.stderr.on('data', capture);
    let json: string;
    try { json = await process.output(helper.body.toString('utf8')); }
    catch (error) {
      throw new ProvisionError('prequalification_fixture_failed', [], { cause: { error, diagnostics } });
    } finally { process.child.stderr.removeListener('data', capture); }
    await process.drain();
    requireProvision(Buffer.byteLength(json) <= 65536, 'fixture_observation_bound');
    const data = provisionRecord(snapshotJsonData(JSON.parse(json)));
    const expected = provisionRecord(JSON.parse(state.snapshot));
    requireProvision(Object.keys(data).sort().join(',') === 'after,before,boot,run,thawObserved,unitInvocation,writes'
      && data.run === context.owner.run && data.boot === context.identity.boot && data.thawObserved === true
      && data.unitInvocation === provisionRecord(expected.unit).invocationId, 'fixture_observation_invalid');
    requireProvision((await (await context.vm.admin(listing)).output()).trim() === '', 'fixture_unit_retained');
    await context.checkpoint();
    state.phase = 'observed';
    return Object.freeze({ json, sha256: createHash('sha256').update(json).digest('hex'),
      helperSha256: helper.sha256, argv: Object.freeze(argv), unitAbsent: true, transportClosed: true });
  } catch (error) {
    state.phase = 'revoked';
    throw error;
  }
}

export function shutdownOwnedController(handle: PreparedProvisionController): Promise<void> {
  const state = PREPARED.get(handle);
  requireProvision(state, 'prepared_handle_invalid');
  state.phase = 'revoked';
  return state.context.relay.shutdown();
}

/** Preserve the existing normal preparation signature and error boundary. */
export async function prepareProvisionController(owner: ProvisionOwner, files: ProvisionAssetFiles):
Promise<LiveProvisionController> {
  const prepared = await prepareOwnedController(owner, files);
  const attempt = await qualifyOwnedController(prepared);
  switch (attempt.kind) {
    case 'qualified': return attempt.controller;
    case 'refused': throw new ProvisionError(attempt.refusal.code, [], { cause: attempt.refusal });
    default: return unreachable(attempt);
  }
}
