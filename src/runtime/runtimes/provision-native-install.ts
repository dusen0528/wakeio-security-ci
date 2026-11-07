import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';
import { NATIVE_INSTALL_CASES, nativeInstallPacket,
  type NativeInstallCase } from './provision-controller-artifacts.js';
import { validateProvisionAssetCatalog } from './provision-asset-catalog.js';
import { authenticateGuest, guestChallenge, type GuestAuthentication } from './provision-controller-auth.js';
import { ProvisionVm } from './provision-controller-vm.js';
import { installInvocation } from './provision-install.js';
import { ProvisionError, provisionOptions, provisionRecord, requireProvision,
  type ProvisionOptions } from './provision-types.js';

export interface NativeInstallPlan {
  readonly caseId: NativeInstallCase;
  readonly options: ProvisionOptions;
  readonly helperDigest: string;
  readonly test: string;
  readonly testSha256: string;
  readonly packetSha256: string;
}
interface OriginalSession { readonly nonce: string; readonly identity: GuestAuthentication }

/** Pure own-data ingress precedes any acquisition, host checks or live resource creation. */
export async function nativeInstallPlan(raw: unknown, fixedCase: unknown): Promise<NativeInstallPlan> {
  requireProvision(raw !== null && typeof raw === 'object' && !types.isProxy(raw), 'consent_required');
  const consent = Object.getOwnPropertyDescriptor(raw, 'executeNativeInstallRegressionConsent');
  requireProvision(consent?.enumerable && 'value' in consent && consent.value === true, 'consent_required');
  const invalid = (): never => { throw new ProvisionError('options_invalid'); };
  const data = provisionRecord(snapshotJsonData(raw, invalid, invalid));
  requireProvision(Object.keys(data).sort().join(',') ===
    'acquisitionDeadlineAt,catalog,consentPacketSha256,deadlineAt,executeNativeInstallRegressionConsent',
  'options_invalid');
  const caseId = NATIVE_INSTALL_CASES.find(value => value === fixedCase);
  requireProvision(caseId, 'native_case_invalid');
  requireProvision(typeof data.consentPacketSha256 === 'string'
    && /^[a-f0-9]{64}$/.test(data.consentPacketSha256), 'native_packet_invalid');
  const catalog = validateProvisionAssetCatalog(data.catalog);
  const options = provisionOptions({ executeTargetConsent: true, requiredGrade: 'rootless-docker', catalog,
    deadlineAt: data.deadlineAt, acquisitionDeadlineAt: data.acquisitionDeadlineAt });
  const packet = await nativeInstallPacket();
  requireProvision(packet.sha256 === data.consentPacketSha256, 'native_packet_changed');
  const selected = packet.policy.cases.find(value => value.caseId === caseId);
  requireProvision(selected, 'native_case_invalid');
  return Object.freeze({ ...selected, options, packetSha256: packet.sha256 });
}

async function checkpoint(vm: ProvisionVm, session: OriginalSession): Promise<void> {
  vm.owner.check();
  const challenge = guestChallenge();
  const process = await vm.admin(['/usr/bin/python3', '-I', '-B',
    '/usr/local/lib/wakeio-controller/bootstrap_identity.py', challenge]);
  const actual = authenticateGuest(await process.output(),
    { nonce: session.nonce, challenge, helper: session.identity.helper });
  requireProvision(actual.boot === session.identity.boot && actual.key === session.identity.key,
    'native_guest_changed');
  await process.drain();
  vm.owner.check();
}

function readiness(stdout: string, expected: Readonly<{
  plan: NativeInstallPlan; session: OriginalSession; unit: string; challenge: string;
}>) {
  const line = stdout.split('\n', 1)[0];
  requireProvision(line && Buffer.byteLength(line) <= 8192, 'native_readiness_bound');
  const frame = provisionRecord(snapshotJsonData(JSON.parse(line)));
  requireProvision(Object.keys(frame).sort().join(',') === 'mac,payload', 'native_readiness_invalid');
  const payload = provisionRecord(frame.payload), { plan, session, unit, challenge } = expected;
  requireProvision(Object.keys(payload).sort().join(',') ===
    'boot,caseId,cgroup,challenge,helper,invocation,mainPid,test,testSha256,unit', 'native_readiness_invalid');
  requireProvision(payload.boot === session.identity.boot && payload.caseId === plan.caseId
    && payload.helper === plan.helperDigest && payload.test === plan.test && payload.testSha256 === plan.testSha256
    && payload.unit === unit && payload.cgroup === '/system.slice/' + unit && payload.challenge === challenge
    && typeof payload.invocation === 'string' && /^[a-f0-9]{32}$/.test(payload.invocation)
    && typeof payload.mainPid === 'number' && Number.isSafeInteger(payload.mainPid) && payload.mainPid > 1,
  'native_readiness_binding');
  requireProvision(typeof frame.mac === 'string' && /^[a-f0-9]{64}$/.test(frame.mac), 'native_readiness_mac');
  const canonical = JSON.stringify(Object.fromEntries(Object.entries(payload).sort(([a], [b]) => a.localeCompare(b))));
  const mac = createHmac('sha256', Buffer.from(session.nonce, 'hex')).update(canonical).digest();
  requireProvision(timingSafeEqual(mac, Buffer.from(frame.mac, 'hex')), 'native_readiness_mac');
  return payload;
}

/** These are evidence candidates, not native qualification or reviewer verdicts. */
function semantic(caseId: NativeInstallCase, stdout: string, stderr: string, code: number | null) {
  const single = /Ran 1 test in [0-9.]+s/.test(stderr);
  if (caseId.endsWith('-corrected')) {
    return code === 0 && single && /\nOK\s*$/.test(stderr) ? 'green-candidate' : 'unclassified';
  }
  if (code !== 1 || !single || !/FAILED \(failures=1\)/.test(stderr) || stderr.includes('ERROR:')) {
    return 'unclassified';
  }
  if (caseId === 'mount-original') {
    return stderr.includes('self.assertEqual(actual, expected)')
      && stderr.includes("AssertionError: b'XXXXXXXXXXXX' != b'sealed-index'") ? 'red-candidate' : 'unclassified';
  }
  const frames = stdout.trim().split('\n').slice(1).map(line => provisionRecord(JSON.parse(line)));
  const captures = frames.filter(frame => Object.hasOwn(frame, 'duplicateLoad'));
  return captures.length === 1 && captures[0]?.duplicateLoad === false
    && frames.filter(frame => typeof frame.nativeInfoFD === 'string').length === 1
    && stderr.includes('FAIL: test_native_single_load_and_duplicate_refusal_before_dpkg')
    && stderr.includes('self.assertEqual([value for key, value in actual') ? 'red-candidate' : 'unclassified';
}

/** Genuine VM only, called from the already-consumed private canonical guest stage. */
export async function runNativeInstall(vm: ProvisionVm, plan: NativeInstallPlan, session: OriginalSession) {
  requireProvision(vm instanceof ProvisionVm && session.identity.helper === plan.helperDigest,
    'native_guest_invalid');
  const seconds = plan.caseId.startsWith('mount-') ? 120 : 510;
  requireProvision(vm.owner.deadlineAt - Date.now() >= seconds * 1000, 'native_deadline_insufficient');
  const timer = setTimeout(() => vm.owner.revoke('native_phase_deadline'), seconds * 1000);
  try {
    await checkpoint(vm, session);
    const invocation = installInvocation(), challenge = guestChallenge();
    const listing = ['/usr/bin/systemctl', 'list-units', '--all', '--full', '--plain', '--no-legend', invocation.unit];
    requireProvision((await (await vm.admin(listing)).output()).trim() === '', 'native_unit_exists');
    const { prepareInstallerEnvelope, confirmInstallerUnitDrained } =
      await import('./provision-controller-installer.js');
    const envelope = plan.caseId.startsWith('apt-') ? await prepareInstallerEnvelope(vm, invocation) : undefined;
    const position = invocation.argv.indexOf('/usr/bin/python3');
    requireProvision(position > 0, 'installer_contract_changed');
    const prefix = envelope?.argv ?? [...invocation.argv.slice(0, position), '--property=IPAddressDeny=any'];
    const argv = [...prefix.map(arg => arg.startsWith('--property=RuntimeMaxSec=')
      ? '--property=RuntimeMaxSec=' + seconds : arg), '/usr/bin/python3', '-I', '-B',
    '/usr/local/lib/wakeio-controller/native_install_regression.py', plan.caseId, plan.helperDigest,
    session.identity.boot, invocation.unit, challenge];
    const process = await vm.admin(argv);
    const observed = await process.observeOpenInput();
    await process.drain();
    if (envelope) await envelope.witness.drain();
    requireProvision(observed.signal === null, 'native_process_interrupted');
    const ready = readiness(observed.stdout, { plan, session, unit: invocation.unit, challenge });
    await confirmInstallerUnitDrained(vm, invocation.unit);
    await checkpoint(vm, session);
    const classification = semantic(plan.caseId, observed.stdout, observed.stderr, observed.code);
    return Object.freeze({ status: classification === 'unclassified' ? 'unavailable' as const : 'observed' as const,
      reason: classification, packetSha256: plan.packetSha256, ready, code: observed.code,
      stdout: observed.stdout, stderr: observed.stderr,
      stdoutSha256: createHash('sha256').update(observed.stdout).digest('hex'),
      stderrSha256: createHash('sha256').update(observed.stderr).digest('hex'),
      transportClosed: true, guestUnitDrained: true, closureDetails: 'not exported by unchanged tests' });
  } finally { clearTimeout(timer); }
}
