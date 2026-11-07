import { randomBytes } from 'node:crypto';
import type { ProvisionAssetFiles } from './provision-assets.js';
import { ProvisionDirectory, ProvisionFile } from './provision-controller-files.js';
import type { ProvisionOwner } from './provision-controller-owner.js';
import { ProvisionVm } from './provision-controller-vm.js';
import { provisionBootstrap, provisionVmConfig, type ProvisionHelper } from './provision-controller-config.js';
import { loadProvisionHelpers, loadNativeInstallHelpers,
  provisionHelperDigest } from './provision-controller-artifacts.js';
import { provisionHostCapacity, provisionPlatformTools } from './provision-controller-host.js';
import { installProvisionGuest } from './provision-controller-installer.js';
import type { ProvisionRelay } from './provision-relay.js';
import { provisionRecord, requireProvision, sameBackendIdentity, type BackendIdentity } from './provision-types.js';
import type { MavenMirror } from './provision-network.js';
import type { GuestAuthentication } from './provision-controller-auth.js';
import { runNativeInstall, type NativeInstallPlan } from './provision-native-install.js';

export interface ControllerContext {
  readonly owner: ProvisionOwner;
  readonly vm: ProvisionVm;
  readonly relay: ProvisionRelay;
  readonly identity: BackendIdentity;
  readonly mirror: MavenMirror;
  checkpoint(): Promise<void>;
}
interface GuestState {
  readonly owner: ProvisionOwner;
  readonly vm: ProvisionVm;
  readonly helpers: readonly ProvisionHelper[];
  readonly platform: readonly ProvisionFile[];
  readonly nonce: string;
  readonly authenticated: GuestAuthentication;
}
const PREINSTALL = new WeakSet<GuestState>();

async function adopt(owner: ProvisionOwner, asset: ProvisionAssetFiles['limactl'], role: string) {
  const file = await ProvisionFile.borrow(asset.path, asset.fd);
  owner.own({ identity: 'asset-anchor:' + role, drained: Promise.resolve(),
    async remove() { await file.close(); return true; } });
  return file;
}

async function bootGuest(owner: ProvisionOwner, files: ProvisionAssetFiles,
  plan?: NativeInstallPlan): Promise<GuestState> {
  owner.check();
  await provisionHostCapacity();
  const helpers = plan ? await loadNativeInstallHelpers(plan.caseId) : await loadProvisionHelpers();
  if (plan) requireProvision(provisionHelperDigest(helpers) === plan.helperDigest, 'native_package_changed');
  const nonce = randomBytes(32).toString('hex');
  requireProvision(nonce !== '0'.repeat(64), 'guest_nonce_invalid');
  const root = await ProvisionDirectory.create();
  owner.own({ identity: root.root, drained: Promise.resolve(), remove: () => root.cleanup() });
  const platform = await provisionPlatformTools(root, owner);
  const executable = await adopt(owner, files.limactl, 'limactl');
  const guestagent = await adopt(owner, files.guestagent, 'guestagent');
  const rootfs = await adopt(owner, files.rootfs, 'rootfs');
  const vm = new ProvisionVm(owner, root, { executable, guestagent, rootfs });
  owner.own({ identity: vm.directory, stop: () => vm.stop(), drained: vm.drained, remove: () => vm.remove() });
  const configuration = await root.write('profile.yaml', provisionVmConfig(files.rootfs.path,
    provisionBootstrap(helpers, nonce)));
  await vm.start(configuration);
  const authenticated = await vm.authenticate({ nonce, helper: provisionHelperDigest(helpers) });
  const state = Object.freeze({ owner, vm, helpers, platform, nonce, authenticated });
  PREINSTALL.add(state);
  return state;
}

function consume(state: GuestState): void {
  state.owner.check();
  requireProvision(PREINSTALL.delete(state), 'preinstall_scope_closed');
}

/** Only these fixed continuations can consume the original private boot stage. */
export async function prepareControllerConnection(owner: ProvisionOwner, files: ProvisionAssetFiles) {
  const state = await bootGuest(owner, files);
  consume(state);
  const { vm, nonce, authenticated, platform, helpers } = state;
  const helperDigest = provisionHelperDigest(helpers);
  await installProvisionGuest(vm);
  const relay = vm.createRelay(nonce);
  await relay.start();
  const identity = await relay.identity(await vm.machineDigest());
  requireProvision(identity.boot === authenticated.boot && identity.helper === helperDigest,
    'collector_origin_changed');
  const network = await relay.request({ operation: 'network-build' });
  requireProvision(typeof network.endpoint === 'string' && network.endpoint === 'https://wakeio-maven:8443'
    && typeof network.network === 'string' && /^[a-f0-9]{64}$/.test(network.network)
    && typeof network.certificateSha256 === 'string' && /^[a-f0-9]{64}$/.test(network.certificateSha256),
  'mirror_identity_invalid');
  const checkpoint = async () => {
    owner.check();
    for (const file of platform) await file.check();
    sameBackendIdentity(identity, await relay.identity(await vm.machineDigest()));
    owner.check();
  };
  await checkpoint();
  const context: ControllerContext = Object.freeze({ owner, vm, relay, identity, checkpoint,
    mirror: Object.freeze({ endpoint: network.endpoint, network: network.network,
      certificateSha256: network.certificateSha256 }) });
  const data = provisionRecord(network.ownership);
  requireProvision(data.run === owner.run && data.boot === identity.boot && data.daemon === identity.daemon
    && data.helper === helperDigest, 'prequalification_owner_changed');
  const snapshot = JSON.stringify(data);
  requireProvision(Buffer.byteLength(snapshot) <= 32768, 'prequalification_inventory_bound');
  return { context, helpers, snapshot };
}

async function verifyInstalled(state: GuestState): Promise<void> {
  const paths = state.helpers.map(helper => '/usr/local/lib/wakeio-' + helper.installation + '/' + helper.name);
  const hashes = (await (await state.vm.admin(['/usr/bin/sha256sum', ...paths])).output()).trim().split('\n');
  const stats = (await (await state.vm.admin(['/usr/bin/stat', '--format=%u:%f:%h:%s', ...paths]))
    .output()).trim().split('\n');
  requireProvision(hashes.length === paths.length && stats.length === paths.length, 'native_installed_count');
  for (const [index, helper] of state.helpers.entries()) {
    requireProvision(hashes[index] === helper.sha256 + '  ' + paths[index], 'native_installed_digest');
    const mode = helper.name === 'install_hook.py' ? '81ed' : '81a4';
    requireProvision(stats[index] === '0:' + mode + ':1:' + helper.body.length, 'native_installed_metadata');
  }
  state.owner.check();
}

export async function executeOwnedNativeInstallCase(owner: ProvisionOwner, files: ProvisionAssetFiles,
  plan: NativeInstallPlan) {
  const state = await bootGuest(owner, files, plan);
  consume(state);
  for (const file of state.platform) await file.check();
  await verifyInstalled(state);
  return await runNativeInstall(state.vm, plan, { nonce: state.nonce, identity: state.authenticated });
}
