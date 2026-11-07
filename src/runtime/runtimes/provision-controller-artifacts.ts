import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ProvisionFile } from './provision-controller-files.js';
import type { ProvisionHelper } from './provision-controller-config.js';
import { PROVISION_ASSET_CATALOG } from './provision-asset-catalog.js';
import { requireProvision } from './provision-types.js';

const CONTROLLER = ['backend_process.py', 'backend_resources.py', 'bootstrap.py',
  'bootstrap_identity.py', 'bootstrap_prepare.py', 'bootstrap_enforce.py', 'collector.py',
  'collector.mjs', 'collector-memory.mjs', 'collector-network.mjs', 'daemon.py', 'network.py',
  'prequalification.py', 'proxy.mjs', 'proxy_owner.py', 'relay.py', 'relay_transport.py'] as const;
const INSTALL = ['install_audit.py', 'install_config.py', 'install_hook.py', 'install_prepare.py',
  'install_process.py', 'install_records.py', 'install_sandbox.py', 'install_supervisor.py',
  'install_transaction.py', 'seal_files.py', 'seal_hook.py', 'seal_operation.py', 'seal_process.py',
  'seal_types.py'] as const;

const BUILD = ['build.py', 'input_resources.py', 'process.py', 'launch.py',
  'input.py', 'input_archive.py', 'profiles.json'] as const;

export const NATIVE_INSTALL_CASES = ['mount-original', 'mount-corrected', 'apt-original', 'apt-corrected'] as const;
export type NativeInstallCase = typeof NATIVE_INSTALL_CASES[number];
const TESTS = [
  { name: 'runtime_provision_install_mount_test.py',
    sha256: 'a217ce99104dba417614e5851414ef376a695f2ff598a7591888ec1757bd296e' },
  { name: 'runtime_provision_install_apt_test.py',
    sha256: '43366a9059c93956ee5bf767465421eb9996e3713b3fe9645b6b24e80393f6d0' },
] as const;
const ORIGINALS = {
  'mount-original': { name: 'install_sandbox.py',
    sha256: 'd415ec310c495e773688b1b07f2964c2c797e86e73233ee758c99fb70d789882' },
  'apt-original': { name: 'install_config.py',
    sha256: '93ad70b2d6c2797e86bf4bdc1a6a7d688c808699cdcbecddb048014a2e5267b4' },
} as const;
interface Entry {
  readonly name: string;
  readonly url: URL;
  readonly installation: 'controller' | 'install';
  readonly expected?: string;
}

async function sourceBytes(url: URL): Promise<Buffer> {
  const source = await ProvisionFile.open(fileURLToPath(url));
  try { return await source.bytes(128 * 1024); }
  finally { await source.close(); }
}

/** One fixed loader: no caller-selected paths, metadata packages or guest evidence inputs. */
async function loadHelpers(caseId?: NativeInstallCase): Promise<readonly ProvisionHelper[]> {
  const helpers: ProvisionHelper[] = [];
  const root = new URL('../../../../workers/runtime-controller/', import.meta.url);
  const entries: Entry[] = [
    ...CONTROLLER.map(name => ({ name, url: new URL(name, root), installation: 'controller' as const })),
    ...INSTALL.map(name => ({ name, url: new URL(name, root), installation: 'install' as const })),
    ...BUILD.map(name => ({ name: 'build/' + name,
      url: new URL('../../../../workers/runtime-build/' + name, import.meta.url),
      installation: 'controller' as const })),
    { name: 'runtime/builders/build-policy.js', url: new URL('../builders/build-policy.js', import.meta.url),
      installation: 'controller' },
    { name: 'json-snapshot.js', url: new URL('../../json-snapshot.js', import.meta.url), installation: 'controller' },
  ];
  if (caseId) {
    entries.push({ name: 'native_install_regression.py', url: new URL('native_install_regression.py', root),
      installation: 'controller' });
    entries.push(...TESTS.map(test => ({ name: 'native/' + test.name, installation: 'controller' as const,
      expected: test.sha256, url: new URL('../../../../tests/native/' + test.name, import.meta.url) })));
    const original = caseId === 'mount-original' || caseId === 'apt-original' ? ORIGINALS[caseId] : undefined;
    if (original) {
      const position = entries.findIndex(entry => entry.name === original.name && entry.installation === 'install');
      requireProvision(position >= 0, 'native_fixture_binding');
      entries[position] = { name: original.name, installation: 'install', expected: original.sha256,
        url: new URL('../../../../tests/native/fixtures/seal002-original/' + original.name, import.meta.url) };
    }
  }
  for (const entry of entries) {
    const body = await sourceBytes(entry.url), sha256 = createHash('sha256').update(body).digest('hex');
    requireProvision(entry.expected === undefined || sha256 === entry.expected, 'native_fixture_binding');
    helpers.push(Object.freeze({ name: entry.name, body, installation: entry.installation, sha256 }));
  }
  const body = Buffer.from('{"type":"module"}\n');
  helpers.push(Object.freeze({ name: 'package.json', installation: 'controller', body,
    sha256: createHash('sha256').update(body).digest('hex') }));
  return Object.freeze(helpers);
}

export function loadProvisionHelpers(): Promise<readonly ProvisionHelper[]> { return loadHelpers(); }
export function loadNativeInstallHelpers(caseId: NativeInstallCase): Promise<readonly ProvisionHelper[]> {
  requireProvision(NATIVE_INSTALL_CASES.includes(caseId), 'native_case_invalid');
  return loadHelpers(caseId);
}

export function provisionHelperDigest(helpers: readonly ProvisionHelper[]): string {
  return createHash('sha256').update(JSON.stringify(helpers.map(({ name, installation, sha256 }) =>
    ({ name, installation, sha256 })))).digest('hex');
}

/** Static review data only. Comparing this digest never creates consent or a live resource. */
export async function nativeInstallPacket() {
  const cases = [];
  for (const caseId of NATIVE_INSTALL_CASES) {
    const helpers = await loadNativeInstallHelpers(caseId);
    const test = caseId.startsWith('mount-') ? TESTS[0] : TESTS[1];
    cases.push({ caseId, helperDigest: provisionHelperDigest(helpers), test: test.name, testSha256: test.sha256 });
  }
  const names = ['assets', 'asset-archive', 'asset-borrow', 'asset-catalog', 'asset-error', 'asset-format',
    'asset-lifetime', 'asset-prefix', 'asset-tool', 'asset-transfer', 'paths', 'backend', 'backend-capability',
    'build-wire', 'controller',
    'controller-guest', 'native-install', 'controller-artifacts', 'controller-auth', 'controller-config',
    'controller-events', 'controller-files', 'controller-host', 'controller-installer', 'controller-owner',
    'controller-process', 'controller-vm', 'install', 'types', 'probe', 'network', 'relay', 'relay-wire'];
  const urls = names.map(name => ({ name: 'provision-' + name + '.js',
    url: new URL('./provision-' + name + '.js', import.meta.url) }));
  urls.push({ name: 'runtime/isolation.js', url: new URL('../isolation.js', import.meta.url) },
    { name: 'package.json', url: new URL('../../../../package.json', import.meta.url) },
    { name: 'operator.mjs', url: new URL('../../../../scripts/qa/native-install-regressions.mjs', import.meta.url) });
  const host = [];
  for (const entry of urls) {
    const bytes = await sourceBytes(entry.url);
    host.push({ name: entry.name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  const policy = { schema: 'wakeio.native-install-execution/v1', cases, host, catalog: PROVISION_ASSET_CATALOG,
    nodeVersion: process.versions.node, platform: 'darwin-arm64', vm: { cpus: 6, memoryGiB: 8, diskGiB: 40 },
    service: { cpus: 2, memoryGiB: 4, pids: 256 }, peakVms: 1, matrixSeconds: 4200, caseSeconds: 900,
    acquisitionSeconds: 300, cleanupReportSeconds: 120, mountSeconds: 120, aptSeconds: 510,
    gates: ['static_review_then_consent', 'acquired_integrity_format_companions_signing_capacity',
      'consented_boot_auth_installed_service_witness', 'unchanged_setup_signed_closure_before_hook',
      'semantic_evidence', 'original_close_and_disposal_before_next'],
    excluded: ['INSTALL', 'ACCEPT', 'dpkg_install', 'engine', 'relay', 'target', 'scanner'],
    preconsentGuestObservationsRequired: false };
  return Object.freeze({ policy, sha256: createHash('sha256').update(JSON.stringify(policy)).digest('hex') });
}
