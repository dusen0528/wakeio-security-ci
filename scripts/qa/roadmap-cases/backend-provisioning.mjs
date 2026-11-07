import { constants } from 'node:fs';
import { chmod, open } from 'node:fs/promises';
import { withProvisionedBackend, withVerifiedBackend,
  observeMissingCpuDelegation } from '../../../build/src/runtime/runtimes/provision-backend.js';
import { PROVISION_ASSET_CATALOG } from '../../../build/src/runtime/runtimes/provision-assets.js';
import { ProvisionAssetError, assetGuard } from '../../../build/src/runtime/runtimes/provision-asset-error.js';
import { downloadAsset, writeAssetStream } from '../../../build/src/runtime/runtimes/provision-asset-transfer.js';
import { AssetDirectory, checkAsset, hashAsset, namedAsset,
  openBoundAsset } from '../../../build/src/runtime/runtimes/provision-paths.js';
import { ProvisionError } from '../../../build/src/runtime/runtimes/provision-types.js';
import { writeArtifact } from './artifacts.mjs';

/** Shared real-file QA operation. The caller retains the original; this scope owns only its copy.
 * @param {import('../../../build/src/runtime/runtimes/provision-paths.js').BoundAssetFile} original
 * @param {Pick<import('../../../build/src/runtime/runtimes/provision-asset-catalog.js').AssetPin,
 * 'bytes'|'sha256'>} expected
 * @param {{ readonly base: string, readonly signal: AbortSignal }} options
 */
export async function refuseTamperedAsset(original, expected, { base, signal }) {
  const directory = await AssetDirectory.create(base);
  try {
    const originalFd = await openBoundAsset(original, signal), byte = Buffer.alloc(1);
    let copy;
    try {
      const { bytesRead } = await originalFd.read(byte, 0, 1, 0);
      assetGuard(bytesRead === 1, 'asset_integrity');
      copy = await writeAssetStream(originalFd.createReadStream({ autoClose: false, start: 0 }),
        { directory, relative: 'copy', limit: expected.bytes, signal }, expected);
    } finally { await originalFd.close(); }
    const originalByte = byte.readUInt8(0);
    byte.writeUInt8(originalByte ^ 1, 0);
    await chmod(copy.path, 0o600);
    const copyFd = await open(copy.path, constants.O_WRONLY | constants.O_NOFOLLOW);
    try {
      const identity = await namedAsset(copy.path, copyFd);
      assetGuard(identity.dev === copy.identity.dev && identity.ino === copy.identity.ino, 'identity_changed');
      const { bytesWritten } = await copyFd.write(byte, 0, 1, 0);
      assetGuard(bytesWritten === 1, 'asset_transfer');
      await copyFd.sync();
    } finally { await copyFd.close(); }
    const corrupt = await hashAsset(copy.path, signal);
    const corruptFd = await openBoundAsset(corrupt, signal);
    let refusal;
    try {
      await writeAssetStream(corruptFd.createReadStream({ autoClose: false, start: 0 }),
        { directory, relative: 'rejected', limit: expected.bytes, signal }, expected);
    } catch (error) {
      if (!(error instanceof ProvisionAssetError) || error.code !== 'asset_integrity') throw error;
      refusal = error.code;
    } finally { await corruptFd.close(); }
    await checkAsset(original, signal);
    const conserved = await hashAsset(original.path, signal);
    return { refusal: refusal ?? null, original, conserved, corrupt,
      mutation: { offset: 0, originalByte, corruptByte: byte.readUInt8(0) },
      cleanup: { confirmed: true, scope: 'owned_byte_copy', directory: directory.root } };
  } finally { await directory.cleanup(); }
}

/** Invocation still requires the independent joined gate and separate explicit startup consent.
 * @param {string} out
 * @param {boolean} consent
 */
async function runAssetTamper(out, consent) {
  if (!consent) throw new ProvisionAssetError('consent_required');
  const signal = AbortSignal.timeout(300000);
  const directory = await AssetDirectory.create('/private/tmp');
  let proof;
  try {
    const pin = PROVISION_ASSET_CATALOG.archive;
    const original = await downloadAsset(pin,
      { directory, relative: 'original', limit: pin.bytes, signal });
    proof = await refuseTamperedAsset(original, pin, { base: '/private/tmp', signal });
  } finally { await directory.cleanup(); }
  const status = proof.refusal === 'asset_integrity' ? 'pass' : 'fail';
  const cleanup = { confirmed: true, scope: 'original_and_copy' };
  const artifacts = [
    await writeArtifact(out, 'backend.json', { status, reason: proof.refusal,
      runtimeQualified: false, published: false, proof }),
    await writeArtifact(out, 'cleanup.json', cleanup),
  ];
  return { status, artifacts, cleanup };
}

async function recordBackend(out, report, result) {
  const artifacts = [
    await writeArtifact(out, 'backend.json', report),
    await writeArtifact(out, 'cleanup.json', { ...result.cleanup,
      assetDisposalConfirmed: result.assetDisposalConfirmed }),
  ];
  return { status: report.status, artifacts, cleanup: result.cleanup };
}

/** Real producer only. Running this case requires separately authorized startup;
 * absence of startup consent is an unavailable result, never a mock-ready pass.
 */
export async function runCase({ out, mutate }) {
  const supported = [undefined, 'missing-consent', 'required-gvisor', 'asset-tamper', 'delegation-missing'];
  if (!supported.includes(mutate)) {
    const cleanup = { confirmed: true, scope: 'not_started' };
    const artifact = await writeArtifact(out, 'backend.json', {
      status: 'unavailable', reason: 'mutation_not_implemented', runtimeQualified: false,
    });
    return { status: 'unavailable', artifacts: [artifact], cleanup };
  }
  const consent = mutate !== 'missing-consent' && process.env.WAKEIO_T6P_EXECUTE_TARGET_CONSENT === 'true';
  let published = false;
  try {
    if (mutate === 'asset-tamper') return await runAssetTamper(out, consent);
    const options = {
      executeTargetConsent: consent, catalog: PROVISION_ASSET_CATALOG,
      deadlineAt: Date.now() + 900000, acquisitionDeadlineAt: Date.now() + 300000,
      requiredGrade: mutate === 'required-gvisor' ? 'gvisor' : 'rootless-docker',
    };
    if (mutate === 'delegation-missing') {
      const result = await observeMissingCpuDelegation(options);
      return await recordBackend(out, result, result);
    }
    const result = await withProvisionedBackend(options, handle => withVerifiedBackend(handle, async backend => {
      published = true;
      await backend.checkpoint();
      return { runId: backend.runId, grade: backend.grade, qualification: backend.qualification,
        mirror: backend.mirror };
    }));
    return await recordBackend(out, { status: 'pass', ...result.value, runtimeQualified: true }, result);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    const code = 'code' in error && typeof error.code === 'string' ? error.code : 'provision_failed';
    const startupRefused = code === 'consent_required' || code === 'required_runtime_unavailable';
    const completed = error instanceof ProvisionError && code === 'delegation_missing'
      && error.cause !== null && typeof error.cause === 'object'
      && 'assetDisposalConfirmed' in error.cause && error.cause.assetDisposalConfirmed === true
      && 'cleanup' in error.cause ? error.cause.cleanup : undefined;
    const cleanup = completed ?? {
      confirmed: startupRefused, scope: startupRefused ? 'not_started' : 'requires_owner_receipt' };
    const artifact = await writeArtifact(out, 'backend.json', {
      status: 'unavailable', reason: code, published, runtimeQualified: false,
      cleanupPending: !cleanup.confirmed,
    });
    return { status: 'unavailable', artifacts: [artifact], cleanup };
  }
}
