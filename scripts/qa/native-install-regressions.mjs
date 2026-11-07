import { MessageChannel } from 'node:worker_threads';
import { nativeInstallPacket,
  NATIVE_INSTALL_CASES } from '../../build/src/runtime/runtimes/provision-controller-artifacts.js';
import { observeNativeInstallCase,
  ProvisionBackendCleanupPending } from '../../build/src/runtime/runtimes/provision-backend.js';
import { ProvisionAssetCleanupPending } from '../../build/src/runtime/runtimes/provision-assets.js';
import { ProvisionError, requireProvision } from '../../build/src/runtime/runtimes/provision-types.js';

const emit = value => process.stdout.write(JSON.stringify(value) + '\n');

async function retainOriginal(error) {
  // A referenced message port keeps this original controller alive without polling,
  // even if an unresolved disposal has no remaining subprocess handle. No port escapes.
  const keeper = new MessageChannel();
  keeper.port1.on('message', () => error.cleanupAfterDrain());
  keeper.port1.ref();
  let confirmed = false;
  try {
    if (error instanceof ProvisionBackendCleanupPending) {
      confirmed = (await error.cleanupAfterDrain()).confirmed;
    } else {
      await error.drained;
      await error.cleanupAfterDrain();
      confirmed = true;
    }
    emit({ status: confirmed ? 'cleanup-confirmed' : 'cleanup-unconfirmed' });
  } catch {
    emit({ status: 'cleanup-unconfirmed' });
  }
  if (confirmed) {
    keeper.port1.close();
    keeper.port2.close();
  } else {
    await new Promise(() => {});
  }
}

async function main() {
  requireProvision(process.argv.length === 2 || process.argv.length === 3
    && process.argv[2] === '--describe', 'native_operator_ingress');
  if (process.argv[2] === '--describe') {
    emit(await nativeInstallPacket());
    return;
  }
  let text = '';
  for await (const chunk of process.stdin) {
    text += chunk;
    requireProvision(Buffer.byteLength(text) <= 16384, 'native_operator_bound');
  }
  const request = JSON.parse(text);
  requireProvision(request !== null && typeof request === 'object' && !Array.isArray(request)
    && Object.keys(request).sort().join(',') ===
      'catalog,consentPacketSha256,executeNativeInstallRegressionConsent,matrixDeadlineAt'
    && request.executeNativeInstallRegressionConsent === true, 'consent_required');
  const now = Date.now();
  requireProvision(Number.isSafeInteger(request.matrixDeadlineAt) && request.matrixDeadlineAt > now
    && request.matrixDeadlineAt <= now + 4200000, 'deadline_invalid');
  const lifetime = new AbortController(), abort = () => lifetime.abort();
  process.once('SIGINT', abort);
  process.once('SIGTERM', abort);
  const timer = setTimeout(abort, request.matrixDeadlineAt - now);
  try {
    for (const caseId of NATIVE_INSTALL_CASES) {
      const started = Date.now();
      requireProvision(request.matrixDeadlineAt - started >= 1020000, 'native_matrix_deadline');
      const result = await observeNativeInstallCase({
        executeNativeInstallRegressionConsent: true, consentPacketSha256: request.consentPacketSha256,
        catalog: request.catalog, deadlineAt: started + 900000, acquisitionDeadlineAt: started + 300000,
      }, caseId, lifetime.signal);
      emit(result);
      if (result.status !== 'observed' || !result.cleanup.confirmed || !result.assetDisposalConfirmed) {
        process.exitCode = 1;
        break;
      }
    }
  } catch (error) {
    process.exitCode = 1;
    if (error instanceof ProvisionBackendCleanupPending || error instanceof ProvisionAssetCleanupPending) {
      emit({ status: 'cleanup-pending', retained: true });
      await retainOriginal(error);
    } else {
      emit({ status: 'unavailable', reason: error instanceof ProvisionError ? error.code : 'native_failed' });
    }
  } finally {
    clearTimeout(timer);
    process.removeListener('SIGINT', abort);
    process.removeListener('SIGTERM', abort);
  }
}

try { await main(); }
catch (error) {
  emit({ status: 'unavailable', reason: error instanceof ProvisionError ? error.code : 'native_failed' });
  process.exitCode = 1;
}
