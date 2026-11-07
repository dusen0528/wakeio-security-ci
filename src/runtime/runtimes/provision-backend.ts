import { withProvisionAssets, withProvisionAssetFiles, ProvisionAssetRetentionError,
  type ProvisionAssetRetention } from './provision-assets.js';
import { prepareOwnedController, runOwnedCpuWithdrawal, shutdownOwnedController,
  type PreparedProvisionController, type DelegationRefusal,
  type FixtureObservation } from './provision-controller.js';
import { withPreparedBackend, revokeBackend, type ProvisionedBackend } from './provision-backend-capability.js';
import { ProvisionOwner } from './provision-controller-owner.js';
import { ProvisionError, provisionOptions, requireProvision, unreachable,
  type ProvisionCleanup } from './provision-types.js';
import { executeOwnedNativeInstallCase } from './provision-controller-guest.js';
import { nativeInstallPlan } from './provision-native-install.js';
import type { ProvisionAssetFiles } from './provision-assets.js';

export { withVerifiedBackend, type ProvisionedBackend, type VerifiedBackend } from './provision-backend-capability.js';

/** The original owner and retention remain private even when a bounded result reports failure. */
export class ProvisionBackendCleanupPending extends ProvisionError {
  constructor(private readonly completion: Promise<ProvisionCleanup>,
    readonly retainedResources: readonly string[]) {
    super('cleanup_unconfirmed', retainedResources);
  }
  cleanupAfterDrain(): Promise<ProvisionCleanup> { return this.completion; }
  toJSON(): { readonly code: string; readonly retained: true } {
    return { code: this.code, retained: true };
  }
}

interface TrustedFlow<T> {
  readonly before: (prepared: PreparedProvisionController) => Promise<FixtureObservation | undefined>;
  readonly use: (handle: ProvisionedBackend) => Promise<T>;
}
type Attempt<T> = Readonly<{ kind: 'returned'; value: T }>
  | Readonly<{ kind: 'refused'; refusal: DelegationRefusal }>
  | Readonly<{ kind: 'failed'; error: unknown }>;
interface Invocation {
  prepared?: PreparedProvisionController;
  handle?: ProvisionedBackend;
  fixture?: FixtureObservation;
  published: boolean;
}

async function consume<T>(owner: ProvisionOwner, flow: TrustedFlow<T>, invocation: Invocation): Promise<Attempt<T>> {
  requireProvision(invocation.prepared, 'prepared_handle_invalid');
  invocation.fixture = await flow.before(invocation.prepared);
  return await withPreparedBackend(invocation.prepared, async handle => {
    invocation.handle = handle;
    invocation.published = true;
    const value = await flow.use(handle);
    owner.check();
    return value;
  });
}

/** Reporting only: physical ownership stays with the existing owner and original token. */
function finish(owner: ProvisionOwner, invocation: Invocation, token: ProvisionAssetRetention) {
  if (invocation.handle) revokeBackend(invocation.handle);
  let expire: (error: Error) => void = () => {};
  const deadline = new Promise<never>((_resolve, reject) => { expire = reject; });
  const timer = setTimeout(() => {
    void owner.close();
    expire(new ProvisionError('cleanup_unconfirmed'));
  }, 120000);
  let failure: unknown;
  const prepared = invocation.prepared;
  const shutdown = prepared && !owner.signal.aborted
    ? owner.borrow(() => shutdownOwnedController(prepared)) : Promise.resolve();
  const permission = shutdown.catch(error => { failure = error; }).then(async () => {
    void owner.close();
    const cleanup = await owner.cleanupAfterDrain();
    if (cleanup.confirmed) await token.release();
    return cleanup;
  });
  const completed = permission.then(async cleanup => {
    if (cleanup.confirmed) await token.disposed;
    return cleanup;
  });
  void completed.then(() => clearTimeout(timer), () => clearTimeout(timer));
  return { permission, completed, deadline, failure: () => failure };
}

type OwnedOperation<T> = (owner: ProvisionOwner, files: ProvisionAssetFiles,
  invocation: Invocation) => Promise<Attempt<T>>;
function backendOperation<T>(flow: TrustedFlow<T>): OwnedOperation<T> {
  return async (owner, files, invocation) => {
    invocation.prepared = await prepareOwnedController(owner, files);
    return await consume(owner, flow, invocation);
  };
}

async function runLifetime<T>(input: unknown, execute: OwnedOperation<T>, signal?: AbortSignal) {
  const options = provisionOptions(input);
  requireProvision(options.requiredGrade === 'rootless-docker', 'required_runtime_unavailable');
  let retention: ProvisionAssetRetention | undefined;
  let complete: (value: ProvisionCleanup | PromiseLike<ProvisionCleanup>) => void = () => {};
  const completion = new Promise<ProvisionCleanup>(resolve => { complete = resolve; }).catch((error: unknown) => {
    if (error instanceof ProvisionAssetRetentionError) {
      throw new ProvisionError('cleanup_unconfirmed', error.retainedDirectory ? [error.retainedDirectory] : []);
    }
    throw error;
  });
  let join: ReturnType<typeof finish> | undefined;
  let rejectReport: (error: Error) => void = () => {};
  const report = new Promise<never>((_resolve, reject) => { rejectReport = reject; });
  void completion.catch(rejectReport);
  const invocation: Invocation = { published: false };
  const operation = withProvisionAssets({
    executeTargetConsent: true, catalog: options.catalog,
    deadlineAt: options.deadlineAt, acquisitionDeadlineAt: options.acquisitionDeadlineAt,
  }, assets => withProvisionAssetFiles(assets, async files => {
    retention = files.retainForDrain();
    const token = retention;
    let owner: ProvisionOwner;
    try { owner = new ProvisionOwner(options.deadlineAt, files.signal); }
    catch (error) {
      complete(token.disposed.then(() => ({ confirmed: true, retained: [], failures: [] })));
      await token.release();
      throw error;
    }
    try {
      return await owner.borrow(() => execute(owner, files, invocation));
    } catch (error) { return { kind: 'failed', error } satisfies Attempt<T>; }
    finally {
      join = finish(owner, invocation, token);
      complete(join.completed);
      void join.deadline.catch(rejectReport);
      await Promise.race([join.permission, report]);
    }
  }), signal);
  try {
    const attempt = await Promise.race([operation, report]);
    const cleanup = await Promise.race([completion, report]);
    requireProvision(cleanup.confirmed, 'cleanup_unconfirmed');
    const failure = join?.failure();
    return { attempt: failure === undefined ? attempt : { kind: 'failed' as const, error: failure },
      invocation, cleanup, assetDisposalConfirmed: true as const };
  } catch (error) {
    if (error instanceof ProvisionAssetRetentionError && retention === error.retention
      || error instanceof ProvisionError && error.code === 'cleanup_unconfirmed') {
      throw new ProvisionBackendCleanupPending(completion,
        error instanceof ProvisionAssetRetentionError && error.retainedDirectory ? [error.retainedDirectory] : []);
    }
    throw error;
  }
}

export async function withProvisionedBackend<T>(input: unknown,
  use: (handle: ProvisionedBackend) => Promise<T>, signal?: AbortSignal):
Promise<Readonly<{ value: T; cleanup: ProvisionCleanup; assetDisposalConfirmed: true }>> {
  const result = await runLifetime(input, backendOperation({ before: async () => undefined, use }), signal);
  switch (result.attempt.kind) {
    case 'returned': return Object.freeze({ value: result.attempt.value,
      cleanup: result.cleanup, assetDisposalConfirmed: result.assetDisposalConfirmed });
    case 'refused': throw new ProvisionError(result.attempt.refusal.code, [],
      { cause: { refusal: result.attempt.refusal, cleanup: result.cleanup, assetDisposalConfirmed: true } });
    case 'failed': throw result.attempt.error;
    default: return unreachable(result.attempt);
  }
}

/** Fixed controller-side observer. There is no adapter-supplied callback or fault option. */
export async function observeMissingCpuDelegation(input: unknown, signal?: AbortSignal) {
  const result = await runLifetime(input,
    backendOperation({ before: runOwnedCpuWithdrawal, use: async () => undefined }), signal);
  const { attempt, invocation, cleanup, assetDisposalConfirmed } = result;
  const common = { published: invocation.published, fixture: invocation.fixture,
    runtimeQualified: false as const, cleanup, assetDisposalConfirmed };
  switch (attempt.kind) {
    case 'returned': return { ...common, status: 'fail' as const, reason: 'unexpected_publication' };
    case 'refused':
      return { ...common, status: invocation.fixture && !invocation.published
        && attempt.refusal.missing.join(',') === 'cpu' ? 'pass' as const : 'unavailable' as const,
      reason: attempt.refusal.code, refusal: attempt.refusal };
    case 'failed': {
      const error = attempt.error;
      const cause = error instanceof ProvisionError ? error.cause : undefined;
      const stderrPrefix = cause && typeof cause === 'object' && 'diagnostics' in cause
        && typeof cause.diagnostics === 'string' ? cause.diagnostics : undefined;
      return { ...common, status: 'unavailable' as const, stderrPrefix,
        reason: error instanceof Error && 'code' in error && typeof error.code === 'string'
          ? error.code : 'provision_failed' };
    }
    default: return unreachable(attempt);
  }
}

/** Fixed native ingress; the same original lifetime owns every outcome and late disposal. */
export async function observeNativeInstallCase(input: unknown, fixedCase: unknown, signal?: AbortSignal) {
  const plan = await nativeInstallPlan(input, fixedCase);
  const result = await runLifetime(plan.options, async (owner, files) =>
    ({ kind: 'returned', value: await executeOwnedNativeInstallCase(owner, files, plan) }), signal);
  const common = { caseId: plan.caseId, published: false as const, runtimeQualified: false as const,
    cleanup: result.cleanup, assetDisposalConfirmed: result.assetDisposalConfirmed };
  switch (result.attempt.kind) {
    case 'returned': return { ...common, ...result.attempt.value };
    case 'failed': return { ...common, status: 'unavailable' as const,
      reason: result.attempt.error instanceof ProvisionError ? result.attempt.error.code : 'native_failed' };
    case 'refused': return { ...common, status: 'unavailable' as const, reason: result.attempt.refusal.code };
    default: return unreachable(result.attempt);
  }
}
