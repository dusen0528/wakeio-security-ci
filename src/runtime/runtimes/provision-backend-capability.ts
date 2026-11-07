import { types } from 'node:util';
import { qualifyOwnedController, type LiveProvisionController, type PreparedProvisionController,
  type DelegationRefusal } from './provision-controller.js';
import { requireProvision, unreachable } from './provision-types.js';
import type { ProvisionQualification } from './provision-probe.js';
import type { MavenMirror } from './provision-network.js';

export interface ProvisionedBackend { readonly kind: 'provisioned-backend' }
export interface VerifiedBackend {
  readonly runId: string;
  readonly grade: 'rootless-docker';
  readonly qualification: ProvisionQualification;
  readonly mirror: MavenMirror;
  readonly signal: AbortSignal;
  checkpoint(): Promise<void>;
  enterRuntime(): Promise<void>;
}
interface BackendBinding {
  readonly controller: LiveProvisionController;
  consumed: boolean;
  active: boolean;
}
const BACKENDS = new WeakMap<ProvisionedBackend, BackendBinding>();

/** Data observations cannot create an entry in BACKENDS. Only the producer below publishes one. */
export async function withVerifiedBackend<T>(handle: ProvisionedBackend,
  use: (backend: VerifiedBackend) => Promise<T>): Promise<T> {
  requireProvision(typeof handle === 'object' && handle !== null && !types.isProxy(handle), 'backend_handle_invalid');
  const binding = BACKENDS.get(handle);
  requireProvision(binding?.active && !binding.consumed, 'backend_handle_invalid');
  binding.consumed = true;
  const controller = binding.controller;
  const checkpoint = async () => {
    requireProvision(binding.active, 'backend_revoked');
    await controller.checkpoint();
    requireProvision(binding.active, 'backend_revoked');
  };
  const view: VerifiedBackend = Object.freeze({
    runId: controller.owner.run, grade: 'rootless-docker', signal: controller.owner.signal,
    qualification: controller.qualification, mirror: controller.mirror, checkpoint,
    async enterRuntime() {
      await controller.owner.borrow(async () => {
        await checkpoint();
        const response = await controller.relay.request({ operation: 'network-runtime' });
        requireProvision(response.phase === 'RUNTIME', 'network_phase_invalid');
        await checkpoint();
      });
    },
  });
  try {
    await checkpoint();
    const result = await use(view);
    await checkpoint();
    return result;
  } finally { binding.active = false; }
}

/** Qualification resolves the original controller's private PREPARED membership before publication. */
export async function withPreparedBackend<T>(prepared: PreparedProvisionController,
  use: (handle: ProvisionedBackend) => Promise<T>):
Promise<Readonly<{ kind: 'returned'; value: T }> | Readonly<{ kind: 'refused'; refusal: DelegationRefusal }>> {
  const attempt = await qualifyOwnedController(prepared);
  switch (attempt.kind) {
    case 'refused': return attempt;
    case 'qualified': {
      const binding: BackendBinding = { controller: attempt.controller, active: true, consumed: false };
      const handle: ProvisionedBackend = Object.freeze({ kind: 'provisioned-backend' });
      BACKENDS.set(handle, binding);
      return { kind: 'returned', value: await use(handle) };
    }
    default: return unreachable(attempt);
  }
}

/** The original backend finish revokes membership before starting any asynchronous cleanup. */
export function revokeBackend(handle: ProvisionedBackend): void {
  const binding = BACKENDS.get(handle);
  if (binding) binding.active = false;
  BACKENDS.delete(handle);
}
