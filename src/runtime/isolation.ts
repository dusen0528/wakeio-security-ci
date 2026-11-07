export type IsolationRequirement = 'rootless-docker' | 'gvisor';
export interface IsolationLimits { readonly cpu: number; readonly memoryBytes: number; readonly pids: number }
export interface IsolationProbe {
  readonly leaseId: string;
  readonly endpoint: string;
  readonly daemonVersion: string;
  readonly runtimeVersion: string;
  readonly securityOptions: readonly string[];
  readonly cgroup: { readonly version: number | null; readonly driver: string; readonly systemd: boolean;
    readonly delegatedUnit: string | null; readonly controllers: readonly string[] };
  readonly measured: { readonly leaseId: string; readonly endpoint: string; readonly artifactSha256: string;
    readonly runtime: 'runc' | 'runsc' | null; readonly cpuQuota: number | null; readonly cpuPeriod: number | null;
    readonly memoryMax: number | null; readonly pidsMax: number | null; readonly targetUid: number | null;
    readonly seccompMode: number | null; readonly seccompProfile: string | null; readonly effectiveCaps: string | null;
    readonly capDropAll: boolean; readonly noNewPrivileges: boolean; readonly readOnlyRootfs: boolean;
    readonly hostMounts: number | null; readonly registryFetchSucceeded: boolean;
    readonly forbiddenBuildEgressBlocked: boolean; readonly externalRuntimeEgressBlocked: boolean;
    readonly secretEnvironmentEmpty: boolean; readonly cleanupConfirmed: boolean };
}
export interface IsolationPreflight {
  readonly requested: IsolationRequirement;
  readonly applied: IsolationRequirement | 'unavailable';
  readonly verified: boolean;
  readonly reasons: readonly string[];
}

const positive = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) > 0;
const text = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;
function validLimits(limits: IsolationLimits): boolean {
  return Number.isFinite(limits.cpu) && limits.cpu > 0 && limits.cpu <= 2
    && positive(limits.memoryBytes) && limits.memoryBytes <= 2 * 1024 ** 3
    && positive(limits.pids) && limits.pids <= 256;
}

/** Immutable M1 62db8cb predicate, with readonly declarations. This is not collector provenance. */
export function checkIsolationProbe(requested: IsolationRequirement, limits: IsolationLimits,
  probe: IsolationProbe | null): { matches: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!['rootless-docker', 'gvisor'].includes(requested) || !validLimits(limits)) reasons.push('invalid_requirement');
  if (!probe?.measured || !probe.cgroup) return { matches: false, reasons: [...reasons, 'probe_unavailable'] };
  const p = probe.measured, c = probe.cgroup;
  if (!text(probe.leaseId) || !/^unix:\/\/\//.test(probe.endpoint) || /[\0\r\n]/.test(probe.endpoint)
    || !text(probe.daemonVersion) || !text(probe.runtimeVersion)
    || p.leaseId !== probe.leaseId || p.endpoint !== probe.endpoint
    || !/^[a-f0-9]{64}$/.test(p.artifactSha256)) reasons.push('probe_binding_missing');
  if (!Array.isArray(probe.securityOptions)
    || !probe.securityOptions.some(option => /^name=rootless(?:,|$)/.test(option))) reasons.push('daemon_not_rootless');
  if (c.version !== 2 || c.driver !== 'systemd' || c.systemd !== true || !text(c.delegatedUnit)
    || !Array.isArray(c.controllers) || !['cpu', 'memory', 'pids'].every(name => c.controllers.includes(name))) {
    reasons.push('cgroup_delegation_missing');
  }
  if (!positive(p.cpuQuota) || !positive(p.cpuPeriod) || p.cpuQuota !== Math.round(limits.cpu * p.cpuPeriod)
    || !positive(p.memoryMax) || p.memoryMax !== limits.memoryBytes
    || !positive(p.pidsMax) || p.pidsMax !== limits.pids) reasons.push('resource_probe_mismatch');
  if (!positive(p.targetUid) || p.seccompMode !== 2 || p.seccompProfile !== 'default'
    || p.effectiveCaps !== '0000000000000000' || p.capDropAll !== true || p.noNewPrivileges !== true
    || p.readOnlyRootfs !== true || p.hostMounts !== 0) reasons.push('target_isolation_unverified');
  if (!['runc', 'runsc'].includes(p.runtime ?? '') || requested === 'gvisor' && p.runtime !== 'runsc') {
    reasons.push('required_runtime_unavailable');
  }
  if (p.registryFetchSucceeded !== true || p.forbiddenBuildEgressBlocked !== true
    || p.externalRuntimeEgressBlocked !== true || p.secretEnvironmentEmpty !== true
    || p.cleanupConfirmed !== true) reasons.push('network_secret_cleanup_unverified');
  return { matches: reasons.length === 0, reasons };
}

/** Preserve the historical data-only refusal; use the owned provision callback for live authority. */
export function preflightIsolation(requested: IsolationRequirement): IsolationPreflight {
  return { requested, applied: 'unavailable', verified: false, reasons: ['backend_unavailable'] };
}
