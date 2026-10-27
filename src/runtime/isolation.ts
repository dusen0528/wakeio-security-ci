export type IsolationRequirement = 'rootless-docker' | 'gvisor';
export interface IsolationLimits { cpu: number; memoryBytes: number; pids: number }
export interface IsolationProbe {
  leaseId: string;
  endpoint: string;
  daemonVersion: string;
  runtimeVersion: string;
  securityOptions: readonly string[];
  cgroup: { version: number | null; driver: string; systemd: boolean;
    delegatedUnit: string | null; controllers: readonly string[] };
  measured: { leaseId: string; endpoint: string; artifactSha256: string;
    runtime: 'runc' | 'runsc' | null; cpuQuota: number | null; cpuPeriod: number | null;
    memoryMax: number | null; pidsMax: number | null; targetUid: number | null;
    seccompMode: number | null; seccompProfile: string | null; effectiveCaps: string | null; capDropAll: boolean;
    noNewPrivileges: boolean; readOnlyRootfs: boolean; hostMounts: number | null;
    registryFetchSucceeded: boolean; forbiddenBuildEgressBlocked: boolean;
    externalRuntimeEgressBlocked: boolean; secretEnvironmentEmpty: boolean; cleanupConfirmed: boolean };
}
export interface IsolationPreflight {
  requested: IsolationRequirement;
  applied: IsolationRequirement | 'unavailable';
  verified: boolean;
  reasons: string[];
}

const positive = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) > 0;
const text = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;
function validLimits(limits: IsolationLimits): boolean {
  return Number.isFinite(limits.cpu) && limits.cpu > 0 && limits.cpu <= 2
    && positive(limits.memoryBytes) && limits.memoryBytes <= 2 * 1024 ** 3
    && positive(limits.pids) && limits.pids <= 256;
}

/** Pure consistency check for a future trusted collector, not provenance authentication or execution authority.
 * Synthetic unit-test data and documented settings cannot activate the unavailable backend below.
 */
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
  if (!positive(p.cpuQuota) || !positive(p.cpuPeriod) || p.cpuQuota !== limits.cpu * p.cpuPeriod
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

/** No backend/probe collector has been implemented. No caller-supplied JSON can authorize target execution. */
export function preflightIsolation(requested: IsolationRequirement): IsolationPreflight {
  return { requested, applied: 'unavailable', verified: false, reasons: ['backend_unavailable'] };
}
