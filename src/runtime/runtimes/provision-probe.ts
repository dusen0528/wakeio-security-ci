import { checkIsolationProbe, type IsolationProbe } from '../isolation.js';
import { provisionRecord, requireProvision } from './provision-types.js';

export interface ProvisionQualification {
  readonly probe: IsolationProbe;
  readonly cpuEnforced: true;
  readonly memoryEnforced: true;
  readonly pidsEnforced: true;
}

/** Data parser only. Publication requires this result from the live authenticated collector operation. */
export function parseProvisionProbe(raw: unknown, binding: Readonly<{
  run: string; endpoint: string; collectorSha256: string;
}>): ProvisionQualification {
  const data = provisionRecord(raw);
  const number = (key: string): number => {
    const value = data[key];
    requireProvision(typeof value === 'number' && Number.isSafeInteger(value), 'collector_number');
    return value;
  };
  const text = (key: string): string => {
    const value = data[key];
    requireProvision(typeof value === 'string' && value.length > 0 && value.length <= 1024, 'collector_text');
    return value;
  };
  const flag = (key: string): boolean => {
    requireProvision(typeof data[key] === 'boolean', 'collector_flag');
    return data[key];
  };
  const strings = (key: string): readonly string[] => {
    const value = data[key];
    requireProvision(Array.isArray(value) && value.length <= 32, 'collector_list');
    return value.map(item => {
      requireProvision(typeof item === 'string' && item.length <= 256, 'collector_list');
      return item;
    });
  };
  requireProvision(text('artifact_sha256') === binding.collectorSha256, 'collector_helper_changed');
  const runtime = text('runtime');
  requireProvision(runtime === 'runc', 'required_runtime_unavailable');
  requireProvision(flag('cpu_enforced') && flag('memory_enforced') && flag('pids_enforced'), 'enforcement_unconfirmed');
  const probe: IsolationProbe = {
    leaseId: binding.run, endpoint: binding.endpoint, daemonVersion: text('daemon_version'),
    runtimeVersion: text('runtime_version'), securityOptions: strings('security_options'),
    cgroup: { version: number('cgroup_version'), driver: text('cgroup_driver'),
      systemd: text('cgroup_driver') === 'systemd', delegatedUnit: text('delegated_unit'),
      controllers: strings('controllers') },
    measured: { leaseId: binding.run, endpoint: binding.endpoint, artifactSha256: text('artifact_sha256'),
      runtime, cpuQuota: number('cpu_quota'), cpuPeriod: number('cpu_period'),
      memoryMax: number('memory_max'), pidsMax: number('pids_max'), targetUid: number('target_uid'),
      seccompMode: number('seccomp_mode'), effectiveCaps: text('effective_caps'),
      seccompProfile: text('seccomp_profile'), capDropAll: flag('cap_drop_all'), hostMounts: number('host_mounts'),
      noNewPrivileges: flag('no_new_privileges'), readOnlyRootfs: flag('read_only_rootfs'),
      secretEnvironmentEmpty: flag('secret_environment_empty'), registryFetchSucceeded: flag('build_repository'),
      forbiddenBuildEgressBlocked: flag('build_denied'), externalRuntimeEgressBlocked: flag('runtime_denied'),
      cleanupConfirmed: flag('probe_cleanup_confirmed') },
  };
  const match = checkIsolationProbe('rootless-docker', { cpu: 2, memoryBytes: 2 * 1024 ** 3, pids: 256 }, probe);
  requireProvision(match.matches, 'isolation_unverified');
  return Object.freeze({ probe, cpuEnforced: true, memoryEnforced: true, pidsEnforced: true });
}
