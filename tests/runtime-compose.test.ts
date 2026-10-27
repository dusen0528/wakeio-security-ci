import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { observeOwnedGroup } from '../src/source/process.js';
import { runRuntimeProcess, type RuntimeProcessOptions } from '../src/runtime/process.js';
import { checkIsolationProbe, preflightIsolation, type IsolationProbe } from '../src/runtime/isolation.js';

async function withProfile(run: (options: RuntimeProcessOptions) => Promise<void>): Promise<void> {
  const home = await mkdtemp(join(tmpdir(), 'wakeio-runtime-owned-'));
  try { await run({ cwd: home, home, timeoutMs: 5_000, deadlineAt: Date.now() + 10_000,
    maxOutputBytes: 1024 }); } finally { await rm(home, { recursive: true, force: true }); }
}

test('runtime trusted child receives literal argv/stdin and no inherited secrets or proxy configuration', async () => {
  await withProfile(async options => {
    const names = ['WAKEIO_RUNTIME_SECRET_CANARY', 'AWS_SECRET_ACCESS_KEY', 'HTTP_PROXY',
      'DOCKER_HOST', 'NODE_OPTIONS'];
    const previous = names.map(name => process.env[name]);
    try {
      for (const name of names) process.env[name] = 'owned-synthetic-canary';
      const script = `let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
        console.log(JSON.stringify({args:process.argv.slice(1),input,keys:Object.keys(process.env),
          inheritedCanary:Object.values(process.env).includes('owned-synthetic-canary')}));});`;
      const result = await runRuntimeProcess(process.execPath, ['-e', script, '$(literal);*'],
        { ...options, input: 'bounded protocol input' });
      assert.equal(result.completed, true);
      assert.equal(result.cleanupConfirmed, true);
      const actual = JSON.parse(result.stdout);
      assert.deepEqual(actual.args, ['$(literal);*']);
      assert.equal(actual.input, 'bounded protocol input');
      // Darwin may add CoreFoundation locale metadata after spawn. Check the inheritance boundary directly.
      assert.deepEqual(names.filter(name => actual.keys.includes(name)), []);
      assert.equal(actual.inheritedCanary, false);
      assert.ok(['PATH', 'HOME', 'LC_ALL', 'LANG', 'TMPDIR'].every(name => actual.keys.includes(name)));
    } finally {
      names.forEach((name, index) => {
        if (previous[index] === undefined) delete process.env[name]; else process.env[name] = previous[index];
      });
    }
  });
});

test('runtime combined output byte cap terminates the owned child and rejects incomplete output', async () => {
  await withProfile(async options => {
    const result = await runRuntimeProcess(process.execPath,
      ['-e', 'process.stdout.write(Buffer.alloc(64));process.stderr.write(Buffer.alloc(8192));'
        + 'setInterval(()=>{},1000)'],
      { ...options, maxOutputBytes: 128 });
    assert.equal(result.completed, false);
    assert.equal(result.stopReason, 'output_limit');
    assert.equal(result.outputLimitExceeded, true);
    assert.ok(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) <= 128);
    assert.equal(result.cleanupConfirmed, true);
    const invalidUtf8 = await runRuntimeProcess(process.execPath,
      ['-e', 'process.stdout.write(Buffer.from([255]))'], { ...options, maxOutputBytes: 2 });
    assert.equal(invalidUtf8.outputLimitExceeded, true);
    assert.equal(invalidUtf8.completed, false);
    assert.equal(invalidUtf8.stdout, '');
  });
});

test('runtime deadline and pre-start cancellation cannot produce a completed result', async () => {
  await withProfile(async options => {
    const args = ['-e', 'setInterval(()=>{},1000)'];
    const result = await runRuntimeProcess(process.execPath, args, { ...options, deadlineAt: Date.now() + 100 });
    assert.equal(result.completed, false);
    assert.equal(result.stopReason, 'timeout');
    assert.equal(result.timedOut, true);
    assert.equal(result.cleanupConfirmed, true);
    const cancelled = await runRuntimeProcess(process.execPath, args, { ...options, signal: AbortSignal.abort() });
    assert.equal(cancelled.stopReason, 'cancelled');
    assert.equal(cancelled.cleanupState, 'not_started');
    const expired = await runRuntimeProcess(process.execPath, args, { ...options, deadlineAt: Date.now() - 1 });
    assert.equal(expired.cleanupState, 'not_started');
    assert.equal(expired.stopReason, 'timeout');
  });
});

async function readyPids(path: string): Promise<{ pid: number; descendant: number }> {
  const end = Date.now() + 3_000;
  while (Date.now() < end) {
    try {
      const result = JSON.parse(await readFile(path, 'utf8'));
      if (Number.isSafeInteger(result.pid) && result.pid > 0
        && Number.isSafeInteger(result.descendant) && result.descendant > 0) return result;
    } catch { /* The owned readiness file may not yet be complete. */ }
    await delay(20);
  }
  throw new Error('owned child did not become ready');
}

test('runtime abort confirms termination of its owned group including an inherited descendant', async () => {
  await withProfile(async options => {
    const controller = new AbortController(), path = join(options.home, 'ready');
    const script = `const {spawn}=require('node:child_process'),{writeFileSync}=require('node:fs');
      const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});
      writeFileSync(process.argv[1],JSON.stringify({pid:process.pid,descendant:child.pid}));
      setInterval(()=>{},1000);`;
    const pending = runRuntimeProcess(process.execPath, ['-e', script, path],
      { ...options, signal: controller.signal });
    const { pid, descendant } = await readyPids(path).catch(async error => {
      controller.abort(); await pending; throw error;
    });
    assert.notEqual(pid, descendant);
    controller.abort();
    const result = await pending;
    assert.equal(result.stopReason, 'cancelled');
    assert.equal(result.completed, false);
    assert.equal(result.closeConfirmed, true);
    assert.equal(result.cleanupConfirmed, true);
    assert.ok(['terminated', 'terminated_zombies'].includes(observeOwnedGroup(pid)));
  });
});

test('runtime rejects relative tools, malformed argv, input overflow and invalid budgets before spawn', async () => {
  await withProfile(async options => {
    for (const [executable, args, profile] of [
      ['node', [], options], [process.execPath, ['bad\0arg'], options],
      [process.execPath, [], { ...options, input: 'x'.repeat(65_537) }],
      [process.execPath, [], { ...options, maxOutputBytes: 0 }],
      [process.execPath, [], { ...options, timeoutMs: 600_001 }],
    ] as const) {
      const result = await runRuntimeProcess(executable, args, profile);
      assert.equal(result.stopReason, 'spawn_error');
      assert.equal(result.cleanupState, 'not_started');
      assert.equal(result.completed, false);
    }
  });
});

// Synthetic contract inputs only. These do not constitute a real Docker/cgroup/network measurement.
const limits = { cpu: 2, memoryBytes: 2 * 1024 ** 3, pids: 256 };
function syntheticProbe(): IsolationProbe {
  const endpoint = 'unix:///owned/docker.sock', leaseId = 'owned-test-lease';
  return { leaseId, endpoint, daemonVersion: 'test-daemon', runtimeVersion: 'test-runtime',
    securityOptions: ['name=rootless', 'name=seccomp,profile=builtin'],
    cgroup: { version: 2, driver: 'systemd', systemd: true,
      delegatedUnit: 'user@10001.service', controllers: ['cpu', 'memory', 'pids'] },
    measured: { leaseId, endpoint, artifactSha256: 'a'.repeat(64), runtime: 'runc',
      cpuQuota: 200_000, cpuPeriod: 100_000, memoryMax: limits.memoryBytes, pidsMax: limits.pids,
      targetUid: 65534, seccompMode: 2, seccompProfile: 'default', effectiveCaps: '0000000000000000', capDropAll: true,
      noNewPrivileges: true, readOnlyRootfs: true, hostMounts: 0, registryFetchSucceeded: true,
      forbiddenBuildEgressBlocked: true, externalRuntimeEgressBlocked: true,
      secretEnvironmentEmpty: true, cleanupConfirmed: true } };
}

test('isolation data consistency passes only complete matching probes; the actual backend remains unavailable', () => {
  assert.deepEqual(checkIsolationProbe('rootless-docker', limits, syntheticProbe()), { matches: true, reasons: [] });
  for (const requested of ['rootless-docker', 'gvisor'] as const) {
    assert.deepEqual(preflightIsolation(requested), { requested, applied: 'unavailable',
      verified: false, reasons: ['backend_unavailable'] });
    assert.equal(checkIsolationProbe(requested, limits, null).matches, false);
  }
  assert.equal(checkIsolationProbe('gvisor', limits, syntheticProbe()).matches, false);
  const gvisor = syntheticProbe(); gvisor.measured.runtime = 'runsc';
  assert.equal(checkIsolationProbe('gvisor', limits, gvisor).matches, true);
});

test('isolation refuses rootful, undelegated, null, unlimited, mismatched and unproven data', () => {
  const mutations: Array<(probe: IsolationProbe) => void> = [
    p => { p.securityOptions = ['name=rootless-fake']; }, p => { p.cgroup.version = 1; },
    p => { p.cgroup.driver = 'cgroupfs'; }, p => { p.cgroup.systemd = false; },
    p => { p.cgroup.delegatedUnit = null; }, p => { p.cgroup.controllers = ['cpu', 'memory']; },
    p => { p.measured.cpuQuota = null; }, p => { p.measured.cpuPeriod = null; },
    p => { p.measured.memoryMax = null; }, p => { p.measured.pidsMax = null; },
    p => { p.measured.memoryMax = limits.memoryBytes * 2; }, p => { p.measured.cpuQuota = 100_000; },
    p => { p.measured.pidsMax = 0; }, p => { p.measured.targetUid = 0; },
    p => { p.measured.seccompMode = 0; }, p => { p.measured.seccompProfile = 'unconfined'; },
    p => { p.measured.effectiveCaps = '0000000000000001'; }, p => { p.measured.capDropAll = false; },
    p => { p.measured.hostMounts = 1; },
    p => { p.measured.readOnlyRootfs = false; }, p => { p.measured.noNewPrivileges = false; },
    p => { p.measured.forbiddenBuildEgressBlocked = false; }, p => { p.measured.registryFetchSucceeded = false; },
    p => { p.measured.externalRuntimeEgressBlocked = false; }, p => { p.measured.secretEnvironmentEmpty = false; },
    p => { p.measured.cleanupConfirmed = false; }, p => { p.measured.artifactSha256 = ''; },
    p => { p.measured.leaseId = 'different'; }, p => { p.measured.endpoint = 'unix:///different'; },
  ];
  for (const mutate of mutations) {
    const probe = syntheticProbe(); mutate(probe);
    assert.equal(checkIsolationProbe('rootless-docker', limits, probe).matches, false);
  }
  assert.equal(checkIsolationProbe('rootless-docker', { ...limits, cpu: 3 }, syntheticProbe()).matches, false);
});
