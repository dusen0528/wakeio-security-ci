import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { observeOwnedGroup } from '../src/source/process.js';
import { runRuntimeProcess, type RuntimeProcessOptions } from '../src/runtime/process.js';
import { checkIsolationProbe, preflightIsolation, type IsolationProbe } from '../src/runtime/isolation.js';
import { normaliseCompose } from '../src/runtime/builders/compose-input.js';
import { normaliseMavenRequest } from '../src/runtime/builders/build-policy.js';
import type { TargetSpec } from '../src/runtime/types.js';
import { parseTargetSpec } from '../src/runtime/target.js';

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

test('fractional CPU compares integer quota without accepting ignored or mismatched limits', () => {
  const probe = syntheticProbe(), fractional = { ...limits, cpu: 0.3 };
  probe.measured.cpuQuota = 30_000;
  assert.equal(checkIsolationProbe('rootless-docker', fractional, probe).matches, true);
  for (const quota of [29_999, 30_001, 0, -1, null, Infinity]) {
    probe.measured.cpuQuota = quota;
    assert.equal(checkIsolationProbe('rootless-docker', fractional, probe).matches, false);
  }
});

const composeSpec: TargetSpec = {
  version: 1, project: 'owned-compose-data', source: '.',
  build: { kind: 'compose', file: 'infra/compose.json', service: 'app' }, pack: { id: 'spring-boot', version: 1 },
  entry: { port: 8080, health: '/health', startupTimeoutSec: 180 },
  dependencies: [{ service: 'db', observer: 'pg-log' }], seed: { sql: ['seed.sql'], snapshot: 'per-request' },
  scope: { include: ['/api/**'], exclude: [] }, budget: { maxRequests: 20, maxMinutes: 15, ratePerSecond: 1 },
};
const declaredPg = 'postgres@sha256:' + 'a'.repeat(64); // Synthetic declaration, never a measured image pin.
function composeData() {
  return { services: {
    app: { build: { context: './app', dockerfile: 'Dockerfile' }, command: ['java', '-jar', 'app.jar'],
      depends_on: ['db'], environment: { SPRING_DATASOURCE_URL: 'wakeio:postgres.url' } },
    db: { image: declaredPg },
  } };
}

test('compose preserves approved relations without producing an executable manifest or trusted PG pin', () => {
  const raw = composeData(), before = JSON.stringify(raw), result = normaliseCompose(raw, composeSpec);
  assert.equal(JSON.stringify(raw), before);
  assert.equal(result.executable, false);
  assert.equal(result.app.build.context, 'infra/app');
  assert.equal(result.app.dependency, 'db');
  assert.equal(result.app.build.dockerfile, 'Dockerfile');
  assert.deepEqual(result.app.environment, [{ name: 'SPRING_DATASOURCE_URL', dependency: 'db', field: 'url' }]);
  assert.equal(result.postgres.imagePin, 'required-from-trusted-builder');
  assert.equal(result.postgres.config, 'trusted-builder-only');
  assert.deepEqual(result.hostPorts, []);
  assert.equal(result.inheritEnvironment, false);
  assert.ok(result.requires.includes('verified-isolation'));
  raw.services.app.command[0] = 'mutated';
  assert.equal(result.app.command![0], 'java');
});

test('compose agrees with Target service dots and 64-character limit and rejects option-like path segments', () => {
  for (const name of ['api.v1', 'a'.repeat(64)]) {
    const spec = parseTargetSpec({ ...composeSpec, build: { ...composeSpec.build, service: name } });
    const raw = composeData();
    const input = { services: { [name]: raw.services.app, db: raw.services.db } };
    assert.equal(normaliseCompose(input, spec).app.service, name);
  }
  assert.throws(() => parseTargetSpec({ ...composeSpec, build: { ...composeSpec.build, service: 'a'.repeat(65) } }));
  for (const field of ['context', 'dockerfile'] as const) {
    for (const path of ['-x', '--file=/etc/passwd', 'safe/-x', 'safe/--file=/etc/passwd']) {
      const raw = composeData(); raw.services.app.build[field] = path;
      assert.throws(() => normaliseCompose(raw, composeSpec), /invalid_runtime_compose/);
    }
  }
});

test('compose rejects every unsupported authority key, including dangerous false or empty options', () => {
  const serviceKeys = ['privileged', 'cap_add', 'devices', 'volumes', 'volumes_from', 'network_mode', 'networks',
    'pid', 'ipc', 'userns_mode', 'extends', 'security_opt', 'use_api_socket', 'hooks', 'post_start', 'pre_stop',
    'healthcheck', 'ports', 'env_file', 'secrets', 'configs', 'extra_hosts', 'runtime', 'user', 'image'];
  for (const key of serviceKeys) {
    const raw = composeData(); Object.assign(raw.services.app, { [key]: false });
    assert.throws(() => normaliseCompose(raw, composeSpec), /invalid_runtime_compose/, key);
  }
  for (const key of ['volumes', 'networks', 'include', 'extends', 'secrets', 'configs', 'x-wakeio-draft', '<<']) {
    assert.throws(() => normaliseCompose({ ...composeData(), [key]: {} }, composeSpec), /invalid_runtime_compose/);
  }
  for (const key of ['secrets', 'ssh', 'additional_contexts', 'network', 'entitlements', 'args', 'dockerfile_inline']) {
    const raw = composeData(); Object.assign(raw.services.app.build, { [key]: [] });
    assert.throws(() => normaliseCompose(raw, composeSpec), /invalid_runtime_compose/);
  }
});

test('compose rejects remote paths, env inheritance/interpolation, shell strings and unmeasured images', () => {
  for (const context of ['../app', '/tmp/app', 'C:\\app', 'https://repo/app', 'git@repo:app', 'app//src',
    'app/./src', '%2e%2e', '${CONTEXT}', '$CONTEXT']) {
    const raw = composeData(); raw.services.app.build.context = context;
    assert.throws(() => normaliseCompose(raw, composeSpec), /invalid_runtime_compose/);
  }
  for (const patch of [
    { command: 'java -jar app.jar' }, { command: ['java', '${FLAGS}'] }, { entrypoint: 'sh -c app' },
    { environment: ['SPRING_DATASOURCE_PASSWORD'] }, { environment: { SPRING_DATASOURCE_PASSWORD: null } },
    { environment: { SPRING_DATASOURCE_PASSWORD: 'raw-credential' } }, { environment: { HTTP_PROXY: 'host' } },
    { depends_on: ['unapproved'] },
  ]) {
    const raw = composeData(); Object.assign(raw.services.app, patch);
    assert.throws(() => normaliseCompose(raw, composeSpec), /invalid_runtime_compose/);
  }
  for (const image of [null, '', 'postgres:18', 'postgres:latest', 'remote/image@sha256:' + 'a'.repeat(64)]) {
    const raw = composeData(); Object.assign(raw.services.db, { image });
    assert.throws(() => normaliseCompose(raw, composeSpec), /invalid_runtime_compose/);
  }
  const config = composeData(); Object.assign(config.services.db, { environment: { POSTGRES_USER: 'admin' } });
  assert.throws(() => normaliseCompose(config, composeSpec), /invalid_runtime_compose/);
});

test('compose rejects getters/proxy traps, prototypes, cycles and unapproved service relations', () => {
  let calls = 0;
  const getter = Object.defineProperty({}, 'services', { enumerable: true, get() { calls++; return {}; } });
  const proxy = new Proxy({}, { ownKeys() { calls++; return []; } });
  const cycle: Record<string, unknown> = {}; cycle.services = cycle;
  for (const raw of [getter, proxy, cycle, Object.create({ services: {} }), 'services: {}']) {
    assert.throws(() => normaliseCompose(raw, composeSpec));
  }
  const maliciousSpec = Object.defineProperty({ ...composeSpec }, 'build', {
    enumerable: true, get() { calls++; return composeSpec.build; },
  });
  assert.throws(() => normaliseCompose(composeData(), maliciousSpec));
  assert.equal(calls, 0);
  const extra = composeData(); Object.assign(extra.services, { other: {} });
  assert.throws(() => normaliseCompose(extra, composeSpec), /invalid_runtime_compose/);
  assert.throws(() => normaliseCompose(composeData(), { ...composeSpec, dependencies: [] }), /invalid_runtime_compose/);
});

function mavenRequest(path = '/maven2/org/example/app/1.0/app-1.0.pom') {
  return { method: 'GET', scheme: 'https', host: 'repo.maven.apache.org', port: 443,
    hostHeader: 'repo.maven.apache.org:443', path };
}
test('Maven policy admits only canonical coordinate/metadata GET or HEAD without claiming network enforcement', () => {
  for (const path of [
    '/maven2/org/example/app/1.0/app-1.0.pom', '/maven2/org/example/app/1.0/app-1.0-sources.jar.sha256',
    '/maven2/org/example/app/1.0/app-1.0.jar.asc', '/maven2/org/example/app/maven-metadata.xml',
    '/maven2/org/example/app/1.0-SNAPSHOT/maven-metadata.xml.sha1',
    '/maven2/org/example/app/1.0-SNAPSHOT/app-1.0-20261028.010203-1.jar',
    '/maven2/org/apache/maven/apache-maven/3.10.0/apache-maven-3.10.0-bin.tar.gz',
  ]) {
    const raw = mavenRequest(path), before = JSON.stringify(raw);
    const result = normaliseMavenRequest(raw);
    assert.equal(result.path, path); assert.equal(result.egressEnforced, false);
    assert.equal(JSON.stringify(raw), before);
  }
  assert.equal(normaliseMavenRequest({ ...mavenRequest(), method: 'HEAD' }).method, 'HEAD');
});

test('Maven policy rejects methods, authority smuggling, noncanonical paths, extra data and executable objects', () => {
  for (const patch of [
    { method: 'CONNECT' }, { method: 'POST' }, { method: 'PUT' }, { method: 'get' }, { scheme: 'http' },
    { port: 80 }, { host: 'repo.maven.apache.org.evil' }, { host: '127.0.0.1' },
    { hostHeader: 'attacker' }, { hostHeader: ['repo.maven.apache.org', 'attacker'] }, { body: 'upload' },
  ]) assert.throws(() => normaliseMavenRequest({ ...mavenRequest(), ...patch }), /invalid_maven_repository_request/);
  for (const path of [
    '/maven2/../secret', '/maven2/a/%2e%2e/x', '/maven2//org/example/a/1/a-1.jar',
    '/maven2/org/example/a/1/a-1.jar?token=x', '/maven2/org/example/a/1/a-1.jar#x',
    '/maven2/org/example/a/1/a-1%2ejar', '/maven2/org/example/a/1/other-1.jar',
    '/maven2/org/example/a/1/a-1.sh', '/maven2/org.example/a/1/a-1.jar',
    'https://repo.maven.apache.org/maven2/org/example/a/1/a-1.jar',
  ]) assert.throws(() => normaliseMavenRequest(mavenRequest(path)), /invalid_maven_repository_request/);
  let calls = 0;
  const getter = Object.defineProperty(mavenRequest(), 'host', { get() { calls++; return 'repo.maven.apache.org'; } });
  assert.throws(() => normaliseMavenRequest(getter));
  assert.throws(() => normaliseMavenRequest(new Proxy(mavenRequest(), { get() { calls++; return 'x'; } })));
  assert.equal(calls, 0);
});
