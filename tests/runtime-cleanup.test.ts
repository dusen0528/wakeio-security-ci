import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdtemp, mkdir, readFile, readdir, realpath, rename, rm, symlink, truncate, writeFile }
  from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { runRuntimeProcess } from '../src/runtime/process.js';
import { compileLimaProfileConfig, createLimaProfilePreparer, prepareLimaProfile,
  createLimaOsPreparer, MAX_LIMA_ROOTFS_BYTES, prepareLimaOsProfile,
  type LimaOsOptions, type LimaPins, type LimaProfileOptions }
  from '../src/runtime/runtimes/controller.js';

// Deliberately synthetic metadata. A mock tool never downloads, starts or validates these assets.
const pins: LimaPins = {
  rootfs: { url: 'https://cloud-images.ubuntu.com/releases/noble/release-20261017/'
    + 'ubuntu-24.04-server-cloudimg-arm64.img', arch: 'aarch64', sha256: 'a'.repeat(64) },
  dockerExtras: { version: '5:29.9.2-1~ubuntu.24.04~noble', sha256: 'b'.repeat(64),
    url: 'https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/arm64/'
      + 'docker-ce-rootless-extras_29.9.2-1~ubuntu.24.04~noble_arm64.deb' },
};
async function scope(run: (base: string) => Promise<void>): Promise<void> {
  const base = await mkdtemp(join(await realpath('/tmp'), 'wk-ctl-'));
  try { await run(base); } finally { await rm(base, { recursive: true, force: true }); }
}
async function mockTool(base: string, mode = ''): Promise<LimaProfileOptions> {
  const executable = join(base, 'mock-limactl');
  await writeFile(executable, `#!/usr/bin/env node
const fs=require('node:fs'),p=require('node:path');
const home=process.env.HOME,a=process.argv.slice(2).filter(x=>x!=='--tty=false'),mode=${JSON.stringify(mode)};
if(process.env.LIMA_HOME||process.env.SSH_AUTH_SOCK||process.env.DOCKER_HOST)process.exit(91);
fs.appendFileSync(p.join(home,'calls.ndjson'),JSON.stringify(a)+String.fromCharCode(10));
if(a[0]==='--version'){console.log('limactl version 1.0.3');process.exit(0);}
if(a[0]==='create'){
 const name=a.find(x=>x.startsWith('--name=')).slice(7),dir=p.join(home,'.lima',name);
 fs.mkdirSync(dir,{mode:0o700});fs.copyFileSync(a.at(-1),p.join(dir,'lima.yaml'));
 fs.writeFileSync(p.join(dir,'state.json'),JSON.stringify({name,dir,status:'Stopped',protected:false}));
 if(mode==='hang-create'){setInterval(()=>{},1000);}else process.exit(0);
}else if(a[0]==='list'){
 console.log(fs.readFileSync(p.join(home,'.lima',a.at(-1),'state.json'),'utf8'));
}else if(a[0]==='delete'){
 if(fs.existsSync(p.join(home,'fail-delete')))process.exit(2);
 fs.rmSync(p.join(home,'.lima',a.at(-1)),{recursive:true});
}else process.exit(3);
`, { mode: 0o700 });
  return { executeTargetConsent: true, baseDirectory: base, limactlExecutable: executable,
    pins, deadlineAt: Date.now() + 10_000 };
}
async function calls(home: string): Promise<string[][]> {
  return (await readFile(join(home, 'calls.ndjson'), 'utf8')).trim().split('\n').map(line => JSON.parse(line));
}

test('Lima consent guard reads no other inputs, creates nothing and invokes no proxy/getter hooks', async () => {
  await scope(async base => {
    let reads = 0;
    const raw = Object.defineProperty({ executeTargetConsent: false }, 'baseDirectory', {
      get() { reads++; throw new Error('must not read'); },
    });
    const proxy = new Proxy({}, { get() { reads++; throw new Error('must not read'); } });
    for (const value of [raw, proxy, null, {}]) {
      const result = await prepareLimaProfile(value as LimaProfileOptions);
      assert.equal(result.reason, 'consent_required'); assert.equal(result.verified, false);
    }
    assert.equal(reads, 0); assert.deepEqual(await readdir(base), []);
  });
});

test('compiled Lima config is isolated, pinned and explicitly fails before incomplete bootstrap or target work', () => {
  const c = JSON.parse(compileLimaProfileConfig(pins));
  assert.deepEqual(c.mounts, []); assert.deepEqual(c.additionalDisks, []); assert.deepEqual(c.networks, []);
  assert.equal(c.cpus, 2); assert.equal(c.memory, '4GiB'); assert.equal(c.disk, '20GiB');
  assert.equal(c.ssh.forwardAgent, false); assert.equal(c.ssh.loadDotSSHPubKeys, false);
  assert.equal(c.propagateProxyEnv, false); assert.equal(c.hostResolver.enabled, false);
  assert.equal(c.images.length, 1); assert.equal(c.images[0].digest, 'sha256:' + pins.rootfs.sha256);
  assert.equal(c.param.dockerExtrasSha256, pins.dockerExtras.sha256);
  assert.equal(c.param.rootlessSocket, '/run/user/10001/docker.sock');
  assert.equal(c.portForwards[1].ignore, true); assert.equal(c.portForwards[1].proto, 'any');
  assert.match(c.message, /SSH22/);
  const boot: string = c.provision[0].script;
  for (const required of ['host\\.lima', '10001', 'Delegate=cpu cpuset io memory pids', '65536',
    'CPUQuota=200%', 'MemoryMax=2G', 'TasksMax=256', 'wakeio_missing_prerequisite', 'exit 125']) {
    assert.ok(boot.includes(required), required);
  }
  assert.ok(boot.endsWith('loginctl enable-linger wakeio-m1\n'
    + 'echo "wakeio_missing_prerequisite: verified packages, daemon relay, nft/proxy and probes" >&2\nexit 125\n'));
  assert.doesNotMatch(boot, /docker run|docker start|curl.*\|.*sh/);
  assert.throws(() => compileLimaProfileConfig({ ...pins, rootfs: { ...pins.rootfs, sha256: '' } }));
  assert.throws(() => compileLimaProfileConfig({ ...pins, rootfs: { ...pins.rootfs, url: 'https://attacker/image' } }));
});

test('private profile preparation binds identity and exact create/list argv; cleanup is idempotent', async () => {
  await scope(async base => {
    const options = await mockTool(base), existing = join(base, 'existing');
    await mkdir(existing); await writeFile(join(existing, 'keep'), 'owned existing instance marker');
    const before = await readdir(base);
    const result = await prepareLimaProfile(options); assert.ok(result.lease);
    const lease = result.lease;
    try {
      assert.equal(result.status, 'unavailable'); assert.equal(result.verified, false);
      assert.equal(result.reason, 'missing_prerequisite'); assert.ok(result.missingPrerequisites.length > 0);
      assert.notEqual(lease.home, process.env.HOME);
      assert.equal((await lstat(lease.home)).mode & 0o777, 0o700);
      assert.equal((await lstat(join(lease.home, 'profile.yaml'))).mode & 0o777, 0o600);
      const id = await lstat(lease.directory); assert.equal(id.ino, lease.profileIdentity.ino);
      const history = await calls(lease.home), create = history.find(args => args[0] === 'create')!;
      assert.deepEqual(create.slice(0, 5), ['create', '--name=' + lease.name, '--cpus=2', '--memory=4', '--disk=20']);
      assert.equal(create[5], join(lease.home, 'profile.yaml'));
      assert.equal(history.some(args => ['start', 'shell', 'prune', 'stop'].includes(args[0])), false);
      assert.equal(Reflect.set(lease, 'name', 'existing-profile'), false);
    } finally { assert.equal((await lease.cleanup()).confirmed, true); }
    assert.equal((await lease.cleanup()).confirmed, true);
    assert.deepEqual(await readdir(base), before);
    assert.equal(await readFile(join(existing, 'keep'), 'utf8'), 'owned existing instance marker');
  });
});

test('replacement profile identity and a running VM are refused without stop/delete authority', async () => {
  await scope(async base => {
    const first = await prepareLimaProfile(await mockTool(base)); assert.ok(first.lease);
    const lease = first.lease;
    await rename(lease.directory, lease.directory + '-old'); await mkdir(lease.directory, { mode: 0o700 });
    assert.equal((await lease.cleanup()).confirmed, false);
    assert.equal((await calls(lease.home)).some(args => args[0] === 'delete'), false);
    const second = await prepareLimaProfile(await mockTool(base)); assert.ok(second.lease);
    const active = second.lease;
    await writeFile(join(active.directory, 'state.json'), JSON.stringify({ name: active.name,
      dir: active.directory, status: 'Running', hostAgentPID: 123, driverPID: 124 }));
    assert.equal((await active.cleanup()).confirmed, false);
    assert.equal((await calls(active.home)).some(args => ['delete', 'stop'].includes(args[0])), false);
  });
});

test('failed deletion retains the owned lease for retry and cannot report confirmed cleanup', async () => {
  await scope(async base => {
    const result = await prepareLimaProfile(await mockTool(base)); assert.ok(result.lease);
    const lease = result.lease; await writeFile(join(lease.home, 'fail-delete'), 'owned failure');
    assert.equal((await lease.cleanup()).confirmed, false);
    assert.ok((await lstat(lease.directory)).isDirectory());
    await rm(join(lease.home, 'fail-delete'));
    assert.equal((await lease.cleanup()).confirmed, true);
  });
});

test('an unconfirmed tool group stays unconfirmed after a later successful owned mock command', async () => {
  await scope(async base => {
    const observed: { command: string; completed: boolean; cleanupConfirmed: boolean | undefined }[] = [];
    const prepare = createLimaProfilePreparer(async (executable, args, options) => {
      const result = await runRuntimeProcess(executable, args, options);
      assert.equal(result.completed, true); assert.equal(result.cleanupConfirmed, true);
      const reported = { ...result, cleanupConfirmed: args.includes('--version') ? false : true };
      observed.push({ command: args[1], completed: reported.completed, cleanupConfirmed: reported.cleanupConfirmed });
      return reported; // Only synthetic supervision metadata changes; the owned Node tool really terminated.
    });
    const result = await prepare(await mockTool(base));
    assert.deepEqual(observed, [
      { command: '--version', completed: true, cleanupConfirmed: false },
      { command: 'create', completed: true, cleanupConfirmed: true },
    ]);
    assert.equal(result.status, 'unavailable'); assert.equal(result.verified, false);
    assert.equal(result.reason, 'prepare_failed'); assert.equal(result.cleanup?.confirmed, false);
    assert.equal(result.lease, undefined); assert.ok(result.pendingHome);
    assert.ok((await lstat(result.pendingHome)).isDirectory());
    assert.deepEqual((await calls(result.pendingHome)).map(args => args[0]), ['--version', 'create']);
  });
});

test('unconfirmed deletion supervision cannot remove HOME or become confirmed on cleanup retry', async () => {
  await scope(async base => {
    const prepare = createLimaProfilePreparer(async (executable, args, options) => {
      const result = await runRuntimeProcess(executable, args, options);
      return args.includes('delete') ? { ...result, cleanupConfirmed: false } : result;
    });
    const result = await prepare(await mockTool(base)); assert.ok(result.lease);
    assert.equal(result.verified, false);
    assert.equal((await result.lease.cleanup()).confirmed, false);
    assert.ok((await lstat(result.lease.home)).isDirectory());
    const before = await calls(result.lease.home);
    assert.equal((await result.lease.cleanup()).confirmed, false);
    assert.deepEqual(await calls(result.lease.home), before);
  });
});

test('the internal executor seam preserves consent zero-I/O and cannot enter through raw options', async () => {
  await scope(async base => {
    let invoked = 0;
    const execute: typeof runRuntimeProcess = async () => { invoked++; throw new Error('must not execute'); };
    const prepare = createLimaProfilePreparer(execute);
    const denied = await prepare({ executeTargetConsent: false } as unknown as LimaProfileOptions);
    assert.equal(denied.reason, 'consent_required'); assert.equal(denied.verified, false);
    const options = await mockTool(base), before = await readdir(base);
    const malformed = await prepareLimaProfile({ ...options, execute } as LimaProfileOptions);
    assert.equal(malformed.reason, 'prepare_failed'); assert.equal(malformed.lease, undefined);
    assert.equal(invoked, 0); assert.deepEqual(await readdir(base), before);
  });
});

test('a HOME that loses private permissions cannot authorize profile deletion', async () => {
  await scope(async base => {
    const result = await prepareLimaProfile(await mockTool(base)); assert.ok(result.lease);
    const lease = result.lease; await chmod(lease.home, 0o755);
    assert.equal((await lease.cleanup()).confirmed, false);
    await chmod(lease.home, 0o700);
    assert.equal((await lease.cleanup()).confirmed, true);
  });
});

async function createdHome(base: string): Promise<string> {
  const end = Date.now() + 3_000;
  while (Date.now() < end) {
    for (const entry of await readdir(base)) {
      if (!entry.startsWith('wk-lima-')) continue;
      const home = join(base, entry);
      try {
        const name = (await readdir(join(home, '.lima'))).find(name => name.startsWith('wk-'));
        if (name && (await lstat(join(home, '.lima', name, 'state.json'))).isFile()) return home;
      } catch { /* The owned mock profile is not yet complete. */ }
    }
    await delay(20);
  }
  throw new Error('owned mock create did not become ready');
}
test('aborted create confirms its process group before separate bounded cleanup of the stopped profile', async () => {
  await scope(async base => {
    const config = await mockTool(base, 'hang-create'), controller = new AbortController();
    const pending = prepareLimaProfile({ ...config, signal: controller.signal });
    await createdHome(base).catch(async error => { controller.abort(); await pending; throw error; });
    controller.abort();
    const result = await pending;
    assert.equal(result.verified, false); assert.equal(result.reason, 'prepare_failed');
    assert.equal(result.cleanup?.confirmed, true);
    assert.equal((await readdir(base)).some(name => name.startsWith('wk-lima-')), false);
  });
});

test('missing pins and pre-aborted operation create no profiles or invoke the trusted mock tool', async () => {
  await scope(async base => {
    const options = await mockTool(base), before = await readdir(base);
    const missing = await prepareLimaProfile({ ...options, pins: null as unknown as LimaPins });
    assert.equal(missing.status, 'unavailable'); assert.equal(missing.lease, undefined);
    const cancelled = await prepareLimaProfile({ ...options, signal: AbortSignal.abort() });
    assert.equal(cancelled.status, 'unavailable'); assert.equal(cancelled.lease, undefined);
    const outside = await prepareLimaProfile({ ...options, baseDirectory: '/' });
    assert.equal(outside.status, 'unavailable'); assert.equal(outside.lease, undefined);
    assert.deepEqual(await readdir(base), before);
  });
});

test('overlong Unix sockets are rejected before tool invocation and the private HOME is removed', async () => {
  await scope(async base => {
    const options = await mockTool(base), longBase = join(base, 'long-'.repeat(18));
    await mkdir(longBase, { mode: 0o700 });
    const result = await prepareLimaProfile({ ...options, baseDirectory: longBase });
    assert.equal(result.status, 'unavailable'); assert.equal(result.lease, undefined);
    assert.equal(result.cleanup?.confirmed, true);
    assert.deepEqual(await readdir(longBase), []);
  });
});

const osBytes = Buffer.from('fixed synthetic OS bytes; not a bootable image');
const machineBytes = 'synthetic VZ GenericMachineIdentifier data';
async function osMockTool(base: string, mode = ''): Promise<LimaOsOptions> {
  const executable = join(base, 'mock-os-limactl'), rootfsFile = join(base, 'input.img');
  await writeFile(rootfsFile, osBytes, { mode: 0o600 });
  await writeFile(executable, `#!/usr/bin/env node
const fs=require('node:fs'),p=require('node:path');
const home=process.env.HOME,a=process.argv.slice(2).filter(x=>x!=='--tty=false'),mode=${JSON.stringify(mode)};
if(process.env.LIMA_HOME||process.env.SSH_AUTH_SOCK||process.env.DOCKER_HOST||process.cwd()!==home)process.exit(91);
fs.appendFileSync(p.join(home,'calls.ndjson'),JSON.stringify(a)+String.fromCharCode(10));
if(a[0]==='--version'){console.log('limactl version 1.0.3');process.exit(0);}
const name=a[0]==='create'?a.find(x=>x.startsWith('--name=')).slice(7):a.at(-1),dir=p.join(home,'.lima',name);
const stateFile=p.join(dir,'state.json');
function state(status,pid=0){fs.writeFileSync(stateFile,JSON.stringify({name,dir,status,protected:false,
 vmType:'vz',arch:'aarch64',limaVersion:'1.0.3',hostAgentPID:pid,driverPID:pid}));}
if(a[0]==='create'){
 fs.mkdirSync(dir,{mode:0o700});fs.copyFileSync(a.at(-1),p.join(dir,'lima.yaml'));
 if(mode!=='missing-machine')fs.writeFileSync(p.join(dir,'vz-identifier'),${JSON.stringify(machineBytes)},{mode:0o600});
 state('Stopped');
}else if(a[0]==='list'){
 console.log(fs.readFileSync(stateFile,'utf8'));
}else if(a[0]==='start'){
 if(!a.includes('--foreground')||!a.includes('--timeout=30s'))process.exit(92);
 fs.writeFileSync(p.join(home,'boot.started'),'owned mock foreground child');
 if(mode==='exit-start'){state('Stopped');process.exit(2);}
 if(mode!=='hang-start')state('Running',process.pid);
 process.on('SIGTERM',()=>{state(mode==='reused-pid'?'Running':'Stopped',mode==='reused-pid'?process.ppid:0);
  process.exit(0);});setInterval(()=>{},1000);
}else if(a[0]==='delete'){
 if(fs.existsSync(p.join(home,'fail-delete')))process.exit(2);
 fs.rmSync(dir,{recursive:true});
}else process.exit(3);
`, { mode: 0o700 });
  return { executeTargetConsent: true, baseDirectory: base, limactlExecutable: executable, rootfsFile,
    pins: { ...pins, rootfs: { ...pins.rootfs, sha256: createHash('sha256').update(osBytes).digest('hex') } },
    deadlineAt: Date.now() + 15_000 };
}
async function waitForOwnedFile(base: string, filename: string, nonempty = false): Promise<string> {
  const deadline = Date.now() + 3_000;
  while (Date.now() < deadline) {
    for (const name of await readdir(base)) {
      if (!name.startsWith('wk-lima-')) continue;
      const file = join(base, name, filename);
      try { if (!nonempty || (await lstat(file)).size > 0) { await lstat(file); return file; } }
      catch { /* Owned asynchronous mock/copy has not yet reached the requested barrier. */ }
    }
    await delay(1);
  }
  throw new Error('owned OS operation did not reach file barrier');
}

test('OS preparation checks consent before reading rootfs path, filesystem or trusted executor', async () => {
  await scope(async base => {
    let accessed = 0;
    const prepare = createLimaOsPreparer(async () => { accessed++; throw new Error('must not run'); });
    const raw = Object.defineProperty({ executeTargetConsent: false }, 'rootfsFile', {
      get() { accessed++; throw new Error('must not read'); },
    });
    const proxy = new Proxy({}, { ownKeys() { accessed++; throw new Error('must not enumerate'); } });
    for (const value of [raw, proxy, {}, null]) {
      const result = await prepare(value as LimaOsOptions);
      assert.equal(result.reason, 'consent_required'); assert.equal(result.verified, false);
    }
    assert.equal(accessed, 0); assert.deepEqual(await readdir(base), []);
  });
});

test('synthetic bytes bind private OS config and VZ identity; foreground boot stops before cleanup', async () => {
  await scope(async base => {
    const options = await osMockTool(base), result = await prepareLimaOsProfile(options); assert.ok(result.lease);
    const lease = result.lease, config = JSON.parse(await readFile(join(lease.home, 'profile.yaml'), 'utf8'));
    assert.equal(result.status, 'unavailable'); assert.equal(result.verified, false);
    assert.ok(result.missingPrerequisites.includes('docker-extras-byte-verification'));
    assert.deepEqual(await readFile(join(lease.home, 'rootfs.img')), osBytes);
    assert.equal(config.images[0].location, join(lease.home, 'rootfs.img'));
    assert.equal(config.images[0].digest, 'sha256:' + options.pins.rootfs.sha256);
    assert.equal(lease.machineIdentitySha256, createHash('sha256').update(machineBytes).digest('hex'));
    assert.deepEqual(config.mounts, []); assert.deepEqual(config.copyToHost, []);
    assert.equal(config.upgradePackages, false); assert.equal(config.hostResolver.enabled, false);
    assert.equal(config.ssh.forwardAgent, false); assert.equal(config.propagateProxyEnv, false);
    assert.equal(config.portForwards[1].ignore, true);
    assert.doesNotMatch(config.provision[0].script, /wakeio_missing_prerequisite|^exit 125$|docker run|apt-get|curl/m);
    assert.match(config.provision[0].script, /cgroup2fs \|\| exit 125/);
    assert.match(config.provision[0].script, /host\\.lima/);
    const osScript: string = config.provision[0].script;
    assert.ok(osScript.endsWith('loginctl enable-linger wakeio-m1\n'));
    const stoppedScript: string = JSON.parse(compileLimaProfileConfig(pins)).provision[0].script;
    assert.equal(stoppedScript, osScript
      + 'echo "wakeio_missing_prerequisite: verified packages, daemon relay, nft/proxy and probes" >&2\nexit 125\n');
    const boot = await lease.boot();
    assert.deepEqual(boot, { status: 'unavailable', verified: false, phase: 'running_observed_then_stopped' });
    assert.equal((await calls(lease.home)).some(args => args[0] === 'stop'), false);
    assert.equal((await lease.cleanup()).confirmed, true);
    assert.deepEqual(await readFile(options.rootfsFile), osBytes);
  });
});

test('wrong rootfs hash, oversize, symlink, hardlink and linked ancestor invoke zero OS tools', async () => {
  await scope(async base => {
    const options = await osMockTool(base); let invoked = 0;
    const prepare = createLimaOsPreparer(async (...args) => { invoked++; return runRuntimeProcess(...args); });
    const hash = await prepare({ ...options, pins });
    assert.equal(hash.reason, 'prepare_failed'); assert.equal(hash.cleanup?.confirmed, true);
    const large = join(base, 'oversize.img'); await writeFile(large, '', { mode: 0o600 });
    await truncate(large, MAX_LIMA_ROOTFS_BYTES + 1);
    const hard = join(base, 'hard.img'), soft = join(base, 'soft.img'), parent = join(base, 'linked-parent');
    await link(options.rootfsFile, hard); await symlink(options.rootfsFile, soft); await symlink(base, parent);
    for (const rootfsFile of [large, hard, soft, join(parent, 'input.img')]) {
      const result = await prepare({ ...options, rootfsFile });
      assert.equal(result.reason, 'prepare_failed'); assert.equal(result.lease, undefined);
      assert.equal(result.cleanup?.confirmed, true);
    }
    assert.equal(invoked, 0);
    assert.equal((await readdir(base)).some(name => name.startsWith('wk-lima-')), false);
    assert.deepEqual(await readFile(options.rootfsFile), osBytes);
  });
});

test('mid-stream abort closes owned files, removes the partial private copy and invokes no tool', async () => {
  await scope(async base => {
    const options = await osMockTool(base), bytes = Buffer.alloc(16 * 1024 * 1024, 0x41);
    await writeFile(options.rootfsFile, bytes);
    options.pins.rootfs.sha256 = createHash('sha256').update(bytes).digest('hex');
    const controller = new AbortController(); let invoked = 0;
    const prepare = createLimaOsPreparer(async (...args) => { invoked++; return runRuntimeProcess(...args); });
    const pending = prepare({ ...options, signal: controller.signal });
    await waitForOwnedFile(base, 'rootfs.img', true).catch(async error => {
      controller.abort(); await pending; throw error;
    });
    controller.abort(); const result = await pending;
    assert.equal(result.reason, 'prepare_failed'); assert.equal(result.cleanup?.confirmed, true);
    assert.equal(invoked, 0); assert.equal((await lstat(options.rootfsFile)).size, bytes.length);
    assert.equal((await readdir(base)).some(name => name.startsWith('wk-lima-')), false);
  });
});

test('a rootfs replacement after hashing is retained and cannot authorize create or cleanup', async () => {
  await scope(async base => {
    const options = await osMockTool(base); let invoked = 0;
    const prepare = createLimaOsPreparer(async (executable, args, config) => {
      invoked++;
      const image = join(config.home, 'rootfs.img');
      await rename(image, image + '-original'); await writeFile(image, 'foreign replacement', { mode: 0o600 });
      return runRuntimeProcess(executable, args, config);
    });
    const result = await prepare(options);
    assert.equal(invoked, 1); assert.equal(result.reason, 'prepare_failed');
    assert.equal(result.cleanup?.confirmed, false); assert.ok(result.pendingHome);
    assert.equal(await readFile(join(result.pendingHome, 'rootfs.img'), 'utf8'), 'foreign replacement');
    assert.deepEqual((await calls(result.pendingHome)).map(args => args[0]), ['--version']);
  });
});

test('config, machine ID and rootfs hardlink drift refuse boot and preserve the unknown HOME', async () => {
  for (const name of ['profile.yaml', 'vz-identifier', 'rootfs-hardlink']) {
    await scope(async base => {
      const options = await osMockTool(base), result = await prepareLimaOsProfile(options); assert.ok(result.lease);
      const lease = result.lease;
      if (name === 'rootfs-hardlink') await link(join(lease.home, 'rootfs.img'), join(base, 'outside.img'));
      else {
        const file = join(name === 'vz-identifier' ? lease.directory : lease.home, name);
        await rename(file, file + '-original'); await writeFile(file, 'foreign replacement', { mode: 0o600 });
      }
      const boot = await lease.boot();
      assert.equal(boot.phase, 'failed'); assert.equal(boot.verified, false);
      assert.equal(boot.cleanup?.confirmed, false);
      assert.equal((await calls(lease.home)).some(args => ['start', 'delete', 'stop'].includes(args[0])), false);
      assert.ok((await lstat(lease.home)).isDirectory());
    });
  }
});

test('partial foreground start failure and external abort stop the owned group before bounded cleanup', async () => {
  for (const mode of ['exit-start', 'hang-start']) {
    await scope(async base => {
      const options = await osMockTool(base, mode), controller = new AbortController();
      const result = await prepareLimaOsProfile({ ...options, signal: controller.signal }); assert.ok(result.lease);
      const pending = result.lease.boot();
      if (mode === 'hang-start') {
        await waitForOwnedFile(base, 'boot.started').catch(async error => {
          controller.abort(); await pending; throw error;
        });
        controller.abort();
      }
      const boot = await pending;
      assert.equal(boot.phase, 'failed'); assert.equal(boot.cleanup?.confirmed, true);
      await assert.rejects(lstat(result.lease.home), { code: 'ENOENT' });
    });
  }
});

test('Running with a reused foreign PID is never stopped or deleted; outside VM stays intact', async () => {
  await scope(async base => {
    const options = await osMockTool(base, 'reused-pid'), outside = join(base, 'existing-vm');
    await mkdir(outside); await writeFile(join(outside, 'keep'), 'outside VM');
    const result = await prepareLimaOsProfile(options); assert.ok(result.lease);
    const boot = await result.lease.boot();
    assert.equal(boot.phase, 'failed'); assert.equal(boot.cleanup?.confirmed, false);
    const history = await calls(result.lease.home);
    assert.equal(history.some(args => ['stop', 'delete', 'prune'].includes(args[0])), false);
    assert.ok((await lstat(result.lease.directory)).isDirectory());
    assert.equal(await readFile(join(outside, 'keep'), 'utf8'), 'outside VM');
    assert.equal(process.kill(process.pid, 0), true);
  });
});

test('OS cleanup failure retains a stopped, identified lease for safe retry', async () => {
  await scope(async base => {
    const options = await osMockTool(base), result = await prepareLimaOsProfile(options); assert.ok(result.lease);
    await writeFile(join(result.lease.home, 'fail-delete'), 'owned failure');
    assert.equal((await result.lease.cleanup()).confirmed, false);
    await rm(join(result.lease.home, 'fail-delete'));
    assert.equal((await result.lease.cleanup()).confirmed, true);
    assert.deepEqual(await readFile(options.rootfsFile), osBytes);
  });
});

test('an expired OS boot deadline never starts a VM and still has a separate cleanup budget', async () => {
  await scope(async base => {
    const options = await osMockTool(base); options.deadlineAt = Date.now() + 2_000;
    const result = await prepareLimaOsProfile(options); assert.ok(result.lease);
    await delay(Math.max(0, options.deadlineAt - Date.now()) + 10);
    const boot = await result.lease.boot();
    assert.equal(boot.phase, 'failed'); assert.equal(boot.cleanup?.confirmed, true);
    await assert.rejects(lstat(result.lease.home), { code: 'ENOENT' });
  });
});

test('a newly created profile without actual VZ identity remains unconfirmed and is never deleted', async () => {
  await scope(async base => {
    const options = await osMockTool(base, 'missing-machine'), result = await prepareLimaOsProfile(options);
    assert.equal(result.reason, 'prepare_failed'); assert.equal(result.lease, undefined);
    assert.equal(result.cleanup?.confirmed, false); assert.ok(result.pendingHome);
    assert.equal((await calls(result.pendingHome)).some(args => ['start', 'stop', 'delete'].includes(args[0])), false);
    assert.ok((await lstat(result.pendingHome)).isDirectory());
  });
});

test('OS foreground group uncertainty stays unconfirmed even when the mock VM actually stopped', async () => {
  await scope(async base => {
    const prepare = createLimaOsPreparer(async (executable, args, config) => {
      const result = await runRuntimeProcess(executable, args, config);
      if (!args.includes('start')) return result;
      assert.equal(result.cleanupConfirmed, true); assert.equal(result.cancelled, true);
      return { ...result, cleanupConfirmed: false }; // Synthetic fault after the real owned Node group terminated.
    });
    const result = await prepare(await osMockTool(base)); assert.ok(result.lease);
    const boot = await result.lease.boot();
    assert.equal(boot.phase, 'failed'); assert.equal(boot.cleanup?.confirmed, false);
    assert.equal((await result.lease.cleanup()).confirmed, false);
    assert.equal((await calls(result.lease.home)).some(args => args[0] === 'delete'), false);
    assert.equal(JSON.parse(await readFile(join(result.lease.directory, 'state.json'), 'utf8')).status, 'Stopped');
  });
});

test('replacing a rootfs input during streaming fails its bound FD/name check before any tool', async () => {
  await scope(async base => {
    const options = await osMockTool(base), bytes = Buffer.alloc(16 * 1024 * 1024, 0x42);
    await writeFile(options.rootfsFile, bytes);
    options.pins.rootfs.sha256 = createHash('sha256').update(bytes).digest('hex');
    let invoked = 0;
    const prepare = createLimaOsPreparer(async (...args) => { invoked++; return runRuntimeProcess(...args); });
    const pending = prepare(options);
    await waitForOwnedFile(base, 'rootfs.img', true);
    await rename(options.rootfsFile, options.rootfsFile + '-original');
    await writeFile(options.rootfsFile, 'foreign input replacement', { mode: 0o600 });
    const result = await pending;
    assert.equal(result.reason, 'prepare_failed'); assert.equal(result.cleanup?.confirmed, true);
    assert.equal(invoked, 0);
    assert.equal(await readFile(options.rootfsFile, 'utf8'), 'foreign input replacement');
  });
});

test('a cleanup already in progress excludes an overlapping OS boot', async () => {
  await scope(async base => {
    const result = await prepareLimaOsProfile(await osMockTool(base)); assert.ok(result.lease);
    const cleanup = result.lease.cleanup();
    assert.deepEqual(await result.lease.boot(), { status: 'unavailable', verified: false, phase: 'failed' });
    assert.equal((await cleanup).confirmed, true);
    await assert.rejects(lstat(result.lease.home), { code: 'ENOENT' });
  });
});

test('an executor exception preserves unknown group state and cannot authorize OS profile deletion', async () => {
  await scope(async base => {
    let executed = 0;
    const prepare = createLimaOsPreparer(async () => { executed++; throw new Error('no supervision result'); });
    const result = await prepare(await osMockTool(base));
    assert.equal(executed, 1); assert.equal(result.reason, 'prepare_failed');
    assert.equal(result.cleanup?.confirmed, false); assert.ok(result.pendingHome);
    assert.ok((await lstat(result.pendingHome)).isDirectory());
  });
});
