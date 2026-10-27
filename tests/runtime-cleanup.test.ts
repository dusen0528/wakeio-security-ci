import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, copyFile, link, lstat, mkdtemp, mkdir, open, readFile, readdir, realpath, rename, rm, symlink,
  truncate, writeFile }
  from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { runRuntimeProcess } from '../src/runtime/process.js';
import { copyPgParserAssetFiles, createPgParserAssetLoader,
  compileLimaProfileConfig, createLimaProfilePreparer, prepareLimaProfile,
  createLimaOsPreparer, createLimaOsSessionRunner, MAX_LIMA_ROOTFS_BYTES, prepareLimaOsProfile, withLimaOsSession,
  type LimaOsOptions, type LimaPins, type LimaProfileOptions, type LimaOsProbeCapability }
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
  assert.equal(Object.hasOwn(c, 'param'), false);
  assert.equal(c.portForwards[1].ignore, true); assert.equal(c.portForwards[1].proto, 'any');
  assert.match(c.message, /SSH22/);
  const boot: string = c.provision[0].script;
  for (const required of ['host\\.lima', '10001', 'Delegate=cpu cpuset io memory pids', '65536',
    'CPUQuota=200%', 'MemoryMax=2G', 'TasksMax=256', 'exit 125']) {
    assert.ok(boot.includes(required), required);
  }
  assert.ok(boot.endsWith('loginctl enable-linger wakeio-m1\nwrite_state complete none\ntrap - EXIT\n'
    + 'exit 125\n'));
  assert.doesNotMatch(boot, /wakeio_missing_prerequisite/);
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

test('unused Docker metadata is absent from Lima YAML while its trusted input pin constraints stay enforced', () => {
  const config = JSON.parse(compileLimaProfileConfig(pins));
  assert.equal(Object.hasOwn(config, 'param'), false);
  assert.equal(JSON.stringify(config).includes(pins.dockerExtras.sha256), false);
  const rejected: unknown[] = [null, {},
    { ...pins.dockerExtras, sha256: '' }, { ...pins.dockerExtras, sha256: 'A'.repeat(64) },
    { ...pins.dockerExtras, sha256: null }, { ...pins.dockerExtras, version: 'latest' },
    { ...pins.dockerExtras, version: '5:29.9.3-1~ubuntu.24.04~noble' },
    { ...pins.dockerExtras, url: pins.dockerExtras.url + '?token=unused' },
    { ...pins.dockerExtras, url: pins.dockerExtras.url.replace('arm64/', 'amd64/') },
    { ...pins.dockerExtras, url: pins.dockerExtras.url.replace('download.docker.com', 'example.invalid') },
    { ...pins.dockerExtras, ready: true }];
  for (const dockerExtras of rejected) {
    assert.throws(() => compileLimaProfileConfig({ ...pins, dockerExtras } as LimaPins));
  }
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
const inventoryNames = ['uidmap', 'dbus-user-session', 'iptables', 'nftables', 'libc6', 'libsystemd0',
  'libseccomp2', 'init-system-helpers', 'slirp4netns', 'apparmor', 'ca-certificates', 'curl', 'gpgv', 'python3',
  'systemd', 'sudo', 'login', 'passwd', 'docker-ce', 'docker-ce-cli', 'docker-ce-rootless-extras', 'containerd.io'];
function inventoryWire(): string {
  return 'wakeio-os-inventory/v1\tubuntu\t24.04\taarch64\n'
    + inventoryNames.map(name => name + (name.startsWith('docker') || name === 'containerd.io'
      ? '\tmissing\t-\n' : '\tinstalled\t1.0+synthetic\n')).join('') + 'end\t22\n';
}
const SESSION_MOCK = `
function exitOwnedMock(){
 if((mode==='startup-exit'&&fs.existsSync(p.join(home,'startup.exit')))||fs.existsSync(p.join(home,'session.exit'))){
  fs.rmSync(p.join(home,'startup.pid'),{force:true});state('Stopped');process.exit(2);}
}
function fixedGuestProbe(){
 if(a[1]!=='--workdir=/'||a[2]!=='--shell=/bin/bash'||a[4]!=='--')process.exit(91);
 const code=a.at(-1),status=JSON.parse(fs.readFileSync(stateFile,'utf8')).status;
 if(code.includes('wakeio-os-inventory/v1')){
  if(status!=='Running')process.exit(255);
  fs.writeFileSync(p.join(home,'inventory.started'),'owned inventory');
  if(mode==='session-inventory-hang'){process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},1000);return;}
  process.stdout.write(${JSON.stringify(inventoryWire())});return;
 }
 if(!code.includes('id -u wakeio-m1')||!code.includes('cgroup.subtree_control'))process.exit(92);
 if(status!=='Running'||mode==='session-probe-unavailable')process.exit(255);
 if(mode==='session-probe-fail')process.exit(125);
 fs.writeFileSync(p.join(home,'probe.started'),'owned probe');
 if(mode==='session-probe-hang'){process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},1000);return;}
 console.log(mode==='session-probe-malformed'?'untrusted output':'wakeio-os-prerequisites/v1');
}
`;
const STARTUP_MOCK = `
function advanceStartup(){
 const owned=p.join(home,'startup.pid');if(!fs.existsSync(owned))return;
 const pid=Number(fs.readFileSync(owned,'utf8')),stepFile=p.join(home,'startup.step');
 const step=fs.existsSync(stepFile)?Number(fs.readFileSync(stepFile,'utf8')):0;
 fs.writeFileSync(stepFile,String(step+1));
 if(step===0){state('Stopped');return;}
 let patch={driverPID:0,errors:[{}]};
 const bad={
  'startup-negative':{driverPID:-1},'startup-string':{hostAgentPID:String(pid)},
  'startup-driver-only':{hostAgentPID:0,driverPID:pid},'startup-mismatch':{driverPID:pid+1},
  'startup-name':{name:'unowned'},'startup-version':{limaVersion:'v1.0.4'},
  'startup-protected':{protected:true},'startup-arch':{arch:'x86_64'},'startup-vmtype':{vmType:'qemu'}
 };
 if(step===1&&bad[mode])patch={...patch,...bad[mode]};
 if(step===1&&mode==='startup-transport')process.exit(3);
 if(step===1&&mode==='startup-unknown'){state('UnknownStatus',pid,patch);return;}
 if(step===1&&mode==='startup-identity')fs.writeFileSync(p.join(dir,'vz-identifier'),'changed identity');
 if(step===1&&mode==='startup-asset')fs.writeFileSync(p.join(home,'rootfs.img'),'changed asset');
 if(step===1&&mode==='startup-exit')fs.writeFileSync(p.join(home,'startup.exit'),'exit owned child');
 if(step===1||mode==='startup-persistent'){state('Broken',pid,patch);return;}
 if(step===2){state('Installing',pid,patch);return;}
 state('Running',pid,mode==='startup-running-errors'?{errors:[{}]}:{});
}
`;
async function osMockTool(base: string, mode = '', listVersion: string | null = '1.0.3'): Promise<LimaOsOptions> {
  const executable = join(base, 'mock-os-limactl'), rootfsFile = join(base, 'input.img');
  await writeFile(rootfsFile, osBytes, { mode: 0o600 });
  await writeFile(executable, `#!/usr/bin/env node
const fs=require('node:fs'),p=require('node:path');
const home=process.env.HOME,a=process.argv.slice(2).filter(x=>x!=='--tty=false'),mode=${JSON.stringify(mode)};
if(process.env.LIMA_HOME||process.env.SSH_AUTH_SOCK||process.env.DOCKER_HOST||process.cwd()!==home)process.exit(91);
fs.appendFileSync(p.join(home,'calls.ndjson'),JSON.stringify(a)+String.fromCharCode(10));
if(a[0]==='--version'){console.log('limactl version 1.0.3');process.exit(0);}
const name=a[0]==='create'?a.find(x=>x.startsWith('--name=')).slice(7):a[0]==='shell'?a[3]:a.at(-1);
const dir=p.join(home,'.lima',name);
const stateFile=p.join(dir,'state.json');
function state(status,pid=0,patch={}){const value={name,dir,status,protected:false,
 vmType:'vz',arch:'aarch64',limaVersion:${JSON.stringify(listVersion)},hostAgentPID:pid,driverPID:pid,...patch};
 if(mode==='omit-zero-pids'&&pid===0){delete value.hostAgentPID;delete value.driverPID;}
 const pending=stateFile+'.tmp-'+process.pid;fs.writeFileSync(pending,JSON.stringify(value));
 fs.renameSync(pending,stateFile);}
${STARTUP_MOCK}
${SESSION_MOCK}
if(a[0]==='create'){
 fs.mkdirSync(dir,{mode:0o700});fs.copyFileSync(a.at(-1),p.join(dir,'lima.yaml'));
 if(mode!=='missing-machine')fs.writeFileSync(p.join(dir,'vz-identifier'),${JSON.stringify(machineBytes)},{mode:0o600});
 state('Stopped');
}else if(a[0]==='list'){
 if(mode.startsWith('startup-'))advanceStartup();
 console.log(fs.readFileSync(stateFile,'utf8'));
}else if(a[0]==='shell'){
 fixedGuestProbe();
}else if(a[0]==='start'){
 if(!a.includes('--foreground')||!a.includes('--timeout=30s'))process.exit(92);
 fs.writeFileSync(p.join(home,'boot.started'),'owned mock foreground child');
 if(mode==='exit-start'){state('Stopped');process.exit(2);}
 if(mode.startsWith('startup-')){fs.writeFileSync(p.join(home,'startup.pid'),String(process.pid));state('Stopped');}
 else if(mode!=='hang-start')state('Running',process.pid);
 process.on('SIGTERM',()=>{fs.rmSync(p.join(home,'startup.pid'),{force:true});
  if(['startup-stuck-cleanup','session-stuck-cleanup'].includes(mode)){
   state('Broken',process.pid,{driverPID:0,errors:[{}]});}
  else state(mode==='reused-pid'?'Running':'Stopped',mode==='reused-pid'?process.ppid:0);process.exit(0);});
 setInterval(exitOwnedMock,5);
}else if(a[0]==='delete'){
 if(fs.existsSync(p.join(home,'fail-delete')))process.exit(2);
 fs.rmSync(dir,{recursive:true});
}else process.exit(3);
`, { mode: 0o700 });
  return { executeTargetConsent: true, baseDirectory: base, limactlExecutable: executable, rootfsFile,
    pins: { ...pins, rootfs: { ...pins.rootfs, sha256: createHash('sha256').update(osBytes).digest('hex') } },
    deadlineAt: Date.now() + 15_000 };
}
function startupRecorder(onFrame?: (frame: Record<string, unknown>) => void) {
  const frames: Record<string, unknown>[] = [], exits: (number | null)[] = [];
  const starts: Awaited<ReturnType<typeof runRuntimeProcess>>[] = [];
  const prepare = createLimaOsPreparer(async (executable, args, config) => {
    const result = await runRuntimeProcess(executable, args, config);
    if (args[1] === 'start') starts.push(result);
    if (args[1] === 'list') {
      exits.push(result.exitCode);
      if (result.completed) {
        const frame = JSON.parse(result.stdout); frames.push(frame); onFrame?.(frame);
      }
    }
    return result;
  });
  return { prepare, frames, exits, starts };
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

test('both stopped and OS preparers reject invalid package metadata before file reads or tool execution', async () => {
  await scope(async base => {
    const stopped = await mockTool(base), os = await osMockTool(base), before = await readdir(base);
    let invoked = 0;
    const execute: typeof runRuntimeProcess = async () => { invoked++; throw new Error('must not run'); };
    for (const dockerExtras of [null, { ...pins.dockerExtras, sha256: '' },
      { ...pins.dockerExtras, url: pins.dockerExtras.url + '/extra' }]) {
      const invalidPins = { ...pins, dockerExtras } as LimaPins;
      for (const result of [await createLimaProfilePreparer(execute)({ ...stopped, pins: invalidPins }),
        await createLimaOsPreparer(execute)({ ...os, rootfsFile: '/missing-rootfs', pins: invalidPins })]) {
        assert.equal(result.reason, 'prepare_failed'); assert.equal(result.verified, false);
        assert.equal(result.lease, undefined); assert.equal(result.cleanup, undefined);
      }
    }
    assert.equal(invoked, 0); assert.deepEqual(await readdir(base), before);
  });
});

test('synthetic bytes bind private OS config and VZ identity; foreground boot stops before cleanup', async () => {
  await scope(async base => {
    const options = await osMockTool(base), result = await prepareLimaOsProfile(options); assert.ok(result.lease);
    const lease = result.lease, config = JSON.parse(await readFile(join(lease.home, 'profile.yaml'), 'utf8'));
    assert.equal(result.status, 'unavailable'); assert.equal(result.verified, false);
    assert.ok(result.missingPrerequisites.includes('docker-extras-byte-verification'));
    assert.equal(Object.hasOwn(config, 'param'), false);
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
    assert.ok(osScript.endsWith('loginctl enable-linger wakeio-m1\nwrite_state complete none\ntrap - EXIT\n'));
    const stoppedScript: string = JSON.parse(compileLimaProfileConfig(pins)).provision[0].script;
    assert.equal(stoppedScript, osScript + 'exit 125\n');
    const boot = await lease.boot();
    assert.deepEqual(boot, { status: 'unavailable', verified: false, phase: 'running_observed_then_stopped' });
    assert.equal((await calls(lease.home)).some(args => args[0] === 'stop'), false);
    assert.equal((await lease.cleanup()).confirmed, true);
    assert.deepEqual(await readFile(options.rootfsFile), osBytes);
  });
});

test('pinned list spellings preserve owned mock boot and cleanup with omitted PID0', async () => {
  for (const version of ['1.0.3', 'v1.0.3']) {
    await scope(async base => {
      const result = await prepareLimaOsProfile(await osMockTool(base, 'omit-zero-pids', version));
      assert.equal(result.reason, 'missing_prerequisite'); assert.ok(result.lease);
      assert.equal(result.verified, false); const lease = result.lease;
      const state = JSON.parse(await readFile(join(lease.directory, 'state.json'), 'utf8'));
      assert.equal(state.limaVersion, version);
      assert.equal(Object.hasOwn(state, 'hostAgentPID'), false);
      assert.equal(Object.hasOwn(state, 'driverPID'), false);
      assert.equal((await lstat(lease.directory)).ino, lease.profileIdentity.ino);
      assert.equal(lease.machineIdentitySha256, createHash('sha256').update(machineBytes).digest('hex'));
      assert.deepEqual(await lease.boot(), {
        status: 'unavailable', verified: false, phase: 'running_observed_then_stopped' });
      assert.equal((await lease.cleanup()).confirmed, true);
      await assert.rejects(lstat(lease.home), { code: 'ENOENT' });
    });
  }
});

test('other list versions, suffixes and whitespace cannot authorize deletion', async () => {
  for (const version of ['1.0.4', 'v1.0.4', '1.0.3-rc1', 'v1.0.3+build', 'latest', '^1.0.3',
    ' 1.0.3', '1.0.3\n', 'v1.0.3\n', '', null]) {
    await scope(async base => {
      const result = await prepareLimaOsProfile(await osMockTool(base, '', version));
      assert.equal(result.reason, 'prepare_failed'); assert.equal(result.verified, false);
      assert.equal(result.cleanup?.confirmed, false); assert.ok(result.pendingHome);
      assert.equal((await calls(result.pendingHome))
        .some(args => ['start', 'delete', 'stop'].includes(args[0])), false);
    });
  }
});

test('a tagged version cannot authorize deletion after its owned profile identity changes', async () => {
  await scope(async base => {
    const result = await prepareLimaOsProfile(await osMockTool(base, '', 'v1.0.3')); assert.ok(result.lease);
    const lease = result.lease;
    await rename(lease.directory, lease.directory + '-original'); await mkdir(lease.directory, { mode: 0o700 });
    assert.equal((await lease.cleanup()).confirmed, false);
    assert.equal((await calls(lease.home)).some(args => args[0] === 'delete'), false);
  });
});

test('owned startup polls Stopped, host-only Broken and Installing before strict Running and Stopped', async () => {
  await scope(async base => {
    const recorder = startupRecorder(), result = await recorder.prepare(await osMockTool(base, 'startup-sequence'));
    assert.ok(result.lease);
    assert.deepEqual(await result.lease.boot(), {
      status: 'unavailable', verified: false, phase: 'running_observed_then_stopped' });
    const states = recorder.frames.map(frame => frame.status); let position = -1;
    for (const state of ['Stopped', 'Broken', 'Installing', 'Running', 'Stopped']) {
      position = states.indexOf(state, position + 1); assert.ok(position >= 0, 'missing startup state ' + state);
    }
    const broken = recorder.frames.find(frame => frame.status === 'Broken')!;
    assert.ok(Number(broken.hostAgentPID) > 0); assert.equal(broken.driverPID, 0);
    assert.ok(Array.isArray(broken.errors));
    assert.equal((await result.lease.cleanup()).confirmed, true);
  });
});

test('persistent Broken consumes the caller deadline; early foreground exit remains a failure', async () => {
  for (const mode of ['startup-persistent', 'startup-exit']) {
    await scope(async base => {
      const options = await osMockTool(base, mode), recorder = startupRecorder();
      if (mode === 'startup-persistent') options.deadlineAt = Date.now() + 3_000;
      const result = await recorder.prepare(options); assert.ok(result.lease);
      const boot = await result.lease.boot();
      assert.equal(boot.phase, 'failed'); assert.equal(boot.cleanup?.confirmed, true);
      assert.ok(recorder.frames.some(frame => frame.status === 'Broken'));
      assert.equal(recorder.starts[0].cleanupConfirmed, true);
      if (mode === 'startup-persistent') assert.ok(Date.now() >= options.deadlineAt);
      else assert.equal(recorder.starts[0].exitCode, 2);
    });
  }
});

test('startup rejects invalid PID, authority, unknown status, transport loss and Running errors', async () => {
  for (const mode of ['startup-negative', 'startup-string', 'startup-driver-only', 'startup-mismatch',
    'startup-name', 'startup-version', 'startup-protected', 'startup-arch', 'startup-vmtype',
    'startup-unknown', 'startup-transport', 'startup-running-errors']) {
    await scope(async base => {
      const recorder = startupRecorder(), result = await recorder.prepare(await osMockTool(base, mode));
      assert.ok(result.lease);
      const boot = await result.lease.boot();
      assert.equal(boot.phase, 'failed', mode); assert.equal(boot.cleanup?.confirmed, true, mode);
      if (mode === 'startup-transport') assert.ok(recorder.exits.includes(3));
      assert.equal(recorder.starts[0].cleanupConfirmed, true);
    });
  }
});

test('startup identity or asset drift and unknown final cleanup preserve the owned profile', async () => {
  for (const mode of ['startup-identity', 'startup-asset', 'startup-stuck-cleanup']) {
    await scope(async base => {
      const recorder = startupRecorder(), result = await recorder.prepare(await osMockTool(base, mode));
      assert.ok(result.lease);
      const boot = await result.lease.boot();
      assert.equal(boot.phase, 'failed'); assert.equal(boot.cleanup?.confirmed, false);
      assert.ok((await lstat(result.lease.directory)).isDirectory());
      assert.equal((await calls(result.lease.home)).some(args => args[0] === 'delete'), false);
    });
  }
});

test('external abort during a verified Broken startup frame stops the owned group before cleanup', async () => {
  await scope(async base => {
    const controller = new AbortController(), recorder = startupRecorder(frame => {
      if (frame.status === 'Broken') controller.abort();
    });
    const options = await osMockTool(base, 'startup-sequence');
    const result = await recorder.prepare({ ...options, signal: controller.signal }); assert.ok(result.lease);
    const boot = await result.lease.boot();
    assert.equal(boot.phase, 'failed'); assert.equal(boot.cleanup?.confirmed, true);
    assert.equal(recorder.starts[0].cleanupConfirmed, true);
    assert.equal(recorder.frames.some(frame => frame.status === 'Running'), false);
  });
});

test('ordinary prepare and cleanup never accept a Broken startup frame as Stopped', async () => {
  await scope(async base => {
    const options = await osMockTool(base);
    const prepare = createLimaOsPreparer(async (executable, args, config) => {
      const result = await runRuntimeProcess(executable, args, config);
      if (args[1] === 'create' && result.completed) {
        const name = args.find(arg => arg.startsWith('--name='))!.slice(7);
        const path = join(config.home, '.lima', name, 'state.json'), state = JSON.parse(await readFile(path, 'utf8'));
        await writeFile(path, JSON.stringify({ ...state, status: 'Broken', hostAgentPID: 123, errors: [{}] }));
      }
      return result;
    });
    const rejected = await prepare(options);
    assert.equal(rejected.reason, 'prepare_failed'); assert.equal(rejected.cleanup?.confirmed, false);
    const result = await prepareLimaOsProfile(await osMockTool(base)); assert.ok(result.lease);
    const path = join(result.lease.directory, 'state.json'), state = JSON.parse(await readFile(path, 'utf8'));
    await writeFile(path, JSON.stringify({ ...state, status: 'Installing', hostAgentPID: 123 }));
    assert.equal((await result.lease.cleanup()).confirmed, false);
    assert.equal((await calls(result.lease.home)).some(args => args[0] === 'delete'), false);
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

function sessionRecorder(uncertain = false) {
  const events: { args: readonly string[]; home: string; result: Awaited<ReturnType<typeof runRuntimeProcess>> }[] = [];
  const run = createLimaOsSessionRunner(async (executable, args, config) => {
    const result = await runRuntimeProcess(executable, args, config); events.push({ args, home: config.home, result });
    return uncertain && args[1] === 'start' ? { ...result, cleanupConfirmed: false } : result;
  });
  return { run, events };
}
test('OS sessions require consent before input getters, tools or the trusted callback run', async () => {
  await scope(async base => {
    let invoked = 0;
    const raw = Object.defineProperty({ executeTargetConsent: false }, 'rootfsFile', {
      get() { invoked++; throw new Error('must not read'); },
    });
    const use = async () => { invoked++; };
    assert.equal((await withLimaOsSession(raw as LimaOsOptions, use)).phase, 'consent_required');
    const options = await osMockTool(base), before = await readdir(base);
    const bad = { ...options, callback: use };
    assert.equal((await withLimaOsSession(bad, use)).phase, 'failed');
    assert.equal(invoked, 0); assert.deepEqual(await readdir(base), before);
  });
});
test('a bounded OS session exposes fixed readers and revokes them after cleanup', async () => {
  await scope(async base => {
    const recorder = sessionRecorder(), options = await osMockTool(base); let retained!: LimaOsProbeCapability;
    const result = await recorder.run(options, async cap => {
      retained = cap; assert.deepEqual(Object.keys(cap), ['probe', 'inventory']);
      assert.equal(Object.isFrozen(cap), true);
      assert.deepEqual(await cap.probe(), { kind: 'os-prerequisites', observed: true,
        backendVerified: false, bootPhase: 'complete', reason: 'none' });
      assert.deepEqual(await cap.probe(), { kind: 'os-prerequisites', observed: true,
        backendVerified: false, bootPhase: 'complete', reason: 'none' });
    });
    assert.equal(result.phase, 'callback_completed'); assert.equal(result.verified, false);
    assert.equal(result.guestPrerequisitesObserved, true); assert.equal(result.cleanup?.confirmed, true);
    const jobs = recorder.events.filter(event => event.args[1] === 'shell'); assert.equal(jobs.length, 2);
    assert.deepEqual(jobs[0].args.slice(2, 4), ['--workdir=/', '--shell=/bin/bash']);
    assert.match(jobs[0].args.at(-1)!, /cpu memory pids/);
    assert.doesNotMatch(jobs[0].args.at(-1)!, /\bdocker(?:[\s;&|]|$)|curl|install|eval/);
    const count = recorder.events.length; await assert.rejects(retained.probe());
    assert.equal(recorder.events.length, count);
  });
});
test('guest/SSH unavailability stays unobserved while malformed probe output fails closed', async () => {
  for (const mode of ['session-probe-fail', 'session-probe-unavailable', 'session-probe-malformed']) {
    await scope(async base => {
      const recorder = sessionRecorder(), result = await recorder.run(await osMockTool(base, mode), async cap => {
        assert.deepEqual(await cap.probe(), { kind: 'os-prerequisites', observed: false,
          backendVerified: false, bootPhase: 'unknown',
          reason: mode === 'session-probe-fail' ? 'guard_unknown' : 'ssh_unavailable' });
      });
      assert.equal(result.phase, mode === 'session-probe-malformed' ? 'failed' : 'callback_completed');
      assert.equal(result.guestPrerequisitesObserved, false); assert.equal(result.cleanup?.confirmed, true);
    });
  }
});
test('callback throw, a never-settling async callback and foreground exit all close bounded sessions', async () => {
  for (const mode of ['throw', 'never', 'foreground']) {
    await scope(async base => {
      const recorder = sessionRecorder(), options = await osMockTool(base);
      if (mode === 'never') options.deadlineAt = Date.now() + 2_500;
      let retained!: LimaOsProbeCapability;
      const result = await recorder.run(options, async cap => {
        retained = cap;
        if (mode === 'throw') throw new Error('discard callback failure text');
        if (mode === 'foreground') {
          const file = await waitForOwnedFile(base, 'boot.started');
          await writeFile(join(file, '..', 'session.exit'), 'owned child exit');
        }
        await new Promise<void>(() => {});
      });
      assert.equal(result.phase, 'failed'); assert.equal(result.cleanup?.confirmed, true);
      assert.equal(recorder.events.find(event => event.args[1] === 'start')?.result.cleanupConfirmed, true);
      const count = recorder.events.length; await assert.rejects(retained.probe());
      assert.equal(recorder.events.length, count);
    });
  }
});
test('a scoped OS probe rejects command/options arguments before any guest probe job', async () => {
  await scope(async base => {
    const recorder = sessionRecorder(), result = await recorder.run(await osMockTool(base), async cap => {
      await assert.rejects((cap.probe as (...args: unknown[]) => Promise<unknown>)('arbitrary-command'));
    });
    assert.equal(result.phase, 'failed'); assert.equal(result.cleanup?.confirmed, true);
    assert.equal(recorder.events.some(event => event.args[1] === 'shell'), false);
  });
});
test('unfinished and concurrent probes are revoked and drained before foreground and profile cleanup', async () => {
  for (const overlap of [false, true]) {
    await scope(async base => {
      const recorder = sessionRecorder();
      const result = await recorder.run(await osMockTool(base, 'session-probe-hang'), async cap => {
        const pending = cap.probe(); void pending.catch(() => undefined);
        await waitForOwnedFile(base, 'probe.started');
        if (overlap) await assert.rejects(cap.probe());
      });
      assert.equal(result.phase, 'failed'); assert.equal(result.cleanup?.confirmed, true);
      const probe = recorder.events.find(event => event.args[1] === 'shell')!;
      assert.equal(probe.result.cancelled, true); assert.equal(probe.result.cleanupConfirmed, true);
      assert.equal(probe.result.closeConfirmed, true);
    });
  }
});
test('PID drift and caller abort revoke scoped probes without authorizing metadata PID kills', async () => {
  for (const abort of [false, true]) {
    await scope(async base => {
      const recorder = sessionRecorder(), controller = new AbortController(), options = await osMockTool(base);
      const result = await recorder.run({ ...options, signal: controller.signal }, async () => {
        if (abort) controller.abort();
        else {
          const file = await waitForOwnedFile(base, 'boot.started'), home = join(file, '..');
          const name = (await readdir(join(home, '.lima'))).find(value => value.startsWith('wk-'))!;
          const path = join(home, '.lima', name, 'state.json'), frame = JSON.parse(await readFile(path, 'utf8'));
          await writeFile(path, JSON.stringify({ ...frame, hostAgentPID: frame.hostAgentPID + 1,
            driverPID: frame.driverPID + 1 }));
        }
        await new Promise<void>(() => {});
      });
      assert.equal(result.phase, 'failed'); assert.equal(result.cleanup?.confirmed, true);
      assert.equal(recorder.events.some(event => event.args[1] === 'stop'), false);
    });
  }
});
test('asset, machine and binary drift or uncertain final state preserve sticky cleanup failure', async () => {
  for (const fault of ['rootfs.img', 'vz-identifier', 'binary', 'state', 'group']) {
    await scope(async base => {
      const recorder = sessionRecorder(fault === 'group');
      const options = await osMockTool(base, fault === 'state' ? 'session-stuck-cleanup' : '');
      const result = await recorder.run(options, async cap => {
        if (['state', 'group'].includes(fault)) { await cap.probe(); return; }
        const file = await waitForOwnedFile(base, 'boot.started'), home = join(file, '..');
        const name = (await readdir(join(home, '.lima'))).find(value => value.startsWith('wk-'))!;
        const path = fault === 'binary' ? options.limactlExecutable
          : fault === 'rootfs.img' ? join(home, fault) : join(home, '.lima', name, fault);
        await writeFile(path, 'changed owned test asset');
        await new Promise<void>(() => {});
      });
      assert.equal(result.phase, 'failed'); assert.equal(result.cleanup?.confirmed, false);
      assert.ok(result.pendingHome); assert.ok((await lstat(result.pendingHome)).isDirectory());
      assert.equal(recorder.events.some(event => event.args[1] === 'delete'), false);
    });
  }
});

// Public deployment bytes only: these tests never import or execute the worker/WASM/SQL.
const parserNames = ['manifest.json', 'pg-parser-worker.cjs', 'libpg-query.wasm',
  'THIRD_PARTY_LICENSES.txt', 'LICENSE.libpg_query', 'COPYRIGHT.PostgreSQL'];
const parserSource = fileURLToPath(new URL('../../workers/pg-parser/', import.meta.url));
async function parserFixture(root: string): Promise<string> {
  const directory = join(root, 'workers/pg-parser'); await mkdir(directory, { recursive: true });
  for (const name of parserNames) await copyFile(join(parserSource, name), join(directory, name));
  return directory;
}
test('parser loader binds host pins and returns branded data copies without installed TS', async () => {
  await scope(async base => {
    await parserFixture(base);
    const paths: string[] = [];
    const load = createPgParserAssetLoader(base, async (path, flags, mode) => {
      paths.push(String(path)); return open(path, flags, mode);
    });
    const result = await load({ executeTargetConsent: true });
    assert.equal(result.reason, 'assets_bound'); assert.equal(result.status, 'unavailable');
    assert.equal(result.verified, false); assert.equal(result.handle?.executionAuthorized, false);
    assert.equal(result.handle?.protocolRevision, 'wakeio.pg-parser/v1');
    assert.equal(result.handle?.lockSha256, 'adc4e4026559ed0e5229acb4cb5354a82437420efdb58056d4a9d73969e37493');
    assert.ok(Object.isFrozen(result.handle));
    assert.deepEqual(paths.map(path => path.slice(path.lastIndexOf('/') + 1)), parserNames);
    const files = copyPgParserAssetFiles(result.handle);
    assert.deepEqual(files.map(file => file.path), parserNames.map(name => 'workers/pg-parser/' + name));
    for (const file of files) assert.deepEqual(file.bytes, await readFile(join(base, file.path)));
    files[1].bytes.fill(0); files[0].path = 'attacker-path';
    const next = copyPgParserAssetFiles(result.handle);
    assert.deepEqual(next[1].bytes, await readFile(join(base, next[1].path)));
    assert.equal(next[0].path, 'workers/pg-parser/manifest.json');
    for (const fake of [{}, { ...result.handle }, JSON.parse(JSON.stringify(result.handle)),
      new Proxy(result.handle!, { get() { throw Error('must not invoke'); } })]) {
      assert.throws(() => copyPgParserAssetFiles(fake), /asset_mismatch/);
    }
    assert.equal('execute' in result.handle!, false); assert.equal('probe' in result.handle!, false);
  });
});
test('parser consent rejects missing, inherited, getter and Proxy consent without I/O/hooks', async () => {
  let operations = 0, hooks = 0;
  const load = createPgParserAssetLoader('/nonexistent-unread-installation', async (...args) => {
    operations++; return open(...args);
  });
  const getter = Object.defineProperty({}, 'executeTargetConsent', { get() { hooks++; return true; } });
  const proxy = new Proxy({}, { ownKeys() { hooks++; throw Error('hook'); },
    getOwnPropertyDescriptor() { hooks++; throw Error('hook'); }, get() { hooks++; throw Error('hook'); } });
  for (const raw of [null, {}, { executeTargetConsent: false }, Object.create({ executeTargetConsent: true }),
    getter, proxy]) assert.equal((await load(raw)).reason, 'consent_required');
  const extraGetter = Object.defineProperty({ executeTargetConsent: true }, 'expectedHash', {
    enumerable: true, get() { hooks++; throw Error('hook'); } });
  assert.equal((await load(extraGetter)).reason, 'asset_mismatch');
  assert.equal(operations, 0); assert.equal(hooks, 0);
});
test('parser loader rejects manifest-only header/provenance tampering by raw host manifest pin', async () => {
  for (const field of ['protocolRevision', 'lock', 'provenance']) {
    await scope(async base => {
      const directory = await parserFixture(base), path = join(directory, 'manifest.json');
      const manifest = JSON.parse(await readFile(path, 'utf8'));
      if (field === 'protocolRevision') manifest.protocolRevision = 'wakeio.pg-parser/v2';
      else if (field === 'lock') manifest.pin.lockSha256 = '0'.repeat(64);
      else manifest.build.provenance.sources[0].sha256 = '0'.repeat(64);
      await writeFile(path, JSON.stringify(manifest, null, 2) + '\n');
      assert.equal((await createPgParserAssetLoader(base)({ executeTargetConsent: true })).reason, 'asset_mismatch');
    });
  }
});
test('worker plus manifest tampering and attacker expected hashes never replace host pins', async () => {
  await scope(async base => {
    const directory = await parserFixture(base), path = join(directory, 'pg-parser-worker.cjs');
    const bytes = Buffer.from('untrusted replacement, never executed\n'); await writeFile(path, bytes);
    const manifestPath = join(directory, 'manifest.json'), manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    manifest.assets[0] = { path: 'workers/pg-parser/pg-parser-worker.cjs', bytes: bytes.length, sha256 };
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    const load = createPgParserAssetLoader(base);
    assert.equal((await load({ executeTargetConsent: true })).reason, 'asset_mismatch');
    for (const override of [{ workerSha256: sha256 }, { expected: manifest.assets }, { assets: {
      workerSha256: sha256, manifestSha256: createHash('sha256').update(await readFile(manifestPath)).digest('hex'),
    } }]) assert.equal((await load({ executeTargetConsent: true, ...override })).reason, 'asset_mismatch');
  });
});
test('parser locator cannot be changed by load options and an incomplete trusted root fails closed', async () => {
  await scope(async base => {
    const valid = join(base, 'valid'), other = join(base, 'other');
    await parserFixture(valid); await mkdir(other);
    for (const key of ['installationRoot', 'root', 'cwd', 'PATH', 'env', 'openTrustedFile']) {
      assert.equal((await createPgParserAssetLoader(other)({ executeTargetConsent: true, [key]: valid })).reason,
        'asset_mismatch');
    }
    assert.equal((await createPgParserAssetLoader(other)({ executeTargetConsent: true })).reason, 'asset_mismatch');
    const alias = join(base, 'alias'); await symlink(valid, alias);
    assert.equal((await createPgParserAssetLoader(alias)({ executeTargetConsent: true })).reason, 'asset_mismatch');
    assert.equal((await createPgParserAssetLoader(valid)({ executeTargetConsent: true })).reason, 'assets_bound');
  });
});
test('parser assets reject links, writable permissions, missing/extra files, wrong types and size caps', async () => {
  for (const fault of ['symlink', 'hardlink', 'writable', 'missing', 'extra', 'directory', 'oversize', 'notice',
    'root-writable', 'dir-writable']) {
    await scope(async base => {
      const directory = await parserFixture(base), path = join(directory, 'libpg-query.wasm');
      if (fault === 'symlink' || fault === 'hardlink') {
        const original = join(base, 'public-wasm'); await rename(path, original);
        if (fault === 'symlink') await symlink(original, path);
        else { await link(original, path); }
      } else if (fault === 'root-writable') await chmod(base, 0o777);
      else if (fault === 'dir-writable') await chmod(directory, 0o777);
      else if (fault === 'writable') await chmod(path, 0o666);
      else if (fault === 'missing') await rm(path);
      else if (fault === 'extra') await writeFile(join(directory, 'unapproved.cjs'), 'not executable');
      else if (fault === 'directory') { await rm(path); await mkdir(path); }
      else if (fault === 'oversize') await truncate(path, 2 * 1024 * 1024 + 1);
      else await writeFile(join(directory, 'COPYRIGHT.PostgreSQL'), 'changed notice');
      const result = await createPgParserAssetLoader(base)({ executeTargetConsent: true });
      assert.equal(result.reason, 'asset_mismatch', fault); assert.equal(result.handle, undefined);
    });
  }
});
test('parser loader detects opened-FD/name replacement and later changes to an already-read asset', async () => {
  for (const fault of ['fd-swap', 'name-swap', 'later-swap', 'root-swap']) {
    await scope(async base => {
      const root = join(base, 'installation'), directory = await parserFixture(root);
      let opens = 0;
      const opened: Awaited<ReturnType<typeof open>>[] = [];
      const load = createPgParserAssetLoader(root, async (path, flags, mode) => {
        opens++; const target = String(path), old = join(base, 'original-manifest');
        if (fault === 'fd-swap' && opens === 1) {
          await copyFile(target, old); const handle = await open(old, flags, mode); opened.push(handle); return handle;
        }
        const handle = await open(path, flags, mode); opened.push(handle);
        if (fault === 'name-swap' && opens === 1 || fault === 'later-swap' && opens === 2) {
          const manifest = join(directory, 'manifest.json'); await rename(manifest, old); await copyFile(old, manifest);
        }
        if (fault === 'root-swap' && opens === 1) {
          await rename(root, join(base, 'retired')); await parserFixture(root);
        }
        return handle;
      });
      const result = await load({ executeTargetConsent: true });
      assert.equal(result.reason, 'asset_mismatch', fault); assert.equal(result.handle, undefined);
      assert.ok(opened.length > 0);
      for (const handle of opened) assert.equal(handle.fd, -1, 'all owned read FDs closed on failure');
    });
  }
});

test('OS bootstrap clears SDK proxy keys and atomically records bounded root-owned boot state', () => {
  const config = JSON.parse(compileLimaProfileConfig(pins)), script: string = config.provision[0].script;
  const names = ['ftp_proxy', 'http_proxy', 'https_proxy', 'no_proxy',
    'FTP_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'];
  assert.deepEqual(config.env, Object.fromEntries(names.map(name => [name, ''])));
  assert.equal(config.propagateProxyEnv, false);
  assert.equal(config.portForwards[0].guestSocket, '/run/wakeio-m1/relay.sock');
  assert.match(script, /^state_dir=\/run\/wakeio-m1-boot$/m);
  assert.doesNotMatch(script, /^state_dir=\/run\/wakeio-m1$/m);
  for (const guard of ['state_dir=/run/wakeio-m1-boot', '/proc/sys/kernel/random/boot_id',
    'test ! -L "$state_dir"', "'%u:%g:%a'", '0:0:700', 'mkdir -m 700', "'%u:%g:%a:%h'", '0:0:600:1',
    'test "$size" -le 192', 'mktemp "$state_dir/.boot.XXXXXX"', 'mv -T -- "$temporary" "$state_file"',
    'write_state failed "$step"', 'write_state pending bootstrap_pending', 'write_state complete none']) {
    assert.ok(script.includes(guard), guard);
  }
  assert.match(script, /id wakeio-m1.*\|\| useradd --uid 10001 --create-home --shell \/bin\/bash/);
  assert.equal((script.match(/-K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0/g) ?? []).length, 1);
  assert.match(script, /non_sudo \|\| exit 125/);
  assert.match(script, /\$1 != "wakeio-m1" && \$2 <= 296607 && \$2 \+ \$3 > 231072 \{exit 1\}/);
  assert.match(script, /test "\$\(grep '\^wakeio-m1:' "\$file"\)" = 'wakeio-m1:231072:65536' \|\| exit 125/);
  assert.match(script, /else echo 'wakeio-m1:231072:65536' >> "\$file"/);
  assert.doesNotMatch(script, /login\.defs|usermod|chown|sed.*subuid|sed.*subgid/);
});

test('fixed OS probe binds current boot and safe FD metadata before any success token', async () => {
  await scope(async base => {
    const recorder = sessionRecorder(), result = await recorder.run(await osMockTool(base), async cap => {
      const answer = await cap.probe(); assert.equal(answer.observed, true); assert.equal(answer.reason, 'none');
    });
    const script = recorder.events.find(event => event.args[1] === 'shell')!.args.at(-1)!;
    for (const guard of ['state_dir=/run/wakeio-m1-boot',
      'state_directory || metadata_failure', 'state_metadata || metadata_failure',
      'exec 3< "$state_file"', '/proc/self/fd/3', 'test "$metadata" = "$fd_metadata"',
      'read -r tag saved_boot phase step extra', 'test "$saved_boot" = "$boot" || metadata_failure',
      'test "$size" -eq "$expected_size" || metadata_failure', 'test -z "$trailing" && test -z "$extra"',
      'phase=pending; probe_failure bootstrap_pending', 'if test "$phase" != complete; then probe_failure "$step";',
      'cgroup_procs_unwritable', 'cgroup_subtree_unwritable', 'subid_overlap', 'subuid_mismatch', 'subgid_mismatch']) {
      assert.ok(script.includes(guard), guard);
    }
    assert.match(script, /non_sudo \|\| probe_failure sudo_allowed/);
    assert.equal(script.match(/\/usr\/bin\/sudo -n -l -U wakeio-m1/g)?.length, 1);
    assert.ok(script.indexOf('state_metadata || metadata_failure')
      < script.lastIndexOf("printf 'wakeio-os-prerequisites/v1\\n'"));
    assert.doesNotMatch(script, /eval|useradd|usermod|write_state|mktemp|\bdocker(?:[\s;&|]|$)|curl|install/);
    assert.equal(result.cleanup?.confirmed, true); assert.equal(result.verified, false);
  });
});

function diagnosticSession(reply: () => { exitCode: number; stdout: string; completed: boolean }) {
  return createLimaOsSessionRunner(async (executable, args, config) => {
    if (args[1] === 'shell') {
      assert.equal(config.timeoutMs, 5_000); assert.equal(config.maxOutputBytes, 16 * 1024);
    }
    if (args[1] === 'start') assert.equal(config.timeoutMs, 30_000);
    const result = await runRuntimeProcess(executable, args, config);
    return args[1] === 'shell' ? { ...result, ...reply() } : result;
  });
}
test('closed boot/guard reasons remain unobserved and cannot authorize backend or retained reuse', async () => {
  await scope(async base => {
    const reasons = ['bootstrap_failed', 'host_alias_present', 'cgroup_v2_missing', 'user_create_failed',
      'uid_mismatch', 'sudo_allowed', 'subid_overlap', 'subuid_mismatch', 'subgid_mismatch', 'delegation_missing'];
    const cases = [['pending', 'bootstrap_pending'], ['unknown', 'boot_metadata_invalid'],
      ...reasons.map(reason => ['failed', reason]),
      ...reasons.filter(reason => !['bootstrap_failed', 'user_create_failed'].includes(reason))
        .concat(['cgroup_procs_unwritable', 'cgroup_subtree_unwritable']).map(reason => ['complete', reason])];
    let current = cases[0], calls = 0, retained!: LimaOsProbeCapability;
    const run = diagnosticSession(() => { calls++; return { exitCode: 125, completed: false,
      stdout: `wakeio-os-prerequisites/v1:${current[0]}:${current[1]}\n` }; });
    const result = await run(await osMockTool(base), async cap => {
      retained = cap;
      for (const row of cases) {
        current = row;
        assert.deepEqual(await cap.probe(), { kind: 'os-prerequisites', observed: false, backendVerified: false,
          bootPhase: row[0], reason: row[1] });
      }
    });
    assert.equal(result.phase, 'callback_completed'); assert.equal(result.guestPrerequisitesObserved, false);
    assert.equal(result.verified, false); assert.equal(result.cleanup?.confirmed, true);
    const before = calls; await assert.rejects(retained.probe()); assert.equal(calls, before);
  });
});
test('unknown, truncated and inconsistent diagnostic tokens fail the session without weakening cleanup', async () => {
  const bad = ['wakeio-os-prerequisites/v1:complete:none\n', 'wakeio-os-prerequisites/v1:pending:uid_mismatch\n',
    'wakeio-os-prerequisites/v1:complete:user_create_failed\n',
    'wakeio-os-prerequisites/v1:complete:bootstrap_failed\n',
    'wakeio-os-prerequisites/v1:failed:new_reason\n', 'wakeio-os-prerequisites/v1:failed:uid_mismatch',
    'wakeio-os-prerequisites/v1:failed:uid_mismatch\nextra\n'];
  for (const stdout of bad) {
    await scope(async base => {
      const run = diagnosticSession(() => ({ exitCode: 125, completed: false, stdout }));
      const result = await run(await osMockTool(base), async cap => { await assert.rejects(cap.probe()); });
      assert.equal(result.phase, 'failed'); assert.equal(result.guestPrerequisitesObserved, false);
      assert.equal(result.verified, false); assert.equal(result.cleanup?.confirmed, true);
    });
  }
});

async function nonSudoFixture(base: string, output: Buffer, exitCode = 0,
  hostname = 'lima-wk-0123456789ab\n', root = true, stderr = '') {
  const script: string = JSON.parse(compileLimaProfileConfig(pins)).provision[0].script;
  const functionText = script.match(/non_sudo\(\) \([\s\S]*?\n\)\n/)![0];
  const executable = join(base, 'owned-policy-mock'), callsFile = join(base, 'policy-calls');
  await writeFile(executable, `#!${process.execPath}
const fs=require('node:fs'),a=process.argv.slice(2);
if(process.env.LC_ALL!=='C'||JSON.stringify(a)!=='["-n","-l","-U","wakeio-m1"]')process.exit(92);
fs.appendFileSync(${JSON.stringify(callsFile)},'list'+String.fromCharCode(10));
process.stdout.write(Buffer.from(${JSON.stringify(output.toString('base64'))},'base64'));
process.stderr.write(Buffer.from(${JSON.stringify(Buffer.from(stderr).toString('base64'))},'base64'));
process.exitCode=${exitCode};
`, { mode: 0o700 });
  const mocked = functionText.replaceAll('/usr/bin/sudo', executable).replaceAll('/usr/bin/id', 'owned_id')
    .replaceAll('/usr/bin/hostname', 'owned_hostname').replaceAll('/usr/bin/timeout', 'owned_timeout');
  assert.doesNotMatch(mocked, /\/usr\/bin\/(?:sudo|id|hostname|timeout)/);
  const command = 'set -eu\nowned_id() { test "$*" = -u; printf "' + (root ? '0' : '10001') + '\\n"; }\n'
    + 'owned_hostname() { test "$*" = -s; printf %s ' + "'" + hostname.replaceAll("'", "'\\''") + "'; }\n"
    + 'owned_timeout() { test "$1" = --signal=KILL; shift; test "$1" = 1s; shift; "$@"; }\n'
    + mocked + '\nnon_sudo';
  const result = await runRuntimeProcess('/bin/sh', ['-c', command], { cwd: base, home: base,
    timeoutMs: 2_000, deadlineAt: Date.now() + 3_000, maxOutputBytes: 256 });
  assert.equal(result.stdout, ''); assert.equal(result.stderr, ''); assert.equal(result.cleanupConfirmed, true);
  const calls = await readFile(callsFile, 'utf8').catch(() => '');
  return { result, calls };
}
test('full sudoers no-grants exit0 is accepted; grants, errors and altered output never prove non-sudo', async () => {
  const line = 'User wakeio-m1 is not allowed to run sudo on lima-wk-0123456789ab.\n';
  const replies = [line, 'User wakeio-m1 may run the following commands on lima-wk-0123456789ab:\n (ALL) ALL\n',
    'Matching Defaults entries for wakeio-m1:\n env_reset\n' + line, line + '\n', line.trimEnd(),
    line + 'diagnostic\n', line.replace('wakeio-m1', 'someone'), line.replace('lima-wk-', 'other-'),
    'unsupported plugin or locale\n', line.replace('run sudo', "run '/usr/bin/id'"),
    line.replace('User', 'U\0ser'), line + 'x'.repeat(600)];
  for (let i = 0; i < replies.length; i++) {
    await scope(async base => {
      const { result, calls } = await nonSudoFixture(base, Buffer.from(replies[i]));
      assert.equal(result.completed, i === 0); assert.equal(calls, 'list\n');
    });
  }
  for (const [exitCode, stderr] of [[1, ''], [0, 'sudo: policy error\n']] as const) {
    await scope(async base => {
      const { result, calls } = await nonSudoFixture(base, Buffer.from(line), exitCode, undefined, true, stderr);
      assert.equal(result.completed, false); assert.equal(calls, 'list\n');
    });
  }
});
test('non-sudo verification requires root context and one bounded valid hostname before listing', async () => {
  for (const hostname of ['bad\nsecond\n', 'bad host\n', 'x'.repeat(64) + '\n', 'bad\x1bhost\n', '\n']) {
    await scope(async base => {
      const { result, calls } = await nonSudoFixture(base, Buffer.from('unused'), 0, hostname);
      assert.equal(result.completed, false); assert.equal(calls, '');
    });
  }
  await scope(async base => {
    const { result, calls } = await nonSudoFixture(base, Buffer.from('unused'), 0, undefined, false);
    assert.equal(result.completed, false); assert.equal(calls, '');
  });
});

test('OS inventory requires a successful guard and accepts only fixed live-session calls', async () => {
  await scope(async base => {
    const recorder = sessionRecorder(); let retained!: LimaOsProbeCapability;
    const result = await recorder.run(await osMockTool(base), async cap => {
      retained = cap; const before = recorder.events.length;
      await assert.rejects(cap.inventory());
      await assert.rejects((cap.inventory as (...args: unknown[]) => Promise<unknown>)('extra-command'));
      assert.equal(recorder.events.length, before);
      await cap.probe(); const ready = recorder.events.length;
      await assert.rejects((cap.inventory as (...args: unknown[]) => Promise<unknown>)('/etc/passwd'));
      assert.equal(recorder.events.length, ready); const answer = await cap.inventory();
      assert.equal(answer.status, 'observed'); assert.equal(answer.backendVerified, false);
      assert.deepEqual(answer.os, { id: 'ubuntu', version: '24.04', arch: 'aarch64' });
      assert.deepEqual(answer.packages.map(row => row.name), inventoryNames);
      assert.deepEqual(answer.packages[18], { name: 'docker-ce', state: 'missing', version: null });
      assert.ok(Object.isFrozen(answer)); assert.ok(Object.isFrozen(answer.packages));
    });
    const job = recorder.events.find(row => row.args.at(-1)!.includes('wakeio-os-inventory/v1'))!;
    assert.ok(job); assert.deepEqual(job.args.slice(2, 4), ['--workdir=/', '--shell=/bin/bash']);
    assert.deepEqual(job.args.slice(7, -1), ['-n', '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
      'LC_ALL=C', '/bin/sh', '-c']);
    assert.doesNotMatch(job.args.at(-1)!, /source |eval|apt-get|apt update|hostname|credential|\/usr\/bin\/id/);
    assert.equal(result.guestPrerequisitesObserved, true); assert.equal(result.verified, false);
    assert.equal(result.cleanup?.confirmed, true);
    const before = recorder.events.length; await assert.rejects(retained.inventory());
    assert.equal(recorder.events.length, before);
  });
});
test('inventory validates order, count, versions, release and architecture without raw data', async () => {
  const valid = inventoryWire(), rows = valid.split('\n');
  const invalid = [valid.replace('dbus-user-session', 'uidmap'), valid + 'extra\n', valid.slice(0, -1),
    valid.replace('1.0+synthetic', '1.0\r'), valid.replace('aarch64', 'x86_64'),
    valid.replace('ubuntu', 'debian'), valid.replace('installed', 'unknown-state'),
    valid.replace('1.0+synthetic', '1'.repeat(129)), valid.replace('end\t22', 'end\t21'),
    rows.slice(0, -3).join('\n') + '\n', 'x'.repeat(16385)];
  await scope(async base => {
    let stdout = valid, timedOut = false;
    const run = createLimaOsSessionRunner(async (executable, args, config) => {
      const result = await runRuntimeProcess(executable, args, config);
      if (!args.at(-1)!.includes('wakeio-os-inventory/v1')) return result;
      assert.equal(config.timeoutMs, 5000); assert.equal(config.maxOutputBytes, 16384);
      return { ...result, stdout, completed: !timedOut, timedOut };
    });
    const result = await run(await osMockTool(base), async cap => {
      await cap.probe();
      for (const raw of invalid) {
        stdout = raw; const answer = await cap.inventory();
        assert.equal(answer.status, 'unknown'); assert.equal(answer.reason, 'invalid_inventory');
        assert.equal(answer.os, null); assert.deepEqual(answer.packages, []);
      }
      stdout = ''; timedOut = true;
      assert.equal((await cap.inventory()).reason, 'inventory_unavailable');
    });
    assert.equal(result.phase, 'callback_completed');
    assert.equal(result.cleanup?.confirmed, true); assert.equal(result.verified, false);
  });
});
test('concurrent inventory starts no new I/O; abort drains the active read and closes authority', async () => {
  await scope(async base => {
    const recorder = sessionRecorder(), controller = new AbortController();
    const options = { ...await osMockTool(base, 'session-inventory-hang'), signal: controller.signal };
    let retained!: LimaOsProbeCapability, answer: Awaited<ReturnType<LimaOsProbeCapability['inventory']>> | undefined;
    const result = await recorder.run(options, async cap => {
      retained = cap; await cap.probe(); const pending = cap.inventory();
      await waitForOwnedFile(base, 'inventory.started'); const before = recorder.events.length;
      await assert.rejects(cap.inventory()); assert.equal(recorder.events.length, before);
      controller.abort(); answer = await pending;
    });
    assert.equal(result.phase, 'failed'); assert.equal(result.cleanup?.confirmed, true);
    assert.equal(answer?.status, 'unknown'); assert.equal(answer?.backendVerified, false);
    await assert.rejects(retained.inventory());
    const read = recorder.events.find(row => row.args.at(-1)!.includes('wakeio-os-inventory/v1'))!;
    assert.equal(read.result.cancelled, true); assert.equal(read.result.closeConfirmed, true);
  });
});
test('a failed fixed guard never grants inventory authority and inventory identity drift stays unknown', async () => {
  await scope(async base => {
    const recorder = sessionRecorder();
    const result = await recorder.run(await osMockTool(base, 'session-probe-fail'), async cap => {
      assert.equal((await cap.probe()).observed, false); const before = recorder.events.length;
      await assert.rejects(cap.inventory()); assert.equal(recorder.events.length, before);
    });
    assert.equal(result.phase, 'callback_completed');
    assert.equal(result.guestPrerequisitesObserved, false); assert.equal(result.cleanup?.confirmed, true);
  });
  await scope(async base => {
    let inventory: Awaited<ReturnType<LimaOsProbeCapability['inventory']>> | undefined;
    const run = createLimaOsSessionRunner(async (executable, args, config) => {
      const result = await runRuntimeProcess(executable, args, config);
      if (args.at(-1)!.includes('wakeio-os-inventory/v1')) {
        await writeFile(join(config.home, 'rootfs.img'), 'changed synthetic identity');
      }
      return result;
    });
    const result = await run(await osMockTool(base), async cap => {
      await cap.probe(); inventory = await cap.inventory();
    });
    assert.equal(result.phase, 'failed'); assert.equal(result.cleanup?.confirmed, false);
    assert.equal(inventory?.status, 'unknown'); assert.equal(inventory?.reason, 'identity_unknown');
    assert.ok(result.pendingHome);
  });
});
test('fixed inventory queries only its allowlist and distinguishes missing packages from errors', async () => {
  await scope(async base => {
    let captured = '';
    const run = createLimaOsSessionRunner(async (executable, args, config) => {
      if (args.at(-1)!.includes('wakeio-os-inventory/v1')) captured = args.at(-1)!;
      return runRuntimeProcess(executable, args, config);
    });
    await run(await osMockTool(base), async cap => { await cap.probe(); await cap.inventory(); });
    assert.ok(captured);
    const mock = join(base, 'owned-dpkg-query');
    await writeFile(mock, `#!${process.execPath}
const a=process.argv.slice(2),allowed=${JSON.stringify(inventoryNames)};
if(a.length!==4||a[0]!=='-W'||a[2]!=='--'||!allowed.includes(a[3]))process.exit(9);
const absent=a[3].startsWith('docker')||a[3]==='containerd.io';
if(absent){process.stderr.write('dpkg-query: no packages found matching '+a[3]+'\\n');process.exitCode=1;}
else process.stdout.write('installed\\t1.0+synthetic\\n');
`, { mode: 0o700 });
    const script = captured.replaceAll('/usr/bin/dpkg-query', mock).replaceAll('/usr/bin/awk', 'owned_release')
      .replaceAll('/usr/bin/uname', 'owned_arch');
    assert.doesNotMatch(script, /\/usr\/bin\/(?:dpkg-query|awk|uname)/);
    const prefix = 'owned_release() { return 0; }\nowned_arch() { printf "aarch64\\n"; }\n';
    const options = { cwd: base, home: base, timeoutMs: 5000, deadlineAt: Date.now() + 10000, maxOutputBytes: 16384 };
    const good = await runRuntimeProcess('/bin/sh', ['-c', prefix + script], options);
    assert.equal(good.completed, true); assert.equal(good.stdout, inventoryWire());
    await writeFile(mock, `#!${process.execPath}
process.stderr.write('dpkg-query: no packages found matching uidmap\\n');process.exitCode=2;
`, { mode: 0o700 });
    const bad = await runRuntimeProcess('/bin/sh', ['-c', prefix + script], options);
    assert.equal(bad.completed, false); assert.equal(bad.exitCode, 125);
  });
});
