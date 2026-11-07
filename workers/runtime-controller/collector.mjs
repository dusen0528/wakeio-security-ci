import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { Worker } from 'node:worker_threads';

const read = path => readFileSync(path, 'utf8').trim();
const status = Object.fromEntries(read('/proc/self/status').split('\n').map(line => {
  const colon = line.indexOf(':');
  return [line.slice(0, colon), line.slice(colon + 1).trim()];
}));
const cpu = read('/sys/fs/cgroup/cpu.max').split(' ').map(Number);
const cpuStat = () => Object.fromEntries(read('/sys/fs/cgroup/cpu.stat').split('\n')
  .map(line => { const [key, value] = line.split(' '); return [key, Number(value)]; }));
const beforeCpu = cpuStat();
const workers = Array.from({ length: 4 }, () => new Worker(`
  const {parentPort}=require('node:worker_threads');
  const {pbkdf2Sync}=require('node:crypto');
  parentPort.once('message',()=>{pbkdf2Sync('owned','probe',1000000,32,'sha256');parentPort.close();});
  parentPort.postMessage('ready');
`, { eval: true }));
const ready = workers.map(worker => once(worker, 'message', { signal: AbortSignal.timeout(10000) }));
const exited = workers.map(worker => once(worker, 'exit', { signal: AbortSignal.timeout(10000) }));
await Promise.all(ready);
for (const worker of workers) worker.postMessage('start');
await Promise.all(exited);
const afterCpu = cpuStat();
const children = [];
let pidsEnforced = false;
try {
  for (let index = 0; index < 300; index++) {
    const child = spawn('/bin/cat', [], { stdio: ['pipe', 'ignore', 'ignore'], env: {} });
    const closed = new Promise(resolve => child.once('close', resolve));
    children.push({ child, closed });
    try { await once(child, 'spawn', { signal: AbortSignal.timeout(10000) }); }
    catch (error) {
      if (!(error instanceof Error) || error.code !== 'EAGAIN') throw error;
      pidsEnforced = true;
      break;
    }
  }
} finally {
  for (const { child } of children) child.stdin.end();
  await Promise.all(children.map(item => item.closed));
}
const root = read('/proc/self/mountinfo').split('\n').find(line => line.split(' ')[4] === '/');
process.stdout.write(JSON.stringify({
  artifactSha256: createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex'),
  targetUid: process.getuid(), effectiveCaps: status.CapEff, seccompMode: Number(status.Seccomp),
  permittedCaps: status.CapPrm, ambientCaps: status.CapAmb, inheritedCaps: status.CapInh,
  noNewPrivileges: status.NoNewPrivs === '1', readOnlyRootfs: root?.split(' ')[5].split(',').includes('ro') === true,
  cpuQuota: cpu[0], cpuPeriod: cpu[1], memoryMax: Number(read('/sys/fs/cgroup/memory.max')),
  pidsMax: Number(read('/sys/fs/cgroup/pids.max')),
  cpuEnforced: afterCpu.nr_throttled > beforeCpu.nr_throttled,
  pidsEnforced: pidsEnforced && /max [1-9][0-9]*/.test(read('/sys/fs/cgroup/pids.events')),
  secretEnvironmentEmpty: Object.keys(process.env).every(name =>
    ['PATH', 'HOSTNAME', 'HOME', 'NODE_VERSION', 'YARN_VERSION'].includes(name)),
}) + '\n');
