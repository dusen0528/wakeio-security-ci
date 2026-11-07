import { availableParallelism, freemem } from 'node:os';
import { statfs } from 'node:fs/promises';
import { join } from 'node:path';
import { ProvisionDirectory, ProvisionFile } from './provision-controller-files.js';
import { ProvisionProcess } from './provision-controller-process.js';
import type { ProvisionOwner } from './provision-controller-owner.js';
import { requireProvision } from './provision-types.js';

export async function provisionHostCapacity(): Promise<void> {
  requireProvision(process.platform === 'darwin' && process.arch === 'arm64', 'platform_unavailable');
  const disk = await statfs('/private/tmp');
  requireProvision(availableParallelism() >= 6 && freemem() >= 9 * 1024 ** 3
    && disk.bavail * disk.bsize >= 43 * 1024 ** 3, 'host_capacity_unavailable');
}

/** Only installed platform binaries; no PATH fallback, download, re-signing or policy modification. */
export async function provisionPlatformTools(root: ProvisionDirectory, owner: ProvisionOwner):
Promise<readonly ProvisionFile[]> {
  const files: ProvisionFile[] = [];
  for (const [index, path] of ['/usr/bin/ssh', '/usr/bin/ssh-keygen', '/usr/bin/python3'].entries()) {
    owner.check();
    const file = await ProvisionFile.open(path, 0);
    try {
      owner.own({ identity: 'platform-file:' + path, drained: Promise.resolve(),
        async remove() { await file.close(); return true; } });
    } catch (error) { await file.close(); throw error; }
    files.push(file);
    const temporary = await root.directory('platform-' + index);
    const verify = new ProvisionProcess({
      executable: '/usr/bin/codesign', argv: ['--verify', '--strict', path],
      home: root.root, limaHome: join(root.root, '.lima'), temporary,
    }, owner.signal);
    owner.own({ identity: 'platform-verifier:' + path, stop: () => verify.stop(), drained: verify.drain(),
      remove: async () => (await verify.closed).groupAbsent });
    const failed = () => {
      owner.revoke('process_failed');
      verify.stop();
    };
    verify.failureSignal.addEventListener('abort', failed, { once: true });
    if (verify.failureSignal.aborted) failed();
    await verify.output();
    await file.check();
  }
  return Object.freeze(files);
}
