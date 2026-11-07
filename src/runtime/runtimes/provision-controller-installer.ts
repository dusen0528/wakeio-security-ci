import { consumeInstallOperation, installInvocation, type InstallObservation } from './provision-install.js';
import type { ProvisionVm } from './provision-controller-vm.js';
import { publicProvisionAddress } from './provision-network.js';
import { provisionRecord, requireProvision } from './provision-types.js';

/** Compose the finalized B1/B2/N1 supervisor without altering its private protocol.
 * The local close promises remain held by the VM owner even when result rejects early.
 */
export async function prepareInstallerEnvelope(vm: ProvisionVm, invocation: ReturnType<typeof installInvocation>) {
  const witness = await vm.admin(['/usr/bin/python3', '-I', '-B',
    '/usr/local/lib/wakeio-controller/bootstrap_prepare.py', invocation.unit]);
  const hello = new Promise<readonly string[]>((resolve, reject) => {
    let text = '';
    witness.child.stdout.on('data', (chunk: Buffer) => {
      text += chunk.toString('utf8');
      try {
        requireProvision(text.length <= 4096, 'prepare_witness_bound');
        if (!text.endsWith('\n')) return;
        const frame = provisionRecord(JSON.parse(text));
        requireProvision(Object.keys(frame).join(',') === 'addresses' && Array.isArray(frame.addresses)
          && frame.addresses.length > 0 && frame.addresses.length <= 64, 'prepare_witness_protocol');
        const addresses: string[] = [];
        for (const value of frame.addresses) {
          requireProvision(typeof value === 'string' && publicProvisionAddress(value), 'prepare_witness_address');
          addresses.push(value);
        }
        resolve(addresses);
      } catch (error) { reject(error); }
    });
    void witness.closed.then(() => reject(new TypeError('prepare_witness_closed')));
  });
  witness.child.stdin.end();
  witness.child.stderr.resume();
  const addresses = await hello;
  const position = invocation.argv.indexOf('/usr/bin/python3');
  requireProvision(position > 0, 'installer_contract_changed');
  const argv = [...invocation.argv.slice(0, position), '--property=IPAddressDeny=any',
    '--property=IPAddressAllow=127.0.0.2', '--property=IPAddressAllow=::1',
    ...addresses.map(ip => '--property=IPAddressAllow=' + ip)];
  return { argv, witness };
}

export async function installProvisionGuest(vm: ProvisionVm): Promise<InstallObservation> {
  const invocation = installInvocation();
  const { argv, witness } = await prepareInstallerEnvelope(vm, invocation);
  const child = await vm.admin([...argv,
    '/usr/bin/python3', '-I', '-B', '/usr/local/lib/wakeio-controller/bootstrap_enforce.py']);
  // ProvisionProcess subscribed to real close synchronously at spawn, before this handoff.
  const operation = consumeInstallOperation(child.child, vm.owner.signal);
  const result = await operation.result;
  await operation.drained;
  await child.drain();
  await witness.drain();
  await confirmInstallerUnitDrained(vm, invocation.unit);
  return result;
}

export async function confirmInstallerUnitDrained(vm: ProvisionVm, unit: string): Promise<void> {
  const state = await vm.admin(['/usr/bin/systemctl', 'show', unit,
    '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup']);
  const observed = Object.fromEntries((await state.output()).trim().split('\n').map(line => line.split('=', 2)));
  requireProvision(observed.MainPID === '0' && observed.ActiveState === 'inactive'
    && observed.ControlGroup === '', 'installer_unit_drain_unconfirmed');
}
