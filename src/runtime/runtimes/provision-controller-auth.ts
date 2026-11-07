import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { snapshotJsonData } from '../../json-snapshot.js';
import { provisionRecord, requireProvision } from './provision-types.js';

export interface GuestAuthentication {
  readonly boot: string;
  readonly helper: string;
  readonly key: string;
}

export function guestChallenge(): string { return randomBytes(32).toString('hex'); }

/** The bootstrap channel supplies no admin authority. Its MAC pins the key used by subsequent strict SSH. */
export function authenticateGuest(text: string, expected: Readonly<{
  nonce: string; challenge: string; helper: string;
}>): GuestAuthentication {
  requireProvision(Buffer.byteLength(text) <= 8192, 'guest_identity_bound');
  const frame = provisionRecord(snapshotJsonData(JSON.parse(text)));
  requireProvision(Object.keys(frame).sort().join(',') === 'mac,payload', 'guest_identity_fields');
  const payload = provisionRecord(frame.payload);
  requireProvision(Object.keys(payload).sort().join(',') === 'boot,challenge,helper,key'
    && payload.challenge === expected.challenge && payload.helper === expected.helper, 'guest_identity_binding');
  const { boot, helper, key } = payload;
  requireProvision(typeof boot === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(boot)
    && typeof helper === 'string' && /^[a-f0-9]{64}$/.test(helper)
    && typeof key === 'string' && /^ssh-ed25519 [A-Za-z0-9+/=]{60,128}$/.test(key), 'guest_identity_fields');
  const canonical = JSON.stringify({ boot, challenge: expected.challenge, helper, key });
  requireProvision(typeof frame.mac === 'string' && /^[a-f0-9]{64}$/.test(frame.mac), 'guest_identity_mac');
  const mac = createHmac('sha256', Buffer.from(expected.nonce, 'hex')).update(canonical).digest();
  requireProvision(timingSafeEqual(mac, Buffer.from(frame.mac, 'hex')), 'guest_identity_mac');
  return Object.freeze({ boot, helper, key });
}

export function sshArgv(guest: Readonly<{
  knownHosts: string; name: string; key: string; port: number;
}>, argv: readonly string[]): readonly string[] {
  return ['-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
    '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
    '-o', 'UserKnownHostsFile=' + guest.knownHosts, '-o', 'HostKeyAlias=' + guest.name,
    '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-i', guest.key,
    '-p', String(guest.port), 'wakeio-admin@127.0.0.1',
    '/usr/bin/sudo', '-n', '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
    ...argv];
}
