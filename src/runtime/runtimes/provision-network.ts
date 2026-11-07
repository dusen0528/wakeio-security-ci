import { isIP } from 'node:net';
import { normaliseMavenRequest } from '../builders/build-policy.js';
import { requireProvision, unreachable } from './provision-types.js';

export type ProvisionNetworkPhase = 'PREPARE' | 'BUILD' | 'RUNTIME';
export interface MavenMirror {
  readonly endpoint: string;
  readonly certificateSha256: string;
  readonly network: string;
}

/** Used both to qualify the one mirror and to construct T6's later Maven settings. */
export const MAVEN_WITNESS = normaliseMavenRequest({
  method: 'HEAD', scheme: 'https', host: 'repo.maven.apache.org', port: 443,
  hostHeader: 'repo.maven.apache.org', path: '/maven2/org/apache/maven/maven/3.9.9/maven-3.9.9.pom',
});

export function publicProvisionAddress(address: string): boolean {
  if (isIP(address) !== 4) return false;
  const parts = address.split('.').map(Number);
  const first = parts[0], second = parts[1];
  if (first === undefined || second === undefined) return false;
  return first !== 0 && first !== 10 && first !== 127 && first < 224
    && !(first === 100 && second >= 64 && second <= 127)
    && !(first === 169 && second === 254) && !(first === 172 && second >= 16 && second <= 31)
    && !(first === 192 && (second === 168 || second === 0 || second === 2))
    && !(first === 198 && (second === 18 || second === 19 || second === 51))
    && !(first === 203 && second === 0);
}

/** Compile only reviewed phase transitions; no target-selected firewall text. */
export function provisionNetworkTransition(before: ProvisionNetworkPhase, after: ProvisionNetworkPhase): void {
  switch (before) {
    case 'PREPARE':
      requireProvision(after === 'BUILD', 'network_phase_invalid');
      return;
    case 'BUILD':
      requireProvision(after === 'RUNTIME', 'network_phase_invalid');
      return;
    case 'RUNTIME': throw new TypeError('network_phase_terminal');
    default: return unreachable(before);
  }
}
