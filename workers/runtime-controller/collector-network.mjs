import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { request } from 'node:https';

const config = JSON.parse(readFileSync('/controller/endpoints.json', 'utf8'));
if (!Array.isArray(config.denied) || config.denied.length < 4 || config.denied.length > 16) {
  throw new TypeError('witness_configuration');
}
async function denied(endpoint) {
  const socket = connect({ host: endpoint.host, port: endpoint.port,
    signal: AbortSignal.timeout(3000) });
  return new Promise(resolve => {
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', error => {
      // Connection refusal or a missing server does not prove isolation.
      resolve(['EACCES', 'EPERM', 'ENETUNREACH', 'EHOSTUNREACH'].includes(error.code));
    });
  });
}
const blocked = [];
for (const endpoint of config.denied) blocked.push(await denied(endpoint));
let repository = false;
if (config.phase === 'BUILD') {
  repository = await new Promise(resolve => {
    const call = request({
      host: 'wakeio-maven', port: 8443, method: 'HEAD',
      path: '/maven2/org/apache/maven/maven/3.9.9/maven-3.9.9.pom',
      ca: readFileSync('/controller/mirror.crt'), servername: 'wakeio-maven',
      headers: { host: 'wakeio-maven:8443' }, rejectUnauthorized: true,
      minVersion: 'TLSv1.3', agent: false, signal: AbortSignal.timeout(15000),
    }, response => { repository = response.statusCode === 200; response.resume(); });
    call.once('error', () => resolve(false));
    call.once('close', () => resolve(repository));
    call.end();
  });
}
process.stdout.write(JSON.stringify({ phase: config.phase, repository, blocked }) + '\n');
