import { createServer } from 'node:https';
import { request } from 'node:https';
import { readFileSync } from 'node:fs';
import { normaliseMavenRequest } from './runtime/builders/build-policy.js';

// These files are populated by the controller in a source-free immutable helper image.
const addresses = JSON.parse(readFileSync('/controller/upstream.json', 'utf8'));
if (!Array.isArray(addresses) || !addresses.length || addresses.length > 32
  || addresses.some(ip => typeof ip !== 'string' || !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip))) {
  throw new TypeError('mirror_addresses_invalid');
}
const sessions = new Set();
let active = 0;
const server = createServer({
  key: readFileSync('/controller/mirror.key'), cert: readFileSync('/controller/mirror.crt'),
  minVersion: 'TLSv1.3', maxHeaderSize: 8192, requestTimeout: 15000, headersTimeout: 5000,
}, (incoming, outgoing) => {
  if (active >= 8) { outgoing.writeHead(503).end(); return; }
  let policy;
  try {
    const hosts = incoming.rawHeaders.filter((_value, index) =>
      index % 2 === 0 && incoming.rawHeaders[index].toLowerCase() === 'host');
    if (hosts.length !== 1 || incoming.headers.host !== 'wakeio-maven:8443'
      || incoming.headers['transfer-encoding'] || incoming.headers['content-length']
      || incoming.headers.authorization || incoming.headers['proxy-authorization']) {
      throw new TypeError('mirror_request_invalid');
    }
    policy = normaliseMavenRequest({ method: incoming.method, scheme: 'https',
      host: 'repo.maven.apache.org', port: 443, hostHeader: 'repo.maven.apache.org', path: incoming.url });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    outgoing.writeHead(403).end();
    return;
  }
  active++;
  const signal = AbortSignal.timeout(15000);
  const upstream = request({
    host: policy.host, port: policy.port, path: policy.path, method: policy.method,
    servername: policy.host, minVersion: 'TLSv1.3', rejectUnauthorized: true,
    agent: false, signal, headers: { host: policy.host, 'accept-encoding': 'identity' },
    lookup: (_host, _options, done) => done(null, addresses[0], 4),
  }, response => {
    if (![200, 404].includes(response.statusCode)) {
      response.destroy();
      outgoing.writeHead(502).end();
      return;
    }
    let bytes = 0;
    outgoing.writeHead(response.statusCode, { 'content-type': 'application/octet-stream' });
    response.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 128 * 1024 * 1024) { upstream.destroy(); outgoing.destroy(); }
    });
    response.pipe(outgoing);
  });
  upstream.once('close', () => { active--; });
  upstream.once('error', error => {
    if (!(error instanceof Error)) throw error;
    if (!outgoing.headersSent) outgoing.writeHead(502);
    outgoing.end();
  });
  outgoing.once('close', () => upstream.destroy());
  upstream.end();
});
server.on('connection', socket => {
  sessions.add(socket);
  socket.once('close', () => sessions.delete(socket));
});
server.on('connect', (_request, socket) => socket.destroy());
server.on('upgrade', (_request, socket) => socket.destroy());
server.on('clientError', (_error, socket) => socket.destroy());
server.listen(8443, '0.0.0.0', () => process.stdout.write('MIRROR_READY\n'));
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  server.close();
  for (const socket of sessions) socket.destroy();
});
