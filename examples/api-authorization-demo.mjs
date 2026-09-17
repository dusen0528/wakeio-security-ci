// Explicitly started local fixture. All credentials and records are synthetic.
import { createServer } from 'node:http';

const vulnerable = process.argv.includes('--vulnerable');
if (process.argv.slice(2).some((arg) => arg !== '--vulnerable')) throw new Error('Use --vulnerable or no arguments');
const server = createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  if (req.method !== 'GET') {
    res.writeHead(405).end(JSON.stringify({ error: 'GET required' }));
    return;
  }
  const owner = req.headers.authorization === 'Bearer demo-owner';
  const other = req.headers.authorization === 'Bearer demo-other';
  const expired = req.headers.authorization === 'Bearer demo-expired';
  if (req.url === '/whoami') {
    if (owner) res.end(JSON.stringify({ userId: 'demo-owner', orgId: 'demo-org' }));
    else if (other) res.end(JSON.stringify({ userId: 'demo-other', orgId: 'demo-org' }));
    else res.writeHead(401).end(JSON.stringify({ error: expired ? 'token-expired' : 'unauthorized' }));
    return;
  }
  if (req.url !== '/documents/demo-owner-report') {
    res.writeHead(404).end(JSON.stringify({ error: 'missing fixture' }));
    return;
  }
  if (owner || (vulnerable && other)) {
    res.end(JSON.stringify({ id: 'demo-owner-report', canary: 'synthetic-private-canary', contents: 'Synthetic private fixture record' }));
  } else {
    res.writeHead(req.headers.authorization ? (expired ? 401 : 403) : 401).end(JSON.stringify({ error: expired ? 'token-expired' : 'denied' }));
  }
});
server.listen(8877, '127.0.0.1', () => {
  process.stdout.write(`Local API fixture: http://127.0.0.1:8877 (${vulnerable ? 'vulnerable' : 'fixed'})\n`);
});
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  server.closeAllConnections();
  server.close();
});
