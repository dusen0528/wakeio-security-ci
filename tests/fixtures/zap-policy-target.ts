import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { DatabaseSync } from 'node:sqlite';
import type { ZapPolicy } from '../../src/zap-policy.js';

/** Owned disposable SQLite target. Never records credentials or attack payloads. */
export async function zapPolicyTarget(options: { tls?: { key: Buffer; cert: Buffer }; ignoreAuth?: boolean; expire?: boolean } = {}) {
  const authorization = 'Bearer owned-zap-test-only';
  const seen: Array<{ method: string; path: string; authenticated: boolean; cookie: boolean; at: number }> = [];
  const db = new DatabaseSync(':memory:');
  db.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT); INSERT INTO items VALUES(1,'first'),(2,'second');");
  let identities = 0;
  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url!, 'http://fixture').pathname, authenticated = req.headers.authorization === authorization;
    seen.push({ method: req.method!, path, authenticated, cookie: !!req.headers.cookie, at: Date.now() });
    if (!options.ignoreAuth && (!authenticated || options.expire && identities >= 1 && path === '/identity')) { res.writeHead(401); res.end(); return; }
    if (path === '/identity') { identities++; res.setHeader('content-type', 'application/json'); res.end('{"principal":"owner"}'); return; }
    if (path === '/xss' || path === '/xss-fixed') {
      const q = new URL(req.url!, 'http://fixture').searchParams.get('q') ?? '';
      res.setHeader('content-type', 'text/html');
      res.end(`<html><head><title>Owned</title></head><body><p>${path === '/xss' ? q : q.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`)}</p></body></html>`); return;
    }
    if (path === '/native') {
      const id = new URL(req.url!, 'http://fixture').searchParams.get('id') ?? '1';
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(db.prepare(`SELECT COUNT(*) AS count FROM items WHERE id=${id}`).get())); return;
    }
    let id: unknown = new URL(req.url!, 'http://fixture').searchParams.get('id') ?? '1';
    if (req.method === 'POST') { const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk)); id = JSON.parse(Buffer.concat(chunks).toString()).id; }
    try {
      const rows = path.endsWith('-fixed') ? db.prepare('SELECT name FROM items WHERE id=?').all(String(id)) : db.prepare(`SELECT name FROM items WHERE id=${id}`).all();
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(rows));
    } catch (error) { res.writeHead(500, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: (error as Error).message })); }
  };
  const server = options.tls ? createHttpsServer(options.tls, (req, res) => { void handler(req, res); }) : createServer((req, res) => { void handler(req, res); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `${options.tls ? 'https' : 'http'}://127.0.0.1:${(server.address() as { port: number }).port}`;
  const policy: ZapPolicy = { version: 1, kind: 'zap-active', origin, authentication: { authorizationEnv: 'WAKEIO_ZAP_TEST_AUTH',
    identity: { path: '/identity', status: 200, jsonPointer: '/principal', equals: 'owner' } }, requests: [
    { method: 'GET', path: '/xss?q=hello' }, { method: 'GET', path: '/xss-fixed?q=hello' },
    { method: 'GET', path: '/sql?id=1' }, { method: 'GET', path: '/sql-fixed?id=1' },
    { method: 'POST', path: '/json', body: { id: '1' } }, { method: 'POST', path: '/json-fixed', body: { id: '1' } },
  ] };
  return { origin, authorization, env: { WAKEIO_ZAP_TEST_AUTH: authorization }, policy, seen,
    close: () => new Promise<void>(resolve => server.close(() => { db.close(); resolve(); })) };
}
