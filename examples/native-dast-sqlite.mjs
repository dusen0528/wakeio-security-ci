import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { DatabaseSync } from 'node:sqlite';
import { gzipSync } from 'node:zlib';

/** Real in-memory SQLite, owned loopback target. Never starts without an explicit test call. */
export async function startNativeDastSqlite(mode = 'vulnerable', tls = undefined) {
  let activeMode = mode;
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL); INSERT INTO items VALUES (1, \'owned\');');
  const requests = [];
  let notifyFirstRequest;
  const firstRequest = new Promise(resolve => { notifyFirstRequest = resolve; });
  const serve = (request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    requests.push({ method: request.method, path: url.pathname, id: url.searchParams.get('id') });
    if (requests.length === 1) notifyFirstRequest();
    if (request.method !== 'GET' || url.pathname !== '/items') { response.writeHead(404); response.end(); return; }
    if (activeMode === 'redirect') { response.writeHead(302, { location: 'http://example.test/' }); response.end(); return; }
    if (activeMode === 'server-error') { response.writeHead(500, { 'content-type': 'application/json' }); response.end('{"count":0}'); return; }
    if (activeMode === 'malformed') { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{bad json'); return; }
    if (activeMode === 'slow') { setTimeout(() => { if (!response.destroyed) { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{"count":1}'); } }, 250); return; }
    if (activeMode === 'echo') { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ count: url.searchParams.get('id') })); return; }
    let count;
    const id = url.searchParams.get('id');
    try {
      if (activeMode === 'bound') count = db.prepare('SELECT COUNT(*) AS count FROM items WHERE id = ?').get(id).count;
      else if (activeMode === 'ignored') count = db.prepare('SELECT COUNT(*) AS count FROM items WHERE id = 1').get().count;
      else count = db.prepare(`SELECT COUNT(*) AS count FROM items WHERE id = ${id}`).get().count;
    } catch { response.writeHead(500, { 'content-type': 'application/json' }); response.end('{"error":"query"}'); return; }
    if (activeMode === 'drift' && requests.length >= 4 && !String(id).includes('AND')) count = 0;
    if (activeMode === 'large-exact' || activeMode === 'large-over' || activeMode === 'large-compressed') {
      const length = 128 * 1024 + (activeMode === 'large-exact' ? 0 : 1);
      const prefix = JSON.stringify({ count, padding: '' });
      const body = JSON.stringify({ count, padding: 'x'.repeat(length - Buffer.byteLength(prefix)) });
      if (activeMode === 'large-compressed') {
        response.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' });
        response.end(gzipSync(body));
      } else {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(body);
      }
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ count }));
  };
  const server = tls ? createHttpsServer(tls, serve) : createServer(serve);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const origin = `${tls ? 'https' : 'http'}://127.0.0.1:${address.port}`;
  return { origin, url: `${origin}/items?id=1`, requests, firstRequest,
    setMode(nextMode) { activeMode = nextMode; }, async close() {
    await new Promise(resolve => server.close(resolve));
    db.close();
  } };
}
