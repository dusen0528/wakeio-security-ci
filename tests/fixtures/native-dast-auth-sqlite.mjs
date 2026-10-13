import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';

/** Owned protected SQLite endpoint. Only an explicit test call starts a server. */
export async function startAuthenticatedSqlite(options = {}) {
  let mode = options.mode ?? 'vulnerable';
  let token = options.token ?? 'Bearer owned-native-secret-739c';
  let principal = options.principal ?? 'owned-principal-739c';
  let identityCount = 0;
  const requests = [];
  const db = new DatabaseSync(':memory:');
  db.exec("CREATE TABLE items (id INTEGER PRIMARY KEY); INSERT INTO items VALUES (1);");
  let firstResolve;
  const firstRequest = new Promise(resolve => { firstResolve = resolve; });
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    requests.push({ path: url.pathname, id: url.searchParams.get('id'), authorization: request.headers.authorization });
    if (requests.length === 1) firstResolve();
    const json = (status, body) => {
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (request.method !== 'GET' || request.headers.authorization !== token) return json(401, { error: 'owned-auth-required' });
    if (url.pathname === '/identity') {
      identityCount++;
      if (mode === 'redirect') {
        response.writeHead(302, { location: options.redirect ?? '/identity-redirected' }); response.end(); return;
      }
      if (mode === 'slow-identity') {
        setTimeout(() => { if (!response.destroyed) json(200, { principal }); }, 250); return;
      }
      if (identityCount > 1 && mode === 'expire-after') return json(401, { error: 'owned-expired' });
      return json(200, { principal: identityCount > 1 && mode === 'change-after' ? `${principal}-changed` : principal });
    }
    if (url.pathname !== '/items') return json(404, { error: 'owned-not-found' });
    const id = url.searchParams.get('id');
    try {
      const result = mode === 'bound'
        ? db.prepare('SELECT COUNT(*) AS count FROM items WHERE id = ?').get(id)
        : db.prepare(`SELECT COUNT(*) AS count FROM items WHERE id = ${id}`).get();
      return json(200, { count: result.count });
    } catch { return json(500, { error: 'owned-query-error' }); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, url: `${origin}/items?id=1`, requests, firstRequest,
    setToken(value) { token = value; }, setMode(value) { mode = value; }, setPrincipal(value) { principal = value; },
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); } };
}
