// Independent author-owned runtime fixture. Root alone executes this module.
// No target application source, package install, model, or external connection.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

export async function startPostJsonSqlite(options = {}) {
  let mode = options.mode ?? 'vulnerable', identities = 0, posts = 0, closed = false;
  const authorization = options.authorization ?? `Bearer owned-post-${randomBytes(16).toString('hex')}`;
  const principal = options.principal ?? 'owned-post-user';
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE owned_rows(id INTEGER PRIMARY KEY, label TEXT NOT NULL); INSERT INTO owned_rows VALUES(1,\'owned-first\'),(2,\'owned-second\');');
  const readState = () => db.prepare('SELECT id,label FROM owned_rows ORDER BY id').all().map(row => ({ id: row.id, label: row.label }));
  const initialState = readState(), requests = [], queryLog = [], sockets = new Set(); let finalState;
  let firstResolve, postResolve;
  const firstRequest = new Promise(resolve => { firstResolve = resolve; });
  const firstPost = new Promise(resolve => { postResolve = resolve; });
  const server = createServer((req, res) => {
    const record = { ordinal: requests.length, method: req.method, path: req.url, authorization: req.headers.authorization ?? null,
      rawBody: '', body: null, bodyType: null, requestBytes: 0, contentType: req.headers['content-type'] ?? null,
      status: null, count: null, stateBefore: readState(), stateAfter: null };
    requests.push(record); firstResolve();
    const json = (status, value) => {
      record.status = status; const bytes = JSON.stringify(value); record.responseBytes = Buffer.byteLength(bytes);
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(bytes);
    };
    void (async () => {
      if (req.headers.authorization !== authorization) return json(401, { denied: true });
      if (req.method === 'GET' && req.url === '/whoami') {
        identities++;
        return json(200, { principal: mode === 'identity-before' && identities === 1 || mode === 'identity-after' && identities === 2 ? 'owned-wrong-user' : principal });
      }
      if (req.url === '/redirected') return json(200, { count: 2, forbiddenFollow: true });
      if (req.method !== 'POST' || req.url !== '/search') return json(405, { denied: true });
      posts++;
      const chunks = []; let bytes = 0;
      for await (const chunk of req) { bytes += chunk.length; if (bytes > 8192) throw Error('owned-body-bound'); chunks.push(Buffer.from(chunk)); }
      record.rawBody = Buffer.concat(chunks).toString('utf8'); record.body = JSON.parse(record.rawBody);
      record.requestBytes = bytes; record.bodyType = record.body === null ? 'null' : Array.isArray(record.body) ? 'array' : typeof record.body;
      chunks.forEach(chunk => chunk.fill(0));
      const minId = record.body.minId;
      if (typeof minId !== 'string') { postResolve(); return json(400, { denied: true }); }
      if (mode === 'all-deny') { postResolve(); return json(403, { denied: true }); }
      if (mode === 'validation-reject' && !/^(?:0|[1-9][0-9]{0,8})$/.test(minId)) { postResolve(); return json(400, { denied: true }); }
      if (mode === 'redirect') { postResolve(); record.status = 307; res.writeHead(307, { location: '/redirected' }); res.end(); return; }
      if (mode === 'constant') { record.count = 2; record.stateAfter = readState(); postResolve(); return json(200, { count: 2 }); }
      if (mode === 'malformed') { postResolve(); record.status = 200; res.writeHead(200, { 'content-type': 'application/json' }); res.end('{'); return; }
      if (mode === 'echo') { postResolve(); return json(200, { count: minId }); }
      const bound = mode === 'bound' || mode === 'validation-reject';
      const sql = mode === 'field-ignored' ? 'SELECT count(*) AS count FROM owned_rows WHERE id >= 1'
        : bound ? 'SELECT count(*) AS count FROM owned_rows WHERE id >= ?' : `SELECT count(*) AS count FROM owned_rows WHERE id >= ${minId}`;
      const row = bound ? db.prepare(sql).get(minId) : db.prepare(sql).get();
      record.count = row.count; record.stateAfter = readState();
      queryLog.push({ requestOrdinal: record.ordinal, sql, bindings: bound ? [minId] : [], count: row.count,
        stateBefore: record.stateBefore, stateAfter: record.stateAfter });
      postResolve();
      if (mode === 'drop-response') { req.socket.destroy(); return; }
      if (mode === 'hang') return;
      if (mode === 'large-over') return json(200, { count: row.count, padding: 'x'.repeat(128 * 1024) });
      if (mode === 'large-run') return json(200, { count: row.count, padding: 'x'.repeat(110 * 1024) });
      return json(200, { count: row.count });
    })().catch(() => { postResolve(); if (!res.headersSent && !res.destroyed) json(500, { ownedFailure: true }); else res.destroy(); });
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const address = server.address();
  return { origin: `http://127.0.0.1:${address.port}`, url: `http://127.0.0.1:${address.port}/search`, authorization, principal,
    requests, queryLog, firstRequest, firstPost, initialState, state: readState, setMode(value) { mode = value; },
    get socketCount() { return sockets.size; },
    get stats() { const currentRows = closed ? finalState : readState(); return { httpRequests: requests.length, postRequests: posts,
      identityRequests: identities, sqlQueries: queryLog.length, openSockets: sockets.size, initialRows: initialState, currentRows,
      stateUnchanged: JSON.stringify(initialState) === JSON.stringify(currentRows) }; },
    async close() { if (closed) return; closed = true; server.closeAllConnections(); for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(() => resolve())); finalState = readState(); db.close(); },
  };
}
