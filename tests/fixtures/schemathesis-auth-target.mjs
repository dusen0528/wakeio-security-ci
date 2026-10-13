// Independent author-owned fixture, DATA ONLY until root explicitly executes it.
// No product imports, target packages, installation, external requests or model.
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { randomBytes } from 'node:crypto';

const MODES = new Set(['vulnerable', 'fixed', 'all-deny', 'ignored-credential', 'expired', 'drift',
  'normal-regression', 'denial-leak', 'redirect', 'drop', 'stream', 'oversize', 'cookie']);
export function ownedSchema() {
  return { openapi: '3.0.3', info: { title: 'Owned auth generation fixture', version: '1.0.0' },
    paths: { '/items/{id}': { get: { operationId: 'ownedReadItem',
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer', enum: [1, 2] } }],
      responses: { '200': { description: 'owned row', content: { 'application/json': { schema: {
        type: 'object', required: ['id', 'name', 'marker'], properties: {
          id: { type: 'integer' }, name: { type: 'string' }, marker: { type: 'string' } } } } } },
        '401': { description: 'unauthenticated', content: { 'application/json': { schema: {
          type: 'object', required: ['error'], properties: { error: { type: 'string' } } } } } },
        '403': { description: 'denied', content: { 'application/json': { schema: {
          type: 'object', required: ['error'], properties: { error: { type: 'string' } } } } } } } } },
      '/whoami': { get: { responses: { '200': { description: 'identity' } } } },
      '/never-selected': { get: { responses: { '200': { description: 'scope tripwire' } } } } } };
}
export function ownedAuthPolicy(origin, options = {}) {
  return { version: 1, kind: 'schemathesis-get-auth', baseUrl: origin + '/',
    authorizationEnv: options.authorizationEnv ?? 'OWNED_SCHEMATHESIS_AUTH',
    identity: { path: '/whoami', status: 200, jsonPointer: '/principal', equals: options.principal ?? 'owned-private-principal' },
    operations: [{ path: '/items/{id}', normal: { path: '/items/1', status: 200, jsonPointer: '/marker',
      equals: options.marker ?? 'owned-private-normal-marker' } }] };
}

export async function startSchemathesisAuthTarget(initialMode = 'vulnerable', options = {}) {
  if (!MODES.has(initialMode)) throw new Error('Invalid owned mode');
  let mode = initialMode, authorization = options.authorization ?? `Bearer owned-auth-${randomBytes(18).toString('hex')}`;
  let principal = options.principal ?? 'owned-private-principal';
  const marker = options.marker ?? 'owned-private-normal-marker';
  const initialRows = [{ id: 1, name: 'owned-row-one' }, { id: 2, name: 'owned-row-two' }];
  const rows = new Map(initialRows.map(row => [row.id, Object.freeze({ ...row })]));
  const requests = [], sockets = new Set(); let identityCount = 0, protectedCount = 0, id2Count = 0, closed = false;
  let resolveFirst, resolveGenerated;
  const firstRequest = new Promise(resolve => { resolveFirst = resolve; });
  const firstGenerated = new Promise(resolve => { resolveGenerated = resolve; });
  const handler = (req, res) => {
    const url = new URL(req.url ?? '/', 'http://owned.invalid');
    const matched = req.headers.authorization === authorization;
    const r = { ordinal: requests.length + 1, method: req.method, path: url.pathname, query: url.search,
      authorization: req.headers.authorization ?? null, cookie: req.headers.cookie ?? null,
      contentBytes: 0, status: null, credentialMatched: matched, principal: null,
      protectedHandler: false, id: null, branch: 'unselected', markerPresent: false, completed: false };
    requests.push(r); resolveFirst(r);
    req.on('data', chunk => { r.contentBytes += chunk.byteLength; });
    res.once('finish', () => { r.completed = true; });
    const json = (status, value, headers = {}) => {
      r.status = status; r.markerPresent = value?.marker === marker;
      const body = JSON.stringify(value);
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers });
      res.end(body);
    };
    if (req.method !== 'GET') { r.branch = 'wrong-method'; return json(405, { error: 'owned-method-denied' }); }
    if (url.pathname === '/whoami') {
      r.branch = 'identity'; identityCount++;
      if ((!matched && mode !== 'ignored-credential') || mode === 'expired') return json(401, { error: 'owned-auth-required' });
      r.principal = mode === 'drift' && identityCount > 1 ? 'owned-other-private-principal' : principal;
      return json(200, { principal: r.principal, privateBody: 'owned-private-identity-body' });
    }
    const match = /^\/items\/([12])$/.exec(url.pathname);
    if (!match) { r.branch = 'unselected'; return json(404, { error: 'owned-not-found' }); }
    r.id = Number(match[1]);
    if (!matched && mode !== 'ignored-credential') {
      r.branch = 'anonymous-denied';
      return json(mode === 'denial-leak' ? 403 : 401,
        mode === 'denial-leak' ? { error: 'owned-denied', marker } : { error: 'owned-auth-required' });
    }
    if (mode === 'all-deny' || mode === 'expired') { r.branch = 'authenticated-denied'; return json(403, { error: 'owned-denied' }); }
    r.protectedHandler = true; r.principal = principal; protectedCount++;
    if (r.id === 2) { id2Count++; resolveGenerated(r); }
    r.branch = r.id === 1 ? 'normal-row' : 'generated-row';
    const row = rows.get(r.id);
    if (r.id === 1 && mode === 'normal-regression') return json(200, { ...row, marker: 'owned-wrong-private-marker' });
    if (r.id === 2) {
      if (mode === 'vulnerable' || mode === 'drift') { r.branch = 'id-two-failure'; return json(500, { error: 'owned-private-failure-body' }); }
      if (mode === 'drop') { r.branch = 'dropped-response'; req.socket.destroy(); return; }
      if (mode === 'redirect') { r.branch = 'redirect'; r.status = 302;
        res.writeHead(302, { location: options.redirectLocation ?? '/never-selected' }); res.end(); return; }
      if (mode === 'stream') { r.branch = 'stream'; r.status = 200;
        res.writeHead(200, { 'content-type': 'application/json' }); res.write('{"id":2,'); return; }
      if (mode === 'oversize') return json(200, { ...row, marker, padding: 'x'.repeat(options.oversizeBytes ?? 262144) });
    }
    return json(200, { ...row, marker }, mode === 'cookie' ? { 'set-cookie': 'owned-cookie=private-cookie-canary; Path=/' } : {});
  };
  const server = options.tls ? httpsServer(options.tls, handler) : httpServer(handler);
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = `${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}`;
  return { origin, authorization, principal, marker, schema: ownedSchema(), requests, firstRequest, firstGenerated,
    policy: () => ownedAuthPolicy(origin, { principal, marker }),
    setMode(value) { if (!MODES.has(value)) throw new Error('Invalid owned mode'); mode = value; },
    setAuthorization(value) { authorization = value; }, setPrincipal(value) { principal = value; },
    get socketCount() { return sockets.size; },
    get stats() { return { httpRequests: requests.length, identityRequests: identityCount, protectedHandlerRequests: protectedCount,
      generatedIdTwoRequests: id2Count, openSockets: sockets.size,
      rows: [...rows.values()].map(row => ({ ...row })), stateUnchanged: JSON.stringify([...rows.values()]) === JSON.stringify(initialRows) }; },
    async close() { if (closed) return; closed = true; server.closeAllConnections(); for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve)); },
  };
}
