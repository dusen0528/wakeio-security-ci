// Original owned HTTP target. Never imported by the scanner. The parent observer
// owns the store and reads it independently at acknowledged write windows.
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, renameSync, appendFileSync } from 'node:fs';
const config = JSON.parse(process.argv[2]);
const { storePath, journalPath, mode, normalField: N, protectedField: P } = config;
const pending = new Map(); let sequence = 0, revision = 0, protectedProbeSeen = false;
let cachedControl, cachedControlTag, identityOwnerCalls = 0;
const read = () => JSON.parse(readFileSync(storePath, 'utf8'));
const save = value => { writeFileSync(storePath + '.next', JSON.stringify(value), { mode: 0o600 }); renameSync(storePath + '.next', storePath); };
const etag = () => `"owned-property-${revision}"`;
const snapshot = state => structuredClone(state.object);
function checkpoint(kind, detail) {
  const id = sequence++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(Error('observer_unavailable')); }, 5000);
    pending.set(id, () => { clearTimeout(timer); resolve(); });
    process.send?.({ kind, id, ...detail });
  });
}
process.on('message', message => { if (message?.ack !== undefined) { pending.get(message.ack)?.(); pending.delete(message.ack); } });
const arrivals = [];
const sockets = new Set();
const server = createServer((req, res) => {
  const task = async () => {
    const ordinal = arrivals.length;
    const actor = req.headers.authorization === config.ownerToken ? 'owner'
      : req.headers.authorization === config.verifierToken ? 'verifier' : 'unknown';
    const entry = { ordinal, actor, method: req.method, path: req.url, ifMatch: req.headers['if-match'] ?? null };
    arrivals.push(entry);
    await checkpoint('arrival', entry);
    const send = (status, body, tag = etag()) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', etag: tag }); res.end(JSON.stringify(body)); };
    if (req.url === '/identity' && req.method === 'GET') {
      if (actor === 'owner') identityOwnerCalls++;
      return send(actor === 'unknown' ? 401 : 200, { principal: mode === 'identity-drift' && actor === 'owner' && identityOwnerCalls > 1 ? 'another-owner' : actor === 'owner' ? 'owner-1' : 'verifier-1' });
    }
    if (req.url !== '/resources/opaque-object') return send(404, { missing: true });
    if (req.method === 'GET') {
      let value = snapshot(read());
      if (actor === 'owner') delete value[P]; // Deliberately different representation.
      if (mode === 'wrong-object') value.id = 'decoy-object';
      if (mode === 'hidden-field' && actor === 'verifier') delete value[P];
      if (mode === 'body-limit' && actor === 'verifier') value.padding = 'x'.repeat(80 * 1024);
      if (mode === 'stale-control' && cachedControl && actor === 'verifier') return send(200, cachedControl, cachedControlTag);
      if (mode === 'stale-probe' && protectedProbeSeen && actor === 'verifier' && cachedControl) {
        // Old protected value/validator with the otherwise current normal field.
        value[P] = cachedControl[P]; return send(200, value, cachedControlTag);
      }
      return send(actor === 'unknown' ? 401 : 200, value, actor === 'owner' ? `"owner-view-${revision}"` : etag());
    }
    if (req.method !== 'PATCH') return send(405, { denied: true });
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    entry.body = body;
    if (mode === 'concurrent-writer' && actor === 'owner' && Object.keys(body).length === 1 && P in body) {
      const state = read(); state.object.guard = 'concurrent-change'; save(state); revision++;
    }
    const wrong = req.headers['if-match'] !== etag();
    if (wrong && mode !== 'ignore-etag') return send(412, { precondition: false });
    const before = read(); await checkpoint('before-write', { ordinal });
    const state = read(); let status = 200;
    const protectedAttempt = actor === 'owner' && P in body;
    if (protectedAttempt) protectedProbeSeen = true;
    if (mode === 'cancel-stall' && protectedAttempt) { await checkpoint('stalled-write', { ordinal }); return; }
    if (actor === 'unknown') status = 401;
    else if (actor === 'owner' && mode === 'deny-all') status = 403;
    else if (actor === 'owner' && mode === 'normal-noop' && N in body) status = 200;
    else if (protectedAttempt && ['fixed', 'stale-probe', 'body-limit'].includes(mode)) status = 403;
    else if (protectedAttempt && mode === 'status-noop') status = 200;
    else {
      for (const field of Object.keys(body)) if (field !== N && field !== P) throw Error('unexpected_property');
      const target = mode === 'write-decoy' ? state.decoy : state.object;
      Object.assign(target, body); save(state); revision++;
      if (protectedAttempt && mode === 'status-mutation') status = 403;
    }
    appendFileSync(journalPath, JSON.stringify({ ordinal, actor, changed: JSON.stringify(before) !== JSON.stringify(read()), revision }) + '\n');
    await checkpoint('after-write', { ordinal });
    if (actor === 'verifier' && P in body && body[P] === config.control) {
      cachedControl = mode === 'stale-control' ? before.object : snapshot(read());
      cachedControlTag = mode === 'stale-control' ? req.headers['if-match'] : etag();
    }
    if (protectedAttempt && mode === 'ambiguous-commit') { res.destroy(); return; }
    return send(status, { acknowledged: true });
  };
  void task().catch(() => { if (!res.headersSent) res.writeHead(500); res.end(); });
});
server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
server.listen(0, '127.0.0.1', () => process.send?.({ kind: 'ready', origin: `http://127.0.0.1:${server.address().port}` }));
process.on('message', message => {
  if (message?.inspect) {
    // Observe client closure before any harness-forced shutdown can hide a leak.
    const closing = [...sockets].map(socket => new Promise(resolve => socket.once('close', resolve)));
    let timer;
    void Promise.race([Promise.all(closing), new Promise(resolve => { timer = setTimeout(resolve, 500); })]).then(() => {
      clearTimeout(timer); process.send?.({ kind: 'socket-state', sockets: sockets.size, arrivals });
    });
  }
  if (message?.stop) {
    const closing = [...sockets].map(socket => new Promise(resolve => socket.once('close', resolve)));
    server.closeAllConnections(); server.close(() => { void Promise.all(closing).then(() => {
      process.send?.({ kind: 'closed', sockets: sockets.size, arrivals }); process.disconnect();
    }); });
  }
});
