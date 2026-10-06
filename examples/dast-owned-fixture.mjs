// Author-owned loopback app. No staging address, real account or persisted secret.
// Seed and cleanup happen in memory, outside the scanner's read-only interface.
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';

export const FIXTURE_MODES = ['safe', 'public-id', 'different-canary', 'direct', 'nested', 'array', 'prefix-only', 'key-only', 'malformed', 'wrong-identity', 'owner-missing', 'server-error', 'too-deep', 'too-wide'];

export async function startOwnedDastFixture(mode = 'safe') {
  if (!FIXTURE_MODES.includes(mode)) throw Error('unknown owned fixture mode');
  const runId = randomUUID();
  const actors = [
    { id: 'userA', role: 'user', tenant: 'tenantA' },
    { id: 'userB', role: 'user', tenant: 'tenantA' },
    { id: 'userC', role: 'user', tenant: 'tenantB' },
    { id: 'admin', role: 'admin', tenant: 'tenantA' },
  ];
  const env = Object.fromEntries(actors.map(a => [`FIXTURE_${a.id.toUpperCase()}_AUTH`, `Bearer synthetic-${runId}-${a.id}`]));
  const credentials = new Map(actors.map(a => [env[`FIXTURE_${a.id.toUpperCase()}_AUTH`], a]));
  const records = new Map(actors.map(a => {
    const row = { id: `${runId}-${a.id}`, owner: a.id, tenant: a.tenant, canary: `synthetic-canary-${runId}-${a.id}` };
    return [`/records/${row.id}`, row];
  }));
  const seededCount = records.size;
  const requests = [];
  let cleaned = false;
  const json = (res, status, value) => res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(value));
  const server = createServer((req, res) => {
    const actor = credentials.get(req.headers.authorization);
    requests.push({ method: req.method, path: req.url, actor: actor?.id ?? 'anonymous' });
    if (req.method !== 'GET') return json(res, 405, { error: 'read-only fixture' });
    if (req.url === '/whoami') {
      if (!actor) return json(res, 401, { error: 'denied' });
      return json(res, 200, { principal: mode === 'wrong-identity' && actor.id === 'userB' ? 'expired-fixture-principal' : actor.id, tenant: actor.tenant, role: actor.role });
    }
    const row = records.get(req.url);
    if (!row) return json(res, 404, { error: 'missing fixture object' });
    const allowed = row.owner === 'admin'
      ? actor?.role === 'admin' && actor.tenant === row.tenant
      : actor?.id === row.owner && actor.tenant === row.tenant;
    if (allowed) {
      if (mode === 'owner-missing') return json(res, 404, { error: 'fixture lifecycle failure' });
      return json(res, 200, { id: row.id, canary: row.canary });
    }
    const status = actor ? 403 : 401;
    if (mode === 'public-id') return json(res, status, { error: 'denied', id: row.id });
    if (mode === 'different-canary') return json(res, status, { error: 'denied', canary: 'synthetic-unrelated-public-marker' });
    if (mode === 'direct') return json(res, status, { id: row.id, canary: row.canary });
    if (mode === 'nested') return json(res, status, { error: 'denied', debug: { record: { privateValue: row.canary } } });
    if (mode === 'array') return json(res, status, { error: 'denied', records: [{ payload: [null, row.canary] }] });
    if (mode === 'prefix-only') return json(res, status, { message: `public prefix ${row.canary}` });
    if (mode === 'key-only') return json(res, status, { [row.canary]: 'public-key-only-control' });
    if (mode === 'malformed') return res.writeHead(status, { 'content-type': 'application/json' }).end('{"error":');
    if (mode === 'server-error') return json(res, 503, { error: 'fixture unavailable' });
    if (mode === 'too-deep') {
      let body = { error: 'denied' };
      for (let i = 0; i < 70; i++) body = { next: body };
      return json(res, status, body);
    }
    if (mode === 'too-wide') return json(res, status, Array.from({ length: 10001 }, () => null));
    return json(res, status, { error: 'denied' });
  });
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const address = server.address();
  if (!address || typeof address === 'string') throw Error('fixture unavailable');
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const policy = (match = 'json-values') => ({
    version: 2, baseUrl,
    actors: [...actors.map(a => ({ id: a.id, authorizationEnv: `FIXTURE_${a.id.toUpperCase()}_AUTH`, identity: { path: '/whoami', status: 200, jsonPointer: '/principal', equals: a.id, organization: { jsonPointer: '/tenant', equals: a.tenant } } })), { id: 'anonymous' }],
    cases: [...records].map(([path, row]) => ({
      id: `read-${row.owner}`, path,
      allow: { actor: row.owner, status: 200, resource: { jsonPointer: '/id', equals: row.id }, protected: { jsonPointer: '/canary', equals: row.canary, ...(match === 'pointer' ? {} : { match }) } },
      deny: [...actors.filter(a => a.id !== row.owner).map(a => ({ actor: a.id, statuses: [403] })), { actor: 'anonymous', statuses: [401] }],
    })),
  });
  return {
    baseUrl, env, policy, requests, seededCount,
    // Independent fixture ground truth, not derived from scanner output.
    expectedExposures: ['direct', 'nested', 'array'].includes(mode) ? 16 : 0,
    expectedRequests: mode === 'owner-missing' ? 12 : 32,
    async close() {
      if (cleaned) return;
      server.closeAllConnections();
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      records.clear(); credentials.clear();
      for (const key of Object.keys(env)) delete env[key];
      cleaned = true;
    },
    lifecycle() { return { seededCount, remainingObjects: records.size, cleaned, listening: server.listening }; },
  };
}
