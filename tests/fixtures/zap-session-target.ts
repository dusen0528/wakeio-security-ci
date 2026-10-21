import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import type { ZapPolicyV2 } from '../../src/zap-policy.js';

export async function zapSessionTarget(options: { fixed?: boolean; format?: 'json' | 'form'; cookie?: boolean; expire?: boolean; wrongPrincipal?: boolean; rejectLogin?: boolean } = {}) {
  const seen: Array<{ method: string; path: string; authenticated: boolean }> = [];
  const sessions = new Map<string, number>(); let serial = 0;
  const password = 'owned-private-password-' + randomBytes(8).toString('hex'), refresh = 'owned-private-refresh-' + randomBytes(8).toString('hex');
  const principal = 'owned-private-principal';
  const database = new DatabaseSync(':memory:');
  database.exec("CREATE TABLE products(id INTEGER, name TEXT, price INTEGER, tag TEXT); INSERT INTO products VALUES(1,'apple',2,'daily'),(2,'orange',3,'daily');");
  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, 'http://owned'), chunks: Buffer[] = [];
    for await (const b of req) chunks.push(Buffer.from(b));
    const text = Buffer.concat(chunks).toString();
    const body = text ? String(req.headers['content-type']).startsWith('application/x-www-form-urlencoded') ? Object.fromEntries(new URLSearchParams(text)) : JSON.parse(text) : {};
    const token = options.cookie ? req.headers.cookie?.split(';').find(c => c.trim().startsWith('sid='))?.trim().slice(4) : req.headers.authorization?.slice(7);
    const authenticated = !!token && sessions.has(token); seen.push({ method: req.method!, path: url.pathname, authenticated });
    if (url.pathname === '/sessions' || url.pathname === '/sessions/refresh') {
      if (options.rejectLogin || (url.pathname === '/sessions' ? body.email !== 'owner@example.test' || body.password !== password : body.refreshToken !== refresh)) { res.writeHead(401); res.end('{}'); return; }
      const access = 'owned-private-access-' + ++serial; sessions.set(access, 0);
      res.setHeader('content-type', 'application/json');
      if (options.cookie) res.setHeader('set-cookie', `sid=${access}; HttpOnly; Path=/`);
      res.end(JSON.stringify({ access, refresh })); return;
    }
    if (!authenticated) { res.writeHead(401); res.end('{}'); return; }
    if (url.pathname === '/identity') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ principal: options.wrongPrincipal && serial > 1 ? 'other-owner' : principal })); return; }
    if (options.expire && serial === 1 && sessions.get(token!)! >= 6) { sessions.delete(token!); res.writeHead(401); res.end('{}'); return; }
    sessions.set(token!, sessions.get(token!)! + 1);
    if (url.pathname === '/api/help/search') {
      const q = url.searchParams.get('q') ?? '';
      res.setHeader('content-type', 'text/html'); res.end(`<html><title>Help</title><body>${options.fixed ? q.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`) : q}</body></html>`); return;
    }
    const query = url.pathname === '/api/products/filter' ? body.filter?.name ?? '' : url.searchParams.get('q') ?? '';
    const tag = url.pathname === '/api/products/filter' ? body.tags?.[0] ?? 'daily' : 'daily';
    try {
      const products = options.fixed ? database.prepare('SELECT name,price FROM products WHERE name LIKE ? AND tag=?').all('%' + query + '%', tag)
        : database.prepare(`SELECT name,price FROM products WHERE name LIKE '%${query}%' AND tag='${tag}'`).all();
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ products, total: products.length }));
    } catch (error) { res.writeHead(500, { 'content-type': 'application/json' }); res.end(JSON.stringify({ code: (error as any).code, message: (error as Error).message })); }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const response = { '200': { description: 'Owned successful response' } };
  const query = { name: 'q', in: 'query', required: true, schema: { type: 'string', default: 'apple' } };
  const policy: ZapPolicyV2 = { version: 2, kind: 'zap-active', origin,
    openapi: { document: { openapi: '3.0.3', info: { title: 'Owned product API', version: '1' }, servers: [{ url: 'https://must-not-contact.invalid' }], paths: {
      '/api/products/search': { get: { parameters: [query], responses: response } },
      '/api/help/search': { get: { parameters: [query], responses: response } },
      '/api/products/filter': { post: { requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/Filter' } } } }, responses: response } },
    }, components: { schemas: { Filter: { type: 'object', required: ['filter', 'tags', 'limit', 'includeDeleted'], properties: {
      filter: { type: 'object', required: ['name'], properties: { name: { type: 'string', default: 'apple' } } },
      tags: { type: 'array', items: { type: 'string', default: 'daily' }, minItems: 1, maxItems: 1 },
      limit: { type: 'integer', default: 5 }, includeDeleted: { type: 'boolean', default: false },
    } } } } }, operations: [{ method: 'GET', path: '/api/products/search' }, { method: 'GET', path: '/api/help/search' }, { method: 'POST', path: '/api/products/filter' }] },
    authentication: { login: { path: '/sessions', format: options.format ?? 'json', fields: { email: 'OWNED_ZAP_EMAIL', password: 'OWNED_ZAP_PASSWORD' } },
      session: options.cookie ? { type: 'cookie', name: 'sid' } : { type: 'bearer', tokenPointer: '/access', refreshPointer: '/refresh' },
      ...(!options.cookie ? { refresh: { path: '/sessions/refresh', field: 'refreshToken' } } : {}),
      identity: { path: '/identity', status: 200, jsonPointer: '/principal', equals: principal }, maxAttempts: 4 },
  };
  return { origin, policy, seen, privateValues: [password, refresh, principal, 'owned-private-access-'],
    env: { OWNED_ZAP_EMAIL: 'owner@example.test', OWNED_ZAP_PASSWORD: password },
    close: () => new Promise<void>(resolve => server.close(() => { database.close(); resolve(); })) };
}
