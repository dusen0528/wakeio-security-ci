import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { parseZapPolicy, prepareZapPolicy, ZAP_RELAY_ORIGIN } from '../src/zap-policy.js';
import { resolveDastOrigin, startEgressGate } from '../src/dast-egress.js';
import { runZap } from '../src/zap.js';
import { zapPolicyTarget } from './fixtures/zap-policy-target.js';

const base = { version: 1, kind: 'zap-active', origin: 'http://127.0.0.1:1234', requests: [{ method: 'POST', path: '/json', body: { id: '1' } }] };
test('ZAP owner policy rejects normalization, duplicate seeds, unbounded bodies and unsafe auth transport', () => {
  assert.match(parseZapPolicy(base).policySha256, /^[a-f0-9]{64}$/);
  for (const patch of [ { requests: [...base.requests, ...base.requests] }, { origin: base.origin + '/' },
    ...['/../json', '/%2e%2e/json', '//evil.invalid/', '/json#x', '/json?x=1'].map(path => ({ requests: [{ ...base.requests[0], path }] })),
    ...[null, [], { id: true }, { id: {} }, { id: 'x', other: 'y' }, { id: 'x'.repeat(513) }, JSON.parse('{"__proto__":"x"}')].map(body => ({ requests: [{ ...base.requests[0], body }] })),
    { requests: [{ method: 'GET', path: '/x?q=1&q=2' }] }, { unknown: true },
  ]) assert.throws(() => parseZapPolicy({ ...base, ...patch }));
  const authentication = { authorizationEnv: 'TEST_AUTH', identity: { path: '/identity', status: 200, jsonPointer: '/id', equals: 'owner' } };
  assert.equal(prepareZapPolicy({ ...base, authentication }, true, { TEST_AUTH: 'Bearer owner' }).authorization, 'Bearer owner');
  assert.throws(() => prepareZapPolicy({ ...base, origin: 'http://example.com', authentication }, true, { TEST_AUTH: 'Bearer owner' }));
  assert.throws(() => prepareZapPolicy({ ...base, authentication }, true, {}));
  assert.throws(() => prepareZapPolicy({ ...base, authentication }, true, { TEST_AUTH: 'Bearer x\r\nInjected: yes' }));
});

test('ZAP relay validates JSON before forwarding, strips worker credentials and isolates principal controls', async () => {
  const seen: Array<{ path: string; auth: string | undefined; cookie: string | undefined; body: string }> = [];
  const server = createServer(async (req, res) => { const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
    seen.push({ path: req.url!, auth: req.headers.authorization, cookie: req.headers.cookie, body: Buffer.concat(chunks).toString() });
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'secret=x' }); res.end('{"id":"owner"}'); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`, controller = new AbortController();
  const gate = await startEgressGate({ ...await resolveDastOrigin(origin, true, controller.signal), signal: controller.signal, methods: new Set(['GET', 'POST']),
    operations: ['/json'], deadlineAt: Date.now() + 10000, maxRequests: 10, maxSingleBodyBytes: 1024, maxTotalBytes: 10000,
    relay: { virtualOrigin: ZAP_RELAY_ORIGIN, authorization: 'Bearer node-only', controlPaths: ['/identity'], requests: [
      { method: 'POST', path: '/json', parameter: 'id' }, { method: 'GET', path: '/query', query: ['id'] },
    ] } });
  const proxy = new URL(gate.proxyUrl);
  const send = (path: string, body?: string, type = 'application/json', chunked = false) => new Promise<number>((resolve, reject) => {
    const req = request({ host: proxy.hostname, port: proxy.port, path, method: body === undefined ? 'GET' : 'POST', headers: {
      'proxy-authorization': 'Basic ' + Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64'), authorization: 'Bearer worker', cookie: 'secret=worker',
      ...(body !== undefined ? { 'content-type': type, ...(chunked ? { 'transfer-encoding': 'chunked' } : { 'content-length': Buffer.byteLength(body) }) } : {}),
    } }, res => { assert.equal(res.headers['set-cookie'], undefined); res.resume(); res.once('end', () => resolve(res.statusCode!)); }); req.once('error', reject); req.end(body);
  });
  try {
    for (const body of ['not json', '{"id":1,"id":2}', '{"id":{},"extra":1}', '{"id":[]}', '{"other":"x"}', '{"__proto__":"x"}', '{"id":"' + 'x'.repeat(2049) + '"}'])
      assert.equal(await send(ZAP_RELAY_ORIGIN + '/json', body), 405);
    assert.equal(await send(ZAP_RELAY_ORIGIN + '/json', '{"id":1}', 'text/plain'), 405);
    for (const path of ['/identity', '/query?id=1&extra=2', '/query?id=1&id=2', '/other?id=1']) assert.equal(await send(ZAP_RELAY_ORIGIN + path), 502);
    assert.equal(await send(origin + '/query?id=1'), 502);
    assert.equal(await send(ZAP_RELAY_ORIGIN + '/json', '{"id":1}', 'application/json', true), 405);
    const tunnel = await new Promise<number>((resolve, reject) => {
      const req = request({ host: proxy.hostname, port: proxy.port, method: 'CONNECT', path: new URL(origin).host, headers: {
        'proxy-authorization': 'Basic ' + Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64') } });
      req.once('connect', (res, socket) => { socket.destroy(); resolve(res.statusCode!); }); req.once('error', reject); req.end();
    });
    assert.equal(tunnel, 502);
    assert.equal(seen.length, 0);
    assert.equal(await send(ZAP_RELAY_ORIGIN + '/json', '{"id":"1 OR 1=1"}'), 200);
    assert.equal(await send(ZAP_RELAY_ORIGIN + '/query?id=2'), 200);
    assert.equal((await gate.relay!.control('/identity', false)).status, 200);
    assert.equal((await gate.relay!.control('/identity', true)).status, 200);
    assert.deepEqual(seen.map(item => item.auth), ['Bearer node-only', 'Bearer node-only', 'Bearer node-only', undefined]);
    assert.ok(seen.every(item => item.cookie === undefined));
    assert.equal(gate.counters.forwarded, seen.length);
    assert.equal(gate.counters.tunnels, 0);
    await assert.rejects(send(ZAP_RELAY_ORIGIN + '/json', '{"id":"' + 'x'.repeat(4097) + '"}'));
    assert.equal(gate.stopReason(), 'body_limit');
    assert.equal(seen.length, 4);
  } finally { await gate.close(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('real ZAP policy detects authenticated query and JSON SQLi/XSS and rejects fixed controls', {
  skip: !process.env.WAKEIO_ZAP_PATH, timeout: 180000,
}, async context => {
  const target = await zapPolicyTarget();
  try {
    const result = (await runZap({ url: target.origin, policy: target.policy, env: target.env, executable: process.env.WAKEIO_ZAP_PATH,
      consent: true, allowPrivate: true, maxRequests: 1000, rateLimit: 50, timeoutMs: 120000 }))[0]!;
    assert.equal(result.status, 'completed', JSON.stringify(result));
    assert.equal(result.metrics!.requestCount, target.seen.length);
    for (const [path, rule] of [['/xss', 'zap.40012'], ['/sql', 'zap.40018'], ['/json', 'zap.40018']])
      assert.ok(result.findings.some(f => new URL(f.location.url!).pathname === path && f.ruleId === rule), path + ': ' + JSON.stringify(result));
    assert.ok(result.findings.every(f => !f.location.url!.includes('-fixed')));
    assert.equal(result.metrics!.identityBefore, true); assert.equal(result.metrics!.identityAfter, true); assert.equal(result.metrics!.anonymousDenied, true);
    assert.ok(target.seen.filter(q => q.path !== '/identity').every(q => q.authenticated && !q.cookie));
    assert.equal(JSON.stringify(result).includes(target.authorization), false);
    context.diagnostic(JSON.stringify({ status: result.status, requests: result.metrics!.requestCount, durationMs: result.metrics!.durationMs, findings: result.findings.map(f => ({ rule: f.ruleId, url: f.location.url })) }));
  } finally { await target.close(); }
});
