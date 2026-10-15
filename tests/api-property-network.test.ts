import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { normalizeUrl, requestPropertyResource } from '../src/url-network.js';

test('standalone property transport sends actual GET/PATCH and refuses redirects without another attempt', async () => {
  const arrivals: Array<{ method: string; body: string; ifMatch?: string; authorization?: string }> = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
    arrivals.push({ method: request.method!, body: Buffer.concat(chunks).toString(), ifMatch: request.headers['if-match'], authorization: request.headers.authorization });
    if (request.url === '/redirect') { response.writeHead(302, { location: '/resource' }); response.end(); return; }
    response.writeHead(200, ['content-type', 'application/json', 'etag', '"first"', 'etag', '"second"']); response.end('{}');
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`, budget = { count: 0, max: 4 }, controller = new AbortController();
  const context = { allowPrivate: true, signal: controller.signal, budget, deadlineAt: Date.now() + 5000, authorization: 'Bearer owned' };
  try {
    const get = await requestPropertyResource(normalizeUrl(origin + '/resource'), context, origin, { method: 'GET' }, 1024, 1024);
    assert.equal(get.etag.kind, 'invalid');
    await requestPropertyResource(normalizeUrl(origin + '/resource'), context, origin, { method: 'PATCH', ifMatch: '"first"', body: '{"normal":"fresh"}' }, 1024, 1024);
    assert.deepEqual(arrivals.map(row => row.method), ['GET', 'PATCH']); assert.equal(arrivals[1]!.ifMatch, '"first"');
    await assert.rejects(requestPropertyResource(normalizeUrl(origin + '/redirect'), context, origin, { method: 'GET' }, 1024, 1024), /redirect_rejected/);
    assert.equal(arrivals.length, 3); assert.equal(budget.count, 3);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
test('property transport invalid validator/body/admission and pre-cancelled attempts make no HTTP', async () => {
  const controller = new AbortController(), budget = { count: 0, max: 4 };
  const url = normalizeUrl('http://127.0.0.1:19999/resource');
  const context = { allowPrivate: true, signal: controller.signal, budget, deadlineAt: Date.now() + 5000, authorization: 'Bearer owned' };
  for (const ifMatch of ['*', 'W/"weak"', '"one", "two"', '"bad\r\nvalue"']) {
    await assert.rejects(requestPropertyResource(url, context, url.origin, { method: 'PATCH', ifMatch, body: '{"normal":"fresh"}' }, 1024, 1024));
  }
  await assert.rejects(requestPropertyResource(url, { ...context, admission: {} as never }, url.origin, { method: 'GET' }, 1024, 1024), /property_admission_unsupported/);
  controller.abort();
  await assert.rejects(requestPropertyResource(url, context, url.origin, { method: 'GET' }, 1024, 1024));
  assert.equal(budget.count, 0);
});
