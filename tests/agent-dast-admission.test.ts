import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import { RunAdmission, DastAdmissionError } from '../src/agent-dast/admission.js';
import { resolveDastOrigin, startEgressGate } from '../src/dast-egress.js';
import { runDast, type DastPolicyV1 } from '../src/dast.js';
import { runSchemathesisLive } from '../src/schemathesis-live.js';

test('one atomic cap and pacing span tasks; failed attempts and controls keep their count', async () => {
  const options = { maxRequests: 2, ratePerSecond: 20, deadlineAt: Date.now() + 5000 };
  const run = new RunAdmission(options), a = run.bindTask('t-a'), b = run.bindTask('t-b');
  options.maxRequests = 200; options.ratePerSecond = 1000;
  const starts: number[] = [];
  try {
    const results = await Promise.allSettled([
      a.reserve({ method: 'GET', kind: 'control' }).then(permit => { starts.push(Date.now()); permit.addBytes(4); permit.finish('transport_error'); permit.finish('response'); }),
      b.reserve({ method: 'HEAD', kind: 'probe', operationIndex: 0 }).then(permit => { starts.push(Date.now()); permit.addBytes(2); permit.finish('response'); }),
      a.reserve({ method: 'GET', kind: 'probe' }),
    ]);
    assert.deepEqual(results.map(result => result.status), ['fulfilled', 'fulfilled', 'rejected']);
    assert.ok(starts[1]! - starts[0]! >= 40, 'the shared rate is not multiplied by task count');
    assert.deepEqual(run.snapshot(), { requestCount: 2, bytes: 6, responseCompleted: 1, transportErrors: 1, pending: 0, refused: 1, attempts: [] });
    assert.equal(a.snapshot().attempts[0]?.kind, 'control');
    const copy = b.snapshot(); copy.attempts[0]!.method = 'POST'; copy.bytes = 999;
    assert.equal(b.snapshot().attempts[0]?.method, 'HEAD'); assert.equal(b.snapshot().bytes, 2);
    assert.equal(JSON.stringify(run.snapshot()).includes('http'), false);
  } finally { run.close(); }
});

test('caller abort stops inflight accounting and queued admissions without charging a waiting request', async () => {
  const owner = new AbortController();
  const run = new RunAdmission({ maxRequests: 3, ratePerSecond: 1, deadlineAt: Date.now() + 5000, signal: owner.signal });
  const task = run.bindTask('t-abort');
  try {
    await task.reserve({ method: 'POST', kind: 'probe' });
    const queued = task.reserve({ method: 'GET', kind: 'control' });
    owner.abort();
    await assert.rejects(queued, error => error instanceof DastAdmissionError && error.code === 'timeout');
    assert.equal(run.signal.aborted, true);
    assert.deepEqual(run.snapshot(), { requestCount: 1, bytes: 0, responseCompleted: 0, transportErrors: 1, pending: 0, refused: 1, attempts: [] });
    await assert.rejects(task.reserve({ method: 'GET', kind: 'probe' }), /timeout/);
    assert.equal(run.snapshot().requestCount, 1);
  } finally { run.close(); }
});

test('an absolute deadline aborts outstanding permits and a paced waiter', async () => {
  const run = new RunAdmission({ maxRequests: 3, ratePerSecond: 1, deadlineAt: Date.now() + 50 });
  const task = run.bindTask('t-deadline');
  try {
    await task.reserve({ method: 'GET', kind: 'probe' });
    await assert.rejects(task.reserve({ method: 'GET', kind: 'probe' }), /timeout/);
    assert.equal(run.snapshot().requestCount, 1); assert.equal(run.snapshot().pending, 0);
    assert.equal(task.signal.aborted, true);
  } finally { run.close(); }
});

test('a disconnected downstream can cancel its rate wait without closing the whole run', async () => {
  const run = new RunAdmission({ maxRequests: 3, ratePerSecond: 0.1, deadlineAt: Date.now() + 5000 });
  const task = run.bindTask('t-disconnected'), downstream = new AbortController();
  try {
    const first = await task.reserve({ method: 'GET', kind: 'probe' }); first.finish('response');
    const started = Date.now(), waiting = task.reserve({ method: 'GET', kind: 'probe' }, downstream.signal);
    downstream.abort();
    await assert.rejects(waiting, /timeout/);
    assert.ok(Date.now() - started < 1000, 'cancel does not wait for the next ten-second rate token');
    assert.equal(run.signal.aborted, false); assert.equal(task.snapshot().requestCount, 1);
  } finally { run.close(); }
});

async function listen(server: Server): Promise<number> {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); return typeof address === 'object' && address ? address.port : 0;
}
async function closeServer(server: Server): Promise<void> {
  server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
}
function proxyGet(proxyUrl: string, url: string): Promise<number> {
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const outgoing = request({ hostname: proxy.hostname, port: proxy.port, path: url, agent: false,
      headers: { 'proxy-authorization': `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}` } }, incoming => {
      incoming.resume(); incoming.once('end', () => resolve(incoming.statusCode ?? 0)); incoming.once('error', reject);
    });
    outgoing.once('error', reject); outgoing.end();
  });
}

test('two external-engine gates share one actual HTTP cap and retain response byte observations', async () => {
  let hits = 0;
  const target = createServer((_req, res) => { hits++; res.end('ok'); });
  const port = await listen(target), originUrl = `http://127.0.0.1:${port}/`;
  const run = new RunAdmission({ maxRequests: 1, ratePerSecond: 1000, deadlineAt: Date.now() + 5000 });
  const a = run.bindTask('t-gate-a'), b = run.bindTask('t-gate-b');
  const resolved = await resolveDastOrigin(originUrl, true, run.signal);
  const policy = { ...resolved, methods: new Set(['GET', 'HEAD']), maxRequests: 10, maxSingleBodyBytes: 1024,
    maxTotalBytes: 4096, signal: run.signal, deadlineAt: run.deadlineAt };
  const first = await startEgressGate(policy, a), second = await startEgressGate(policy, b);
  try {
    const status = await Promise.all([proxyGet(first.proxyUrl, originUrl), proxyGet(second.proxyUrl, originUrl)]);
    assert.deepEqual(status.sort(), [200, 503]); assert.equal(hits, 1);
    assert.equal(run.snapshot().requestCount, 1); assert.equal(run.snapshot().bytes, 2);
    assert.equal(a.snapshot().requestCount + b.snapshot().requestCount, 1);
    assert.equal(run.snapshot().pending, 0); assert.equal(run.snapshot().responseCompleted, 1);
  } finally { run.close(); await Promise.all([first.close(), second.close()]); await closeServer(target); }
});

test('native controls use the same trusted attempts; one shared cap limits concurrent native tasks', async () => {
  let hits = 0;
  const target = createServer((req, res) => {
    hits++; const value = new URL(req.url!, 'http://owned.invalid').searchParams.get('id');
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ count: value?.includes('1=2') ? 0 : 1 }));
  });
  const port = await listen(target), baseUrl = `http://127.0.0.1:${port}/`;
  const policy: DastPolicyV1 = { version: 1, kind: 'sql-boolean-differential', baseUrl, url: `${baseUrl}items?id=1`, parameter: 'id',
    profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
  const run = new RunAdmission({ maxRequests: 9, ratePerSecond: 1000, deadlineAt: Date.now() + 5000 });
  const a = run.bindTask('t-native-a'), b = run.bindTask('t-native-b');
  try {
    const checks = await Promise.all([a, b].map(runtime => runDast({ policy, consent: true, allowPrivate: true }, runtime)));
    assert.equal(hits, 9); assert.equal(run.snapshot().requestCount, hits);
    assert.equal(a.snapshot().requestCount + b.snapshot().requestCount, hits);
    assert.equal(run.snapshot().pending, 0);
    assert.ok(checks.some(group => group[0]?.status === 'partial'));
    assert.ok(a.snapshot().attempts.some(attempt => attempt.kind === 'control'));
    assert.ok(b.snapshot().attempts.some(attempt => attempt.kind === 'control'));
  } finally { run.close(); await closeServer(target); }
});

test('a strict runtime refuses opaque unauthenticated Schemathesis HTTPS before a worker or target starts', async () => {
  const run = new RunAdmission({ maxRequests: 8, ratePerSecond: 1000, deadlineAt: Date.now() + 5000 });
  try {
    const [check] = await runSchemathesisLive({ document: {}, operations: [{ method: 'GET', path: '/items' }],
      baseUrl: 'https://owned.invalid/', consent: true }, run.bindTask('t-https'));
    assert.equal(check?.status, 'error'); assert.equal(check?.metrics?.errorCode, 'https_wire_budget_unsupported');
    assert.equal(run.snapshot().requestCount, 0);
  } finally { run.close(); }
});
