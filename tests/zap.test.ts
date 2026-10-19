import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildZapPlan, parseZapReport, runZap, ZAP_VERSION, type ZapOptions } from '../src/zap.js';

function report(origin: string) {
  return { '@version': ZAP_VERSION, site: [{ '@name': origin, alerts: [{ pluginid: '40012', riskcode: '3', confidence: '2',
    name: 'untrusted-payload', desc: 'secret-body', solution: 'secret-solution', instances: [
      { uri: `${origin}/vulnerable?q=secret-payload`, method: 'GET', param: 'q', attack: 'secret-attack', evidence: 'secret-evidence' },
    ] }] }] };
}

test('ZAP projection validates scope and strips payloads, engine HTML and response evidence', () => {
  const origin = 'http://127.0.0.1:8000', raw = report(origin);
  raw.site[0]!.alerts[0]!.instances.push({ ...raw.site[0]!.alerts[0]!.instances[0]! });
  const parsed = parseZapReport(raw, origin, ['/vulnerable?q=test']);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.malformed, 0);
  assert.equal(parsed.findings[0]!.location.url, `${origin}/vulnerable?[REDACTED]`);
  assert.equal(parsed.findings[0]!.severity, 'high');
  assert.ok(!JSON.stringify(parsed).includes('secret-'));
  assert.ok(!JSON.stringify(parsed).includes('untrusted-payload'));
  raw.site[0]!.alerts[0]!.instances[0]!.uri = `${origin}/unapproved?q=x`;
  assert.equal(parseZapReport(raw, origin, ['/vulnerable?q=test']).outOfScope, 1);
  assert.equal(parseZapReport({ ...raw, '@version': 'other' }, origin, ['/vulnerable?q=test']).malformed, 1);
  assert.equal(parseZapReport({ site: 'broken' }, origin, ['/vulnerable?q=test']).malformed, 1);
  raw.site[0]!.alerts[0]!.riskcode = '10';
  assert.equal(parseZapReport(raw, origin, ['/vulnerable?q=test']).malformed, 1);
});

test('ZAP plan permits only explicit query seeds, two active rules and no crawler', () => {
  const plan = buildZapPlan([new URL('http://127.0.0.1:8000/vulnerable?q=test')], new URL('http://wakeio:token@127.0.0.1:1234'), '/tmp/private') as any;
  assert.deepEqual(plan.jobs.map((job: any) => job.type), ['passiveScan-config', 'activeScan-config', 'requestor', 'activeScan', 'report']);
  assert.equal(plan.jobs[1].inputVectors.postData.enabled, false);
  assert.equal(plan.jobs[1].inputVectors.scripts, false);
  assert.equal(plan.jobs[3].policyDefinition.defaultThreshold, 'Off');
  assert.deepEqual(plan.jobs[3].policyDefinition.rules.map((rule: any) => rule.id), [40012, 40018]);
  const pattern = new RegExp(plan.env.contexts[0].includePaths[0]);
  assert.ok(pattern.test('http://127.0.0.1:8000/vulnerable?q=next'));
  assert.ok(!pattern.test('http://127.0.0.1:8000/vulnerable/other?q=next'));
  assert.ok(!pattern.test('http://127.0.0.1:8001/vulnerable?q=next'));
  const excluded = new RegExp(plan.env.contexts[0].excludePaths[0]);
  assert.ok(excluded.test('http://127.0.0.1:8000/'));
  assert.ok(excluded.test('http://127.0.0.1:8000/random-404-probe'));
  assert.ok(!excluded.test('http://127.0.0.1:8000/vulnerable?q=next'));
});

async function fixture() {
  const requests: Array<{ method: string; path: string; at: number }> = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url!, 'http://fixture');
    requests.push({ method: req.method!, path: url.pathname, at: Date.now() });
    const query = url.searchParams.get('q') ?? '';
    res.writeHead(200, { 'content-type': 'text/html', 'cache-control': 'no-store' });
    const encoded = query.replace(/[&<>"']/g, char => `&#${char.charCodeAt(0)};`);
    res.end(`<html><head><title>Owned fixture</title></head><body><p>Search: ${url.pathname === '/vulnerable' ? query : encoded}</p></body></html>`);
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  return { server, origin, requests, close: () => new Promise<void>(resolve => server.close(() => resolve())) };
}

async function fakeEngine(directory: string, behavior: { requests?: number; exit?: number; report?: 'missing' | 'invalid'; forbidden?: boolean; delay?: number } = {}) {
  const file = join(directory, `fake-zap-${Math.random().toString(16).slice(2)}`);
  await writeFile(file, `#!/usr/bin/env node
import { request } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const args = process.argv.slice(2);
if (args.includes('-version')) { console.log('${ZAP_VERSION}'); process.exit(0); }
const plan = JSON.parse(readFileSync(args[args.indexOf('-autorun') + 1], 'utf8'));
const proxy = plan.env.proxy;
const url = plan.jobs.find(job => job.type === 'requestor').requests[0].url;
const send = (method, path) => new Promise(resolve => {
 const req = request({ hostname: proxy.hostname, port: proxy.port, path, method, headers: { 'proxy-authorization': 'Basic ' + Buffer.from(proxy.username + ':' + proxy.password).toString('base64') } }, res => { res.resume(); res.on('end', resolve); });
 req.on('error', resolve); req.end();
});
${behavior.forbidden ? "await send('POST', url); await send('GET', new URL('/unapproved?q=test', url).href);" : ''}
for (let i = 0; i < ${behavior.requests ?? 3}; i++) { await send('GET', url); ${behavior.delay ? `await new Promise(resolve => setTimeout(resolve, ${behavior.delay}));` : ''} }
const path = join(plan.jobs.find(job => job.type === 'report').parameters.reportDir, 'report.json');
${behavior.report === 'missing' ? '' : behavior.report === 'invalid' ? "writeFileSync(path, '{broken');" : `writeFileSync(path, JSON.stringify({ '@version': '${ZAP_VERSION}', site: [{ '@name': new URL(url).origin, alerts: [] }] }));`}
process.exit(${behavior.exit ?? 0});
`);
  await chmod(file, 0o755);
  return file;
}

test('ZAP adapter rejects unapproved input before starting the engine or issuing requests', async () => {
  const target = await fixture();
  try {
    const options: ZapOptions = { url: target.origin, paths: ['/vulnerable?q=test'], consent: true, allowPrivate: true, executable: '/missing-zap' };
    for (const [extra, code] of [
      [{ consent: false }, 'consent_required'], [{ url: 'https://127.0.0.1' }, 'https_wire_budget_unsupported'],
      [{ paths: ['/vulnerable'] }, 'invalid_paths'], [{ paths: ['//other.test/?q=x'] }, 'invalid_paths'],
      [{ paths: ['/vulnerable?q=x#frag'] }, 'invalid_paths'], [{ maxRequests: 0 }, 'invalid_budget'],
      [{ rateLimit: 51 }, 'invalid_budget'], [{}, 'engine_missing'],
    ] as Array<[Partial<ZapOptions>, string]>) assert.equal((await runZap({ ...options, ...extra }))[0]!.metrics!.errorCode, code);
    assert.equal(target.requests.length, 0);
  } finally { await target.close(); }
});

test('ZAP requires report and observed active requests, and preserves AF warnings as incomplete', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-zap-test-')), target = await fixture();
  try {
    const options: ZapOptions = { url: target.origin, paths: ['/vulnerable?q=test'], consent: true, allowPrivate: true, rateLimit: 50, timeoutMs: 10_000 };
    const run = async (behavior: Parameters<typeof fakeEngine>[1]) => (await runZap({ ...options, executable: await fakeEngine(directory, behavior) }))[0]!;
    const complete = await run({});
    assert.equal(complete.status, 'completed', complete.notes.join(' | '));
    assert.equal(complete.metrics!.requestCount, 3);
    assert.equal(target.requests.length, 3);
    assert.equal((await run({ report: 'missing' })).metrics!.stopReason, 'invalid_report');
    assert.equal((await run({ report: 'invalid' })).metrics!.stopReason, 'invalid_report');
    assert.equal((await run({ requests: 1 })).metrics!.stopReason, 'active_scan_unobserved');
    assert.equal((await run({ exit: 2 })).metrics!.stopReason, 'engine_exit');
    const scoped = await run({ forbidden: true });
    assert.equal(scoped.metrics!.stopReason, 'scope_violation');
    assert.equal(scoped.metrics!.blockedMethod, 1);
    assert.equal(scoped.metrics!.blockedOrigin, 1);
    assert.ok(target.requests.every(req => req.method === 'GET' && req.path === '/vulnerable'));
  } finally { await target.close(); await rm(directory, { recursive: true, force: true }); }
});

test('ZAP proxy enforces exact request cap and cancellation stops further traffic', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-zap-budget-')), target = await fixture();
  try {
    const options: ZapOptions = { url: target.origin, paths: ['/vulnerable?q=test'], consent: true, allowPrivate: true, rateLimit: 50, timeoutMs: 10_000 };
    const result = (await runZap({ ...options, executable: await fakeEngine(directory, { requests: 20 }), maxRequests: 2 }))[0]!;
    assert.equal(result.status, 'partial');
    assert.equal(result.metrics!.stopReason, 'request_limit');
    assert.equal(result.metrics!.requestCount, 2);
    assert.equal(target.requests.length, 2);
    const controller = new AbortController();
    const pending = runZap({ ...options, executable: await fakeEngine(directory, { requests: 100, delay: 30 }), signal: controller.signal });
    const waitUntil = Date.now() + 5000;
    while (target.requests.length < 3 && Date.now() < waitUntil) await new Promise(resolve => setTimeout(resolve, 5));
    assert.ok(target.requests.length >= 3, 'Engine must reach the fixture before cancellation');
    controller.abort();
    const cancelled = (await pending)[0]!;
    assert.equal(cancelled.metrics!.stopReason, 'cancelled');
    const count = target.requests.length;
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.equal(target.requests.length, count);
    const timedOut = (await runZap({ ...options, executable: await fakeEngine(directory, { requests: 10, delay: 2000 }), timeoutMs: 1000 }))[0]!;
    assert.equal(timedOut.status, 'partial');
    assert.equal(timedOut.metrics!.stopReason, 'timeout');
  } finally { await target.close(); await rm(directory, { recursive: true, force: true }); }
});

test('ZAP enforces its advertised rate at the shared admission gate', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-zap-rate-')), target = await fixture();
  try {
    const result = (await runZap({ url: target.origin, paths: ['/safe?q=test'], consent: true, allowPrivate: true,
      executable: await fakeEngine(directory), maxRequests: 3, rateLimit: 2, timeoutMs: 5000 }))[0]!;
    assert.equal(result.status, 'completed');
    assert.equal(result.metrics!.rateLimit, 2);
    assert.equal(target.requests.length, 3);
    assert.ok(target.requests[2]!.at - target.requests[0]!.at >= 900, 'Three attempts at 2/s need two paced intervals');
  } finally { await target.close(); await rm(directory, { recursive: true, force: true }); }
});

test('real ZAP detects owned reflected XSS, rejects the encoded control, and accounts every fixture request', {
  skip: !process.env.WAKEIO_ZAP_PATH, timeout: 240_000,
}, async context => {
  const target = await fixture();
  try {
    const result = (await runZap({ url: target.origin, paths: ['/vulnerable?q=hello', '/safe?q=hello'], executable: process.env.WAKEIO_ZAP_PATH,
      consent: true, allowPrivate: true, maxRequests: 1000, rateLimit: 50, timeoutMs: 180_000 }))[0]!;
    assert.equal(result.status, 'completed', JSON.stringify(result));
    assert.ok(result.findings.some(finding => finding.ruleId === 'zap.40012' && finding.location.url?.includes('/vulnerable?')));
    assert.ok(!result.findings.some(finding => finding.location.url?.includes('/safe?')));
    assert.equal(result.metrics!.requestCount, target.requests.length, 'Every target request must pass the gate; no local-proxy bypass');
    assert.ok(target.requests.every(req => req.method === 'GET' && ['/vulnerable', '/safe'].includes(req.path)));
    assert.ok(!JSON.stringify(result).includes('<script'));
    context.diagnostic(JSON.stringify({ engineVersion: ZAP_VERSION, requestCount: result.metrics!.requestCount,
      targetRequestCount: target.requests.length, findingRules: result.findings.map(finding => finding.ruleId), status: result.status }));
  } finally { await target.close(); }
});

test('real ZAP request cap stops the engine and leaves a partial result', {
  skip: !process.env.WAKEIO_ZAP_PATH, timeout: 120_000,
}, async context => {
  const target = await fixture();
  try {
    const result = (await runZap({ url: target.origin, paths: ['/safe?q=hello'], executable: process.env.WAKEIO_ZAP_PATH,
      consent: true, allowPrivate: true, maxRequests: 2, rateLimit: 50, timeoutMs: 90_000 }))[0]!;
    assert.equal(result.status, 'partial');
    assert.equal(result.metrics!.stopReason, 'request_limit');
    assert.equal(result.metrics!.requestCount, 2);
    assert.equal(target.requests.length, 2);
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.equal(target.requests.length, 2);
    context.diagnostic(JSON.stringify({ engineVersion: ZAP_VERSION, requestCount: 2, targetRequestCount: 2, stopReason: 'request_limit', status: result.status }));
  } finally { await target.close(); }
});


test('ZAP cleanup failure remains incomplete and is not reported as a clean scan', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-zap-cleanup-test-')), target = await fixture();
  const original = fsPromises.rm;
  const retained: string[] = [];
  try {
    const executable = await fakeEngine(directory);
    fsPromises.rm = (async (path, options) => {
      if (typeof path === 'string' && path.includes('wakeio-zap-')) { retained.push(path); throw new Error('owned cleanup failure'); }
      return original(path, options);
    }) as typeof original;
    syncBuiltinESMExports();
    const result = (await runZap({ url: target.origin, paths: ['/safe?q=test'], consent: true, allowPrivate: true,
      executable, rateLimit: 50, timeoutMs: 10_000 }))[0]!;
    assert.equal(result.status, 'partial');
    assert.equal(result.metrics?.cleanupConfirmed, false);
    assert.equal(result.metrics?.stopReason, 'cleanup_error');
    assert.equal(retained.length, 1);
  } finally {
    fsPromises.rm = original; syncBuiltinESMExports();
    for (const path of retained) await original(path, { recursive: true, force: true });
    await target.close(); await original(directory, { recursive: true, force: true });
  }
});
