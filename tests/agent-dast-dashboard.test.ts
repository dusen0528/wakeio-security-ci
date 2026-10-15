import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { startDashboard } from '../src/agent-dast/loop/dashboard.js';

const token = 'local-test-token-'.repeat(4);
const waitFor = async (fn: () => Promise<boolean>) => {
  const end = Date.now() + 12_000;
  while (!await fn()) { if (Date.now() > end) throw Error('test_timeout'); await new Promise(resolve => setTimeout(resolve, 50)); }
};
test('authenticated owned dashboard repeats scans and bounds concurrent target ledgers', async () => {
  const base = new URL('../../benchmarks/agent-eval/targets/local-sqlite/', import.meta.url);
  const { startFixture } = await import(new URL('fixture.mjs', base).href);
  const { prepare } = await import(new URL('run.mjs', base).href);
  const root = await mkdtemp(join(tmpdir(), 'wakeio-dashboard-'));
  const fixtures = await Promise.all([startFixture({ activeConsent: true }), startFixture({ activeConsent: true })]);
  let dashboard: Awaited<ReturnType<typeof startDashboard>> | undefined;
  try {
    const targets = await Promise.all(fixtures.map(async (fixture, i) => ({ id: 'target-' + i, origin: fixture.origin,
      ...await prepare(fixture, join(root, 'inputs-' + i), ['/catalog']), maxRequests: i ? 5 : 8, ratePerSecond: 10 })));
    await assert.rejects(startDashboard({ targets, token, outDir: join(root,'refused'), activeConsent: false }), /consent/);
    dashboard = await startDashboard({ targets, token, outDir: join(root, 'runs'), activeConsent: true });
    const url = dashboard.origin;
    const api = (path: string, body?: unknown, headers = {}) => fetch(url + path, { method: body ? 'POST' : 'GET',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', ...headers }, ...(body ? { body: JSON.stringify(body) } : {}) });
    assert.equal((await fetch(url + '/api/state')).status, 401);
    assert.equal((await api('/api/state', undefined, { Origin: 'http://127.0.0.1:1' })).status, 403);
    const { get } = await import('node:http');
    const hostStatus = await new Promise<number | undefined>(resolve => get(url + '/api/state', { headers: { Host: 'attacker.invalid' } }, res => { res.resume(); resolve(res.statusCode); }));
    assert.equal(hostStatus, 403);
    assert.ok((await (await fetch(url)).text()).includes('소유 대상 검사'));
    const command = (i: number, action: string, extra = {}) => api('/api/target', { id: targets[i].id, origin: targets[i].origin, action, ...extra });
    assert.equal((await command(0, 'scan')).status, 403);
    assert.equal((await command(0, 'register')).status, 400);
    assert.equal((await command(0, 'register', { origin: 'http://127.0.0.1:1', ownerAuthorized: true, activeConsent: true })).status, 403);
    for (let i=0;i<2;i++) assert.equal((await command(i, 'register', { ownerAuthorized: true, activeConsent: true })).status, 200);
    const consent = JSON.parse(await readFile(join(root, 'runs/target-0-consent.json'), 'utf8'));
    assert.equal(consent.activeConsent, true); assert.equal(consent.origin, fixtures[0].origin);
    await Promise.all([command(0, 'scan'), command(1, 'scan')]);
    const state = async () => (await api('/api/state')).json();
    assert.ok((await state()).targets.every((t: any) => t.running));
    await waitFor(async () => (await state()).targets.every((t: any) => t.completed === 1));
    let current = await state();
    assert.equal(current.targets[0].latest.requests, 8); assert.ok(current.targets[1].latest.requests <= 5);
    assert.ok(current.events.some((e: any) => e.reason === 'out_of_scope'));
    assert.equal(current.targets[0].latest.findings, 1);
    await command(0, 'repeat', { intervalMs: 1000 });
    await waitFor(async () => (await state()).targets[0].completed >= 3);
    await command(0, 'pause');
    current = await state(); assert.equal(current.targets[0].enabled, false);
    await dashboard.close(); dashboard = undefined;
    const totals = [0,0];
    for (const name of await readdir(join(root,'runs'))) {
      if (name.endsWith('.json')) continue;
      const db = new DatabaseSync(join(root,'runs',name,'run.db'), {readOnly:true});
      try {
        const requests = Number(db.prepare('SELECT coalesce(sum(request_count),0) n FROM ledger').get()!.n);
        const i = name.startsWith('target-0-') ? 0 : 1;
        assert.ok(requests <= targets[i].maxRequests); totals[i] += requests;
      } finally { db.close(); }
    }
    assert.deepEqual(totals, fixtures.map(f => f.requests.length));
  } finally {
    await dashboard?.close(); await Promise.all(fixtures.map(f => f.close())); await rm(root, { recursive: true, force: true });
  }
});

test('runner rejects a granted input whose policy points outside the approved target', async () => {
  const base = new URL('../../benchmarks/agent-eval/targets/local-sqlite/', import.meta.url);
  const { startFixture } = await import(new URL('fixture.mjs', base).href);
  const { prepare } = await import(new URL('run.mjs', base).href);
  const root = await mkdtemp(join(tmpdir(), 'wakeio-dashboard-scope-'));
  const fixtures = await Promise.all([startFixture({ activeConsent: true }), startFixture({ activeConsent: true })]);
  let dashboard: Awaited<ReturnType<typeof startDashboard>> | undefined;
  try {
    const prepared = await prepare(fixtures[1], join(root, 'inputs'), ['/catalog']);
    const target = { id: 'owned', origin: fixtures[0].origin, plan: { ...prepared.plan, origin: fixtures[0].origin }, inputs: prepared.inputs, maxRequests: 8, ratePerSecond: 10 };
    dashboard = await startDashboard({ targets: [target], token, outDir: join(root,'runs'), activeConsent: true });
    const post = (action: string) => fetch(dashboard!.origin + '/api/target', { method: 'POST', headers: { Authorization: 'Bearer ' + token }, body: JSON.stringify({ id: target.id, origin: target.origin, action, ownerAuthorized: true, activeConsent: true }) });
    await post('register'); await post('scan');
    const state = async () => (await (await fetch(dashboard!.origin + '/api/state', { headers: { Authorization: 'Bearer ' + token } })).json()).targets[0];
    await waitFor(async () => !(await state()).running);
    const result = await state();
    assert.equal(result.status, 'error'); assert.ok(result.reason.length > 0);
    assert.deepEqual(fixtures.map(f => f.requests.length), [0,0]);
  } finally { await dashboard?.close(); await Promise.all(fixtures.map(f => f.close())); await rm(root, {recursive:true,force:true}); }
});

test('logout discards pending authenticated UI responses', async () => {
  const { runInNewContext } = await import('node:vm');
  const { dashboardScript } = await import('../src/agent-dast/loop/dashboard-view.js');
  const elements: Record<string, any> = Object.fromEntries(['login','token','workspace','targets','events','message','refresh','logout','updated'].map(id => [id, { hidden: id === 'workspace', value: token, replaceChildren() {} }]));
  let finish!: (value: unknown) => void;
  const response = new Promise(resolve => { finish = resolve; });
  runInNewContext(dashboardScript, { document: { getElementById: (id: string) => elements[id], createElement: () => ({}) },
    fetch: () => response, setInterval() {} });
  const pending = elements.login.onsubmit({ preventDefault() {} });
  elements.logout.onclick();
  finish({ ok: true, json: async () => ({ targets: [], events: [] }) });
  await pending;
  assert.equal(elements.workspace.hidden, true); assert.equal(elements.login.hidden, false);
});
