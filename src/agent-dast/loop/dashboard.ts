import { createServer } from 'node:http';
import { timingSafeEqual, randomUUID } from 'node:crypto';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { parseExecutionInputs, parseExecutionPlan, type ExecutionPlan, type ExecutionInputs } from '../plan.js';
import { runExecutionPlan } from '../runner.js';
import { dashboardHtml, dashboardScript, dashboardStyle } from './dashboard-view.js';

export interface ApprovedTarget {
  id: string; origin: string; plan: ExecutionPlan; inputs: ExecutionInputs;
  maxRequests: number; ratePerSecond: number;
}
export interface DashboardOptions { targets: ApprovedTarget[]; outDir: string; token: string; activeConsent: boolean }
/** Local operator grants are fixed at startup. HTTP clients cannot supply plans, files or new origins. */
export async function startDashboard(options: DashboardOptions) {
  if (!options.activeConsent || typeof options.token !== 'string' || options.token.length < 32) throw Error('dashboard_consent_and_token_required');
  if (!Array.isArray(options.targets) || options.targets.length < 1 || options.targets.length > 2) throw Error('invalid_targets');
  const token = Buffer.from(options.token);
  const targets = options.targets.map(raw => {
    const item = structuredClone(raw), origin = new URL(item.origin);
    if (!/^[a-z0-9-]{1,40}$/.test(item.id) || origin.origin !== item.origin || origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1'
      || !origin.port || !Number.isSafeInteger(item.maxRequests) || item.maxRequests < 1 || item.maxRequests > 64
      || !Number.isSafeInteger(item.ratePerSecond) || item.ratePerSecond < 1 || item.ratePerSecond > 10) throw Error('invalid_targets');
    const plan = parseExecutionPlan(item.plan), inputs = parseExecutionInputs(item.inputs);
    if (plan.origin !== item.origin) throw Error('out_of_scope');
    return { ...item, plan, inputs };
  });
  if (new Set(targets.map(t => t.id)).size !== targets.length || new Set(targets.map(t => t.origin)).size !== targets.length) throw Error('duplicate_target');
  await mkdir(options.outDir, { mode: 0o700 });
  const states = targets.map(target => ({ target, consent: false, enabled: false, intervalMs: 60_000, nextAt: 0,
    running: false, completed: 0, status: 'unregistered', reason: '', latest: null as null | { runId: string; exitCode: number; requests: number; findings: number; report: unknown } }));
  const events: Array<{ at: string; reason: string }> = [];
  const pending = new Set<Promise<void>>(), abort = new AbortController();
  let closed = false, origin = '';
  const log = (reason: string) => { events.push({ at: new Date().toISOString(), reason }); if (events.length > 100) events.shift(); };
  const snapshot = () => ({ targets: states.map(s => ({ id: s.target.id, origin: s.target.origin, maxRequests: s.target.maxRequests, ratePerSecond: s.target.ratePerSecond,
    consent: s.consent, enabled: s.enabled, running: s.running, completed: s.completed, status: s.status, reason: s.reason, latest: s.latest })), events });
  const scan = (state: typeof states[number]) => {
    if (closed || !state.consent || state.running) return;
    state.running = true; state.status = 'running'; state.reason = '';
    const work = (async () => {
      try {
        const outDir = join(options.outDir, state.target.id + '-' + randomUUID());
        const run = await runExecutionPlan({ plan: state.target.plan, inputs: state.target.inputs, outDir, consent: state.consent,
          allowedOrigin: state.target.origin, allowPrivate: true, maxRequests: state.target.maxRequests,
          ratePerSecond: state.target.ratePerSecond, concurrency: 1, timeoutMs: 30_000, failOn: 'high', signal: abort.signal });
        if (run.delivery !== 'published' || !run.outDir) throw Error('execution_refused');
        const db = new DatabaseSync(join(run.outDir, 'run.db'), { readOnly: true });
        let requests: number, findings: number;
        try {
          requests = Number(db.prepare('SELECT coalesce(sum(request_count),0) n FROM ledger').get()!.n);
          findings = Number(db.prepare('SELECT count(*) n FROM findings').get()!.n);
        } finally { db.close(); }
        if (requests !== run.requests.requestCount || requests > state.target.maxRequests) throw Error('ledger_mismatch');
        state.latest = { runId: run.runId, exitCode: run.exitCode, requests, findings, report: JSON.parse(await readFile(join(run.outDir, 'run-report.json'), 'utf8')) };
        state.completed++; state.status = run.status; state.reason = run.exitCode === 2 ? 'gate_or_engine_incomplete' : '';
      } catch { state.status = 'error'; state.reason = 'execution_refused_or_storage_error'; log(state.reason); }
      finally { state.running = false; state.nextAt = Date.now() + state.intervalMs; }
    })();
    pending.add(work); void work.finally(() => pending.delete(work));
  };
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const send = (code: number, body: unknown) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.headers.host !== new URL(origin).host || req.headers.origin && req.headers.origin !== origin) { send(403, { error: 'origin_rejected' }); return; }
    const assets: Record<string, [string,string]> = { '/': ['text/html',dashboardHtml], '/app.js': ['text/javascript',dashboardScript], '/app.css': ['text/css',dashboardStyle] };
    if (req.method === 'GET' && Object.hasOwn(assets, req.url ?? '')) { const [type,body] = assets[req.url!]; res.writeHead(200, { 'Content-Type': type }); res.end(body); return; }
    const supplied = Buffer.from((req.headers.authorization ?? '').replace(/^Bearer /, ''));
    if (supplied.length !== token.length || !timingSafeEqual(supplied, token)) { send(401, { error: 'authentication_required' }); return; }
    if (req.method === 'GET' && req.url === '/api/state') { send(200, snapshot()); return; }
    if (req.method !== 'POST' || req.url !== '/api/target') { send(404, { error: 'not_found' }); return; }
    try {
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > 8192) { send(413, { error: 'body_too_large' }); return; } chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const state = states.find(s => s.target.id === body.id);
      if (!state || body.origin !== state.target.origin) { log('out_of_scope'); send(403, { error: 'out_of_scope' }); return; }
      if (body.action === 'register') {
        if (body.ownerAuthorized !== true || body.activeConsent !== true) { send(400, { error: 'explicit_consent_required' }); return; }
        // Re-registering cannot replace or broaden an operator grant.
        if (!state.consent) {
          await writeFile(join(options.outDir, state.target.id + '-consent.json'), JSON.stringify({ ...state.target, ownerAuthorized: true, activeConsent: true, grantedAt: new Date().toISOString() }), { mode: 0o600, flag: 'wx' });
          state.consent = true; state.status = 'ready';
        }
      } else if (!state.consent) { send(403, { error: 'target_not_registered' }); return; }
      else if (body.action === 'scan') scan(state);
      else if (body.action === 'repeat') {
        if (!Number.isSafeInteger(body.intervalMs) || body.intervalMs < 1000 || body.intervalMs > 86_400_000) { send(400, { error: 'invalid_interval' }); return; }
        state.intervalMs = body.intervalMs; state.enabled = true; scan(state);
      } else if (body.action === 'pause') state.enabled = false;
      else { send(400, { error: 'invalid_action' }); return; }
      send(200, snapshot());
    } catch { send(400, { error: 'invalid_request_or_storage_error' }); }
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address(); if (!address || typeof address === 'string') throw Error('listen_failed');
  origin = `http://127.0.0.1:${address.port}`;
  const timer = setInterval(() => { for (const state of states) if (state.enabled && state.nextAt <= Date.now()) scan(state); }, 100);
  return { origin, async close() {
    closed = true; clearInterval(timer); abort.abort(); await Promise.allSettled([...pending]);
    server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  } };
}
