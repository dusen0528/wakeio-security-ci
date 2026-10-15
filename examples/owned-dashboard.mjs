#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { startDashboard } from '../build/src/agent-dast/loop/dashboard.js';
import { startFixture } from '../benchmarks/agent-eval/targets/local-sqlite/fixture.mjs';
import { prepare } from '../benchmarks/agent-eval/targets/local-sqlite/run.mjs';
if (!process.argv.includes('--active-consent')) throw Error('active_consent_required');
const index = process.argv.indexOf('--out');
if (index < 0 || !process.argv[index + 1]) throw Error('new_output_directory_required');
const out = resolve(process.argv[index + 1]); await mkdir(out, { mode: 0o700 });
const fixtures = [], token = randomBytes(32).toString('hex'); let dashboard;
try {
  const targets = [];
  for (let i = 0; i < 2; i++) {
    const fixture = await startFixture({ activeConsent: true }); fixtures.push(fixture);
    const prepared = await prepare(fixture, join(out, 'inputs-' + i), ['/catalog']);
    targets.push({ id: 'local-sqlite-' + (i + 1), origin: fixture.origin, plan: prepared.plan, inputs: prepared.inputs, maxRequests: 8, ratePerSecond: 10 });
  }
  await writeFile(join(out, 'token.txt'), token, { mode: 0o600, flag: 'wx' });
  await writeFile(join(out, 'approval.json'), JSON.stringify({ ownerApproved: true, activeConsent: true, scope: 'locally created synthetic SQLite fixtures only', targets, approvedAt: new Date().toISOString() }), { mode: 0o600, flag: 'wx' });
  dashboard = await startDashboard({ targets, token, outDir: join(out, 'runs'), activeConsent: true });
  console.log(JSON.stringify({ url: dashboard.origin, tokenFile: join(out, 'token.txt'), scope: 'two owned loopback fixtures; no scans until UI consent' }));
  await new Promise(resolve => { process.once('SIGINT', resolve); process.once('SIGTERM', resolve); });
} finally { await dashboard?.close(); await Promise.all(fixtures.map(f => f.close())); }
