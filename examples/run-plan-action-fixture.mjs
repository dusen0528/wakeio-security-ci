#!/usr/bin/env node
// Explicit CI fixture preparation only; uses the existing real in-memory SQLite target.
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { startNativeDastSqlite } from './native-dast-sqlite.mjs';

const mode = process.env.WAKEIO_OWNED_PLAN_MODE;
if (!['vulnerable', 'bound'].includes(mode)) throw Error('invalid_owned_fixture_mode');
const raw = process.env.WAKEIO_OWNED_PLAN_FIXTURE;
if (!raw || !/^[A-Za-z0-9_-]{1,80}$/.test(raw)) throw Error('invalid_owned_fixture_directory');
const out = resolve(process.cwd(), raw);
await mkdir(out, { mode: 0o700 });
const target = await startNativeDastSqlite(mode);
let closing = false;
async function close() {
  if (closing) return; closing = true;
  await target.close();
  await writeFile(join(out, 'counts.json'), JSON.stringify({ version: 1, requestCount: target.requests.length }) + '\n', { mode: 0o600 });
}
process.on('SIGTERM', () => { void close().then(() => { process.exitCode = 0; }); });
process.on('SIGINT', () => { void close().then(() => { process.exitCode = 0; }); });
const policy = JSON.stringify({ version: 1, kind: 'sql-boolean-differential', baseUrl: `${target.origin}/`, url: target.url,
  parameter: 'id', profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } }) + '\n';
await writeFile(join(out, 'policy.json'), policy, { mode: 0o600 });
await writeFile(join(out, 'inputs.json'), JSON.stringify({ version: 1, inputs: [{ id: 'owned_policy', path: 'policy.json',
  sha256: createHash('sha256').update(policy).digest('hex') }] }) + '\n', { mode: 0o600 });
await writeFile(join(out, 'plan.json'), JSON.stringify({ version: 1, kind: 'wakeio.execution-plan', origin: target.origin,
  tasks: [{ id: 't-owned', engine: 'native-dast', policy: 'owned_policy', maxRequests: 8 }] }) + '\n', { mode: 0o600 });
await writeFile(join(out, 'ready.json'), JSON.stringify({ version: 1, origin: target.origin, pid: process.pid }) + '\n', { mode: 0o600 });
