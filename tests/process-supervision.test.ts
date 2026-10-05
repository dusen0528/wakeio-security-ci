import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { observeOwnedGroup, parseStrictRows, runProcess } from '../src/source/process.js';

async function owned(script: string, options: Partial<Parameters<typeof runProcess>[2]> = {}) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-owned-process-'));
  try { return await runProcess(process.execPath, ['-e', script], { cwd: top, home: top, tmpdir: top, timeoutMs: 1500, supervision: 'native-offline', ...options }); }
  finally { await rm(top, { recursive: true, force: true }); }
}

test('strict pre-abort starts no process and rejects auth/custom environment profiles', async () => {
  const controller = new AbortController(); controller.abort();
  const p = await owned('throw Error("must not execute")', { signal: controller.signal });
  assert.equal(p.cancelled, true); assert.equal(p.cleanupState, 'not_started'); assert.equal(p.exited, false); assert.equal(p.stdout, '');
  for (const option of [{ environment: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: '/db' } }, { authentication: { variable: 'CODEX_API_KEY' as const, value: 'synthetic' } }]) {
    assert.equal((await owned('throw Error("must not execute")', option)).stopReason, 'spawn_error');
  }
});

test('strict ps parser rejects empty/malformed and group EPERM remains unknown', () => {
  for (const raw of ['', 'pid pgid rss state', '1 1 -1 S', '1 1 0 S extra', '9007199254740993 1 0 S', '42 42 1 Zgarbage']) assert.throws(() => parseStrictRows(raw));
  assert.deepEqual(parseStrictRows('42 42 1024 S\n'), [{ pid: 42, pgid: 42, rss: 1024, state: 'S' }]);
  assert.deepEqual(parseStrictRows('42 42 1 Zs+\n43 43 1 ?\n44 44 1 SA\n').map((row) => row.state), ['Zs+', '?', 'SA']);
  const original = process.kill;
  try { process.kill = (() => { throw Object.assign(new Error('owned synthetic'), { code: 'EPERM' }); }) as typeof process.kill;
    assert.equal(observeOwnedGroup(123456), 'unknown');
  } finally { process.kill = original; }
  const originalPs = childProcess.execFileSync;
  try {
    process.kill = (() => true) as typeof process.kill;
    childProcess.execFileSync = (() => '42 42 1 ?\n') as unknown as typeof originalPs; syncBuiltinESMExports();
    assert.equal(observeOwnedGroup(42), 'unknown');
  } finally { process.kill = original; childProcess.execFileSync = originalPs; syncBuiltinESMExports(); }
});

test('strict environment contains only private OS paths and never inherits auth/proxy', async () => {
  const previous = process.env.HTTPS_PROXY; process.env.HTTPS_PROXY = 'http://synthetic-proxy.test';
  try {
    const p = await owned('process.stdout.write(JSON.stringify(process.env)); setTimeout(()=>{},180)');
    assert.equal(p.stopReason, undefined); assert.equal(p.rss?.failedSamples, 0);
    const env = JSON.parse(p.stdout); assert.equal(env.HTTPS_PROXY, undefined); assert.equal(env.CODEX_API_KEY, undefined);
    assert.equal(env.PATH, '/usr/bin:/bin:/usr/sbin:/sbin'); assert.equal(env.HOME, env.TMPDIR);
    assert.equal(p.closeConfirmed, true); assert.equal(p.cleanupConfirmed, true); assert.equal(p.rss?.assessment, 'measured');
  } finally { if (previous === undefined) delete process.env.HTTPS_PROXY; else process.env.HTTPS_PROXY = previous; }
});

test('strict timeout and abort settle with the actual first reason and confirmed cleanup', async () => {
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 140);
  try {
    const p = await owned('setInterval(()=>{},1000)', { signal: controller.signal, timeoutMs: 900 });
    assert.equal(p.stopReason, 'cancelled'); assert.equal(p.cancelled, true);
    assert.equal(p.closeConfirmed, true); assert.equal(p.cleanupConfirmed, true);
  } finally { clearTimeout(timer); }
  const p = await owned('setInterval(()=>{},1000)', { timeoutMs: 160 });
  assert.equal(p.stopReason, 'timeout'); assert.equal(p.timedOut, true); assert.equal(p.cleanupConfirmed, true);
});

test('strict root exit actually cleans inherited and detached stdio descendants', async () => {
  for (const stdio of ['inherit', 'ignore']) {
    const script = `const {spawn}=require('node:child_process'); spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:${JSON.stringify(stdio)}});setTimeout(()=>process.exit(0),200);`;
    const started = Date.now(), p = await owned(script);
    assert.ok(Date.now() - started < 5000);
    assert.equal(p.stopReason, undefined); assert.equal(p.rss?.assessment, 'measured');
    assert.equal(p.exitCode, 0); assert.equal(p.exited, true); assert.equal(p.closeConfirmed, true);
    assert.equal(p.cleanupConfirmed, true); assert.ok(['terminated', 'terminated_zombies'].includes(p.cleanupState ?? ''));
  }
});

test('strict output byte cap never emits more than the declared bytes and UTF8 is decoded after collection', async () => {
  const p = await owned('process.stdout.write("😀".repeat(10000));setInterval(()=>{},1000)', { maxOutputBytes: 128 });
  assert.equal(p.stopReason, 'output_limit'); assert.equal(p.outputLimitExceeded, true); assert.ok(Buffer.byteLength(p.stdout) <= 128);
  const fragmented = await owned('const b=Buffer.from("가😀");process.stdout.write(b.subarray(0,2));setTimeout(()=>process.stdout.write(b.subarray(2)),50);setTimeout(()=>{},180)');
  assert.equal(fragmented.stopReason, undefined); assert.equal(fragmented.stdout, '가😀');
});

test('explicit owned observer failure is unassessed and never a normal-success substitute', async () => {
  const original = childProcess.execFileSync;
  try {
    childProcess.execFileSync = (() => { throw Object.assign(new Error('owned observer fault'), { code: 'EPERM' }); }) as typeof original;
    syncBuiltinESMExports();
    const p = await owned('setInterval(()=>{},1000)');
    assert.equal(p.stopReason, 'observer_unknown'); assert.equal(p.rss?.assessment, 'unassessed'); assert.ok((p.rss?.failedSamples ?? 0) > 0);
  } finally { childProcess.execFileSync = original; syncBuiltinESMExports(); }
});
