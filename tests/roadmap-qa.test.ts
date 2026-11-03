import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, mkdir, symlink, writeFile, readdir, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { once } from 'node:events';

const exec = promisify(execFile);
const cli = resolve('scripts/qa/roadmap.mjs');
type Capture = {
  readonly reason: string | null; readonly exitCode: number | null; readonly stdout: string;
  readonly stderr: string; readonly truncated: boolean;
  readonly cleanup: { readonly confirmed: boolean; readonly pid: number | null; readonly groupGone: boolean };
};
const processQa: {
  readonly captureProcess: (command: string, args: readonly string[], options?: {
    readonly signal?: AbortSignal; readonly timeoutMs?: number; readonly maxOutputBytes?: number;
    readonly onStdout?: (text: string) => void;
  }) => Promise<Capture>;
} = await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/process.mjs')).href);

async function invoke(args: readonly string[]) {
  try {
    const result = await exec(process.execPath, [cli, ...args], { timeout: 15000 });
    return { code: 0, ...result };
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && 'stdout' in error && 'stderr' in error)) throw error;
    return { code: error.code, stdout: String(error.stdout), stderr: String(error.stderr) };
  }
}

async function json(out: string, name: string): Promise<Record<string, unknown>> {
  const value: unknown = JSON.parse(await readFile(join(out, name), 'utf8'));
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  return Object.fromEntries(Object.entries(value));
}

async function sandbox(t: test.TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'roadmap-qa-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('harness CLI captures real Node output and loopback HTTP with bound artifacts and no residue', async t => {
  const out = join(await sandbox(t), 'happy');
  const result = await invoke(['--case', 'harness', '--out', out]);
  assert.equal(result.code, 0, result.stderr);
  const child = await json(out, 'cli.json'), http = await json(out, 'http.json');
  assert.equal(child.exitCode, 0);
  assert.deepEqual(JSON.parse(String(child.stdout)), { surface: 'node-cli', value: 42 });
  assert.equal(child.stderr, 'password=[REDACTED]\n');
  assert.equal(child.truncated, false);
  assert.equal(http.status, 200); assert.equal(http.complete, true);
  assert.deepEqual(JSON.parse(String(http.body)), { surface: 'loopback-http', value: 42 });
  assert.ok(http.headers && typeof http.headers === 'object' && 'content-type' in http.headers);
  assert.equal(http.headers['content-type'], 'application/json');
  const cleanup = await json(out, 'cleanup.json');
  assert.equal(cleanup.confirmed, true); assert.equal(cleanup.portReleased, true);
  const probe = createServer(), ready = once(probe, 'listening', { signal: AbortSignal.timeout(2000) });
  assert.equal(typeof cleanup.port, 'number');
  probe.listen(Number(cleanup.port), '127.0.0.1');
  await ready;
  const closed = once(probe, 'close'); probe.close(); await closed;
  assert.ok(Array.isArray(cleanup.children));
  assert.equal(cleanup.children.length, 1);
  for (const item of cleanup.children) {
    assert.throws(() => process.kill(item.pid, 0), { code: 'ESRCH' });
  }
  const receipt = await json(out, 'result.json');
  assert.equal(receipt.exitCode, 0); assert.equal(receipt.status, 'pass');
  assert.match(String(receipt.head), /^[a-f0-9]{40}$/);
  assert.ok(Array.isArray(receipt.artifacts));
  assert.equal(receipt.artifacts.length, 3);
  for (const artifact of receipt.artifacts) {
    const bytes = await readFile(join(out, artifact.path));
    assert.equal(artifact.bytes, bytes.length);
    assert.equal(artifact.sha256, createHash('sha256').update(bytes).digest('hex'));
  }
});

for (const scenario of [
  { mutate: 'child-abort', code: 2, reason: 'cancelled' },
  { mutate: 'handler-error', code: 2, reason: 'handler_error' },
  { mutate: 'long-child', code: 2, reason: 'timeout' },
  { mutate: 'output-limit', code: 2, reason: 'output_limit' },
  { mutate: 'truncated-output', code: 1, reason: null },
  { mutate: 'child-fail', code: 1, reason: null },
] as const) {
  test(`harness rejects ${scenario.mutate} and reaps its owned child and socket`, async t => {
    const out = join(await sandbox(t), 'negative');
    const result = await invoke(['--case', 'harness', '--out', out, '--mutate', scenario.mutate]);
    assert.equal(result.code, scenario.code, result.stderr);
    const child = await json(out, 'cli.json'), cleanup = await json(out, 'cleanup.json');
    assert.equal(child.reason, scenario.reason);
    assert.equal(cleanup.confirmed, true); assert.equal(cleanup.portReleased, true);
    assert.ok(Array.isArray(cleanup.children));
    const children = cleanup.children;
    assert.equal(children.length, 1);
    assert.throws(() => process.kill(children[0].pid, 0), { code: 'ESRCH' });
    assert.equal((await json(out, 'result.json')).exitCode, scenario.code);
  });
}

test('incomplete cleanup cannot qualify an otherwise successful CLI and HTTP run', async t => {
  const out = join(await sandbox(t), 'incomplete');
  assert.equal((await invoke(['--case', 'harness', '--out', out, '--mutate', 'incomplete-cleanup'])).code, 2);
  assert.equal((await json(out, 'cleanup.json')).confirmed, false);
  assert.equal((await json(out, 'result.json')).status, 'unavailable');
});

test('unknown and missing future cases remain unavailable without starting resources', async t => {
  const top = await sandbox(t);
  const missing = ['unknown'];
  // Future lanes may add these real cases. Only their absence is this driver's contract.
  for (const name of ['policy', 'manifest']) {
    try { await lstat(resolve('scripts/qa/roadmap-cases', name + '.mjs')); }
    catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
      missing.push(name);
    }
  }
  for (const name of missing) {
    const out = join(top, name);
    assert.equal((await invoke(['--case', name, '--out', out])).code, 2);
    assert.equal((await json(out, 'result.json')).status, 'unavailable');
    assert.equal((await json(out, 'cleanup.json')).scope, 'not_started');
  }
});

test('malformed argv is refused before creating evidence', async t => {
  const top = await sandbox(t);
  for (const args of [
    [], ['--out', join(top, 'missing-case')], ['--case', 'harness'],
    ['--case', '../harness', '--out', join(top, 'path')],
    ['--case', 'harness', '--out', join(top, 'duplicate'), '--case', 'harness'],
    ['--case', 'harness', '--out', join(top, 'odd'), '--mutate'],
    ['--case', 'harness', '--out', join(top, 'flag'), '--dry-run', 'true'],
  ]) assert.equal((await invoke(args)).code, 2);
  assert.deepEqual(await readdir(top), []);
});

test('existing outputs and symlink ancestors preserve foreign files and reject stale green receipts', async t => {
  const top = await sandbox(t), dirty = join(top, 'dirty'), outside = join(top, 'outside');
  await mkdir(dirty); await mkdir(outside);
  const stale = '{"status":"pass","exitCode":0}\n';
  await writeFile(join(dirty, 'result.json'), stale);
  await symlink(outside, join(top, 'link'));
  for (const out of [dirty, join(top, 'link'), join(top, 'link', 'new')]) {
    assert.equal((await invoke(['--case', 'harness', '--out', out])).code, 2);
  }
  assert.equal(await readFile(join(dirty, 'result.json'), 'utf8'), stale);
  assert.deepEqual(await readdir(outside), []);
});

test('external SIGTERM during a ready real case preserves cleanup and exits unavailable', async t => {
  const out = join(await sandbox(t), 'signal');
  const child = spawn(process.execPath, [cli, '--case', 'harness', '--out', out, '--mutate', 'long-child'],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  const completion = once(child, 'close', { signal: AbortSignal.timeout(15000) });
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  let text = '', signalled = false;
  child.stdout.on('data', chunk => {
    text += chunk.toString();
    if (!signalled && text.includes('"event":"case_ready"')) { signalled = true; child.kill('SIGTERM'); }
  });
  const [code, signal] = await completion;
  assert.equal(signalled, true); assert.equal(signal, null); assert.equal(code, 2);
  assert.equal((await json(out, 'cleanup.json')).confirmed, true);
  assert.equal((await json(out, 'cli.json')).reason, 'cancelled');
});

test('capture redacts credentials split across writes only after complete collection', async () => {
  const result = await processQa.captureProcess(process.execPath, ['-e',
    'process.stdout.write("pass",()=>process.stdout.write("word=private-value\\n")); process.stderr.write("Bearer split-",()=>process.stderr.write("private\\n"))']);
  assert.equal(result.exitCode, 0); assert.equal(result.cleanup.confirmed, true);
  assert.equal(result.stdout, 'password=[REDACTED]\n');
  assert.equal(result.stderr, 'Bearer [REDACTED]\n');
});

test('pre-aborted capture starts no child and invalid budgets are rejected', async () => {
  const controller = new AbortController(); controller.abort();
  const result = await processQa.captureProcess(process.execPath, ['-e', 'process.exit(99)'], { signal: controller.signal });
  assert.equal(result.reason, 'cancelled'); assert.equal(result.cleanup.pid, null);
  assert.equal(result.cleanup.confirmed, true); assert.equal(result.stdout, '');
  await assert.rejects(processQa.captureProcess(process.execPath, [], { timeoutMs: 0 }), TypeError);
  await assert.rejects(processQa.captureProcess(process.execPath, [], { maxOutputBytes: 0 }), TypeError);
});

test('capture discards incomplete private-key output rather than retaining a capped secret fragment', async () => {
  const result = await processQa.captureProcess(process.execPath, ['-e',
    'process.stdout.write("-----BEGIN PRIVATE KEY-----\\n"+"private".repeat(20000)); setInterval(()=>{},1000)'],
  { maxOutputBytes: 128 });
  assert.equal(result.reason, 'output_limit'); assert.equal(result.truncated, true);
  assert.equal(result.cleanup.confirmed, true);
  assert.doesNotMatch(result.stdout, /BEGIN|private/);
  assert.doesNotMatch(result.stderr, /BEGIN|private/);
});
