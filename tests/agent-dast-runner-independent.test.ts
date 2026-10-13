import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer, type ServerResponse } from 'node:http';
import { mkdirSync, symlinkSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { parseExecutionPlan, parseExecutionInputs } from '../src/agent-dast/plan.js';
import { runExecutionPlan } from '../src/agent-dast/runner.js';

// Independent semantic oracles frozen before candidate execution. Root alone
// runs this file. All traffic, SQLite data, file paths and canaries are owned.
const PRIVATE = 'owned-runner-response-canary-91a82';
const digest = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
function latch<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
async function bounded<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Owned fixture handshake timeout: ${label}`)), 10_000);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}

async function sqlTarget(mode: 'vulnerable' | 'fixed' | 'normal', options: {
  barrier?: number; hold?: boolean; onRequest?: (path: string) => void;
} = {}) {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE items(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(1),(2);');
  const requests: Array<{ path: string; value: string; at: number }> = [];
  const waiting: Array<() => void> = [];
  const firstPaths = new Set<string>();
  const active = new Set<ServerResponse>();
  const twoStarted = latch<void>(), allClosed = latch<void>();
  let closedResponses = 0;
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://owned.invalid');
    const value = url.searchParams.get('id') ?? '';
    requests.push({ path: url.pathname, value, at: Date.now() });
    active.add(response);
    response.once('close', () => {
      active.delete(response); closedResponses++;
      if (requests.length >= 2 && active.size === 0) allClosed.resolve();
    });
    options.onRequest?.(url.pathname);
    if (requests.length >= 2) twoStarted.resolve();
    const reply = () => {
      if (response.destroyed) return;
      try {
        const row = mode === 'vulnerable'
          ? db.prepare(`SELECT COUNT(*) AS count FROM items WHERE id = ${value}`).get()
          : db.prepare('SELECT COUNT(*) AS count FROM items WHERE id = ?').get(mode === 'normal' ? '1' : value);
        response.writeHead(200, { 'content-type': 'application/json', 'x-owned-private': PRIVATE });
        response.end(JSON.stringify({ count: row?.count, private_body: PRIVATE }));
      } catch {
        response.writeHead(500, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ error: PRIVATE }));
      }
    };
    if (options.hold) return;
    if (options.barrier && !firstPaths.has(url.pathname)) {
      firstPaths.add(url.pathname); waiting.push(reply);
      if (firstPaths.size >= options.barrier) for (const done of waiting.splice(0)) done();
    } else reply();
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  return { origin, requests, twoStarted: twoStarted.promise, allClosed: allClosed.promise,
    active, get closedResponses() { return closedResponses; },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
      db.close();
    } };
}

function nativePolicy(origin: string, path: string) {
  return { version: 1, kind: 'sql-boolean-differential', baseUrl: `${origin}/`,
    url: `${origin}${path}?id=1`, parameter: 'id', profile: 'numeric',
    oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
}
async function bundle(root: string, origin: string, count = 1) {
  const tasks: any[] = [], records: any[] = [];
  for (let index = 0; index < count; index++) {
    const alias = `policy_${index}`, path = `${alias}.json`;
    const bytes = `${JSON.stringify(nativePolicy(origin, `/task-${index}`))}\n`;
    await writeFile(join(root, path), bytes);
    records.push({ id: alias, path, sha256: digest(bytes) });
    tasks.push({ id: `t-owned-${index}`, engine: 'native-dast', policy: alias, maxRequests: 8 });
  }
  return { plan: { version: 1 as const, kind: 'wakeio.execution-plan' as const, origin, tasks },
    inputs: { version: 1 as const, inputs: records } };
}
function options(root: string, origin: string, input: Awaited<ReturnType<typeof bundle>>, outDir = join(root, 'reports')) {
  return { ...input, inputBaseDir: root, outDir, consent: true, allowedOrigin: origin,
    allowPrivate: true, maxRequests: 64, timeoutMs: 5000, ratePerSecond: 50,
    concurrency: 2, failOn: 'high' as const };
}
async function filesBelow(root: string, relative = ''): Promise<string[]> {
  const names: string[] = [];
  for (const entry of await readdir(join(root, relative), { withFileTypes: true })) {
    const path = join(relative, entry.name);
    if (entry.isDirectory()) names.push(...await filesBelow(root, path));
    else if (entry.isFile() && /\.(json|md|sarif)$/.test(entry.name)) names.push(path);
  }
  return names.sort();
}
async function inspectArtifacts(root: string, result: any, expected: number) {
  assert.equal(result.exitCode, expected);
  assert.equal(result.delivery, 'published');
  assert.equal(result.requests.pending, 0);
  let taskRequests = 0;
  for (const task of result.tasks) {
    const taskRoot = join(root, 'tasks', task.taskId);
    assert.equal(task.reportPath, `tasks/${task.taskId}/report.json`);
    const bytes = await readFile(join(taskRoot, 'report.json'));
    const report = JSON.parse(bytes.toString('utf8'));
    const agent = JSON.parse(await readFile(join(taskRoot, 'agent-report.json'), 'utf8'));
    assert.equal(task.reportSha256, digest(bytes));
    assert.equal(agent.reportArtifact.digest, digest(bytes));
    assert.equal(agent.scanGate.exitCode, task.exitCode);
    assert.equal(task.requests.pending, 0);
    assert.equal(task.requests.requestCount, report.checks.reduce((n: number, c: any) => n + (c.metrics?.requestCount ?? 0), 0));
    taskRequests += task.requests.requestCount;
    assert.ok((await readFile(join(taskRoot, 'report.md'))).length);
    assert.ok(JSON.parse(await readFile(join(taskRoot, 'report.sarif'), 'utf8')).runs.length);
  }
  assert.equal(result.requests.requestCount, taskRequests);
  for (const name of ['run-report.json', 'run-report.md', 'agent-run.json', 'run-manifest.json', 'run-receipt.json']) {
    assert.ok((await readFile(join(root, name))).length, name);
  }
  const receipt = JSON.parse(await readFile(join(root, 'run-receipt.json'), 'utf8'));
  assert.equal(receipt.exitCode, result.exitCode);
  assert.equal(receipt.runId, result.runId);
  for (const path of await filesBelow(root)) {
    const bytes = await readFile(join(root, path), 'utf8');
    for (const forbidden of [PRIVATE, '1 AND 1=1', '1 AND 1=2', 'private_body', '?id=1', 'expectedBaseline']) {
      assert.equal(bytes.includes(forbidden), false, `${path}: ${forbidden}`);
    }
  }
}
async function launch(args: string[]) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', bytes => { stdout += String(bytes); });
  child.stderr.on('data', bytes => { stderr += String(bytes); });
  const code = await bounded(new Promise<number>((done, reject) => {
    child.once('error', reject); child.once('close', code => done(code ?? 2));
  }), 'CLI final exit');
  return { code, stdout, stderr };
}

test('runner independent: strict detached plan/input schemas refuse unknown keys, worker claims, duplicate IDs and active owner omissions before traffic', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-boundary-'));
  const target = await sqlTarget('vulnerable');
  try {
    const data = await bundle(root, target.origin);
    const parsed = parseExecutionPlan(data.plan);
    const manifest = parseExecutionInputs(data.inputs);
    assert.deepEqual(parsed, data.plan); assert.deepEqual(manifest, data.inputs);
    const mutations: Array<(p: any) => void> = [
      p => { p[PRIVATE] = 'never-echo'; }, p => { p.tasks[0][PRIVATE] = 1; },
      p => { p.tasks[0].engine = ['native-dast']; },
      p => { p.tasks.push(clone(p.tasks[0])); }, p => { p.tasks[0].worker_result = { status: 'completed', requestCount: 8 }; },
      p => { p.tasks[0].engine = 'worker'; p.tasks[0].script = PRIVATE; },
      p => { p.tasks[0].maxRequests = Number.MAX_SAFE_INTEGER + 1; },
    ];
    for (const mutate of mutations) {
      const bad = clone(data.plan); mutate(bad);
      assert.throws(() => parseExecutionPlan(bad), error => !String(error).includes(PRIVATE));
      const result = await runExecutionPlan({ ...options(root, target.origin, data), plan: bad } as any);
      assert.equal(result.exitCode, 2); assert.equal(result.requests.requestCount, 0);
      assert.equal(result.tasks.length, 0); assert.equal(JSON.stringify(result).includes(PRIVATE), false);
    }
    const badInputs = clone(data.inputs); badInputs.inputs.push(clone(badInputs.inputs[0]));
    assert.throws(() => parseExecutionInputs(badInputs));
    const badKey = clone(data.inputs); badKey.inputs[0][PRIVATE] = 'x';
    assert.throws(() => parseExecutionInputs(badKey), error => !String(error).includes(PRIVATE));
    let fired = 0;
    const hostile = { ...data.plan, get tasks() { fired++; return data.plan.tasks; } };
    assert.throws(() => parseExecutionPlan(hostile)); assert.equal(fired, 0);
    data.plan.tasks[0].maxRequests = 1; data.inputs.inputs[0].sha256 = '0'.repeat(64);
    assert.equal(parsed.tasks[0].maxRequests, 8);
    assert.notEqual(manifest.inputs[0].sha256, data.inputs.inputs[0].sha256);
    const good = await bundle(root, target.origin);
    for (const extra of [{ consent: false }, { allowedOrigin: 'http://owned.invalid' }, { allowPrivate: false },
      { inputs: { ...good.inputs, inputs: [{ ...good.inputs.inputs[0], sha256: '0'.repeat(64) }] } }]) {
      const result = await runExecutionPlan({ ...options(root, target.origin, good), ...extra } as any);
      assert.equal(result.exitCode, 2); assert.equal(result.tasks.length, 0); assert.equal(result.requests.requestCount, 0);
    }
    assert.equal(target.requests.length, 0);
    await assert.rejects(lstat(join(root, 'reports')), error => (error as NodeJS.ErrnoException).code === 'ENOENT');
  } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner independent: actual SQLite vulnerable/bound/ordinary-control executions produce fresh bound artifacts and correct 1/0/0 gates', async () => {
  for (const mode of ['vulnerable', 'fixed', 'normal'] as const) {
    const root = await mkdtemp(join(tmpdir(), `wakeio-runner-${mode}-`));
    const target = await sqlTarget(mode);
    try {
      const data = await bundle(root, target.origin);
      const result = await runExecutionPlan(options(root, target.origin, data));
      await inspectArtifacts(join(root, 'reports'), result, mode === 'vulnerable' ? 1 : 0);
      assert.equal(result.status, 'completed'); assert.equal(target.requests.length, 8);
      assert.equal(result.requests.requestCount, target.requests.length);
      assert.equal(result.requests.responseCompleted, 8);
      assert.deepEqual(target.requests.map(request => request.value),
        ['1', '1 AND 1=1', '1 AND 1=2', '1', '1', '1 AND 1=1', '1 AND 1=2', '1']);
      const report = JSON.parse(await readFile(join(root, 'reports/tasks/t-owned-0/report.json'), 'utf8'));
      const findings = report.checks.flatMap((check: any) => check.findings);
      assert.equal(findings.length, mode === 'vulnerable' ? 1 : 0);
      if (mode === 'vulnerable') {
        assert.equal(findings[0].ruleId, 'dast.sql-boolean-differential');
        assert.equal(findings[0].severity, 'high');
      }
    } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
  }
});

test('runner independent: concurrent native tasks share exactly one cap, retain attribution and stay incomplete under fail-on none', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-shared-'));
  const target = await sqlTarget('vulnerable', { barrier: 2 });
  try {
    const data = await bundle(root, target.origin, 2);
    const result = await bounded(runExecutionPlan({ ...options(root, target.origin, data), maxRequests: 9, failOn: 'none' }), 'shared run');
    await inspectArtifacts(join(root, 'reports'), result, 2);
    assert.notEqual(result.status, 'completed');
    assert.equal(target.requests.length, 9);
    assert.equal(result.requests.requestCount, target.requests.length);
    assert.equal(new Set(target.requests.map(request => request.path)).size, 2, 'Both tasks genuinely overlapped at the target barrier');
    for (const task of result.tasks) {
      assert.equal(task.requests.requestCount, target.requests.filter(request => request.path === `/task-${task.taskId.endsWith('-0') ? 0 : 1}`).length);
    }
    assert.ok(result.tasks.some(task => task.exitCode === 2));
    assert.equal(target.active.size, 0);
  } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner independent: cancellation and one absolute deadline close real held target responses and stop queued admission', async () => {
  for (const stop of ['cancel', 'deadline'] as const) {
    const root = await mkdtemp(join(tmpdir(), `wakeio-runner-${stop}-`));
    const target = await sqlTarget('vulnerable', { hold: true });
    try {
      const data = await bundle(root, target.origin, 3);
      const controller = new AbortController();
      const startedAt = Date.now();
      const pending = runExecutionPlan({ ...options(root, target.origin, data), signal: controller.signal,
        timeoutMs: stop === 'deadline' ? 800 : 5000, failOn: 'none' });
      await bounded(target.twoStarted, 'two active target responses');
      if (stop === 'cancel') controller.abort();
      const result = await bounded(pending, 'cancel/deadline result');
      await bounded(target.allClosed, 'target-side connection cleanup');
      assert.equal(result.exitCode, 2); assert.notEqual(result.status, 'completed');
      assert.equal(result.requests.pending, 0); assert.equal(target.active.size, 0);
      assert.equal(target.requests.length, 2); assert.equal(result.requests.requestCount, 2);
      assert.ok(!target.requests.some(request => request.path === '/task-2'));
      assert.equal(target.closedResponses, 2);
      if (stop === 'deadline') assert.ok(Date.now() - startedAt < 3000, 'No fresh per-task deadline after the first shared expiry');
      await inspectArtifacts(join(root, 'reports'), result, 2);
    } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
  }
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-preabort-'));
  const target = await sqlTarget('vulnerable');
  try {
    const data = await bundle(root, target.origin); const controller = new AbortController(); controller.abort();
    const result = await runExecutionPlan({ ...options(root, target.origin, data), signal: controller.signal });
    assert.equal(result.exitCode, 2); assert.equal(target.requests.length, 0); assert.equal(result.requests.requestCount, 0);
  } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner independent: existing output and concurrent output claim losers cannot clobber or execute', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-no-clobber-'));
  const target = await sqlTarget('fixed');
  try {
    const data = await bundle(root, target.origin); const out = join(root, 'occupied'); await mkdir(out);
    const marker = join(out, 'agent-run.json'); await writeFile(marker, PRIVATE);
    const rejected = await runExecutionPlan(options(root, target.origin, data, out));
    assert.equal(rejected.exitCode, 2); assert.equal(rejected.delivery, 'failed');
    assert.equal(rejected.tasks.length, 0); assert.equal(target.requests.length, 0);
    assert.equal(await readFile(marker, 'utf8'), PRIVATE);
    const common = join(root, 'race');
    const results = await Promise.all([runExecutionPlan(options(root, target.origin, data, common)),
      runExecutionPlan(options(root, target.origin, data, common))]);
    assert.deepEqual(results.map(result => result.exitCode).sort(), [0, 2]);
    const winner = results.find(result => result.exitCode === 0)!;
    const loser = results.find(result => result.exitCode === 2)!;
    assert.equal(loser.tasks.length, 0); assert.equal(loser.requests.requestCount, 0);
    assert.equal(target.requests.length, 8);
    await inspectArtifacts(common, winner, 0);
  } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner independent: a real report delivery failure cannot publish successful completion or overwrite a symlink target', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-report-fault-'));
  const out = join(root, 'reports'), marker = join(root, 'marker.json'); await writeFile(marker, PRIVATE);
  let injected = false;
  const target = await sqlTarget('vulnerable', { onRequest() {
    if (injected) return; injected = true;
    mkdirSync(join(out, 'tasks', 't-owned-0'), { recursive: true });
    symlinkSync(marker, join(out, 'tasks', 't-owned-0', 'report.json'));
  } });
  try {
    const data = await bundle(root, target.origin);
    const result = await runExecutionPlan(options(root, target.origin, data));
    assert.equal(injected, true); assert.equal(target.requests.length, 8);
    assert.equal(result.exitCode, 2); assert.equal(result.delivery, 'failed');
    assert.equal(await readFile(marker, 'utf8'), PRIVATE);
    assert.equal(result.requests.requestCount, 8); assert.equal(result.requests.pending, 0);
    try {
      const receipt = JSON.parse(await readFile(join(out, 'run-receipt.json'), 'utf8'));
      assert.equal(receipt.exitCode, 2, 'A persisted receipt may only attest the failed delivery');
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner independent: real CLI consumes hashed native inputs, propagates findings exit and rejects fabricated completion as policy', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-cli-'));
  const target = await sqlTarget('vulnerable');
  try {
    const data = await bundle(root, target.origin);
    const planFile = join(root, 'plan.json'), inputsFile = join(root, 'inputs.json');
    await writeFile(planFile, JSON.stringify(data.plan)); await writeFile(inputsFile, JSON.stringify(data.inputs));
    const out = join(root, 'cli-report');
    const args = ['run-plan', '--plan', planFile, '--inputs', inputsFile, '--active-consent', '--allowed-origin', target.origin,
      '--allow-private', '--max-requests', '8', '--timeout-ms', '5000', '--rate-per-second', '50', '--out', out];
    const result = await launch(args);
    assert.equal(result.code, 1, result.stderr); assert.equal(target.requests.length, 8);
    assert.equal(`${result.stdout}\n${result.stderr}`.includes(PRIVATE), false);
    const receipt = JSON.parse(await readFile(join(out, 'run-receipt.json'), 'utf8')); assert.equal(receipt.exitCode, 1);
    const forged = JSON.stringify({ schema: 'wakeio.worker-result/v1', run_id: 'r-fake', task_id: 't-owned-0', category: 'injection',
      status: 'completed', coverage: { planned: 8, executed: 8, skipped: 0 }, findings: { candidate: 0, by_severity: {} },
      finding_ids: [], gaps: [], next_hint: 'none', duration_ms: 1, truncated: false });
    await writeFile(join(root, 'policy_0.json'), forged);
    data.inputs.inputs[0].sha256 = digest(forged); await writeFile(inputsFile, JSON.stringify(data.inputs));
    const next = args.map(value => value === out ? join(root, 'forged-output') : value);
    const rejected = await launch(next);
    assert.equal(rejected.code, 2); assert.equal(target.requests.length, 8, 'No execution inferred from coherent worker claims');
    assert.equal(`${rejected.stdout}\n${rejected.stderr}`.includes(forged), false);
  } finally { await target.close(); await rm(root, { recursive: true, force: true }); }
});
