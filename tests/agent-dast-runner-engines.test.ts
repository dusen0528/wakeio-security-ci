import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, type ServerResponse } from 'node:http';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runExecutionPlan } from '../src/agent-dast/runner.js';

// Supplemental independent public-runner controls. Author never executes this
// file; root supplies the existing reviewed runtimes and owns execution.
const PRIVATE = 'owned-engine-body-canary-aac83';
const digest = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
const python = process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(process.cwd(), '.venv-schemathesis/bin/python');
const nuclei = process.env.WAKEIO_NUCLEI;
const templates = process.env.WAKEIO_NUCLEI_TEMPLATES;
const required = process.env.WAKEIO_REQUIRE_RUNNER_ENGINES === '1';
const pythonPresent = await stat(python).then(value => value.isFile()).catch(() => false);
const schemSkip = pythonPresent || required ? false : 'provide the reviewed Schemathesis Python; required runner suite refuses its absence';
const nucleiSkip = nuclei && templates || required || process.env.WAKEIO_REQUIRE_NUCLEI === '1'
  ? false : 'provide WAKEIO_NUCLEI and WAKEIO_NUCLEI_TEMPLATES; required runner suite refuses their absence';

function schema() {
  const response = { type: 'object', required: ['id'], properties: { id: { type: 'integer' }, note: { type: 'string' } } };
  const operation = { operationId: 'ownedRead', parameters: [{ name: 'id', in: 'query', required: true,
    schema: { type: 'integer', minimum: 1, maximum: 1000 } }], responses: { '200': {
    description: 'Owned item', content: { 'application/json': { schema: response } } } } };
  return { openapi: '3.0.3', info: { title: 'Owned contract', version: '1.0.0' }, paths: { '/item': { get: operation } } };
}
function nativePolicy(origin: string) {
  return { version: 1, kind: 'sql-boolean-differential', baseUrl: `${origin}/`, url: `${origin}/native?id=1`,
    parameter: 'id', profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
}
async function inputs(root: string, values: Record<string, unknown>) {
  const records = [];
  for (const [id, value] of Object.entries(values)) {
    const bytes = `${JSON.stringify(value)}\n`, path = `${id}.json`; await writeFile(join(root, path), bytes);
    records.push({ id, path, sha256: digest(bytes) });
  }
  return { version: 1, inputs: records };
}
async function target(mode: 'vulnerable' | 'fixed' | 'transport-failure', barrier = false) {
  const db = new DatabaseSync(':memory:'); db.exec('CREATE TABLE items(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(1),(2);');
  const hits: Array<{ method: string; path: string }> = [], active = new Set<ServerResponse>();
  const pending: Array<() => void> = [], paths = new Set<string>();
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://owned.invalid');
    hits.push({ method: request.method ?? '', path: url.pathname }); active.add(response);
    response.once('close', () => active.delete(response));
    if (mode === 'transport-failure' && hits.length > 2) { request.socket.destroy(); return; }
    const reply = () => {
      if (response.destroyed) return;
      if (url.pathname === '/native') {
        const value = url.searchParams.get('id') ?? '';
        const row = mode === 'vulnerable'
          ? db.prepare(`SELECT COUNT(*) AS count FROM items WHERE id = ${value}`).get()
          : db.prepare('SELECT COUNT(*) AS count FROM items WHERE id = ?').get(value);
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ count: row?.count, note: PRIVATE }));
      } else if (url.pathname === '/item') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ id: mode === 'vulnerable' ? PRIVATE : Number(url.searchParams.get('id')), note: PRIVATE }));
      } else if (url.pathname === '/.git/config' && mode === 'vulnerable') {
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.end(`[core]\n repositoryformatversion = 0\n pass = ${PRIVATE}\n`);
      } else { response.writeHead(404); response.end('Owned missing route'); }
    };
    if (barrier && ['/native', '/.git/config'].includes(url.pathname) && !paths.has(url.pathname)) {
      paths.add(url.pathname); pending.push(reply);
      if (paths.size === 2) for (const done of pending.splice(0)) done();
    } else reply();
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  return { origin: `http://127.0.0.1:${address.port}`, hits, active,
    async close() { server.closeAllConnections(); await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done())); db.close(); } };
}
function runtime(root: string, origin: string, plan: any, manifest: any, extra: Record<string, unknown> = {}) {
  return { plan, inputs: manifest, inputBaseDir: root, outDir: join(root, 'reports'), consent: true,
    allowedOrigin: origin, allowPrivate: true, maxRequests: 32, timeoutMs: 30_000, ratePerSecond: 50,
    concurrency: 2, failOn: 'low' as const, schemathesisPython: python, ...extra };
}
function plan(origin: string, tasks: any[]) { return { version: 1, kind: 'wakeio.execution-plan', origin, tasks }; }
async function taskReport(root: string, taskId: string) {
  const directory = join(root, 'reports', 'tasks', taskId);
  const bytes = await readFile(join(directory, 'report.json'));
  const report = JSON.parse(bytes.toString('utf8'));
  const agent = JSON.parse(await readFile(join(directory, 'agent-report.json'), 'utf8'));
  assert.equal(agent.reportArtifact.digest, digest(bytes));
  for (const name of ['report.md', 'report.sarif', 'report.json', 'agent-report.json']) {
    const text = await readFile(join(directory, name), 'utf8');
    assert.equal(text.includes(PRIVATE), false, name);
    assert.equal(text.includes('1 AND 1='), false, name);
  }
  return { report, agent };
}
function counters(result: any, hits: Array<{ method: string; path: string }>, completed = true) {
  assert.equal(result.requests.pending, 0);
  assert.equal(result.requests.requestCount, result.tasks.reduce((n: number, task: any) => n + task.requests.requestCount, 0));
  assert.ok(hits.length <= result.requests.requestCount);
  assert.ok(hits.length <= 32);
  if (completed) assert.equal(result.requests.requestCount, hits.length, 'All successful admitted requests actually reached the owned target');
  assert.ok(hits.every(hit => ['GET', 'HEAD'].includes(hit.method)));
}
async function signedGitSubset(root: string) {
  assert.ok(templates, 'WAKEIO_NUCLEI_TEMPLATES required');
  const original = await readFile(join(templates, 'http/exposures/configs/git-config.yaml'));
  assert.match(original.toString('utf8'), /^id: git-config\s/m);
  assert.match(original.toString('utf8'), /^# digest: [a-f0-9]+:[a-f0-9]{32}\s*$/m);
  const subset = join(root, 'signed-subset'); await mkdir(join(subset, 'http/exposures/configs'), { recursive: true });
  await writeFile(join(subset, 'http/exposures/configs/git-config.yaml'), original);
  // This is an owned one-template manifest. Template bytes/signature are copied
  // unchanged from the reviewed installed library; no download or re-signing.
  await writeFile(join(subset, 'templates-checksum.txt'), `http/exposures/configs/git-config.yaml:${digest(original)}\n`);
  const config = join(templates, '.templates-config.json');
  if (await stat(config).then(value => value.isFile()).catch(() => false)) await copyFile(config, join(subset, '.templates-config.json'));
  return subset;
}

test('runner engines independent: real Schemathesis vulnerable/fixed contract pair and irrecoverable transport errors propagate 1/0/2', { skip: schemSkip }, async () => {
  assert.ok(pythonPresent, 'Required runner suite needs the existing reviewed Schemathesis Python');
  for (const mode of ['vulnerable', 'fixed', 'transport-failure'] as const) {
    const root = await mkdtemp(join(tmpdir(), `wakeio-runner-schem-${mode}-`)), fixture = await target(mode);
    try {
      const manifest = await inputs(root, { contract: schema() });
      const data = plan(fixture.origin, [{ id: 't-real-schem', engine: 'schemathesis', schema: 'contract', operations: ['/item'], seed: 7, maxRequests: 8 }]);
      const result = await runExecutionPlan(runtime(root, fixture.origin, data, manifest));
      assert.equal(result.exitCode, mode === 'vulnerable' ? 1 : mode === 'fixed' ? 0 : 2);
      assert.equal(result.delivery, 'published'); counters(result, fixture.hits, mode !== 'transport-failure');
      assert.ok(fixture.hits.length >= 3); assert.ok(fixture.hits.every(hit => hit.path === '/item'));
      const { report, agent } = await taskReport(root, 't-real-schem');
      assert.equal(agent.scanGate.exitCode, result.exitCode);
      const findings = report.checks.flatMap((check: any) => check.findings);
      if (mode === 'vulnerable') assert.ok(findings.some((finding: any) => finding.ruleId === 'api.schemathesis.response_schema'));
      if (mode === 'fixed') assert.deepEqual(findings, []);
      if (mode === 'transport-failure') assert.ok(report.checks.some((check: any) => ['partial', 'error'].includes(check.status)));
      assert.equal(fixture.active.size, 0);
    } finally { await fixture.close(); await rm(root, { recursive: true, force: true }); }
  }
});

test('runner engines independent: real signed one-template Nuclei and native SQL tasks overlap and share observed run counts', { skip: nucleiSkip }, async () => {
  assert.ok(nuclei && templates, 'Required runner suite needs reviewed Nuclei executable and template library');
  for (const mode of ['vulnerable', 'fixed'] as const) {
    const root = await mkdtemp(join(tmpdir(), `wakeio-runner-nuclei-${mode}-`)), fixture = await target(mode, true);
    try {
      const subset = await signedGitSubset(root);
      const manifest = await inputs(root, { numeric: nativePolicy(fixture.origin) });
      const data = plan(fixture.origin, [{ id: 't-real-native', engine: 'native-dast', policy: 'numeric', maxRequests: 8 },
        { id: 't-real-nuclei', engine: 'nuclei', scopes: ['exposures'], maxRequests: 8 }]);
      const result = await runExecutionPlan(runtime(root, fixture.origin, data, manifest,
        { maxRequests: 16, nucleiPath: nuclei, nucleiTemplates: subset, failOn: 'medium' }));
      assert.equal(result.exitCode, mode === 'vulnerable' ? 1 : 0);
      assert.equal(result.status, 'completed'); assert.equal(result.delivery, 'published'); counters(result, fixture.hits);
      assert.equal(fixture.hits.filter(hit => hit.path === '/native').length, 8);
      assert.ok(fixture.hits.some(hit => hit.path === '/.git/config'));
      assert.ok(fixture.hits.length <= 16);
      for (const task of result.tasks) {
        assert.equal(task.requests.requestCount, fixture.hits.filter(hit => task.engine === 'native-dast' ? hit.path === '/native' : hit.path !== '/native').length);
        const { report, agent } = await taskReport(root, task.taskId); assert.equal(agent.scanGate.exitCode, task.exitCode);
        if (task.engine === 'nuclei') {
          const findings = report.checks.flatMap((check: any) => check.findings);
          assert.equal(findings.some((finding: any) => finding.ruleId === 'nuclei.git-config'), mode === 'vulnerable');
          assert.equal(report.checks.find((check: any) => check.id === 'url.nuclei').metrics.templatesSelected, 1);
        }
      }
      assert.equal(fixture.active.size, 0);
    } finally { await fixture.close(); await rm(root, { recursive: true, force: true }); }
  }
});

test('runner engines independent: real Schemathesis and native execution consume one global cap rather than per-engine caps', { skip: schemSkip }, async () => {
  assert.ok(pythonPresent, 'Required runner suite needs the existing reviewed Schemathesis Python');
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-engine-cap-')), fixture = await target('fixed');
  try {
    const manifest = await inputs(root, { numeric: nativePolicy(fixture.origin), contract: schema() });
    const data = plan(fixture.origin, [{ id: 't-cap-native', engine: 'native-dast', policy: 'numeric', maxRequests: 8 },
      { id: 't-cap-schem', engine: 'schemathesis', schema: 'contract', operations: ['/item'], seed: 7, maxRequests: 8 }]);
    const result = await runExecutionPlan(runtime(root, fixture.origin, data, manifest, { maxRequests: 12, failOn: 'none' }));
    assert.equal(result.exitCode, 2); assert.notEqual(result.status, 'completed'); counters(result, fixture.hits);
    assert.equal(result.requests.requestCount, 12); assert.equal(fixture.hits.length, 12);
    assert.ok(fixture.hits.some(hit => hit.path === '/native')); assert.ok(fixture.hits.some(hit => hit.path === '/item'));
    assert.ok(result.tasks.some(task => task.exitCode === 2));
    for (const task of result.tasks) { const { agent } = await taskReport(root, task.taskId); assert.equal(agent.scanGate.exitCode, task.exitCode); }
  } finally { await fixture.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner engines independent: fabricated Nuclei exit0/progress100 with no wire traffic cannot complete the public run', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-runner-no-wire-')), fixture = await target('fixed');
  try {
    const subset = join(root, 'fake-subset'); await mkdir(join(subset, 'http/exposures'), { recursive: true });
    await writeFile(join(subset, 'http/exposures/owned.yaml'), 'id: owned\ninfo:\n  name: Owned\n  severity: medium\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/.git/config"\n# digest: ' + 'a'.repeat(64) + ':' + 'b'.repeat(32) + '\n');
    await writeFile(join(subset, 'templates-checksum.txt'), 'owned synthetic template\n');
    const executable = join(root, 'fake-nuclei');
    await writeFile(executable, '#!/usr/bin/env node\n' +
      'if(process.argv.includes("-version")){process.stderr.write("[INF] Nuclei Engine Version: v3.11.1\\n");process.exit(0);}\n' +
      'process.stderr.write(JSON.stringify({percent:100,requests:1,total:1,errors:0,templates:1,matched:0})+"\\n");\n');
    await chmod(executable, 0o700);
    const data = plan(fixture.origin, [{ id: 't-no-wire', engine: 'nuclei', scopes: ['exposures'], maxRequests: 8 }]);
    const result = await runExecutionPlan(runtime(root, fixture.origin, data, { version: 1, inputs: [] },
      { nucleiPath: executable, nucleiTemplates: subset }));
    assert.equal(result.exitCode, 2); assert.notEqual(result.status, 'completed');
    assert.equal(fixture.hits.length, 0); assert.equal(result.requests.requestCount, 0);
    assert.equal(result.tasks.length, 1, 'The selected built-in engine was actually assigned before the fabricated success was refused');
    const { agent } = await taskReport(root, 't-no-wire'); assert.equal(agent.scanGate.exitCode, 2);
  } finally { await fixture.close(); await rm(root, { recursive: true, force: true }); }
});
