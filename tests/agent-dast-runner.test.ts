import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { parseExecutionInputs, parseExecutionPlan } from '../src/agent-dast/plan.js';
import { runExecutionPlan } from '../src/agent-dast/runner.js';
import { parseRunPlanArgs } from '../src/agent-dast/cli.js';

test('agent run plan: strict data parser rejects code, enum coercion and caller accessors', () => {
  const plan = { version: 1, kind: 'wakeio.execution-plan', origin: 'https://owned.example', tasks: [{ id: 't-one', engine: 'native-dast', policy: 'policy', maxRequests: 8 }] };
  const parsed = parseExecutionPlan(plan); plan.tasks[0].maxRequests = 64; assert.equal(parsed.tasks[0].maxRequests, 8);
  assert.throws(() => parseExecutionPlan({ ...plan, code: 'private-marker' }), /invalid_execution_plan/);
  assert.throws(() => parseExecutionPlan({ ...plan, tasks: [{ ...plan.tasks[0], engine: ['native-dast'] }] }), /invalid_execution_plan/);
  assert.throws(() => parseExecutionPlan({ ...plan, tasks: [plan.tasks[0], plan.tasks[0]] }), /invalid_execution_plan/);
  let invoked = false;
  const accessor = Object.defineProperty({ ...plan }, 'origin', { enumerable: true, get() { invoked = true; return 'https://owned.example'; } });
  assert.throws(() => parseExecutionPlan(accessor)); assert.equal(invoked, false);
  assert.deepEqual(parseExecutionInputs({ version: 1, inputs: [] }), { version: 1, inputs: [] });
  assert.throws(() => parseRunPlanArgs(['run-plan', '--plan', 'p', '--inputs', 'i', '--allowed-origin', 'https://owned.example', '--out', 'fresh']));
});

async function ownedPair() {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-plan-core-'));
  const db = new DatabaseSync(':memory:'); db.exec('CREATE TABLE items(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(1),(2)');
  let requests = 0;
  const server = createServer((request, response) => {
    requests++;
    const url = new URL(request.url!, 'http://127.0.0.1'), value = url.searchParams.get('id')!;
    const row = url.pathname === '/v' ? db.prepare(`SELECT count(*) AS count FROM items WHERE id=${value}`).get()
      : db.prepare('SELECT count(*) AS count FROM items WHERE id=?').get(value);
    response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(row));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  const inputs = { version: 1 as const, inputs: [] as Array<{ id: string; path: string; sha256: string }> };
  for (const id of ['v', 'f']) {
    const bytes = Buffer.from(JSON.stringify({ version: 1, kind: 'sql-boolean-differential', baseUrl: origin, url: `${origin}/${id}?id=1`, parameter: 'id', profile: 'numeric',
      oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } }));
    const path = join(root, `${id}.json`); await writeFile(path, bytes);
    inputs.inputs.push({ id, path, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  const plan = parseExecutionPlan({ version: 1, kind: 'wakeio.execution-plan', origin, tasks: ['v', 'f'].map(id => ({ id: `t-${id}`, engine: 'native-dast', policy: id, maxRequests: 8 })) });
  return { root, plan, inputs, origin, requests: () => requests, async close() { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); db.close(); await rm(root, { recursive: true, force: true }); } };
}

test('agent run plan: actual SQLite risk and bound normal keep separate reports and digest manifest', async () => {
  const fixture = await ownedPair();
  try {
    let unrelatedRead = false;
    const env = Object.defineProperty({}, 'UNSELECTED', { enumerable: true, get() { unrelatedRead = true; throw Error('private-marker'); } });
    const result = await runExecutionPlan({ plan: fixture.plan, inputs: fixture.inputs, outDir: join(fixture.root, 'out'), consent: true, allowedOrigin: fixture.origin,
      allowPrivate: true, maxRequests: 16, ratePerSecond: 100, timeoutMs: 5000, concurrency: 2, env });
    assert.equal(result.exitCode, 1); assert.equal(result.delivery, 'published'); assert.equal(result.requests.requestCount, 16);
    assert.deepEqual(result.tasks.map(task => task.exitCode), [1, 0]); assert.equal(unrelatedRead, false);
    const receipt = JSON.parse(await readFile(join(result.outDir!, 'run-receipt.json'), 'utf8'));
    const manifestBytes = await readFile(join(result.outDir!, 'run-manifest.json'));
    assert.equal(receipt.manifestSha256, createHash('sha256').update(manifestBytes).digest('hex'));
    const manifest = JSON.parse(manifestBytes.toString());
    for (const file of manifest.artifacts) {
      const bytes = await readFile(join(result.outDir!, file.path)); assert.equal(bytes.byteLength, file.bytes);
      assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256);
    }
    assert.equal(manifest.artifacts.filter((file: { path: string }) => file.path.startsWith('tasks/')).length, 8);
    const before = fixture.requests();
    const refused = await runExecutionPlan({ plan: fixture.plan, inputs: fixture.inputs, outDir: result.outDir!, consent: true, allowedOrigin: fixture.origin, allowPrivate: true });
    assert.equal(refused.exitCode, 2); assert.equal(refused.outDir, null); assert.equal(fixture.requests(), before);
  } finally { await fixture.close(); }
});

test('agent run plan: competing native tasks share one cap and incomplete stays 2 with fail-on none', async () => {
  const fixture = await ownedPair();
  try {
    const result = await runExecutionPlan({ plan: fixture.plan, inputs: fixture.inputs, outDir: join(fixture.root, 'cap'), consent: true, allowedOrigin: fixture.origin,
      allowPrivate: true, maxRequests: 9, ratePerSecond: 100, timeoutMs: 5000, concurrency: 2, failOn: 'none' });
    assert.equal(result.exitCode, 2); assert.equal(result.requests.requestCount, 9); assert.equal(fixture.requests(), 9);
    assert.equal(result.tasks.reduce((sum, task) => sum + task.requests.requestCount, 0), 9);
    assert.ok(result.tasks.some(task => task.exitCode === 2));
  } finally { await fixture.close(); }
});

test('agent run plan: an arbitrary ancestor symlink is refused without traffic or output claim', async () => {
  const fixture = await ownedPair();
  try {
    const alias = join(fixture.root, 'caller-alias'); await symlink(fixture.root, alias, 'dir');
    const result = await runExecutionPlan({ plan: fixture.plan, inputs: fixture.inputs, outDir: join(alias, 'out'), consent: true,
      allowedOrigin: fixture.origin, allowPrivate: true });
    assert.equal(result.exitCode, 2); assert.equal(result.outDir, null); assert.equal(fixture.requests(), 0);
  } finally { await fixture.close(); }
});

test('agent run plan: real Schemathesis template findings keep approved brace path identity in the store', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-plan-template-'));
  const server = createServer((_request, response) => { response.statusCode = 500; response.setHeader('content-type', 'application/json'); response.end('{}'); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const schema = { openapi: '3.0.3', info: { title: 'Owned template identity', version: '1.0' }, paths: { '/items/{id}': { get: {
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer', enum: [1, 2] } }],
      responses: { '200': { description: 'normal', content: { 'application/json': { schema: { type: 'object' } } } },
        '500': { description: 'owned risk', content: { 'application/json': { schema: { type: 'object' } } } } }
    } } } };
    const bytes = Buffer.from(JSON.stringify(schema)), path = join(directory, 'schema.json'); await writeFile(path, bytes);
    const result = await runExecutionPlan({ plan: parseExecutionPlan({ version: 1, kind: 'wakeio.execution-plan', origin, tasks: [
      { id: 't-template', engine: 'schemathesis', schema: 'schema', operations: ['/items/{id}'], seed: 7, maxRequests: 8 } ] }),
      inputs: { version: 1, inputs: [{ id: 'schema', path, sha256: createHash('sha256').update(bytes).digest('hex') }] },
      outDir: join(directory, 'out'), consent: true, allowedOrigin: origin, allowPrivate: true, maxRequests: 8, ratePerSecond: 100,
      timeoutMs: 30000, failOn: 'medium', schemathesisPython: process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(process.cwd(), '.venv-schemathesis/bin/python') });
    assert.equal(result.exitCode, 1); assert.equal(result.tasks[0].status, 'completed');
    const db = new DatabaseSync(join(result.outDir!, 'run.db'), { readOnly: true });
    try { assert.equal(db.prepare('SELECT s.path FROM findings f JOIN surface s ON s.surface_id=f.surface_id').get()?.path, '/items/{id}'); }
    finally { db.close(); }
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});
