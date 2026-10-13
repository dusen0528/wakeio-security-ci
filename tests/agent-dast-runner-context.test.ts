import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runExecutionPlan } from '../src/agent-dast/runner.js';

// Independent actual SQLite context oracle; root executes, author only writes.
const digest = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
async function databases(root: string): Promise<string[]> {
  const paths: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (entry.isDirectory()) paths.push(...await databases(join(root, entry.name)));
    else if (entry.isFile() && entry.name === 'run.db') paths.push(join(root, entry.name));
  }
  return paths;
}

test('runner context independent: two actual vulnerable endpoints retain distinct canonical findings and task observations in read-only run.db', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-runner-context-'));
  const targetDb = new DatabaseSync(':memory:');
  targetDb.exec('CREATE TABLE items(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(1),(2);');
  const hits: Array<{ path: string; parameter: string }> = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://owned.invalid');
    const parameter = url.pathname === '/alpha' ? 'id' : 'key';
    hits.push({ path: url.pathname, parameter });
    const row = targetDb.prepare(`SELECT COUNT(*) AS count FROM items WHERE id = ${url.searchParams.get(parameter)}`).get();
    response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ count: row?.count }));
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const cases = [{ id: 't-context-alpha', alias: 'alpha', path: '/alpha', parameter: 'id' },
      { id: 't-context-beta', alias: 'beta', path: '/beta', parameter: 'key' }];
    const inputs = [], tasks = [];
    for (const item of cases) {
      const policy = { version: 1, kind: 'sql-boolean-differential', baseUrl: `${origin}/`,
        url: `${origin}${item.path}?${item.parameter}=1`, parameter: item.parameter, profile: 'numeric',
        oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
      const bytes = JSON.stringify(policy); await writeFile(join(directory, `${item.alias}.json`), bytes);
      inputs.push({ id: item.alias, path: `${item.alias}.json`, sha256: digest(bytes) });
      tasks.push({ id: item.id, engine: 'native-dast' as const, policy: item.alias, maxRequests: 8 });
    }
    const out = join(directory, 'reports');
    const result = await runExecutionPlan({ plan: { version: 1, kind: 'wakeio.execution-plan', origin, tasks },
      inputs: { version: 1, inputs }, inputBaseDir: directory, outDir: out, consent: true, allowedOrigin: origin,
      allowPrivate: true, maxRequests: 16, timeoutMs: 5000, ratePerSecond: 50, concurrency: 2, failOn: 'high' });
    assert.equal(result.exitCode, 1); assert.equal(result.status, 'completed'); assert.equal(result.delivery, 'published');
    assert.equal(result.requests.requestCount, 16); assert.equal(hits.length, 16);
    assert.equal(hits.filter(hit => hit.path === '/alpha').length, 8);
    assert.equal(hits.filter(hit => hit.path === '/beta').length, 8);
    const paths = await databases(out); assert.equal(paths.length, 1, 'Exactly one controller-owned run.db exists');
    const before = digest(await readFile(paths[0]));
    const oracle = new DatabaseSync(paths[0], { readOnly: true });
    try {
      const rows = oracle.prepare(`SELECT f.finding_id, f.rule_id, f.severity, s.method, s.path, s.param, s.location, s.auth_state
        FROM findings f JOIN surface s ON s.surface_id=f.surface_id ORDER BY s.path`).all();
      assert.equal(rows.length, 2, 'Same rule on different endpoints/parameters cannot collapse behind root path metadata');
      assert.equal(new Set(rows.map(row => row.finding_id)).size, 2);
      assert.deepEqual(rows.map(({ finding_id: _, ...row }) => ({ ...row })), [
        { rule_id: 'dast.sql-boolean-differential', severity: 'high', method: 'GET', path: '/alpha', param: 'id', location: 'query', auth_state: 'anonymous' },
        { rule_id: 'dast.sql-boolean-differential', severity: 'high', method: 'GET', path: '/beta', param: 'key', location: 'query', auth_state: 'anonymous' },
      ]);
      const observations = oracle.prepare('SELECT task_id, finding_id FROM finding_observations ORDER BY task_id').all();
      assert.deepEqual(observations.map(row => row.task_id), cases.map(item => item.id));
      assert.equal(new Set(observations.map(row => row.finding_id)).size, 2);
      const statuses = oracle.prepare('SELECT task_id,status FROM tasks ORDER BY task_id').all();
      assert.deepEqual(statuses.map(row => ({ ...row })), cases.map(item => ({ task_id: item.id, status: 'completed' })));
    } finally { oracle.close(); }
    assert.equal(digest(await readFile(paths[0])), before, 'The independent read-only DB oracle does not alter evidence');
  } finally {
    server.closeAllConnections(); await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
    targetDb.close(); await rm(directory, { recursive: true, force: true });
  }
});
