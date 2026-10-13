import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runExecutionPlan } from '../src/agent-dast/runner.js';

// Independent supported template-path oracle; author does not execute tests.
const python = process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(process.cwd(), '.venv-schemathesis/bin/python');
const present = await stat(python).then(value => value.isFile()).catch(() => false);
const required = process.env.WAKEIO_REQUIRE_RUNNER_ENGINES === '1';
const skip = present || required ? false : 'provide reviewed Schemathesis Python; required runner suite refuses absence';
const hash = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');

test('runner template independent: actual generated path-parameter vulnerable/fixed findings retain declared template context and completed1/0 gates', { skip }, async () => {
  assert.ok(present, 'Required runner suite needs the reviewed Schemathesis runtime');
  const operation = '/owned-items/{id}';
  const item = { type: 'object', required: ['id', 'name'], properties: { id: { type: 'integer' }, name: { type: 'string' } } };
  const get = { operationId: 'ownedTemplatedRead', parameters: [{ name: 'id', in: 'path', required: true,
    schema: { type: 'integer', minimum: 1, maximum: 1000 } }], responses: { '200': { description: 'Owned item',
    content: { 'application/json': { schema: item } } } } };
  const document = { openapi: '3.0.3', info: { title: 'Owned path contract', version: '1.0.0' }, paths: { [operation]: { get } } };
  for (const mode of ['vulnerable', 'fixed'] as const) {
    const root = await mkdtemp(join(tmpdir(), `wakeio-runner-template-${mode}-`));
    const paths: string[] = [];
    const server = createServer((request, response) => {
      const path = new URL(request.url ?? '/', 'http://owned.invalid').pathname; paths.push(path);
      const match = path.match(/^\/owned-items\/(\d+)$/);
      response.writeHead(match ? 200 : 404, { 'content-type': 'application/json' });
      response.end(JSON.stringify(match ? { id: Number(match[1]), name: mode === 'vulnerable' ? 17 : 'owned-normal' } : { error: 'owned-route-refusal' }));
    });
    await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
    const address = server.address(); assert.ok(address && typeof address === 'object');
    const origin = `http://127.0.0.1:${address.port}`;
    try {
      const bytes = JSON.stringify(document); await writeFile(join(root, 'contract.json'), bytes);
      const result = await runExecutionPlan({ plan: { version: 1, kind: 'wakeio.execution-plan', origin, tasks: [
        { id: 't-owned-template', engine: 'schemathesis', schema: 'contract', operations: [operation], seed: 7, maxRequests: 8 }] },
        inputs: { version: 1, inputs: [{ id: 'contract', path: 'contract.json', sha256: hash(bytes) }] }, inputBaseDir: root,
        outDir: join(root, 'reports'), consent: true, allowedOrigin: origin, allowPrivate: true, maxRequests: 8,
        timeoutMs: 30_000, ratePerSecond: 50, concurrency: 1, failOn: 'low', schemathesisPython: python });
      assert.equal(result.exitCode, mode === 'vulnerable' ? 1 : 0);
      assert.equal(result.status, 'completed'); assert.equal(result.delivery, 'published');
      assert.equal(paths.length, 8); assert.equal(result.requests.requestCount, paths.length); assert.equal(result.requests.pending, 0);
      assert.ok(paths.every(path => /^\/owned-items\/\d+$/.test(path)));
      const reportBytes = await readFile(join(root, 'reports/tasks/t-owned-template/report.json'));
      const report = JSON.parse(reportBytes.toString('utf8'));
      const agent = JSON.parse(await readFile(join(root, 'reports/tasks/t-owned-template/agent-report.json'), 'utf8'));
      assert.equal(agent.reportArtifact.digest, hash(reportBytes)); assert.equal(agent.scanGate.exitCode, result.exitCode);
      assert.ok(report.checks.every((check: any) => check.status === 'completed'));
      const findings = report.checks.flatMap((check: any) => check.findings);
      assert.equal(findings.length, mode === 'vulnerable' ? 1 : 0);
      if (mode === 'vulnerable') {
        assert.equal(findings[0].ruleId, 'api.schemathesis.response_schema');
        const oracle = new DatabaseSync(join(root, 'reports/run.db'), { readOnly: true });
        try {
          const contexts = oracle.prepare('SELECT s.path FROM findings f JOIN surface s ON s.surface_id=f.surface_id').all();
          assert.deepEqual(contexts.map(row => row.path), [operation], 'Persist original operation template instead of losing context to URL brace encoding');
          assert.deepEqual(oracle.prepare('SELECT status FROM tasks').all().map(row => row.status), ['completed']);
        } finally { oracle.close(); }
      }
    } finally {
      server.closeAllConnections(); await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
      await rm(root, { recursive: true, force: true });
    }
  }
});
