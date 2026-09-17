import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, parseCliArgs } from '../src/cli.js';

const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));

test('CLI accepts explicit Python and API scopes', () => {
  const python = parseCliArgs(['scan', '--source', '.', '--tools', 'bandit', '--bandit', '/trusted/bandit']);
  assert.ok(!('help' in python));
  assert.deepEqual(python.tools, ['bandit']);
  assert.equal(python.toolPaths.bandit, '/trusted/bandit');
  const api = parseCliArgs(['scan', '--api-policy', 'policy.json', '--allow-private']);
  assert.ok(!('help' in api));
  assert.equal(api.apiPolicy, 'policy.json');
});

test('CLI dispatches doctor and init help without entering scan parsing', async () => {
  const doctor = await exec(process.execPath, [cli, 'doctor', '--help']);
  assert.match(doctor.stdout, /read-only inventory/i);
  const init = await exec(process.execPath, [cli, 'init', '--help']);
  assert.match(init.stdout, /Create a local CI workflow/i);
});

test('CLI keeps logical project and bounded same-origin page options explicit', () => {
  const options = parseCliArgs([
    'scan', '--url', 'https://example.test', '--project-id', 'acme/example',
    '--page', '/docs', '--page=/settings', '--max-pages', '3',
  ]);
  assert.ok(!('help' in options));
  if (!('help' in options)) {
    assert.equal(options.projectId, 'acme/example');
    assert.deepEqual(options.pages, ['/docs', '/settings']);
    assert.equal(options.maxPages, 3);
  }
  assert.throws(() => parseCliArgs(['scan', '--source', '.', '--page', '/docs']));
  assert.throws(() => parseCliArgs(['scan', '--url', 'https://example.test', '--max-pages', '9']));
  assert.throws(() => parseCliArgs(['scan', '--source', '.', '--project-id', '../other']));
});

test('CLI forwards explicit same-origin pages and the root-inclusive page budget', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-preview-pages-'));
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end(`<html><body>${req.url === '/docs' ? 'docs' : 'root'}</body></html>`);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  try {
    const out = join(root, 'reports');
    const code = await main([
      'scan', '--url', `http://127.0.0.1:${address.port}/`, '--page', '/docs',
      '--max-pages', '2', '--allow-private', '--fail-on', 'none', '--out', out,
    ]);
    assert.equal(code, 0);
    const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8')) as any;
    assert.equal(report.checks[0].metrics.pagesFetched, 2);
    assert.equal(report.checks[0].metrics.pagesSkipped, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
});

test('real CLI exercises a policy before and after an authorization fix, then compares artifacts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-preview-cli-'));
  let vulnerable = true;
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    res.setHeader('content-type', 'application/json');
    if (req.url === '/whoami') {
      if (req.headers.authorization === 'Bearer synthetic-owner') res.end(JSON.stringify({ userId: 'owner-user', orgId: 'shared-org' }));
      else if (req.headers.authorization === 'Bearer synthetic-other') res.end(JSON.stringify({ userId: 'other-user', orgId: 'shared-org' }));
      else res.writeHead(401).end(JSON.stringify({ error: 'unauthorized' }));
    } else if (req.headers.authorization === 'Bearer synthetic-owner' || (vulnerable && req.headers.authorization === 'Bearer synthetic-other')) {
      res.end(JSON.stringify({ id: 'owned-fixture', canary: 'synthetic-private-canary', secret: 'raw_response_must_not_be_reported' }));
    } else res.writeHead(req.headers.authorization ? 403 : 401).end(JSON.stringify({ error: 'denied' }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const env = { PATH: process.env.PATH, WAKEIO_OWNER_AUTH: 'Bearer synthetic-owner', WAKEIO_OTHER_AUTH: 'Bearer synthetic-other' };
  try {
    const policy = join(root, 'policy.json');
    await writeFile(policy, JSON.stringify({ version: 2, baseUrl: `http://127.0.0.1:${address.port}`,
      actors: [
        { id: 'owner', authorizationEnv: 'WAKEIO_OWNER_AUTH', identity: { path: '/whoami', status: 200, jsonPointer: '/userId', equals: 'owner-user', organization: { jsonPointer: '/orgId', equals: 'shared-org' } } },
        { id: 'other', authorizationEnv: 'WAKEIO_OTHER_AUTH', identity: { path: '/whoami', status: 200, jsonPointer: '/userId', equals: 'other-user', organization: { jsonPointer: '/orgId', equals: 'shared-org' } } },
        { id: 'anonymous' },
      ],
      cases: [{ id: 'owned-read', path: '/documents/owned-fixture', allow: { actor: 'owner', status: 200,
        resource: { jsonPointer: '/id', equals: 'owned-fixture' }, protected: { jsonPointer: '/canary', equals: 'synthetic-private-canary' } },
        deny: [{ actor: 'other', statuses: [403] }, { actor: 'anonymous', statuses: [401] }] }] }));
    const beforeDir = join(root, 'before');
    const afterDir = join(root, 'after');
    const scan = (out: string) => exec(process.execPath, [cli, 'scan', '--api-policy', policy, '--allow-private', '--out', out, '--fail-on', 'none'], { env });
    await scan(beforeDir);
    const before = JSON.parse(await readFile(join(beforeDir, 'report.json'), 'utf8'));
    assert.equal(before.mode, 'api');
    assert.ok(before.checks.flatMap((check: any) => check.findings).length > 0);
    vulnerable = false;
    await scan(afterDir);
    const after = JSON.parse(await readFile(join(afterDir, 'report.json'), 'utf8'));
    assert.equal(after.checks.flatMap((check: any) => check.findings).length, 0);
    assert.ok(requests >= 6);
    const out = join(root, 'comparison');
    await exec(process.execPath, [cli, 'compare', '--before', join(beforeDir, 'report.json'), '--after', join(afterDir, 'report.json'), '--out', out]);
    const comparison = JSON.parse(await readFile(join(out, 'comparison.json'), 'utf8'));
    assert.equal(comparison.comparable, true);
    assert.ok(comparison.summary.not_observed > 0);
    const serialized = JSON.stringify({ before, after, comparison });
    for (const value of ['Bearer synthetic-owner', 'Bearer synthetic-other', 'raw_response_must_not_be_reported']) assert.equal(serialized.includes(value), false);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
});
