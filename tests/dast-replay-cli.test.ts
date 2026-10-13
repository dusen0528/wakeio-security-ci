import test from 'node:test';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main, parseDastReplayArgs, parseReplayArgs } from '../src/cli.js';

const id = 'a'.repeat(64);
test('native replay arguments require explicit consent and keep the original execution budgets', () => {
  const args = ['replay', '--report', 'report.json', '--dast-policy', 'policy.json', '--finding', id, '--out', 'new'];
  assert.throws(() => parseDastReplayArgs(args), /active-consent/);
  const parsed = parseDastReplayArgs([...args, '--active-consent']);
  assert.equal(parsed.consent, true); assert.equal(parsed.allowPrivate, false);
  assert.throws(() => parseDastReplayArgs([...args, '--active-consent', '--timeout-ms', '2000']), /budgets come from the original/);
  assert.throws(() => parseDastReplayArgs([...args, '--active-consent', '--dast-max-requests', '16']), /budgets come from the original/);
  assert.throws(() => parseDastReplayArgs([...args, '--active-consent', '--api-policy', 'api.json']));
  assert.throws(() => parseDastReplayArgs([...args, '--active-consent', '--active-consent']));
  assert.deepEqual(parseReplayArgs(['replay', '--report', 'r.json', '--api-policy', 'p.json', '--finding', id, '--out', 'o']),
    { report: 'r.json', apiPolicy: 'p.json', findingId: id, outDir: 'o', allowPrivate: false });
});

// Only CLI/receipt behavior: the SDK suite uses a real SQLite fixture for SQL effects.
test('native replay CLI records reproduction and non-reproduction without changing the source report', async () => {
  let hits = 0, bound = false;
  const server = createServer((request, response) => {
    hits++;
    const value = new URL(request.url!, 'http://fixture.invalid').searchParams.get('id')!;
    const count = bound ? (value === '1' ? 1 : 0) : value.includes('1=2') ? 0 : 1;
    response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ count }));
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-native-replay-cli-'));
  try {
    const origin = `http://127.0.0.1:${address.port}`;
    const policy = { version: 1, kind: 'sql-boolean-differential', baseUrl: `${origin}/`, url: `${origin}/items?id=1`, parameter: 'id', profile: 'numeric',
      oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
    const policyPath = join(directory, 'policy.json'); await writeFile(policyPath, JSON.stringify(policy));
    const original = join(directory, 'original');
    assert.equal(await main(['scan', '--dast-policy', policyPath, '--active-consent', '--allow-private', '--dast-max-requests', '9', '--timeout-ms', '2500', '--out', original]), 1);
    assert.equal(hits, 8);
    const originalBytes = await readFile(join(original, 'report.json'));
    const originalAgent = await readFile(join(original, 'agent-report.json'));
    const report = JSON.parse(originalBytes.toString());
    const findingId = report.checks[0].findings[0].id;
    const args = ['replay', '--report', join(original, 'report.json'), '--dast-policy', policyPath, '--finding', findingId, '--active-consent'];
    assert.equal(await main([...args, '--allow-private', '--out', original]), 2);
    assert.equal(hits, 8, 'existing output fails before target traffic');
    const denied = join(directory, 'private-denied');
    assert.equal(await main([...args, '--out', denied]), 2);
    assert.equal(hits, 8, 'private authorization is not taken from the original ledger');
    assert.deepEqual(await readdir(denied), ['replay.json']);
    const refused = JSON.parse(await readFile(join(denied, 'replay.json'), 'utf8'));
    assert.equal(refused.outcome, 'refused');
    const reproduced = join(directory, 'reproduced');
    assert.equal(await main([...args, '--allow-private', '--out', reproduced]), 1);
    assert.equal(hits, 16);
    const replayed = JSON.parse(await readFile(join(reproduced, 'report.json'), 'utf8'));
    assert.equal(replayed.checks[0].dastExecution.maxRequests, 9);
    assert.equal(replayed.checks[0].dastExecution.timeoutMs, 2500);
    const receipt = JSON.parse(await readFile(join(reproduced, 'replay.json'), 'utf8'));
    assert.equal(receipt.kind, 'native-dast-finding-replay'); assert.equal(receipt.outcome, 'reproduced');
    assert.equal(receipt.findingId, findingId);
    assert.deepEqual(receipt.reportArtifact, { name: 'report.json', algorithm: 'sha256',
      digest: createHash('sha256').update(await readFile(join(reproduced, 'report.json'))).digest('hex') });
    const agent = JSON.parse(await readFile(join(reproduced, 'agent-report.json'), 'utf8'));
    assert.deepEqual(agent.findings[0].verification, { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
    bound = true;
    const notReproduced = join(directory, 'not-reproduced');
    assert.equal(await main([...args, '--allow-private', '--out', notReproduced]), 0);
    assert.equal(hits, 24);
    const cleanReceipt = JSON.parse(await readFile(join(notReproduced, 'replay.json'), 'utf8'));
    assert.equal(cleanReceipt.outcome, 'not_reproduced');
    assert.deepEqual(await readFile(join(original, 'report.json')), originalBytes);
    assert.deepEqual(await readFile(join(original, 'agent-report.json')), originalAgent);
    for (const output of [reproduced, notReproduced]) for (const file of await readdir(output)) {
      const text = await readFile(join(output, file), 'utf8');
      for (const forbidden of ['1 AND 1=', 'expectedBaseline', 'id=1']) assert.ok(!text.includes(forbidden), `${file} leaked ${forbidden}`);
    }
  } finally { await new Promise<void>(done => server.close(() => done())); await rm(directory, { recursive: true, force: true }); }
});

// Synthetic authenticated protocol fixture; no real target or database behavior is asserted here.
test('authenticated native replay resolves fresh environment credentials and refuses partial trailing identity', async () => {
  const authName = 'WAKEIO_OWNED_AUTH_REPLAY', previous = process.env[authName];
  let hits = 0, identityHits = 0, failAfter = false;
  const observedHeaders: string[] = [];
  const server = createServer((request, response) => {
    hits++; observedHeaders.push(request.headers.authorization ?? '');
    response.setHeader('content-type', 'application/json');
    if (request.url === '/private-replay-identity') {
      identityHits++;
      response.end(JSON.stringify({ user: failAfter && identityHits % 2 === 0 ? 'different-private-user' : 'owned-private-user' }));
    } else response.end(JSON.stringify({ count: request.url?.includes('1%3D2') ? 0 : 1 }));
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const top = await mkdtemp(join(tmpdir(), 'wakeio-auth-replay-cli-'));
  try {
    const origin = `http://127.0.0.1:${address.port}`, input = join(top, 'policy.json');
    const policy = { version: 2, kind: 'sql-boolean-differential', baseUrl: `${origin}/`, url: `${origin}/items?id=1`, parameter: 'id', profile: 'numeric',
      authorizationEnv: authName, identity: { path: '/private-replay-identity', status: 200, jsonPointer: '/user', equals: 'owned-private-user' },
      oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
    await writeFile(input, JSON.stringify(policy)); process.env[authName] = 'Bearer owned-original-token';
    const original = join(top, 'original');
    assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--out', original]), 1);
    const originalBytes = await readFile(join(original, 'report.json'));
    const report = JSON.parse(originalBytes.toString()), finding = report.checks[0].findings[0].id;
    const replay = ['replay', '--report', join(original, 'report.json'), '--dast-policy', input, '--finding', finding, '--active-consent', '--allow-private'];
    delete process.env[authName];
    assert.equal(await main([...replay, '--out', join(top, 'missing')]), 2); assert.equal(hits, 10);
    process.env[authName] = 'Bearer owned-fresh-token';
    const repeated = join(top, 'repeated');
    assert.equal(await main([...replay, '--out', repeated]), 1); assert.equal(hits, 20);
    assert.ok(observedHeaders.slice(0, 10).every(value => value === 'Bearer owned-original-token'));
    assert.ok(observedHeaders.slice(10).every(value => value === 'Bearer owned-fresh-token'));
    const receipt = JSON.parse(await readFile(join(repeated, 'replay.json'), 'utf8'));
    assert.equal(receipt.outcome, 'reproduced'); assert.equal(receipt.profileRevision, 'sql-boolean-numeric-auth-v2');
    failAfter = true;
    const incomplete = join(top, 'incomplete');
    assert.equal(await main(['scan', '--dast-policy', input, '--active-consent', '--allow-private', '--out', incomplete]), 2);
    const partial = JSON.parse(await readFile(join(incomplete, 'report.json'), 'utf8'));
    assert.equal(partial.checks[0].findings.length, 1); assert.equal(partial.checks[0].findings[0].confidence, 'low');
    const partialReplay = [...replay]; partialReplay[2] = join(incomplete, 'report.json'); partialReplay[6] = partial.checks[0].findings[0].id;
    assert.equal(await main([...partialReplay, '--out', join(top, 'refused-partial')]), 2); assert.equal(hits, 30);
    assert.deepEqual(await readFile(join(original, 'report.json')), originalBytes);
    for (const file of await readdir(repeated)) {
      const text = await readFile(join(repeated, file), 'utf8');
      for (const forbidden of [authName, 'owned-original-token', 'owned-fresh-token', '/private-replay-identity', 'owned-private-user', 'AND 1=']) assert.equal(text.includes(forbidden), false, file);
    }
  } finally {
    if (previous === undefined) delete process.env[authName]; else process.env[authName] = previous;
    await new Promise<void>(done => server.close(() => done())); await rm(top, { recursive: true, force: true });
  }
});
