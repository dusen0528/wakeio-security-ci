import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { runDast, parseDastPolicy, prepareDastPolicy, snapshotDastEnvironment, dastDefaultMaxRequests, dastProfileRevision, type DastPolicyV1, type DastPolicyV2 } from '../src/dast.js';
import { sanitizeDastExecution, isDastObservedEvidence, isDastReplayableExecution, type DastExecutionV2, type DastAuthExecutionStep } from '../src/dast-execution.js';

const policy: DastPolicyV1 = { version: 1, kind: 'sql-boolean-differential', baseUrl: 'https://owned.example.test/',
  url: 'https://owned.example.test/items?id=1', parameter: 'id', profile: 'numeric',
  oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
const auth = (): DastPolicyV2 => ({ ...policy, version: 2, authorizationEnv: 'OWNED_AUTH',
  identity: { path: '/owned-identity', status: 200, jsonPointer: '/principal', equals: 'owned-principal' } });

test('v1 numeric parsed policy bytes and digest preserve the independently captured old implementation', () => {
  const parsed = parseDastPolicy(policy);
  assert.equal(JSON.stringify(parsed.policy), '{"version":1,"kind":"sql-boolean-differential","baseUrl":"https://owned.example.test/","url":"https://owned.example.test/items?id=1","parameter":"id","profile":"numeric","oracle":{"jsonPointer":"/count","expectedBaseline":1,"expectedTrue":1,"expectedFalse":0}}');
  assert.equal(parsed.policySha256, 'b05072fc6998789810b5733f999ff723566dcb10b02ca0fd23d18fe58ceb8d89');
  assert.equal(dastDefaultMaxRequests(parsed.policy), 8);
  assert.equal(dastProfileRevision(parsed.policy), 'sql-boolean-numeric-v1');
  let reads = 0;
  const hostile = new Proxy({}, { get() { reads++; throw Error('must not read'); }, ownKeys() { reads++; throw Error('must not enumerate'); } });
  assert.equal(snapshotDastEnvironment(policy, hostile), undefined);
  assert.equal(reads, 0);
});

test('v2 policy binds declared authorization and principal but never the selected credential', () => {
  const input = auth();
  const first = prepareDastPolicy(input, { env: { OWNED_AUTH: 'Bearer first-owned-value' } });
  const second = prepareDastPolicy(input, { env: { OWNED_AUTH: 'Bearer rotated-owned-value' } });
  assert.deepEqual(first, second);
  assert.equal(dastDefaultMaxRequests(first.policy), 10);
  assert.equal(dastProfileRevision(first.policy), 'sql-boolean-numeric-auth-v2');
  for (const changed of [{ ...input, authorizationEnv: 'OTHER_AUTH' }, { ...input, identity: { ...input.identity, equals: 'other-principal' } },
    { ...input, identity: { ...input.identity, path: '/other-identity' } }, { ...input, identity: { ...input.identity, status: 201 } }]) {
    assert.notEqual(parseDastPolicy(changed).policySha256, first.policySha256);
  }
  assert.equal(JSON.stringify(first).includes('Bearer'), false);
  let unrelatedReads = 0;
  const env = Object.defineProperty({ OWNED_AUTH: 'Bearer only-owned-value' }, 'UNRELATED_SECRET', { enumerable: true, get() { unrelatedReads++; throw Error('must not read'); } });
  assert.deepEqual(snapshotDastEnvironment(input, env), { OWNED_AUTH: 'Bearer only-owned-value' });
  assert.equal(unrelatedReads, 0);
});

test('strict authenticated policy and preparation reject unsafe input without exposing configured values', () => {
  const p = auth();
  const invalid = [
    { ...p, authorizationEnv: 'lowercase' }, { ...p, authorizationEnv: 'A\nHEADER' },
    { ...p, identity: { ...p.identity, equals: '' } }, { ...p, identity: { ...p.identity, equals: 1 } },
    { ...p, identity: { ...p.identity, status: 401 } }, { ...p, identity: { ...p.identity, status: 200.5 } },
    ...['//external.example.test/x', '/identity?secret=1', '/identity#value', '/identity\\x'].map(path => ({ ...p, identity: { ...p.identity, path } })),
    { ...p, identity: { ...p.identity, extra: 'private-value' } }, { ...p, headers: { Authorization: 'private-value' } },
  ];
  for (const candidate of invalid) assert.throws(() => prepareDastPolicy(candidate, { env: { OWNED_AUTH: 'Bearer owned-token' } }), error => error instanceof Error && error.message === 'DAST preparation failed: invalid_policy. No requests were made.');
  for (const baseUrl of ['http://example.test/', 'http://localhost/', 'http://192.168.1.1/']) {
    const candidate = { ...p, baseUrl, url: new URL('/items?id=1', baseUrl).href };
    assert.throws(() => prepareDastPolicy(candidate, { allowPrivate: true, env: { OWNED_AUTH: 'Bearer owned-token' } }), /insecure_authenticated_transport/);
  }
  for (const baseUrl of ['http://127.0.0.1/', 'http://[::1]/']) {
    const candidate = { ...p, baseUrl, url: new URL('/items?id=1', baseUrl).href };
    assert.throws(() => prepareDastPolicy(candidate, { env: { OWNED_AUTH: 'Bearer owned-token' } }), /insecure_authenticated_transport/);
    assert.equal(prepareDastPolicy(candidate, { allowPrivate: true, env: { OWNED_AUTH: 'Bearer owned-token' } }).policy.version, 2);
  }
  assert.throws(() => prepareDastPolicy(p, { allowPrivate: 'true' as unknown as boolean }), /invalid_options/);
});

function completed(): DastExecutionV2 {
  const phases = ['baseline-before', 'true', 'false', 'baseline-after'] as const;
  const steps: DastAuthExecutionStep[] = Array.from({ length: 10 }, (_, ordinal) => {
    const identity = ordinal === 0 || ordinal === 9;
    const phase = identity ? ordinal === 0 ? 'identity-before' : 'identity-after' : phases[(ordinal - 1) % 4]!;
    return { ordinal, round: identity ? 0 : ordinal <= 4 ? 1 : 2, phase, outcome: 'evaluated', reason: 'evaluated', attemptStart: ordinal,
      httpAttempts: 1, httpStatus: 200, oracleMatch: identity ? 'unavailable' : phase === 'false' ? 'false' : 'baseline' };
  });
  return { version: 2, policySha256: 'a'.repeat(64), profile: 'numeric', profileRevision: 'sql-boolean-numeric-auth-v2', maxRequests: 10, timeoutMs: 30000, allowPrivate: true,
    status: 'complete', outcome: 'observed', probeOutcome: 'observed', identityControls: { before: 'matched', after: 'matched' }, plannedRequests: 10, steps,
    counts: { evaluated: 10, inconclusive: 0, notAttempted: 0, httpAttempts: 10 }, stopReason: 'none' };
}

test('v2 ledger validator recomputes identity and SQL outcomes without accepting secret-bearing or forged completion', () => {
  const valid = completed(); assert.deepEqual(sanitizeDastExecution(valid), valid);
  assert.equal(isDastObservedEvidence(valid), true); assert.equal(isDastReplayableExecution(valid), true);
  const mutations: Array<(input: any) => void> = [
    input => input.steps[0].phase = 'baseline-before', input => input.steps[9].ordinal = 8,
    input => input.steps[0].round = 1, input => input.steps[1].ordinal = 0,
    input => input.steps[0].oracleMatch = 'baseline', input => input.steps[3].oracleMatch = 'baseline',
    input => input.identityControls.after = 'mismatched', input => input.probeOutcome = 'not_observed',
    input => input.counts.httpAttempts = 9, input => input.maxRequests = 9,
    input => input.authorizationEnv = 'PRIVATE_ENV', input => input.identityControls.principal = 'private-principal',
    input => input.steps[0].url = '/private-identity', input => input.profileRevision = 'sql-boolean-numeric-v1',
  ];
  for (const mutate of mutations) { const value = structuredClone(valid); mutate(value); assert.equal(sanitizeDastExecution(value), null); }
});

test('failed after identity retains the observed probe but cannot validate completed evidence or replay authority', () => {
  for (const zeroWire of [false, true]) {
    const value = completed(); value.status = 'partial'; value.outcome = 'inconclusive'; value.identityControls.after = zeroWire ? 'not_attempted' : 'mismatched';
    value.steps[9] = { ...value.steps[9]!, outcome: 'inconclusive', reason: zeroWire ? 'request_budget' : 'identity_mismatch', httpAttempts: zeroWire ? 0 : 1, httpStatus: zeroWire ? null : 200 };
    value.counts = { evaluated: 9, inconclusive: 1, notAttempted: 0, httpAttempts: zeroWire ? 9 : 10 };
    value.maxRequests = zeroWire ? 9 : 10; value.stopReason = zeroWire ? 'request_budget' : 'identity_mismatch';
    assert.deepEqual(sanitizeDastExecution(value), value);
    assert.equal(isDastObservedEvidence(value), true); assert.equal(isDastReplayableExecution(value), false);
    assert.equal(sanitizeDastExecution({ ...value, status: 'complete', outcome: 'observed' }), null);
  }
});


/** Labeled transport controls only; independent SQLite tests establish the SQL differential. */
async function transportFixture(mode: 'slow' | 'large-exact' | 'large-over') {
  let count = 0, first!: () => void;
  const firstRequest = new Promise<void>(resolve => { first = resolve; });
  const server = createServer((_request, response) => {
    count++; first();
    if (mode === 'slow') return;
    const prefix = JSON.stringify({ principal: 'owned-principal', count: 1 });
    const bytes = 128 * 1024 + (mode === 'large-over' ? 1 : 0);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(prefix + ' '.repeat(bytes - Buffer.byteLength(prefix)));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const baseUrl = `http://127.0.0.1:${address.port}/`;
  return { policy: { ...auth(), baseUrl, url: new URL('/items?id=1', baseUrl).href }, firstRequest,
    count: () => count, close: async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}

test('authenticated identity and SQL phases consume one aggregate response budget', async () => {
  for (const mode of ['large-exact', 'large-over'] as const) {
    const target = await transportFixture(mode);
    try {
      const [check] = await runDast({ policy: target.policy, consent: true, allowPrivate: true, env: { OWNED_AUTH: 'Bearer owned-transport' } });
      assert.equal(check?.status, 'partial'); assert.equal(check?.findings.length, 0);
      const execution = check?.dastExecution; assert.ok(execution?.version === 2);
      assert.equal(execution.stopReason, 'body_budget');
      assert.equal(execution.counts.httpAttempts, mode === 'large-exact' ? 4 : 1);
      assert.equal(target.count(), mode === 'large-exact' ? 4 : 1);
      assert.equal(execution.counts.evaluated, mode === 'large-exact' ? 4 : 0);
      assert.equal(execution.identityControls.after, 'not_attempted');
      if (mode === 'large-exact') {
        assert.equal(check.metrics?.responseBytes, 512 * 1024);
        assert.equal(execution.steps[4]?.httpAttempts, 0, 'identity bytes cannot be reset before SQL requests');
      }
    } finally { await target.close(); }
  }
});

test('authenticated deadline cause remains deadline when the wall clock is frozen', async t => {
  const target = await transportFixture('slow'); const now = Date.now();
  const clock = t.mock.method(Date, 'now', () => now);
  try {
    const [check] = await runDast({ policy: target.policy, consent: true, allowPrivate: true, env: { OWNED_AUTH: 'Bearer owned-transport' }, timeoutMs: 20 });
    assert.equal(check.status, 'partial'); assert.equal(check.dastExecution?.stopReason, 'deadline');
    assert.equal(check.dastExecution?.steps[0]?.reason, 'deadline');
    assert.ok(check.dastExecution!.steps.slice(1).every(step => step.outcome === 'not_attempted'));
    assert.ok(target.count() <= 1);
  } finally { clock.mock.restore(); await target.close(); }
});

test('authenticated caller abort is not relabeled after wall-clock advancement', async t => {
  const target = await transportFixture('slow'); let now = Date.now();
  const clock = t.mock.method(Date, 'now', () => now); const controller = new AbortController();
  try {
    const pending = runDast({ policy: target.policy, consent: true, allowPrivate: true, env: { OWNED_AUTH: 'Bearer owned-transport' }, signal: controller.signal, timeoutMs: 30000 });
    await target.firstRequest; controller.abort(); now += 60000;
    const [check] = await pending;
    assert.equal(check.status, 'partial'); assert.equal(check.dastExecution?.stopReason, 'cancelled');
    assert.equal(check.dastExecution?.steps[0]?.reason, 'cancelled'); assert.equal(target.count(), 1);
    assert.ok(check.dastExecution!.steps.slice(1).every(step => step.outcome === 'not_attempted'));
  } finally { clock.mock.restore(); await target.close(); }
});

test('authenticated HTTPS address retries charge the shared identity and SQL attempt budget', { timeout: 30000 }, async () => {
  const { mkdtemp, readFile, writeFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
  const { createServer: createHttpsServer } = await import('node:https');
  const { createServer: createTcpServer } = await import('node:net');
  const { spawn, execFileSync } = await import('node:child_process');
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-auth-retry-'));
  const caKey = join(directory, 'ca.key'), ca = join(directory, 'ca.crt'), key = join(directory, 'server.key'), cert = join(directory, 'server.crt'), csr = join(directory, 'server.csr'), ext = join(directory, 'server.ext');
  const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
  let server: ReturnType<typeof createHttpsServer> | undefined;
  let resetServer: ReturnType<typeof createTcpServer> | undefined;
  let accepted = 0;
  try {
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', ca, '-subj', '/CN=Owned Auth Retry CA', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE');
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', '/CN=owned-auth.test');
    await writeFile(ext, 'subjectAltName=DNS:owned-auth.test\nextendedKeyUsage=serverAuth\n');
    openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-out', cert, '-days', '1', '-extfile', ext);
    server = createHttpsServer({ key: await readFile(key), cert: await readFile(cert) }, (request, response) => {
      accepted++;
      assert.equal(request.headers.authorization, 'Bearer owned-retry-value');
      const url = new URL(request.url ?? '/', 'https://owned-auth.test');
      // Synthetic transport oracle: independent real SQLite fixtures cover actual SQL evaluation.
      const body = url.pathname === '/owned-identity' ? { principal: 'owned-principal' } : { count: url.searchParams.get('id') === '1 AND 1=2' ? 0 : 1 };
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(body));
    });
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve));
    const address = server.address(); assert.ok(address && typeof address !== 'string');
    // An owned IPv6 listener fails TLS immediately; an unbound loopback address
    // can instead blackhole on macOS and cannot prove address retry accounting.
    resetServer = createTcpServer(socket => socket.destroy());
    await new Promise<void>((resolve, reject) => {
      resetServer!.once('error', reject);
      resetServer!.listen({ port: address.port, host: '::1', ipv6Only: true }, resolve);
    });
    const origin = `https://owned-auth.test:${address.port}`;
    const runtime = new URL('../src/dast.js', import.meta.url).href;
    const script = `import dns from 'node:dns/promises';import {syncBuiltinESMExports} from 'node:module';
      dns.lookup=async()=>[{address:'::1',family:6},{address:'127.0.0.1',family:4}];syncBuiltinESMExports();
      const {runDast}=await import(process.argv[1]);const origin=process.argv[2];
      const [check]=await runDast({policy:{version:2,kind:'sql-boolean-differential',baseUrl:origin+'/',url:origin+'/items?id=1',parameter:'id',profile:'numeric',oracle:{jsonPointer:'/count',expectedBaseline:1,expectedTrue:1,expectedFalse:0},authorizationEnv:'OWNED_AUTH',identity:{path:'/owned-identity',status:200,jsonPointer:'/principal',equals:'owned-principal'}},consent:true,allowPrivate:true,maxRequests:Number(process.argv[3]),env:{OWNED_AUTH:'Bearer owned-retry-value'}});console.log(JSON.stringify(check));`;
    for (const maxRequests of [19, 20]) {
      accepted = 0;
      const child = spawn(process.execPath, ['--input-type=module', '-e', script, runtime, origin, String(maxRequests)],
        { env: { PATH: process.env.PATH ?? '', NODE_EXTRA_CA_CERTS: ca }, stdio: ['ignore', 'pipe', 'pipe'] });
      const stdout: Buffer[] = [], stderr: Buffer[] = [];
      child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk)); child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
      let timedOut = false;
      const cleanupTimer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 8000);
      let code: number | null;
      try {
        code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
      } finally { clearTimeout(cleanupTimer); if (child.exitCode === null) child.kill('SIGKILL'); }
      assert.equal(timedOut, false, `Owned retry child exceeded its cleanup timeout: ${Buffer.concat(stderr).toString('utf8')}`);
      assert.equal(code, 0, Buffer.concat(stderr).toString('utf8'));
      const check = JSON.parse(Buffer.concat(stdout).toString('utf8'));
      assert.equal(check.status, maxRequests === 20 ? 'completed' : 'partial');
      assert.equal(check.dastExecution.counts.httpAttempts, maxRequests);
      assert.equal(accepted, maxRequests === 20 ? 10 : 9);
      assert.equal(check.dastExecution.steps[0].httpAttempts, 2);
      assert.equal(check.dastExecution.steps[9].httpAttempts, maxRequests === 20 ? 2 : 1);
      assert.equal(check.dastExecution.probeOutcome, 'observed'); assert.equal(check.findings.length, 1);
      assert.equal(check.findings[0].confidence, maxRequests === 20 ? 'medium' : 'low');
      assert.equal(check.dastExecution.identityControls.after, maxRequests === 20 ? 'matched' : 'inconclusive');
      assert.equal(JSON.stringify(check).includes('owned-retry-value'), false);
    }
  } finally {
    if (resetServer) await new Promise<void>(resolve => resetServer!.close(() => resolve()));
    if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server!.close(() => resolve())); }
    await rm(directory, { recursive: true, force: true });
  }
});
