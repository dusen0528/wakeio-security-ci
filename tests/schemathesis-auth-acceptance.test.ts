import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { access, chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { setTimeout as pause } from 'node:timers/promises';
import { createServer } from 'node:http';
import { runSchemathesisLive } from '../src/schemathesis-live.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';
import { parseScanReport, compareReports } from '../src/compare.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';

// Independent expectations frozen before producer output. Real engine only;
// target's private wire/handler observer is the oracle, not product mode labels.
const FIXTURE = new URL('../../tests/fixtures/schemathesis-auth-target.mjs', import.meta.url).href;
const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PYTHON = resolve(process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(process.cwd(), '.venv-schemathesis/bin/python'));
const ENV = 'OWNED_SCHEMATHESIS_AUTH', REVISION = 'schemathesis-get-auth-v1';
const PHASES = ['identity-before', 'anonymous-normal', 'normal-before', 'normal-after', 'identity-after'];
type Target = any;
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
async function fixture(mode = 'vulnerable', options: Record<string, unknown> = {}): Promise<Target> {
  return (await import(FIXTURE)).startSchemathesisAuthTarget(mode, options);
}
function options(target: Target, extra: Record<string, unknown> = {}): any {
  return { document: target.schema, baseUrl: target.origin + '/', operations: [{ method: 'GET', path: '/items/{id}' }],
    consent: true, allowPrivate: true, python: PYTHON, maxRequests: 12, timeoutMs: 15_000, seed: 7,
    authPolicy: target.policy(), env: { [ENV]: target.authorization }, ...extra };
}
async function run(target: Target, extra: Record<string, unknown> = {}): Promise<any> {
  const checks = await runSchemathesisLive(options(target, extra)); assert.equal(checks.length, 1); return checks[0];
}
function report(check: any): any { return createReport([check], 'api', '2026-10-13T00:00:00.000Z'); }
function gate(check: any, expected: number) {
  const r = report(check); assert.equal(evaluateGate(r, 'medium').exitCode, expected);
  assert.equal(toAgentReport(r, 'medium').scanGate.exitCode, expected);
  if (expected === 2) { assert.equal(evaluateGate(r, 'none').exitCode, 2); assert.equal(toSarif(r).runs[0].invocations[0].executionSuccessful, false); }
}
function noSecrets(value: string, target: Target) {
  for (const secret of [ENV, target.authorization, target.authorization.slice(7), sha(target.authorization), sha(target.authorization.slice(7)),
    target.principal, target.marker, 'owned-other-private-principal', 'owned-wrong-private-marker',
    'owned-private-identity-body', 'owned-private-failure-body', 'private-cookie-canary']) {
    assert.equal(value.includes(secret), false, 'Auth evidence leaked a private fixture value or credential-derived hash');
  }
}
function fourFormats(check: any, target: Target, expected: number) {
  const r = report(check), agent = toAgentReport(r, 'medium'); gate(check, expected);
  for (const text of [JSON.stringify(r), JSON.stringify(agent), toMarkdown(r), JSON.stringify(toSarif(r))]) {
    noSecrets(text, target); assert.ok(text.includes(REVISION), 'Each report format must carry the auth evidence revision');
  }
}
function wire(check: any, target: Target, complete: boolean) {
  const e = check.schemathesisAuth; assert.ok(e, 'Typed auth evidence required');
  assert.equal(e.version, 1); assert.equal(e.profileRevision, REVISION);
  assert.deepEqual(e.controls.map((c: any) => c.phase), PHASES);
  assert.deepEqual(e.controls.map((c: any) => c.ordinal), [1, 2, 3, 4, 5]);
  assert.deepEqual(e.controls.map((c: any) => c.operationIndex), [null, 0, 0, 0, null]);
  assert.equal(e.requests.attempted, target.requests.length); assert.ok(e.requests.attempted <= 12);
  assert.equal(e.requests.completedGenerated, e.records.length);
  assert.ok(target.requests.every((q: any) => q.method === 'GET' && q.contentBytes === 0));
  assert.ok(target.requests.every((q: any) => q.path === '/whoami' || /^\/items\/[12]$/.test(q.path)));
  assert.equal(target.stats.stateUnchanged, true);
  if (complete) {
    assert.equal(e.status, 'completed'); assert.equal(e.stopReason, 'complete');
    assert.ok(e.controls.every((c: any) => c.outcome === 'matched'));
    assert.ok(e.records.length >= 1); assert.equal(e.operations.length, 1);
    assert.equal(e.operations[0].operation, 'GET /items/{id}');
    assert.equal(e.operations[0].generatedRequests, e.requests.generated); assert.equal(e.operations[0].deniedRequests, 0);
    assert.equal(target.requests[0].path, '/whoami'); assert.equal(target.requests.at(-1).path, '/whoami');
    assert.deepEqual(target.requests.slice(0, 3).map((q: any) => [q.path, q.credentialMatched]),
      [['/whoami', true], ['/items/1', false], ['/items/1', true]]);
    assert.equal(target.requests.at(-2).path, '/items/1');
    for (const c of e.controls) { const q = target.requests[c.attempt - 1]; assert.ok(q); assert.equal(q.status, c.httpStatus); }
    for (const row of e.records) {
      const q = target.requests[row.attempt - 1]; assert.ok(q); assert.equal(q.protectedHandler, true);
      assert.equal(q.credentialMatched, true); assert.equal(q.principal, target.principal); assert.equal(row.status, q.status);
      assert.equal(row.operationIndex, 0); assert.ok(!e.controls.some((c: any) => c.attempt === row.attempt));
    }
    assert.ok(e.records.some((row: any) => target.requests[row.attempt - 1].id === 2), 'Real generated id2 must reach protected handler');
  }
}
async function child(entry: string, args: string[], env: NodeJS.ProcessEnv = {}, cwd = ROOT) {
  return new Promise<{ code: number | null; out: string; err: string }>((done, reject) => {
    const p = spawn(process.execPath, [entry, ...args], { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; const timer = setTimeout(() => { p.kill('SIGKILL'); reject(new Error('Owned auth consumer exceeded deadline')); }, 35_000);
    p.stdout.on('data', chunk => { out += String(chunk); }); p.stderr.on('data', chunk => { err += String(chunk); });
    p.once('error', error => { clearTimeout(timer); reject(error); }); p.once('close', code => { clearTimeout(timer); done({ code, out, err }); });
  });
}
async function inputs(top: string, target: Target) {
  const schema = join(top, 'schema.json'), policy = join(top, 'auth-policy.json');
  await writeFile(schema, JSON.stringify(target.schema)); await writeFile(policy, JSON.stringify(target.policy())); return { schema, policy };
}
function cliArgs(input: { schema: string; policy: string }, target: Target, out: string) {
  return ['scan', '--openapi', input.schema, '--api-base', target.origin + '/', '--operation', '/items/{id}',
    '--schemathesis-auth-policy', input.policy, '--active-consent', '--allow-private', '--schemathesis-python', PYTHON,
    '--api-max-requests', '12', '--seed', '7', '--timeout-ms', '15000', '--fail-on', 'medium', '--tools', 'none', '--out', out];
}

test('auth independent: documented401 legacy clean never reaches protected handler; real generated id2 V/F discriminates1/0', { timeout: 90_000 }, async () => {
  const legacy = await fixture('vulnerable');
  try {
    const unauth = options(legacy); delete unauth.authPolicy; delete unauth.env;
    const [check] = await runSchemathesisLive(unauth); assert.equal(check!.status, 'completed'); gate(check, 0);
    assert.ok(legacy.requests.length > 0); assert.ok(legacy.requests.every((q: any) => q.status === 401));
    assert.equal(legacy.stats.protectedHandlerRequests, 0); assert.equal(legacy.stats.generatedIdTwoRequests, 0);
  } finally { await legacy.close(); }
  for (const [mode, expected] of [['vulnerable', 1], ['fixed', 0]] as const) {
    const target = await fixture(mode);
    try {
      const check = await run(target); assert.equal(check.status, 'completed'); wire(check, target, true); fourFormats(check, target, expected);
      assert.ok(target.stats.generatedIdTwoRequests > 0);
      const reached = target.requests.filter((q: any) => q.protectedHandler && q.id === 2);
      assert.ok(reached.every((q: any) => q.branch === (expected ? 'id-two-failure' : 'generated-row') && q.status === (expected ? 500 : 200)));
      if (expected) { assert.ok(check.findings.some((f: any) => f.ruleId === 'api.schemathesis.server_error' && f.severity === 'medium' && f.kind === 'observation')); }
      else assert.deepEqual(check.findings, []);
    } finally { await target.close(); }
    assert.equal(target.socketCount, 0);
  }
});

test('auth independent: initial denial/ignored credential/expiry/normal failure prohibit generation; trailing drift retains observed failure2', { timeout: 90_000 }, async () => {
  for (const mode of ['all-deny', 'ignored-credential', 'expired', 'normal-regression', 'denial-leak', 'drift']) {
    const target = await fixture(mode);
    try {
      const check = await run(target); gate(check, 2); assert.notEqual(check.status, 'completed'); fourFormats(check, target, 2); wire(check, target, false);
      if (mode === 'drift') { assert.ok(target.stats.generatedIdTwoRequests > 0); assert.ok(check.findings.some((f: any) => f.ruleId === 'api.schemathesis.server_error'));
        assert.equal(check.schemathesisAuth.controls.at(-1).outcome, 'not_matched'); }
      else { assert.equal(target.stats.generatedIdTwoRequests, 0); assert.equal(check.schemathesisAuth.records.length, 0); assert.deepEqual(check.findings, []); }
      if (mode === 'expired') assert.equal(target.requests.length, 1);
      if (mode === 'ignored-credential') { assert.ok(target.requests.some((q: any) => !q.credentialMatched && q.markerPresent)); assert.equal(target.requests.length, 2); }
    } finally { await target.close(); }
  }
  // Supplemental owned malformed-denial wrapper; frozen target v1 is unchanged.
  for (const body of ['not-json', '{"marker":']) {
    let generated = 0; const target = await fixture('fixed');
    const server = createServer((req, res) => {
      const path = new URL(req.url!, 'http://owned.invalid').pathname;
      const auth = req.headers.authorization === target.authorization;
      if (path === '/items/1' && !auth) { res.writeHead(403, { 'content-type': 'application/json' }); res.end(body); return; }
      if (path === '/items/2') generated++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(path === '/whoami' ? { principal: target.principal } : { id: 1, name: 'owned-row', marker: target.marker }));
    });
    await new Promise<void>(done => server.listen(0, '127.0.0.1', done)); const address = server.address(); assert.ok(address && typeof address !== 'string');
    const origin = `http://127.0.0.1:${address.port}`, policy = target.policy(); policy.baseUrl = origin + '/';
    try { const check = await run(target, { baseUrl: origin + '/', authPolicy: policy }); gate(check, 2); assert.equal(generated, 0);
      assert.equal(check.schemathesisAuth.controls[1].outcome, 'not_matched'); }
    finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); await target.close(); }
  }
});

test('auth independent: strict policy/credential boundaries refuse traffic; snapshots remain stable and SetCookie cannot alter auth', { timeout: 90_000 }, async () => {
  const target = await fixture('fixed'); let invoked = 0;
  try {
    const base = target.policy();
    const mutations: Array<(p: any) => void> = [p => { p.version = 2; }, p => { p.kind = 'other'; }, p => { p.baseUrl = 'https://outside.invalid/'; },
      p => { p.identity.path = 'https://outside.invalid/whoami'; }, p => { p.identity.status = 401; }, p => { p.operations = []; },
      p => { p.operations.push(copy(p.operations[0])); }, p => { p.operations[0].path = '/never-selected'; },
      p => { p.operations[0].normal.path = '/never-selected'; }, p => { p.operations[0].normal.path = '//outside.invalid/'; },
      p => { p.operations[0].normal.status = 403; }, p => { p.secretExtra = 'owned-private-policy-canary'; }];
    for (const mutate of mutations) { const p = copy(base); mutate(p); gate(await run(target, { authPolicy: p }), 2); }
    for (const env of [{}, Object.create({ [ENV]: target.authorization }), { get [ENV]() { invoked++; return target.authorization; } },
      new Proxy({ [ENV]: target.authorization }, { get() { invoked++; throw Error('private proxy'); } }), { [ENV]: 'Bearer bad\nvalue' }]) gate(await run(target, { env }), 2);
    const hostile = options(target); Object.defineProperty(hostile, 'authPolicy', { enumerable: true, get() { invoked++; return base; } });
    gate((await runSchemathesisLive(hostile))[0], 2); gate(await run(target, { consent: false }), 2);
    assert.equal(invoked, 0); assert.equal(target.requests.length, 0);
    const schema = copy(target.schema); schema.paths['/items/{id}'].get.parameters.push({ name: 'Authorization', in: 'header', required: true, schema: { type: 'string' } });
    gate(await run(target, { document: schema }), 2); assert.equal(target.requests.length, 0);
    const p = target.policy(), env = { [ENV]: target.authorization }, config = options(target, { authPolicy: p, env });
    const pending = runSchemathesisLive(config); await target.firstRequest;
    env[ENV] = 'Bearer changed-after-start'; p.identity.equals = 'changed-after-start'; p.operations[0].normal.equals = 'changed-after-start';
    config.operations[0].path = '/never-selected'; const [check] = await pending; wire(check, target, true); gate(check, 0);
    assert.ok(target.requests.filter((q: any) => q.credentialMatched).every((q: any) => q.authorization === target.authorization));
  } finally { await target.close(); }
  const cookies = await fixture('cookie');
  try { const check = await run(cookies); gate(check, 0); assert.ok(cookies.requests.every((q: any) => q.cookie === null)); noSecrets(JSON.stringify(report(check)), cookies); }
  finally { await cookies.close(); }
});

test('auth independent: exact shared budget, no dropped-reply retry, streaming abort/descendants and verified owned TLS', { timeout: 120_000 }, async () => {
  const insufficient = await fixture('fixed');
  try { gate(await run(insufficient, { maxRequests: 5 }), 2); assert.equal(insufficient.requests.length, 0); }
  finally { await insufficient.close(); }
  for (const [mode, extra] of [['fixed', { maxRequests: 6 }], ['drop', {}], ['oversize', { maxBodyBytes: 128 }], ['stream', { timeoutMs: 800 }],
    ['redirect', {}]] as const) {
    const target = await fixture(mode);
    try { const check = await run(target, extra); gate(check, mode === 'fixed' ? 0 : 2); assert.ok(target.requests.length <= Number((extra as Record<string, unknown>).maxRequests ?? 12));
      if (mode === 'fixed') { assert.equal(check.schemathesisAuth.requests.completedGenerated, 1); assert.equal(target.requests.length, 6); }
      if (mode === 'drop') assert.equal(target.stats.generatedIdTwoRequests, 1, 'Dropped reply must not cause another generated HTTP attempt');
      if (mode === 'redirect') assert.ok(!target.requests.some((q: any) => q.path === '/never-selected'));
      assert.ok(target.requests.every((q: any) => q.method === 'GET'));
      const stopped = target.requests.length; await pause(60); assert.equal(target.requests.length, stopped); }
    finally { await target.close(); }
  }
  const top = await mkdtemp(join(tmpdir(), 'wakeio-auth-lifecycle-'));
  try {
    const pidFile = join(top, 'descendant.pid'), wrapper = join(top, 'owned-python-wrapper');
    const quote = (s: string) => `'${s.replaceAll("'", "'\\''")}'`;
    await writeFile(wrapper, `#!/bin/sh\n${quote(process.execPath)} -e 'setInterval(()=>{},1000)' &\nprintf '%s' "$!" > ${quote(pidFile)}\nexec ${quote(PYTHON)} "$@"\n`); await chmod(wrapper, 0o700);
    const target = await fixture('stream'); const abort = new AbortController();
    try { const pending = run(target, { python: wrapper, signal: abort.signal }); await target.firstGenerated; abort.abort();
      const check = await pending; gate(check, 2); assert.equal(check.schemathesisAuth.stopReason, 'cancelled');
      const pid = Number(await readFile(pidFile, 'utf8')); let alive = true;
      for (let i = 0; i < 40 && alive; i++) { try { process.kill(pid, 0); await pause(25); } catch (e) { assert.equal((e as NodeJS.ErrnoException).code, 'ESRCH'); alive = false; } }
      assert.equal(alive, false, 'Owned worker descendant must terminate'); const count = target.requests.length; await pause(60); assert.equal(target.requests.length, count);
    } finally { await target.close(); }
    const caKey = join(top, 'ca.key'), ca = join(top, 'ca.pem'), key = join(top, 'server.key'), csr = join(top, 'server.csr'), cert = join(top, 'server.pem'), ext = join(top, 'server.ext');
    const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', ca, '-subj', '/CN=Owned Schemathesis QA CA', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE');
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', '/CN=127.0.0.1');
    await writeFile(ext, 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n');
    openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-out', cert, '-days', '1', '-extfile', ext);
    const tls = { key: await readFile(key), cert: await readFile(cert) }; const secure = await fixture('vulnerable', { tls });
    try {
      const input = await inputs(top, secure);
      const untrusted = await child(CLI, cliArgs(input, secure, join(top, 'untrusted')), { [ENV]: secure.authorization, NODE_EXTRA_CA_CERTS: '' });
      assert.equal(untrusted.code, 2); assert.equal(secure.requests.length, 0);
      const disabledGlobal = await child(CLI, cliArgs(input, secure, join(top, 'untrusted-global-disabled')),
        { [ENV]: secure.authorization, NODE_EXTRA_CA_CERTS: '', NODE_TLS_REJECT_UNAUTHORIZED: '0' });
      assert.equal(disabledGlobal.code, 2); assert.equal(secure.requests.length, 0, 'Product explicit TLS verification overrides unsafe global setting');
      const trusted = await child(CLI, cliArgs(input, secure, join(top, 'trusted')), { [ENV]: secure.authorization, NODE_EXTRA_CA_CERTS: ca });
      assert.equal(trusted.code, 1, trusted.err); assert.ok(secure.stats.generatedIdTwoRequests > 0); assert.ok(secure.requests.every((q: any) => q.method === 'GET'));
    } finally { await secure.close(); }
    await writeFile(ext, 'subjectAltName=DNS:owned-wrong-host.invalid\nextendedKeyUsage=serverAuth\n');
    openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-out', cert, '-days', '1', '-extfile', ext);
    const wrong = await fixture('fixed', { tls: { key: tls.key, cert: await readFile(cert) } });
    try { const input = await inputs(top, wrong); const result = await child(CLI, cliArgs(input, wrong, join(top, 'wrong-host')), { [ENV]: wrong.authorization, NODE_EXTRA_CA_CERTS: ca });
      assert.equal(result.code, 2); assert.equal(wrong.requests.length, 0); }
    finally { await wrong.close(); }
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('auth independent: malformed/missing control metadata never upgrades report to clean and secret extras never escape', { timeout: 45_000 }, async () => {
  const target = await fixture('fixed');
  try {
    const valid = await run(target); wire(valid, target, true); gate(valid, 0);
    const mutations: Array<(c: any) => void> = [c => { delete c.schemathesisAuth; }, c => { c.schemathesisAuth.profileRevision = 'wrong'; },
      c => { c.schemathesisAuth.operations.push(copy(c.schemathesisAuth.operations[0])); }, c => { c.schemathesisAuth.operations = []; },
      c => { c.schemathesisAuth.controls[1].outcome = 'not_matched'; }, c => { c.schemathesisAuth.controls[1].httpStatus = 200; },
      c => { c.schemathesisAuth.controls[0].attempt = 2; }, c => { c.schemathesisAuth.controls.pop(); },
      c => { c.schemathesisAuth.controls[2].phase = 'normal-after'; }, c => { c.schemathesisAuth.requests.attempted++; },
      c => { c.schemathesisAuth.records[0].operationIndex = 1; }, c => { c.schemathesisAuth.records[0].status = 401; },
      c => { c.schemathesisAuth.records[0].attempt = c.schemathesisAuth.controls[0].attempt; },
      c => { c.schemathesisAuth.operations[0].generatedRequests++; }, c => { c.schemathesisAuth.records[0].ordinal = 2; },
      c => { c.schemathesisAuth.records[0].attempt = c.schemathesisAuth.controls.at(-1).attempt; },
      c => { c.schemathesisAuth.records[0].check = 'response_contract'; c.schemathesisAuth.records[0].failures = [{ rule: 'response_schema_conformance', kind: 'schema_violation', keyword: target.marker }]; },
      c => { c.schemathesisAuth.controls[0].outcome = {}; }, c => { c.schemathesisAuth.engineVersion = '0.0.0'; },
      c => { c.schemathesisAuth.secretExtra = target.authorization; c.schemathesisAuth.controls[0].rawBody = target.marker; }];
    for (const mutate of mutations) {
      const check = copy(valid); mutate(check); gate(check, 2); const r = report(check);
      for (const text of [JSON.stringify(r), JSON.stringify(toAgentReport(r)), toMarkdown(r), JSON.stringify(toSarif(r))]) noSecrets(text, target);
      try { const parsed = parseScanReport(copy(r)); assert.ok(parsed); const comparison = compareReports(r, report(valid)); assert.equal(comparison.comparable, false); }
      catch (error) { assert.match(String(error), /Invalid scan report|Invalid report|invalid.*report/i); }
    }
  } finally { await target.close(); }
});

test('auth independent: public CLI and real DAST Action retain0/1/2 gates, four reports, typed advice and digest-bound outputs', { timeout: 120_000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-auth-consumers-'));
  try {
    for (const [mode, expected] of [['vulnerable', 1], ['fixed', 0], ['all-deny', 2]] as const) {
      for (const consumer of ['cli', 'action']) {
        const target = await fixture(mode);
        try {
          const prefix = join(top, mode + '-' + consumer), input = await inputs(top, target), out = prefix + '-reports', outputs = prefix + '-outputs';
          const result = consumer === 'cli' ? await child(CLI, cliArgs(input, target, out), { [ENV]: target.authorization })
            : await child(join(ROOT, 'scripts/action-run.mjs'), [], { [ENV]: target.authorization, WAKEIO_MODE: 'dast', GITHUB_WORKSPACE: top,
              WAKEIO_ACTION_PATH: ROOT, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_OUTPUT: outputs, GITHUB_STEP_SUMMARY: prefix + '-summary',
              WAKEIO_ACTIVE_CONSENT: 'true', WAKEIO_ALLOWED_ORIGINS: target.origin, WAKEIO_OPENAPI: input.schema,
              WAKEIO_API_BASE: target.origin + '/', WAKEIO_OPERATIONS: '/items/{id}', WAKEIO_SCHEMATHESIS_AUTH_POLICY: input.policy,
              WAKEIO_SCHEMATHESIS_PYTHON: PYTHON, WAKEIO_API_MAX_REQUESTS: '12', WAKEIO_SEED: '7', WAKEIO_ALLOW_PRIVATE: 'true',
              WAKEIO_FAIL_ON: 'medium', WAKEIO_TIMEOUT_MS: '15000', WAKEIO_OUT: out }, top);
          assert.equal(result.code, expected, `${consumer}/${mode}: ${result.err}`); noSecrets(result.out + result.err, target);
          const reportBytes = await readFile(join(out, 'report.json')), r = JSON.parse(reportBytes.toString('utf8'));
          const agent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
          assert.equal(evaluateGate(r, 'medium').exitCode, expected); assert.equal(agent.scanGate.exitCode, expected);
          assert.equal(agent.reportArtifact.digest, sha(reportBytes)); assert.equal(agent.checks.length, 1);
          assert.equal(agent.checks[0].schemathesisAuth.profileRevision, REVISION);
          for (const name of ['report.json', 'agent-report.json', 'report.md', 'report.sarif']) { const text = await readFile(join(out, name), 'utf8');
            assert.ok(text.includes(REVISION), `${consumer}/${name} lacks typed auth revision`); noSecrets(text, target); }
          if (expected !== 2) { assert.ok(target.stats.generatedIdTwoRequests > 0); assert.ok(agent.checks[0].schemathesisAuth.controls.every((c: any) => c.outcome === 'matched')); }
          else assert.equal(target.stats.generatedIdTwoRequests, 0);
          const advice: any = projectAdviceContext(agent, false); noSecrets(JSON.stringify(advice), target);
          assert.ok(advice.input.checks.some((c: any) => c.schemathesisAuth?.profileRevision === REVISION), 'Advice needs bounded typed auth metadata');
          assert.ok(advice.input.findings.every((f: any) => f.replayAvailable === false), 'Seed rerun is not exact-input replay');
          if (consumer === 'action') { const text = await readFile(outputs, 'utf8'); assert.ok(text.split(/\r?\n/).includes(`exit-code=${expected}`));
            assert.ok(text.includes('report-agent=')); const status = JSON.parse(await readFile(join(out, 'action-status.json'), 'utf8'));
            assert.equal(status.exitCode, expected); assert.equal(status.scanStatus, expected === 0 ? 'success' : expected === 1 ? 'findings' : 'incomplete'); }
        } finally { await target.close(); }
      }
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});
