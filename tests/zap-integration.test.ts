import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runZap } from '../src/zap.js';
import { runExecutionPlan } from '../src/agent-dast/runner.js';
import { zapPolicyTarget } from './fixtures/zap-policy-target.js';
import { zapPolicyEngine } from './fixtures/zap-policy-engine.js';
const ROOT = process.cwd(), CLI = join(ROOT, 'build/src/cli.js');
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
async function child(entry: string, args: string[], env: NodeJS.ProcessEnv, cwd = ROOT) {
  return new Promise<{ code: number | null; out: string; err: string }>((resolve, reject) => {
    const proc = spawn(process.execPath, [entry, ...args], { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; proc.stdout.on('data', b => { out += b; }); proc.stderr.on('data', b => { err += b; });
    proc.once('error', reject); proc.once('close', code => resolve({ code, out, err }));
  });
}

test('ZAP principal controls, shared cap and cancellation prevent a false completed result', { timeout: 20000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-controls-'));
  try {
    const engine = await zapPolicyEngine(top, 2);
    for (const options of [{ ignoreAuth: true }, { expire: true }]) {
      const target = await zapPolicyTarget(options); target.policy.requests = [target.policy.requests[0]!];
      try { const result = (await runZap({ url: target.origin, policy: target.policy, env: target.env, executable: engine,
        consent: true, allowPrivate: true, rateLimit: 50, timeoutMs: 5000 }))[0]!;
        assert.equal(result.status, 'partial'); assert.equal(result.metrics!.stopReason, 'identity_control_failed');
        assert.equal(result.metrics!.requestCount, target.seen.length);
        if (options.ignoreAuth) assert.ok(target.seen.every(q => q.path === '/identity'), 'No probes when anonymous principal control succeeds');
      } finally { await target.close(); }
    }
    const target = await zapPolicyTarget(); target.policy.requests = [target.policy.requests[0]!];
    try {
      const bytes = JSON.stringify(target.policy); await writeFile(join(top, 'policy.json'), bytes);
      const plan = { version: 1 as const, kind: 'wakeio.execution-plan' as const, origin: target.origin,
        tasks: [{ id: 't-zap-a', engine: 'zap' as const, policy: 'policy', maxRequests: 10 }, { id: 't-zap-b', engine: 'zap' as const, policy: 'policy', maxRequests: 10 }] };
      const options = { plan, inputs: { version: 1 as const, inputs: [{ id: 'policy', path: 'policy.json', sha256: sha(bytes) }] }, inputBaseDir: top,
        outDir: join(top, 'run'), consent: true, allowedOrigin: target.origin, allowPrivate: true, maxRequests: 5, timeoutMs: 10000,
        ratePerSecond: 50, concurrency: 2, zapPath: await zapPolicyEngine(top, 20), env: target.env, failOn: 'none' as const };
      const capped = await runExecutionPlan(options);
      assert.equal(capped.exitCode, 2); assert.equal(capped.requests.requestCount, 5); assert.equal(target.seen.length, 5);
      assert.equal(capped.requests.pending, 0); assert.equal(capped.requests.requestCount, capped.tasks.reduce((n, t) => n + t.requests.requestCount, 0));
      const signal = new AbortController(), before = target.seen.length;
      const pending = runExecutionPlan({ ...options, outDir: join(top, 'cancelled'), maxRequests: 100, zapPath: await zapPolicyEngine(top, 30, 100), signal: signal.signal });
      for (let i = 0; i < 100 && target.seen.length <= before + 2; i++) await new Promise(r => setTimeout(r, 10));
      assert.ok(target.seen.length > before + 2); signal.abort(); const cancelled = await pending;
      assert.equal(cancelled.exitCode, 2); const count = target.seen.length; await new Promise(r => setTimeout(r, 120)); assert.equal(target.seen.length, count);
    } finally { await target.close(); }
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('ZAP and native DAST share one request budget and paced admission across concurrent tasks', { timeout: 10000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-mixed-')), target = await zapPolicyTarget({ ignoreAuth: true });
  try {
    delete target.policy.authentication; target.policy.requests = [target.policy.requests[0]!];
    const native = { version: 1, kind: 'sql-boolean-differential', baseUrl: target.origin + '/', url: target.origin + '/native?id=1',
      parameter: 'id', profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
    const inputs = [];
    for (const [id, policy] of [['zap', target.policy], ['native', native]] as const) {
      const bytes = JSON.stringify(policy); await writeFile(join(top, id + '.json'), bytes); inputs.push({ id, path: id + '.json', sha256: sha(bytes) });
    }
    const result = await runExecutionPlan({ plan: { version: 1, kind: 'wakeio.execution-plan', origin: target.origin, tasks: [
      { id: 't-native', engine: 'native-dast', policy: 'native', maxRequests: 8 }, { id: 't-zap', engine: 'zap', policy: 'zap', maxRequests: 20 },
    ] }, inputs: { version: 1, inputs }, inputBaseDir: top, outDir: join(top, 'run'), consent: true, allowedOrigin: target.origin,
      allowPrivate: true, maxRequests: 10, timeoutMs: 6000, ratePerSecond: 10, concurrency: 2, zapPath: await zapPolicyEngine(top, 20) });
    assert.equal(result.exitCode, 2); assert.equal(result.requests.requestCount, 10); assert.equal(target.seen.length, 10);
    assert.ok(target.seen.some(q => q.path === '/native')); assert.ok(target.seen.some(q => q.path === '/xss'));
    assert.equal(result.requests.requestCount, result.tasks.reduce((n, task) => n + task.requests.requestCount, 0));
    assert.ok(target.seen.at(-1)!.at - target.seen[0]!.at >= 850, 'All tasks consume one paced 10/s admission');
  } finally { await target.close(); await rm(top, { recursive: true, force: true }); }
});

test('ZAP CLI verifies owned HTTPS CA and hostname despite disabled global TLS, and refuses invalid input with zero traffic', { timeout: 30000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-tls-'));
  try {
    const engine = await zapPolicyEngine(top), caKey = join(top, 'ca.key'), ca = join(top, 'ca.pem'), key = join(top, 'key'), csr = join(top, 'csr'), cert = join(top, 'cert'), ext = join(top, 'ext');
    const ssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
    ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', ca, '-subj', '/CN=Owned ZAP CA', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE');
    ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', '/CN=127.0.0.1');
    for (const wrong of [false, true]) {
      await writeFile(ext, `subjectAltName=${wrong ? 'DNS:wrong.invalid' : 'IP:127.0.0.1'}\nextendedKeyUsage=serverAuth\n`);
      ssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-out', cert, '-days', '1', '-extfile', ext);
      const target = await zapPolicyTarget({ tls: { key: await readFile(key), cert: await readFile(cert) } }); target.policy.requests = [target.policy.requests[0]!];
      try {
        const policy = join(top, 'policy.json'); await writeFile(policy, JSON.stringify(target.policy));
        const args = ['scan', '--url', target.origin, '--engine', 'zap', '--zap-policy', policy, '--zap', engine, '--zap-rate-limit', '50', '--active-consent', '--allow-private', '--tools', 'none', '--fail-on', 'none'];
        for (const trusted of wrong ? [true] : [false, true]) {
          const before = target.seen.length, out = join(top, `out-${wrong}-${trusted}`);
          const result = await child(CLI, [...args, '--out', out], { ...target.env, NODE_EXTRA_CA_CERTS: trusted ? ca : '', NODE_TLS_REJECT_UNAUTHORIZED: '0' });
          assert.equal(result.code, !wrong && trusted ? 0 : 2, result.err);
          if (!wrong && trusted) { assert.equal(target.seen.length - before, 5); const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8'));
            assert.equal(report.checks.find((c: any) => c.id === 'url.zap').metrics.identityAfter, true);
          } else assert.equal(target.seen.length, before, 'Invalid TLS peer receives no HTTP request');
          assert.equal((result.out + result.err).includes(target.authorization), false);
        }
        await writeFile(policy, JSON.stringify({ ...target.policy, requests: [{ method: 'POST', path: '/json', body: { id: [] } }] }));
        const before = target.seen.length; assert.equal((await child(CLI, [...args, '--out', join(top, 'bad-' + wrong)], target.env)).code, 2); assert.equal(target.seen.length, before);
      } finally { await target.close(); }
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('real ZAP run-plan Action publishes matching DB, evidence, report and shared request ledger', { skip: !process.env.WAKEIO_ZAP_PATH, timeout: 180000 }, async context => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-plan-action-')), target = await zapPolicyTarget();
  try {
    await mkdir(join(top, 'actions/run-plan'), { recursive: true }); await mkdir(join(top, 'dist-action'));
    for (const file of ['run.mjs', 'supervise.mjs']) await copyFile(join(ROOT, 'actions/run-plan', file), join(top, 'actions/run-plan', file));
    await copyFile(join(ROOT, 'dist-action/wakeio-security-ci.mjs'), join(top, 'dist-action/wakeio-security-ci.mjs'));
    const bytes = JSON.stringify(target.policy); await writeFile(join(top, 'policy.json'), bytes);
    await writeFile(join(top, 'inputs.json'), JSON.stringify({ version: 1, inputs: [{ id: 'policy', path: 'policy.json', sha256: sha(bytes) }] }));
    await writeFile(join(top, 'plan.json'), JSON.stringify({ version: 1, kind: 'wakeio.execution-plan', origin: target.origin,
      tasks: [{ id: 't-zap', engine: 'zap', policy: 'policy', maxRequests: 1000 }] }));
    const result = await child(join(top, 'actions/run-plan/run.mjs'), [], { ...target.env, GITHUB_WORKSPACE: top, GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_OUTPUT: join(top, 'outputs'), GITHUB_STEP_SUMMARY: join(top, 'summary'), WAKEIO_ACTION_PATH: join(top, 'actions/run-plan'),
      WAKEIO_PLAN: 'plan.json', WAKEIO_PLAN_INPUTS: 'inputs.json', WAKEIO_PLAN_ACTIVE_CONSENT: 'true', WAKEIO_PLAN_ALLOWED_ORIGIN: target.origin,
      WAKEIO_PLAN_OUT: 'result', WAKEIO_PLAN_TIMEOUT_MS: '120000', WAKEIO_PLAN_MAX_REQUESTS: '1000', WAKEIO_PLAN_RATE: '50',
      WAKEIO_PLAN_CONCURRENCY: '2', WAKEIO_PLAN_FAIL_ON: 'high', WAKEIO_PLAN_ALLOW_PRIVATE: 'true', WAKEIO_PLAN_ZAP_PATH: process.env.WAKEIO_ZAP_PATH }, top);
    assert.equal(result.code, 1, result.err + result.out);
    const outputs = await readFile(join(top, 'outputs'), 'utf8'); assert.match(outputs, /delivery-status=delivered/); assert.match(outputs, /exit-code=1/);
    const out = join(top, 'result'), reportBytes = await readFile(join(out, 'tasks/t-zap/report.json')), report = JSON.parse(reportBytes.toString());
    const check = report.checks.find((c: any) => c.id === 'url.zap'); assert.equal(check.status, 'completed'); assert.equal(check.findings.length, 3);
    assert.equal(check.metrics.requestCount, target.seen.length);
    const db = new DatabaseSync(join(out, 'run.db'), { readOnly: true });
    try { const rows = db.prepare('SELECT * FROM findings').all(); assert.equal(rows.length, 3);
      for (const row of rows) { const evidence = JSON.parse(await readFile(join(out, row.evidence_ref as string), 'utf8'));
        assert.equal(evidence.taskId, 't-zap'); assert.equal(evidence.reportPath, 'tasks/t-zap/report.json'); assert.ok(check.findings.some((f: any) => f.id === evidence.findingId)); }
      const surfaces = db.prepare('SELECT * FROM surface').all(); assert.ok(surfaces.some(row => row.method === 'POST' && row.location === 'body'));
    } finally { db.close(); }
    const agent = JSON.parse(await readFile(join(out, 'tasks/t-zap/agent-report.json'), 'utf8')); assert.equal(agent.reportArtifact.digest, sha(reportBytes));
    for (const file of ['report.md', 'report.sarif', 'agent-report.json', 'report.json']) assert.equal((await readFile(join(out, 'tasks/t-zap', file), 'utf8')).includes(target.authorization), false);
    assert.ok((await readdir(out)).includes('run-receipt.json'));
    context.diagnostic(JSON.stringify({ requestCount: check.metrics.requestCount, findings: check.findings.length, actionGate: result.code }));
  } finally { await target.close(); await rm(top, { recursive: true, force: true }); }
});

test('ZAP DAST Action refuses missing consent, credentials, policy and budgets before engine launch or target traffic', { timeout: 20000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-action-refuse-')), target = await zapPolicyTarget();
  try {
    await writeFile(join(top, 'policy.json'), JSON.stringify(target.policy));
    const env = { ...target.env, WAKEIO_MODE: 'dast', WAKEIO_ACTION_PATH: ROOT, GITHUB_WORKSPACE: top, GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_OUTPUT: join(top, 'outputs'), WAKEIO_ACTIVE_CONSENT: 'true', WAKEIO_ALLOWED_ORIGINS: target.origin, WAKEIO_URL: target.origin,
      WAKEIO_ENGINES: 'zap', WAKEIO_ZAP_PATH: '/missing-engine-must-not-start', WAKEIO_ZAP_POLICY: 'policy.json', WAKEIO_ALLOW_PRIVATE: 'true', WAKEIO_OUT: 'reports' };
    for (const patch of [{ WAKEIO_ACTIVE_CONSENT: 'false' }, { WAKEIO_ZAP_TEST_AUTH: '' }, { WAKEIO_ALLOWED_ORIGINS: 'https://unapproved.invalid' },
      { WAKEIO_ZAP_POLICY: '' }, { WAKEIO_ZAP_MAX_REQUESTS: '1' }, { WAKEIO_ZAP_RATE_LIMIT: '51' }, { WAKEIO_ZAP_TIMEOUT_MS: '0' }, { GITHUB_EVENT_NAME: 'pull_request_target' }]) {
      const result = await child(join(ROOT, 'scripts/action-run.mjs'), [], { ...env, ...patch }, top);
      assert.equal(result.code, 2); assert.match(result.err, /DAST refused/); assert.equal(target.seen.length, 0);
    }
  } finally { await target.close(); await rm(top, { recursive: true, force: true }); }
});

test('real ZAP DAST Action runs its bundled CLI and delivers four reports with a digest-bound finding gate', { skip: !process.env.WAKEIO_ZAP_PATH, timeout: 180000 }, async context => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-dast-action-'));
  const ca = join(top, 'ca.pem'), caKey = join(top, 'ca.key'), key = join(top, 'key'), csr = join(top, 'csr'), cert = join(top, 'cert'), ext = join(top, 'ext');
  const ssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', ca, '-subj', '/CN=Owned ZAP Action CA', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE');
  ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', '/CN=127.0.0.1');
  await writeFile(ext, 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n');
  ssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-out', cert, '-days', '1', '-extfile', ext);
  const target = await zapPolicyTarget({ tls: { key: await readFile(key), cert: await readFile(cert) } });
  try {
    await mkdir(join(top, 'scripts')); await mkdir(join(top, 'dist-action'));
    for (const file of ['action-run.mjs', 'install-tools.mjs']) await copyFile(join(ROOT, 'scripts', file), join(top, 'scripts', file));
    await copyFile(join(ROOT, 'dist-action/wakeio-security-ci.mjs'), join(top, 'dist-action/wakeio-security-ci.mjs'));
    await writeFile(join(top, 'policy.json'), JSON.stringify(target.policy));
    const result = await child(join(top, 'scripts/action-run.mjs'), [], { ...target.env, NODE_EXTRA_CA_CERTS: ca, WAKEIO_MODE: 'dast', WAKEIO_ACTION_PATH: top,
      GITHUB_WORKSPACE: top, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_OUTPUT: join(top, 'outputs'), GITHUB_STEP_SUMMARY: join(top, 'summary'),
      WAKEIO_ACTIVE_CONSENT: 'true', WAKEIO_ALLOWED_ORIGINS: target.origin, WAKEIO_URL: target.origin, WAKEIO_ENGINES: 'zap',
      WAKEIO_ZAP_PATH: process.env.WAKEIO_ZAP_PATH, WAKEIO_ZAP_POLICY: 'policy.json', WAKEIO_ZAP_MAX_REQUESTS: '1000', WAKEIO_ZAP_RATE_LIMIT: '50',
      WAKEIO_ZAP_TIMEOUT_MS: '120000', WAKEIO_ALLOW_PRIVATE: 'true', WAKEIO_OUT: 'reports', WAKEIO_FAIL_ON: 'high' }, top);
    assert.equal(result.code, 1, result.err + result.out);
    const values = Object.fromEntries((await readFile(join(top, 'outputs'), 'utf8')).trim().split('\n').map(line => { const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)]; }));
    assert.equal(values['exit-code'], '1'); assert.equal(values['scan-status'], 'findings'); assert.equal(values['delivery-status'], 'delivered'); assert.equal(values['incomplete-count'], '0');
    const reportBytes = await readFile(join(top, 'reports/report.json')), report = JSON.parse(reportBytes.toString());
    assert.equal(report.checks.find((c: any) => c.id === 'url.zap').metrics.requestCount, target.seen.length);
    assert.equal(JSON.parse(await readFile(join(top, 'reports/agent-report.json'), 'utf8')).reportArtifact.digest, sha(reportBytes));
    for (const name of ['report.json', 'report.sarif', 'report.md', 'agent-report.json']) assert.equal((await readFile(join(top, 'reports', name), 'utf8')).includes(target.authorization), false);
    context.diagnostic(JSON.stringify({ requests: target.seen.length, actionGate: result.code, fourReports: true }));
  } finally { await target.close(); await rm(top, { recursive: true, force: true }); }
});
