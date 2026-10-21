// Required real-engine suite: bounded stages, structured Node reporter, zero skips.
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { mkdir, mkdtemp, readFile, chmod, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { NUCLEI_SETUP_FILE, requiredNucleiEnvironment } from './bootstrap-nuclei.mjs';
import { runBounded, sourceSnapshot, currentTestFiles, cleanGeneratedBuild, validateTestEvents } from './ci-process.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const python = resolve(process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(root, '.venv-schemathesis/bin/python'));
const required = ['real Schemathesis fixture: broken/fixed, limits, redaction, reproducibility and storage',
  'real worker deadline and running cancellation interrupt slow fixture'];
const receiptRoot = resolve(process.env.WAKEIO_TEST_RECEIPT_DIR ?? join(root, 'artifacts/ci'));
await mkdir(receiptRoot, { recursive: true, mode: 0o700 });
const directory = await mkdtemp(join(receiptRoot, 'required-engine-'));
const receipt = { version: 1, status: 'error', node: process.version, python, startedAt: new Date().toISOString(), stages: [] };
async function stage(name, command, args, timeoutMs, env) {
  const result = await runBounded(command, args, { cwd: root, env, timeoutMs });
  await writeFile(join(directory, name + '.log'), result.stdout + result.stderr, { mode: 0o600, flag: 'wx' });
  const { stdout, stderr, ...metadata } = result;
  receipt.stages.push({ name, ...metadata });
  if (stdout) process.stdout.write(stdout); if (stderr) process.stderr.write(stderr);
  if (result.reason || !result.cleanupConfirmed || result.exitCode !== 0) {
    const error = Error(name + ':' + (result.reason ?? (result.cleanupConfirmed ? 'command_failed' : 'cleanup_unknown')));
    error.exitCode = !result.reason && result.cleanupConfirmed && result.exitCode === 1 && name === 'tests' ? 1 : 2;
    throw error;
  }
  return result;
}
try {
  if (process.platform === 'win32') throw Error('POSIX_required');
  const setup = process.env.WAKEIO_NUCLEI && process.env.WAKEIO_NUCLEI_TEMPLATES ? undefined
    : JSON.parse(await readFile(NUCLEI_SETUP_FILE, 'utf8').catch(error => { if (error.code === 'ENOENT') return 'null'; throw error; }));
  const engineEnvironment = requiredNucleiEnvironment(process.env, setup);
  for (const name of ['WAKEIO_SEMGREP_TEST_PATH', 'WAKEIO_GOVULNCHECK_EXECUTABLE', 'WAKEIO_GO_EXECUTABLE',
    'WAKEIO_GO_MODULE_CACHE', 'WAKEIO_TRIVY_EXECUTABLE', 'WAKEIO_TRIVY_CACHE', 'WAKEIO_TRIVY_IMAGE_ARCHIVE', 'WAKEIO_ZAP_PATH']) {
    if (!engineEnvironment[name] || /[\r\n\0]/.test(engineEnvironment[name])) throw Error('security_toolchain_setup_required:' + name);
  }
  receipt.nucleiRuntime = { executable: engineEnvironment.WAKEIO_NUCLEI, templates: engineEnvironment.WAKEIO_NUCLEI_TEMPLATES };
  receipt.sourceBefore = sourceSnapshot(root);
  const files = currentTestFiles(root);
  const lock = await readFile(join(root, 'workers/schemathesis/requirements.lock.txt'));
  receipt.versionPinLockSha256 = createHash('sha256').update(lock).digest('hex');
  receipt.distributionHashesVerified = false;
  const probe = await stage('preflight', python, ['-I', '-c',
    "import importlib.metadata,json,sys; from pathlib import Path; rows=Path(sys.argv[1]).read_text().splitlines(); expected={r.split('==')[0]:r.split('==')[1] for r in rows if r.strip() and not r.startswith('#')}; actual={k:importlib.metadata.version(k) for k in expected}; assert actual==expected; assert sys.version_info[:2]==(3,12); print(json.dumps({'python':sys.version.split()[0], 'packages':actual}))",
    join(root, 'workers/schemathesis/requirements.lock.txt')], 10000);
  receipt.runtime = JSON.parse(probe.stdout);
  await cleanGeneratedBuild(root);
  receipt.generatedBuildCleaned = true;
  await stage('build', 'npm', ['run', 'build'], 120000);
  if (!files.length) throw Error('no_test_files');
  const eventsPath = join(directory, 'tests.ndjson');
  // Three Linux runs exhausted 360s after 1,578/1,579 passes, in the final ZAP controls.
  // Allow eight minutes for the aggregate suite; per-test/engine/request limits,
  // cancellation, cleanup and the zero-skip contract are unchanged.
  await stage('tests', process.execPath, ['--test', '--test-concurrency=2', '--test-reporter=spec', '--test-reporter-destination=stdout',
    '--test-reporter=' + join(root, 'scripts/ci-test-reporter.mjs'), '--test-reporter-destination=' + eventsPath, ...files],
    480000, { ...engineEnvironment, WAKEIO_SCHEMATHESIS_PYTHON: python,
      WAKEIO_REQUIRE_SCHEMATHESIS: '1', WAKEIO_REQUIRE_RUNNER_ENGINES: '1' });
  const bytes = await readFile(eventsPath);
  await chmod(eventsPath, 0o600);
  if (bytes.length > 8 * 1024 * 1024) throw Error('test_receipt_limit');
  const events = bytes.toString().trim().split('\n').map(line => JSON.parse(line));
  receipt.tests = validateTestEvents(events, required, join(root, 'build/tests/schemathesis.test.js'));
  receipt.dast = validateTestEvents(events,
    ['owned DAST corpus gates positive, safe and error controls with lifecycle and exact request counts'],
    join(root, 'build/tests/dast-corpus.test.js'));
  receipt.live = validateTestEvents(events,
    ['schemathesis live: risk/normal pair through the egress gate', 'schemathesis live: a target that fails mid-run is partial, never clean'],
    join(root, 'build/tests/schemathesis-live.test.js'));
  receipt.schemathesisAuth = validateTestEvents(events, [
    'auth independent: documented401 legacy clean never reaches protected handler; real generated id2 V/F discriminates1/0',
    'auth independent: initial denial/ignored credential/expiry/normal failure prohibit generation; trailing drift retains observed failure2',
    'auth independent: strict policy/credential boundaries refuse traffic; snapshots remain stable and SetCookie cannot alter auth',
    'auth independent: exact shared budget, no dropped-reply retry, streaming abort/descendants and verified owned TLS',
    'auth independent: malformed/missing control metadata never upgrades report to clean and secret extras never escape',
    'auth independent: public CLI and real DAST Action retain0/1/2 gates, four reports, typed advice and digest-bound outputs',
  ], join(root, 'build/tests/schemathesis-auth-acceptance.test.js'));
  receipt.schemathesisAuthMultiOperation = validateTestEvents(events,
    ['schemathesis auth: real two-operation generated risk/normal pair preserves controls and denominator'],
    join(root, 'build/tests/schemathesis-auth.test.js'));
  receipt.nuclei = validateTestEvents(events,
    ['real nuclei: risk/normal pair, wire coverage and egress refusal counts',
      'real nuclei: request budget and a failing target are partial even though nuclei exits 0'],
    join(root, 'build/tests/nuclei.test.js'));
  receipt.semgrep = validateTestEvents(events,
    ['Semgrep CE real owned Go fixtures detect six risky patterns and reject fixed counterparts'],
    join(root, 'build/tests/semgrep.test.js'));
  receipt.govulncheck = validateTestEvents(events,
    ['real govulncheck distinguishes an affected Go call from its fixed dependency and a clean module'],
    join(root, 'build/tests/govulncheck.test.js'));
  receipt.trivyVulnerabilities = validateTestEvents(events,
    ['real Trivy detects a known package CVE, accepts a clean inventory, and reads an image without running it'],
    join(root, 'build/tests/trivy-vuln.test.js'));
  receipt.zap = validateTestEvents(events,
    ['real ZAP detects owned XSS and SQLite SQLi, rejects fixed controls, and accounts every fixture request',
      'real ZAP rejects unauthenticated and absent seed responses as incomplete',
      'real ZAP runs simultaneous owned scans with independent listeners and request accounting',
      'real ZAP request cap stops the engine and leaves a partial result'],
    join(root, 'build/tests/zap.test.js'));
  receipt.agentDastRunner = validateTestEvents(events, [
    'runner engines independent: real Schemathesis vulnerable/fixed contract pair and irrecoverable transport errors propagate 1/0/2',
    'runner engines independent: real signed one-template Nuclei and native SQL tasks overlap and share observed run counts',
    'runner engines independent: real Schemathesis and native execution consume one global cap rather than per-engine caps',
    'runner engines independent: fabricated Nuclei exit0/progress100 with no wire traffic cannot complete the public run',
  ], join(root, 'build/tests/agent-dast-runner-engines.test.js'));
  receipt.zapPolicy = validateTestEvents(events, [
    'ZAP owner policy rejects normalization, duplicate seeds, unbounded bodies and unsafe auth transport',
    'ZAP relay validates JSON before forwarding, strips worker credentials and isolates principal controls',
    'real ZAP policy detects authenticated query and JSON SQLi/XSS and rejects fixed controls',
  ], join(root, 'build/tests/zap-policy.test.js'));
  receipt.zapIntegration = validateTestEvents(events, [
    'ZAP principal controls, shared cap and cancellation prevent a false completed result',
    'ZAP and native DAST share one request budget and paced admission across concurrent tasks',
    'ZAP CLI verifies owned HTTPS CA and hostname despite disabled global TLS, and refuses invalid input with zero traffic',
    'real ZAP run-plan Action publishes matching DB, evidence, report and shared request ledger',
    'ZAP v2 public CLI and DAST Action retain JSON/Bearer and form/cookie policy scope without credentials',
    'ZAP DAST Action refuses missing consent, credentials, policy and budgets before engine launch or target traffic',
    'real ZAP DAST Action runs its bundled CLI and delivers four reports with a digest-bound finding gate',
  ], join(root, 'build/tests/zap-integration.test.js'));
  receipt.zapOpenApiSession = validateTestEvents(events, [
    'ZAP OpenAPI compiler binds selected nested/array inputs, rejects remote refs and preserves other body fields',
    'real ZAP native OpenAPI and JSON authentication handle expiry/refresh and bind nested findings',
    'real ZAP native form/cookie session reauthenticates and leaves the fixed API without findings',
    'ZAP v2 login refusals and all global admission attempts include session controls and cancellation',
    'ZAP session snapshots never expose credentials and reject malformed, cross-scope and exhausted renewal',
    'ZAP native session capability isolates the random virtual origin, controller and pending principal verification',
    'real ZAP refuses renewed principal drift before sending more authenticated probes',
    'ZAP v2 native projection preserves unauthenticated and static Authorization policies',
    'ZAP OpenAPI bounds reject duplicate operations, oversized arrays, mixed bodies and unknown fields before traffic',
  ], join(root, 'build/tests/zap-openapi-session.test.js'));
  receipt.zapOpenApiMemory = validateTestEvents(events, [
    'ZAP OpenAPI memory: shared references reject without exhausting a 64 MiB heap',
    'ZAP OpenAPI memory: encoded byte and field boundaries keep independent valid operations',
    'ZAP OpenAPI memory: public plan scan and run-plan refuse amplification with zero target traffic',
  ], join(root, 'build/tests/zap-openapi-memory.test.js'));
  receipt.agentDastRunnerTemplate = validateTestEvents(events, [
    'runner template independent: actual generated path-parameter vulnerable/fixed findings retain declared template context and completed1/0 gates',
  ], join(root, 'build/tests/agent-dast-runner-template.test.js'));
  receipt.agentDastRunnerAuth = validateTestEvents(events, [
    'runner auth independent: real authenticated Schemathesis public plan retains identity normal generated controls and global1/0/2 gates without secrets',
  ], join(root, 'build/tests/agent-dast-runner-auth.test.js'));
  receipt.runPlanAction = validateTestEvents(events, [
    'consent, pull_request_target and fork refusals happen before reading inputs or starting the CLI',
    'exit-zero without a current receipt, tampered hashes, child/JSON disagreement and stale outputs all fail closed',
    'Action cancellation terminates a trusted CLI, its detached ignoring engine and that engine descendant',
    'an existing unowned Action receipt is preserved on collision after a real completed native run',
    'the bounded Action protocol accepts a published partial ledger with 20000 attempt records',
  ], join(root, 'tests/run-plan-action.test.mjs'));
  receipt.dastAction = validateTestEvents(events,
    ['DAST Action runs Schemathesis from the bundled layout for a same-repository pull request',
      'DAST Action runs pinned Nuclei through the bundled layout',
      'dast Action cancellation forwards SIGTERM and retains fresh partial evidence even when the child exits zero',
      'source Action cancellation forwards SIGINT and retains fresh partial evidence even when the child exits zero',
      'DAST Action cancellation bounds ignored/repeated signals and kills the owned child process group',
      'dast Action cancellation during tool setup prevents scan launch and removes its temporary tools',
      'dast Action cancellation during native policy preflight prevents scan launch',
      'dast-preflight Action cancellation during native policy preflight prevents scan launch',
      'Action cancellation while a successful receipt is being written corrects status and outputs before exit'],
    join(root, 'build/tests/dast-action.test.js'));
  receipt.dastTeardown = validateTestEvents(events,
    ['egress gate abort closes the target while streaming',
      'egress gate close closes the target while streaming',
      'egress gate client disconnect closes the target while streaming',
      'egress gate already-aborted startup never forwards a target request',
      'egress gate incomplete upstream body remains one transport failure',
      'egress gate CONNECT abort awaits both tunnel sockets'],
    join(root, 'build/tests/dast-egress.test.js'));
  receipt.testEventsSha256 = createHash('sha256').update(bytes).digest('hex');
  receipt.testFiles = files.map(file => ({ path: file, sha256: createHash('sha256').update(readFileSync(file)).digest('hex') }));
  receipt.sourceAfter = sourceSnapshot(root);
  if (receipt.sourceBefore.sha256 !== receipt.sourceAfter.sha256) throw Error('source_changed_during_suite');
  receipt.status = 'passed'; process.exitCode = 0;
} catch (error) {
  receipt.reason = error.message; process.exitCode = error.exitCode ?? 2;
  process.stderr.write('Required-engine verification failed: ' + receipt.reason + '\n');
} finally {
  receipt.exitCode = process.exitCode; receipt.finishedAt = new Date().toISOString();
  await writeFile(join(directory, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  process.stdout.write('Verification receipt: ' + join(directory, 'receipt.json') + '\n');
}
