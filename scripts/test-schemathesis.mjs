// Required real-engine suite: bounded stages, structured Node reporter, zero skips.
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { mkdir, mkdtemp, readFile, chmod, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
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
  await stage('tests', process.execPath, ['--test', '--test-reporter=spec', '--test-reporter-destination=stdout',
    '--test-reporter=' + join(root, 'scripts/ci-test-reporter.mjs'), '--test-reporter-destination=' + eventsPath, ...files],
    180000, { ...process.env, WAKEIO_SCHEMATHESIS_PYTHON: python });
  const bytes = await readFile(eventsPath);
  await chmod(eventsPath, 0o600);
  if (bytes.length > 8 * 1024 * 1024) throw Error('test_receipt_limit');
  const events = bytes.toString().trim().split('\n').map(line => JSON.parse(line));
  receipt.tests = validateTestEvents(events, required, join(root, 'build/tests/schemathesis.test.js'));
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
