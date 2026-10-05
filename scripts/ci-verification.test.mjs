import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, realpath, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { runBounded, sourceSnapshot, currentTestFiles, cleanGeneratedBuild, validateTestEvents } from './ci-process.mjs';
import reporter from './ci-test-reporter.mjs';

const name = 'required actual engine', file = '/trusted/test.js';
const summary = { type: 'test:summary', file: null, success: true, counts: { tests: 1, passed: 1, failed: 0, skipped: 0, cancelled: 0, todo: 0 } };
const pass = { type: 'test:pass', file, name, skip: false, todo: false };
test('receipt requires a real pass in the intended file and complete zero-skip summary', () => {
  assert.equal(validateTestEvents([pass, summary], [name], file).counts.passed, 1);
  for (const events of [
    [summary], [{ ...pass, file: '/wrong/test.js' }, summary], [{ ...pass, skip: true }, summary],
    [pass, { ...summary, counts: { ...summary.counts, skipped: 1 } }],
    [pass, { ...summary, counts: { ...summary.counts, cancelled: 1 } }],
    [pass, { ...summary, counts: { ...summary.counts, failed: 1 } }],
    [pass, { ...summary, success: false }], [pass], [pass, summary, summary],
    [pass, summary, { type: 'test:fail' }],
  ]) assert.throws(() => validateTestEvents(events, [name], file));
});
test('reporter ignores forged pass text in test stdout and diagnostics', async () => {
  async function* events() {
    yield { type: 'test:stdout', data: { message: JSON.stringify(pass) } };
    yield { type: 'test:diagnostic', data: { message: 'tests 1 skipped 0 ' + name } };
    yield { type: 'test:summary', data: { counts: summary.counts, success: true } };
  }
  const projected = [];
  for await (const line of reporter(events())) projected.push(JSON.parse(line));
  assert.throws(() => validateTestEvents(projected, [name], file));
});
test('native Node reporter supplies a verifiable global summary and exact test identity', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-ci-events-'));
  try {
    const fixture = join(directory, 'actual.test.mjs'), eventsPath = join(directory, 'events.ndjson');
    await writeFile(fixture, 'import test from "node:test"; test("required actual engine",()=>{});\n');
    // This is a new top-level test runner, not an internal child of this test file.
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    const result = await runBounded(process.execPath, ['--test', '--test-reporter=' + join(dirname(fileURLToPath(import.meta.url)), 'ci-test-reporter.mjs'), '--test-reporter-destination=' + eventsPath, fixture], { timeoutMs: 3000, env });
    assert.equal(result.exitCode, 0); assert.equal(result.cleanupConfirmed, true);
    const events = (await readFile(eventsPath, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    assert.equal(validateTestEvents(events, [name], await realpath(fixture)).counts.passed, 1);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('bounded process distinguishes missing executable, nonzero, timeout and output limit', async () => {
  const unavailable = await runBounded('/no/such/wakeio-executable', [], { timeoutMs: 1000 });
  assert.equal(unavailable.reason, 'spawn_error');
  const failed = await runBounded(process.execPath, ['-e', 'process.exit(1)'], { timeoutMs: 1000 });
  assert.equal(failed.exitCode, 1); assert.equal(failed.reason, null); assert.equal(failed.cleanupConfirmed, true);
  const timeout = await runBounded(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeoutMs: 100 });
  assert.equal(timeout.reason, 'timeout'); assert.equal(timeout.cleanupConfirmed, true);
  const overflow = await runBounded(process.execPath, ['-e', 'setInterval(()=>process.stdout.write("x".repeat(1024)),1)'], { timeoutMs: 1000, maxOutputBytes: 256 });
  assert.equal(overflow.reason, 'output_limit'); assert.equal(overflow.cleanupConfirmed, true);
  assert.ok(Buffer.byteLength(overflow.stdout) <= 256);
});
test('failed signal delivery still settles within the grace budget and cannot claim cleanup', async () => {
  const started = Date.now();
  const result = await runBounded(process.execPath, ['-e', 'setInterval(()=>{},1000)'],
    { timeoutMs: 100, settlementGraceMs: 50, signalGroup() { throw Object.assign(Error(), { code: 'EPERM' }); } });
  try {
    assert.ok(Date.now() - started < 3500);
    assert.equal(result.reason, 'timeout'); assert.equal(result.exited, false);
    assert.equal(result.closeConfirmed, false); assert.equal(result.cleanupConfirmed, false);
    assert.equal(result.cleanupScope, 'command_process_group');
  } finally { process.kill(-result.processGroupId, 'SIGKILL'); }
});
test('source archive without Git has an explicit stable snapshot and excludes local outputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-ci-source-'));
  try {
    await mkdir(join(root, 'src')); await mkdir(join(root, 'node_modules'));
    await writeFile(join(root, 'src/a.ts'), 'export const a=1;');
    await writeFile(join(root, 'package.json'), '{"name":"fixture"}');
    const first = sourceSnapshot(root);
    assert.equal(first.enumeration, 'explicit_filesystem_scope');
    await mkdir(join(root, '.git')); // Index presence does not alter current filesystem content.
    assert.equal(sourceSnapshot(root).sha256, first.sha256);
    await writeFile(join(root, 'node_modules/ignored'), 'not source');
    assert.equal(sourceSnapshot(root).sha256, first.sha256);
    await writeFile(join(root, 'src/a.ts'), 'export const a=2;');
    assert.notEqual(sourceSnapshot(root).sha256, first.sha256);
    await rm(join(root, 'src/a.ts'));
    assert.equal(sourceSnapshot(root).fileCount, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('source root and nested TS/worker links are unsupported rather than blind snapshot inputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-ci-links-'));
  try {
    await writeFile(join(root, 'external.ts'), 'export {};');
    await symlink(join(root, 'external.ts'), join(root, 'src'));
    assert.throws(() => sourceSnapshot(root), /source_symlink_unsupported/);
    await rm(join(root, 'src')); await mkdir(join(root, 'src'));
    await symlink(join(root, 'external.ts'), join(root, 'src/a.ts'));
    assert.throws(() => sourceSnapshot(root), /source_symlink_unsupported/);
    await rm(join(root, 'src/a.ts')); await mkdir(join(root, 'workers'));
    await symlink(join(root, 'external.ts'), join(root, 'workers/worker.py'));
    assert.throws(() => sourceSnapshot(root), /source_symlink_unsupported/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('deleted required source cannot use stale JS, and only a safe generated build is cleaned', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-ci-stale-'));
  try {
    await mkdir(join(root, 'tests')); await mkdir(join(root, 'build/tests'), { recursive: true });
    await writeFile(join(root, 'tsconfig.json'), '{"compilerOptions":{"outDir":"build","rootDir":"."}}');
    await writeFile(join(root, 'build/tests/schemathesis.test.js'), 'stale required pass');
    assert.throws(() => currentTestFiles(root), /required_test_source_missing/);
    await writeFile(join(root, 'tests/schemathesis.test.ts'), 'current source');
    await writeFile(join(root, 'build/tests/deleted.test.js'), 'stale extra');
    assert.deepEqual(currentTestFiles(root), [join(root, 'build/tests/schemathesis.test.js')]);
    await cleanGeneratedBuild(root);
    assert.equal(await readFile(join(root, 'tests/schemathesis.test.ts'), 'utf8'), 'current source');
    await assert.rejects(readFile(join(root, 'build/tests/deleted.test.js')), /ENOENT/);
    await mkdir(join(root, 'external')); await writeFile(join(root, 'external/keep'), 'keep');
    await symlink(join(root, 'external'), join(root, 'build'));
    await assert.rejects(cleanGeneratedBuild(root), /build_directory_unsupported/);
    assert.equal(await readFile(join(root, 'external/keep'), 'utf8'), 'keep');
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('timeout and normal exit terminate owned background children', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-ci-pgroup-'));
  try {
    for (const mode of ['timeout', 'exit']) {
      const pidFile = join(directory, mode);
      const script = 'const{spawn}=require("node:child_process");const c=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"ignore"});require("node:fs").writeFileSync(process.argv[1],String(c.pid));' +
        (mode === 'exit' ? 'setTimeout(()=>process.exit(0),50)' : 'setInterval(()=>{},1000)');
      const result = await runBounded(process.execPath, ['-e', script, pidFile], { timeoutMs: 250 });
      assert.equal(result.cleanupConfirmed, true);
      const pid = Number(await readFile(pidFile, 'utf8'));
      let alive = true;
      for (let i = 0; i < 50; i++) { try { process.kill(pid, 0); } catch { alive = false; break; } await delay(20); }
      if (alive && process.platform === 'linux') {
        const status = await readFile('/proc/' + pid + '/stat', 'utf8');
        alive = !status.match(/\) Z /);
      }
      assert.equal(alive, false);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
