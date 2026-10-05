// Bounded supervisor for trusted build/test/bootstrap commands on POSIX.
// Process-group cleanup is not a hostile-code sandbox or crash-recovery daemon.
import { spawn, execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { readFileSync, lstatSync, readdirSync, existsSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';

function groupState(pid) {
  try { process.kill(-pid, 0); }
  catch (error) { if (error.code === 'ESRCH') return 'terminated'; if (error.code !== 'EPERM') return 'unknown'; }
  try {
    const rows = execFileSync('ps', ['-eo', 'pgid=,stat='], { encoding: 'utf8', timeout: 250 });
    const members = rows.trim().split('\n').map(row => row.trim().split(/\s+/)).filter(row => Number(row[0]) === pid);
    if (!members.length) return 'terminated';
    if (members.every(row => row[1].startsWith('Z'))) return 'terminated_zombies';
    return 'running';
  } catch { return 'unknown'; }
}

export async function runBounded(command, args, { cwd, env = process.env, timeoutMs, maxOutputBytes = 8 * 1024 * 1024,
  signalGroup = (pid, signal) => process.kill(pid, signal), settlementGraceMs = 2000 } = {}) {
  if (process.platform === 'win32' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw Error('invalid_POSIX_execution_budget');
  const started = Date.now();
  let reason = null, exited = false, exitCode = null, signal = null, closeConfirmed = false, outputBytes = 0;
  const stdout = [], stderr = [];
  let settle, stopTimer, closeTimer, settled = false;
  const child = spawn(command, args, { cwd, env, shell: false, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  function killGroup() {
    if (!child.pid) return;
    try { signalGroup(-child.pid, 'SIGKILL'); } catch { /* Final group-state confirmation decides cleanup, never this signal alone. */ }
  }
  function stop(value) {
    reason ??= value; killGroup();
    stopTimer ??= setTimeout(() => {
      child.stdout.destroy(); child.stderr.destroy(); child.unref(); settle?.();
    }, settlementGraceMs);
  }
  const cancel = () => stop('cancelled');
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  const timer = setTimeout(() => stop('timeout'), timeoutMs);
  function collect(chunk, buffers) {
    const room = Math.max(0, maxOutputBytes - outputBytes);
    if (room) buffers.push(chunk.subarray(0, room));
    outputBytes += chunk.length;
    if (outputBytes > maxOutputBytes) stop('output_limit');
  }
  child.stdout.on('data', chunk => collect(chunk, stdout));
  child.stderr.on('data', chunk => collect(chunk, stderr));
  await new Promise(resolve => {
    settle = () => { settled = true; resolve(); };
    child.once('error', () => { reason ??= 'spawn_error'; exited = true; settle(); });
    child.once('exit', (code, sig) => {
      exited = true; exitCode = code; signal = sig;
      killGroup();
      if (!settled) closeTimer = setTimeout(() => {
        reason ??= 'close_unknown'; child.stdout.destroy(); child.stderr.destroy(); child.unref(); settle();
      }, settlementGraceMs);
    });
    child.once('close', () => { closeConfirmed = true; clearTimeout(closeTimer); settle(); });
  });
  clearTimeout(timer); clearTimeout(stopTimer); clearTimeout(closeTimer);
  process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
  killGroup();
  let cleanup = child.pid ? groupState(child.pid) : 'not_started';
  const cleanupDeadline = Date.now() + 2000;
  while (cleanup === 'running' && Date.now() < cleanupDeadline) { await delay(20); cleanup = groupState(child.pid); }
  const cleanupConfirmed = ['terminated', 'terminated_zombies', 'not_started'].includes(cleanup) && (closeConfirmed || !child.pid);
  return { command, args, exitCode, signal, reason, elapsedMs: Date.now() - started,
    exited, closeConfirmed, cleanup, cleanupConfirmed, cleanupScope: 'command_process_group', processGroupId: child.pid ?? null, outputBytes,
    stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
}

export function sourceSnapshot(root) {
  const paths = [], enumeration = 'explicit_filesystem_scope';
  const excluded = new Set(['.git', 'node_modules', '__pycache__', '.hypothesis', '.venv-schemathesis']);
  function walk(path) {
    const full = join(root, path);
    let stat;
    try { stat = lstatSync(full); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (stat.isSymbolicLink()) throw Error('source_symlink_unsupported');
    if (stat.isDirectory()) {
      for (const name of readdirSync(full).sort()) if (!excluded.has(name) && !name.endsWith('.pyc')) walk(path + '/' + name);
    } else {
      if (paths.length >= 10000 || !stat.isFile() || stat.size > 32 * 1024 * 1024) throw Error('source_snapshot_limit');
      paths.push(path);
    }
  }
  for (const path of ['src', 'tests', 'scripts', 'workers', '.github', 'package.json', 'package-lock.json', 'tsconfig.json', 'action.yml']) walk(path);
  const files = [...new Set(paths)].sort().filter(path => /^(src\/|tests\/|scripts\/|workers\/|\.github\/|package(?:-lock)?\.json$|tsconfig\.json$|action\.yml$)/.test(path));
  const hash = createHash('sha256');
  let totalBytes = 0;
  for (const path of files) {
    const full = join(root, path);
    const stat = lstatSync(full);
    if (stat.isSymbolicLink()) throw Error('source_symlink_unsupported');
    const bytes = readFileSync(full);
    totalBytes += bytes.length;
    if (totalBytes > 128 * 1024 * 1024) throw Error('source_snapshot_limit');
    hash.update(path + '\0').update(createHash('sha256').update(bytes).digest());
  }
  return { sha256: hash.digest('hex'), fileCount: files.length, totalBytes, enumeration, gitPresent: existsSync(join(root, '.git')),
    scope: 'src/tests/scripts/workers/workflows/package-lock/tsconfig/action; generated outputs excluded; input symlinks unsupported' };
}

export function currentTestFiles(root) {
  const requiredSource = join(root, 'tests/schemathesis.test.ts');
  if (!existsSync(requiredSource) || !lstatSync(requiredSource).isFile()) throw Error('required_test_source_missing');
  const names = readdirSync(join(root, 'tests')).filter(name => name.endsWith('.test.ts')).sort();
  if (names.some(name => !lstatSync(join(root, 'tests', name)).isFile())) throw Error('test_source_unsupported');
  return names.map(name => join(root, 'build/tests', name.replace(/\.ts$/, '.js')));
}

export async function cleanGeneratedBuild(root) {
  const config = JSON.parse(readFileSync(join(root, 'tsconfig.json'), 'utf8'));
  if (config.compilerOptions?.outDir !== 'build' || config.compilerOptions?.rootDir !== '.') throw Error('build_scope_unsupported');
  const directory = join(root, 'build');
  let stat;
  try { stat = lstatSync(directory); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw Error('build_directory_unsupported');
  await rm(directory, { recursive: true, force: false });
}

export function validateTestEvents(events, required, testFile) {
  const summaries = events.filter(event => event.type === 'test:summary' && event.file === null);
  if (summaries.length !== 1) throw Error('missing_or_duplicate_global_summary');
  const summary = summaries[0], counts = summary.counts;
  for (const key of ['tests', 'passed', 'failed', 'skipped', 'cancelled', 'todo']) {
    if (!Number.isSafeInteger(counts?.[key]) || counts[key] < 0) throw Error('invalid_test_counts');
  }
  if (summary.success !== true || counts.tests < required.length || counts.tests !== counts.passed || counts.failed || counts.skipped || counts.cancelled || counts.todo) throw Error('suite_incomplete_or_failed');
  if (events.some(event => event.type === 'test:fail')) throw Error('test_failure');
  for (const name of required) {
    const results = events.filter(event => ['test:pass', 'test:fail'].includes(event.type) && event.name === name && event.file === testFile);
    if (results.length !== 1 || results[0].type !== 'test:pass' || results[0].skip || results[0].todo) throw Error('required_test_not_passed');
  }
  return { counts, requiredPassed: required, globalSummarySuccess: true };
}
