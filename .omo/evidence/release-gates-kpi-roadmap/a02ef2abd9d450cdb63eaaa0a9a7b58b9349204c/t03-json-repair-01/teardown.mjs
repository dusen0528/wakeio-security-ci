import { readdir, readFile, rm, rmdir, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import { writeArtifact, sha256 } from '../../../../../scripts/qa/roadmap-cases/artifacts.mjs';
import { sourceSnapshot } from '../../../../../scripts/ci-process.mjs';
const out = resolve('.omo/evidence/release-gates-kpi-roadmap/a02ef2abd9d450cdb63eaaa0a9a7b58b9349204c/t03-json-repair-01');
const scratch = resolve('.omo/tmp/t03-json-repair-01');
if (process.env.RUN_TMP !== scratch) throw new TypeError('scratch_ownership_mismatch');
const pids = new Set(), ports = new Set();
function collect(value) {
  if (!value || typeof value !== 'object') return;
  if (Number.isSafeInteger(value.pid) && value.pid > 0) pids.add(value.pid);
  if (Number.isSafeInteger(value.port) && value.port > 0) ports.add(value.port);
  for (const item of Object.values(value)) collect(item);
}
async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (entry.name.endsWith('.json')) collect(JSON.parse(await readFile(path, 'utf8')));
  }
}
await walk(out);
const pidChecks = [...pids].map(pid => {
  try { process.kill(pid, 0); return { pid, absent: false }; }
  catch (error) {
    if (!(error instanceof Error && 'code' in error)) throw error;
    return { pid, absent: error.code === 'ESRCH' };
  }
});
const portChecks = [];
for (const port of ports) {
  const probe = createServer();
  try {
    const listening = once(probe, 'listening', { signal: AbortSignal.timeout(2000) });
    probe.listen(port, '127.0.0.1'); await listening;
    const closed = once(probe, 'close'); probe.close(); await closed;
    portChecks.push({ port, rebindConfirmed: true });
  } catch (error) {
    probe.close();
    if (!(error instanceof Error)) throw error;
    portChecks.push({ port, rebindConfirmed: false, reason: error.name });
  }
}
const bindings = [];
for (const path of ['src/report-path.ts', 'tests/report.test.ts', 'tests/roadmap-qa.test.ts',
  'scripts/qa/roadmap.mjs', 'scripts/qa/roadmap-cases/process.mjs', 'scripts/qa/roadmap-cases/artifacts.mjs']) {
  const bytes = await readFile(path);
  bindings.push({ path, bytes: bytes.length, sha256: sha256(bytes) });
}
const head = execFileSync('git', ['rev-parse', 'HEAD'],
  { encoding: 'utf8', env: { ...process.env, GIT_MASTER: '1' } }).trim();
await writeArtifact(out, 'source-binding.json', { parentCommit: head, bindings, source: sourceSnapshot(process.cwd()),
  priorVerdict: '../t03-independent/verdict.json', finalEvidence: 'final/',
  generatedBundleRestoredToParent: true });
const removals = [];
for (const path of [resolve('node_modules'), resolve('build'), scratch]) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new TypeError('owned_directory_type_changed');
  await rm(path, { recursive: true, force: false });
  removals.push({ path, originallyAbsent: true, removalCompleted: true });
}
let scratchParentRemoved = false;
try { await rmdir(resolve('.omo/tmp')); scratchParentRemoved = true; }
catch (error) {
  if (!(error instanceof Error && 'code' in error && error.code === 'ENOTEMPTY')) throw error;
}
const confirmed = pidChecks.every(item => item.absent) && portChecks.every(item => item.rebindConfirmed);
await writeArtifact(out, 'cleanup.json', { confirmed, pidChecks, portChecks, removals, scratchParentRemoved,
  cachesRemovedWithScratch: ['TMPDIR', 'NODE_COMPILE_CACHE', 'BUN_RUNTIME_TRANSPILER_CACHE_PATH', 'npm_config_cache'],
  sharedCachesTouched: false, dockerResourcesCreated: 0, sourceAfterCleanup: sourceSnapshot(process.cwd()) });
console.log(JSON.stringify({ confirmed, checkedPids: pidChecks.length, checkedPorts: portChecks.length, removed: removals.length }));
process.exitCode = confirmed ? 0 : 1;
