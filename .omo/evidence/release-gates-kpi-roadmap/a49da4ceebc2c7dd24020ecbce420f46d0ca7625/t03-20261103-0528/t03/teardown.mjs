import { readdir, readFile, rm, rmdir, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createServer } from 'node:net';
import { once } from 'node:events';
const { writeArtifact } = await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/artifacts.mjs')).href);
const { sourceSnapshot } = await import(pathToFileURL(resolve('scripts/ci-process.mjs')).href);
const out = resolve('.omo/evidence/release-gates-kpi-roadmap/a49da4ceebc2c7dd24020ecbce420f46d0ca7625/t03-20261103-0528/t03');
const ownedTmp = resolve('.omo/tmp/t03-20261103-0528');
if (process.env.RUN_TMP !== ownedTmp) throw new TypeError('scratch_ownership_mismatch');
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
const pidChecks = [...pids].sort((a, b) => a - b).map(pid => {
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
    const ready = once(probe, 'listening', { signal: AbortSignal.timeout(2000) });
    probe.listen(port, '127.0.0.1'); await ready;
    const closed = once(probe, 'close'); probe.close(); await closed;
    portChecks.push({ port, rebindConfirmed: true });
  } catch (error) {
    probe.close();
    if (!(error instanceof Error)) throw error;
    portChecks.push({ port, rebindConfirmed: false, reason: error.name });
  }
}
const removals = [];
for (const path of [resolve('node_modules'), resolve('build'), ownedTmp]) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new TypeError('owned_directory_type_changed');
  await rm(path, { recursive: true, force: false });
  removals.push({ path, originallyAbsent: true, recursiveRemovalCompleted: true });
}
await rmdir(resolve('.omo/tmp'));
const confirmed = pidChecks.every(check => check.absent) && portChecks.every(check => check.rebindConfirmed);
await writeArtifact(out, 'teardown.json', { confirmed, pidChecks, portChecks, removals,
  cacheScope: { TMPDIR: ownedTmp, NODE_COMPILE_CACHE: join(ownedTmp, 'node-cache'),
    BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(ownedTmp, 'bun-cache'), npm: join(ownedTmp, 'npm-cache') },
  sourceAfterTeardown: sourceSnapshot(process.cwd()),
  retained: ['worktree', 'scripts/qa', 'tests/roadmap-qa.test.ts', out],
  sharedCachesTouched: false, dockerResourcesCreated: 0 });
console.log(JSON.stringify({ confirmed, checkedPids: pidChecks.length, checkedPorts: portChecks.length, removed: removals.length }));
process.exitCode = confirmed ? 0 : 1;
