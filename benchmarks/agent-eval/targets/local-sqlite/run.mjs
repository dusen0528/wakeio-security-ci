import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runExecutionPlan } from '../../../../build/src/agent-dast/runner.js';
import { runAgentLoop } from '../../../../build/src/agent-dast/loop/loop.js';
import { createAgent } from '../../../../build/src/agent-dast/providers/codex.js';
import { openRunStore } from '../../../../build/src/agent-dast/store.js';

export const sha = data => createHash('sha256').update(data).digest('hex');
export const save = (path, value) => writeFile(path, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
export async function prepare(fixture, directory, paths) {
  await mkdir(directory, { mode: 0o700 });
  const inputs = [], tasks = [];
  for (const [index, path] of paths.entries()) {
    const id = `endpoint_${index}`, filename = join(directory, id + '.json');
    const policy = { version: 1, kind: 'sql-boolean-differential', baseUrl: fixture.origin + '/', url: fixture.origin + path + '?id=1',
      parameter: 'id', profile: 'numeric', oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
    await save(filename, policy);
    inputs.push({ id, path: filename, sha256: sha(await readFile(filename)) });
    tasks.push({ id: `t-endpoint-${index}`, engine: 'native-dast', policy: id, maxRequests: 8 });
  }
  return { coverageCells: paths.map((path, i) => ({ surface: `GET ${path} query:id anonymous`, checkId: `c-endpoint-${i}` })), plan: { version: 1, kind: 'wakeio.execution-plan', origin: fixture.origin, tasks }, inputs: { version: 1, inputs } };
}
export async function runArm(name, fixture, prepared, outDir, cap = 64) {
  fixture.reset();
  const start = performance.now();
  const execution = { inputs: prepared.inputs, consent: true, allowedOrigin: fixture.origin, allowPrivate: true, ratePerSecond: 10, concurrency: 1, timeoutMs: 30_000, failOn: 'high' };
  if (name === 'A') {
    const run = await runExecutionPlan({ ...execution, plan: prepared.plan, outDir, maxRequests: cap });
    return { name, durationMs: Math.round(performance.now() - start), status: run.status, exitCode: run.exitCode, actualRequests: fixture.requests.length,
      rounds: [{ round: 1, action: 'initial', runId: run.runId, requestCount: run.requests.requestCount, outDir, ledgerVerified: true }] };
  }
  const recon = await openRunStore(':memory:');
  recon.createRun({ runId: 'r-recon', targetOrigin: fixture.origin, scopeHash: sha('empty-recon-v1'), provider: 'fixed', startedAt: new Date().toISOString() });
  try {
    const agent = await createAgent({ template: prepared.plan, recordDir: outDir + '-provider', live: true, authMode: 'cli-login' });
    const run = await runAgentLoop({ agent, reconStore: recon, reconRunId: 'r-recon', origin: fixture.origin, outDir, sharedRequestCap: cap,
      taskCatalog: prepared.plan.tasks.map((task, i) => ({ task, checkId: `c-endpoint-${i}` })),
      coverageCells: prepared.coverageCells, execution });
    const gates = run.status === 'completed' ? await Promise.all(run.rounds.map(async round => JSON.parse(await readFile(join(round.outDir, 'run-report.json'), 'utf8')).exitCode)) : [];
    return { ...run, name, durationMs: Math.round(performance.now() - start), actualRequests: fixture.requests.length,
      exitCode: run.status === 'completed' ? Math.max(0, ...gates) : 2 };
  } finally { recon.close(); }
}

export async function recordArm(name, fixture, prepared, outDir, cap = 64) {
  const start = performance.now();
  let result;
  try { result = await runArm(name, fixture, prepared, outDir, cap); }
  catch {
    result = { name, status: 'error', exitCode: 2, reason: 'arm_execution_failed',
      durationMs: Math.round(performance.now() - start), actualRequests: fixture.requests.length,
      requestCount: null, rounds: [] };
  }
  await save(outDir + '.json', result);
  return result;
}
