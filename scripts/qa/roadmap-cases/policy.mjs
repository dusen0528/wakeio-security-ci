import { readFile, writeFile, rm } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { captureProcess } from './process.mjs';
import { writeArtifact } from './artifacts.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

export async function runCase({ out, mutate }) {
  if (mutate && !['missing-gate', 'unavailable-pass'].includes(mutate)) {
    const cleanup = { confirmed: true, children: [], mutationInputRemoved: true };
    await writeArtifact(out, 'cleanup.json', cleanup);
    return { status: 'unavailable', artifacts: ['cleanup.json'], cleanup };
  }
  const policy = JSON.parse(await readFile(join(ROOT, 'benchmarks/kpi-policy.json'), 'utf8'));
  const temporary = join(out, 'policy-input.json');
  const args = [join(ROOT, 'scripts/kpi-policy.mjs'), 'validate', '--policy', join(ROOT, 'benchmarks/kpi-policy.json'),
    '--input', join(ROOT, 'benchmarks/kpi-baseline.json'), '--out', join(out, 'cli')];
  let child = null, temporaryCreated = false, status = 'unavailable', failure = null;
  const artifacts = [];
  try {
    if (mutate === 'missing-gate') {
      policy.gates = policy.gates.filter(g => g.id !== 'G5');
      await writeFile(temporary, JSON.stringify(policy), { flag: 'wx', mode: 0o600 });
      temporaryCreated = true;
      args[3] = temporary;
    }
    if (mutate === 'unavailable-pass') {
      const report = JSON.parse(await readFile(join(ROOT, 'benchmarks/kpi-baseline.json'), 'utf8'));
      const missing = report.metrics.find(row => row.status === 'unavailable');
      missing.value = 0;
      report.claimedStatus = 'pass';
      await writeFile(temporary, JSON.stringify(report), { flag: 'wx', mode: 0o600 });
      temporaryCreated = true;
      args[5] = temporary;
    }
    child = await captureProcess(process.execPath, args, { timeoutMs: 30000 });
    artifacts.push(await writeArtifact(out, 'process.json', child));
    if (!child.reason && !child.truncated && !child.signal && child.cleanup.confirmed) {
      if (mutate) {
        const diagnostic = child.stderr ? JSON.parse(child.stderr) : null;
        const rejected = child.exitCode === 2 && diagnostic?.status === 'unavailable'
          && (mutate !== 'missing-gate' || diagnostic.reason === 'missing_gate:G5');
        status = rejected ? 'unavailable' : 'fail';
        artifacts.push(await writeArtifact(out, 'mutation.json', { mutation: mutate, productionRejected: rejected,
          exitCode: child.exitCode, diagnostic }));
      } else if (child.exitCode === 0) {
        const result = JSON.parse(await readFile(join(out, 'cli/policy-result.json'), 'utf8'));
        artifacts.push(await writeArtifact(out, 'policy.json', result));
        status = isDeepStrictEqual(result, JSON.parse(child.stdout)) && result.status === 'pass'
          && result.readerSchema === 'wakeio.kpi/v1' && result.releaseQualified === false
          && result.gates === policy.gates.length && result.metrics === policy.metrics.length ? 'pass' : 'fail';
      } else status = 'fail';
    }
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    failure = error.name;
  } finally {
    if (temporaryCreated) await rm(temporary);
  }
  const cleanup = { confirmed: child?.cleanup.confirmed ?? true, children: child ? [child.cleanup] : [],
    mutationInputRemoved: true };
  artifacts.push(await writeArtifact(out, 'cleanup.json', cleanup));
  if (failure) artifacts.push(await writeArtifact(out, 'failure.json', { reason: failure }));
  return { status, artifacts, cleanup };
}
