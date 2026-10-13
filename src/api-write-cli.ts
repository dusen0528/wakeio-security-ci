import { mkdir, lstat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { runOwnedApiWriteStatePilot, deliverOwnedApiWriteStatePilot, type ApiWriteStateCandidate } from './api-write-state.js';
import { writeArtifacts } from './report.js';

const HELP = 'Usage: wakeio-security-ci api-write-state --candidate fixed|ineffective|all-deny|normal-regression|status-only|wrong-object --active-consent --out NEW_DIR [--timeout-ms 1..30000]\nOwned synthetic PATCH resources only. No external target, arbitrary handler/observer, repeat or automatic write retry.\n';
export async function apiWriteStateMain(argv: readonly string[]): Promise<number> {
  if (argv.length === 2 && ['--help', '-h'].includes(argv[1])) { process.stdout.write(HELP); return 0; }
  const values = new Map<string, string>(); let consent = false;
  try {
    if (argv[0] !== 'api-write-state') throw new Error('args');
    for (let index = 1; index < argv.length; index++) {
      const flag = argv[index];
      if (flag === '--active-consent' && !consent) { consent = true; continue; }
      if (!['--candidate', '--out', '--timeout-ms'].includes(flag) || values.has(flag) || !argv[index + 1] || argv[index + 1].startsWith('--')) throw new Error('args');
      values.set(flag, argv[++index]);
    }
    if (!consent || !values.get('--out')?.trim() || !['fixed', 'ineffective', 'all-deny', 'normal-regression', 'status-only', 'wrong-object'].includes(values.get('--candidate') ?? '')) throw new Error('args');
    if (values.has('--timeout-ms') && (!/^\d+$/.test(values.get('--timeout-ms')!) || Number(values.get('--timeout-ms')) < 1 || Number(values.get('--timeout-ms')) > 30000)) throw new Error('args');
  } catch { process.stderr.write(HELP); return 2; }
  const controller = new AbortController(), cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const out = resolve(values.get('--out')!);
    try { await lstat(out); throw new Error('existing_output'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (controller.signal.aborted) throw new Error('cancelled');
    await writeArtifacts(dirname(out), []); await mkdir(out, { mode: 0o700 });
    process.stderr.write('Wakeio: owned synthetic PATCH state pilot; writes only fixed temporary resources, never an external service.\n');
    const result = await runOwnedApiWriteStatePilot({ candidate: values.get('--candidate') as ApiWriteStateCandidate, activeConsent: true,
      signal: controller.signal, ...(values.has('--timeout-ms') ? { timeoutMs: Number(values.get('--timeout-ms')) } : {}) });
    const delivery = await deliverOwnedApiWriteStatePilot(result, { outDir: out });
    const finalExitCode = controller.signal.aborted ? 2 : delivery.finalExitCode;
    process.stdout.write(JSON.stringify({ version: 1, scope: result.scope, runId: result.runId, deliveryAttemptId: delivery.deliveryAttemptId,
      outputRelativePath: delivery.outputRelativePath, delivery: delivery.status, verificationExitCode: result.verificationGate.exitCode,
      finalExitCode, apiReexecuted: false, commandStatus: controller.signal.aborted ? 'cancelled' : 'completed' }) + '\n');
    return finalExitCode;
  } catch { process.stderr.write('Owned synthetic PATCH pilot or artifact delivery could not be completed. No external target was selected.\n'); return 2; }
  finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}
