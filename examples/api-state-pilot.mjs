// Explicit owned synthetic SDK exercise; no target URL, source upload or arbitrary code.
import { runOwnedApiStatePilot, deliverOwnedApiStatePilot } from '../build/src/index.js';
const args = process.argv.slice(2);
if (args.length !== 2 || !['fixed', 'ineffective', 'all-deny', 'normal-regression'].includes(args[0])) {
  process.stderr.write('Usage: node examples/api-state-pilot.mjs fixed|ineffective|all-deny|normal-regression OUT_DIR\n');
  process.exitCode = 2;
} else {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
  try {
    const result = await runOwnedApiStatePilot({ candidate: args[0], signal: controller.signal });
    const delivered = await deliverOwnedApiStatePilot(result, { outDir: args[1] });
    const finalExitCode = controller.signal.aborted ? 2 : delivered.finalExitCode;
    process.stdout.write(JSON.stringify({ scope: result.scope, before: result.before?.scanGate.exitCode ?? null,
      after: result.after?.scanGate.exitCode ?? null, verification: result.verificationGate.exitCode,
      delivery: delivered.status, outputRelativePath: delivered.outputRelativePath, runId: delivered.runId,
      deliveryAttemptId: delivered.deliveryAttemptId, commandStatus: controller.signal.aborted ? 'cancelled' : 'completed', finalExitCode, apiRequests: result.execution.apiRequests }) + '\n');
    process.exitCode = finalExitCode;
  } catch {
    process.stderr.write('Owned synthetic pilot or delivery could not be completed.\n'); process.exitCode = 2;
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}
