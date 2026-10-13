import { dirname, resolve } from 'node:path';
import { readJsonInput } from '../json-input.js';
import { parseExecutionInputs, parseExecutionPlan } from './plan.js';
import { runExecutionPlan, type ExecutionRunOptions } from './runner.js';

export const RUN_PLAN_USAGE = `Usage:
  wakeio-security-ci run-plan --plan FILE --inputs FILE --active-consent --allowed-origin ORIGIN --out NEW_DIR
    [--max-requests N] [--timeout-ms N] [--rate-per-second N] [--concurrency N] [--fail-on LEVEL]
    [--allow-private] [--schemathesis-python PATH] [--nuclei PATH] [--nuclei-templates DIR]

Execute 1..16 built-in native DAST, Schemathesis or Nuclei tasks from a reviewed JSON plan.
The agent supplies data only. No model, arbitrary code, installation, patch, or direct agent DB access.
Owner limits: admitted HTTP attempts 1..20000 (default 64), deadline 1..600000ms (default 120000),
rate 1..150/sec (default 10), concurrency 1..4 (default 2). Active consent and one exact allowed origin are required.
Input aliases bind raw-file SHA256. The output directory must be new; incomplete work or delivery returns 2.
`;
export interface RunPlanCliOptions {
  planFile: string; inputsFile: string; outDir: string; allowedOrigin: string; consent: true; allowPrivate: boolean;
  maxRequests?: number; timeoutMs?: number; ratePerSecond?: number; concurrency?: number;
  failOn?: ExecutionRunOptions['failOn']; schemathesisPython?: string; nucleiPath?: string; nucleiTemplates?: string;
}
export function parseRunPlanArgs(argv: readonly string[]): RunPlanCliOptions | { help: true } {
  if (argv[0] !== 'run-plan') throw new TypeError('invalid_run_plan_arguments');
  if (argv.length === 2 && ['--help', '-h'].includes(argv[1])) return { help: true };
  const values = new Map<string, string>(), flags = new Set<string>();
  const names = ['--plan', '--inputs', '--out', '--allowed-origin', '--max-requests', '--timeout-ms', '--rate-per-second', '--concurrency', '--fail-on', '--schemathesis-python', '--nuclei', '--nuclei-templates'];
  for (let index = 1; index < argv.length; index++) {
    const [name, ...parts] = argv[index].split('=');
    if (name === '--active-consent' || name === '--allow-private') {
      if (parts.length || flags.has(name)) throw new TypeError('invalid_run_plan_arguments'); flags.add(name); continue;
    }
    if (!names.includes(name) || values.has(name)) throw new TypeError('invalid_run_plan_arguments');
    const value = parts.length ? parts.join('=') : argv[++index];
    if (!value || value.startsWith('--') || value.length > 4096 || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError('invalid_run_plan_arguments');
    values.set(name, value);
  }
  if (!flags.has('--active-consent') || ['--plan', '--inputs', '--out', '--allowed-origin'].some(name => !values.has(name))) throw new TypeError('invalid_run_plan_arguments');
  const number = (name: string, cap: number): number | undefined => {
    const value = values.get(name); if (value === undefined) return undefined;
    if (!/^[1-9][0-9]{0,8}$/.test(value) || Number(value) > cap) throw new TypeError('invalid_run_plan_arguments'); return Number(value);
  };
  const failOn = values.get('--fail-on');
  if (failOn && !['critical', 'high', 'medium', 'low', 'info', 'none'].includes(failOn)) throw new TypeError('invalid_run_plan_arguments');
  return { planFile: values.get('--plan')!, inputsFile: values.get('--inputs')!, outDir: values.get('--out')!, allowedOrigin: values.get('--allowed-origin')!,
    consent: true, allowPrivate: flags.has('--allow-private'), maxRequests: number('--max-requests', 20_000), timeoutMs: number('--timeout-ms', 600_000),
    ratePerSecond: number('--rate-per-second', 150), concurrency: number('--concurrency', 4), failOn: failOn as RunPlanCliOptions['failOn'],
    schemathesisPython: values.get('--schemathesis-python'), nucleiPath: values.get('--nuclei'), nucleiTemplates: values.get('--nuclei-templates') };
}
export async function runPlanMain(argv: readonly string[]): Promise<number> {
  let options: RunPlanCliOptions | { help: true };
  try { options = parseRunPlanArgs(argv); } catch {
    process.stderr.write('Run plan refused: explicit consent, bounded owner options and valid input files are required.\n'); return 2;
  }
  if ('help' in options) { process.stdout.write(RUN_PLAN_USAGE); return 0; }
  const controller = new AbortController(), cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const plan = parseExecutionPlan(await readJsonInput(options.planFile, 1024 * 1024));
    const inputs = parseExecutionInputs(await readJsonInput(options.inputsFile, 1024 * 1024));
    const result = await runExecutionPlan({ plan, inputs, inputBaseDir: dirname(resolve(options.inputsFile)), outDir: options.outDir,
      consent: true, allowedOrigin: options.allowedOrigin, allowPrivate: options.allowPrivate, maxRequests: options.maxRequests, timeoutMs: options.timeoutMs,
      ratePerSecond: options.ratePerSecond, concurrency: options.concurrency, failOn: options.failOn, nucleiPath: options.nucleiPath,
      nucleiTemplates: options.nucleiTemplates, schemathesisPython: options.schemathesisPython, env: process.env, signal: controller.signal });
    process.stdout.write(JSON.stringify(result) + '\n');
    return controller.signal.aborted ? 2 : result.exitCode;
  } catch { process.stderr.write('Run plan refused: the bounded local plan or owner inputs could not be read.\n'); return 2; }
  finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
}
