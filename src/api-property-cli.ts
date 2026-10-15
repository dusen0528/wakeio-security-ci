import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { dirname, parse, resolve } from 'node:path';
import type { FailOn } from './contracts.js';
import { parseApiPropertyPolicy, parsePropertyJsonText } from './api-property-policy.js';
import { preflightApiPropertyWrite, runApiPropertyWrite } from './api-property-write.js';
import { createReport, exitCode, writeArtifacts, writeReports } from './report.js';

const HELP = 'Usage: wakeio-security-ci api-property-write --policy FILE --active-consent --out NEW_DIR [--allow-private] [--timeout-ms 1..120000] [--max-requests 1..23] [--fail-on LEVEL]\n'
  + '       wakeio-security-ci api-property-write --policy FILE --preflight [--allow-private] [--timeout-ms 1..120000] [--max-requests 1..23]\n'
  + 'Explicit disposable single-origin resource only. GET/conditional merge PATCH; 22 planned HTTP requests, at most 23/8 PATCH. No redirects, retries, DELETE or post-cancel cleanup.\n';
async function policyFile(filename: string) {
  const path = resolve(filename);
  let parent = dirname(path);
  for (;;) {
    const stat = await lstat(parent);
    if (stat.isSymbolicLink()) {
      // Match existing report/handoff policy for these exact macOS system aliases only.
      if (!['/tmp', '/var'].includes(parent) || !(await lstat(await realpath(parent))).isDirectory()) throw new Error('invalid_policy_file');
    } else if (!stat.isDirectory()) throw new Error('invalid_policy_file');
    if (parent === parse(parent).root) break;
    parent = dirname(parent);
  }
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > 64 * 1024) throw new Error('invalid_policy_file');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 64 * 1024 || stat.dev !== before.dev || stat.ino !== before.ino) throw new Error('invalid_policy_file');
    // Bounded read even if a concurrently changed file grows after stat.
    const buffer = Buffer.alloc(64 * 1024 + 1);
    let length = 0;
    while (length < buffer.length) {
      const part = await handle.read(buffer, length, buffer.length - length, length);
      if (!part.bytesRead) break;
      length += part.bytesRead;
    }
    const after = await handle.stat(), pathAfter = await lstat(path);
    if (length > 64 * 1024 || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs
      || pathAfter.ino !== stat.ino || pathAfter.dev !== stat.dev) throw new Error('invalid_policy_file');
    return parseApiPropertyPolicy(parsePropertyJsonText(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length))));
  } finally { await handle.close(); }
}
export async function apiPropertyWriteMain(argv: readonly string[]): Promise<number> {
  if (argv.length === 2 && ['--help', '-h'].includes(argv[1]!)) { process.stdout.write(HELP); return 0; }
  const values = new Map<string, string>(), switches = new Set<string>();
  try {
    if (argv[0] !== 'api-property-write') throw new Error('args');
    for (let i = 1; i < argv.length; i++) {
      const flag = argv[i]!;
      if (['--active-consent', '--preflight', '--allow-private'].includes(flag)) {
        if (switches.has(flag)) throw new Error('args'); switches.add(flag); continue;
      }
      if (!['--policy', '--out', '--timeout-ms', '--max-requests', '--fail-on'].includes(flag) || values.has(flag) || !argv[i + 1] || argv[i + 1]!.startsWith('--')) throw new Error('args');
      values.set(flag, argv[++i]!);
    }
    if (!values.get('--policy')?.trim() || switches.has('--preflight') === switches.has('--active-consent')) throw new Error('args');
    if (switches.has('--preflight') ? values.has('--out') || values.has('--fail-on') : !values.get('--out')?.trim()) throw new Error('args');
    for (const [key, max] of [['--timeout-ms', 120000], ['--max-requests', 23]] as const) {
      if (values.has(key) && (!/^[1-9]\d*$/.test(values.get(key)!) || !Number.isSafeInteger(Number(values.get(key))) || Number(values.get(key)) > max)) throw new Error('args');
    }
    if (values.has('--fail-on') && !['critical', 'high', 'medium', 'low', 'info', 'none'].includes(values.get('--fail-on')!)) throw new Error('args');
  } catch { process.stderr.write(HELP); return 2; }
  const controller = new AbortController(), cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const policy = await policyFile(values.get('--policy')!);
    const options = { policy, allowPrivate: switches.has('--allow-private'), signal: controller.signal,
      ...(values.has('--timeout-ms') ? { timeoutMs: Number(values.get('--timeout-ms')) } : {}),
      ...(values.has('--max-requests') ? { maxRequests: Number(values.get('--max-requests')) } : {}) };
    if (switches.has('--preflight')) {
      const plan = preflightApiPropertyWrite(options); process.stdout.write(JSON.stringify(plan) + '\n'); return plan.status === 'ready' ? 0 : 2;
    }
    const out = resolve(values.get('--out')!);
    try { await lstat(out); throw new Error('existing_output'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    // Output ownership and all ancestor checks complete before the first network request.
    await writeArtifacts(dirname(out), []); await mkdir(out, { mode: 0o700 });
    const started = new Date(), checks = await runApiPropertyWrite({ ...options, activeConsent: true });
    const markCancelled = () => {
      if (controller.signal.aborted && !checks.some(check => check.id === 'scan.cancelled')) checks.push({ id: 'scan.cancelled', status: 'partial', findings: [],
        notes: ['The command was cancelled; completed HTTP stages do not establish command completion.'] });
    };
    markCancelled();
    let report = createReport(checks, 'api', started);
    const failOn = (values.get('--fail-on') ?? 'high') as FailOn;
    await writeReports(report, out, { failOn });
    if (controller.signal.aborted && !report.checks.some(check => check.id === 'scan.cancelled')) {
      markCancelled(); report = createReport(checks, 'api', started);
      await writeReports(report, out, { failOn });
    }
    const code = exitCode(report, failOn);
    process.stdout.write(JSON.stringify({ version: 1, scope: 'policy-resource-property-write', execution: code === 2 ? 'partial' : 'completed',
      apiReexecuted: false, finalExitCode: code }) + '\n');
    return code;
  } catch {
    process.stderr.write('Property-write policy validation or artifact delivery failed. No automatic API retry was made.\n'); return 2;
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}
