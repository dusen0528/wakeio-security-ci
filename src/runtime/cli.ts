import { snapshotJsonData } from '../json-snapshot.js';

const HELP = `Usage: wakeio-security-ci init-target --source DIR --out NEW_FILE
       wakeio-security-ci init-target --help
Read-only Pack detection; writes a schema-valid draft, never builds or runs the source.
Output must be new, outside source, in an existing parent containing the source.
Compose, service, seed and scope require review. No Docker, network or project scripts.
0: draft written; 2: refused. verify execution is not available yet.
`;
export type InitTargetArgs = { help: true } | { source: string; out: string };
function invalid(): never { throw new TypeError('invalid_init_target_arguments'); }

/** Pure own-data parsing: help and rejected grammar perform no target or output I/O. */
export function parseInitTargetArgs(raw: unknown): InitTargetArgs {
  const args = snapshotJsonData(raw, invalid, invalid);
  if (!Array.isArray(args) || args.some(value => typeof value !== 'string'
    || !value.trim() || /[\x00-\x1f\x7f]/.test(value)) || args[0] !== 'init-target') invalid();
  if (args.length === 2 && args[1] === '--help') return { help: true };
  if (args.length !== 5) invalid();
  const values = new Map<string, string>();
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (!['--source', '--out'].includes(flag) || values.has(flag) || value.startsWith('-')
      || value.length > 4096 || value.includes('\\') || value.split('/').includes('..')) invalid();
    values.set(flag, value);
  }
  if (!values.has('--source') || !values.has('--out')) invalid();
  return { source: values.get('--source')!, out: values.get('--out')! };
}

export async function initTargetMain(raw: unknown): Promise<number> {
  let args: InitTargetArgs;
  try { args = parseInitTargetArgs(raw); }
  catch { process.stderr.write('invalid_init_target_arguments\n'); return 2; }
  if ('help' in args) { process.stdout.write(HELP); return 0; }
  try {
    await (await import('../init-target.js')).writeInitTargetDraft(args.source, args.out);
    process.stdout.write('Draft only: review compose file/service, dependencies, seed and scope; '
      + 'nothing was executed.\n');
    return 0;
  } catch (error) {
    const reasons = ['unsafe_init_target_path', 'init_target_source_reference', 'unsupported_runtime_source',
      'invalid_init_target_source', 'invalid_builtin_pack', 'init_target_output_exists'];
    const reason = error instanceof Error && reasons.includes(error.message) ? error.message : 'init_target_failed';
    process.stderr.write(reason + '\n'); return 2;
  }
}
