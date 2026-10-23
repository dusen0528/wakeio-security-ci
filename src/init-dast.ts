import { lstat, mkdir, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { readJsonInput } from './json-input.js';
import { enumerateOpenApiGetOperations, OPENAPI_MAX_INPUT_BYTES, type OpenApiInventoryGapReason } from './openapi.js';

export interface SurfaceInventory {
  schema: 'wakeio.surface-inventory/v1';
  origin: string | null;
  scope: { openapi_get: 'observed' | 'none_detected' | 'partial'; source_routes: 'unverified' };
  surfaces: Array<{ method: 'GET'; pathTemplate: string }>;
  unverified: Array<{ area: 'source_routes' | 'openapi_path_item'; pathTemplate: string | null;
    reason: 'deferred_to_p1b' | OpenApiInventoryGapReason }>;
  counts: { declaredGetOperations: number | null; enumeratedGetOperations: number; unresolvedPathItems: number };
}

/** Only an explicit origin is retained. URL parsing never resolves a host or sends a request. */
function originOf(value?: string): string | null {
  if (value === undefined) return null;
  if (/[\u0000-\u0020\u007f\\]/.test(value) || value.includes('?') || value.includes('#')) throw Error('invalid_origin');
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.pathname !== '/') throw Error('invalid_origin');
  return url.origin;
}

export function buildSurfaceInventory(document: unknown, url?: string): SurfaceInventory {
  const origin = originOf(url), { operations, unresolved } = enumerateOpenApiGetOperations(document);
  return {
    schema: 'wakeio.surface-inventory/v1', origin,
    scope: { openapi_get: unresolved.length ? 'partial' : operations.length ? 'observed' : 'none_detected', source_routes: 'unverified' },
    surfaces: operations.map(operation => ({ method: operation.method, pathTemplate: operation.path })),
    unverified: [{ area: 'source_routes', pathTemplate: null, reason: 'deferred_to_p1b' },
      ...unresolved.map(gap => ({ area: 'openapi_path_item' as const, pathTemplate: gap.path, reason: gap.reason }))],
    counts: { declaredGetOperations: unresolved.length ? null : operations.length,
      enumeratedGetOperations: operations.length, unresolvedPathItems: unresolved.length },
  };
}

const HELP = `Usage: wakeio-security-ci init-dast --source DIR --openapi LOCAL_JSON --out NEW_DIR [--url ORIGIN]

Enumerate declared OpenAPI GETs offline. Source routes remain unverified (P1b).
No target scripts, DNS, HTTP, model, workflow or plan execution. --url validates a string only.
Output must be new, outside source, with an existing parent directory.
Exit 0: inventory produced, including explicit partial/unverified scope. Exit 2: input/output error.
`;

// Same directory policy as run-plan: no caller symlinks, except verified macOS system aliases.
async function directory(path: string): Promise<string> {
  const target = resolve(path), root = resolve(target, '/');
  let current = root;
  for (const part of target.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink()) {
      if (process.platform !== 'darwin' || !['/tmp', '/var'].includes(current) || await realpath(current) !== '/private' + current) throw Error('unsafe_path');
    } else if (!info.isDirectory()) throw Error('unsafe_path');
  }
  return realpath(target);
}

export async function initDastMain(argv: readonly string[]): Promise<number> {
  const args = argv[0] === 'init-dast' ? argv.slice(1) : [...argv];
  if (args.length === 1 && ['--help', '-h'].includes(args[0]!)) { process.stdout.write(HELP); return 0; }
  try {
    const flags = new Map<string, string>();
    for (let i = 0; i < args.length; i += 2) {
      const flag = args[i]!, value = args[i + 1];
      if (!['--source', '--openapi', '--out', '--url'].includes(flag) || flags.has(flag) || !value
        || value.startsWith('--') || /[\u0000-\u001f\u007f]/.test(value)) throw Error('invalid_arguments');
      flags.set(flag, value);
    }
    if (!['--source', '--openapi', '--out'].every(flag => flags.has(flag))) throw Error('invalid_arguments');
    const source = await directory(flags.get('--source')!);
    const input = resolve(flags.get('--openapi')!), destination = resolve(flags.get('--out')!);
    await directory(dirname(input));
    const parent = await directory(dirname(destination)), output = join(parent, basename(destination));
    if (output === source || output.startsWith(source.endsWith(sep) ? source : source + sep)) throw Error('unsafe_output');
    const inventory = buildSurfaceInventory(await readJsonInput(input, OPENAPI_MAX_INPUT_BYTES), flags.get('--url'));
    await mkdir(output, { mode: 0o700 });
    await writeFile(join(output, 'inventory.json'), JSON.stringify(inventory, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    process.stdout.write(`Inventory status=${inventory.scope.openapi_get} partial=${inventory.counts.unresolvedPathItems} unverified=${inventory.unverified.length} GET=${inventory.surfaces.length}\n`);
    return 0;
  } catch {
    process.stderr.write('Inventory error: use valid bounded local OpenAPI JSON, an existing source, an optional HTTP(S) origin and a fresh output outside source.\n');
    return 2;
  }
}
