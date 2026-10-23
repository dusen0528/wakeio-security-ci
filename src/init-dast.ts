import { lstat, mkdir, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { readJsonInputBytes } from './json-input.js';
import { enumerateOpenApiGetOperations, OPENAPI_MAX_INPUT_BYTES, OpenApiPolicyError, type OpenApiInventoryGapReason } from './openapi.js';

export interface SurfaceInventory {
  schema: 'wakeio.surface-inventory/v1';
  openapiDigest: string;
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
  let url: URL;
  try { url = new URL(value); } catch { throw Error('invalid_origin'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.pathname !== '/') throw Error('invalid_origin');
  return url.origin;
}

export function buildSurfaceInventory(bytes: Uint8Array, url?: string): SurfaceInventory {
  const origin = originOf(url);
  if (bytes.byteLength > OPENAPI_MAX_INPUT_BYTES) throw Error('input_limit');
  const document: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  const { operations, unresolved } = enumerateOpenApiGetOperations(document);
  return {
    schema: 'wakeio.surface-inventory/v1', openapiDigest: createHash('sha256').update(bytes).digest('hex'), origin,
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
--source is used only to validate the output location in P1a.
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
    let info;
    try { info = await lstat(current); } catch { throw Error('unsafe_path'); }
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
    if (output === source || output.startsWith(source.endsWith(sep) ? source : source + sep)) throw Error('unsafe_path');
    const inventory = buildSurfaceInventory(await readJsonInputBytes(input, OPENAPI_MAX_INPUT_BYTES), flags.get('--url'));
    try {
      await mkdir(output, { mode: 0o700 });
      await writeFile(join(output, 'inventory.json'), JSON.stringify(inventory, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    } catch (error) {
      throw Error((error as NodeJS.ErrnoException).code === 'EEXIST' ? 'output_exists' : 'output_error');
    }
    process.stdout.write(`Inventory status=${inventory.scope.openapi_get} unresolved=${inventory.counts.unresolvedPathItems} unverified=${inventory.unverified.length} GET=${inventory.surfaces.length}\n`);
    return 0;
  } catch (error) {
    let reason = 'invalid_openapi';
    if (error instanceof OpenApiPolicyError) reason = error.code === 'openapi_limit' ? 'input_limit'
      : error.code === 'unsupported_openapi' ? 'unsupported_openapi' : 'invalid_openapi';
    else if (error instanceof Error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (['ELOOP', 'ENOENT', 'ENOTDIR', 'EACCES', 'EPERM', 'unsafe_path'].includes(code ?? '')) reason = 'unsafe_path';
      else if (code === 'input_limit') reason = 'input_limit';
      else if (['invalid_arguments', 'unsafe_path', 'output_exists', 'output_error', 'invalid_origin', 'input_limit'].includes(error.message)) reason = error.message;
    }
    process.stderr.write(reason + '\n');
    return 2;
  }
}
