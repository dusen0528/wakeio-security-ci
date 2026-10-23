import { lstat, mkdir, realpath, rmdir, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { OpenApiPolicyError } from './openapi.js';

// Same policy as run-plan: caller symlinks are refused, except verified macOS aliases.
export async function offlineDirectory(path: string): Promise<string> {
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

export async function writeOfflineBundle(output: string, files: ReadonlyArray<readonly [string, string | Buffer]>): Promise<void> {
  try { await mkdir(output, { mode: 0o700 }); }
  catch (error) { throw Error((error as NodeJS.ErrnoException).code === 'EEXIST' ? 'output_exists' : 'output_error'); }
  try {
    for (const [name, bytes] of files) await writeFile(join(output, name), bytes, { mode: 0o600, flag: 'wx' });
  } catch {
    // Remove only our empty claim; never recursively remove partial or caller files.
    try { await rmdir(output); } catch { /* Preserve the original publication failure. */ }
    throw Error('output_error');
  }
}

const reasons = new Set(['invalid_arguments', 'unsafe_path', 'path_not_found', 'input_changed', 'input_limit', 'output_exists', 'output_error',
  'invalid_origin', 'invalid_inventory', 'invalid_preset', 'openapi_digest_mismatch', 'inventory_mismatch', 'origin_required', 'origin_mismatch',
  'preset_https_unsupported', 'surface_not_in_inventory', 'no_operations', 'operation_limit', 'inventory_partial', 'insufficient_budget', 'invalid_openapi']);

export function offlineErrorCode(error: unknown, fallback: string): string {
  if (error instanceof OpenApiPolicyError) return error.code === 'openapi_limit' ? 'input_limit'
    : error.code === 'unsupported_openapi' ? 'unsupported_openapi' : 'invalid_openapi';
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return 'path_not_found';
    if (['ELOOP', 'ENOTDIR', 'EACCES', 'EPERM'].includes(code ?? '')) return 'unsafe_path';
    if (reasons.has(code ?? '')) return code!;
    if (reasons.has(error.message)) return error.message;
  }
  return fallback;
}
