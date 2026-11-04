#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, lstat, realpath } from 'node:fs/promises';
import { dirname, join, resolve, parse, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeArtifact, sha256 } from './roadmap-cases/artifacts.mjs';
import { sourceSnapshot } from '../ci-process.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
// Only literal, reviewed imports. Missing future modules are unavailable, not stubs.
const cases = new Map([
  ['harness', () => import('./roadmap-cases/harness.mjs')],
  ['policy', () => import('./roadmap-cases/policy.mjs')],
  ['manifest', () => import('./roadmap-cases/manifest.mjs')],
]);

export function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index], value = argv[index + 1];
    if (!['--case', '--out', '--mutate'].includes(flag) || values.has(flag)
      || typeof value !== 'string' || !value || value.startsWith('-') || /[\x00-\x1f\x7f]/.test(value)) {
      throw new TypeError('invalid_arguments');
    }
    values.set(flag, value);
  }
  const name = values.get('--case'), out = values.get('--out'), mutate = values.get('--mutate');
  if (!name || !out || !/^[a-z][a-z0-9-]*$/.test(name)
    || mutate !== undefined && !/^[a-z][a-z0-9-]*$/.test(mutate)) throw new TypeError('invalid_arguments');
  return { name, out: resolve(out), mutate };
}

async function artifactBindings(out, artifacts) {
  if (!Array.isArray(artifacts) || !artifacts.length || new Set(artifacts).size !== artifacts.length) {
    throw new TypeError('missing_artifacts');
  }
  return await Promise.all(artifacts.map(async path => {
    if (typeof path !== 'string' || !/^[a-z][a-z0-9-]*\.json$/.test(path)) throw new TypeError('invalid_artifact_path');
    const full = join(out, path), stat = await lstat(full);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0 || stat.size > 1024 * 1024) throw new TypeError('invalid_artifact');
    const bytes = await readFile(full);
    return { path, bytes: bytes.length, sha256: sha256(bytes) };
  }));
}

export async function main(argv) {
  let options, owned = false;
  try {
    options = parseArgs(argv);
    // Match report.ts's ancestor policy without importing its product dependency graph.
    let current = parse(options.out).root;
    for (const component of dirname(options.out).slice(current.length).split(sep).filter(Boolean)) {
      current = join(current, component);
      let stat;
      try { stat = await lstat(current); }
      catch (error) {
        if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
        await mkdir(current);
        stat = await lstat(current);
      }
      if (stat.isSymbolicLink() && ['/tmp', '/var'].includes(current)) current = await realpath(current);
      else if (!stat.isDirectory() || stat.isSymbolicLink()) throw new TypeError('unsafe_output_ancestor');
    }
    await mkdir(options.out, { mode: 0o700 }); // Existing outputs, including symlinks, are never reused.
    owned = true;
    const head = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root, env: { ...process.env, GIT_MASTER: '1' }, encoding: 'utf8', timeout: 2000,
    }).trim();
    const source = sourceSnapshot(root);
    const provenance = { head, source, node: process.version, platform: process.platform };
    let result = { status: 'unavailable', artifacts: [], cleanup: { confirmed: true, scope: 'not_started' } };
    let reason = 'case_not_implemented';
    const load = cases.get(options.name);
    if (load) {
      let loaded = false;
      try {
        const module = await load();
        loaded = true;
        result = await module.runCase({ out: options.out, mutate: options.mutate });
        reason = null;
      } catch (error) {
        reason = error instanceof Error && 'code' in error && error.code === 'ERR_MODULE_NOT_FOUND'
          ? 'case_not_implemented' : 'case_exception';
        result = { status: 'unavailable', artifacts: [],
          cleanup: { confirmed: !loaded, scope: loaded ? 'case_exception' : 'not_started' } };
      }
    }
    if (!['pass', 'fail', 'unavailable'].includes(result?.status) || result?.cleanup?.confirmed !== true) {
      result = { ...result, status: 'unavailable' };
      reason ??= 'cleanup_unconfirmed_or_invalid_result';
    }
    if (!result.artifacts?.includes('cleanup.json')) {
      await writeArtifact(options.out, 'cleanup.json', result.cleanup);
      result.artifacts = [...(result.artifacts ?? []), 'cleanup.json'];
    }
    const artifacts = await artifactBindings(options.out, result.artifacts);
    const exitCode = result.status === 'pass' ? 0 : result.status === 'fail' ? 1 : 2;
    await writeArtifact(options.out, 'result.json', { schema: 'wakeio.roadmap-qa/v1',
      case: options.name, mutate: options.mutate ?? null, invocation: [process.execPath, 'scripts/qa/roadmap.mjs', ...argv],
      ...provenance, status: result.status, exitCode, reason, artifacts, cleanup: result.cleanup });
    process.stdout.write(JSON.stringify({ status: result.status, exitCode }) + '\n');
    return exitCode;
  } catch (error) {
    // CLI boundary: never print raw error text or argv, which can contain credentials.
    if (owned) {
      await writeArtifact(options.out, 'error.json', { status: 'unavailable',
        reason: error instanceof Error ? error.name : 'non_error_exception' });
    }
    process.stderr.write('roadmap_qa_unavailable\n');
    return 2;
  }
}

if (process.argv[1] && await realpath(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
