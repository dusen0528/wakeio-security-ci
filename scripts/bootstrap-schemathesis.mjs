// CI-only explicit installer. Reuses the version-pin lock; no distribution-hash claim.
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { runBounded } from './ci-process.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
const python = process.env.WAKEIO_BOOTSTRAP_PYTHON ?? 'python3';
const venv = join(root, '.venv-schemathesis');
for (const [name, command, args, timeoutMs] of [
  ['python-version', python, ['-I', '-c', 'import sys; assert sys.version_info[:3] == (3,12,13)'], 10000],
  ['venv', python, ['-m', 'venv', venv], 30000],
  ['version-pinned-install', join(venv, 'bin/python'), ['-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--only-binary=:all:',
    '--timeout', '20', '--retries', '1', '-r', join(root, 'workers/schemathesis/requirements.lock.txt')], 180000],
]) {
  const result = await runBounded(command, args, { cwd: root, timeoutMs });
  process.stdout.write(result.stdout); process.stderr.write(result.stderr);
  if (result.reason || !result.cleanupConfirmed || result.exitCode !== 0) {
    process.stderr.write(name + ' failed or incomplete; no required tests may be skipped.\n'); process.exitCode = 2; break;
  }
}
