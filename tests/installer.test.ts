import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';

const exec = promisify(execFile);

test('pinned installer is executable by Node and supports an explicit no-download scope', async () => {
  const script = resolve(process.cwd(), 'scripts/install-tools.mjs');
  const { stdout } = await exec(process.execPath, [script, '--tools', 'none', '--json']);
  assert.deepEqual(JSON.parse(stdout), {});
});

test('pinned installer rejects unknown options before any download', async () => {
  const script = resolve(process.cwd(), 'scripts/install-tools.mjs');
  await assert.rejects(exec(process.execPath, [script, '--definitely-unknown']), (error: any) => {
    assert.equal(error.code, 2);
    assert.match(error.stderr, /Unknown installer option/);
    return true;
  });
});

test('pinned installer rejects missing option values before any download', async () => {
  const script = resolve(process.cwd(), 'scripts/install-tools.mjs');
  for (const args of [['--tools'], ['--dir'], ['--tools', '--json'], ['--dir', '--json']]) {
    await assert.rejects(exec(process.execPath, [script, ...args]), (error: any) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /requires a value/);
      return true;
    });
  }
});
