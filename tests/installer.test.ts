import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';

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

test('pinned installer offers Nuclei only on request and validates zip entry paths', async () => {
  const script = resolve(process.cwd(), 'scripts/install-tools.mjs');
  const installer = await import(pathToFileURL(script).href);
  assert.deepEqual(Object.keys(installer.TOOL_RELEASES.nuclei.assets).sort(), ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64']);
  assert.equal(installer.TOOL_RELEASES.nuclei.version, '3.11.1');
  assert.equal(installer.TOOL_RELEASES.nuclei.assets['darwin-arm64'].sha256, '7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0');
  assert.equal(installer.TOOL_RELEASES.nuclei.assets['linux-x64'].sha256, 'ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6');
  assert.deepEqual(await installer.installTools({ tools: [], offline: true }), {});
  await assert.rejects(installer.installTools({ tools: ['nuclei'], offline: true, cacheDirectory: await mkdtemp(join(tmpdir(), 'wakeio-cache-')) }),
    /No verified cached nuclei archive/);
  installer.validateArchivePaths('LICENSE.md\nnuclei\n');
  for (const listing of ['../nuclei', '/usr/bin/nuclei', 'a/../../nuclei', 'C:/nuclei']) {
    assert.throws(() => installer.validateArchivePaths(listing), /Refusing/);
  }
});
