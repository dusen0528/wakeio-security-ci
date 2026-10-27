import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseInitTargetArgs } from '../src/runtime/cli.js';
import { parseTargetYaml } from '../src/runtime/target.js';

test('init-target grammar snapshots own data and rejects ambiguity without invoking caller code', () => {
  assert.deepEqual(parseInitTargetArgs(['init-target', '--out', 'draft.yml', '--source', 'service']),
    { source: 'service', out: 'draft.yml' });
  assert.deepEqual(parseInitTargetArgs(['init-target', '--help']), { help: true });
  let calls = 0; const getter = ['init-target', '--help'];
  Object.defineProperty(getter, '1', { enumerable: true, get() { calls++; return '--help'; } });
  const proxy = new Proxy([], { get() { calls++; throw Error('must not run'); } });
  for (const args of [getter, proxy, Object.create(['init-target', '--help']), null,
    ['init-target'], ['init-target', '--help', '--source', 'service'],
    ['init-target', '--source', 'service', '--source', 'other'],
    ['init-target', '--unknown', 'service', '--out', 'draft'],
    ['init-target', '--source', '', '--out', 'draft'],
    ['init-target', '--source', 'service\nprivate', '--out', 'draft'],
    ['init-target', '--source', 'service', '--out', '--help'],
    ['init-target', '--source', '../service', '--out', 'draft'],
  ]) assert.throws(() => parseInitTargetArgs(args), /invalid_init_target_arguments/);
  assert.equal(calls, 0);
});

async function guard(top: string, source: string, output: string, denyReads: boolean) {
  const preload = join(top, 'guard.mjs'), marker = join(top, 'side-effects');
  await writeFile(preload, `import fs from 'node:fs'; import p from 'node:fs/promises';
import cp from 'node:child_process'; import http from 'node:http'; import https from 'node:https';
import net from 'node:net'; import dns from 'node:dns'; import {syncBuiltinESMExports} from 'node:module';
const marker=${JSON.stringify(marker)};
const stop = name => { fs.appendFileSync(marker, name+'\\n'); throw Error('forbidden'); };
globalThis.fetch=()=>stop('fetch'); net.Socket.prototype.connect=()=>stop('socket.connect');
dns.promises.lookup=()=>stop('dns.lookup'); dns.promises.resolve=()=>stop('dns.resolve');
for (const [object,names] of [[cp,['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']],
 [http,['request','get']], [https,['request','get']],
 [net,['connect','createConnection']], [dns,['lookup','resolve']]]) {
 for (const name of names) object[name] = () => stop(name);
}
for (const [object,names] of [[p,['lstat','stat','readFile','readdir','open','mkdir','writeFile','link','unlink']],
 [fs,['lstatSync','statSync','readFileSync','readdirSync','openSync','mkdirSync','writeFileSync','linkSync']]]) {
 for (const name of names) { const original=object[name]; object[name]=function(path,...args) {
  const value=String(path); const source=value.startsWith(${JSON.stringify(source)});
  if (${denyReads} && (source || value.startsWith(${JSON.stringify(output)}) || value.includes('/packs/'))
    || source && ['mkdir','writeFile','link','unlink','mkdirSync','writeFileSync','linkSync'].includes(name)
    || source && ['open','openSync'].includes(name) && args[0]!==fs.constants.O_RDONLY
      && args[0]!== (fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK)) stop(name);
  return original.call(this,path,...args);
 }; }
}
syncBuiltinESMExports();
`);
  return { preload, marker };
}
const entries = [resolve('build/src/cli.js'), resolve('dist-action/wakeio-security-ci.mjs')];
function launch(entry: string, args: string[], cwd: string, preload: string) {
  const result = spawnSync(process.execPath, ['--import', preload, entry, ...args], {
    cwd, encoding: 'utf8', timeout: 15000,
    env: { PATH: '', NODE_OPTIONS: '', WAKEIO_SECRET: 'environment-canary-private' },
  });
  assert.ifError(result.error); return result;
}

test('source and Action CLI help/grammar perform zero selected-input/output/process/network operations', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-cli-help-'));
  try {
    const source = join(top, 'must-not-read'), output = join(top, 'must-not-write');
    const { preload, marker } = await guard(top, source, output, true);
    for (const entry of entries) {
      const help = launch(entry, ['init-target', '--help'], top, preload);
      assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /Draft|draft/);
      for (const args of [
        ['init-target', '--source', source],
        ['init-target', '--source', source, '--source', output],
        ['init-target', '--source', source, '--out', output, '--help'],
        ['init-target', '--unknown', source, '--out', output],
        ['init-target', '--source', source + '\nprivate', '--out', output],
      ]) {
        const run = launch(entry, args, top, preload);
        assert.equal(run.status, 2); assert.equal(run.stderr.trim(), 'invalid_init_target_arguments');
      }
    }
    await assert.rejects(readFile(marker), { code: 'ENOENT' });
    assert.deepEqual(await readdir(top), ['guard.mjs']);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('actual source/isolated Action CLI locate tool-local Pack and schema without project execution', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-cli-assets-'));
  try {
    const source = join(top, 'service'); await mkdir(source);
    const before = 'org.springframework.boot\nprivate-pom-canary';
    await writeFile(join(source, 'pom.xml'), before);
    await writeFile(join(source, 'package.json'), '{"scripts":{"prepare":"exit 99","test":"exit 99"}}');
    const vendored = join(top, 'tool'); await mkdir(vendored); await mkdir(join(vendored, 'dist-action'));
    await mkdir(join(vendored, 'packs'));
    await copyFile(entries[1], join(vendored, 'dist-action', 'wakeio-security-ci.mjs'));
    await copyFile(resolve('packs/spring-boot.v1.yml'), join(vendored, 'packs', 'spring-boot.v1.yml'));
    const output = join(top, 'draft.yml'), { preload, marker } = await guard(top, source, output, false);
    for (const [index, entry] of [entries[0], join(vendored, 'dist-action', 'wakeio-security-ci.mjs')].entries()) {
      const out = join(top, `draft-${index}.yml`);
      const run = launch(entry, ['init-target', '--source', source, '--out', out], top, preload);
      assert.equal(run.status, 0, run.stderr); assert.match(run.stdout, /Draft only/);
      assert.ok(!(run.stdout + run.stderr).includes('private'));
      const yaml = await readFile(out, 'utf8'); assert.ok(!yaml.includes('private'));
      assert.equal(parseTargetYaml(yaml).source, 'service');
      const collision = launch(entry, ['init-target', '--source', source, '--out', out], top, preload);
      assert.equal(collision.status, 2); assert.match(collision.stderr, /init_target_output_exists/);
      const unsafe = launch(entry, ['init-target', '--source', source, '--out', join(source, 'bad.yml')], top, preload);
      assert.equal(unsafe.status, 2); assert.equal(await readFile(out, 'utf8'), yaml);
    }
    await assert.rejects(readFile(marker), { code: 'ENOENT' });
    assert.equal(await readFile(join(source, 'pom.xml'), 'utf8'), before);
    assert.deepEqual((await readdir(source)).sort(), ['package.json', 'pom.xml']);
    const unsupported = join(top, 'unsupported'); await mkdir(unsupported);
    for (const entry of [entries[0], join(vendored, 'dist-action', 'wakeio-security-ci.mjs')]) {
      const run = launch(entry, ['init-target', '--source', unsupported, '--out', output], top, preload);
      assert.equal(run.status, 2); assert.equal(run.stderr.trim(), 'unsupported_runtime_source');
      await assert.rejects(readFile(output), { code: 'ENOENT' });
    }
    await assert.rejects(readFile(marker), { code: 'ENOENT' });
  } finally { await rm(top, { recursive: true, force: true }); }
});
