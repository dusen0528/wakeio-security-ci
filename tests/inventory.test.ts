import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { enumerateOpenApiGetOperations, selectOpenApiLiveOperations } from '../src/openapi.js';
import { buildSurfaceInventory } from '../src/init-dast.js';

const exec = promisify(execFile);
const corpus = JSON.parse(await readFile('benchmarks/inventory-corpus.json', 'utf8'));
const sha = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
for (const fixture of corpus.cases) {
  test(`GET inventory ground truth: ${fixture.id}`, async () => {
    const raw = await readFile(join('benchmarks', fixture.fixture));
    assert.equal(sha(raw), fixture.sha256);
    const inventory = buildSurfaceInventory(raw);
    assert.deepEqual(inventory.surfaces.map(item => item.method + ' ' + item.pathTemplate), fixture.expectedGetKeys);
    assert.deepEqual(inventory.counts, { declaredGetOperations: fixture.declaredGetOperations,
      enumeratedGetOperations: fixture.expectedGetKeys.length, unresolvedPathItems: fixture.unresolvedPathItems });
    assert.equal(inventory.openapiDigest, fixture.sha256);
    assert.equal(inventory.scope.openapi_get, fixture.state);
    assert.equal(inventory.scope.source_routes, 'unverified');
    assert.equal(sha(raw), fixture.sha256);
    assert.equal(inventory.unverified.length, fixture.unresolvedPathItems + 1);
  });
}

test('inventory enumeration does not widen the existing execution selector', async () => {
  for (const name of ['empty-paths', 'unresolved-path-item']) {
    const fixture = corpus.cases.find((item: any) => item.id === name);
    const document = JSON.parse(await readFile(join('benchmarks', fixture.fixture), 'utf8'));
    assert.throws(() => selectOpenApiLiveOperations(document, [{ method: 'GET', path: '/local' }]));
  }
  assert.throws(() => enumerateOpenApiGetOperations({ openapi: '3.1.0', paths: { '/invalid': { $ref: 42 } } }));
  let invoked = false;
  const accessor = Object.defineProperty({}, 'paths', { enumerable: true, get() { invoked = true; return {}; } });
  assert.throws(() => enumerateOpenApiGetOperations(accessor)); assert.equal(invoked, false);
});

test('OpenAPI digest binds exact original bytes, including a single whitespace byte', async () => {
  const original = Buffer.from('{ "openapi":"3.1.0","paths":{}}');
  const changed = Buffer.from(original); changed[1] = 9;
  assert.equal(original.filter((byte, i) => byte !== changed[i]).length, 1);
  assert.deepEqual(JSON.parse(original.toString()), JSON.parse(changed.toString()));
  const first = buildSurfaceInventory(original), second = buildSurfaceInventory(changed);
  assert.equal(first.openapiDigest, sha(original));
  assert.equal(second.openapiDigest, sha(changed));
  assert.notEqual(first.openapiDigest, second.openapiDigest);
  assert.deepEqual(buildSurfaceInventory(original), first);
});

for (const reason of ['invalid_arguments', 'unsafe_path', 'path_not_found', 'output_exists', 'invalid_origin', 'unsupported_openapi', 'invalid_openapi', 'input_limit', 'output_error']) {
  test(`CLI emits only fixed reason code: ${reason}`, async t => {
    const top = await mkdtemp(join(tmpdir(), 'wakeio-reason-')); t.after(() => rm(top, { recursive: true, force: true }));
    const source = join(top, 'source'), input = join(top, 'CANARY-input.json'), out = join(top, 'out'); await mkdir(source);
    await writeFile(input, '{"openapi":"3.1.0","paths":{}}');
    const args = ['init-dast', '--source', source, '--openapi', input, '--out', out];
    if (reason === 'invalid_arguments') args.push('--CANARY');
    if (reason === 'unsafe_path') { const link = join(top, 'linked'); await symlink(source, link); args[2] = link; }
    if (reason === 'path_not_found') args[4] = join(top, 'CANARY-missing.json');
    if (reason === 'output_error') args[6] = join(top, 'x'.repeat(300));
    if (reason === 'output_exists') { await mkdir(out); await writeFile(join(out, 'sentinel'), 'keep'); }
    if (reason === 'invalid_origin') args.push('--url', 'CANARY-invalid-url');
    if (reason === 'unsupported_openapi') await writeFile(input, '{"openapi":"2.0.0","paths":{},"CANARY":true}');
    const inputs = reason === 'invalid_openapi'
      ? ['{"CANARY":', '{"openapi":"3.1.0","paths":{"/CANARY":42}}', Buffer.from([0xff])]
      : reason === 'input_limit'
        ? [' '.repeat(1024 * 1024 + 1), JSON.stringify({ openapi: '3.1.0', paths: Object.fromEntries(Array.from({ length: 1001 }, (_, i) => ['/p' + i, {}])) }),
          JSON.stringify({ openapi: '3.1.0', paths: {}, description: Array(20001).fill(null) }),
          '{"openapi":"3.1.0","paths":{},"description":' + '['.repeat(41) + '0' + ']'.repeat(41) + '}']
        : [null];
    for (const bytes of inputs) {
      if (bytes !== null) await writeFile(input, bytes);
      await assert.rejects(exec(process.execPath, ['build/src/cli.js', ...args]), (error: any) => {
        assert.equal(error.code, 2); assert.equal(error.stdout, ''); assert.equal(error.stderr, reason + '\n'); return true;
      });
    }
    if (reason === 'output_exists') assert.equal(await readFile(join(out, 'sentinel'), 'utf8'), 'keep');
    else await assert.rejects(stat(out), { code: 'ENOENT' });
  });
}

test('CLI publishes byte-identical inventory three times and leaves source code/config unexecuted', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-inventory-')); t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'), marker = join(top, 'target-executed'); await mkdir(source);
  const code = `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed')`;
  await writeFile(join(source, 'next.config.js'), code);
  await writeFile(join(source, 'package.json'), JSON.stringify({ scripts: { install: code, build: code, test: code } }));
  for (const item of corpus.cases) {
    const fixture = resolve('benchmarks', item.fixture), bytes = [];
    for (let i = 0; i < 3; i++) {
      const out = join(top, item.id + '-' + i);
      const result = await exec(process.execPath, ['build/src/cli.js', 'init-dast', '--source', source, '--openapi', fixture,
        '--url', 'https://no-dns-required.invalid', '--out', out]);
      assert.equal(result.stdout.split('\n')[0], `Inventory status=${item.state} unresolved=${item.unresolvedPathItems} unverified=${item.unresolvedPathItems + 1} GET=${item.expectedGetKeys.length}`);
      bytes.push(await readFile(join(out, 'inventory.json'), 'utf8'));
      assert.equal(JSON.parse(bytes.at(-1)!).openapiDigest, item.sha256);
      assert.deepEqual(await readdir(out), ['inventory.json']);
      if (process.platform !== 'win32') {
        assert.equal((await stat(out)).mode & 0o777, 0o700);
        assert.equal((await stat(join(out, 'inventory.json'))).mode & 0o777, 0o600);
      }
    }
    assert.equal(new Set(bytes).size, 1, item.id);
  }
  assert.deepEqual((await readdir(source)).sort(), ['next.config.js', 'package.json']);
  await assert.rejects(readFile(marker), { code: 'ENOENT' });
});

test('CLI rejects unsafe/missing inputs and fresh-output violations with exit2, preserving existing files', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-inventory-errors-')); t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'); await mkdir(source);
  const fixture = resolve('benchmarks/fixtures/inventory/existing-live.json');
  const valid = ['init-dast', '--source', source, '--openapi', fixture];
  const existing = join(top, 'existing'); await mkdir(existing); await writeFile(join(existing, 'sentinel'), 'keep');
  const linked = join(top, 'linked'); await symlink(source, linked);
  const fileLink = join(top, 'spec-link.json'); await symlink(fixture, fileLink);
  const malformed = join(top, 'malformed.json'); await writeFile(malformed, '{');
  const invalidArgs = [
    ['init-dast'], ['init-dast', '--source', '/', '--openapi', fixture, '--out', join(top, 'root-inside')], [...valid, '--out', existing], [...valid, '--out', join(source, 'inside')],
    ['init-dast', '--source', linked, '--openapi', fixture, '--out', join(top, 'bad-source')],
    ['init-dast', '--source', source, '--openapi', fileLink, '--out', join(top, 'bad-spec-link')],
    ['init-dast', '--source', source, '--openapi', malformed, '--out', join(top, 'bad-json')],
    [...valid, '--out', join(top, 'duplicate'), '--out', join(top, 'another')],
    [...valid, '--out', join(top, 'unknown'), '--tools', 'none'],
    ...['https://user:CANARY@host.invalid', 'https://host.invalid/path', 'https://host.invalid?token=CANARY', 'file:///tmp/x']
      .map(url => [...valid, '--out', join(top, 'bad-origin'), '--url', url]),
  ];
  for (const args of invalidArgs) {
    await assert.rejects(exec(process.execPath, ['build/src/cli.js', ...args]), (error: any) => {
      assert.equal(error.code, 2); assert.equal(error.stdout, ''); assert.doesNotMatch(error.stderr, /CANARY|next\.config|malformed\.json/); return true;
    });
  }
  assert.equal(await readFile(join(existing, 'sentinel'), 'utf8'), 'keep');
  assert.deepEqual(await readdir(source), []);
  for (const name of ['root-inside', 'bad-source', 'bad-spec-link', 'bad-json', 'duplicate', 'unknown', 'bad-origin']) await assert.rejects(stat(join(top, name)), { code: 'ENOENT' });
  const help = await exec(process.execPath, ['build/src/cli.js', 'init-dast', '--help']); assert.match(help.stdout, /Exit 0/);
  assert.match(help.stdout, /--source is used only to validate the output location in P1a/);
});

test('legacy npm and Action init output stays byte-identical to frozen pre-P1a main templates', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-snapshot-')); t.after(() => rm(top, { recursive: true, force: true }));
  const manifest = JSON.parse(await readFile('tests/fixtures/compat-0.5/init/manifest.json', 'utf8'));
  assert.equal(manifest.sourceCommit, '7c13b24624af44f9192a1df49908aa25e1d074c9');
  for (const item of manifest.cases) {
    const source = join(top, item.name); await mkdir(source);
    const args = ['build/src/cli.js', 'init', '--source', source];
    if (item.name === 'action') args.push('--mode', 'action', '--action-ref', 'a'.repeat(40));
    await exec(process.execPath, args);
    const actual = await readFile(join(source, '.github/workflows/wakeio-security-ci.yml'));
    assert.equal(sha(actual), item.sha256);
    assert.deepEqual(actual, await readFile('tests/fixtures/compat-0.5/init/' + item.name + '.yml'));
    await assert.rejects(exec(process.execPath, args), (error: any) => error.code === 2);
    assert.deepEqual(actual, await readFile(join(source, '.github/workflows/wakeio-security-ci.yml')));
  }
});
