import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, mkdtemp, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import fsp from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { buildPresetBundle, PROVENANCE_NOTICE } from '../src/preset-plan.js';
import { buildSurfaceInventory, initDastMain } from '../src/init-dast.js';
import { parseExecutionInputs, parseExecutionPlan } from '../src/agent-dast/plan.js';
import { parseRunPlanArgs } from '../src/agent-dast/cli.js';
import { readJsonInputBytes } from '../src/json-input.js';
import { offlineErrorCode, writeOfflineBundle } from '../src/offline-output.js';

const exec = promisify(execFile), encode = (value: unknown) => Buffer.from(JSON.stringify(value));
const sha = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
const preset = await readFile('presets/openapi-get-contract.json');
const corpus = JSON.parse(await readFile('benchmarks/inventory-corpus.json', 'utf8'));
function spec(count: number) {
  return encode({ openapi: '3.0.3', info: { title: 'offline', version: '1' },
    paths: Object.fromEntries(Array.from({ length: count }, (_, i) => ['/p' + i, { get: { responses: { '200': { description: 'ok' } } } }]).reverse()) });
}
const inventory = (bytes: Buffer, origin?: string) => encode(buildSurfaceInventory(bytes, origin));
const generate = (bytes: Buffer, budget = 64, selected: Buffer = preset) => buildPresetBundle(selected, inventory(bytes), bytes, 'http://127.0.0.1:3000', budget);
function refuses(read: () => unknown, code: string) { assert.throws(read, (error: any) => { assert.equal(error.message, code); return true; }); }

for (const item of corpus.cases) test(`preset exact fixture contract: ${item.id}`, async () => {
  const bytes = await readFile(join('benchmarks', item.fixture));
  if (item.state === 'partial') return refuses(() => generate(bytes), 'inventory_partial');
  if (!item.expectedGetKeys.length) return refuses(() => generate(bytes), 'no_operations');
  const result = generate(bytes);
  assert.deepEqual(parseExecutionPlan(result.plan), result.plan);
  assert.deepEqual(parseExecutionInputs(result.inputs), result.inputs);
  assert.deepEqual(result.plan.tasks.flatMap(task => task.engine === 'schemathesis' ? task.operations.map(path => 'GET ' + path) : []), item.expectedGetKeys);
});

for (const count of [1, 16, 17, 256]) test(`partitions ${count} GETs without loss, overlap or budget reissue`, () => {
  const budget = Math.ceil(count / 16) * 64, result = generate(spec(count), budget);
  assert.equal(result.plan.tasks.length, Math.ceil(count / 16));
  const paths = result.plan.tasks.flatMap((task, i) => {
    assert.equal(task.id, 't-openapi-get-contract-' + String(i + 1).padStart(2, '0'));
    assert.equal(task.maxRequests, 64); assert.equal(task.engine, 'schemathesis');
    if (task.engine !== 'schemathesis') throw Error('unexpected_engine');
    assert.ok(task.operations.length <= 16); assert.equal(task.schema, 'openapi'); return task.operations;
  });
  assert.deepEqual(paths, Array.from({ length: count }, (_, i) => '/p' + i).sort());
  assert.equal(new Set(paths).size, count);
  assert.equal(result.plan.tasks.reduce((sum, task) => sum + task.maxRequests, 0), budget);
  assert.deepEqual(parseExecutionPlan(result.plan), result.plan);
});

test('257 operations and the sum of all task request caps are rejected before publication', () => {
  refuses(() => generate(spec(257), 20000), 'operation_limit');
  for (const [count, budget, required] of [[17, 64, 128], [17, 127, 128], [256, 1023, 1024]]) {
    assert.throws(() => generate(spec(count), budget), (error: any) => error.message === 'insufficient_budget' && error.requiredBudget === required);
  }
  const small = encode({ ...JSON.parse(preset.toString()), maxRequests: 15 });
  refuses(() => generate(spec(16), 64, small), 'insufficient_budget');
});

test('explicit GET selection is exact, case-sensitive, unique and codepoint ordered', () => {
  const bytes = encode({ openapi: '3.1.0', paths: Object.fromEntries(['/a', '/Z', '/a/', '/A'].map(path => [path, { get: {} }])) });
  const choose = (paths: string[]) => encode({ ...JSON.parse(preset.toString()), operations: paths.map(pathTemplate => ({ method: 'GET', pathTemplate })) });
  const first = generate(bytes, 64, choose(['/a/', '/A', '/Z'])), second = generate(bytes, 64, choose(['/Z', '/a/', '/A']));
  assert.deepEqual(first.plan, second.plan);
  assert.deepEqual((first.plan.tasks[0] as any).operations, ['/A', '/Z', '/a/']);
  assert.notEqual(first.provenance.preset.sha256, second.provenance.preset.sha256);
  refuses(() => generate(bytes, 64, choose(['/missing'])), 'surface_not_in_inventory');
  refuses(() => generate(bytes, 64, choose(['/A', '/missing'])), 'surface_not_in_inventory');
  refuses(() => generate(bytes, 64, choose(['/a', '/a'])), 'invalid_preset');
  refuses(() => generate(bytes, 64, encode({ ...JSON.parse(preset.toString()), operations: [{ method: 'POST', pathTemplate: '/a' }] })), 'invalid_preset');
});

test('preset bounds and exact keys forbid commands, credentials and invalid budgets', () => {
  const bytes = spec(1), parsed = JSON.parse(preset.toString());
  for (const patch of [{ seed: 0 }, { seed: 2147483648 }, { seed: 1.5 }, { maxRequests: 0 }, { maxRequests: 65 }, { maxRequests: '64' },
    { id: 'other' }, { command: 'CANARY' }, { credential: 'CANARY' }, { operations: [] }, { operations: 'unknown' }]) {
    refuses(() => generate(bytes, 64, encode({ ...parsed, ...patch })), 'invalid_preset');
  }
  assert.equal(generate(bytes, 1, encode({ ...parsed, seed: 2147483647, maxRequests: 1 })).plan.tasks[0]!.maxRequests, 1);
  for (const budget of [0, 20001, 1.5]) refuses(() => generate(bytes, budget), 'invalid_arguments');
  refuses(() => generate(bytes, 64, Buffer.alloc(65537, 32)), 'input_limit');
});

test('raw OpenAPI binding and full inventory projection reject forged surfaces, counts, scopes and gaps', () => {
  const bytes = spec(2), inv = JSON.parse(inventory(bytes).toString());
  refuses(() => buildPresetBundle(preset, inventory(bytes), Buffer.concat([bytes, Buffer.from(' ')]), 'http://localhost'), 'openapi_digest_mismatch');
  for (const patch of [{ surfaces: [{ method: 'GET', pathTemplate: '/other' }] }, { counts: { ...inv.counts, declaredGetOperations: 99 } },
    { scope: { ...inv.scope, source_routes: 'observed' } }, { unverified: [] }]) {
    refuses(() => buildPresetBundle(preset, encode({ ...inv, ...patch }), bytes, 'http://localhost'), 'inventory_mismatch');
  }
  for (const patch of [{ schema: 'unknown' }, { openapiDigest: 'bad' }, { extra: 'CANARY' }]) {
    refuses(() => buildPresetBundle(preset, encode({ ...inv, ...patch }), bytes, 'http://localhost'), 'invalid_inventory');
  }
});

test('origin is explicit, string-only and limited to the existing unauthenticated HTTP lane', () => {
  const bytes = spec(1);
  refuses(() => buildPresetBundle(preset, inventory(bytes), bytes), 'origin_required');
  assert.equal(buildPresetBundle(preset, inventory(bytes, 'http://localhost:3000'), bytes).plan.origin, 'http://localhost:3000');
  refuses(() => buildPresetBundle(preset, inventory(bytes, 'http://localhost:3000'), bytes, 'http://localhost:3001'), 'origin_mismatch');
  refuses(() => buildPresetBundle(preset, inventory(bytes), bytes, 'https://localhost'), 'preset_https_unsupported');
  for (const url of ['bad', 'http://user:CANARY@host', 'http://host/path', 'http://host?CANARY', 'http://host#CANARY', 'file:///tmp/a']) {
    refuses(() => buildPresetBundle(preset, inventory(bytes), bytes, url), 'invalid_origin');
  }
});

test('preset permits only the three loopback hostnames, including inventory-provided origins', () => {
  const bytes = spec(1);
  for (const url of ['http://127.0.0.1:3000', 'http://[::1]:3000', 'http://localhost:3000']) {
    assert.equal(buildPresetBundle(preset, inventory(bytes), bytes, url).plan.origin, url);
    assert.equal(buildPresetBundle(preset, inventory(bytes, url), bytes).plan.origin, url);
  }
  for (const url of ['http://remote.invalid', 'https://remote.invalid', 'http://192.168.1.2', 'http://10.0.0.1', 'http://172.16.0.1',
    'http://127.0.0.2', 'http://localhost.evil.invalid', 'http://localhost.', 'http://[::ffff:127.0.0.1]']) {
    refuses(() => buildPresetBundle(preset, inventory(bytes), bytes, url), 'preset_remote_unsupported');
    refuses(() => buildPresetBundle(preset, inventory(bytes, url), bytes), 'preset_remote_unsupported');
  }
});

test('existing execution selector remains strict even for an observed inventory', () => {
  for (const get of [{ requestBody: {} }, { callbacks: {} }, { responses: { '200': { $ref: 'https://remote.invalid/CANARY' } } }]) {
    const bytes = encode({ openapi: '3.1.0', paths: { '/p': { get } } });
    assert.throws(() => generate(bytes));
  }
});

test('six files preserve raw bytes and non-circular, reproducible SHA bindings', () => {
  const bytes = spec(17), result = generate(bytes, 128), files = new Map(result.files);
  assert.equal(files.size, 6); assert.deepEqual(generate(bytes, 128).files, result.files);
  assert.equal(result.provenance.planSha256, sha(files.get('execution-plan.json')!));
  for (const input of result.inputs.inputs) assert.equal(input.sha256, sha(files.get(input.path)!));
  assert.equal(result.provenance.inventory.openapiDigest, sha(bytes));
  assert.equal(result.provenance.inventory.sha256, sha(files.get('inventory.json')!));
  assert.equal(result.provenance.preset.sha256, sha(preset));
  assert.deepEqual(files.get('openapi.json'), bytes); assert.deepEqual(files.get('preset.json'), preset);
  const changed = generate(bytes, 128, Buffer.concat([preset, Buffer.from(' ')]));
  assert.deepEqual(changed.plan, result.plan); assert.notEqual(changed.provenance.preset.sha256, result.provenance.preset.sha256);
  assert.throws(() => parseExecutionPlan({ ...result.plan, provenance: result.provenance }));
});

test('CLI generates identical bundles three times under guards against network and child execution', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-preset-')); t.after(() => rm(top, { recursive: true, force: true }));
  const bytes = spec(17); await writeFile(join(top, 'openapi.json'), bytes); await writeFile(join(top, 'inventory.json'), inventory(bytes));
  const marker = join(top, 'unexpected-effect');
  await writeFile(join(top, 'guard.mjs'), `import cp from 'node:child_process';import http from 'node:http';import https from 'node:https';import dns from 'node:dns/promises';import net from 'node:net';import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';const deny=()=>{fs.writeFileSync(${JSON.stringify(marker)},'called');throw Error('effect_forbidden')};for(const [obj,names] of [[cp,['spawn','exec','execFile','execFileSync']],[http,['request','get']],[https,['request','get']],[dns,['lookup','resolve']],[net,['connect','createConnection']]])for(const name of names)obj[name]=deny;syncBuiltinESMExports();`);
  let previous: Buffer[] | undefined;
  for (let i = 0; i < 3; i++) {
    const out = join(top, "out-' $(echo substituted) `echo substituted`-" + i);
    const result = await exec(process.execPath, ['--import', join(top, 'guard.mjs'), 'build/src/cli.js', 'plan', '--preset', resolve('presets/openapi-get-contract.json'),
      '--inventory', join(top, 'inventory.json'), '--openapi', join(top, 'openapi.json'), '--url', 'http://LOCALHOST:3000/', '--max-requests', '128', '--out', out]);
    assert.equal(result.stderr, ''); assert.equal(result.stdout.split('\n')[0], 'Plan status=generated preset=openapi-get-contract tasks=2 operations=17 maxRequests=128');
    assert.ok(result.stdout.includes(PROVENANCE_NOTICE));
    const command = result.stdout.split('\n').find(line => line.includes(' run-plan ')); assert.ok(command);
    // Parse shell words only: the example must never run an active scan in this test.
    const words = await exec('/bin/sh', ['-c', `set -- ${command}; printf '%s\\0' "$@"`]);
    const argv = words.stdout.split('\0').slice(0, -1);
    assert.deepEqual(argv.slice(0, 2), [process.execPath, resolve('build/src/cli.js')]);
    const parsed = parseRunPlanArgs(argv.slice(2)); assert.ok(!('help' in parsed));
    const output = await realpath(out), plan = JSON.parse(await readFile(join(out, 'execution-plan.json'), 'utf8'));
    const sidecar = JSON.parse(await readFile(join(out, 'plan-provenance.json'), 'utf8'));
    assert.equal(parsed.maxRequests, sidecar.maxRequests); assert.equal(parsed.maxRequests, 128);
    assert.equal(parsed.allowedOrigin, plan.origin); assert.equal(parsed.allowedOrigin, 'http://localhost:3000');
    assert.equal(parsed.planFile, join(output, 'execution-plan.json')); assert.equal(parsed.inputsFile, join(output, 'inputs.json'));
    assert.equal(parsed.outDir, join(output, 'run')); assert.equal(parsed.allowPrivate, true); assert.equal(parsed.consent, true);
    await assert.rejects(stat(parsed.outDir), { code: 'ENOENT' });
    const names = (await readdir(out)).sort(); assert.equal(names.length, 6);
    const raw = await Promise.all(names.map(name => readFile(join(out, name))));
    if (previous) assert.deepEqual(raw, previous); previous = raw;
    if (process.platform !== 'win32') { assert.equal((await stat(out)).mode & 0o777, 0o700); for (const name of names) assert.equal((await stat(join(out, name))).mode & 0o777, 0o600); }
  }
  await assert.rejects(stat(marker), { code: 'ENOENT' });
  const valid = ['build/src/cli.js', 'plan', '--preset', resolve('presets/openapi-get-contract.json'), '--inventory', join(top, 'inventory.json'), '--openapi', join(top, 'openapi.json'), '--url', 'http://localhost', '--out', join(top, 'refused')];
  for (const extra of [[], ['--max-requests', '64'], ['--api-policy', 'CANARY'], ['--verify-provenance'], ['--max-requests', '20001'], ['--out', 'CANARY']]) {
    await assert.rejects(exec(process.execPath, [...valid, ...extra]), (error: any) => {
      assert.equal(error.code, 2); assert.equal(error.stdout, '');
      assert.equal(error.stderr, extra.length === 0 || extra[1] === '64' ? 'insufficient_budget required=128\n' : 'invalid_arguments\n'); return true;
    });
  }
  await assert.rejects(stat(join(top, 'refused')), { code: 'ENOENT' });
});

test('input changes have a structured reason and missing paths differ from unsafe paths', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-path-')); t.after(() => rm(top, { recursive: true, force: true }));
  const original = fsp.open; let closed = false, stats = 0;
  t.mock.method(fsp, 'open', async () => ({ stat: async () => ({ isFile: () => true, size: 2, mtimeMs: stats++, ctimeMs: 0 }),
    read: async (buffer: Buffer, _offset: number, _length: number, position: number) => { if (position) return { bytesRead: 0 }; buffer.write('{}'); return { bytesRead: 2 }; }, close: async () => { closed = true; } }));
  const stderr: string[] = [];
  t.mock.method(process.stderr, 'write', (message: any) => { stderr.push(String(message)); return true; });
  syncBuiltinESMExports();
  try {
    await assert.rejects(readJsonInputBytes('/synthetic', 10), (error: any) => error.code === 'input_changed'); assert.equal(closed, true);
    const code = await initDastMain(['init-dast', '--source', top, '--openapi', resolve('benchmarks/fixtures/inventory/existing-live.json'), '--out', join(top, '..', 'unused-publish')]);
    assert.equal(code, 2); assert.deepEqual(stderr, ['input_changed\n']);
  }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  assert.equal(fsp.open, original);
  assert.equal(offlineErrorCode(Object.assign(new Error('CANARY'), { code: 'ENOENT' }), 'invalid_openapi'), 'path_not_found');
  const link = join(top, 'link'); await symlink(top, link);
  await assert.rejects(exec(process.execPath, ['build/src/cli.js', 'init-dast', '--source', link, '--openapi', 'missing', '--out', join(top, 'out')]), (error: any) => error.code === 2 && error.stderr === 'unsafe_path\n');
});

test('write failure removes only our empty directory and preserves existing or nonempty directories', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-publish-')); t.after(() => rm(top, { recursive: true, force: true }));
  const empty = join(top, 'empty'), partial = join(top, 'partial'), existing = join(top, 'existing');
  await mkdir(existing); await writeFile(join(existing, 'sentinel'), 'keep');
  t.mock.method(fsp, 'writeFile', async () => { throw Error('CANARY'); }); syncBuiltinESMExports();
  try { await assert.rejects(writeOfflineBundle(empty, [['inventory.json', '{}']]), { message: 'output_error' }); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  await assert.rejects(stat(empty), { code: 'ENOENT' });
  await assert.rejects(writeOfflineBundle(existing, [['inventory.json', '{}']]), { message: 'output_exists' });
  assert.equal(await readFile(join(existing, 'sentinel'), 'utf8'), 'keep');
  const realWrite = fsp.writeFile; let calls = 0;
  t.mock.method(fsp, 'writeFile', async (...args: any[]) => { if (++calls === 2) throw Error('CANARY'); return (realWrite as any)(...args); }); syncBuiltinESMExports();
  try { await assert.rejects(writeOfflineBundle(partial, [['first.json', '{}'], ['second.json', '{}']]), { message: 'output_error' }); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  assert.deepEqual(await readdir(partial), ['first.json']);
  const cleanup = join(top, 'cleanup-failed');
  t.mock.method(fsp, 'writeFile', async () => { throw Error('CANARY'); });
  t.mock.method(fsp, 'rmdir', async () => { throw Error('SECOND-CANARY'); }); syncBuiltinESMExports();
  try { await assert.rejects(writeOfflineBundle(cleanup, [['inventory.json', '{}']]), { message: 'output_error' }); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  assert.deepEqual(await readdir(cleanup), []);
});

test('CLI reason codes reject invalid data without emitting input strings or publishing a bundle', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-preset-reasons-')); t.after(() => rm(top, { recursive: true, force: true }));
  for (const reason of ['invalid_preset', 'invalid_inventory', 'invalid_openapi', 'openapi_digest_mismatch', 'inventory_mismatch', 'origin_required',
    'origin_mismatch', 'preset_https_unsupported', 'preset_remote_unsupported', 'surface_not_in_inventory', 'no_operations', 'operation_limit', 'inventory_partial', 'input_limit', 'path_not_found', 'output_exists']) {
    let bytes = reason === 'no_operations' ? spec(0) : reason === 'operation_limit' ? spec(257) : spec(1);
    if (reason === 'inventory_partial') bytes = await readFile('benchmarks/fixtures/inventory/unresolved-path-item.json');
    const inv: any = buildSurfaceInventory(bytes), custom: any = JSON.parse(preset.toString());
    let url: string | undefined = 'http://localhost:3000';
    if (reason === 'origin_required') url = undefined;
    if (reason === 'origin_mismatch') inv.origin = 'http://localhost:3001';
    if (reason === 'preset_https_unsupported') url = 'https://localhost';
    if (reason === 'preset_remote_unsupported') url = 'http://192.168.1.2';
    if (reason === 'surface_not_in_inventory') custom.operations = [{ method: 'GET', pathTemplate: '/CANARY' }];
    if (reason === 'inventory_mismatch') inv.counts.enumeratedGetOperations = 42;
    const data = reason === 'invalid_openapi' ? Buffer.from('{CANARY') : reason === 'openapi_digest_mismatch' ? Buffer.concat([bytes, Buffer.from(' ')])
      : reason === 'input_limit' ? Buffer.alloc(1024 * 1024 + 1, 32) : bytes;
    const input = join(top, reason + '-spec.json'), invFile = join(top, reason + '-inventory.json'), presetFile = join(top, reason + '-preset.json'), out = join(top, reason + '-out');
    await writeFile(input, data); await writeFile(invFile, reason === 'invalid_inventory' ? '{CANARY' : encode(inv));
    await writeFile(presetFile, reason === 'invalid_preset' ? '{CANARY' : encode(custom));
    if (reason === 'output_exists') { await mkdir(out); await writeFile(join(out, 'sentinel'), 'keep'); }
    const args = ['build/src/cli.js', 'plan', '--preset', presetFile, '--inventory', invFile, '--openapi', reason === 'path_not_found' ? join(top, 'CANARY-missing') : input,
      '--max-requests', '20000', '--out', out, ...(url ? ['--url', url] : [])];
    await assert.rejects(exec(process.execPath, args), (error: any) => {
      assert.equal(error.code, 2); assert.equal(error.stdout, ''); assert.equal(error.stderr, reason + '\n'); return true;
    });
    if (reason === 'output_exists') assert.equal(await readFile(join(out, 'sentinel'), 'utf8'), 'keep');
    else await assert.rejects(stat(out), { code: 'ENOENT' });
  }
});
