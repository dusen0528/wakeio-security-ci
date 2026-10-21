import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { mkdtemp, readFile, writeFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { compileZapOpenApi, reconstructZapBody, type ZapOpenApiInput } from '../src/zap-openapi.js';

const exec = promisify(execFile), cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
function input(schema: object, schemas: object = {}): ZapOpenApiInput {
  return { document: { openapi: '3.0.3', paths: { '/filter': { post: {
    requestBody: { content: { 'application/json': { schema } } }, responses: { '200': { description: 'OK' } },
  } } }, components: { schemas } }, operations: [{ method: 'POST', path: '/filter' }] };
}
function amplified(leaf: object): ZapOpenApiInput {
  const schemas: Record<string, object> = { Leaf: leaf }; let next = 'Leaf';
  for (let level = 0; level < 5; level++) {
    const key = 'Level' + level;
    schemas[key] = { type: 'object', properties: Object.fromEntries(Array.from({ length: 32 }, (_, i) => ['p' + i, { $ref: '#/components/schemas/' + next }])) };
    next = key;
  }
  return input({ $ref: '#/components/schemas/' + next }, schemas);
}
const objectSchema = (body: Record<string, string>) => ({ type: 'object', properties: Object.fromEntries(Object.keys(body).map(k => [k, { type: 'string' }])) });

test('ZAP OpenAPI memory: shared references reject without exhausting a 64 MiB heap', { timeout: 10000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-memory-'));
  try {
    const cases = [{ type: 'string', default: 'x' }, { type: 'boolean' }, { type: 'null' }, { type: 'object', properties: {} }].map(amplified);
    let array: object = { type: 'string', default: 'x'.repeat(512) };
    for (let i = 0; i < 5; i++) array = { type: 'array', minItems: 8, items: array };
    cases.push(input({ type: 'object', properties: { data: array } }));
    const file = join(top, 'inputs.json'); await writeFile(file, JSON.stringify(cases));
    const source = `import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
      import {compileZapOpenApi} from ${JSON.stringify(new URL('../src/zap-openapi.js', import.meta.url).href)};
      const cases=JSON.parse(await readFile(process.argv[1],'utf8'));
      for(const value of cases) assert.throws(()=>compileZapOpenApi(value),/invalid_zap_openapi/);
      console.log(JSON.stringify({rejected:cases.length}));`;
    const result = await exec(process.execPath, ['--max-old-space-size=64', '--input-type=module', '-e', source, file], { timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 128 * 1024, cwd: top });
    assert.equal(JSON.parse(result.stdout).rejected, cases.length);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('ZAP OpenAPI memory: encoded byte and field boundaries keep independent valid operations', () => {
  const body = Object.fromEntries(Array.from({ length: 16 }, (_, i) => ['p' + i, i === 15 ? '' : 'x'.repeat(512)]));
  body.p15 = 'x'.repeat(8192 - Buffer.byteLength(JSON.stringify(body)));
  assert.equal(Buffer.byteLength(JSON.stringify(body)), 8192);
  const value = input(objectSchema(body)); value.operations[0]!.body = body;
  const compiled = compileZapOpenApi(value).requests[0]!;
  assert.equal(compiled.fields!.length, 16); assert.deepEqual(reconstructZapBody(compiled, compiled.body!), body);
  value.operations[0]!.body = { ...body, p15: body.p15 + 'x' }; assert.throws(() => compileZapOpenApi(value), /invalid_zap_openapi/);
  const encoded = Object.fromEntries(Array.from({ length: 12 }, (_, i) => ['p' + i, '한"\\'.repeat(100)]));
  assert.ok(JSON.stringify(encoded).length < 8192); assert.ok(Buffer.byteLength(JSON.stringify(encoded)) > 8192);
  const utf8 = input(objectSchema(encoded)); utf8.operations[0]!.body = encoded; assert.throws(() => compileZapOpenApi(utf8), /invalid_zap_openapi/);
  const seventeen = input({ type: 'object', properties: Object.fromEntries(Array.from({ length: 17 }, (_, i) => ['p' + i, { type: 'string' }])) });
  assert.throws(() => compileZapOpenApi(seventeen), /invalid_zap_openapi/);
  const paths = Object.fromEntries(Array.from({ length: 16 }, (_, i) => ['/filter' + i, (value.document as any).paths['/filter']]));
  const many = { document: { ...(value.document as any), paths }, operations: Object.keys(paths).map(path => ({ method: 'POST' as const, path, body })) };
  assert.equal(compileZapOpenApi(many).requests.length, 16);
});

test('ZAP OpenAPI memory: public plan scan and run-plan refuse amplification with zero target traffic', { timeout: 20000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-memory-cli-')); let requests = 0;
  const server = createServer((_req, res) => { requests++; res.end('{}'); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const bytes = JSON.stringify({ version: 2, kind: 'zap-active', origin, openapi: amplified({ type: 'boolean' }) });
    const policy = join(top, 'policy.json'); await writeFile(policy, bytes);
    const plan = join(top, 'plan.json'), inputs = join(top, 'inputs.json'), out = join(top, 'run');
    await writeFile(plan, JSON.stringify({ version: 1, kind: 'wakeio.execution-plan', origin, tasks: [{ id: 't-zap', engine: 'zap', policy: 'owner', maxRequests: 200 }] }));
    await writeFile(inputs, JSON.stringify({ version: 1, inputs: [{ id: 'owner', path: 'policy.json', sha256: createHash('sha256').update(bytes).digest('hex') }] }));
    const args = [
      ['plan', '--zap-policy', policy, '--allow-private'],
      ['scan', '--url', origin, '--engine', 'zap', '--zap-policy', policy, '--zap', join(top, 'must-not-run'), '--active-consent', '--allow-private', '--tools', 'none', '--fail-on', 'none', '--out', join(top, 'scan')],
      ['run-plan', '--plan', plan, '--inputs', inputs, '--active-consent', '--allowed-origin', origin, '--allow-private', '--out', out],
    ];
    for (const argv of args) {
      await assert.rejects(exec(process.execPath, ['--max-old-space-size=64', cli, ...argv], { timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 128 * 1024, cwd: top }), (error: any) => {
        assert.equal(error.code, 2, error.stderr); assert.equal(error.signal, null);
        if (argv[0] === 'plan') { const result = JSON.parse(error.stdout); assert.equal(result.status, 'blocked'); assert.equal(result.networkRequests, 0); }
        if (argv[0] === 'run-plan') { const result = JSON.parse(error.stdout); assert.equal(result.exitCode, 2); assert.equal(result.requests.requestCount, 0); assert.equal(result.outDir, null); }
        return true;
      });
      assert.equal(requests, 0);
    }
    const report = JSON.parse(await readFile(join(top, 'scan/report.json'), 'utf8'));
    assert.ok(report.checks.some((check: any) => check.id === 'url.zap' && check.status === 'error' && check.notes.some((note: string) => /policy.*invalid/.test(note))));
    await assert.rejects(access(out));
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await rm(top, { recursive: true, force: true }); }
});
