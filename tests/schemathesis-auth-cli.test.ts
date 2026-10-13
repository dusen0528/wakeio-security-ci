import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { parseCliArgs } from '../src/cli.js';

const exec = promisify(execFile);
const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const ACTION = fileURLToPath(new URL('../../scripts/action-run.mjs', import.meta.url));
const scan = ['scan', '--openapi', 'owned-schema.json', '--api-base', 'http://127.0.0.1:1/', '--operation', '/items/{id}', '--active-consent'];

async function child(entry: string, args: string[], env: NodeJS.ProcessEnv, cwd: string) {
  try { const result = await exec(process.execPath, [entry, ...args], { cwd, env, timeout: 15_000, maxBuffer: 256 * 1024 });
    return { code: 0, text: result.stdout + result.stderr }; }
  catch (error) { const failure = error as { code?: number; stdout?: string; stderr?: string };
    if (typeof failure.code !== 'number') throw error;
    return { code: failure.code, text: String(failure.stdout ?? '') + String(failure.stderr ?? '') }; }
}

test('Schemathesis auth CLI requires OpenAPI selections and consent, with a single explicit policy file', () => {
  const parsed = parseCliArgs([...scan, '--schemathesis-auth-policy', 'owned-auth.json']);
  assert.ok(!('help' in parsed)); assert.equal(parsed.schemathesisAuthPolicy, 'owned-auth.json');
  for (const args of [
    ['scan', '--schemathesis-auth-policy', 'owned-auth.json'],
    ['scan', '--source', '.', '--schemathesis-auth-policy', 'owned-auth.json'],
    [...scan.filter(value => value !== '--active-consent'), '--schemathesis-auth-policy', 'owned-auth.json'],
    ['scan', '--openapi', 'owned-schema.json', '--active-consent', '--schemathesis-auth-policy', 'owned-auth.json'],
    [...scan, '--schemathesis-auth-policy', 'owned-auth.json', '--schemathesis-auth-policy=second.json'],
  ]) assert.throws(() => parseCliArgs(args));
});

test('Schemathesis auth CLI invalid bounded policy inputs retain required-auth errors and all four reports', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-auth-cli-input-'));
  try {
    await writeFile(join(top, 'invalid.json'), JSON.stringify({ secretExtra: 'owned-private-policy-canary' }));
    await writeFile(join(top, 'oversized.json'), ' '.repeat(64 * 1024 + 1));
    await symlink(join(top, 'invalid.json'), join(top, 'linked.json'));
    for (const name of ['invalid.json', 'oversized.json', 'linked.json', 'missing.json']) {
      const out = join(top, name + '-reports');
      const result = await child(CLI, [...scan, '--schemathesis-auth-policy', join(top, name), '--out', out, '--tools', 'none'],
        { PATH: process.env.PATH }, top);
      assert.equal(result.code, 2, result.text);
      const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8'));
      assert.equal(report.checks.length, 1); assert.equal(report.checks[0].id, 'api.schemathesis');
      assert.equal(report.checks[0].schemathesisAuthRequired, true); assert.notEqual(report.checks[0].status, 'completed');
      for (const artifact of ['report.json', 'report.md', 'report.sarif', 'agent-report.json']) {
        const text = await readFile(join(out, artifact), 'utf8');
        assert.equal(text.includes('owned-private-policy-canary'), false);
      }
      assert.equal(result.text.includes('owned-private-policy-canary'), false);
    }
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('Schemathesis auth CLI scope binds canonical policy and selected schema without exposing private inputs', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-auth-cli-scope-'));
  const policy = { version: 1, kind: 'schemathesis-get-auth', baseUrl: 'http://127.0.0.1:1/', authorizationEnv: 'OWNED_SCOPE_AUTH',
    identity: { path: '/whoami', status: 200, jsonPointer: '/principal', equals: 'owned-private-principal' },
    operations: [{ path: '/items/{id}', normal: { path: '/items/1', status: 200, jsonPointer: '/marker', equals: 'owned-private-marker' } }] };
  const schema = { openapi: '3.0.3', info: { title: 'Owned fixture', version: '1.0.0' }, paths: { '/items/{id}': { get: {
    parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer', minimum: 1, maximum: 2 } }],
    responses: { '200': { description: 'Owned response' } },
  } } } };
  try {
    const fingerprints: string[] = [], policyHashes: string[] = [], schemaHashes: string[] = [];
    const reordered = { operations: policy.operations, identity: policy.identity, authorizationEnv: policy.authorizationEnv,
      baseUrl: policy.baseUrl, kind: policy.kind, version: policy.version };
    for (const [index, changed] of [policy, reordered, { ...policy, identity: { ...policy.identity, equals: 'owned-other-private-principal' } }, policy].entries()) {
      const schemaFile = join(top, 'owned-schema.json'), policyFile = join(top, 'owned-auth.json'), out = join(top, `reports-${index}`);
      await writeFile(schemaFile, JSON.stringify(index === 3 ? { ...schema, info: { ...schema.info, version: '1.0.1' } } : schema));
      await writeFile(policyFile, JSON.stringify(changed));
      const result = await child(CLI, ['scan', '--openapi', schemaFile, '--api-base', policy.baseUrl, '--operation', '/items/{id}',
        '--schemathesis-auth-policy', policyFile, '--active-consent', '--allow-private', '--tools', 'none', '--out', out],
        { PATH: process.env.PATH }, top);
      assert.equal(result.code, 2, result.text);
      const text = await readFile(join(out, 'report.json'), 'utf8'), report = JSON.parse(text), scoped = report.scope.schemathesisAuthPolicy;
      assert.equal(report.checks[0].schemathesisAuthRequired, true); assert.notEqual(report.checks[0].status, 'completed');
      assert.equal(scoped.profileRevision, 'schemathesis-get-auth-v1');
      fingerprints.push(report.scope.fingerprint); policyHashes.push(scoped.policySha256); schemaHashes.push(scoped.schemaSha256);
      for (const privateValue of [policy.authorizationEnv, policy.identity.equals, policy.operations[0].normal.equals, 'owned-other-private-principal']) {
        assert.equal(text.includes(privateValue), false); assert.equal(result.text.includes(privateValue), false);
      }
    }
    assert.equal(fingerprints[0], fingerprints[1]); assert.equal(policyHashes[0], policyHashes[1]);
    assert.notEqual(fingerprints[0], fingerprints[2]); assert.notEqual(policyHashes[0], policyHashes[2]); assert.equal(schemaHashes[0], schemaHashes[2]);
    assert.notEqual(fingerprints[0], fingerprints[3]); assert.equal(policyHashes[0], policyHashes[3]); assert.notEqual(schemaHashes[0], schemaHashes[3]);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('Schemathesis auth Action preflight requires OpenAPI and preserves consent, origin and fork refusals', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-auth-action-plan-'));
  try {
    const output = join(top, 'outputs'), event = join(top, 'event.json');
    await writeFile(event, JSON.stringify({ pull_request: { head: { repo: { full_name: 'other/app' } }, base: { repo: { full_name: 'owned/app' } } } }));
    const base = { PATH: process.env.PATH, WAKEIO_MODE: 'dast-preflight', GITHUB_WORKSPACE: top, GITHUB_OUTPUT: output,
      GITHUB_EVENT_NAME: 'workflow_dispatch', WAKEIO_ACTIVE_CONSENT: 'true', WAKEIO_ALLOWED_ORIGINS: 'https://owned.invalid',
      WAKEIO_API_BASE: 'https://owned.invalid/', WAKEIO_OPERATIONS: '/items/{id}', WAKEIO_OPENAPI: 'owned-schema.json',
      WAKEIO_SCHEMATHESIS_AUTH_POLICY: 'owned-auth.json', OWNED_AUTHORIZATION: 'Bearer owned-private-action-canary' };
    for (const extra of [{ WAKEIO_OPENAPI: '' }, { WAKEIO_ACTIVE_CONSENT: '' }, { WAKEIO_ALLOWED_ORIGINS: 'https://other.invalid' },
      { GITHUB_EVENT_NAME: 'pull_request_target' }, { GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: event }]) {
      await writeFile(output, '');
      const result = await child(ACTION, [], { ...base, ...extra }, top);
      assert.equal(result.code, 0, result.text); assert.match(result.text, /preflight refused/);
      assert.equal(await readFile(output, 'utf8'), 'prepare-schemathesis=false\n');
      assert.equal(result.text.includes(base.OWNED_AUTHORIZATION), false);
    }
    await writeFile(output, ''); const ready = await child(ACTION, [], base, top);
    assert.equal(ready.code, 0, ready.text); assert.equal(await readFile(output, 'utf8'), 'prepare-schemathesis=true\n');
  } finally { await rm(top, { recursive: true, force: true }); }
});
