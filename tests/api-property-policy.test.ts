import test from 'node:test';
import assert from 'node:assert/strict';
import { parseApiPropertyPolicy, parsePropertyJsonText, type ApiPropertyPolicyV1 } from '../src/api-property-policy.js';
import { preflightApiPropertyWrite, runApiPropertyWrite } from '../src/api-property-write.js';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';

function policy(): ApiPropertyPolicyV1 {
  return { version: 1, origin: 'http://127.0.0.1:19999', declarations: { disposable: true, staging: true, sharedStrongEtag: true, normalNonceFormat: 'wakeio-property-v1' },
    actors: { owner: { authorizationEnv: 'OWNED_OWNER', identity: { path: '/identity', pointer: '/id', equals: 'owner' } },
      verifier: { authorizationEnv: 'OWNED_VERIFIER', identity: { path: '/identity', pointer: '/id', equals: 'verifier' } } },
    resource: { path: '/items/owned', id: { pointer: '/id', equals: 'owned' }, ownerPointer: '/owner', runMarker: { pointer: '/marker', equals: 'owned-run-marker-123456' } },
    normal: { field: 'name', initial: 'initial' }, protected: { field: 'privileged', initial: false, probe: true, control: true } };
}
const env = { OWNED_OWNER: 'Bearer owned-owner', OWNED_VERIFIER: 'Bearer owned-verifier' };
test('property policy snapshots data and rejects executable/unknown/overlapping shapes', () => {
  const original = policy(), parsed = parseApiPropertyPolicy(original); original.normal.field = 'changed'; assert.equal(parsed.normal.field, 'name');
  for (const modify of [
    (p: any) => { p.extra = true; }, (p: any) => { p.ignore = ['/updatedAt']; },
    (p: any) => { p.resource.path = '//other.example/item'; }, (p: any) => { p.resource.path = '/a/../b'; },
    (p: any) => { p.resource.path = '/a%2fb'; }, (p: any) => { p.resource.ownerPointer = '/name/id'; },
    (p: any) => { p.protected.initial = null; }, (p: any) => { p.protected.probe = 'true'; },
    (p: any) => { p.actors.verifier.identity.equals = 'owner'; }, (p: any) => { p.normal.field = '__proto__'; },
    (p: any) => { p.normal.initial = '한'.repeat(1024); p.protected = { field: 'privileged', initial: '한'.repeat(1024), probe: 'probe', control: 'control' }; },
  ]) { const p = policy(); modify(p); assert.throws(() => parseApiPropertyPolicy(p)); }
  let getters = 0;
  const accessor = policy(); Object.defineProperty(accessor, 'origin', { enumerable: true, get() { getters++; return 'http://127.0.0.1'; } });
  assert.throws(() => parseApiPropertyPolicy(accessor)); assert.equal(getters, 0);
  assert.throws(() => parseApiPropertyPolicy(new Proxy(policy(), { get() { throw new Error('must not run'); } })));
});
test('property JSON parser rejects duplicate, escaped duplicate and prototype keys', () => {
  for (const value of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"nested":{"__proto__":1}}']) assert.throws(() => parsePropertyJsonText(value));
  assert.deepEqual(JSON.parse(JSON.stringify(parsePropertyJsonText('{"a":[{"a":1}],"b":"{\\\"a\\\":2}"}'))), { a: [{ a: 1 }], b: '{"a":2}' });
});
test('offline property preflight has no target/credential data and refuses missing, duplicate and accessor credentials', () => {
  const ready = preflightApiPropertyWrite({ policy: policy(), allowPrivate: true, env });
  assert.equal(ready.status, 'ready'); assert.equal(ready.execution, 'not_run');
  assert.equal(preflightApiPropertyWrite({ policy: policy(), allowPrivate: true, env: {} }).status, 'blocked');
  assert.equal(preflightApiPropertyWrite({ policy: policy(), allowPrivate: true, env: { OWNED_OWNER: 'same', OWNED_VERIFIER: 'same' } }).status, 'blocked');
  assert.equal(preflightApiPropertyWrite({ policy: policy(), allowPrivate: true, env: { ...env, OWNED_OWNER: 'Bearer 한글' } }).status, 'blocked');
  let reads = 0; const accessor = Object.defineProperty({}, 'OWNED_OWNER', { get() { reads++; return 'secret'; } });
  assert.equal(preflightApiPropertyWrite({ policy: policy(), allowPrivate: true, env: accessor }).status, 'blocked'); assert.equal(reads, 0);
  const text = JSON.stringify(ready); assert(!text.includes('19999')); assert(!text.includes('OWNED_OWNER')); assert(!text.includes('Bearer'));
});
test('insufficient property request budget refuses before HTTP with a valid redacted partial ledger', async () => {
  const [check] = await runApiPropertyWrite({ policy: policy(), activeConsent: true, allowPrivate: true, env, maxRequests: 21 });
  assert.equal(check.status, 'partial'); assert.equal(check.propertyWriteEvidence!.stopReason, 'request_limit');
  assert.equal(check.propertyWriteEvidence!.counts.httpAttempts, 0); assert.equal(check.findings.length, 0);
});
test('offline CLI accepts the stable macOS tmp alias but refuses a policy-file symlink', async () => {
  const directory = await mkdtemp('/tmp/wakeio-property-policy-');
  try {
    const file = join(directory, 'policy.json'); await writeFile(file, JSON.stringify(policy()), { mode: 0o600 });
    const run = promisify(execFile), command = resolve('build/src/cli.js');
    const result = await run(process.execPath, [command, 'api-property-write', '--policy', file, '--preflight', '--allow-private'], { env: { ...process.env, ...env } });
    assert.equal(JSON.parse(result.stdout).execution, 'not_run'); assert.equal(JSON.parse(result.stdout).status, 'ready');
    const link = join(directory, 'link.json'); await symlink(file, link);
    await assert.rejects(run(process.execPath, [command, 'api-property-write', '--policy', link, '--preflight', '--allow-private'], { env: { ...process.env, ...env } }));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
