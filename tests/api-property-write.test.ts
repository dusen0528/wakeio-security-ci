import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { runApiPropertyWrite } from '../src/api-property-write.js';
import type { ApiPropertyPolicyV1 } from '../src/api-property-policy.js';
import { parseApiPropertyWriteEvidence } from '../src/api-property-evidence.js';
import { createReport, exitCode } from '../src/report.js';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

type Mode = 'vulnerable' | 'deny' | 'ignore' | 'ignored-owner-cas' | 'ignored-verifier-cas' | 'cleanup-fail' | 'metadata' | 'missing-etag' | 'barrier-conflict' | 'async' | 'cancel';
async function owned(mode: Mode, controller?: AbortController) {
  const state: Record<string, unknown> = { id: 'resource-owned', owner: 'actor-owner', marker: 'owned-run-marker-123456', name: 'baseline', privileged: false, extra: { unchanged: [1, 2] } };
  const arrivals: Array<{ method: string; authorization: string; body: Record<string, unknown> }> = [];
  let patches = 0;
  const etag = () => '"' + createHash('sha256').update(JSON.stringify(state)).digest('hex') + '"';
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const part of request) chunks.push(Buffer.from(part));
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) as Record<string, unknown> : {};
    const owner = request.headers.authorization === 'Bearer owned-owner';
    arrivals.push({ method: request.method!, authorization: request.headers.authorization ?? '', body });
    response.setHeader('content-type', 'application/json');
    if (request.url === '/identity') { response.end(JSON.stringify({ id: owner ? 'actor-owner' : 'actor-verifier' })); return; }
    if (request.method === 'PATCH') {
      patches++;
      if (mode === 'cancel' && patches === 3) { controller!.abort(); return; }
      if (mode === 'barrier-conflict' && patches === 7) { response.writeHead(412); response.end('{}'); return; }
      if (request.headers['if-match'] !== etag() && !(mode === 'ignored-owner-cas' && owner || mode === 'ignored-verifier-cas' && !owner)) {
        response.writeHead(412); response.end('{}'); return;
      }
      if (mode === 'cleanup-fail' && patches === 8) { response.writeHead(500); response.end('{}'); return; }
      if (mode === 'async' && patches === 3) { response.writeHead(202); response.end('{}'); return; }
      if (owner && Object.hasOwn(body, 'privileged') && mode === 'deny') { response.writeHead(403); response.end('{}'); return; }
      for (const [key, value] of Object.entries(body)) if (!(owner && key === 'privileged' && mode === 'ignore')) state[key] = value;
      if (mode === 'metadata' && patches === 3) state.updatedAt = 'changed';
      response.writeHead(204); response.end(); return;
    }
    if (mode !== 'missing-etag') response.setHeader('etag', etag());
    response.end(JSON.stringify(state));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert(address && typeof address !== 'string');
  const policy: ApiPropertyPolicyV1 = { version: 1, origin: `http://127.0.0.1:${address.port}`,
    declarations: { disposable: true, staging: true, sharedStrongEtag: true, normalNonceFormat: 'wakeio-property-v1' },
    actors: { owner: { authorizationEnv: 'OWNED_OWNER', identity: { path: '/identity', pointer: '/id', equals: 'actor-owner' } },
      verifier: { authorizationEnv: 'OWNED_VERIFIER', identity: { path: '/identity', pointer: '/id', equals: 'actor-verifier' } } },
    resource: { path: '/resource', id: { pointer: '/id', equals: 'resource-owned' }, ownerPointer: '/owner', runMarker: { pointer: '/marker', equals: 'owned-run-marker-123456' } },
    normal: { field: 'name', initial: 'baseline' }, protected: { field: 'privileged', initial: false, probe: true, control: true } };
  return { policy, state, arrivals, close: async () => { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); } };
}
const env = { OWNED_OWNER: 'Bearer owned-owner', OWNED_VERIFIER: 'Bearer owned-verifier' };
test('owned property effect and strict403/ignored-field normal controls complete the exact22/8 protocol and restore state', async () => {
  for (const mode of ['vulnerable', 'deny', 'ignore'] as const) {
    const target = await owned(mode);
    try {
      const [check] = await runApiPropertyWrite({ policy: target.policy, activeConsent: true, allowPrivate: true, env });
      assert.equal(check.status, 'completed', JSON.stringify(check.propertyWriteEvidence));
      const evidence = check.propertyWriteEvidence!;
      assert(parseApiPropertyWriteEvidence(evidence));
      assert.equal(evidence.counts.httpAttempts, 22); assert.equal(evidence.counts.patchAttempts, 8);
      assert.equal(evidence.effect, mode === 'vulnerable' ? 'observed' : 'not_observed'); assert.equal(evidence.cleanup, 'confirmed');
      assert.equal(exitCode(createReport([check], 'api', new Date()), 'high'), mode === 'vulnerable' ? 1 : 0);
      assert.equal(target.state.name, 'baseline'); assert.equal(target.state.privileged, false);
      const ownerProbe = target.arrivals[14]!; assert.deepEqual(ownerProbe.body, { privileged: true });
      assert.deepEqual(Object.keys(target.arrivals[16]!.body), ['name']);
      assert.match(String(target.arrivals[16]!.body.name), /^wakeio-property-v1-[a-f0-9]{32}$/);
      assert(!JSON.stringify(check).includes('Bearer owned')); assert(!JSON.stringify(check).includes('owned-run-marker'));
    } finally { await target.close(); }
  }
});
test('each actor CAS control is independent and failure permits no later writes or effect', async () => {
  for (const mode of ['ignored-owner-cas', 'ignored-verifier-cas'] as const) {
    const target = await owned(mode);
    try {
      const [check] = await runApiPropertyWrite({ policy: target.policy, activeConsent: true, allowPrivate: true, env });
      assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 0);
      assert.equal(check.propertyWriteEvidence!.stopReason, 'precondition_not_enforced');
      assert.equal(target.arrivals.filter(row => row.method === 'PATCH').length, mode === 'ignored-owner-cas' ? 1 : 2);
      assert(parseApiPropertyWriteEvidence(check.propertyWriteEvidence));
    } finally { await target.close(); }
  }
});
test('freshness conflict, dynamic unmodeled metadata, missing validator and asynchronous writes never complete cleanly', async () => {
  for (const mode of ['barrier-conflict', 'metadata', 'missing-etag', 'async'] as const) {
    const target = await owned(mode);
    try {
      const [check] = await runApiPropertyWrite({ policy: target.policy, activeConsent: true, allowPrivate: true, env });
      assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 0); assert.equal(check.propertyWriteEvidence!.effect, 'unknown');
      assert(parseApiPropertyWriteEvidence(check.propertyWriteEvidence), JSON.stringify(check.propertyWriteEvidence));
      if (mode === 'missing-etag') assert.equal(check.propertyWriteEvidence!.counts.patchAttempts, 0);
      if (mode === 'barrier-conflict') assert.equal(check.propertyWriteEvidence!.counts.patchAttempts, 7);
    } finally { await target.close(); }
  }
});
test('observed API effect is retained when cleanup fails, with partial gate and no write recovery', async () => {
  const target = await owned('cleanup-fail');
  try {
    const [check] = await runApiPropertyWrite({ policy: target.policy, activeConsent: true, allowPrivate: true, env });
    assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 1); assert.equal(check.propertyWriteEvidence!.effect, 'observed');
    assert.equal(check.propertyWriteEvidence!.cleanup, 'unknown'); assert.equal(check.propertyWriteEvidence!.counts.patchAttempts, 8);
    assert.equal(exitCode(createReport([check], 'api', new Date()), 'none'), 2);
    assert(parseApiPropertyWriteEvidence(check.propertyWriteEvidence));
  } finally { await target.close(); }
});
test('cancellation during an owned write stops all laterHTTP including cleanup and preserves exact attempts', async () => {
  const controller = new AbortController(), target = await owned('cancel', controller);
  try {
    const [check] = await runApiPropertyWrite({ policy: target.policy, activeConsent: true, allowPrivate: true, env, signal: controller.signal });
    assert.equal(check.propertyWriteEvidence!.stopReason, 'cancelled'); assert.equal(check.propertyWriteEvidence!.counts.httpAttempts, 9);
    assert.equal(target.arrivals.length, 9); assert.equal(check.propertyWriteEvidence!.counts.patchAttempts, 3);
    assert.equal(check.propertyWriteEvidence!.cleanup, 'unknown'); assert(parseApiPropertyWriteEvidence(check.propertyWriteEvidence));
  } finally { await target.close(); }
});
test('delivery-phase cancellation rewrites all four reports with partial command status and preserves effect without HTTP replay', async () => {
  const target = await owned('vulnerable'), directory = await mkdtemp(join(tmpdir(), 'wakeio-property-delivery-'));
  try {
    const policyFile = join(directory, 'policy.json'), out = join(directory, 'reports');
    await writeFile(policyFile, JSON.stringify(target.policy), { mode: 0o600 });
    const script = `import fsp from 'node:fs/promises';import {syncBuiltinESMExports} from 'node:module';
      const rename=fsp.rename;let fired=false;fsp.rename=async(...args)=>{await rename(...args);if(!fired&&String(args[1]).endsWith('/report.json')){fired=true;process.emit('SIGINT');}};syncBuiltinESMExports();
      const {apiPropertyWriteMain}=await import(${JSON.stringify(pathToFileURL(resolve('build/src/api-property-cli.js')).href)});
      process.exitCode=await apiPropertyWriteMain(['api-property-write','--policy',${JSON.stringify(policyFile)},'--active-consent','--allow-private','--out',${JSON.stringify(out)}]);
      if(!fired)throw Error('delivery seam not reached');`;
    let stdout = '';
    try { await promisify(execFile)(process.execPath, ['--input-type=module', '-e', script], { env: { ...process.env, ...env } }); assert.fail('must exit2'); }
    catch (error) { const result = error as Error & { code?: number; stdout?: string }; assert.equal(result.code, 2); stdout = result.stdout ?? ''; }
    const summary = JSON.parse(stdout.trim()); assert.equal(summary.execution, 'partial'); assert.equal(summary.finalExitCode, 2);
    const report = JSON.parse(await readFile(join(out, 'report.json'), 'utf8'));
    assert.equal(report.checks.find((check: any) => check.id === 'api.property-write').propertyWriteEvidence.effect, 'observed');
    assert.equal(report.checks.find((check: any) => check.id === 'scan.cancelled').status, 'partial');
    assert.equal(JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8')).scanGate.exitCode, 2);
    assert.equal(JSON.parse(await readFile(join(out, 'report.sarif'), 'utf8')).runs[0].invocations[0].executionSuccessful, false);
    assert.match(await readFile(join(out, 'report.md'), 'utf8'), /Declared work is incomplete/);
    assert.equal(target.arrivals.length, 22); assert.equal(target.state.name, 'baseline'); assert.equal(target.state.privileged, false);
  } finally { await target.close(); await rm(directory, { recursive: true, force: true }); }
});
