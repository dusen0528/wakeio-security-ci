import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require=createRequire(import.meta.url);

test('experimental agent-dast SDK and reference schema resolve through separate package subpaths',async()=>{
  const sdk=await import(require.resolve('wakeio-security-ci/agent-dast'));
  for (const name of ['parseWorkerResult','validateWorkerResult','failedWorkerResult','openRunStore','RunStore']) assert.equal(typeof sdk[name],'function');
  const schema=JSON.parse(await readFile(require.resolve('wakeio-security-ci/schemas/worker-result.v1.json'),'utf8'));
  assert.equal(schema.$id,sdk.WORKER_RESULT_SCHEMA);
  const root=await import(require.resolve('wakeio-security-ci'));
  assert.equal(Object.hasOwn(root,'openRunStore'),false,'The ordinary root import must not expose the experimental store');
});

test('reference schema changes affect CI source snapshots and schema symlinks remain unsupported',async()=>{
  const {sourceSnapshot}=await import(new URL('../../scripts/ci-process.mjs',import.meta.url).href);
  const root=await mkdtemp(join(tmpdir(),'wakeio-agent-sdk-snapshot-'));
  try {
    await mkdir(join(root,'schemas'));
    const schema=join(root,'schemas/worker-result.v1.json');
    await writeFile(schema,'{"type":"object"}');
    const before=sourceSnapshot(root);
    assert.equal(before.fileCount,1);assert.match(before.scope,/schemas/);
    await writeFile(schema,'{"type":"object","additionalProperties":false}');
    assert.notEqual(sourceSnapshot(root).sha256,before.sha256);
    await rm(schema);
    await writeFile(join(root,'outside.json'),'{}');
    await symlink(join(root,'outside.json'),schema);
    assert.throws(()=>sourceSnapshot(root),/source_symlink_unsupported/);
  } finally {await rm(root,{recursive:true,force:true});}
});
