import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { isBuiltin } from 'node:module';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import ts from 'typescript';
import { PG_PARSER_PIN, PG_PARSER_PROTOCOL_REVISION } from '../src/runtime/observers/pg-parser-helper.js';

const exec = promisify(execFile), root = process.cwd(), directory = 'workers/pg-parser';
const protocol = 'wakeio.pg-parser/v1';
const assetNames = ['pg-parser-worker.cjs', 'libpg-query.wasm', 'THIRD_PARTY_LICENSES.txt',
  'LICENSE.libpg_query', 'COPYRIGHT.PostgreSQL'];
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
type Ref = { path: string; bytes: number; sha256: string };
type Manifest = {
  schemaVersion: string; kind: string; protocolRevision: string;
  pin: { version: string; pgMajor: number; lockSha256: string; wasmSha256: string };
  assets: Ref[]; localWasm: string;
  packages: Array<{ name: string; version: string; integrity: string; files: Ref[] }>;
  build: { esbuildVersion: string; platform: string; format: string; target: string; lock: Ref;
    provenance: { purpose: string; sources: Ref[]; runtimeIdentity: string };
    graph: { inputs: string[]; nodeBuiltinExternals: string[]; dynamicModuleLoads: number } };
  limitations: string[];
};
async function readManifest(base: string): Promise<{ manifest: Manifest; raw: Buffer }> {
  const raw = await readFile(join(base, directory, 'manifest.json'));
  return { manifest: JSON.parse(raw.toString('utf8')), raw };
}
/** Packaging checksum contract only; this is not the R3 runtime asset authenticator. */
async function checkAssets(base: string, manifestSha256: string): Promise<Manifest> {
  const { manifest, raw } = await readManifest(base);
  assert.equal(hash(raw), manifestSha256);
  assert.equal(manifest.protocolRevision, protocol);
  assert.equal(manifest.localWasm, 'libpg-query.wasm');
  assert.deepEqual(manifest.assets.map(item => item.path).sort(),
    assetNames.map(name => `${directory}/${name}`).sort());
  for (const ref of manifest.assets) {
    const bytes = await readFile(join(base, ref.path));
    assert.equal(bytes.length, ref.bytes, ref.path); assert.equal(hash(bytes), ref.sha256, ref.path);
  }
  return manifest;
}
function staticModuleGraph(text: string): void {
  const source = ts.createSourceFile('worker.cjs', text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword
      || ts.isIdentifier(node.expression) && ['require', '__require'].includes(node.expression.text)
      || ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'require')) {
      assert.equal(node.arguments.length, 1);
      assert.ok(ts.isStringLiteral(node.arguments[0]) && isBuiltin(node.arguments[0].text));
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  assert.ok(text.includes('__dirname') && text.includes('libpg-query.wasm') && text.includes('pg-parser-worker.cjs'));
  assert.ok(!text.includes('import.meta') && !text.includes(resolve(root)));
}

test('parser manifest binds exact inputs, assets and build provenance without execution', async () => {
  const { manifest, raw } = await readManifest(root); await checkAssets(root, hash(raw));
  assert.ok(raw.length <= 65536);
  assert.equal(manifest.schemaVersion, '1.0.0'); assert.equal(manifest.kind, 'wakeio-pg-parser-assets');
  assert.equal(manifest.protocolRevision, PG_PARSER_PROTOCOL_REVISION);
  assert.deepEqual(manifest.pin, PG_PARSER_PIN);
  assert.deepEqual(manifest.pin, { version: '18.2.1', pgMajor: 18,
    lockSha256: hash(await readFile('package-lock.json')),
    wasmSha256: '355c489d8b0bf2bac28b48408f656e818852d7000e1e66a67503ad2bc7cc6062' });
  assert.equal(manifest.assets.find(item => item.path.endsWith('.wasm'))!.bytes, 1717872);
  assert.equal(manifest.build.esbuildVersion, '0.28.2'); assert.equal(manifest.build.format, 'cjs');
  assert.equal(manifest.build.platform, 'node'); assert.equal(manifest.build.target, 'node22');
  assert.equal(manifest.build.lock.sha256, manifest.pin.lockSha256);
  const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
  assert.deepEqual(manifest.packages.map(item => [item.name, item.version]),
    [['libpg-query', '18.2.1'], ['@pgsql/types', '18.0.0']]);
  for (const item of manifest.packages) {
    assert.equal(lock.packages[`node_modules/${item.name}`].integrity, item.integrity);
    for (const ref of item.files) {
      const bytes = await readFile(join('node_modules', item.name, ref.path));
      assert.equal(bytes.length, ref.bytes); assert.equal(hash(bytes), ref.sha256);
    }
  }
  assert.equal(manifest.build.provenance.purpose, 'build-provenance-only');
  assert.equal(manifest.build.provenance.runtimeIdentity, 'explicit-protocol-revision-and-deployed-asset-pins');
  assert.ok(manifest.build.provenance.sources.some(item => item.path.endsWith('pg-parser-worker.ts')));
  assert.ok(manifest.build.provenance.sources.some(item => item.path.endsWith('pg-parser-helper.ts')));
  assert.equal(manifest.build.graph.dynamicModuleLoads, 0);
  assert.ok(manifest.build.graph.nodeBuiltinExternals.every(isBuiltin));
  assert.ok(manifest.build.graph.inputs.some(path => path.includes('node_modules/libpg-query/')));
  assert.ok(manifest.limitations.includes('source-wasm-correspondence-unverified'));
  assert.ok(manifest.limitations.includes('raw-hashes-are-not-producer-authentication'));
  staticModuleGraph(await readFile(join(directory, 'pg-parser-worker.cjs'), 'utf8'));
  const action = await readFile('dist-action/wakeio-security-ci.mjs', 'utf8');
  assert.ok(!action.includes(protocol) && !action.includes('pg-parser-worker.cjs'));
});

test('both MIT texts and pinned upstream notices are distributed without claiming source correspondence', async () => {
  const workerNotice = await readFile(join(directory, 'THIRD_PARTY_LICENSES.txt'));
  const actionNotice = await readFile('dist-action/THIRD_PARTY_LICENSES.txt');
  for (const name of ['libpg-query', '@pgsql/types']) {
    const license = await readFile(join('node_modules', name, 'LICENSE'));
    assert.ok(workerNotice.includes(license) && actionNotice.includes(license));
    assert.ok(workerNotice.includes(Buffer.from(name)));
  }
  for (const [name, expected] of [
    ['LICENSE.libpg_query', 'f9352c20940619a380a5e9f23cebe34d8f797cfbd747fc236a7a3e5fc8ef9b41'],
    ['COPYRIGHT.PostgreSQL', '5ed3ce5c9373dff7f98b1fae7a6c7ccd98df7d734d46d24c1bcebf1240be8307'],
  ]) {
    const bytes = await readFile(join(directory, name));
    assert.equal(hash(bytes), expected); assert.ok(actionNotice.includes(bytes));
  }
  const central = await readFile('THIRD_PARTY_NOTICES.md', 'utf8');
  assert.ok(central.includes('workers/pg-parser/THIRD_PARTY_LICENSES.txt'));
  assert.ok(central.includes('source correspondence to the published WASM remains unverified'));
});

test('filtered archives and isolated Action retain parser assets without source or modules',
  async () => {
    const temporary = await mkdtemp(join(tmpdir(), 'wakeio-parser-delivery-'));
    try {
      const artifacts = join(temporary, 'artifacts'), npm = join(temporary, 'npm');
      const source = join(temporary, 'source'), action = join(temporary, 'action');
      const { raw } = await readManifest(root), manifestPin = hash(raw);
      await exec(process.execPath, ['scripts/package-release.mjs', '--root', root, '--out-dir', artifacts],
        { cwd: root, maxBuffer: 10 * 1024 * 1024, timeout: 60000,
          env: { ...process.env, npm_config_cache: join(temporary, 'npm-cache') } });
      const version = JSON.parse(await readFile('package.json', 'utf8')).version;
      const tar = process.platform === 'win32' ? 'tar.exe' : 'tar';
      await mkdir(npm); await mkdir(source); await mkdir(join(action, 'dist-action'), { recursive: true });
      const npmArchive = join(artifacts, `wakeio-security-ci-${version}.tgz`);
      const sourceArchive = join(artifacts, `wakeio-security-ci-source-${version}.tar.gz`);
      await exec(tar, ['-xzf', npmArchive, '--strip-components', '1', '-C', npm]);
      await exec(tar, ['-xzf', sourceArchive, '--strip-components', '1',
        '-C', source, 'wakeio-security-ci/workers/pg-parser']);
      await cp(join(root, directory), join(action, directory), { recursive: true });
      for (const name of ['wakeio-security-ci.mjs', 'THIRD_PARTY_LICENSES.txt']) {
        await cp(join(root, 'dist-action', name), join(action, 'dist-action', name));
      }
      for (const base of [npm, source, action]) {
        await checkAssets(base, manifestPin);
        await assert.rejects(readFile(join(base, 'node_modules', 'libpg-query', 'package.json')), { code: 'ENOENT' });
        await assert.rejects(readFile(join(base, 'src/runtime/observers/pg-parser-worker.ts')), { code: 'ENOENT' });
        staticModuleGraph(await readFile(join(base, directory, 'pg-parser-worker.cjs'), 'utf8'));
      }
      const worker = join(action, directory, 'pg-parser-worker.cjs');
      const bytes = await readFile(worker); await writeFile(worker, Buffer.concat([bytes, Buffer.from('\n')]));
      await assert.rejects(checkAssets(action, manifestPin)); await writeFile(worker, bytes);
      const manifest = join(action, directory, 'manifest.json');
      await writeFile(manifest, Buffer.concat([raw, Buffer.from(' ')]));
      await assert.rejects(checkAssets(action, manifestPin));
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });
