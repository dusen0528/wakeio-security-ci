#!/usr/bin/env node

/**
 * Build the dependency-free scanner entrypoint used by the composite Action.
 *
 * The Action checkout is allowed to contain source and package metadata, but
 * the runtime path must not call npm or depend on node_modules. esbuild is a
 * pinned development dependency, so release packaging can produce this file
 * deterministically after TypeScript has emitted build/src.
 */

import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isBuiltin } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, version as esbuildVersion } from 'esbuild';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const entryPoint = join(root, 'build', 'src', 'cli.js');
const outputFile = join(root, 'dist-action', 'wakeio-security-ci.mjs');
const licenseOutput = join(root, 'dist-action', 'THIRD_PARTY_LICENSES.txt');
const parserDirectory = 'workers/pg-parser';
const parserProtocol = 'wakeio.pg-parser/v1';
const parserLock = 'adc4e4026559ed0e5229acb4cb5354a82437420efdb58056d4a9d73969e37493';
const parserWasm = '355c489d8b0bf2bac28b48408f656e818852d7000e1e66a67503ad2bc7cc6062';
const mitLicense = '6676f35ef9ae1f095f420c56ab2078cf321227a88599ad224218b76d05fec731';
const parserPackages = [
  { name: 'libpg-query', version: '18.2.1',
    integrity: 'sha512-0zPlJei06//awjKmslKEwmGMSjF0n4p4OnPa3boRp8Xzl6ZnDIOddyLAsoJcJntrPCBLrWUbEwv5Laxg8BZYlA==',
    files: [
      ['package.json', 2044, '0c5b52c800362f051bf0b786388b3758627efd17aa6595ac978e180275822e08'],
      ['wasm/index.cjs', 19005, '34c24e944916fdf23de94300372a8e98e5b0e6a40bcd6a7e7318d9071faad9a5'],
      ['wasm/index.js', 17686, 'faa60804c3e6868197ef81044829aa09e6dc9b99fc546adadac68704d2df5344'],
      ['wasm/libpg-query.js', 61661, '219217cc9ed5d8522c6ab273e9ed0bfb56c84a7181d9dd01dc32bf77efd15281'],
      ['LICENSE', 1160, mitLicense],
    ] },
  { name: '@pgsql/types', version: '18.0.0',
    integrity: 'sha512-jtAY4JU7jdVYZ/Vv3zlZqVP+FRWZokyCLKPPCnAApiaJAElpyyiMC3HRiquBu29kSrVs+rkqZD50SUIb/zyEGw==',
    files: [
      ['package.json', 1207, 'f9819f6aca085cadfa9bb58c1b8323aef885d520a9c2d69bae401c0ab219b928'],
      ['index.js', 843, 'a166516984a6d37505a8930c4a57971e95cc1a5a8ab0955779ff1d7fb09d1be9'],
      ['types.js', 77, 'd43aa81f5bc89faa359e0f97c814ba25155591ff078fbb9bfd40f8c7c9683230'],
      ['enums.js', 77, 'd43aa81f5bc89faa359e0f97c814ba25155591ff078fbb9bfd40f8c7c9683230'],
      ['esm/index.js', 50, 'fe83f7a008c2b4d20a8ddf5ff62c136fbea0a796a516eda4bcf1a47252bd4468'],
      ['esm/types.js', 11, '8e609bb71c20b858c77f0e9f90bb1319db8477b13f9f965f1a1e18524bf50881'],
      ['esm/enums.js', 11, '8e609bb71c20b858c77f0e9f90bb1319db8477b13f9f965f1a1e18524bf50881'],
      ['LICENSE', 1160, mitLicense],
    ] },
];
const parserNotices = [
  ['LICENSE.libpg_query', 1561, 'f9352c20940619a380a5e9f23cebe34d8f797cfbd747fc236a7a3e5fc8ef9b41'],
  ['COPYRIGHT.PostgreSQL', 1198, '5ed3ce5c9373dff7f98b1fae7a6c7ccd98df7d734d46d24c1bcebf1240be8307'],
];

await mkdir(dirname(outputFile), { recursive: true, mode: 0o755 });
await rm(join(root, 'build', 'action'), { recursive: true, force: true });
await rm(licenseOutput, { force: true });
await build({
  entryPoints: [entryPoint],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  outfile: outputFile,
  legalComments: 'none',
  sourcemap: false,
  logLevel: 'warning',
  // TypeScript's Node system contains a guarded dynamic require. Supplying a
  // real ESM-scoped require keeps that hook working after bundling while all
  // package dependencies remain embedded in this one file.
  banner: {
    js: "import { createRequire as __wakeioCreateRequire } from 'node:module'; import { fileURLToPath as __wakeioFileURLToPath } from 'node:url'; import { dirname as __wakeioDirname } from 'node:path'; const require = __wakeioCreateRequire(import.meta.url); const __filename = __wakeioFileURLToPath(import.meta.url); const __dirname = __wakeioDirname(__filename);",
  },
});
await chmod(outputFile, 0o755);
await buildParserAssets();
await writeFile(licenseOutput, await bundledDependencyNotices(), { mode: 0o644 });
process.stdout.write(`Built dependency-free Action bundle: ${outputFile}\n`);

async function bundledDependencyNotices() {
  const dependencies = [
    ['parse5', 'LICENSE'],
    ['entities', 'LICENSE'],
    ['typescript', 'LICENSE.txt'],
    ['typescript', 'ThirdPartyNoticeText.txt'],
    ['esbuild', 'LICENSE.md'],
    // Approved target-data parsers; include their notices before CLI wiring.
    ['yaml', 'LICENSE'],
    ['ajv', 'LICENSE'],
    ['fast-deep-equal', 'LICENSE'],
    ['fast-uri', 'LICENSE'],
    ['json-schema-traverse', 'LICENSE'],
    ['require-from-string', 'license'],
    ['libpg-query', 'LICENSE'],
    ['@pgsql/types', 'LICENSE'],
  ];
  const sections = ['Third-party notices for the generated Wakeio Security CI Action bundle.', ''];
  for (const [name, file] of dependencies) {
    const packagePath = join(root, 'node_modules', name, 'package.json');
    const packageJson = JSON.parse(await readFile(packagePath, 'utf8'));
    const licensePath = join(root, 'node_modules', name, file);
    sections.push(`===== ${name} ${packageJson.version} :: ${file} =====`);
    sections.push((await readFile(licensePath, 'utf8')).replace(/\r\n/g, '\n'));
    sections.push('');
  }
  for (const [name] of parserNotices) {
    sections.push(`===== Separate PostgreSQL parser asset :: ${parserDirectory}/${name} =====`);
    sections.push(await readFile(join(root, parserDirectory, name), 'utf8'), '');
  }
  return `${sections.join('\n').trimEnd()}\n`;
}

function requireBuild(ok) { if (!ok) throw new Error('invalid_pg_parser_build_input'); }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
async function reference(path, bytes, sha256) {
  const raw = await readFile(join(root, path));
  requireBuild((bytes === undefined || raw.length === bytes) && (sha256 === undefined || digest(raw) === sha256));
  return { path, bytes: raw.length, sha256: digest(raw) };
}
function sourceRevision(text, name) {
  const source = ts.createSourceFile('protocol.ts', text, ts.ScriptTarget.Latest, true);
  const values = source.statements.filter(ts.isVariableStatement)
    .filter(row => row.modifiers?.some(item => item.kind === ts.SyntaxKind.ExportKeyword))
    .filter(row => row.declarationList.flags & ts.NodeFlags.Const)
    .flatMap(row => row.declarationList.declarations)
    .filter(row => ts.isIdentifier(row.name) && row.name.text === name);
  requireBuild(values.length === 1);
  let value = values[0].initializer;
  while (value && (ts.isAsExpression(value) || ts.isParenthesizedExpression(value))) value = value.expression;
  requireBuild(value && ts.isStringLiteral(value) && value.text === parserProtocol);
  return value.text;
}
function auditWorker(text, metafile) {
  const externals = new Set();
  for (const output of Object.values(metafile.outputs)) for (const item of output.imports) {
    requireBuild(item.external && isBuiltin(item.path)); externals.add(item.path);
  }
  const source = ts.createSourceFile('worker.cjs', text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const visit = node => {
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword
      || ts.isIdentifier(node.expression) && ['require', '__require'].includes(node.expression.text)
      || ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'require')) {
      requireBuild(node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])
        && isBuiltin(node.arguments[0].text));
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  requireBuild(!text.includes(root) && !text.includes('import.meta'));
  return { inputs: Object.keys(metafile.inputs).sort(), nodeBuiltinExternals: [...externals].sort(),
    dynamicModuleLoads: 0 };
}
async function packageReferences(lock) {
  const packages = [];
  for (const expected of parserPackages) {
    const prefix = `node_modules/${expected.name}`, installed = lock.packages[prefix];
    requireBuild(installed?.version === expected.version && installed.integrity === expected.integrity);
    const files = [];
    for (const [path, bytes, sha256] of expected.files) {
      const measured = await reference(`${prefix}/${path}`, bytes, sha256);
      files.push({ ...measured, path });
    }
    packages.push({ name: expected.name, version: expected.version, integrity: expected.integrity, files });
  }
  return packages;
}
async function parserLicenseText() {
  const pieces = [Buffer.from('Third-party notices for the separate PostgreSQL parser worker.\n\n')];
  for (const item of parserPackages) {
    pieces.push(Buffer.from(`===== ${item.name} ${item.version} :: LICENSE (MIT) =====\n`));
    pieces.push(await readFile(join(root, 'node_modules', item.name, 'LICENSE')), Buffer.from('\n'));
  }
  pieces.push(Buffer.from('Additional upstream notices: LICENSE.libpg_query and COPYRIGHT.PostgreSQL.\n'
    + 'Exact upstream source correspondence to the published WASM is unverified.\n'));
  return Buffer.concat(pieces);
}
async function parserProvenance() {
  const sources = [
    ['pg-parser-helper', 'PG_PARSER_PROTOCOL_REVISION'],
    ['pg-parser-worker', 'PG_PARSER_WORKER_PROTOCOL_REVISION'],
  ];
  const refs = [];
  for (const [name, constant] of sources) {
    const path = `src/runtime/observers/${name}.ts`;
    sourceRevision(await readFile(join(root, path), 'utf8'), constant);
    refs.push(await reference(path), await reference(`build/src/runtime/observers/${name}.js`));
  }
  return { purpose: 'build-provenance-only', sources: refs,
    runtimeIdentity: 'explicit-protocol-revision-and-deployed-asset-pins' };
}
async function buildParserAssets() {
  requireBuild(esbuildVersion === '0.28.2');
  const lockRef = await reference('package-lock.json', undefined, parserLock);
  const lock = JSON.parse(await readFile(join(root, lockRef.path), 'utf8'));
  const packages = await packageReferences(lock), provenance = await parserProvenance();
  await mkdir(join(root, parserDirectory), { recursive: true, mode: 0o755 });
  for (const [name, bytes, sha256] of parserNotices) await reference(`${parserDirectory}/${name}`, bytes, sha256);
  const wasm = await reference('node_modules/libpg-query/wasm/libpg-query.wasm', 1717872, parserWasm);
  const built = await build({
    absWorkingDir: root, entryPoints: ['build/src/runtime/observers/pg-parser-worker.js'],
    bundle: true, platform: 'node', format: 'cjs', target: 'node22', write: false, metafile: true,
    legalComments: 'none', sourcemap: false, logLevel: 'warning',
  });
  requireBuild(built.outputFiles.length === 1);
  const graph = auditWorker(built.outputFiles[0].text, built.metafile);
  for (const path of graph.inputs.filter(path => path.startsWith('node_modules/'))) {
    requireBuild(packages.some(item => item.files.some(file => path === `node_modules/${item.name}/${file.path}`)));
  }
  await writeFile(join(root, parserDirectory, 'pg-parser-worker.cjs'), built.outputFiles[0].contents, { mode: 0o644 });
  await writeFile(join(root, parserDirectory, 'libpg-query.wasm'),
    await readFile(join(root, wasm.path)), { mode: 0o644 });
  await reference(`${parserDirectory}/libpg-query.wasm`, 1717872, parserWasm);
  await writeFile(join(root, parserDirectory, 'THIRD_PARTY_LICENSES.txt'), await parserLicenseText(), { mode: 0o644 });
  const assets = [];
  for (const name of ['pg-parser-worker.cjs', 'libpg-query.wasm', 'THIRD_PARTY_LICENSES.txt',
    ...parserNotices.map(row => row[0])]) assets.push(await reference(`${parserDirectory}/${name}`));
  const manifest = { schemaVersion: '1.0.0', kind: 'wakeio-pg-parser-assets', protocolRevision: parserProtocol,
    pin: { version: '18.2.1', pgMajor: 18, lockSha256: lockRef.sha256, wasmSha256: parserWasm },
    build: { esbuildVersion, platform: 'node', format: 'cjs', target: 'node22', lock: lockRef, provenance, graph },
    packages, assets, localWasm: 'libpg-query.wasm',
    limitations: ['source-wasm-correspondence-unverified', 'publisher-signature-unverified',
      'reproducible-upstream-build-unverified', 'raw-hashes-are-not-producer-authentication',
      'runtime-sandbox-and-wasm-execution-not-verified-by-packaging'] };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
  requireBuild(manifestBytes.length <= 65536);
  await writeFile(join(root, parserDirectory, 'manifest.json'), manifestBytes, { mode: 0o644 });
}
