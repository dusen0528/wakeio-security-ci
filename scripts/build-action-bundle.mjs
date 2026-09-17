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
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const entryPoint = join(root, 'build', 'src', 'cli.js');
const outputFile = join(root, 'dist-action', 'wakeio-security-ci.mjs');
const licenseOutput = join(root, 'dist-action', 'THIRD_PARTY_LICENSES.txt');

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
await writeFile(licenseOutput, await bundledDependencyNotices(), { mode: 0o644 });
process.stdout.write(`Built dependency-free Action bundle: ${outputFile}\n`);

async function bundledDependencyNotices() {
  const dependencies = [
    ['parse5', 'LICENSE'],
    ['entities', 'LICENSE'],
    ['typescript', 'LICENSE.txt'],
    ['typescript', 'ThirdPartyNoticeText.txt'],
    ['esbuild', 'LICENSE.md'],
  ];
  const sections = ['Third-party notices for the generated Wakeio Security CI Action bundle.', ''];
  for (const [name, file] of dependencies) {
    const packagePath = join(root, 'node_modules', name, 'package.json');
    const packageJson = JSON.parse(await readFile(packagePath, 'utf8'));
    const licensePath = join(root, 'node_modules', name, file);
    sections.push(`===== ${name} ${packageJson.version} :: ${file} =====`);
    sections.push(await readFile(licensePath, 'utf8'));
    sections.push('');
  }
  return `${sections.join('\n').trimEnd()}\n`;
}
