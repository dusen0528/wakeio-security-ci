import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const root = process.cwd();
const tar = process.platform === 'win32' ? 'tar.exe' : 'tar';

test('release npm archive exposes root and contracts types to strict TypeScript consumers', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'wakeio-security-ci-package-types-'));
  try {
    const artifacts = join(temporary, 'artifacts');
    const consumer = join(temporary, 'consumer');
    const modules = join(consumer, 'node_modules');
    const installedPackage = join(modules, 'wakeio-security-ci');
    const packageJson = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));

    // Exercise the actual release pipeline, including its filtered npm staging
    // tree. The test never installs dependencies or runs package lifecycle hooks.
    await exec(process.execPath, [join(root, 'scripts', 'package-release.mjs'), '--root', root, '--out-dir', artifacts], {
      cwd: root,
      env: { ...process.env, npm_config_cache: join(temporary, 'npm-cache') },
      maxBuffer: 10 * 1024 * 1024,
    });
    await mkdir(installedPackage, { recursive: true });
    await exec(tar, ['-xzf', join(artifacts, `wakeio-security-ci-${packageJson.version}.tgz`), '--strip-components', '1', '-C', installedPackage]);

    const packedPackage = JSON.parse(await readFile(join(installedPackage, 'package.json'), 'utf8'));
    assert.equal(packedPackage.scripts, undefined);
    assert.equal(packedPackage.devDependencies, undefined);
    assert.equal(packedPackage.types, './build/src/index.d.ts');
    assert.deepEqual(packedPackage.exports, {
      '.': { types: './build/src/index.d.ts', default: './build/src/index.js' },
      './contracts': { types: './build/src/contracts.d.ts', default: './build/src/contracts.js' },
    });

    // Supply only this Node consumer's type dependencies, copied rather than
    // linked so package resolution cannot accidentally fall back to the checkout.
    await mkdir(join(modules, '@types'), { recursive: true });
    await cp(join(root, 'node_modules', '@types', 'node'), join(modules, '@types', 'node'), { recursive: true });
    await cp(join(root, 'node_modules', 'undici-types'), join(modules, 'undici-types'), { recursive: true });
    await writeFile(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
    await writeFile(join(consumer, 'consumer.ts'), `
import { runSource, type SourceOptions, type CheckResult } from 'wakeio-security-ci';
import type { SourceOptions as ContractSourceOptions } from 'wakeio-security-ci/contracts';

const options = { root: '.', tools: [], analysisProfile: 'extended' } satisfies SourceOptions;
const contractOptions: ContractSourceOptions = options;
const results: Promise<CheckResult[]> = runSource(contractOptions);
void results;

// @ts-expect-error Invalid tool names must be rejected by the published API.
runSource({ root: '.', tools: ['not-a-scanner'] });
// @ts-expect-error Root options must retain their concrete field types.
const invalidRootOptions: SourceOptions = { root: 123, tools: [] };
// @ts-expect-error The contracts subpath must expose the same checked types.
const invalidContractOptions: ContractSourceOptions = { root: '.', tools: [], timeoutMs: '1000' };
`);

    for (const [module, moduleResolution] of [['NodeNext', 'NodeNext'], ['ESNext', 'Bundler']]) {
      await writeFile(join(consumer, 'tsconfig.json'), JSON.stringify({
        compilerOptions: {
          target: 'ES2022', module, moduleResolution,
          strict: true, skipLibCheck: false, noEmit: true, types: ['node'],
        },
        files: ['consumer.ts'],
      }));
      const { stdout, stderr } = await exec(process.execPath, [join(root, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(consumer, 'tsconfig.json')], {
        cwd: consumer,
        maxBuffer: 10 * 1024 * 1024,
      });
      assert.equal(stdout + stderr, '', `strict ${moduleResolution} consumer should compile without diagnostics`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
