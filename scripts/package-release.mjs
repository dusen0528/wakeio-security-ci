import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createReadStream } from 'node:fs';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  utimes,
  writeFile,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const PROJECT_NAME = 'wakeio-security-ci';
const SOURCE_ARCHIVE_ROOT = PROJECT_NAME;
const DEFAULT_OUTPUT_DIR = 'artifacts';
const SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]*$/;
const EPOCH = new Date(0);

// Keep this list deliberately explicit. Directory entries are copied
// recursively so newly added documentation, benchmarks, examples, and
// tests are carried into a source release without silently admitting a new
// top-level runtime or local-state directory.
const SOURCE_ALLOWLIST = [
  '.github',
  '.gitignore',
  '.nvmrc',
  'CHANGELOG.md',
  'LICENSE',
  'README.md',
  'README.ko.md',
  'README.ja.md',
  'README.zh-CN.md',
  'SECURITY.md',
  'THIRD_PARTY_NOTICES.md',
  'CONTRIBUTING.md',
  'action.yml',
  'benchmarks',
  'docs',
  'dist-action',
  'examples',
  'package-lock.json',
  'package.json',
  'scripts',
  'src',
  'tests',
  'tsconfig.json',
];

const EXCLUDED_DIRECTORY_NAMES = new Set([
  '.git',
  'artifacts',
  'build',
  'node_modules',
  'realreports',
  'results',
  'wakeio-security-reports',
  '.wakeio-security-ci',
]);

// macOS exposes /var and /tmp as stable aliases to /private/var and
// /private/tmp. They are safe OS aliases for temporary test/release paths;
// every other existing ancestor must be a real directory.
const ALLOWED_SYSTEM_SYMLINKS = new Set(['/var', '/tmp']);

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function usage() {
  return [
    'Usage: node scripts/package-release.mjs [options]',
    '',
    'Options:',
    '  --root <directory>      Repository root (default: current directory)',
    '  --out-dir <directory>   Artifact directory (default: <root>/artifacts)',
    '  --help                  Show this help',
  ].join('\n');
}

export function parseArgs(argv) {
  let root = process.cwd();
  let outDir;
  let help = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      help = true;
      continue;
    }
    if (argument === '--root' || argument === '--out-dir') {
      const value = argv[index + 1];
      if (!value || value.startsWith('-')) {
        throw new Error(`${argument} requires a directory path`);
      }
      index += 1;
      if (argument === '--root') root = value;
      else outDir = value;
      continue;
    }
    throw new Error(`unknown option: ${argument}`);
  }

  root = resolve(root);
  return { root, outDir: resolve(outDir ?? join(root, DEFAULT_OUTPUT_DIR)), help };
}

async function assertDirectory(directory, label) {
  let info;
  try {
    info = await lstat(directory);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    await mkdir(directory, { recursive: true, mode: 0o755 });
    info = await lstat(directory);
  }

  if (info.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link: ${directory}`);
  }
  if (!info.isDirectory()) {
    throw new Error(`${label} must be a directory: ${directory}`);
  }
}

function isPathWithin(candidate, parent) {
  const pathWithinParent = relative(parent, candidate);
  return pathWithinParent === '' || (!pathWithinParent.startsWith('..') && !isAbsolute(pathWithinParent));
}

async function assertSafeOutputLocation(root, outputDirectory) {
  const absolute = resolve(outputDirectory);
  const rootPart = parse(absolute).root;
  let current = rootPart;
  const components = absolute.slice(rootPart.length).split(sep).filter(Boolean);
  for (const component of components) {
    current = join(current, component);
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      if (error?.code === 'ENOENT') break;
      throw error;
    }
    if (info.isSymbolicLink() && !ALLOWED_SYSTEM_SYMLINKS.has(current)) {
      throw new Error(`output path ancestor must not be a symbolic link: ${current}`);
    }
    if (!info.isDirectory() && !info.isSymbolicLink() && current !== absolute) {
      throw new Error(`output path ancestor must be a directory: ${current}`);
    }
  }

  for (const entry of SOURCE_ALLOWLIST) {
    if (isPathWithin(absolute, resolve(root, entry))) {
      throw new Error(`output directory cannot be inside source allowlist entry ${entry}: ${absolute}`);
    }
  }
}

async function assertRegularFile(file, label) {
  let info;
  try {
    info = await lstat(file);
  } catch (error) {
    if (error?.code === 'ENOENT') throw new Error(`${label} is missing: ${file}`);
    throw error;
  }
  if (info.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link: ${file}`);
  }
  if (!info.isFile()) {
    throw new Error(`${label} must be a regular file: ${file}`);
  }
}

async function assertOutputTargetSafe(file) {
  try {
    const info = await lstat(file);
    if (info.isSymbolicLink()) {
      throw new Error(`refusing to overwrite symbolic link artifact: ${file}`);
    }
    if (!info.isFile()) {
      throw new Error(`refusing to overwrite non-file artifact: ${file}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
}

async function readPackage(root) {
  const packagePath = join(root, 'package.json');
  let packageJson;
  try {
    packageJson = JSON.parse(await readFile(packagePath, 'utf8'));
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`package.json is not valid JSON: ${packagePath}`);
    }
    throw error;
  }

  if (!packageJson || typeof packageJson !== 'object' || Array.isArray(packageJson)) {
    throw new Error(`package.json must contain an object: ${packagePath}`);
  }
  if (packageJson.name !== PROJECT_NAME) {
    throw new Error(`package.json name must be ${PROJECT_NAME}`);
  }
  if (typeof packageJson.version !== 'string' || !SAFE_VERSION.test(packageJson.version)) {
    throw new Error(`package.json version must be a safe non-empty version string`);
  }
  return packageJson;
}

function packageBinTargets(packageJson) {
  if (typeof packageJson.bin === 'string') return [packageJson.bin];
  if (packageJson.bin && typeof packageJson.bin === 'object' && !Array.isArray(packageJson.bin)) {
    return Object.values(packageJson.bin);
  }
  throw new Error('package.json must declare a CLI bin target');
}

async function validateBuild(root, packageJson) {
  for (const target of packageBinTargets(packageJson)) {
    if (typeof target !== 'string' || target.length === 0) {
      throw new Error('package.json contains an invalid CLI bin target');
    }
    const targetPath = resolve(root, target);
    const pathWithinRoot = relative(root, targetPath);
    if (pathWithinRoot.startsWith('..') || pathWithinRoot.includes(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
      throw new Error(`CLI bin target escapes repository root: ${target}`);
    }
    await assertRegularFile(targetPath, 'CLI build output');
  }
  // A real checkout includes the bundle builder. Require its generated
  // dependency-free Action entrypoint at release time, while retaining the
  // small fixture contract used by package-release tests that model only npm
  // and source archive behavior.
  const bundleBuilder = join(root, 'scripts', 'build-action-bundle.mjs');
  try {
    await assertRegularFile(bundleBuilder, 'Action bundle builder');
  } catch (error) {
    if (error?.message?.includes('missing')) return;
    throw error;
  }
  await assertRegularFile(join(root, 'dist-action', 'wakeio-security-ci.mjs'), 'prebuilt Action bundle');
}

function isExcludedName(name, directory) {
  if (name === '.env' || name.startsWith('.env.')) return true;
  return directory && EXCLUDED_DIRECTORY_NAMES.has(name);
}

async function copySourceEntry(source, destination) {
  let info;
  try {
    info = await lstat(source);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }

  // A source archive must never follow a link into an unallowlisted or
  // user-controlled location. The allowlist remains useful when a checkout
  // contains generated links, so skip those entries rather than dereference.
  if (info.isSymbolicLink()) return;

  if (info.isDirectory()) {
    await mkdir(destination, { recursive: true, mode: info.mode & 0o7777 });
    const entries = (await readdir(source, { withFileTypes: true })).sort((left, right) => compareStrings(left.name, right.name));
    for (const entry of entries) {
      if (isExcludedName(entry.name, entry.isDirectory())) continue;
      await copySourceEntry(join(source, entry.name), join(destination, entry.name));
    }
    await chmod(destination, info.mode & 0o7777);
    return;
  }

  if (info.isFile()) {
    await mkdir(dirname(destination), { recursive: true, mode: 0o755 });
    await copyFile(source, destination);
    await chmod(destination, info.mode & 0o7777);
  }
}

async function normalizeTree(path) {
  const info = await lstat(path);
  if (info.isSymbolicLink()) return;
  if (info.isDirectory()) {
    const entries = (await readdir(path, { withFileTypes: true })).sort((left, right) => compareStrings(left.name, right.name));
    for (const entry of entries) await normalizeTree(join(path, entry.name));
  }
  // A fixed mtime makes source archives independent of checkout mtimes. File
  // order and path membership are controlled by the explicit allowlist.
  await utimes(path, EPOCH, EPOCH);
}

async function stageSource(root, workDirectory) {
  const stagedRoot = join(workDirectory, SOURCE_ARCHIVE_ROOT);
  await mkdir(stagedRoot, { recursive: true, mode: 0o755 });
  for (const entry of SOURCE_ALLOWLIST) {
    if (isExcludedName(entry, false)) continue;
    await copySourceEntry(join(root, entry), join(stagedRoot, entry));
  }
  await normalizeTree(stagedRoot);
  return stagedRoot;
}

async function createSourceArchive(workDirectory, archivePath) {
  // The command uses argv values directly. No shell is involved, and these
  // flags are supported by both BSD tar (macOS) and GNU tar (Linux).
  const tarArguments = [
    '-czf',
    archivePath,
    '--format',
    'ustar',
  ];
  // ustar avoids host-specific pax ctime/provenance records. The source tree
  // uses ordinary short paths; tar reports a clear error if a future path is
  // outside ustar's portable name limits.
  if (process.platform === 'darwin') tarArguments.push('--no-mac-metadata', '--no-xattrs', '--no-acls', '--no-fflags');
  else tarArguments.push('--no-xattrs', '--no-acls');
  tarArguments.push('-C', workDirectory, SOURCE_ARCHIVE_ROOT);
  await execFileAsync('tar', tarArguments, { cwd: workDirectory, maxBuffer: 2 * 1024 * 1024 });
}

async function normalizeGzipHeader(file) {
  const bytes = await readFile(file);
  if (bytes.length < 10 || bytes[0] !== 0x1f || bytes[1] !== 0x8b || bytes[2] !== 0x08) {
    throw new Error(`tar output is not a gzip archive: ${file}`);
  }
  // BSD tar writes the current clock into the gzip header. Clear it in the
  // staging file so repeated runs over the same source produce the same
  // archive bytes while retaining the system tar implementation.
  bytes.fill(0, 4, 8);
  await writeFile(file, bytes);
}

function npmExecutable() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

async function createNpmArchive(root, sourceStage, workDirectory, version) {
  const npmRoot = join(workDirectory, 'npm-root');
  await copySourceEntry(sourceStage, npmRoot);
  // npm's package.json intentionally ships build/src. Copy only that runtime
  // output into the filtered npm staging tree; source-stage filtering prevents
  // docs/.env and other local state from being admitted by npm's `files` rule.
  await copySourceEntry(join(root, 'build', 'src'), join(npmRoot, 'build', 'src'));
  // The checkout scripts are useful for contributors but are not runtime
  // package entrypoints. Remove them from the package.json that npm packs so
  // a consumer never sees test/benchmark/release lifecycle commands.
  const packedPackagePath = join(npmRoot, 'package.json');
  const packedPackage = JSON.parse(await readFile(packedPackagePath, 'utf8'));
  delete packedPackage.scripts;
  delete packedPackage.devDependencies;
  await writeFile(packedPackagePath, `${JSON.stringify(packedPackage, null, 2)}\n`, { mode: 0o644 });
  await normalizeTree(npmRoot);

  const packageDirectory = join(workDirectory, 'npm-pack');
  await mkdir(packageDirectory, { recursive: true, mode: 0o755 });
  const environment = {
    ...process.env,
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_ignore_scripts: 'true',
    npm_config_offline: 'true',
    npm_config_update_notifier: 'false',
  };
  const result = await execFileAsync(npmExecutable(), [
    'pack',
    '--ignore-scripts',
    '--offline',
    '--json',
    '--pack-destination',
    packageDirectory,
  ], {
    cwd: npmRoot,
    env: environment,
    maxBuffer: 10 * 1024 * 1024,
  });

  let metadata;
  try {
    const parsed = JSON.parse(result.stdout);
    metadata = Array.isArray(parsed) ? parsed[0] : parsed;
  } catch {
    throw new Error('npm pack did not return machine-readable JSON metadata');
  }

  if (!metadata || metadata.name !== PROJECT_NAME || metadata.version !== version || typeof metadata.filename !== 'string') {
    throw new Error('npm pack metadata does not match package.json');
  }
  const archivePath = join(packageDirectory, basename(metadata.filename));
  await assertRegularFile(archivePath, 'npm archive');
  return archivePath;
}

async function sha256File(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function writeChecksums(files, destination) {
  const lines = [];
  for (const file of files.slice().sort((left, right) => compareStrings(left.name, right.name))) {
    lines.push(`${await sha256File(file.path)}  ${file.name}`);
  }
  await writeFile(destination, `${lines.join('\n')}\n`, { mode: 0o644, flag: 'wx' });
}

async function commitArtifact(source, destination) {
  await assertOutputTargetSafe(destination);
  // workDirectory is created below the output directory, so rename is an
  // atomic same-filesystem install for each completed artifact.
  await rename(source, destination);
}

export async function packageRelease({ root, outDir }) {
  root = resolve(root ?? process.cwd());
  outDir = resolve(outDir ?? join(root, DEFAULT_OUTPUT_DIR));

  await assertDirectory(root, 'repository root');
  const packageJson = await readPackage(root);
  await validateBuild(root, packageJson);
  await assertSafeOutputLocation(root, outDir);
  await assertDirectory(outDir, 'output directory');

  const version = packageJson.version;
  const sourceName = `${PROJECT_NAME}-source-${version}.tar.gz`;
  const npmName = `${PROJECT_NAME}-${version}.tgz`;
  const checksumsName = `${PROJECT_NAME}-${version}-SHA256SUMS.txt`;
  const outputFiles = [sourceName, npmName, checksumsName].map((name) => join(outDir, name));
  for (const file of outputFiles) await assertOutputTargetSafe(file);

  const workDirectory = await mkdtemp(join(outDir, '.package-release-'));
  try {
    const stagedRoot = await stageSource(root, workDirectory);
    const sourcePath = join(workDirectory, sourceName);
    await createSourceArchive(workDirectory, sourcePath);
    await normalizeGzipHeader(sourcePath);

    const npmPath = await createNpmArchive(root, stagedRoot, workDirectory, version);
    const stagedNpmPath = join(workDirectory, npmName);
    if (basename(npmPath) !== npmName) {
      throw new Error(`npm pack filename must be ${npmName}; received ${basename(npmPath)}`);
    }
    await rename(npmPath, stagedNpmPath);
    await normalizeGzipHeader(stagedNpmPath);

    const stagedChecksumsPath = join(workDirectory, checksumsName);
    await writeChecksums([
      { name: npmName, path: stagedNpmPath },
      { name: sourceName, path: sourcePath },
    ], stagedChecksumsPath);

    await commitArtifact(stagedNpmPath, join(outDir, npmName));
    await commitArtifact(sourcePath, join(outDir, sourceName));
    await commitArtifact(stagedChecksumsPath, join(outDir, checksumsName));

    return {
      version,
      outputDirectory: outDir,
      sourceArchive: join(outDir, sourceName),
      npmArchive: join(outDir, npmName),
      checksums: join(outDir, checksumsName),
    };
  } finally {
    await rm(workDirectory, { recursive: true, force: true });
  }
}

async function main(argv) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const result = await packageRelease(options);
  process.stdout.write([
    `Release artifacts for ${PROJECT_NAME} ${result.version}:`,
    `- ${result.sourceArchive}`,
    `- ${result.npmArchive}`,
    `- ${result.checksums}`,
  ].join('\n') + '\n');
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === thisFile) {
  main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`package-release: ${message}\n`);
    process.exitCode = 1;
  });
}
