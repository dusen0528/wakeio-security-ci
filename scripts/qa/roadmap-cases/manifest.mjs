// T3 adapter. No driver implementation here: runCase({out, mutate}) is the seam.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, writeFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { loadManifest, sha256, SCANNER_IMAGE, TestbedError } from '../../testbed-manifest.mjs';
import { fixJuiceSearch } from '../../../benchmarks/dast-zap/juice-shop.mjs';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../../../', import.meta.url));
export async function runCase({ out, mutate }) {
  const output = resolve(out);
  await mkdir(output, { recursive: true });
  const temporary = await realpath(await mkdtemp(join(tmpdir(), 'wakeio-t4-')));
  const owner = `t4-${randomUUID()}`, owned = [], artifacts = [], bindings = [], commands = [];
  let status = 'fail', reason, inventoryBefore, cleanup;
  const record = async (name, value) => {
    const bytes = JSON.stringify(value, null, 2) + '\n';
    if (!/^[a-z][a-z0-9-]*\.json$/.test(name) || Buffer.byteLength(bytes) > 1024 * 1024) throw new TestbedError('artifact_contract');
    const path = join(output, name);
    await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
    artifacts.push(name);
    bindings.push({ path: name, sha256: sha256(bytes), bytes: Buffer.byteLength(bytes) });
    return path;
  };
  // Each child is bounded and captured; maxBuffer failure is failure, not a
  // truncated success. No daemon connection fallback, pull or timed readiness.
  const run = async (binary, argv) => {
    const ordinal = commands.length, command = { binary, argv, exit: null };
    commands.push(command);
    try {
      const result = await exec(binary, argv, {
        cwd: root, timeout: 60000, maxBuffer: 128 * 1024, killSignal: 'SIGKILL',
        env: { ...process.env, TMPDIR: temporary, NODE_COMPILE_CACHE: join(temporary, 'node-cache'),
          BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(temporary, 'bun-cache'), GIT_MASTER: '1', GIT_PAGER: 'cat' },
      });
      command.exit = 0;
      await record(`command-${ordinal}-stdout.json`, { stdout: result.stdout });
      await record(`command-${ordinal}-stderr.json`, { stderr: result.stderr });
      return result.stdout.trim();
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      command.exit = error.code ?? null;
      command.killed = error.killed === true;
      await record(`command-${ordinal}-stdout.json`, { stdout: typeof error.stdout === 'string' ? error.stdout : '' });
      await record(`command-${ordinal}-stderr.json`, { stderr: typeof error.stderr === 'string' ? error.stderr : error.message });
      throw error;
    }
  };
  const docker = (...args) => run('docker', args);
  const inventory = async () => (await docker('ps', '-aq', '--no-trunc')).split('\n').filter(Boolean).sort();
  const create = async args => {
    const id = await docker('create', '--name', `${owner}-${owned.length}`, '--label', `wakeio.t4=${owner}`, ...args);
    if (!/^[a-f0-9]{64}$/.test(id)) throw new TestbedError('invalid_created_id');
    owned.push(id);
    return id;
  };
  try {
    if (mutate !== undefined && !['truth-mounted', 'missing-pin'].includes(mutate)) throw new TestbedError('unknown_mutation');
    inventoryBefore = await inventory();
    const manifestPath = join(root, 'benchmarks/testbeds/manifest.json');
    let candidate = manifestPath;
    if (mutate === 'missing-pin') {
      const data = JSON.parse(await readFile(manifestPath, 'utf8'));
      delete data.targets[0].image;
      candidate = join(temporary, 'missing-pin.json');
      await writeFile(candidate, JSON.stringify(data), { flag: 'wx' });
    }
    const input = join(temporary, 'inventory.mjs'), scanner = join(root, 'dist-action/wakeio-security-ci.mjs');
    await run(process.execPath, ['scripts/testbed-manifest.mjs', '--manifest', candidate, '--scanner-out', input]);
    const manifest = await loadManifest(), target = manifest.data.targets[0];
    const [image] = JSON.parse(await docker('image', 'inspect', target.image));
    const labels = image.Config.Labels;
    if (labels['org.opencontainers.image.version'] !== target.version
      || labels['org.opencontainers.image.licenses'] !== target.license.spdx
      || !target.source.commit.startsWith(labels['org.opencontainers.image.revision'])
      || labels['org.opencontainers.image.source'] !== target.source.repository) throw new TestbedError('target_image_provenance');
    const targetId = await create(['--network', 'none', target.image]);
    const route = join(temporary, 'search.js');
    await docker('cp', `${targetId}:/juice-shop/build/routes/search.js`, route);
    const original = await readFile(route), fixed = fixJuiceSearch(original);
    if (sha256(original) !== target.variants.find(v => v.id === 'vulnerable')?.artifactSha256
      || sha256(fixed) !== target.variants.find(v => v.id === 'fixed')?.artifactSha256) throw new TestbedError('target_route_pin');
    const mounts = ['--mount', `type=bind,source=${input},target=/input/inventory.mjs,readonly`,
      '--mount', `type=bind,source=${scanner},target=/scanner.mjs,readonly`];
    if (mutate === 'truth-mounted') mounts.push('--mount', `type=bind,source=${manifestPath},target=/hidden-truth.json,readonly`);
    const scannerId = await create(['--network', 'none', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--memory', '512m', '--pids-limit', '64',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--entrypoint', 'node', ...mounts, SCANNER_IMAGE,
      '/scanner.mjs', 'scan', '--source', '/input', '--tools', 'none', '--out', '/tmp/report']);
    await record('docker-inspect.json', JSON.parse(await docker('inspect', '--type', 'container', scannerId)));
    await run(process.execPath, ['scripts/testbed-manifest.mjs', '--inspect', scannerId, '--input', input, '--scanner', scanner]);
    await docker('start', '--attach', scannerId);
    const [completed] = JSON.parse(await docker('inspect', '--type', 'container', scannerId));
    if (completed.State.Running || completed.State.ExitCode !== 0 || completed.State.OOMKilled || completed.State.Error) throw new TestbedError('scanner_execution');
    await record('scanner-completed.json', completed);
    await record('scanner-input.json', { source: await readFile(input, 'utf8') });
    await record('evaluator.json', {
      manifestSha256: manifest.sha256, privateMetadataReadable: true, truthUnits: target.truth.length,
      targetImageId: image.Id, targetSource: target.source, license: target.license,
      originalRouteSha256: sha256(original), fixedRouteSha256: sha256(fixed), scannerSha256: sha256(await readFile(scanner)),
      scope: manifest.data.scope, targetExecuted: false, accuracyMeasured: false,
      prerequisites: manifest.data.prerequisites,
    });
    status = 'pass';
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    reason = error.message;
    const refusedInput = commands.at(-1)?.binary === process.execPath && commands.at(-1)?.exit === 2;
    status = refusedInput || (error instanceof TestbedError && error.code === 'unknown_mutation') ? 'unavailable' : 'fail';
  } finally {
    const failures = [];
    // Query by our unpredictable label, not by global inventory. This also
    // recovers a container if create succeeded but its reply was interrupted.
    try {
      const ids = (await docker('ps', '-aq', '--no-trunc', '--filter', `label=wakeio.t4=${owner}`)).split('\n').filter(Boolean);
      for (const id of ids) await docker('rm', '-f', id);
      const containers = await docker('ps', '-aq', '--filter', `label=wakeio.t4=${owner}`);
      const networks = await docker('network', 'ls', '-q', '--filter', `label=wakeio.t4=${owner}`);
      const volumes = await docker('volume', 'ls', '-q', '--filter', `label=wakeio.t4=${owner}`);
      const inventoryAfter = await inventory();
      const existingPreserved = !inventoryBefore || inventoryBefore.every(id => inventoryAfter.includes(id));
      cleanup = { owner, containers, networks, volumes, existingPreserved, inventoryBefore, inventoryAfter, removed: ids,
        temporaryRemoved: true, childProcessesSettled: true, networkCreated: false, volumeCreated: false, hostPortBound: false };
      if (containers || networks || volumes || !existingPreserved) failures.push('resource_residue');
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      failures.push(error.message);
    }
    try { await rm(temporary, { recursive: true, force: true }); } catch (error) {
      if (!(error instanceof Error)) throw error;
      failures.push(error.message);
      cleanup = { ...cleanup, temporaryRemoved: false };
    }
    cleanup = { ...cleanup, confirmed: failures.length === 0, status: failures.length ? 'fail' : 'pass', failures };
    if (failures.length) { status = 'fail'; reason = 'cleanup_failed'; }
    await record('cleanup.json', cleanup);
    await record('commands.json', { commands });
  }
  await record('case-result.json', { status, reason: reason ?? null, cleanup, artifacts, artifactDigests: bindings });
  return { status, artifacts, cleanup };
}
