import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, realpath, readdir, readFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadProvisionHelpers, loadNativeInstallHelpers, NATIVE_INSTALL_CASES, nativeInstallPacket,
  provisionHelperDigest } from '../src/runtime/runtimes/provision-controller-artifacts.js';
import { provisionBootstrap, provisionVmConfig,
  type ProvisionHelper } from '../src/runtime/runtimes/provision-controller-config.js';

const interpreter = process.env['T6P_TEST_PYTHON'];
if (!interpreter) throw new Error('T6P_TEST_PYTHON is required');
const python = interpreter;
const buildNames = ['build.py', 'input_resources.py', 'process.py', 'launch.py',
  'input.py', 'input_archive.py', 'profiles.json'] as const;
async function checkPython(body: string, enforceBounds = false, helpers?: readonly ProvisionHelper[]): Promise<void> {
  const root = await mkdtemp(join(await realpath(tmpdir()), 't6p005-syntax-'));
  try {
    const parser = ['import ast,json,sys', 'body=sys.stdin.read();tree=ast.parse(body)',
      'rows=[{"line":n.lineno,"lines":n.end_lineno-n.lineno+1} for n in ast.walk(tree) '
        + 'if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]',
      'encoded=[n.args[0].value for n in ast.walk(tree) if isinstance(n,ast.Call) '
        + 'and isinstance(n.func,ast.Attribute) and n.func.attr=="b64decode" '
        + 'and isinstance(n.args[0],ast.Constant)]',
      'print(json.dumps({"python":sys.version,"functions":rows,"encoded":encoded}))',
      enforceBounds ? 'assert all(n["lines"]<=60 for n in rows)' : 'pass',
      helpers ? 'access=tree.body[-2]\nassert isinstance(access,ast.For)' : 'pass',
      helpers ? 'assert ast.literal_eval(access.iter)==("/usr/local/lib/wakeio-controller",'
        + '"/usr/local/lib/wakeio-controller/build")' : 'pass',
      helpers ? 'assert [(n.value.func.attr,[ast.literal_eval(a) for a in n.value.args[1:]]) '
        + 'for n in access.body]==[("chown",[0,10001]),("chmod",[0o750])]' : 'pass',
      helpers ? 'assert all(n.value.args[0].id==access.target.id for n in access.body)' : 'pass',
      helpers ? 'private=[n for n in tree.body if isinstance(n,ast.With)]\nassert len(private)==2' : 'pass',
      helpers ? 'assert all(n.end_lineno<access.lineno and ast.literal_eval(n.body[0].value.args[1])==0o600 '
        + 'for n in private)' : 'pass'].join('\n');
    const argv = ['-I', '-B', '-c', parser];
    const child = spawn(python, argv,
      { stdio: ['pipe', 'pipe', 'pipe'], signal: AbortSignal.timeout(10000), env: {
        RUN_TMP: root, TMPDIR: root, NODE_COMPILE_CACHE: join(root, 'node'),
        BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun') } });
    let failure: Error | undefined;
    child.once('error', error => { failure = error; });
    const closed = new Promise<number | null>(resolve => child.once('close', resolve));
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk; });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk; });
    child.stdin.end(body);
    const code = await closed;
    console.log('PYTHON_AST=' + JSON.stringify({ interpreter: python, argv, code, stdout, stderr,
      bytes: Buffer.byteLength(body), sha256: createHash('sha256').update(body).digest('hex') }));
    assert.equal(code, 0, stderr);
    if (failure) throw failure;
    if (helpers) {
      const { encoded }: { readonly encoded: readonly string[] } = JSON.parse(stdout);
      assert.deepEqual(encoded.map(value => JSON.parse(Buffer.from(value, 'base64').toString())),
        [helpers.map(({ name, installation, sha256, body }) =>
          ({ name, installation, sha256, body: body.toString('base64') })),
        helpers.map(({ name, installation, sha256 }) => ({ name, installation, sha256 }))]);
    }
  } finally { await rm(root, { recursive: true }); }
}

async function generatedBundle(caseId: string, helpers: readonly ProvisionHelper[], source: string) {
  const hash = (body: string | Buffer) => createHash('sha256').update(body).digest('hex');
  assert.equal(helpers.length, caseId === 'normal' ? 41 : 44);
  const expectedNames = (await readdir(source)).filter(name => /\.(py|mjs)$/.test(name)
    && (caseId !== 'normal' || name !== 'native_install_regression.py'));
  expectedNames.push(...buildNames.map(name => 'build/' + name),
    'runtime/builders/build-policy.js', 'json-snapshot.js', 'package.json');
  if (caseId !== 'normal') expectedNames.push('native/runtime_provision_install_mount_test.py',
    'native/runtime_provision_install_apt_test.py');
  assert.deepEqual(helpers.map(item => item.name).sort(), expectedNames.sort());
  assert.deepEqual(helpers.filter(item => item.name.startsWith('build/')).map(item =>
    ({ name: item.name, installation: item.installation })),
  buildNames.map(name => ({ name: 'build/' + name, installation: 'controller' })));
  const bindings = helpers.map(({ name, installation, body }) => ({ name, installation, sha256: hash(body) }));
  assert.equal(provisionHelperDigest(helpers), hash(JSON.stringify(bindings)));
  for (const helper of helpers.filter(item => /\.(py|mjs)$/.test(item.name) || item.name === 'build/profiles.json')) {
    let expected = helper.name.startsWith('build/')
      ? join(dirname(source), 'runtime-build', helper.name.slice(6)) : join(source, helper.name);
    if (helper.name.startsWith('native/')) expected = join(process.cwd(), 'tests', helper.name);
    if (caseId === 'mount-original' && helper.name === 'install_sandbox.py'
      || caseId === 'apt-original' && helper.name === 'install_config.py') {
      expected = join(process.cwd(), 'tests/native/fixtures/seal002-original', helper.name);
    }
    assert.deepEqual(helper.body, await readFile(expected));
  }
  assert.equal(helpers.filter(item => item.installation === 'install').length, 14);
  const bootstrap = provisionBootstrap(helpers, '12'.repeat(32));
  const configuration = provisionVmConfig('/private/tmp/owned-rootfs.img', bootstrap);
  const profile = JSON.parse(configuration);
  assert.deepEqual({ mounts: profile.mounts, networks: profile.networks, disks: profile.additionalDisks },
    { mounts: [], networks: [], disks: [] });
  assert.equal(profile.provision[2].script, bootstrap);
  assert.deepEqual(profile.containerd, { system: false, user: false });
  assert.equal(profile.ssh.forwardAgent, false);
  assert.equal(profile.propagateProxyEnv, false);
  assert.equal(profile.cpus, 6);
  assert.equal(profile.memory, '8GiB');
  assert.equal(profile.disk, '40GiB');
  const first = helpers[0];
  assert.ok(first);
  assert.throws(() => provisionBootstrap([{ ...first, body: Buffer.from('replaced') }], '12'.repeat(32)),
    { code: 'helper_digest_mismatch' });
  const script = bootstrap.split("<<'WAKEIO_FIXED_BOOT'\n")[1]?.split('\nWAKEIO_FIXED_BOOT\n')[0];
  assert.ok(script);
  await checkPython(script, false, helpers);
  console.log('GENERATED_ARTIFACT=' + JSON.stringify({ caseId,
    nonce: 'synthetic-12-times-32', rootfs: 'synthetic-owned-rootfs-path',
    manifestSha256: provisionHelperDigest(helpers), bootstrap, profile: configuration,
    bootstrapSha256: hash(bootstrap), profileSha256: hash(configuration),
    bootstrapBytes: Buffer.byteLength(bootstrap), profileBytes: Buffer.byteLength(configuration),
    helpers: helpers.map(({ name, installation, sha256, body }) =>
      ({ name, installation, sha256, bytes: body.length, mode: name === 'install_hook.py' ? '0755' : '0644' })),
    executed: false,
  }));
}

async function checkPackage(exported: string, nativeFiles: readonly string[]) {
  const npm = process.env['T6P_TEST_NPMCLI'] ?? process.env['npm_execpath'];
  assert.ok(npm);
  const root = await mkdtemp(join(await realpath(tmpdir()), 'native-pack-'));
  const argv = [npm, 'pack', '--dry-run', '--json', '--ignore-scripts', '--offline', '--cache=' + root + '/npm'];
  try {
    const child = spawn(process.execPath, argv, { cwd: exported, stdio: ['ignore', 'pipe', 'pipe'],
      signal: AbortSignal.timeout(15000), env: { PATH: dirname(process.execPath), HOME: root,
        RUN_TMP: root, TMPDIR: root, NODE_COMPILE_CACHE: join(root, 'node'),
        BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun'),
        NPM_CONFIG_USERCONFIG: join(root, 'user.npmrc'), NPM_CONFIG_GLOBALCONFIG: join(root, 'global.npmrc') } });
    let stdout = '', stderr = '', failure: Error | undefined;
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk; });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk; });
    child.once('error', error => { failure = error; });
    const code = await new Promise<number | null>(resolve => child.once('close', resolve));
    console.log('PACKAGE_DRY_RUN=' + JSON.stringify({ executable: process.execPath, argv, cwd: exported,
      code, stdout, stderr, scope: 'scoped compiled payload, not a complete release build' }));
    if (failure) throw failure;
    assert.equal(code, 0, stderr);
    const packed = JSON.parse(stdout);
    const files: { readonly path: string; readonly size: number; readonly mode: number }[] = packed[0].files;
    assert.deepEqual(files.filter(file => file.path.startsWith('workers/runtime-build/')).map(file => file.path).sort(),
      buildNames.map(name => 'workers/runtime-build/' + name).sort());
    for (const path of [...nativeFiles, 'workers/runtime-controller/native_install_regression.py',
      'build/src/runtime/runtimes/provision-controller-guest.js',
      'build/src/runtime/runtimes/provision-native-install.js']) {
      assert.equal(files.filter(file => file.path === path).length, 1);
    }
    assert.equal(files.some(file => file.path === 'scripts/qa/native-install-regressions.mjs'), false);
    assert.equal(files.some(file => file.path.includes('.omo/') || file.path.includes('.handoff/')), false);
    const bindings = [];
    for (const file of files) {
      const bytes = await readFile(join(exported, file.path));
      assert.equal(bytes.length, file.size);
      if (file.path.startsWith('workers/runtime-build/')) assert.deepEqual(bytes, await readFile(file.path));
      bindings.push({ ...file, sha256: createHash('sha256').update(bytes).digest('hex') });
    }
    console.log('PACKAGE_SHIPPED_BINDINGS=' + JSON.stringify(bindings));
  } finally { await rm(root, { recursive: true }); }
}

test('compiled package loads exact helper bytes and emits a mount-free bounded bootstrap',
  { timeout: 30000 }, async () => {
    // Borrow in-tree sources read-only; only a separate compiled export receives
    // disposable worker copies.
    const workers = fileURLToPath(new URL('../../workers/runtime-controller/', import.meta.url));
    const source = join(process.cwd(), 'workers/runtime-controller');
    const exported = fileURLToPath(new URL('../../', import.meta.url));
    const copied = await realpath(exported) !== await realpath(process.cwd());
    if (copied) await mkdir(workers, { recursive: true });
    try {
      for (const entry of await readdir(source, { withFileTypes: true })) {
        if (copied && entry.isFile() && /\.(py|mjs)$/.test(entry.name)) {
          await copyFile(join(source, entry.name), join(workers, entry.name));
        }
      }
      const packageManifest = JSON.parse(await readFile(join(process.cwd(), 'package.json'), 'utf8'));
      const nativeFiles: string[] = packageManifest.files.filter((path: string) => path.startsWith('tests/native/'));
      assert.equal(nativeFiles.length, 4);
      for (const relative of ['package.json', 'scripts/qa/native-install-regressions.mjs', ...nativeFiles,
        ...buildNames.map(name => 'workers/runtime-build/' + name)]) {
        if (!copied) continue;
        await mkdir(dirname(join(exported, relative)), { recursive: true });
        await copyFile(join(process.cwd(), relative), join(exported, relative));
        assert.deepEqual(await readFile(join(exported, relative)), await readFile(join(process.cwd(), relative)));
      }
      const normal = await loadProvisionHelpers();
      assert.equal(normal.filter(item => item.name === 'prequalification.py'
        && item.installation === 'controller').length, 1);
      const bundles = [{ caseId: 'normal', helpers: normal }];
      for (const caseId of NATIVE_INSTALL_CASES) {
        bundles.push({ caseId, helpers: await loadNativeInstallHelpers(caseId) });
      }
      for (const { caseId, helpers } of bundles) await generatedBundle(caseId, helpers, source);
      for (const name of ['prequalification.py', 'bootstrap_enforce.py', 'native_install_regression.py']) {
        await checkPython(await readFile(join(source, name), 'utf8'), true);
      }
      for (const relative of nativeFiles.filter(path => path.includes('/fixtures/'))) {
        await checkPython(await readFile(join(process.cwd(), relative), 'utf8'), true);
      }
      const packet = await nativeInstallPacket();
      for (const name of ['provision-backend-capability.js', 'provision-build-wire.js']) {
        const bytes = await readFile(join(exported, 'build/src/runtime/runtimes', name));
        assert.deepEqual(packet.policy.host.filter(item => item.name === name),
          [{ name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }]);
      }
      const { nativeInstallPlan } = await import('../src/runtime/runtimes/provision-native-install.js');
      const request = { executeNativeInstallRegressionConsent: true, consentPacketSha256: packet.sha256,
        catalog: packet.policy.catalog, deadlineAt: Date.now() + 900000, acquisitionDeadlineAt: Date.now() + 300000 };
      const plan = await nativeInstallPlan(request, 'mount-original');
      assert.equal(plan.testSha256, createHash('sha256').update(await readFile(join(process.cwd(),
        'tests/native/runtime_provision_install_mount_test.py'))).digest('hex'));
      await assert.rejects(nativeInstallPlan({ ...request, consentPacketSha256: 'ff'.repeat(32) }, 'mount-original'),
        { code: 'native_packet_changed' });
      console.log('STATIC_NATIVE_PACKET=' + JSON.stringify(packet));
      await checkPackage(exported, nativeFiles);
    } finally {
      if (copied) await rm(workers, { recursive: true });
      if (copied) await rm(join(dirname(workers), 'runtime-build'), { recursive: true });
    }
  });

test('delegation adapter reaches the actual consent refusal before the asset acquisition boundary', async t => {
  const exported = fileURLToPath(new URL('../../', import.meta.url));
  for (const relative of ['scripts/qa/roadmap-cases/backend-provisioning.mjs',
    'scripts/qa/roadmap-cases/artifacts.mjs', 'src/report-path.ts']) {
    await mkdir(dirname(join(exported, relative)), { recursive: true });
    await copyFile(join(process.cwd(), relative), join(exported, relative));
  }
  const assetsUrl = new URL('../src/runtime/runtimes/provision-assets.js', import.meta.url);
  const assets = await import(assetsUrl.href);
  let acquisitions = 0;
  t.mock.module(assetsUrl, { namedExports: { ...assets,
    async withProvisionAssets() { acquisitions++; throw new Error('acquisition forbidden in this test'); } } });
  const guarded = await import(assetsUrl.href);
  await assert.rejects(guarded.withProvisionAssets({}, async () => undefined), /acquisition forbidden/);
  acquisitions = 0;
  const adapterUrl = new URL('../../scripts/qa/roadmap-cases/backend-provisioning.mjs', import.meta.url);
  const { runCase }: { readonly runCase: (input: { out: string; mutate: string }) =>
    Promise<{ status: string; cleanup: unknown }> } = await import(adapterUrl.href);
  const out = await mkdtemp(join(await realpath(tmpdir()), 't6p005-consent-'));
  const previous = process.env.WAKEIO_T6P_EXECUTE_TARGET_CONSENT;
  delete process.env.WAKEIO_T6P_EXECUTE_TARGET_CONSENT;
  try {
    const result = await runCase({ out, mutate: 'delegation-missing' });
    assert.equal(result.status, 'unavailable');
    assert.deepEqual(result.cleanup, { confirmed: true, scope: 'not_started' });
    assert.equal(JSON.parse(await readFile(join(out, 'backend.json'), 'utf8')).reason, 'consent_required');
    assert.equal(acquisitions, 0);
  } finally {
    if (previous === undefined) delete process.env.WAKEIO_T6P_EXECUTE_TARGET_CONSENT;
    else process.env.WAKEIO_T6P_EXECUTE_TARGET_CONSENT = previous;
    await rm(out, { recursive: true });
  }
});
