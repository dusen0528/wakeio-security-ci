import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { renderWorkflow } from '../src/init.js';

const exec = promisify(execFile);
const cli = resolve(process.cwd(), 'build', 'src', 'cli.js');
const actionRunner = resolve(process.cwd(), 'scripts', 'action-run.mjs');
const actionBundle = resolve(process.cwd(), 'dist-action', 'wakeio-security-ci.mjs');
const releaseScript = resolve(process.cwd(), 'scripts', 'package-release.mjs');

test('doctor is read-only, skips vendored Python, and marks Bandit not applicable without Python', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-doctor-v04-'));
  try {
    await mkdir(join(root, 'vendor'), { recursive: true });
    await writeFile(join(root, 'vendor', 'ignored.py'), 'raise RuntimeError("must not be read or run")\n');
    await writeFile(join(root, 'app.js'), 'export const safe = true;\n');
    await writeFile(join(root, 'package.json'), JSON.stringify({ scripts: { postinstall: 'touch DOCTOR_EXECUTED' } }));
    const result = await exec(process.execPath, [cli, 'doctor', '--source', root, '--tools', 'bandit', '--json']);
    const doctor = JSON.parse(result.stdout);
    assert.equal(doctor.execution.targetCode, 'none');
    assert.equal(doctor.execution.network, 'none');
    assert.equal(doctor.inventory.pythonFiles, 0);
    assert.equal(doctor.tools[0].availability, 'not_applicable');
    assert.deepEqual(doctor.expectedTransfers, []);
    await assert.rejects(readFile(join(root, 'DOCTOR_EXECUTED')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('init renders a parseable block-scalar command and quotes YAML artifact paths', () => {
  const workflow = renderWorkflow({ out: "reports: reviewer's copy", tools: ['none'], pythonFiles: 1 });
  assert.match(workflow, /run: >-\n\s+npx --no-install/);
  assert.match(workflow, /--out 'reports: reviewer'\\''s copy'/);
  assert.match(workflow, /path: "reports: reviewer's copy"/);
  assert.match(workflow, /actions\/checkout@11d5960a326750d5838078e36cf38b85af677262/);
  assert.match(workflow, /actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /detected 1 Python file/);
});

test('source archive Action bundle runs without node_modules and keeps reports on a clean scan', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-action-v04-'));
  const action = join(top, 'action');
  const workspace = join(top, 'workspace');
  try {
    await mkdir(join(action, 'dist-action'), { recursive: true });
    await mkdir(join(action, 'scripts'), { recursive: true });
    await mkdir(join(workspace, 'app'), { recursive: true });
    await copyFile(actionRunner, join(action, 'scripts', 'action-run.mjs'));
    await copyFile(resolve(process.cwd(), 'scripts', 'install-tools.mjs'), join(action, 'scripts', 'install-tools.mjs'));
    await copyFile(actionBundle, join(action, 'dist-action', 'wakeio-security-ci.mjs'));
    await chmod(join(action, 'scripts', 'action-run.mjs'), 0o755);
    await writeFile(join(workspace, 'app', 'main.ts'), 'export const safe = true;\n');
    await writeFile(join(workspace, 'app', 'package.json'), JSON.stringify({ scripts: { postinstall: 'touch ACTION_TARGET_EXECUTED' } }));
    const output = join(workspace, 'output');
    const summary = join(workspace, 'summary');
    await writeFile(output, '');
    await writeFile(summary, '');
    const result = await exec(process.execPath, [join(action, 'scripts', 'action-run.mjs')], {
      cwd: workspace,
      env: {
        ...process.env,
        WAKEIO_ACTION_PATH: action,
        GITHUB_WORKSPACE: workspace,
        WAKEIO_SOURCE: 'app',
        WAKEIO_TOOLS: 'none',
        WAKEIO_FAIL_ON: 'none',
        WAKEIO_PROJECT_ID: '',
        WAKEIO_OUT: 'wakeio-security-reports',
        GITHUB_OUTPUT: output,
        GITHUB_STEP_SUMMARY: summary,
        GITHUB_REPOSITORY: '',
      },
      maxBuffer: 4 * 1024 * 1024,
    });
    assert.equal(result.stderr.includes('npm ci') || result.stderr.includes('npm run build'), false);
    assert.match(await readFile(output, 'utf8'), /exit-code=0/);
    assert.match(await readFile(summary, 'utf8'), /Native archive cache: not/);
    for (const name of ['report.json', 'report.sarif', 'report.md', 'action-status.json']) {
      await assert.doesNotReject(readFile(join(workspace, 'wakeio-security-reports', name)));
    }
    await assert.rejects(readFile(join(workspace, 'ACTION_TARGET_EXECUTED')));
    await assert.rejects(readFile(join(action, 'node_modules')));
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test('setup failure does not reuse a stale report for Action outputs', async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-action-stale-v04-'));
  const action = join(top, 'action');
  const workspace = join(top, 'workspace');
  try {
    await mkdir(action, { recursive: true });
    await mkdir(join(workspace, 'wakeio-security-reports'), { recursive: true });
    await copyFile(actionRunner, join(action, 'action-run.mjs'));
    await writeFile(join(workspace, 'wakeio-security-reports', 'report.json'), JSON.stringify({ checks: [{ status: 'completed', findings: [{ id: 'stale-secret' }] }] }));
    const output = join(workspace, 'output');
    const summary = join(workspace, 'summary');
    await writeFile(output, '');
    await writeFile(summary, '');
    await assert.rejects(exec(process.execPath, [join(action, 'action-run.mjs')], {
      cwd: workspace,
      env: { ...process.env, WAKEIO_ACTION_PATH: action, GITHUB_WORKSPACE: workspace, WAKEIO_SOURCE: '.', WAKEIO_TOOLS: 'none', WAKEIO_OUT: 'wakeio-security-reports', GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary, GITHUB_REPOSITORY: '' },
    }), (error: any) => error.code === 2);
    const outputText = await readFile(output, 'utf8');
    const summaryText = await readFile(summary, 'utf8');
    assert.match(outputText, /setup-status=failure/);
    assert.match(outputText, /scan-status=not-run/);
    assert.match(outputText, /finding-count=0/);
    assert.match(summaryText, /report unavailable/);
    assert.equal(summaryText.includes('stale-secret'), false);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test('offline native installer refuses a cache miss before network access', async () => {
  const cache = await mkdtemp(join(tmpdir(), 'wakeio-installer-cache-v04-'));
  try {
    await assert.rejects(exec(process.execPath, [resolve(process.cwd(), 'scripts', 'install-tools.mjs'), '--tools', 'gitleaks', '--cache-dir', cache, '--offline', '--json', '--metadata']), (error: any) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /No verified cached gitleaks archive/);
      return true;
    });
  } finally {
    await rm(cache, { recursive: true, force: true });
  }
});

test('release source archive carries the bundle licenses and packed npm metadata drops dev scripts', async () => {
  const out = await mkdtemp(join(tmpdir(), 'wakeio-release-v04-'));
  try {
    await exec(process.execPath, [releaseScript, '--root', process.cwd(), '--out-dir', out], { maxBuffer: 4 * 1024 * 1024 });
    const files = await readdir(out);
    const sourceArchive = join(out, files.find((file) => file.includes('-source-'))!);
    const npmArchive = join(out, files.find((file) => file.endsWith('.tgz'))!);
    const sourceListing = (await exec('tar', ['-tzf', sourceArchive])).stdout;
    assert.match(sourceListing, /dist-action\/wakeio-security-ci\.mjs/);
    assert.match(sourceListing, /dist-action\/THIRD_PARTY_LICENSES\.txt/);
    const notices = (await exec('tar', ['-xOf', sourceArchive, 'wakeio-security-ci/dist-action/THIRD_PARTY_LICENSES.txt'])).stdout;
    assert.match(notices, /typescript .*ThirdPartyNoticeText\.txt/i);
    const packed = JSON.parse((await exec('tar', ['-xOf', npmArchive, 'package/package.json'])).stdout);
    assert.equal('scripts' in packed, false);
    assert.equal('devDependencies' in packed, false);
  } finally {
    await rm(out, { recursive: true, force: true });
  }
});
