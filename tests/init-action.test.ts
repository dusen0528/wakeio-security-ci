import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initMain, parseInitArgs, renderWorkflow, type WorkflowOptions } from '../src/init.js';

const PIN = 'a'.repeat(40);
const options: WorkflowOptions = { mode: 'action', actionRef: PIN, out: 'wakeio-security-reports', tools: ['none'], pythonFiles: 0 };
async function quiet(args: string[]) {
  const out = process.stdout.write, err = process.stderr.write;
  process.stdout.write = (() => true) as typeof out; process.stderr.write = (() => true) as typeof err;
  try { return await initMain(args); } finally { process.stdout.write = out; process.stderr.write = err; }
}

test('explicit pinned Action template separates collected source and fresh report delivery', () => {
  const workflow = renderWorkflow({ ...options, requireCodeAnalysis: true, sourceMaxFiles: 10000,
    sourceMaxBytes: 134217728, analysisProfile: 'extended' });
  assert.match(workflow, new RegExp(`uses: dusen0528/wakeio-security-ci@${PIN}`));
  assert.match(workflow, /persist-credentials: false\n\s+path: wakeio-source/);
  assert.match(workflow, /source: wakeio-source/);
  assert.match(workflow, /tools: "none"/);
  assert.match(workflow, /out: "wakeio-security-reports\/\$\{\{ github.run_id \}\}-\$\{\{ github.run_attempt \}\}"/);
  assert.match(workflow, /path: "wakeio-security-reports\/\$\{\{ github.run_id \}\}-\$\{\{ github.run_attempt \}\}"/);
  assert.match(workflow, /require-code-analysis: 'true'/); assert.match(workflow, /analysis-profile: extended/);
  assert.match(workflow, /source-max-files: '10000'/); assert.match(workflow, /source-max-bytes: '134217728'/);
  assert.match(workflow, /if: always\(\)/); assert.match(workflow, /if-no-files-found: error/);
  assert.equal(/\brun:\s|npm ci|npx|npm install|continue-on-error|working-directory:/.test(workflow), false);
});

test('CLI and exported renderer reject unreviewed Action references and output interpretation', () => {
  for (const actionRef of ['', 'main', 'v0.5.0', 'a'.repeat(39), 'a'.repeat(41), '${{ inputs.ref }}', PIN + '\n']) {
    assert.throws(() => renderWorkflow({ ...options, actionRef }));
    assert.throws(() => parseInitArgs(['init', '--mode', 'action', '--action-ref', actionRef]));
  }
  assert.throws(() => renderWorkflow({ ...options, mode: 'npm' }));
  assert.throws(() => parseInitArgs(['init', '--action-ref', PIN]));
  assert.throws(() => parseInitArgs(['init', '--mode', 'action']));
  assert.throws(() => parseInitArgs(['init', '--mode', 'action', '--mode', 'npm', '--action-ref', PIN]));
  for (const out of ['wakeio-source', 'wakeio-source/reports', 'Wakeio-Source/reports', '../reports', '/reports',
    'C:\\reports', './reports', 'one//two', 'reports/*', '${{ runner.temp }}', 'reports\nwith: evil', 'reports: evil', 'one/../two']) {
    assert.throws(() => renderWorkflow({ ...options, out }), out);
    assert.throws(() => parseInitArgs(['init', '--mode', 'action', '--action-ref', PIN, '--out', out]), out);
  }
  for (const malformed of [{ tools: ['none\nwith: evil'] }, { sourceMaxFiles: 0 }, { sourceMaxBytes: 134217729 },
    { analysisProfile: 'floating' }, { requireCodeAnalysis: 'true' }, { pythonFiles: '1\nrun: evil' }])
    assert.throws(() => renderWorkflow({ ...options, ...malformed } as WorkflowOptions));
});

test('legacy npm rendering remains the default and does not silently acquire an Action', () => {
  const legacy = { out: "reports: reviewer's copy", tools: ['none'], pythonFiles: 1 };
  assert.equal(renderWorkflow(legacy), renderWorkflow({ ...legacy, mode: 'npm' }));
  assert.match(renderWorkflow(legacy), /npm ci --ignore-scripts/); assert.match(renderWorkflow(legacy), /npx --no-install/);
  assert.equal(renderWorkflow(legacy).includes('dusen0528/wakeio-security-ci@'), false);
  assert.equal(parseInitArgs(['init']).mode, 'npm');
});

test('public renderer uses captured values instead of rereading changing caller getters', () => {
  let refs = 0, paths = 0, tools = 0, controls = 0;
  const changing = { ...options };
  Object.defineProperties(changing, {
    actionRef: { enumerable: true, get: () => refs++ === 0 ? PIN : 'main\nwith: injected' },
    out: { enumerable: true, get: () => paths++ === 0 ? 'owned-reports' : 'wakeio-source/reports' },
    tools: { enumerable: true, get: () => tools++ === 0 ? ['none'] : ['none\nwith: injected'] },
    requireCodeAnalysis: { enumerable: true, get: () => controls++ === 0 ? true : 'injected' },
  });
  const workflow = renderWorkflow(changing);
  assert.match(workflow, new RegExp(`uses: dusen0528/wakeio-security-ci@${PIN}`));
  assert.match(workflow, /out: "owned-reports\//); assert.match(workflow, /tools: "none"/);
  assert.match(workflow, /require-code-analysis: 'true'/);
  assert.equal(workflow.includes('injected'), false); assert.equal(workflow.includes('wakeio-source/reports'), false);
  assert.deepEqual([refs, paths, tools, controls], [1, 1, 1, 1]);
});

test('owned non-npm init writes only the workflow, never reads or executes project code, and refuses overwrite', async t => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-init-action-producer-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'); await mkdir(source);
  const app = "throw new Error('OWNED_CODE_MUST_NOT_EXECUTE');\n";
  await writeFile(join(source, 'app.js'), app);
  const args = ['init', '--source', source, '--mode', 'action', '--action-ref', PIN];
  assert.equal(await quiet(args), 0);
  const workflow = join(source, '.github', 'workflows', 'wakeio-security-ci.yml'), before = await readFile(workflow, 'utf8');
  assert.equal(before, renderWorkflow(options));
  assert.equal(await quiet(args), 2); assert.equal(await readFile(workflow, 'utf8'), before);
  assert.equal(await readFile(join(source, 'app.js'), 'utf8'), app);
  assert.deepEqual((await readdir(source)).sort(), ['.github', 'app.js']);
  const invalidRoot = join(top, 'invalid'); await mkdir(invalidRoot);
  assert.equal(await quiet(['init', '--source', invalidRoot, '--mode', 'action', '--action-ref', 'main']), 2);
  assert.deepEqual(await readdir(invalidRoot), []);
});
