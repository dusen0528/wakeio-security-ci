import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseInitArgs, renderWorkflow, type WorkflowOptions } from '../src/init.js';
import { createReport, toSarif } from '../src/report.js';

const root = fileURLToPath(new URL('../../', import.meta.url));
const options: WorkflowOptions = { mode: 'action', actionRef: 'a'.repeat(40), out: 'wakeio-security-reports', tools: ['none'], pythonFiles: 0 };
const workflow = renderWorkflow({ ...options, codeScanning: true });
const hash = (text: string) => createHash('sha256').update(text).digest('hex');
function temporary(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), 'wakeio-code-scanning-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('non-opt-in templates match pre-change BASE_SHA bytes', () => {
  // Captured from f18b75bb0731e71620f8638c1b3482d91139d9b2 with these exact inputs.
  assert.equal(hash(renderWorkflow(options)), '28fe6dc1be619670fff41a108c35ec684b8e58897197f28ab7c15c53ffd23128');
  const { actionRef, ...npm } = options;
  assert.equal(hash(renderWorkflow({ ...npm, mode: 'npm' })), '1c991de2e1c2fc3500e989df47b1b0220ba97828a3944b62ec71b578a4495cb1');
});

test('code scanning is action-only and rejects malformed or repeated flags', () => {
  assert.equal(parseInitArgs(['init', '--mode', 'action', '--action-ref', options.actionRef!, '--code-scanning']).codeScanning, true);
  for (const args of [[], ['--mode', 'npm'], ['--mode', 'action', '--action-ref', 'main']]) {
    assert.throws(() => parseInitArgs(['init', ...args, '--code-scanning']));
  }
  for (const flag of ['--code-scanning=true', '--code-scanning=false', '--code-scanning\n']) {
    assert.throws(() => parseInitArgs(['init', '--mode', 'action', '--action-ref', options.actionRef!, flag]));
  }
  assert.throws(() => parseInitArgs(['init', '--mode', 'action', '--action-ref', options.actionRef!, '--code-scanning', '--code-scanning']));
  assert.throws(() => renderWorkflow({ ...options, codeScanning: 'true' } as unknown as WorkflowOptions));
  assert.throws(() => renderWorkflow({ out: 'reports', tools: [], pythonFiles: 0, codeScanning: true }), /requires explicit --mode action/);
});

test('opt-in CLI exits 2 for npm and preserves existing workflows', t => {
  const dir = temporary(t);
  const cli = join(root, 'build/src/cli.js');
  for (const mode of [[], ['--mode', 'npm']]) {
    const result = spawnSync(process.execPath, [cli, 'init', '--source', dir, ...mode, '--code-scanning'], { encoding: 'utf8' });
    assert.equal(result.status, 2); assert.match(result.stderr, /--code-scanning requires explicit --mode action/);
  }
  const args = [cli, 'init', '--source', dir, '--mode', 'action', '--action-ref', options.actionRef!, '--code-scanning'];
  assert.equal(spawnSync(process.execPath, args).status, 0);
  const path = join(dir, '.github/workflows/wakeio-security-ci.yml'), before = readFileSync(path, 'utf8');
  assert.equal(spawnSync(process.execPath, args).status, 2);
  assert.equal(readFileSync(path, 'utf8'), before); assert.equal(before, workflow);
});

test('generated upload has exact permissions, pinned actions and no gate suppression', () => {
  assert.equal(workflow.match(/permissions:\n([\s\S]*?)\njobs:/)![1], '  contents: read\n  actions: read\n  security-events: write\n');
  for (const [, uses] of workflow.matchAll(/uses: (.+)/g)) assert.match(uses, /^[\w/-]+@[a-f0-9]{40}$/);
  assert.match(workflow, /sarif_file: \$\{\{ steps.wakeio.outputs.report-sarif \}\}/);
  assert.match(workflow, /checkout_path: wakeio-source\n          category: wakeio-security-ci/);
  assert.doesNotMatch(workflow, /continue-on-error|pull_request_target|npm (ci|install)|\|\| true/);
  assert.match(workflow, /name: Upload reports\n        if: always\(\)/);
});

// Evaluate only the expressions emitted by our template, with controlled test contexts.
function conditions(event: string, fork: boolean, path: string, valid: string, cancelled: boolean) {
  return [...workflow.matchAll(/if: \$\{\{ (.+) \}\}/g)].map(([, expression]) => {
    const replaced = expression.replaceAll('steps.wakeio.outputs.report-sarif', 'path')
      .replaceAll('steps.wakeio-sarif.outputs.valid', 'valid')
      .replaceAll('github.event_name', 'event').replaceAll('github.event.pull_request.head.repo.full_name', 'head')
      .replaceAll('github.repository', 'repo');
    return Boolean(Function('event', 'head', 'repo', 'path', 'valid', 'cancelled', `return ${replaced}`)(event, fork ? 'fork/repo' : 'owned/repo', 'owned/repo', path, valid, () => cancelled));
  });
}

test('upload conditions permit gate failures but exclude forks, missing SARIF and cancellation', () => {
  for (const event of ['push', 'workflow_dispatch', 'pull_request']) {
    assert.deepEqual(conditions(event, false, '/fresh/report.sarif', 'true', false), [true, true]);
    assert.deepEqual(conditions(event, false, '', '', false), [false, false]);
    assert.deepEqual(conditions(event, false, '/fresh/report.sarif', 'true', true), [false, false]);
  }
  assert.deepEqual(conditions('pull_request', true, '/fresh/report.sarif', 'true', false), [false, false]);
});

function validateSarif(dir: string, path: string) {
  const script = workflow.split("          node --input-type=module <<'NODE'\n")[1].split('          NODE')[0]
    .split('\n').map(line => line.replace(/^          /, '')).join('\n');
  const output = join(dir, 'validation-output'); writeFileSync(output, '');
  execFileSync(process.execPath, ['--input-type=module', '-'], { input: script, env: { ...process.env, WAKEIO_SARIF: path, GITHUB_OUTPUT: output } });
  return readFileSync(output, 'utf8');
}

test('emitted validator skips absent, malformed, non-SARIF and symlink files', t => {
  const dir = temporary(t), path = join(dir, 'report.sarif');
  assert.equal(validateSarif(dir, path), '');
  for (const text of ['broken', '{}', 'null', '{"version":"2.1.0","runs":[]}', '{"version":"2.1.0","runs":[null]}']) {
    writeFileSync(path, text); assert.equal(validateSarif(dir, path), '');
  }
  writeFileSync(path, JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'fixture' } }, results: [] }] }));
  assert.equal(validateSarif(dir, path), 'valid=true\n');
  const link = join(dir, 'link'); symlinkSync(path, link); assert.equal(validateSarif(dir, link), '');
});

test('real Action preserves 0/1/2 and fresh SARIF resolves to source files without checkout prefix', t => {
  const dir = temporary(t), source = join(dir, 'wakeio-source'); mkdirSync(source);
  const name = 'owned space #?% 한글.ts';
  for (const [index, text, expected] of [[0, 'export const ready = true;', 0], [1, "export function route(req){db.query('SELECT '+req.query.sql)}", 1], [2, '', 2], [3, '', 2]] as const) {
    writeFileSync(join(source, name), text);
    const out = join(dir, `reports-${index}`), output = join(dir, `output-${index}`);
    writeFileSync(output, '');
    const result = spawnSync(process.execPath, [join(root, 'scripts/action-run.mjs')], { cwd: dir, encoding: 'utf8', env: {
      ...process.env, GITHUB_WORKSPACE: dir, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: join(dir, `summary-${index}`),
      GITHUB_REPOSITORY: 'owned/code-scanning', WAKEIO_ACTION_PATH: root, WAKEIO_SOURCE: index === 2 ? 'missing' : 'wakeio-source',
      WAKEIO_OUT: out, WAKEIO_TOOLS: index === 3 ? 'invalid' : 'none', WAKEIO_FAIL_ON: 'high', WAKEIO_URL: '', WAKEIO_API_POLICY: '',
    } });
    assert.equal(result.status, expected, result.stderr);
    const outputs = Object.fromEntries(readFileSync(output, 'utf8').trim().split('\n').map(line => { const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)]; }));
    assert.equal(outputs['exit-code'], String(expected));
    if (index === 3) { assert.equal(outputs['report-sarif'], ''); continue; }
    assert.equal(validateSarif(dir, outputs['report-sarif']), 'valid=true\n');
    const sarif = JSON.parse(readFileSync(outputs['report-sarif'], 'utf8'));
    assert.equal(sarif.version, '2.1.0');
    if (expected === 1) assert.ok(sarif.runs[0].results.length > 0);
    for (const result of sarif.runs[0].results) for (const location of result.locations ?? []) {
      const uri = location.physicalLocation?.artifactLocation?.uri; if (!uri) continue;
      const decoded = decodeURIComponent(uri);
      assert.equal(decoded, name); assert.doesNotMatch(uri, /^(?:\/|[A-Za-z]:|wakeio-source\/)|\\|(?:^|\/)\.\.(?:\/|$)/);
      assert.equal(readFileSync(resolve(source, decoded), 'utf8'), text);
    }
  }
});

test('SARIF projection encodes literal percent paths and normalizes separators without traversal', () => {
  for (const [path, expected] of [['src\\space #?.ts', 'src/space%20%23%3F.ts'], ['src/%2e%2e.ts', 'src/%252e%252e.ts'], ['../outside.ts', undefined], ['/absolute.ts', undefined], ['C:\\absolute.ts', undefined]]) {
    const report = createReport([{ id: 'fixture', status: 'completed', notes: [], findings: [{ ruleId: 'fixture', title: 'fixture', description: '', severity: 'high', confidence: 'high', kind: 'candidate', location: { path }, remediation: '' }] }], 'source', new Date());
    const sarif = toSarif(report) as any;
    assert.equal(sarif.runs[0].results[0].locations?.[0]?.physicalLocation?.artifactLocation?.uri, expected);
  }
});
