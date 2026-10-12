import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { parseCliArgs } from '../src/cli.js';
import { parseDoctorArgs } from '../src/doctor.js';
import { parseInitArgs, renderWorkflow } from '../src/init.js';

const exec = promisify(execFile), cli = resolve('build/src/cli.js'), runner = resolve('scripts/action-run.mjs');
const badValues = ['0', '-1', '+1', '1.5', '1e3', ' 1', '1 ', '01', 'NaN', 'Infinity', '9007199254740992'];
async function command(args: string[], env?: NodeJS.ProcessEnv) {
  try { const result = await exec(process.execPath, args, { env, timeout: 30_000, maxBuffer: 8 * 1024 * 1024 }); return { code: 0, ...result }; }
  catch (error) { const e = error as { code: number; stdout: string; stderr: string }; return { code: e.code, stdout: e.stdout, stderr: e.stderr }; }
}
async function reportAt(out: string, expected: number) {
  const bytes = await readFile(join(out, 'report.json'));
  const report = JSON.parse(bytes.toString());
  const agent = JSON.parse(await readFile(join(out, 'agent-report.json'), 'utf8'));
  assert.equal(agent.scanGate.exitCode, expected);
  for (const finding of agent.findings) assert.equal(finding.verification.vulnerabilityConfirmed, false);
  assert.equal(agent.reportArtifact.digest, createHash('sha256').update(bytes).digest('hex'));
  for (const name of ['report.md', 'report.sarif']) assert.ok((await readFile(join(out, name))).length);
  return report;
}

test('collector CLI, doctor and init strictly validate canonical bounded integers and duplicates', () => {
  for (const [flag, maximum] of [['--source-max-files', 10_000], ['--source-max-bytes', 134_217_728]] as const) {
    for (const parser of [parseCliArgs, parseDoctorArgs, parseInitArgs]) {
      const prefix = parser === parseCliArgs ? ['scan', '--source', 'missing'] : ['--source', 'missing'];
      for (const value of [...badValues, String(maximum + 1)]) assert.throws(() => parser([...prefix, flag, value]), `${flag} ${value}`);
      assert.throws(() => parser([...prefix, flag, '1', flag, '2']));
      assert.doesNotThrow(() => parser([...prefix, flag, String(maximum)]));
    }
    assert.throws(() => parseCliArgs(['scan', '--url', 'https://example.invalid', flag, '1']), /source/);
    assert.doesNotThrow(() => parseCliArgs(['scan', '--source', 'missing', '--url', 'https://example.invalid', flag, '1']));
    assert.throws(() => parseCliArgs(['scan', '--source', 'missing', `${flag}=1`, flag, '2']));
  }
});

test('doctor labels metadata inventory and preserves explicit collection and AST choices in the next command and init', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-collection-doctor-'));
  try {
    await writeFile(join(root, 'app.ts'), 'export const fixed = 1;');
    const flags = ['--source-max-files', '1002', '--source-max-bytes', '134217728', '--analysis-profile', 'extended'];
    const result = await command([cli, 'doctor', '--source', root, '--tools', 'none', '--json', ...flags]);
    assert.equal(result.code, 0, result.stderr);
    const doctor = JSON.parse(result.stdout);
    assert.equal(doctor.inventoryBasis, 'metadata_estimate_not_collector_coverage');
    assert.ok(doctor.collectionBudget);
    for (const choice of ['--source-max-files 1002', '--source-max-bytes 134217728', '--analysis-profile extended']) assert.ok(doctor.nextCommand.includes(choice));
    const parsed = parseInitArgs(['--source', root, ...flags]);
    const workflow = renderWorkflow({ ...parsed, pythonFiles: 0 });
    for (const choice of ['--source-max-files 1002', '--source-max-bytes 134217728', '--analysis-profile extended']) assert.ok(workflow.includes(choice));
    assert.deepEqual(await readdir(root), ['app.ts']);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('owned CLI collection default stays partial; explicit limits complete and find a late sorted source sink with Action parity', { timeout: 60_000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-collection-cli-')), root = join(top, 'source');
  try {
    await mkdir(root);
    for (let i = 0; i < 1001; i++) await writeFile(join(root, `a${String(i).padStart(4, '0')}.ts`), 'export const fixed = 1;\n');
    const late = join(root, 'zzz.ts'); await writeFile(late, 'export const fixed = 1;\n');
    const scan = async (name: string, flags: string[], code: number) => {
      const out = join(top, name); const result = await command([cli, 'scan', '--source', root, '--tools', 'none', '--analysis-profile', 'extended', '--out', out, ...flags]);
      assert.equal(result.code, code, result.stderr); return reportAt(out, code);
    };
    const baseline = await scan('default', [], 2);
    assert.equal(baseline.checks.find((c: any) => c.id === 'source.inventory').metrics.filesSelected, 1000);
    const flags = ['--source-max-files', '1002', '--source-max-bytes', '134217728'];
    const complete = await scan('complete', flags, 0);
    assert.equal(complete.checks.find((c: any) => c.id === 'source.inventory').metrics.filesSelected, 1002);
    await writeFile(late, 'function route(req) { eval(req.query.code); }\n');
    const omitted = await scan('late-default', [], 2);
    assert.equal(omitted.checks.flatMap((c: any) => c.findings).length, 0);
    const risky = await scan('late-expanded', flags, 1);
    const candidates = risky.checks.flatMap((c: any) => c.findings).filter((f: any) => f.kind === 'candidate');
    const finding = candidates.find((f: any) => f.ruleId === 'ast:dynamic-code');
    assert.ok(finding);
    assert.deepEqual(finding.location, { path: 'zzz.ts', line: 1, column: 23 });
    assert.equal(finding.staticFlow?.truncated, false);
    assert.ok(finding.staticFlow.steps.some((step: any) => step.role === 'source' && step.location.path === 'zzz.ts' && step.location.line === 1 && step.location.column === 28));
    assert.equal(finding.staticFlow.steps.at(-1).role, 'sink');
    assert.deepEqual(finding.staticFlow.steps.at(-1).location, { path: 'zzz.ts', line: 1, column: 23 });
    const actionOut = join(top, 'action');
    const action = await command([runner], { ...process.env, WAKEIO_MODE: '', WAKEIO_SOURCE: root, WAKEIO_URL: '', WAKEIO_API_POLICY: '', WAKEIO_ACTION_PATH: process.cwd(), GITHUB_WORKSPACE: top, WAKEIO_TOOLS: 'none', WAKEIO_ANALYSIS_PROFILE: 'extended', WAKEIO_SOURCE_MAX_FILES: '1002', WAKEIO_SOURCE_MAX_BYTES: '134217728', WAKEIO_OUT: actionOut });
    assert.equal(action.code, 1, action.stderr);
    const bundled = await reportAt(actionOut, 1);
    const semantics = (r: any) => r.checks.map((c: any) => ({ id: c.id, status: c.status, collectionBudget: c.collectionBudget, collectionEvidence: c.collectionEvidence, findings: c.findings }));
    assert.deepEqual(semantics(bundled), semantics(risky));
    assert.deepEqual(bundled.scope.collectionBudget, risky.scope.collectionBudget);
    assert.equal((await readdir(root)).length, 1002);
    assert.equal(await readFile(late, 'utf8'), 'function route(req) { eval(req.query.code); }\n');
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('Action numeric grammar rejects invalid selectors before setup or target access, including the shell preflight', async () => {
  const yaml = await readFile('action.yml', 'utf8');
  const shell = yaml.slice(yaml.indexOf('      run: |\n') + '      run: |\n'.length, yaml.indexOf('    - name: Set up Node.js 22')).split('\n').map(line => line.replace(/^        /, '')).join('\n');
  assert.ok(shell.includes('validate_limit'));
  for (const [key, name, maximum] of [['WAKEIO_SOURCE_MAX_FILES', 'source-max-files', 10_000], ['WAKEIO_SOURCE_MAX_BYTES', 'source-max-bytes', 134_217_728]] as const) {
    for (const value of [...badValues, String(maximum + 1)]) {
      const env = { ...process.env, WAKEIO_MODE: '', WAKEIO_SOURCE: '/missing-source', WAKEIO_ANALYSIS_PROFILE: 'default', WAKEIO_SOURCE_MAX_FILES: '', WAKEIO_SOURCE_MAX_BYTES: '', WAKEIO_ACTION_PATH: '/missing-action', [key]: value };
      const result = await command([runner], env); assert.equal(result.code, 2); assert.ok(result.stderr.includes(name)); assert.doesNotMatch(result.stderr, /setup failed/);
      await assert.rejects(exec('bash', ['-c', shell], { env }), (e: any) => e.code === 2 && e.stderr.includes(name));
    }
    await exec('bash', ['-c', shell], { env: { ...process.env, WAKEIO_SOURCE: '/source', WAKEIO_ANALYSIS_PROFILE: 'default', WAKEIO_SOURCE_MAX_FILES: '', WAKEIO_SOURCE_MAX_BYTES: '', [key]: String(maximum) } });
  }
  for (const key of ['WAKEIO_SOURCE_MAX_FILES', 'WAKEIO_SOURCE_MAX_BYTES']) {
    const env = { ...process.env, WAKEIO_MODE: '', WAKEIO_SOURCE: '', WAKEIO_ANALYSIS_PROFILE: 'default', WAKEIO_SOURCE_MAX_FILES: '', WAKEIO_SOURCE_MAX_BYTES: '', [key]: '1', WAKEIO_ACTION_PATH: '/missing-action' };
    const result = await command([runner], env);
    assert.equal(result.code, 2); assert.match(result.stderr, /requires source/);
    await assert.rejects(exec('bash', ['-c', shell], { env }), (e: any) => e.code === 2 && /requires source/.test(e.stderr));
  }
});
