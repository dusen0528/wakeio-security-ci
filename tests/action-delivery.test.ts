import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const exec = promisify(execFile);
const runner = process.env.WAKEIO_TEST_ACTION_RUNNER ?? resolve('scripts/action-run.mjs');
async function fixture(t: TestContext) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-action-delivery-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const action = join(top, 'action'), workspace = join(top, 'workspace'), reports = join(workspace, 'reports');
  await mkdir(join(action, 'dist-action'), { recursive: true }); await mkdir(workspace);
  // Source mode invokes the Action's trusted installer even for tools=none;
  // that selection returns empty metadata before any download or executable.
  await mkdir(join(action, 'scripts'));
  await copyFile(resolve('scripts/install-tools.mjs'), join(action, 'scripts', 'install-tools.mjs'));
  // Owned protocol fixture: writes synthetic artifacts only, with no scan, target read or network.
  await writeFile(join(action, 'dist-action', 'wakeio-security-ci.mjs'), `
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
const out = resolve(process.argv[process.argv.indexOf('--out') + 1]);
const code = Number(process.env.OWNED_SCAN_EXIT);
const checks = [{ id:'owned.fixture',status:code===2?'partial':'completed',findings:code===1?[{severity:'high'}]:[],notes:[] }];
const report = JSON.stringify({schemaVersion:'1.0.0',checks,startedAt:new Date().toISOString()})+'\\n';
await mkdir(out,{recursive:true});
await writeFile(join(out,'report.json'),report);
if(process.env.OWNED_AUX_MODE !== 'json-only') {
  await writeFile(join(out,'report.md'),'Owned synthetic report '+new Date().toISOString()+'\\n');
  await writeFile(join(out,'report.sarif'),JSON.stringify({version:'2.1.0',runs:[],ownedTimestamp:new Date().toISOString()}));
  await writeFile(join(out,'agent-report.json'),JSON.stringify({schemaVersion:'1.0.0',reportArtifact:{name:'report.json',algorithm:'sha256',digest:createHash('sha256').update(report).digest('hex')},scanGate:{exitCode:code}}));
}
process.exitCode=code;
`);
  return { top, action, workspace, reports, output: join(top, 'outputs'), summary: join(top, 'summary') };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function run(f: Fixture, code: number, overrides: NodeJS.ProcessEnv = {}) {
  const env = { ...process.env, WAKEIO_MODE: '', WAKEIO_ACTION_PATH: f.action, GITHUB_WORKSPACE: f.workspace,
    WAKEIO_SOURCE: '.', WAKEIO_URL: '', WAKEIO_API_POLICY: '', WAKEIO_OUT: 'reports', WAKEIO_TOOLS: 'none',
    WAKEIO_REQUIRE_CODE_ANALYSIS: 'false', WAKEIO_ANALYSIS_PROFILE: 'default', WAKEIO_SOURCE_MAX_FILES: '',
    WAKEIO_SOURCE_MAX_BYTES: '', GITHUB_OUTPUT: f.output, GITHUB_STEP_SUMMARY: f.summary, OWNED_SCAN_EXIT: String(code), ...overrides };
  try { const result = await exec(process.execPath, [runner], { env, timeout: 15_000 }); return { code: 0, ...result }; }
  catch (error) { const e = error as { code: number; stdout: string; stderr: string }; return { code: e.code, stdout: e.stdout, stderr: e.stderr }; }
}
async function outputs(path: string) {
  return Object.fromEntries((await readFile(path, 'utf8')).trim().split('\n').map(line => {
    const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)];
  }));
}

for (const code of [0, 1, 2]) {
  test(`Action delivery preserves scanner ${code} when every required channel is writable`, async t => {
    const f = await fixture(t), result = await run(f, code);
    assert.equal(result.code, code, result.stderr);
    const receipt = JSON.parse(await readFile(join(f.reports, 'action-status.json'), 'utf8'));
    assert.equal(receipt.exitCode, code); assert.equal(receipt.scanExitCode, code); assert.equal(receipt.deliveryStatus, 'delivered');
    const out = await outputs(f.output);
    assert.equal(out['exit-code'], String(code)); assert.equal(out['scan-exit-code'], String(code)); assert.equal(out['delivery-status'], 'delivered');
    for (const name of ['report-json', 'report-sarif', 'report-markdown', 'report-agent']) assert.ok(out[name]);
  });
}

for (const code of [0, 1]) {
  test(`Action delivery output failure overrides scanner ${code} and corrects persisted receipt`, async t => {
    const f = await fixture(t), badOutput = join(f.top, 'output-directory'); await mkdir(badOutput);
    const result = await run(f, code, { GITHUB_OUTPUT: badOutput });
    assert.equal(result.code, 2, result.stderr);
    const receipt = JSON.parse(await readFile(join(f.reports, 'action-status.json'), 'utf8'));
    assert.equal(receipt.exitCode, 2); assert.equal(receipt.scanExitCode, code); assert.equal(receipt.deliveryStatus, 'failed');
    assert.equal(receipt.failurePhase, 'delivery');
    assert.equal(JSON.parse(await readFile(join(f.reports, 'agent-report.json'), 'utf8')).scanGate.exitCode, code);
  });
  test(`Action delivery status-artifact failure overrides scanner ${code} in writable outputs`, async t => {
    const f = await fixture(t); await mkdir(join(f.reports, 'action-status.json'), { recursive: true });
    const result = await run(f, code); assert.equal(result.code, 2, result.stderr);
    const out = await outputs(f.output);
    assert.equal(out['exit-code'], '2'); assert.equal(out['scan-exit-code'], String(code)); assert.equal(out['delivery-status'], 'failed');
  });
}

test('Action setup failure never advertises stale report paths as current artifacts', async t => {
  const f = await fixture(t); await run(f, 0);
  const before = await readFile(join(f.reports, 'report.json'));
  await writeFile(f.output, '');
  const result = await run(f, 0, { WAKEIO_ACTION_PATH: join(f.top, 'missing-action') }); assert.equal(result.code, 2);
  const out = await outputs(f.output);
  for (const name of ['report-json', 'report-sarif', 'report-markdown', 'report-agent']) assert.equal(out[name], '', name);
  assert.equal(out['scan-exit-code'], '');
  assert.deepEqual(await readFile(join(f.reports, 'report.json')), before, 'stale evidence remains preserved, without current-run outputs');
});

for (const existing of [false, true]) {
  test(`Action fresh JSON does not advertise ${existing ? 'stale' : 'missing'} sibling formats`, async t => {
    const f = await fixture(t);
    if (existing) { await run(f, 0); await writeFile(f.output, ''); }
    const result = await run(f, 0, { OWNED_AUX_MODE: 'json-only' }); assert.equal(result.code, 0);
    const out = await outputs(f.output); assert.equal(out['report-json'], join(f.reports, 'report.json'));
    for (const name of ['report-sarif', 'report-markdown', 'report-agent']) assert.equal(out[name], '', name);
  });
}
