// Packaged, owned-loopback demonstration: one SQLite endpoint changes behavior
// between the original finding and three explicitly consented rechecks.
// Requires Node.js 22.13+ for node:sqlite; never contacts an external target.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startNativeDastSqlite } from './native-dast-sqlite.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, '../build/src/cli.js');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const REPORTS = ['report.md', 'report.json', 'report.sarif', 'agent-report.json'];

async function command(args) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = [];
  child.stdout.on('data', chunk => out.push(chunk));
  child.stderr.on('data', chunk => err.push(chunk));
  const code = await new Promise((done, fail) => {
    child.once('error', fail);
    child.once('close', done);
  });
  return { code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') };
}

async function reportAt(directory, expectedStatus, expectedOutcome, expectedFindings) {
  const bytes = await readFile(join(directory, 'report.json'));
  const report = JSON.parse(bytes.toString('utf8'));
  const check = report.checks.find(value => value.id === 'url.sql-boolean');
  assert.equal(check?.status, expectedStatus);
  assert.equal(check?.dastExecution?.outcome, expectedOutcome);
  assert.equal(check?.findings.length, expectedFindings);
  for (const name of REPORTS) {
    const text = await readFile(join(directory, name), 'utf8');
    assert.ok(text.length > 0, `${name} must exist`);
    for (const forbidden of ['1 AND 1=1', '1 AND 1=2', 'id=1', 'expectedBaseline']) {
      assert.equal(text.includes(forbidden), false, `${name} exposed ${forbidden}`);
    }
  }
  return { bytes, report, check, sha256: sha256(bytes) };
}

async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== '--out' || !isAbsolute(process.argv[3])) {
    throw new Error('usage: node examples/native-dast-replay-demo.mjs --out ABSOLUTE_NEW_DIRECTORY');
  }
  const root = process.argv[3];
  await mkdir(root); // Existing artifacts are never reused or overwritten.
  const temporary = await mkdtemp(join(tmpdir(), 'wakeio-native-replay-demo-'));
  let target;
  try {
    target = await startNativeDastSqlite('vulnerable');
    const pkg = JSON.parse(await readFile(resolve(here, '../package.json'), 'utf8'));
    const policy = { version: 1, kind: 'sql-boolean-differential', baseUrl: `${target.origin}/`,
      url: target.url, parameter: 'id', profile: 'numeric',
      oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
    const policyPath = join(temporary, 'owned-policy.json');
    await writeFile(policyPath, `${JSON.stringify(policy)}\n`, { mode: 0o600 });
    const originalDir = join(root, 'original');
    const originalRun = await command(['scan', '--dast-policy', policyPath, '--active-consent', '--allow-private',
      '--dast-max-requests', '8', '--out', originalDir]);
    assert.equal(originalRun.code, 1, originalRun.stderr || originalRun.stdout);
    assert.equal(target.requests.length, 8);
    const original = await reportAt(originalDir, 'completed', 'observed', 1);
    const originalAgent = await readFile(join(originalDir, 'agent-report.json'));
    const sourceReportDataSha256 = sha256(JSON.stringify(original.report));
    const sourceExecutionSha256 = sha256(JSON.stringify(original.check.dastExecution));
    const findingId = original.check.findings[0].id;
    assert.match(findingId, /^[0-9a-f]{64}$/);
    const rows = [{ phase: 'original', exitCode: 1, httpRequests: 8, outcome: 'observed',
      findings: 1, reportSha256: original.sha256, files: REPORTS }];
    const replayArgs = ['replay', '--report', join(originalDir, 'report.json'), '--dast-policy', policyPath,
      '--finding', findingId, '--active-consent', '--allow-private'];

    for (const [phase, mode, expectedExit, expectedOutcome, expectedStatus, findings, requests] of [
      ['reproduced', 'vulnerable', 1, 'reproduced', 'completed', 1, 8],
      ['not-reproduced', 'bound', 0, 'not_reproduced', 'completed', 0, 8],
      ['inconclusive', 'server-error', 2, 'inconclusive', 'partial', 0, 1],
    ]) {
      target.setMode(mode);
      target.requests.length = 0;
      const directory = join(root, phase);
      const run = await command([...replayArgs, '--out', directory]);
      assert.equal(run.code, expectedExit, `${phase}: ${run.stderr || run.stdout}`);
      assert.equal(target.requests.length, requests, `${phase}: unexpected request count`);
      const checked = await reportAt(directory, expectedStatus,
        expectedOutcome === 'reproduced' ? 'observed' : expectedOutcome === 'not_reproduced' ? 'not_observed' : 'inconclusive', findings);
      assert.equal(checked.check.metrics.requestCount, requests);
      const receipt = JSON.parse(await readFile(join(directory, 'replay.json'), 'utf8'));
      assert.equal(receipt.kind, 'native-dast-finding-replay');
      assert.equal(receipt.outcome, expectedOutcome);
      assert.equal(receipt.findingId, findingId);
      assert.deepEqual(receipt.reportArtifact, { name: 'report.json', algorithm: 'sha256', digest: checked.sha256 });
      assert.equal(receipt.sourceReportSha256, sourceReportDataSha256);
      assert.equal(receipt.sourceExecutionSha256, sourceExecutionSha256);
      assert.equal(receipt.freshExecutionSha256, sha256(JSON.stringify(checked.check.dastExecution)));
      assert.deepEqual(await readFile(join(originalDir, 'report.json')), original.bytes);
      assert.deepEqual(await readFile(join(originalDir, 'agent-report.json')), originalAgent);
      rows.push({ phase, exitCode: run.code, httpRequests: requests, outcome: expectedOutcome,
        findings, reportSha256: checked.sha256, files: [...REPORTS, 'replay.json'] });
      process.stdout.write(`${phase}: exit ${run.code}, ${requests} GET(s), ${expectedOutcome}; ${directory}\n`);
    }
    const receipt = { version: 1, scope: 'owned-loopback-real-sqlite-only', packageVersion: pkg.version,
      originalReportSha256: original.sha256, originalReportsUnchanged: true, rows };
    await writeFile(join(root, 'demo-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    process.stdout.write(`Owned replay demonstration complete: ${root}\n`);
  } finally {
    await target?.close();
    await rm(temporary, { recursive: true, force: true });
  }
}

await main();
