// Reproducible, owned loopback demonstration of the native numeric SQL DAST slice.
// Requires this package's built CLI and Node 22.13+ for the example SQLite fixture.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startNativeDastSqlite } from './native-dast-sqlite.mjs';

const REPORT_FILES = ['report.md', 'report.json', 'report.sarif', 'agent-report.json'];
const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, '../build/src/cli.js');

async function launch(args) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const stdout = [], stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  const code = await new Promise((done, fail) => {
    child.once('error', fail);
    child.once('close', done);
  });
  return { code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
}

async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== '--out' || !isAbsolute(process.argv[3])) {
    throw new Error('usage: node examples/native-dast-demo.mjs --out ABSOLUTE_NEW_DIRECTORY');
  }
  const root = process.argv[3];
  await mkdir(root); // Refuse to overwrite an earlier demonstration or user reports.
  const temporary = await mkdtemp(join(tmpdir(), 'wakeio-native-dast-demo-'));
  try {
    for (const [mode, expectedCode, expectedFindings] of [['vulnerable', 1, 1], ['bound', 0, 0]]) {
      const fixture = await startNativeDastSqlite(mode);
      try {
        const policy = { version: 1, kind: 'sql-boolean-differential', baseUrl: `${fixture.origin}/`,
          url: fixture.url, parameter: 'id', profile: 'numeric',
          oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
        const policyFile = join(temporary, `${mode}-policy.json`);
        const reportDir = join(root, mode);
        await writeFile(policyFile, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o600 });
        const run = await launch(['scan', '--dast-policy', policyFile, '--active-consent',
          '--allowed-origin', fixture.origin, '--allow-private', '--dast-max-requests', '8',
          '--fail-on', 'high', '--out', reportDir]);
        assert.equal(run.code, expectedCode, `${mode} CLI exit: ${run.stderr || run.stdout}`);
        assert.equal(fixture.requests.length, 8, `${mode} must make exactly eight GET requests`);
        assert.ok(fixture.requests.every(request => request.method === 'GET' && request.path === '/items'));
        const reportText = await readFile(join(reportDir, 'report.json'), 'utf8');
        const report = JSON.parse(reportText);
        const check = report.checks.find(value => value.id === 'url.sql-boolean');
        assert.equal(check?.status, 'completed');
        assert.equal(check?.findings.length, expectedFindings);
        assert.equal(check?.metrics?.requestCount, 8);
        assert.equal(check?.dastExecution?.outcome, mode === 'vulnerable' ? 'observed' : 'not_observed');
        for (const name of REPORT_FILES) {
          const artifact = await readFile(join(reportDir, name), 'utf8');
          assert.ok(artifact.length > 0, `${name} must exist`);
          assert.equal(artifact.includes('1 AND 1=1'), false, `${name} leaked a probe value`);
          assert.equal(artifact.includes('1 AND 1=2'), false, `${name} leaked a probe value`);
        }
        process.stdout.write(`${mode}: exit ${run.code}, ${expectedFindings} candidate(s), 8 GETs; ${reportDir}\n`);
      } finally { await fixture.close(); }
    }
    process.stdout.write(`Owned loopback reports: ${root}\n`);
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

await main();
