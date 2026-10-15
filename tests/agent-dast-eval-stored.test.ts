import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { storedRunReader } from '../src/agent-dast/eval/stored-results.js';
import { parsePassCriteria, verifyFindingProvenance, type EvalFinding } from '../src/agent-dast/eval/aggregate.js';

import { finalLabels, parseLabelSet } from '../src/agent-dast/eval/labels.js';
import { buildRunManifest, manifestDigest, parseChecklist } from '../src/agent-dast/eval/manifest.js';

// Only the engine is replaced. The real runner writes run.db, evidence, reports and its manifest.
// A separate process keeps module mocking out of other tests. No target server or target request.
const producer = `
import { mock } from 'node:test';
import { writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import * as engine from './build/src/dast.js';
mock.module('./build/src/dast.js', { namedExports: { ...engine, runDast: async () => [{
  id: 'offline-engine', status: 'completed', notes: [], findings: [{
    ruleId: 'native.sql', title: 'Synthetic storage fixture', description: 'No request sent',
    severity: 'high', confidence: 'high', kind: 'candidate', location: {url: 'http://127.0.0.1/items?id=1'}, remediation: 'fixture'
  }]
}] } });
const { runExecutionPlan } = await import('./build/src/agent-dast/runner.js');
const root=process.argv[1];
const policy=Buffer.from(JSON.stringify({version:1,kind:'sql-boolean-differential',baseUrl:'http://127.0.0.1',url:'http://127.0.0.1/items?id=1',parameter:'id',profile:'numeric',oracle:{jsonPointer:'/count',expectedBaseline:1,expectedTrue:1,expectedFalse:0}}));
await writeFile(root+'/policy.json',policy);
const result=await runExecutionPlan({plan:{version:1,kind:'wakeio.execution-plan',origin:'http://127.0.0.1',tasks:['t-sql','t-repeat'].map(id=>({id,engine:'native-dast',policy:'sql',maxRequests:8}))},inputs:{version:1,inputs:[{id:'sql',path:root+'/policy.json',sha256:createHash('sha256').update(policy).digest('hex')}]},outDir:root+'/out',consent:true,allowedOrigin:'http://127.0.0.1',allowPrivate:true,concurrency:1});
if(result.delivery!=='published'||result.requests.requestCount!==0) throw Error('offline fixture failed');
`;

test('offline: actual runner bundle links DB observation filename to engine finding in the task report', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-eval-stored-'));
  try {
    execFileSync(process.execPath, ['--experimental-test-module-mocks', '--input-type=module', '-e', producer, root], { cwd: process.cwd(), stdio: 'pipe' });
    const out = join(root, 'out');
    const files = await readdir(join(out, 'evidence'));
    const file = files.find(name => name === 'f-' + createHash('sha256').update('t-sql:0').digest('hex').slice(0, 32) + '.json')!;
    assert.ok(file, 'actual runner must persist the finding');
    const raw = await readFile(join(out, 'evidence', file)), evidence = JSON.parse(raw.toString());
    const db = new DatabaseSync(join(out, 'run.db'), { readOnly: true });
    let runId: string;
    try { runId = db.prepare('SELECT run_id FROM runs').get()!.run_id as string; } finally { db.close(); }
    const finding: EvalFinding = { findingId: file.slice(0, -5), type: 'sqli', severity: 'high', state: 'candidate',
      method: 'GET', path: '/items', param: 'id', location: 'query', authState: 'anonymous', round: 1,
      runRef: { runId, taskId: 't-sql' }, evidenceRef: `evidence/${file}`, evidenceSha256: createHash('sha256').update(raw).digest('hex') };
    assert.notEqual(finding.findingId, evidence.findingId, 'database and engine IDs are distinct');
    assert.equal(evidence.run_id, undefined);
    const reader = storedRunReader(out);
    const verify = (f = finding) => verifyFindingProvenance(f, reader.readEvidence, reader.verifyStoredFinding);
    assert.equal(verify().status, 'ok');
    assert.equal(verify({ ...finding, runRef: { runId: 'r-unrelated', taskId: 't-sql' } }).status, 'evidence_content_mismatch');
    assert.equal(verify({ ...finding, path: '/unrelated' }).status, 'evidence_content_mismatch');
    const repeatDb = new DatabaseSync(join(out, 'run.db'), { readOnly: true });
    try {
      const observation = repeatDb.prepare("SELECT * FROM finding_observations WHERE task_id='t-repeat'").get()!;
      assert.notEqual(observation.observation_id, observation.finding_id, 'repeat observation is deduplicated under the first finding');
      const ref = observation.evidence_ref as string, rawRepeat = await readFile(join(out, ref));
      assert.equal(verify({ ...finding, findingId: observation.observation_id as string, evidenceRef: ref,
        evidenceSha256: createHash('sha256').update(rawRepeat).digest('hex'), runRef: { runId, taskId: 't-repeat' } }).status, 'ok');
    } finally { repeatDb.close(); }
    const labelSet = parseLabelSet({ version: 1, target: 'offline-storage', commit: 'abc1234', negatives: [],
      vulnerabilities: [{ vulnId: 'v-sql', type: 'sqli', severity: 'high', split: 'final', site: finding }] });
    const labels = finalLabels(labelSet);
    const criteria = parsePassCriteria({ version: 1, labelSetHash: labels.hash, committedBeforeArmB: true, sharedRequestCap: 8, basis: 'candidate' });
    const checklist = parseChecklist({ version: 1, entries: [{ checkId: 'c-sql', engine: 'native-dast', check: 'native.sql' }] });
    const manifest = buildRunManifest({ runId: 'run-offline', createdAt: '2026-10-14T00:00:00Z', labels, criteria, checklist,
      coverageCells: [{ surface: 'GET /items id', checkId: 'c-sql' }] });
    const arm = (name: string) => ({ name, findings: [finding], rounds: [{ round: 1, kind: 'initial', requestCount: 0 }],
      coverage: { plannedCells: 1, executedCells: 0 }, durationMs: 0 });
    const inputs = { labels: labelSet, criteria, checklist, manifest,
      results: { manifestDigest: manifestDigest(manifest), armA: arm('A'), armB: arm('B') } };
    const args: string[] = [];
    for (const [name, value] of Object.entries(inputs)) {
      const path = join(root, name + '.json'); await writeFile(path, JSON.stringify(value)); args.push('--' + name, path);
    }
    const cli = JSON.parse(execFileSync(process.execPath, ['benchmarks/agent-eval/aggregate.mjs', ...args, '--run-a', out, '--run-b', out], { encoding: 'utf8', stdio: 'pipe' }));
    assert.equal(cli.provenanceAllOk, true);
    assert.equal(cli.provenance.a.findings[0].contentOk, true);
    assert.equal(cli.comparison.a.budget.total, 0);
    const reportPath = join(out, evidence.reportPath), report = JSON.parse(await readFile(reportPath, 'utf8'));
    const item = report.checks.flatMap((c: { findings: { id: string; ruleId: string }[] }) => c.findings).find((f: { id: string }) => f.id === evidence.findingId);
    item.ruleId = 'unrelated.rule'; await writeFile(reportPath, JSON.stringify(report));
    assert.equal(verify().status, 'evidence_content_mismatch', 'same engine ID with different rule must fail');
  } finally { await rm(root, { recursive: true, force: true }); }
});
