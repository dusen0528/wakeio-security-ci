import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { sha } from './run.mjs';

/** Projection from an untouched runner bundle; no label input or state promotion. */
export async function projectArm(result) {
  if (result.rounds.length !== 1) throw Error('multi_round_cli_support_required');
  const round = result.rounds[0], db = new DatabaseSync(join(round.outDir, 'run.db'), { readOnly: true });
  try {
    const admitted = Number(db.prepare('SELECT coalesce(sum(request_count),0) n FROM ledger').get().n);
    assert.equal(admitted, round.requestCount); assert.equal(admitted, result.actualRequests);
    const rows = db.prepare(`SELECT o.observation_id AS findingId, o.task_id AS taskId, o.evidence_ref AS evidenceRef,
      o.severity, f.rule_id AS ruleId, f.state, s.method,s.path,s.param,s.location,s.auth_state AS authState
      FROM finding_observations o JOIN findings f ON f.finding_id=o.finding_id
      JOIN surface s ON s.surface_id=o.surface_id`).all();
    const findings = await Promise.all(rows.map(async ({taskId,ruleId,...row}) => {
      if (ruleId !== 'dast.sql-boolean-differential') throw Error('unexpected_fixture_rule');
      return { ...row, type: 'sqli', round: 1, runRef: { runId: round.runId, taskId }, evidenceSha256: sha(await readFile(join(round.outDir,row.evidenceRef))) };
    }));
    const completed = db.prepare("SELECT c.task_id FROM coverage c JOIN tasks t ON t.task_id=c.task_id WHERE c.\"check\"='group.native-dast' AND c.result='executed' AND t.status='completed'").all();
    const ids = new Set(completed.map(row => row.task_id));
    const coverage = { plannedCells: 2, executedCells: ['t-endpoint-0','t-endpoint-1'].filter(id => ids.has(id)).length };
    let tokens = 0;
    if (result.name === 'B') {
      const records = (await readFile(result.rounds[0].outDir.replace(/\/round-1$/, '') + '-provider/ledger.jsonl', 'utf8')).trim().split('\n').map(JSON.parse);
      if (records.some(row => row.inputTokens === null || row.outputTokens === null)) throw Error('model_usage_unavailable');
      tokens = records.reduce((n,row) => n + row.inputTokens + row.outputTokens, 0);
    }
    return { name: result.name, durationMs: result.durationMs, tokens, coverage, findings,
      rounds: [{ round: 1, kind: 'initial', requestCount: admitted }] };
  } finally { db.close(); }
}
