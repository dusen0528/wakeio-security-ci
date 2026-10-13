import test from 'node:test';
import assert from 'node:assert/strict';
import type { CheckResult, Finding } from '../src/contracts.js';
import { createReport, toAgentReport, toMarkdown } from '../src/report.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';

const START = '2026-10-14T00:00:00.000Z';
const finding = (line: number, overrides: Partial<Finding> = {}): Finding => ({
  ruleId: 'owned:report-selector', title: `Owned metadata ${line}`,
  description: 'Inert report metadata; no source execution.', severity: 'high',
  confidence: 'medium', kind: 'candidate', location: { path: 'app.ts', line, column: 1 },
  remediation: 'Review the local evidence independently.', ...overrides,
});
const check = (id: string, findings: Finding[] = []): CheckResult => ({
  id, status: 'completed', findings, notes: [],
});

// Read the displayed selector within each human-facing finding block, including
// repeated rows. The expected values come from the separate canonical projection.
function displayedPairs(markdown: string) {
  const section = markdown.split('## Findings\n')[1];
  assert.ok(section, 'human report has a Findings section');
  const blocks = section.split(/(?=^- \[(?:INFO|LOW|MEDIUM|HIGH|CRITICAL)\] \[)/m)
    .filter(block => /^- \[(?:INFO|LOW|MEDIUM|HIGH|CRITICAL)\] \[/.test(block));
  return blocks.map(block => {
    const indexes = [...block.matchAll(/^  - Check index: (0|[1-9]\d*)$/gm)];
    const ids = [...block.matchAll(/^  - ID: ([a-f0-9]{64})$/gm)];
    assert.equal(indexes.length, 1, 'each displayed row has one canonical numeric index');
    assert.equal(ids.length, 1, 'each displayed row has one finding ID');
    return { checkIndex: Number(indexes[0][1]), findingId: ids[0][1] };
  });
}

test('report selector: empty checks and multiple rows use check indexes, including same IDs across checks', () => {
  const report = createReport([
    check('empty-before'),
    check('shared-check', [finding(1), finding(2, { kind: 'observation', severity: 'low' })]),
    check('empty-middle'),
    check('shared-check', [finding(1)]),
  ], 'source', START);
  const original = JSON.stringify(report), agent = toAgentReport(report, 'high');
  const pairs = displayedPairs(toMarkdown(report, 'high'));
  assert.deepEqual(pairs, agent.findings.map(({ checkIndex, findingId }) => ({ checkIndex, findingId })));
  assert.deepEqual(pairs.map(row => row.checkIndex), [1, 1, 3]);
  assert.equal(pairs[0].findingId, pairs[2].findingId, 'same check ID and metadata retain the same finding ID');
  assert.notEqual(pairs[0].findingId, pairs[1].findingId);

  for (const pair of pairs) {
    const { input, referenceRoutes } = projectAdviceContext(agent, false, pair);
    assert.deepEqual(input.selection, pair);
    assert.deepEqual(input.checks.map(row => row.checkIndex), [pair.checkIndex]);
    assert.deepEqual(input.findings.map(({ checkIndex, findingId }) => ({ checkIndex, findingId })), [pair]);
    assert.deepEqual([...referenceRoutes.keys()], ['scope', `check:${pair.checkIndex}`,
      `finding:${pair.checkIndex}:${pair.findingId}`]);
    assert.equal(input.scanGate.exitCode, agent.scanGate.exitCode);
    assert.deepEqual(input.counts, agent.summary?.counts);
  }
  assert.equal(JSON.stringify(report), original, 'rendering and focused projection leave the source report unchanged');
});

test('report selector: repeated finding rows remain displayed and indexes follow check order', () => {
  const repeated = check('repeated-check', [finding(4), finding(4, { severity: 'low' })]);
  const later = check('later-check', [finding(8, { kind: 'advisory' })]);
  for (const checks of [[check('empty'), repeated, later], [later, check('empty'), repeated]]) {
    const report = createReport(checks, 'source', START), agent = toAgentReport(report, 'none');
    const pairs = displayedPairs(toMarkdown(report, 'none'));
    assert.equal(pairs.length, 3, 'human report does not collapse duplicate rows');
    assert.deepEqual(pairs, agent.findings.map(({ checkIndex, findingId }) => ({ checkIndex, findingId })));
    const duplicateRows = pairs.filter(pair => pair.findingId === agent.findings.find(row => row.checkId === 'repeated-check')!.findingId);
    assert.equal(duplicateRows.length, 2);
    assert.equal(duplicateRows[0].checkIndex, checks.indexOf(repeated));
    assert.deepEqual(duplicateRows[0], duplicateRows[1]);
    assert.equal(agent.scanGate.exitCode, 0);
    assert.equal(agent.findings.every(row => !row.reachesFailOn), true);
  }
});
