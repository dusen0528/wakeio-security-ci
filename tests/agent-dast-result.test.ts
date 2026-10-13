import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  GAP_REASONS, NEXT_HINTS, SEVERITIES, WORKER_CATEGORIES, WORKER_RESULT_MAX_BYTES, WORKER_STATUSES,
  failedWorkerResult, parseWorkerResult, type WorkerIdentity,
} from '../src/agent-dast/result.js';

const identity: WorkerIdentity = { runId: 'r-20261013-01', taskId: 't-injection-sqli-03', category: 'injection' };

function sample(): Record<string, unknown> {
  return {
    schema: 'wakeio.worker-result/v1',
    run_id: 'r-20261013-01',
    task_id: 't-injection-sqli-03',
    category: 'injection',
    status: 'completed',
    coverage: { planned: 40, executed: 38, skipped: 2 },
    findings: { candidate: 3, by_severity: { high: 2, medium: 1 } },
    finding_ids: ['f-012', 'f-013', 'f-014'],
    gaps: [{ reason: 'auth_required', count: 2 }],
    next_hint: 'verify',
    duration_ms: 41230,
    truncated: false,
  };
}

const parse = (value: unknown) => parseWorkerResult(JSON.stringify(value), identity);
const rejectedAt = (value: unknown, path: string) => {
  const parsed = parse(value);
  assert.equal(parsed.ok, false);
  if (!parsed.ok) assert.equal(parsed.path, path);
};

test('the design-doc example is a valid worker result well under the byte budget', () => {
  const text = JSON.stringify(sample());
  assert.ok(Buffer.byteLength(text) < WORKER_RESULT_MAX_BYTES / 4);
  const parsed = parseWorkerResult(`${text}\n`, identity);
  assert.equal(parsed.ok, true);
  if (parsed.ok) assert.deepEqual(parsed.result, sample());
});

test('output over 2 KB is rejected before parsing', () => {
  const parsed = parseWorkerResult(`${JSON.stringify(sample())}${' '.repeat(WORKER_RESULT_MAX_BYTES)}`, identity);
  assert.deepEqual(parsed, { ok: false, reason: 'output_too_large' });
});

test('non-JSON and multiple documents are rejected without echoing the output', () => {
  const leaked = 'HTTP/1.1 200 OK\r\nSet-Cookie: session=secret';
  const parsed = parseWorkerResult(leaked, identity);
  assert.deepEqual(parsed, { ok: false, reason: 'not_json' });
  assert.ok(!JSON.stringify(parsed).includes('secret'));
  assert.equal(parseWorkerResult(`${JSON.stringify(sample())}\n${JSON.stringify(sample())}`, identity).ok, false);
});

test('unknown fields are rejected at every level', () => {
  rejectedAt({ ...sample(), raw_response: '<html>' }, '$.raw_response');
  rejectedAt({ ...sample(), coverage: { planned: 1, executed: 1, skipped: 0, extra: 1 } }, '$.coverage.extra');
  rejectedAt({ ...sample(), findings: { candidate: 0, by_severity: { severe: 0 } } }, '$.findings.by_severity.severe');
  rejectedAt({ ...sample(), gaps: [{ reason: 'timeout', count: 1, url: 'https://x' }] }, '$.gaps[0].url');
});

test('counts must agree with each other', () => {
  rejectedAt({ ...sample(), coverage: { planned: 10, executed: 9, skipped: 2 } }, '$.coverage');
  rejectedAt({ ...sample(), findings: { candidate: 4, by_severity: { high: 2, medium: 1 } } }, '$.findings.by_severity');
  rejectedAt({ ...sample(), finding_ids: ['f-1', 'f-2', 'f-3', 'f-4'] }, '$.finding_ids');
  rejectedAt({ ...sample(), finding_ids: ['f-1', 'f-1'] }, '$.finding_ids');
  rejectedAt({ ...sample(), coverage: { planned: 1.5, executed: 0, skipped: 0 } }, '$.coverage.planned');
});

test('a partial task must name its gaps and a skipped task cannot have executed checks', () => {
  rejectedAt({ ...sample(), status: 'partial', gaps: [] }, '$.gaps');
  assert.equal(parse({ ...sample(), status: 'partial' }).ok, true);
  rejectedAt({ ...sample(), status: 'skipped' }, '$.coverage.executed');
  rejectedAt({ ...sample(), gaps: [{ reason: 'timeout', count: 1 }, { reason: 'timeout', count: 2 }] }, '$.gaps[1].reason');
});

test('identifiers are pattern-checked and bound to the assigned task', () => {
  rejectedAt({ ...sample(), finding_ids: ['f-../../etc'] }, '$.finding_ids[0]');
  const other = parse({ ...sample(), task_id: 't-other' });
  assert.deepEqual(other, { ok: false, reason: 'identity_mismatch', path: '$.task_id' });
  const category = parse({ ...sample(), category: 'authz' });
  assert.deepEqual(category, { ok: false, reason: 'identity_mismatch', path: '$.category' });
});

test('only the runner may mark a result truncated', () => {
  rejectedAt({ ...sample(), truncated: true }, '$.truncated');
});

test('runner fallback results are valid, claim no findings, and keep the failure as a gap', () => {
  const timeout = failedWorkerResult(identity, 'timeout', 120_000);
  assert.equal(timeout.status, 'error');
  assert.deepEqual(timeout.gaps, [{ reason: 'timeout', count: 1 }]);
  assert.equal(timeout.next_hint, 'retry');
  assert.equal(timeout.truncated, false);
  const oversized = failedWorkerResult(identity, 'output_too_large', 10);
  assert.deepEqual(oversized.gaps, [{ reason: 'tool_error', count: 1 }]);
  assert.equal(oversized.truncated, true);
  assert.equal(oversized.findings.candidate, 0);
  // The fallback itself passes validation (apart from the runner-only flag).
  assert.equal(parseWorkerResult(JSON.stringify({ ...oversized, truncated: false }), identity).ok, true);
});

test('the reference JSON Schema and the runtime validator use the same enums and limits', async () => {
  const schema = JSON.parse(await readFile(new URL('../../schemas/worker-result.v1.json', import.meta.url), 'utf8'));
  const p = schema.properties;
  assert.deepEqual(p.category.enum, [...WORKER_CATEGORIES]);
  assert.deepEqual(p.status.enum, [...WORKER_STATUSES]);
  assert.deepEqual(p.next_hint.enum, [...NEXT_HINTS]);
  assert.deepEqual(p.gaps.items.properties.reason.enum, [...GAP_REASONS]);
  assert.deepEqual(Object.keys(p.findings.properties.by_severity.properties), [...SEVERITIES]);
  assert.deepEqual(schema.required, Object.keys(sample()));
  assert.equal(p.finding_ids.maxItems, 20);
  assert.equal(p.gaps.maxItems, 10);
});
