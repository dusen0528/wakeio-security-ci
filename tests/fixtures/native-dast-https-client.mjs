import { runDast } from '../../build/src/dast.js';

const targetUrl = process.argv[2];
const origin = new URL(targetUrl).origin;
const [check] = await runDast({ policy: {
  version: 1, kind: 'sql-boolean-differential', baseUrl: `${origin}/`, url: targetUrl,
  parameter: 'id', profile: 'numeric',
  oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 },
}, consent: true, allowPrivate: true });
process.stdout.write(JSON.stringify({ status: check.status, findings: check.findings.length,
  attempts: check.metrics.requestCount, stopReason: check.dastExecution?.stopReason }) + '\n');
