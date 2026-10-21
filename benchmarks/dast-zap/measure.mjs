// Creates its own disposable loopback target. No caller-supplied target authority.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { platform, arch } from 'node:os';
import { runZap, ZAP_VERSION, ZAP_POLICY_REVISION } from '../../build/src/zap.js';
import { zapSurfaceKey } from '../../build/src/zap-policy.js';
import { zapPolicyTarget } from '../../build/tests/fixtures/zap-policy-target.js';
const labelsBytes = await readFile(new URL('./labels.json', import.meta.url)), labels = JSON.parse(labelsBytes).labels;
const repeats = Number(process.argv[2] ?? 5), output = process.argv[3];
if (!Number.isInteger(repeats) || repeats < 1 || repeats > 5 || !output || !process.env.WAKEIO_ZAP_PATH) throw Error('Usage: WAKEIO_ZAP_PATH=/prepared/zap.sh node benchmarks/dast-zap/measure.mjs [1..5] OUTPUT.json');
const rows = [];
for (let round = 1; round <= repeats; round++) {
  const target = await zapPolicyTarget();
  try {
    const started = performance.now(), check = (await runZap({ url: target.origin, policy: target.policy, env: target.env,
      executable: process.env.WAKEIO_ZAP_PATH, consent: true, allowPrivate: true, maxRequests: 200, rateLimit: 50, timeoutMs: 120000 }))[0];
    const elapsedMs = Number((performance.now() - started).toFixed(2));
    assert.equal(check.status, 'completed', JSON.stringify(check));
    assert.equal(check.metrics.requestCount, target.seen.length);
    assert.ok(target.seen.every(req => req.path === '/identity' || req.authenticated && !req.cookie));
    const keys = new Set(check.findings.map(f => f.comparisonKey)), known = new Set(); let TP = 0, FP = 0, FN = 0, TN = 0;
    for (const label of labels) {
      const key = zapSurfaceKey(label.rule.slice(4), { method: label.method, path: label.path }, label.parameter); known.add(key);
      if (label.vulnerable) keys.has(key) ? TP++ : FN++; else keys.has(key) ? FP++ : TN++;
    }
    FP += [...keys].filter(key => !known.has(key)).length;
    rows.push({ round, TP, FP, FN, TN, elapsedMs, requests: target.seen.length, maxRequests: 200,
      identityBefore: check.metrics.identityBefore, anonymousDenied: check.metrics.anonymousDenied, identityAfter: check.metrics.identityAfter });
    process.stdout.write(JSON.stringify(rows.at(-1)) + '\n');
  } finally { await target.close(); }
}
const times = rows.map(row => row.elapsedMs).sort((a, b) => a - b), requests = rows.map(row => row.requests);
const result = { version: 1, kind: 'owned-zap-pilot', engine: { zap: ZAP_VERSION, automation: '0.58.0', ascanrules: '78' }, profileRevision: ZAP_POLICY_REVISION,
  runtime: { node: process.version, platform: platform(), arch: arch() }, measuredAt: new Date().toISOString(),
  labelsSha256: createHash('sha256').update(labelsBytes).digest('hex'), rounds: rows,
  summary: { repeats, TP: rows.map(row => row.TP), FP: rows.map(row => row.FP), FN: rows.map(row => row.FN), TN: rows.map(row => row.TN),
    elapsedP50Ms: times[Math.ceil(times.length * .5) - 1], elapsedMaxMs: times.at(-1), requestsMin: Math.min(...requests), requestsMax: Math.max(...requests) },
  limits: ['Small self-authored SQLite fixture; not external-target efficacy or an autonomous-agent comparison.',
    'Three vulnerable and three fixed sites; one label per distinct rule/method/path/parameter. Unexpected distinct findings count as FP.',
    'Elapsed includes engine version check, startup, seeds, three principal controls, active scan, shutdown and cleanup.',
    'Policy and fixture are public. No hidden evaluation split or production-coverage claim.'] };
await writeFile(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
