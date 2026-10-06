// Finite, independent application-shaped controls. Only generated 127.0.0.1
// fixtures are contacted. These counts are task coverage, not overall security.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { runApiPolicy } from '../build/src/index.js';
import { startOwnedDastFixture } from './dast-owned-fixture.mjs';

const CORPUS = [
  ['direct', 'positive'], ['nested', 'positive'], ['array', 'positive'],
  ['safe', 'negative'], ['public-id', 'negative'], ['different-canary', 'negative'],
  ['malformed', 'error'], ['wrong-identity', 'error'], ['owner-missing', 'error'],
  ['server-error', 'error'], ['too-deep', 'error'], ['too-wide', 'error'],
];

export async function evaluateOwnedDastCorpus({ run = runApiPolicy, repeats = 2 } = {}) {
  if (!Number.isInteger(repeats) || repeats < 1 || repeats > 3) throw Error('bounded corpus repeats required');
  const rows = [];
  for (let repeat = 0; repeat < repeats; repeat++) {
    for (const [mode, category] of CORPUS) {
      for (const match of ['pointer', 'json-values']) {
        const fixture = await startOwnedDastFixture(mode);
        const policy = fixture.policy(match);
        const forbidden = [...Object.values(fixture.env), ...policy.cases.map(c => c.allow.protected.equals)];
        try {
          const start = performance.now();
          const checks = await run({ policy, env: fixture.env, allowPrivate: true, timeoutMs: 5000 });
          const elapsedMs = Math.round(performance.now() - start);
          assert.equal(checks.length, 1);
          const check = checks[0];
          const count = check.findings.filter(f => f.ruleId === 'api.authorization-data-exposure').length;
          assert.equal(check.metrics.requestCount, fixture.requests.length);
          assert.equal(check.metrics.requestCount, fixture.expectedRequests);
          assert.ok(fixture.requests.every(r => r.method === 'GET'));
          assert.ok(fixture.requests.every(r => r.path === '/whoami' || policy.cases.some(c => c.path === r.path)));
          const identities = policy.actors.filter(a => a.identity).map(a => ({ method: 'GET', path: a.identity.path, actor: a.id }));
          const caseRequests = policy.cases.flatMap(c => mode === 'owner-missing'
            ? [{ method: 'GET', path: c.path, actor: c.allow.actor }]
            : [c.allow, ...c.deny, c.allow].map(a => ({ method: 'GET', path: c.path, actor: a.actor })));
          assert.deepEqual(fixture.requests, [...identities, ...caseRequests, ...identities]);
          for (const value of forbidden) assert.equal(JSON.stringify(checks).includes(value), false);
          if (match === 'json-values') {
            assert.equal(count, fixture.expectedExposures, `${mode}: scoped exposure count`);
            assert.deepEqual(check.findings.map(f => f.id).sort(), category === 'positive'
              ? policy.cases.flatMap(c => c.deny.map(d => `api.authorization-data-exposure:${c.id}:${d.actor}`)).sort()
              : [], `${mode}: exact case and actor evidence`);
            assert.equal(check.status, category === 'error' ? 'partial' : 'completed', `${mode}: completion status`);
          } else if (category !== 'error') {
            assert.equal(count, mode === 'direct' ? fixture.expectedExposures : 0);
            assert.equal(check.status, 'completed');
          }
          rows.push({ repeat, mode, category, match, status: check.status, findings: count, expectedFindings: fixture.expectedExposures, requests: fixture.requests.length, elapsedMs });
        } finally {
          await fixture.close();
          assert.deepEqual(fixture.lifecycle(), { seededCount: 4, remainingObjects: 0, cleaned: true, listening: false });
        }
      }
    }
  }
  const summary = Object.fromEntries(['pointer', 'json-values'].map(match => {
    const group = rows.filter(r => r.match === match);
    return [match, {
      positiveTasks: group.filter(r => r.category === 'positive').length,
      detectedPositiveTasks: group.filter(r => r.category === 'positive' && r.findings === r.expectedFindings).length,
      missedPositiveTasks: group.filter(r => r.category === 'positive' && r.findings !== r.expectedFindings).length,
      negativeTasks: group.filter(r => r.category === 'negative').length,
      falsePositiveTasks: group.filter(r => r.category === 'negative' && r.findings > 0).length,
      errorTasks: group.filter(r => r.category === 'error').length,
      incompleteErrorTasks: group.filter(r => r.category === 'error' && r.status !== 'completed').length,
      requests: group.reduce((sum, r) => sum + r.requests, 0),
      elapsedMs: group.reduce((sum, r) => sum + r.elapsedMs, 0),
      maxRunMs: Math.max(...group.map(r => r.elapsedMs)),
    }];
  }));
  return { scope: 'owned-loopback-exact-canary-json-values', comparison: 'same-build pointer configuration versus opt-in json-values configuration; not an overall-security score', repeats, summary, rows };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const result = await evaluateOwnedDastCorpus();
  process.stdout.write(JSON.stringify({ scope: result.scope, comparison: result.comparison, repeats: result.repeats, summary: result.summary }, null, 2) + '\n');
}
