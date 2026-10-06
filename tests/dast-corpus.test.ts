import test from 'node:test';
import assert from 'node:assert/strict';
import { runApiPolicy, parseApiPolicy } from '../src/api.js';

const fixtureModule = new URL('../../examples/dast-owned-fixture.mjs', import.meta.url).href;
const corpusModule = new URL('../../examples/dast-owned-corpus.mjs', import.meta.url).href;

test('owned DAST corpus gates positive, safe and error controls with lifecycle and exact request counts', { timeout: 30_000 }, async (t) => {
  const { evaluateOwnedDastCorpus } = await import(corpusModule);
  const result = await evaluateOwnedDastCorpus({ run: runApiPolicy, repeats: 2 });
  assert.equal(result.summary.pointer.detectedPositiveTasks, 2);
  assert.equal(result.summary.pointer.missedPositiveTasks, 4);
  assert.equal(result.summary['json-values'].detectedPositiveTasks, 6);
  assert.equal(result.summary['json-values'].missedPositiveTasks, 0);
  assert.equal(result.summary['json-values'].falsePositiveTasks, 0);
  assert.equal(result.summary['json-values'].incompleteErrorTasks, 12);
  t.diagnostic(JSON.stringify(result.summary));
});

test('canary traversal remains opt-in, exact-value-only and does not weaken owner controls', async () => {
  const { startOwnedDastFixture } = await import(fixtureModule);
  for (const mode of ['prefix-only', 'key-only']) {
    const fixture = await startOwnedDastFixture(mode);
    try {
      const [check] = await runApiPolicy({ policy: fixture.policy(), env: fixture.env, allowPrivate: true });
      assert.equal(check.findings.length, 0, 'substrings and keys remain explicitly outside exact-value evidence');
    } finally { await fixture.close(); }
  }
  const fixture = await startOwnedDastFixture('nested');
  try {
    const policy = fixture.policy();
    policy.cases[0].allow.protected.jsonPointer = '/wrong-owner-pointer';
    const [check] = await runApiPolicy({ policy, env: fixture.env, allowPrivate: true });
    assert.equal(check.status, 'partial');
    assert.ok(check.notes.some(n => n.includes('protected canary mismatch')));
    assert.equal(check.findings.some(f => f.id?.includes('read-userA:')), false);
    policy.cases[0].allow.protected.match = 'arbitrary-pattern';
    assert.throws(() => parseApiPolicy(policy));
  } finally { await fixture.close(); }
});

test('owned fixture cleanup is repeatable and removes synthetic objects and credentials', async () => {
  const { startOwnedDastFixture } = await import(fixtureModule);
  const fixture = await startOwnedDastFixture();
  assert.equal(fixture.lifecycle().remainingObjects, 4);
  await fixture.close(); await fixture.close();
  assert.equal(fixture.lifecycle().remainingObjects, 0);
  assert.deepEqual(fixture.env, {});
});
