import test from 'node:test';
import assert from 'node:assert/strict';

const fixtureModule = '../benchmarks/agent-eval/targets/local-sqlite/fixture.mjs';
test('owned evaluation fixture requires consent and separates positive, negative and tuning sites', async () => {
  const { startFixture } = await import(new URL('../../' + fixtureModule.slice(3), import.meta.url).href);
  await assert.rejects(startFixture(), /active_consent_required/);
  const fixture = await startFixture({ activeConsent: true });
  try {
    for (const path of ['/items','/catalog']) {
      const result = await fetch(fixture.origin + path + '?id=' + encodeURIComponent('1 AND 1=1'));
      assert.deepEqual(await result.json(), { count: 1 });
    }
    for (const path of ['/lookup','/inventory']) {
      const result = await fetch(fixture.origin + path + '?id=' + encodeURIComponent('1 AND 1=1'));
      assert.deepEqual(await result.json(), { count: 0 });
    }
    assert.equal((await fetch(fixture.origin + '/items?id=1', { method: 'POST' })).status, 404);
    fixture.reset(); assert.equal(fixture.requests.length, 0);
    assert.deepEqual(await (await fetch(fixture.origin + '/items?id=1')).json(), { count: 1 });
  } finally { await fixture.close(); }
});
