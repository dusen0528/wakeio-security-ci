import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectSource, limitsFromOptions } from '../src/source/collector.js';
import { COLLECTION_DEFAULT_MAX_BYTES, COLLECTION_MAX_BYTES, COLLECTION_MAX_FILES, COLLECTION_MAX_FILE_BYTES,
  COLLECTION_MAX_DIRECTORY_DEPTH, collectionEvidence, parseCollectionLimit, resolveCollectionBudget,
  sanitiseCollectionBudget, sanitiseCollectionEvidence, sameCollectionBudget } from '../src/source/collection-budget.js';
import { runSource } from '../src/source.js';
import { buildScanScope } from '../src/scan-scope.js';
import type { CheckResult } from '../src/contracts.js';

async function withRoot(fn: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-collection-budget-'));
  try { await fn(root); } finally { await rm(root, { recursive: true, force: true }); }
}
const inventory = (checks: CheckResult[]) => checks.find(check => check.id === 'source.inventory')!;

test('collection effective normalization preserves SDK defaults, invalid fallback, clamps and entry formula', () => {
  const defaults = resolveCollectionBudget();
  assert.deepEqual(defaults, { revision: 'collection-v1', limits: { maxFiles: 1000, maxBytes: COLLECTION_DEFAULT_MAX_BYTES,
    maxFileBytes: COLLECTION_MAX_FILE_BYTES, maxEntries: 8000 } });
  assert.ok(Object.isFrozen(defaults) && Object.isFrozen(defaults.limits));
  for (const invalid of [0, -1, 1.2, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '2', null]) {
    assert.deepEqual(resolveCollectionBudget({ maxFiles: invalid as number, maxBytes: invalid as number }), defaults);
  }
  const clamped = resolveCollectionBudget({ maxFiles: COLLECTION_MAX_FILES + 1, maxBytes: COLLECTION_MAX_BYTES + 1 });
  assert.equal(clamped.limits.maxFiles, COLLECTION_MAX_FILES);
  assert.equal(clamped.limits.maxBytes, COLLECTION_MAX_BYTES);
  assert.equal(clamped.limits.maxEntries, 80000);
  assert.deepEqual(limitsFromOptions({ maxFiles: 1, maxBytes: 1 }), { maxFiles: 1, maxBytes: 1, maxFileBytes: COLLECTION_MAX_FILE_BYTES });
  assert.equal(resolveCollectionBudget({ maxFiles: 1 }).limits.maxEntries, 1000);
  assert.ok(sameCollectionBudget(defaults, resolveCollectionBudget({ maxFiles: 0 })));
});

test('strict public selection rejects noncanonical and out-of-bound numbers without SDK fallback', () => {
  for (const maximum of [COLLECTION_MAX_FILES, COLLECTION_MAX_BYTES]) {
    assert.equal(parseCollectionLimit('1', maximum), 1);
    assert.equal(parseCollectionLimit(String(maximum), maximum), maximum);
    for (const invalid of ['', '0', '-1', '+1', '01', '1.0', '1e2', '0x10', ' 1', '1 ', '١', String(maximum + 1), '9007199254740992']) {
      assert.throws(() => parseCollectionLimit(invalid, maximum), /canonical positive integer/);
    }
  }
});

test('closed metadata validation checks normalized bounds, exact aggregate codes and own data properties', () => {
  const budget = resolveCollectionBudget({ maxFiles: 2, maxBytes: 17 });
  assert.deepEqual(sanitiseCollectionBudget(JSON.parse(JSON.stringify(budget))), budget);
  for (const bad of [null, [], { ...budget, extra: true }, { ...budget, revision: 'unknown' },
    { ...budget, limits: { ...budget.limits, maxEntries: 8000 } }, { ...budget, limits: { ...budget.limits, maxFileBytes: 8 * 1024 * 1024 } },
    { ...budget, limits: { ...budget.limits, maxFiles: 0 } }, { ...budget, limits: { ...budget.limits, maxBytes: NaN } }]) {
    assert.equal(sanitiseCollectionBudget(bad), undefined);
  }
  const evidence = collectionEvidence([{ code: 'size_limit' }, { code: 'file_limit' }, { code: 'size_limit' }]);
  assert.deepEqual(evidence, { revision: 'collection-v1', issueCount: 3, issues: [{ code: 'file_limit', count: 1 }, { code: 'size_limit', count: 2 }] });
  assert.deepEqual(sanitiseCollectionEvidence(evidence), evidence);
  assert.deepEqual(sanitiseCollectionEvidence(collectionEvidence([])), { revision: 'collection-v1', issueCount: 0, issues: [] });
  for (const bad of [{ ...evidence, issueCount: 2 }, { ...evidence, issues: [...evidence.issues].reverse() },
    { ...evidence, issues: [{ code: 'path_error', count: 0 }] }, { ...evidence, issues: [{ code: 'byte_limit', count: 3 }] },
    { ...evidence, issues: [{ code: 'size_limit', count: 1 }, { code: 'size_limit', count: 2 }] },
    { ...evidence, issues: [{ code: 'size_limit', count: 3, path: '/private/source' }] }, { ...evidence, path: '/private/source' }]) {
    assert.equal(sanitiseCollectionEvidence(bad), undefined);
  }
  let read = false;
  const accessor = { ...budget };
  Object.defineProperty(accessor, 'limits', { enumerable: true, get() { read = true; return budget.limits; } });
  assert.equal(sanitiseCollectionBudget(accessor), undefined);
  const accessorEvidence = { ...evidence };
  Object.defineProperty(accessorEvidence, 'issues', { enumerable: true, get() { read = true; return evidence.issues; } });
  assert.equal(sanitiseCollectionEvidence(accessorEvidence), undefined);
  const proxyBudget = new Proxy(budget, { ownKeys() { read = true; throw new Error('must not inspect proxy'); } });
  assert.equal(sanitiseCollectionBudget(proxyBudget), undefined);
  const rows = [...evidence.issues];
  Object.setPrototypeOf(rows, { [Symbol.iterator]() { read = true; throw new Error('must not invoke iterator'); } });
  assert.deepEqual(sanitiseCollectionEvidence({ ...evidence, issues: rows }), evidence);
  const proxyRows = new Proxy([...evidence.issues], { get() { read = true; throw new Error('must not inspect proxy array'); } });
  assert.equal(sanitiseCollectionEvidence({ ...evidence, issues: proxyRows }), undefined);
  assert.equal(read, false);
});

test('real collector and inventory always expose effective budget and actual issue aggregate, including root error', async () => {
  await withRoot(async root => {
    await writeFile(join(root, 'a.js'), 'export const fixed=1;\n');
    await writeFile(join(root, 'b.js'), 'export const fixed=1;\n');
    const snapshot = await collectSource({ root, maxFiles: 1 });
    assert.deepEqual(snapshot.collectionBudget, resolveCollectionBudget({ maxFiles: 1 }));
    const check = inventory(await runSource({ root, tools: [], maxFiles: 1 }));
    assert.equal(check.status, 'partial');
    assert.deepEqual(check.collectionBudget, snapshot.collectionBudget);
    assert.deepEqual(check.collectionEvidence, { revision: 'collection-v1', issueCount: 1, issues: [{ code: 'file_limit', count: 1 }] });
    assert.ok(!JSON.stringify(check).includes(root));
    assert.ok(!JSON.stringify(check.collectionEvidence).includes('b.js'));
    const missing = join(root, 'does-not-exist');
    const errorSnapshot = await collectSource({ root: missing, maxFiles: 2, maxBytes: 9 });
    assert.deepEqual(errorSnapshot.collectionBudget, resolveCollectionBudget({ maxFiles: 2, maxBytes: 9 }));
    const error = inventory(await runSource({ root: missing, tools: [], maxFiles: 2, maxBytes: 9 }));
    assert.equal(error.status, 'error');
    assert.deepEqual(error.collectionEvidence, { revision: 'collection-v1', issueCount: 1, issues: [{ code: 'root_error', count: 1 }] });
    assert.deepEqual(error.collectionBudget, errorSnapshot.collectionBudget);
  });
});

test('total byte selection and fixed per-file bound retain the actual shared size_limit code', async () => {
  await withRoot(async root => {
    const code = 'export const fixed=1;\n', bytes = Buffer.byteLength(code);
    await writeFile(join(root, 'a.js'), code);
    await writeFile(join(root, 'b.js'), code);
    const limited = inventory(await runSource({ root, tools: [], maxBytes: bytes }));
    assert.equal(limited.status, 'partial');
    assert.equal(limited.metrics?.filesSelected, 1);
    assert.equal(limited.collectionBudget?.limits.maxBytes, bytes);
    assert.deepEqual(limited.collectionEvidence?.issues, [{ code: 'size_limit', count: 1 }]);
    const expanded = inventory(await runSource({ root, tools: [], maxBytes: 2 * bytes }));
    assert.equal(expanded.status, 'completed');
    assert.equal(expanded.metrics?.filesSelected, 2);
    assert.deepEqual(expanded.collectionEvidence?.issues, []);
    await writeFile(join(root, 'oversize.txt'), 'x'.repeat(COLLECTION_MAX_FILE_BYTES + 1));
    for (const maxBytes of [COLLECTION_DEFAULT_MAX_BYTES, COLLECTION_MAX_BYTES]) {
      const perFile = inventory(await runSource({ root, tools: [], maxBytes }));
      assert.equal(perFile.status, 'partial');
      assert.equal(perFile.collectionBudget?.limits.maxFileBytes, COLLECTION_MAX_FILE_BYTES);
      assert.deepEqual(perFile.collectionEvidence?.issues, [{ code: 'size_limit', count: 1 }]);
    }
  });
});

test('traversal and directory depth keep shared file_limit evidence rather than fabricated selected-file subtypes', async () => {
  await withRoot(async root => {
    for (let i = 0; i <= 1000; i++) await writeFile(join(root, `skip-${String(i).padStart(4, '0')}.bin`), 'inert');
    const check = inventory(await runSource({ root, tools: [], maxFiles: 1 }));
    assert.equal(check.status, 'partial');
    assert.equal(check.metrics?.filesSelected, 0);
    assert.equal(check.collectionBudget?.limits.maxEntries, 1000);
    assert.deepEqual(check.collectionEvidence?.issues, [{ code: 'file_limit', count: 1 }]);
  });
  await withRoot(async root => {
    let directory = root;
    for (let i = 0; i <= COLLECTION_MAX_DIRECTORY_DEPTH; i++) { directory = join(directory, 'd'); await mkdir(directory); }
    await writeFile(join(directory, 'app.js'), 'export const fixed=1;');
    const check = inventory(await runSource({ root, tools: [], maxFiles: COLLECTION_MAX_FILES }));
    assert.equal(check.status, 'partial');
    assert.equal(check.metrics?.filesSelected, 0);
    assert.deepEqual(check.collectionEvidence?.issues, [{ code: 'file_limit', count: 1 }]);
  });
});

test('nonfatal unsupported text remains an honest completed inventory with observed exclusion evidence', async () => {
  await withRoot(async root => {
    await writeFile(join(root, 'binary.txt'), Buffer.from([65, 0, 66]));
    const check = inventory(await runSource({ root, tools: [] }));
    assert.equal(check.status, 'completed');
    assert.deepEqual(check.collectionEvidence, { revision: 'collection-v1', issueCount: 1, issues: [{ code: 'unsupported_file', count: 1 }] });
  });
});

test('scope identity binds normalized source collection selection; URL scope has no source budget', async () => {
  await withRoot(async source => {
    await writeFile(join(source, 'a.js'), 'export const fixed=1;');
    for (const mode of ['source', 'both', 'combined'] as const) {
      const common = { mode, source, tools: [], ruleset: 'fixture-rules' };
      const implicit = await buildScanScope(common);
      const explicit = await buildScanScope({ ...common, sourceMaxFiles: 1000, sourceMaxBytes: COLLECTION_DEFAULT_MAX_BYTES });
      assert.deepEqual(explicit, implicit);
      assert.deepEqual(implicit.collectionBudget, resolveCollectionBudget());
      const expanded = await buildScanScope({ ...common, sourceMaxFiles: 2000 });
      assert.notEqual(expanded.fingerprint, implicit.fingerprint);
      const smallerBytes = await buildScanScope({ ...common, sourceMaxBytes: 1 });
      assert.notEqual(smallerBytes.fingerprint, implicit.fingerprint);
      const clamped = await buildScanScope({ ...common, sourceMaxFiles: COLLECTION_MAX_FILES + 1 });
      const maximum = await buildScanScope({ ...common, sourceMaxFiles: COLLECTION_MAX_FILES });
      assert.deepEqual(clamped, maximum);
    }
    const url = await buildScanScope({ mode: 'url', url: 'https://example.invalid', tools: [], ruleset: 'fixture-rules' });
    assert.equal(url.collectionBudget, undefined);
  });
});
