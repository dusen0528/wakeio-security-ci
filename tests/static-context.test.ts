import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Finding, StaticCandidateContext } from '../src/contracts.js';
import { STATIC_CONTEXT_LIMIT, mergeStaticContexts, sanitiseStaticContext } from '../src/static-context.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';
import { compareReports, parseScanReport } from '../src/compare.js';
import { resolveAnalysisBudget } from '../src/source/analysis-budget.js';

const context = (line = 132): StaticCandidateContext => ({ revision: 'static-context-v1', authority: 'conditional',
  items: [{ kind: 'unresolved_cjs_dispatch', location: { path: 'server.js', line, column: 1 },
    target: { path: 'app/routes/index.js', line: 11, column: 1 } }], truncated: false });
const finding = (staticContext?: StaticCandidateContext): Finding => ({ ruleId: 'ast:nosql-input-sink', title: 'Input in observed selector',
  description: 'Conditional source evidence.', severity: 'high', confidence: 'medium', kind: 'candidate',
  location: { path: 'app/data/allocations-dao.js', line: 78, column: 21 }, remediation: 'Review source evidence.',
  staticFlow: { kind: 'static_flow', truncated: false, steps: [
    { role: 'source', location: { path: 'app/routes/allocations.js', line: 21, column: 13 } },
    { role: 'sink', location: { path: 'app/data/allocations-dao.js', line: 86, column: 9 } },
  ] }, ...(staticContext ? { staticContext } : {}) });
const report = (staticContext?: StaticCandidateContext) => createReport([{ id: 'source.builtin-ast', status: 'completed',
  findings: [finding(staticContext)], notes: [], analysisBudget: resolveAnalysisBudget() }], 'source', '2026-10-13T00:00:00.000Z',
  { fingerprint: 'a'.repeat(64), ruleset: 'test.1', analysisBudget: resolveAnalysisBudget() });

test('context ledger is canonical, bounded and separate from contributing source trace', () => {
  const aliases = context();
  aliases.items.push({ ...aliases.items[0], location: { ...aliases.items[0].location, path: './server.js' } });
  assert.deepEqual(sanitiseStaticContext(aliases), context());
  let merged: StaticCandidateContext | undefined;
  for (let line = 1; line <= STATIC_CONTEXT_LIMIT + 2; line++) merged = mergeStaticContexts(merged, context(line));
  assert.equal(merged!.authority, 'conditional');
  assert.equal(merged!.items.length, STATIC_CONTEXT_LIMIT);
  assert.equal(merged!.truncated, true);
  assert.deepEqual(mergeStaticContexts(context(1), context(2)), mergeStaticContexts(context(2), context(1)));
  assert.deepEqual(mergeStaticContexts(context(), context()), context());
  assert.equal(mergeStaticContexts(undefined, undefined), undefined);
  assert.equal(sanitiseStaticContext({ ...context(), items: [], truncated: false }), undefined);
  assert.deepEqual(sanitiseStaticContext({ ...context(), items: [], truncated: true }), { ...context(), items: [], truncated: true });
  const malformed = mergeStaticContexts({ ...context(), items: [] });
  assert.deepEqual(malformed, { ...context(), items: [], truncated: true });
});

test('conditional context keeps candidate low and check partial without inventing taint hops or control proof', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-static-context-'));
  try {
    const output = report(context());
    assert.equal(output.checks[0].status, 'partial');
    assert.equal(evaluateGate(output, 'none').exitCode, 2);
    const result = output.checks[0].findings[0];
    assert.equal(result.confidence, 'low');
    assert.equal(result.staticFlow!.truncated, true);
    assert.equal(result.staticContext!.truncated, false);
    assert.deepEqual(result.staticFlow!.steps, finding().staticFlow!.steps);
    assert.deepEqual(sanitiseReport(output), output);
    assert.deepEqual(parseScanReport(output), output);
    const agent = toAgentReport(output);
    assert.deepEqual(agent.findings[0].evidence.staticContext, context());
    assert.equal(agent.findings[0].evidence.traceStatus, 'static_truncated');
    assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
    const sarif: any = toSarif(output);
    assert.deepEqual(sarif.runs[0].results[0].properties.staticContext, context());
    assert.equal(sarif.runs[0].results[0].codeFlows[0].threadFlows[0].locations.length, 2);
    const markdown = toMarkdown(output);
    assert.match(markdown, /Conditional static context/);
    assert.match(markdown, /separate from input trace steps/);
    assert.ok(markdown.includes('server\\.js:132:1; observed target app/routes/index\\.js:11:1'));
    await writeReports(output, root);
    assert.deepEqual(JSON.parse(await readFile(join(root, 'report.json'), 'utf8')).checks[0].findings[0].staticContext, context());
    assert.deepEqual(JSON.parse(await readFile(join(root, 'agent-report.json'), 'utf8')).findings[0].evidence.staticContext, context());
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('closed data schema rejects malformed, oversized, unsafe and secret context metadata', () => {
  const invalid = [
    null, [], { ...context(), revision: 'other' }, { ...context(), authority: 'resolved' },
    { ...context(), extra: 'not allowed' }, { ...context(), items: Array.from({ length: STATIC_CONTEXT_LIMIT + 1 }, () => context().items[0]) },
    { ...context(), items: [{ ...context().items[0], kind: 'run_command' }] },
    { ...context(), items: [{ ...context().items[0], command: 'do not execute' }] },
    { ...context(), items: [{ ...context().items[0], target: undefined }] },
    ...['/private/root.js', '../escape.js', 'api-key=secret.js', 'ghp_privateSecret123.js'].map(path => ({ ...context(), items: [{ ...context().items[0], location: { path, line: 1, column: 1 } }] })),
    { ...context(), items: [{ ...context().items[0], location: { path: 'server.js', line: NaN, column: 1 } }] },
  ];
  for (const metadata of invalid) {
    assert.equal(sanitiseStaticContext(metadata), undefined);
    const raw = report();
    (raw.checks[0].findings[0] as any).staticContext = metadata;
    assert.throws(() => parseScanReport(raw), /Invalid scan report/);
    const safe = sanitiseReport(raw);
    assert.equal(safe.checks[0].status, 'partial');
    assert.equal(safe.checks[0].findings[0].confidence, 'low');
    assert.equal(safe.checks[0].findings[0].staticContext, undefined);
    assert.equal(safe.checks[0].findings[0].staticFlow!.truncated, true);
    assert.equal(evaluateGate(safe, 'none').exitCode, 2);
    assert.deepEqual(sanitiseReport(safe), safe);
  }
});

test('new context wrapper and nested data never execute getters, proxies or iterators', () => {
  let calls = 0;
  const getter = () => { calls++; throw new Error('must not execute'); };
  const nested = { ...context() };
  Object.defineProperty(nested, 'items', { enumerable: true, get: getter });
  assert.equal(sanitiseStaticContext(nested), undefined);
  const proxy = new Proxy(context(), { ownKeys: getter, get: getter });
  assert.equal(sanitiseStaticContext(proxy), undefined);
  const rows = context();
  Object.setPrototypeOf(rows.items, { [Symbol.iterator]: getter });
  assert.deepEqual(sanitiseStaticContext(rows), context());
  const rowGetter = context();
  Object.defineProperty(rowGetter.items, '0', { enumerable: true, get: getter });
  assert.equal(sanitiseStaticContext(rowGetter), undefined);
  for (const metadata of [nested, proxy]) {
    const raw = report(); raw.checks[0].findings[0].staticContext = metadata;
    assert.throws(() => parseScanReport(raw), /Invalid scan report/);
    assert.equal(sanitiseReport(raw).checks[0].status, 'partial');
  }
  const wrapper = report();
  Object.defineProperty(wrapper.checks[0].findings[0], 'staticContext', { enumerable: true, get: getter });
  assert.throws(() => parseScanReport(wrapper), /Invalid scan report/);
  assert.equal(sanitiseReport(wrapper).checks[0].findings[0].confidence, 'low');
  assert.equal(sanitiseReport(wrapper).checks[0].status, 'partial');
  const proxyWrapper = report();
  proxyWrapper.checks[0].findings[0] = new Proxy(finding(context()), { get: getter, ownKeys: getter });
  assert.throws(() => parseScanReport(proxyWrapper), /Invalid scan report/);
  assert.equal(sanitiseReport(proxyWrapper).checks[0].status, 'partial');
  assert.equal(sanitiseReport(proxyWrapper).checks[0].findings[0].confidence, 'low');
  assert.equal(calls, 0);
});

test('legacy absent context stays absent; changed or removed context cannot become comparable or not observed', () => {
  const legacy = report();
  assert.equal(legacy.checks[0].status, 'completed');
  assert.equal(legacy.checks[0].findings[0].confidence, 'medium');
  assert.equal(legacy.checks[0].findings[0].staticFlow!.truncated, false);
  assert.equal(toAgentReport(legacy).findings[0].evidence.staticContext, undefined);
  assert.equal(compareReports(legacy, legacy).comparable, true);
  const before = report(context());
  const changed = compareReports(before, report(context(133)));
  assert.ok(changed.reasons.some(reason => /Conditional static context changed/.test(reason)));
  const removed = compareReports(before, legacy);
  assert.equal(removed.comparable, false);
  assert.equal(removed.summary.not_observed, 0);
  assert.ok(removed.reasons.some(reason => /Conditional static context changed/.test(reason)));
  const inconsistent = structuredClone(before);
  inconsistent.checks[0].status = 'completed';
  assert.throws(() => parseScanReport(inconsistent), /Invalid scan report/);
  inconsistent.checks[0].status = 'partial'; inconsistent.checks[0].findings[0].confidence = 'medium';
  assert.throws(() => parseScanReport(inconsistent), /Invalid scan report/);
});
