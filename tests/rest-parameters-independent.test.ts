import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { createReport, evaluateGate, toAgentReport } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

// Owned inert source strings only. No fixture import, target execution or provider.
const EXEC = "import { exec } from 'node:child_process';\n";
function scan(text: string, more: Record<string, string> = {}) {
  const files = Object.entries({ 'app.ts': text, ...more }).map(([path, text]) => ({
    path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false,
  }));
  const snapshot: SourceSnapshot = { root: '/owned-inert-rest-review', files, issues: [],
    complete: true, ignoredFiles: 0, totalBytes: files.reduce((sum, f) => sum + f.bytes, 0) };
  const check = runBuiltinAst(snapshot, false);
  const report = createReport([check], 'source', new Date(0));
  return { check, report, agent: toAgentReport(report, 'high'),
    shell: check.findings.filter(f => f.ruleId === 'ast:shell-input-sink') };
}
function clean(result: ReturnType<typeof scan>) {
  assert.equal(result.check.status, 'completed');
  assert.equal(result.shell.length, 0);
  assert.equal(evaluateGate(result.report, 'high').exitCode, 0);
}
function candidate(result: ReturnType<typeof scan>) {
  assert.equal(result.check.status, 'completed');
  assert.equal(result.shell.length, 1);
  const finding = result.shell[0];
  assert.equal(finding.kind, 'candidate');
  assert.equal(finding.confidence, 'medium');
  assert.ok(finding.staticFlow?.steps.some(step => step.role === 'source'));
  assert.equal(evaluateGate(result.report, 'high').exitCode, 1);
  assert.equal(result.agent.scanGate.exitCode, 1);
  const row = result.agent.findings.find(row => row.ruleId === finding.ruleId
    && row.location.path === finding.location.path && row.location.line === finding.location.line
    && row.location.column === finding.location.column);
  assert.ok(row);
  assert.deepEqual(row.verification, { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
  return finding;
}
function incomplete(result: ReturnType<typeof scan>) {
  assert.equal(result.check.status, 'partial', 'unsupported rest shape must not certify a precise completed result');
  assert.ok((result.check.analysisGaps?.eventsObserved ?? 0) > 0, 'unsupported shape needs explicit gap evidence');
  assert.equal(evaluateGate(result.report, 'none').exitCode, 2);
  for (const row of result.agent.findings) assert.equal(row.verification.vulnerabilityConfirmed, false);
}

test('rest independent: second actual is selected without tainting a fixed or absent slot', () => {
  const helper = EXEC + 'function helper(...args) { exec(args[1]); }\n';
  candidate(scan(helper + "export function route(req) { helper('safe', req.query.value); }"));
  clean(scan(helper + "export function route(req) { helper(req.query.value, 'safe'); }"));
  clean(scan(helper + 'export function route(req) { helper(req.query.value); }'));
  clean(scan(helper + 'export function route(req) { helper(); }'));
});

test('rest independent: formal offset and readonly aliases preserve only the selected actual trace', () => {
  const text = EXEC + [
    'function helper(prefix, ...args) { const same = args; exec(same[1]); }',
    'export function route(req) {',
    '  helper(',
    '    req.query.prefix,',
    '    req.query.unselected,',
    '    req.query.selected);',
    '}',
  ].join('\n');
  const finding = candidate(scan(text));
  const sources = finding.staticFlow!.steps.filter(step => step.role === 'source');
  assert.ok(sources.some(step => step.location.path === 'app.ts' && step.location.line === 7));
  assert.equal(sources.some(step => [5, 6].includes(step.location.line)), false,
    'unused prefix and earlier rest actual are not selected-slot provenance');
  clean(scan(text.replace('req.query.selected', "'fixed'")));
});

test('rest independent: a caller array remains one actual rather than flattening its slots', () => {
  const caller = 'export function route(req) { const original = [\'safe\', req.query.value]; helper(original); }';
  clean(scan(EXEC + 'function helper(...args) { exec(args[1]); }\n' + caller));
  candidate(scan(EXEC + 'function helper(...args) { exec(args[0][1]); }\n' + caller));
});

test('rest independent: fresh array length does not inherit input content', () => {
  clean(scan(EXEC + "function helper(...args) { exec(String(args.length)); }\nexport function route(req) { helper(req.query.value, 'fixed'); }"));
});

test('rest independent: alias mutation and opaque effects revoke exact slot authority', () => {
  for (const effect of [
    "const same = args; same[0] = 'fixed';",
    'const same = args; delete same[0];',
    'const same = args; same.length = 0;',
    'opaque(args);',
  ]) {
    incomplete(scan(EXEC + `function helper(...args) { ${effect} exec(args[0]); }\nexport function route(req) { helper(req.query.value); }`));
  }
  // A initially clean carrier cannot grant a clean certificate after a new input write through an alias.
  incomplete(scan(EXEC + "function helper(req, ...args) { const same = args; same[0] = req.query.value; exec(args[0]); }\nexport function route(req) { helper(req, 'fixed'); }"));
});

test('rest independent: extracted object mutation and slot escape cannot leave stale fixed properties', () => {
  incomplete(scan(EXEC + "function helper(req, ...args) { const item = args[0]; item.cmd = req.query.value; exec(args[0].cmd); }\nexport function route(req) { helper(req, {cmd:'fixed'}); }"));
  incomplete(scan(EXEC + "function helper(...args) { opaque(args[0]); exec(args[0].cmd); }\nexport function route(req) { helper({cmd:'fixed'}); }"));
  clean(scan(EXEC + "function helper(...args) { exec(args[0].cmd); }\nexport function route(req) { helper({cmd:'fixed'}); }"));
});

test('rest independent: a dynamic index retains aggregate input with an explicit gap', () => {
  const result = scan(EXEC + "function helper(key, ...args) { exec(args[key]); }\nexport function route(req) { helper(req.query.slot, 'safe', req.query.value); }");
  incomplete(result);
  assert.equal(result.shell.length, 1);
  assert.equal(result.shell[0].confidence, 'low');
  assert.equal(result.shell[0].staticFlow?.truncated, true);
  assert.ok(result.shell[0].staticFlow?.steps.some(step => step.role === 'source'));
  const namedLength = scan(EXEC + 'function helper(length, ...args) { exec(args[length]); }\nexport function route(req) { helper(0, req.query.value); }');
  incomplete(namedLength);
  assert.equal(namedLength.shell.length, 1, 'an identifier named length is a dynamic index, not the array length property');
  assert.equal(namedLength.shell[0].confidence, 'low');
  assert.equal(namedLength.shell[0].staticFlow?.truncated, true);
  assert.ok(namedLength.shell[0].staticFlow?.steps.some(step => step.role === 'source'));
  for (const property of ["args['length']", 'args.length']) {
    clean(scan(EXEC + `function helper(...args) { exec(String(${property})); }\nexport function route(req) { helper(req.query.value); }`));
  }
});

test('rest independent: spread, nested rest binding and default effects stay explicitly unsupported', () => {
  for (const text of [
    EXEC + "function helper(...args) { exec(args[1]); } export function route(req) { helper(...req.body.items, req.query.value); }",
    EXEC + "function helper(prefix, ...args) { exec(args[0]); } export function route(req) { helper(...req.body.items, req.query.value); }",
    EXEC + "function helper(...[head, ...tail]) { exec(tail[0]); } export function route(req) { helper('safe', req.query.value); }",
    EXEC + "function helper(seed, unused = (seed.box.command = seed.input), ...args) { exec(args[0].command); } export function route(req) { const box = {command: 'fixed'}; helper({box, input: req.query.value}, undefined, box); }",
  ]) incomplete(scan(text));
});

test('rest independent: relative imported helper receives the same positional actual semantics', () => {
  const leaf = EXEC + 'export function helper(prefix, ...args) { exec(args[1]); }';
  const app = "import { helper } from './helper'; export function route(req) { helper('tag', 'fixed', req.query.value); }";
  const finding = candidate(scan(app, { 'helper.ts': leaf }));
  assert.equal(finding.location.path, 'helper.ts');
  assert.ok(finding.staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'app.ts'));
  clean(scan(app.replace("'fixed', req.query.value", "req.query.value, 'fixed'"), { 'helper.ts': leaf }));
});

test('rest independent: carrying encoded data does not mint a native sanitizer certificate', () => {
  const helper = "function helper(...args) { fetch('https://owned.invalid/path?' + args[0]); }\n";
  const result = scan(helper + "export function route(req) { const encoded = new URLSearchParams({q:req.query.value}).toString(); helper(encoded); }");
  assert.ok(result.check.status === 'partial' || result.check.findings.some(f => f.ruleId === 'ast:server-request'),
    'rest slot transport must not introduce a completed native encoded-query exclusion');
  if (result.check.status === 'partial') incomplete(result);
  clean(scan(helper + "export function route(req) { helper('q=fixed'); }"));
});
