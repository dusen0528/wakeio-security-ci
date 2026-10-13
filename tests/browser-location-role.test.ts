import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import type { SourceSnapshot } from '../src/source/types.js';
import type { CheckResult } from '../src/contracts.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';

const RULE = 'ast:open-redirect';
const START = '2026-10-14T00:00:00.000Z';
const MARKER = 'OWNED_BROWSER_LOCATION_DATA_ONLY_MARKER';

// Source text is passed directly to the scanner; these programs are never executed.
function scan(text: string, extra: Record<string, string> = {}, complete = true, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries({ 'app.ts': text, ...extra }).map(([path, text]) => ({
    path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false,
  }));
  const snapshot: SourceSnapshot = { root: '/never-execute-browser-location-fixture', files,
    issues: [], complete, ignoredFiles: 0, totalBytes: files.reduce((total, file) => total + file.bytes, 0) };
  return runBuiltinAst(snapshot, false, limits);
}

const navigation = (check: CheckResult) => check.findings.filter(finding => finding.ruleId === RULE);
function unresolved(check: CheckResult, label: string) {
  const findings = navigation(check);
  assert.equal(findings.length, 1, label);
  const finding = findings[0];
  assert.equal(finding.kind, 'candidate', label);
  assert.equal(finding.severity, 'medium', label);
  assert.equal(finding.confidence, 'low', label);
  assert.match(finding.description, /(?:receiver[^.]*unresolved|unresolved[^.]*receiver)/i, label);
  assert.ok(finding.staticFlow?.steps.some(step => step.role === 'source'), label);
  assert.ok(finding.staticFlow?.steps.some(step => step.role === 'sink'), label);
  return finding;
}

test('browser location: unbound direct global window keeps the existing navigation candidate', () => {
  const text = 'function route(req){window.location=req.query.next}';
  const check = scan(text), finding = navigation(check)[0];
  assert.equal(check.status, 'completed');
  assert.equal(navigation(check).length, 1);
  assert.equal(finding.kind, 'candidate');
  assert.equal(finding.severity, 'medium');
  assert.equal(finding.confidence, 'medium');
  assert.match(finding.description, /browser navigation target/);
  assert.deepEqual(finding.location, { path: 'app.ts', line: 1, column: text.indexOf('window.location') + 1 });
  const report = createReport([check], 'source', START);
  assert.equal(evaluateGate(report, 'medium').exitCode, 1);
  assert.equal(evaluateGate(report, 'high').exitCode, 0);
  assert.equal(evaluateGate(report, 'none').exitCode, 0);
});

test('browser location: exact fresh const data object excludes only the direct own location assignment', () => {
  const cases = [
    'export {};const window={location:{}};function render(req){window.location=req.query.next}',
    'function render(req){const window={location:{}};window.location=req.query.next}',
  ];
  for (const text of cases) {
    const check = scan(text);
    assert.equal(check.status, 'completed', text);
    assert.equal(navigation(check).length, 0, text);
    assert.equal(evaluateGate(createReport([check], 'source', START), 'medium').exitCode, 0, text);
  }
});

for (const [label, effect] of [['without an opaque call', ''], ['with an opaque call', 'opaque();']] as const) {
  test(`browser location: script-global const stays unresolved ${label}`, () => {
    const text = 'const window={location:{}};' + effect
      + 'function render(req){window.location=req.query.next}';
    const check = scan(text);
    unresolved(check, label);
    assert.equal(check.status, 'completed');
    assert.equal(check.metrics?.indexComplete, true);
    assert.equal(evaluateGate(createReport([check], 'source', START), 'medium').exitCode, 1);
  });
}

test('browser location: parameters imports opaque values mutable bindings and global aliases stay unresolved', () => {
  const cases: Array<[string, string, Record<string, string>?]> = [
    ['parameter', 'function render(window,req){window.location=req.query.next}'],
    ['opaque initializer', 'const window=getReceiver();function render(req){window.location=req.query.next}'],
    ['mutable binding', 'let window={location:{}};function render(req){window.location=req.query.next}'],
    ['alias from browser global', 'const window=globalThis.window;function render(req){window.location=req.query.next}'],
    ['alias from local object', 'const mock={location:{}};const window=mock;function render(req){window.location=req.query.next}'],
    ['imported binding', "import {window} from './mock';export function render(req){window.location=req.query.next}",
      { 'mock.ts': 'export const window={location:{}};' }],
  ];
  for (const [label, text, extra] of cases) unresolved(scan('export {};' + text, extra), label);
});

test('browser location: accessor and non-data literal forms revoke the direct assignment exclusion', () => {
  const initializers = [
    ['getter', '{get location(){return globalThis.location}}'],
    ['setter', '{set location(value){globalThis.location=value}}'],
    ['computed key', "{['location']:{}}"],
    ['spread', '{...base,location:{}}'],
    ['prototype key', '{__proto__:base,location:{}}'],
    ['missing own slot', '{}'],
  ];
  for (const [label, initializer] of initializers) {
    unresolved(scan(`export {};const window=${initializer};function render(req){window.location=req.query.next}`), label);
  }
});

test('browser location: descriptor delete escape export and alias references invalidate closed receiver proof', () => {
  const suffix = 'function render(req){window.location=req.query.next}';
  const cases = [
    ['descriptor', `const window={location:{}};Object.defineProperty(window,'location',{set(value){globalThis.location=value}});${suffix}`],
    ['delete', `const window={location:{}};delete window.location;${suffix}`],
    ['escape', `const window={location:{}};mutate(window);${suffix}`],
    ['export', `export const window={location:{}};${suffix}`],
    ['alias', `const window={location:{}};const other=window;${suffix}`],
    ['prototype mutation', `const window={location:{}};Object.setPrototypeOf(window,base);${suffix}`],
    ['unrelated member mutation', `const window={location:{}};window.other=base;${suffix}`],
  ];
  for (const [label, text] of cases) unresolved(scan('export {};' + text), label);
});

test('browser location: string evaluation and with prevent a closed-object exclusion without indexed receiver references', () => {
  const prefix = 'export {};const window={location:{}};';
  const suffix = 'function render(req){window.location=req.query.next}';
  // The window spelling below is inside inert source literals, so a symbol-reference
  // audit alone cannot prove that the receiver descriptor remains unchanged.
  const mutation = "Object.defineProperty(window,'location',{set(value){globalThis.location=value}})";
  const cases = [
    ['direct eval', `eval(${JSON.stringify(mutation)});`],
    ['indirect eval', `(0,eval)(${JSON.stringify(mutation)});`],
    ['Function call', `Function(${JSON.stringify(mutation)})();`],
    ['Function constructor', `new Function(${JSON.stringify(mutation)})();`],
    ['with statement', 'with(scope){mutateReceiver()}'],
  ];
  for (const [label, effect] of cases) unresolved(scan(prefix + effect + suffix), label);
  // The veto is conservative across the collected snapshot, without attempting
  // to decide which dynamically evaluated string can see a particular binding.
  unresolved(scan(prefix + suffix, { 'dynamic.ts': `function effect(){eval(${JSON.stringify(mutation)})}` }),
    'dynamic code in another collected input');
});

for (const [label, evaluator] of [
  ['literal self eval', "self['eval'](CODE);"],
  ['aliased literal self Function', "const make=self['Function'];make(CODE)();"],
  ['literal top-level this eval', "this['eval'](CODE);"],
] as const) {
  test(`browser location: ${label} invalidates the local descriptor proof`, () => {
    const mutation = "Object.defineProperty(window,'location',{set(value){self.location=value}})";
    const text = 'export {};const window={location:{}};'
      + evaluator.replace('CODE', JSON.stringify(mutation))
      + 'function render(req){window.location=req.query.next}';
    // Literal member keys contain no evaluator Identifier, and the descriptor
    // mutation exists only in source text; neither string nor target is executed.
    unresolved(scan(text), label);
  });
}

for (const [label, evaluator] of [
  ['quoted eval destructuring', "const {'eval':run}=self;run(CODE);"],
  ['quoted Function destructuring', "const {'Function':make}=self;make(CODE)();"],
  ['template literal eval member', 'self[`eval`](CODE);'],
  ['composed computed eval binding', "const {['ev'+'al']:run}=self;run(CODE);"],
  ['opaque computed eval binding', "const key='ev'+'al';const {[key]:run}=self;run(CODE);"],
] as const) {
  test(`browser location: ${label} cannot certify an unchanged local data descriptor`, () => {
    const mutation = "Object.defineProperty(window,'location',{set(value){self.location=value}})";
    const text = 'export {};const window={location:{}};'
      + evaluator.replace('CODE', JSON.stringify(mutation))
      + 'function render(req){window.location=req.query.next}';
    unresolved(scan(text), label);
  });
}

test('browser location: assertion-wrapped initializers and literal computed targets remain outside the exemption', () => {
  for (const initializer of ['{location:{}} as const', '({location:{}} as const)']) {
    unresolved(scan(`export {};const window=${initializer};function render(req){window.location=req.query.next}`), initializer);
  }
  // The existing name matcher recognizes literal element access. Its receiver
  // is not granted the new direct-dot-assignment exclusion.
  const check = scan("export {};const window={location:{}};function render(req){window['location']=req.query.next}");
  const findings = navigation(check);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'candidate');
  assert.equal(findings[0].severity, 'medium');
});

test('browser location: nested href and standalone location behavior remain outside the new exclusion', () => {
  const cases = [
    'function route(req){window.location.href=req.query.next}',
    'const window={location:{}};function route(req){window.location.href=req.query.next}',
    "const window={location:{href:''}};function route(req){window.location.href=req.query.next}",
    "Object.defineProperty(Object.prototype,'href',{set(value){globalThis.location=value}});const window={location:{}};function route(req){window.location.href=req.query.next}",
    'function route(req){location=req.query.next}',
    'function route(req){location.href=req.query.next}',
  ];
  for (const text of cases) {
    const findings = navigation(scan(text));
    assert.equal(findings.length, 1, text);
    assert.equal(findings[0].kind, 'candidate', text);
    assert.equal(findings[0].severity, 'medium', text);
    assert.equal(findings[0].confidence, 'medium', text);
  }
});

test('browser location: call-context order never promotes a parameter receiver into a closed local object', () => {
  const local = 'render({location:{}},req.query.next);';
  const opaque = 'render(globalThis.window,req.query.next);';
  for (const calls of [local + opaque, opaque + local]) {
    const text = `function render(window,next){window.location=next}function route(req){${calls}}`;
    unresolved(scan(text), calls);
  }
});

test('browser location: incomplete scope parse and index work cannot certify a closed receiver', () => {
  const text = 'export {};const window={location:{}};window.location=req.query.next;';
  const incomplete = scan(text, {}, false);
  unresolved(incomplete, 'incomplete source snapshot');
  const report = createReport([{ id: 'source.inventory', status: 'partial', findings: [], notes: [] }, incomplete], 'source', START);
  assert.equal(evaluateGate(report, 'none').exitCode, 2);

  const parseGap = scan(text, { 'broken.ts': 'function broken(' });
  unresolved(parseGap, 'another input has a parse error');
  assert.equal(parseGap.status, 'partial');
  assert.equal(evaluateGate(createReport([parseGap], 'source', START), 'none').exitCode, 2);

  const indexGap = scan(text, {}, true, { ...FLOW_LIMITS, indexWork: 1 });
  assert.equal(indexGap.status, 'partial');
  assert.equal(indexGap.metrics?.indexComplete, false);
  assert.match(String(indexGap.metrics?.incompleteReasons), /index_work_limit/);
  // Top-level direct evidence remains observable without a complete function index.
  unresolved(indexGap, 'incomplete binding/reference index');
  assert.equal(evaluateGate(createReport([indexGap], 'source', START), 'none').exitCode, 2);
});

test('browser location: other sinks and public evidence remain intact after local receiver exclusion', () => {
  const text = `export {};const window={location:{}};function route(req){window.location=req.query.${MARKER};db.query(req.query.${MARKER});document.write(req.query.${MARKER})}`;
  const check = scan(text);
  assert.equal(navigation(check).length, 0);
  assert.equal(check.findings.filter(finding => finding.ruleId === 'ast:sql-input-sink').length, 1);
  assert.equal(check.findings.filter(finding => finding.ruleId === 'ast:html-input-sink').length, 1);
  const report = createReport([check], 'source', START), agent = toAgentReport(report);
  assert.equal(evaluateGate(report, 'high').exitCode, 1);
  assert.equal(agent.scanGate.exitCode, 1);
  assert.equal(evaluateGate(report, 'none').exitCode, 0);
  assert.ok(agent.findings.every(finding => finding.verification.state === 'not_run'
    && !finding.verification.vulnerabilityConfirmed && !finding.verification.remediationVerified
    && finding.remediation.state === 'not_verified'));
  for (const output of [JSON.stringify(report), JSON.stringify(agent), toMarkdown(report), JSON.stringify(toSarif(report))]) {
    assert.equal(output.includes(MARKER), false);
    assert.equal(output.includes(text), false);
  }
});

test('browser location: unresolved receiver remains a candidate in every projection and severity gate', () => {
  const text = `function render(window,req){window.location=req.query.${MARKER}}`;
  const check = scan(text);
  unresolved(check, 'parameter navigation-shaped write');
  assert.equal(check.status, 'completed');
  const report = createReport([check], 'source', START), agent = toAgentReport(report, 'medium');
  assert.equal(evaluateGate(report, 'medium').exitCode, 1);
  assert.equal(evaluateGate(report, 'high').exitCode, 0);
  assert.equal(evaluateGate(report, 'none').exitCode, 0);
  assert.equal(agent.findings.length, 1);
  assert.equal(agent.findings[0].confidence, 'low');
  assert.equal(agent.findings[0].reachesFailOn, true);
  assert.equal(agent.findings[0].verification.state, 'not_run');
  assert.equal(agent.findings[0].verification.vulnerabilityConfirmed, false);
  assert.equal(agent.findings[0].verification.remediationVerified, false);
  assert.equal(agent.findings[0].remediation.state, 'not_verified');
  for (const output of [JSON.stringify(report), JSON.stringify(agent), toMarkdown(report), JSON.stringify(toSarif(report))]) {
    assert.match(output, /receiver/i);
    assert.match(output, /unresolved/i);
    assert.equal(output.includes(MARKER), false);
    assert.equal(output.includes(text), false);
  }
});
