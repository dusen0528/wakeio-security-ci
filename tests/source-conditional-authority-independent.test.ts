import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { runSource } from '../src/source.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { CheckResult, Finding, SourceOptions } from '../src/contracts.js';

type Files = Record<string, string>;
const meta = {
  'package.json': JSON.stringify({ dependencies: { mongodb: '^2.1.18' } }),
  'package-lock.json': JSON.stringify({ packages: { 'node_modules/mongodb': { version: '2.2.36' } }, dependencies: { mongodb: { version: '2.2.36' } } }),
};
const sourceLine = '    const threshold = req.query.threshold;';
const operatorLine = "      return {$where: `this.value > '${threshold}'`};";
const sinkLine = '    collection.find(criteria());';
const privateSentinel = 'owned-private-conditional-4f2e9a-sentinel';
const sourceSentinel = `// Owned source-only marker: ${privateSentinel}`;
function chain(): Files {
  return { ...meta,
    'entry.js': `const MongoClient = require('mongodb').MongoClient;
const setup = require('./routes');
MongoClient.connect('mongodb://owned-static-only', (err, db) => setup(app, db));
`,
    'routes.js': `const Handler = require('./handler');
function setup(app, db) {
  const handler = new Handler(db);
  app.get('/lookup', handler.show);
}
module.exports = setup;
`,
    'handler.js': `const DAO = require('./dao').DAO;
function Handler(db) {
  const dao = new DAO(db);
  this.show = (req, res) => {
${sourceLine}
    dao.query(threshold);
  };
}
module.exports = Handler;
`,
    'dao.js': `function DAO(db) {
  const collection = db.collection('records');
  this.query = (threshold) => {
    const criteria = () => {
${operatorLine}
    };
${sinkLine}
  };
}
module.exports.DAO = DAO;
`,
    // Deliberately unknown loader destination. It is never executed.
    'loader.js': 'const extension = require(selectedExtension);\n',
  };
}
const onlyNoSql = (check: CheckResult) => check.findings.filter(f => f.ruleId === 'ast:nosql-input-sink');
async function scan(files: Files, options: Pick<SourceOptions, 'maxFiles' | 'maxBytes'> = {}) {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-independent-conditional-'));
  // Append inert data without moving any source/sink coordinates or adding a detector trigger.
  files = { ...files, 'handler.js': files['handler.js'] + '\n' + sourceSentinel + '\n' };
  try {
    for (const [path, text] of Object.entries(files)) { await mkdir(dirname(join(root, path)), { recursive: true }); await writeFile(join(root, path), text); }
    const checks = await runSource({ root, tools: [], analysisProfile: 'extended', ...options });
    for (const [path, text] of Object.entries(files)) assert.equal(await readFile(join(root, path), 'utf8'), text, `target changed: ${path}`);
    const report = createReport(checks, 'source', new Date());
    const outputs = [JSON.stringify(report), JSON.stringify(toAgentReport(report)), toMarkdown(report), JSON.stringify(toSarif(report))];
    for (const serialized of outputs) {
      assert.equal(serialized.includes(privateSentinel), false, 'Private synthetic value leaked');
      assert.equal(serialized.includes(sourceSentinel), false, 'Source marker leaked');
      assert.equal(serialized.includes(sourceLine.trim()), false, 'Request source excerpt leaked');
      for (const [path, content] of Object.entries(files).filter(([path]) => path.endsWith('.js'))) {
        const excerpt = content.trim();
        assert.equal(serialized.includes(excerpt), false, `Full source excerpt leaked: ${path}`);
        assert.equal(serialized.includes(JSON.stringify(excerpt).slice(1, -1)), false, `JSON-escaped source excerpt leaked: ${path}`);
      }
    }
    const ast = checks.find(check => check.id === 'source.builtin-ast'); assert.ok(ast);
    return { checks, ast, findings: onlyNoSql(ast), gate: evaluateGate(report, 'none').exitCode };
  } finally { await rm(root, { recursive: true, force: true }); }
}
function assertPartial(result: Awaited<ReturnType<typeof scan>>) {
  assert.equal(result.ast.status, 'partial'); assert.equal(result.gate, 2);
}
function assertThresholdWitness(finding: Finding) {
  assert.equal(finding.kind, 'candidate');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.confidence, 'low');
  assert.equal(finding.staticFlow?.truncated, true);
  assert.equal(finding.staticContext?.revision, 'static-context-v1');
  assert.equal(finding.staticContext?.authority, 'conditional');
  assert.ok(finding.staticContext!.items.length > 0 && finding.staticContext!.items.length <= 8);
  assert.equal(finding.staticContext?.truncated, false);
  assert.ok(finding.staticContext!.items.some(item => item.kind === 'unresolved_cjs_dispatch'));
  assert.deepEqual(finding.location, { path: 'dao.js', line: 5, column: operatorLine.indexOf('$where') + 1 });
  const steps = finding.staticFlow!.steps;
  assert.ok(steps.some(step => step.role === 'source' && step.location.path === 'handler.js' && step.location.line === 5 && step.location.column === sourceLine.indexOf('req.query') + 1));
  assert.ok(steps.some(step => step.role === 'parameter' && step.location.path === 'dao.js'));
  assert.ok(steps.some(step => step.role === 'intermediate' && step.location.path === 'dao.js' && step.location.line === 5));
  assert.deepEqual(steps.at(-1), { role: 'sink', location: { path: 'dao.js', line: 7, column: sinkLine.indexOf('collection.find') + 1 } });
}

test('independent public scan retains the real threshold chain through conditional CJS construction and captured return', async () => {
  const result = await scan(chain()); assertPartial(result);
  assert.equal(result.findings.length, 1); assertThresholdWitness(result.findings[0]);
});

test('constant counterpart and unused earlier opaque input cannot bootstrap a conditional selector source', async () => {
  for (const use of ['dao.query(opaque(req.body.unused), \'fixed\');', "dao.query('fixed');"]) {
    const files = chain();
    files['handler.js'] = files['handler.js'].replace('dao.query(threshold);', use);
    if (use.includes('opaque')) files['dao.js'] = files['dao.js'].replace('this.query = (threshold)', 'this.query = (unused, threshold)');
    const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 0, use);
  }
});

test('mixed opaque earlier actual does not replace the later real threshold witness', async () => {
  const files = chain();
  files['handler.js'] = files['handler.js'].replace('dao.query(threshold);', 'dao.query(opaque(req.body.unused), threshold);');
  files['dao.js'] = files['dao.js'].replace('this.query = (threshold)', 'this.query = (unused, threshold)');
  const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 1); assertThresholdWitness(result.findings[0]);
});

test('both interpolated contributors retain the concrete later threshold source over an earlier opaque result', async () => {
  const files = chain();
  files['handler.js'] = files['handler.js'].replace('dao.query(threshold);', 'dao.query(opaque(req.body.unused), threshold);');
  files['dao.js'] = files['dao.js'].replace('this.query = (threshold)', 'this.query = (earlier, threshold)').replace("this.value > '${threshold}'", "this.earlier == '${earlier}' && this.value > '${threshold}'");
  const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 1); assertThresholdWitness(result.findings[0]);
});

test('known producer overwrite and local loader shadowing cannot traverse a stale declared body', async () => {
  for (const change of ['overwrite', 'shadow'] as const) {
    const files = chain();
    if (change === 'overwrite') files['dao.js'] += '\nmodule.exports.DAO = function Replacement() { this.query = () => 0; };\n';
    else files['handler.js'] = files['handler.js'].replace("const DAO = require('./dao').DAO;", "const require = customLoader; const DAO = require('./dao').DAO;");
    const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 0, change);
  }
});

test('legacy Db authority comes from the actual second driver callback slot rather than a variable name', async () => {
  const files = chain(); files['entry.js'] = files['entry.js'].replace('(err, db) => setup(app, db)', '(db, error) => setup(app, db)');
  const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 0);
});

test('unsupported and contradictory collected driver metadata do not revive the legacy Db callback origin', async () => {
  for (const version of ['3.0.0', 'conflicting']) {
    const files = chain();
    if (version === '3.0.0') files['package.json'] = JSON.stringify({ dependencies: { mongodb: '^3.0.0' } });
    files['package-lock.json'] = JSON.stringify({ packages: { 'node_modules/mongodb': { version: '3.0.0' } }, dependencies: { mongodb: { version: version === 'conflicting' ? '2.2.36' : '3.0.0' } } });
    const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 0, version);
  }
});

test('concrete singleton loader changes and escaped require aliases veto the original conditional body', async () => {
  const mutations = [
    "const Module = require('node:module'); Module._load = replacement;\n",
    "const Module = require('module'); Module._load = replacement;\n",
    "import Module from 'node:module'; Module._load = replacement;\n",
    "require.cache['owned-module'] = replacement;\n",
    "const loader = require; opaque(loader);\n",
  ];
  for (const mutation of mutations) {
    const files = chain(); files['mutation.js'] = mutation;
    const result = await scan(files); assertPartial(result);
    assert.equal(result.findings.length, 0, mutation);
  }
});

test('missing actual and lexical capture cannot be replaced by a freshly seeded parameter name', async () => {
  for (const mutation of ['missing-actual', 'missing-capture'] as const) {
    const files = chain();
    if (mutation === 'missing-actual') files['handler.js'] = files['handler.js'].replace('dao.query(threshold);', 'dao.query();');
    else files['dao.js'] = files['dao.js'].replace('this.query = (threshold)', 'this.query = (unused)');
    const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 0, mutation);
  }
});

test('conditional construction does not turn a no-new guard with mutated hasInstance into closed authority', async () => {
  const files = chain();
  files['dao.js'] = files['dao.js'].replace('function DAO(db) {', 'function DAO(db) {\n  if (false === (this instanceof DAO)) return new DAO(db);');
  files['mutation.js'] = 'Function.prototype[Symbol.hasInstance] = customInstanceCheck;\n';
  const result = await scan(files); assertPartial(result);
  assert.equal(result.findings.length, 0); // Known intrinsic mutation forbids skipping the fallback guard or traversing a stale owned body.
});

test('factory sideband preserves returned receiver without laundering an unused input into a fixed selector', async () => {
  for (const actual of ['threshold', "'fixed'"]) {
    const files = chain();
    files['handler.js'] = files['handler.js'].replace('    dao.query(threshold);', `    function keep(value, unused) { return value; }\n    keep(dao, req.body.unused).query(${actual});`);
    const result = await scan(files); assertPartial(result);
    assert.equal(result.findings.length, actual === 'threshold' ? 1 : 0);
    if (result.findings.length) assertThresholdWitness(result.findings[0]);
  }
});

test('native package mutation never promotes conditional receiver evidence to a closed or completed result', async () => {
  const files = chain(); files['mutation.js'] = "const other = require('mongodb').MongoClient; other.connect = customConnect;\n";
  const result = await scan(files); assertPartial(result);
  assert.equal(result.findings.length, 0); // Concrete driver writes cannot revive the original legacy Db origin.
});

test('separate allocation contexts keep fixed and tainted selector calls independent', async () => {
  const files = chain();
  files['handler.js'] = files['handler.js'].replace('  const dao = new DAO(db);', '  const dao = new DAO(db);\n  const fixedDao = new DAO(db);').replace('    dao.query(threshold);', "    fixedDao.query('fixed');\n    dao.query(threshold);");
  const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 1);
  assert.ok(result.findings[0].staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'handler.js' && step.location.line === 6));
});

test('public collection budget truncation cannot produce a complete conditional scan', async () => {
  const result = await scan(chain(), { maxFiles: 1 });
  assert.equal(result.gate, 2);
  assert.equal(result.checks.find(check => check.id === 'source.inventory')?.status, 'partial');
  assert.equal(result.findings.length, 0);
});

test('multiple real contributors keep a representative actual input witness without certifying all contributors', async () => {
  const files = chain();
  files['handler.js'] = files['handler.js'].replace('    dao.query(threshold);', '    const tenant = req.query.tenant;\n    dao.query(tenant, threshold);');
  files['dao.js'] = files['dao.js'].replace('this.query = (threshold)', 'this.query = (tenant, threshold)').replace("this.value > '${threshold}'", "this.tenant == '${tenant}' && this.value > '${threshold}'");
  const result = await scan(files); assertPartial(result); assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.staticContext?.authority, 'conditional');
  assert.equal(finding.staticFlow?.truncated, true);
  assert.ok(finding.staticFlow!.steps.some(step => step.role === 'source' && step.location.path === 'handler.js' && [5, 6].includes(step.location.line)));
  assert.equal(finding.staticFlow!.steps.at(-1)?.location.path, 'dao.js');
  assert.equal(finding.staticFlow!.steps.at(-1)?.location.line, 7);
});

test('real call-depth exhaustion stays partial independently of conditional dispatch evidence', async () => {
  const files = chain();
  const wrappers = Array.from({ length: 14 }, (_, i) => `function layer${i}(value) { return ${i === 13 ? 'value' : `layer${i + 1}(value)`}; }`).join('\n');
  files['handler.js'] = files['handler.js'].replace('    dao.query(threshold);', `    dao.query(layer0(threshold));\n${wrappers}`);
  const result = await scan(files); assertPartial(result);
  assert.ok(result.ast.analysisGaps?.reasonSummary?.rows.some(row => row.reason === 'depth_limit' && Number(row.eventsObserved) > 0));
  assert.ok(result.findings.every(finding => finding.staticFlow?.truncated === true && finding.confidence === 'low'));
});
