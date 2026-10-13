import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runBuiltinAst } from '../src/source/ast.js';
import { runSource } from '../src/source.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import type { CheckResult, Finding } from '../src/contracts.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';

// Independent behavioral oracle: no prospective engine module imports or target execution.
const direct = ['execFile', 'execFileSync', 'spawn', 'spawnSync'] as const;
const shell = ['exec', 'execSync'] as const;
const methods = [...shell, ...direct];
const privateValue = 'owned-process-private-84af70-marker';
const marker = `// ${privateValue}`;
const processRules = new Set(['ast:shell-input-sink', 'ast:process-executable']);
type Files = Record<string, string>;
function snapshot(texts: Files): SourceSnapshot {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  return { root: '/never-import-or-execute', files, issues: [], ignoredFiles: 0, totalBytes: files.reduce((n, f) => n + f.bytes, 0), complete: true };
}
function projections(checks: CheckResult[], texts: Files) {
  const report = createReport(checks, 'source', '2026-10-13T00:00:00.000Z');
  const agent = toAgentReport(report, 'none');
  const outputs = [JSON.stringify(report), JSON.stringify(agent), toMarkdown(report), JSON.stringify(toSarif(report))];
  for (const output of outputs) {
    assert.equal(output.includes(privateValue), false, 'synthetic private value leaked');
    assert.equal(output.includes(marker), false, 'source marker leaked');
    for (const text of Object.values(texts)) {
      for (const line of text.split('\n').filter(line => /req\.(?:query|body)/.test(line))) {
        assert.equal(output.includes(line.trim()), false, 'source excerpt leaked');
        assert.equal(output.includes(JSON.stringify(line.trim()).slice(1, -1)), false, 'escaped source excerpt leaked');
      }
    }
  }
  return { report, agent };
}
function scan(text: string, more: Files = {}, limits: FlowLimits = FLOW_LIMITS) {
  const files = { 'app.ts': text + '\n' + marker, ...more };
  const ast = runBuiltinAst(snapshot(files), false, limits);
  const projected = projections([ast], files);
  return { ast, findings: ast.findings.filter(f => processRules.has(f.ruleId)), ...projected };
}
function known(result: ReturnType<typeof scan>, rule: 'ast:shell-input-sink' | 'ast:process-executable') {
  assert.equal(result.ast.status, 'completed');
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.ruleId, rule);
  assert.equal(finding.kind, 'candidate');
  assert.equal(finding.severity, rule === 'ast:shell-input-sink' ? 'critical' : 'high');
  assert.equal(finding.confidence, 'medium');
  assert.ok(finding.staticFlow?.steps.some(step => step.role === 'source'));
  assert.equal(evaluateGate(result.report, 'high').exitCode, 1);
  assert.equal(toAgentReport(result.report, 'high').scanGate.exitCode, 1);
  return finding;
}
function closed(result: ReturnType<typeof scan>) {
  assert.equal(result.ast.status, 'completed');
  assert.equal(result.findings.length, 0);
  assert.equal(evaluateGate(result.report, 'high').exitCode, 0);
}
function uncertain(result: ReturnType<typeof scan>) {
  assert.ok(result.findings.length > 0 || result.ast.status === 'partial', 'unknown process role was silently completed clean');
  for (const finding of result.findings) {
    assert.equal(finding.kind, 'candidate');
    assert.equal(finding.confidence, 'low');
    assert.equal(finding.staticFlow?.truncated, true);
    assert.match(`${finding.title} ${finding.description}`, /unknown|unresolved|possible|unverified/i);
  }
  if (result.ast.status === 'partial') {
    assert.equal(evaluateGate(result.report, 'none').exitCode, 2);
    assert.equal(result.agent.scanGate.exitCode, 2);
  }
}
function location(text: string, needle: string) {
  const position = text.indexOf(needle); assert.ok(position >= 0, needle);
  const preceding = text.slice(0, position).split('\n');
  return { path: 'app.ts', line: preceding.length, column: preceding.at(-1)!.length + 1 };
}
function sourceAt(finding: Finding, text: string, needle: string) {
  assert.ok(finding.staticFlow!.steps.some(step => step.role === 'source' && JSON.stringify(step.location) === JSON.stringify(location(text, needle))), `missing true source ${needle}`);
}

test('all six native APIs distinguish command/executable input with the Node 22 default mode', () => {
  for (const method of methods) {
    const args = direct.includes(method as typeof direct[number]) ? 'req.query.executable, []' : 'req.query.command';
    const text = `import {${method} as launch} from 'node:child_process';\nexport function route(req) { launch(${args}); }`;
    const finding = known(scan(text), shell.includes(method as typeof shell[number]) ? 'ast:shell-input-sink' : 'ast:process-executable');
    assert.deepEqual(finding.location, location(text, 'launch('));
    sourceAt(finding, text, direct.includes(method as typeof direct[number]) ? 'req.query.executable' : 'req.query.command');
  }
});

test('exec and execSync shell:false still interpret argument zero as shell command', () => {
  for (const method of shell) for (const options of ['{shell:false}', "{shell:'/bin/sh'}"]) {
    known(scan(`import {${method}} from 'child_process'; export function route(req) { ${method}(req.query.command, ${options}); }`), 'ast:shell-input-sink');
  }
});

test('empty shell string is falsey after all six Node normalizers without hiding executable input', () => {
  for (const method of methods) {
    const args = direct.includes(method as typeof direct[number]) ? 'req.query.executable, [], {shell:""}' : 'req.query.executable, {shell:""}';
    known(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch(${args}); }`), 'ast:process-executable');
    const fixed = direct.includes(method as typeof direct[number]) ? "'owned-fixed-program', [req.query.argument], {shell:''}" : "'owned-fixed-command', {shell:''}";
    closed(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch(${fixed}); }`));
  }
});

test('non-string exec shell normalizes true while unsupported direct shell types remain uncertain', () => {
  for (const method of shell) for (const value of ['null', '1', '{}']) {
    known(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch(req.query.command, {shell:${value}}); }`), 'ast:shell-input-sink');
  }
  // Direct null is runtime falsey although docs list boolean|string; numeric/object values throw.
  for (const method of direct) {
    closed(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', [req.query.argument], {shell:null}); }`));
    known(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch(req.query.executable, [], {shell:null}); }`), 'ast:process-executable');
  }
  for (const method of direct) for (const value of ['1', '{}']) {
    uncertain(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', [req.query.argument], {shell:${value}}); }`));
  }
});

test('user-controlled shell executable is independently visible with fixed command and argv', () => {
  for (const method of methods) {
    const args = direct.includes(method as typeof direct[number]) ? "'owned-fixed-program', ['fixed'], {shell:req.query.shell}" : "'owned-fixed-command', {shell:req.query.shell}";
    const text = `import {${method} as launch} from 'child_process';\nexport function route(req) { launch(${args}); }`;
    const finding = known(scan(text), 'ast:process-executable');
    sourceAt(finding, text, 'req.query.shell');
    assert.deepEqual(finding.staticFlow!.steps.at(-1), { role: 'sink', location: location(text, 'launch(') });
    assert.match(`${finding.title} ${finding.description}`, /shell|executable/i);
  }
});

test('shell field trace survives const options and does not borrow earlier unrelated input', () => {
  const text = `import {spawn as launch} from 'node:child_process';
function fixed(unused) { return 'owned-fixed-program'; }
export function route(req) {
  const options = {shell:req.query.shell};
  launch(fixed(opaque(req.body.unused)), ['fixed'], options);
}`;
  const finding = known(scan(text), 'ast:process-executable');
  sourceAt(finding, text, 'req.query.shell');
  assert.equal(finding.staticFlow!.steps.some(step => step.role === 'source' && JSON.stringify(step.location) === JSON.stringify(location(text, 'req.body.unused'))), false);
});

test('each direct API has true/string shell argv candidates and false/default counterparts', () => {
  for (const method of direct) {
    for (const options of ['{shell:true}', "{shell:'/bin/sh'}"]) {
      known(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', [req.query.argument], ${options}); }`), 'ast:shell-input-sink');
    }
    for (const suffix of ['', ', {}', ', {shell:false}']) {
      closed(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', [req.query.argument]${suffix}); }`));
    }
  }
});

test('all six fixed counterparts avoid bootstrapping input from unrelated evaluation', () => {
  for (const method of methods) {
    const args = direct.includes(method as typeof direct[number]) ? "'owned-fixed-program', ['fixed'], {shell:true}" : "'owned-fixed-command'";
    closed(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { const unused = req.body.unused; launch(${args}); }`));
  }
});

test('native named namespace default and const CommonJS aliases bind independently of spelling', () => {
  const forms = [
    ["import {spawn as launch} from 'child_process';", 'launch'],
    ["import * as cp from 'node:child_process';", 'cp.spawn'],
    ["import cp from 'child_process';", 'cp.spawn'],
    ["const cp = require('node:child_process');", 'cp.spawn'],
    ["const {spawn: launch} = require('child_process');", 'launch'],
    ["const launch = require('node:child_process').spawn;", 'launch'],
    ["const cp = require('child_process'); const launch = cp.spawn;", 'launch'],
    ['', "require('node:child_process').spawn"],
  ];
  for (const [declaration, callee] of forms) {
    known(scan(`${declaration}\nexport function route(req) { ${callee}('owned-fixed-program', [req.query.argument], {shell:true}); }`), 'ast:shell-input-sink');
    closed(scan(`${declaration}\nexport function route(req) { ${callee}('owned-fixed-program', [req.query.argument], {shell:false}); }`));
  }
});

test('options overload at argument one and callback positions do not become argv', () => {
  for (const method of direct) for (const option of ['{shell:false}', '{shell:true}']) {
    closed(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', ${option}); }`));
    known(scan(`import {${method} as launch} from 'node:child_process'; export function route(req) { launch(req.query.executable, ${option}); }`), option.includes('true') ? 'ast:shell-input-sink' : 'ast:process-executable');
  }
  closed(scan("import {execFile as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', () => req.body.unused); }"));
  known(scan("import {execFile as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', [req.query.argument], {shell:true}, () => 0); }"), 'ast:shell-input-sink');
});

test('arg1 source coordinates are independent of earlier opaque arg0 input evaluation', () => {
  const text = `import {spawn as launch} from 'node:child_process';
function fixed(unused) { return 'owned-fixed-program'; }
export function route(req) {
  launch(fixed(opaque(req.body.unused)),
    ['literal', req.query.argument], {shell:true});
}`;
  const finding = known(scan(text), 'ast:shell-input-sink');
  sourceAt(finding, text, 'req.query.argument');
  assert.equal(finding.staticFlow!.steps.some(step => step.role === 'source' && JSON.stringify(step.location) === JSON.stringify(location(text, 'req.body.unused'))), false);
  assert.deepEqual(finding.staticFlow!.steps.at(-1), { role: 'sink', location: location(text, 'launch(') });
});

test('const argv alias and completed scalar helper preserve the contributing array element', () => {
  const text = `import {execFile as launch} from 'child_process';
function identity(value) { return value; }
export function route(req) {
  const argv = ['literal', identity(req.query.argument)];
  launch('owned-fixed-program', argv, {shell:'/bin/sh'});
}`;
  sourceAt(known(scan(text), 'ast:shell-input-sink'), text, 'req.query.argument');
});

test('argument evaluation order cannot substitute a later write for captured executable input', () => {
  const fixedFirst = "import {spawn as launch} from 'child_process'; export function route(req) { let executable = 'owned-fixed-program'; launch(executable, [(executable = req.query.later)], {shell:false}); }";
  closed(scan(fixedFirst));
  const inputFirst = "import {spawn as launch} from 'child_process'; export function route(req) { let executable = req.query.executable; launch(executable, [(executable = 'fixed')], {shell:false}); }";
  sourceAt(known(scan(inputFirst), 'ast:process-executable'), inputFirst, 'req.query.executable');
});

test('same call across local contexts retains risky evidence in either visit order', () => {
  for (const calls of ["execute('fixed'); execute(req.query.argument);", "execute(req.query.argument); execute('fixed');"]) {
    known(scan(`import {spawn as launch} from 'child_process'; function execute(value) { launch('owned-fixed-program', [value], {shell:true}); } export function route(req) { ${calls} }`), 'ast:shell-input-sink');
  }
});

test('literal shell field order chooses the last property and const options preserve the mode', () => {
  const declaration = "import {spawn as launch} from 'node:child_process';";
  closed(scan(declaration + "export function route(req) { launch('owned-fixed-program', [req.query.argument], {shell:true, shell:false}); }"));
  known(scan(declaration + "export function route(req) { launch('owned-fixed-program', [req.query.argument], {shell:false, shell:true}); }"), 'ast:shell-input-sink');
  known(scan(declaration + "export function route(req) { const options = {shell:true}; launch('owned-fixed-program', [req.query.argument], options); }"), 'ast:shell-input-sink');
  closed(scan(declaration + "export function route(req) { const options = {shell:false}; launch('owned-fixed-program', [req.query.argument], options); }"));
});

test('unknown options spreads getters fields and overloaded second arguments cannot silently clean', () => {
  for (const options of ['opaqueOptions', '{shell:mode}', '{shell:false, ...opaqueOptions}', '{...opaqueOptions, shell:false}', '{get shell() { return false; }}', "{[key]:false}", '{shell:false, get cwd() { opaque(); return "."; }}']) {
    uncertain(scan(`import {spawn as launch} from 'child_process'; export function route(req) { launch('owned-fixed-program', [req.query.argument], ${options}); }`));
  }
  uncertain(scan("import {execFile as launch} from 'child_process'; export function route(req) { launch('owned-fixed-program', req.body.argvOrOptions); }"));
});

test('mutated escaped and aliased options cannot retain a stale false exclusion', () => {
  for (const mutation of ['options.shell = true;', 'const other = options; other.shell = true;', 'opaque(options);', 'Object.assign(options, opaqueOptions);']) {
    uncertain(scan(`import {spawn as launch} from 'node:child_process'; export function route(req) { const options = {shell:false}; ${mutation} launch('owned-fixed-program', [req.query.argument], options); }`));
  }
});

test('native binding writes and escapes cannot retain pristine shell-disabled authority', () => {
  const cases = [
    "const cp=require('child_process'); cp.spawn=replacement; export function route(req){cp.spawn('owned-fixed-program',[req.query.argument],{shell:false})}",
    "const cp=require('child_process'); opaque(cp); export function route(req){cp.spawn('owned-fixed-program',[req.query.argument],{shell:false})}",
    "const {spawn:launch}=require('child_process'); opaque(launch); export function route(req){launch('owned-fixed-program',[req.query.argument],{shell:false})}",
    "let launch=require('child_process').spawn; launch=replacement; export function route(req){launch('owned-fixed-program',[req.query.argument],{shell:false})}",
    "import {spawn as launch} from 'child_process'; const other=require('node:child_process'); other.spawn=replacement; export function route(req){launch('owned-fixed-program',[req.query.argument],{shell:false})}",
  ];
  for (const text of cases) uncertain(scan(text));
});

test('mutated escaped and unresolved argv shapes under shell true cannot silently clean', () => {
  for (const body of [
    "const argv=['fixed']; argv[0]=req.query.argument; launch('owned-fixed-program',argv,{shell:true});",
    "const argv=[req.query.argument]; opaque(argv); launch('owned-fixed-program',argv,{shell:true});",
    "launch('owned-fixed-program',[...req.body.argv],{shell:true});",
    "launch('owned-fixed-program',opaque(req.body.argv),{shell:true});",
  ]) {
    const result = scan(`import {spawn as launch} from 'child_process'; export function route(req) { ${body} }`);
    assert.ok(result.findings.length > 0 || result.ast.status === 'partial', 'input-related argv shape disappeared');
  }
});

test('local names lexical loader shadows and type-only imports do not manufacture native sinks', () => {
  for (const text of [
    "function exec(value) { return value; } export function route(req) { exec(req.query.argument); }",
    "function spawn(value) { return value; } export function route(req) { spawn(req.query.argument); }",
    "const require = (name) => ({spawn: value => value}); const cp = require('child_process'); export function route(req) { cp.spawn(req.query.argument); }",
    "import {spawn as launch} from 'child_process'; export function route(req) { const launch = value => value; launch(req.query.argument); }",
    "import type {spawn} from 'child_process'; function spawn(value) { return value; } export function route(req) { spawn(req.query.argument); }",
  ]) closed(scan(text));
});

test('local helper suppression preserves nested native and eval findings', () => {
  known(scan("import {exec as nativeExec} from 'node:child_process'; function spawn(value) { nativeExec(value); } export function route(req) { spawn(req.query.command); }"), 'ast:shell-input-sink');
  const result = scan("import {spawn as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program', [eval(req.body.code)], {shell:false}); }");
  assert.equal(result.findings.length, 0);
  assert.ok(result.ast.findings.some(f => f.ruleId === 'ast:dynamic-code' && f.kind === 'candidate'));
});

test('relative completed CommonJS helper preserves native inner argv source and sink files', () => {
  const main = "const execute=require('./helper'); export function route(req) { execute(req.query.argument); }";
  const helper = "const {spawn:launch}=require('node:child_process'); module.exports=function execute(value) { launch('owned-fixed-program',[value],{shell:true}); };";
  const finding = known(scan(main, { 'helper.js': helper }), 'ast:shell-input-sink');
  sourceAt(finding, main, 'req.query.argument');
  assert.equal(finding.location.path, 'helper.js');
  assert.equal(finding.staticFlow!.steps.at(-1)!.location.path, 'helper.js');
});

test('index and flow budgets keep gap accounting partial and all public gates incomplete', () => {
  const text = "import {spawn as launch} from 'node:child_process'; export function route(req) { launch('owned-fixed-program',[req.query.argument],{shell:false}); }";
  for (const limits of [{ ...FLOW_LIMITS, indexWork: 1 }, { ...FLOW_LIMITS, flowWork: 1 }]) {
    const result = scan(text, {}, limits);
    assert.equal(result.ast.status, 'partial');
    assert.equal(evaluateGate(result.report, 'none').exitCode, 2);
    assert.equal(result.agent.scanGate.exitCode, 2);
    const metrics = result.ast.metrics!;
    assert.equal(metrics.nodeVisits, Number(metrics.indexWork) + Number(metrics.flowWork));
    assert.ok(Number(metrics.indexWork) <= Number(metrics.maxIndexWork));
    assert.ok(Number(metrics.flowWork) <= Number(metrics.maxFlowWork));
    assert.ok(Number(metrics.nodeVisits) <= Number(metrics.maxNodeVisits));
    assert.ok(result.ast.analysisGaps?.items.length);
    assert.ok(result.ast.analysisGaps!.items.length <= 32);
    assert.equal(result.ast.analysisGaps!.accounting, 'exact');
  }
});

test('parse uncertainty cannot turn a process candidate into a completed clean result', () => {
  const result = scan("import {exec as launch} from 'node:child_process'; export function route(req) { launch(req.query.command); }", { 'broken.js': 'function {' });
  assert.equal(result.ast.status, 'partial');
  assert.equal(evaluateGate(result.report, 'none').exitCode, 2);
  assert.equal(result.agent.scanGate.exitCode, 2);
  assert.ok(result.ast.analysisGaps?.items.some(gap => gap.reason === 'parse_error'));
});

test('public source collection is read-only redacted and incomplete under collection truncation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-process-independent-'));
  const files = {
    'a.ts': `import {execFile as launch} from 'node:child_process';\nexport function route(req) { launch('owned-fixed-program', [req.query.argument], {shell:true}); }\n${marker}\n`,
    'z.ts': `export const inert = '${privateValue}';\n`,
  };
  try {
    for (const [path, text] of Object.entries(files)) await writeFile(join(root, path), text);
    for (const options of [{}, { maxFiles: 1 }]) {
      const checks = await runSource({ root, tools: [], analysisProfile: 'extended', ...options });
      const { report, agent } = projections(checks, files);
      if ('maxFiles' in options) { assert.equal(evaluateGate(report, 'none').exitCode, 2); assert.equal(agent.scanGate.exitCode, 2); }
      else assert.equal(evaluateGate(report, 'high').exitCode, 1);
      for (const [path, text] of Object.entries(files)) assert.equal(await readFile(join(root, path), 'utf8'), text, `scanner changed fixture ${path}`);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});
