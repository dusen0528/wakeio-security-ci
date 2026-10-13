import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { createReport, toAgentReport, toMarkdown, toSarif, evaluateGate } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';

// Owned source data only: these strings are parsed, never imported or executed.
const imports = "import unzipper from 'unzipper'; import fs from 'node:fs'; import path from 'node:path';\n";
const secret = 'owned-archive-private-source-f706';
function analyze(body: string, manifest = '{"private":true,"dependencies":{"unzipper":"^0.12.3"}}', directory = '', extra: Record<string, string> = {}) {
  const code = imports + `async function extract(buffer){ const directory=await unzipper.Open.buffer(buffer); for(const entry of directory.files){ ${body} } }\n// ${secret}`;
  return analyzeCode(code, manifest, directory, extra);
}
function analyzeCode(code: string, manifest = '{"private":true,"dependencies":{"unzipper":"^0.12.3"}}', directory = '', extra: Record<string, string> = {}) {
  const files: SourceSnapshot['files'] = [
    { path: directory + 'app.ts', text: code, bytes: Buffer.byteLength(code), sensitive: false, category: 'code' },
    { path: directory + 'package.json', text: manifest, bytes: Buffer.byteLength(manifest), sensitive: false, category: 'dependency' },
    ...Object.entries(extra).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), sensitive: false,
      category: /\.[cm]?[jt]s$/.test(path) ? 'code' as const : 'dependency' as const })),
  ];
  const check = runBuiltinAst({ root: '/owned/archive', files, issues: [], ignoredFiles: 0,
    totalBytes: files.reduce((sum, file) => sum + file.bytes, 0), complete: true });
  return { code, check, findings: check.findings.filter(finding => finding.ruleId === 'ast:archive-path-write') };
}
const guard = "const root=path.resolve('owned/uploads'); const destination=path.resolve(root,entry.path); const relative=path.relative(root,destination); if(relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative)){throw new Error('rejected');} ";

test('archive path scalar passes same-file aliases/helper to the actual writer operand', () => {
  const result = analyze("function rename(value){ return 'owned/'+value; } const filename=entry.path; const alias=filename; fs.createWriteStream(rename(alias));");
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.kind, 'candidate'); assert.equal(finding.confidence, 'low'); assert.equal(finding.severity, 'high');
  assert.equal(finding.staticFlow?.sourceKind, 'archive_entry_path'); assert.equal(finding.staticFlow?.truncated, true);
  assert.equal(finding.staticFlow?.steps[0].role, 'source');
  const start = result.code.indexOf('entry.path'), prefix = result.code.slice(0, start).split('\n');
  assert.deepEqual(finding.staticFlow?.steps[0].location, { path: 'app.ts', line: prefix.length, column: prefix.at(-1)!.length + 1 });
  assert.ok(finding.staticContext?.items.some(item => item.kind === 'declared_package_api'));
  assert.equal(result.check.status, 'partial');
  const report = createReport([result.check], 'source', '2026-10-13T00:00:00.000Z');
  assert.equal(evaluateGate(report, 'none').exitCode, 2);
  for (const output of [JSON.stringify(report), JSON.stringify(toAgentReport(report)), JSON.stringify(toSarif(report)), toMarkdown(report)]) {
    assert.ok(output.includes('archive_entry_path')); assert.equal(output.includes(secret), false);
    assert.equal(output.includes('entry.path'), false); assert.equal(output.includes("'owned/'+value"), false);
  }
});

test('fixed path/content and predicate results never become archive path operands', () => {
  for (const body of ["entry.stream().pipe(fs.createWriteStream('owned/fixed'));", 'fs.createWriteStream(path.isAbsolute(entry.path));', 'fs.createWriteStream(entry);']) {
    const result = analyze(body); assert.equal(result.findings.length, 0, body); assert.equal(result.check.status, 'partial');
  }
});

test('same destination lexical rejection excludes direct call and const writer only', () => {
  for (const write of ['fs.createWriteStream(destination);', 'const writer=fs.createWriteStream(destination); entry.stream().pipe(writer);']) {
    const result = analyze(guard + write);
    assert.equal(result.findings.length, 0, write); assert.ok(Number(result.check.metrics?.archiveLexicalExclusions) > 0);
    assert.equal(result.check.status, 'partial');
  }
  for (const body of [guard + 'await pause(); fs.createWriteStream(destination);',
    guard.replace("relative.startsWith('..'+path.sep)", "relative.includes('..')") + 'fs.createWriteStream(destination);',
    guard + "fs.createWriteStream('owned/'+entry.path);", guard + 'pipeline(entry.stream(),fs.createWriteStream(destination));']) {
    assert.equal(analyze(body).findings.length, 1, body);
  }
});

test('known receiver replacement revokes future path origins, while options remain conditional', () => {
  for (const method of ['fill', "['fill']"]) {
    const receiver = method.startsWith('[') ? `directory.files${method}` : `directory.files.${method}`;
    const result = analyze(`${receiver}({path:'owned-fixed'}); fs.createWriteStream(entry.path);`);
    assert.equal(result.findings.length, 0); assert.equal(result.check.status, 'partial');
  }
  const options = analyze('fs.createWriteStream(entry.path,{fd:7});');
  assert.equal(options.findings.length, 1); assert.ok(Number(options.check.metrics?.archiveUnsupportedUses) > 0);
  assert.equal(options.findings[0].confidence, 'low');
});

test('package self-reference cannot certify external archive API semantics', () => {
  const result = analyze('fs.createWriteStream(entry.path);', '{"name":"unzipper","exports":"./fake.mjs","dependencies":{"unzipper":"^0.12.3"}}');
  assert.equal(result.findings.length, 0); assert.equal(result.check.status, 'partial');
  assert.ok(Number(result.check.metrics?.archiveUnsupportedUses) > 0);
});

test('metadata ancestor budget exhaustion never invents absence of a root resolver', () => {
  const directory = Array.from({ length: 72 }, () => 'owned').join('/') + '/';
  const result = analyze('fs.createWriteStream(entry.path);', '{"dependencies":{"unzipper":"^0.12.3"}}', directory,
    { 'npm-shrinkwrap.json': '{"lockfileVersion":3}' });
  assert.equal(result.findings.length, 0); assert.equal(result.check.status, 'partial');
  assert.ok(Number(result.check.metrics?.archiveUnsupportedUses) > 0);
});

test('literal and computed intrinsic prototype replacement cannot preserve lexical exclusion', () => {
  for (const mutation of ["''.constructor.prototype.startsWith=()=>false;", "''['constructor']['prototype']['startsWith']=()=>false;",
    "const prototype=''.constructor.prototype; prototype.startsWith=()=>false;"]) {
    const result = analyze(mutation + guard + 'fs.createWriteStream(destination);');
    assert.equal(result.findings.length, 1); assert.equal(result.check.status, 'partial');
    assert.equal(result.check.metrics?.archiveLexicalExclusions, 0);
  }
});

test('unrelated shared member mutation downgrades authority but selected API mutation vetoes it', () => {
  const write = 'fs.createWriteStream(entry.path);';
  for (const [method, count] of [['readFileSync', 1], ['createWriteStream', 0]] as const) {
    const result = analyze(write, undefined, '', { 'other.ts': `import otherFs from 'node:fs'; otherFs.${method}=ownedReplacement;` });
    assert.equal(result.findings.length, count); assert.equal(result.check.status, 'partial');
  }
  const guarded = analyze(guard + 'fs.createWriteStream(destination);', undefined, '',
    { 'other.ts': "import otherFs from 'node:fs'; otherFs.readFileSync=ownedReplacement;" });
  assert.equal(guarded.findings.length, 1); assert.equal(guarded.check.metrics?.archiveLexicalExclusions, 0);
});

test('rejected const alias and CJS archive declarations retain incomplete without invented origin', () => {
  const tail = 'async function extract(buffer){const directory=await zip.Open.buffer(buffer);for(const entry of directory.files){fs.createWriteStream(entry.path);}}';
  for (const header of ["import unzipper from 'unzipper';const zip=unzipper;", "const zip=require('unzipper');"]) {
    const result = analyzeCode("import fs from 'node:fs';" + header + 'zip.Open.buffer=ownedReplacement;' + tail);
    assert.equal(result.findings.length, 0); assert.equal(result.check.status, 'partial');
    assert.ok(Number(result.check.metrics?.archiveUnsupportedUses) > 0);
  }
});

test('shared CJS destructured/member loads cannot hide selected API replacement', () => {
  for (const text of ["const {Open}=require('unzipper'); Open.buffer=ownedReplacement;",
    "const Open=require('unzipper').Open; Open.buffer=ownedReplacement;",
    "require('unzipper').Open.buffer=ownedReplacement;",
    "require('node:fs').createWriteStream=ownedReplacement;"]) {
    const result = analyze('fs.createWriteStream(entry.path);', undefined, '', { 'mutation.cjs': text });
    assert.equal(result.findings.length, 0, text); assert.equal(result.check.status, 'partial');
  }
  const pathMutation = analyze(guard + 'fs.createWriteStream(destination);', undefined, '',
    { 'mutation.cjs': "require('node:path').relative=ownedReplacement;" });
  assert.equal(pathMutation.findings.length, 1); assert.equal(pathMutation.check.metrics?.archiveLexicalExclusions, 0);
});
