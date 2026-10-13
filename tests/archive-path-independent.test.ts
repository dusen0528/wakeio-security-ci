import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { main } from '../src/cli.js';
import { runSource } from '../src/source.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { compareReports, parseScanReport } from '../src/compare.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';

// Independent owned source, DATA ONLY. Existing public imports load on baseline.
// Rule/enum names are the public interface; no prospective role helper import.
const RULE = 'ast:archive-path-write', KIND = 'archive_entry_path';
const CANARY = 'owned-archive-private-marker-40dc', PROJECT = 'owned/archive-independent';
const IMPORTS = "import unzipper from 'unzipper';\nimport fs from 'node:fs';\nimport path from 'node:path';\n";
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const body = (statements: string) => IMPORTS + 'export async function extract(buffer) {\n' +
  'const directory = await unzipper.Open.buffer(buffer);\nfor (const entry of directory.files) {\n' + statements + '\n}\n}\n';
const RISK = body("const filename = entry.path;\nfs.createWriteStream('owned/out/' + filename);");
const ROOT_DEST = "const root = path.resolve('owned/out');\nconst dest = path.resolve(root, entry.path);\nconst rel = path.relative(root, dest);\n";
const REJECT = "rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)";
const guarded = (terminal = "throw new Error('outside');") => body(ROOT_DEST + 'if (' + REJECT + ') { ' + terminal + ' }\nfs.createWriteStream(dest);');
type Files = Record<string, string>;
const pkg = (version = '^0.12.3') => JSON.stringify({ name: 'owned-archive-data', private: true, type: 'module', dependencies: { unzipper: version } });
const lock = (version: string, declared = version) => JSON.stringify({ name: 'owned-archive-data', lockfileVersion: 3, packages: {
  '': { name: 'owned-archive-data', dependencies: { unzipper: declared } },
  'node_modules/unzipper': { version, resolved: `https://registry.npmjs.org/unzipper/-/unzipper-${version}.tgz` },
} });
async function captured(args: string[]) {
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try { return await main(args); } finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
async function workspace(t: TestContext, text: string, extra: Files = {}) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-archive-independent-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const root = join(top, 'source'); await mkdir(root);
  const files: Files = { 'app.mts': text + '\n// ' + CANARY + '\n', 'package.json': pkg(), ...extra };
  for (const [name, data] of Object.entries(files)) {
    await mkdir(dirname(join(root, name)), { recursive: true }); await writeFile(join(root, name), data);
  }
  return { top, root, files };
}
async function scan(t: TestContext, text: string, extra: Files = {}) {
  const w = await workspace(t, text, extra), out = join(w.top, 'reports');
  const code = await captured(['scan', '--source', w.root, '--tools', 'none', '--require-code-analysis',
    '--project-id', PROJECT, '--fail-on', 'high', '--out', out]);
  const formats: Record<string, string> = {};
  for (const name of ['report.json', 'agent-report.json', 'report.md', 'report.sarif']) {
    formats[name] = await readFile(join(out, name), 'utf8');
    assert.equal(formats[name].includes(CANARY), false, name + ': source marker leaked');
    for (const line of text.split('\n').filter(line => /entry\.path|createWriteStream\(/.test(line) && line.trim().length > 24)) {
      assert.equal(formats[name].includes(line.trim()), false, name + ': raw source leaked');
      assert.equal(formats[name].includes(JSON.stringify(line.trim()).slice(1, -1)), false, name + ': escaped source leaked');
    }
  }
  const report = JSON.parse(formats['report.json']), agent = JSON.parse(formats['agent-report.json']), sarif = JSON.parse(formats['report.sarif']);
  const ast = report.checks.find((c: any) => c.id === 'source.builtin-ast'); assert.ok(ast);
  assert.equal(agent.scanGate.exitCode, code); assert.equal(agent.reportArtifact.digest, sha(formats['report.json']));
  for (const [name, data] of Object.entries(w.files)) assert.equal(await readFile(join(w.root, name), 'utf8'), data, 'source changed');
  assert.equal((await readdir(w.root)).includes('node_modules'), false, 'target dependencies installed');
  return { ...w, text, code, formats, report, agent, sarif, ast, findings: ast.findings.filter((f: any) => f.ruleId === RULE) };
}
type Result = Awaited<ReturnType<typeof scan>>;
function at(text: string, needle: string, file = 'app.mts') {
  const offset = text.indexOf(needle); assert.ok(offset >= 0, needle);
  const preceding = text.slice(0, offset).split('\n'); return { path: file, line: preceding.length, column: preceding.at(-1)!.length + 1 };
}
function partial(r: Result) {
  assert.equal(r.ast.status, 'partial', 'unresolved archive role became completed clean');
  assert.equal(r.code, 2); assert.equal(evaluateGate(r.report, 'none').exitCode, 2);
}
function noOrigin(r: Result) {
  assert.equal(r.findings.length, 0, 'unrelated/unqualified role minted archive write finding');
  assert.equal(r.report.checks.flatMap((c: any) => c.findings).some((f: any) => f.staticFlow?.sourceKind === KIND), false);
}
function witness(r: Result, source = 'entry.path', sink = 'fs.createWriteStream(') {
  const finding = r.findings.find((f: any) => JSON.stringify(f.location) === JSON.stringify(at(r.text, sink)));
  assert.ok(finding, 'missing exact archive-path destination candidate');
  assert.equal(finding.kind, 'candidate'); assert.equal(finding.severity, 'high'); assert.equal(finding.confidence, 'low');
  assert.equal(finding.staticFlow?.sourceKind, KIND); assert.equal(finding.staticFlow?.truncated, true);
  assert.ok(finding.staticFlow.steps.some((s: any) => s.role === 'source' && JSON.stringify(s.location) === JSON.stringify(at(r.text, source))),
    'archive origin borrowed buffer/content/other entry provenance');
  assert.deepEqual(finding.staticFlow.steps.at(-1), { role: 'sink', location: at(r.text, sink) });
  assert.equal(finding.staticContext?.authority, 'conditional');
  assert.ok(finding.staticContext.items.some((item: any) => item.kind === 'declared_package_api'));
  assert.equal(/HTTP|request input/i.test(finding.title), false);
  partial(r); return finding;
}

test('archive independent: exact directory files entry path reaches native destination without HTTP origin', async t => {
  const r = await scan(t, RISK); witness(r);
  assert.equal(r.findings.length, 1);
  assert.ok(r.ast.metrics.archiveDirectoriesRecognized >= 1); assert.ok(r.ast.metrics.archiveEntryPaths >= 1);
  assert.ok(r.ast.metrics.archiveWriteCandidates >= 1);
});

test('archive independent: scalar aliases, template, resolve reuse and local helper preserve selected filename provenance', async t => {
  for (const statements of [
    "const filename = entry.path; const alias = filename;\nfs.createWriteStream('owned/out/' + alias);",
    'const filename = entry.path;\nfs.createWriteStream(`owned/out/${filename}`);',
    "const filename = entry.path; const dest = path.resolve('owned/out', filename);\nfs.createWriteStream(dest);",
  ]) witness(await scan(t, body(statements)));
  const text = IMPORTS + "function forward(value) { const alias = value; return alias; }\n" +
    body("const filename = entry.path;\nfs.createWriteStream('owned/out/' + forward(filename));").slice(IMPORTS.length);
  witness(await scan(t, text));
});

test('archive independent: content into a fixed path and unrelated path objects never borrow archive filename origin', async t => {
  for (const text of [
    body("const filename = entry.path; console.log(filename);\nentry.stream().pipe(fs.createWriteStream('owned/fixed.bin'));"),
    body("const content = await entry.buffer();\nfs.createWriteStream('owned/fixed.bin'); consume(content);"),
    IMPORTS + "const directory = { files: [{path:'owned-fixed'}] };\nfor(const entry of directory.files) fs.createWriteStream(entry.path);",
    body("const {path: filename} = {path:'owned-fixed'};\nfs.createWriteStream(filename);"),
  ]) noOrigin(await scan(t, text));
});

test('archive independent: same immutable resolved candidate after terminating boundary guard excludes lexical escape only', async t => {
  for (const terminal of ["throw new Error('outside');", 'return;']) {
    const r = await scan(t, guarded(terminal)); assert.equal(r.findings.length, 0);
    assert.ok(r.ast.metrics.archiveLexicalExclusions >= 1, 'guard was ignored rather than modeled');
    partial(r);
  }
});

test('archive independent: weak, wrong-object, late and non-dominating guards cannot suppress the actual destination', async t => {
  const variants = [
    ROOT_DEST + "if (dest.startsWith(root)) fs.createWriteStream(dest);",
    ROOT_DEST + "if (dest.includes(path.resolve('.'))) fs.createWriteStream(dest);",
    ROOT_DEST.replace('path.relative(root, dest)', "path.relative(root, path.resolve(root, 'fixed'))") + 'if (' + REJECT + ") throw new Error('outside');\nfs.createWriteStream(dest);",
    ROOT_DEST + 'fs.createWriteStream(dest);\nif (' + REJECT + ") throw new Error('outside');",
    ROOT_DEST + 'if (opaqueBranch) { if (' + REJECT + ") throw new Error('outside'); }\nfs.createWriteStream(dest);",
    ROOT_DEST.replace('const dest', 'let dest') + 'if (' + REJECT + ") throw new Error('outside');\ndest = path.resolve(root, entry.path);\nfs.createWriteStream(dest);",
  ];
  for (const [index, statements] of variants.entries()) witness(await scan(t, body(statements)),
    index === variants.length - 1 ? 'entry.path);\nfs.createWriteStream(dest)' : 'entry.path');
});

test('archive independent: local/shadowed/mutated source and sink identities cannot mint a native archive certificate', async t => {
  const fake = "const unzipper = {Open:{buffer:async()=>({files:[{path:'fixed'}]})}};\n" + RISK.replace("import unzipper from 'unzipper';\n", '');
  noOrigin(await scan(t, fake));
  for (const text of [
    RISK.replace('export async function extract(buffer)', 'export async function extract(buffer, unzipper)'),
    RISK.replace('export async function extract(buffer)', "unzipper.Open.buffer = ownedReplacement;\nexport async function extract(buffer)"),
    RISK.replace('export async function extract(buffer)', "fs.createWriteStream = ownedReplacement;\nexport async function extract(buffer)"),
    RISK.replace('export async function extract(buffer)', 'export async function extract(buffer, fs)'),
  ]) {
    const r = await scan(t, text); noOrigin(r); partial(r);
  }
});

test('archive independent: reviewed coherent package declarations remain conditional while contradictory identity stays unsupported', async t => {
  for (const [declared, resolved] of [['0.12.3', undefined], ['^0.12.3', undefined], ['0.12.3', '0.12.3'], ['^0.12.3', '0.12.5']] as const) {
    const r = await scan(t, RISK, { 'package.json': pkg(declared), ...(resolved ? { 'package-lock.json': lock(resolved, declared) } : {}) });
    witness(r);
  }
  for (const extra of [
    { 'package.json': pkg('0.12.3'), 'package-lock.json': lock('0.12.5', '0.12.3') },
    { 'package.json': pkg('0.12.3'), 'package-lock.json': lock('0.12.3', '0.12.5') },
    { 'package.json': pkg('0.12.5'), 'package-lock.json': lock('0.12.5', '0.12.5') },
    { 'package.json': pkg('99.0.0') },
  ] as Files[]) { const r = await scan(t, RISK, extra); noOrigin(r); partial(r); }
});

test('archive independent: descriptor/custom-fs/dynamic options cannot establish ordinary pathname-write safety', async t => {
  for (const options of ['{fd:42}', '{fs:ownedCustomFs}', 'ownedOptions']) {
    const r = await scan(t, RISK.replace("'owned/out/' + filename)", "'owned/out/' + filename, " + options + ')'));
    partial(r);
    assert.ok(r.findings.every((f: any) => f.confidence === 'low' && f.staticContext?.authority === 'conditional'),
      'opaque destination mechanism upgraded to native certainty');
  }
});

test('archive independent: explicit path flavors and separator mismatch do not become generic filesystem safety exclusions', async t => {
  for (const statements of [
    ROOT_DEST.replaceAll('path.', 'path.posix.') + 'if (' + REJECT.replaceAll('path.', 'path.posix.') + ") throw new Error('outside');\nfs.createWriteStream(dest);",
    ROOT_DEST.replaceAll('path.', 'path.win32.') + 'if (' + REJECT.replaceAll('path.', 'path.win32.') + ") throw new Error('outside');\nfs.createWriteStream(dest);",
    ROOT_DEST + 'if (' + REJECT.replace("'..' + path.sep", "'../'") + ") throw new Error('outside');\nfs.createWriteStream(dest);",
    ROOT_DEST + 'if (' + REJECT + ') continue;\nfs.createWriteStream(dest);',
  ]) {
    const r = await scan(t, body(statements));
    // Declared archive API authority remains partial, even for a supported continue.
    partial(r);
  }
});

test('archive independent: bounded dispatch and incomplete collection retain gate two regardless of fail-on', async t => {
  const r = await scan(t, RISK, { 'noise.ts': Array.from({length:2001}, (_, i) => `function helper${i}(v){return v;}`).join('\n') });
  partial(r);
  const w = await workspace(t, RISK), checks = await runSource({root:w.root, tools:[], requireCodeAnalysis:true, maxFiles:1});
  const report = createReport(checks, 'source', '2026-10-13T00:00:00Z');
  assert.equal(evaluateGate(report, 'high').exitCode, 2); assert.equal(evaluateGate(report, 'none').exitCode, 2);
  assert.equal(toAgentReport(report, 'none').scanGate.exitCode, 2);
});

test('archive independent: four report formats and advisory projection preserve conditional origin without execution instructions', async t => {
  const r = await scan(t, RISK), f = witness(r);
  const af = r.agent.findings.find((x: any) => x.findingId === f.id); assert.ok(af);
  assert.deepEqual(af.evidence.staticFlow, f.staticFlow); assert.deepEqual(af.evidence.staticContext, f.staticContext);
  assert.equal(af.verification.vulnerabilityConfirmed, false); assert.equal(af.verification.remediationVerified, false);
  const sf = r.sarif.runs[0].results.find((x: any) => x.fingerprints?.['wakeio-security-ci/v2'] === f.id); assert.ok(sf);
  assert.deepEqual(sf.properties.staticFlow, f.staticFlow);
  for (const [name, text] of Object.entries(r.formats)) {
    const visible = name === 'report.md' ? text.replace(/\\([\\`*_{}\[\]()#+\-.!<>])/g, '$1') : text;
    assert.ok(visible.includes(KIND), name + ': missing archive origin');
  }
  const projected: any = projectAdviceContext(r.agent, false), card = projected.input.findings.find((x: any) => x.findingId === f.id);
  assert.ok(card); assert.equal(card.staticFlow.sourceKind, KIND); assert.equal(card.staticContext.authority, 'conditional');
  assert.equal(card.verification, 'not_run'); assert.equal(card.recheckRoute, 'review_static_flow_or_budget');
  assert.equal(card.replayAvailable, false); assert.equal(projected.clean, false);
  assert.equal(JSON.stringify(projected.input).includes(CANARY), false);
});

test('archive independent: malformed/disappearing source origin cannot be laundered into passing comparable evidence', async t => {
  const r = await scan(t, RISK), f = witness(r);
  parseScanReport(copy(r.report));
  assert.equal(compareReports(r.report, copy(r.report)).comparable, false,
    'a repeated conditional partial scan cannot establish verified comparison');
  for (const change of ['remove', 'wrong', 'malformed-flow']) {
    const altered: any = copy(r.report), selected = altered.checks.find((c: any) => c.id === r.ast.id).findings.find((x: any) => x.id === f.id);
    if (change === 'remove') delete selected.staticFlow.sourceKind;
    if (change === 'wrong') selected.staticFlow.sourceKind = 'invented_archive_origin';
    if (change === 'malformed-flow') selected.staticFlow.steps = [];
    const agent = toAgentReport(altered); assert.equal(agent.scanGate.exitCode, 2);
    assert.equal(JSON.stringify(agent).includes('invented_archive_origin'), false);
    toMarkdown(altered); toSarif(altered);
    try { assert.equal(compareReports(r.report, altered).comparable, false); }
    catch (error) { assert.ok(error instanceof Error && error.message === 'Invalid scan report', 'unrelated comparison exception'); }
    if (change === 'wrong') assert.throws(() => parseScanReport(altered));
  }
});
