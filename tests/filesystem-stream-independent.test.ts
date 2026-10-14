import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { main } from '../src/cli.js';
import { createReport, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { compareReports, parseScanReport } from '../src/compare.js';

// Own synthetic source only. No prospective producer helper import or target execution.
const FS_RULE = 'ast:filesystem-shell-input', PRIVATE = 'owned-fs-private-marker-f792';
const IMPORTS = "import { globStream } from 'glob';\nimport { foregroundChild } from 'foreground-child';\n";
const deps = { glob: '10.4.5', 'foreground-child': '3.2.1' };
const lock = () => ({ name: 'owned-data-only', version: '1.0.0', lockfileVersion: 3, packages: {
  '': { name: 'owned-data-only', version: '1.0.0', dependencies: deps },
  'node_modules/glob': { version: '10.4.5', resolved: 'https://registry.npmjs.org/glob/-/glob-10.4.5.tgz' },
  'node_modules/foreground-child': { version: '3.2.1', resolved: 'https://registry.npmjs.org/foreground-child/-/foreground-child-3.2.1.tgz',
    integrity: 'sha512-PXUUyLqrR2XCWICfv6ukppP96sdFwWbNEnfEMt7jNsISjMsvaLNinAHNDYyvkyU+SZG2BTSbT5NjG+vZslfGTA==' },
} });
type Files = Record<string, string>;
async function cli(args: string[]) {
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write; process.stderr.write = (() => true) as typeof process.stderr.write;
  try { return await main(args); } finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
async function scan(t: TestContext, text: string, extra: Files = {}, flags: string[] = []) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-independent-fs-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'), out = join(top, 'reports'); await mkdir(source);
  const files: Files = { 'app.mts': text + '\n// ' + PRIVATE + '\n',
    'package.json': JSON.stringify({ name: 'owned-data-only', private: true, dependencies: deps }),
    'package-lock.json': JSON.stringify(lock()), ...extra };
  for (const [name, data] of Object.entries(files)) {
    await mkdir(dirname(join(source, name)), { recursive: true }); await writeFile(join(source, name), data);
  }
  const code = await cli(['scan', '--source', source, '--tools', 'none', '--project-id', 'owned/filesystem-independent',
    '--analysis-profile', 'default', '--fail-on', 'high', '--out', out, ...flags]);
  const outputs: Record<string, string> = {};
  for (const name of ['report.json', 'agent-report.json', 'report.sarif', 'report.md']) {
    outputs[name] = await readFile(join(out, name), 'utf8');
    assert.equal(outputs[name].includes(PRIVATE), false, name + ': raw source marker leaked');
    for (const line of text.split('\n').filter(line => /(?:\.push\(|foregroundChild\(|req\.query)/.test(line) && line.trim().length > 20)) {
      assert.equal(outputs[name].includes(line.trim()), false, name + ': raw source line leaked');
      assert.equal(outputs[name].includes(JSON.stringify(line.trim()).slice(1, -1)), false, name + ': escaped source line leaked');
    }
  }
  const report = JSON.parse(outputs['report.json']), agent = JSON.parse(outputs['agent-report.json']);
  const sarif = JSON.parse(outputs['report.sarif']), ast = report.checks.find((c: any) => c.id === 'source.builtin-ast');
  assert.ok(ast); assert.equal(agent.scanGate.exitCode, code);
  assert.equal(agent.reportArtifact.digest, createHash('sha256').update(outputs['report.json']).digest('hex'));
  for (const [name, data] of Object.entries(files)) assert.equal(await readFile(join(source, name), 'utf8'), data, 'source changed: ' + name);
  assert.equal((await readdir(source)).includes('node_modules'), false, 'target dependencies installed');
  return { code, report, agent, sarif, ast, outputs, text, findings: ast.findings.filter((f: any) => f.ruleId === FS_RULE) };
}
type Result = Awaited<ReturnType<typeof scan>>;
function at(text: string, needle: string, path = 'app.mts') {
  const offset = text.indexOf(needle); assert.ok(offset >= 0, needle);
  const prior = text.slice(0, offset).split('\n');
  return { path, line: prior.length, column: prior.at(-1)!.length + 1 };
}
function filenameWitness(r: Result, sourceNeedle: string, sinkNeedle = 'foregroundChild(', accumulatorNeedle?: string) {
  const f = r.findings.find((f: any) => JSON.stringify(f.location) === JSON.stringify(at(r.text, sinkNeedle)));
  assert.ok(f, 'missing exact filename-argv finding at actual sink');
  assert.equal(f.kind, 'candidate'); assert.equal(f.severity, 'high'); assert.equal(f.confidence, 'low');
  assert.equal(f.staticFlow?.sourceKind, 'filesystem_filename'); assert.equal(f.staticFlow?.truncated, true);
  assert.ok(f.staticFlow.steps.some((s: any) => s.role === 'source' && JSON.stringify(s.location) === JSON.stringify(at(r.text, sourceNeedle))),
    'filename tag borrowed a command/HTTP/unrelated source trace');
  assert.deepEqual(f.staticFlow.steps.at(-1), { role: 'sink', location: at(r.text, sinkNeedle) });
  if (accumulatorNeedle) assert.ok(f.staticFlow.steps.some((s: any) => JSON.stringify(s.location) === JSON.stringify(at(r.text, accumulatorNeedle))),
    'missing actual shared-accumulator step');
  assert.equal(f.staticContext?.authority, 'conditional');
  assert.ok(f.staticContext.items.some((x: any) => x.kind === 'declared_filesystem_stream_origin'));
  assert.ok(f.staticContext.items.some((x: any) => x.kind === 'declared_stream_callback_schedule'));
  assert.ok(f.staticContext.items.some((x: any) => x.kind === 'declared_process_wrapper'));
  assert.equal(r.ast.status, 'partial'); assert.equal(r.code, 2);
  assert.equal(r.ast.metrics.filesystemStreamModel, 'glob-stream-filename-v1');
  const af = r.agent.findings.find((a: any) => a.findingId === f.id); assert.ok(af);
  assert.deepEqual(af.evidence.staticFlow, f.staticFlow); assert.deepEqual(af.evidence.staticContext, f.staticContext);
  assert.equal(af.verification.vulnerabilityConfirmed, false); assert.equal(af.verification.remediationVerified, false);
  const sf = r.sarif.runs[0].results.find((s: any) => s.fingerprints?.['wakeio-security-ci/v2'] === f.id); assert.ok(sf);
  assert.deepEqual(sf.properties.staticFlow, f.staticFlow);
  assert.equal(/request|HTTP/i.test(f.title), false, 'filesystem origin must not be titled as HTTP input');
  return f;
}
function unsupported(r: Result) {
  assert.ok(r.ast.status === 'partial' || r.findings.some((f: any) => f.confidence === 'low'),
    'known filename-shaped unsupported flow silently became completed clean');
  if (r.ast.status === 'partial') assert.equal(r.code, 2);
}
const basic = (options = '{shell:true}', initial = '[]') => IMPORTS +
  "const stream = globStream('*.owned', {withFileTypes:false});\n" +
  'const matches = ' + initial + ';\n' +
  "stream.on('data', filename => matches.push(filename));\n" +
  "stream.on('end', () => foregroundChild('owned-tool', matches, " + options + '));\n';

test('filesystem independent: exact ESM package stream filename crosses data/shared-cell/end into operand one', async t => {
  const r = await scan(t, basic());
  filenameWitness(r, 'filename =>', 'foregroundChild(', 'matches.push(');
  assert.ok(r.ast.metrics.filesystemFilenameCallbacks >= 1); assert.ok(r.ast.metrics.filesystemAccumulatorWrites >= 1);
  assert.ok(r.ast.metrics.filesystemWrapperArgvUses >= 1); assert.ok(r.ast.metrics.filesystemShellEnabledUses >= 1);
});

test('filesystem independent: HTTP and benign pushes, branches and alias cannot overwrite the chosen filename witness', async t => {
  const text = IMPORTS + "export function route(req) {\nconst stream = globStream('*.owned');\nconst matches = [];\n" +
    "stream.on('data', filename => { matches.push(req.query.unrelated); matches.push(filename); matches.push('benign'); });\n" +
    "const alias = matches;\nif (opaqueCondition) alias.push('later-benign');\n" +
    "stream.on('end', () => foregroundChild('owned-tool', alias, {shell:true}));\n}\n";
  const r = await scan(t, text), f = filenameWitness(r, 'filename =>', 'foregroundChild(', 'matches.push(filename)');
  assert.equal(f.staticFlow.steps.some((s: any) => s.role === 'source' && JSON.stringify(s.location) === JSON.stringify(at(text, 'req.query.unrelated'))), false);
});

test('filesystem independent: opaque parser accumulator and dynamic shell remain positive unknown, not actual Array proof', async t => {
  const text = IMPORTS + "const { cmdArg, shell } = parseOpaqueFlags();\nconst stream = globStream('*.owned');\n" +
    "stream.on('data', filename => cmdArg.push(filename));\nstream.on('end', () => foregroundChild('owned-tool', cmdArg, {shell}));\n";
  const r = await scan(t, text), f = filenameWitness(r, 'filename =>', 'foregroundChild(', 'cmdArg.push(');
  assert.ok(f.staticContext.items.some((x: any) => x.kind === 'conditional_array_accumulator'));
  assert.ok(r.ast.metrics.filesystemShellUnknownUses >= 1);
  assert.equal(/(?:proven|verified) (?:Array|intrinsic|runtime)/i.test(f.description), false);
});

test('filesystem independent: explicit disabled-shell primitive argv and fixed benign items exclude only filename shell reinterpretation', async t => {
  for (const options of ['{shell:false}', '{}']) {
    const r = await scan(t, basic(options));
    assert.equal(r.findings.length, 0); assert.ok(r.ast.metrics.filesystemShellDisabledExclusions >= 1);
  }
  const r = await scan(t, IMPORTS + "foregroundChild('owned-tool', ['fixed-one', 'fixed-two'], {shell:true});\n");
  assert.equal(r.findings.length, 0, 'benign array item is not a filesystem source');
});

test('filesystem independent: configured foreground-child identity vetoes the same shell-disabled argv exclusion', async t => {
  const normal = await scan(t, basic('{shell:false}'));
  assert.equal(normal.findings.length, 0);
  assert.ok(normal.ast.metrics.filesystemShellDisabledExclusions >= 1);
  const mapped = await scan(t, basic('{shell:false}'), {
    'tsconfig.json': '{"compilerOptions":{"paths":{"foreground-child":["./shim.ts"]}}}',
    'shim.ts': 'export function foregroundChild(command, values, options) { return unknown(values); }',
  });
  filenameWitness(mapped, 'filename =>', 'foregroundChild(', 'matches.push(');
  assert.equal(mapped.ast.metrics.filesystemShellDisabledExclusions, 0);
  assert.equal(mapped.ast.metrics.configuredNativeIdentityComplete, false);
  assert.ok(mapped.findings[0].staticContext.items.some((item: any) => item.kind === 'configured_module_resolution'));
  assert.equal(mapped.code, 2);
});

test('filesystem independent: explicit interpreter argv remains reviewable even with Node shell disabled', async t => {
  const text = IMPORTS + "const stream = globStream('*.owned');\nconst matches = [];\n" +
    "stream.on('data', filename => matches.push(filename));\n" +
    "stream.on('end', () => foregroundChild('sh', ['-c', 'printf \"%s\" \"$@\"', 'owned', ...matches], {shell:false}));\n";
  const r = await scan(t, text); filenameWitness(r, 'filename =>');
  assert.ok(r.ast.metrics.filesystemInterpreterUnknownUses >= 1);
});

test('filesystem independent: arbitrary emitters and shadowed/local glob names never mint filename source identity', async t => {
  for (const text of [
    "import {foregroundChild} from 'foreground-child';\nconst stream = arbitraryEmitter();\nconst matches=[];\nstream.on('data', filename=>matches.push(filename));\nstream.on('end',()=>foregroundChild('owned-tool', matches,{shell:true}));",
    "import {foregroundChild} from 'foreground-child';\nfunction globStream(){return arbitraryEmitter()}\nconst stream=globStream(); const matches=[];\nstream.on('data', filename=>matches.push(filename));\nstream.on('end',()=>foregroundChild('owned-tool',matches,{shell:true}));",
  ]) {
    const r = await scan(t, text); assert.equal(r.findings.length, 0);
    assert.equal(r.report.checks.flatMap((c: any) => c.findings).some((f: any) => f.staticFlow?.sourceKind === 'filesystem_filename'), false);
  }
  const fakeText = "import {globStream} from './index.js';\nimport {foregroundChild} from 'foreground-child';\n" +
    "const stream=globStream('*.owned'); const matches=[];\nstream.on('data', filename=>matches.push(filename));\n" +
    "stream.on('end',()=>foregroundChild('owned-tool',matches,{shell:true}));\n";
  const fakeLock: any = lock(); fakeLock.name = 'glob'; fakeLock.version = '10.4.5';
  fakeLock.packages[''] = { name: 'glob', version: '10.4.5', dependencies: { 'foreground-child': '3.2.1' } };
  const fake = await scan(t, fakeText, {
    'package.json': JSON.stringify({ name: 'glob', version: '10.4.5', private: true, dependencies: { 'foreground-child': '3.2.1' } }),
    'package-lock.json': JSON.stringify(fakeLock),
    'index.ts': "import {Glob} from './glob.js';\nexport function globStream(pattern:string):unknown;\nexport function globStream(pattern:any){return new Glob(pattern).stream();}\n",
    'glob.ts': "import {FixedEmitter} from './fixed.js';\nexport class Glob { constructor(pattern:any){} stream(){return new FixedEmitter().stream();} }\n",
    'fixed.ts': "export class FixedEmitter { stream(){return this;} on(event:any, callback:any){if(event==='data')callback('constant-safe-name');return this;} }\n",
  });
  assert.equal(fake.findings.length, 0, 'local constructor/method spelling plus spoofed root metadata is not filesystem semantics');
  assert.equal(fake.report.checks.flatMap((c: any) => c.findings).some((f: any) => f.staticFlow?.sourceKind === 'filesystem_filename'), false);
});

test('filesystem independent: missing/version-mismatched imports and mutated package/member identity do not grant native safety', async t => {
  const wrongLock = lock(); wrongLock.packages['node_modules/foreground-child'].version = '99.0.0';
  for (const [text, extra] of [
    [basic(), { 'package-lock.json': JSON.stringify(wrongLock) }],
    [basic(), { 'package.json': '{"name":"owned-data-only","private":true}', 'package-lock.json': '{"lockfileVersion":3,"packages":{}}' }],
    [basic().replace('const matches = [];', 'const matches = [];\nglobStream = opaqueReplacement;'), {}],
    [basic().replace("import { foregroundChild } from 'foreground-child';", "import * as fg from 'foreground-child';").replace("const matches = [];", 'const matches = [];\nfg.foregroundChild = opaqueReplacement;').replace('foregroundChild(', 'fg.foregroundChild('), {}],
  ] as Array<[string, Files]>) {
    const r = await scan(t, text, extra); unsupported(r);
    assert.equal(r.findings.some((f: any) => f.confidence !== 'low'), false);
  }
  const declaredMismatch = JSON.stringify({ name: 'owned-data-only', private: true,
    dependencies: { glob: '10.4.5', 'foreground-child': '^2.0.0' } });
  const conflictingShrinkwrap: any = lock(); conflictingShrinkwrap.packages['node_modules/foreground-child'].version = '2.0.0';
  for (const extra of [
    { 'package.json': declaredMismatch },
    { 'npm-shrinkwrap.json': JSON.stringify(conflictingShrinkwrap) },
  ] as Files[]) {
    const r = await scan(t, basic('{shell:false}'), extra);
    unsupported(r); assert.equal(Number(r.ast.metrics.filesystemShellDisabledExclusions ?? 0), 0, 'conflicting install metadata cannot certify safe wrapper semantics');
  }
  const nested = await scan(t, 'export const rootOnly=true;', {
    'workspace/app.mts': basic('{shell:false}'),
    'workspace/package.json': declaredMismatch,
  });
  unsupported(nested); assert.equal(Number(nested.ast.metrics.filesystemShellDisabledExclusions ?? 0), 0,
    'nested dependency ambiguity cannot borrow the root lock safe qualification');
  const noArgs = await scan(t, IMPORTS + 'foregroundChild();\n');
  assert.ok(noArgs.ast, 'misused wrapper must not crash the scanner');
  assert.equal(noArgs.report.checks.some((c: any) => c.id === 'source.runtime'), false);
  assert.equal(noArgs.findings.length, 0, 'no arguments alone do not require a security finding');
});

test('filesystem independent: unrelated array or stream/event does not borrow a complete accumulator/scheduling proof', async t => {
  const separateArray = basic().replace("stream.on('end',", "const unrelated = ['benign'];\nstream.on('end',").replace("'owned-tool', matches", "'owned-tool', unrelated");
  assert.equal((await scan(t, separateArray)).findings.length, 0, 'filename contribution to one array cannot taint an unrelated array');
  for (const text of [
    basic().replace("stream.on('end',", "const other = globStream('*.other');\nother.on('end',"),
    basic().replace("stream.on('data',", "const eventName = opaqueEvent;\nstream.on(eventName,"),
  ]) unsupported(await scan(t, text));
});

test('filesystem independent: push numeric return is not a filename value; filename survives known escape and push replacement as unknown', async t => {
  const text = IMPORTS + "const stream = globStream('*.owned');\nconst matches=[]; const lengths=[];\n" +
    "stream.on('data', filename=>{ const length=matches.push(filename); lengths.push(length); });\n" +
    "stream.on('end',()=>foregroundChild('owned-tool',lengths,{shell:true}));\n";
  assert.equal((await scan(t, text)).findings.length, 0, 'push length is not a filename argv contributor');
  for (const injected of ['opaqueMutator(matches);', 'matches.push = opaqueReplacement;']) {
    const r = await scan(t, basic().replace("stream.on('end',", injected + "\nstream.on('end',"));
    unsupported(r); assert.equal(r.findings.some((f: any) => f.confidence !== 'low'), false);
  }
});

test('filesystem independent: withFileTypes true/dynamic and incomplete collection keep unsupported filename qualification visible', async t => {
  for (const value of ['true', 'opaqueMode']) {
    const r = await scan(t, basic().replace('withFileTypes:false', 'withFileTypes:' + value)); unsupported(r);
    assert.ok(r.ast.metrics.filesystemUnsupportedUses >= 1 || r.ast.analysisGaps);
  }
  const r = await scan(t, basic(), { 'zzz.mts': 'export const untouched=true;' }, ['--source-max-files', '1']);
  assert.equal(r.code, 2); assert.equal(r.report.checks.find((c: any) => c.id === 'source.inventory').status, 'partial');
});

test('filesystem independent: ordinary ESM overload signatures plus one same-symbol body dispatch actual HTTP input independently of glob', async t => {
  for (const alias of [false, true]) {
    const provider = (alias ? '' : 'export ') + 'function relay(value:string):string;\n' +
      (alias ? '' : 'export ') + 'function relay(value:number):number;\n' +
      (alias ? '' : 'export ') + 'function relay(value:any){return value;}\n' + (alias ? 'export {relay as forward};\n' : '');
    const text = "import { " + (alias ? 'forward as relay' : 'relay') + " } from './relay.js';\nimport {spawn} from 'node:child_process';\n" +
      "export function route(req){spawn('owned-tool',[relay(req.query.actual)],{shell:true});}\n";
    const r = await scan(t, text, { 'relay.ts': provider });
    const f = r.ast.findings.find((f: any) => f.ruleId === 'ast:shell-input-sink'); assert.ok(f);
    assert.equal(f.confidence, 'medium'); assert.equal(f.kind, 'candidate'); assert.equal(f.severity, 'critical');
    assert.equal(r.ast.status, 'completed'); assert.equal(r.code, 1);
    assert.ok(f.staticFlow.steps.some((s: any) => s.role === 'source' && JSON.stringify(s.location) === JSON.stringify(at(text, 'req.query.actual'))));
    assert.ok(f.staticFlow.steps.some((s: any) => s.role === 'parameter' && s.location.path === 'relay.ts'));
    assert.equal(f.staticFlow.sourceKind, undefined, 'HTTP trace cannot inherit a filename tag');
  }
});

test('filesystem independent: ambiguous/type-only/mutated/opaque/budgeted ESM dispatch and public origin metadata fail closed', async t => {
  const body = 'export function relay(value:string):string;\nexport function relay(value:any){return value;}\n';
  const app = "import {relay} from './relay.js';\nimport {spawn} from 'node:child_process';\nexport function route(req){spawn('owned-tool',[relay(req.query.actual)],{shell:true});}\n";
  for (const [text, provider] of [
    [app, 'export function relay(v:any){return v;}\nexport function relay(v:any){return \"fixed\";}\n'],
    [app.replace('import {relay}', 'import type {relay}'), body],
    [app.replace('export function route', 'relay = opaqueReplacement;\nexport function route'), body],
    [app, "export {relay} from './not-collected.js';\n"],
    [app, body + Array.from({ length: 2001 }, (_, i) => 'function helper' + i + '(v:any){return v;}').join('\n')],
  ]) {
    const r = await scan(t, text, { 'relay.ts': provider });
    const native = r.ast.findings.filter((f: any) => f.ruleId === 'ast:shell-input-sink');
    assert.equal(native.some((f: any) => f.confidence === 'medium' && !f.staticFlow?.truncated), false, 'unsupported export became complete dispatch proof');
    assert.ok(r.ast.status === 'partial' || native.some((f: any) => f.confidence === 'low'), 'unsupported dispatch silently became clean');
  }
  const finding: any = { ruleId: 'fixture:origin', title: 'Synthetic origin contract', description: 'Fixture metadata only.', remediation: 'Review.',
    kind: 'candidate', severity: 'high', confidence: 'medium', location: { path: 'app.mts', line: 2, column: 1 },
    staticFlow: { kind: 'static_flow', sourceKind: 'filesystem_filename', truncated: false,
      steps: [{ role: 'source', location: { path: 'app.mts', line: 1, column: 1 } }, { role: 'sink', location: { path: 'app.mts', line: 2, column: 1 } }] } };
  const make = (f: any) => createReport([{ id: 'fixture:origin-contract', status: 'completed', findings: [f], notes: [] }],
    'source', '2026-10-13T00:00:00Z', { fingerprint: 'a'.repeat(64), ruleset: 'synthetic.origin' });
  const before = make(finding), same = make(JSON.parse(JSON.stringify(finding))); assert.equal(compareReports(before, same).comparable, true);
  assert.equal((toAgentReport(before).findings[0].evidence.staticFlow as any).sourceKind, 'filesystem_filename');
  assert.ok(toMarkdown(before).includes('filesystem_filename')); assert.ok(JSON.stringify(toSarif(before)).includes('filesystem_filename'));
  const removed = JSON.parse(JSON.stringify(finding)); delete removed.staticFlow.sourceKind;
  assert.equal(compareReports(before, make(removed)).comparable, false, 'origin disappearance cannot look like comparable same evidence');
  const raw: any = JSON.parse(JSON.stringify(before)); raw.checks[0].findings[0].staticFlow.sourceKind = 'invented_unknown_origin';
  assert.throws(() => parseScanReport(raw), 'external unknown origin enum must be rejected');
  const projected = toAgentReport(raw); assert.equal(projected.scanGate.exitCode, 2, 'sanitization cannot launder invalid origin into completed legacy evidence');
  assert.equal(JSON.stringify(projected).includes('invented_unknown_origin'), false);
});
