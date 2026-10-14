import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import { projectAdviceContext } from '../src/agent-advice-context.js';

const URL_RULE = 'ast:html-url-input-sink';
const UNKNOWN_RULE = 'ast:html-output-context-unknown';
const privateMarker = 'owned-html-context-private-a4891d';
const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));

// Original inert fixtures. Imported target packages below are never loaded or executed.
function sendFixture(body: string, response = 'outgoing', callback = 'function deliver(outgoing)') {
  return `const makeStream = require('send');
module.exports = function mount(incoming, reply, next) {
  const stream = makeStream(incoming, incoming.url, {});
  stream.on('directory', makeListener());
  stream.pipe(reply);
};
function makeListener() {
  return ${callback} {
    const value = this.req.url;
    ${response}.setHeader('Content-Type', 'text/html; charset=UTF-8');
    ${body}
  };
}
// ${privateMarker}
`;
}
function coreFixture(body: string, mime = 'text/html', prefix = "import { createServer as start } from 'node:http';", invocation = 'start') {
  return `${prefix}
${invocation}((incoming, outgoing) => {
  const value = incoming.url;
  outgoing.setHeader('Content-Type', '${mime}');
  ${body}
});
// ${privateMarker}`;
}
function scan(text: string, more: Record<string, string> = {}, limits: FlowLimits = FLOW_LIMITS) {
  const files = Object.entries({ 'app.ts': text, ...more }).map(([path, text]) => ({ path, text,
    bytes: Buffer.byteLength(text), category: path.endsWith('.json') ? 'config' as const : 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/owned-inert-html-output', files, issues: [], complete: true,
    ignoredFiles: 0, totalBytes: files.reduce((sum, f) => sum + f.bytes, 0) };
  const check = runBuiltinAst(snapshot, false, limits), report = createReport([check], 'source', new Date(0));
  return { check, report, agent: toAgentReport(report, 'medium'),
    url: check.findings.filter(f => f.ruleId === URL_RULE), unknown: check.findings.filter(f => f.ruleId === UNKNOWN_RULE) };
}
function known(result: ReturnType<typeof scan>, conditional = false) {
  assert.ok(result.url.length > 0, 'request data in a supported quoted URL attribute needs a contextual candidate');
  for (const finding of result.url) {
    assert.equal(finding.kind, 'candidate'); assert.equal(finding.severity, 'medium');
    assert.ok(finding.staticFlow?.steps.some(step => step.role === 'source'));
    if (conditional) {
      assert.equal(finding.confidence, 'low');
      assert.equal(finding.staticContext?.authority, 'conditional');
      assert.equal(result.check.status, 'partial');
    }
  }
  assert.equal(result.agent.scanGate.exitCode, evaluateGate(result.report, 'medium').exitCode);
  for (const row of result.agent.findings.filter(row => row.ruleId === URL_RULE)) {
    assert.equal(row.reachesFailOn, true);
    assert.deepEqual(row.verification, { state: 'not_run', vulnerabilityConfirmed: false, remediationVerified: false });
  }
}
function uncertain(result: ReturnType<typeof scan>) {
  assert.equal(result.check.status, 'partial');
  assert.ok(result.unknown.length > 0, 'unresolved HTML context must retain the observed input');
  assert.equal(result.url.length, 0, 'unknown context must not assert a known URL-attribute position');
  for (const finding of result.unknown) {
    assert.equal(finding.kind, 'candidate'); assert.equal(finding.confidence, 'low');
  }
  assert.ok((result.check.analysisGaps?.eventsObserved ?? 0) > 0);
  assert.equal(evaluateGate(result.report, 'none').exitCode, 2);
}

test('HTML independent: returned regular callbacks use invocation request and response despite renamed bindings', () => {
  known(scan(sendFixture(`outgoing.end('<a href="' + value + '">go</a>');`)), true);
  known(scan(sendFixture(`sink.end('<a href="' + value + '">go</a>');`, 'sink', 'function renamed(sink)')), true);
});

test('HTML independent: core Node request callbacks cover aliases, named handlers and HTTPS options shape', () => {
  known(scan(coreFixture(`outgoing.end('<a href="' + value + '">go</a>');`)));
  known(scan(`import * as transport from 'node:https';
transport.createServer({}, handle);
function handle(incoming, outgoing) { outgoing.writeHead(200, {'Content-Type':'text/html'}); outgoing.end('<form action="' + incoming.url + '"></form>'); }`));
});

test('HTML independent: quoted URL attributes preserve whole-hole and fixed-prefix context without exploit proof', () => {
  for (const [tag, attr] of [['a', 'href'], ['img', 'src'], ['form', 'action'], ['button', 'formaction'], ['video', 'poster']]) {
    known(scan(coreFixture(`outgoing.end('<${tag} ${attr}="' + value + '">item</${tag}>');`)));
  }
  known(scan(coreFixture(`outgoing.end('<a href="/fixed?q=' + value + '">go</a>');`)));
});

test('HTML independent: fixed URLs are normal while unverified raw text remains an unknown HTML candidate', () => {
  const rawText = scan(coreFixture(`outgoing.end('<a href="/fixed">' + value + '</a>');`));
  uncertain(rawText);
  const fixed = scan(coreFixture(`outgoing.end('<a href="/fixed">fixed text</a>');`));
  assert.equal(fixed.url.length, 0); assert.equal(fixed.unknown.length, 0);
  const nonHtml = scan(coreFixture(`outgoing.end('<a href="' + value + '">go</a>');`, 'application/json'));
  assert.equal(nonHtml.url.length, 0); assert.equal(nonHtml.unknown.length, 0);
});

test('HTML independent: an encoder-looking name never certifies a URL or HTML text as safe', () => {
  const named = coreFixture(`outgoing.end('<a href="' + escapeHtml(value) + '">go</a>');`)
    + '\nfunction escapeHtml(value) { return value; }';
  known(scan(named));
  const opaque = coreFixture(`outgoing.end('<p>' + escapeHtml(value) + '</p>');`)
    + '\nconst escapeHtml = opaqueEncoder;';
  uncertain(scan(opaque));
});

test('HTML independent: malformed, unquoted, raw-text and dynamic markup cannot receive known attribute authority', () => {
  for (const body of [
    `outgoing.end('<a href=' + value + '>go</a>');`,
    `outgoing.end('<a href="' + value);`,
    `outgoing.end('<script>' + value + '</script>');`,
    `outgoing.end('<div title="' + value + '">go</div>');`,
    `outgoing.end(value + '<a href="/fixed">go</a>');`,
  ]) uncertain(scan(coreFixture(body)));
});

test('HTML independent: cross-write HTML context stays unknown rather than becoming clean text', () => {
  const result = scan(coreFixture(`outgoing.write('<a href="'); outgoing.end(value + '">go</a>');`));
  uncertain(result);
});

test('HTML independent: MIME and response mutations never retain a stale precise HTML certificate', () => {
  uncertain(scan(coreFixture(`outgoing.setHeader('Content-Type', unknownMime); outgoing.end('<a href="' + value + '">go</a>');`)));
  uncertain(scan(coreFixture(`outgoing.write('<p>fixed</p>'); outgoing.setHeader('Content-Type', 'application/json'); outgoing.end(value);`)));
  for (const effect of ["outgoing.end = opaque;", 'opaque(outgoing);']) {
    const result = scan(coreFixture(`${effect} outgoing.end('<a href="' + value + '">go</a>');`));
    assert.equal(result.url.length, 0);
    assert.equal(result.check.status, 'partial');
    assert.equal(evaluateGate(result.report, 'none').exitCode, 2);
  }
});

test('HTML independent: fake, shadowed and configured native bindings grant no known Node output authority', () => {
  const body = `outgoing.end('<a href="' + value + '">go</a>');`;
  for (const text of [
    coreFixture(body, 'text/html', 'const start = opaqueServer;'),
    `import {createServer as start} from 'node:http'; function wrapper(start) { ${coreFixture(body, 'text/html', '')} } wrapper(opaqueServer);`,
  ]) assert.equal(scan(text).url.length, 0);
  const mapped = scan(coreFixture(body), {
    'tsconfig.json': '{"compilerOptions":{"paths":{"node:http":["./shim.ts"]}}}',
    'shim.ts': 'export function createServer(callback) { return opaque(callback); }',
  });
  assert.equal(mapped.url.length, 0);
});

test('HTML independent: arrow callbacks and replaced listener identities do not acquire an event receiver', () => {
  const text = sendFixture(`outgoing.end('<a href="' + value + '">go</a>');`, 'outgoing', '(outgoing) =>');
  assert.equal(scan(text).url.length, 0);
  const replaced = sendFixture(`outgoing.end('<a href="' + value + '">go</a>');`)
    .replace("stream.on('directory', makeListener());", "let listener = makeListener(); listener = opaqueListener; stream.on('directory', listener);");
  assert.equal(scan(replaced).url.length, 0);
});

test('HTML independent: fragment and work caps remain explicit without displacing an ordinary source root', () => {
  const expression = Array.from({ length: 30 }, () => 'value').join(' + ');
  const capped = scan(coreFixture(`outgoing.end('<a href="' + ${expression} + '">go</a>');`));
  assert.equal(capped.check.status, 'partial');
  assert.ok((capped.check.analysisGaps?.eventsObserved ?? 0) > 0);
  assert.equal(evaluateGate(capped.report, 'none').exitCode, 2);
  const long = scan(coreFixture(`outgoing.end('<a href="${'x'.repeat(2050)}' + value + '">go</a>');`));
  assert.equal(long.check.status, 'partial');
  assert.equal(evaluateGate(long.report, 'none').exitCode, 2);
  const text = coreFixture(`outgoing.end('<a href="' + value + '">go</a>');`)
    + "\nimport {exec} from 'node:child_process'; export function later(req) { exec(req.query.command); }";
  const allRoots = scan(text);
  assert.ok(allRoots.check.findings.some(f => f.ruleId === 'ast:shell-input-sink'));
  assert.equal(allRoots.check.metrics?.entryRootsSkipped, 0);
  const exhausted = scan(text, {}, { ...FLOW_LIMITS, flowWork: 1 });
  assert.equal(exhausted.check.status, 'partial');
  assert.equal(evaluateGate(exhausted.report, 'none').exitCode, 2);
});

test('HTML independent: machine-readable findings, advice and local formats preserve candidacy and privacy', () => {
  const result = scan(sendFixture(`outgoing.end('<a href="' + value + '">go</a>');`));
  known(result, true);
  const sarif = toSarif(result.report), advice = projectAdviceContext(result.agent, false);
  const formats = [JSON.stringify(result.report), JSON.stringify(result.agent), JSON.stringify(sarif), JSON.stringify(advice)];
  for (const output of formats) { assert.ok(output.includes(URL_RULE)); assert.equal(output.includes(privateMarker), false); }
  assert.equal(toMarkdown(result.report, 'medium').includes(privateMarker), false);
  assert.equal(JSON.stringify(advice).includes('app.ts'), false);
  assert.equal(result.agent.scanGate.exitCode, 2);
});

test('HTML independent: an owned CLI report hands off its exact candidate without altering the scan gate', async t => {
  const base = await mkdtemp(join(tmpdir(), 'owned-html-handoff-'));
  t.after(() => rm(base, { recursive: true, force: true }));
  const source = join(base, 'source'), before = join(base, 'before'), packet = join(base, 'review'), after = join(base, 'recheck');
  await mkdir(source); await writeFile(join(source, 'app.js'), sendFixture(`outgoing.end('<a href="' + value + '">go</a>');`));
  async function run(args: string[]) {
    try { await exec(process.execPath, [cli, ...args], { timeout: 30000 }); return 0; }
    catch (error) { const e = error as { code: number; killed?: boolean }; assert.equal(e.killed, false); assert.equal(typeof e.code, 'number'); return e.code; }
  }
  assert.equal(await run(['scan', '--source', source, '--tools', 'none', '--project-id', 'owned/html-handoff', '--fail-on', 'medium', '--out', before]), 2);
  const reportBytes = await readFile(join(before, 'report.json'));
  const agent = JSON.parse(await readFile(join(before, 'agent-report.json'), 'utf8'));
  const row = agent.findings.find((f: { ruleId: string }) => f.ruleId === URL_RULE); assert.ok(row);
  assert.equal(await run(['handoff', 'create', '--report', before, '--source', source, '--finding', row.findingId,
    '--check-index', String(row.checkIndex), '--out', packet]), 0);
  const ready = JSON.parse(await readFile(join(packet, 'handoff.json'), 'utf8'));
  assert.equal(ready.version, 1); assert.equal(ready.selected.ruleId, URL_RULE);
  assert.equal(ready.originalScanGate.exitCode, 2);
  assert.deepEqual(await readFile(join(packet, 'report.json')), reportBytes);
  assert.equal(await run(['handoff', 'finish', '--handoff', packet, '--report', before, '--source', source, '--out', after]), 2);
  const finished = JSON.parse(await readFile(join(after, 'handoff.json'), 'utf8'));
  assert.equal(finished.after.scanGate.exitCode, 2); assert.equal(finished.comparison.comparable, false);
  assert.equal(finished.selectedState, 'unverified');
  assert.equal(finished.verification.vulnerabilityConfirmed, false); assert.equal(finished.verification.remediationVerified, false);
});
