import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { main } from '../src/cli.js';

// Independent own source, never imported/executed as target code. The two negatives
// predate this test file: qa-provider-holdouts/manifest.json SHA256
// e8fc82b754b27ff2704e4e9e3eca193ef66e266417707322695b5e1bdbddd298.
// The connected positive is added afterwards by removing the prototype replacement
// from the second fixture. No upstream source or prospective product-helper import.
const RULE = 'ast:filesystem-shell-input', MARKER = 'owned-provider-private-source-196d';
const app = `import { globStream } from './index.js';
import { foregroundChild } from 'foreground-child';
const matches: string[] = [];
const stream = globStream('**/*', {});
stream.on('data', p => matches.push(p));
stream.on('end', () => foregroundChild('owned-review-command', matches, { shell: true }));
`;
const index = `import { Glob } from './glob.js';
export function globStream(pattern: string, options: object) {
  return new Glob(pattern, options).stream();
}
`;
const glob = `import { GlobStream } from './walker.js';
export class Glob {
  constructor(pattern: string, options: object) {}
  stream() { return new GlobStream().stream(); }
}
`;
const replacedGlob = `import { GlobStream } from './walker.js';
import { Minipass } from 'minipass';
GlobStream.prototype.stream = function () {
  const fixed = new Minipass<string>({ objectMode: true });
  fixed.end('owned-constant-output');
  return fixed;
};
export class Glob {
  constructor(pattern: string, options: object) {}
  stream() { return new GlobStream().stream(); }
}
`;
const disconnected = `import { Minipass } from 'minipass';
import { PathScurry } from 'path-scurry';
export class GlobUtil {
  unusedRead() {
    new PathScurry('.').cwd.readdirCB((_error, entries) => {
      for (const entry of entries) entry.fullpath();
    });
  }
}
export class GlobStream extends GlobUtil {
  results = new Minipass<string>({ objectMode: true });
  matchEmit(p: string) { this.results.write(p); }
  stream() {
    this.matchEmit('owned-constant-output');
    this.results.end();
    return this.results;
  }
}
`;
const connected = `import { Minipass } from 'minipass';
import { PathScurry } from 'path-scurry';
export abstract class GlobUtil {
  abstract matchEmit(p: string): void;
  walk() {
    new PathScurry('.').cwd.readdirCB((_error, entries) => {
      for (const entry of entries) this.matchEmit(entry.fullpath());
      this.walkEnd();
    });
  }
  abstract walkEnd(): void;
}
export class GlobStream extends GlobUtil {
  results = new Minipass<string>({ objectMode: true });
  matchEmit(p: string) { this.results.write(p); }
  walkEnd() { this.results.end(); }
  stream() { this.walk(); return this.results; }
}
`;
// These three v2 contradictions were identified after the first source freeze;
// their expected rejection is frozen before producer correction or author runs.
const contradictoryPathActual = `import { Minipass } from 'minipass';
import { PathScurry, Path } from 'path-scurry';
export abstract class GlobUtil {
  abstract matchEmit(p: string): void;
  walk() {
    new PathScurry('.').cwd.readdirCB((_error, entries) => {});
    this.matchFinish({ fullpath() { return 'owned-constant-output'; } } as Path);
  }
  matchFinish(p: Path) { this.matchEmit(p.fullpath()); }
}
export class GlobStream extends GlobUtil {
  results: Minipass<string>;
  constructor() { super(); this.results = new Minipass<string>({ objectMode: true }); }
  matchEmit(p: string) { this.results.write(p); }
  stream() { this.walk(); this.results.end(); return this.results; }
}
`;
const fakeDirectoryReceiver = `import { Minipass } from 'minipass';
export abstract class GlobUtil {
  abstract matchEmit(p: string): void;
  walk() {
    const ownedFake = {
      readdirCB(callback: (_error: unknown, entries: {fullpath(): string}[]) => void) {
        callback(null, [{fullpath() { return 'owned-fixed-output'; }}]);
      }
    };
    ownedFake.readdirCB((_error, entries) => {
      for (const entry of entries) this.matchEmit(entry.fullpath());
      this.walkEnd();
    });
  }
  abstract walkEnd(): void;
}
export class GlobStream extends GlobUtil {
  results = new Minipass<string>({ objectMode: true });
  matchEmit(p: string) { this.results.write(p); }
  walkEnd() { this.results.end(); }
  stream() { this.walk(); return this.results; }
}
`;
const overwrittenReturnedStream = `import { Minipass } from 'minipass';
import { PathScurry } from 'path-scurry';
export abstract class GlobUtil {
  abstract matchEmit(p: string): void;
  walk() {
    new PathScurry('.').cwd.readdirCB((_error, entries) => {
      for (const entry of entries) this.matchEmit(entry.fullpath());
      this.walkEnd();
    });
  }
  abstract walkEnd(): void;
}
export class GlobStream extends GlobUtil {
  results: any;
  constructor() {
    super();
    this.results = new Minipass<string>({ objectMode: true });
    this.results = {
      write(_p: string) {}, end() {},
      on(event: string, callback: (...args: any[]) => void) {
        if (event === 'data') callback('owned-constant-output');
        if (event === 'end') callback();
        return this;
      }
    };
  }
  matchEmit(p: string) { this.results.write(p); }
  walkEnd() { this.results.end(); }
  stream() { this.walk(); return this.results; }
}
`;
// The same visible overwrite through destructuring; original six inputs remain unchanged.
const destructuringReturnedStream = overwrittenReturnedStream
  .replace('    this.results = {', '    const constantEmitter = {')
  .replace('    };\n  }', '    };\n    [this.results] = [constantEmitter];\n  }');
type Shape = 'cooccurrence-constant' | 'imported-prototype-mutation' | 'connected-original'
  | 'path-formal-contradiction' | 'fake-directory-receiver' | 'returned-stream-overwrite' | 'destructuring-stream-overwrite';
async function scan(t: TestContext, shape: Shape, walkerOverride?: string) {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-provider-independent-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'), out = join(top, 'reports'); await mkdir(source);
  const dependencies = { 'foreground-child': '3.2.1', minipass: '7.1.2', 'path-scurry': '1.11.1' };
  const manifest = { name: 'glob', version: '10.4.5', private: true, type: 'module', dependencies };
  const files: Record<string, string> = {
    'app.mts': app + '// ' + MARKER + '\n', 'index.ts': index,
    'glob.ts': shape === 'imported-prototype-mutation' ? replacedGlob : glob,
    'walker.ts': walkerOverride ?? (shape === 'cooccurrence-constant' ? disconnected
      : shape === 'path-formal-contradiction' ? contradictoryPathActual
        : shape === 'fake-directory-receiver' ? fakeDirectoryReceiver
          : shape === 'returned-stream-overwrite' ? overwrittenReturnedStream
            : shape === 'destructuring-stream-overwrite' ? destructuringReturnedStream : connected),
    'package.json': JSON.stringify(manifest),
    'package-lock.json': JSON.stringify({ name: 'glob', version: '10.4.5', lockfileVersion: 3,
      packages: { '': manifest, ...Object.fromEntries(Object.entries(dependencies).map(([name, version]) =>
        ['node_modules/' + name, { version }])) } }),
  };
  for (const [name, text] of Object.entries(files)) await writeFile(join(source, name), text);
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  let code: number;
  try {
    code = await main(['scan', '--source', source, '--tools', 'none', '--project-id', 'owned/provider-boundaries',
      '--analysis-profile', 'default', '--fail-on', 'high', '--out', out]);
  } finally { process.stdout.write = stdout; process.stderr.write = stderr; }
  const outputs: Record<string, string> = {};
  for (const name of ['report.json', 'agent-report.json', 'report.sarif', 'report.md']) {
    outputs[name] = await readFile(join(out, name), 'utf8');
    assert.equal(outputs[name].includes(MARKER), false, name + ': raw source marker leaked');
  }
  const report = JSON.parse(outputs['report.json']), agent = JSON.parse(outputs['agent-report.json']);
  const sarif = JSON.parse(outputs['report.sarif']);
  const ast = report.checks.find((c: any) => c.id === 'source.builtin-ast'); assert.ok(ast);
  assert.equal(agent.scanGate.exitCode, code);
  assert.equal(agent.reportArtifact.digest, createHash('sha256').update(outputs['report.json']).digest('hex'));
  for (const [name, text] of Object.entries(files)) assert.equal(await readFile(join(source, name), 'utf8'), text, 'target source changed');
  assert.equal((await readdir(source)).includes('node_modules'), false, 'target dependencies installed');
  return { code, report, agent, sarif, ast };
}
type Result = Awaited<ReturnType<typeof scan>>;
function noFilenameCertificate(r: Result) {
  const findings = r.report.checks.flatMap((c: any) => c.findings);
  assert.equal(findings.some((f: any) => f.ruleId === RULE), false, 'disconnected/replaced provider minted filesystem finding');
  assert.equal(findings.some((f: any) => f.staticFlow?.sourceKind === 'filesystem_filename'), false,
    'disconnected/replaced provider minted filename origin on another rule');
  assert.equal(r.agent.findings.some((f: any) => f.evidence?.staticFlow?.sourceKind === 'filesystem_filename'), false);
  assert.equal(r.sarif.runs.flatMap((run: any) => run.results).some((f: any) =>
    f.properties?.staticFlow?.sourceKind === 'filesystem_filename'), false);
  // A declared local provider whose certificate cannot be established is a gap;
  // denying its source tag must not turn incomplete source coverage into clean.
  assert.equal(r.ast.status, 'partial'); assert.equal(r.code, 2);
}
function location(needle: string) {
  const offset = app.indexOf(needle); assert.ok(offset >= 0);
  const prior = app.slice(0, offset).split('\n');
  return { path: 'app.mts', line: prior.length, column: prior.at(-1)!.length + 1 };
}

test('filesystem provider boundary: uncalled PathScurry reads cannot certify constant-only returned stream data', async t => {
  noFilenameCertificate(await scan(t, 'cooccurrence-constant'));
});

test('filesystem provider boundary: imported class prototype replacement revokes the original connected declaration', async t => {
  noFilenameCertificate(await scan(t, 'imported-prototype-mutation'));
});

test('filesystem provider boundary: connected original read/path/write/returned-stream chain supplies a conditional filename witness', async t => {
  const r = await scan(t, 'connected-original');
  const finding = r.ast.findings.find((f: any) => f.ruleId === RULE &&
    JSON.stringify(f.location) === JSON.stringify(location('foregroundChild(')));
  assert.ok(finding, 'rejecting all local providers must not pass both negative boundaries');
  assert.equal(finding.kind, 'candidate'); assert.equal(finding.severity, 'high'); assert.equal(finding.confidence, 'low');
  assert.equal(finding.staticFlow?.sourceKind, 'filesystem_filename'); assert.equal(finding.staticFlow?.truncated, true);
  assert.ok(finding.staticFlow.steps.some((s: any) => s.role === 'source' &&
    JSON.stringify(s.location) === JSON.stringify(location('p =>'))), 'source trace does not identify actual data parameter');
  assert.ok(finding.staticFlow.steps.some((s: any) => JSON.stringify(s.location) === JSON.stringify(location('matches.push('))));
  assert.deepEqual(finding.staticFlow.steps.at(-1), { role: 'sink', location: location('foregroundChild(') });
  assert.equal(finding.staticContext?.authority, 'conditional');
  for (const kind of ['declared_filesystem_stream_origin', 'declared_stream_callback_schedule', 'declared_process_wrapper']) {
    assert.ok(finding.staticContext.items.some((item: any) => item.kind === kind));
  }
  assert.equal(r.ast.status, 'partial'); assert.equal(r.code, 2);
  const af = r.agent.findings.find((f: any) => f.findingId === finding.id); assert.ok(af);
  assert.deepEqual(af.evidence.staticFlow, finding.staticFlow); assert.deepEqual(af.evidence.staticContext, finding.staticContext);
  assert.equal(af.verification.vulnerabilityConfirmed, false); assert.equal(af.verification.remediationVerified, false);
  const sf = r.sarif.runs.flatMap((run: any) => run.results).find((f: any) =>
    f.fingerprints?.['wakeio-security-ci/v2'] === finding.id); assert.ok(sf);
  assert.deepEqual(sf.properties.staticFlow, finding.staticFlow);
});

test('filesystem provider boundary: visible constant object actual contradicts a Path formal despite a reachable unrelated real read', async t => {
  noFilenameCertificate(await scan(t, 'path-formal-contradiction'));
});

test('filesystem provider boundary: local fake readdirCB receiver emitting fixed path objects is not filesystem source identity', async t => {
  noFilenameCertificate(await scan(t, 'fake-directory-receiver'));
});

test('filesystem provider boundary: visible overwrite of returned Minipass field invalidates its earlier construction certificate', async t => {
  noFilenameCertificate(await scan(t, 'returned-stream-overwrite'));
});

test('filesystem provider boundary: destructuring overwrite of returned stream field cannot bypass instance write qualification', async t => {
  noFilenameCertificate(await scan(t, 'destructuring-stream-overwrite'));
  // Loop initializers are existing assignment targets too. for-of replaces the
  // stream with the literal emitter; for-in replaces it with a fixed key string.
  // Both contradict the original Minipass certificate, including destructuring.
  for (const overwrite of [
    'for (this.results of [constantEmitter]) {}',
    'for ([this.results] of [[constantEmitter]]) {}',
    'for (this.results in { fixed: constantEmitter }) {}',
    'for ([this.results] in { fixed: constantEmitter }) {}',
  ]) {
    t.diagnostic(overwrite);
    const walker = destructuringReturnedStream.replace('[this.results] = [constantEmitter];', overwrite);
    noFilenameCertificate(await scan(t, 'destructuring-stream-overwrite', walker));
  }
});
