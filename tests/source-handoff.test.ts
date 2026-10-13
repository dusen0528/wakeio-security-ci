import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { copyFile, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
// Deliberately import only APIs present before handoff implementation.
import { main } from '../src/cli.js';
import { toAgentReport } from '../src/report.js';

const RISK = 'function route(req) { db.query("SELECT " + req.query.id); }\n';
const FIXED = 'function route(req) { db.query("SELECT * FROM users WHERE id = ?", [req.query.id]); }\n';
const NEW_HIGH = 'function another(req) { eval(req.query.code); }\n';
const sha = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
type Workspace = { top: string; source: string; app: string };
type Pair = { dir: string; report: any; agent: any; reportBytes: Buffer; agentBytes: Buffer; code: number };

async function cli(args: string[]) {
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try { return await main(args); }
  finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
async function workspace(t: TestContext): Promise<Workspace> {
  const top = await mkdtemp(join(tmpdir(), 'wakeio-independent-handoff-'));
  t.after(() => rm(top, { recursive: true, force: true }));
  const source = join(top, 'source'), app = join(source, 'app.ts');
  await mkdir(source); await writeFile(app, RISK);
  return { top, source, app };
}
async function pairAt(dir: string, code = 0): Promise<Pair> {
  const reportBytes = await readFile(join(dir, 'report.json'));
  const agentBytes = await readFile(join(dir, 'agent-report.json'));
  return { dir, report: JSON.parse(reportBytes.toString()), agent: JSON.parse(agentBytes.toString()), reportBytes, agentBytes, code };
}
async function scan(w: Workspace, name: string, flags: string[] = []): Promise<Pair> {
  const dir = join(w.top, name);
  const choices = [['--analysis-profile', 'default'], ['--source-max-files', '1000'],
    ['--source-max-bytes', '26214400'], ['--timeout-ms', '30000']];
  const code = await cli(['scan', '--source', w.source, '--tools', 'none', '--project-id', 'owned/handoff-acceptance',
    ...choices.filter(([flag]) => !flags.includes(flag)).flat(), '--out', dir, ...flags]);
  return pairAt(dir, code);
}
function selected(pair: Pair) {
  const finding = pair.agent.findings.find((f: any) => f.ruleId === 'ast:sql-input-sink');
  assert.ok(finding, 'owned source must produce the actual SQL candidate');
  return finding;
}
async function create(w: Workspace, before: Pair, out = join(w.top, 'handoff'), overrides: string[] = []) {
  const finding = selected(before);
  const code = await cli(['handoff', 'create', '--report', before.dir, '--source', w.source,
    '--finding', finding.findingId, '--check-index', String(finding.checkIndex), '--out', out, ...overrides]);
  return { code, out };
}
async function finish(w: Workspace, handoff: string, after: Pair, out = join(w.top, 'finished')) {
  const code = await cli(['handoff', 'finish', '--handoff', handoff, '--report', after.dir, '--source', w.source, '--out', out]);
  return { code, out };
}
async function receipt(out: string) { return JSON.parse(await readFile(join(out, 'handoff.json'), 'utf8')); }
async function ready(w: Workspace) {
  const before = await scan(w, 'before'); assert.equal(before.code, 1);
  const handoff = await create(w, before); assert.equal(handoff.code, 0, 'create must produce a review packet');
  return { before, handoff };
}
function unverified(r: any) {
  assert.deepEqual(r.verification, { vulnerabilityConfirmed: false, remediationVerified: false,
    securityControl: 'not_run', normalControl: 'not_run' });
}
async function resign(pair: Pair, mutate: (report: any) => void, failOn = pair.agent.scanGate.failOn) {
  const report = JSON.parse(pair.reportBytes.toString()); mutate(report);
  await writeFile(join(pair.dir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
  await writeFile(join(pair.dir, 'agent-report.json'), `${JSON.stringify(toAgentReport(report, failOn), null, 2)}\n`);
  return pairAt(pair.dir, pair.code);
}
async function tree(dir: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  const visit = async (current: string, prefix: string) => {
    for (const name of (await readdir(current)).sort()) {
      const path = join(current, name), relative = `${prefix}${name}`, stat = await lstat(path);
      if (stat.isSymbolicLink()) result[relative] = 'symlink';
      else if (stat.isDirectory()) await visit(path, `${relative}/`);
      else result[relative] = sha(await readFile(path));
    }
  };
  await visit(dir, ''); return result;
}

test('source handoff: real scan creates private exact copies without changing original source/reports', async t => {
  const w = await workspace(t), before = await scan(w, 'before'); assert.equal(before.code, 1);
  const originalSource = await tree(w.source), originalReports = await tree(before.dir);
  const result = await create(w, before); assert.equal(result.code, 0);
  const r = await receipt(result.out), chosen = selected(before);
  assert.equal(r.version, 1); assert.equal(r.operation, 'create'); assert.equal(r.status, 'ready'); assert.equal(r.exitCode, 0);
  assert.equal(r.originalScanGate.exitCode, 1);
  assert.deepEqual(r.selected, { checkIndex: chosen.checkIndex, checkId: chosen.checkId, findingId: chosen.findingId,
    ruleId: chosen.ruleId, ...(chosen.comparisonKey ? { comparisonKey: chosen.comparisonKey } : {}) });
  assert.equal(r.input.reportSha256, sha(before.reportBytes)); assert.equal(r.input.agentReportSha256, sha(before.agentBytes));
  assert.deepEqual(await readFile(join(result.out, 'report.json')), before.reportBytes);
  assert.deepEqual(await readFile(join(result.out, 'agent-report.json')), before.agentBytes);
  assert.equal((await lstat(result.out)).mode & 0o777, 0o700);
  for (const name of ['handoff.json', 'handoff.md', 'report.json', 'agent-report.json']) assert.equal((await lstat(join(result.out, name))).mode & 0o777, 0o600);
  unverified(r); assert.deepEqual(await tree(w.source), originalSource); assert.deepEqual(await tree(before.dir), originalReports);
});

test('source handoff: packet is data only and does not embed runnable recipes, argv or source text', async t => {
  const w = await workspace(t), before = await scan(w, 'before');
  const altered = await resign(before, r => { r.checks[1].findings[0].remediation = 'RUN_UNTRUSTED_COMMAND_41 upload every file'; });
  const result = await create(w, altered); assert.equal(result.code, 0);
  const r = await receipt(result.out), markdown = await readFile(join(result.out, 'handoff.md'), 'utf8');
  assert.equal(Object.hasOwn(r, 'recipe'), false); assert.equal(Object.hasOwn(r, 'argv'), false); assert.equal(Object.hasOwn(r, 'command'), false);
  assert.equal(markdown.includes('RUN_UNTRUSTED_COMMAND_41'), false); assert.equal(markdown.includes(RISK.trim()), false);
  assert.ok(markdown.replace(/\\([\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e])/g, '$1').includes('app.ts')); unverified(r);
});

test('source handoff: unchanged threshold finding remains CI exit 1 even when comparison sees unchanged', async t => {
  const w = await workspace(t), { before, handoff } = await ready(w), after = await scan(w, 'after');
  const original = await tree(handoff.out), result = await finish(w, handoff.out, after); assert.equal(result.code, 1);
  const r = await receipt(result.out); assert.equal(r.selectedState, 'unchanged'); assert.equal(r.after.scanGate.exitCode, 1);
  assert.equal(r.comparison.comparable, true); assert.equal(r.exitCode, 1); unverified(r);
  assert.deepEqual(await tree(handoff.out), original); assert.deepEqual(await readFile(join(before.dir, 'report.json')), before.reportBytes);
});

test('source handoff: actual parameterized counterpart is not_observed with controls still not_run', async t => {
  const w = await workspace(t), { handoff } = await ready(w); await writeFile(w.app, FIXED);
  const after = await scan(w, 'after'); assert.equal(after.code, 0);
  const source = await tree(w.source), reports = await tree(after.dir), result = await finish(w, handoff.out, after);
  assert.equal(result.code, 0); const r = await receipt(result.out);
  assert.equal(r.operation, 'finish'); assert.equal(r.selectedState, 'not_observed'); assert.equal(r.after.scanGate.exitCode, 0);
  assert.equal(r.comparison.comparable, true); assert.equal(r.after.reportSha256, sha(after.reportBytes));
  assert.equal(r.after.agentReportSha256, sha(after.agentBytes)); unverified(r);
  assert.deepEqual(await tree(w.source), source); assert.deepEqual(await tree(after.dir), reports);
});

test('source handoff: removing selected candidate while adding another high issue still exits 1', async t => {
  const w = await workspace(t), { handoff } = await ready(w); await writeFile(w.app, FIXED + NEW_HIGH);
  const after = await scan(w, 'after'); assert.equal(after.code, 1);
  const result = await finish(w, handoff.out, after); assert.equal(result.code, 1);
  const r = await receipt(result.out); assert.equal(r.selectedState, 'not_observed'); assert.equal(r.after.scanGate.exitCode, 1);
  assert.ok(r.comparison.entries.some((e: any) => e.state === 'new' && e.finding.severity === 'high')); unverified(r);
});

test('source handoff: collector-complete AST-partial candidate can be reviewed but cannot finish successfully', async t => {
  const w = await workspace(t); await writeFile(join(w.source, 'broken.ts'), 'function {');
  const before = await scan(w, 'before'); assert.equal(before.code, 2);
  assert.equal(before.report.checks.find((c: any) => c.id === 'source.inventory').status, 'completed');
  assert.equal(before.report.checks.find((c: any) => c.id === 'source.builtin-ast').status, 'partial');
  const handoff = await create(w, before); assert.equal(handoff.code, 0);
  assert.equal((await receipt(handoff.out)).originalScanGate.exitCode, 2);
  const after = await scan(w, 'after'), result = await finish(w, handoff.out, after); assert.equal(result.code, 2);
  unverified(await receipt(handoff.out));
});

test('source handoff: collector truncation refuses even with an actual retained candidate and fail-on none', async t => {
  const w = await workspace(t); await writeFile(join(w.source, 'zzz.ts'), 'export const safe = true;');
  const before = await scan(w, 'before', ['--source-max-files', '1', '--fail-on', 'none']); assert.equal(before.code, 2);
  assert.equal(before.report.checks.find((c: any) => c.id === 'source.inventory').status, 'partial');
  assert.equal((await create(w, before)).code, 2);
});

test('source handoff: stale before source refuses literal edits even when semantic anchor stays unchanged', async t => {
  const w = await workspace(t), before = await scan(w, 'before');
  await writeFile(w.app, RISK.replace('SELECT ', 'SELECT x '));
  const after = await scan(w, 'same-anchor');
  assert.equal(selected(before).comparisonKey, selected(after).comparisonKey);
  assert.equal((await create(w, before)).code, 2);
});

test('source handoff: add, delete and rename selected source files cannot reuse old snapshot', async t => {
  for (const change of ['add', 'delete', 'rename'] as const) {
    const w = await workspace(t), before = await scan(w, `before-${change}`);
    if (change === 'add') await writeFile(join(w.source, 'another.ts'), 'export const safe = true;');
    else if (change === 'delete') await rm(w.app);
    else { await copyFile(w.app, join(w.source, 'moved.ts')); await rm(w.app); }
    assert.equal((await create(w, before)).code, 2, change);
  }
});

test('source handoff: scan-time collected strings survive mutation before legacy tree provenance hashing', async t => {
  const w = await workspace(t), original = fs.createReadStream; let changed = false;
  t.mock.method(fs, 'createReadStream', (path: any, options: any) => {
    if (!changed && String(path) === w.app) { fs.writeFileSync(w.app, FIXED); changed = true; }
    return original(path, options);
  });
  syncBuiltinESMExports();
  try {
    const before = await scan(w, 'before'); assert.equal(before.code, 1); assert.equal(changed, true, 'legacy raw tree pass was observed');
    assert.equal((await create(w, before)).code, 2, 'later tree hash must not substitute for collected scanner input');
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('source handoff: stale AFTER source refuses a report from a different current text state', async t => {
  const w = await workspace(t), { handoff } = await ready(w); await writeFile(w.app, FIXED);
  const after = await scan(w, 'after'); await writeFile(w.app, RISK);
  assert.equal((await finish(w, handoff.out, after)).code, 2);
});

test('source handoff: BOM-only raw changes preserve explicitly decoded string binding', async t => {
  const w = await workspace(t); await writeFile(w.app, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(RISK)]));
  const before = await scan(w, 'before'), inventory = before.report.checks.find((c: any) => c.id === 'source.inventory');
  assert.equal(inventory.sourceSnapshot.basis, 'collected_utf8_strings');
  assert.equal(inventory.sourceSnapshot.bytesSelected, Buffer.byteLength(RISK));
  await writeFile(w.app, RISK); const result = await create(w, before); assert.equal(result.code, 0);
  const r = await receipt(result.out); assert.equal(r.sourceBinding.basis, 'collected_utf8_strings');
  assert.equal(r.sourceBinding.digest, inventory.sourceSnapshot.digest); unverified(r);
});

test('source handoff: malformed UTF8 replacement is string identity and never a raw-byte attestation', async t => {
  const w = await workspace(t); await writeFile(w.app, Buffer.concat([Buffer.from(RISK + '// '), Buffer.from([0x80]), Buffer.from('\n')]));
  const before = await scan(w, 'before'); await writeFile(w.app, Buffer.concat([Buffer.from(RISK + '// '), Buffer.from([0x81]), Buffer.from('\n')]));
  const result = await create(w, before); assert.equal(result.code, 0);
  assert.equal((await receipt(result.out)).sourceBinding.basis, 'collected_utf8_strings');
});

test('source handoff: included non-code/private text changes invalidate aggregate without exposing raw values', async t => {
  const w = await workspace(t), sentinel = 'owned-private-snapshot-value-83b7';
  await writeFile(join(w.source, '.env'), `PRIVATE_SYNTHETIC=${sentinel}\n`);
  const before = await scan(w, 'before'); assert.equal(before.reportBytes.includes(Buffer.from(sentinel)), false);
  const handoff = await create(w, before); assert.equal(handoff.code, 0);
  assert.equal((await readFile(join(handoff.out, 'handoff.json'))).includes(Buffer.from(sentinel)), false);
  await writeFile(join(w.source, '.env'), 'PRIVATE_SYNTHETIC=changed-owned-private-value\n');
  assert.equal((await create(w, before, join(w.top, 'second'))).code, 2);
});

test('source handoff: intentional unsupported extensions remain outside the declared selected snapshot', async t => {
  const w = await workspace(t); await writeFile(join(w.source, 'opaque.unknown-extension'), 'outside-before');
  const before = await scan(w, 'before'); await writeFile(join(w.source, 'opaque.unknown-extension'), 'outside-after');
  const result = await create(w, before); assert.equal(result.code, 0);
  assert.equal((await receipt(result.out)).sourceBinding.filesSelected, 1);
});

test('source handoff: a scan excluding an internal output subtree cannot provide reusable source binding', async t => {
  const w = await workspace(t), internal = join(w.source, 'reports'); await mkdir(internal);
  await writeFile(join(internal, 'hidden.ts'), NEW_HIGH);
  const code = await cli(['scan', '--source', w.source, '--tools', 'none', '--out', internal]);
  const before = await pairAt(internal, code);
  assert.equal(before.report.checks.find((c: any) => c.id === 'source.inventory').sourceSnapshot.outputDirectoryExcluded, true);
  assert.equal((await create(w, before)).code, 2);
});

test('source handoff: source roots, source leaves and input artifact links are refused', async t => {
  for (const kind of ['root-symlink', 'source-symlink', 'source-hardlink', 'report-symlink', 'report-hardlink'] as const) {
    const w = await workspace(t), before = await scan(w, `before-${kind}`), out = join(w.top, 'handoff');
    if (kind === 'root-symlink') {
      const rootLink = join(w.top, 'source-link'); await symlink(w.source, rootLink);
      const f = selected(before);
      assert.equal(await cli(['handoff', 'create', '--report', before.dir, '--source', rootLink, '--finding', f.findingId, '--check-index', String(f.checkIndex), '--out', out]), 2);
    } else {
      if (kind === 'source-symlink') { await rm(w.app); await writeFile(join(w.top, 'outside.ts'), RISK); await symlink(join(w.top, 'outside.ts'), w.app); }
      if (kind === 'source-hardlink') await link(w.app, join(w.top, 'source-alias.ts'));
      if (kind.startsWith('report-')) {
        const reportPath = join(before.dir, 'report.json'), outside = join(w.top, 'outside-report.json');
        if (kind === 'report-symlink') { await copyFile(reportPath, outside); await rm(reportPath); await symlink(outside, reportPath); }
        else await link(reportPath, outside);
      }
      assert.equal((await create(w, before, out)).code, 2, kind);
    }
  }
});

test('source handoff: outputs are new, private, outside source and never symlink redirected', async t => {
  const w = await workspace(t), before = await scan(w, 'before'), existing = join(w.top, 'existing');
  await mkdir(existing); await writeFile(join(existing, 'preserve.txt'), 'owned-preserve');
  assert.equal((await create(w, before, existing)).code, 2);
  assert.equal(await readFile(join(existing, 'preserve.txt'), 'utf8'), 'owned-preserve');
  assert.equal((await create(w, before, join(w.source, 'handoff'))).code, 2);
  const alias = join(w.top, 'out-link'); await symlink(existing, alias);
  assert.equal((await create(w, before, join(alias, 'child'))).code, 2);
  assert.equal((await create(w, before, before.dir)).code, 2);
  assert.deepEqual(await readFile(join(before.dir, 'report.json')), before.reportBytes);
});

test('source handoff: report digest and canonical projection mismatches fail closed', async t => {
  for (const kind of ['report-byte', 'agent-gate', 'agent-finding'] as const) {
    const w = await workspace(t), before = await scan(w, `before-${kind}`);
    if (kind === 'report-byte') await writeFile(join(before.dir, 'report.json'), Buffer.concat([before.reportBytes, Buffer.from(' ')]));
    else {
      const agent = JSON.parse(before.agentBytes.toString());
      if (kind === 'agent-gate') agent.scanGate.exitCode = 0;
      else agent.findings[0].ruleId = 'invented:unrelated';
      await writeFile(join(before.dir, 'agent-report.json'), JSON.stringify(agent));
    }
    assert.equal((await create(w, before)).code, 2, kind);
  }
});

test('source handoff: selection requires exact check membership and finding identity', async t => {
  const w = await workspace(t), before = await scan(w, 'before'), f = selected(before);
  for (const [id, index] of [[f.findingId, 0], ['missing-finding', f.checkIndex], [f.findingId, 999], [f.findingId, -1]] as const) {
    assert.equal(await cli(['handoff', 'create', '--report', before.dir, '--source', w.source, '--finding', id,
      '--check-index', String(index), '--out', join(w.top, `bad-${index}-${id.slice(0, 3)}`)]), 2);
  }
});

test('source handoff: missing, malformed and unknown snapshot revisions never receive guessed binding', async t => {
  for (const kind of ['missing', 'digest', 'revision', 'count', 'complete'] as const) {
    const w = await workspace(t), before = await scan(w, `before-${kind}`);
    const changed = await resign(before, report => {
      const c = report.checks.find((c: any) => c.id === 'source.inventory');
      if (kind === 'missing') delete c.sourceSnapshot;
      else if (kind === 'digest') c.sourceSnapshot.digest = 'f'.repeat(64);
      else if (kind === 'revision') c.sourceSnapshot.revision = 'source-snapshot-future';
      else if (kind === 'count') c.sourceSnapshot.filesSelected += 1;
      else c.sourceSnapshot.complete = false;
    });
    assert.equal((await create(w, changed)).code, 2, kind);
  }
});

test('source handoff: legacy rulesets, mixed check sets and incoherent budgets are refused', async t => {
  for (const kind of ['ruleset', 'tool-version', 'mixed-mode', 'extra-check', 'budget', 'profile'] as const) {
    const w = await workspace(t), before = await scan(w, `before-${kind}`);
    const changed = await resign(before, report => {
      if (kind === 'ruleset') report.scope.ruleset = 'old.unknown';
      else if (kind === 'tool-version') report.toolVersion = '0.4.0';
      else if (kind === 'mixed-mode') report.mode = 'combined';
      else if (kind === 'extra-check') report.checks.push({ id: 'source.external', status: 'completed', findings: [], notes: [] });
      else if (kind === 'budget') report.scope.collectionBudget.limits.maxFiles = 999;
      else report.scope.analysisBudget.profile = 'future';
    });
    assert.equal((await create(w, changed)).code, 2, kind);
  }
});

test('source handoff: edited receipt and private before-copy hashes cannot authorize finish', async t => {
  for (const kind of ['selected', 'snapshot', 'gate', 'copy', 'receipt-symlink'] as const) {
    const w = await workspace(t), { handoff } = await ready(w), after = await scan(w, 'after');
    const path = join(handoff.out, 'handoff.json');
    if (kind === 'copy') await writeFile(join(handoff.out, 'report.json'), '{}');
    else if (kind === 'receipt-symlink') { const outside = join(w.top, 'receipt.json'); await copyFile(path, outside); await rm(path); await symlink(outside, path); }
    else {
      const r = await receipt(handoff.out);
      if (kind === 'selected') r.selected.findingId = 'unrelated';
      else if (kind === 'snapshot') r.sourceBinding.digest = 'a'.repeat(64);
      else r.originalScanGate.exitCode = 0;
      await writeFile(path, JSON.stringify(r));
    }
    assert.equal((await finish(w, handoff.out, after)).code, 2, kind);
  }
});

test('source handoff: partial after, changed declared scope and duplicate semantic keys remain incomplete', async t => {
  for (const kind of ['partial', 'scope', 'budget', 'ruleset', 'duplicate'] as const) {
    const w = await workspace(t), { handoff } = await ready(w);
    if (kind === 'partial') await writeFile(join(w.source, 'broken.ts'), 'function {');
    let after = await scan(w, 'after');
    if (['scope', 'budget', 'ruleset', 'duplicate'].includes(kind)) after = await resign(after, report => {
      if (kind === 'scope') report.scope.fingerprint = 'c'.repeat(64);
      else if (kind === 'budget') report.scope.collectionBudget.limits.maxFiles = 999;
      else if (kind === 'ruleset') report.scope.ruleset = 'changed.unknown';
      else {
        const check = report.checks.find((c: any) => c.id === 'source.builtin-ast');
        const duplicate = JSON.parse(JSON.stringify(check.findings[0]));
        duplicate.location.line += 10; check.findings.push(duplicate);
      }
    });
    assert.equal((await finish(w, handoff.out, after)).code, 2, kind);
  }
});

test('source handoff: original fail-on policy is preserved and cannot be relaxed in after artifacts', async t => {
  const w = await workspace(t), { handoff } = await ready(w), after = await scan(w, 'after', ['--fail-on', 'none']);
  assert.equal(after.code, 0); assert.equal((await finish(w, handoff.out, after)).code, 2);
});

test('source handoff: after-only legacy duplicates cannot select the first row even under none or critical', async t => {
  for (const failOn of ['none', 'critical']) {
    const w = await workspace(t);
    const before = await resign(await scan(w, 'before', ['--fail-on', failOn]), report => {
      for (const check of report.checks) for (const finding of check.findings) delete finding.comparisonKey;
    });
    assert.equal(before.code, 0);
    const handoff = await create(w, before); assert.equal(handoff.code, 0);
    assert.equal((await receipt(handoff.out)).selected.comparisonKey, undefined);
    const after = await resign(await scan(w, 'after', ['--fail-on', failOn]), report => {
      for (const check of report.checks) for (const finding of check.findings) delete finding.comparisonKey;
      const check = report.checks.find((c: any) => c.id === 'source.builtin-ast');
      check.findings.push(structuredClone(check.findings[0]));
    });
    assert.equal(after.agent.scanGate.exitCode, 0);
    const source = await tree(w.source), beforeBytes = await tree(before.dir), afterBytes = await tree(after.dir);
    const result = await finish(w, handoff.out, after); assert.equal(result.code, 2, failOn);
    const r = await receipt(result.out);
    assert.equal(r.selectedState, 'unverified'); assert.equal(r.reason, 'comparison_unverified');
    assert.equal(r.comparison.comparable, false); assert.equal(r.after.scanGate.exitCode, 0);
    assert.ok(r.comparison.entries.every((row: any) => row.state === 'unverified')); unverified(r);
    assert.deepEqual(await tree(w.source), source); assert.deepEqual(await tree(before.dir), beforeBytes);
    assert.deepEqual(await tree(after.dir), afterBytes);
  }
});

test('source handoff: old ID-wide threshold projection is rejected while corrected canonical pair is accepted', async t => {
  const w = await workspace(t);
  await writeFile(w.app, RISK + NEW_HIGH);
  let duplicateRule: string | undefined;
  const before = await resign(await scan(w, 'before'), report => {
    const ast = report.checks.find((check: any) => check.id === 'source.builtin-ast');
    const high = ast.findings.find((row: any) => row.ruleId !== 'ast:sql-input-sink');
    assert.ok(high, 'second owned source candidate provides a valid unrelated row');
    assert.equal(high.severity, 'high'); duplicateRule = high.ruleId;
    // Retain the actual deterministic ID; severity is outside its namespace.
    ast.findings.push({ ...structuredClone(high), severity: 'low' });
  });
  const rows = before.agent.findings.filter((row: any) => row.ruleId === duplicateRule);
  assert.equal(rows.length, 2); assert.equal(rows[0].findingId, rows[1].findingId);
  assert.deepEqual(rows.map((row: any) => row.reachesFailOn), [true, false]);
  const oldAgent = structuredClone(before.agent);
  for (const row of oldAgent.findings) if (row.ruleId === duplicateRule) row.reachesFailOn = true;
  await writeFile(join(before.dir, 'agent-report.json'), `${JSON.stringify(oldAgent, null, 2)}\n`);
  const rejected = await create(w, before, join(w.top, 'old-pair')); assert.equal(rejected.code, 2);
  assert.equal((await receipt(rejected.out)).reason, 'invalid_report_pair');
  await writeFile(join(before.dir, 'agent-report.json'), before.agentBytes);
  const corrected = await create(w, before, join(w.top, 'corrected-pair')); assert.equal(corrected.code, 0);
  const r = await receipt(corrected.out); assert.equal(r.originalScanGate.exitCode, 1); unverified(r);
  assert.deepEqual(await readFile(join(before.dir, 'report.json')), before.reportBytes);
  assert.deepEqual(await readFile(join(before.dir, 'agent-report.json')), before.agentBytes);
});

test('source handoff: explicitly original fail-on none stays none without claiming remediation', async t => {
  const w = await workspace(t), before = await scan(w, 'before', ['--fail-on', 'none']); assert.equal(before.code, 0);
  const handoff = await create(w, before); assert.equal(handoff.code, 0);
  const after = await scan(w, 'after', ['--fail-on', 'none']), result = await finish(w, handoff.out, after);
  assert.equal(result.code, 0); const r = await receipt(result.out);
  assert.equal(r.selectedState, 'unchanged'); assert.equal(r.after.scanGate.failOn, 'none'); unverified(r);
});

test('source handoff: lifecycle/source canaries remain inert and recipe, model, patch arguments are rejected', async t => {
  const w = await workspace(t), marker = join(w.top, 'must-not-exist');
  await writeFile(join(w.source, 'package.json'), JSON.stringify({ scripts: { install: `touch ${marker}`, test: `touch ${marker}` } }));
  await writeFile(join(w.source, 'inert.mjs'), `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'EXECUTED');\n`);
  const before = await scan(w, 'before'), handoff = await create(w, before); assert.equal(handoff.code, 0);
  for (const flag of ['--recipe', '--command', '--agent', '--proposal', '--allow-source-upload']) {
    assert.equal((await create(w, before, join(w.top, flag.slice(2)), [flag, 'UNTRUSTED_EXECUTION'])).code, 2, flag);
  }
  assert.equal(await lstat(marker).then(() => true, () => false), false);
  assert.deepEqual(await readFile(w.app, 'utf8'), RISK);
});

test('source handoff: invalid grammar and occupied finish output refuse without damaging input artifacts', async t => {
  const w = await workspace(t), { handoff } = await ready(w), after = await scan(w, 'after');
  const original = await tree(handoff.out), out = join(w.top, 'occupied'); await mkdir(out); await writeFile(join(out, 'keep'), 'keep');
  assert.equal((await finish(w, handoff.out, after, out)).code, 2);
  assert.equal(await cli(['handoff', 'finish', '--handoff', handoff.out, '--report', after.dir, '--source', w.source,
    '--out', join(w.top, 'invalid'), '--out', join(w.top, 'duplicate')]), 2);
  assert.equal(await cli(['handoff', 'execute', '--source', w.source]), 2);
  assert.equal(await readFile(join(out, 'keep'), 'utf8'), 'keep'); assert.deepEqual(await tree(handoff.out), original);
});
