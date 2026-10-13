import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { main } from '../src/cli.js';

const RISK = 'function route(req) { db.query("SELECT " + req.query.id); }\n';
const sha = (value: Buffer) => createHash('sha256').update(value).digest('hex');
async function cli(args: string[]) {
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try { return await main(args); }
  finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
async function fixture(t: TestContext, filename = 'app.ts', contents = RISK) {
  const top = await fsp.mkdtemp(join(tmpdir(), 'wakeio-handoff-boundary-')), source = join(top, 'source'), reports = join(top, 'reports');
  t.after(() => fsp.rm(top, { recursive: true, force: true }));
  await fsp.mkdir(source); const path = join(source, filename); await fsp.writeFile(path, contents);
  assert.equal(await cli(['scan', '--source', source, '--tools', 'none', '--project-id', 'owned/handoff-boundaries', '--out', reports]), 1);
  const reportBytes = await fsp.readFile(join(reports, 'report.json')), agentBytes = await fsp.readFile(join(reports, 'agent-report.json'));
  const report = JSON.parse(reportBytes.toString()), agent = JSON.parse(agentBytes.toString());
  const selected = agent.findings.find((f: any) => f.ruleId === 'ast:sql-input-sink'); assert.ok(selected);
  return { top, source, reports, path, contents, reportBytes, agentBytes, report, agent, selected };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function create(f: Fixture, out: string) {
  return cli(['handoff', 'create', '--report', f.reports, '--source', f.source, '--finding', f.selected.findingId,
    '--check-index', String(f.selected.checkIndex), '--out', out]);
}
async function unchanged(f: Fixture) {
  assert.deepEqual(await fsp.readFile(f.path), Buffer.from(f.contents));
  assert.deepEqual(await fsp.readFile(join(f.reports, 'report.json')), f.reportBytes);
  assert.deepEqual(await fsp.readFile(join(f.reports, 'agent-report.json')), f.agentBytes);
}
async function noSuccessMarker(out: string) {
  const bytes = await fsp.readFile(join(out, 'handoff.json')).catch(() => undefined);
  if (bytes) {
    const receipt = JSON.parse(bytes.toString());
    assert.equal(receipt.status, 'incomplete'); assert.equal(receipt.exitCode, 2);
    assert.notEqual(receipt.reason, 'review_packet_created');
  }
  const markdown = await fsp.readFile(join(out, 'handoff.md'), 'utf8').catch(() => undefined);
  if (markdown !== undefined) {
    assert.ok(/incomplete/i.test(markdown), 'retained guidance must explicitly describe incomplete delivery');
    assert.equal(/\b(?:ready|rechecked)\b/.test(markdown), false, 'Markdown must not retain a successful packet state');
    assert.equal(/(?:command\s+)?exit\s*:?\s*[01]\b/i.test(markdown), false, 'Markdown must not retain success/finding command exit');
  }
  const files = await fsp.readdir(out).catch(() => []);
  assert.equal(files.some(name => /^\.handoff-.*\.tmp$/.test(name)), false, 'temporary success marker must not survive');
}

test('source handoff boundary: actual Markdown/HTML filenames remain escaped navigation data', async t => {
  for (const name of ['[review](mailto:owned-review@example.invalid).ts', '<img onerror=owned_marker>.ts']) {
    const f = await fixture(t, name), out = join(f.top, 'handoff');
    assert.equal(f.selected.location.path, name, 'use an actual collected hostile filename, not a report-only invention');
    assert.equal(await create(f, out), 0);
    const markdown = await fsp.readFile(join(out, 'handoff.md'), 'utf8');
    assert.equal(markdown.includes('[review](mailto:owned-review@example.invalid)'), false, 'raw Markdown must not become a mail link');
    assert.equal(markdown.includes('<img onerror=owned_marker>'), false, 'raw HTML must not become markup');
    assert.equal(/<mailto:[^>]*>/.test(markdown), false);
    assert.ok(markdown.replace(/\\([\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e])/g, '$1').includes(name.includes('review') ? 'review' : 'owned_marker'), 'navigation remains human-readable');
    await unchanged(f);
  }
});

test('source handoff boundary: raw payload and synthetic secret stay out of four reports and private packet, with coherent snapshot', async t => {
  const payload = 'owned-untrusted-source-marker-94a7', secret = 'ghp_SYNTHETIC_HANDOFF_SECRET_94a7123456789';
  const contents = `// ${payload}\nconst credential = "${secret}";\n${RISK}`;
  const f = await fixture(t, 'app.ts', contents), out = join(f.top, 'handoff'); assert.equal(await create(f, out), 0);
  for (const name of ['report.json', 'agent-report.json', 'report.sarif', 'report.md']) {
    const text = await fsp.readFile(join(f.reports, name), 'utf8');
    for (const raw of [payload, secret, RISK.trim(), contents.trim()]) assert.equal(text.includes(raw), false, `${name} leaked raw input`);
  }
  for (const name of ['report.json', 'agent-report.json', 'handoff.json', 'handoff.md']) {
    const text = await fsp.readFile(join(out, name), 'utf8');
    assert.equal(text.includes(payload), false, `${name} leaked marker`); assert.equal(text.includes(secret), false, `${name} leaked secret`);
  }
  assert.deepEqual(await fsp.readFile(join(out, 'report.json')), f.reportBytes);
  assert.deepEqual(await fsp.readFile(join(out, 'agent-report.json')), f.agentBytes);
  assert.equal(f.agent.reportArtifact.digest, sha(f.reportBytes));
  const inventory = f.report.checks.find((c: any) => c.id === 'source.inventory');
  const agentInventory = f.agent.checks.find((c: any) => c.checkId === 'source.inventory');
  const receipt = JSON.parse(await fsp.readFile(join(out, 'handoff.json'), 'utf8'));
  assert.deepEqual(agentInventory.sourceSnapshot, inventory.sourceSnapshot);
  assert.deepEqual(receipt.sourceBinding, inventory.sourceSnapshot);
  const sarif = JSON.parse(await fsp.readFile(join(f.reports, 'report.sarif'), 'utf8'));
  assert.deepEqual(sarif.runs[0].properties.sourceSnapshots.find((x: any) => x.checkId === 'source.inventory').sourceSnapshot, inventory.sourceSnapshot);
  assert.ok((await fsp.readFile(join(f.reports, 'report.md'), 'utf8')).includes(inventory.sourceSnapshot.digest));
  assert.equal(inventory.sourceSnapshot.filesSelected, 1); assert.equal(inventory.sourceSnapshot.bytesSelected, Buffer.byteLength(contents));
  await unchanged(f);
});

test('source handoff boundary: SIGINT during collector read refuses and leaves no ready receipt', async t => {
  const f = await fixture(t), out = join(f.top, 'cancelled'), original = fsp.open; let intercepted = false;
  t.mock.method(fsp, 'open', async (...args: any[]) => {
    const handle = await (original as any)(...args);
    if (!intercepted && String(args[0]).endsWith('/app.ts')) { intercepted = true; process.emit('SIGINT'); }
    return handle;
  });
  syncBuiltinESMExports();
  try {
    assert.equal(await create(f, out), 2); assert.equal(intercepted, true, 'cancellation happened at an actual collector read');
    await noSuccessMarker(out); await unchanged(f);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('source handoff boundary: SIGTERM after guidance publication cannot leave ready success marker', async t => {
  const f = await fixture(t), out = join(f.top, 'cancelled-late'), original = fsp.writeFile; let intercepted = false;
  t.mock.method(fsp, 'writeFile', async (...args: any[]) => {
    const result = await (original as any)(...args);
    if (!intercepted && String(args[0]).endsWith('/handoff.md')) { intercepted = true; process.emit('SIGTERM'); }
    return result;
  });
  syncBuiltinESMExports();
  try {
    assert.equal(await create(f, out), 2); assert.equal(intercepted, true, 'cancel occurred after real Markdown write');
    await noSuccessMarker(out); await unchanged(f);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('source handoff boundary: late publication I/O failure or newly occupied receipt never leaves ready authority', async t => {
  for (const failure of ['io-error', 'occupied'] as const) {
    const f = await fixture(t), out = join(f.top, 'fault'), original = fsp.link; let intercepted = false;
    t.mock.method(fsp, 'link', async (...args: any[]) => {
      if (String(args[1]).endsWith('/handoff.json')) {
        if (failure === 'io-error') { intercepted = true; throw Object.assign(new Error('owned publication fault'), { code: 'EIO' }); }
        if (!intercepted) { intercepted = true; await fsp.writeFile(String(args[1]), 'owned-occupied', { flag: 'wx', mode: 0o600 }); }
      }
      return (original as any)(...args);
    });
    syncBuiltinESMExports();
    try {
      assert.equal(await create(f, out), 2, failure); assert.equal(intercepted, true, 'fault reached final publication');
      await noSuccessMarker(out); await unchanged(f);
    } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  }
});
