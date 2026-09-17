import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, mkdir, symlink, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runSource } from '../src/source.js';
import { runUrl } from '../src/url.js';
import { createReport, writeReports, exitCode } from '../src/report.js';
import type { CheckResult } from '../src/contracts.js';

const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const now = '2026-09-15T00:00:00.000Z';
async function scratch() { return mkdtemp(join(tmpdir(), 'wakeio-ci-acceptance-')); }
async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === 'object');
  return `http://127.0.0.1:${addr.port}`;
}
async function close(server: Server) {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((e) => e ? reject(e) : resolve()));
}
const hasIncomplete = (checks: CheckResult[]) => checks.some((c) => ['error', 'partial', 'skipped'].includes(c.status));

test('acceptance: a missing required scanner cannot pass even with failure threshold disabled', async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, 'app.ts'), 'export const answer = 42;\n');
    const checks = await runSource({ root, tools: ['gitleaks'], toolPaths: { gitleaks: join(root, 'absent') }, timeoutMs: 1000 });
    assert.ok(hasIncomplete(checks));
    assert.equal(exitCode(createReport(checks, 'source', now), 'none'), 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('acceptance: a native finding exit with empty findings is contradictory and cannot pass', async () => {
  const top = await scratch();
  const root = join(top, 'source');
  try {
    await mkdir(root);
    await writeFile(join(root, 'app.ts'), 'export const answer = 42;\n');
    const fake = join(top, 'gitleaks');
    await writeFile(fake, '#!/usr/bin/env node\nif (process.argv.includes("version") || process.argv.includes("--version")) { console.log("8.30.1"); } else { console.log("[]"); process.exitCode = 1; }\n');
    await chmod(fake, 0o700);
    const checks = await runSource({ root, tools: ['gitleaks'], toolPaths: { gitleaks: fake }, timeoutMs: 1000 });
    assert.ok(hasIncomplete(checks));
    assert.equal(exitCode(createReport(checks, 'source', now), 'none'), 2);
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('acceptance: Terraform references requiring external resolution never reach the native scanner', async () => {
  const cases = [
    ['main.tf', 'module "remote" /* comment */ { source = "http://127.0.0.1/module.zip" }'],
    ['main.tf', 'module "escape" { source = "../../../../outside" }'],
    ['main.tf', 'locals { value = file /* comment */ ("/outside/secret") }'],
    ['main.tf', 'locals { value = filesha256("/outside/secret") }'],
    ['main.tf.json', '{"mo\\u0064ule":{"remote":{"source":"http://127.0.0.1/module.zip"}}}']
  ];
  for (const [name, content] of cases) {
    const top = await scratch();
    const root = join(top, 'source');
    try {
      await mkdir(root);
      await writeFile(join(root, name), content);
      const fake = join(top, 'trivy');
      const marker = join(top, 'NATIVE_WAS_INVOKED');
      await writeFile(fake, '#!/usr/bin/env node\nif (process.argv.includes("--version")) { console.log("Version: 0.74.0"); } else { require("node:fs").writeFileSync(' + JSON.stringify(marker) + ', "unsafe input reached native tool"); process.exitCode=2; }\n');
      await chmod(fake, 0o700);
      const checks = await runSource({ root, tools: ['trivy'], toolPaths: { trivy: fake }, timeoutMs: 1000 });
      assert.equal(exitCode(createReport(checks, 'source', now), 'none'), 2);
      await assert.rejects(readFile(marker), `unsafe config reached scanner: ${name}`);
    } finally { await rm(top, { recursive: true, force: true }); }
  }
});

test('acceptance: file limits cannot be reported as a complete source scan', async () => {
  const root = await scratch();
  try {
    for (let i = 0; i < 4; i++) await writeFile(join(root, `file${i}.ts`), `export const item${i} = 1;\n`);
    const checks = await runSource({ root, tools: [], maxFiles: 1 });
    assert.ok(hasIncomplete(checks));
    assert.equal(exitCode(createReport(checks, 'source', now), 'none'), 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('acceptance: source scan never follows a symlink to outside source or executes target scripts', async () => {
  const top = await scratch();
  const root = join(top, 'source');
  try {
    await mkdir(root);
    await writeFile(join(top, 'outside.env'), 'PASSWORD=synthetic_outside_password_6CYwg64\n');
    await symlink(join(top, 'outside.env'), join(root, 'linked.env'));
    await writeFile(join(root, 'package.json'), JSON.stringify({ name: 'synthetic-fixture', scripts: { postinstall: 'touch SCRIPT_EXECUTED' } }));
    await writeFile(join(root, 'app.ts'), 'export const ok = true;\n');
    const checks = await runSource({ root, tools: [] });
    const data = JSON.stringify(checks);
    assert.equal(data.includes('synthetic_outside_password_6CYwg64'), false);
    await assert.rejects(readFile(join(root, 'SCRIPT_EXECUTED')));
    assert.ok(checks.some(c => c.notes.some(n => /symlink|symbolic|excluded|link/i.test(n))));
  } finally { await rm(top, { recursive: true, force: true }); }
});

test('acceptance: default URL mode blocks loopback before sending an HTTP request', async () => {
  let requests = 0;
  const server = createServer((_req, res) => { requests++; res.end('hello'); });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, timeoutMs: 500 });
    assert.equal(requests, 0);
    assert.ok(hasIncomplete(checks));
    assert.equal(exitCode(createReport(checks, 'url', now), 'none'), 2);
  } finally { await close(server); }
});

test('acceptance: explicitly local URL mode inspects a linked script and redacts the fake secret', async () => {
  const token = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0'.repeat(2);
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(req.url ?? '');
    if (req.url === '/app.js') {
      res.setHeader('Content-Type', 'application/javascript');
      res.end(`const apiKey = '${token}'; document.body.innerHTML = location.hash;`);
    } else {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Set-Cookie', 'session=synthetic_cookie_value_b6Da35; Path=/');
      res.end('<!doctype html><html><script src="/app.js"></script></html>');
    }
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 3000 });
    assert.ok(requests.includes('/app.js'));
    assert.ok(checks.flatMap(c => c.findings).some(f => /dom|sink|innerhtml/i.test(`${f.ruleId} ${f.title} ${f.description}`)));
    const data = JSON.stringify(createReport(checks, 'url', now));
    assert.equal(data.includes(token), false);
    assert.equal(data.includes('synthetic_cookie_value_b6Da35'), false);
  } finally { await close(server); }
});

test('acceptance: redirects and script references do not make cross-origin requests', async () => {
  let outsideRequests = 0;
  const outside = createServer((_req, res) => { outsideRequests++; res.end('outside'); });
  const outsideUrl = await listen(outside);
  const server = createServer((req, res) => {
    if (req.url === '/redirect.js') { res.writeHead(302, { Location: outsideUrl + '/escape.js' }); res.end(); }
    else { res.setHeader('Content-Type', 'text/html'); res.end(`<script src="${outsideUrl}/foreign.js"></script><script src="/redirect.js"></script>`); }
  });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, timeoutMs: 1000 });
    assert.equal(outsideRequests, 0);
    assert.ok(hasIncomplete(checks), 'failed linked script must remain incomplete');
  } finally { await close(server); await close(outside); }
});

test('acceptance: body size and network failure cannot produce a clean report', async () => {
  const server = createServer((_req, res) => { res.setHeader('Content-Type', 'text/html'); res.end('a'.repeat(32768)); });
  const url = await listen(server);
  try {
    const checks = await runUrl({ url, allowPrivate: true, maxBytes: 1024, timeoutMs: 1000 });
    assert.equal(exitCode(createReport(checks, 'url', now), 'none'), 2);
  } finally { await close(server); }
});

test('acceptance: report pipeline preserves candidate labels, error priority, and all three files', async () => {
  const root = await scratch();
  const checks: CheckResult[] = [{ id: 'fixture', status: 'completed', notes: [], findings: [{ ruleId: 'FIXTURE-001', severity: 'high', kind: 'candidate', confidence: 'low', title: 'Test candidate', description: 'Needs verification', location: { path: 'src/app.ts', line: 4 }, remediation: 'Validate input.' }] }];
  try {
    const report = createReport(checks, 'source', now);
    assert.equal(exitCode(report, 'high'), 1);
    assert.equal(exitCode(report, 'critical'), 0);
    await writeReports(report, root);
    const json = JSON.parse(await readFile(join(root, 'report.json'), 'utf8'));
    assert.equal(json.checks[0].findings[0].kind, 'candidate');
    const sarif = JSON.parse(await readFile(join(root, 'report.sarif'), 'utf8'));
    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.runs[0].results.length > 0);
    assert.ok((await readFile(join(root, 'report.md'), 'utf8')).length > 30);
    assert.equal(exitCode(createReport([...checks, { id: 'failed', status: 'error', notes: ['timeout'], findings: [] }], 'source', now), 'none'), 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('acceptance: report output does not overwrite a symlink target', async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, 'preserve.txt'), 'KEEP_THIS');
    await symlink(join(root, 'preserve.txt'), join(root, 'report.json'));
    const report = createReport([{ id: 'clean', status: 'completed', findings: [], notes: [] }], 'source', now);
    try { await writeReports(report, root); } catch { /* a rejected output is acceptable */ }
    assert.equal(await readFile(join(root, 'preserve.txt'), 'utf8'), 'KEEP_THIS');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('acceptance: CLI rejects invalid flags and a missing target with configuration exit code 2', async () => {
  for (const args of [['scan', '--typo'], ['scan']]) {
    try { await exec(process.execPath, [cli, ...args]); assert.fail('CLI accepted invalid options'); }
    catch (error) { assert.equal((error as { code?: number }).code, 2); }
  }
});
