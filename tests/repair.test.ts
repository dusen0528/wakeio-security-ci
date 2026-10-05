import test from 'node:test';
import assert from 'node:assert/strict';
import { main } from '../src/cli.js';
import { chmod, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-repair-'));
  const source = join(root, 'source');
  await mkdir(source);
  await writeFile(join(source, 'query.py'), `def lookup(db, name):
    return db.execute("SELECT name FROM users WHERE name = '" + name + "'").fetchall()
`);
  const verifier = '# trusted verifier placeholder\n';
  await writeFile(join(root, 'check.py'), verifier);
  const policy = `schema_version = 1\nprofile = "sql_injection"\nfiles = ["query.py"]\ninstructions = "Use SQL parameter binding; preserve normal queries."\ntimeout_ms = 10000\n[verification]\nimage = "sha256:${'a'.repeat(64)}"\nverifier = "check.py"\nverifier_sha256 = "${sha(verifier)}"\n`;
  await writeFile(join(root, 'policy.toml'), policy);
  await writeFile(join(root, 'proposal.json'), JSON.stringify({ version: 1, replacements: [] }));
  return { root, source, policy, args: ['repair', '--source', source, '--policy', join(root, 'policy.toml'),
    '--out', join(root, 'output'), '--proposal', join(root, 'proposal.json'), '--docker', '/missing/docker'] };
}

test('repair is a separate opt-in CLI boundary with its own help and strict arguments', async () => {
  assert.equal(await main(['repair', '--help']), 0);
  assert.equal(await main(['repair', '--unknown']), 2);
  assert.equal(await main(['repair']), 2);
});

test('repair replays a fixed SQL assertion before/after and delivers a private patch without changing the source', async () => {
  const f = await fixture();
  try {
    const original = await readFile(join(f.source, 'query.py'), 'utf8');
    const fixed = 'def lookup(db, name):\n    return db.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()\n';
    const verifier = await readFile(join(process.cwd(), 'examples', 'repair-sql-verifier.py'), 'utf8');
    await writeFile(join(f.root, 'check.py'), verifier);
    await writeFile(join(f.root, 'policy.toml'), f.policy.replace(sha('# trusted verifier placeholder\n'), sha(verifier)));
    await writeFile(join(f.root, 'proposal.json'), JSON.stringify({ version: 1, replacements: [{ path: 'query.py', beforeSha256: sha(original), content: fixed }] }));
    const docker = fileURLToPath(new URL('../../tests/fixtures/repair-docker.py', import.meta.url));
    await chmod(docker, 0o755);
    const args = [...f.args]; args[args.length - 1] = docker;
    assert.equal(await main(args), 0);
    const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
    assert.equal(report.status, 'verified');
    assert.equal(report.before.security, 'failed');
    assert.equal(report.after.security, 'passed');
    assert.equal(report.before.inputFingerprint, report.after.inputFingerprint);
    assert.match(report.runtime.sqlite, /^3\.\d+\.\d+$/);
    assert.equal(report.provider, 'none');
    assert.equal(await readFile(join(f.source, 'query.py'), 'utf8'), original);
    assert.match(await readFile(join(f.root, 'output', 'changes.patch'), 'utf8'), /\+.*execute\("SELECT name FROM users WHERE name = \?"/);
    assert.deepEqual(await readdir(f.source), ['query.py']);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('repair rejects unknown policy fields and non-string instructions with an incomplete artifact', async () => {
  for (const invalid of ['\nunknown = true\n', '\ninstructions = ["bind parameters"]\n']) {
    const f = await fixture();
    try {
      const policy = invalid.includes('instructions') ? f.policy.replace('instructions = "Use SQL parameter binding; preserve normal queries."', 'instructions = ["bind parameters"]')
        : f.policy.replace('[verification]', 'unknown = true\n[verification]');
      await writeFile(join(f.root, 'policy.toml'), policy);
      assert.equal(await main(f.args), 2);
      const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
      assert.equal(report.status, 'error');
      assert.equal(report.reason, 'invalid_policy');
      assert.equal(report.verified, false);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  }
});

test('repair accepts an explicit local Docker socket without inheriting caller daemon settings', async () => {
  const f = await fixture();
  const saved = process.env.DOCKER_HOST;
  try {
    process.env.DOCKER_HOST = 'tcp://must-not-connect.invalid:2375';
    const original = await readFile(join(f.source, 'query.py'), 'utf8');
    const verifier = await readFile(join(process.cwd(), 'examples', 'repair-sql-verifier.py'), 'utf8');
    await writeFile(join(f.root, 'check.py'), verifier);
    await writeFile(join(f.root, 'policy.toml'), f.policy.replace(sha('# trusted verifier placeholder\n'), sha(verifier)));
    await writeFile(join(f.root, 'proposal.json'), JSON.stringify({ version: 1, replacements: [{ path: 'query.py', beforeSha256: sha(original),
      content: 'def lookup(db, name):\n    return db.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()\n' }] }));
    const args = [...f.args];
    const driver = await readFile(join(process.cwd(), 'tests', 'fixtures', 'repair-docker.py'), 'utf8');
    const socketDriver = join(f.root, 'socket-only-docker.py');
    await writeFile(socketDriver, driver.replace('args = sys.argv[1:]', 'args = sys.argv[1:]\nif args[:1] != ["--host"]: sys.exit(94)'));
    args[args.length - 1] = socketDriver;
    await chmod(args[args.length - 1], 0o755);
    args.push('--docker-host', 'unix:///tmp/wakeio-test-docker.sock');
    assert.equal(await main(args), 0);
    const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
    assert.equal(report.verified, true);
    args[args.length - 1] = 'tcp://127.0.0.1:2375';
    args[args.indexOf('--out') + 1] = join(f.root, 'refused');
    assert.equal(await main(args), 2);
    assert.equal(await readFile(join(f.source, 'query.py'), 'utf8'), original);
  } finally {
    if (saved === undefined) delete process.env.DOCKER_HOST; else process.env.DOCKER_HOST = saved;
    await rm(f.root, { recursive: true, force: true });
  }
});

test('agent repair requires explicit upload consent and never falls back to an offline proposal', async () => {
  const f = await fixture();
  try {
    const args = f.args.slice(0, f.args.indexOf('--proposal'));
    args.push('--agent', 'codex', '--agent-path', '/must/not/run');
    assert.equal(await main(args), 2);
    const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
    assert.equal(report.reason, 'agent_consent_required');
    assert.equal(report.verified, false);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('selected Codex and Claude adapters return proposals, not trusted success; only named authentication reaches the provider', async () => {
  for (const agent of ['codex', 'claude']) {
    const f = await fixture();
    const variable = agent === 'codex' ? 'CODEX_API_KEY' : 'ANTHROPIC_API_KEY';
    const saved = process.env[variable], canary = process.env.WAKEIO_TEST_SECRET_CANARY;
    try {
      process.env[variable] = 'synthetic-test-auth';
      process.env.WAKEIO_TEST_SECRET_CANARY = 'must-not-forward';
      const verifier = await readFile(join(process.cwd(), 'examples', 'repair-sql-verifier.py'), 'utf8');
      await writeFile(join(f.root, 'check.py'), verifier);
      await writeFile(join(f.root, 'policy.toml'), f.policy.replace(sha('# trusted verifier placeholder\n'), sha(verifier)));
      const docker = join(process.cwd(), 'tests', 'fixtures', 'repair-docker.py');
      const provider = join(process.cwd(), 'tests', 'fixtures', 'repair-provider.py');
      await chmod(docker, 0o755); await chmod(provider, 0o755);
      const args = f.args.slice(0, f.args.indexOf('--proposal'));
      args.push('--agent', agent, '--allow-source-upload', '--agent-path', provider, '--docker', docker);
      assert.equal(await main(args), 0);
      const reportText = await readFile(join(f.root, 'output', 'repair.json'), 'utf8');
      const report = JSON.parse(reportText);
      assert.equal(report.provider, agent);
      assert.equal(report.providerVersion, 'test-provider 1.0.0');
      assert.equal(report.before.security, 'failed');
      assert.equal(report.after.security, 'passed');
      assert.equal(reportText.includes('synthetic-test-auth'), false);
      assert.equal(reportText.includes('must-not-forward'), false);
    } finally {
      if (saved === undefined) delete process.env[variable]; else process.env[variable] = saved;
      if (canary === undefined) delete process.env.WAKEIO_TEST_SECRET_CANARY; else process.env.WAKEIO_TEST_SECRET_CANARY = canary;
      await rm(f.root, { recursive: true, force: true });
    }
  }
});

test('target code cannot forge the frozen verifier result by printing success and exiting', async () => {
  const f = await fixture();
  try {
    const original = await readFile(join(f.source, 'query.py'), 'utf8');
    const verifier = await readFile(join(process.cwd(), 'examples', 'repair-sql-verifier.py'), 'utf8');
    await writeFile(join(f.root, 'check.py'), verifier);
    await writeFile(join(f.root, 'policy.toml'), f.policy.replace(sha('# trusted verifier placeholder\n'), sha(verifier)));
    const forged = `import hashlib,json,sys
def lookup(db, name):
    samples = {"normal":"alice","attack":"' OR 1=1 --"}
    fp = hashlib.sha256(json.dumps(samples,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    print(json.dumps({"version":1,"inputFingerprint":fp,"security":"passed","normal":"passed"}))
    sys.exit(0)
`;
    await writeFile(join(f.root, 'proposal.json'), JSON.stringify({ version: 1, replacements: [{ path: 'query.py', beforeSha256: sha(original), content: forged }] }));
    const docker = join(process.cwd(), 'tests', 'fixtures', 'repair-docker.py');
    await chmod(docker, 0o755);
    const args = [...f.args]; args[args.length - 1] = docker;
    assert.equal(await main(args), 2);
    const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
    assert.equal(report.verified, false);
    assert.equal(report.reason, 'verification_incomplete');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('skipped, wrong-type and changed-input verification cannot become a verified patch', async () => {
  for (const after of [
    { security: 'skipped', inputFingerprint: 'd'.repeat(64) },
    { security: ['passed'], inputFingerprint: 'd'.repeat(64) },
    { security: 'passed', inputFingerprint: 'e'.repeat(64) },
  ]) {
    const f = await fixture();
    try {
      const original = await readFile(join(f.source, 'query.py'), 'utf8');
      const verifier = `import json,sys\nbefore = sys.argv[1].endswith('/before')\nr = {"version":1,"normal":"passed","security":"failed","inputFingerprint":"${'d'.repeat(64)}"}\nif not before: r.update(${JSON.stringify(after)})\nprint(json.dumps(r))\nsys.exit(10 if before else 0)\n`;
      await writeFile(join(f.root, 'check.py'), verifier);
      await writeFile(join(f.root, 'policy.toml'), f.policy.replace(sha('# trusted verifier placeholder\n'), sha(verifier)));
      await writeFile(join(f.root, 'proposal.json'), JSON.stringify({ version: 1, replacements: [{ path: 'query.py', beforeSha256: sha(original), content: original + '# changed\n' }] }));
      const docker = join(process.cwd(), 'tests', 'fixtures', 'repair-docker.py');
      await chmod(docker, 0o755);
      const args = [...f.args]; args[args.length - 1] = docker;
      assert.equal(await main(args), 2);
      const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
      assert.equal(report.verified, false);
      assert.equal(report.reason, 'verification_incomplete');
    } finally { await rm(f.root, { recursive: true, force: true }); }
  }
});

test('unavailable isolation cannot report a fix or deliver an unverified patch as success', async () => {
  const f = await fixture();
  try {
    assert.equal(await main(f.args), 2);
    const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
    assert.equal(report.reason, 'sandbox_unavailable');
    assert.equal(report.verified, false);
    assert.deepEqual(await readdir(join(f.root, 'output')), ['repair.json']);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('source symlinks and an output inside the source are refused without following or modifying targets', async () => {
  const f = await fixture();
  try {
    await writeFile(join(f.root, 'outside.py'), 'private_test_canary\n');
    await rm(join(f.source, 'query.py'));
    await symlink(join(f.root, 'outside.py'), join(f.source, 'query.py'));
    assert.equal(await main(f.args), 2);
    const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
    assert.equal(report.reason, 'invalid_snapshot');
    assert.equal(JSON.stringify(report).includes('private_test_canary'), false);
    const args = [...f.args]; args[args.indexOf('--out') + 1] = join(f.source, 'output');
    assert.equal(await main(args), 2);
    assert.deepEqual(await readdir(f.source), ['query.py']);
    assert.equal(await readFile(join(f.root, 'outside.py'), 'utf8'), 'private_test_canary\n');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('unconfirmed container cleanup is an execution failure, not verified completion', async () => {
  const f = await fixture();
  try {
    const verifier = await readFile(join(process.cwd(), 'examples', 'repair-sql-verifier.py'), 'utf8');
    const original = await readFile(join(f.source, 'query.py'), 'utf8');
    await writeFile(join(f.root, 'check.py'), verifier);
    await writeFile(join(f.root, 'policy.toml'), f.policy.replace(sha('# trusted verifier placeholder\n'), sha(verifier)));
    await writeFile(join(f.root, 'proposal.json'), JSON.stringify({ version: 1, replacements: [{ path: 'query.py', beforeSha256: sha(original),
      content: 'def lookup(db, name):\n    return db.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()\n' }] }));
    const driver = await readFile(join(process.cwd(), 'tests', 'fixtures', 'repair-docker.py'), 'utf8');
    const docker = join(f.root, 'broken-cleanup.py');
    await writeFile(docker, driver.replace('elif args[:1] == ["rm"]:\n    pass', 'elif args[:1] == ["rm"]:\n    sys.exit(50)'));
    await chmod(docker, 0o755);
    const args = [...f.args]; args[args.length - 1] = docker;
    assert.equal(await main(args), 2);
    const report = JSON.parse(await readFile(join(f.root, 'output', 'repair.json'), 'utf8'));
    assert.equal(report.reason, 'container_cleanup_unverified');
    assert.equal(report.verified, false);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
