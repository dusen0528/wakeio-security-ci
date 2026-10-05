import { dirname, join, relative, resolve, sep } from 'node:path';
import { constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, mkdtemp, open, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { runProcess } from './source/process.js';
import { readJsonInput } from './json-input.js';
import { providerProposal } from './repair-provider.js';

const digest = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
const SHA = /^[a-f0-9]{64}$/;
const inside = (root: string, path: string) => path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
function exact(v: unknown, keys: readonly string[]): asserts v is Record<string, unknown> {
  if (!object(v) || Object.keys(v).length !== keys.length || keys.some(k => !Object.hasOwn(v, k))) throw new Error('invalid');
}
async function readBounded(path: string, cap = 128 * 1024): Promise<string> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > cap) throw new Error('invalid');
    const bytes = Buffer.alloc(before.size + 1);
    let count = 0;
    while (count < bytes.length) {
      const read = await handle.read(bytes, count, bytes.length - count, count);
      if (!read.bytesRead) break;
      count += read.bytesRead;
    }
    const after = await handle.stat();
    if (count !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error('invalid');
    const text = bytes.subarray(0, count).toString('utf8');
    if (!Buffer.from(text).equals(bytes.subarray(0, count)) || text.includes('\0')) throw new Error('invalid');
    return text;
  } finally { await handle.close(); }
}

interface Policy {
  schema_version: 1; profile: 'sql_injection'; files: string[]; instructions: string; timeout_ms: number;
  verification: { image: string; verifier: string; verifier_sha256: string };
}
async function policyInput(options: Options): Promise<{ policy: Policy; hash: string }> {
  const text = await readBounded(options.policy, 64 * 1024);
  // Python's standard TOML parser, not eval or a permissive home-grown grammar.
  const result = await runProcess(options.python, ['-I', '-c', 'import sys,json,tomllib; json.dump(tomllib.loads(sys.stdin.read()),sys.stdout)'],
    { cwd: dirname(options.policy), timeoutMs: 5000, maxOutputBytes: 64 * 1024, input: text });
  if (result.exitCode !== 0 || result.spawnError || result.timedOut || result.outputLimitExceeded) throw new Error('invalid');
  const p: unknown = JSON.parse(result.stdout);
  exact(p, ['schema_version', 'profile', 'files', 'instructions', 'timeout_ms', 'verification']);
  exact(p.verification, ['image', 'verifier', 'verifier_sha256']);
  if (p.schema_version !== 1 || p.profile !== 'sql_injection' || typeof p.instructions !== 'string' ||
      !p.instructions.trim() || p.instructions.length > 4096 || !Number.isSafeInteger(p.timeout_ms) ||
      Number(p.timeout_ms) < 1000 || Number(p.timeout_ms) > 600000 ||
      !Array.isArray(p.files) || p.files.length < 1 || p.files.length > 8 || new Set(p.files).size !== p.files.length ||
      p.files.some(f => typeof f !== 'string' || !/^[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*\.(?:py|js|ts|mjs|json)$/.test(f)) ||
      typeof p.verification.image !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(p.verification.image) ||
      typeof p.verification.verifier !== 'string' || !p.verification.verifier || p.verification.verifier.length > 1024 ||
      typeof p.verification.verifier_sha256 !== 'string' || !SHA.test(p.verification.verifier_sha256)) throw new Error('invalid');
  return { policy: p as unknown as Policy, hash: digest(text) };
}

async function snapshot(source: string, files: string[]): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  let total = 0;
  for (const path of files) {
    let current = source;
    for (const part of path.split('/')) {
      current = join(current, part);
      if ((await lstat(current)).isSymbolicLink()) throw new Error('invalid');
    }
    const text = await readBounded(current);
    total += Buffer.byteLength(text);
    if (total > 256 * 1024) throw new Error('invalid');
    result.set(path, text);
  }
  return result;
}
async function workspace(path: string, files: Map<string, string>): Promise<void> {
  await mkdir(path, { mode: 0o755 });
  for (const [name, text] of files) {
    await mkdir(dirname(join(path, name)), { recursive: true, mode: 0o755 });
    await writeFile(join(path, name), text, { mode: 0o444, flag: 'wx' });
  }
}

interface Verification { version: 1; inputFingerprint: string; security: 'passed' | 'failed'; normal: 'passed' | 'failed' }
function verification(text: string): Verification {
  const v: unknown = JSON.parse(text);
  exact(v, ['version', 'inputFingerprint', 'security', 'normal']);
  if (v.version !== 1 || typeof v.inputFingerprint !== 'string' || !SHA.test(v.inputFingerprint) ||
      (v.security !== 'passed' && v.security !== 'failed') || (v.normal !== 'passed' && v.normal !== 'failed')) throw new Error('invalid');
  return v as unknown as Verification;
}
function replacements(value: unknown, before: Map<string, string>): Map<string, string> {
  exact(value, ['version', 'replacements']);
  if (value.version !== 1 || !Array.isArray(value.replacements) || value.replacements.length < 1 || value.replacements.length > before.size) throw new Error('invalid');
  const after = new Map(before), seen = new Set<string>();
  let total = 0;
  for (const r of value.replacements) {
    exact(r, ['path', 'beforeSha256', 'content']);
    if (typeof r.path !== 'string' || !before.has(r.path) || seen.has(r.path) || typeof r.beforeSha256 !== 'string' ||
        r.beforeSha256 !== digest(before.get(r.path)!) || typeof r.content !== 'string' || r.content.includes('\0') ||
        Buffer.byteLength(r.content) > 128 * 1024 || r.content === before.get(r.path)) throw new Error('invalid');
    seen.add(r.path); total += Buffer.byteLength(r.content);
    if (total > 256 * 1024) throw new Error('invalid');
    after.set(r.path, r.content);
  }
  if ([...after.values()].reduce((bytes, text) => bytes + Buffer.byteLength(text), 0) > 256 * 1024) throw new Error('invalid');
  return after;
}
function patch(before: Map<string, string>, after: Map<string, string>): string {
  // ponytail: snapshots are each bounded to 256 KiB; use minimal diff hunks if full-file review size becomes a measured problem.
  const lines = (text: string) => text === '' ? [] : text.replace(/\n$/, '').split('\n');
  const section = (text: string, prefix: string) => lines(text).map((line, i, all) => `${prefix}${line}\n${i === all.length - 1 && !text.endsWith('\n') ? '\\ No newline at end of file\n' : ''}`).join('');
  return [...before].filter(([name, text]) => text !== after.get(name)).map(([name, text]) => {
    const fixed = after.get(name)!;
    return `--- a/${name}\n+++ b/${name}\n@@ -${text ? 1 : 0},${lines(text).length} +${fixed ? 1 : 0},${lines(fixed).length} @@\n` + section(text, '-') + section(fixed, '+');
  }).join('');
}

const dockerArgs = (options: Options, args: string[]) => options.dockerHost ? ['--host', options.dockerHost, ...args] : args;
async function dockerRun(options: Options, p: Policy, deadline: number, command: string[], mounts: string[] = []) {
  const name = `wakeio-repair-${randomUUID()}`;
  if (Date.now() >= deadline) throw new Error('invalid');
  let result: Awaited<ReturnType<typeof runProcess>> | undefined;
  try {
    result = await runProcess(options.docker, dockerArgs(options, ['run', '--rm', '--name', name, '--pull=never', '--network=none', '--read-only',
      '--user=65534:65534', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=256m', '--cpus=1',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', ...mounts, p.verification.image, ...command]),
      { cwd: tmpdir(), timeoutMs: Math.max(1, deadline - Date.now()), maxOutputBytes: 65536 });
    return result;
  } finally {
    // Name is generated here, never supplied by target data. Kill owned containers even on CLI timeout.
    const cleanup = await runProcess(options.docker, dockerArgs(options, ['rm', '--force', name]), { cwd: tmpdir(), timeoutMs: 5000, maxOutputBytes: 1024 });
    const alreadyRemoved = cleanup.exitCode === 1 &&
      [
        `Error response from daemon: No such container: ${name}`,
        `No such container: ${name}`,
      ].includes(cleanup.stderr.trim());
    if (result && completed(result) && (!completed(cleanup) || (cleanup.exitCode !== 0 && !alreadyRemoved))) {
      throw new Error('container_cleanup_unverified');
    }
  }
}
const completed = (r: Awaited<ReturnType<typeof runProcess>>) => !r.spawnError && !r.timedOut && !r.outputLimitExceeded && r.signal === null;

const HELP = `Usage:
  wakeio-security-ci repair --source DIR --policy FILE --out NEW_DIR --proposal FILE
  wakeio-security-ci repair --source DIR --policy FILE --out NEW_DIR --agent codex|claude --allow-source-upload

Opt-in, isolated repair. Generates private patch and verification artifacts only.
Requires a trusted TOML policy, Python 3.11+, and a prepared local Docker image.
No source upload without --allow-source-upload. No original writes, commit or push.
Options: --python PATH, --docker PATH, --docker-host unix:///absolute/socket, --agent-path PATH
Exit: 0 declared verification passed; 1 patch failed security checks; 2 incomplete/error.
`;

interface Options {
  source: string; policy: string; out: string; proposal?: string;
  agent?: 'codex' | 'claude'; upload: boolean; python: string; docker: string; dockerHost?: string; agentPath?: string;
}

function parse(args: readonly string[]): Options {
  const flags = new Map<string, string>();
  let upload = false;
  for (let i = 1; i < args.length; i++) {
    const key = args[i];
    if (key === '--allow-source-upload' && !upload) { upload = true; continue; }
    if (!['--source', '--policy', '--out', '--proposal', '--agent', '--python', '--docker', '--docker-host', '--agent-path'].includes(key) ||
        flags.has(key) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('invalid_arguments');
    flags.set(key, args[++i]);
  }
  if (!flags.has('--source') || !flags.has('--policy') || !flags.has('--out') ||
      flags.has('--proposal') === flags.has('--agent') ||
      (flags.has('--agent') && !['codex', 'claude'].includes(flags.get('--agent')!)) ||
      (upload && !flags.has('--agent')) || (flags.has('--agent-path') && !flags.has('--agent')) ||
      (flags.has('--docker-host') && !/^unix:\/\/\/[a-zA-Z0-9_./-]+$/.test(flags.get('--docker-host')!))) throw new Error('invalid_arguments');
  return { source: resolve(flags.get('--source')!), policy: resolve(flags.get('--policy')!), out: resolve(flags.get('--out')!),
    proposal: flags.get('--proposal'), agent: flags.get('--agent') as Options['agent'], upload,
    python: flags.get('--python') ?? 'python3', docker: flags.get('--docker') ?? 'docker', dockerHost: flags.get('--docker-host'), agentPath: flags.get('--agent-path') };
}

export async function repairMain(args: readonly string[]): Promise<number> {
  if (args.length === 2 && args[1] === '--help') { process.stdout.write(HELP); return 0; }
  let out: string | undefined;
  let reason = 'invalid_arguments';
  let temporary: string | undefined;
  const report: Record<string, unknown> = { version: 1, status: 'error', verified: false };
  let code = 2;
  try {
    const options = parse(args);
    const source = await realpath(options.source);
    const output = join(await realpath(dirname(options.out)), relative(dirname(options.out), options.out));
    if (!(await lstat(options.source)).isDirectory() || inside(source, output)) throw new Error('invalid');
    await mkdir(output, { mode: 0o700 });
    out = output;
    if (options.agent && !options.upload) { reason = 'agent_consent_required'; throw new Error('invalid'); }
    reason = 'invalid_policy';
    const { policy: p, hash } = await policyInput(options);
    report.policySha256 = hash;
    report.provider = options.agent ?? 'none';
    report.scope = 'declared-sql-regression-and-normal-control';
    reason = 'invalid_snapshot';
    const before = await snapshot(source, p.files);
    report.snapshotSha256 = digest(JSON.stringify([...before].map(([name, text]) => [name, digest(text)])));
    const verifierPath = resolve(dirname(options.policy), p.verification.verifier);
    if (inside(source, await realpath(verifierPath))) throw new Error('invalid');
    const verifier = await readBounded(verifierPath);
    if (digest(verifier) !== p.verification.verifier_sha256) throw new Error('invalid');
    report.verifierSha256 = digest(verifier);
    report.image = p.verification.image;
    const deadline = Date.now() + p.timeout_ms;
    reason = 'sandbox_unavailable';
    const server = await runProcess(options.docker, dockerArgs(options, ['info', '--format', '{{.ServerVersion}}']), { cwd: tmpdir(), timeoutMs: 5000, maxOutputBytes: 1024 });
    const image = await runProcess(options.docker, dockerArgs(options, ['image', 'inspect', '--format', '{{.Id}}', p.verification.image]), { cwd: tmpdir(), timeoutMs: 5000, maxOutputBytes: 1024 });
    if (!completed(server) || server.exitCode !== 0 || !/^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$/.test(server.stdout.trim()) ||
        !completed(image) || image.exitCode !== 0 || image.stdout.trim() !== p.verification.image) throw new Error('invalid');
    report.dockerVersion = server.stdout.trim();
    const runtime = await dockerRun(options, p, deadline, ['python3', '-I', '-c',
      'import platform,sqlite3,json; print(json.dumps({"python":platform.python_version(),"sqlite":sqlite3.sqlite_version}))']);
    if (!completed(runtime) || runtime.exitCode !== 0) throw new Error('invalid');
    const actual: unknown = JSON.parse(runtime.stdout);
    exact(actual, ['python', 'sqlite']);
    if ([actual.python, actual.sqlite].some(v => typeof v !== 'string' || !/^\d+\.\d+\.\d+$/.test(v))) throw new Error('invalid');
    report.runtime = actual;
    temporary = await mkdtemp(join(tmpdir(), 'wakeio-repair-run-'));
    const original = join(temporary, 'before'), fixed = join(temporary, 'after'), checks = join(temporary, 'verifier');
    await workspace(original, before);
    await workspace(checks, new Map([['check.py', verifier]]));
    const execute = (path: string) => dockerRun(options, p, deadline, ['python3', '-I', '/verifier/check.py', '/workspace'],
      ['--mount', `type=bind,source=${path},target=/workspace,readonly`, '--mount', `type=bind,source=${checks},target=/verifier,readonly`]);
    reason = 'baseline_incomplete';
    const red = await execute(original);
    if (!completed(red)) throw new Error('invalid');
    const baseline = verification(red.stdout);
    report.before = baseline;
    if (red.exitCode !== 10 || baseline.security !== 'failed' || baseline.normal !== 'passed') {
      reason = red.exitCode === 0 && baseline.security === 'passed' ? 'not_reproduced' : 'baseline_incomplete';
      throw new Error('invalid');
    }
    report.reproduced = true;
    reason = 'invalid_proposal';
    let proposal: unknown;
    if (options.agent) {
      reason = 'agent_execution_incomplete';
      const providerDir = join(temporary, 'provider');
      await mkdir(providerDir, { mode: 0o700 });
      try {
        const result = await providerProposal(options.agent, options.agentPath, providerDir, deadline, before, p.instructions);
        proposal = result.proposal; report.providerVersion = result.version; report.providerExecutableSha256 = result.executableSha256;
        report.model = 'unknown'; report.cost = 'unknown';
      } catch (error) {
        const allowed = ['agent_unavailable', 'agent_authentication_missing', 'agent_policy_unsupported', 'agent_budget_exhausted',
          'agent_execution_failed', 'agent_protocol_invalid', 'agent_tools_not_allowed'];
        if (error instanceof Error && allowed.includes(error.message)) reason = error.message;
        throw error;
      }
    } else proposal = await readJsonInput(resolve(options.proposal!), 512 * 1024);
    reason = 'invalid_proposal';
    const after = replacements(proposal, before);
    const diff = patch(before, after);
    await writeFile(join(out, 'changes.patch'), diff, { mode: 0o600, flag: 'wx' });
    report.patchSha256 = digest(diff);
    report.changedFiles = [...before.keys()].filter(name => before.get(name) !== after.get(name));
    await workspace(fixed, after);
    reason = 'verification_incomplete';
    const green = await execute(fixed);
    if (!completed(green)) throw new Error('invalid');
    const verified = verification(green.stdout);
    report.after = verified;
    if (verified.inputFingerprint !== baseline.inputFingerprint) throw new Error('invalid');
    if (green.exitCode === 0 && verified.security === 'passed' && verified.normal === 'passed') {
      report.status = 'verified'; report.verified = true; reason = 'declared_checks_passed'; code = 0;
    } else if (green.exitCode === 10 && verified.security === 'failed' && verified.normal === 'passed') {
      report.status = 'unverified'; reason = 'security_assertion_failed'; code = 1;
    } else throw new Error('invalid');
    reason = 'source_changed';
    if (digest(JSON.stringify([...await snapshot(source, p.files)])) !== digest(JSON.stringify([...before]))) throw new Error('invalid');
    reason = code === 0 ? 'declared_checks_passed' : 'security_assertion_failed';
  } catch (error) {
    if (error instanceof Error && error.message === 'container_cleanup_unverified') reason = error.message;
    report.status = 'error'; report.verified = false; code = 2;
  } finally {
    if (temporary) await rm(temporary, { recursive: true, force: true });
  }
  report.reason = reason;
  if (out) {
    try { await writeFile(join(out, 'repair.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' }); }
    catch { code = 2; reason = 'artifact_delivery_failed'; }
  }
  process.stdout.write(`Repair ${code === 0 ? 'VERIFIED declared checks only' : code === 1 ? 'UNVERIFIED patch' : 'INCOMPLETE'}: ${reason}.\n`);
  return code;
}
