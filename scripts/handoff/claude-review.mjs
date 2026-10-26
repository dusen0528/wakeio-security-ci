#!/usr/bin/env node
// Codex가 체크포인트·게이트마다 호출하는 비대화식 Claude 리뷰 래퍼.
// 사용: node scripts/handoff/claude-review.mjs --request .handoff/M1-CP2.request.md
//        [--auth login|api-key] [--budget-usd 3] [--max-turns 80] [--timeout-min 40] [--claude PATH]
// 종료 코드: 0 승인 · 10 수정 요청 · 11 BLOCKED · 12 사람 판단 필요 · 2 실행 오류
// 이 파일과 docs/runtime-verify/prompts/* 는 Codex가 수정하지 않는다 (HANDOFF.md 규칙 8).
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const MAX_ROUNDS = 3;
const sha = (data) => createHash('sha256').update(data).digest('hex');
const fail = (message, code = 2) => { console.error(`claude-review: ${message}`); process.exit(code); };
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
const git = (args, cwd) => {
  const r = run('git', args, { cwd });
  if (r.status !== 0) fail(`git ${args.join(' ')} failed: ${r.stderr.trim()}`);
  return r.stdout.trim();
};

function parseArgs(argv) {
  const opts = { auth: 'login', budgetUsd: '3', maxTurns: '80', timeoutMin: '40', claude: process.env.WAKEIO_CLAUDE_BIN || 'claude' };
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i], value = argv[i + 1];
    if (value === undefined) fail(`missing value for ${key}`);
    if (key === '--request') opts.request = value;
    else if (key === '--auth') opts.auth = value;
    else if (key === '--budget-usd') opts.budgetUsd = value;
    else if (key === '--max-turns') opts.maxTurns = value;
    else if (key === '--timeout-min') opts.timeoutMin = value;
    else if (key === '--claude') opts.claude = value;
    else fail(`unknown option ${key}`);
  }
  if (!opts.request) fail('--request is required');
  if (!['login', 'api-key'].includes(opts.auth)) fail('--auth must be login or api-key');
  return opts;
}

const opts = parseArgs(process.argv.slice(2));
const root = git(['rev-parse', '--show-toplevel'], process.cwd());
const name = basename(opts.request);
const match = /^(M[0-5]-(CP[0-9]+|CPx[0-9]*|GATE))(-r[0-9]+)?\.request\.md$/.exec(name);
if (!opts.request.replace(/^\.\//, '').startsWith('.handoff/') || !match) fail('request must be .handoff/M<N>-<CP|GATE>[-rK].request.md');
const prefix = match[1];
const mode = match[2] === 'GATE' ? 'gate' : 'review';
const requestPath = join(root, '.handoff', name);
if (!existsSync(requestPath)) fail(`request not found: ${requestPath}`);

// 1) 작업 트리가 깨끗하고 요청서의 head SHA가 실제 HEAD와 같아야 한다.
if (git(['status', '--porcelain'], root) !== '') fail('working tree is not clean; commit before requesting review');
const head = git(['rev-parse', 'HEAD'], root);
const request = readFileSync(requestPath, 'utf8');
const declared = /head SHA:\s*([0-9a-f]{7,40})/i.exec(request)?.[1];
if (!declared || !head.startsWith(declared)) fail(`request head SHA (${declared ?? 'missing'}) != HEAD (${head})`);

// 2) 같은 체크포인트 왕복 횟수 제한. 넘으면 사람이 판단한다.
const rounds = readdirSync(join(root, '.handoff')).filter((f) => f.startsWith(prefix) && f.endsWith('.response.json')).length;
if (rounds >= MAX_ROUNDS) fail(`${prefix} already has ${rounds} review rounds; human decision required`, 12);

// 3) 리뷰 대상 커밋의 임시 worktree. 원래 작업 트리는 건드리지 않는다.
const work = mkdtempSync(join(tmpdir(), 'wakeio-review-'));
const tree = join(work, 'wt');
git(['worktree', 'add', '--detach', tree, head], root);
cpSync(join(root, '.handoff'), join(tree, '.handoff'), { recursive: true });

const here = fileURLToPath(import.meta.url);
const templatePath = join(root, 'docs/runtime-verify/prompts', `${mode}.md`);
const schemaPath = join(root, 'docs/runtime-verify/prompts/response.schema.json');
const template = readFileSync(templatePath, 'utf8');
const schema = readFileSync(schemaPath, 'utf8');
const prompt = template.replaceAll('{{REQUEST}}', `.handoff/${name}`).replaceAll('{{HEAD}}', head).replaceAll('{{PREFIX}}', prefix);

const allowed = [
  'Read', 'Grep', 'Glob',
  'Bash(git diff:*)', 'Bash(git log:*)', 'Bash(git show:*)', 'Bash(git status:*)', 'Bash(git rev-parse:*)',
  'Bash(npm ci --ignore-scripts:*)', 'Bash(npm run build:*)', 'Bash(node --test:*)', 'Bash(npm test:*)',
  'Bash(shasum -a 256:*)', 'Bash(ls:*)', 'Bash(wc:*)',
  ...(mode === 'gate' ? ['Bash(node scripts/kpi.mjs:*)', 'Bash(node build/src/cli.js:*)', 'Bash(docker ps:*)',
    'Bash(docker compose ps:*)', 'Bash(gh run list:*)', 'Bash(gh run view:*)'] : []),
];
const args = ['--print', '--output-format', 'json', '--json-schema', schema,
  '--permission-mode', 'dontAsk', '--tools', 'Read,Grep,Glob,Bash', '--allowedTools', ...allowed,
  '--max-turns', opts.maxTurns, '--max-budget-usd', opts.budgetUsd,
  '--no-session-persistence', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--disable-slash-commands',
  ...(opts.auth === 'api-key' ? ['--bare'] : [])];
if (opts.auth === 'api-key' && !process.env.ANTHROPIC_API_KEY) fail('ANTHROPIC_API_KEY is required for --auth api-key');

console.error(`claude-review: ${mode} ${prefix} @ ${head.slice(0, 12)} (round ${rounds + 1}/${MAX_ROUNDS})`);
const result = run(opts.claude, args, { cwd: tree, input: prompt, timeout: Number(opts.timeoutMin) * 60_000 });
try { git(['worktree', 'remove', '--force', tree], root); rmSync(work, { recursive: true, force: true }); } catch { /* best effort */ }
if (result.error || result.status !== 0) fail(`claude exited ${result.status ?? result.error?.message}: ${(result.stderr || '').slice(-2000)}`);

// 4) 응답 검증: 구조화 출력이 있어야 하고 판정과 지적 사항이 서로 모순되면 안 된다.
let envelope;
try { envelope = JSON.parse(result.stdout); } catch { fail('claude output is not JSON'); }
const out = envelope?.structured_output;
if (envelope?.type !== 'result' || envelope?.subtype !== 'success' || envelope?.is_error !== false || !out) fail('claude did not return a successful structured result');
const verdicts = ['APPROVE', 'APPROVE_WITH_NITS', 'CHANGES_REQUESTED', 'BLOCKED'];
if (!verdicts.includes(out.verdict) || !Array.isArray(out.findings) || !Array.isArray(out.gate)) fail('structured output does not match schema');
const blocking = out.findings.filter((f) => f.severity === 'blocking');
const gateFail = out.gate.filter((g) => g.status === 'FAIL');
const gateUnverified = out.gate.filter((g) => g.status === 'UNVERIFIED');
let code = { APPROVE: 0, APPROVE_WITH_NITS: 0, CHANGES_REQUESTED: 10, BLOCKED: 11 }[out.verdict];
if (code === 0 && (blocking.length || gateFail.length)) code = 10;           // 승인인데 blocking이 있으면 수정 요청으로 강등
if (mode === 'gate' && code === 0 && (out.gate.length === 0 || gateUnverified.length)) code = 12; // 게이트 미검증은 사람 판단

// 5) 응답 기록. Codex는 이 파일을 수정하지 않는다.
const base = name.replace('.request.md', '');
const meta = {
  head, mode, round: rounds + 1, exitCode: code,
  claudeSession: envelope.session_id ?? null, costUsd: envelope.total_cost_usd ?? null,
  scriptSha256: sha(readFileSync(here)), templateSha256: sha(template), schemaSha256: sha(schema), requestSha256: sha(request),
};
writeFileSync(join(root, '.handoff', `${base}.response.json`), JSON.stringify({ meta, ...out }, null, 2));
const lines = [
  `# ${base} 응답 (Claude, 비대화식)`, '',
  `- 판정: **${out.verdict}** → 처리: **${{ 0: '승인', 10: '수정 요청', 11: 'BLOCKED', 12: '사람 판단 필요' }[code]}** (종료 코드 ${code})`,
  `- head: \`${head}\` · round ${meta.round}/${MAX_ROUNDS} · 비용 ${meta.costUsd ?? '?'} USD`, '',
  '## 요약', '', out.summary ?? '', '',
  '## 지적 사항', '',
  ...(out.findings.length ? out.findings.map((f) => `- **${f.id}** (${f.severity}) \`${f.file}:${f.line}\` — ${f.problem}\n  - 요구 수정: ${f.required_fix}\n  - 검증: ${f.how_to_verify}`) : ['없음']), '',
  ...(mode === 'gate' ? ['## 게이트 기준', '', '| 기준 | 상태 | 근거 |', '| --- | --- | --- |',
    ...out.gate.map((g) => `| ${g.criterion} | ${g.status} | ${String(g.evidence).replaceAll('|', '\\|')} |`), ''] : []),
  '## 실행한 검증', '',
  ...(out.checks_run ?? []).map((c) => `- \`${c.command}\` → exit ${c.exit_code}: ${c.result}`),
];
writeFileSync(join(root, '.handoff', `${base}.response.md`), lines.join('\n') + '\n');
console.log(`REVIEW ${out.verdict} -> exit ${code}: .handoff/${base}.response.md`);
process.exit(code);
