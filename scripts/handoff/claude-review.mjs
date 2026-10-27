#!/usr/bin/env node
// Codex가 체크포인트·게이트마다 호출하는 비대화식 Claude 리뷰 래퍼.
// 사용: node scripts/handoff/claude-review.mjs --request .handoff/M1-CP2.request.md
//        [--auth login|api-key] [--budget-usd 3] [--max-turns 120] [--timeout-min 40] [--claude PATH]
// 종료 코드: 0 승인 · 10 수정 요청 · 11 BLOCKED · 12 사람 판단 필요 · 2 실행 오류
// 실행 오류(2)일 때는 원인을 .handoff/<요청 이름>.error.json 에 남긴다 (cause: max_turns | budget | permission | auth | not_clean | ...).
// 사용자 전역 훅·플러그인·CLAUDE.md는 --safe-mode(로그인) / --bare(API 키)로 끈다.
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
  const opts = { auth: 'login', budgetUsd: '3', maxTurns: '120', timeoutMin: '40', claude: process.env.WAKEIO_CLAUDE_BIN || 'claude' };
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
const base = name.replace('.request.md', '');
const errorPath = join(root, '.handoff', `${base}.error.json`);
// 실행 오류는 원인을 파일로 남기고 종료한다. Codex는 이 파일의 cause로 재시도 여부를 정한다.
const failWith = (cause, message, details = {}) => {
  writeFileSync(errorPath, JSON.stringify({ cause, message, at: new Date().toISOString(), ...details }, null, 2));
  fail(`${cause}: ${message} (details: .handoff/${base}.error.json)`);
};

// 1) 추적 중인 파일에 커밋 안 된 변경이 없고, 요청서의 head SHA가 실제 HEAD와 같아야 한다.
if (git(['status', '--porcelain', '--untracked-files=no'], root) !== '') failWith('not_clean', 'tracked files have uncommitted changes; commit before requesting review');
const head = git(['rev-parse', 'HEAD'], root);
const request = readFileSync(requestPath, 'utf8');
const declared = /head SHA:\s*`?([0-9a-f]{7,40})/i.exec(request)?.[1];
if (!declared || !head.startsWith(declared)) failWith('head_mismatch', `request head SHA (${declared ?? 'missing'}) != HEAD (${head})`);

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
  'Bash(git diff *)', 'Bash(git log *)', 'Bash(git show *)', 'Bash(git status *)', 'Bash(git rev-parse *)',
  'Bash(npm ci --ignore-scripts *)', 'Bash(npm run build *)', 'Bash(node --test *)', 'Bash(npm test *)',
  'Bash(shasum -a 256 *)', 'Bash(ls *)', 'Bash(wc *)',
  ...(mode === 'gate' ? ['Bash(node scripts/kpi.mjs *)', 'Bash(node build/src/cli.js *)', 'Bash(docker ps *)',
    'Bash(docker compose ps *)', 'Bash(gh run list *)', 'Bash(gh run view *)'] : []),
];
// --safe-mode: 사용자 전역 훅(예: Intent Loop review_gate)·플러그인·CLAUDE.md·MCP를 끄고 로그인 인증은 유지한다.
// --bare: API 키 전용 최소 모드(훅·플러그인·키체인 미사용).
const args = ['--print', '--output-format', 'json', '--json-schema', schema,
  '--permission-mode', 'dontAsk', '--tools', 'Read,Grep,Glob,Bash', '--allowedTools', ...allowed,
  '--max-turns', opts.maxTurns, '--max-budget-usd', opts.budgetUsd,
  '--no-session-persistence', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--disable-slash-commands',
  ...(opts.auth === 'api-key' ? ['--bare'] : ['--safe-mode'])];
if (opts.auth === 'api-key' && !process.env.ANTHROPIC_API_KEY) failWith('auth', 'ANTHROPIC_API_KEY is required for --auth api-key');

console.error(`claude-review: ${mode} ${prefix} @ ${head.slice(0, 12)} (round ${rounds + 1}/${MAX_ROUNDS})`);
const result = run(opts.claude, args, { cwd: tree, input: prompt, timeout: Number(opts.timeoutMin) * 60_000 });
try { git(['worktree', 'remove', '--force', tree], root); rmSync(work, { recursive: true, force: true }); } catch { /* best effort */ }

// 4) 응답 검증. 실패해도 원인(subtype·턴 수·권한 거부·비용)을 .error.json에 남긴다.
let envelope = null;
try { envelope = JSON.parse(result.stdout); } catch { /* 아래에서 분류 */ }
const out = envelope?.structured_output;
const ok = !result.error && result.status === 0 && envelope?.type === 'result' && envelope?.subtype === 'success' && envelope?.is_error === false && out;
if (!ok) {
  const subtype = String(envelope?.subtype ?? '');
  const reason = String(envelope?.terminal_reason ?? '');
  const denials = Array.isArray(envelope?.permission_denials) ? envelope.permission_denials : [];
  const stderr = String(result.stderr ?? '');
  const cause = result.error?.code === 'ENOENT' ? 'claude_not_found'
    : result.error?.code === 'ETIMEDOUT' || result.signal ? 'timeout'
    : /max_turns/.test(subtype + reason) ? 'max_turns'
    : /budget/.test(subtype + reason) ? 'budget'
    : /auth|login|api key|401|403/i.test(stderr + String(envelope?.result ?? '')) ? 'auth'
    : envelope && !out && envelope.subtype === 'success' ? 'no_structured_output'
    : denials.length ? 'permission'
    : envelope ? 'claude_error' : 'not_json';
  failWith(cause, `claude did not return a successful structured result (exit ${result.status ?? result.error?.code})`, {
    exitStatus: result.status ?? null, signal: result.signal ?? null, subtype: subtype || null, terminalReason: reason || null,
    numTurns: envelope?.num_turns ?? null, costUsd: envelope?.total_cost_usd ?? null, maxTurns: Number(opts.maxTurns), budgetUsd: Number(opts.budgetUsd),
    permissionDenials: denials.slice(0, 20).map((d) => ({ tool: d?.tool_name ?? null, input: JSON.stringify(d?.tool_input ?? '').slice(0, 200) })),
    resultExcerpt: String(envelope?.result ?? '').slice(0, 1000), stderrTail: stderr.slice(-2000),
  });
}
const verdicts = ['APPROVE', 'APPROVE_WITH_NITS', 'CHANGES_REQUESTED', 'BLOCKED'];
if (!verdicts.includes(out.verdict) || !Array.isArray(out.findings) || !Array.isArray(out.gate)) failWith('schema_mismatch', 'structured output does not match schema', { output: out });
try { rmSync(errorPath, { force: true }); } catch { /* 이전 실패 기록 정리 */ }
const blocking = out.findings.filter((f) => f.severity === 'blocking');
const gateFail = out.gate.filter((g) => g.status === 'FAIL');
const gateUnverified = out.gate.filter((g) => g.status === 'UNVERIFIED');
let code = { APPROVE: 0, APPROVE_WITH_NITS: 0, CHANGES_REQUESTED: 10, BLOCKED: 11 }[out.verdict];
if (code === 0 && (blocking.length || gateFail.length)) code = 10;           // 승인인데 blocking이 있으면 수정 요청으로 강등
if (mode === 'gate' && code === 0 && (out.gate.length === 0 || gateUnverified.length)) code = 12; // 게이트 미검증은 사람 판단

// 5) 응답 기록. Codex는 이 파일을 수정하지 않는다.
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
