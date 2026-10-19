import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { CheckResult, Finding } from '../contracts.js';
import { stageSnapshot } from './collector.js';
import { runProcess } from './process.js';
import { SEMGREP_RULE_REVISION, SEMGREP_RULES } from './semgrep-rules.js';
import type { CollectedFile, SourceSnapshot } from './types.js';

export const SEMGREP_CHECK_ID = 'source.semgrep';
export const SEMGREP_RULES_SHA256 = createHash('sha256').update(SEMGREP_RULES).digest('hex');
const MAX_OUTPUT = 8 * 1024 * 1024;
const NOTE = 'Semgrep CE runs six bundled Go rules for SQL input, trusted HTML, TLS verification, command execution, outbound HTTP destinations and filesystem paths. These intraprocedural candidates require review; authentication/authorization logic and whole-project coverage are not established.';
const GUIDANCE: Record<string, { title: string; description: string; remediation: string; cwe: number }> = {
  'wakeio.go.sql-request-input': { title: 'Request input reaches a SQL query', description: 'An intraprocedural rule observed request-shaped input reaching a selected query argument. Receiver identity and exploitability require review.', remediation: 'Use a fixed SQL statement and pass untrusted values as separate bound parameters; review Query, QueryRow and Exec call sites.', cwe: 89 },
  'wakeio.go.html-request-input': { title: 'Request input becomes trusted HTML', description: 'An intraprocedural rule observed request-shaped input converted to template.HTML, bypassing normal template escaping.', remediation: 'Pass untrusted text as ordinary template data so html/template escapes it. Do not convert request input to template.HTML.', cwe: 79 },
  'wakeio.go.insecure-tls': { title: 'TLS certificate verification is disabled', description: 'A Go TLS configuration explicitly enables InsecureSkipVerify. Review whether equivalent certificate verification exists.', remediation: 'Keep InsecureSkipVerify false and configure trusted root certificates and the expected server name.', cwe: 295 },
  'wakeio.go.command-request-input': { title: 'Request input controls an executable or shell command', description: 'An intraprocedural rule observed request-shaped input selecting an executable or reaching a selected Unix shell command argument. Ordinary arguments to a fixed executable are not classified as shell commands.', remediation: 'Use an allowlist of fixed executables and operations. Pass data as separate arguments and avoid constructing shell command strings from request values.', cwe: 78 },
  'wakeio.go.ssrf-request-input': { title: 'Request input controls an outbound HTTP destination', description: 'An intraprocedural rule observed request-shaped input reaching the destination argument of a selected net/http client helper. Review destination allowlists, DNS resolution and redirect policy.', remediation: 'Map permitted actions to fixed destinations. Validate scheme, host and resolved addresses, and constrain redirects before making outbound requests.', cwe: 918 },
  'wakeio.go.path-request-input': { title: 'Request input controls a filesystem path', description: 'An intraprocedural rule observed request-shaped input reaching a selected file access path. filepath.Join and filepath.Clean alone do not prove containment.', remediation: 'Map public identifiers to fixed files, or enforce filesystem-root containment with an appropriate rooted filesystem API. Reject traversal and account for symlinks.', cwe: 22 },
};
type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue => v !== null && typeof v === 'object' && !Array.isArray(v);
export const semgrepFiles = (snapshot: SourceSnapshot): CollectedFile[] => snapshot.files.filter(f => f.category === 'code' && !f.sensitive && /\.go$/i.test(f.path));

// The existing wire parser has a 64 KiB policy cap; scanner JSON needs its own 8 MiB bound.
function scannerJson(text: string): unknown {
  if (Buffer.byteLength(text) > MAX_OUTPUT) throw new Error('output_limit');
  const parsed: unknown = JSON.parse(text);
  const stack: Array<Set<string> | null> = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '{') stack.push(new Set());
    else if (text[i] === '[') stack.push(null);
    else if (text[i] === '}' || text[i] === ']') stack.pop();
    else if (text[i] === '"') {
      const start = i++;
      for (; i < text.length; i++) { if (text[i] === '\\') i++; else if (text[i] === '"') break; }
      let next = i + 1; while (/\s/.test(text[next] ?? '') && next < text.length) next++;
      if (text[next] === ':') {
        const keys = stack[stack.length - 1], key = JSON.parse(text.slice(start, i + 1)) as string;
        if (!keys || keys.has(key) || ['__proto__', 'constructor', 'prototype'].includes(key)) throw new Error('duplicate_key');
        keys.add(key);
      }
    }
    if (stack.length > 64) throw new Error('json_depth');
  }
  return parsed;
}

function fileAt(value: unknown, stage: string, files: Map<string, CollectedFile>): CollectedFile {
  if (typeof value !== 'string' || !value || /[\x00-\x1f\\]/.test(value)) throw new Error('invalid_path');
  const local = relative(resolve(stage), isAbsolute(value) ? resolve(value) : resolve(stage, value)).split(sep).join('/');
  const file = files.get(local);
  if (!file || local === '..' || local.startsWith('../') || isAbsolute(local)) throw new Error('outside_snapshot');
  return file;
}

type PositionCache = Map<string, { bytes: Buffer; starts: number[] }>;
function point(value: unknown, file: CollectedFile, cache: PositionCache): { offset: number; line: number; column: number } {
  if (!object(value) || !['offset', 'line', 'col'].every(k => Number.isSafeInteger(value[k]))) throw new Error('invalid_position');
  const offset = value.offset as number, line = value.line as number, column = value.col as number;
  let prepared = cache.get(file.path);
  if (!prepared) {
    const bytes = Buffer.from(file.text), starts = [0];
    for (let index = 0; index < bytes.length; index++) if (bytes[index] === 10) starts.push(index + 1);
    prepared = { bytes, starts }; cache.set(file.path, prepared);
  }
  const { bytes, starts } = prepared;
  if (offset < 0 || offset > bytes.length || line < 1 || column < 1 || offset < bytes.length && (bytes[offset] & 0xc0) === 0x80) throw new Error('invalid_position');
  const start = starts[line - 1];
  if (start === undefined || offset < start || line < starts.length && offset >= starts[line] || column !== offset - start + 1) throw new Error('invalid_position');
  return { offset, line, column: bytes.subarray(start, offset).toString('utf8').length + 1 };
}

export function parseSemgrepOutput(text: string, stage: string, input: CollectedFile[], exitCode: number | null): CheckResult {
  const files = new Map(input.map(f => [f.path, f]));
  const top = scannerJson(text);
  if (!object(top) || typeof top.version !== 'string' || !/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(top.version) || !Array.isArray(top.results) || !Array.isArray(top.errors) || !object(top.paths) || !Array.isArray(top.paths.scanned)) throw new Error('invalid_envelope');
  if (top.errors.some(e => !object(e)) || top.skipped_rules !== undefined && !Array.isArray(top.skipped_rules) || top.paths.skipped !== undefined && !Array.isArray(top.paths.skipped)) throw new Error('invalid_errors');
  const scanned = new Set<string>();
  for (const path of top.paths.scanned) { const file = fileAt(path, stage, files); if (scanned.has(file.path)) throw new Error('duplicate_scanned'); scanned.add(file.path); }
  const findings = new Map<string, Finding>();
  const positions: PositionCache = new Map();
  for (const raw of top.results) {
    if (!object(raw) || typeof raw.check_id !== 'string' || !Object.hasOwn(GUIDANCE, raw.check_id) || !object(raw.extra) || raw.extra.severity !== 'ERROR') throw new Error('invalid_finding');
    const file = fileAt(raw.path, stage, files);
    if (!scanned.has(file.path)) throw new Error('unscanned_finding');
    const start = point(raw.start, file, positions), end = point(raw.end, file, positions);
    if (end.offset <= start.offset) throw new Error('invalid_range');
    const guide = GUIDANCE[raw.check_id], key = `${raw.check_id}:${file.path}:${start.offset}:${end.offset}`;
    findings.set(key, { ruleId: `semgrep:${raw.check_id}`, title: guide.title, description: guide.description,
      severity: 'high', confidence: 'medium', kind: 'candidate', location: { path: file.path, line: start.line, column: start.column }, remediation: guide.remediation,
      references: [`https://cwe.mitre.org/data/definitions/${guide.cwe}.html`] });
  }
  const skipped = (top.skipped_rules as unknown[] | undefined)?.length ?? 0;
  const skippedPaths = (top.paths.skipped as unknown[] | undefined)?.length ?? 0;
  const complete = scanned.size === files.size && top.errors.length === 0 && skipped === 0 && skippedPaths === 0 && (exitCode === 0 && findings.size === 0 || exitCode === 1 && findings.size > 0);
  return { id: SEMGREP_CHECK_ID, status: complete ? 'completed' : 'partial', findings: [...findings.values()], notes: [NOTE, ...(!complete ? ['Semgrep reported errors, skipped inputs/rules, incomplete input accounting or an inconsistent exit status.'] : [])],
    metrics: { filesRequested: files.size, filesAnalyzed: scanned.size, errorCount: top.errors.length, skippedRules: skipped, skippedPaths, findingCount: findings.size,
      engineVersion: top.version, ruleRevision: SEMGREP_RULE_REVISION, rulePackSha256: SEMGREP_RULES_SHA256 } };
}

export async function runSemgrep(context: { snapshot: SourceSnapshot; stageDir: string; toolPath: string; timeoutMs: number; signal?: AbortSignal }): Promise<CheckResult> {
  const files = semgrepFiles(context.snapshot);
  const failure = (reason: string, status: CheckResult['status'] = 'partial'): CheckResult => ({ id: SEMGREP_CHECK_ID, status, findings: [], notes: [NOTE, reason], metrics: { filesRequested: files.length, filesAnalyzed: 0, errorCount: 1, ruleRevision: SEMGREP_RULE_REVISION, rulePackSha256: SEMGREP_RULES_SHA256 } });
  if (!files.length) return { id: SEMGREP_CHECK_ID, status: 'not_applicable', findings: [], notes: [NOTE, 'No collected Go input is available.'], metrics: { filesRequested: 0, filesAnalyzed: 0, errorCount: 0 } };
  if (context.signal?.aborted) return failure('Semgrep was cancelled before launch.');
  let work: string | undefined, staged: Awaited<ReturnType<typeof stageSnapshot>> | undefined;
  let check: CheckResult | undefined;
  try {
    // Only Go inputs enter this separate stage; repository ignore/config files cannot alter the scan.
    staged = await stageSnapshot({ ...context.snapshot, files });
    work = await mkdtemp(join(tmpdir(), 'wakeio-semgrep-'));
    const home = join(work, 'home'); await mkdir(home, { mode: 0o700 });
    const config = join(work, 'rules.yaml'); await writeFile(config, SEMGREP_RULES, { mode: 0o600, flag: 'wx' });
    const args = ['scan', '--oss-only', '--config', config, '--json', '--error', '--strict', '--metrics', 'off', '--disable-version-check', '--disable-nosem', '--no-rewrite-rule-ids', '--no-git-ignore', '--jobs', '1', '--max-memory', '512', '--timeout', '5', '--timeout-threshold', '1', '--max-target-bytes', '8388608', '--project-root', staged.dir, '--', ...files.map(f => join(staged!.dir, f.path))];
    const result = await runProcess(context.toolPath, args, { cwd: staged.dir, home, tmpdir: work, timeoutMs: context.timeoutMs, maxOutputBytes: MAX_OUTPUT, signal: context.signal });
    if (result.cancelled || result.timedOut || result.outputLimitExceeded || result.spawnError || result.signal || result.exitCode === null) check = failure('Semgrep did not complete: cancellation, timeout, output limit or process failure.');
    else check = parseSemgrepOutput(result.stdout, staged.dir, files, result.exitCode);
    if (!context.snapshot.complete && check.status === 'completed') { check.status = 'partial'; check.notes.push('The collected source snapshot is incomplete.'); }
  } catch { check = failure('Semgrep could not produce a valid bounded result.', 'error'); }
  finally {
    const cleanup = await Promise.allSettled([staged?.cleanup(), work ? rm(work, { recursive: true, force: true }) : undefined]);
    if (cleanup.some(r => r.status === 'rejected')) { check ??= failure('Semgrep temporary data cleanup failed.'); check.status = 'partial'; check.notes.push('Semgrep temporary data cleanup failed.'); }
  }
  return check!;
}
