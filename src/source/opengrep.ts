import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, lstat, mkdir, mkdtemp, open, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { CheckResult, Finding, SourceOptions, StaticFlow } from '../contracts.js';
import { runProcess } from './process.js';
import type { CollectedFile, ProcessResult, SourceSnapshot } from './types.js';
import { OPENGREP_PROFILE, OPENGREP_SHA256, OPENGREP_SIZE, OPENGREP_VERSION, OWN_RULE_IDS, OWN_RULES, OWN_RULES_SHA256 } from './opengrep-rules.js';

export const NATIVE_CHECK_ID = 'source.opengrep.preview';
export const NATIVE_DENY_POLICY = '(version 1)\n(allow default)\n(deny network*)\n';
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const NOTE = 'Experimental native candidate positions only; binding identity, exploitability and complete dataflow edges are not verified.';
type ObjectValue = Record<string, unknown>;
const object = (value: unknown): value is ObjectValue => !!value && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value: ObjectValue, allowed: readonly string[]): boolean => Object.keys(value).every((key) => allowed.includes(key));
const digest = (bytes: string | Buffer): string => createHash('sha256').update(bytes).digest('hex');
export const nativeFiles = (snapshot: SourceSnapshot): CollectedFile[] => snapshot.files.filter((file) => file.category === 'code' && !file.sensitive && /\.(?:[cm]?[jt]sx?|py)$/i.test(file.path));

/** Bounded strict JSON: duplicate keys/nonfinite values cannot override evidence. */
function nativeJson(text: string): unknown {
  if (Buffer.byteLength(text) > MAX_JSON_BYTES) throw new Error('output budget');
  let cursor = 0, nodes = 0;
  const space = (): void => { while (/\s/.test(text[cursor] ?? '') && cursor < text.length) cursor++; };
  const string = (): string => {
    if (text[cursor] !== '"') throw new Error('string');
    const start = cursor++;
    while (cursor < text.length) {
      if (text[cursor] === '\\') { cursor += 2; continue; }
      if (text[cursor++] === '"') return JSON.parse(text.slice(start, cursor)) as string;
    }
    throw new Error('unterminated');
  };
  const value = (depth: number): void => {
    if (++nodes > 200_000 || depth > 64) throw new Error('json budget');
    space();
    if (text[cursor] === '{') {
      cursor++; space(); const keys = new Set<string>();
      if (text[cursor] === '}') { cursor++; return; }
      while (true) {
        space(); const key = string(); if (keys.has(key)) throw new Error('duplicate'); keys.add(key);
        space(); if (text[cursor++] !== ':') throw new Error('colon'); value(depth + 1); space();
        const next = text[cursor++]; if (next === '}') return; if (next !== ',') throw new Error('object');
      }
    }
    if (text[cursor] === '[') {
      cursor++; space(); if (text[cursor] === ']') { cursor++; return; }
      while (true) { value(depth + 1); space(); const next = text[cursor++]; if (next === ']') return; if (next !== ',') throw new Error('array'); }
    }
    if (text[cursor] === '"') { string(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(cursor));
    if (!match) throw new Error('primitive');
    if (!Number.isFinite(Number(match[0])) && !['true', 'false', 'null'].includes(match[0])) throw new Error('nonfinite');
    cursor += match[0].length;
  };
  value(0); space(); if (cursor !== text.length) throw new Error('trailing');
  return JSON.parse(text) as unknown;
}

function fileFor(path: unknown, stage: string, files: Map<string, CollectedFile>): CollectedFile | undefined {
  if (typeof path !== 'string' || !path || path.includes('\0') || path.includes('\\')) return undefined;
  const absolute = isAbsolute(path) ? resolve(path) : resolve(stage, path);
  const local = relative(resolve(stage), absolute).split(sep).join('/');
  if (local === '..' || local.startsWith('../') || isAbsolute(local)) return undefined;
  return files.get(local);
}

type PositionCache = Map<string, { bytes: Buffer; starts: number[]; points: Map<number, { offset: number; line: number; column: number }> }>;
function point(raw: unknown, file: CollectedFile, cache: PositionCache): { offset: number; line: number; column: number } {
  if (!object(raw) || !exactKeys(raw, ['line', 'col', 'offset']) ||
      !['line', 'col', 'offset'].every((key) => Number.isSafeInteger(raw[key])) ||
      (raw.line as number) < 1 || (raw.col as number) < 1 || (raw.offset as number) < 0) throw new Error('position');
  let prepared = cache.get(file.path);
  if (!prepared) {
    const bytes = Buffer.from(file.text, 'utf8'), starts = [0];
    for (let index = 0; index < bytes.length; index++) if (bytes[index] === 10) starts.push(index + 1);
    prepared = { bytes, starts, points: new Map() }; cache.set(file.path, prepared);
  }
  const { bytes, starts } = prepared, offset = raw.offset as number, line = raw.line as number;
  if (offset > bytes.length || (offset < bytes.length && (bytes[offset] & 0xc0) === 0x80)) throw new Error('byte boundary');
  const lineStart = starts[line - 1];
  if (lineStart === undefined || offset < lineStart || (line < starts.length && offset >= starts[line]) || raw.col !== offset - lineStart + 1) throw new Error('byte column');
  // Public columns are UTF-16 code units, matching the existing TypeScript API.
  let normal = prepared.points.get(offset);
  if (!normal) { normal = { offset, line, column: bytes.subarray(lineStart, offset).toString('utf8').length + 1 }; prepared.points.set(offset, normal); }
  return normal;
}

function range(raw: unknown, stage: string, files: Map<string, CollectedFile>, cache: PositionCache): { file: CollectedFile; start: ReturnType<typeof point>; end: ReturnType<typeof point> } {
  if (!object(raw) || !exactKeys(raw, ['path', 'start', 'end'])) throw new Error('location');
  const file = fileFor(raw.path, stage, files); if (!file) throw new Error('outside');
  const start = point(raw.start, file, cache), end = point(raw.end, file, cache);
  if (end.offset <= start.offset) throw new Error('empty range');
  return { file, start, end };
}

function nativeTrace(raw: unknown, sink: ReturnType<typeof range>, stage: string, files: Map<string, CollectedFile>, cache: PositionCache): StaticFlow {
  if (!object(raw) || !exactKeys(raw, ['taint_source', 'taint_sink', 'intermediate_vars']) || !Array.isArray(raw.intermediate_vars)) throw new Error('trace schema');
  const steps: StaticFlow['steps'] = [];
  const add = (role: 'source' | 'intermediate' | 'sink', loc: unknown, content: unknown): ReturnType<typeof range> => {
    const item = range(loc, stage, files, cache);
    if (item.file.path !== sink.file.path) throw new Error('intrafile trace');
    if (typeof content !== 'string' || Buffer.from(item.file.text).subarray(item.start.offset, item.end.offset).toString('utf8') !== content) throw new Error('trace bytes');
    steps.push({ role, location: { path: item.file.path, line: item.start.line, column: item.start.column } });
    return item;
  };
  const cliLoc = (role: 'source' | 'sink', value: unknown): ReturnType<typeof range> => {
    if (!Array.isArray(value) || value.length !== 2 || value[0] !== 'CliLoc' || !Array.isArray(value[1]) || value[1].length !== 2) throw new Error('trace variant');
    return add(role, value[1][0], value[1][1]);
  };
  cliLoc('source', raw.taint_source);
  if (raw.intermediate_vars.length > 10_000) throw new Error('trace budget');
  for (const item of raw.intermediate_vars) {
    if (!object(item) || !exactKeys(item, ['location', 'content'])) throw new Error('intermediate');
    add('intermediate', item.location, item.content);
  }
  const last = cliLoc('sink', raw.taint_sink);
  if (last.file.path !== sink.file.path || last.start.offset !== sink.start.offset || last.end.offset !== sink.end.offset) throw new Error('trace sink mismatch');
  return { kind: 'static_flow', steps: steps.length > 24 ? [...steps.slice(0, 23), steps.at(-1)!] : steps, truncated: true };
}

/** Internal parser entry point, not a public fake-engine/pin override. */
export function parseNativeOutput(stdout: string, exitCode: number | null, stage: string, inputFiles: readonly CollectedFile[]): CheckResult {
  const findings: Finding[] = [], reasons = new Set<string>();
  const files = new Map(inputFiles.map((file) => [file.path, file]));
  const positionCache: PositionCache = new Map();
  let ignored = 0, invalid = 0, errors = 0, skipped = 0, scanned = 0;
  const metrics = (): NonNullable<CheckResult['metrics']> => ({ profile: OPENGREP_PROFILE, filesDeclared: inputFiles.length, filesScanned: scanned,
    nativeErrors: errors, skippedRules: skipped, ignoredFindings: ignored, invalidFindings: invalid, engineExit: exitCode ?? 'unknown',
    incompleteReasons: [...reasons].sort().join(','), rulePackSha256: OWN_RULES_SHA256 });
  let parsed: unknown;
  try { parsed = nativeJson(stdout); } catch { return { id: NATIVE_CHECK_ID, status: 'error', findings, notes: ['Native preview returned invalid bounded JSON.'], metrics: { ...metrics(), incompleteReasons: 'invalid_json' } }; }
  if (!object(parsed) || parsed.version !== OPENGREP_VERSION || !Array.isArray(parsed.results)) {
    return { id: NATIVE_CHECK_ID, status: 'error', findings, notes: ['Native preview protocol or version did not match the selected profile.'], metrics: { ...metrics(), incompleteReasons: 'invalid_protocol' } };
  }
  // Missing coverage/diagnostic fields do not erase independently valid locations.
  if (!Array.isArray(parsed.errors)) { reasons.add('invalid_protocol'); parsed.errors = []; }
  if (!Array.isArray(parsed.skipped_rules)) { reasons.add('invalid_protocol'); parsed.skipped_rules = []; }
  if (!Array.isArray(parsed.interfile_languages_used)) { reasons.add('invalid_protocol'); parsed.interfile_languages_used = []; }
  if (!object(parsed.paths)) { reasons.add('invalid_protocol'); parsed.paths = {}; }
  const paths = parsed.paths as ObjectValue;
  if (!Array.isArray(paths.scanned)) { reasons.add('invalid_protocol'); paths.scanned = []; }
  if (!exactKeys(parsed, ['version', 'results', 'errors', 'paths', 'skipped_rules', 'interfile_languages_used'])) reasons.add('unknown_schema');
  if (!exactKeys(paths, ['scanned', 'skipped'])) reasons.add('unknown_paths');
  errors = (parsed.errors as unknown[]).length; skipped = (parsed.skipped_rules as unknown[]).length;
  if (errors) reasons.add('native_errors'); if (skipped) reasons.add('skipped_rules');
  if ((parsed.interfile_languages_used as unknown[]).length) reasons.add('unexpected_interfile');
  if (paths.skipped !== undefined && (!Array.isArray(paths.skipped) || paths.skipped.length)) reasons.add('skipped_files');
  const seen = new Set<string>();
  for (const path of paths.scanned as unknown[]) {
    const file = fileFor(path, stage, files);
    if (!file || seen.has(file.path)) reasons.add('coverage_mismatch'); else seen.add(file.path);
  }
  scanned = seen.size; if (seen.size !== files.size) reasons.add('coverage_mismatch');
  if (parsed.results.length > 10_000) reasons.add('finding_limit');
  for (const raw of parsed.results.slice(0, 10_000)) {
    try {
      if (!object(raw) || typeof raw.check_id !== 'string' || !(OWN_RULE_IDS as readonly string[]).includes(raw.check_id) || !object(raw.extra)) throw new Error('finding');
      const loc = range({ path: raw.path, start: raw.start, end: raw.end }, stage, files, positionCache);
      const extra = raw.extra;
      if (!exactKeys(raw, ['check_id', 'path', 'start', 'end', 'extra']) || !exactKeys(extra,
        ['metavars', 'message', 'metadata', 'severity', 'fingerprint', 'lines', 'is_ignored', 'validation_state', 'dataflow_trace', 'engine_kind'])) reasons.add('unknown_finding_schema');
      const isPython = raw.check_id.includes('.python.');
      if (isPython !== /\.py$/i.test(loc.file.path)) throw new Error('language mismatch');
      if (extra.is_ignored !== false) { ignored++; reasons.add('ignored_finding'); }
      if (extra.severity !== 'ERROR' || extra.validation_state !== 'NO_VALIDATOR' || extra.engine_kind !== 'OSS' || !object(extra.metadata)) reasons.add('finding_state');
      let staticFlow: StaticFlow | undefined;
      if (extra.dataflow_trace !== undefined && extra.dataflow_trace !== null) {
        try { staticFlow = nativeTrace(extra.dataflow_trace, loc, stage, files, positionCache); }
        catch { reasons.add('invalid_trace'); }
      }
      const sql = raw.check_id.includes('.sql.');
      findings.push({ ruleId: raw.check_id, title: sql ? 'Request-shaped input in SQL argument' : 'Request-shaped input in command argument',
        description: 'The selected native rule reported a static input candidate. Binding identity and runtime exploitability require independent review.',
        severity: 'high', confidence: 'low', kind: 'candidate', location: { path: loc.file.path, line: loc.start.line, column: loc.start.column },
        remediation: sql ? 'Review the SQL statement argument and use parameter binding; verify the risky, fixed and normal paths independently.' : 'Review shell interpretation and prefer an explicit executable with separate arguments; verify the risky, fixed and normal paths independently.',
        references: [sql ? 'https://cwe.mitre.org/data/definitions/89.html' : 'https://cwe.mitre.org/data/definitions/78.html'], ...(staticFlow ? { staticFlow } : {}) });
    } catch { invalid++; reasons.add('invalid_finding'); }
  }
  if (![0, 1].includes(exitCode as number) || (exitCode === 0 && parsed.results.length > 0) || (exitCode === 1 && parsed.results.length === 0)) reasons.add('exit_mismatch');
  return { id: NATIVE_CHECK_ID, status: reasons.size ? 'partial' : 'completed', findings,
    notes: [NOTE, ...(reasons.size ? ['Native preview completion is unverified; inspect incompleteReasons and retained candidates.'] : [])], metrics: metrics() };
}

export function nativeCheckFromProcess(result: ProcessResult, stage: string, files: readonly CollectedFile[], snapshotComplete: boolean): CheckResult {
  const check = parseNativeOutput(result.stdout, result.exitCode, stage, files);
  const reasons = new Set(String(check.metrics?.incompleteReasons ?? '').split(',').filter(Boolean));
  if (result.spawnError) reasons.add('spawn_error');
  if (result.signal !== null) reasons.add('process_signal');
  if (result.stopReason) reasons.add(result.stopReason);
  if (result.timedOut) reasons.add('timeout'); if (result.outputLimitExceeded) reasons.add('output_limit'); if (result.cancelled) reasons.add('cancelled');
  if (result.exited !== true || result.closeConfirmed !== true) reasons.add('close_unknown');
  if (result.cleanupConfirmed !== true || !['terminated', 'terminated_zombies'].includes(result.cleanupState ?? 'unknown')) reasons.add('cleanup_unknown');
  if (result.rss?.assessment !== 'measured' || !Number.isSafeInteger(result.rss.samples) || result.rss.samples < 1 || result.rss.failedSamples !== 0 ||
      !Number.isSafeInteger(result.rss.peakBytes) || result.rss.peakBytes < 0 || result.rss.capBytes !== 512 * 1024 * 1024) reasons.add('rss_unassessed');
  if (result.rss && result.rss.peakBytes > 512 * 1024 * 1024) reasons.add('rss_limit');
  if (!snapshotComplete) reasons.add('snapshot_incomplete');
  if (reasons.size && check.status === 'completed') check.status = 'partial';
  if (!result.spawnError && (result.timedOut || result.cancelled || result.outputLimitExceeded || result.stopReason === 'observer_unknown' || result.stopReason === 'rss_limit')) check.status = 'partial';
  check.metrics = { ...check.metrics, incompleteReasons: [...reasons].sort().join(','), closeConfirmed: result.closeConfirmed === true,
    cleanupConfirmed: result.cleanupConfirmed === true, cleanupState: result.cleanupState ?? 'unknown', rssAssessment: result.rss?.assessment ?? 'unassessed',
    rssSamples: result.rss?.samples ?? 0, rssPeakBytes: result.rss?.peakBytes ?? 0, snapshotComplete };
  if (reasons.size && !check.notes.some((note) => note.includes('completion is unverified'))) check.notes.push('Native preview completion is unverified; inspect incompleteReasons and retained candidates.');
  return check;
}

/** Trusted wrapper assembly is shared by the adapter and owned network probes. */
export function nativeSandboxCommand(policyPath: string, executable: string, args: readonly string[]): { executable: string; args: string[] } {
  if (!isAbsolute(policyPath) || !isAbsolute(executable)) throw new Error('absolute native paths required');
  return { executable: '/usr/bin/sandbox-exec', args: ['-f', policyPath, executable, ...args] };
}

async function hashRegular(path: string, expectedSize: number): Promise<string> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size !== expectedSize) throw new Error('identity size');
    const hash = createHash('sha256'), buffer = Buffer.alloc(64 * 1024); let position = 0;
    while (position <= expectedSize) {
      const result = await handle.read(buffer, 0, Math.min(buffer.length, expectedSize + 1 - position), position);
      if (!result.bytesRead) break;
      hash.update(buffer.subarray(0, result.bytesRead)); position += result.bytesRead;
    }
    const after = await handle.stat();
    if (position !== expectedSize || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error('changed file');
    return hash.digest('hex');
  } finally { await handle.close(); }
}

async function inventoryMatches(stage: string, files: readonly CollectedFile[]): Promise<boolean> {
  const expected = new Map(files.map((file) => [file.path, file])); let count = 0;
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name), stat = await lstat(path);
      if (stat.isSymbolicLink()) throw new Error('stage link');
      if (stat.isDirectory()) { await walk(path); continue; }
      const local = relative(stage, path).split(sep).join('/'), file = expected.get(local);
      if (!file || !stat.isFile() || ++count > files.length || stat.nlink !== 1 || await hashRegular(path, file.bytes) !== digest(file.text)) throw new Error('stage identity');
    }
  };
  try { await walk(stage); return count === files.length; } catch { return false; }
}

/** Internal post-run verifier; read failures revoke completion, retain candidates. */
export async function verifyNativePostRun(check: CheckResult, stage: string, files: readonly CollectedFile[], pack: string, policy: string, executable: string): Promise<void> {
  let stable = false;
  try {
    stable = await inventoryMatches(stage, files) && await hashRegular(pack, Buffer.byteLength(OWN_RULES)) === OWN_RULES_SHA256 &&
      await hashRegular(policy, Buffer.byteLength(NATIVE_DENY_POLICY)) === digest(NATIVE_DENY_POLICY) && await hashRegular(executable, OPENGREP_SIZE) === OPENGREP_SHA256;
  } catch { /* Unknown identity is incomplete, even after valid JSON. */ }
  if (!stable) {
    check.status = 'partial'; check.metrics = { ...check.metrics, identityUnchanged: false,
      incompleteReasons: [check.metrics?.incompleteReasons, 'identity_changed'].filter(Boolean).join(',') };
    check.notes.push('Post-run native input or engine identity could not be verified.');
  } else check.metrics = { ...check.metrics, identityUnchanged: true, engineSha256: OPENGREP_SHA256 };
}

export async function runNativePreview(snapshot: SourceSnapshot, options: SourceOptions): Promise<CheckResult> {
  const files = nativeFiles(snapshot);
  const failed = (reason: string, status: 'error' | 'partial' = 'error'): CheckResult => ({ id: NATIVE_CHECK_ID, status, findings: [],
    notes: ['Selected native preview could not be verified.'], metrics: { profile: OPENGREP_PROFILE, filesDeclared: files.length, incompleteReasons: reason } });
  if (options.signal?.aborted) return failed('cancelled', 'partial');
  const executable = options.nativePreview?.executable;
  if (typeof executable !== 'string' || !isAbsolute(executable) || executable.includes('\0')) return failed('invalid_executable_path');
  if (process.platform !== 'darwin' || process.arch !== 'arm64') return failed('unsupported_platform');
  if (!snapshot.complete && snapshot.rootError) return failed('snapshot_incomplete', 'partial');
  if (files.length === 0) return { id: NATIVE_CHECK_ID, status: 'not_applicable', findings: [], notes: ['No collected JS/TS/Python code file was available for the selected native preview.'], metrics: { filesDeclared: 0, profile: OPENGREP_PROFILE } };
  let top: string | undefined, check: CheckResult | undefined;
  try {
    if (await hashRegular(executable, OPENGREP_SIZE) !== OPENGREP_SHA256 || digest(OWN_RULES) !== OWN_RULES_SHA256) return failed('identity_mismatch');
    await access(executable, constants.X_OK);
    if (!(await lstat('/usr/bin/sandbox-exec')).isFile()) return failed('network_boundary_unavailable');
    top = await mkdtemp(join(tmpdir(), 'wakeio-native-'));
    const stage = join(top, 'snapshot'), home = join(top, 'home'), temporary = join(top, 'tmp');
    for (const path of [stage, home, temporary]) await mkdir(path, { mode: 0o700 });
    for (const file of files) { const path = join(stage, file.path); await mkdir(dirname(path), { recursive: true, mode: 0o700 }); await writeFile(path, file.text, { flag: 'wx', mode: 0o600 }); }
    const pack = join(top, 'owned-rules.yaml'), policy = join(top, 'deny-network.sb');
    await writeFile(pack, OWN_RULES, { mode: 0o600, flag: 'wx' }); await writeFile(policy, NATIVE_DENY_POLICY, { mode: 0o600, flag: 'wx' });
    if (!(await inventoryMatches(stage, files))) throw new Error('stage identity');
    const args = ['scan', '--experimental', '--disable-version-check', '--json', '--error', '--strict', '--no-autofix', '--disable-nosem',
      '--no-rewrite-rule-ids', '--no-git-ignore', '--taint-intrafile', '--jobs', '1', '--max-memory', '256', '--timeout', '2', '--timeout-threshold', '1',
      '--project-root', stage, '--config', pack, stage];
    const command = nativeSandboxCommand(policy, executable, args);
    const result = await runProcess(command.executable, command.args, { cwd: stage, home, tmpdir: temporary, timeoutMs: Math.min(options.timeoutMs ?? 10_000, 10_000),
      maxOutputBytes: MAX_JSON_BYTES, supervision: 'native-offline', signal: options.signal });
    check = nativeCheckFromProcess(result, stage, files, snapshot.complete);
    await verifyNativePostRun(check, stage, files, pack, policy, executable);
  } catch {
    if (!check) check = failed('native_execution_error');
    else { check.status = 'partial'; check.metrics = { ...check.metrics, incompleteReasons: [check.metrics?.incompleteReasons, 'native_execution_error'].filter(Boolean).join(',') }; }
  }
  finally {
    if (top) {
      try { await rm(top, { recursive: true, force: true }); if (check) check.metrics = { ...check.metrics, stageCleanupConfirmed: true }; }
      catch { check ??= failed('stage_cleanup_unknown', 'partial'); check.status = 'partial'; check.metrics = { ...check.metrics, stageCleanupConfirmed: false, incompleteReasons: [check.metrics?.incompleteReasons, 'stage_cleanup_unknown'].filter(Boolean).join(',') }; }
    }
  }
  return check ?? failed('native_execution_error');
}
