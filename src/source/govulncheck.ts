import { mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import type { CheckResult, Finding } from '../contracts.js';
import { findExecutable, runProcess } from './process.js';
import { stageSnapshot, type StagedSnapshot } from './collector.js';
import type { CollectedFile, ParsedToolResult, SourceSnapshot } from './types.js';

export interface GovulncheckContext {
  snapshot: SourceSnapshot;
  stageDir: string;
  toolPath: string;
  timeoutMs: number;
  signal?: AbortSignal;
  goPath?: string;
  moduleCache?: string;
  /** Explicit database endpoint; defaults to the official Go vulnerability database. */
  database?: string;
  buildTags?: string[];
}

export function normalizeGoBuildTags(tags: string[] = []): string[] {
  if (!Array.isArray(tags) || tags.length > 32 || tags.some(tag => typeof tag !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_.]{0,63}$/.test(tag))) throw new TypeError('invalid_go_build_tags');
  return [...new Set(tags)].sort();
}

export function govulncheckFiles(snapshot: SourceSnapshot): CollectedFile[] {
  return snapshot.files.filter(file => !file.sensitive && (/\.go$/.test(file.path) || /(?:^|\/)go\.(?:mod|sum)$/.test(file.path)));
}

export function govulncheckHasApplicableInput(snapshot: SourceSnapshot): boolean {
  return govulncheckFiles(snapshot).some(file => /(?:^|\/)go\.mod$/.test(file.path));
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid object');
  return value as Record<string, unknown>;
}

function token(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._/+!@~-]{0,511}$/.test(value)) throw new Error('invalid identifier');
  return value;
}

/** The Go encoder emits pretty-printed consecutive objects, not JSON lines. */
function messages(text: string): Record<string, unknown>[] {
  if (Buffer.byteLength(text) > 8 * 1024 * 1024) throw new Error('output limit');
  const result: Record<string, unknown>[] = [];
  let start = -1, depth = 0, quoted = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (start < 0) {
      if (/\s/.test(char!)) continue;
      if (char !== '{') throw new Error('invalid stream');
      start = i;
    }
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === '{' || char === '[') { if (++depth > 100) throw new Error('nesting limit'); }
    else if (char === '}' || char === ']') {
      if (--depth < 0) throw new Error('invalid stream');
      if (depth === 0) {
        result.push(object(JSON.parse(text.slice(start, i + 1))));
        if (result.length > 50_000) throw new Error('message limit');
        start = -1;
      }
    }
  }
  if (start !== -1 || !result.length) throw new Error('incomplete stream');
  return result;
}

export function parseGovulncheckOutput(text: string, files: CollectedFile[]): ParsedToolResult {
  const moduleMatches = [...(files.find(file => file.path === 'go.mod')?.text ?? '').matchAll(/^\s*module\s+(?:"([^"\r\n]+)"|([^\s]+))/gm)];
  if (moduleMatches.length !== 1) throw new Error('missing or ambiguous main module');
  const mainModule = token(moduleMatches[0]![1] ?? moduleMatches[0]![2]);
  if (mainModule.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('invalid main module');
  const stream = messages(text);
  const config = object(stream[0]?.config);
  if (Object.keys(stream[0]!).length !== 1 || config.protocol_version !== 'v1.0.0' || config.scan_level !== 'symbol' || config.scan_mode !== 'source') throw new Error('unsupported protocol');
  const entries = new Set<string>();
  const records: Record<string, unknown>[] = [];
  const modules = new Map<string, string>();
  let sbomSeen = false, roots = 0;
  for (const message of stream.slice(1)) {
    const keys = Object.keys(message);
    if (keys.length !== 1) throw new Error('invalid message');
    const key = keys[0]!, value = object(message[key]);
    if (key === 'osv') {
      if (typeof value.id !== 'string' || !/^GO-\d{4}-\d{4,}$/.test(value.id)) throw new Error('invalid advisory');
      entries.add(value.id);
    } else if (key === 'finding') records.push(value);
    else if (key === 'SBOM') {
      if (sbomSeen || !Array.isArray(value.roots) || !value.roots.length || !Array.isArray(value.modules)) throw new Error('invalid inventory');
      const rootPaths = value.roots.map(token);
      if (new Set(rootPaths).size !== rootPaths.length || rootPaths.some(path =>
        (path !== mainModule && !path.startsWith(`${mainModule}/`)) || path.split('/').some(part => !part || part === '.' || part === '..'))) throw new Error('unbound roots');
      const modulePaths = value.modules.map(module => { const m = object(module), path = token(m.path); modules.set(path, m.version ? token(m.version) : 'unknown'); return path; });
      if (modulePaths.filter(path => path === mainModule).length !== 1 || new Set(modulePaths).size !== modulePaths.length) throw new Error('unbound module inventory');
      sbomSeen = true; roots = value.roots.length;
    } else if (key !== 'progress') throw new Error('unknown message');
  }
  if (!sbomSeen) throw new Error('missing inventory');
  const findings = new Map<string, { finding: Finding; rank: number }>();
  for (const record of records) {
    const id = token(record.osv);
    if (!entries.has(id) || !Array.isArray(record.trace) || !record.trace.length || record.trace.length > 1024) throw new Error('invalid finding');
    const trace = record.trace.map(object), frame = trace[0]!;
    const module = token(frame.module), version = frame.version ? token(frame.version) : 'unknown';
    if (modules.get(module) !== version) throw new Error('unbound finding module or version');
    const fixed = record.fixed_version ? token(record.fixed_version) : undefined;
    const rank = frame.function ? 2 : frame.package ? 1 : 0;
    const location: Finding['location'] = { path: 'go.mod' };
    for (const current of trace) {
      token(current.module);
      if (current.package) token(current.package);
      if (current.function !== undefined && (typeof current.function !== 'string' || current.function.length > 1024)) throw new Error('invalid symbol');
      if (!current.position || current.module !== mainModule) continue;
      const position = object(current.position);
      const file = files.find(candidate => candidate.path === position.filename);
      const line = position.line;
      if (!file || !Number.isSafeInteger(line) || Number(line) < 1 || Number(line) > file.text.split('\n').length) throw new Error('unmapped position');
      location.path = file.path; location.line = Number(line);
    }
    const key = `${id}:${module}:${version}`;
    if ((findings.get(key)?.rank ?? -1) >= rank) continue;
    findings.set(key, { rank, finding: {
      ruleId: `govulncheck:${id}`,
      title: `${id} in ${module}`,
      description: `${module} ${version} is affected by a known Go vulnerability. ${rank === 2 ? 'Govulncheck reports a static call path to an affected symbol.' : rank === 1 ? 'An affected package is imported; a call to an affected symbol was not observed.' : 'The affected module is required; an affected package import was not observed.'} Severity is medium because the Go advisory protocol does not supply a severity rating.`,
      severity: 'medium', confidence: rank === 2 ? 'high' : 'medium', kind: 'advisory', location,
      remediation: fixed ? `Upgrade ${module === 'stdlib' ? 'the Go toolchain' : module} to ${fixed} or a newer unaffected version, then rerun the scan.` : 'No fixed version was reported. Review the Go advisory and remove or isolate the affected dependency until a fix is available.',
      references: [`https://pkg.go.dev/vuln/${id}`],
    } });
  }
  const values = [...findings.values()];
  return { findings: values.map(value => value.finding), status: 'completed',
    notes: ['Go module advisories are deduplicated by vulnerability and module version; the strongest observed reachability is retained. Static reachability is build-specific and cannot prove runtime exploitability or cover reflect/unsafe calls. No source snippets or raw scanner messages are retained.'],
    metrics: { rootsAnalyzed: roots, findingCount: values.length, reachableFindings: values.filter(value => value.rank === 2).length,
      goVersion: typeof config.go_version === 'string' && /^go[0-9][A-Za-z0-9.+_-]{0,79}$/.test(config.go_version) ? config.go_version : 'unknown',
      scannerVersion: typeof config.scanner_version === 'string' && /^[A-Za-z0-9.+_-]{1,80}$/.test(config.scanner_version) ? config.scanner_version : 'unknown' } };
}

export async function runGovulncheck(context: GovulncheckContext): Promise<CheckResult> {
  const check = (status: CheckResult['status'], note: string): CheckResult => ({ id: 'source.govulncheck', status, findings: [], notes: [note] });
  let buildTags: string[];
  try {
    buildTags = normalizeGoBuildTags(context.buildTags);
  } catch { return check('error', 'Invalid Go build tags; no engine was started.'); }
  const files = govulncheckFiles(context.snapshot), modules = files.filter(file => /(?:^|\/)go\.mod$/.test(file.path));
  if (!modules.length) return check('not_applicable', 'No collected Go module was available for govulncheck.');
  if (!context.snapshot.complete || modules.length !== 1 || modules[0]?.path !== 'go.mod') return check('partial', 'Govulncheck requires one complete root Go module. Incomplete snapshots and nested modules must be scanned separately.');
  // shortcut: all local replacements are refused; support a replacement only with a separately validated staged module graph.
  if (/=>\s*(?:"|`)?(?:\.{1,2}[\\/]|[\\/]|[A-Za-z]:[\\/])/.test(modules[0].text)) return check('partial', 'Local Go module replacements are unsupported because they can leave the staged source boundary.');
  if (!context.toolPath) return check('partial', 'Govulncheck executable was not found; Go vulnerability analysis was not performed.');
  const go = await findExecutable(context.goPath ?? 'go');
  if (!go) return check('partial', 'Go executable was not found. Supply a prepared Go toolchain; WakeIO does not install or download it during a scan.');
  let staged: StagedSnapshot | undefined;
  try {
    staged = await stageSnapshot({ ...context.snapshot, files });
    const privateRoot = join(dirname(staged.dir), 'govulncheck');
    const home = join(privateRoot, 'home'), cache = join(privateRoot, 'build-cache'), gopath = join(privateRoot, 'gopath');
    await Promise.all([home, cache, gopath].map(path => mkdir(path, { recursive: true, mode: 0o700 })));
    const args = ['-json', '-mode', 'source', '-scan', 'symbol', ...(context.database ? ['-db', context.database] : []),
      ...(buildTags.length ? ['-tags', buildTags.join(',')] : []), './...'];
    const result = await runProcess(context.toolPath, args, { cwd: staged.dir, timeoutMs: context.timeoutMs, home, signal: context.signal,
      runtimePath: dirname(go), environment: { GOTOOLCHAIN: 'local', GOWORK: 'off', GOFLAGS: '-mod=readonly', CGO_ENABLED: '0', GOENV: 'off', GOPROXY: 'off', GOSUMDB: 'off', GOPATH: gopath, GOCACHE: cache, GOMODCACHE: context.moduleCache ? resolve(context.moduleCache) : join(gopath, 'pkg', 'mod') } });
    if (result.cancelled || result.spawnError || result.timedOut || result.outputLimitExceeded || result.signal || result.exitCode !== 0) return check('error', 'Govulncheck did not complete. Check the prepared Go toolchain/module cache, build compatibility, vulnerability database, and timeout. Target dependencies and toolchains are never downloaded automatically.');
    const parsed = parseGovulncheckOutput(result.stdout, files);
    return { id: 'source.govulncheck', status: parsed.status ?? 'completed', findings: parsed.findings,
      notes: [...parsed.notes, `Go build tags: ${buildTags.join(',') || 'default'}; test packages: excluded. Other build configurations were not analyzed.`],
      metrics: { ...parsed.metrics, buildTags: buildTags.join(','), testPackages: false } };
  } catch { return check('error', 'Govulncheck output or staged runtime was invalid; Go vulnerability analysis is incomplete.'); }
  finally { await staged?.cleanup(); }
}
