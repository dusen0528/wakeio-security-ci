#!/usr/bin/env node

/** Whole-checkout, source-only measurement against reviewed, pinned OSS sites. */
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const require = createRequire(import.meta.url);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_MANIFEST = join(ROOT, 'benchmarks', 'oss-corpus.json');
const ENGINE = join(ROOT, 'build', 'src', 'index.js');
const COLLECTOR = join(ROOT, 'build', 'src', 'source', 'collector.js');
export const SOURCE_LIMITS = Object.freeze({ maxFiles: 10_000, maxBytes: 128 * 1024 * 1024 });
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const SAFE_ID = /^[a-z][a-z0-9-]{1,63}$/;
const SAFE_RULE = /^[a-z][a-z0-9:._-]{1,127}$/;
const GIT_ENV = Object.freeze({
  PATH: '/usr/bin:/bin', HOME: '/nonexistent', XDG_CONFIG_HOME: '/nonexistent', LC_ALL: 'C',
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_COUNT: '0',
  GIT_ATTR_NOSYSTEM: '1', GIT_OPTIONAL_LOCKS: '0', GIT_NO_REPLACE_OBJECTS: '1',
  GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: '',
});

export class OssBenchmarkError extends Error {
  constructor(code) { super(code); this.name = 'OssBenchmarkError'; this.code = code; }
}
function fail(code) { throw new OssBenchmarkError(code); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
function safePath(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 && !value.includes('\\')
    && !value.includes('\0') && !value.startsWith('/') && !value.split('/').some((piece) => !piece || piece === '.' || piece === '..');
}
function required(value, predicate, code) { if (!predicate(value)) fail(code); return value; }
function digest(value) { return createHash('sha256').update(value).digest('hex'); }
function percent(numerator, denominator) { return denominator ? Number((numerator / denominator).toFixed(4)) : null; }

export async function loadOssCorpus(path = DEFAULT_MANIFEST) {
  const manifestPath = resolve(path);
  const manifestStat = await lstat(manifestPath).catch(() => fail('manifest_unreadable'));
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size > 1024 * 1024) fail('manifest_invalid_file');
  const bytes = await readFile(manifestPath);
  let data;
  try { data = JSON.parse(bytes.toString('utf8')); } catch { fail('manifest_invalid_json'); }
  if (!object(data) || data.schemaVersion !== 'oss-corpus-v1' || !Array.isArray(data.repositories)
    || data.repositories.length === 0 || data.repositories.length > 32) fail('manifest_invalid_shape');
  const repoIds = new Set();
  const findingIds = new Set();
  for (const repo of data.repositories) {
    if (!object(repo) || !SAFE_ID.test(repo.id) || repoIds.has(repo.id)
      || typeof repo.url !== 'string' || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/.test(repo.url)
      || !SHA40.test(repo.commit) || !SHA40.test(repo.tree) || typeof repo.license !== 'string'
      || !object(repo.fileSha256) || Object.keys(repo.fileSha256).length > 1000
      || !Array.isArray(repo.expectedFindings) || repo.expectedFindings.length > 100
      || !Array.isArray(repo.reviewedNegativeSites) || repo.reviewedNegativeSites.length > 100) fail('manifest_invalid_repository');
    repoIds.add(repo.id);
    for (const [path, hash] of Object.entries(repo.fileSha256)) if (!safePath(path) || !SHA64.test(hash)) fail('manifest_invalid_file_hash');
    if (Object.keys(repo.fileSha256).length === 0) fail('manifest_missing_file_hash');
    for (const expected of repo.expectedFindings) {
      if (!object(expected) || !SAFE_ID.test(expected.id) || findingIds.has(expected.id)
        || !SAFE_RULE.test(expected.ruleId) || !safePath(expected.path) || !repo.fileSha256[expected.path]
        || !Array.isArray(expected.requiredFindings) || expected.requiredFindings.length === 0 || expected.requiredFindings.length > 8
        || !expected.requiredFindings.every((position) => object(position) && positive(position.line) && positive(position.column))) fail('manifest_invalid_expectation');
      if (new Set(expected.requiredFindings.map((position) => `${position.line}:${position.column}`)).size !== expected.requiredFindings.length) fail('manifest_duplicate_required_site');
      if (!['supported', 'known_unsupported', 'exploratory'].includes(expected.support)
        || !['source.builtin-ast', 'source.framework'].includes(expected.checkId)
        || typeof expected.basis !== 'string' || expected.basis.length < 12 || expected.basis.length > 500
        || typeof expected.sourceUrl !== 'string' || !expected.sourceUrl.includes(`/blob/${repo.commit}/`)) fail('manifest_invalid_expectation');
      if (expected.support !== 'known_unsupported' && !expected.requiredFindings.every((position) => object(position.source)
        && safePath(position.source.path) && !!repo.fileSha256[position.source.path]
        && positive(position.source.line) && positive(position.source.column))) fail('manifest_missing_source_trace');
      findingIds.add(expected.id);
    }
    for (const site of repo.reviewedNegativeSites) {
      if (!object(site) || !SAFE_ID.test(site.id) || findingIds.has(site.id) || !safePath(site.path)
        || !repo.fileSha256[site.path] || !positive(site.firstLine) || !positive(site.lastLine)
        || site.lastLine < site.firstLine || site.lastLine - site.firstLine > 100
        || !Array.isArray(site.ruleIds) || site.ruleIds.length === 0 || !site.ruleIds.every((rule) => SAFE_RULE.test(rule))
        || !['supported', 'known_unsupported', 'exploratory'].includes(site.support)
        || typeof site.basis !== 'string' || site.basis.length < 12 || site.basis.length > 500
        || typeof site.sourceUrl !== 'string' || !site.sourceUrl.includes(`/blob/${repo.commit}/`)) fail('manifest_invalid_negative_site');
      findingIds.add(site.id);
    }
  }
  return { data, sha256: digest(bytes) };
}

function parseArgs(argv) {
  const options = { manifest: DEFAULT_MANIFEST, profile: 'extended', checkouts: new Map() };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name === '--help') { options.help = true; continue; }
    if (!['--manifest', '--checkout', '--out', '--profile'].includes(name)) fail('unknown_option');
    const value = argv[++index];
    if (!value || value.startsWith('--')) fail('missing_option_value');
    if (name === '--manifest') options.manifest = resolve(value);
    else if (name === '--out') options.out = resolve(value);
    else if (name === '--profile') options.profile = value;
    else {
      const split = value.indexOf('=');
      const id = value.slice(0, split);
      const checkout = value.slice(split + 1);
      if (split < 1 || !SAFE_ID.test(id) || !isAbsolute(checkout) || !checkout || options.checkouts.has(id)) fail('invalid_checkout_argument');
      options.checkouts.set(id, checkout);
    }
  }
  if (options.help) return options;
  if (!options.out || !['default', 'extended'].includes(options.profile) || options.checkouts.size === 0) fail('invalid_options');
  return options;
}

async function git(checkout, args) {
  const fixed = ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '--no-optional-locks', '-C', checkout, ...args];
  try {
    const { stdout } = await exec('git', fixed, { encoding: 'buffer', env: GIT_ENV, maxBuffer: 32 * 1024 * 1024, timeout: 30_000, windowsHide: true });
    return stdout;
  } catch { fail('checkout_git_probe_failed'); }
}

async function hashFile(path, size) {
  const blob = createHash('sha1').update(`blob ${size}\0`);
  const sha256 = createHash('sha256');
  let read = 0;
  try {
    for await (const chunk of createReadStream(path)) {
      blob.update(chunk); sha256.update(chunk); read += chunk.length;
      if (read > size) fail('checkout_changed_during_hash');
    }
  } catch { fail('checkout_file_read_failed'); }
  if (read !== size) fail('checkout_changed_during_hash');
  return { blob: blob.digest('hex'), sha256: sha256.digest('hex') };
}

async function walkCheckout(root) {
  const paths = new Map();
  let totalBytes = 0;
  async function visit(dir, relativeDir = '', depth = 0) {
    if (depth > 64) fail('checkout_depth_limit');
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { fail('checkout_walk_failed'); }
    for (const entry of entries) {
      if (!relativeDir && entry.name === '.git') continue;
      const path = relativeDir ? `${relativeDir}/${entry.name}` : entry.name;
      if (!safePath(path)) fail('checkout_unsafe_path');
      const full = join(dir, entry.name);
      const stat = await lstat(full);
      if (stat.isSymbolicLink()) fail('checkout_symlink');
      if (stat.isDirectory()) await visit(full, path, depth + 1);
      else if (stat.isFile() && stat.nlink === 1) {
        totalBytes += stat.size;
        if (paths.size >= 20_000 || totalBytes > 2 * 1024 * 1024 * 1024) fail('checkout_verification_limit');
        paths.set(path, { full, stat });
      }
      else fail('checkout_special_or_hardlink');
    }
  }
  await visit(root);
  return paths;
}

/** Exact tracked tree plus no extra files, including ignored/untracked files. No git status/diff/filter is invoked. */
export async function verifyCheckout(repo, checkout) {
  if (!isAbsolute(checkout)) fail('checkout_not_absolute');
  const root = resolve(checkout);
  const rootStat = await lstat(root).catch(() => fail('checkout_unreadable'));
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || await realpath(root) !== root) fail('checkout_unsafe_root');
  const gitDir = await lstat(join(root, '.git')).catch(() => fail('checkout_git_dir_missing'));
  if (!gitDir.isDirectory() || gitDir.isSymbolicLink()) fail('checkout_unsafe_git_dir');
  const top = (await git(root, ['rev-parse', '--show-toplevel'])).toString('utf8').trim();
  if (top !== root) fail('checkout_not_repository_root');
  const objectFormat = (await git(root, ['rev-parse', '--show-object-format'])).toString('utf8').trim();
  if (objectFormat !== 'sha1') fail('checkout_unsupported_object_format');
  const head = (await git(root, ['rev-parse', '--verify', 'HEAD'])).toString('utf8').trim();
  const tree = (await git(root, ['rev-parse', 'HEAD^{tree}'])).toString('utf8').trim();
  if (head !== repo.commit || tree !== repo.tree) fail('checkout_commit_or_tree_mismatch');
  const tracked = new Map();
  for (const row of (await git(root, ['ls-tree', '-rz', '--full-tree', 'HEAD'])).toString('utf8').split('\0')) {
    if (!row) continue;
    const split = row.indexOf('\t');
    const header = row.slice(0, split).split(' ');
    const path = row.slice(split + 1);
    if (split < 0 || header.length !== 3 || !safePath(path) || tracked.has(path)) fail('checkout_invalid_tree');
    if (!['100644', '100755'].includes(header[0]) || header[1] !== 'blob' || !SHA40.test(header[2])) fail('checkout_symlink_or_submodule');
    tracked.set(path, { blob: header[2], executable: header[0] === '100755' });
  }
  const onDisk = await walkCheckout(root);
  if (tracked.size !== onDisk.size) fail('checkout_dirty_or_sparse');
  const expectedHashes = new Map(Object.entries(repo.fileSha256));
  for (const [path, gitFile] of tracked) {
    const disk = onDisk.get(path);
    if (!disk) fail('checkout_dirty_or_sparse');
    if (disk.stat.size > 512 * 1024 * 1024) fail('checkout_file_too_large_to_verify');
    const hashes = await hashFile(disk.full, disk.stat.size);
    const after = await lstat(disk.full);
    if (after.dev !== disk.stat.dev || after.ino !== disk.stat.ino || after.size !== disk.stat.size || after.mtimeMs !== disk.stat.mtimeMs) fail('checkout_changed_during_hash');
    if (hashes.blob !== gitFile.blob) fail('checkout_dirty_tracked_file');
    const executable = (disk.stat.mode & 0o111) !== 0;
    if (executable !== gitFile.executable) fail('checkout_dirty_file_mode');
    if (expectedHashes.has(path) && hashes.sha256 !== expectedHashes.get(path)) fail('checkout_expected_file_hash_mismatch');
    expectedHashes.delete(path);
  }
  if (expectedHashes.size > 0) fail('checkout_expected_file_missing');
  return { root, commit: head, tree, trackedFiles: tracked.size };
}

function findingSite(check, finding) {
  const path = finding?.location?.path;
  const line = finding?.location?.line;
  const column = finding?.location?.column;
  if (typeof finding?.ruleId !== 'string' || !['candidate', 'observation', 'advisory'].includes(finding.kind)
    || !safePath(path) || !positive(line)) fail('scan_invalid_finding');
  const flow = finding.staticFlow;
  const steps = flow?.kind === 'static_flow' && Array.isArray(flow.steps) ? flow.steps : [];
  const sourceSteps = steps.filter((step) => step.role === 'source').map((step) => step.location);
  const sinkSteps = steps.filter((step) => step.role === 'sink').map((step) => step.location);
  return { checkId: check.id, ruleId: finding.ruleId, kind: finding.kind, path, line,
    ...(positive(column) ? { column } : {}), flowComplete: flow?.kind === 'static_flow' && flow.truncated === false,
    sourceSteps, sinkSteps };
}
function samePosition(left, right) {
  return left?.path === right?.path && left?.line === right?.line && left?.column === right?.column;
}
function traceMatches(candidate, item, site) {
  return object(site.source) && candidate.flowComplete && candidate.sourceSteps.some((source) => samePosition(source, site.source))
    && candidate.sinkSteps.some((sink) => samePosition(sink, { path: item.path, line: site.line, column: site.column }));
}
function gapAt(check, path) {
  const gaps = check?.analysisGaps;
  return gaps?.accounting === 'unknown' || gaps?.truncated === true || (gaps?.eventsDropped ?? 0) > 0
    || Array.isArray(gaps?.items) && gaps.items.some((item) => item?.extent === 'check' || item?.location?.path === path);
}
function checkComplete(check) { return check?.status === 'completed'; }

/** No unmatched finding is called a false positive without independent review. */
export function evaluateOssRepository(repo, snapshot, checks) {
  if (!Array.isArray(checks)) fail('scan_invalid_checks');
  const checkMap = new Map();
  for (const check of checks) {
    if (!object(check) || typeof check.id !== 'string' || checkMap.has(check.id) || !Array.isArray(check.findings)) fail('scan_invalid_checks');
    checkMap.set(check.id, check);
  }
  const requiredChecks = ['source.inventory', 'source.builtin-ast', 'source.framework'];
  const statuses = requiredChecks.map((id) => ({ id, status: checkMap.get(id)?.status ?? 'missing' }));
  const ast = checkMap.get('source.builtin-ast');
  const scanComplete = snapshot.complete === true
    && statuses.every(({ id, status }) => status === 'completed' || id === 'source.framework' && status === 'not_applicable')
    && checks.every((check) => check.status === 'completed' || check.status === 'not_applicable')
    && ast?.metrics?.indexComplete === true && ast?.metrics?.parseErrorCount === 0 && !gapAt(ast, '');
  const selected = new Set(snapshot.files?.map((file) => file.path) ?? []);
  const candidates = checks.flatMap((check) => check.findings.map((finding) => findingSite(check, finding)));
  const unmatched = [...candidates];
  const expected = [];
  for (const item of repo.expectedFindings) {
    const observed = [];
    let traceMismatches = 0;
    for (const site of item.requiredFindings) {
      const index = unmatched.findIndex((candidate) => candidate.kind === 'candidate' && candidate.checkId === item.checkId && candidate.ruleId === item.ruleId
        && candidate.path === item.path && site.line === candidate.line && site.column === candidate.column && traceMatches(candidate, item, site));
      if (index >= 0) observed.push(unmatched.splice(index, 1)[0]);
      else if (unmatched.some((candidate) => candidate.kind === 'candidate' && candidate.checkId === item.checkId && candidate.ruleId === item.ruleId
        && candidate.path === item.path && site.line === candidate.line && site.column === candidate.column)) traceMismatches += 1;
    }
    const check = checkMap.get(item.checkId);
    const scopeComplete = selected.has(item.path) && snapshot.complete === true && checkComplete(check)
      && !gapAt(check, item.path) && item.support !== 'exploratory'
      && (item.checkId !== 'source.builtin-ast' || check?.metrics?.indexComplete === true && check?.metrics?.parseErrorCount === 0);
    if (observed.length === item.requiredFindings.length) {
      expected.push({ id: item.id, support: item.support, outcome: 'matched', scopeComplete, observed });
      continue;
    }
    if (observed.length > 0) {
      expected.push({ id: item.id, support: item.support, outcome: 'partial_match', scopeComplete, observed,
        traceMismatches, requiredCount: item.requiredFindings.length });
      continue;
    }
    const reason = !selected.has(item.path) ? 'expected_file_not_collected'
      : !snapshot.complete ? 'collector_incomplete'
      : !checkComplete(check) ? 'check_incomplete'
      : gapAt(check, item.path) ? 'analysis_gap'
      : item.support === 'exploratory' ? 'model_scope_uncommitted' : undefined;
    const outcome = item.support === 'known_unsupported' ? 'missing_known_unsupported'
      : !scopeComplete ? 'unevaluable_scope' : traceMismatches > 0 ? 'trace_mismatch' : 'missed_evaluable';
    expected.push({ id: item.id, support: item.support, outcome, scopeComplete,
      ...(traceMismatches ? { traceMismatches } : {}), ...(reason ? { coverageReason: reason } : {}) });
  }
  const negativeSites = repo.reviewedNegativeSites.map((site) => {
    const overlaps = unmatched.filter((candidate) => candidate.kind === 'candidate' && site.ruleIds.includes(candidate.ruleId) && site.path === candidate.path
      && candidate.line >= site.firstLine && candidate.line <= site.lastLine);
    return { id: site.id, status: site.support === 'known_unsupported' ? 'not_assessed_unsupported'
      : !selected.has(site.path) || !scanComplete ? 'unevaluable_scope' : overlaps.length ? 'unexpectedAtReviewedSite' : 'not_observed_at_reviewed_site', overlappingCandidates: overlaps.length };
  });
  const counts = {
    declaredExpected: expected.length,
    matched: expected.filter((entry) => entry.outcome === 'matched').length,
    partialMatch: expected.filter((entry) => entry.outcome === 'partial_match').length,
    traceMismatch: expected.filter((entry) => entry.outcome === 'trace_mismatch').length,
    missedEvaluable: expected.filter((entry) => entry.outcome === 'missed_evaluable').length,
    missingKnownUnsupported: expected.filter((entry) => entry.outcome === 'missing_known_unsupported').length,
    unevaluableScope: expected.filter((entry) => entry.outcome === 'unevaluable_scope').length,
    unreviewedCandidates: unmatched.filter((candidate) => candidate.kind === 'candidate').length,
    unreviewedObservations: unmatched.filter((candidate) => candidate.kind === 'observation').length,
    unreviewedAdvisories: unmatched.filter((candidate) => candidate.kind === 'advisory').length,
    unexpectedAtReviewedSite: negativeSites.reduce((sum, site) => sum + site.overlappingCandidates, 0),
  };
  return {
    id: repo.id, commit: repo.commit, tree: repo.tree, scanComplete,
    inventory: { complete: snapshot.complete === true, selectedFiles: selected.size, totalBytes: snapshot.totalBytes, issues: snapshot.issues?.map((issue) => ({ code: issue.code, path: issue.path })) ?? [] },
    checkStatuses: statuses,
    analysis: { profile: checkMap.get('source.builtin-ast')?.analysisBudget?.effectiveProfile ?? null,
      indexComplete: checkMap.get('source.builtin-ast')?.metrics?.indexComplete ?? null,
      parseErrorCount: checkMap.get('source.builtin-ast')?.metrics?.parseErrorCount ?? null,
      analysisGaps: checkMap.get('source.builtin-ast')?.analysisGaps ?? null },
    expected, negativeSites, unreviewedCandidates: unmatched, counts,
  };
}

export async function measureOssCorpus(corpus, checkouts, { runSource, collectSource, profile = 'extended', engineFingerprint = null, harnessSha256 = null }) {
  if (!['default', 'extended'].includes(profile) || typeof runSource !== 'function' || typeof collectSource !== 'function') fail('invalid_measurement_options');
  if (checkouts.size !== corpus.data.repositories.length || corpus.data.repositories.some((repo) => !checkouts.has(repo.id))) fail('checkout_set_mismatch');
  const roots = new Map();
  for (const repo of corpus.data.repositories) roots.set(repo.id, await verifyCheckout(repo, checkouts.get(repo.id)));
  const results = [];
  const rawChecks = new Map();
  for (const repo of corpus.data.repositories) {
    const root = roots.get(repo.id).root;
    const options = { root, tools: [], analysisProfile: profile, ...SOURCE_LIMITS };
    const snapshot = await collectSource(options);
    if (!object(snapshot) || !Array.isArray(snapshot.files) || !Array.isArray(snapshot.issues)) fail('collector_invalid_snapshot');
    let checks;
    try { checks = await runSource(options); }
    catch { checks = [{ id: 'source.inventory', status: 'error', findings: [], notes: [] }]; }
    await verifyCheckout(repo, root);
    results.push(evaluateOssRepository(repo, snapshot, checks));
    rawChecks.set(repo.id, checks);
  }
  const totals = { declaredExpected: 0, matched: 0, partialMatch: 0, traceMismatch: 0, missedEvaluable: 0, missingKnownUnsupported: 0, unevaluableScope: 0, unreviewedCandidates: 0, unreviewedObservations: 0, unreviewedAdvisories: 0, unexpectedAtReviewedSite: 0 };
  for (const result of results) for (const key of Object.keys(totals)) totals[key] += result.counts[key];
  const scanComplete = results.every((result) => result.scanComplete);
  const supported = results.flatMap((result) => result.expected).filter((item) => item.support === 'supported');
  const supportedUnevaluable = supported.filter((item) => !item.scopeComplete).length;
  const supportedMatched = supported.filter((item) => item.outcome === 'matched').length;
  const supportedPartial = supported.filter((item) => item.outcome === 'partial_match').length;
  const supportedMissed = supported.filter((item) => item.outcome === 'missed_evaluable').length;
  return {
    report: {
      schemaVersion: 'oss-benchmark-v1', corpusSha256: corpus.sha256, corpusVersion: corpus.data.schemaVersion,
      harnessSha256: harnessSha256 ?? digest(await readFile(fileURLToPath(import.meta.url))), engineFingerprint,
      measuredAt: new Date().toISOString(), configuration: { tools: [], analysisProfile: profile, ...SOURCE_LIMITS },
      summary: { ...totals, scanComplete, declaredObservedFraction: percent(totals.matched, totals.declaredExpected),
        supportedExpected: supported.length, supportedMatched, supportedPartial, supportedMissed, supportedUnevaluable,
        supportedRecall: scanComplete && supportedUnevaluable === 0 && supportedPartial === 0 ? percent(supportedMatched, supported.length) : null,
        precision: null, falsePositives: null, gateScope: 'all_declared_positive_sites_and_reviewed_negative_sites',
        exitCode: !scanComplete ? 2 : totals.matched !== totals.declaredExpected || totals.unexpectedAtReviewedSite > 0 ? 1 : 0 },
      repositories: results,
    }, rawChecks,
  };
}

function renderMarkdown(report) {
  const s = report.summary;
  const lines = [
    '# Pinned OSS source benchmark', '',
    `Manifest SHA-256: \`${report.corpusSha256}\``,
    `Configuration: \`runSource({ tools: [], analysisProfile: '${report.configuration.analysisProfile}', maxFiles: ${report.configuration.maxFiles}, maxBytes: ${report.configuration.maxBytes} })\``, '',
    '| Declared expectations | Matched | Partial match | Evaluable misses | Known unsupported missing | Unevaluable scope | Unreviewed candidates |',
    '| ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
    `| ${s.declaredExpected} | ${s.matched} | ${s.partialMatch} | ${s.missedEvaluable} | ${s.missingKnownUnsupported} | ${s.unevaluableScope} | ${s.unreviewedCandidates} |`, '',
    `Declared observed fraction: ${s.matched}/${s.declaredExpected} (${s.declaredObservedFraction ?? 'n/a'}). This is not population recall.`,
    `Supported-site recall: ${s.supportedRecall ?? 'unavailable because supported scope is incomplete'}.`,
    'Precision and false-positive count: unavailable; unmatched findings have not all been adjudicated.',
    `Scan complete: ${s.scanComplete}. Gate exit: ${s.exitCode}.`, '',
  ];
  for (const repo of report.repositories) {
    lines.push(`## ${repo.id} at ${repo.commit}`, '', `Scan complete: ${repo.scanComplete}. Collection issues: ${repo.inventory.issues.length}.`, '',
      '| Expected flow | Support | Outcome | Reason |', '| --- | --- | --- | --- |');
    for (const item of repo.expected) lines.push(`| ${item.id} | ${item.support} | ${item.outcome} | ${item.coverageReason ?? ''} |`);
    lines.push('', `Unreviewed candidates: ${repo.counts.unreviewedCandidates}; observations: ${repo.counts.unreviewedObservations}; advisories: ${repo.counts.unreviewedAdvisories}; unexpected at reviewed sites: ${repo.counts.unexpectedAtReviewedSite}.`, '');
  }
  return `${lines.join('\n')}\n`;
}

async function fingerprintEngine(buildRoot, toolVersion) {
  const files = [];
  async function visit(dir, prefix = '') {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (!safePath(path)) fail('engine_unsafe_path');
      if (entry.isDirectory()) await visit(join(dir, entry.name), path);
      else if (entry.isFile() && path.endsWith('.js')) files.push(path);
      else if (entry.isSymbolicLink()) fail('engine_symlink');
    }
  }
  await visit(buildRoot);
  if (files.length === 0) fail('engine_empty_build');
  const aggregate = createHash('sha256');
  for (const path of files.sort()) {
    const bytes = await readFile(join(buildRoot, path));
    aggregate.update(path).update('\0').update(digest(bytes)).update('\n');
  }
  const parserEntry = require.resolve('typescript');
  const parserPackage = join(ROOT, 'node_modules', 'typescript', 'package.json');
  const parserMeta = JSON.parse((await readFile(parserPackage)).toString('utf8'));
  return { buildJsSha256: aggregate.digest('hex'), buildJsFiles: files.length,
    typescriptEntrySha256: digest(await readFile(parserEntry)), typescriptVersion: parserMeta.version,
    typescriptPackageSha256: digest(await readFile(parserPackage)), packageLockSha256: digest(await readFile(join(ROOT, 'package-lock.json'))),
    toolVersion, nodeVersion: process.version, module: 'build/src/index.js' };
}
function sameFingerprint(left, right) { return JSON.stringify(left) === JSON.stringify(right); }

async function makeFreshOut(out, roots) {
  const target = resolve(out);
  for (const root of roots) if (target === root || target.startsWith(`${root}${sep}`)) fail('output_inside_checkout');
  const parent = dirname(target);
  if (await realpath(parent).catch(() => '') !== parent) fail('output_unsafe_parent');
  const parentStat = await lstat(parent).catch(() => fail('output_parent_missing'));
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) fail('output_unsafe_parent');
  try { await mkdir(target, { mode: 0o700 }); } catch { fail('output_must_be_new_directory'); }
  return target;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write('Usage: node scripts/benchmark-oss.mjs --checkout id=ABS_PATH [--checkout id=ABS_PATH] --out NEW_DIR [--manifest FILE] [--profile default|extended]\n');
    return 0;
  }
  const corpus = await loadOssCorpus(options.manifest);
  const harnessBefore = digest(await readFile(fileURLToPath(import.meta.url)));
  const packageVersion = JSON.parse((await readFile(join(ROOT, 'package.json'))).toString('utf8')).version;
  const buildBefore = await fingerprintEngine(dirname(ENGINE), packageVersion);
  const [{ runSource, createReport, writeReports, exitCode, REPORT_TOOL_VERSION }, { collectSource }] = await Promise.all([import(pathToFileURL(ENGINE).href), import(pathToFileURL(COLLECTOR).href)]);
  const engineFingerprint = await fingerprintEngine(dirname(ENGINE), REPORT_TOOL_VERSION);
  if (!sameFingerprint(buildBefore, engineFingerprint)) fail('engine_changed_during_import');
  const { report, rawChecks } = await measureOssCorpus(corpus, options.checkouts, { runSource, collectSource, profile: options.profile, engineFingerprint, harnessSha256: harnessBefore });
  if (!sameFingerprint(await fingerprintEngine(dirname(ENGINE), REPORT_TOOL_VERSION), engineFingerprint)
    || digest(await readFile(options.manifest)) !== corpus.sha256
    || digest(await readFile(fileURLToPath(import.meta.url))) !== report.harnessSha256) fail('measurement_inputs_changed');
  const out = await makeFreshOut(options.out, [...options.checkouts.values()].map((path) => resolve(path)));
  try {
    for (const repo of report.repositories) {
      const dir = join(out, repo.id);
      await mkdir(dir, { mode: 0o700 });
      const scanReport = createReport(rawChecks.get(repo.id), 'source', report.measuredAt);
      repo.scanExitCode = exitCode(scanReport, 'high');
      await writeReports(scanReport, dir, { failOn: 'high' });
      repo.reportArtifacts = Object.fromEntries(await Promise.all(['report.json', 'report.sarif', 'report.md', 'agent-report.json']
        .map(async (name) => [name, digest(await readFile(join(dir, name)))])));
    }
    if (!sameFingerprint(await fingerprintEngine(dirname(ENGINE), REPORT_TOOL_VERSION), engineFingerprint)
      || digest(await readFile(options.manifest)) !== corpus.sha256
      || digest(await readFile(fileURLToPath(import.meta.url))) !== report.harnessSha256) fail('measurement_inputs_changed');
    await writeFile(join(out, 'oss-benchmark.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await writeFile(join(out, 'oss-benchmark.md'), renderMarkdown(report), { mode: 0o600, flag: 'wx' });
  } catch (error) {
    await rm(out, { recursive: true, force: true });
    throw error;
  }
  process.stdout.write(`${JSON.stringify({ summary: report.summary, out }, null, 2)}\n`);
  return report.summary.exitCode;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`oss benchmark error: ${error instanceof OssBenchmarkError ? error.code : 'internal_error'}\n`);
    process.exitCode = 2;
  });
}
