#!/usr/bin/env node

/**
 * Entrypoint for the local composite GitHub Action.
 *
 * The Action executes the checked-in prebuilt bundle. It does not run npm in
 * the action checkout and it never invokes a script from the scanned project.
 * Inputs are converted into an argv array, so paths and URLs remain data.
 */

import { createHash } from 'node:crypto';
import { appendFile, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';

const spawnAsync = promisify(spawnProcess);
const TOOL_NAMES = new Set(['gitleaks', 'osv', 'trivy', 'bandit']);
const INCOMPLETE_STATUSES = new Set(['partial', 'error', 'skipped']);
const STABLE_SYSTEM_ALIASES = new Set(['/tmp', '/var']);

async function main() {
  const env = process.env;
  if (value(env.WAKEIO_MODE) === 'dast') return dastMain(env);
  const actionPath = resolve(env.WAKEIO_ACTION_PATH || env.GITHUB_ACTION_PATH || process.cwd());
  const source = value(env.WAKEIO_SOURCE);
  const url = value(env.WAKEIO_URL);
  const apiPolicy = value(env.WAKEIO_API_POLICY);
  const out = value(env.WAKEIO_OUT) || 'wakeio-security-reports';
  const requestedTools = value(env.WAKEIO_TOOLS) || 'gitleaks,osv,trivy';
  const sourceMode = Boolean(source);
  const analysisProfile = env.WAKEIO_ANALYSIS_PROFILE === undefined ? 'default' : env.WAKEIO_ANALYSIS_PROFILE;
  if (!['default', 'extended'].includes(analysisProfile) || (!sourceMode && analysisProfile !== 'default')) {
    process.stderr.write('wakeio-security-ci: analysis-profile must be default or extended; extended requires source.\n');
    process.exitCode = 2;
    return;
  }
  const tools = sourceMode ? requestedTools : 'none';
  const workspace = resolve(env.GITHUB_WORKSPACE || process.cwd());
  const reportDirectory = resolve(workspace, out);
  let previousReport;
  try { previousReport = await reportFingerprint(reportDirectory); } catch { previousReport = undefined; }
  const toolsRoot = await mkdtemp(join(tmpdir(), 'wakeio-security-ci-action-'));
  const state = {
    exitCode: 2,
    setupStatus: 'not-run',
    scanStatus: 'not-run',
    selectedTools: [],
    cacheMetadata: {},
    failurePhase: undefined,
  };
  let reportSummary;

  try {
    state.setupStatus = 'running';
    const cliEntry = await findCliEntry(actionPath);
    state.selectedTools = parseToolList(tools);
    const banditPath = value(env.WAKEIO_BANDIT_PATH);
    const nativeTools = state.selectedTools.filter((tool) => tool !== 'bandit').join(',') || 'none';
    const toolPaths = sourceMode
      ? await installTools(actionPath, toolsRoot, nativeTools, env)
      : { paths: {}, metadata: {} };
    // Bandit is applicability-aware in the CLI. A non-Python project stays
    // not_applicable without downloading or requiring a Bandit executable.
    if (state.selectedTools.includes('bandit') && banditPath) {
      toolPaths.paths.bandit = resolve(workspace, banditPath);
    }
    state.cacheMetadata = toolPaths.metadata ?? {};
    state.setupStatus = 'success';

    const args = [cliEntry, 'scan'];
    if (source) args.push('--source', source, '--analysis-profile', analysisProfile);
    if (url) args.push('--url', url);
    if (apiPolicy) args.push('--api-policy', apiPolicy);
    args.push('--out', out, '--tools', tools, '--fail-on', value(env.WAKEIO_FAIL_ON) || 'high');
    addValueOption(args, '--timeout-ms', env.WAKEIO_TIMEOUT_MS);
    addRepeatedOption(args, '--page', env.WAKEIO_PAGES);
    addValueOption(args, '--max-pages', env.WAKEIO_MAX_PAGES);
    if (asBoolean(env.WAKEIO_ALLOW_PRIVATE)) args.push('--allow-private');
    if (asBoolean(env.WAKEIO_OSV_OFFLINE)) args.push('--osv-offline');
    const projectId = value(env.WAKEIO_PROJECT_ID) || value(env.GITHUB_REPOSITORY);
    if (projectId) args.push('--project-id', projectId);
    for (const name of ['gitleaks', 'osv', 'trivy', 'bandit']) {
      if (toolPaths.paths?.[name] || toolPaths[name]) args.push(`--${name}`, toolPaths.paths?.[name] || toolPaths[name]);
    }

    state.scanStatus = 'running';
    const childEnv = {
      ...env,
      // Keep vulnerability databases on separate, explicitly unknown paths.
      // An explicitly prepared OSV path always wins; otherwise this is only a
      // namespace hint and is never presented as a verified DB cache.
      ...(value(env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY)
        ? {}
        : { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: join(cacheDirectory(env), 'osv-db') }),
    };
    const result = await runCommand(process.execPath, args, {
      // The scanned checkout is only the child cwd. No target package manager,
      // lifecycle hook, build, test, or script is invoked by this runner.
      cwd: workspace,
      env: childEnv,
      inherit: true,
      acceptedStatuses: [0, 1, 2],
    });
    state.exitCode = result.status;
    state.scanStatus = scanStatusFor(result.status);
  } catch (error) {
    state.exitCode = 2;
    if (state.setupStatus !== 'success') {
      state.setupStatus = 'failure';
      state.failurePhase = 'setup';
    } else {
      state.scanStatus = 'failure';
      state.failurePhase = 'scan';
    }
    // Keep setup errors bounded and free of scanner output, source snippets,
    // and credentials. The phase/status are available in the summary and
    // action outputs; the raw exception is intentionally not echoed.
    process.stderr.write(`wakeio-security-ci ${state.failurePhase} failed; no raw scanner output was retained.\n`);
    void error;
  } finally {
    try {
      reportSummary = await readReportSummary(reportDirectory, previousReport);
    } catch {
      reportSummary = undefined;
    }
    if (state.setupStatus === 'success' && state.scanStatus !== 'not-run' && !reportSummary) {
      // A prior report must never be surfaced as this run's result. A scan
      // without a newly written report is therefore incomplete even when the
      // child happened to return a clean status.
      state.exitCode = 2;
      state.scanStatus = 'failure';
    }
    try {
      await writeStatusArtifact(reportDirectory, state, reportSummary);
    } catch {
      process.stderr.write('wakeio-security-ci could not write its bounded status artifact.\n');
      if (state.exitCode === 0) state.exitCode = 2;
    }
    try {
      await writeActionOutputs(env, reportDirectory, state, reportSummary);
    } catch {
      process.stderr.write('wakeio-security-ci could not write GitHub Action outputs.\n');
      if (state.exitCode === 0) state.exitCode = 2;
    }
    try {
      await writeStepSummary(env, reportDirectory, state, reportSummary);
    } catch {
      process.stderr.write('wakeio-security-ci could not write the GitHub job summary.\n');
    }
    await rm(toolsRoot, { recursive: true, force: true }).catch(() => undefined);
  }
  process.exitCode = state.exitCode;
}

/**
 * Active DAST entrypoint (dast/action.yml). Every refusal happens before any
 * tool download, DNS lookup or request, and is still recorded as a bounded
 * status artifact, Action outputs and job summary.
 */
async function dastMain(env) {
  const actionPath = resolve(env.WAKEIO_ACTION_PATH || env.GITHUB_ACTION_PATH || process.cwd());
  const workspace = resolve(env.GITHUB_WORKSPACE || process.cwd());
  const out = value(env.WAKEIO_OUT) || 'wakeio-dast-reports';
  const reportDirectory = resolve(workspace, out);
  let previousReport;
  try { previousReport = await reportFingerprint(reportDirectory); } catch { previousReport = undefined; }
  const toolsRoot = await mkdtemp(join(tmpdir(), 'wakeio-security-ci-dast-'));
  const state = { exitCode: 2, setupStatus: 'not-run', scanStatus: 'not-run', selectedTools: [], cacheMetadata: {}, failurePhase: undefined };
  let reportSummary;
  let plan;
  try {
    plan = await dastPolicy(env);
    if (plan.refusal) {
      state.setupStatus = 'refused';
      state.failurePhase = 'policy';
      process.stderr.write(`wakeio-security-ci DAST refused: ${plan.refusal}\n`);
      return;
    }
    state.setupStatus = 'running';
    const cliEntry = await findCliEntry(actionPath);
    const args = [cliEntry, 'scan', '--active-consent', '--tools', 'none', '--out', out, '--fail-on', value(env.WAKEIO_FAIL_ON) || 'high'];
    if (plan.nuclei) {
      // Verify the pinned template set before downloading the engine.
      const templates = resolve(workspace, value(env.WAKEIO_NUCLEI_TEMPLATES));
      const digest = createHash('sha256').update(await readFile(join(templates, 'templates-checksum.txt'))).digest('hex');
      if (digest !== value(env.WAKEIO_NUCLEI_TEMPLATES_SHA256).toLowerCase()) throw new Error('nuclei templates digest mismatch');
      const installed = await installTools(actionPath, toolsRoot, 'nuclei', env);
      state.cacheMetadata = installed.metadata ?? {};
      if (typeof installed.paths?.nuclei !== 'string' || !installed.paths.nuclei) throw new Error('pinned nuclei installation returned no executable');
      args.push('--url', plan.nuclei, '--engine', 'nuclei', '--nuclei', installed.paths.nuclei, '--nuclei-templates', templates);
      addValueOption(args, '--nuclei-scope', env.WAKEIO_NUCLEI_SCOPE);
      addValueOption(args, '--nuclei-max-requests', env.WAKEIO_NUCLEI_MAX_REQUESTS);
      addValueOption(args, '--nuclei-rate-limit', env.WAKEIO_NUCLEI_RATE_LIMIT);
      addValueOption(args, '--nuclei-timeout-ms', env.WAKEIO_NUCLEI_TIMEOUT_MS);
    }
    if (plan.apiBase) {
      args.push('--openapi', value(env.WAKEIO_OPENAPI), '--api-base', plan.apiBase);
      addRepeatedOption(args, '--operation', env.WAKEIO_OPERATIONS);
      addValueOption(args, '--api-max-requests', env.WAKEIO_API_MAX_REQUESTS);
      addValueOption(args, '--seed', env.WAKEIO_SEED);
      addValueOption(args, '--schemathesis-python', env.WAKEIO_SCHEMATHESIS_PYTHON);
    }
    addValueOption(args, '--timeout-ms', env.WAKEIO_TIMEOUT_MS);
    if (asBoolean(env.WAKEIO_ALLOW_PRIVATE)) args.push('--allow-private');
    const projectId = value(env.WAKEIO_PROJECT_ID) || value(env.GITHUB_REPOSITORY);
    if (projectId) args.push('--project-id', projectId);
    state.setupStatus = 'success';
    state.scanStatus = 'running';
    const result = await runCommand(process.execPath, args, { cwd: workspace, env, inherit: true, acceptedStatuses: [0, 1, 2] });
    state.exitCode = result.status;
    state.scanStatus = scanStatusFor(result.status);
  } catch (error) {
    state.exitCode = 2;
    if (state.setupStatus !== 'success') { state.setupStatus = 'failure'; state.failurePhase = 'setup'; }
    else { state.scanStatus = 'failure'; state.failurePhase = 'scan'; }
    process.stderr.write(`wakeio-security-ci DAST ${state.failurePhase} failed; no raw scanner output was retained.\n`);
    void error;
  } finally {
    try { reportSummary = await readReportSummary(reportDirectory, previousReport); } catch { reportSummary = undefined; }
    if (state.setupStatus === 'success' && state.scanStatus !== 'not-run' && !reportSummary) { state.exitCode = 2; state.scanStatus = 'failure'; }
    try { await writeStatusArtifact(reportDirectory, state, reportSummary); }
    catch { process.stderr.write('wakeio-security-ci could not write its bounded status artifact.\n'); if (state.exitCode === 0) state.exitCode = 2; }
    try { await writeActionOutputs(env, reportDirectory, state, reportSummary); }
    catch { process.stderr.write('wakeio-security-ci could not write GitHub Action outputs.\n'); if (state.exitCode === 0) state.exitCode = 2; }
    try { await writeStepSummary(env, reportDirectory, state, reportSummary, plan); }
    catch { process.stderr.write('wakeio-security-ci could not write the GitHub job summary.\n'); }
    await rm(toolsRoot, { recursive: true, force: true }).catch(() => undefined);
    // Set inside finally: a policy refusal returns early and must still exit 2.
    process.exitCode = state.exitCode;
  }
}

/** Fixed refusal reasons only; never echoes inputs, URLs or event contents. */
async function dastPolicy(env) {
  const refuse = (refusal) => ({ refusal });
  if (value(env.WAKEIO_ACTIVE_CONSENT) !== 'true') return refuse('active-consent must be exactly "true" for an owned or authorized target');
  const event = value(env.GITHUB_EVENT_NAME);
  if (event === 'pull_request_target') return refuse('pull_request_target is not allowed for active DAST');
  if (event.startsWith('pull_request') || event === 'workflow_run') {
    let payload;
    try { payload = JSON.parse(await readFile(value(env.GITHUB_EVENT_PATH), 'utf8')); } catch { return refuse('the event payload could not be read to rule out a fork'); }
    const head = event === 'workflow_run' ? payload?.workflow_run?.head_repository?.full_name : payload?.pull_request?.head?.repo?.full_name;
    const base = event === 'workflow_run' ? payload?.workflow_run?.repository?.full_name : payload?.pull_request?.base?.repo?.full_name;
    if (typeof head !== 'string' || typeof base !== 'string' || head !== base) return refuse('changes from a fork cannot run active DAST');
  }
  const allowed = new Set();
  for (const raw of value(env.WAKEIO_ALLOWED_ORIGINS).split(/[,\r\n]+/).map((item) => item.trim()).filter(Boolean)) {
    const origin = originOf(raw);
    if (!origin) return refuse('allowed-origins must list origins only, such as https://staging.example.test');
    allowed.add(origin);
  }
  if (allowed.size === 0) return refuse('allowed-origins is required');
  const engines = value(env.WAKEIO_ENGINES).split(',').map((item) => item.trim()).filter(Boolean);
  if (engines.some((engine) => engine !== 'nuclei') || new Set(engines).size !== engines.length) return refuse('engines must be nuclei or empty');
  const plan = {};
  if (engines.includes('nuclei')) {
    const target = originOf(value(env.WAKEIO_URL), true);
    if (!target) return refuse('engines: nuclei requires an http(s) url');
    if (!value(env.WAKEIO_NUCLEI_TEMPLATES) || !/^[a-f0-9]{64}$/i.test(value(env.WAKEIO_NUCLEI_TEMPLATES_SHA256))) return refuse('engines: nuclei requires nuclei-templates and nuclei-templates-sha256');
    if (!allowed.has(target)) return refuse('the url origin is not in allowed-origins');
    plan.nuclei = `${target}/`;
  }
  if (value(env.WAKEIO_OPENAPI)) {
    const target = originOf(value(env.WAKEIO_API_BASE));
    if (!target || !value(env.WAKEIO_OPERATIONS)) return refuse('openapi requires an origin api-base and at least one operation');
    if (!allowed.has(target)) return refuse('the api-base origin is not in allowed-origins');
    plan.apiBase = `${target}/`;
  }
  if (!plan.nuclei && !plan.apiBase) return refuse('select engines: nuclei and/or openapi');
  return plan;
}

function originOf(raw, allowPath = false) {
  let parsed;
  try { parsed = new URL(raw); } catch { return undefined; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) return undefined;
  if (!allowPath && parsed.pathname !== '/') return undefined;
  return parsed.origin;
}

async function findCliEntry(actionPath) {
  const candidates = [
    join(actionPath, 'dist-action', 'wakeio-security-ci.mjs'),
    join(actionPath, 'build', 'action', 'wakeio-security-ci.mjs'),
    join(actionPath, 'build', 'action', 'wakeio-security-ci.cjs'),
    // A source checkout that has been built locally can still be exercised;
    // release archives and the committed Action path use the first candidate.
    join(actionPath, 'build', 'src', 'cli.js'),
  ];
  for (const candidate of candidates) {
    try {
      const info = await lstat(candidate);
      if (info.isFile() && !info.isSymbolicLink()) return candidate;
    } catch {
      // Try the next explicit build output.
    }
  }
  throw new Error('prebuilt Action bundle is missing');
}

async function installTools(actionPath, toolsRoot, tools, env) {
  const script = join(actionPath, 'scripts', 'install-tools.mjs');
  const cacheRoot = cacheDirectory(env);
  const result = await runCommand(
    process.execPath,
    [script, '--tools', tools, '--dir', toolsRoot, '--cache-dir', cacheRoot, '--json', '--metadata'],
    { cwd: actionPath, env, capture: true },
  );
  try {
    const parsed = JSON.parse(result.stdout.trim() || '{}');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
    if (parsed.paths && typeof parsed.paths === 'object') return parsed;
    // Keep compatibility with an older local installer while the Action
    // bundle is being upgraded in a vendored checkout.
    return { paths: parsed, metadata: {} };
  } catch {
    throw new Error('scanner tool installer returned invalid JSON');
  }
}

function cacheDirectory(env) {
  const configured = value(env.WAKEIO_TOOL_CACHE);
  if (configured) return resolve(configured);
  const runnerCache = value(env.RUNNER_TOOL_CACHE);
  if (runnerCache) return resolve(runnerCache, 'wakeio-security-ci', 'native');
  const xdg = value(env.XDG_CACHE_HOME);
  if (xdg) return resolve(xdg, 'wakeio-security-ci', 'native');
  return join(tmpdir(), 'wakeio-security-ci-cache', 'native');
}

function parseToolList(raw) {
  if (raw.trim().toLowerCase() === 'none') return [];
  const tools = raw.split(',').map((tool) => tool.trim().toLowerCase()).filter(Boolean);
  if (tools.length === 0 || tools.includes('none') || tools.some((tool) => !TOOL_NAMES.has(tool)) || new Set(tools).size !== tools.length) {
    throw new Error('invalid scanner tool selection');
  }
  return tools;
}

function scanStatusFor(status) {
  if (status === 0) return 'success';
  if (status === 1) return 'findings';
  return 'incomplete';
}

function addValueOption(args, name, raw) {
  const valueText = value(raw);
  if (valueText) args.push(name, valueText);
}

function addRepeatedOption(args, name, raw) {
  const values = typeof raw === 'string'
    ? raw.split(/[,\r\n]+/).map((item) => item.trim()).filter(Boolean)
    : [];
  for (const item of values) args.push(name, item);
}

function value(input) {
  return typeof input === 'string' ? input.trim() : '';
}

function asBoolean(input) {
  return ['1', 'true', 'yes', 'on'].includes(value(input).toLowerCase());
}

async function reportFingerprint(reportDirectory) {
  const reportPath = join(reportDirectory, 'report.json');
  let info;
  try { info = await lstat(reportPath); } catch (error) { if (error?.code === 'ENOENT') return undefined; throw error; }
  if (info.isSymbolicLink() || !info.isFile() || info.size > 16 * 1024 * 1024) return undefined;
  const digest = createHash('sha256').update(await readFile(reportPath)).digest('hex');
  return `${info.size}:${info.mtimeMs}:${digest}`;
}

async function readReportSummary(reportDirectory, previousReport) {
  const reportPath = join(reportDirectory, 'report.json');
  const info = await lstat(reportPath);
  if (info.isSymbolicLink() || !info.isFile() || info.size > 16 * 1024 * 1024) return undefined;
  const bytes = await readFile(reportPath);
  const digest = createHash('sha256').update(bytes).digest('hex');
  const currentReport = `${info.size}:${info.mtimeMs}:${digest}`;
  if (previousReport && currentReport === previousReport) return undefined;
  const parsed = JSON.parse(bytes.toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.checks)) return undefined;
  const checks = parsed.checks.filter((check) => check && typeof check === 'object');
  const findings = checks.reduce((total, check) => total + (Array.isArray(check.findings) ? check.findings.length : 0), 0);
  const incomplete = checks.filter((check) => INCOMPLETE_STATUSES.has(check.status)).length;
  let agentReportAvailable = false;
  try {
    const agentPath = join(reportDirectory, 'agent-report.json');
    const agentInfo = await lstat(agentPath);
    if (!agentInfo.isSymbolicLink() && agentInfo.isFile() && agentInfo.size <= 16 * 1024 * 1024) {
      const agent = JSON.parse(await readFile(agentPath, 'utf8'));
      agentReportAvailable = agent?.schemaVersion === '1.0.0'
        && agent.reportArtifact?.name === 'report.json'
        && agent.reportArtifact?.algorithm === 'sha256'
        && agent.reportArtifact?.digest === digest;
    }
  } catch {
    // Optional projection availability cannot turn an old artifact into a
    // fresh receipt, or discard the three existing report consumers.
  }
  return {
    findingCount: findings,
    incompleteCount: incomplete,
    agentReportAvailable,
    checks: checks.map((check) => ({
      // Check IDs are generated by the package and are safe to display only
      // after reducing them to a bounded identifier string.
      id: safeIdentifier(check.id),
      status: safeStatus(check.status),
    })),
  };
}

function safeIdentifier(input) {
  return typeof input === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(input) ? input : 'check';
}

function safeStatus(input) {
  return ['completed', 'partial', 'error', 'not_applicable', 'skipped'].includes(input) ? input : 'unknown';
}

async function writeStatusArtifact(reportDirectory, state, reportSummary) {
  await ensureSafeDirectory(reportDirectory);
  const target = join(reportDirectory, 'action-status.json');
  let info;
  try { info = await lstat(target); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  if (info?.isSymbolicLink() || (info && !info.isFile())) throw new Error('status artifact target is not a regular file');
  const contents = JSON.stringify({
    schemaVersion: '1.0.0',
    setupStatus: state.setupStatus,
    scanStatus: state.scanStatus,
    exitCode: state.exitCode,
    findingCount: reportSummary?.findingCount ?? 0,
    incompleteCount: reportSummary?.incompleteCount ?? 0,
    nativeArchiveCache: cacheStatus(state.cacheMetadata),
    databaseCaches: { osv: 'unknown', trivy: 'unknown' },
  }, null, 2) + '\n';
  await writeFile(target, contents, { encoding: 'utf8', mode: 0o644 });
}

function cacheStatus(metadata) {
  const entries = Object.entries(metadata ?? {});
  if (entries.length === 0) return 'not_requested';
  return Object.fromEntries(entries.map(([name, item]) => [name, item?.cacheHit === true ? 'hit' : 'miss']));
}

async function writeActionOutputs(env, reportDirectory, state, reportSummary) {
  const outputFile = value(env.GITHUB_OUTPUT);
  if (!outputFile) return;
  const values = {
    'report-dir': reportDirectory,
    'report-json': join(reportDirectory, 'report.json'),
    'report-sarif': join(reportDirectory, 'report.sarif'),
    'report-markdown': join(reportDirectory, 'report.md'),
    'report-agent': reportSummary?.agentReportAvailable ? join(reportDirectory, 'agent-report.json') : '',
    'exit-code': String(state.exitCode),
    'finding-count': String(reportSummary?.findingCount ?? 0),
    'incomplete-count': String(reportSummary?.incompleteCount ?? 0),
    'setup-status': state.setupStatus,
    'scan-status': state.scanStatus,
  };
  const lines = Object.entries(values).map(([key, item]) => `${key}=${safeOutputValue(item)}`).join('\n') + '\n';
  await appendFile(outputFile, lines, { encoding: 'utf8' });
}

async function writeStepSummary(env, reportDirectory, state, reportSummary, dastPlan) {
  const summaryFile = value(env.GITHUB_STEP_SUMMARY);
  if (!summaryFile) return;
  const checks = reportSummary?.checks?.map((check) => `${check.id}: ${check.status}`).join(', ') || 'report unavailable';
  const cache = cacheStatus(state.cacheMetadata);
  const cacheText = typeof cache === 'string' ? cache : Object.entries(cache).map(([name, status]) => `${name} ${status}`).join(', ');
  const lines = [
    dastPlan ? '## Wakeio Security CI (active DAST)' : '## Wakeio Security CI',
    '',
    ...(dastPlan ? [`- Active targets: ${escapeMarkdown([dastPlan.nuclei && `nuclei ${dastPlan.nuclei}`, dastPlan.apiBase && `schemathesis ${dastPlan.apiBase}`].filter(Boolean).join(', ') || 'none (refused before setup)')}`] : []),
    `- Setup: **${state.setupStatus}**`,
    `- Scan: **${state.scanStatus}** (exit code ${state.exitCode})`,
    `- Findings: **${reportSummary?.findingCount ?? 0}**`,
    `- Incomplete checks: **${reportSummary?.incompleteCount ?? 0}**`,
    `- Checks: ${escapeMarkdown(checks)}`,
    `- Native archive cache: ${escapeMarkdown(cacheText)}`,
    '- OSV database cache: **unknown** (scanner-managed; not verified by this Action)',
    '- Trivy database cache: **unknown** (scanner-managed; not verified by this Action)',
    `- Reports: ${escapeMarkdown(reportDirectory)}`,
    `- Agent report: ${reportSummary?.agentReportAvailable ? 'agent-report.json (digest bound to this run\'s report.json)' : 'unavailable'}`,
    '- Agent scanGate is scan adjudication; final Action/process status is a separate receipt. Stale or partial artifacts do not prove CI success.',
    '',
  ];
  await appendFile(summaryFile, lines.join('\n'), { encoding: 'utf8' });
  if (state.setupStatus === 'refused') emitAnnotation('error', 'Wakeio active DAST was refused by its consent, origin or trigger policy; no request was sent.');
  else if (state.setupStatus === 'failure') emitAnnotation('error', 'Wakeio setup failed; reports may be unavailable.');
  else if (state.scanStatus === 'incomplete') emitAnnotation('warning', 'Wakeio scan incomplete; review report statuses before relying on coverage.');
}

function safeOutputValue(input) {
  return String(input).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\r\n]/g, ' ');
}

function escapeMarkdown(input) {
  return String(input)
    .replace(/\\/g, '\\\\')
    .replace(/[`|*_{}\[\]<>]/g, (character) => `\\${character}`)
    .replace(/[\r\n]/g, ' ')
    .slice(0, 512);
}

export function escapeWorkflowCommandProperty(input) {
  return String(input)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A')
    .replace(/:/g, '%3A')
    .replace(/,/g, '%2C');
}

export function escapeWorkflowCommandMessage(input) {
  return String(input).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function emitAnnotation(level, message) {
  process.stdout.write(`::${level}::${escapeWorkflowCommandMessage(message)}\n`);
}

function spawnProcess(command, args, options, callback) {
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: options.capture ? ['ignore', 'pipe', 'inherit'] : options.inherit === false ? 'pipe' : 'inherit',
    shell: false,
  });
  let stdout = '';
  if (child.stdout) child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
  let settled = false;
  const finish = (error, result) => {
    if (settled) return;
    settled = true;
    callback(error, result);
  };
  child.on('error', (error) => finish(error));
  child.on('close', (status, signal) => finish(null, { status: status ?? 2, signal, stdout }));
}

async function runCommand(command, args, options = {}) {
  const result = await spawnAsync(command, args, options);
  const accepted = options.acceptedStatuses || [0];
  if (!accepted.includes(result.status)) throw new Error(`${command} exited with status ${result.status}`);
  return result;
}

async function ensureSafeDirectory(directory) {
  const absolute = resolve(directory);
  const root = resolve(absolute, sep);
  const parts = absolute.slice(root.length).split(sep).filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = resolve(current, part);
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await mkdir(current);
      info = await lstat(current);
    }
    if (info.isSymbolicLink()) {
      if (!STABLE_SYSTEM_ALIASES.has(current)) throw new Error('report directory contains a symbolic link');
      continue;
    }
    if (!info.isDirectory()) throw new Error('report output path is not a directory');
  }
}

// This file is the Action's dedicated process entrypoint; run it directly.
// Avoid comparing /var and /private/var spellings because macOS may expose
// the extracted source archive through either stable alias.
main().catch(() => {
  process.stderr.write('wakeio-security-ci action failed before a report could be finalized.\n');
  process.exitCode = 2;
});
