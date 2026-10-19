import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createApiRunControl } from './api.js';
import { RunAdmission } from './agent-dast/admission.js';
import type { CheckResult, Finding, Severity } from './contracts.js';
import { resolveDastOrigin, startEgressGate, type EgressGate } from './dast-egress.js';
import { findExecutable, MAX_PROCESS_OUTPUT_BYTES, MAX_TOOL_TIMEOUT_MS, runProcess } from './source/process.js';
import { normalizeUrl, safeUrl, UrlNetworkError } from './url-network.js';

export const ZAP_CHECK_ID = 'url.zap';
export const ZAP_VERSION = '2.17.0';
export const ZAP_DEFAULT_MAX_REQUESTS = 200;
export const ZAP_MAX_REQUESTS = 2000;
export const ZAP_DEFAULT_TIMEOUT_MS = 300_000;
export const ZAP_DEFAULT_RATE_LIMIT = 10;
export const ZAP_MAX_RATE_LIMIT = 50;
const RULES = [40012, 40018];
const SCOPE = 'ZAP actively tests only the supplied HTTP GET query URLs for reflected XSS and SQL injection through the shared egress gate. No spider, authentication flow, script, out-of-band callback or update is enabled. GET attacks can still have side effects; use an explicitly approved disposable target. This is not an authorization or complete application-security assessment.';
export interface ZapOptions {
  url: string;
  paths: string[];
  executable?: string;
  consent: boolean;
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxRequests?: number;
  rateLimit?: number;
  signal?: AbortSignal;
}

function error(code: string, message: string): CheckResult[] {
  return [{ id: ZAP_CHECK_ID, status: 'error', findings: [], notes: [SCOPE, message], metrics: { engine: 'zap', errorCode: code, requestCount: 0 } }];
}
function bounded(value: number | undefined, fallback: number, cap: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > cap) throw new TypeError('invalid_budget');
  return result;
}
function selectedUrls(origin: string, paths: string[]): URL[] {
  if (!Array.isArray(paths) || !paths.length || paths.length > 16 || new Set(paths).size !== paths.length) throw new TypeError('invalid_paths');
  return paths.map(path => {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.length > 2048 || /[\u0000-\u0020\u007f#\\]/.test(path)) throw new TypeError('invalid_paths');
    const url = new URL(path, origin);
    if (url.origin !== origin || !url.search || ![...url.searchParams.keys()].length || url.username || url.password) throw new TypeError('invalid_paths');
    for (const segment of url.pathname.split('/')) {
      const value = decodeURIComponent(segment);
      if (value === '.' || value === '..' || /[%\\/;\u0000-\u001f\u007f]/.test(value)) throw new TypeError('invalid_paths');
    }
    return url;
  });
}
const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** JSON is a YAML subset; generated data cannot inject extra automation jobs. */
export function buildZapPlan(urls: URL[], proxy: URL, directory: string): object {
  const allowed = [...new Set(urls.map(url => `${escapeRegex(url.origin + url.pathname)}(?:\\?.*)?`))];
  return {
    env: {
      // Context urls add broad regexes; exclusions must constrain their union, not just add includePaths.
      contexts: [{ name: 'wakeio', urls: [urls[0]!.origin], includePaths: allowed.map(path => `^${path}$`), excludePaths: [`^(?!(?:${allowed.join('|')})$).*$`] }],
      parameters: { failOnError: true, failOnWarning: true, continueOnFailure: false, progressToStdout: false },
      proxy: { hostname: proxy.hostname, port: Number(proxy.port), username: proxy.username, password: proxy.password },
    },
    jobs: [
      { type: 'passiveScan-config', parameters: { disableAllRules: true } },
      { type: 'activeScan-config', parameters: { threadPerHost: 1, handleAntiCSRFTokens: false }, inputVectors: {
        urlQueryStringAndDataDrivenNodes: { enabled: true, addParam: false, odata: false },
        postData: { enabled: false }, urlPath: false, httpHeaders: { enabled: false, allRequests: false },
        cookieData: { enabled: false }, scripts: false,
      } },
      { type: 'requestor', requests: urls.map(url => ({ url: url.href, method: 'GET', responseCode: 200 })) },
      // Only the outer supervisor/gate may stop a scan: ZAP's per-rule timeouts can silently skip work.
      { type: 'activeScan', parameters: { context: 'wakeio', threadPerHost: 1, handleAntiCSRFTokens: false, maxRuleDurationInMins: 0, maxScanDurationInMins: 0 },
        policyDefinition: { defaultThreshold: 'Off', defaultStrength: 'Low', rules: RULES.map(id => ({ id, strength: 'Low', threshold: 'Medium' })) } },
      { type: 'report', parameters: { template: 'traditional-json', reportDir: directory, reportFile: 'report.json', displayReport: false } },
    ],
  };
}

function object(value: unknown): value is Record<string, unknown> { return !!value && typeof value === 'object' && !Array.isArray(value); }
/** Project only rule metadata. Engine strings, payloads and evidence never enter the shared report. */
export function parseZapReport(raw: unknown, origin: string, paths: string[]): { findings: Finding[]; malformed: number; outOfScope: number } {
  const result = { findings: [] as Finding[], malformed: 0, outOfScope: 0 };
  if (!object(raw) || raw['@version'] !== ZAP_VERSION || !Array.isArray(raw.site)) return { ...result, malformed: 1 };
  const urls = selectedUrls(origin, paths), seen = new Set<string>();
  const severities: Severity[] = ['info', 'low', 'medium', 'high'];
  for (const site of raw.site) {
    if (!object(site) || typeof site['@name'] !== 'string' || !Array.isArray(site.alerts)) { result.malformed++; continue; }
    try { if (normalizeUrl(site['@name']).origin !== origin) { result.outOfScope++; continue; } } catch { result.malformed++; continue; }
    for (const alert of site.alerts) {
      if (!object(alert) || !RULES.some(id => String(id) === alert.pluginid) || !['0', '1', '2', '3'].includes(String(alert.riskcode))
        || !['0', '1', '2', '3', '4'].includes(String(alert.confidence)) || !Array.isArray(alert.instances) || !alert.instances.length) { result.malformed++; continue; }
      if (String(alert.confidence) === '0') continue;
      for (const instance of alert.instances) {
        if (!object(instance) || typeof instance.uri !== 'string' || instance.method !== 'GET' || typeof instance.param !== 'string') { result.malformed++; continue; }
        let url: URL;
        try { url = new URL(normalizeUrl(instance.uri).href); } catch { result.malformed++; continue; }
        if (url.origin !== origin || !urls.some(seed => seed.pathname === url.pathname && seed.searchParams.has(instance.param as string))) { result.outOfScope++; continue; }
        const key = JSON.stringify([alert.pluginid, url.pathname, instance.param]);
        if (seen.has(key)) continue;
        seen.add(key);
        const xss = alert.pluginid === '40012';
        result.findings.push({ ruleId: `zap.${alert.pluginid}`, title: xss ? 'Reflected cross-site scripting' : 'SQL injection',
          comparisonKey: createHash('sha256').update(key).digest('hex'),
          description: `ZAP ${ZAP_VERSION} reported ${xss ? 'reflected XSS' : 'SQL injection'} at an approved GET query surface. Confirm the observation before treating it as an independently verified exploit. Raw attacks and response evidence are not retained.`,
          severity: severities[Number(alert.riskcode)]!, confidence: Number(alert.confidence) >= 3 ? 'high' : Number(alert.confidence) === 2 ? 'medium' : 'low',
          kind: 'observation', location: { url: safeUrl(url) },
          remediation: xss ? 'Use context-appropriate output encoding and safe template APIs. Avoid inserting query values into HTML or script. Rerun the same approved scan after the fix.'
            : 'Use parameterized queries or prepared statements. Keep query structure separate from user input and rerun the same approved scan after the fix.',
          references: [`https://www.zaproxy.org/docs/alerts/${alert.pluginid}/`],
        });
      }
    }
  }
  return result;
}

export async function runZap(options: ZapOptions): Promise<CheckResult[]> {
  if (!options || options.consent !== true) return error('consent_required', 'Active ZAP testing requires explicit consent; no target requests were made.');
  let maxRequests: number, timeoutMs: number, rateLimit: number, urls: URL[], targetUrl: string;
  try {
    maxRequests = bounded(options.maxRequests, ZAP_DEFAULT_MAX_REQUESTS, ZAP_MAX_REQUESTS); timeoutMs = bounded(options.timeoutMs, ZAP_DEFAULT_TIMEOUT_MS, MAX_TOOL_TIMEOUT_MS);
    rateLimit = bounded(options.rateLimit, ZAP_DEFAULT_RATE_LIMIT, ZAP_MAX_RATE_LIMIT);
  } catch { return error('invalid_budget', 'Invalid ZAP request, rate or time budget; no requests were made.'); }
  try {
    targetUrl = options.url;
    const origin = normalizeUrl(targetUrl);
    const url = new URL(origin.href);
    if (url.pathname !== '/' || url.search || url.hash) throw new TypeError();
    if (origin.protocol !== 'http:') return error('https_wire_budget_unsupported', 'ZAP HTTPS uses an opaque CONNECT tunnel; the mandatory per-request budget cannot be enforced. No requests were made.');
    urls = selectedUrls(origin.origin, [...options.paths]);
  } catch { return error('invalid_paths', 'Provide one origin and 1–16 explicit relative GET URLs with query parameters; no requests were made.'); }
  const executable = await findExecutable(options.executable ?? 'zap.sh');
  if (!executable) return error('engine_missing', `ZAP ${ZAP_VERSION} was not found. Provide the local zap.sh path; the adapter never downloads an engine during scanning.`);
  const work = await mkdtemp(join(tmpdir(), 'wakeio-zap-'));
  const control = createApiRunControl(timeoutMs, options.signal, MAX_TOOL_TIMEOUT_MS);
  const localAdmission = new RunAdmission({ maxRequests, ratePerSecond: rateLimit, deadlineAt: control.deadlineAt, signal: control.signal });
  const admission = localAdmission.bindTask('t-zap');
  const engine = new AbortController(), stopEngine = () => engine.abort();
  control.signal.addEventListener('abort', stopEngine, { once: true });
  let gate: EgressGate | undefined;
  let result: CheckResult[] | undefined;
  try {
    // ZAP 2.17 ignores a CLI -port 0 override; the native config accepts an OS-assigned port.
    const args = ['-Xmx512m', '-silent', '-dir', work, '-host', '127.0.0.1', '-config', 'network.localServers.mainProxy.port=0', '-config', 'start.checkForUpdates=false', '-config', 'start.checkAddonUpdates=false',
      '-config', 'start.downloadNewRelease=false', '-config', 'start.installAddonUpdates=false', '-config', 'start.installScannerRules=false',
      '-config', 'callhome.tel.enabled=false', '-config', 'network.connection.socksProxy.enabled=false', '-config', 'network.connection.httpProxy.authEnabled=true'];
    const version = await runProcess(executable, [...args, '-version'], { cwd: work, home: work, timeoutMs: Math.min(30_000, timeoutMs), signal: control.signal });
    if (version.exitCode !== 0 || !version.stdout.split(/\r?\n/).includes(ZAP_VERSION)) return error('unsupported_engine_version', `This adapter requires a working ZAP ${ZAP_VERSION}; no target requests were made.`);
    let resolved;
    try { resolved = await resolveDastOrigin(targetUrl, options.allowPrivate === true, control.signal); }
    catch (cause) { return error(cause instanceof UrlNetworkError ? cause.code : 'invalid_origin', 'The URL-network policy rejected the target; no requests were made.'); }
    gate = await startEgressGate({ ...resolved, methods: new Set(['GET']), operations: [...new Set(urls.map(url => url.pathname))],
      maxRequests, maxSingleBodyBytes: 2 * 1024 * 1024, maxTotalBytes: 64 * 1024 * 1024, signal: control.signal, deadlineAt: control.deadlineAt }, admission);
    gate.onStop(stopEngine);
    const plan = join(work, 'plan.json');
    await writeFile(plan, JSON.stringify(buildZapPlan(urls, new URL(gate.proxyUrl), work)), { mode: 0o600 });
    const started = Date.now();
    const run = await runProcess(executable, [...args, '-cmd', '-autorun', plan], { cwd: work, home: work,
      timeoutMs: Math.max(1, control.deadlineAt - Date.now()), signal: AbortSignal.any([control.signal, engine.signal]) });
    let parsed = { findings: [] as Finding[], malformed: 1, outOfScope: 0 };
    try {
      const report = join(work, 'report.json'), stat = await lstat(report);
      if (stat.isFile() && !stat.isSymbolicLink() && stat.size <= MAX_PROCESS_OUTPUT_BYTES) parsed = parseZapReport(JSON.parse(await readFile(report, 'utf8')), resolved.origin.origin, urls.map(url => `${url.pathname}${url.search}`));
    } catch { /* Missing/truncated report is an incomplete scan, never a clean result. */ }
    const counters = { ...gate.counters };
    const reason = gate.stopReason() ?? (options.signal?.aborted ? 'cancelled' : run.timedOut || control.signal.aborted ? 'timeout'
      : run.spawnError ? 'engine_spawn_failed' : run.outputLimitExceeded ? 'output_limit' : run.exitCode !== 0 ? 'engine_exit'
      : parsed.malformed ? 'invalid_report' : parsed.outOfScope || counters.blockedOrigin || counters.blockedMethod ? 'scope_violation'
      : counters.upstreamErrors || counters.rejectedEncoding ? 'transport_error' : counters.forwarded <= urls.length ? 'active_scan_unobserved' : 'complete');
    result = [{ id: ZAP_CHECK_ID, status: reason === 'complete' ? 'completed' : 'partial', findings: parsed.findings,
      notes: [SCOPE, `ZAP ${ZAP_VERSION}: ${counters.forwarded} forwarded request(s); ${urls.length} seed URL(s).`,
        'Every seed GET must return HTTP 200; a mismatched seed response makes the automation run incomplete.',
        ...(reason === 'complete' ? ['The configured engine jobs finished; no exhaustive endpoint or authorization coverage is inferred.'] : [`Incomplete: ${reason}; absent findings are not a clean security result.`])],
      metrics: { engine: 'zap', engineVersion: ZAP_VERSION, rules: RULES.join(','), requestCount: counters.forwarded,
        seedExpectedStatus: 200,
        maxRequests, rateLimit, durationMs: Date.now() - started, blockedOrigin: counters.blockedOrigin, blockedMethod: counters.blockedMethod,
        skippedByBudget: counters.blockedBudget, upstreamErrors: counters.upstreamErrors, responseBytes: counters.responseBytes,
        malformedEngineOutput: parsed.malformed, outOfScopeResults: parsed.outOfScope, stopReason: reason, gateTunnels: counters.tunnels } }];
    return result;
  } finally {
    control.signal.removeEventListener('abort', stopEngine); control.dispose(); localAdmission.close();
    const cleanup = await Promise.allSettled([gate?.close(), rm(work, { recursive: true, force: true })]);
    if (cleanup.some(item => item.status === 'rejected') && result) {
      result[0]!.status = 'partial';
      result[0]!.notes.push('ZAP temporary data or gate cleanup could not be confirmed.');
      result[0]!.metrics = { ...result[0]!.metrics, cleanupConfirmed: false, stopReason: 'cleanup_error' };
    }
  }
}
