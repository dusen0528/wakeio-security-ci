import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createApiRunControl } from './api.js';
import { RunAdmission, admissionSignal, type TaskAdmission } from './agent-dast/admission.js';
import type { CheckResult, Finding, Severity } from './contracts.js';
import { resolveDastOrigin, startEgressGate, type EgressGate } from './dast-egress.js';
import { findExecutable, MAX_PROCESS_OUTPUT_BYTES, MAX_TOOL_TIMEOUT_MS, runProcess } from './source/process.js';
import { normalizeUrl, safeUrl, UrlNetworkError } from './url-network.js';
import { authScalarMatches } from './schemathesis-auth.js';
import { ZapSessionBridge, ZAP_SESSION_PATH } from './zap-session.js';
import { projectedZapOpenApi, type ZapCompiledRequest } from './zap-openapi.js';
import { prepareZapPolicy, ZAP_OPENAPI_REVISION, zapSurfaceKey, ZAP_RELAY_ORIGIN, ZAP_POLICY_REVISION, type ZapPolicyInput, type ZapRequest } from './zap-policy.js';
export { parseZapPolicy, ZAP_POLICY_REVISION, ZAP_OPENAPI_REVISION } from './zap-policy.js';
export type { ZapPolicy, ZapPolicyV2, ZapPolicyInput, ZapRequest } from './zap-policy.js';

export const ZAP_CHECK_ID = 'url.zap';
export const ZAP_VERSION = '2.17.0';
export const ZAP_DEFAULT_MAX_REQUESTS = 200;
export const ZAP_MAX_REQUESTS = 2000;
export const ZAP_DEFAULT_TIMEOUT_MS = 300_000;
export const ZAP_DEFAULT_RATE_LIMIT = 10;
export const ZAP_MAX_RATE_LIMIT = 50;
const RULES = [40012, 40018];
const SCOPE = 'ZAP tests only explicitly selected inputs for reflected XSS and SQL injection through the shared egress gate. No spider, arbitrary script, out-of-band callback or update is enabled. API login and session renewal require the explicit version-2 profile. Active requests can have side effects; use an approved disposable target. This is not an authorization or complete application-security assessment.';
export interface ZapOptions {
  url: string;
  paths?: string[];
  policy?: ZapPolicyInput;
  env?: NodeJS.ProcessEnv;
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
export function buildZapPlan(urls: URL[], proxy: URL, directory: string, requests?: ZapCompiledRequest[], automation?: { openapi: boolean; session: boolean; format?: 'json' | 'form' }): object {
  const allowed = [...new Set(urls.map(url => `${escapeRegex(url.origin + url.pathname)}(?:\\?.*)?`))];
  return {
    env: {
      // Context urls add broad regexes; exclusions must constrain their union, not just add includePaths.
      contexts: [{ name: 'wakeio', urls: [urls[0]!.origin], includePaths: allowed.map(path => `^${path}$`), excludePaths: [`^(?!(?:${allowed.join('|')})$).*$`],
        ...(automation?.session ? { authentication: { method: automation.format, parameters: { loginPageUrl: '', loginRequestUrl: urls[0]!.origin + ZAP_SESSION_PATH,
          loginRequestBody: automation.format === 'form' ? 'username={%username%}&password={%password%}' : JSON.stringify({ username: '{%username%}', password: '{%password%}' }) },
          verification: { method: 'response', loggedInRegex: '(?i)x-wakeio-session: valid', loggedOutRegex: '(?i)x-wakeio-session: expired' } },
          sessionManagement: { method: 'cookie' }, users: [{ name: 'wakeio-user', credentials: { username: 'wakeio-user', password: 'wakeio-password' } }] } : {}) }],
      parameters: { failOnError: true, failOnWarning: true, continueOnFailure: false, progressToStdout: false },
      proxy: { hostname: proxy.hostname, port: Number(proxy.port), username: proxy.username, password: proxy.password },
    },
    jobs: [
      { type: 'passiveScan-config', parameters: { disableAllRules: true } },
      { type: 'activeScan-config', parameters: { threadPerHost: 1, handleAntiCSRFTokens: false }, inputVectors: {
        urlQueryStringAndDataDrivenNodes: { enabled: true, addParam: false, odata: false },
        postData: requests?.some(request => request.method === 'POST') ? { enabled: true, multiPartFormData: false, xml: false,
          json: { enabled: true, scanNullValues: false }, googleWebToolkit: false, directWebRemoting: false } : { enabled: false },
        urlPath: false, httpHeaders: { enabled: false, allRequests: false },
        cookieData: { enabled: false }, scripts: false,
      } },
      ...(automation?.openapi ? [{ type: 'openapi', parameters: { apiFile: join(directory, 'openapi.json'), targetUrl: urls[0]!.origin, context: 'wakeio', ...(automation.session ? {user:'wakeio-user'} : {}) } }] : []),
      { type: 'requestor', ...(automation?.session ? { parameters: { user: 'wakeio-user' } } : {}), requests: urls.map((url, index) => ({ url: url.href, method: requests?.[index].method ?? 'GET', responseCode: 200,
        ...(requests?.[index].method === 'POST' ? { data: JSON.stringify(requests[index].body),
          headers: ['Content-Type:application/json'] } : {}) })) },
      // Only the outer supervisor/gate may stop a scan: ZAP's per-rule timeouts can silently skip work.
      { type: 'activeScan', parameters: { context: 'wakeio', ...(automation?.session ? {user:'wakeio-user'} : {}), threadPerHost: 1, handleAntiCSRFTokens: false, maxRuleDurationInMins: 0, maxScanDurationInMins: 0 },
        policyDefinition: { defaultThreshold: 'Off', defaultStrength: 'Low', rules: RULES.map(id => ({ id, strength: 'Low', threshold: 'Medium' })) } },
      { type: 'report', parameters: { template: 'traditional-json', reportDir: directory, reportFile: 'report.json', displayReport: false } },
    ],
  };
}

function object(value: unknown): value is Record<string, unknown> { return !!value && typeof value === 'object' && !Array.isArray(value); }
/** Project only rule metadata. Engine strings, payloads and evidence never enter the shared report. */
export function parseZapReport(raw: unknown, origin: string, paths: string[], policy?: { requests: ZapCompiledRequest[] }): { findings: Finding[]; malformed: number; outOfScope: number } {
  const result = { findings: [] as Finding[], malformed: 0, outOfScope: 0 };
  if (!object(raw) || raw['@version'] !== ZAP_VERSION || !Array.isArray(raw.site)) return { ...result, malformed: 1 };
  const urls = policy ? policy.requests.map(request => new URL(request.path, origin)) : selectedUrls(origin, paths), seen = new Set<string>();
  const severities: Severity[] = ['info', 'low', 'medium', 'high'];
  for (const site of raw.site) {
    if (!object(site) || typeof site['@name'] !== 'string' || !Array.isArray(site.alerts)) { result.malformed++; continue; }
    try { if (normalizeUrl(site['@name']).origin !== origin) { result.outOfScope++; continue; } } catch { result.malformed++; continue; }
    for (const alert of site.alerts) {
      if (!object(alert) || !RULES.some(id => String(id) === alert.pluginid) || !['0', '1', '2', '3'].includes(String(alert.riskcode))
        || !['0', '1', '2', '3', '4'].includes(String(alert.confidence)) || !Array.isArray(alert.instances) || !alert.instances.length) { result.malformed++; continue; }
      if (String(alert.confidence) === '0') continue;
      for (const instance of alert.instances) {
        if (!object(instance) || typeof instance.uri !== 'string' || !['GET', ...(policy ? ['POST'] : [])].includes(String(instance.method)) || typeof instance.param !== 'string') { result.malformed++; continue; }
        let url: URL;
        try { url = new URL(normalizeUrl(instance.uri).href); } catch { result.malformed++; continue; }
        const selected = policy?.requests.find(request => request.method === instance.method && new URL(request.path, origin).pathname === url.pathname
          && (request.method === 'POST' ? !!request.body && Object.hasOwn(request.body, instance.param as string) : new URL(request.path, origin).searchParams.has(instance.param as string)));
        if (url.origin !== origin || (policy ? !selected : !urls.some(seed => seed.pathname === url.pathname && seed.searchParams.has(instance.param as string)))) { result.outOfScope++; continue; }
        const parameter = selected?.fields?.find(field => field.alias === instance.param)?.pointer ?? instance.param;
        const key = policy ? zapSurfaceKey(String(alert.pluginid), selected!, parameter) : createHash('sha256').update(JSON.stringify([alert.pluginid, url.pathname, instance.param])).digest('hex');
        if (seen.has(key)) continue;
        seen.add(key);
        const xss = alert.pluginid === '40012';
        result.findings.push({ ruleId: `zap.${alert.pluginid}`, title: xss ? 'Reflected cross-site scripting' : 'SQL injection',
          comparisonKey: key,
          description: `ZAP ${ZAP_VERSION} reported ${xss ? 'reflected XSS' : 'SQL injection'} at an approved ${instance.method === 'POST' ? 'POST JSON' : 'GET query'} surface. Confirm the observation before treating it as an independently verified exploit. Raw attacks and response evidence are not retained.`,
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

export async function runZap(options: ZapOptions, runtime?: TaskAdmission): Promise<CheckResult[]> {
  if (!options || options.consent !== true) return error('consent_required', 'Active ZAP testing requires explicit consent; no target requests were made.');
  const started = Date.now();
  let maxRequests: number, timeoutMs: number, rateLimit: number, urls: URL[], targetUrl: string;
  let prepared: ReturnType<typeof prepareZapPolicy> | undefined;
  try {
    maxRequests = bounded(options.maxRequests, ZAP_DEFAULT_MAX_REQUESTS, ZAP_MAX_REQUESTS); timeoutMs = bounded(options.timeoutMs, ZAP_DEFAULT_TIMEOUT_MS, MAX_TOOL_TIMEOUT_MS);
    rateLimit = bounded(options.rateLimit, ZAP_DEFAULT_RATE_LIMIT, ZAP_MAX_RATE_LIMIT);
  } catch { return error('invalid_budget', 'Invalid ZAP request, rate or time budget; no requests were made.'); }
  try {
    targetUrl = options.url;
    const origin = normalizeUrl(targetUrl);
    const url = new URL(origin.href);
    if (url.pathname !== '/' || url.search || url.hash) throw new TypeError();
    if (options.policy !== undefined) {
      if (options.paths !== undefined) throw new TypeError();
      prepared = prepareZapPolicy(options.policy, options.allowPrivate === true, options.env);
      if (prepared.policy.origin !== origin.origin) throw new TypeError();
      urls = prepared.requests.map(request => new URL(request.path, ZAP_RELAY_ORIGIN));
      if (maxRequests < urls.length * (prepared.policy.version === 2 ? 2 : 1) + (prepared.policy.authentication ? 3 : 0) + (prepared.loginEnv ? 1 : 0) + 1) throw new TypeError();
    } else {
      if (origin.protocol !== 'http:') return error('https_wire_budget_unsupported', 'Legacy ZAP paths require HTTP. Use an explicit ZAP policy for request-observable HTTPS forwarding. No requests were made.');
      urls = selectedUrls(origin.origin, [...options.paths!]);
    }
  } catch { return error('invalid_paths', 'Provide one origin and either explicit GET query paths or a valid bounded ZAP policy; no requests were made.'); }
  const executable = await findExecutable(options.executable ?? 'zap.sh');
  if (!executable) return error('engine_missing', `ZAP ${ZAP_VERSION} was not found. Provide the local zap.sh path; the adapter never downloads an engine during scanning.`);
  const work = await mkdtemp(join(tmpdir(), 'wakeio-zap-'));
  const control = createApiRunControl(timeoutMs, admissionSignal(runtime, options.signal), MAX_TOOL_TIMEOUT_MS);
  const localAdmission = runtime ? undefined : new RunAdmission({ maxRequests, ratePerSecond: rateLimit, deadlineAt: control.deadlineAt, signal: control.signal });
  const admission = runtime ?? localAdmission!.bindTask('t-zap');
  const engine = new AbortController(), stopEngine = () => engine.abort();
  control.signal.addEventListener('abort', stopEngine, { once: true });
  let gate: EgressGate | undefined;
  const session = prepared?.loginEnv && prepared.policy.authentication && 'login' in prepared.policy.authentication ? new ZapSessionBridge(prepared.policy.authentication, prepared.loginEnv) : undefined;
  let result: CheckResult[] | undefined;
  const virtualOrigin = session?.virtualOrigin ?? ZAP_RELAY_ORIGIN;
  if (session) urls = urls.map(url => new URL(url.pathname + url.search, virtualOrigin));
  let controlFailure: string | undefined, identityBefore = false, identityAfter = false, anonymousDenied = false;
  const identityControl = async (anonymous: boolean): Promise<boolean> => {
    const auth = prepared!.policy.authentication!;
    try {
      const response = await gate!.relay!.control(auth.identity.path, anonymous);
      return anonymous ? [401, 403].includes(response.status) : response.status === auth.identity.status && authScalarMatches(response.body, auth.identity);
    } catch { controlFailure = 'control_transport_error'; return false; }
  };
  try {
    // ZAP 2.17 ignores a CLI -port 0 override; the native config accepts an OS-assigned port.
    const args = ['-Xmx512m', '-silent', '-dir', work, '-host', '127.0.0.1', '-config', 'network.localServers.mainProxy.port=0', '-config', 'start.checkForUpdates=false', '-config', 'start.checkAddonUpdates=false',
      '-config', 'start.downloadNewRelease=false', '-config', 'start.installAddonUpdates=false', '-config', 'start.installScannerRules=false',
      '-config', 'callhome.tel.enabled=false', '-config', 'network.connection.socksProxy.enabled=false', '-config', 'network.connection.httpProxy.authEnabled=true'];
    const version = await runProcess(executable, [...args, '-version'], { cwd: work, home: work, timeoutMs: Math.max(1, control.deadlineAt - Date.now()), signal: control.signal });
    if (version.timedOut || version.cancelled || control.signal.aborted) return error('engine_version_incomplete', 'ZAP version readiness was cancelled or exceeded the shared scan deadline; no target requests were made.');
    if (version.exitCode !== 0 || !version.stdout.split(/\r?\n/).includes(ZAP_VERSION)) return error('unsupported_engine_version', `This adapter requires a working ZAP ${ZAP_VERSION}; no target requests were made.`);
    let resolved;
    try { resolved = await resolveDastOrigin(targetUrl, options.allowPrivate === true, control.signal); }
    catch (cause) { return error(cause instanceof UrlNetworkError ? cause.code : 'invalid_origin', 'The URL-network policy rejected the target; no requests were made.'); }
    gate = await startEgressGate({ ...resolved, methods: new Set(prepared ? ['GET', 'POST'] : ['GET']), operations: [...new Set(urls.map(url => url.pathname))],
      maxRequests, maxSingleBodyBytes: 2 * 1024 * 1024, maxTotalBytes: 64 * 1024 * 1024, signal: control.signal, deadlineAt: control.deadlineAt,
      ...(prepared ? { relay: { virtualOrigin, authorization: prepared.authorization, session,
        controlPaths: prepared.policy.authentication ? [prepared.policy.authentication.identity.path] : [],
        requests: prepared.requests.map(request => ({ method: request.method, path: new URL(request.path, ZAP_RELAY_ORIGIN).pathname,
          ...(request.method === 'GET' ? { query: [...new URL(request.path, ZAP_RELAY_ORIGIN).searchParams.keys()] } : { parameter: Object.keys(request.body!)[0], compiled: request }) })) } } : {}) }, admission);
    gate.onStop(stopEngine);
    if (session) {
      try { if ((await gate.relay!.authenticate()).status !== 200) controlFailure = 'login_failed'; } catch { controlFailure = 'login_failed'; }
    }
    if (prepared?.policy.authentication && !controlFailure) {
      identityBefore = await identityControl(false);
      if (identityBefore) anonymousDenied = await identityControl(true);
      if (!identityBefore || !anonymousDenied) controlFailure ??= 'identity_control_failed';
    }
    if (session) session.onRenewed = async () => { const matched = await identityControl(false); if (!matched) { controlFailure = 'identity_control_failed'; stopEngine(); } return matched; };
    const imported = prepared?.policy.version === 2;
    const projection = imported ? projectedZapOpenApi(prepared!.requests, virtualOrigin) : undefined;
    const projectionSha256 = projection ? createHash('sha256').update(JSON.stringify(projectedZapOpenApi(prepared!.requests, ZAP_RELAY_ORIGIN))).digest('hex') : undefined;
    if (projection) await writeFile(join(work, 'openapi.json'), JSON.stringify(projection), {mode:0o600});
    const plan = join(work, 'plan.json');
    await writeFile(plan, JSON.stringify(buildZapPlan(urls, new URL(gate.proxyUrl), work, prepared?.requests, { openapi: imported, session: !!session, format: session?.policy.login.format })), { mode: 0o600 });
    const run = controlFailure ? { exitCode: 2, timedOut: false, spawnError: false, outputLimitExceeded: false } : await runProcess(executable, [...args, '-cmd', '-autorun', plan], { cwd: work, home: work,
      timeoutMs: Math.max(1, control.deadlineAt - Date.now()), signal: AbortSignal.any([control.signal, engine.signal]) });
    if (prepared?.policy.authentication && !controlFailure && !control.signal.aborted && !gate.stopReason() && !gate.counters.upstreamErrors) {
      identityAfter = await identityControl(false);
      if (!identityAfter) controlFailure ??= 'identity_control_failed';
    }
    let parsed = { findings: [] as Finding[], malformed: 1, outOfScope: 0 };
    try {
      const report = join(work, 'report.json'), stat = await lstat(report);
      if (stat.isFile() && !stat.isSymbolicLink() && stat.size <= MAX_PROCESS_OUTPUT_BYTES) {
        parsed = parseZapReport(JSON.parse(await readFile(report, 'utf8')), prepared ? virtualOrigin : resolved.origin.origin, urls.map(url => `${url.pathname}${url.search}`), prepared ? { requests: prepared.requests } : undefined);
        if (prepared) for (const finding of parsed.findings) finding.location.url = finding.location.url!.replace(virtualOrigin, prepared.policy.origin);
      }
    } catch { /* Missing/truncated report is an incomplete scan, never a clean result. */ }
    const counters = { ...gate.counters };
    const reason = gate.stopReason() ?? (options.signal?.aborted ? 'cancelled' : run.timedOut || control.signal.aborted ? 'timeout' : controlFailure ? controlFailure
      : run.spawnError ? 'engine_spawn_failed' : run.outputLimitExceeded ? 'output_limit' : run.exitCode !== 0 ? 'engine_exit'
      : parsed.malformed ? 'invalid_report' : parsed.outOfScope || counters.blockedOrigin || counters.blockedMethod ? 'scope_violation'
      : counters.upstreamErrors || counters.rejectedEncoding ? 'transport_error'
      : gate.relay?.redirectResponses ? 'redirect_observed' : session && !session.ready ? 'session_incomplete' : prepared?.policy.authentication && !session && gate.relay?.deniedResponses ? 'authenticated_request_denied'
      : counters.forwarded <= urls.length * (prepared?.policy.version === 2 ? 2 : 1) + (prepared?.policy.authentication ? 3 : 0) + (session ? 1 : 0) ? 'active_scan_unobserved' : 'complete');
    result = [{ id: ZAP_CHECK_ID, status: reason === 'complete' ? 'completed' : 'partial', findings: parsed.findings,
      notes: [SCOPE, `ZAP ${ZAP_VERSION}: ${counters.forwarded} forwarded request(s); ${urls.length} seed URL(s).`,
        'Every seed must return HTTP 200; a mismatched seed response makes the automation run incomplete.',
        ...(prepared ? ['Node forwards only the declared requests to the pinned HTTP(S) peer. Identity controls do not establish uninterrupted authentication or authorization correctness.'] : []),
        ...(reason === 'complete' ? ['The configured engine jobs finished; no exhaustive endpoint or authorization coverage is inferred.'] : [`Incomplete: ${reason}; absent findings are not a clean security result.`])],
      metrics: { engine: 'zap', engineVersion: ZAP_VERSION, rules: RULES.join(','), requestCount: counters.forwarded,
        seedExpectedStatus: 200,
        ...(prepared ? { policyRevision: prepared.policy.version === 2 ? ZAP_OPENAPI_REVISION : ZAP_POLICY_REVISION, policySha256: prepared.policySha256, identityBefore, anonymousDenied, identityAfter,
          ...(prepared.sourceSha256 ? { openapiSourceSha256: prepared.sourceSha256, openapiProjectionSha256: projectionSha256!, importedOperations: prepared.requests.length } : {}),
          ...(session ? { loginRequests: session.metrics.loginRequests, refreshRequests: session.metrics.refreshRequests, authChallenges: session.metrics.challenges, nativeAuthentication: session.policy.login.format } : {}),
          authenticated: !!prepared.policy.authentication, jsonRequests: prepared.requests.filter(request => request.method === 'POST').length } : {}),
        maxRequests, rateLimit, durationMs: Date.now() - started, blockedOrigin: counters.blockedOrigin, blockedMethod: counters.blockedMethod,
        skippedByBudget: counters.blockedBudget, upstreamErrors: counters.upstreamErrors, responseBytes: counters.responseBytes,
        malformedEngineOutput: parsed.malformed, outOfScopeResults: parsed.outOfScope, stopReason: reason, gateTunnels: counters.tunnels } }];
    return result;
  } finally {
    control.signal.removeEventListener('abort', stopEngine); control.dispose(); localAdmission?.close();
    const cleanup = await Promise.allSettled([gate?.close(), rm(work, { recursive: true, force: true })]);
    if (cleanup.some(item => item.status === 'rejected') && result) {
      result[0]!.status = 'partial';
      result[0]!.notes.push('ZAP temporary data or gate cleanup could not be confirmed.');
      result[0]!.metrics = { ...result[0]!.metrics, cleanupConfirmed: false, stopReason: 'cleanup_error' };
    }
  }
}
