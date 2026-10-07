#!/usr/bin/env node
import { resolveAnalysisBudget } from './source/analysis-budget.js';
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isAbsolute, resolve } from "node:path";
import type { Mode, ScanScope, SourceOptions, ToolName, UrlOptions } from "./contracts.js";
import { runSource } from "./source.js";
import { runUrl } from "./url.js";
import { createReport, exitCode, writeReports, RULESET_VERSION } from "./report.js";
import { compareReports, comparisonExitCode, readScanReport, writeComparison } from "./compare.js";
import { runApiPolicy, parseApiPolicy, type ApiPolicy } from "./api.js";
import { readJsonInput } from "./json-input.js";
import { DEFAULT_TOOL_TIMEOUT_MS, MAX_TOOL_TIMEOUT_MS } from "./source/process.js";
import { buildScanScope, validateProjectId } from "./scan-scope.js";
import { doctorMain } from "./doctor.js";
import { initMain } from "./init.js";
import { planMain } from "./plan.js";
import { repairMain } from "./repair.js";
import { API_MAX_REQUESTS, API_MAX_TIMEOUT_MS } from "./api.js";
import { runSchemathesisLive } from "./schemathesis-live.js";
import { NUCLEI_MAX_RATE_LIMIT, NUCLEI_MAX_REQUESTS, NUCLEI_SCOPES, runNuclei, type NucleiScope } from "./nuclei.js";

const SEVERITY_VALUES = new Set(["critical", "high", "medium", "low", "info", "none"] as const);
const TOOL_VALUES = new Set<ToolName>(["gitleaks", "osv", "trivy", "bandit"]);

export interface CliOptions {
  analysisProfile?: SourceOptions['analysisProfile'];
  source?: string;
  url?: string;
  projectId?: string;
  pages: string[];
  maxPages?: number;
  apiPolicy?: string;
  outDir: string;
  tools: ToolName[];
  failOn: "critical" | "high" | "medium" | "low" | "info" | "none";
  allowPrivate: boolean;
  timeoutMs: number;
  osvOffline: boolean;
  toolPaths: Partial<Record<ToolName, string>>;
  nativePreview?: { executable: string };
  /** Active DAST is opt-in and requires `activeConsent`; see parseCliArgs. */
  activeConsent: boolean;
  openapi?: string;
  apiBase?: string;
  operations: string[];
  apiMaxRequests?: number;
  seed?: number;
  schemathesisPython?: string;
  engines: Array<"nuclei">;
  nucleiPath?: string;
  nucleiTemplates?: string;
  nucleiScopes: NucleiScope[];
  nucleiMaxRequests?: number;
  nucleiRateLimit?: number;
  nucleiTimeoutMs?: number;
}

export class CliUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliUsageError";
  }
}

export const USAGE = `Usage:
  wakeio-security-ci scan --source DIR [options]
  wakeio-security-ci scan --url URL [options]
  wakeio-security-ci scan --source DIR --url URL [options]
  wakeio-security-ci scan --api-policy policy.json [options]
  wakeio-security-ci plan --api-policy FILE | --openapi-input FILE [--allow-private] [--timeout-ms N]
  wakeio-security-ci scan --openapi openapi.json --api-base URL --operation PATH --active-consent [options]
  wakeio-security-ci scan --url URL --engine nuclei --nuclei-templates DIR --active-consent [options]
  wakeio-security-ci compare --before report.json --after report.json --out DIR [--fail-on LEVEL]
  wakeio-security-ci doctor [--source DIR] [--tools ...] [--json] [--strict]
  wakeio-security-ci init [--source DIR] [--workflow FILE] [--out DIR] [--tools ...]
  wakeio-security-ci repair --source DIR --policy FILE --out NEW_DIR --proposal FILE
  wakeio-security-ci repair --help

Options:
  --out DIR                    Report directory (default: wakeio-security-reports)
  --tools gitleaks,osv,trivy   External source scanners (default: all three)
  --tools bandit               Optional Python SAST (install Bandit separately)
  --tools none                 Run built-in source checks only
  --analysis-profile PROFILE   default|extended AST workload (source only; default: default)
  --fail-on LEVEL              critical|high|medium|low|info|none (default: high)
  --api-policy FILE            Explicit read-only API authorization policy JSON
  --project-id ID              Logical repository identity for cross-checkout comparison
  --page URL                    Additional same-origin page (repeatable, root is always first)
  --max-pages N                 Maximum pages including the root page, 1..8
  --allow-private              Allow private URL/API targets (metadata remains blocked)
  --timeout-ms N               Per-scanner timeout, 1..600000 ms
  --osv-offline                Require a prepared local OSV vulnerability DB
  --gitleaks PATH              Gitleaks executable
  --osv PATH                   OSV-Scanner executable
  --trivy PATH                 Trivy executable
  --bandit PATH                Bandit executable
  --opengrep-core ABS_PATH     Explicit pinned Darwin arm64 native preview (BYO)

Active DAST (off by default; sends generated or template requests to the target):
  --active-consent             Required: you own or are authorized to test the target
  --openapi FILE               Local OpenAPI 3.0/3.1 JSON (same-document $ref only)
  --api-base URL               Target origin for --openapi (servers are never used)
  --operation PATH             Documented GET path to test (repeatable, 1..16)
  --api-max-requests N         Schemathesis request budget, 1..64 (default 32)
  --seed N                     Hypothesis seed (default 1)
  --schemathesis-python PATH   Python with workers/schemathesis/requirements.lock.txt
  --engine nuclei              Run pinned Nuclei 3.11.1 against the --url origin
  --nuclei PATH                Nuclei executable (default: PATH lookup)
  --nuclei-templates DIR       Prepared nuclei-templates directory (never downloaded)
  --nuclei-scope LIST          misconfiguration,exposures (default: misconfiguration)
  --nuclei-max-requests N      Gate request budget, 1..20000 (default 6000)
  --nuclei-rate-limit N        Requests per second, 1..150 (default 50)
  --nuclei-timeout-ms N        Nuclei time budget, 1..600000 (default 300000; --timeout-ms is unchanged)
  --help                       Show this help
`;

function valueAfter(args: string[], index: number, flag: string): [string, number] {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new CliUsageError(`${flag} requires a value`);
  return [value, index + 1];
}

function parseTools(value: string): ToolName[] {
  if (value === "none") return [];
  const parts = value.split(",").map((part) => part.trim()).filter(Boolean);
  if (parts.length === 0 || parts.some((part) => !TOOL_VALUES.has(part as ToolName)) || new Set(parts).size !== parts.length) {
    throw new CliUsageError("--tools must be a comma-separated list of gitleaks, osv, trivy, bandit, or none");
  }
  return parts as ToolName[];
}

function parsePositiveTimeout(value: string): number {
  if (!/^\d+$/.test(value)) throw new CliUsageError("--timeout-ms must be a positive integer");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TOOL_TIMEOUT_MS) throw new CliUsageError(`--timeout-ms must be between 1 and ${MAX_TOOL_TIMEOUT_MS}`);
  return parsed;
}

function parseBoundedInteger(flag: string, value: string, max: number): number {
  if (!/^\d+$/.test(value)) throw new CliUsageError(`${flag} must be a positive integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > max) throw new CliUsageError(`${flag} must be between 1 and ${max}`);
  return parsed;
}

function parsePageLimit(value: string): number {
  if (!/^\d+$/.test(value)) throw new CliUsageError("--max-pages must be a positive integer");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 8) throw new CliUsageError("--max-pages must be between 1 and 8");
  return parsed;
}

/** Parses the intentionally small, strict public CLI grammar. */
export function parseCliArgs(argv: readonly string[]): CliOptions | { help: true } {
  const args = [...argv];
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") return { help: true };
  if (args[0] !== "scan") throw new CliUsageError("the command must be scan");
  const options: CliOptions = {
    outDir: "wakeio-security-reports",
    tools: ["gitleaks", "osv", "trivy"],
    pages: [],
    failOn: "high",
    allowPrivate: false,
    timeoutMs: DEFAULT_TOOL_TIMEOUT_MS,
    osvOffline: false,
    toolPaths: {},
    activeConsent: false,
    operations: [],
    engines: [],
    nucleiScopes: [],
  };
  const seen = new Set<string>();
  let help = false;
  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") {
      help = true;
      continue;
    }
    const valueFlag = (flag: string): string | undefined => {
      if (arg === flag) {
        if (seen.has(flag)) throw new CliUsageError(`${flag} may only be specified once`);
        seen.add(flag);
        const result = valueAfter(args, index, flag);
        index = result[1];
        return result[0];
      }
      if (arg.startsWith(`${flag}=`)) {
        if (seen.has(flag)) throw new CliUsageError(`${flag} may only be specified once`);
        seen.add(flag);
        const value = arg.slice(flag.length + 1);
        if (!value) throw new CliUsageError(`${flag} requires a value`);
        return value;
      }
      return undefined;
    };
    let value: string | undefined;
    if ((value = valueFlag("--source")) !== undefined) options.source = value;
    else if ((value = valueFlag("--url")) !== undefined) options.url = value;
    else if ((value = valueFlag("--project-id")) !== undefined) {
      const projectId = validateProjectId(value);
      if (!projectId) throw new CliUsageError("--project-id must be a bounded identifier using letters, numbers, ., _, :, /, or -");
      options.projectId = projectId;
    }
    else if (arg === "--page" || arg.startsWith("--page=")) {
      let page: string;
      if (arg === "--page") {
        const result = valueAfter(args, index, "--page");
        page = result[0];
        index = result[1];
      } else {
        page = arg.slice("--page=".length);
        if (!page || page.startsWith("--")) throw new CliUsageError("--page requires a value");
      }
      // The root URL is always one page, so at most seven additional page
      // targets can be requested under the scanner's total hard limit of 8.
      if (options.pages.length >= 7) throw new CliUsageError("--page may be specified at most 7 times");
      options.pages.push(page);
    }
    else if ((value = valueFlag("--max-pages")) !== undefined) options.maxPages = parsePageLimit(value);
    else if ((value = valueFlag("--api-policy")) !== undefined) options.apiPolicy = value;
    else if ((value = valueFlag("--out")) !== undefined) options.outDir = value;
    else if ((value = valueFlag('--analysis-profile')) !== undefined) {
      try { options.analysisProfile = resolveAnalysisBudget(value).requestedProfile; }
      catch { throw new CliUsageError('--analysis-profile must be default or extended'); }
    }
    else if ((value = valueFlag("--tools")) !== undefined) options.tools = parseTools(value);
    else if ((value = valueFlag("--fail-on")) !== undefined) {
      if (!SEVERITY_VALUES.has(value as never)) throw new CliUsageError("--fail-on must be critical, high, medium, low, info, or none");
      options.failOn = value as CliOptions["failOn"];
    } else if ((value = valueFlag("--timeout-ms")) !== undefined) options.timeoutMs = parsePositiveTimeout(value);
    else if ((value = valueFlag("--gitleaks")) !== undefined) options.toolPaths.gitleaks = value;
    else if ((value = valueFlag("--osv")) !== undefined) options.toolPaths.osv = value;
    else if ((value = valueFlag("--trivy")) !== undefined) options.toolPaths.trivy = value;
    else if ((value = valueFlag("--bandit")) !== undefined) options.toolPaths.bandit = value;
    else if ((value = valueFlag('--opengrep-core')) !== undefined) {
      if (!isAbsolute(value) || value.includes('\0')) throw new CliUsageError('--opengrep-core requires an absolute executable path');
      options.nativePreview = { executable: value };
    }
    else if ((value = valueFlag("--openapi")) !== undefined) options.openapi = value;
    else if ((value = valueFlag("--api-base")) !== undefined) options.apiBase = value;
    else if (arg === "--operation" || arg.startsWith("--operation=")) {
      let operation: string;
      if (arg === "--operation") {
        const result = valueAfter(args, index, "--operation");
        operation = result[0];
        index = result[1];
      } else operation = arg.slice("--operation=".length);
      if (!operation.startsWith("/") || operation.length > 2048) throw new CliUsageError("--operation must be a documented absolute OpenAPI path");
      if (options.operations.length >= 16) throw new CliUsageError("--operation may be specified at most 16 times");
      options.operations.push(operation);
    }
    else if ((value = valueFlag("--api-max-requests")) !== undefined) options.apiMaxRequests = parseBoundedInteger("--api-max-requests", value, API_MAX_REQUESTS);
    else if ((value = valueFlag("--seed")) !== undefined) options.seed = parseBoundedInteger("--seed", value, 2147483647);
    else if ((value = valueFlag("--schemathesis-python")) !== undefined) options.schemathesisPython = value;
    else if ((value = valueFlag("--engine")) !== undefined) {
      const engines = value.split(",").map((part) => part.trim()).filter(Boolean);
      if (engines.length === 0 || engines.some((engine) => engine !== "nuclei") || new Set(engines).size !== engines.length) throw new CliUsageError("--engine must be nuclei");
      options.engines = engines as CliOptions["engines"];
    }
    else if ((value = valueFlag("--nuclei")) !== undefined) options.nucleiPath = value;
    else if ((value = valueFlag("--nuclei-templates")) !== undefined) options.nucleiTemplates = value;
    else if ((value = valueFlag("--nuclei-scope")) !== undefined) {
      const scopes = value.split(",").map((part) => part.trim()).filter(Boolean);
      if (scopes.length === 0 || scopes.some((scope) => !(scope in NUCLEI_SCOPES)) || new Set(scopes).size !== scopes.length) throw new CliUsageError("--nuclei-scope must be a comma-separated list of misconfiguration, exposures");
      options.nucleiScopes = scopes as NucleiScope[];
    }
    else if ((value = valueFlag("--nuclei-max-requests")) !== undefined) options.nucleiMaxRequests = parseBoundedInteger("--nuclei-max-requests", value, NUCLEI_MAX_REQUESTS);
    else if ((value = valueFlag("--nuclei-rate-limit")) !== undefined) options.nucleiRateLimit = parseBoundedInteger("--nuclei-rate-limit", value, NUCLEI_MAX_RATE_LIMIT);
    else if ((value = valueFlag("--nuclei-timeout-ms")) !== undefined) options.nucleiTimeoutMs = parseBoundedInteger("--nuclei-timeout-ms", value, MAX_TOOL_TIMEOUT_MS);
    else if (arg === "--active-consent") {
      if (seen.has(arg)) throw new CliUsageError(`${arg} may only be specified once`);
      seen.add(arg);
      options.activeConsent = true;
    }
    else if (arg === "--allow-private") {
      if (seen.has(arg)) throw new CliUsageError(`${arg} may only be specified once`);
      seen.add(arg);
      options.allowPrivate = true;
    } else if (arg === "--osv-offline") {
      if (seen.has(arg)) throw new CliUsageError(`${arg} may only be specified once`);
      seen.add(arg);
      options.osvOffline = true;
    } else {
      throw new CliUsageError("unknown option");
    }
  }
  if (help) return { help: true };
  if (!options.source && !options.url && !options.apiPolicy && !options.openapi) throw new CliUsageError("provide --source, --url, --api-policy, or --openapi");
  if (options.pages.length > 0 && !options.url) throw new CliUsageError("--page requires --url");
  if (options.maxPages !== undefined && !options.url) throw new CliUsageError("--max-pages requires --url");
  if (options.allowPrivate && !options.url && !options.apiPolicy && !options.openapi) throw new CliUsageError("--allow-private requires URL or API mode");
  const schemathesisOnly = options.apiBase !== undefined || options.operations.length > 0 || options.apiMaxRequests !== undefined || options.seed !== undefined || options.schemathesisPython !== undefined;
  if (schemathesisOnly && !options.openapi) throw new CliUsageError("--api-base, --operation, --api-max-requests, --seed and --schemathesis-python require --openapi");
  if (options.openapi && (!options.apiBase || options.operations.length === 0)) throw new CliUsageError("--openapi requires --api-base and at least one --operation");
  const nucleiOnly = options.nucleiPath !== undefined || options.nucleiTemplates !== undefined || options.nucleiScopes.length > 0 || options.nucleiMaxRequests !== undefined || options.nucleiRateLimit !== undefined || options.nucleiTimeoutMs !== undefined;
  if (nucleiOnly && !options.engines.includes("nuclei")) throw new CliUsageError("--nuclei* options require --engine nuclei");
  if (options.engines.includes("nuclei") && (!options.url || !options.nucleiTemplates)) throw new CliUsageError("--engine nuclei requires --url and --nuclei-templates");
  const active = Boolean(options.openapi) || options.engines.length > 0;
  // Consent is checked before any DNS lookup or request: active testing never starts implicitly.
  if (active && !options.activeConsent) throw new CliUsageError("active DAST (--openapi or --engine) requires --active-consent; only test targets you own or are authorized to test");
  if (options.activeConsent && !active) throw new CliUsageError("--active-consent requires --openapi or --engine");
  if (options.engines.includes("nuclei") && options.nucleiScopes.length === 0) options.nucleiScopes = ["misconfiguration"];
  if (options.osvOffline && !options.source) throw new CliUsageError("--osv-offline requires source mode");
  if (options.analysisProfile !== undefined && !options.source) throw new CliUsageError('--analysis-profile requires source mode');
  if (options.nativePreview && !options.source) throw new CliUsageError('--opengrep-core requires source mode');
  return options;
}

function modeFor(options: CliOptions): Mode {
  if (options.apiPolicy || options.openapi) return options.source || options.url ? 'combined' : 'api';
  if (options.source && options.url) return "both";
  return options.source ? "source" : "url";
}

function runtimeErrorCheck(id: string, message: string) {
  return { id, status: "error" as const, findings: [], notes: [message] };
}

export function parseCompareArgs(argv: readonly string[]): { before: string; after: string; outDir: string; failOn: CliOptions['failOn'] } {
  const values = new Map<string, string>();
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--before', '--after', '--out', '--fail-on'].includes(flag) || values.has(flag) || !value || value.startsWith('--')) {
      throw new CliUsageError('compare requires unique --before, --after, --out and optional --fail-on values');
    }
    values.set(flag, value);
  }
  if (!values.get('--before') || !values.get('--after') || !values.get('--out')) throw new CliUsageError('compare requires --before, --after and --out');
  const failOn = values.get('--fail-on') ?? 'high';
  if (!SEVERITY_VALUES.has(failOn as never)) throw new CliUsageError('invalid comparison severity threshold');
  return { before: values.get('--before')!, after: values.get('--after')!, outDir: values.get('--out')!, failOn: failOn as CliOptions['failOn'] };
}

async function runComparison(argv: readonly string[]): Promise<number> {
  try {
    const options = parseCompareArgs(argv);
    const [before, after] = await Promise.all([readScanReport(options.before), readScanReport(options.after)]);
    const result = compareReports(before, after);
    await writeComparison(result, options.outDir);
    process.stdout.write(`Wakeio comparison: ${result.comparable ? 'comparable declared scope' : 'UNVERIFIED scope'}\n`);
    process.stdout.write(Object.entries(result.summary).map(([state, count]) => `${state}: ${count}`).join(', ') + '\n');
    process.stdout.write('Not observed is not proof of a fix. Details: comparison.json, comparison.md\n');
    return comparisonExitCode(result, options.failOn);
  } catch (error) {
    process.stderr.write(error instanceof CliUsageError ? `Error: ${error.message}\n` : 'Error: comparison inputs or output could not be processed.\n');
    return 2;
  }
}

async function declaredScope(options: CliOptions, apiPolicy: ApiPolicy | undefined): Promise<ScanScope> {
  return buildScanScope({
    mode: modeFor(options),
    source: options.source,
    analysisProfile: options.analysisProfile,
    url: options.url,
    projectId: options.projectId,
    tools: options.source ? options.tools : [],
    // Tool paths are used only to resolve/hash the selected executable in
    // provenance. They are intentionally excluded from the stable scope.
    toolPaths: options.source ? options.toolPaths : {},
    nativePreview: options.nativePreview,
    allowPrivate: options.allowPrivate,
    timeoutMs: options.timeoutMs,
    osvOffline: options.osvOffline,
    pages: options.pages,
    maxPages: options.maxPages,
    apiPolicy,
    ruleset: RULESET_VERSION,
    ...(options.openapi || options.engines.length > 0 ? { dast: {
      ...(options.openapi ? { schemathesis: { apiBase: options.apiBase, operations: [...options.operations], maxRequests: options.apiMaxRequests ?? 32, seed: options.seed ?? 1 } } : {}),
      ...(options.engines.includes("nuclei") ? { nuclei: { scopes: [...options.nucleiScopes].sort(), maxRequests: options.nucleiMaxRequests ?? null, rateLimit: options.nucleiRateLimit ?? null } } : {}),
    } } : {}),
  });
}

/** Executes a scan and writes public reports when scanning starts. */
export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  if (argv[0] === 'plan') return planMain(argv);
  if (argv[0] === 'compare') return runComparison(argv);
  if (argv[0] === 'doctor') return doctorMain(argv);
  if (argv[0] === 'init') return initMain(argv);
  if (argv[0] === 'repair') return repairMain(argv);
  let parsed: CliOptions | { help: true };
  try {
    parsed = parseCliArgs(argv);
  } catch (error) {
    const message = error instanceof CliUsageError ? error.message : "invalid command line";
    process.stderr.write(`Error: ${message}\n\n${USAGE}`);
    return 2;
  }
  if ("help" in parsed) {
    process.stdout.write(USAGE);
    return 0;
  }
  const controller = new AbortController();
  const cancel = (): void => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
  const startedAt = new Date().toISOString();
  const mode = modeFor(parsed);
  process.stderr.write(`Wakeio: scanning ${mode === "both" ? "source and URL" : mode} scope...\n`);
  const checks = [] as Awaited<ReturnType<typeof runSource>>;
  let apiPolicy: ApiPolicy | undefined;
  if (parsed.apiPolicy) {
    try {
      apiPolicy = parseApiPolicy(await readJsonInput(parsed.apiPolicy, 1024 * 1024)).policy;
    } catch {
      checks.push(runtimeErrorCheck('api.policy', 'API policy must be a valid bounded JSON file with the supported schema.'));
    }
  }
  if (parsed.source) {
    const sourceOptions: SourceOptions = {
      root: parsed.source,
      analysisProfile: parsed.analysisProfile,
      tools: parsed.tools,
      toolPaths: parsed.toolPaths,
      timeoutMs: parsed.timeoutMs,
      osvOffline: parsed.osvOffline,
      outDir: parsed.outDir,
      nativePreview: parsed.nativePreview,
      signal: controller.signal,
    };
    try {
      checks.push(...await runSource(sourceOptions));
    } catch {
      checks.push(runtimeErrorCheck("source.runtime", "Source scanning could not be completed."));
    }
  }
  if (parsed.url && !controller.signal.aborted) {
    const urlOptions: UrlOptions = {
      url: parsed.url,
      pages: parsed.pages,
      maxPages: parsed.maxPages,
      allowPrivate: parsed.allowPrivate,
      timeoutMs: parsed.timeoutMs,
      signal: controller.signal,
    };
    try {
      checks.push(...await runUrl(urlOptions));
    } catch {
      checks.push(runtimeErrorCheck("url.runtime", "URL scanning could not be completed."));
    }
  }
  if (apiPolicy && !controller.signal.aborted) {
    try {
      checks.push(...await runApiPolicy({ policy: apiPolicy, allowPrivate: parsed.allowPrivate, timeoutMs: parsed.timeoutMs, signal: controller.signal }));
    } catch {
      checks.push(runtimeErrorCheck('api.runtime', 'API authorization scanning could not be completed.'));
    }
  }
  if (parsed.engines.includes("nuclei") && parsed.url && !controller.signal.aborted) {
    try {
      checks.push(...await runNuclei({
        url: `${new URL(parsed.url).origin}/`, executable: parsed.nucleiPath, templatesDir: parsed.nucleiTemplates!, scopes: parsed.nucleiScopes,
        consent: parsed.activeConsent, allowPrivate: parsed.allowPrivate, timeoutMs: parsed.nucleiTimeoutMs,
        maxRequests: parsed.nucleiMaxRequests, rateLimit: parsed.nucleiRateLimit, signal: controller.signal,
      }));
    } catch {
      checks.push(runtimeErrorCheck('url.nuclei', 'Nuclei scanning could not be completed.'));
    }
  }
  if (parsed.openapi && !controller.signal.aborted) {
    try {
      const document = await readJsonInput(parsed.openapi, 1024 * 1024);
      checks.push(...await runSchemathesisLive({
        document, baseUrl: parsed.apiBase!, operations: parsed.operations.map((path) => ({ method: "GET" as const, path })),
        consent: parsed.activeConsent, allowPrivate: parsed.allowPrivate,
        python: parsed.schemathesisPython ?? process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? "python3",
        timeoutMs: Math.min(parsed.timeoutMs, API_MAX_TIMEOUT_MS), maxRequests: parsed.apiMaxRequests, seed: parsed.seed, signal: controller.signal,
      }));
    } catch {
      checks.push(runtimeErrorCheck('api.schemathesis', 'OpenAPI input must be a bounded local JSON file; Schemathesis live testing did not start.'));
    }
  }
  const scope = await declaredScope(parsed, apiPolicy);
  const markCancelled = (): void => {
    if (controller.signal.aborted && !checks.some((check) => check.id === 'scan.cancelled')) checks.push({ id: 'scan.cancelled', status: 'partial', findings: [], notes: ['The command was cancelled; completed stages do not establish command completion.'] });
  };
  markCancelled();
  let report = createReport(checks, mode, startedAt, scope);
  try {
    await writeReports(report, parsed.outDir, { failOn: parsed.failOn });
    if (controller.signal.aborted && !report.checks.some((check) => check.id === 'scan.cancelled')) {
      markCancelled(); report = createReport(checks, mode, startedAt, scope);
      await writeReports(report, parsed.outDir, { failOn: parsed.failOn });
    }
  } catch {
    process.stderr.write("Error: report files could not be written.\n");
    return 2;
  }
  const code = exitCode(report, parsed.failOn);
  const findings = report.checks.flatMap((check) => check.findings);
  const completed = report.checks.filter((check) => check.status === "completed").length;
  const incomplete = report.checks.filter((check) => ["partial", "error", "skipped"].includes(check.status)).length;
  const notApplicable = report.checks.filter((check) => check.status === "not_applicable").length;
  const levels = ["critical", "high", "medium", "low", "info"] as const;
  const outcome = code === 2 ? "INCOMPLETE: review check statuses before relying on this scan."
    : code === 1 ? `FINDINGS: the ${parsed.failOn} threshold was reached.`
    : parsed.failOn === "none" ? "COMPLETED: selected checks finished; findings do not block this run."
    : "COMPLETED: no findings at or above the selected threshold in the checked scope.";
  process.stdout.write([
    `Wakeio Security CI: ${mode} scope`,
    `Checks: ${completed} completed, ${incomplete} incomplete, ${notApplicable} not applicable`,
    `Findings: ${findings.length} (${levels.map((level) => `${level} ${findings.filter((finding) => finding.severity === level).length}`).join(", ")})`,
    outcome,
    ...(parsed.failOn === "none" ? ["Finding threshold disabled (--fail-on none); incomplete scans still fail."] : []),
    `Reports: ${JSON.stringify(resolve(parsed.outDir))} (report.json, report.sarif, report.md, agent-report.json)`,
    "Scope details and limitations are recorded in report.md.",
    "",
  ].join("\n"));
  return code;
  } finally {
    process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
  }
}

function canonicalFile(path: string): string {
  try { return realpathSync(path); } catch { return resolve(path); }
}

if (process.argv[1] && canonicalFile(process.argv[1]) === canonicalFile(fileURLToPath(import.meta.url))) {
  main().then((code) => { process.exitCode = code; }).catch(() => { process.exitCode = 2; });
}
