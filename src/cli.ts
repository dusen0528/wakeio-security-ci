#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
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

const SEVERITY_VALUES = new Set(["critical", "high", "medium", "low", "info", "none"] as const);
const TOOL_VALUES = new Set<ToolName>(["gitleaks", "osv", "trivy", "bandit"]);

export interface CliOptions {
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
  wakeio-security-ci compare --before report.json --after report.json --out DIR [--fail-on LEVEL]
  wakeio-security-ci doctor [--source DIR] [--tools ...] [--json] [--strict]
  wakeio-security-ci init [--source DIR] [--workflow FILE] [--out DIR] [--tools ...]

Options:
  --out DIR                    Report directory (default: wakeio-security-reports)
  --tools gitleaks,osv,trivy   External source scanners (default: all three)
  --tools bandit               Optional Python SAST (install Bandit separately)
  --tools none                 Run built-in source checks only
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
    else if ((value = valueFlag("--tools")) !== undefined) options.tools = parseTools(value);
    else if ((value = valueFlag("--fail-on")) !== undefined) {
      if (!SEVERITY_VALUES.has(value as never)) throw new CliUsageError("--fail-on must be critical, high, medium, low, info, or none");
      options.failOn = value as CliOptions["failOn"];
    } else if ((value = valueFlag("--timeout-ms")) !== undefined) options.timeoutMs = parsePositiveTimeout(value);
    else if ((value = valueFlag("--gitleaks")) !== undefined) options.toolPaths.gitleaks = value;
    else if ((value = valueFlag("--osv")) !== undefined) options.toolPaths.osv = value;
    else if ((value = valueFlag("--trivy")) !== undefined) options.toolPaths.trivy = value;
    else if ((value = valueFlag("--bandit")) !== undefined) options.toolPaths.bandit = value;
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
  if (!options.source && !options.url && !options.apiPolicy) throw new CliUsageError("provide --source, --url, or --api-policy");
  if (options.pages.length > 0 && !options.url) throw new CliUsageError("--page requires --url");
  if (options.maxPages !== undefined && !options.url) throw new CliUsageError("--max-pages requires --url");
  if (options.allowPrivate && !options.url && !options.apiPolicy) throw new CliUsageError("--allow-private requires URL or API mode");
  if (options.osvOffline && !options.source) throw new CliUsageError("--osv-offline requires source mode");
  return options;
}

function modeFor(options: CliOptions): Mode {
  if (options.apiPolicy) return options.source || options.url ? 'combined' : 'api';
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
    url: options.url,
    projectId: options.projectId,
    tools: options.source ? options.tools : [],
    // Tool paths are used only to resolve/hash the selected executable in
    // provenance. They are intentionally excluded from the stable scope.
    toolPaths: options.source ? options.toolPaths : {},
    allowPrivate: options.allowPrivate,
    timeoutMs: options.timeoutMs,
    osvOffline: options.osvOffline,
    pages: options.pages,
    maxPages: options.maxPages,
    apiPolicy,
    ruleset: RULESET_VERSION,
  });
}

/** Executes a scan and writes the three contract reports when scanning starts. */
export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  if (argv[0] === 'compare') return runComparison(argv);
  if (argv[0] === 'doctor') return doctorMain(argv);
  if (argv[0] === 'init') return initMain(argv);
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
      tools: parsed.tools,
      toolPaths: parsed.toolPaths,
      timeoutMs: parsed.timeoutMs,
      osvOffline: parsed.osvOffline,
      outDir: parsed.outDir,
    };
    try {
      checks.push(...await runSource(sourceOptions));
    } catch {
      checks.push(runtimeErrorCheck("source.runtime", "Source scanning could not be completed."));
    }
  }
  if (parsed.url) {
    const urlOptions: UrlOptions = {
      url: parsed.url,
      pages: parsed.pages,
      maxPages: parsed.maxPages,
      allowPrivate: parsed.allowPrivate,
      timeoutMs: parsed.timeoutMs,
    };
    try {
      checks.push(...await runUrl(urlOptions));
    } catch {
      checks.push(runtimeErrorCheck("url.runtime", "URL scanning could not be completed."));
    }
  }
  if (apiPolicy) {
    try {
      checks.push(...await runApiPolicy({ policy: apiPolicy, allowPrivate: parsed.allowPrivate, timeoutMs: parsed.timeoutMs }));
    } catch {
      checks.push(runtimeErrorCheck('api.runtime', 'API authorization scanning could not be completed.'));
    }
  }
  const report = createReport(checks, mode, startedAt, await declaredScope(parsed, apiPolicy));
  try {
    await writeReports(report, parsed.outDir);
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
    `Reports: ${JSON.stringify(resolve(parsed.outDir))} (report.json, report.sarif, report.md)`,
    "Scope details and limitations are recorded in report.md.",
    "",
  ].join("\n"));
  return code;
}

function canonicalFile(path: string): string {
  try { return realpathSync(path); } catch { return resolve(path); }
}

if (process.argv[1] && canonicalFile(process.argv[1]) === canonicalFile(fileURLToPath(import.meta.url))) {
  main().then((code) => { process.exitCode = code; }).catch(() => { process.exitCode = 2; });
}
