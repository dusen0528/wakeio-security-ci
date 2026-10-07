import { createHash } from "node:crypto";
import { lstat, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApiRunControl } from "./api.js";
import type { CheckResult, Finding, Severity } from "./contracts.js";
import { resolveDastOrigin, startEgressGate, type EgressGate } from "./dast-egress.js";
import { findExecutable, MAX_TOOL_TIMEOUT_MS, runProcess } from "./source/process.js";
import { normalizeUrl, safeUrl, UrlNetworkError } from "./url-network.js";

/**
 * Opt-in Nuclei adapter. Template selection is explicit and static; all
 * traffic crosses the egress gate, and engine success is never inferred from
 * exit 0 alone (Nuclei exits 0 after partial progress).
 */
export const NUCLEI_CHECK_ID = "url.nuclei";
export const NUCLEI_VERSION = "3.11.1";
export const NUCLEI_SCOPES = Object.freeze({ misconfiguration: "http/misconfiguration", exposures: "http/exposures" } as const);
export type NucleiScope = keyof typeof NUCLEI_SCOPES;
export const NUCLEI_DEFAULT_MAX_REQUESTS = 6_000;
export const NUCLEI_MAX_REQUESTS = 20_000;
export const NUCLEI_DEFAULT_RATE_LIMIT = 50;
export const NUCLEI_MAX_RATE_LIMIT = 150;
export const NUCLEI_MAX_SINGLE_BODY_BYTES = 2 * 1024 * 1024;
export const NUCLEI_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_TEMPLATE_FILES = 10_000;
const MAX_TEMPLATE_BYTES = 256 * 1024;
const SCOPE_NOTE = "Nuclei runs only signed HTTP GET/HEAD templates from the selected local template scopes against one consented origin through the egress gate; raw/unsafe, non-GET, self-contained and other-protocol templates are excluded, and no interactsh, update check, redirect following or template download occurs.";

export interface NucleiOptions {
  url: string;
  executable?: string;
  templatesDir: string;
  scopes: NucleiScope[];
  consent: boolean;
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxRequests?: number;
  rateLimit?: number;
  signal?: AbortSignal;
}

export interface TemplateSelection {
  selected: string[];
  excluded: { rawOrUnsafe: number; method: number; unsigned: number; protocol: number; selfContained: number; unreadable: number };
  truncated: boolean;
}

const PROTOCOL_KEYS = /^(?:dns|file|network|tcp|headless|ssl|websocket|whois|code|javascript|workflows|flow):/m;
const RAW_KEYS = /^\s*-?\s*(?:raw|unsafe|race|race_count|pipeline)\s*:/m;
const METHOD = /^\s*-?\s*method\s*:\s*["']?([A-Za-z]+)/gm;
const SIGNATURE = /^# digest: [0-9a-f]{32,}:[0-9a-f]{32}\s*$/m;

/** Static, conservative template filter; anything ambiguous is excluded and counted. */
export function classifyTemplate(text: string): keyof TemplateSelection["excluded"] | "selected" {
  if (!SIGNATURE.test(text)) return "unsigned";
  if (PROTOCOL_KEYS.test(text) || !/^http:/m.test(text)) return "protocol";
  if (/^\s*self-contained\s*:\s*true/m.test(text)) return "selfContained";
  if (RAW_KEYS.test(text)) return "rawOrUnsafe";
  for (const match of text.matchAll(METHOD)) {
    if (!["GET", "HEAD"].includes(match[1]!.toUpperCase())) return "method";
  }
  return "selected";
}

export async function selectNucleiTemplates(templatesRoot: string, scopes: NucleiScope[]): Promise<TemplateSelection> {
  const result: TemplateSelection = { selected: [], excluded: { rawOrUnsafe: 0, method: 0, unsigned: 0, protocol: 0, selfContained: 0, unreadable: 0 }, truncated: false };
  let visited = 0;
  const walk = async (directory: string): Promise<void> => {
    const entries = (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (visited >= MAX_TEMPLATE_FILES) { result.truncated = true; return; }
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) { result.excluded.unreadable += 1; continue; }
      if (entry.isDirectory()) { await walk(path); continue; }
      if (!entry.isFile() || !/\.ya?ml$/i.test(entry.name)) continue;
      visited += 1;
      const stats = await lstat(path);
      if (!stats.isFile() || stats.size > MAX_TEMPLATE_BYTES) { result.excluded.unreadable += 1; continue; }
      const verdict = classifyTemplate(await readFile(path, "utf8"));
      if (verdict === "selected") result.selected.push(path);
      else result.excluded[verdict] += 1;
    }
  };
  for (const scope of scopes) {
    const directory = join(templatesRoot, ...NUCLEI_SCOPES[scope].split("/"));
    const stats = await lstat(directory).catch(() => undefined);
    if (!stats?.isDirectory() || stats.isSymbolicLink()) throw new Error("template_scope_missing");
    await walk(directory);
  }
  return result;
}

/**
 * The version is read from `.templates-config.json`, as written by `nuclei -ut`:
 * beside the templates or in the user's Nuclei config directory, and only when
 * that config names this same directory. The checksum-file digest is always recorded.
 */
async function templateProvenance(root: string): Promise<{ templatesChecksumSha256: string; templatesVersion: string }> {
  const checksum = await readFile(join(root, "templates-checksum.txt")).catch(() => undefined);
  let version = "unknown";
  const home = process.env.HOME;
  const candidates = [join(root, ".templates-config.json"),
    ...(home ? [join(home, "Library", "Application Support", "nuclei", ".templates-config.json"),
      join(process.env.XDG_CONFIG_HOME ?? join(home, ".config"), "nuclei", ".templates-config.json")] : [])];
  for (const candidate of candidates) {
    try {
      const config = JSON.parse(await readFile(candidate, "utf8")) as Record<string, unknown>;
      const directory = config["nuclei-templates-directory"];
      if (candidate !== candidates[0] && (typeof directory !== "string" || await realpath(directory).catch(() => "") !== root)) continue;
      const value = config["nuclei-templates-version"];
      if (typeof value === "string" && /^v?\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(value)) { version = value; break; }
    } catch { /* optional provenance file */ }
  }
  return { templatesChecksumSha256: checksum ? createHash("sha256").update(checksum).digest("hex") : "unknown", templatesVersion: version };
}

const SEVERITIES: Record<string, Severity> = { info: "info", low: "low", medium: "medium", high: "high", critical: "critical" };
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

function cleanText(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const text = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return text ? text.slice(0, max) : undefined;
}

interface StatsLine { percent: number; requests: number; total: number; errors: number; templates: number; matched: number }

export function parseNucleiOutput(stdout: string, stderr: string, origin: string): { findings: Finding[]; droppedOutOfOrigin: number; malformed: number; stats?: StatsLine } {
  const findings = new Map<string, Finding>();
  let dropped = 0, malformed = 0;
  let stats: StatsLine | undefined;
  for (const line of `${stdout}\n${stderr}`.split("\n")) {
    if (!line.startsWith("{")) continue;
    let value: Record<string, unknown>;
    try { value = JSON.parse(line) as Record<string, unknown>; } catch { malformed += 1; continue; }
    if ("percent" in value && "requests" in value) {
      const number = (key: string) => Number.parseInt(String(value[key] ?? ""), 10);
      const parsed = { percent: number("percent"), requests: number("requests"), total: number("total"), errors: number("errors"), templates: number("templates"), matched: number("matched") };
      if (Object.values(parsed).every((item) => Number.isSafeInteger(item) && item >= 0)) stats = parsed;
      else malformed += 1;
      continue;
    }
    if (!("template-id" in value)) continue;
    const templateId = value["template-id"];
    const info = value.info && typeof value.info === "object" ? value.info as Record<string, unknown> : {};
    const matcher = value["matcher-name"];
    const matchedAt = value["matched-at"];
    if (typeof templateId !== "string" || !IDENTIFIER.test(templateId) || (matcher !== undefined && (typeof matcher !== "string" || !IDENTIFIER.test(matcher))) || typeof matchedAt !== "string") { malformed += 1; continue; }
    let location: string;
    try {
      const normalized = normalizeUrl(matchedAt);
      if (normalized.origin !== origin) { dropped += 1; continue; }
      location = safeUrl(normalized);
    } catch { dropped += 1; continue; }
    const severity = SEVERITIES[String(info.severity ?? "").toLowerCase()] ?? "info";
    const name = cleanText(info.name, 160) ?? templateId;
    const references = (Array.isArray(info.reference) ? info.reference : typeof info.reference === "string" ? [info.reference] : [])
      .filter((item): item is string => typeof item === "string" && /^https:\/\/[^\s]{1,300}$/.test(item)).slice(0, 3);
    const key = `${templateId}\u0000${matcher ?? ""}\u0000${location}`;
    if (findings.has(key)) continue;
    findings.set(key, {
      // Matcher names distinguish results of one template at one location (e.g. each missing header).
      ruleId: `nuclei.${templateId}${matcher ? `.${matcher}` : ""}`,
      title: name,
      description: `Nuclei template ${templateId}${matcher ? ` (matcher ${matcher})` : ""} matched the response. Template output, extracted values and raw request/response data are not retained.`,
      severity, confidence: "medium", kind: "observation",
      location: { url: location },
      remediation: "Confirm the matched exposure or misconfiguration on the consented target, fix it, and rerun the same template scope and template digest.",
      ...(references.length ? { references } : {}),
    });
  }
  return { findings: [...findings.values()], droppedOutOfOrigin: dropped, malformed, ...(stats ? { stats } : {}) };
}

function errorCheck(code: string, message: string, metrics: Record<string, number | string | boolean> = {}): CheckResult[] {
  return [{ id: NUCLEI_CHECK_ID, status: "error", findings: [], notes: [SCOPE_NOTE, message], metrics: { requestCount: 0, errorCode: code, ...metrics } }];
}

function bounded(value: number | undefined, fallback: number, cap: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > cap) throw new RangeError("invalid budget");
  return result;
}

export async function runNuclei(options: NucleiOptions): Promise<CheckResult[]> {
  if (!options || options.consent !== true) return errorCheck("consent_required", "Active Nuclei testing requires explicit consent; no requests were made.");
  let maxRequests: number, rateLimit: number, timeoutMs: number;
  try {
    maxRequests = bounded(options.maxRequests, NUCLEI_DEFAULT_MAX_REQUESTS, NUCLEI_MAX_REQUESTS);
    rateLimit = bounded(options.rateLimit, NUCLEI_DEFAULT_RATE_LIMIT, NUCLEI_MAX_RATE_LIMIT);
    timeoutMs = bounded(options.timeoutMs, 300_000, MAX_TOOL_TIMEOUT_MS);
  } catch {
    return errorCheck("invalid_budget", "Nuclei budgets are invalid; no requests were made.");
  }
  const scopes = [...new Set(options.scopes)];
  if (scopes.length === 0 || scopes.some((scope) => !(scope in NUCLEI_SCOPES))) return errorCheck("invalid_scope", "Nuclei template scope is invalid; no requests were made.");
  const executable = await findExecutable(options.executable ?? "nuclei");
  if (!executable) return errorCheck("engine_missing", `Nuclei ${NUCLEI_VERSION} was not found; install it with scripts/install-tools.mjs --tools nuclei or pass --nuclei. No requests were made.`);
  let templatesRoot: string;
  try {
    templatesRoot = await realpath(options.templatesDir);
    if (!(await lstat(templatesRoot)).isDirectory()) throw new Error("not_directory");
  } catch {
    return errorCheck("templates_missing", "The prepared nuclei-templates directory could not be read; templates are never downloaded during a scan. No requests were made.");
  }
  const work = await mkdtemp(join(tmpdir(), "wakeio-nuclei-"));
  const control = createApiRunControl(timeoutMs, options.signal, MAX_TOOL_TIMEOUT_MS);
  const engine = new AbortController();
  const stopEngine = () => engine.abort();
  control.signal.addEventListener("abort", stopEngine, { once: true });
  let gate: EgressGate | undefined;
  try {
    const version = await runProcess(executable, ["-version", "-duc", "-nc"], { cwd: work, home: work, timeoutMs: 30_000, signal: engine.signal });
    if (!`${version.stdout}\n${version.stderr}`.includes(`Nuclei Engine Version: v${NUCLEI_VERSION}`)) {
      return errorCheck("unsupported_engine_version", `This adapter is verified only with Nuclei ${NUCLEI_VERSION}; no requests were made.`);
    }
    let selection: TemplateSelection;
    try { selection = await selectNucleiTemplates(templatesRoot, scopes); }
    catch { return errorCheck("template_scope_missing", "A selected template scope is missing from the prepared templates directory; no requests were made."); }
    if (selection.selected.length === 0) return errorCheck("no_templates", "No templates remained after the safety filter; no requests were made.");
    const provenance = await templateProvenance(templatesRoot);
    let resolved;
    try {
      resolved = await resolveDastOrigin(options.url, options.allowPrivate === true, control.signal);
    } catch (error) {
      return errorCheck(error instanceof UrlNetworkError ? error.code : "dast_origin_required", "The target origin was rejected by the URL-network policy (origin only; metadata/private rules apply); no requests were made.");
    }
    gate = await startEgressGate({ origin: resolved.origin, address: resolved.address, methods: new Set(["GET", "HEAD"]),
      maxRequests, maxSingleBodyBytes: NUCLEI_MAX_SINGLE_BODY_BYTES, maxTotalBytes: NUCLEI_MAX_TOTAL_BYTES,
      signal: control.signal, deadlineAt: control.deadlineAt });
    gate.onStop(stopEngine);
    const list = join(work, "templates.txt");
    await writeFile(list, `${selection.selected.join("\n")}\n`, { mode: 0o600 });
    const args = ["-u", resolved.origin.href, "-t", list, "-ud", templatesRoot, "-pt", "http", "-dut",
      "-ni", "-duc", "-dr", "-nc", "-jsonl", "-or", "-ot", "-silent", "-stats", "-sj", "-si", "1",
      "-retries", "0", "-timeout", "10", "-rl", String(rateLimit), "-c", "10", "-bs", "1", "-proxy", gate.proxyUrl];
    const started = Date.now();
    const run = await runProcess(executable, args, { cwd: work, home: work, timeoutMs, signal: engine.signal });
    const parsed = parseNucleiOutput(run.stdout, run.stderr, resolved.origin.origin);
    const counters = { ...gate.counters };
    const stop = gate.stopReason();
    const stats = parsed.stats;
    const relativeScopes = scopes.map((scope) => NUCLEI_SCOPES[scope]).join(",");
    const metrics: Record<string, number | string | boolean> = {
      engine: "nuclei", engineVersion: NUCLEI_VERSION, scopes: relativeScopes,
      templatesSelected: selection.selected.length,
      templatesExcludedRawOrUnsafe: selection.excluded.rawOrUnsafe, templatesExcludedMethod: selection.excluded.method,
      templatesExcludedUnsigned: selection.excluded.unsigned, templatesExcludedProtocol: selection.excluded.protocol,
      templatesExcludedSelfContained: selection.excluded.selfContained, templatesUnreadable: selection.excluded.unreadable,
      templatesVersion: provenance.templatesVersion, templatesChecksumSha256: provenance.templatesChecksumSha256,
      requestCount: counters.forwarded, gateTunnels: counters.tunnels, skippedByBudget: counters.blockedBudget,
      blockedOrigin: counters.blockedOrigin, blockedMethod: counters.blockedMethod, upstreamErrors: counters.upstreamErrors,
      rejectedEncoding: counters.rejectedEncoding, responseBytes: counters.responseBytes,
      maxRequests, rateLimit, durationMs: Date.now() - started,
      droppedOutOfOriginResults: parsed.droppedOutOfOrigin, malformedEngineLines: parsed.malformed,
      ...(stats ? { enginePercent: stats.percent, enginePlannedRequests: stats.total, engineRequests: stats.requests, engineErrors: stats.errors, engineTemplatesLoaded: stats.templates } : {}),
    };
    if (run.spawnError) return errorCheck("engine_spawn_failed", "Nuclei could not be started.", metrics);
    const cancelled = options.signal?.aborted === true;
    const reason = stop ?? (cancelled ? "cancelled" : run.timedOut || control.signal.aborted ? "timeout" : run.outputLimitExceeded ? "output_limit"
      : run.exitCode !== 0 ? "engine_exit" : !stats ? "stats_missing" : stats.percent < 100 ? "engine_incomplete"
      : stats.errors > 0 ? "engine_errors" : counters.upstreamErrors > 0 ? "upstream_error" : counters.rejectedEncoding > 0 ? "rejected_encoding"
      : selection.truncated ? "template_scan_truncated" : parsed.malformed > 0 ? "malformed_engine_output" : "complete");
    metrics.stopReason = reason;
    const notes = [SCOPE_NOTE,
      `Target ${safeUrl(resolved.origin)}; ${counters.forwarded} request(s) forwarded, ${counters.blockedBudget} refused by the request budget, ${counters.blockedOrigin} refused for leaving the origin; ${selection.selected.length} template(s) selected from ${relativeScopes}.`,
      `Templates ${provenance.templatesVersion} (templates-checksum.txt sha256 ${provenance.templatesChecksumSha256.slice(0, 16)}…); Nuclei ${NUCLEI_VERSION}.`];
    if (resolved.origin.protocol === "https:") notes.push(`HTTPS: the gate sees CONNECT tunnels only. It caps tunnels at the request budget (${counters.tunnels} opened), but requests reused inside a tunnel are not counted on the wire; time and byte budgets still apply, and Nuclei does not verify TLS certificates.`);
    if (reason !== "complete") notes.push(`Incomplete: ${reason}. Nuclei exit status alone does not establish completion; treat absent findings as unverified.`);
    return [{ id: NUCLEI_CHECK_ID, status: reason === "complete" ? "completed" : "partial", findings: parsed.findings, notes, metrics }];
  } finally {
    control.signal.removeEventListener("abort", stopEngine);
    control.dispose();
    await gate?.close();
    await rm(work, { recursive: true, force: true }).catch(() => undefined);
  }
}

