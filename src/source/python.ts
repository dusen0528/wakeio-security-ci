import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { CheckResult, Finding, Severity } from "../contracts.js";
import { runProcess } from "./process.js";
import type { CollectedFile, ParsedToolResult, ProcessResult, SourceSnapshot } from "./types.js";

interface BanditContext {
  snapshot: SourceSnapshot;
  stageDir: string;
  timeoutMs: number;
  toolPath: string;
}

const MAX_LINE = 10_000_000;

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function requiredObject(value: unknown, field: string): Record<string, unknown> {
  const object = objectValue(value);
  if (!object) throw new Error(`Bandit output has an invalid ${field} record`);
  return object;
}

function requiredArray(value: Record<string, unknown>, key: string): unknown[] {
  const child = value[key];
  if (!Array.isArray(child)) throw new Error(`Bandit output has an invalid ${key} field`);
  return child;
}

function requiredString(value: Record<string, unknown>, key: string): string {
  const child = value[key];
  if (typeof child !== "string" || child.length === 0) throw new Error(`Bandit output has an invalid ${key} field`);
  return child;
}

function nonNegativeInt(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > MAX_LINE) {
    throw new Error(`Bandit output has an invalid ${field} field`);
  }
  return value;
}

function positiveInt(value: unknown, field: string): number {
  const result = nonNegativeInt(value, field);
  if (result < 1) throw new Error(`Bandit output has an invalid ${field} field`);
  return result;
}

function pathFromBandit(value: unknown, stageDir: string, allowed: Set<string>): string | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  const candidate = value.replaceAll("\\", "/");
  const absoluteCandidate = isAbsolute(candidate) ? resolve(candidate) : resolve(stageDir, candidate);
  const stage = resolve(stageDir);
  const relativePath = relative(stage, absoluteCandidate).replaceAll("\\", "/");
  if (relativePath && relativePath !== "." && !relativePath.startsWith("../") && relativePath !== ".." && !isAbsolute(relativePath) && allowed.has(relativePath)) {
    return relativePath;
  }
  const normalized = candidate.replace(/^\.\//, "");
  return allowed.has(normalized) ? normalized : undefined;
}

function parseJson(text: string): Record<string, unknown> {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Bandit produced no JSON output");
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed) as unknown;
  } catch {
    throw new Error("Bandit produced malformed JSON output");
  }
  return requiredObject(parsed, "root");
}

function severityFrom(value: unknown): Severity {
  if (typeof value !== "string") throw new Error("Bandit output has an invalid issue severity");
  switch (value.trim().toUpperCase()) {
    case "HIGH": return "high";
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    case "UNDEFINED": return "info";
    default: throw new Error("Bandit output has an unsupported issue severity");
  }
}

function confidenceFrom(value: unknown): Finding["confidence"] {
  if (typeof value !== "string") throw new Error("Bandit output has an invalid issue confidence");
  switch (value.trim().toUpperCase()) {
    case "HIGH": return "high";
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    case "UNDEFINED": return "low";
    default: throw new Error("Bandit output has an unsupported issue confidence");
  }
}

function banditTestId(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("Bandit output has an invalid test id");
  const id = value;
  if (!/^B\d{3}$/.test(id)) throw new Error("Bandit output has an unsupported test id");
  return id;
}

interface BanditGuidance {
  title: string;
  description: string;
  remediation: string;
  reference: string;
}

const BANDIT_GUIDANCE: Record<string, BanditGuidance> = {
  B404: {
    title: "Python subprocess module requires review",
    description: "Bandit identified an import of subprocess. The import is not itself a shell injection, but calls using it should use fixed argument arrays and avoid shell interpretation.",
    remediation: "Review subprocess call sites and use shell=False with fixed executables and validated arguments.",
    reference: "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html",
  },
  B301: {
    title: "Unsafe Python deserialization",
    description: "Bandit identified a pickle or related deserialization call that can construct unsafe objects from untrusted data.",
    remediation: "Do not deserialize untrusted data with pickle or equivalent object loaders; use a constrained data format or an explicit allowlist.",
    reference: "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html",
  },
  B307: {
    title: "Dynamic Python evaluation",
    description: "Bandit identified eval(), which can execute attacker-controlled Python expressions.",
    remediation: "Replace eval() with a fixed operation or ast.literal_eval() when parsing a constrained literal format.",
    reference: "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html",
  },
  B501: {
    title: "TLS certificate verification is disabled",
    description: "Bandit identified a requests or httpx call that disables TLS certificate validation.",
    remediation: "Keep certificate verification enabled and configure a trusted CA bundle when a private authority is required.",
    reference: "https://bandit.readthedocs.io/en/latest/plugins/b501_request_with_no_cert_validation.html",
  },
  B506: {
    title: "Unsafe YAML loading",
    description: "Bandit identified yaml.load() or a related loader that may construct arbitrary Python objects from untrusted YAML.",
    remediation: "Use a safe YAML loader such as yaml.safe_load() and validate the resulting data against the expected schema.",
    reference: "https://bandit.readthedocs.io/en/latest/plugins/b506_yaml_load.html",
  },
  B602: {
    title: "Subprocess call uses a shell",
    description: "Bandit identified a subprocess call with shell=True, which can turn untrusted command data into shell syntax.",
    remediation: "Use a fixed executable and argument array with shell=False, and validate any user-controlled arguments.",
    reference: "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
  },
  B603: {
    title: "Subprocess call requires argument validation",
    description: "Bandit identified a subprocess call without shell=True. The call avoids shell parsing but still needs fixed executables and validated arguments.",
    remediation: "Use an absolute or controlled executable and validate every argument that can be influenced by input.",
    reference: "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
  },
  B607: {
    title: "Subprocess executable path is partial",
    description: "Bandit identified a process call whose executable path relies on PATH lookup instead of a fully qualified path.",
    remediation: "Use a fully qualified executable path or a tightly controlled executable resolution policy.",
    reference: "https://bandit.readthedocs.io/en/latest/plugins/b607_start_process_with_partial_path.html",
  },
  B608: {
    title: "SQL expression is constructed from strings",
    description: "Bandit identified string construction that resembles a SQL expression and may be vulnerable when values are interpolated.",
    remediation: "Use parameterized queries for values and keep identifiers behind a strict allowlist.",
    reference: "https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html",
  },
};

function guidanceFor(testId: string): BanditGuidance {
  return BANDIT_GUIDANCE[testId] ?? {
    title: `Python security finding (${testId})`,
    description: `Bandit identified ${testId} in the allowlisted Python snapshot. The scanner message and source snippet are intentionally omitted.`,
    remediation: "Review the Bandit rule documentation and apply the documented secure alternative.",
    reference: "https://bandit.readthedocs.io/en/latest/",
  };
}

function sourceLineCount(text: string): number {
  if (text.length === 0) return 1;
  const lines = text.split(/\r\n|\r|\n/);
  return /(?:\r\n|\r|\n)$/.test(text) ? Math.max(1, lines.length - 1) : lines.length;
}

function validateLineRange(value: unknown, maxLine: number, line: number): void {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "number" || !Number.isSafeInteger(entry) || entry < 1 || entry > MAX_LINE || entry > maxLine)) {
    throw new Error("Bandit output has an invalid line_range field");
  }
  if (line > maxLine) throw new Error("Bandit output line_number is outside the selected Python file");
  if (!(value as number[]).includes(line)) throw new Error("Bandit output line_number is outside line_range");
}

function metricForFile(metrics: Record<string, unknown>, file: CollectedFile, stageDir: string, allowed: Set<string>): Record<string, unknown> | undefined {
  for (const [key, value] of Object.entries(metrics)) {
    if (key === "_totals") continue;
    if (pathFromBandit(key, stageDir, allowed) !== file.path) continue;
    return requiredObject(value, "per-file metrics");
  }
  return undefined;
}

function validateMetrics(metrics: Record<string, unknown>, files: CollectedFile[], stageDir: string, allowed: Set<string>): number {
  const totals = requiredObject(metrics._totals, "metrics totals");
  nonNegativeInt(totals.loc, "metrics totals loc");
  const matched = new Set<string>();
  for (const file of files) {
    const metric = metricForFile(metrics, file, stageDir, allowed);
    if (!metric) continue;
    nonNegativeInt(metric.loc, "per-file metrics loc");
    matched.add(file.path);
  }
  return matched.size;
}

/** Returns the allowlisted Python files that may be passed to Bandit. */
export function pythonFiles(snapshot: SourceSnapshot): CollectedFile[] {
  return snapshot.files.filter((file) => file.category === "code" && /\.py$/i.test(file.path));
}

/**
 * Parse Bandit's JSON formatter without retaining code snippets, issue text,
 * filenames outside the bounded snapshot, or arbitrary scanner metadata.
 */
export function parseBanditOutput(text: string, stageDir: string, files: CollectedFile[]): ParsedToolResult {
  const top = parseJson(text);
  const errors = requiredArray(top, "errors");
  const results = requiredArray(top, "results");
  const metrics = requiredObject(top.metrics, "metrics");
  const generatedAt = requiredString(top, "generated_at");
  if (!Number.isFinite(Date.parse(generatedAt))) throw new Error("Bandit output has an invalid generated_at field");
  const allowed = new Set(files.map((file) => file.path));

  for (const entry of errors) {
    const error = requiredObject(entry, "error");
    const errorPath = pathFromBandit(error.filename, stageDir, allowed);
    if (!errorPath) throw new Error("Bandit output has an unmapped error filename");
    requiredString(error, "reason");
  }

  const filesReported = validateMetrics(metrics, files, stageDir, allowed);
  const findings: Finding[] = [];
  for (const entry of results) {
    const result = requiredObject(entry, "result");
    const path = pathFromBandit(result.filename, stageDir, allowed);
    if (!path) throw new Error("Bandit output has an unmapped result filename");
    const line = positiveInt(result.line_number, "line_number");
    const source = files.find((file) => file.path === path);
    if (!source) throw new Error("Bandit output result filename is not in the selected Python files");
    validateLineRange(result.line_range, sourceLineCount(source.text), line);
    const testId = banditTestId(result.test_id);
    // Validate the documented fields but deliberately omit code and issue_text
    // from every public result. Both fields can contain arbitrary source data.
    requiredString(result, "code");
    requiredString(result, "issue_text");
    requiredString(result, "test_name");
    const severity = severityFrom(result.issue_severity);
    const confidence = confidenceFrom(result.issue_confidence);
    const guidance = guidanceFor(testId);
    findings.push({
      ruleId: `bandit:${testId}`,
      title: guidance.title,
      description: guidance.description,
      severity,
      confidence,
      kind: "candidate",
      location: { path, line },
      remediation: guidance.remediation,
      references: [guidance.reference],
    });
  }

  const metricsIncomplete = filesReported !== files.length;
  return {
    findings,
    status: errors.length > 0 || metricsIncomplete ? "partial" : "completed",
    notes: [
      `Bandit parsed ${findings.length} finding${findings.length === 1 ? "" : "s"} across ${filesReported} of ${files.length} allowlisted Python file${files.length === 1 ? "" : "s"}.`,
      "Bandit was run with inline #nosec suppressions ignored; source snippets and scanner text are omitted.",
      ...(errors.length > 0 ? [`Bandit reported ${errors.length} file scan error${errors.length === 1 ? "" : "s"}; Python coverage is incomplete.`] : []),
      ...(metricsIncomplete ? ["Bandit did not report per-file metrics for every selected Python file; coverage is incomplete."] : []),
    ],
    metrics: { filesAnalyzed: filesReported, filesRequested: files.length, findingCount: findings.length, errorCount: errors.length },
  };
}

function processFailure(result: ProcessResult, timeoutMs: number): string | undefined {
  if (result.spawnError) return "Bandit could not be started.";
  if (result.timedOut) return `Bandit exceeded the ${timeoutMs} ms scanner timeout.`;
  if (result.outputLimitExceeded) return "Bandit exceeded the scanner output limit.";
  if (result.exitCode !== null && result.exitCode > 1) return `Bandit exited with code ${result.exitCode}.`;
  if (result.signal) return `Bandit was terminated by ${result.signal}.`;
  if (result.exitCode === null) return "Bandit returned no exit status.";
  return undefined;
}

function errorCheck(message: string): CheckResult {
  return { id: "source.bandit", status: "error", findings: [], notes: [message] };
}

/** Run Bandit against only the staged allowlisted Python files. */
export async function runBandit(context: BanditContext): Promise<CheckResult> {
  const files = pythonFiles(context.snapshot);
  if (files.length === 0) {
    return { id: "source.bandit", status: "not_applicable", findings: [], notes: ["No allowlisted Python files were available for Bandit."], metrics: { files: 0 } };
  }
  if (!context.toolPath) return { id: "source.bandit", status: "partial", findings: [], notes: ["Bandit executable was not found; Python SAST coverage is unavailable."], metrics: { files: files.length } };

  const args = ["-f", "json", "--ignore-nosec", "--", ...files.map((file) => join(context.stageDir, ...file.path.split("/")))];
  const result = await runProcess(context.toolPath, args, {
    cwd: context.stageDir,
    timeoutMs: context.timeoutMs,
    home: join(dirname(context.stageDir), "home"),
  });
  const failure = processFailure(result, context.timeoutMs);
  if (failure) return errorCheck(failure);
  try {
    const parsed = parseBanditOutput(result.stdout, context.stageDir, files);
    if (result.exitCode === 1 && parsed.findings.length === 0 && parsed.status === "completed") {
      return errorCheck("Bandit exited with a finding status but returned an empty report.");
    }
    if (!context.snapshot.complete && parsed.status === "completed") {
      parsed.status = "partial";
      parsed.notes = [...parsed.notes, "The collected Python snapshot was incomplete; Bandit coverage may be incomplete."];
      parsed.metrics = { ...(parsed.metrics ?? {}), snapshotComplete: false };
    }
    return {
      id: "source.bandit",
      status: parsed.status ?? "completed",
      findings: parsed.findings,
      notes: parsed.notes,
      ...(parsed.metrics ? { metrics: parsed.metrics } : {}),
    };
  } catch {
    return errorCheck("Bandit returned an invalid or incomplete JSON report.");
  }
}
