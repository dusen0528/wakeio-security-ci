import { isAbsolute, relative, resolve } from "node:path";
import type { Finding, Severity } from "../contracts.js";
import type { CollectedFile, ParsedToolResult } from "./types.js";

function own(object: object, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(object, key) ? (object as Record<string, unknown>)[key] : undefined;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function cleanText(value: unknown, fallback: string, max = 240): string {
  if (typeof value !== "string") return fallback;
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  return clean ? clean.slice(0, max) : fallback;
}

function cleanRuleId(value: unknown, fallback: string): string {
  const candidate = cleanText(value, fallback, 120);
  const safe = candidate.replace(/[^A-Za-z0-9_.:/-]/g, "_");
  return safe || fallback;
}

function positiveInt(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= 10_000_000) return value;
  if (typeof value === "string" && /^\d{1,8}$/.test(value)) {
    const parsed = Number(value);
    if (parsed >= 1) return parsed;
  }
  return undefined;
}

function severityFrom(value: unknown, fallback: Severity = "medium"): Severity {
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized.includes("critical") || normalized === "blocker") return "critical";
    if (normalized.includes("high") || normalized === "severe") return "high";
    if (normalized.includes("moderate") || normalized.includes("medium") || normalized === "warning") return "medium";
    if (normalized.includes("low")) return "low";
    if (normalized.includes("info") || normalized.includes("unknown") || normalized === "none") return "info";
    const numeric = Number(normalized);
    if (Number.isFinite(numeric)) return severityFrom(numeric, fallback);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value >= 9) return "critical";
    if (value >= 7) return "high";
    if (value >= 4) return "medium";
    if (value > 0) return "low";
    return "info";
  }
  return fallback;
}

function referencesFrom(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const references = value.map((entry) => {
    if (typeof entry === "string") return entry.trim();
    const object = objectValue(entry);
    if (!object || typeof object.url !== "string" || object.url.length === 0) throw new Error("scanner output has an invalid reference");
    return object.url.trim();
  })
    .filter((entry) => /^https?:\/\/[^\s]{1,500}$/i.test(entry))
    .slice(0, 5);
  return references.length > 0 ? references : undefined;
}

function pathFromScanner(value: unknown, stageDir: string, allowed: Set<string>): string | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  const candidate = value.replaceAll("\\", "/");
  const absoluteCandidate = isAbsolute(candidate) ? resolve(candidate) : resolve(stageDir, candidate);
  const stage = resolve(stageDir);
  const relativePath = relative(stage, absoluteCandidate).replaceAll("\\", "/");
  if (relativePath && relativePath !== "." && !relativePath.startsWith("../") && relativePath !== ".." && !isAbsolute(relativePath) && allowed.has(relativePath)) return relativePath;
  // Some adapters report only the relative path even when their working
  // directory differs. Accept it only when it exactly names a staged file.
  const normalized = candidate.replace(/^\.\//, "");
  return allowed.has(normalized) ? normalized : undefined;
}

function makeFinding(input: {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Finding["confidence"];
  kind: Finding["kind"];
  path?: string;
  line?: number;
  column?: number;
  remediation: string;
  references?: string[];
}): Finding {
  return {
    ruleId: cleanRuleId(input.ruleId, "scanner.finding"),
    title: cleanText(input.title, "Security finding"),
    description: cleanText(input.description, "A scanner reported a security finding."),
    severity: input.severity,
    confidence: input.confidence,
    kind: input.kind,
    location: {
      ...(input.path ? { path: input.path } : {}),
      ...(input.line ? { line: input.line } : {}),
      ...(input.column ? { column: input.column } : {}),
    },
    remediation: cleanText(input.remediation, "Review the finding and apply the scanner's recommended fix."),
    ...(input.references ? { references: input.references } : {}),
  };
}

function parseJson(text: string, tool: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) throw new Error(`${tool} produced no JSON output`);
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    throw new Error(`${tool} produced malformed JSON output`);
  }
}

function requiredArray(value: Record<string, unknown>, key: string, tool: string): unknown[] {
  const child = own(value, key);
  if (!Array.isArray(child)) throw new Error(`${tool} output has an invalid ${key} field`);
  return child;
}

function requiredObject(value: unknown, field: string, tool: string): Record<string, unknown> {
  const object = objectValue(value);
  if (!object) throw new Error(`${tool} output has an invalid ${field} record`);
  return object;
}

function requiredPositiveInt(value: Record<string, unknown>, key: string, tool: string): number {
  const child = own(value, key);
  if (typeof child !== "number" || !Number.isSafeInteger(child) || child < 1 || child > 10_000_000) throw new Error(`${tool} output has an invalid ${key} field`);
  return child;
}

function requiredString(value: Record<string, unknown>, key: string, tool: string): string {
  const child = own(value, key);
  if (typeof child !== "string" || child.length === 0) throw new Error(`${tool} output has an invalid ${key} field`);
  return child;
}

export function parseGitleaksOutput(text: string, stageDir: string, files: CollectedFile[]): ParsedToolResult {
  const parsed = parseJson(text, "Gitleaks");
  if (!Array.isArray(parsed)) throw new Error("Gitleaks output must be a JSON array");
  const entries = parsed;
  const allowed = new Set(files.map((file) => file.path));
  const findings: Finding[] = [];
  let unknownLocations = 0;
  for (const entry of entries) {
    const object = requiredObject(entry, "finding", "Gitleaks");
    const ruleId = cleanRuleId(requiredString(object, "RuleID", "Gitleaks"), "gitleaks.secret");
    const filePath = requiredString(object, "File", "Gitleaks");
    const path = pathFromScanner(filePath, stageDir, allowed);
    if (!path) unknownLocations += 1;
    const line = requiredPositiveInt(object, "StartLine", "Gitleaks");
    const column = requiredPositiveInt(object, "StartColumn", "Gitleaks");
    const title = cleanText(requiredString(object, "Description", "Gitleaks"), `Secret detected by Gitleaks (${ruleId})`);
    const severity: Severity = /private[-_ ]?key|password|token|secret|credential|aws|github|slack/i.test(`${ruleId} ${title}`) ? "high" : "medium";
    findings.push(makeFinding({
      ruleId,
      title: `Secret detected: ${title}`,
      description: `Gitleaks identified a potential secret using rule ${ruleId}. The matched value is intentionally omitted.`,
      severity,
      confidence: "high",
      kind: "observation",
      path,
      line,
      column,
      remediation: "Revoke or rotate the exposed credential, then remove it from the source and history.",
    }));
  }
  return {
    findings,
    notes: [
      `Gitleaks parsed ${findings.length} finding${findings.length === 1 ? "" : "s"}.`,
      ...(unknownLocations > 0 ? [`${unknownLocations} Gitleaks location${unknownLocations === 1 ? "" : "s"} could not be mapped to the bounded snapshot.`] : []),
    ],
    metrics: { findingCount: findings.length },
  };
}

function vulnerabilitySeverity(vulnerability: Record<string, unknown>, group: Record<string, unknown> | undefined): Severity {
  const databaseSpecific = objectValue(own(vulnerability, "database_specific"));
  const directSeverity = own(databaseSpecific ?? {}, "severity");
  if (directSeverity !== undefined) {
    if (typeof directSeverity !== "string" && typeof directSeverity !== "number") throw new Error("OSV-Scanner output has an invalid database severity");
    return severityFrom(directSeverity);
  }
  const groupSeverity = own(group ?? {}, "max_severity");
  if (groupSeverity !== undefined) {
    if (typeof groupSeverity !== "string" && typeof groupSeverity !== "number") throw new Error("OSV-Scanner output has an invalid group severity");
    return severityFrom(groupSeverity);
  }
  const severities = own(vulnerability, "severity");
  if (Array.isArray(severities)) {
    for (const item of severities) {
      const severity = objectValue(item);
      if (!severity) throw new Error("OSV-Scanner output has an invalid severity record");
      const score = own(severity, "score");
      if (typeof score !== "string") throw new Error("OSV-Scanner output has an invalid severity score");
      const mapped = severityFrom(score, "info");
      if (mapped !== "info") return mapped;
    }
  }
  const cvss = own(vulnerability, "cvss");
  if (typeof cvss === "string") {
    const scoreMatch = cvss.match(/(?:^|\/|:)\s*(\d+(?:\.\d+)?)/);
    if (scoreMatch) return severityFrom(Number(scoreMatch[1]));
  }
  return "medium";
}

function vulnerabilityIds(vulnerability: Record<string, unknown>, group: Record<string, unknown> | undefined): string[] {
  const ids: string[] = [];
  const id = own(vulnerability, "id");
  if (typeof id === "string" && id) ids.push(id);
  for (const key of ["ids", "aliases"]) {
    const values = own(group ?? {}, key);
    if (values !== undefined) {
      if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) throw new Error(`OSV-Scanner output has an invalid ${key} field`);
      for (const value of values) if (value) ids.push(value);
    }
    const vulnerabilityValues = own(vulnerability, key);
    if (vulnerabilityValues !== undefined) {
      if (!Array.isArray(vulnerabilityValues) || vulnerabilityValues.some((value) => typeof value !== "string")) throw new Error(`OSV-Scanner output has an invalid ${key} field`);
      for (const value of vulnerabilityValues) if (value) ids.push(value);
    }
  }
  return [...new Set(ids)].slice(0, 10);
}

function fixedVersions(vulnerability: Record<string, unknown>): string[] {
  const affected = own(vulnerability, "affected");
  if (affected === undefined) return [];
  if (!Array.isArray(affected)) throw new Error("OSV-Scanner output has an invalid affected field");
  const versions: string[] = [];
  for (const affectedEntry of affected) {
    const affectedObject = requiredObject(affectedEntry, "affected", "OSV-Scanner");
    const ranges = own(affectedObject, "ranges");
    if (ranges === undefined) continue;
    if (!Array.isArray(ranges)) throw new Error("OSV-Scanner output has an invalid ranges field");
    for (const rangeEntry of ranges) {
      const range = requiredObject(rangeEntry, "range", "OSV-Scanner");
      const events = own(range, "events");
      if (events === undefined) continue;
      if (!Array.isArray(events)) throw new Error("OSV-Scanner output has an invalid events field");
      for (const eventEntry of events) {
        const event = requiredObject(eventEntry, "event", "OSV-Scanner");
        const fixed = own(event, "fixed");
        if (fixed !== undefined) {
          if (typeof fixed !== "string" || fixed.length === 0) throw new Error("OSV-Scanner output has an invalid fixed version");
          versions.push(fixed);
        }
      }
    }
  }
  return [...new Set(versions)].slice(0, 8);
}

export function parseOsvOutput(text: string, stageDir: string, files: CollectedFile[]): ParsedToolResult {
  const parsed = parseJson(text, "OSV-Scanner");
  const top = requiredObject(parsed, "root", "OSV-Scanner");
  const results = requiredArray(top, "results", "OSV-Scanner");
  if (results.length === 0) throw new Error("OSV-Scanner output has no source result records");
  const allowed = new Set(files.map((file) => file.path));
  const findings: Finding[] = [];
  let packageCount = 0;
  for (const resultEntry of results) {
    const result = requiredObject(resultEntry, "result", "OSV-Scanner");
    const source = requiredObject(own(result, "source"), "source", "OSV-Scanner");
    const sourcePath = requiredString(source, "path", "OSV-Scanner");
    const path = pathFromScanner(sourcePath, stageDir, allowed);
    const packages = requiredArray(result, "packages", "OSV-Scanner");
    if (packages.length === 0) throw new Error("OSV-Scanner output has no parsed package records");
    packageCount += packages.length;
    for (const packageEntry of packages) {
      const packageObject = requiredObject(packageEntry, "package result", "OSV-Scanner");
      const packageIdentity = requiredObject(own(packageObject, "package"), "package identity", "OSV-Scanner");
      const packageName = requiredString(packageIdentity, "name", "OSV-Scanner");
      const ecosystem = requiredString(packageIdentity, "ecosystem", "OSV-Scanner");
      const packageVersion = requiredString(packageIdentity, "version", "OSV-Scanner");
      const vulnerabilities = requiredArray(packageObject, "vulnerabilities", "OSV-Scanner");
      const groupsValue = own(packageObject, "groups");
      if (groupsValue !== undefined && !Array.isArray(groupsValue)) throw new Error("OSV-Scanner output has an invalid groups field");
      const groups = groupsValue ?? [];
      const groupById = new Map<string, Record<string, unknown>>();
      for (const groupEntry of groups) {
        const group = requiredObject(groupEntry, "group", "OSV-Scanner");
        for (const id of ["ids", "aliases"]) {
          const values = own(group, id);
          if (values === undefined) continue;
          if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) throw new Error(`OSV-Scanner output has an invalid ${id} field`);
          for (const value of values) groupById.set(value, group);
        }
      }
      for (const vulnerabilityEntry of vulnerabilities) {
        const vulnerability = requiredObject(vulnerabilityEntry, "vulnerability", "OSV-Scanner");
        const vulnerabilityId = requiredString(vulnerability, "id", "OSV-Scanner");
        const databaseSpecific = own(vulnerability, "database_specific");
        if (databaseSpecific !== undefined && !objectValue(databaseSpecific)) throw new Error("OSV-Scanner output has an invalid database_specific field");
        const severityField = own(vulnerability, "severity");
        if (severityField !== undefined && !Array.isArray(severityField)) throw new Error("OSV-Scanner output has an invalid severity field");
        const referencesField = own(vulnerability, "references");
        if (referencesField !== undefined) {
          if (!Array.isArray(referencesField)) throw new Error("OSV-Scanner output has an invalid references field");
          for (const reference of referencesField) {
            const referenceObject = requiredObject(reference, "reference", "OSV-Scanner");
            requiredString(referenceObject, "url", "OSV-Scanner");
          }
        }
        const ids = vulnerabilityIds(vulnerability, undefined);
        const primaryId = ids[0] ?? vulnerabilityId;
        const group = groupById.get(primaryId);
        const fixed = fixedVersions(vulnerability);
        const packageLabel = `${cleanText(ecosystem, "unknown", 40)}/${cleanText(packageName, "unknown", 120)}@${cleanText(packageVersion, "unknown", 80)}`;
        const safeRulePackage = `${ecosystem}:${packageName}:${packageVersion}`.replace(/[^A-Za-z0-9_.:/@-]/g, "_");
        findings.push(makeFinding({
          ruleId: `osv:${safeRulePackage}:${primaryId}`,
          title: `Dependency advisory: ${primaryId} (${packageLabel})`,
          description: `OSV-Scanner reported ${primaryId} for ${packageLabel} in the bounded lockfile snapshot.`,
          severity: vulnerabilitySeverity(vulnerability, group),
          confidence: "high",
          kind: "advisory",
          path,
          remediation: fixed.length > 0
            ? `Upgrade ${packageLabel} to a fixed version (${fixed.join(", ")}) and regenerate the lockfile.`
            : `Upgrade ${packageLabel} to a version outside the advisory range and regenerate the lockfile.`,
          references: referencesFrom(own(vulnerability, "references")),
        }));
      }
    }
  }
  return {
    findings,
    notes: [`OSV-Scanner parsed ${packageCount} package record${packageCount === 1 ? "" : "s"} and ${findings.length} advisory finding${findings.length === 1 ? "" : "s"}.`],
    metrics: { packageCount, findingCount: findings.length },
  };
}

function trivyResults(parsed: unknown): { results: unknown[]; notApplicable: boolean } {
  const top = requiredObject(parsed, "root", "Trivy");
  const schema = own(top, "SchemaVersion");
  if (schema !== 2) throw new Error("Trivy output has an unsupported SchemaVersion field");
  const resultsValue = own(top, "Results");
  if (resultsValue === undefined) {
    // Trivy 0.74 emits this envelope when config scanning found no supported
    // target. Accept it only after validating the stable identity fields, so
    // an empty or truncated object can never be normalized into a clean scan.
    requiredString(requiredObject(own(top, "Trivy"), "Trivy metadata", "Trivy"), "Version", "Trivy");
    for (const key of ["ReportID", "CreatedAt", "ArtifactName", "ArtifactType"]) requiredString(top, key, "Trivy");
    return { results: [], notApplicable: true };
  }
  if (!Array.isArray(resultsValue)) throw new Error("Trivy output has an invalid Results field");
  return { results: resultsValue, notApplicable: false };
}

export function parseTrivyOutput(text: string, stageDir: string, files: CollectedFile[]): ParsedToolResult {
  const parsed = parseJson(text, "Trivy");
  const allowed = new Set(files.map((file) => file.path));
  const findings: Finding[] = [];
  let misconfigurationCount = 0;
  const envelope = trivyResults(parsed);
  for (const resultEntry of envelope.results) {
    const result = requiredObject(resultEntry, "result", "Trivy");
    const target = requiredString(result, "Target", "Trivy");
    const path = pathFromScanner(target, stageDir, allowed);
    const entriesValue = own(result, "Misconfigurations");
    if (entriesValue !== null && !Array.isArray(entriesValue)) throw new Error("Trivy output has an invalid Misconfigurations field");
    const entries = entriesValue ?? [];
    let failedCount = 0;
    for (const entry of entries) {
      const misconfiguration = requiredObject(entry, "misconfiguration", "Trivy");
      const status = requiredString(misconfiguration, "Status", "Trivy").toUpperCase();
      if (status === "PASS") continue;
      if (status !== "FAIL") throw new Error("Trivy output has an unknown Misconfiguration status");
      failedCount += 1;
      const id = cleanRuleId(requiredString(misconfiguration, "ID", "Trivy"), "trivy.misconfiguration");
      const cause = objectValue(own(misconfiguration, "CauseMetadata"));
      if (own(misconfiguration, "CauseMetadata") !== undefined && !cause) throw new Error("Trivy output has an invalid CauseMetadata field");
      const startLine = positiveInt(own(cause ?? {}, "StartLine") ?? own(cause ?? {}, "startLine"));
      const startColumn = positiveInt(own(cause ?? {}, "StartColumn") ?? own(cause ?? {}, "startColumn"));
      const title = cleanText(requiredString(misconfiguration, "Title", "Trivy"), `Trivy misconfiguration ${id}`);
      const severityField = requiredString(misconfiguration, "Severity", "Trivy");
      const referencesField = own(misconfiguration, "References");
      if (referencesField !== undefined && !Array.isArray(referencesField)) throw new Error("Trivy output has an invalid References field");
      findings.push(makeFinding({
        ruleId: `trivy:${id}`,
        title,
        description: `Trivy identified a configuration issue using rule ${id}.`,
        severity: severityFrom(severityField, "medium"),
        confidence: "high",
        kind: "advisory",
        path,
        line: startLine,
        column: startColumn,
        remediation: "Review the configuration and apply the rule's recommended secure setting.",
        references: referencesFrom(referencesField),
      }));
    }
    misconfigurationCount += failedCount;
  }
  return {
    findings,
    notes: [
      ...(envelope.notApplicable
        ? ["Trivy found no supported configuration target in the bounded snapshot; the config check is not applicable."]
        : [`Trivy parsed ${misconfigurationCount} configuration result${misconfigurationCount === 1 ? "" : "s"}.`]),
    ],
    metrics: { misconfigurationCount, findingCount: findings.length },
    ...(envelope.notApplicable ? { status: "not_applicable" as const } : {}),
  };
}
