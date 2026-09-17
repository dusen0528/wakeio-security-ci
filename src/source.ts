import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import * as ts from "typescript";
import type { CheckResult, SourceOptions, ToolName } from "./contracts.js";
import { runBuiltinAst } from "./source/ast.js";
import { collectSource, stageSnapshot } from "./source/collector.js";
import { frameworkHasApplicableInput, maskSql, runFrameworkRules } from "./source/framework.js";
import { parseGitleaksOutput, parseOsvOutput, parseTrivyOutput } from "./source/parsers.js";
import { DEFAULT_TOOL_TIMEOUT_MS, MAX_TOOL_TIMEOUT_MS, findExecutable, runProcess } from "./source/process.js";
import { pythonFiles, runBandit } from "./source/python.js";
import type { ParsedToolResult, ProcessResult, SourceSnapshot } from "./source/types.js";

export const DEFAULT_SOURCE_TOOLS: ToolName[] = ["gitleaks", "osv", "trivy"];

const OSV_LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
  "cargo.lock",
  "go.sum",
  "gemfile.lock",
  "composer.lock",
  "pipfile.lock",
  "poetry.lock",
  "uv.lock",
  "deno.lock",
]);

const OSV_MANIFEST_NAMES = new Set([
  "package.json",
  "composer.json",
  "cargo.toml",
  "go.mod",
  "gemfile",
  "pipfile",
  "pyproject.toml",
  "requirements.txt",
  "requirements-dev.txt",
  "requirements-prod.txt",
]);

interface ToolContext {
  snapshot: SourceSnapshot;
  stageDir: string;
  timeoutMs: number;
  toolPath: string;
  osvOffline?: boolean;
  blockedConfigCount?: number;
}

const SOURCE_CODE_EXTENSIONS = /\.(?:[cm]?[jt]sx?)$/i;
const SOURCE_PYTHON_EXTENSION = /\.py$/i;
const SOURCE_SQL_EXTENSION = /\.sql$/i;
const SOURCE_LITERAL_TOKENS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.StringLiteral,
  ts.SyntaxKind.NoSubstitutionTemplateLiteral,
  ts.SyntaxKind.NumericLiteral,
  ts.SyntaxKind.BigIntLiteral,
  ts.SyntaxKind.RegularExpressionLiteral,
  ts.SyntaxKind.TemplateHead,
  ts.SyntaxKind.TemplateMiddle,
  ts.SyntaxKind.TemplateTail,
  ts.SyntaxKind.JsxText,
  ts.SyntaxKind.JsxTextAllWhiteSpaces,
]);

interface AnchorLines {
  text: string;
  lines: string[];
  starts: number[];
  ends: number[];
}

interface AnchorPrepared extends AnchorLines {
  regions: Array<{ start: number; end: number }>;
}

function splitAnchorLines(text: string): AnchorLines {
  const lines: string[] = [];
  const starts: number[] = [];
  const ends: number[] = [];
  let start = 0;
  for (let index = 0; index <= text.length; index += 1) {
    if (index < text.length && text[index] !== "\r" && text[index] !== "\n") continue;
    lines.push(text.slice(start, index));
    starts.push(start);
    ends.push(index);
    if (index >= text.length) break;
    if (text[index] === "\r" && text[index + 1] === "\n") index += 1;
    start = index + 1;
  }
  return { text, lines, starts, ends };
}

function statementRegions(lines: AnchorLines, includeBraces: boolean): Array<{ start: number; end: number }> {
  const boundaries = includeBraces ? new Set([";", "{", "}"]) : new Set([";"]);
  const regions = lines.lines.map(() => ({ start: 0, end: 0 }));
  let previous = 0;
  for (let line = 0; line < lines.lines.length; line += 1) {
    regions[line].start = previous;
    for (let index = lines.starts[line]; index < lines.ends[line]; index += 1) {
      if (boundaries.has(lines.text[index])) previous = index + 1;
    }
  }
  let next = lines.text.length;
  for (let line = lines.lines.length - 1; line >= 0; line -= 1) {
    let boundary = -1;
    for (let index = lines.ends[line] - 1; index >= lines.starts[line]; index -= 1) {
      if (boundaries.has(lines.text[index])) {
        boundary = index;
        break;
      }
    }
    regions[line].end = boundary >= 0 ? boundary + 1 : next;
    if (boundary >= 0) next = boundary;
  }
  return regions;
}

function anchorRegion(prepared: AnchorPrepared, line: number | undefined): string | undefined {
  if (!Number.isSafeInteger(line) || (line ?? 0) < 1) return undefined;
  const region = prepared.regions[(line as number) - 1];
  return region ? prepared.text.slice(region.start, region.end) : undefined;
}

function redactAnchorToken(token: string): string {
  if (/^(?:sb_(?:secret|service_role)_[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|(?:ghp|github_pat)_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,})$/i.test(token)) return "<credential>";
  if (/^\d+(?:\.\d+)?$/.test(token)) return "<literal>";
  return token;
}

function compactAnchorTokens(text: string): string {
  const tokens = text.match(/"(?:""|[^"])*"|[A-Za-z_][A-Za-z0-9_$]*|\d+(?:\.\d+)?|[^\s]/g) ?? [];
  return tokens.map(redactAnchorToken).join(" ");
}

function scriptKindForSource(path: string): ts.ScriptKind {
  if (/\.tsx$/i.test(path)) return ts.ScriptKind.TSX;
  if (/\.jsx$/i.test(path)) return ts.ScriptKind.JSX;
  if (/\.(?:ts|mts|cts)$/i.test(path)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function maskAstLiteralRanges(text: string, path: string): string {
  const sourceFile = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, scriptKindForSource(path));
  const output = text.split("");
  const blankRange = (start: number, end: number): void => {
    for (let index = Math.max(0, start); index < Math.min(output.length, end); index += 1) {
      if (output[index] !== "\n" && output[index] !== "\r") output[index] = " ";
    }
  };
  const visit = (node: ts.Node): void => {
    if (ts.isRegularExpressionLiteral(node) || ts.isJsxText(node)) blankRange(node.getStart(sourceFile), node.getEnd());
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return output.join("");
}

function maskTypeScriptComments(text: string, path: string): string {
  const output = maskAstLiteralRanges(text, path).split("");
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    false,
    /\.(?:tsx|jsx)$/i.test(path) ? ts.LanguageVariant.JSX : ts.LanguageVariant.Standard,
    output.join(""),
  );
  const blankRange = (start: number, end: number): void => {
    for (let index = Math.max(0, start); index < Math.min(output.length, end); index += 1) {
      if (output[index] !== "\n" && output[index] !== "\r") output[index] = " ";
    }
  };
  let token = scanner.scan();
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if (token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia) {
      blankRange(scanner.getTokenPos(), scanner.getTextPos());
    }
    token = scanner.scan();
  }
  return output.join("");
}

function normalizedTypeScriptAnchorLine(prepared: AnchorPrepared, path: string, line: number | undefined): string {
  const selected = anchorRegion(prepared, line);
  if (selected === undefined) return "<file>";
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    false,
    /\.(?:tsx|jsx)$/i.test(path) ? ts.LanguageVariant.JSX : ts.LanguageVariant.Standard,
    selected,
  );
  const tokens: string[] = [];
  let token = scanner.scan();
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if (token !== ts.SyntaxKind.WhitespaceTrivia
      && token !== ts.SyntaxKind.NewLineTrivia
      && token !== ts.SyntaxKind.SingleLineCommentTrivia
      && token !== ts.SyntaxKind.MultiLineCommentTrivia
      && token !== ts.SyntaxKind.ConflictMarkerTrivia) {
      tokens.push(SOURCE_LITERAL_TOKENS.has(token) ? "<literal>" : redactAnchorToken(scanner.getTokenText()));
    }
    token = scanner.scan();
  }
  return tokens.join(" ") || "<line>";
}

function maskPythonLiterals(text: string): string {
  const output = text.split("");
  let state: "normal" | "comment" | "single" | "double" | "triple-single" | "triple-double" = "normal";
  let index = 0;
  const blank = (at: number): void => {
    if (output[at] !== "\n" && output[at] !== "\r") output[at] = " ";
  };
  while (index < text.length) {
    const character = text[index];
    if (state === "comment") {
      if (character === "\n" || character === "\r") state = "normal";
      else blank(index);
      index += 1;
      continue;
    }
    if (state === "single" || state === "double") {
      blank(index);
      if (character === "\\" && index + 1 < text.length) {
        blank(index + 1);
        index += 2;
      } else if ((state === "single" && character === "'") || (state === "double" && character === '"')) {
        state = "normal";
        index += 1;
      } else {
        index += 1;
      }
      continue;
    }
    if (state === "triple-single" || state === "triple-double") {
      const delimiter = state === "triple-single" ? "'''" : '\"\"\"';
      if (text.startsWith(delimiter, index)) {
        for (let offset = 0; offset < delimiter.length; offset += 1) blank(index + offset);
        index += delimiter.length;
        state = "normal";
      } else {
        blank(index);
        index += 1;
      }
      continue;
    }
    if (character === "#") {
      blank(index);
      state = "comment";
      index += 1;
    } else if (text.startsWith("'''", index)) {
      for (let offset = 0; offset < 3; offset += 1) blank(index + offset);
      state = "triple-single";
      index += 3;
    } else if (text.startsWith('\"\"\"', index)) {
      for (let offset = 0; offset < 3; offset += 1) blank(index + offset);
      state = "triple-double";
      index += 3;
    } else if (character === "'") {
      blank(index);
      state = "single";
      index += 1;
    } else if (character === '"') {
      blank(index);
      state = "double";
      index += 1;
    } else {
      index += 1;
    }
  }
  return output.join("");
}

function normalizedPythonAnchorLine(prepared: AnchorPrepared, line: number | undefined): string {
  if (!Number.isSafeInteger(line) || (line ?? 0) < 1) return "<file>";
  const selected = prepared.lines[(line as number) - 1];
  return compactAnchorTokens(selected ?? "<file>") || "<line>";
}

function normalizedSqlAnchorLine(prepared: AnchorPrepared, line: number | undefined): string {
  return compactAnchorTokens(anchorRegion(prepared, line) ?? "<file>") || "<line>";
}

function maskSqlForAnchor(text: string): string {
  // Use the private identity view so a quoted table name remains semantic,
  // while comments and string/dollar bodies are still excluded.
  return maskSql(text).identifierText;
}

function prepareAnchor(file: SourceSnapshot["files"][number]): AnchorPrepared {
  if (file.sensitive) return { ...splitAnchorLines(""), regions: [] };
  if (SOURCE_SQL_EXTENSION.test(file.path)) {
    const lines = splitAnchorLines(maskSqlForAnchor(file.text));
    return { ...lines, regions: statementRegions(lines, false) };
  }
  if (SOURCE_PYTHON_EXTENSION.test(file.path)) {
    return { ...splitAnchorLines(maskPythonLiterals(file.text)), regions: [] };
  }
  if (SOURCE_CODE_EXTENSIONS.test(file.path)) {
    const lines = splitAnchorLines(maskTypeScriptComments(file.text, file.path));
    return { ...lines, regions: statementRegions(lines, true) };
  }
  return { ...splitAnchorLines(""), regions: [] };
}

function normalizedSemanticAnchor(file: SourceSnapshot["files"][number], prepared: AnchorPrepared, line: number | undefined): string {
  if (file.sensitive) return "<sensitive-file>";
  if (SOURCE_SQL_EXTENSION.test(file.path)) return normalizedSqlAnchorLine(prepared, line);
  if (SOURCE_PYTHON_EXTENSION.test(file.path)) return normalizedPythonAnchorLine(prepared, line);
  if (SOURCE_CODE_EXTENSIONS.test(file.path)) return normalizedTypeScriptAnchorLine(prepared, file.path, line);
  // Configuration, documentation, and other text files can contain
  // unquoted credentials or arbitrary scanner code. Their path/rule anchor
  // remains useful without retaining any source token in the hash input.
  return line === undefined ? "<file>" : "<static-line>";
}

function sourceComparisonKey(
  checkId: string,
  finding: CheckResult["findings"][number],
  files: Map<string, SourceSnapshot["files"][number]>,
  preparedFiles: Map<string, AnchorPrepared>,
  semanticCache: Map<string, string>,
): string | undefined {
  const path = finding.location.path?.replaceAll("\\", "/");
  if (!path) return undefined;
  const file = files.get(path);
  if (!file) return undefined;
  let prepared = preparedFiles.get(path);
  if (!prepared) {
    // Prepare each selected file once. In particular, TypeScript parsing and
    // SQL/Python masking must not repeat for every finding line in a large
    // file.
    prepared = prepareAnchor(file);
    preparedFiles.set(path, prepared);
  }
  const cacheKey = `${path}\u0000${finding.location.line ?? ""}`;
  let semantic = semanticCache.get(cacheKey);
  if (semantic === undefined) {
    semantic = normalizedSemanticAnchor(file, prepared, finding.location.line);
    semanticCache.set(cacheKey, semantic);
  }
  return createHash("sha256")
    .update(["source.v1", checkId, finding.ruleId, path, semantic].join("\u0000"), "utf8")
    .digest("hex");
}

function addSourceComparisonKeys(checks: CheckResult[], snapshot: SourceSnapshot): CheckResult[] {
  const files = new Map(snapshot.files.map((file) => [file.path, file]));
  const preparedFiles = new Map<string, AnchorPrepared>();
  const semanticCache = new Map<string, string>();
  return checks.map((check) => ({
    ...check,
    findings: check.findings.map((finding) => {
      const comparisonKey = sourceComparisonKey(check.id, finding, files, preparedFiles, semanticCache);
      return comparisonKey ? { ...finding, comparisonKey } : finding;
    }),
  }));
}

function normalizeTimeout(value: number | undefined): number {
  if (!Number.isSafeInteger(value) || (value ?? 0) <= 0) return DEFAULT_TOOL_TIMEOUT_MS;
  return Math.min(value!, MAX_TOOL_TIMEOUT_MS);
}

function isToolName(value: unknown): value is ToolName {
  return value === "gitleaks" || value === "osv" || value === "trivy" || value === "bandit";
}

function requestedTools(options: SourceOptions): ToolName[] {
  // An omitted tools value means the secure default. An explicit empty array
  // is the CLI's `--tools none` scope reduction; built-in AST checks still run.
  if (!Array.isArray(options.tools)) return [...DEFAULT_SOURCE_TOOLS];
  return [...new Set(options.tools.filter(isToolName))];
}

function checkStatusForSnapshot(snapshot: SourceSnapshot): CheckResult["status"] {
  if (snapshot.rootError) return "error";
  return snapshot.complete ? "completed" : "partial";
}

function inventoryCheck(snapshot: SourceSnapshot, tools: ToolName[]): CheckResult {
  const issueCounts = new Map<string, number>();
  for (const entry of snapshot.issues) issueCounts.set(entry.code, (issueCounts.get(entry.code) ?? 0) + 1);
  const issueSummary = [...issueCounts.entries()].map(([code, count]) => `${code}:${count}`).join(", ");
  const notes = [
    `Collected ${snapshot.files.length} allowlisted file${snapshot.files.length === 1 ? "" : "s"} (${snapshot.totalBytes} bytes).`,
    ...(snapshot.ignoredFiles > 0 ? [`Ignored ${snapshot.ignoredFiles} path${snapshot.ignoredFiles === 1 ? "" : "s"} outside the static-analysis allowlist.`] : []),
    ...(issueSummary ? [`Collection coverage issues: ${issueSummary}.`] : []),
    ...(tools.length === 0 ? ["External scanner scope was narrowed to built-in checks (--tools none)."] : [`External scanner scope: ${tools.join(", ")}.`]),
    ...(snapshot.rootError ? [snapshot.rootError] : []),
  ];
  return {
    id: "source.inventory",
    status: checkStatusForSnapshot(snapshot),
    findings: [],
    notes,
    metrics: {
      filesSelected: snapshot.files.length,
      bytesSelected: snapshot.totalBytes,
      ignoredFiles: snapshot.ignoredFiles,
      issueCount: snapshot.issues.length,
      complete: snapshot.complete,
    },
  };
}

function errorCheck(id: string, message: string, metrics?: Record<string, number | string | boolean>): CheckResult {
  return { id, status: "error", findings: [], notes: [message], ...(metrics ? { metrics } : {}) };
}

function partialCheck(id: string, message: string, metrics?: Record<string, number | string | boolean>): CheckResult {
  return { id, status: "partial", findings: [], notes: [message], ...(metrics ? { metrics } : {}) };
}

function notApplicableCheck(id: string, message: string, metrics?: Record<string, number | string | boolean>): CheckResult {
  return { id, status: "not_applicable", findings: [], notes: [message], ...(metrics ? { metrics } : {}) };
}

function processFailure(result: ProcessResult, tool: string, timeoutMs: number): string | undefined {
  if (result.spawnError) return `${tool} could not be started.`;
  if (result.timedOut) return `${tool} exceeded the ${timeoutMs} ms scanner timeout.`;
  if (result.outputLimitExceeded) return `${tool} exceeded the scanner output limit.`;
  if (result.exitCode !== null && result.exitCode > 1) return `${tool} exited with code ${result.exitCode}.`;
  if (result.signal) return `${tool} was terminated by ${result.signal}.`;
  return undefined;
}

function ensureParsedResult(id: string, parsed: ParsedToolResult): CheckResult {
  return {
    id,
    status: parsed.status ?? "completed",
    findings: parsed.findings,
    notes: parsed.notes,
    ...(parsed.metrics ? { metrics: parsed.metrics } : {}),
  };
}

function trivyInputCandidate(path: string, text: string): boolean {
  const lower = path.toLowerCase();
  const name = lower.slice(lower.lastIndexOf("/") + 1);
  if (name === "dockerfile" || name.endsWith(".dockerfile")) return true;
  if (/\.(?:yaml|yml)$/.test(lower)) return true;
  if (/\.(?:tf|tfvars|hcl)(?:\.json)?$/.test(lower)) return true;
  // Kubernetes manifests are also commonly stored as JSON. Generic JSON
  // (package metadata, tsconfig, editor settings) is excluded so it cannot
  // make Trivy appear applicable to an ordinary source project.
  if (!lower.endsWith(".json")) return false;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const object = parsed as Record<string, unknown>;
    return typeof object.apiVersion === "string" && typeof object.kind === "string";
  } catch {
    return false;
  }
}

function fileBasename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1).toLowerCase();
}

function packageManifestHasExplicitlyEmptyDependencies(text: string): boolean {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const object = parsed as Record<string, unknown>;
    const fields = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundledDependencies", "bundleDependencies"];
    if (!fields.some((key) => Object.prototype.hasOwnProperty.call(object, key))) return false;
    for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundledDependencies", "bundleDependencies", "require", "require-dev"]) {
      const value = object[key];
      if (Array.isArray(value) && value.length > 0) return false;
      if (value !== undefined && (value === null || typeof value !== "object" || Object.keys(value as object).length > 0)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function dependencyManifestNeedsLockfile(file: SourceSnapshot["files"][number]): boolean {
  const name = fileBasename(file.path);
  // A known dependency manifest is an expected-input signal even when its
  // syntax is too rich for this bounded adapter to interpret. An explicit
  // empty package dependency map is the one safe exception.
  return name !== "package.json" || !packageManifestHasExplicitlyEmptyDependencies(file.text);
}

interface RequirementsInspection {
  pinned: boolean;
  packageCount: number;
}

function inspectRequirementsFile(text: string): RequirementsInspection {
  let packageCount = 0;
  let unresolved = false;
  for (const rawLine of text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    // Includes and constraints require resolver context outside this bounded
    // snapshot. Passing them to OSV as if they were a lock would be a clean
    // result with unknown package coverage, so retain them as partial input.
    if (/^(?:-r|--requirement|-c|--constraint)(?:\s+|=)/i.test(line)) {
      unresolved = true;
      continue;
    }
    // A small set of pip options does not declare a package. Other options
    // (and editable/VCS/URL requirements) are deliberately unresolved.
    if (/^--(?:hash(?:=|\s)|require-hashes(?:=|\s|$)|index-url(?:=|\s)|extra-index-url(?:=|\s)|trusted-host(?:=|\s)|find-links(?:=|\s)|no-index(?:=|\s|$)|only-binary(?:=|\s)|no-binary(?:=|\s)|prefer-binary(?:=|\s)|pre(?:=|\s|$))/i.test(line)) continue;
    if (/^(?:-|git\+|hg\+|svn\+|bzr\+|https?:|file:|ssh:|\.?\.?\/|[A-Za-z0-9_.-]+\s*@\s*)/i.test(line)) {
      unresolved = true;
      continue;
    }
    // Keep markers and hash options out of the version check. A requirement
    // is lock-like only when its package specifier contains exactly ==.
    const withoutHash = line.split(/\s+--hash(?:=|\s+)/i, 1)[0].trim();
    const spec = withoutHash.split(";", 1)[0].trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]\r\n]+\])?\s*==\s*([^\s,;#=]+)$/i.exec(spec);
    if (!match || (spec.match(/==/g)?.length ?? 0) !== 1 || /(?:[<>~!]=?|\*|,)/.test(spec.replace(/==/g, ""))) {
      unresolved = true;
      continue;
    }
    packageCount += 1;
  }
  return { pinned: !unresolved && packageCount > 0, packageCount };
}

function requirementsInspection(snapshot: SourceSnapshot): { pinned: string[]; unresolved: string[] } {
  const pinned: string[] = [];
  const unresolved: string[] = [];
  for (const file of snapshot.files) {
    if (file.category !== "dependency" || !/^requirements(?:-[^/]+)?\.txt$/i.test(fileBasename(file.path))) continue;
    if (inspectRequirementsFile(file.text).pinned) pinned.push(file.path);
    else unresolved.push(file.path);
  }
  return { pinned, unresolved };
}

function osvLockfiles(snapshot: SourceSnapshot): string[] {
  const requirements = new Set(requirementsInspection(snapshot).pinned);
  return snapshot.files
    .filter((file) => file.category === "dependency"
      && (OSV_LOCKFILE_NAMES.has(fileBasename(file.path)) || requirements.has(file.path)))
    .map((file) => file.path);
}

function osvManifestDeclaresDependencies(snapshot: SourceSnapshot): boolean {
  return snapshot.files.some((file) => file.category === "dependency"
    && OSV_MANIFEST_NAMES.has(fileBasename(file.path))
    && dependencyManifestNeedsLockfile(file));
}

function osvHasApplicableInput(snapshot: SourceSnapshot): boolean {
  return osvLockfiles(snapshot).length > 0 || osvManifestDeclaresDependencies(snapshot);
}

function trivyHasApplicableInput(snapshot: SourceSnapshot): boolean {
  return snapshot.files.some((file) => file.category === "config" && trivyInputCandidate(file.path, file.text));
}

function hasOtherSecurityCheck(snapshot: SourceSnapshot, tools: ToolName[]): boolean {
  return tools.some((tool) => {
    if (tool === "gitleaks") return snapshot.files.length > 0;
    if (tool === "osv") return osvHasApplicableInput(snapshot);
    if (tool === "trivy") return trivyHasApplicableInput(snapshot);
    return pythonFiles(snapshot).length > 0;
  }) || frameworkHasApplicableInput(snapshot);
}

function pathForTool(snapshot: SourceSnapshot, tool: ToolName): string[] {
  if (tool === "osv") {
    return osvLockfiles(snapshot);
  }
  if (tool === "trivy") return snapshot.files.filter((file) => file.category === "config" && trivyInputCandidate(file.path, file.text) && isTrivyConfigSafe(file.path, file.text)).map((file) => file.path);
  return snapshot.files.map((file) => file.path);
}

function isTrivyConfigSafe(path: string, text: string): boolean {
  const lower = path.toLowerCase();
  if (!/\.(?:tf|tfvars|hcl)(?:\.json)?$/.test(lower)) return true;
  let inspected = text;
  if (lower.endsWith(".tf.json")) {
    try {
      inspected = JSON.stringify(JSON.parse(text)) as string;
    } catch {
      return false;
    }
  }
  // Trivy/Terraform can download modules or evaluate file functions. Keep
  // those files out of the Trivy staging root unless they contain neither
  // capability. They remain available to Gitleaks and the inventory notes.
  if (/\bmodule\b/i.test(inspected)) return false;
  if (/\b(?:file[A-Za-z0-9_]*|templatefile)\s*(?:\/\*[\s\S]*?\*\/\s*)*\(/i.test(inspected)) return false;
  return true;
}

async function neutralOsvConfig(stageDir: string): Promise<string> {
  const path = join(dirname(stageDir), "osv-empty.toml");
  await writeFile(path, "", { encoding: "utf8", mode: 0o600, flag: "wx" });
  return path;
}

async function neutralTrivyConfig(stageDir: string): Promise<string> {
  const path = join(dirname(stageDir), "trivy-empty.yaml");
  await writeFile(path, "{}\n", { encoding: "utf8", mode: 0o600, flag: "wx" });
  return path;
}

async function runGitleaks(context: ToolContext): Promise<CheckResult> {
  const result = await runProcess(context.toolPath, [
    "dir",
    "--no-banner",
    "--no-color",
    "--redact=100",
    "--ignore-gitleaks-allow",
    "--report-format",
    "json",
    "--report-path",
    "-",
    "--exit-code",
    "1",
    "--max-archive-depth",
    "0",
    "--max-decode-depth",
    "0",
    context.stageDir,
  ], { cwd: context.stageDir, timeoutMs: context.timeoutMs, home: join(dirname(context.stageDir), "home") });
  const failure = processFailure(result, "Gitleaks", context.timeoutMs);
  if (failure) return errorCheck("source.gitleaks", failure);
  try {
    const parsed = parseGitleaksOutput(result.stdout, context.stageDir, context.snapshot.files);
    if (result.exitCode === 1 && parsed.findings.length === 0) return errorCheck("source.gitleaks", "Gitleaks exited with a finding status but returned an empty report.");
    return ensureParsedResult("source.gitleaks", parsed);
  } catch {
    return errorCheck("source.gitleaks", "Gitleaks returned an invalid or incomplete JSON report.");
  }
}

async function runOsv(context: ToolContext): Promise<CheckResult> {
  const lockfiles = pathForTool(context.snapshot, "osv");
  const requirements = requirementsInspection(context.snapshot);
  if (lockfiles.length === 0) {
    return osvManifestDeclaresDependencies(context.snapshot)
      ? partialCheck("source.osv", requirements.unresolved.length > 0
        ? "Python requirements input contains an unresolved range, URL, option, or include; OSV coverage is partial until a pinned lockfile is supplied."
        : "A dependency manifest declares packages, but no supported lockfile was available for OSV-Scanner.", { lockfiles: 0, dependencyManifest: true, unresolvedRequirements: requirements.unresolved.length })
      : notApplicableCheck("source.osv", "No allowlisted dependency manifest or supported lockfile was available for OSV-Scanner.", { lockfiles: 0, dependencyManifest: false });
  }
  const preparedDb = context.osvOffline ? process.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY : undefined;
  if (context.osvOffline && (!preparedDb || !preparedDb.startsWith("/"))) {
    return errorCheck("source.osv", "OSV offline mode requires an absolute prepared database directory in OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY.");
  }
  let configPath: string;
  try {
    configPath = await neutralOsvConfig(context.stageDir);
  } catch {
    return errorCheck("source.osv", "OSV-Scanner neutral configuration could not be created.");
  }
  const args = [
    "scan",
    "source",
    "--no-resolve",
    "--no-call-analysis=all",
    "--format=json",
    "--all-packages",
    "--config",
    configPath,
    ...lockfiles.flatMap((path) => ["--lockfile", join(context.stageDir, ...path.split("/"))]),
  ];
  // Online vulnerability lookup is the default. Offline mode deliberately
  // does not download a database; a scanner without a prepared local DB must
  // fail rather than silently reporting a clean result.
  if (context.osvOffline) args.push("--offline", "--offline-vulnerabilities");
  const result = await runProcess(context.toolPath, args, {
    cwd: context.stageDir,
    timeoutMs: context.timeoutMs,
    home: join(dirname(context.stageDir), "home"),
    ...(preparedDb ? { environment: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: preparedDb } } : {}),
  });
  const failure = processFailure(result, "OSV-Scanner", context.timeoutMs);
  if (failure) return errorCheck("source.osv", failure);
  try {
    const parsed = parseOsvOutput(result.stdout, context.stageDir, context.snapshot.files);
    const packageCount = typeof parsed.metrics?.packageCount === "number" ? parsed.metrics.packageCount : 0;
    if (packageCount === 0) return partialCheck("source.osv", "OSV-Scanner returned no parsed package records for the selected lockfile(s); coverage is incomplete.", { ...(parsed.metrics ?? {}), packageCount });
    if (result.exitCode === 1 && parsed.findings.length === 0) return errorCheck("source.osv", "OSV-Scanner exited with a finding status but returned an empty report.");
    const check = ensureParsedResult("source.osv", parsed);
    if (requirements.unresolved.length > 0) {
      check.status = "partial";
      check.notes = [...check.notes, "At least one requirements file was excluded because it was not a fully pinned, self-contained input; only pinned requirements files were passed to OSV-Scanner."];
      check.metrics = { ...(check.metrics ?? {}), unresolvedRequirements: requirements.unresolved.length };
    }
    return check;
  } catch {
    return errorCheck("source.osv", "OSV-Scanner returned an invalid or incomplete JSON report.");
  }
}

async function runTrivy(context: ToolContext): Promise<CheckResult> {
  const configs = pathForTool(context.snapshot, "trivy");
  if (configs.length === 0) {
    return context.blockedConfigCount
      ? partialCheck("source.trivy", "Terraform configuration requiring module or external file resolution was excluded from Trivy to prevent network or filesystem egress.", { configFiles: 0, blockedConfigFiles: context.blockedConfigCount })
      : notApplicableCheck("source.trivy", "No supported Dockerfile, Kubernetes manifest, or Terraform configuration was available for Trivy config scanning.", { configFiles: 0, blockedConfigFiles: 0 });
  }
  let configPath: string;
  try {
    configPath = await neutralTrivyConfig(context.stageDir);
  } catch {
    return errorCheck("source.trivy", "Trivy neutral configuration could not be created.");
  }
  const privateCache = join(dirname(context.stageDir), "trivy-cache");
  const privateModules = join(dirname(context.stageDir), "trivy-modules");
  try {
    await mkdir(privateCache, { recursive: true, mode: 0o700 });
    await mkdir(privateModules, { recursive: true, mode: 0o700 });
  } catch {
    return errorCheck("source.trivy", "Trivy private cache directories could not be created.");
  }
  const result = await runProcess(context.toolPath, [
    "config",
    "--quiet",
    "--disable-telemetry",
    "--skip-version-check",
    "--format",
    "json",
    "--exit-code",
    "1",
    "--include-non-failures",
    "--misconfig-scanners",
    "dockerfile,kubernetes,terraform",
    "--config",
    configPath,
    "--cache-dir",
    privateCache,
    "--module-dir",
    privateModules,
    context.stageDir,
  ], { cwd: context.stageDir, timeoutMs: context.timeoutMs, home: join(dirname(context.stageDir), "home") });
  const failure = processFailure(result, "Trivy", context.timeoutMs);
  if (failure) return errorCheck("source.trivy", failure);
  try {
    const parsed = ensureParsedResult("source.trivy", parseTrivyOutput(result.stdout, context.stageDir, context.snapshot.files));
    if (result.exitCode === 1 && parsed.findings.length === 0) return errorCheck("source.trivy", "Trivy exited with a finding status but returned an empty report.");
    if (context.blockedConfigCount) {
      parsed.status = "partial";
      parsed.notes = [...parsed.notes, `${context.blockedConfigCount} Terraform configuration file${context.blockedConfigCount === 1 ? " was" : "s were"} excluded because its module/file references were not provably local.`];
      parsed.metrics = { ...(parsed.metrics ?? {}), blockedConfigFiles: context.blockedConfigCount };
    }
    return parsed;
  } catch {
    return errorCheck("source.trivy", "Trivy returned an invalid or incomplete JSON report.");
  }
}

async function runTool(tool: ToolName, snapshot: SourceSnapshot, stageDir: string, options: SourceOptions, timeoutMs: number, blockedConfigCount = 0): Promise<CheckResult> {
  // Do this applicability check before resolving the executable. A project
  // without IaC should not fail merely because Trivy is not installed.
  if (tool === "trivy" && pathForTool(snapshot, "trivy").length === 0) {
    return runTrivy({ snapshot, stageDir, timeoutMs, toolPath: "", blockedConfigCount });
  }
  // Dependency scanning has the same distinction: an unrelated source tree
  // should not fail merely because OSV-Scanner is not installed. A manifest
  // with declared packages still proceeds to the executable check so that
  // its missing lockfile remains an incomplete security check.
  if (tool === "osv" && !osvHasApplicableInput(snapshot)) {
    return runOsv({ snapshot, stageDir, timeoutMs, toolPath: "" });
  }
  // Bandit is optional and only applies to collected Python files. Resolve
  // its executable after this check so a non-Python project stays explicitly
  // not_applicable even when no Bandit installation is present.
  if (tool === "bandit" && pythonFiles(snapshot).length === 0) {
    return runBandit({ snapshot, stageDir, timeoutMs, toolPath: "" });
  }
  const configuredPath = options.toolPaths?.[tool];
  const executable = await findExecutable(configuredPath ?? (tool === "osv" ? "osv-scanner" : tool));
  if (!executable) return partialCheck(`source.${tool}`, `${tool} executable was not found; this scanner's coverage is unavailable.`);
  if (tool === "gitleaks") return runGitleaks({ snapshot, stageDir, timeoutMs, toolPath: executable });
  if (tool === "osv") return runOsv({ snapshot, stageDir, timeoutMs, toolPath: executable, ...(options.osvOffline ? { osvOffline: true } : {}) });
  if (tool === "bandit") return runBandit({ snapshot, stageDir, timeoutMs, toolPath: executable });
  return runTrivy({ snapshot, stageDir, timeoutMs, toolPath: executable, blockedConfigCount });
}

/** Runs bounded built-in and selected native source scanners. */
export async function runSource(options: SourceOptions): Promise<CheckResult[]> {
  if (!options || typeof options.root !== "string" || options.root.trim().length === 0) {
    return [errorCheck("source.inventory", "A source directory is required.")];
  }
  const tools = requestedTools(options);
  const timeoutMs = normalizeTimeout(options.timeoutMs);
  let snapshot: SourceSnapshot;
  try {
    snapshot = await collectSource(options);
  } catch {
    return [errorCheck("source.inventory", "The source snapshot could not be collected.")];
  }
  const checks: CheckResult[] = [
    inventoryCheck(snapshot, tools),
    runBuiltinAst(snapshot, hasOtherSecurityCheck(snapshot, tools)),
    runFrameworkRules(snapshot),
  ];
  if (tools.length === 0 || snapshot.files.length === 0 || snapshot.rootError) {
    if (snapshot.files.length === 0 && !snapshot.rootError) {
      checks.push(...tools.map((tool) => {
        if (tool === "trivy") return notApplicableCheck("source.trivy", "No supported Dockerfile, Kubernetes manifest, or Terraform configuration was available for Trivy config scanning.", { configFiles: 0, blockedConfigFiles: 0 });
        if (tool === "osv") return notApplicableCheck("source.osv", "No allowlisted dependency manifest or supported lockfile was available for OSV-Scanner.", { lockfiles: 0, dependencyManifest: false });
        if (tool === "bandit") return notApplicableCheck("source.bandit", "No allowlisted Python file was available for Bandit.", { files: 0 });
        return notApplicableCheck("source.gitleaks", "No allowlisted source file was available for Gitleaks.", { files: 0 });
      }));
      if (tools.length > 0 && checks.filter((check) => check.id !== "source.inventory").every((check) => check.status === "not_applicable")) {
        checks.push(partialCheck("source.coverage", "No applicable security check could run for this source snapshot; coverage is incomplete."));
      }
    }
    if (snapshot.rootError) checks.push(...tools.map((tool) => errorCheck(`source.${tool}`, `The source root could not be scanned by ${tool}.`)));
    return addSourceComparisonKeys(checks, snapshot);
  }
  let staged: Awaited<ReturnType<typeof stageSnapshot>>;
  try {
    staged = await stageSnapshot(snapshot);
    await mkdir(join(dirname(staged.dir), "home"), { recursive: true, mode: 0o700 });
  } catch {
    checks.push(...tools.map((tool) => errorCheck(`source.${tool}`, `The bounded snapshot could not be staged for ${tool}.`)));
    return addSourceComparisonKeys(checks, snapshot);
  }
  let trivyStaged: Awaited<ReturnType<typeof stageSnapshot>> | undefined;
  let trivySnapshot: SourceSnapshot | undefined;
  let blockedConfigCount = 0;
  if (tools.includes("trivy")) {
    const trivyCandidates = snapshot.files.filter((file) => file.category === "config" && trivyInputCandidate(file.path, file.text));
    const trivyFiles = trivyCandidates.filter((file) => isTrivyConfigSafe(file.path, file.text));
    blockedConfigCount = trivyCandidates.filter((file) => !isTrivyConfigSafe(file.path, file.text)).length;
    trivySnapshot = { ...snapshot, files: trivyFiles };
    if (trivyFiles.length > 0) {
      try {
        trivyStaged = await stageSnapshot(trivySnapshot);
        await mkdir(join(dirname(trivyStaged.dir), "home"), { recursive: true, mode: 0o700 });
      } catch {
        trivyStaged = undefined;
      }
    }
  }
  let banditStaged: Awaited<ReturnType<typeof stageSnapshot>> | undefined;
  let banditSnapshot: SourceSnapshot | undefined;
  if (tools.includes("bandit")) {
    const banditFiles = pythonFiles(snapshot);
    banditSnapshot = { ...snapshot, files: banditFiles };
    if (banditFiles.length > 0) {
      try {
        banditStaged = await stageSnapshot(banditSnapshot);
        await mkdir(join(dirname(banditStaged.dir), "home"), { recursive: true, mode: 0o700 });
      } catch {
        banditStaged = undefined;
      }
    }
  }
  try {
    const external = await Promise.all(tools.map(async (tool) => {
      if (tool === "trivy" && trivySnapshot) {
        if (trivySnapshot.files.length > 0 && !trivyStaged) {
          return errorCheck("source.trivy", "The bounded Trivy snapshot could not be staged for Trivy.");
        }
        try {
          return await runTool(tool, trivySnapshot, trivyStaged?.dir ?? staged.dir, options, timeoutMs, blockedConfigCount);
        } catch {
          return errorCheck("source.trivy", "Trivy scanning could not be completed.");
        }
      }
      if (tool === "bandit" && banditSnapshot) {
        if (banditSnapshot.files.length > 0 && !banditStaged) {
          return errorCheck("source.bandit", "The bounded Python snapshot could not be staged for Bandit.");
        }
        try {
          return await runTool(tool, banditSnapshot, banditStaged?.dir ?? staged.dir, options, timeoutMs);
        } catch {
          return errorCheck("source.bandit", "Bandit scanning could not be completed.");
        }
      }
      try {
        return await runTool(tool, snapshot, staged.dir, options, timeoutMs);
      } catch {
        return errorCheck(`source.${tool}`, `${tool} scanning could not be completed.`);
      }
    }));
    checks.push(...external);
    if (checks.filter((check) => check.id !== "source.inventory").length > 0
      && checks.filter((check) => check.id !== "source.inventory").every((check) => check.status === "not_applicable")) {
      checks.push(partialCheck("source.coverage", "No applicable security check could run for this source snapshot; coverage is incomplete."));
    }
  } finally {
    try { await banditStaged?.cleanup(); } catch { /* best effort cleanup */ }
    try { await trivyStaged?.cleanup(); } catch { /* best effort cleanup */ }
    try { await staged.cleanup(); } catch { /* best effort cleanup */ }
  }
  return addSourceComparisonKeys(checks, snapshot);
}
