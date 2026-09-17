import * as ts from "typescript";
import { posix } from "node:path";
import type { CheckResult, Finding } from "../contracts.js";
import type { CollectedFile, SourceSnapshot } from "./types.js";

const FRONTEND_EXTENSIONS = /\.(?:[cm]?[jt]sx?)$/i;
const MIGRATION_PATH = /(?:^|\/)supabase\/migrations\/(?:[^/]+\/)*[^/]+\.sql$/i;

interface MaskedSql {
  text: string;
  /** Comments/literals are masked while quoted identifiers remain available
   * for table identity matching. This view is never emitted in findings. */
  identifierText: string;
  complete: boolean;
}

interface FrontendAnalysis {
  file: CollectedFile;
  sourceFile: ts.SourceFile;
  parseError: boolean;
  useClient: boolean;
  useServer: boolean;
  publicSecretDeclarations: ts.VariableDeclaration[];
  serverSecretLiterals: ts.StringLiteralLike[];
  reactImport: boolean;
  nextConfig: boolean;
  envReferences: ts.Node[];
  relativeImports: string[];
  envConfigDeclarations: ts.PropertyAssignment[];
}

function isMigration(file: CollectedFile): boolean {
  return file.category === "text" && MIGRATION_PATH.test(file.path.replaceAll("\\", "/"));
}

function isNextConfigPath(path: string): boolean {
  return /(?:^|\/)next\.config\.(?:[cm]?[jt]s)$/i.test(path.replaceAll("\\", "/"));
}

function scriptKind(path: string): ts.ScriptKind {
  if (/\.tsx$/i.test(path)) return ts.ScriptKind.TSX;
  if (/\.jsx$/i.test(path)) return ts.ScriptKind.JSX;
  if (/\.(?:ts|mts|cts)$/i.test(path)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function parseError(sourceFile: ts.SourceFile): boolean {
  const diagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics;
  return Array.isArray(diagnostics) && diagnostics.length > 0;
}

function hasUseClientDirective(sourceFile: ts.SourceFile): boolean {
  const first = sourceFile.statements[0];
  return !!first
    && ts.isExpressionStatement(first)
    && ts.isStringLiteral(first.expression)
    && first.expression.text === "use client";
}

function hasUseServerDirective(sourceFile: ts.SourceFile): boolean {
  const first = sourceFile.statements[0];
  return !!first
    && ts.isExpressionStatement(first)
    && ts.isStringLiteral(first.expression)
    && first.expression.text === "use server";
}

function isSecretPublicName(name: string): boolean {
  if (!/^NEXT_PUBLIC_[A-Z0-9_]+$/i.test(name)) return false;
  // Supabase anon/publishable keys are intentionally public client keys. The
  // marker set below is limited to names that conventionally identify a
  // server credential or another secret-bearing value.
  return /(?:SECRET|SERVICE[_-]?ROLE|PRIVATE[_-]?KEY|PASSWORD|TOKEN|CREDENTIAL|API[_-]?KEY|ACCESS[_-]?KEY|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY)/i.test(name);
}

function isPublicKeyName(name: string): boolean {
  return /^NEXT_PUBLIC_(?:[A-Z0-9]+_)*(?:ANON|PUBLISHABLE)(?:_[A-Z0-9]+)*$/i.test(name);
}

function jwtPayloadRole(value: string): string | undefined {
  const parts = value.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as unknown;
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return undefined;
    const role = (payload as Record<string, unknown>).role;
    return typeof role === "string" ? role : undefined;
  } catch {
    return undefined;
  }
}

function jwtPayloadHasServiceRole(value: string): boolean {
  return jwtPayloadRole(value) === "service_role";
}

function isActualServerSecretLiteral(value: string): boolean {
  return /(?:^|[^A-Za-z0-9_])sb_secret_[A-Za-z0-9_-]{8,}(?:$|[^A-Za-z0-9_-])/i.test(value)
    || jwtPayloadHasServiceRole(value);
}

function isPublicSupabaseKeyLiteral(value: string): boolean {
  return /^sb_(?:anon|publishable)_[A-Za-z0-9_-]{4,}$/i.test(value)
    || jwtPayloadRole(value) === "anon";
}

function initializerHasActualServerSecret(initializer: ts.Expression): boolean {
  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) return;
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && isActualServerSecretLiteral(node.text)) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(initializer);
  return found;
}

function initializerHasPublicSupabaseKey(initializer: ts.Expression): boolean {
  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) return;
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && isPublicSupabaseKeyLiteral(node.text)) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(initializer);
  return found;
}

function staticEnvName(node: ts.Node): string | undefined {
  if (!ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node)) return undefined;
  const property = ts.isPropertyAccessExpression(node) ? node.name.text : (ts.isStringLiteral(node.argumentExpression) || ts.isNoSubstitutionTemplateLiteral(node.argumentExpression) ? node.argumentExpression.text : undefined);
  if (property === undefined) return undefined;
  const receiver = node.expression;
  if (!ts.isPropertyAccessExpression(receiver) || !ts.isIdentifier(receiver.expression) || receiver.expression.text !== "process" || receiver.name.text !== "env") return undefined;
  return property;
}

function staticPropertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  return undefined;
}

function importSpecifier(node: ts.Node): string | undefined {
  if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
    return node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier) ? node.moduleSpecifier.text : undefined;
  }
  if (ts.isCallExpression(node)) {
    const expression = node.expression;
    const isRequire = ts.isIdentifier(expression) && expression.text === "require";
    const isDynamicImport = expression.kind === ts.SyntaxKind.ImportKeyword;
    const argument = node.arguments[0];
    if ((isRequire || isDynamicImport) && argument && ts.isStringLiteral(argument)) return argument.text;
  }
  return undefined;
}

function analyzeFrontend(file: CollectedFile): FrontendAnalysis {
  const sourceFile = ts.createSourceFile(file.path, file.text, ts.ScriptTarget.Latest, true, scriptKind(file.path));
  const publicSecretDeclarations: ts.VariableDeclaration[] = [];
  const serverSecretLiterals: ts.StringLiteralLike[] = [];
  let reactImport = false;
  const envReferences: ts.Node[] = [];
  const relativeImports: string[] = [];
  const envConfigDeclarations: ts.PropertyAssignment[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && isSecretPublicName(node.name.text)) {
      publicSecretDeclarations.push(node);
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (isActualServerSecretLiteral(node.text)) {
        serverSecretLiterals.push(node);
      }
    }
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && /^react(?:\/|$)/i.test(node.moduleSpecifier.text)) {
      reactImport = true;
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
      const first = node.arguments[0];
      if (first && ts.isStringLiteral(first) && /^react(?:\/|$)/i.test(first.text)) reactImport = true;
    }
    if (staticEnvName(node)) envReferences.push(node);
    const imported = importSpecifier(node);
    if (imported?.startsWith(".")) relativeImports.push(imported);
    if (isNextConfigPath(file.path) && ts.isPropertyAssignment(node)) {
      const parent = node.parent.parent;
      const isEnvObject = ts.isPropertyAssignment(parent)
        && staticPropertyName(parent.name)?.toLowerCase() === "env"
        && parent.initializer === node.parent;
      if (isEnvObject) {
        envConfigDeclarations.push(node);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return {
    file,
    sourceFile,
    parseError: parseError(sourceFile),
    useClient: hasUseClientDirective(sourceFile),
    useServer: hasUseServerDirective(sourceFile),
    publicSecretDeclarations,
    serverSecretLiterals,
    reactImport,
    nextConfig: isNextConfigPath(file.path),
    envReferences,
    relativeImports,
    envConfigDeclarations,
  };
}

function frontendRelevant(analysis: FrontendAnalysis): boolean {
  return analysis.useClient || analysis.publicSecretDeclarations.length > 0 || analysis.reactImport
    || analysis.envReferences.some((node) => /^NEXT_PUBLIC_[A-Z0-9_]+$/i.test(staticEnvName(node) ?? ""))
    || (analysis.nextConfig && analysis.envConfigDeclarations.length > 0);
}

/** True when the bounded framework rules have a recognized migration or UI input. */
export function frameworkHasApplicableInput(snapshot: SourceSnapshot): boolean {
  for (const file of snapshot.files) {
    if (isMigration(file)) return true;
    if (file.category === "code" && FRONTEND_EXTENSIONS.test(file.path) && frontendRelevant(analyzeFrontend(file))) return true;
  }
  return false;
}

interface EnvSignal {
  actualSecret: boolean;
  publicKey: boolean;
}

function isDotEnvPath(path: string): boolean {
  const name = path.slice(path.lastIndexOf("/") + 1).toLowerCase();
  return name === ".env" || name.startsWith(".env.") || name.endsWith(".env");
}

function envValue(value: string): string {
  const trimmed = value.trim();
  if ((trimmed.startsWith("\"") && trimmed.endsWith("\"")) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function collectStaticEnv(snapshot: SourceSnapshot): Map<string, EnvSignal> {
  const signals = new Map<string, EnvSignal>();
  for (const file of snapshot.files) {
    if (file.category !== "secret" || !isDotEnvPath(file.path)) continue;
    for (const rawLine of file.text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
      const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(rawLine);
      if (!match || match[1].startsWith("#")) continue;
      const name = match[1];
      const value = envValue(match[2]);
      const existing = signals.get(name);
      signals.set(name, {
        actualSecret: !!existing?.actualSecret || isActualServerSecretLiteral(value),
        publicKey: !!existing?.publicKey || isPublicKeyName(name) || isPublicSupabaseKeyLiteral(value),
      });
    }
  }
  return signals;
}

function resolveRelativeImport(fromPath: string, specifier: string, available: Map<string, FrontendAnalysis>): FrontendAnalysis | undefined {
  const normalized = posix.normalize(posix.join(posix.dirname(fromPath), specifier)).replace(/^\.\//, "");
  if (normalized.startsWith("../") || normalized === "..") return undefined;
  const candidates = [normalized];
  if (!/\.[A-Za-z0-9]+$/.test(normalized)) {
    for (const extension of [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]) candidates.push(`${normalized}${extension}`);
    for (const extension of [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]) candidates.push(`${normalized}/index${extension}`);
  } else if (/\.(?:[cm]?js|jsx)$/i.test(normalized)) {
    const withoutExtension = normalized.replace(/\.(?:[cm]?js|jsx)$/i, "");
    for (const extension of [".ts", ".tsx", ".mts", ".cts"]) candidates.push(`${withoutExtension}${extension}`);
  }
  for (const candidate of candidates) {
    const analysis = available.get(candidate);
    if (analysis) return analysis;
  }
  return undefined;
}

function reachableFrontend(entry: FrontendAnalysis, available: Map<string, FrontendAnalysis>): FrontendAnalysis[] {
  const result: FrontendAnalysis[] = [];
  const seen = new Set<string>();
  const visit = (analysis: FrontendAnalysis): void => {
    // A file-level `use server` module is an explicit Next server-action
    // boundary. A client module may import its action stubs, but the server
    // implementation and its environment references are not part of the
    // client module graph observed by this bounded rule.
    if (analysis.useServer) return;
    if (seen.has(analysis.file.path)) return;
    seen.add(analysis.file.path);
    result.push(analysis);
    for (const specifier of analysis.relativeImports) {
      const imported = resolveRelativeImport(analysis.file.path, specifier, available);
      if (imported) visit(imported);
    }
  };
  visit(entry);
  return result;
}

function blank(value: string[], index: number): void {
  if (value[index] !== "\n" && value[index] !== "\r") value[index] = " ";
}

function dollarDelimiter(text: string, index: number): string | undefined {
  if (text[index] !== "$") return undefined;
  const match = text.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/);
  return match?.[0];
}

/** Masks SQL comments, quoted literals, and dollar quoted bodies while preserving line positions. */
export function maskSql(text: string): MaskedSql {
  const output = text.split("");
  const identifierOutput = text.split("");
  let state: "normal" | "single" | "double" | "line" | "block" | "dollar" = "normal";
  let delimiter = "";
  let blockDepth = 0;
  let singleEscapesBackslash = false;
  let index = 0;
  const blankBoth = (at: number): void => {
    blank(output, at);
    blank(identifierOutput, at);
  };
  while (index < text.length) {
    const character = text[index];
    if (state === "line") {
      if (character === "\n" || character === "\r") state = "normal";
      else blankBoth(index);
      index += 1;
      continue;
    }
    if (state === "block") {
      if (text.startsWith("/*", index)) {
        blankBoth(index);
        blankBoth(index + 1);
        blockDepth += 1;
        index += 2;
        continue;
      }
      if (text.startsWith("*/", index)) {
        blankBoth(index);
        blankBoth(index + 1);
        index += 2;
        blockDepth -= 1;
        if (blockDepth <= 0) {
          blockDepth = 0;
          state = "normal";
        }
      } else {
        blankBoth(index);
        index += 1;
      }
      continue;
    }
    if (state === "single") {
      blankBoth(index);
      if (character === "\\" && singleEscapesBackslash && index + 1 < text.length) {
        blankBoth(index + 1);
        index += 2;
      } else if (character === "'" && text[index + 1] === "'") {
        blankBoth(index + 1);
        index += 2;
      } else if (character === "'") {
        index += 1;
        state = "normal";
        singleEscapesBackslash = false;
      } else {
        index += 1;
      }
      continue;
    }
    if (state === "double") {
      blank(output, index);
      // Keep quoted identifier spelling in the private identity view. SQL
      // uses doubled quotes for an embedded quote; a backslash is ordinary
      // identifier content and must not hide the closing quote.
      if (character === '"' && text[index + 1] === '"') {
        blank(output, index + 1);
        index += 2;
      } else if (character === '"') {
        index += 1;
        state = "normal";
      } else {
        index += 1;
      }
      continue;
    }
    if (state === "dollar") {
      if (delimiter && text.startsWith(delimiter, index)) {
        for (let offset = 0; offset < delimiter.length; offset += 1) blankBoth(index + offset);
        index += delimiter.length;
        state = "normal";
        delimiter = "";
      } else {
        blankBoth(index);
        index += 1;
      }
      continue;
    }
    if (text.startsWith("--", index)) {
      blankBoth(index);
      blankBoth(index + 1);
      index += 2;
      state = "line";
    } else if (text.startsWith("/*", index)) {
      blankBoth(index);
      blankBoth(index + 1);
      index += 2;
      blockDepth = 1;
      state = "block";
    } else if (character === "'") {
      blankBoth(index);
      index += 1;
      const previous = text[index - 2];
      singleEscapesBackslash = (previous === "e" || previous === "E")
        && (index - 2 === 0 || !/[A-Za-z0-9_]/.test(text[index - 3] ?? ""));
      state = "single";
    } else if (character === '"') {
      blank(output, index);
      index += 1;
      state = "double";
    } else {
      const foundDelimiter = dollarDelimiter(text, index);
      if (foundDelimiter) {
        for (let offset = 0; offset < foundDelimiter.length; offset += 1) blankBoth(index + offset);
        index += foundDelimiter.length;
        delimiter = foundDelimiter;
        state = "dollar";
      } else {
        index += 1;
      }
    }
  }
  // A line comment ends at EOF just as it does at a newline. Only quoted or
  // block-comment states require a terminator for coverage to be complete.
  const masked: MaskedSql = { text: output.join(""), complete: state === "normal" || state === "line", identifierText: identifierOutput.join("") };
  // Keep the exported mask shape compatible with the original `{text,
  // complete}` result while retaining the identity view for this module.
  Object.defineProperty(masked, "identifierText", { enumerable: false, value: identifierOutput.join("") });
  return masked;
}

interface Statement {
  text: string;
  start: number;
}

interface RlsOperation {
  action: "disable" | "enable";
  table?: string;
}

function statements(masked: string): Statement[] {
  const result: Statement[] = [];
  let start = 0;
  for (let index = 0; index <= masked.length; index += 1) {
    if (index !== masked.length && masked[index] !== ";") continue;
    result.push({ text: masked.slice(start, index), start });
    start = index + 1;
  }
  return result;
}

function location(text: string, index: number): { line: number; column: number } {
  const before = text.slice(0, index);
  const lineStart = Math.max(before.lastIndexOf("\n"), before.lastIndexOf("\r"));
  return { line: before.split(/\r\n|\r|\n/).length, column: index - lineStart };
}

function normalizedTable(value: string): string {
  const segments: string[] = [];
  let current = "";
  let quoted = false;
  let wasQuoted = false;
  const pushSegment = (): void => {
    // Whitespace inside a quoted identifier is significant in PostgreSQL;
    // only the unquoted spelling may be folded/trimmed.
    const value = wasQuoted ? current : current.trim().toLowerCase();
    segments.push(value);
    current = "";
    wasQuoted = false;
  };
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quoted) {
      if (character === '"' && value[index + 1] === '"') {
        current += '"';
        index += 1;
      } else if (character === '"') {
        quoted = false;
      } else {
        current += character;
      }
      continue;
    }
    if (character === '"') {
      quoted = true;
      wasQuoted = true;
    } else if (character === ".") {
      pushSegment();
    } else if (!/\s/.test(character)) {
      current += character;
    }
  }
  if (quoted) return JSON.stringify([value.trim()]);
  pushSegment();
  return JSON.stringify(segments);
}

function rlsOperation(statement: string, identifierStatement = statement): RlsOperation | undefined {
  const action = /\b(DISABLE|ENABLE)\s+ROW\s+LEVEL\s+SECURITY\b/i.exec(statement);
  if (!action) return undefined;
  const identifier = '(?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*)';
  const prefix = /\bALTER\s+TABLE\s+?(?:(?:IF\s+)?EXISTS\s+)?(?:ONLY\s+)?/i.exec(statement);
  const tableMatch = prefix
    ? new RegExp(`^(${identifier}(?:\\s*\\.\\s*${identifier})?)`, "i").exec(identifierStatement.slice(prefix.index + prefix[0].length))
    : null;
  return { action: action[1].toLowerCase() as RlsOperation["action"], ...(tableMatch ? { table: normalizedTable(tableMatch[1]) } : {}) };
}

function finding(input: {
  ruleId: string;
  title: string;
  description: string;
  severity: Finding["severity"];
  path: string;
  source: string;
  index: number;
  remediation: string;
}): Finding {
  const position = location(input.source, input.index);
  return {
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: "low",
    kind: "candidate",
    location: { path: input.path, line: position.line, column: position.column },
    remediation: input.remediation,
  };
}

function migrationFindings(file: CollectedFile): { findings: Finding[]; incomplete: boolean } {
  const masked = maskSql(file.text);
  const findings: Finding[] = [];
  const sqlStatements = statements(masked.text);
  const operations = sqlStatements.map((statement) => rlsOperation(
    statement.text,
    masked.identifierText.slice(statement.start, statement.start + statement.text.length),
  ));
  for (const [statementIndex, statement] of sqlStatements.entries()) {
    const disable = /\bALTER\s+TABLE\b[\s\S]{0,500}?\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/i.exec(statement.text);
    const operation = operations[statementIndex];
    const laterSameTableOperation = operation?.table
      ? operations.slice(statementIndex + 1).reverse().find((candidate) => candidate?.table === operation.table)
      : undefined;
    if (disable && !(operation?.action === "disable" && laterSameTableOperation?.action === "enable")) {
      const absoluteIndex = statement.start + disable.index + disable[0].toUpperCase().lastIndexOf("DISABLE");
      findings.push(finding({
        ruleId: "supabase:disable-row-level-security",
        title: "Supabase migration explicitly disables row level security",
        description: "A bounded Supabase migration contains an explicit DISABLE ROW LEVEL SECURITY statement. This is a local migration candidate; live database state and later deployment changes were not checked.",
        severity: "high",
        path: file.path,
        source: file.text,
        index: absoluteIndex,
        remediation: "Review whether this migration should disable RLS, and verify the effective RLS state and grants separately before exposing the table.",
      }));
    }
    const createsPolicy = /\bCREATE\s+POLICY\b/i.test(statement.text);
    const restrictive = /\bAS\s+RESTRICTIVE\b/i.test(statement.text);
    const toClause = /\bTO\s+([^\s;]+(?:\s*,\s*[^\s;]+)*)/i.exec(statement.text);
    const appliesToPublic = toClause
      ? /\bPUBLIC\b/i.test(toClause[1])
      : createsPolicy;
    const permissivePredicate = /\b(?:USING\s*\(\s*TRUE\s*\)|WITH\s+CHECK\s*\(\s*TRUE\s*\))/i;
    const policy = createsPolicy && appliesToPublic && !restrictive ? permissivePredicate.exec(statement.text) : null;
    if (policy) {
      findings.push(finding({
        ruleId: "supabase:permissive-public-policy",
        title: "Supabase migration contains a permissive public policy candidate",
        description: "A bounded Supabase migration creates a policy that applies to PUBLIC, explicitly or by PostgreSQL's default, with USING (true) or WITH CHECK (true). This is a medium review candidate; grants, table contents, and live database behavior were not checked.",
        severity: "medium",
        path: file.path,
        source: file.text,
        index: statement.start + policy.index,
        remediation: "Review the policy role and predicate, then restrict access to the intended roles and ownership conditions; verify the effective policy and grants separately.",
      }));
    }
  }
  return { findings, incomplete: !masked.complete };
}

interface MigrationTableState {
  path: string;
  createIndex: number;
  grantPath?: string;
  grantIndex?: number;
  created: boolean;
  granted: boolean;
  enabled: boolean;
  disabled: boolean;
}

function tableReference(statement: string, identifierStatement: string, keyword: "CREATE TABLE" | "GRANT"): { table: string; index: number } | undefined {
  const identifier = '(?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*)';
  const prefix = keyword === "CREATE TABLE"
    ? /\bCREATE\s+TABLE\s+?(?:(?:IF\s+)?NOT\s+EXISTS\s+)?(?:ONLY\s+)?/i.exec(statement)
    : /\bGRANT\b[\s\S]*?\bON\s+?(?:TABLE\s+)?/i.exec(statement);
  if (!prefix) return undefined;
  const match = new RegExp(`^(${identifier}(?:\\s*\\.\\s*${identifier})?)`, "i").exec(identifierStatement.slice(prefix.index + prefix[0].length));
  return match ? { table: normalizedTable(match[1]), index: prefix.index + prefix[0].length + match.index } : undefined;
}

function grantExposesRows(statement: string): boolean {
  const privileges = /^\s*GRANT\s+([\s\S]*?)\s+ON\s+/i.exec(statement)?.[1] ?? "";
  return /(?:^|,)\s*(?:SELECT|INSERT|UPDATE|DELETE|ALL)(?:\s+PRIVILEGES)?\s*(?:,|$)/i.test(privileges);
}

function migrationStateFindings(files: CollectedFile[]): Finding[] {
  const states = new Map<string, MigrationTableState>();
  for (const file of files) {
    const masked = maskSql(file.text);
    const sqlStatements = statements(masked.text);
    for (const statement of sqlStatements) {
      const identifierStatement = masked.identifierText.slice(statement.start, statement.start + statement.text.length);
      const create = tableReference(statement.text, identifierStatement, "CREATE TABLE");
      if (create) {
        const existing = states.get(create.table);
        states.set(create.table, existing ?? {
          path: file.path,
          createIndex: statement.start + create.index,
          created: true,
          granted: false,
          enabled: false,
          disabled: false,
        });
      }
      const grant = tableReference(statement.text, identifierStatement, "GRANT");
      if (grant && grantExposesRows(statement.text)) {
        const roleClause = /\bTO\s+([\s\S]*)$/i.exec(statement.text);
        if (roleClause && /\b(?:PUBLIC|anon|authenticated)\b/i.test(roleClause[1])) {
          const existing = states.get(grant.table) ?? {
            path: file.path,
            createIndex: statement.start + grant.index,
            created: false,
            granted: false,
            enabled: false,
            disabled: false,
          };
          existing.granted = true;
          existing.grantPath = file.path;
          existing.grantIndex = statement.start + grant.index;
          states.set(grant.table, existing);
        }
      }
      const operation = rlsOperation(statement.text, identifierStatement);
      if (operation?.table) {
        const existing = states.get(operation.table) ?? {
          path: file.path,
          createIndex: statement.start,
          created: false,
          granted: false,
          enabled: false,
          disabled: false,
        };
        if (operation.action === "enable") existing.enabled = true;
        else {
          existing.disabled = true;
          existing.enabled = false;
        }
        states.set(operation.table, existing);
      }
    }
  }
  const findings: Finding[] = [];
  for (const state of states.values()) {
    if (!state.created || !state.granted || state.enabled) continue;
    const reportPath = state.grantPath ?? state.path;
    const reportSource = files.find((file) => file.path === reportPath)?.text ?? "";
    findings.push(finding({
      ruleId: "supabase:grant-without-observed-rls",
      title: "Supabase table grant has no observed RLS enable",
      description: "The bounded migration history creates a table and grants it to PUBLIC, anon, or authenticated without an observed ENABLE ROW LEVEL SECURITY. This is an uncertain local candidate; later migrations, rollback order, and live database state were not checked.",
      severity: "medium",
      path: reportPath,
      source: reportSource,
      index: state.grantIndex ?? state.createIndex,
      remediation: "Enable row level security before granting table access, add role-specific policies, and verify the effective database state separately.",
    }));
  }
  return findings;
}

function likelySecretName(name: string): boolean {
  return /(?:SECRET|SERVICE[_-]?ROLE|PRIVATE[_-]?KEY|PASSWORD|TOKEN|CREDENTIAL|API[_-]?KEY|ACCESS[_-]?KEY|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY)/i.test(name);
}

function frontendFindings(analysis: FrontendAnalysis, available: Map<string, FrontendAnalysis>, envSignals: Map<string, EnvSignal>): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (input: {
    ruleId: string;
    title: string;
    description: string;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
    source: CollectedFile;
    node: ts.Node;
    remediation: string;
  }): void => {
    const position = location(input.source.text, input.node.getStart());
    const key = `${input.ruleId}:${input.source.path}:${position.line}:${position.column}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      ruleId: input.ruleId,
      title: input.title,
      description: input.description,
      severity: input.severity,
      confidence: input.confidence,
      kind: "candidate",
      location: { path: input.source.path, line: position.line, column: position.column },
      remediation: input.remediation,
    });
  };

  const clientEntry = analysis.useClient;
  const reachable = clientEntry ? reachableFrontend(analysis, available) : [analysis];
  for (const candidate of reachable) {
    if (clientEntry) {
      const imported = candidate.file.path !== analysis.file.path;
      const literal = candidate.serverSecretLiterals[0];
      if (literal) {
        push({
          ruleId: "next:client-server-secret-literal",
          title: imported ? "Server secret literal is reachable from a client module" : "Server secret literal appears in a client module",
          description: imported
            ? "A bounded relative import or re-export from a use client module reaches a server-secret-shaped literal. The value is intentionally omitted; the finding does not validate the deployed bundle."
            : "A use client module contains a server-secret-shaped literal. The value is intentionally omitted; the finding does not validate whether a deployed bundle contains it.",
          severity: "critical",
          confidence: "high",
          source: candidate.file,
          node: literal,
          remediation: "Remove the server secret from the client module and keep privileged Supabase operations behind a server-side boundary.",
        });
      }
    }
    if (!clientEntry) continue;
    for (const reference of candidate.envReferences) {
      const name = staticEnvName(reference);
      if (!name) continue;
      const signal = envSignals.get(name);
      const actualSecret = !!signal?.actualSecret;
      const publicKey = isPublicKeyName(name) || !!signal?.publicKey;
      if (!actualSecret && publicKey) continue;
      if (!actualSecret && !isSecretPublicName(name) && !likelySecretName(name)) continue;
      push({
        ruleId: "next:client-server-secret-env",
        title: "Client module references a server-secret-shaped environment value",
        description: actualSecret
          ? "A bounded client import graph references an environment value whose collected .env value matches a server-secret shape. The value is intentionally omitted."
          : "A bounded client import graph references an environment name associated with a server secret. This name-only candidate has low confidence; public and publishable/anon Supabase keys are excluded.",
        severity: actualSecret ? "critical" : "medium",
        confidence: actualSecret ? "high" : "low",
        source: candidate.file,
        node: reference,
        remediation: "Remove the server credential from the NEXT_PUBLIC namespace and keep privileged values behind a server-side boundary.",
      });
    }
  }

  for (const candidate of clientEntry ? reachable : [analysis]) {
    for (const declaration of candidate.publicSecretDeclarations) {
      const actualSecret = !!declaration.initializer && initializerHasActualServerSecret(declaration.initializer);
      const publicKey = isPublicKeyName(ts.isIdentifier(declaration.name) ? declaration.name.text : "")
        || (!!declaration.initializer && initializerHasPublicSupabaseKey(declaration.initializer));
      if (!actualSecret && publicKey) continue;
      push({
        ruleId: "next:public-server-secret-variable",
        title: "NEXT_PUBLIC variable appears to carry a server secret",
        description: actualSecret
          ? "A bounded JavaScript or TypeScript declaration exposes a server-secret-shaped value through a NEXT_PUBLIC name. The value is intentionally omitted."
          : "A bounded JavaScript or TypeScript declaration uses a NEXT_PUBLIC name associated with a server secret. This name-only candidate has low confidence; public and publishable/anon Supabase keys are excluded.",
        severity: actualSecret ? "critical" : "medium",
        confidence: actualSecret ? "high" : "low",
        source: candidate.file,
        node: declaration.name,
        remediation: "Rename the variable without the NEXT_PUBLIC prefix and keep the server secret out of client modules and browser bundles.",
      });
    }
  }

  if (analysis.nextConfig) {
    for (const declaration of analysis.envConfigDeclarations) {
      const key = staticPropertyName(declaration.name);
      if (!key) continue;
      const sourceName = staticEnvName(declaration.initializer);
      const sourceSignal = sourceName ? envSignals.get(sourceName) : undefined;
      const actualSecret = initializerHasActualServerSecret(declaration.initializer) || !!sourceSignal?.actualSecret;
      const publicKey = isPublicKeyName(key) || !!sourceSignal?.publicKey || initializerHasPublicSupabaseKey(declaration.initializer);
      const nameLooksSecret = likelySecretName(key) || (sourceName ? likelySecretName(sourceName) : false);
      if (!actualSecret && publicKey) continue;
      if (!actualSecret && !nameLooksSecret) continue;
      push({
        ruleId: "next:config-env-server-secret",
        title: "Next config env object may expose a server secret",
        description: actualSecret
          ? "A bounded next.config env object contains a server-secret-shaped value. Next.js exposes entries from this object to application code; the value is intentionally omitted."
          : "A bounded next.config env object uses a name associated with a server secret. This is a low-confidence candidate because build-time resolution and the effective value were not checked.",
        severity: actualSecret ? "critical" : "medium",
        confidence: actualSecret ? "high" : "low",
        source: analysis.file,
        node: declaration.name,
        remediation: "Keep server credentials out of next.config env and expose only intentionally public, non-privileged configuration.",
      });
    }
  }
  return findings;
}

/** Run bounded Supabase migration and Next/React source candidates. */
export function runFrameworkRules(snapshot: SourceSnapshot): CheckResult {
  if (snapshot.rootError) return { id: "source.framework", status: "error", findings: [], notes: ["The source root could not be scanned by the framework rules."] };
  const migrations = snapshot.files.filter(isMigration);
  const frontendAnalyses = snapshot.files
    .filter((file) => file.category === "code" && FRONTEND_EXTENSIONS.test(file.path))
    .map(analyzeFrontend);
  const frontend = frontendAnalyses.filter(frontendRelevant);
  if (migrations.length === 0 && frontend.length === 0) {
    return { id: "source.framework", status: "not_applicable", findings: [], notes: ["No recognized Supabase migration or Next/React source file was available for the bounded framework rules."], metrics: { filesAnalyzed: 0, migrationFiles: 0, frontendFiles: 0, findingCount: 0 } };
  }
  const migrationResults = migrations.map(migrationFindings);
  const available = new Map(frontendAnalyses.map((analysis) => [analysis.file.path, analysis]));
  const envSignals = collectStaticEnv(snapshot);
  const rawFindings = [
    ...migrationResults.flatMap((result) => result.findings),
    ...migrationStateFindings(migrations),
    ...frontend.flatMap((analysis) => frontendFindings(analysis, available, envSignals)),
  ];
  // A shared helper can be reachable from more than one client entry. Keep
  // one candidate for an identical rule/location so later comparison layers
  // do not receive ambiguous duplicate anchors.
  const findingKeys = new Set<string>();
  const findings = rawFindings.filter((candidate) => {
    const location = candidate.location;
    const key = `${candidate.ruleId}\u0000${location.path ?? ""}\u0000${location.line ?? ""}\u0000${location.column ?? ""}`;
    if (findingKeys.has(key)) return false;
    findingKeys.add(key);
    return true;
  });
  const reachableParseErrors = new Set<string>();
  for (const analysis of frontend) {
    if (analysis.parseError) reachableParseErrors.add(analysis.file.path);
    if (analysis.useClient) {
      for (const candidate of reachableFrontend(analysis, available)) {
        if (candidate.parseError) reachableParseErrors.add(candidate.file.path);
      }
    }
  }
  const parseErrorCount = reachableParseErrors.size;
  const incomplete = !snapshot.complete || parseErrorCount > 0 || migrationResults.some((result) => result.incomplete);
  return {
    id: "source.framework",
    status: incomplete ? "partial" : "completed",
    findings,
    notes: [
      `Bounded framework rules inspected ${migrations.length + frontend.length} recognized file${migrations.length + frontend.length === 1 ? "" : "s"}.`,
      "These are local candidates; live database state, grants, deployed bundles, and complete import/build boundaries were not checked.",
      "Next environment references and relative imports are followed only when their names and paths are static; build-time replacement, package imports, non-literal or conditional dynamic imports, and generated bundles remain unresolved.",
      ...(parseErrorCount > 0 ? [`${parseErrorCount} frontend file${parseErrorCount === 1 ? " had" : "s had"} syntax diagnostics; framework findings may be incomplete.`] : []),
      ...(migrationResults.some((result) => result.incomplete) ? ["At least one migration had an unterminated SQL comment or literal; migration candidates may be incomplete."] : []),
      ...(!snapshot.complete ? ["The collected source snapshot was incomplete; framework coverage may be incomplete."] : []),
    ],
    metrics: { filesAnalyzed: migrations.length + frontend.length, migrationFiles: migrations.length, frontendFiles: frontend.length, parseErrorCount, findingCount: findings.length },
  };
}
