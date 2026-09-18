import * as ts from "typescript";
import type { CheckResult, Finding, Severity } from "../contracts.js";
import { findInputFlows, type InputFlowUse } from "./dataflow.js";
import type { CollectedFile, SourceSnapshot } from "./types.js";

interface AstFile {
  file: CollectedFile;
  sourceFile: ts.SourceFile;
  parseError: boolean;
}

interface Observation {
  file: CollectedFile;
  sourceFile: ts.SourceFile;
  node: ts.Node;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  remediation: string;
  confidence: Finding["confidence"];
}

const HTML_SINK = /(?:\.innerHTML\b|\.outerHTML\b|\.insertAdjacentHTML\b|\bdocument\.write\b|\bdangerouslySetInnerHTML\b)/i;
const SQL_SINK = /(?:^|\.)(?:query|execute|raw|unsafe|sql)(?:$|\()/i;
const RAW_SQL_SINK = /(?:^|\.)\$?(?:queryRawUnsafe|executeRawUnsafe|queryRaw|executeRaw)$/i;
const REDIRECT_SINK = /(?:^|\.)(?:redirect|permanentRedirect)(?:$|\()/i;
const FETCH_SINK = /^(?:fetch|axios\.(?:get|post|put|patch|request)|got|undici\.request)$/i;
const SHELL_SINK = /^(?:exec|execSync|spawn|spawnSync|fork|child_process\.(?:exec|execSync|spawn|spawnSync))$/i;

function scriptKind(path: string): ts.ScriptKind {
  if (/\.tsx$/i.test(path)) return ts.ScriptKind.TSX;
  if (/\.jsx$/i.test(path)) return ts.ScriptKind.JSX;
  if (/\.(?:ts|mts|cts)$/i.test(path)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function withoutComments(source: string): string {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, source);
  let token = scanner.scan();
  let cursor = 0;
  let output = "";
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    const start = scanner.getTokenPos();
    const end = scanner.getTextPos();
    output += source.slice(cursor, start);
    if (token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia) {
      output += source.slice(start, end).replace(/[^\n\r]/g, " ");
    } else {
      output += source.slice(start, end);
    }
    cursor = end;
    token = scanner.scan();
  }
  return output + source.slice(cursor);
}

function expressionName(node: ts.Expression): string {
  return node.getText().replace(/\s+/g, "").slice(0, 160);
}

function sourceLocation(sourceFile: ts.SourceFile, node: ts.Node): { line: number; column: number } {
  const location = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return { line: location.line + 1, column: location.character + 1 };
}

function findingFromObservation(observation: Observation): Finding {
  const location = sourceLocation(observation.sourceFile, observation.node);
  return {
    ruleId: observation.ruleId,
    title: observation.title,
    description: observation.description,
    severity: observation.severity,
    confidence: observation.confidence,
    kind: "candidate",
    location: { path: observation.file.path, line: location.line, column: location.column },
    remediation: observation.remediation,
  };
}

function callName(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return `${callName(expression.expression)}.${expression.name.text}`;
  if (ts.isElementAccessExpression(expression)) {
    const property = staticMemberName(expression);
    return property === undefined ? callName(expression.expression) : `${callName(expression.expression)}.${property}`;
  }
  return expressionName(expression);
}

function isSqlSink(name: string): boolean {
  return SQL_SINK.test(name) || RAW_SQL_SINK.test(name);
}

function isFunctionLikeNode(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node)
    || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node)
    || ts.isConstructorDeclaration(node);
}

function isUrlSearchParamsFactory(expression: ts.Expression): boolean {
  if (ts.isNewExpression(expression)) {
    return ts.isIdentifier(expression.expression) && expression.expression.text === "URLSearchParams";
  }
  return ts.isCallExpression(expression)
    && ts.isIdentifier(expression.expression)
    && expression.expression.text === "URLSearchParams";
}

function isUrlSearchParamsToString(expression: ts.Expression, variables: ReadonlySet<string>): boolean {
  if (!ts.isCallExpression(expression)
    || !ts.isPropertyAccessExpression(expression.expression)
    || expression.expression.name.text !== "toString"
    || expression.arguments.length !== 0) {
    return false;
  }
  const receiver = expression.expression.expression;
  return (ts.isIdentifier(receiver) && variables.has(receiver.text))
    || isUrlSearchParamsFactory(receiver);
}

function isObjectEntriesCall(expression: ts.Expression): boolean {
  return ts.isCallExpression(expression)
    && ts.isPropertyAccessExpression(expression.expression)
    && ts.isIdentifier(expression.expression.expression)
    && expression.expression.expression.text === "Object"
    && expression.expression.name.text === "entries";
}

function isAllowedUrlSearchParamsCall(node: ts.CallExpression, variables: ReadonlySet<string>): boolean {
  const expression = node.expression;
  if (ts.isIdentifier(expression)) {
    return expression.text === "String" || expression.text === "URLSearchParams";
  }
  if (!ts.isPropertyAccessExpression(expression)) return false;
  const receiver = expression.expression;
  if (expression.name.text === "entries") {
    return ts.isIdentifier(receiver) && receiver.text === "Object";
  }
  if (expression.name.text === "forEach") return isObjectEntriesCall(receiver);
  if (!ts.isIdentifier(receiver) || !variables.has(receiver.text)) return false;
  if (expression.name.text === "toString") return node.arguments.length === 0;
  return expression.name.text === "set";
}

function isDerivedSerializerExpression(expression: ts.Expression, variables: ReadonlySet<string>, serialized: ReadonlySet<string>): boolean {
  if (ts.isIdentifier(expression) && serialized.has(expression.text)) return true;
  if (isUrlSearchParamsToString(expression, variables)) return true;
  let derived = false;
  expression.forEachChild((child) => {
    if (derived || !ts.isExpression(child)) return;
    derived = isDerivedSerializerExpression(child, variables, serialized);
  });
  return derived;
}

/**
 * A bare local function named `query` can be a URL query-string serializer,
 * rather than a database sink. Keep this exception deliberately narrow: only
 * a top-level `function query` whose body contains the known URLSearchParams
 * serializer calls and returns their derived string is eligible. Property
 * calls (for example `db.query(...)`) and unproven bare calls remain SQL
 * candidates.
 */
function isUrlSearchParamsSerializer(functionLike: ts.FunctionLikeDeclaration): boolean {
  const body = functionLike.body;
  if (!body) return false;

  const variables = new Set<string>();
  const collectVariables = (node: ts.Node): void => {
    if (node !== body && isFunctionLikeNode(node)) return;
    if (ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.initializer
      && isUrlSearchParamsFactory(node.initializer)) {
      variables.add(node.name.text);
    }
    if (ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isIdentifier(node.left)
      && isUrlSearchParamsFactory(node.right)) {
      variables.add(node.left.text);
    }
    ts.forEachChild(node, collectVariables);
  };
  collectVariables(body);
  if (variables.size === 0) return false;

  const serialized = new Set<string>();
  const collectSerialized = (node: ts.Node): void => {
    if (node !== body && isFunctionLikeNode(node)) return;
    if (ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.initializer
      && isUrlSearchParamsToString(node.initializer, variables)) {
      serialized.add(node.name.text);
    }
    if (ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isIdentifier(node.left)
      && isUrlSearchParamsToString(node.right, variables)) {
      serialized.add(node.left.text);
    }
    ts.forEachChild(node, collectSerialized);
  };
  collectSerialized(body);

  let valid = true;
  const validate = (node: ts.Node): void => {
    if (!valid) return;
    if (ts.isNewExpression(node) && !isUrlSearchParamsFactory(node)) valid = false;
    if (ts.isCallExpression(node) && !isAllowedUrlSearchParamsCall(node, variables)) valid = false;
    if ((ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment)
      || ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)
      || ts.isDeleteExpression(node)) {
      valid = false;
    }
    ts.forEachChild(node, validate);
  };
  validate(body);
  if (!valid) return false;

  let returnedDerived = false;
  const findReturns = (node: ts.Node): void => {
    if (returnedDerived || (node !== body && isFunctionLikeNode(node))) return;
    if (ts.isReturnStatement(node) && node.expression && ts.isExpression(node.expression)) {
      returnedDerived = isDerivedSerializerExpression(node.expression, variables, serialized);
      return;
    }
    ts.forEachChild(node, findReturns);
  };
  if (ts.isBlock(body)) findReturns(body);
  else returnedDerived = isDerivedSerializerExpression(body, variables, serialized);
  return returnedDerived;
}

// Deliberately conservative: any other binding or write to these names in
// this file disables the exemption, rather than guessing lexical resolution.
function localUrlSearchParamsSerializer(sourceFile: ts.SourceFile): boolean {
  const declarations = sourceFile.statements.filter((statement): statement is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(statement) && statement.name?.text === "query");
  if (declarations.length !== 1 || !isUrlSearchParamsSerializer(declarations[0])) return false;
  const protectedNames = new Set(["query", "URLSearchParams", "Object", "String"]);
  const touches = (node: ts.Node): boolean => {
    if (ts.isIdentifier(node)) return protectedNames.has(node.text);
    return ts.forEachChild(node, touches) ?? false;
  };
  let ambiguous = false;
  const visit = (node: ts.Node): void => {
    if (ambiguous) return;
    const binding = ts.isVariableDeclaration(node) || ts.isParameter(node)
      || ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)
      || ts.isClassDeclaration(node) || ts.isClassExpression(node)
      || ts.isImportClause(node) || ts.isImportSpecifier(node)
      || ts.isNamespaceImport(node) || ts.isBindingElement(node);
    if (binding && node !== declarations[0] && node.name && touches(node.name)) ambiguous = true;
    if (ts.isBinaryExpression(node)
      && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
      && touches(node.left)) ambiguous = true;
    if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) && touches(node.operand)) ambiguous = true;
    if ((ts.isForOfStatement(node) || ts.isForInStatement(node)) && touches(node.initializer)) ambiguous = true;
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return !ambiguous;
}

function isLocalUrlSearchParamsSerializerCall(node: ts.CallExpression, proven: boolean): boolean {
  return proven && ts.isIdentifier(node.expression) && node.expression.text === "query";
}

function hasDangerousHtmlProp(expression: ts.Expression | undefined): boolean {
  if (!expression || !ts.isObjectLiteralExpression(expression)) return false;
  return expression.properties.some((property) => {
    if (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) {
      return staticMemberName(property.name as ts.Expression) === "dangerouslySetInnerHTML"
        || (ts.isIdentifier(property.name) && property.name.text === "dangerouslySetInnerHTML");
    }
    return false;
  });
}

function pushObservation(output: Observation[], file: CollectedFile, sourceFile: ts.SourceFile, node: ts.Node, ruleId: string, title: string, description: string, severity: Severity, remediation: string, confidence: Finding["confidence"] = "medium"): void {
  output.push({ file, sourceFile, node, ruleId, title, description, severity, remediation, confidence });
}

function staticMemberName(expression: ts.Expression): string | undefined {
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression)) {
    const argument = expression.argumentExpression;
    if (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument) || ts.isNumericLiteral(argument)) return argument.text;
  }
  return undefined;
}

function memberPath(expression: ts.Expression): string[] {
  if (ts.isIdentifier(expression)) return [expression.text];
  const property = staticMemberName(expression);
  if (!property) return [];
  if (ts.isPropertyAccessExpression(expression)) return [...memberPath(expression.expression), property];
  if (ts.isElementAccessExpression(expression)) return [...memberPath(expression.expression), property];
  return [];
}

function isHtmlAssignmentTarget(expression: ts.Expression): boolean {
  return ["innerHTML", "outerHTML", "insertAdjacentHTML", "dangerouslySetInnerHTML"].includes(staticMemberName(expression) ?? "");
}

function isRedirectLocationTarget(expression: ts.Expression): boolean {
  const path = memberPath(expression);
  return path.length === 1 && path[0] === "location"
    || path.length === 2 && path[0] === "location" && path[1] === "href"
    || path.length === 2 && path[0] === "window" && path[1] === "location"
    || path.length === 3 && path[0] === "window" && path[1] === "location" && path[2] === "href";
}

function flowConfidence(use: InputFlowUse, index = 0): Finding["confidence"] | undefined {
  const flow = use.argumentFlows?.find((candidate) => candidate.index === index);
  return flow ? flow.certainty === "unknown" ? "low" : "medium" : undefined;
}

function observeFile(astFile: AstFile): Observation[] {
  const observations: Observation[] = [];
  const { file, sourceFile } = astFile;
  const localUrlSearchParamsSerializerBinding = localUrlSearchParamsSerializer(sourceFile);
  const flowUses = new Map<ts.Node, InputFlowUse>();
  for (const use of findInputFlows(sourceFile)) flowUses.set(use.node, use);
  const walk = (node: ts.Node): void => {
    if (ts.isBinaryExpression(node)) {
      const use = flowUses.get(node);
      const confidence = use ? flowConfidence(use) : undefined;
      if (use?.kind === "assignment" && confidence && isHtmlAssignmentTarget(node.left)) {
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink", "Request input reaches an HTML sink", "Untrusted request or URL input appears to flow into an HTML rendering sink.", "high", "Validate and contextually encode untrusted values before rendering them.", confidence);
      }
      if (use?.kind === "assignment" && confidence && isRedirectLocationTarget(node.left)) {
        pushObservation(observations, file, sourceFile, node, "ast:open-redirect", "Request input reaches a redirect location", "Untrusted request input appears to control a browser navigation target.", "medium", "Allowlist destination origins or paths before redirecting.", confidence);
      }
    }
    if (ts.isJsxAttribute(node) && ts.isIdentifier(node.name) && node.name.text.toLowerCase() === "dangerouslysetinnerhtml") {
      const use = flowUses.get(node);
      if (use?.kind === "jsx" && flowConfidence(use)) {
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink", "Request input reaches a React HTML sink", "Untrusted request or URL input appears in a dangerouslySetInnerHTML prop.", "high", "Avoid dangerouslySetInnerHTML or sanitize and contextually encode untrusted values before rendering them.", flowConfidence(use));
      }
    }
    if (ts.isCallExpression(node)) {
      const name = callName(node.expression);
      const use = flowUses.get(node);
      if ((name === "eval" || name === "window.eval" || name === "Function" || name === "window.Function") && node.arguments.length > 0) {
        pushObservation(observations, file, sourceFile, node, "ast:dynamic-code", "Dynamic code execution", "The code invokes a dynamic evaluation API; user controlled input may become executable code.", "high", "Remove dynamic evaluation or replace it with a fixed, validated operation.");
      } else if (use?.kind === "call" && HTML_SINK.test(name) && (use.argumentFlows?.length ?? 0) > 0) {
        const confidence = use.argumentFlows?.some((flow) => flow.certainty === "unknown") ? "low" : "medium";
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink", "Request input reaches an HTML sink", "Untrusted request or URL input appears to flow into an HTML rendering sink.", "high", "Validate and contextually encode untrusted values before rendering them.", confidence);
      } else if (use?.kind === "call" && name === "React.createElement" && hasDangerousHtmlProp(node.arguments[1]) && flowConfidence(use, 1)) {
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink", "Request input reaches a React HTML sink", "Untrusted request or URL input appears in a dangerouslySetInnerHTML prop passed to React.createElement.", "high", "Avoid dangerouslySetInnerHTML or sanitize and contextually encode untrusted values before rendering them.", flowConfidence(use, 1));
      } else if (use?.kind === "call"
        && isSqlSink(name)
        && !isLocalUrlSearchParamsSerializerCall(node, localUrlSearchParamsSerializerBinding)
        && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:sql-input-sink", "Request input reaches a dynamic SQL call", "Request input appears in a dynamically constructed SQL argument.", "high", "Use a parameterized query API and keep SQL structure separate from user input.", flowConfidence(use, 0));
      } else if (use?.kind === "call" && REDIRECT_SINK.test(name) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:open-redirect", "Request input reaches a redirect call", "Untrusted request input appears to control a redirect destination.", "medium", "Allowlist destination origins or paths before redirecting.", flowConfidence(use, 0));
      } else if (use?.kind === "call" && FETCH_SINK.test(name) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:server-request", "Request input reaches an outbound request", "Request input appears to control an outbound URL or request target.", "high", "Use an origin and path allowlist before making server side requests.", flowConfidence(use, 0));
      } else if (use?.kind === "call" && SHELL_SINK.test(name) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:shell-input-sink", "Request input reaches a shell call", "Request input appears to control a process or shell command argument.", "critical", "Avoid shell execution; use fixed argument arrays and strict allowlists when a process is required.", flowConfidence(use, 0));
      } else if (use?.kind === "call" && /^setTimeout$/i.test(name) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:dynamic-code", "Request input reaches a timer code argument", "Request input appears to reach a timer API that accepts executable code.", "high", "Pass a function reference and validate all inputs before scheduling work.", flowConfidence(use, 0));
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(sourceFile);
  return observations;
}

function inlineSecretFindings(file: CollectedFile): Finding[] {
  const findings: Finding[] = [];
  // This is intentionally a small candidate detector. Gitleaks remains the
  // authoritative secret scanner when selected; this built-in rule gives
  // `--tools none` a useful local signal without copying a secret value.
  const source = withoutComments(file.text);
  const lines = source.split(/\r?\n/);
  const patterns: Array<[RegExp, string, Severity]> = [
    [/\bAKIA[0-9A-Z]{16}\b/, "ast:aws-access-key", "high"],
    [/(?:ghp|github_pat)_[A-Za-z0-9_]{20,}/, "ast:github-token", "high"],
    [/\bxox[baprs]-[A-Za-z0-9-]{16,}/, "ast:slack-token", "high"],
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "ast:private-key", "critical"],
    [/(?:^|[\s=:'"])(?:sk|rk)-[A-Za-z0-9_-]{20,}/, "ast:api-key", "high"],
  ];
  for (const [pattern, ruleId, severity] of patterns) {
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      if (!pattern.test(lines[lineIndex])) continue;
      const column = Math.max(1, lines[lineIndex].search(pattern) + 1);
      findings.push({
        ruleId,
        title: "Potential credential in source",
        description: "The bounded local candidate detector found a credential shaped value. The value is intentionally omitted.",
        severity,
        confidence: "low",
        kind: "candidate",
        location: { path: file.path, line: lineIndex + 1, column },
        remediation: "Revoke or rotate the credential, then remove it from source and history.",
      });
      break;
    }
  }
  return findings;
}

function syntacticParseError(sourceFile: ts.SourceFile): boolean {
  const diagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics;
  return Array.isArray(diagnostics) && diagnostics.length > 0;
}

export function runBuiltinAst(snapshot: SourceSnapshot, hasOtherSecurityCheck = false): CheckResult {
  const astFiles: AstFile[] = [];
  const skippedSensitive = snapshot.files.filter((file) => file.sensitive && file.category === "code").length;
  for (const file of snapshot.files) {
    if (file.category !== "code" || file.sensitive || !/\.(?:[cm]?[jt]sx?)$/i.test(file.path)) continue;
    const sourceFile = ts.createSourceFile(file.path, file.text, ts.ScriptTarget.Latest, true, scriptKind(file.path));
    astFiles.push({ file, sourceFile, parseError: syntacticParseError(sourceFile) });
  }
  if (astFiles.length === 0) {
    return {
      id: "source.builtin-ast",
      status: hasOtherSecurityCheck ? "not_applicable" : "partial",
      findings: [],
      notes: [
        hasOtherSecurityCheck
          ? "No allowlisted JavaScript or TypeScript files were available; the built-in AST check is not applicable to this source snapshot."
          : "No allowlisted JavaScript or TypeScript files were available for the built-in AST checks; coverage is incomplete.",
        ...(skippedSensitive ? ["Sensitive code-like paths were retained for secret scanning and excluded from AST analysis."] : []),
      ],
      metrics: { filesAnalyzed: 0, parseErrorCount: 0 },
    };
  }
  const observations = astFiles.flatMap((file) => observeFile(file));
  const secretFindings = astFiles.filter((file) => !file.parseError).flatMap((file) => inlineSecretFindings(file.file));
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const finding of [...observations.map(findingFromObservation), ...secretFindings]) {
    const key = `${finding.location.path}:${finding.location.line}:${finding.location.column}:${finding.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(finding);
  }
  const parseErrorCount = astFiles.filter((file) => file.parseError).length;
  return {
    id: "source.builtin-ast",
    status: parseErrorCount > 0 ? "partial" : "completed",
    findings,
    notes: [
      `Built-in AST checks analyzed ${astFiles.length} JavaScript or TypeScript file${astFiles.length === 1 ? "" : "s"}.`,
      "Input-flow candidates are bounded to recognized request-shaped expressions and same-function assignments; unknown helper returns remain low-confidence candidates, and interprocedural, cross-file, and type-aware flows are not resolved.",
      ...(parseErrorCount > 0 ? [`${parseErrorCount} JavaScript or TypeScript file${parseErrorCount === 1 ? "" : "s"} had syntax diagnostics; findings may be incomplete.`] : []),
    ],
    metrics: { filesAnalyzed: astFiles.length, parseErrorCount, findingCount: findings.length },
  };
}
