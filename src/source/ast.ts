import { redactSecrets, safeRelativePath } from '../report-path.js';
import type { AstAnalysisBudget } from '../contracts.js';
import { mergeSqlRoles } from './sql-role.js';
import * as ts from "typescript";
import type { CheckResult, Finding, Severity, StaticFlow } from "../contracts.js";
import { findSnapshotInputFlows, type InputFlowUse, type ParseFileEvidence } from "./dataflow.js";
import { FLOW_LIMITS, type FlowLimits } from "./modules.js";
import type { CollectedFile, SourceSnapshot } from "./types.js";
import { mergeHttpRoles } from './http-role.js';

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
  kind?: Finding["kind"];
  staticFlow?: StaticFlow;
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
    kind: observation.kind ?? "candidate",
    location: { path: observation.file.path, line: location.line, column: location.column },
    remediation: observation.remediation,
    ...(observation.staticFlow ? { staticFlow: observation.staticFlow } : {}),
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

function dynamicCodeShape(node: ts.Node): 'eval' | 'function' | undefined {
  if (ts.isCallExpression(node)) {
    const name = callName(node.expression);
    if (name === 'eval' || name === 'window.eval') return 'eval';
    if (name === 'Function' || name === 'window.Function') return 'function';
  } else if (ts.isNewExpression(node) && (ts.isIdentifier(node.expression) && node.expression.text === 'Function'
    || ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression)
      && node.expression.expression.text === 'window' && node.expression.name.text === 'Function')) return 'function';
  return undefined;
}

/** Direct/static spelling only. callName's legacy computed fallback is not operand-role proof. */
function directDynamicCodeShape(node: ts.Node): 'eval' | 'function' | undefined {
  if (!ts.isCallExpression(node) && !ts.isNewExpression(node)) return undefined;
  const callee = node.expression, call = ts.isCallExpression(node);
  let name: string | undefined;
  if (ts.isIdentifier(callee)) name = callee.text;
  else if ((ts.isPropertyAccessExpression(callee) || call && ts.isElementAccessExpression(callee))
    && ts.isIdentifier(callee.expression) && callee.expression.text === 'window') name = staticMemberName(callee);
  return name === 'Function' ? 'function' : call && name === 'eval' ? 'eval' : undefined;
}

/** Operand syntax and observed input only; never native identity or generated-code safety. */
function dynamicCodeObservation(astFile: AstFile, node: ts.CallExpression | ts.NewExpression, use: InputFlowUse | undefined): Observation | undefined {
  const shape = dynamicCodeShape(node), direct = directDynamicCodeShape(node), args = node.arguments ?? [];
  if (!shape || args.length === 0) return undefined;
  const relevant = (index: number): boolean => !direct || shape === 'function' || index === 0;
  const flows = (use?.argumentFlows ?? []).filter(flow => relevant(flow.index));
  const flow = flows.find(candidate => candidate.certainty === 'tainted')
    ?? flows.reduce<(typeof flows)[number] | undefined>((first, candidate) => !first || candidate.index < first.index ? candidate : first, undefined);
  // Flow arrays are normally index ordered, but select explicitly for merged contexts too.
  const selected = flow?.certainty === 'tainted'
    ? flows.filter(candidate => candidate.certainty === 'tainted').reduce((first, candidate) => candidate.index < first.index ? candidate : first)
    : flow;
  const spread = args.some(ts.isSpreadElement);
  const literal = !!direct && !astFile.parseError && !spread && flows.length === 0
    && args.every((arg, index) => !relevant(index) || ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg));
  const base = { file: astFile.file, sourceFile: astFile.sourceFile, node, ruleId: 'ast:dynamic-code',
    remediation: 'Review the code operand and callable binding. Prefer a fixed operation; generated code and runtime effects need separate review.' };
  if (literal) return { ...base, kind: 'observation', severity: 'info', confidence: 'medium',
    title: 'Literal code operand at an evaluation-shaped call',
    description: 'Direct literal code operand(s) are present at API-shaped syntax. Callee identity, generated-code safety and runtime execution are unverified.' };
  const operand = selected ? !direct ? ` Observed input is at syntactic argument ${selected.index + 1}; code role is unresolved.`
    : spread ? ` Observed input is at syntactic argument ${selected.index + 1}; expanded ordinal and code role are unverified.`
    : ` Observed input is at syntactic argument ${selected.index + 1} (${shape === 'eval' ? 'code operand' : selected.index === args.length - 1 ? 'body' : 'parameter-source'} under the API convention).` : '';
  return { ...base, kind: 'candidate', severity: 'high', confidence: !!direct && !spread && selected?.certainty === 'tainted' ? 'medium' : 'low',
    title: direct && !spread && selected ? 'Input reaches an evaluation-shaped code operand' : 'Unresolved code operand at an evaluation-shaped call',
    description: !direct ? 'A legacy evaluation-shaped name match has unresolved computed dispatch and code operand roles. Callee identity, input dependence and runtime execution are unverified.' + operand
      : spread ? 'A spread argument leaves evaluation-shaped code operand roles and arity unresolved. Callee identity, input dependence and runtime execution are unverified.' + operand
      : selected ? 'Input-related data reaches a code operand at API-shaped syntax. Callee identity, generated code and runtime execution are unverified.' + operand
        : 'The code operand or dispatch is unresolved by the declared model. Input dependence, callee identity and runtime execution are unverified.',
    ...(selected?.staticFlow ? { staticFlow: selected.staticFlow } : {}) };
}

function isSqlSink(name: string): boolean {
  return SQL_SINK.test(name) || RAW_SQL_SINK.test(name);
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

function dataOnlyOptions(node: ts.Expression): boolean {
  if (!ts.isObjectLiteralExpression(node)) return false;
  return node.properties.every((property) => {
    if (!ts.isPropertyAssignment(property) || ts.isComputedPropertyName(property.name)) return false;
    const key = ts.isIdentifier(property.name) || ts.isStringLiteral(property.name) ? property.name.text : undefined;
    if (key === 'method') return ts.isStringLiteral(property.initializer) && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/i.test(property.initializer.text);
    if (key !== 'headers' || !ts.isObjectLiteralExpression(property.initializer)) return false;
    return property.initializer.properties.every((header) => ts.isPropertyAssignment(header) && !ts.isComputedPropertyName(header.name)
      && (ts.isIdentifier(header.name) || ts.isStringLiteral(header.name)) && !/^(host|:authority)$/i.test(header.name.text)
      && ts.isStringLiteral(header.initializer));
  });
}
function destinationQualified(use: InputFlowUse, node: ts.CallExpression): boolean {
  // Opaque options may alter the transport or effective target; no initial-target proof is claimed.
  return use.argumentFlows?.find((flow) => flow.index === 0)?.fixedDestination === true
    && (node.arguments.length === 1 || node.arguments.length === 2 && dataOnlyOptions(node.arguments[1]));
}

function observeFile(astFile: AstFile, flowUses: ReadonlyMap<ts.Node, InputFlowUse>): Observation[] {
  const observations: Observation[] = [];
  const { file, sourceFile } = astFile;
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
      if (use?.forkRole) {
        const confidence = flowConfidence(use, 0);
        if (confidence) pushObservation(observations, file, sourceFile, node, 'ast:fork-module-path',
          use.forkRole.identity === 'native' ? 'Input reaches a Node fork module path' : 'Input reaches an unresolved fork-shaped call',
          use.forkRole.identity === 'native' ? 'Input-related data reaches the modulePath argument of a statically bound Node fork API. Runtime identity, module execution and path escape are unverified.' : 'Known input reaches the first argument of an exact-load fork-shaped binding whose native identity is unresolved. Module execution and path escape are unverified.',
          'high', 'Review module selection and restrict executable module paths. argv and execution options require separate review.', use.forkRole.identity === 'native' ? confidence : 'low');
      } else if ((name === "eval" || name === "window.eval" || name === "Function" || name === "window.Function") && node.arguments.length > 0) {
        observations.push(dynamicCodeObservation(astFile, node, use)!);
      } else if (use?.htmlResponse === "express" && flowConfidence(use, 0)) {
        const json = ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "json";
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink",
          json ? "Request input reaches JSON with HTML or unknown MIME; set application/json" : "Request input reaches res.send; encode HTML or set a non-HTML type",
          "Input reaches a response-shaped body whose MIME can render HTML. JSON serialization does not reset an existing Content-Type. Confirm the binding, headers and encoding before assessing exploitability.",
          "high", "For JSON data, explicitly set application/json before res.json; for HTML, contextually encode untrusted text. Review custom header changes.", use.htmlResponseMime === "unknown" ? "low" : flowConfidence(use, 0));
      } else if (use?.kind === "call" && HTML_SINK.test(name) && (use.argumentFlows?.length ?? 0) > 0) {
        const confidence = use.argumentFlows?.some((flow) => flow.certainty === "unknown") ? "low" : "medium";
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink", "Request input reaches an HTML sink", "Untrusted request or URL input appears to flow into an HTML rendering sink.", "high", "Validate and contextually encode untrusted values before rendering them.", confidence);
      } else if (use?.kind === "call" && name === "React.createElement" && hasDangerousHtmlProp(node.arguments[1]) && flowConfidence(use, 1)) {
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink", "Request input reaches a React HTML sink", "Untrusted request or URL input appears in a dangerouslySetInnerHTML prop passed to React.createElement.", "high", "Avoid dangerouslySetInnerHTML or sanitize and contextually encode untrusted values before rendering them.", flowConfidence(use, 1));
      } else if (use?.sqlRole) {
        const role=use.sqlRole;
        if (role.inputRelated && role.outcome!=='values_only_fixed_text') pushObservation(observations,file,sourceFile,node,'ast:sql-input-sink',
          role.outcome==='statement_input' ? 'Request input reaches a SQL statement text argument' : 'Input-related SQL API argument roles are unresolved',
          role.outcome==='statement_input' ? 'An input-related value reaches the statement text of the declared pg API. SQL structure control, execution and exploitability are unverified.' : 'Observed input reaches a query-shaped API, but default dispatch or statement/parameter roles are unresolved. This is not a claim that parameter data controls SQL text.',
          'high','Keep statement text independent of parameter data and review API binding, dispatch and unmodeled side effects.',role.outcome==='statement_input' && role.certainty==='tainted' ? 'medium' : 'low');
      } else if (use?.kind === "call" && !use.localCall && isSqlSink(name) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:sql-input-sink", "Request input reaches a dynamic SQL call", "Request input appears in a dynamically constructed SQL argument.", "high", "Use a parameterized query API and keep SQL structure separate from user input.", flowConfidence(use, 0));
      } else if (use?.kind === "call" && REDIRECT_SINK.test(name) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:open-redirect", "Request input reaches a redirect call", "Untrusted request input appears to control a redirect destination.", "medium", "Allowlist destination origins or paths before redirecting.", flowConfidence(use, 0));
      } else if (use?.httpRole?.inputRelated) {
        const role = use.httpRole;
        if (role.outcome === 'target_input') {
          pushObservation(observations, file, sourceFile, node, 'ast:server-request', 'Request input reaches an outbound destination field',
            'An input-related value appears in the URL field of a supported Axios request config. Runtime destination control is unverified.', 'high',
            'Review the destination field and restrict initial origins and paths before making requests.', role.certainty === 'tainted' ? 'medium' : 'low');
        } else if (role.outcome === 'unknown_role' && !(FETCH_SINK.test(name) && destinationQualified(use, node))) {
          pushObservation(observations, file, sourceFile, node, 'ast:server-request', 'Input-related configuration reaches an outbound API-shaped call',
            'An input-related argument reaches a request-shaped call, but its destination field or API identity is unresolved by the declared model. Review target configuration; runtime destination control is unverified.', 'high',
            'Review the collected API binding and target configuration without treating payload input as proven URL authority control.', 'low');
        }
      } else if (use?.kind === "call" && FETCH_SINK.test(name) && flowConfidence(use, 0) && !destinationQualified(use, node)) {
        pushObservation(observations, file, sourceFile, node, "ast:server-request", "Request input reaches an outbound request", "Request input appears to control an outbound URL or request target.", "high", "Use an origin and path allowlist before making server side requests.", flowConfidence(use, 0));
      } else if (use?.kind === "call" && SHELL_SINK.test(name) && !(name === "fork" && use.localForkCall?.complete === true) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:shell-input-sink", "Request input reaches a shell call", "Request input appears to control a process or shell command argument.", "critical", "Avoid shell execution; use fixed argument arrays and strict allowlists when a process is required.", flowConfidence(use, 0));
      } else if (use?.kind === "call" && /^setTimeout$/i.test(name) && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:dynamic-code", "Request input reaches a timer code argument", "Request input appears to reach a timer API that accepts executable code.", "high", "Pass a function reference and validate all inputs before scheduling work.", flowConfidence(use, 0));
      }
    }
    if (ts.isNewExpression(node)) {
      const observation = dynamicCodeObservation(astFile, node, flowUses.get(node));
      if (observation) observations.push(observation);
      const use = flowUses.get(node);
      if (use?.htmlResponse === "web" && flowConfidence(use, 0)) {
        pushObservation(observations, file, sourceFile, node, "ast:html-input-sink", "Request input reaches an HTML response; encode text or return JSON",
          "Input reaches a Response-shaped body with an explicit text/html header. Runtime constructor identity, rendering and exploitability are unverified.",
          "high", "Use Response.json for data, or contextually encode untrusted text before returning HTML.", flowConfidence(use, 0));
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(sourceFile);
  return observations.map((observation) => {
    // Dynamic code selects its actual relevant operand; timers still use the generic arg0 trace.
    if (observation.ruleId === 'ast:dynamic-code' && dynamicCodeShape(observation.node)) return observation;
    const use = flowUses.get(observation.node);
    const index = ts.isCallExpression(observation.node) && callName(observation.node.expression) === "React.createElement" ? 1 : 0;
    const staticFlow = observation.ruleId === 'ast:sql-input-sink' && use?.sqlRole ? use.sqlRole.staticFlow : observation.ruleId === 'ast:server-request' && use?.httpRole
      ? use.httpRole.staticFlow : use?.argumentFlows?.find((argument) => argument.index === index)?.staticFlow;
    return staticFlow ? { ...observation, staticFlow } : observation;
  });
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

function parseDiagnostics(sourceFile: ts.SourceFile): readonly ts.Diagnostic[] {
  const diagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics;
  return Array.isArray(diagnostics) ? diagnostics : [];
}

/** No source text/message leaves this lazy, one-representative-per-error-file projection. */
function* parseFileEvidence(files: readonly AstFile[]): Iterable<ParseFileEvidence> {
  for (const { file, sourceFile, parseError } of files) {
    if (!parseError) continue;
    const path = file.path;
    if (path.length > 4096 || path.includes('\\') || path.split('/').includes('..')
      || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path) || redactSecrets(path) !== path || safeRelativePath(path) !== path) { yield {}; continue; }
    let selected: ts.Diagnostic | undefined;
    for (const diagnostic of parseDiagnostics(sourceFile)) {
      if (!Number.isSafeInteger(diagnostic.start) || diagnostic.start! < 0 || diagnostic.start! > sourceFile.text.length
        || !Number.isSafeInteger(diagnostic.code) || diagnostic.code <= 0) continue;
      if (!selected || diagnostic.start! < selected.start! || diagnostic.start === selected.start && diagnostic.code < selected.code) selected = diagnostic;
    }
    if (!selected) { yield {}; continue; }
    const position = sourceFile.getLineAndCharacterOfPosition(selected.start!);
    yield { location: { path, line: position.line + 1, column: position.character + 1 }, diagnosticCode: selected.code };
  }
}

export function runBuiltinAst(snapshot: SourceSnapshot, hasOtherSecurityCheck = false, limits: FlowLimits = FLOW_LIMITS, analysisBudget?: AstAnalysisBudget): CheckResult {
  const astFiles: AstFile[] = [];
  const skippedSensitive = snapshot.files.filter((file) => file.sensitive && file.category === "code").length;
  for (const file of snapshot.files) {
    if (file.category !== "code" || file.sensitive || !/\.(?:[cm]?[jt]sx?)$/i.test(file.path)) continue;
    const sourceFile = ts.createSourceFile(file.path, file.text, ts.ScriptTarget.Latest, true, scriptKind(file.path));
    astFiles.push({ file, sourceFile, parseError: parseDiagnostics(sourceFile).length > 0 });
  }
  if (astFiles.length === 0) {
    return {
      id: "source.builtin-ast",
    ...(analysisBudget && sameLimits(analysisBudget.limits, limits) ? { analysisBudget } : {}),
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
  const parseErrorCount = astFiles.filter((file) => file.parseError).length;
  const sensitiveJsTsExcluded = snapshot.files.some(file => file.sensitive && file.category === 'code' && /\.(?:[cm]?[jt]sx?)$/i.test(file.path));
  const roleProofScopeComplete = snapshot.complete && parseErrorCount === 0 && !sensitiveJsTsExcluded;
  const analysis = findSnapshotInputFlows(astFiles.filter((file) => !file.parseError).map((file) => file.sourceFile), limits, parseErrorCount, roleProofScopeComplete, parseFileEvidence(astFiles));
  const flowUses = new Map<ts.Node, InputFlowUse>();
  for (const use of analysis.uses) {
    const prior = flowUses.get(use.node);
    if (!prior) { flowUses.set(use.node, use); continue; }
    const argumentsByIndex = new Map(prior.argumentFlows?.map((argument) => [argument.index, argument]));
    for (const argument of use.argumentFlows ?? []) {
      const before = argumentsByIndex.get(argument.index);
      if (!before) argumentsByIndex.set(argument.index, argument);
      else {
        // Any unsafe context retains the sink and its evidence, independent of evaluation order.
        const preferred = before.fixedDestination && !argument.fixedDestination ? argument
          : !before.fixedDestination && argument.fixedDestination ? before
          : before.certainty === 'unknown' && argument.certainty === 'tainted' ? argument : before;
        argumentsByIndex.set(argument.index, { ...preferred, fixedDestination: before.fixedDestination === true && argument.fixedDestination === true });
      }
    }
    flowUses.set(use.node, { ...prior, htmlResponse: prior.htmlResponse ?? use.htmlResponse, htmlResponseMime: prior.htmlResponseMime === "unknown" || use.htmlResponseMime === "unknown" ? "unknown" : prior.htmlResponseMime ?? use.htmlResponseMime, argumentFlows: [...argumentsByIndex.values()].sort((a, b) => a.index - b.index), localForkCall: prior.localForkCall && use.localForkCall ? {complete:prior.localForkCall.complete && use.localForkCall.complete} : undefined, forkRole: prior.forkRole?.identity === 'unresolved' || use.forkRole?.identity === 'unresolved' ? {identity:'unresolved'} : prior.forkRole ?? use.forkRole, sqlRole:mergeSqlRoles(prior.sqlRole,use.sqlRole), httpRole: mergeHttpRoles(prior.httpRole, use.httpRole) });
  }
  const outboundUses = [...flowUses.values()].filter((use) => ts.isCallExpression(use.node) && FETCH_SINK.test(callName(use.node.expression)) && flowConfidence(use, 0));
  const outboundFixedDestinationSuppressed = outboundUses.filter((use) => destinationQualified(use, use.node as ts.CallExpression)).length;
  const forkUses = [...flowUses.values()].filter(use => use.forkRole);
  const forkInputUses = forkUses.filter(use => flowConfidence(use, 0));
  const sqlUses=[...flowUses.values()].filter(use=>use.sqlRole);
  const sqlInputUses=sqlUses.filter(use=>use.sqlRole!.inputRelated);
  const roleUses = [...flowUses.values()].filter(use => use.httpRole);
  const candidateRoleUses = roleUses.filter(use => use.httpRole!.inputRelated);
  const observations = astFiles.flatMap((file) => observeFile(file, flowUses));
  const secretFindings = astFiles.filter((file) => !file.parseError).flatMap((file) => inlineSecretFindings(file.file));
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const finding of [...observations.map(findingFromObservation), ...secretFindings]) {
    const key = `${finding.location.path}:${finding.location.line}:${finding.location.column}:${finding.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(finding);
  }
  return {
    id: "source.builtin-ast",
    ...(analysisBudget && sameLimits(analysisBudget.limits, limits) ? { analysisBudget } : {}),
    status: parseErrorCount > 0 || analysis.reasons.length > 0 ? "partial" : "completed",
    findings,
    ...(analysis.analysisGaps ? { analysisGaps: analysis.analysisGaps } : {}),
    notes: [
      `Built-in AST checks parsed ${astFiles.length} JavaScript or TypeScript file${astFiles.length === 1 ? "" : "s"}.`,
      "Declared flow model: request-shaped entry parameters, same-function assignments, statically bound local functions/immutable const arrows, named relative ESM imports and constant static CommonJS destructuring exports within the collected snapshot. Source/sink API shapes are candidates, not runtime framework or database identity proof.",
      "Dynamic/package imports, namespace/default/re-exports, mutable exports, callbacks, closures and arbitrary class dispatch are model limitations. A canonical relative CommonJS local class singleton supports receiver-bound actual/body dispatch; opaque native dynamic loading retains only a declared possible body with low-confidence input and partial coverage, without return safety or runtime identity proof. Unknown external calls are not trusted sanitizers and do not alone make declared coverage incomplete. Resolved callees are not freshly seeded unless explicitly exported or passed as a callback to an unresolved/external call; callback execution and runtime entry reachability are not proven.",
      "Outbound destination qualifier covers only canonical literal HTTP(S) origin/path plus native encoded query, direct const params record/toString/append/set and scalar local transfer. Object containers, alias/escape, modified or shadowed native intrinsics and opaque options retain candidates. Options support absent or plain literal method/fixed non-Host headers only. This is initial destination control, not redirect, DNS, proxy, remote query processing or runtime SSRF safety proof.",
      'Axios request config role model separates a closed fixed INITIAL url field from payload-only input under the declared v1.13.2 API contract. Lexical imports/static require bindings and indexed snapshot validation do not authenticate runtime packages or external side effects. Defaults/interceptors/custom transport, alias/mutation, incomplete scope and opaque target roles retain low-confidence candidates; unknown is not safe. No body source is asserted to control URL authority.',
      'pg SQL role model separates supported statement text from bound values under the declared pg JS API. Default dispatch and closed statement shape are required before a text-input claim. A fixed text/values exclusion is not runtime package identity, SQL syntax validity, database-side dynamic SQL safety or confirmed remediation. Unsupported identity, mutation, prototype, native, callback and opaque value/array roles remain unknown; generic SQL/input seed behavior is retained.',
      'Bare fork spelling is not classified as a shell API when every observed invocation resolves to an immutable local/relative function and its actual analysis completes. This is not function safety: nested native/SQL/HTTP/HTML sinks remain findings. Unresolved, mutable and incomplete analysis retain the legacy heuristic and partial gate.',
      'Node fork role model recognizes declared lexical child_process bindings and only the modulePath argument. Fixed modulePath does not establish whole-call safety: argv, execPath, execArgv, cwd and env are unmodeled. Mutable/escaped/incomplete identity retains low candidates; socket dispatch and guards are not newly modeled.',
      `Budget model: one charged common indexing walk with index ${limits.indexWork ?? FLOW_LIMITS.indexWork} and flow ${limits.flowWork ?? FLOW_LIMITS.flowWork} work, plus ${limits.nodeVisits} aggregate cap. nodeVisits is total index+flow; legacy overrides remain aggregate caps. Parsed files are not fully analyzed files. Partial indexing disables immutable callee/native destination proof; known root counts do not imply complete global inventory. AST observation/render and TS parse/bind work are outside these counters.`,
      "Parser/binder and collector limits remain separate from deterministic flow-work budgets; this is not hostile-code CPU/memory isolation.",
      ...analysis.reasons.map((reason) => `Supported static analysis was incomplete: ${reason}.`),
      ...(parseErrorCount > 0 ? [`${parseErrorCount} JavaScript or TypeScript file${parseErrorCount === 1 ? "" : "s"} had syntax diagnostics; findings may be incomplete.`] : []),
    ],
    metrics: { filesAnalyzed: astFiles.length, filesParsed: astFiles.length, filesParseValid: astFiles.length - parseErrorCount, parseErrorCount, findingCount: findings.length, ...analysis.metrics, rootInventoryComplete: analysis.metrics.indexComplete === true && parseErrorCount === 0, outboundDestinationModel: "literal-http-query-native-params-v1", outboundFixedDestinationSuppressed, outboundQueryQualifiedUses: outboundUses.filter((use) => use.argumentFlows?.find((argument) => argument.index === 0)?.fixedDestination).length,
      forkRoleModel:'node-child-process-fork-v1', forkRoleRecognizedUses:forkUses.length, forkModulePathInputUses:forkInputUses.filter(use=>use.forkRole!.identity==='native').length, forkUnresolvedInputUses:forkInputUses.filter(use=>use.forkRole!.identity==='unresolved').length,
      sqlRoleModel:'pg-query-config-v1', sqlRoleBoundUses:sqlUses.filter(u=>u.sqlRole!.bound).length, sqlStatementInputUses:sqlInputUses.filter(u=>u.sqlRole!.outcome==='statement_input').length, sqlValuesOnlyExcluded:sqlInputUses.filter(u=>u.sqlRole!.outcome==='values_only_fixed_text').length, sqlRoleUnknownUses:sqlInputUses.filter(u=>u.sqlRole!.outcome==='unknown_role').length,
      outboundRoleModel: 'axios-request-config-query-v2', roleProofScopeComplete,
      outboundRoleBoundUses: roleUses.filter(use => use.httpRole!.bound).length,
      outboundEncodedQueryExcluded: candidateRoleUses.filter(use => use.httpRole!.outcome === 'encoded_query_fixed_initial_url').length,
      outboundPayloadOnlyExcluded: candidateRoleUses.filter(use => use.httpRole!.outcome === 'payload_only_fixed_initial_url').length,
      outboundTargetInputUses: candidateRoleUses.filter(use => use.httpRole!.outcome === 'target_input').length,
      outboundRoleUnknownUses: candidateRoleUses.filter(use => use.httpRole!.outcome === 'unknown_role').length },
  };
}

function sameLimits(a: AstAnalysisBudget['limits'], b: FlowLimits): boolean { return Object.entries(a).every(([key, value]) => b[key as keyof FlowLimits] === value); }
