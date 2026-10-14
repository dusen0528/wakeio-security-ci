import * as ts from "typescript";
import type { StaticFlow, StaticCandidateContext, AnalysisGap } from "../contracts.js";
import { mergeStaticContexts } from '../static-context.js';
import { AnalysisGapRecorder } from "../analysis-gaps.js";
import { FLOW_LIMITS, StaticModules, type FlowLimits, type SingletonReceiver, type CallResolution } from "./modules.js";
import { NativeQueryModel, boundedFragments, fixedQueryDestination, type UrlFragment } from "./url-destination.js";
import { ForkRoleModel, type ForkRoleUse } from './fork-role.js';
import { ProcessRoleModel, PROCESS_METHODS, type ProcessRoleUse } from './process-role.js';
import type { ChildProcessBindingUse } from './fork-role.js';
import { SqlRoleModel, type SqlRoleUse } from './sql-role.js';
import { HttpRoleModel, fixedInitialHttpUrl, legacyAxiosRequest, type HttpRoleUse } from './http-role.js';
import { ExpressRoleModel } from './express-role.js';
import { KoaRoleModel, type KoaRequestRole } from './koa-role.js';
import { HonoRoleModel, type HonoRequestRole } from './hono-role.js';
import { NoSqlRoleModel, type NoSqlRoleUse } from './nosql-role.js';
import { analyzeClosureShape, analyzeConstructedShape, type ClosureShape, type ConstructorShape, type ShapeResult } from './closure-shape.js';
import { MongoRoleModel, type MongoDbRole, type MongoCollectionRole } from './mongo-role.js';
import type { CollectedFile } from './types.js';
import { FilesystemRoleModel, type FilesystemStreamRole } from './filesystem-role.js';
import { ArchiveRoleModel, type ArchiveRole } from './archive-role.js';
import { BrowserLocationRoleModel, directBrowserLocationReceiver, type BrowserLocationRole } from './browser-location-role.js';

/** A source-to-sink use found by the bounded, same-function analysis. */
export interface InputFlowUse {
  staticContext?: StaticCandidateContext;
  node: ts.Node;
  kind: "assignment" | "call" | "jsx";
  argumentFlows?: Array<{ index: number; certainty: "tainted" | "unknown"; staticFlow?: StaticFlow; fixedDestination?: boolean }>;
  localCall?: boolean;
  /** Internal sink shape only; framework identity and runtime rendering stay unverified. */
  htmlResponse?: "express" | "web";
  htmlResponseMime?: "default" | "html" | "unknown";
  /** Entry-model authority only; never runtime request or response identity. */
  htmlResponseAuthority?: 'registered_express' | 'unqualified_response';
  httpRole?: HttpRoleUse;
  browserLocationRole?: BrowserLocationRole;
  sqlRole?: SqlRoleUse;
  nosqlRole?: NoSqlRoleUse;
  forkRole?: ForkRoleUse;
  processRole?: ProcessRoleUse;
  filesystemProcess?: { outcome: 'argv_shell_input' | 'argv_shell_unknown' | 'direct_argv_interpreter_unknown' | 'argv_only_shell_disabled'; staticFlow?: StaticFlow };
  archiveWrite?: { outcome: 'path_input' | 'path_role_unknown' | 'lexically_contained'; staticFlow?: StaticFlow };
  /** Scan-local monotonic actual-analysis proof; never general callable safety. */
  localForkCall?: { complete: boolean };
  localProcessCall?: { complete: boolean };
}

type RootKind =
  | "request"
  | "params"
  | "query"
  | "body"
  | "headers"
  | "location"
  | "window"
  | "event"
  | "formData"
  | "searchParams";

type ExpressMime = "default" | "html" | "non_html" | "unknown";
interface ExpressResponseState {
  readonly identity: object;
  authority: 'registered_express' | 'unqualified_response';
  mime: ExpressMime;
  valid: boolean;
  /** General container/heap alias effects are outside the MIME exclusion proof. */
  contained?: boolean;
}

function joinResponse(left?: ExpressResponseState, right?: ExpressResponseState): ExpressResponseState | undefined {
  return left && right && left.identity === right.identity
    ? { identity: left.identity, authority: left.authority === 'registered_express' && right.authority === 'registered_express' ? 'registered_express' : 'unqualified_response', mime: left.mime === right.mime ? left.mime : "unknown", valid: left.valid && right.valid, contained: left.contained || right.contained }
    : undefined;
}

function containResponse(value: FlowValue): void {
  if (!value.expressResponse) return;
  value.expressResponse.contained = true;
  value.expressResponse.authority = 'unqualified_response';
  // Retain the positive HTML candidate, but never a stale non-HTML exclusion.
  if (value.expressResponse.mime !== "html") value.expressResponse.mime = "unknown";
}

interface FlowValue {
  koaRequest?: KoaRequestRole;
  honoRequest?: HonoRequestRole;
  /** Qualified request-return data only; never changes input taint or SQL dispatch. */
  honoSqlData?: 'request_data' | 'json_promise';
  traceSourceKind?: StaticFlow['sourceKind'];
  archiveRole?: ArchiveRole;
  /** Independent path-origin witness when another input wins the general trace. */
  archiveContent?: FlowValue;
  filesystemStream?: FilesystemStreamRole;
  /** Separate filename subset prevents mixed HTTP traces from being tagged as filenames. */
  filesystemContent?: FlowValue;
  sequenceContent?: { value: FlowValue; filename: FlowValue; node: ts.Node; closed: boolean; valid: boolean };
  staticContext?: StaticCandidateContext;
  /** Unknown return alternatives only; never seeded into a hypothesized body. */
  boundaryInput?: FlowValue;
  kind: "safe" | "unknown" | "tainted" | "root";
  expressResponse?: ExpressResponseState;
  /** Object/array literal type for Express default JSON serialization only. */
  expressObjectBody?: boolean;
  root?: RootKind;
  inputRelated?: boolean;
  properties?: ReadonlyMap<string, FlowValue>;
  /** NoSQL-only monotonic literal/alias content; never general taint safety. */
  nosqlObject?: { node: ts.ObjectLiteralExpression; value: FlowValue; modified: boolean; closed: boolean };
  nosqlUnknown?: FlowValue;
  callable?: { target: ts.ArrowFunction; captures: ReadonlyMap<ts.Symbol, FlowValue>; lexicalThis?: FlowValue; identity: number; valid?: boolean; staticContext?: StaticCandidateContext; boundaryInput?: FlowValue };
  opaqueClosure?: FlowValue;
  constructed?: { valid: boolean; shape: ConstructorShape; slots: Map<string, FlowValue>; staticContext?: StaticCandidateContext };
  nosqlWhere?: { node: ts.Node; value: FlowValue };
  mongoDb?: MongoDbRole;
  mongoCollection?: MongoCollectionRole;
  trace?: StaticFlow["steps"];
  traceTruncated?: boolean;
  urlFragments?: readonly UrlFragment[];
  nativeQuery?: boolean;
  queryContent?: { value: QueryContent };
  /** HTTP config target proof is unavailable; not general taint or a direct URL veto. */
  httpTargetUnavailable?: boolean;
  sqlScalarUnavailable?: boolean;
  /** All supported scalar outcomes are fixed strings; no literal contents are retained here. */
  sqlFixedText?: { readonly maxCharacters: number };
  sqlCallback?: boolean;
  sqlDataUnavailable?: boolean;
  sqlArray?: { node: ts.ArrayLiteralExpression; closed: boolean; count: number };
  sqlConfig?: { node: ts.ObjectLiteralExpression; closed: boolean; text: FlowValue; values?: FlowValue };
  httpConfig?: { node: ts.ObjectLiteralExpression; closed: boolean; fixedInitialUrl: boolean; encodedQueryInitialUrl: boolean; target: FlowValue };
}
type QueryContent = Pick<FlowValue, 'kind' | 'root' | 'inputRelated' | 'trace' | 'traceTruncated' | 'traceSourceKind' | 'httpTargetUnavailable'>;
function queryContent(value: FlowValue): QueryContent {
  const current = currentQuery(value);
  return { kind: current.kind, root: current.root, inputRelated: current.inputRelated, trace: current.trace, traceTruncated: current.traceTruncated, traceSourceKind: current.traceSourceKind, httpTargetUnavailable: current.httpTargetUnavailable };
}
function currentQuery(value: FlowValue): FlowValue {
  if (!value.queryContent) return value;
  const content = value.queryContent.value;
  return { ...value, kind: isInputRelated(content) ? 'root' : content.kind, root: isInputRelated(content) ? 'searchParams' : undefined,
    inputRelated: content.inputRelated, trace: content.trace, traceTruncated: content.traceTruncated,
    traceSourceKind: content.traceSourceKind,
    httpTargetUnavailable: value.httpTargetUnavailable || content.httpTargetUnavailable };
}

/** Negative HTTP proof only; preserve query wrapper and content-cell invalidation. */
function httpUnavailable(values: readonly FlowValue[]): boolean {
  return values.some(value => value.httpTargetUnavailable || value.queryContent?.value.httpTargetUnavailable);
}
function withHttpUnavailable(value: FlowValue, values: readonly FlowValue[]): FlowValue {
  return { ...value, httpTargetUnavailable: httpUnavailable([value, ...values]) };
}

function step(node: ts.Node, role: StaticFlow["steps"][number]["role"]): StaticFlow["steps"][number] {
  const file = node.getSourceFile();
  const position = file.getLineAndCharacterOfPosition(node.getStart(file));
  return { role, location: { path: file.fileName, line: position.line + 1, column: position.character + 1 } };
}

function traced(value: FlowValue, node: ts.Node, role: StaticFlow["steps"][number]["role"]): FlowValue {
  if (!isInputRelated(value)) return value;
  const next = step(node, role);
  const previous = value.trace ?? [];
  if (JSON.stringify(previous.at(-1)) === JSON.stringify(next)) return value;
  const steps = [...previous, next];
  const truncated = value.traceTruncated || steps.length > FLOW_LIMITS.traceSteps;
  // Keep the real endpoint while exposing omission. Never invent missing hops.
  return { ...value, ...(value.archiveContent ? { archiveContent: traced(value.archiveContent, node, role) } : {}), ...(value.nosqlWhere ? { nosqlWhere: { ...value.nosqlWhere, value: traced(value.nosqlWhere.value, node, role) } } : {}), trace: steps.length > FLOW_LIMITS.traceSteps
    ? [...steps.slice(0, FLOW_LIMITS.traceSteps - 1), next] : steps, traceTruncated: Boolean(truncated) };
}

function inheritTrace(value: FlowValue, values: readonly FlowValue[]): FlowValue {
  const evidence = values.find((candidate) => candidate.kind === "tainted" && candidate.trace?.length)
    ?? values.find((candidate) => isInputRelated(candidate) && candidate.trace?.length);
  const staticContext = contexts(value.staticContext, ...values.map(item => item.staticContext));
  return { ...value, ...(evidence ? { trace: evidence.trace, traceTruncated: evidence.traceTruncated, traceSourceKind: evidence.traceSourceKind } : {}), ...(staticContext ? { staticContext } : {}) };
}

function contexts(...values: Array<StaticCandidateContext | undefined>): StaticCandidateContext | undefined {
  return values.reduce<StaticCandidateContext | undefined>((left, right) => mergeStaticContexts(left, right), undefined);
}
function conditionalContext(kind: StaticCandidateContext['items'][number]['kind'], node: ts.Node, target?: ts.Node): StaticCandidateContext {
  return { revision: 'static-context-v1', authority: 'conditional', truncated: false,
    items: [{ kind, location: step(node, 'call').location, ...(target ? { target: step(target, 'call').location } : {}) }] };
}
function withContext(value: FlowValue, context?: StaticCandidateContext): FlowValue {
  const staticContext = contexts(value.staticContext, context);
  return staticContext ? { ...value, staticContext } : value;
}
function consumedInput(value: FlowValue): FlowValue {
  if (value.sequenceContent) {
    const sequence = value.sequenceContent;
    value = { ...combineValues([{ ...value, sequenceContent: undefined }, sequence.value]), sequenceContent: sequence,
      filesystemContent: sequence.filename };
  }
  return value.boundaryInput ? inheritTrace(combineValues([value, value.boundaryInput]), [value, value.boundaryInput]) : value;
}
function filenamePart(value: FlowValue): FlowValue | undefined {
  const part = value.sequenceContent?.filename ?? value.filesystemContent;
  if (part && isInputRelated(part)) return part;
  return value.traceSourceKind === 'filesystem_filename' && isInputRelated(value)
    ? { ...value, sequenceContent: undefined, filesystemContent: undefined } : undefined;
}
function archivePart(value: FlowValue): FlowValue | undefined {
  if (value.archiveContent && isInputRelated(value.archiveContent)) return value.archiveContent;
  return value.traceSourceKind === 'archive_entry_path' && isInputRelated(value)
    ? { ...value, archiveContent: undefined } : undefined;
}
function invalidateMongo(role: MongoDbRole | MongoCollectionRole | undefined, reason: 'opaque' | 'write'): void {
  if (!role) return;
  role.valid = false;
  if (!role.invalidReason || role.invalidReason === 'opaque' || reason === 'write') role.invalidReason = reason;
}

function invalidateHono(role: HonoRequestRole): void {
  role.state.valid = false;
  role.state.jsonDataValid = false;
  if (role.jsonSourceState) role.jsonSourceState.jsonDataValid = false;
}

function evidence(value: FlowValue, node: ts.Node): StaticFlow | undefined {
  if (!value.trace?.some((item) => item.role === "source")) return undefined;
  const output = traced(value, node, "sink");
  return output.trace?.length ? { kind: "static_flow", steps: output.trace,
    ...(output.traceSourceKind ? { sourceKind: output.traceSourceKind } : {}), truncated: !!value.staticContext || (output.traceTruncated ?? false) } : undefined;
}

function evaluationShapedCallee(callee: ts.Expression, constructor = false): boolean {
  if (ts.isIdentifier(callee)) return callee.text === 'Function' || !constructor && callee.text === 'eval';
  if ((ts.isPropertyAccessExpression(callee) || !constructor && ts.isElementAccessExpression(callee))
    && ts.isIdentifier(callee.expression) && callee.expression.text === 'window') {
    const name = ts.isPropertyAccessExpression(callee) ? callee.name.text
      : ts.isStringLiteral(callee.argumentExpression) || ts.isNoSubstitutionTemplateLiteral(callee.argumentExpression) ? callee.argumentExpression.text : undefined;
    return name === 'Function' || !constructor && name === 'eval';
  }
  return false;
}

const SAFE: FlowValue = { kind: "safe" };
const UNKNOWN: FlowValue = { kind: "unknown" };
const TAINTED: FlowValue = { kind: "tainted" };
const UNKNOWN_INPUT: FlowValue = { kind: "unknown", inputRelated: true };

const SQL_FIXED_TEXT_CHARACTERS = 2048;
function fixedSqlCharacters(value: FlowValue): number | undefined {
  const maximum = value.sqlFixedText?.maxCharacters;
  return value.kind === 'safe' && !isInputRelated(value) && !value.sqlScalarUnavailable
    && Number.isSafeInteger(maximum) && maximum! >= 0 && maximum! <= SQL_FIXED_TEXT_CHARACTERS ? maximum : undefined;
}
function literalValue(text: string): FlowValue {
  return { ...SAFE, urlFragments: boundedFragments([{ literal: text }]),
    ...(text.length <= SQL_FIXED_TEXT_CHARACTERS ? { sqlFixedText: { maxCharacters: text.length } } : {}) };
}

const ASSIGNMENT_OPERATORS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken,
  ts.SyntaxKind.AsteriskAsteriskEqualsToken,
  ts.SyntaxKind.SlashEqualsToken,
  ts.SyntaxKind.PercentEqualsToken,
  ts.SyntaxKind.LessThanLessThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.AmpersandEqualsToken,
  ts.SyntaxKind.BarEqualsToken,
  ts.SyntaxKind.CaretEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
]);

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return ASSIGNMENT_OPERATORS.has(kind);
}

function isSimpleAssignment(kind: ts.SyntaxKind): boolean {
  return kind === ts.SyntaxKind.EqualsToken;
}

function sourceRootForName(name: string): RootKind | undefined {
  switch (name) {
    case "req":
    case "request":
      return "request";
    case "params":
      return "params";
    case "query":
      return "query";
    case "body":
      return "body";
    case "headers":
      return "headers";
    case "location":
      return "location";
    case "window":
      return "window";
    case "event":
      return "event";
    case "formData":
      return "formData";
    case "searchParams":
      return "searchParams";
    default:
      return undefined;
  }
}

function rootValue(root: RootKind): FlowValue {
  return { kind: "root", root };
}

function rootProperty(root: RootKind, property: string): FlowValue {
  switch (root) {
    case "request":
      return ["query", "body", "params", "url", "headers", "nextUrl"].includes(property)
        ? TAINTED
        : UNKNOWN_INPUT;
    case "params":
      return TAINTED;
    case "query":
    case "body":
    case "headers":
      return TAINTED;
    case "location":
      return ["search", "hash", "href"].includes(property) ? TAINTED : UNKNOWN_INPUT;
    case "window":
      return property === "name" ? TAINTED : UNKNOWN_INPUT;
    case "event":
      return property === "data" ? TAINTED : UNKNOWN_INPUT;
    case "formData":
    case "searchParams":
      return UNKNOWN_INPUT;
    default:
      return UNKNOWN_INPUT;
  }
}

function propertyName(node: ts.PropertyName | ts.Expression | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) return node.text;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isNumericLiteral(node)) return node.text;
  return undefined;
}

function staticMemberPath(expression: ts.Expression): string[] {
  if (ts.isIdentifier(expression)) return [expression.text];
  if (ts.isPropertyAccessExpression(expression)) return [...staticMemberPath(expression.expression), expression.name.text];
  if (ts.isElementAccessExpression(expression)) {
    const property = propertyName(expression.argumentExpression);
    return property === undefined ? [] : [...staticMemberPath(expression.expression), property];
  }
  return [];
}

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node)
    || ts.isMethodDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node)
    || ts.isConstructorDeclaration(node);
}

function joinValues(left: FlowValue, right: FlowValue): FlowValue {
  const sharedQueryContent = left.queryContent === right.queryContent ? left.queryContent : undefined;
  left = currentQuery(left); right = currentQuery(right);
  const propertyNames = new Set<string>([
    ...left.properties?.keys() ?? [],
    ...right.properties?.keys() ?? [],
  ]);
  const properties = propertyNames.size > 0
    ? new Map([...propertyNames].map((name) => [
        name,
        joinValues(left.properties?.get(name) ?? UNKNOWN, right.properties?.get(name) ?? UNKNOWN),
      ] as [string, FlowValue]))
    : undefined;
  const withProperties = (value: FlowValue): FlowValue => {
    const result = inheritTrace(value, [left, right]);
    const changed = [left.nosqlUnknown, right.nosqlUnknown,
      ...(left.nosqlObject?.modified ? [left.nosqlObject.value] : []), ...(right.nosqlObject?.modified ? [right.nosqlObject.value] : [])].filter((item): item is FlowValue => !!item);
    const nosqlUnknown = changed.length ? combineValues(changed) : undefined;
    const a = left.nosqlWhere, b = right.nosqlWhere;
    const nosqlWhere = a && b ? a.node === b.node ? { node: a.node, value: joinValues(a.value, b.value) }
      : !isInputRelated(a.value) && isInputRelated(b.value) || a.value.kind !== 'tainted' && b.value.kind === 'tainted' ? b : a : a ?? b;
    const urlFragments = left.urlFragments && right.urlFragments && JSON.stringify(left.urlFragments) === JSON.stringify(right.urlFragments) ? left.urlFragments : undefined;
    // node is construction AST provenance, not a network URL origin. Never
    // certify a union of URL alternatives after exact fragments were lost.
    const joinedTarget = left.httpConfig && right.httpConfig && left.httpConfig.node === right.httpConfig.node
      ? joinValues(left.httpConfig.target, right.httpConfig.target) : undefined;
    const httpConfig = joinedTarget && left.httpConfig && right.httpConfig
      ? { node: left.httpConfig.node, closed: left.httpConfig.closed && right.httpConfig.closed,
        fixedInitialUrl: left.httpConfig.fixedInitialUrl && right.httpConfig.fixedInitialUrl,
        encodedQueryInitialUrl: left.httpConfig.encodedQueryInitialUrl && right.httpConfig.encodedQueryInitialUrl
          && !joinedTarget.httpTargetUnavailable && fixedQueryDestination(joinedTarget.urlFragments),
        target: joinedTarget } : undefined;
    const sqlArray = left.sqlArray && right.sqlArray && left.sqlArray.node === right.sqlArray.node
      ? { node:left.sqlArray.node, closed:left.sqlArray.closed && right.sqlArray.closed, count:left.sqlArray.count } : undefined;
    const sqlConfig = left.sqlConfig && right.sqlConfig && left.sqlConfig.node === right.sqlConfig.node
      ? { node:left.sqlConfig.node, closed:left.sqlConfig.closed && right.sqlConfig.closed, text:joinValues(left.sqlConfig.text,right.sqlConfig.text),
        values:left.sqlConfig.values && right.sqlConfig.values ? joinValues(left.sqlConfig.values,right.sqlConfig.values) : undefined } : undefined;
    const leftCharacters = fixedSqlCharacters(left), rightCharacters = fixedSqlCharacters(right);
    const sqlFixedText = leftCharacters !== undefined && rightCharacters !== undefined
      ? { maxCharacters: Math.max(leftCharacters, rightCharacters) } : undefined;
    // Different observed capabilities cannot certify dispatch. Retain an invalid
    // witness so consuming an unsupported union cannot silently become clean.
    const db = left.mongoDb ?? right.mongoDb, collection = left.mongoCollection ?? right.mongoCollection;
    const mongoDb = left.mongoDb === right.mongoDb ? left.mongoDb : db ? { ...db, valid: false, invalidReason: 'ambiguous' as const } : undefined;
    const mongoCollection = left.mongoCollection === right.mongoCollection ? left.mongoCollection : collection ? { ...collection, valid: false, invalidReason: 'ambiguous' as const } : undefined;
    const sequenceContent = left.sequenceContent === right.sequenceContent ? left.sequenceContent : undefined;
    const filesystemStream = left.filesystemStream === right.filesystemStream ? left.filesystemStream : undefined;
    const filenameValues = [filenamePart(left), filenamePart(right)].filter((value): value is FlowValue => !!value);
    const filesystemContent = filenameValues.length ? combineValues(filenameValues) : undefined;
    const archiveValues = [archivePart(left), archivePart(right)].filter((part): part is FlowValue => !!part);
    result.archiveContent = archiveValues.length ? inheritTrace(UNKNOWN_INPUT, archiveValues) : undefined;
    const archiveRole = left.archiveRole ?? right.archiveRole;
    result.archiveRole = left.archiveRole === right.archiveRole ? left.archiveRole
      : archiveRole ? { ...archiveRole, state: { valid: false } } : undefined;
    const koaRole = left.koaRequest ?? right.koaRequest;
    result.koaRequest = left.koaRequest?.state === right.koaRequest?.state && left.koaRequest?.stage === right.koaRequest?.stage
      ? left.koaRequest : koaRole ? { ...koaRole, state: { valid: false } } : undefined;
    const honoRole = left.honoRequest ?? right.honoRequest;
    result.honoRequest = left.honoRequest?.state === right.honoRequest?.state && left.honoRequest?.stage === right.honoRequest?.stage
      ? left.honoRequest : honoRole ? { ...honoRole, state: { valid: false } } : undefined;
    return { ...result, sequenceContent, filesystemStream, filesystemContent, expressResponse: joinResponse(left.expressResponse, right.expressResponse), nosqlObject: left.nosqlObject === right.nosqlObject ? left.nosqlObject : undefined, nosqlUnknown, nosqlWhere, mongoDb, mongoCollection, expressObjectBody: left.expressObjectBody === true && right.expressObjectBody === true, ...(properties ? { properties } : {}), sqlFixedText, sqlArray, sqlConfig, sqlScalarUnavailable:left.sqlScalarUnavailable || right.sqlScalarUnavailable, sqlCallback:left.sqlCallback || right.sqlCallback, sqlDataUnavailable:left.sqlDataUnavailable || right.sqlDataUnavailable, httpTargetUnavailable:httpUnavailable([left,right]), urlFragments, nativeQuery: left.nativeQuery === true && right.nativeQuery === true, queryContent: sharedQueryContent, httpConfig };
  };
  if (left.kind === right.kind && (left.kind !== "root" || left.root === right.root)) {
    if (left.kind === "root") return withProperties(left);
    if (left.kind === "unknown" && (left.inputRelated || right.inputRelated)) return withProperties(UNKNOWN_INPUT);
    return withProperties({ kind: left.kind });
  }
  return withProperties(isInputRelated(left) || isInputRelated(right) ? UNKNOWN_INPUT : UNKNOWN);
}

function combineValues(values: readonly FlowValue[]): FlowValue {
  const value=values.some((value) => value.kind === "tainted") ? inheritTrace(TAINTED, values)
    : values.some((value) => isInputRelated(value)) ? inheritTrace(UNKNOWN_INPUT, values)
    : values.some((value) => value.kind === "root" || value.kind === "unknown") ? UNKNOWN : SAFE;
  const archiveValues = values.map(archivePart).filter((part): part is FlowValue => !!part);
  const archiveContent = archiveValues.length ? inheritTrace(UNKNOWN_INPUT, archiveValues) : undefined;
  return {...value, archiveContent, sqlDataUnavailable:values.some(v=>v.sqlDataUnavailable || v.sqlCallback), httpTargetUnavailable:httpUnavailable(values)};
}

function concatValues(values: readonly FlowValue[]): FlowValue {
  const result = combineValues(values);
  const fragments = values.every((value) => value.urlFragments) ? boundedFragments(values.flatMap((value) => [...value.urlFragments!])) : undefined;
  let maximum = 0;
  let qualified = values.length > 0;
  for (const value of values) {
    const characters = fixedSqlCharacters(value);
    if (characters === undefined || characters > SQL_FIXED_TEXT_CHARACTERS - maximum) { qualified = false; break; }
    maximum += characters;
  }
  return { ...result, ...(qualified ? { sqlFixedText: { maxCharacters: maximum } } : {}), urlFragments: fragments, sqlScalarUnavailable:values.some(v=>v.sqlScalarUnavailable) };
}

function isInputRelated(value: FlowValue): boolean {
  if (value.queryContent) return isInputRelated(value.queryContent.value);
  return value.kind === "tainted" || value.kind === "root" || value.inputRelated === true;
}

function withoutUrlProof(value: FlowValue): FlowValue {
  return { ...value, urlFragments: undefined, nativeQuery: undefined, httpConfig: undefined, sqlFixedText:undefined, sqlConfig:undefined, sqlArray:undefined,
    properties: value.properties ? new Map([...value.properties].map(([key, item]) => [key, withoutUrlProof(item)])) : undefined };
}

function projectValue(base: FlowValue, property: string): FlowValue {
  if (base.honoRequest) {
    const known = base.properties?.get(property);
    if (known) return known;
    const role = base.honoRequest;
    if (role.state.valid && role.stage === 'context' && property === 'req') return { ...UNKNOWN, honoRequest: { ...role, stage: 'request' } };
    return UNKNOWN; // Method reads/detached aliases and unresolved Context fields are not input.
  }
  if (base.koaRequest) {
    const known = base.properties?.get(property);
    if (known) return known;
    const role = base.koaRequest;
    if (!role.state.valid) return UNKNOWN;
    if (role.stage === 'context' && property === 'request') return { ...UNKNOWN, koaRequest: { ...role, stage: 'request' } };
    if (role.stage === 'context' || role.stage === 'request') {
      if (property === 'query' || property === 'header' || property === 'headers') return {
        ...rootValue(property === 'query' ? 'query' : 'headers'),
        koaRequest: { ...role, stage: 'input' },
      };
      return ['querystring', 'url', 'originalUrl', 'path'].includes(property) ? TAINTED : UNKNOWN;
    }
    if (role.stage === 'next') return UNKNOWN;
  }
  if (base.archiveRole?.state.valid) {
    const role = base.archiveRole;
    if (role.stage === 'directory' && property === 'files') return { ...UNKNOWN, archiveRole: { ...role, stage: 'files' } };
    if (role.stage === 'files' && (property === '*' || /^\d+$/.test(property))) return { ...UNKNOWN, archiveRole: { ...role, stage: 'entry' } };
    return UNKNOWN; // Neither entry content nor the whole record is a path input.
  }
  const propertyValue = base.properties?.get(property);
  const value = propertyValue ?? (base.kind === "root" && base.root ? inheritTrace(rootProperty(base.root, property), [base])
    : base.kind === "tainted" ? inheritTrace(TAINTED, [base]) : base.kind === "safe" ? SAFE
    : base.inputRelated ? inheritTrace(UNKNOWN_INPUT, [base]) : UNKNOWN);
  return {...value,sqlDataUnavailable:base.sqlDataUnavailable || value.sqlDataUnavailable, httpTargetUnavailable:httpUnavailable([base,value])};
}

function functionBody(functionLike: ts.FunctionLikeDeclaration): ts.Block | ts.Expression | undefined {
  const body = functionLike.body;
  return body;
}

class FlowEnv {
  private readonly scopes: Map<string, FlowValue>[];
  private readonly symbols: Map<ts.Symbol, string>[];
  terminated = false;

  constructor(scopes?: Map<string, FlowValue>[], symbols?: Map<ts.Symbol, string>[]) {
    this.scopes = scopes ?? [new Map<string, FlowValue>()];
    this.symbols = symbols ?? [new Map()];
  }

  clone(): FlowEnv {
    // Copy MIME state per control-flow branch while preserving direct aliases.
    const states = new Map<ExpressResponseState, ExpressResponseState>();
    const clone = (value: FlowValue): FlowValue => {
      if (!value.expressResponse) return value;
      let state = states.get(value.expressResponse);
      if (!state) { state = { ...value.expressResponse }; states.set(value.expressResponse, state); }
      return { ...value, expressResponse: state };
    };
    const env = new FlowEnv(this.scopes.map((scope) => new Map([...scope].map(([key, value]) => [key, clone(value)]))), this.symbols.map(scope => new Map(scope)));
    env.terminated = this.terminated;
    return env;
  }

  push(): void {
    this.scopes.push(new Map<string, FlowValue>());
    this.symbols.push(new Map());
  }

  pop(): void {
    if (this.scopes.length > 1) { this.scopes.pop(); this.symbols.pop(); }
  }

  declare(name: string, value: FlowValue, blockScoped: boolean, symbol?: ts.Symbol): void {
    const index = blockScoped ? this.scopes.length - 1 : 0;
    this.scopes[index].set(name, value);
    if (symbol) this.symbols[index].set(symbol, name);
  }

  captured(symbol: ts.Symbol): FlowValue | undefined {
    for (let index = this.symbols.length - 1; index >= 0; index--) {
      const name = this.symbols[index].get(symbol);
      if (name !== undefined) return this.scopes[index].get(name);
    }
    return undefined;
  }

  assign(name: string, value: FlowValue): void {
    for (let index = this.scopes.length - 1; index >= 0; index -= 1) {
      if (this.scopes[index].has(name)) {
        this.scopes[index].set(name, value);
        return;
      }
    }
    this.scopes[this.scopes.length - 1].set(name, value);
  }

  /** Preserve a bounded object property assignment for later sink checks. */
  assignProperty(path: readonly string[], value: FlowValue): void {
    if (path.length < 2) {
      if (path.length === 1) this.assign(path[0], value);
      return;
    }
    containResponse(value);
    const update = (base: FlowValue, index: number): FlowValue => {
      const property = path[index];
      const properties = new Map(base.properties ?? []);
      if (index === path.length - 1) {
        properties.set(property, value);
      } else {
        properties.set(property, update(properties.get(property) ?? (base.koaRequest || base.honoRequest ? projectValue(base, property) : UNKNOWN), index + 1));
      }
      const combined = combineValues([base, value]);
      if (base.nosqlObject) {
        base.nosqlObject.value = combineValues([base.nosqlObject.value, value]);
        base.nosqlObject.modified = true;
      }
      // These documented data fields do not replace the response API shape.
      // Unknown API writes (including send/status/prototype) invalidate it.
      const benignResponseWrite = index === 1 && ['locals', 'statusCode', 'statusMessage'].includes(property);
      if (base.expressResponse && !benignResponseWrite) base.expressResponse.valid = false;
      const expressResponse = benignResponseWrite ? base.expressResponse : undefined;
      const benignKoaWrite = base.koaRequest?.stage === 'context' && ['body', 'state', 'status', 'type', 'response'].includes(property);
      if (base.koaRequest && !benignKoaWrite) base.koaRequest.state.valid = false;
      const benignHonoWrite = base.honoRequest?.stage === 'context' && property === 'res';
      if (base.honoRequest && !benignHonoWrite) base.honoRequest.state.valid = false;
      if (base.honoRequest?.stage === 'request') base.honoRequest.state.jsonDataValid = false;
      if (base.constructed) base.constructed.valid = false;
      if (base.archiveRole) base.archiveRole.state.valid = false;
      invalidateMongo(base.mongoDb, 'write');
      invalidateMongo(base.mongoCollection, 'write');
      return { ...combined, koaRequest: base.koaRequest, honoRequest: base.honoRequest, expressResponse, expressObjectBody: base.expressObjectBody, properties, nosqlObject: base.nosqlObject, constructed: base.constructed, mongoDb: base.mongoDb, mongoCollection: base.mongoCollection };
    };
    this.assign(path[0], update(this.resolve(path[0]), 1));
  }

  resolve(name: string): FlowValue {
    for (let index = this.scopes.length - 1; index >= 0; index -= 1) {
      const value = this.scopes[index].get(name);
      if (value) return value;
    }
    const root = sourceRootForName(name);
    return root ? rootValue(root) : UNKNOWN;
  }

  has(name: string): boolean { return this.scopes.some((scope) => scope.has(name)); }

  merge(branches: readonly FlowEnv[]): void {
    const live = branches.filter((branch) => !branch.terminated);
    if (live.length === 0) { this.terminated = true; return; }
    branches = live;
    const responseStates = new Map<object, ExpressResponseState>();
    for (const scope of this.scopes) for (const value of scope.values()) {
      if (value.expressResponse) responseStates.set(value.expressResponse.identity, value.expressResponse);
    }
    for (let depth = 0; depth < this.scopes.length; depth += 1) {
      const names = new Set<string>(this.scopes[depth].keys());
      for (const branch of branches) {
        for (const name of branch.scopes[depth]?.keys() ?? []) names.add(name);
      }
      for (const name of names) {
        const values = branches.map((branch) => branch.scopes[depth]?.get(name) ?? this.scopes[depth].get(name) ?? UNKNOWN);
        const joined = values.reduce(joinValues);
        if (joined.expressResponse) {
          const state = responseStates.get(joined.expressResponse.identity) ?? joined.expressResponse;
          state.mime = joined.expressResponse.mime; state.valid = joined.expressResponse.valid;
          state.authority = joined.expressResponse.authority;
          state.contained = joined.expressResponse.contained;
          responseStates.set(state.identity, state);
          joined.expressResponse = state;
        }
        this.scopes[depth].set(name, joined);
      }
    }
  }
}

function isBindingPattern(node: ts.Node): node is ts.ObjectBindingPattern | ts.ArrayBindingPattern {
  return ts.isObjectBindingPattern(node) || ts.isArrayBindingPattern(node);
}

function isAssignmentPattern(node: ts.Node): node is ts.ObjectLiteralExpression | ts.ArrayLiteralExpression {
  return ts.isObjectLiteralExpression(node) || ts.isArrayLiteralExpression(node);
}

function isSupportedBindingTarget(node: ts.Node): node is ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression {
  return ts.isIdentifier(node)
    || ts.isObjectBindingPattern(node)
    || ts.isArrayBindingPattern(node)
    || ts.isObjectLiteralExpression(node)
    || ts.isArrayLiteralExpression(node);
}

/** Only an actual node belonging to this collected source object has a position. */
export interface ParseFileEvidence { location?: AnalysisGap['location']; diagnosticCode?: number; }

export function observedGapLocation(node: ts.Node, files: ReadonlyMap<string, ts.SourceFile>): AnalysisGap['location'] | undefined {
  try {
    const file = node.getSourceFile();
    if (!file || files.get(file.fileName) !== file) return undefined;
    const start = node.getStart(file); const end = node.getEnd();
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || start >= file.text.length
      || end <= start || end > file.text.length) return undefined;
    const position = file.getLineAndCharacterOfPosition(start);
    return { path: file.fileName, line: position.line + 1, column: position.character + 1 };
  } catch { return undefined; }
}

interface FunctionSummary { returned: FlowValue; }
interface ConfiguredInspection {
  call: ts.CallExpression;
  target: ts.FunctionLikeDeclaration;
  actuals: readonly FlowValue[];
  context: StaticCandidateContext;
  ancestors: readonly string[];
  identity: string;
}
// Mutable content must not be reused through a cached return or skipped side effect.
function hasMutableQuery(value: FlowValue, seen = new Set<FlowValue>(), depth = 0): boolean {
  if (value.koaRequest || value.honoRequest) return true;
  if (value.archiveRole || value.archiveContent) return true;
  if (value.sequenceContent || value.filesystemStream || value.staticContext || value.boundaryInput || value.expressResponse || value.queryContent || value.nosqlObject || value.nosqlUnknown || value.callable || value.constructed || value.mongoDb || value.mongoCollection || seen.has(value) || depth > 16 || seen.size > 128) return true;
  seen.add(value);
  return [...value.properties?.values() ?? []].some((item) => hasMutableQuery(item, seen, depth + 1));
}

function contextValue(value: FlowValue): unknown {
  return [value.kind, value.root, value.expressResponse ? [value.expressResponse.authority, value.expressResponse.mime, value.expressResponse.valid, value.expressResponse.contained] : undefined, value.expressObjectBody, value.inputRelated, value.trace, value.traceTruncated, value.urlFragments, value.nativeQuery, value.queryContent ? queryContent(value) : undefined,
    value.httpTargetUnavailable, value.sqlScalarUnavailable, value.sqlFixedText?.maxCharacters, value.sqlCallback, value.sqlDataUnavailable, value.sqlArray ? [value.sqlArray.node.getSourceFile().fileName,value.sqlArray.node.pos,value.sqlArray.closed,value.sqlArray.count] : undefined,
    value.sqlConfig ? [value.sqlConfig.node.getSourceFile().fileName,value.sqlConfig.node.pos,value.sqlConfig.closed,contextValue(value.sqlConfig.text),value.sqlConfig.values ? contextValue(value.sqlConfig.values) : undefined] : undefined,
    value.httpConfig ? [value.httpConfig.node.getSourceFile().fileName, value.httpConfig.node.pos, value.httpConfig.closed,
      value.httpConfig.fixedInitialUrl, value.httpConfig.encodedQueryInitialUrl, contextValue(value.httpConfig.target)] : undefined,
    value.properties ? [...value.properties].sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => [key, contextValue(item)]) : undefined];
}

/** Scan-local, argument-specific summaries; cache identity includes concrete origins. */
class FlowSession {
  readonly uses: InputFlowUse[] = [];
  readonly diagnostics = new AnalysisGapRecorder();
  readonly reasons = new Set<string>();
  readonly modules: StaticModules;
  readonly queryModel: NativeQueryModel;
  readonly httpModel: HttpRoleModel;
  readonly sqlModel: SqlRoleModel;
  readonly nosqlModel: NoSqlRoleModel;
  readonly mongoModel: MongoRoleModel;
  readonly forkModel: ForkRoleModel;
  readonly processModel: ProcessRoleModel;
  readonly filesystemModel: FilesystemRoleModel;
  readonly archiveModel: ArchiveRoleModel;
  readonly expressModel: ExpressRoleModel;
  readonly koaModel: KoaRoleModel;
  readonly honoModel: HonoRoleModel;
  readonly browserLocationModel: BrowserLocationRoleModel;
  readonly active = new Set<string>();
  readonly cache = new Map<string, FunctionSummary>();
  readonly localForkCalls = new WeakMap<ts.CallExpression, { complete: boolean }>();
  private readonly closureShapes = new WeakMap<ts.ArrowFunction, ShapeResult<ClosureShape>>();
  private readonly constructorShapes = new WeakMap<ts.FunctionLikeDeclaration, ShapeResult<ConstructorShape>>();
  private capabilityIdentity = 0;
  indexWork = 0;
  flowWork = 0;
  readonly maxIndexWork: number;
  readonly maxFlowWork: number;
  indexComplete = true;
  private phase: 'index' | 'flow' = 'index';
  private incompleteEvents = 0;
  topLevelStarted = 0; topLevelCompleted = 0; topLevelPartial = 0; topLevelSkipped = 0;
  entryRootsDeclared = 0; entryRootsStarted = 0; entryRootsCompleted = 0; entryRootsPartial = 0; entryRootsSkipped = 0;
  functionContextsStarted = 0; functionContextsCompleted = 0; functionContextsPartial = 0;
  get nodeVisits(): number { return this.indexWork + this.flowWork; }
  summaryWork = 0;
  resolvedCalls = 0;
  unsupportedCalls = 0;
  configuredCallContexts = 0;
  private readonly configuredInspections: Array<ConfiguredInspection | undefined> = [];
  private configuredSnapshotValues = 0;
  configuredInspectionsQueued = 0;
  configuredInspectionsStarted = 0;
  configuredInspectionsDropped = 0;
  configuredInspectionWork = 0;
  readonly nativeModuleContext?: StaticCandidateContext;

  constructor(files: readonly ts.SourceFile[], readonly limits: FlowLimits, parseErrorCount = 0, readonly roleProofScopeComplete = true, parseFiles?: Iterable<ParseFileEvidence>, metadata: readonly CollectedFile[] = []) {
    if (parseFiles === undefined) this.diagnostics.record('parse_error', 'parse', undefined, parseErrorCount);
    else {
      let observed = 0;
      for (const evidence of parseFiles) {
        if (observed >= parseErrorCount) { this.diagnostics.markUnknown(); break; }
        this.diagnostics.record('parse_error', 'parse', evidence.location, 1, evidence.diagnosticCode);
        observed++;
      }
      if (observed !== parseErrorCount) {
        this.diagnostics.markUnknown();
        if (Number.isSafeInteger(parseErrorCount) && parseErrorCount > observed) this.diagnostics.record('parse_error', 'parse', undefined, parseErrorCount - observed);
      }
    }
    this.maxIndexWork = limits.indexWork ?? FLOW_LIMITS.indexWork;
    this.maxFlowWork = limits.flowWork ?? FLOW_LIMITS.flowWork;
    this.modules = new StaticModules(files, () => this.tick(), limits, (reason) => this.incomplete(reason), roleProofScopeComplete, metadata);
    this.queryModel = new NativeQueryModel(this.modules, () => this.tick(), this.indexComplete);
    this.httpModel = new HttpRoleModel(this.modules, () => this.tick(), roleProofScopeComplete, this.indexComplete);
    this.sqlModel = new SqlRoleModel(this.modules, () => this.tick(), roleProofScopeComplete, this.indexComplete);
    this.nosqlModel = new NoSqlRoleModel(this.modules, () => this.tick(), roleProofScopeComplete);
    this.mongoModel = new MongoRoleModel(this.modules, metadata, () => this.tick(), (reason, node) => this.gap(reason, node), roleProofScopeComplete, this.indexComplete);
    this.forkModel = new ForkRoleModel(this.modules, () => this.tick(), roleProofScopeComplete, this.indexComplete);
    this.processModel = new ProcessRoleModel(this.modules, () => this.tick(), roleProofScopeComplete, this.indexComplete);
    this.filesystemModel = new FilesystemRoleModel(this.modules, metadata, () => this.tick(), (reason, node) => this.gap(reason, node), roleProofScopeComplete, limits.aliasSteps);
    this.archiveModel = new ArchiveRoleModel(this.modules, metadata, () => this.tick(), (reason, node) => this.gap(reason, node), roleProofScopeComplete, limits.aliasSteps);
    this.expressModel = new ExpressRoleModel(this.modules, () => this.tick(), this.indexComplete);
    this.koaModel = new KoaRoleModel(this.modules, () => this.tick(), this.indexComplete);
    this.honoModel = new HonoRoleModel(this.modules, () => this.tick(), this.indexComplete, roleProofScopeComplete);
    this.browserLocationModel = new BrowserLocationRoleModel(this.modules, () => this.tick(), roleProofScopeComplete, limits.aliasSteps);
    this.modules.finishIndex(this.indexComplete);
    this.phase = 'flow';
    const nativeLoad = this.modules.configuredNativeLoads.values().next().value as ts.Node | undefined;
    if (nativeLoad) {
      this.nativeModuleContext = conditionalContext('configured_module_resolution', nativeLoad);
      this.gap('module_export_unsupported', nativeLoad);
    }
  }

  private incomplete(reason: string, call?: ts.Node): void {
    this.reasons.add(reason); this.incompleteEvents += 1;
    if (this.phase === 'index') this.indexComplete = false;
    this.diagnostics.record(reason, this.phase, call ? observedGapLocation(call, this.modules.files) : undefined);
  }

  tick(): boolean {
    if (this.nodeVisits >= this.limits.nodeVisits) { this.incomplete('node_limit'); return false; }
    if (this.phase === 'index') {
      if (this.indexWork >= this.maxIndexWork) { this.incomplete('index_work_limit'); return false; }
      this.indexWork += 1;
    } else {
      if (this.flowWork >= this.maxFlowWork) { this.incomplete('flow_work_limit'); return false; }
      this.flowWork += 1;
    }
    return true;
  }

  private canStartFlow(): boolean { return this.flowWork < this.maxFlowWork && this.nodeVisits < this.limits.nodeVisits; }

  gap(reason: string, call?: ts.Node): void { this.incomplete(reason, call); }

  closure(target: ts.ArrowFunction, env: FlowEnv, lexicalThis?: FlowValue, staticContext?: StaticCandidateContext): FlowValue['callable'] | undefined {
    if (!this.modules.indexComplete) return undefined;
    let result = this.closureShapes.get(target);
    if (!result) { result = analyzeClosureShape(target, this.modules, () => this.tick()); this.closureShapes.set(target, result); }
    if (result.kind !== 'supported' || result.shape.lexicalThis && !lexicalThis) return undefined;
    const captures = new Map<ts.Symbol, FlowValue>();
    for (const symbol of result.shape.captures) {
      if (!this.tick()) return undefined;
      const captured = env.captured(symbol);
      if (symbol.declarations?.some(declaration => ts.isVariableDeclaration(declaration) && declaration.initializer
        && declaration.getSourceFile() === target.getSourceFile() && declaration.initializer.pos <= target.pos && declaration.initializer.end >= target.end)) return undefined;
      if (!captured && sourceRootForName(symbol.name)) this.incomplete('module_export_unsupported');
      captures.set(symbol, captured ?? UNKNOWN);
    }
    return { target, captures, lexicalThis: result.shape.lexicalThis ? lexicalThis : undefined, identity: ++this.capabilityIdentity, staticContext };
  }

  opaqueCaptures(target: ts.ArrowFunction, env: FlowEnv): FlowValue {
    if (!this.modules.indexComplete) return UNKNOWN;
    const values: FlowValue[] = [];
    const visit = (node: ts.Node): void => {
      if (!this.tick()) return;
      if (ts.isIdentifier(node)) {
        const symbol = this.modules.symbol(node);
        if (symbol && !symbol.declarations?.some(declaration => declaration.getSourceFile() === target.getSourceFile() && declaration.pos >= target.pos && declaration.end <= target.end)) {
          const value = env.captured(symbol); if (value) values.push(value);
        }
      }
      node.forEachChild(visit);
    };
    visit(target);
    const value = combineValues(values);
    return isInputRelated(value) ? { ...value, kind: 'unknown', inputRelated: true, traceTruncated: true } : UNKNOWN;
  }

  declaredOwnedRoot(target: ts.ArrowFunction): void {
    if (!this.modules.indexComplete) return; // The existing index gap already denies complete coverage.
    const assignment = target.parent;
    if (!ts.isBinaryExpression(assignment) || assignment.right !== target || !ts.isPropertyAccessExpression(assignment.left)
      || assignment.left.expression.kind !== ts.SyntaxKind.ThisKeyword) return;
    let shape = this.closureShapes.get(target);
    if (!shape) { shape = analyzeClosureShape(target, this.modules, () => this.tick()); this.closureShapes.set(target, shape); }
    if (shape.kind !== 'supported' || shape.shape.captures.length || shape.shape.lexicalThis) this.incomplete('module_export_unsupported');
  }

  construct(node: ts.NewExpression, args: FlowValue[], env: FlowEnv, inheritedContext?: StaticCandidateContext): FlowValue | undefined {
    const resolved = this.modules.resolveConstruct(node);
    const target = resolved ?? this.modules.discoverCjsBody(node);
    if (!target) return undefined;
    const inherited = contexts(inheritedContext, ...args.map(value => value.staticContext));
    const staticContext = !resolved || inherited ? contexts(inherited, conditionalContext('constructor_continuation', node, target)) : undefined;
    const snapshots = new Map<FlowValue, FlowValue>();
    const actualFrame = args.map(value => staticContext ? this.conditionalValue(value, staticContext, 0, snapshots) : value);
    if (staticContext) { this.gap('module_export_unsupported', node); this.invalidateActuals(args, staticContext); }
    let result = this.constructorShapes.get(target);
    if (!result) { result = analyzeConstructedShape(target, this.modules, () => this.tick()); this.constructorShapes.set(target, result); }
    if (result.kind !== 'supported') { this.incomplete('module_export_unsupported'); return undefined; }
    if (target.parameters.slice(args.length).some(parameter => ts.isIdentifier(parameter.name) && !!sourceRootForName(parameter.name.text))) this.incomplete('module_export_unsupported');
    const identity = `new:${target.getSourceFile().fileName}:${target.pos}`;
    if (this.active.has(identity) || this.active.size >= this.limits.callDepth || this.summaryWork >= this.limits.summaryWork) {
      this.incomplete(this.active.has(identity) ? 'summary_cycle' : this.active.size >= this.limits.callDepth ? 'depth_limit' : 'summary_limit'); return undefined;
    }
    this.active.add(identity); this.summaryWork += 1; this.functionContextsStarted += 1;
    const before = this.incompleteEvents;
    const analyzer = new DataflowAnalyzer(target.getSourceFile(), this);
    const captures = new Map<ts.Symbol, FlowValue>();
    // A constructor's module globals are not caller-local variables. Only
    // same-file lexical captures can be read from the actual allocation frame.
    for (const arrow of result.shape.ownArrows.values()) for (const symbol of arrow.captures) {
      if (!this.tick()) break;
      if (symbol.declarations?.some(declaration => declaration.pos >= target.pos && declaration.end <= target.end)) continue;
      captures.set(symbol, target.getSourceFile() === node.getSourceFile() ? env.captured(symbol) ?? UNKNOWN : UNKNOWN);
    }
    const returned = analyzer.analyzeConstructor(result.shape, actualFrame.map(value => traced(value, node, 'call')), captures, staticContext);
    this.uses.push(...analyzer.output()); this.active.delete(identity);
    if (before === this.incompleteEvents) this.functionContextsCompleted += 1; else this.functionContextsPartial += 1;
    return staticContext ? { ...returned, boundaryInput: this.returnInput(args) } : returned;
  }

  callback(value: FlowValue['callable'], registration?: ts.CallExpression, actuals?: readonly FlowValue[]): void {
    if (!value || !this.modules.indexComplete) return;
    const identity = `callback:${value.target.getSourceFile().fileName}:${value.target.pos}:${value.identity}`;
    if (this.active.size >= this.limits.callDepth || this.summaryWork >= this.limits.summaryWork) { this.incomplete(this.active.size >= this.limits.callDepth ? 'depth_limit' : 'summary_limit'); return; }
    this.active.add(identity); this.summaryWork += 1; this.functionContextsStarted += 1;
    const before = this.incompleteEvents;
    const analyzer = new DataflowAnalyzer(value.target.getSourceFile(), this);
    const staticContext = value.staticContext && registration ? contexts(value.staticContext, conditionalContext('declared_callback_entry', registration, value.target)) : value.staticContext;
    if (staticContext) this.gap('module_export_unsupported', registration);
    analyzer.analyzeFunction(value.target, actuals, undefined, !!staticContext, { ...value, staticContext });
    this.uses.push(...analyzer.output()); this.active.delete(identity);
    if (before === this.incompleteEvents) this.functionContextsCompleted += 1; else this.functionContextsPartial += 1;
  }

  invoke(call: ts.CallExpression, args: FlowValue[], receiver?: SingletonReceiver, declaredContext = false, capability?: FlowValue['callable'], inheritedContext?: StaticCandidateContext): FlowValue | undefined {
    const localFork = ts.isIdentifier(call.expression) && (call.expression.text === 'fork' || PROCESS_METHODS.has(call.expression.text));
    let proof = localFork ? this.localForkCalls.get(call) : undefined;
    if (localFork && !proof) { proof = { complete: true }; this.localForkCalls.set(call, proof); }
    const observed = (complete: boolean): void => { if (proof) proof.complete &&= complete && this.roleProofScopeComplete && this.modules.indexComplete && this.modules.configuredNativeIdentityComplete; };
    const initial: CallResolution = capability && this.modules.indexComplete ? { kind: 'resolved' as const, target: capability.target } : this.modules.resolveCall(call,true,receiver);
    let resolution = initial.kind === 'resolved' || initial.kind === 'declared' ? initial : this.modules.resolveCjsFunctionCall(call) ?? initial;
    let staticContext = contexts(inheritedContext, capability?.staticContext, ...args.map(value => value.staticContext));
    if ((resolution.kind === 'resolved' || resolution.kind === 'declared') && resolution.configured) {
      staticContext = contexts(staticContext, conditionalContext('configured_module_resolution', call, resolution.target));
      this.configuredCallContexts++;
    }
    if (resolution.kind !== 'resolved' && resolution.kind !== 'declared') {
      const target = this.modules.discoverCjsBody(call);
      if (target) { resolution = { kind: 'declared', target }; staticContext = contexts(staticContext, conditionalContext('unresolved_cjs_dispatch', call, target)); }
    }
    if (resolution.kind !== "resolved" && resolution.kind !== "declared") {
      observed(false);
      if (["missing", "ambiguous", "module_budget", "export_unsupported"].includes(resolution.kind)) this.incomplete(`module_${resolution.kind}`, call);
      else this.unsupportedCalls += 1;
      if (resolution.kind === "export_unsupported") this.unsupportedCalls += 1;
      return undefined;
    }
    if (resolution.configured) {
      // This newly discovered body never precedes the existing root inventory.
      // Its eventual return/capabilities cannot flow back into the caller.
      observed(false);
      this.gap('module_export_unsupported', call);
      const context = staticContext!;
      const identity = this.invocationIdentity(resolution.target, undefined, true);
      // Caller fallback covers every already-evaluated argument. Optional body
      // copy limits must not erase input in an argument omitted from its frame.
      const callerInput = this.returnInput(args);
      const snapshots = this.configuredActuals(args, context, call);
      this.invalidateActuals(args, context);
      if (this.active.has(identity)) { this.configuredInspectionsDropped++; this.gap('summary_cycle', call); }
      else if (this.active.size >= this.limits.callDepth) { this.configuredInspectionsDropped++; this.gap('depth_limit', call); }
      else if (this.configuredInspectionsQueued >= this.limits.functions
        || this.configuredSnapshotValues >= this.limits.summaryWork) {
        this.configuredInspectionsDropped++; this.gap('summary_limit', call);
      } else if (!this.tick()) this.configuredInspectionsDropped++;
      else {
        this.configuredInspections.push({ call, target: resolution.target, actuals: snapshots,
          context, ancestors: [...this.active], identity });
        this.configuredInspectionsQueued++;
      }
      return withContext({ kind: 'unknown', inputRelated: !!callerInput,
        trace: callerInput?.trace, traceSourceKind: callerInput?.traceSourceKind, traceTruncated: true,
        sqlScalarUnavailable: true, sqlDataUnavailable: true, httpTargetUnavailable: true }, context);
    }
    const declared = declaredContext || resolution.kind === 'declared' || !!staticContext;
    const snapshots = new Map<FlowValue, FlowValue>();
    const actualFrame = args.map(value => staticContext ? this.conditionalValue(value, staticContext, 0, snapshots) : declared ? this.declaredValue(value) : value);
    if (staticContext) { this.gap('module_export_unsupported', call); this.invalidateActuals(args, staticContext); }
    if (resolution.kind === 'declared') { this.unsupportedCalls += 1; this.incomplete('module_export_unsupported',call); observed(false); }
    else this.resolvedCalls += 1;
    const target = resolution.target;
    const seeded = actualFrame.map(value => traced(value, call, 'call'));
    const identity = this.invocationIdentity(target,resolution.receiver,declared) + (capability ? `:${capability.identity}` : '');
    const cacheable = !declared && !capability && !seeded.some((value) => hasMutableQuery(value));
    const key = cacheable ? `${identity}:${JSON.stringify(seeded.map((value) => contextValue(value)))}` : undefined;
    const cached = key ? this.cache.get(key) : undefined;
    if (cached) { observed(true); return resolution.receiver ? this.receiverReturned(cached.returned) : this.sqlReturned(target, cached.returned); }
    if (this.active.has(identity)) {
      observed(false);
      if (seeded.some(isInputRelated) || [...capability?.captures.values() ?? []].some(isInputRelated)) this.incomplete("summary_cycle");
      else this.unsupportedCalls += 1;
      return undefined;
    }
    if (this.active.size >= this.limits.callDepth) { observed(false); this.incomplete("depth_limit"); return undefined; }
    if (this.summaryWork >= this.limits.summaryWork) { observed(false); this.incomplete("summary_limit"); return undefined; }
    this.summaryWork += 1;
    this.active.add(identity);
    const analyzer = new DataflowAnalyzer(target.getSourceFile(), this);
    const before = this.incompleteEvents;
    this.functionContextsStarted += 1;
    const frame = capability ? { ...capability, staticContext, captures: new Map([...capability.captures].map(([symbol, value]) => [symbol, traced(staticContext ? this.conditionalValue(value, staticContext) : value, call, 'call')])) } : undefined;
    const returned = analyzer.analyzeFunction(target, seeded,resolution.receiver,declared,frame,staticContext);
    observed(this.incompleteEvents === before);
    if (this.incompleteEvents === before) this.functionContextsCompleted += 1;
    else this.functionContextsPartial += 1;
    this.active.delete(identity);
    this.uses.push(...analyzer.output());
    if (key && this.incompleteEvents === before && !hasMutableQuery(returned)) this.cache.set(key, { returned });
    if (declared) {
      if (staticContext) {
        const projected = this.conditionalValue(returned, staticContext);
        const fallback = this.returnInput([...seeded, ...(capability?.boundaryInput ? [capability.boundaryInput] : [])]);
        if (projected.callable || projected.constructed || projected.mongoDb || projected.mongoCollection) {
          const boundaryInput = this.returnInput([...(projected.boundaryInput ? [projected.boundaryInput] : []), ...(fallback ? [fallback] : [])]);
          return { ...projected, boundaryInput, ...(projected.callable ? { callable: { ...projected.callable, boundaryInput } } : {}) };
        }
        return isInputRelated(projected) ? projected : fallback ? withContext(fallback, staticContext) : projected;
      }
      const inputReturn = isInputRelated(currentQuery(returned));
      const value = this.declaredValue(inputReturn ? returned : combineValues(seeded));
      // Returned input carries real formal/body/return steps; actuals are fallback only.
      return isInputRelated(value) ? {...value,traceTruncated: !!value.traceTruncated || seeded.some(v=>isInputRelated(v)&&!!v.traceTruncated)} : value;
    }
    return resolution.receiver || capability ? this.receiverReturned(returned) : this.sqlReturned(target, returned);
  }

  private returnInput(values: readonly FlowValue[]): FlowValue | undefined {
    const inputs = values.map(consumedInput).filter(isInputRelated);
    return inputs.length ? combineValues(inputs) : undefined;
  }

  /** Detached positive data only: no shared heap cell or negative certificate. */
  private configuredActuals(values: readonly FlowValue[], context: StaticCandidateContext, call: ts.CallExpression): readonly FlowValue[] {
    let copied = 0;
    const seen = new Set<FlowValue>();
    const snapshot = (value: FlowValue, depth: number): FlowValue => {
      const current = currentQuery(consumedInput(value));
      const input = isInputRelated(current);
      const plain: FlowValue = { kind: input ? current.kind : 'unknown', root: current.root,
        inputRelated: input, traceTruncated: true, traceSourceKind: current.traceSourceKind,
        sqlScalarUnavailable: true, sqlDataUnavailable: true, httpTargetUnavailable: true, staticContext: context };
      if (depth >= this.limits.callDepth || copied >= this.limits.traceSteps
        || this.configuredSnapshotValues >= this.limits.summaryWork || seen.has(value)) {
        this.gap('alias_limit', call); return Object.freeze(plain);
      }
      if (!this.tick()) return Object.freeze(plain);
      copied++; this.configuredSnapshotValues++; seen.add(value);
      if (current.trace) {
        plain.trace = [];
        for (const item of current.trace.slice(0, this.limits.traceSteps)) {
          if (!this.tick()) break;
          plain.trace.push(Object.freeze({ role: item.role, location: Object.freeze({ ...item.location }) }));
        }
        Object.freeze(plain.trace);
      }
      if (current.properties) {
        const properties = new Map<string, FlowValue>();
        for (const [name, child] of current.properties) {
          if (copied >= this.limits.traceSteps || this.configuredSnapshotValues >= this.limits.summaryWork) {
            this.gap('alias_limit', call); break;
          }
          properties.set(name, snapshot(child, depth + 1));
        }
        plain.properties = properties;
      }
      seen.delete(value);
      return Object.freeze(plain);
    };
    const result: FlowValue[] = [];
    for (const value of values) {
      if (result.length >= this.limits.traceSteps) { this.gap('alias_limit', call); break; }
      result.push(snapshot(value, 0));
    }
    return Object.freeze(result);
  }

  private inspectConfiguredBodies(): void {
    const start = this.flowWork;
    for (let cursor = 0; cursor < this.configuredInspections.length; cursor++) {
      const inspection = this.configuredInspections[cursor]!;
      this.configuredInspections[cursor] = undefined;
      if (!this.canStartFlow()) {
        this.configuredInspectionsDropped += this.configuredInspections.length - cursor;
        this.tick(); break;
      }
      if (!this.tick()) { this.configuredInspectionsDropped++; continue; }
      if (this.summaryWork >= this.limits.summaryWork) {
        this.configuredInspectionsDropped++; this.gap('summary_limit', inspection.call); continue;
      }
      for (const identity of inspection.ancestors) this.active.add(identity);
      if (this.active.has(inspection.identity) || this.active.size >= this.limits.callDepth) {
        this.configuredInspectionsDropped++;
        this.gap(this.active.has(inspection.identity) ? 'summary_cycle' : 'depth_limit', inspection.call);
        this.active.clear(); continue;
      }
      this.active.add(inspection.identity); this.summaryWork++; this.functionContextsStarted++;
      this.configuredInspectionsStarted++;
      const before = this.incompleteEvents;
      const analyzer = new DataflowAnalyzer(inspection.target.getSourceFile(), this);
      analyzer.analyzeFunction(inspection.target, inspection.actuals.map(value => traced(value, inspection.call, 'call')),
        undefined, true, undefined, inspection.context);
      this.uses.push(...analyzer.output()); this.active.clear();
      if (this.incompleteEvents === before) this.functionContextsCompleted++;
      else this.functionContextsPartial++;
    }
    this.configuredInspections.length = 0;
    this.configuredInspectionWork = this.flowWork - start;
  }

  /** Unknown call effects are applied even when a possible body is inspected. */
  invalidateActuals(values: readonly FlowValue[], staticContext?: StaticCandidateContext): void {
    const seen = new Set<FlowValue>();
    const visit = (value: FlowValue, depth: number): void => {
      if (!this.tick() || seen.has(value)) return;
      if (depth > this.limits.callDepth) { this.gap('alias_limit'); return; }
      seen.add(value);
      if (value.sequenceContent) value.sequenceContent.closed = value.sequenceContent.valid = false;
      if (value.filesystemStream) value.filesystemStream.valid = false;
      if (value.archiveRole) { value.archiveRole.state.valid = false; this.archiveModel.unsupported(value.archiveRole.origin); }
      if (value.koaRequest) { value.koaRequest.state.valid = false; this.gap('module_export_unsupported'); }
      if (value.honoRequest) { invalidateHono(value.honoRequest); this.gap('module_export_unsupported'); }
      invalidateMongo(value.mongoDb, 'opaque'); invalidateMongo(value.mongoCollection, 'opaque');
      if (value.constructed) { value.constructed.valid = false; value.constructed.staticContext = contexts(value.constructed.staticContext, staticContext); for (const slot of value.constructed.slots.values()) visit(slot, depth + 1); }
      if (value.callable) { value.callable.valid = false; value.callable.staticContext = contexts(value.callable.staticContext, staticContext); for (const captured of value.callable.captures.values()) visit(captured, depth + 1); if (value.callable.lexicalThis) visit(value.callable.lexicalThis, depth + 1); }
      // Preserve a previously recognized response shape, but no MIME exclusion.
      // Concrete member writes already invalidate the shared response separately.
      if (value.expressResponse) { value.expressResponse.mime = 'unknown'; value.expressResponse.authority = 'unqualified_response'; }
      if (value.nosqlObject) { value.nosqlObject.modified = true; value.nosqlObject.value = combineValues([value.nosqlObject.value, ...values.map(consumedInput)]); }
      for (const child of value.properties?.values() ?? []) visit(child, depth + 1);
    };
    for (const value of values) visit(value, 0);
  }

  /** Origin is retained; safety is discarded. Conditional authority is orthogonal to taint certainty. */
  conditionalValue(value: FlowValue, staticContext: StaticCandidateContext, depth = 0, seen = new Map<FlowValue, FlowValue>()): FlowValue {
    if (!this.tick() || depth > this.limits.callDepth) { this.gap('alias_limit'); return withContext(isInputRelated(value) ? inheritTrace(UNKNOWN_INPUT, [value]) : UNKNOWN, staticContext); }
    const known = seen.get(value); if (known) return known;
    const current = currentQuery(value);
    const result: FlowValue = withContext({ kind: isInputRelated(current) ? current.kind : 'unknown', root: current.root,
      inputRelated: current.inputRelated, trace: current.trace, traceTruncated: current.traceTruncated, traceSourceKind: current.traceSourceKind,
      sqlScalarUnavailable: true, httpTargetUnavailable: true, sqlDataUnavailable: true }, staticContext);
    seen.set(value, result);
    if (result.staticContext?.truncated) this.gap('module_export_unsupported');
    const project = (child: FlowValue) => this.conditionalValue(child, staticContext, depth + 1, seen);
    if (value.filesystemContent) result.filesystemContent = project(value.filesystemContent);
    if (value.archiveContent) result.archiveContent = project(value.archiveContent);
    if (value.archiveRole) result.archiveRole = value.archiveRole;
    if (value.sequenceContent) result.sequenceContent = value.sequenceContent;
    if (value.properties) result.properties = new Map([...value.properties].map(([name, child]) => [name, project(child)]));
    if (value.nosqlWhere) result.nosqlWhere = { node: value.nosqlWhere.node, value: project(value.nosqlWhere.value) };
    if (value.nosqlUnknown) result.nosqlUnknown = project(value.nosqlUnknown);
    if (value.mongoDb && value.mongoDb.conditionalOrigin !== false && !['write', 'ambiguous'].includes(value.mongoDb.invalidReason ?? '')) {
      result.mongoDb = value.mongoDb;
      result.staticContext = contexts(result.staticContext, conditionalContext('unqualified_mongo_origin', value.mongoDb.origin));
    } else if (value.mongoDb) this.gap('module_export_unsupported');
    if (value.mongoCollection && value.mongoCollection.db.conditionalOrigin !== false && !['write', 'ambiguous'].includes(value.mongoCollection.invalidReason ?? '')
      && !['write', 'ambiguous'].includes(value.mongoCollection.db.invalidReason ?? '')) {
      result.mongoCollection = value.mongoCollection;
      result.staticContext = contexts(result.staticContext, conditionalContext('unqualified_mongo_origin', value.mongoCollection.origin));
    } else if (value.mongoCollection) this.gap('module_export_unsupported');
    if (value.constructed?.valid) {
      result.constructed = { ...value.constructed, staticContext: contexts(value.constructed.staticContext, staticContext), slots: new Map() };
      for (const [name, slot] of value.constructed.slots) result.constructed.slots.set(name, project(slot));
    }
    if (value.callable && value.callable.valid !== false) result.callable = { ...value.callable, staticContext: contexts(value.callable.staticContext, staticContext),
      captures: new Map([...value.callable.captures].map(([symbol, child]) => [symbol, project(child)])), lexicalThis: value.callable.lexicalThis ? project(value.callable.lexicalThis) : undefined };
    if (value.opaqueClosure) result.opaqueClosure = project(value.opaqueClosure);
    if (value.boundaryInput) result.boundaryInput = project(value.boundaryInput);
    return result;
  }

  private invocationIdentity(target: ts.FunctionLikeDeclaration, receiver?: SingletonReceiver, declared=false): string {
    return `${target.getSourceFile().fileName}:${target.pos}:${receiver ? `${receiver.file.fileName}:${receiver.classNode.pos}:${receiver.exportNode.pos}` : ''}:${declared}`;
  }

  private declaredValue(value: FlowValue): FlowValue {
    const current = currentQuery(value);
    return isInputRelated(current) ? {kind:'unknown',inputRelated:true,trace:current.trace,traceTruncated:current.traceTruncated,traceSourceKind:current.traceSourceKind,
      filesystemContent:current.filesystemContent,sequenceContent:current.sequenceContent,
      archiveContent:current.archiveContent,
      sqlScalarUnavailable:true,httpTargetUnavailable:true,sqlDataUnavailable:current.sqlDataUnavailable} : UNKNOWN;
  }

  private receiverReturned(value: FlowValue): FlowValue {
    return {...withoutUrlProof(value),sqlScalarUnavailable:true,httpTargetUnavailable:true};
  }

  private sqlReturned(target: ts.FunctionLikeDeclaration, value: FlowValue): FlowValue {
    const asyncOrGenerator = target.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword) || "asteriskToken" in target && !!target.asteriskToken;
    return asyncOrGenerator ? { ...value, sqlFixedText:undefined, sqlConfig:undefined, sqlArray:undefined, sqlScalarUnavailable:true, httpTargetUnavailable:true } : value;
  }

  run(files: readonly ts.SourceFile[]): void {
    const roots = this.modules.functions.filter((fn) => !this.indexComplete || !this.modules.called.has(fn) || this.modules.externalEntries.has(fn));
    this.entryRootsDeclared = roots.length;
    for (const file of files) {
      if (!this.canStartFlow()) { this.topLevelSkipped += 1; this.tick(); continue; }
      const before = this.incompleteEvents;
      this.topLevelStarted += 1;
      const analyzer = new DataflowAnalyzer(file, this);
      analyzer.analyzeTopLevel();
      if (this.incompleteEvents === before) this.topLevelCompleted += 1; else this.topLevelPartial += 1;
      this.uses.push(...analyzer.output());
    }
    for (const fn of roots) {
      if (!this.canStartFlow()) { this.entryRootsSkipped += 1; this.tick(); continue; }
      const before = this.incompleteEvents;
      this.entryRootsStarted += 1; this.functionContextsStarted += 1;
      const analyzer = new DataflowAnalyzer(fn.getSourceFile(), this);
      const receiver=this.modules.rootReceiver(fn);
      const identity=this.invocationIdentity(fn,receiver);
      this.active.add(identity);
      analyzer.analyzeFunction(fn,undefined,receiver);
      this.active.delete(identity);
      if (this.incompleteEvents === before) { this.entryRootsCompleted += 1; this.functionContextsCompleted += 1; }
      else { this.entryRootsPartial += 1; this.functionContextsPartial += 1; }
      this.uses.push(...analyzer.output());
    }
    this.inspectConfiguredBodies();
  }
}

class DataflowAnalyzer {
  private readonly uses: InputFlowUse[] = [];
  private readonly returns: FlowValue[] = [];
  // Only evaluation-shaped operands, scoped to this analyzer and exact environment.
  // A following initializer/return read must not replay operands against later argument writes.
  private readonly evaluationActuals = new WeakMap<ts.Node, { env: FlowEnv; values: FlowValue[] }>();
  private readonly objectActuals = new WeakMap<ts.ObjectLiteralExpression, { env: FlowEnv; values: Map<ts.Node, FlowValue>; keys: Map<ts.Node, FlowValue> }>();
  private readonly arrayActuals = new WeakMap<ts.ArrayLiteralExpression, { env: FlowEnv; values: Map<ts.Node, FlowValue> }>();
  private readonly constructedActuals = new WeakMap<ts.NewExpression, { env: FlowEnv; value: FlowValue }>();
  private readonly callableActuals = new WeakMap<ts.CallExpression, { env: FlowEnv; value?: FlowValue }>();
  private honoDataReads?: WeakMap<ts.CallExpression, { env: FlowEnv; value: FlowValue }>;
  private readonly conditionalActuals = new WeakMap<ts.ConditionalExpression, { env: FlowEnv; value: FlowValue }>();
  private constructedReceiver?: FlowValue;
  private constructorGuards?: ReadonlySet<ts.IfStatement>;

  /** Lookup selected callable values without replaying arbitrary callee expressions. */
  private capabilityValue(expression: ts.Expression, env: FlowEnv): FlowValue {
    if (!this.session?.modules.indexComplete) return UNKNOWN;
    if (ts.isIdentifier(expression)) {
      const value = env.has(expression.text) ? env.resolve(expression.text) : UNKNOWN;
      return value.callable?.valid === false ? { ...UNKNOWN, staticContext: value.staticContext,
        opaqueClosure: { ...combineValues([...value.callable.captures.values(), ...(value.boundaryInput ? [value.boundaryInput] : [])]), traceTruncated: true } } : value;
    }
    if (expression.kind === ts.SyntaxKind.ThisKeyword) return this.constructedReceiver ?? UNKNOWN;
    if (ts.isPropertyAccessExpression(expression)) {
      const receiver = this.capabilityValue(expression.expression, env);
      if (receiver.constructed) {
        if (!receiver.constructed.valid) return receiver.constructed.slots.has(expression.name.text)
          ? { ...UNKNOWN, staticContext: contexts(receiver.staticContext, receiver.constructed.staticContext), opaqueClosure: receiver.boundaryInput ?? UNKNOWN } : UNKNOWN;
        const selected = receiver.constructed.slots.get(expression.name.text) ?? UNKNOWN;
        const staticContext = contexts(receiver.staticContext, receiver.constructed.staticContext, selected.staticContext);
        const boundaryInput = receiver.boundaryInput ?? selected.boundaryInput;
        return { ...withContext(selected, staticContext), boundaryInput,
          ...(selected.callable ? { callable: { ...selected.callable, staticContext: contexts(selected.callable.staticContext, staticContext), boundaryInput } } : {}) };
      }
      return receiver.properties?.get(expression.name.text) ?? UNKNOWN;
    }
    if (ts.isCallExpression(expression)) return this.callableActuals.get(expression)?.env === env ? this.callableActuals.get(expression)!.value ?? UNKNOWN : UNKNOWN;
    if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isNonNullExpression(expression)) return this.capabilityValue(expression.expression, env);
    return UNKNOWN;
  }
  private receiver?: SingletonReceiver;
  private declared = false;
  private staticContext?: StaticCandidateContext;

  constructor(private readonly sourceFile: ts.SourceFile, private readonly session?: FlowSession) {}
  private certificateAvailable(): boolean {
    return !this.declared && !this.staticContext && this.session?.modules.configuredNativeIdentityComplete !== false;
  }
  private filesystemCertificateAvailable(values: readonly FlowValue[]): boolean {
    if (this.session?.modules.configuredNativeIdentityComplete === false) return false;
    // Existing stream/callback provenance does not contradict a separately
    // qualified shell-disabled primitive argv layout. Configured module
    // identity (or a truncated context hiding it) still forbids that exclusion.
    for (const context of [this.staticContext, ...values.map(value => consumedInput(value).staticContext)]) {
      if (!context) continue;
      if (this.session && !this.session.tick()) return false;
      if (context.truncated || context.items.some(item => item.kind === 'configured_module_resolution')) return false;
    }
    return true;
  }

  output(): InputFlowUse[] {
    return this.uses.map(use => {
      const staticContext = contexts(this.staticContext, use.staticContext, this.session?.nativeModuleContext);
      if (!staticContext) return use;
      if (staticContext.truncated) this.session?.gap('module_export_unsupported', use.node);
      const conditionalFlow = (flow: StaticFlow | undefined) => flow ? { ...flow, truncated: true } : undefined;
      return { ...use, staticContext,
        argumentFlows: use.argumentFlows?.map(flow => ({ ...flow, certainty: 'unknown' as const, fixedDestination: false, staticFlow: conditionalFlow(flow.staticFlow) })),
        ...(use.nosqlRole ? { nosqlRole: { ...use.nosqlRole, certainty: 'unknown' as const, staticFlow: conditionalFlow(use.nosqlRole.staticFlow) } } : {}),
        ...(use.sqlRole ? { sqlRole: { ...use.sqlRole, certainty: 'unknown' as const, staticFlow: conditionalFlow(use.sqlRole.staticFlow) } } : {}),
        ...(use.httpRole ? { httpRole: { ...use.httpRole, certainty: 'unknown' as const, staticFlow: conditionalFlow(use.httpRole.staticFlow) } } : {}),
        ...(use.processRole ? { processRole: { ...use.processRole, certainty: 'unknown' as const, staticFlow: conditionalFlow(use.processRole.staticFlow) } } : {}) };
    });
  }
  analyzeTopLevel(): void { this.analyzeStatements(this.sourceFile.statements, new FlowEnv()); }

  run(): InputFlowUse[] {
    this.analyzeStatements(this.sourceFile.statements, new FlowEnv());
    const functions: ts.FunctionLikeDeclaration[] = [];
    const collect = (node: ts.Node): void => {
      if (isFunctionLike(node)) functions.push(node);
      node.forEachChild(collect);
    };
    collect(this.sourceFile);
    for (const functionLike of functions) this.analyzeFunction(functionLike);
    return this.uses;
  }

  analyzeFunction(functionLike: ts.FunctionLikeDeclaration, actuals?: readonly FlowValue[], receiver?: SingletonReceiver, declared=false, capability?: FlowValue['callable'], inheritedContext?: StaticCandidateContext): FlowValue {
    this.staticContext = contexts(inheritedContext, capability?.staticContext);
    if (this.staticContext?.truncated) this.session?.gap('module_export_unsupported', functionLike);
    this.receiver=receiver; this.declared=declared || !!this.staticContext;
    const env = new FlowEnv();
    if (!actuals && !capability && ts.isArrowFunction(functionLike)) this.session?.declaredOwnedRoot(functionLike);
    this.constructedReceiver = capability?.lexicalThis;
    for (const [symbol, value] of capability?.captures ?? []) env.declare(symbol.name, value, true, symbol);
    const expressEntry = this.session?.expressModel.entry(functionLike);
    const koaEntry = this.session?.koaModel.entry(functionLike);
    const koaState = { valid: true };
    const honoEntry = this.session?.honoModel.entry(functionLike);
    const honoState = { valid: true, jsonDataValid: this.session?.honoModel.isolatedJsonEntry(functionLike) === true };
    const mongoEntry = actuals ? undefined : this.session?.mongoModel.entry(functionLike);
    for (const [index, parameter] of functionLike.parameters.entries()) {
      if (actuals) this.declareBinding(parameter.name, traced(actuals[index] ?? UNKNOWN, parameter, "parameter"), env, true);
      else if (honoEntry) this.declareBinding(parameter.name, index === 0
        ? { ...UNKNOWN, honoRequest: { stage: 'context', state: honoState } }
          : { ...UNKNOWN, honoRequest: { stage: 'next', state: honoState } }, env, true);
      else if (koaEntry) this.declareBinding(parameter.name, { ...UNKNOWN, koaRequest: { stage: index === 0 ? 'context' : 'next', state: koaState } }, env, true);
      else if (mongoEntry && index === 1) this.declareBinding(parameter.name, { ...UNKNOWN, mongoDb: mongoEntry }, env, true);
      else if (expressEntry) this.declareBinding(parameter.name,
        index === expressEntry.request ? rootValue('request')
          : index === expressEntry.response ? { ...UNKNOWN, expressResponse: { identity: {}, authority: 'registered_express', mime: 'default', valid: true } }
            : UNKNOWN, env, true);
      else if (index === 1 && ts.isIdentifier(parameter.name) && /^(res|response)$/.test(parameter.name.text)
        && functionLike.parameters[0] && ts.isIdentifier(functionLike.parameters[0].name)
        && /^(req|request)$/.test(functionLike.parameters[0].name.text)) {
        this.declareBinding(parameter.name, { ...UNKNOWN, expressResponse: { identity: {}, authority: 'unqualified_response', mime: "default", valid: true } }, env, true);
      } else this.declareParameter(parameter, env);
    }
    const body = functionBody(functionLike);
    if (!body) return UNKNOWN;
    if (ts.isBlock(body)) this.analyzeStatement(body, env);
    else {
      this.analyzeExpression(body, env);
      this.returns.push(traced(this.evalExpression(body, env), body, "return"));
      env.terminated = true;
    }
    const values = [...this.returns, ...(!env.terminated ? [UNKNOWN] : [])];
    return values.length ? values.reduce(joinValues) : UNKNOWN;
  }

  analyzeConstructor(shape: ConstructorShape, args: readonly FlowValue[], captures: ReadonlyMap<ts.Symbol, FlowValue>, staticContext?: StaticCandidateContext): FlowValue {
    this.staticContext = staticContext; this.declared = !!staticContext;
    const env = new FlowEnv();
    for (const [symbol, value] of captures) env.declare(symbol.name, value, true, symbol);
    for (const [index, parameter] of shape.target.parameters.entries()) this.declareBinding(parameter.name, traced(args[index] ?? UNKNOWN, parameter, 'parameter'), env, true);
    this.constructedReceiver = { ...UNKNOWN, staticContext, constructed: { valid: true, shape, slots: new Map(), staticContext } };
    this.constructorGuards = staticContext ? undefined : new Set(shape.guards);
    this.analyzeStatement(shape.target.body!, env);
    return this.constructedReceiver;
  }

  private declareParameter(parameter: ts.ParameterDeclaration, env: FlowEnv): void {
    if (ts.isIdentifier(parameter.name)) {
      const root = sourceRootForName(parameter.name.text);
      this.declareBinding(parameter.name, withContext(root ? rootValue(root) : UNKNOWN, this.staticContext), env, true);
      return;
    }
    // Next route handlers commonly destructure the second context parameter
    // (`{ params }`, `{ searchParams }`) and Express-style handlers commonly
    // destructure request fields (`{ query }`, `{ body }`). The old generic
    // UNKNOWN value made these inputs disappear before reaching a sink.
    if (ts.isObjectBindingPattern(parameter.name)) {
      for (const element of parameter.name.elements) {
        if (ts.isOmittedExpression(element)) continue;
        const key = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
        const root = key ? sourceRootForName(key) : undefined;
        const value = element.dotDotDotToken
          ? UNKNOWN
          : root
            ? rootValue(root)
            : UNKNOWN;
        this.declareBinding(element.name, value, env, true);
      }
      return;
    }
    this.declareBinding(parameter.name, UNKNOWN, env, true);
  }

  private declareBinding(name: ts.BindingName, value: FlowValue, env: FlowEnv, blockScoped: boolean): void {
    if (ts.isIdentifier(name)) {
      if (value.archiveRole && this.session) {
        if (this.session.archiveModel.bindingMutated(name)) {
          value.archiveRole.state.valid = false; this.session.archiveModel.unsupported(name);
        }
      }
      if (value.filesystemStream) {
        const symbol = this.session?.modules.symbol(name);
        if (symbol && (this.session?.modules.mutated.has(symbol) || this.session?.modules.mutatedMembers.has(symbol))) value.filesystemStream.valid = false;
      }
      if (!value.sequenceContent && this.session) {
        const shape = this.session.filesystemModel.accumulator(name);
        if (shape) value = { ...value, sequenceContent: { ...shape, value: { ...value }, filename: filenamePart(value) ?? UNKNOWN } };
      }
      if (value.sqlArray && ts.isParameter(name.parent) && this.session?.sqlModel.arrayParameter(name) !== true) value = { ...value, sqlArray:{ ...value.sqlArray, closed:false } };
      env.declare(name.text, value, blockScoped, this.session?.modules.symbol(name));
      return;
    }
    if (ts.isObjectBindingPattern(name)) {
      for (const element of name.elements) {
        if (ts.isOmittedExpression(element)) continue;
        const key = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
        let elementValue = element.dotDotDotToken
          ? value
          : key === undefined
            ? UNKNOWN
            : projectValue(value, key);
        if (value.koaRequest && isInputRelated(elementValue)) elementValue = traced(elementValue, element.name, 'source');
        this.declareBinding(element.name, elementValue, env, blockScoped);
      }
      return;
    }
    for (let index = 0; index < name.elements.length; index += 1) {
      const element = name.elements[index];
      if (ts.isOmittedExpression(element)) continue;
      const elementValue = element.dotDotDotToken ? value : projectValue(value, String(index));
      this.declareBinding(element.name, elementValue, env, blockScoped);
    }
  }

  private assignBinding(name: ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression, value: FlowValue, env: FlowEnv): void {
    if (ts.isIdentifier(name)) {
      env.assign(name.text, value);
      return;
    }
    if (ts.isObjectBindingPattern(name)) {
      for (const element of name.elements) {
        const key = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
        this.assignBinding(element.name, element.dotDotDotToken ? value : key === undefined ? UNKNOWN : projectValue(value, key), env);
      }
      return;
    }
    if (ts.isArrayBindingPattern(name)) {
      for (let index = 0; index < name.elements.length; index += 1) {
        const element = name.elements[index];
        if (ts.isOmittedExpression(element)) continue;
        this.assignBinding(element.name, element.dotDotDotToken ? value : projectValue(value, String(index)), env);
      }
      return;
    }
    if (ts.isObjectLiteralExpression(name)) {
      for (const element of name.properties) {
        if (ts.isSpreadAssignment(element)) {
          if (isSupportedBindingTarget(element.expression)) this.assignBinding(element.expression, value, env);
        } else if (ts.isPropertyAssignment(element)) {
          const key = propertyName(element.name);
          if (key !== undefined && isSupportedBindingTarget(element.initializer)) this.assignBinding(element.initializer, projectValue(value, key), env);
        } else if (ts.isShorthandPropertyAssignment(element)) {
          this.assignBinding(element.name, projectValue(value, element.name.text), env);
        }
      }
      return;
    }
    for (const [index, element] of name.elements.entries()) {
      if (ts.isOmittedExpression(element)) continue;
      if (ts.isSpreadElement(element)) {
        if (isSupportedBindingTarget(element.expression)) this.assignBinding(element.expression, value, env);
      } else if (isSupportedBindingTarget(element)) {
        this.assignBinding(element, projectValue(value, String(index)), env);
      }
    }
  }

  private analyzeStatements(statements: readonly ts.Statement[], env: FlowEnv): void {
    for (const statement of statements) {
      if (ts.isVariableStatement(statement)) {
        const blockScoped = (statement.declarationList.flags & ts.NodeFlags.BlockScoped) !== 0;
        for (const declaration of statement.declarationList.declarations) this.declareBinding(declaration.name, UNKNOWN, env, blockScoped);
      } else if (ts.isFunctionDeclaration(statement) && statement.name) env.declare(statement.name.text, UNKNOWN, true, this.session?.modules.symbol(statement.name));
    }
    for (const statement of statements) {
      if (env.terminated) break;
      this.analyzeStatement(statement, env);
    }
  }

  private analyzeStatement(statement: ts.Statement, env: FlowEnv): void {
    if (this.session && !this.session.tick()) return;
    if (isFunctionLike(statement)) return;
    if (ts.isVariableStatement(statement)) {
      this.analyzeVariableList(statement.declarationList, env);
      return;
    }
    if (ts.isExpressionStatement(statement)) {
      this.analyzeExpression(statement.expression, env);
      return;
    }
    if (ts.isBlock(statement)) {
      env.push();
      this.analyzeStatements(statement.statements, env);
      env.pop();
      return;
    }
    if (ts.isIfStatement(statement)) {
      if (this.constructorGuards?.has(statement)) return;
      this.analyzeExpression(statement.expression, env);
      const whenTrue = env.clone();
      this.analyzeStatement(statement.thenStatement, whenTrue);
      const branches = [whenTrue];
      if (statement.elseStatement) {
        const whenFalse = env.clone();
        this.analyzeStatement(statement.elseStatement, whenFalse);
        branches.push(whenFalse);
      } else {
        branches.push(env.clone());
      }
      env.merge(branches);
      return;
    }
    if (ts.isForStatement(statement)) {
      const loop = env.clone();
      loop.push();
      if (statement.initializer) {
        if (ts.isVariableDeclarationList(statement.initializer)) this.analyzeVariableList(statement.initializer, loop);
        else this.analyzeExpression(statement.initializer, loop);
      }
      if (statement.condition) this.analyzeExpression(statement.condition, loop);
      this.analyzeStatement(statement.statement, loop);
      if (statement.incrementor) this.analyzeExpression(statement.incrementor, loop);
      loop.pop();
      env.merge([loop, env.clone()]);
      return;
    }
    if (ts.isForInStatement(statement) || ts.isForOfStatement(statement)) {
      const loop = env.clone();
      loop.push();
      this.analyzeExpression(statement.expression, loop);
      const iterable = this.evalExpression(statement.expression, loop);
      if (ts.isVariableDeclarationList(statement.initializer)) {
        const blockScoped = (statement.initializer.flags & ts.NodeFlags.BlockScoped) !== 0;
        for (const declaration of statement.initializer.declarations) {
          // A loop element inherits the taint of the iterable. For an object or
          // array with tracked fields, wildcard projection keeps the useful
          // property-independent input signal without inventing a value.
          const elementValue = ts.isForOfStatement(statement) ? projectValue(iterable, "*") : iterable.archiveRole ? UNKNOWN : projectValue(iterable, "*");
          if (declaration.initializer) this.analyzeExpression(declaration.initializer, loop);
          this.declareBinding(declaration.name, elementValue, loop, blockScoped);
        }
      } else {
        this.analyzeAssignmentTarget(statement.initializer, loop);
        const elementValue = ts.isForOfStatement(statement) ? projectValue(iterable, "*") : iterable.archiveRole ? UNKNOWN : projectValue(iterable, "*");
        if (ts.isIdentifier(statement.initializer)) loop.assign(statement.initializer.text, elementValue);
        else if (isAssignmentPattern(statement.initializer) || isBindingPattern(statement.initializer)) {
          this.assignBinding(statement.initializer as ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression, elementValue, loop);
        } else {
          this.assignMemberPath(statement.initializer, elementValue, loop);
        }
      }
      this.analyzeStatement(statement.statement, loop);
      loop.pop();
      env.merge([loop, env.clone()]);
      return;
    }
    if (ts.isWhileStatement(statement) || ts.isDoStatement(statement)) {
      if (ts.isWhileStatement(statement)) this.analyzeExpression(statement.expression, env);
      const body = env.clone();
      this.analyzeStatement(statement.statement, body);
      if (ts.isDoStatement(statement)) this.analyzeExpression(statement.expression, body);
      env.merge([body, env.clone()]);
      return;
    }
    if (ts.isSwitchStatement(statement)) {
      this.analyzeExpression(statement.expression, env);
      const branches: FlowEnv[] = [env.clone()];
      for (const clause of statement.caseBlock.clauses) {
        const branch = env.clone();
        if (ts.isCaseClause(clause)) this.analyzeExpression(clause.expression, branch);
        this.analyzeStatements(clause.statements, branch);
        branches.push(branch);
      }
      env.merge(branches);
      return;
    }
    if (ts.isTryStatement(statement)) {
      const returnsBeforeTry = this.returns.length;
      const tryEnv = env.clone();
      this.analyzeBlockLike(statement.tryBlock, tryEnv);
      const branches = [tryEnv];
      if (statement.catchClause) {
        const catchEnv = env.clone();
        if (statement.catchClause.variableDeclaration) {
          catchEnv.push();
          this.declareBinding(statement.catchClause.variableDeclaration.name, UNKNOWN, catchEnv, true);
        }
        this.analyzeBlockLike(statement.catchClause.block, catchEnv);
        if (statement.catchClause.variableDeclaration) catchEnv.pop();
        branches.push(catchEnv);
      } else {
        branches.push(env.clone());
      }
      env.merge(branches);
      if (statement.finallyBlock) {
        const terminatedBeforeFinally = env.terminated;
        const returnsBeforeFinally = this.returns.length;
        // finally executes on return/throw paths too; merge their values for its body.
        const finalBranches = branches.map((branch) => { const copy = branch.clone(); copy.terminated = false; return copy; });
        env.terminated = false;
        env.merge(finalBranches);
        this.analyzeBlockLike(statement.finallyBlock, env);
        if (env.terminated) {
          // An unconditional finally return/throw overrides earlier completions.
          this.returns.splice(returnsBeforeTry, returnsBeforeFinally - returnsBeforeTry);
        } else env.terminated = terminatedBeforeFinally;
      }
      return;
    }
    if (ts.isReturnStatement(statement) || ts.isThrowStatement(statement)) {
      if (statement.expression) this.analyzeExpression(statement.expression, env);
      if (ts.isReturnStatement(statement)) this.returns.push(statement.expression
        ? traced(this.evalExpression(statement.expression, env), statement, "return") : SAFE);
      env.terminated = true;
      return;
    }
    if (ts.isWithStatement(statement)) {
      this.analyzeExpression(statement.expression, env);
      this.analyzeStatement(statement.statement, env);
      return;
    }
    if (ts.isLabeledStatement(statement)) {
      this.analyzeStatement(statement.statement, env);
      return;
    }
    if (ts.isClassDeclaration(statement)) {
      for (const member of statement.members) {
        if (ts.isPropertyDeclaration(member) && member.initializer) this.analyzeExpression(member.initializer, env);
      }
      return;
    }
    statement.forEachChild((child) => {
      if (isFunctionLike(child)) return;
      if (ts.isStatement(child)) this.analyzeStatement(child, env);
      else if (ts.isExpression(child)) this.analyzeExpression(child, env);
    });
  }

  private analyzeBlockLike(block: ts.Block, env: FlowEnv): void {
    this.analyzeStatement(block, env);
  }

  private analyzeVariableList(list: ts.VariableDeclarationList, env: FlowEnv): void {
    const blockScoped = (list.flags & ts.NodeFlags.BlockScoped) !== 0;
    for (const declaration of list.declarations) {
      if (declaration.initializer) this.analyzeExpression(declaration.initializer, env);
      const value = declaration.initializer ? this.evalExpression(declaration.initializer, env) : UNKNOWN;
      if (ts.isIdentifier(declaration.name)) {
        this.declareBinding(declaration.name, value, env, blockScoped);
      } else {
        this.declareBinding(declaration.name, value, env, blockScoped);
      }
    }
  }

  private analyzeExpression(expression: ts.Expression, env: FlowEnv): void {
    if (this.session && !this.session.tick()) return;
    if (isFunctionLike(expression)) return;
    if (ts.isBinaryExpression(expression) && isAssignmentOperator(expression.operatorToken.kind)) {
      this.analyzeExpression(expression.right, env);
      this.analyzeAssignmentTarget(expression.left, env);
      const right = this.evalExpression(expression.right, env);
      if (this.constructedReceiver?.constructed && ts.isPropertyAccessExpression(expression.left)
        && expression.left.expression.kind === ts.SyntaxKind.ThisKeyword && expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && this.constructedReceiver.constructed.shape.ownArrows.has(expression.left.name.text)) {
        this.constructedReceiver.constructed.slots.set(expression.left.name.text, right);
        return;
      }
      if (isSimpleAssignment(expression.operatorToken.kind)) {
        this.recordAssignment(expression, right);
        if (ts.isIdentifier(expression.left) || isAssignmentPattern(expression.left) || isBindingPattern(expression.left)) {
          this.assignBinding(expression.left as ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression, right, env);
        } else {
          this.assignMemberPath(expression.left, right, env);
        }
      } else {
        const prior = ts.isIdentifier(expression.left) ? env.resolve(expression.left.text) : UNKNOWN;
        const value = combineValues([prior, right]);
        this.recordAssignment(expression, value);
        if (ts.isIdentifier(expression.left)) env.assign(expression.left.text, value);
        else this.assignMemberPath(expression.left, value, env);
      }
      return;
    }
    if (ts.isCallExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      const callee = expression.expression;
      const selectedCallable = this.capabilityValue(callee, env);
      const response = ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee) ? this.evalExpression(callee.expression, env) : undefined;
      // Body interpretation happens when send/json runs, after argument evaluation.
      const responseState = response?.expressResponse;
      const processBinding = this.session?.processModel.binding(expression);
      const filesystemStream = this.session?.filesystemModel.stream(expression);
      const filesystemWrapper = this.session?.filesystemModel.wrapper(expression);
      const archiveOpen = this.session?.archiveModel.open(expression);
      const archivePathCall = this.session?.archiveModel.pathCall(expression);
      const archiveWriter = this.session?.archiveModel.writer(expression);
      const koaRegistration = this.session?.koaModel.registration(expression);
      const honoRegistration = this.session?.honoModel.registration(expression);
      this.session?.mongoModel.observe(expression);
      const mongoCollection = this.session?.mongoModel.collection(expression, response?.mongoDb);
      // Preserve operand order in this syntax-shaped lane: later writes cannot replace earlier actual evidence.
      const orderedActuals = !!processBinding || !!filesystemWrapper || evaluationShapedCallee(callee) || this.session?.nosqlModel.bound(expression) === true || !!selectedCallable.callable || !!selectedCallable.opaqueClosure
        || this.session?.mongoModel.selector(expression, response?.mongoCollection) === true || this.session?.modules.localCallable(expression) === true || this.session?.modules.resolveCjsFunctionCall(expression)?.kind === 'resolved'
        || !!this.session?.modules.discoverCjsBody(expression);
      const args = orderedActuals ? expression.arguments.map(argument => {
        this.analyzeExpression(argument, env);
        return this.evalExpression(argument, env);
      }) : (() => {
        for (const argument of expression.arguments) this.analyzeExpression(argument, env);
        return expression.arguments.map(argument => this.evalExpression(argument, env));
      })();
      if (orderedActuals) this.evaluationActuals.set(expression, { env, values: args });
      const cell = response?.sequenceContent;
      const arrayMutation = cell && ts.isPropertyAccessExpression(callee) && ['push', 'unshift'].includes(callee.name.text);
      if (arrayMutation) {
        const appended = combineValues(args.map(consumedInput));
        const parts = args.map(filenamePart).filter((value): value is FlowValue => !!value);
        cell.value = combineValues([cell.value, appended]);
        if (parts.length || isInputRelated(cell.filename)) {
          const context = conditionalContext('conditional_array_accumulator', expression, cell.node);
          cell.filename = traced(withContext(combineValues([cell.filename, ...parts]), context), expression, 'intermediate');
          cell.value = withContext(cell.value, context);
          this.session!.filesystemModel.accumulatorWrites++;
          this.session?.gap('module_export_unsupported', expression);
        }
      }
      const event = response?.filesystemStream && ts.isPropertyAccessExpression(callee) && callee.name.text === 'on'
        && expression.arguments.length === 2 && ts.isStringLiteralLike(expression.arguments[0]) ? expression.arguments[0].text : undefined;
      const eventCallback = args[1]?.callable;
      const filesystemEvent = (event === 'data' || event === 'end') && response?.filesystemStream?.valid && eventCallback;
      if (filesystemEvent) {
        const stream = response!.filesystemStream!;
        const context = contexts(conditionalContext('declared_filesystem_stream_origin', stream.origin, stream.provider),
          conditionalContext('declared_stream_callback_schedule', expression, eventCallback!.target));
        this.session?.gap('module_export_unsupported', expression);
        if (event === 'data') {
          this.session!.filesystemModel.filenameCallbacks++;
          const parameter = eventCallback!.target.parameters[0];
          const input = parameter ? traced(withContext({ ...UNKNOWN_INPUT, traceSourceKind: 'filesystem_filename' }, context), parameter.name, 'source') : UNKNOWN;
          this.session?.callback({ ...eventCallback!, staticContext: contexts(eventCallback!.staticContext, context) }, expression, [input]);
        } else this.session?.callback({ ...eventCallback!, staticContext: contexts(eventCallback!.staticContext, context) }, expression, []);
      } else if (response?.filesystemStream && ts.isPropertyAccessExpression(callee) && callee.name.text === 'on') {
        this.session!.filesystemModel.unsupportedUses++; this.session?.gap('module_export_unsupported', expression);
      }
      if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && ['append', 'set'].includes(callee.name.text)) {
        const receiver = env.resolve(callee.expression.text);
        if (receiver.queryContent) {
          // Scan/context-local identity shared by direct aliases. Monotonic union
          // across branch clones is conservative; set-overwrite precision is not claimed.
          // Preserve the original content kind/trace selection. currentQuery
          // normalizes tainted content to a searchParams root for reads, which
          // would make a later tainted argument replace the existing source.
          receiver.queryContent.value = queryContent(withHttpUnavailable(
            combineValues([receiver.queryContent.value, ...args]), [receiver]));
        }
      }
      if (responseState?.valid && ts.isPropertyAccessExpression(callee)) {
        this.updateResponseMime(callee.name.text, expression.arguments, responseState);
        if (responseState.contained && responseState.mime !== "html") responseState.mime = "unknown";
      }
      const callable = selectedCallable.callable;
      if (koaRegistration && args[0]?.callable) this.session?.callback(args[0].callable, expression);
      if (honoRegistration && args[1]?.callable) this.session?.callback(args[1].callable, expression);
      if (response?.koaRequest || selectedCallable.koaRequest?.stage === 'next') {
        const role = response?.koaRequest ?? selectedCallable.koaRequest!;
        role.state.valid = false; this.session?.gap('module_export_unsupported', expression);
      }
      const archiveMethod = ts.isPropertyAccessExpression(callee) ? callee.name.text
        : ts.isElementAccessExpression(callee) ? propertyName(callee.argumentExpression) : undefined;
      if (response?.archiveRole && !(response.archiveRole.stage === 'entry' && archiveMethod === 'stream' && expression.arguments.length === 0)) {
        response.archiveRole.state.valid = false; this.session?.archiveModel.unsupported(expression);
      }
      if (selectedCallable.opaqueClosure) this.session?.gap('module_export_unsupported', expression);
      const honoRead = this.honoRead(expression, response);
      if (selectedCallable.honoRequest?.stage === 'next') {
        selectedCallable.honoRequest.state.jsonDataValid = false;
        this.session?.gap('module_export_unsupported', expression);
      }
      if (honoRead?.honoSqlData) {
        this.honoDataReads ??= new WeakMap();
        this.honoDataReads.set(expression, { env, value: honoRead });
      }
      const applied = koaRegistration || honoRegistration ? UNKNOWN : honoRead ?? (archiveOpen ? { ...UNKNOWN, archiveRole: archiveOpen }
        : archivePathCall ? archivePathCall === 'predicate' ? SAFE : traced(combineValues(args), expression, 'call')
        : archiveWriter ? UNKNOWN : filesystemStream ? { ...UNKNOWN, filesystemStream }
        : arrayMutation ? cell.closed && cell.valid ? SAFE : UNKNOWN // Only qualified arrays have a length return; opaque methods remain unknown.
        : filesystemEvent ? { ...UNKNOWN, filesystemStream: response!.filesystemStream }
        : mongoCollection ? { ...UNKNOWN, mongoCollection } : selectedCallable.opaqueClosure ? traced({ ...selectedCallable.opaqueClosure, traceTruncated: true }, expression, 'call')
        : this.session?.invoke(expression, args,this.receiver,this.declared,callable,this.staticContext));
      const invoked = !archiveOpen && !archiveWriter && !arrayMutation && !filesystemStream && !filesystemEvent
        && applied?.kind === 'unknown' && !applied.inputRelated && !applied.constructed && !applied.callable && !applied.mongoCollection && !applied.mongoDb && args.some(isInputRelated)
        ? { ...traced(combineValues(args), expression, 'call'), kind: 'unknown' as const, inputRelated: true, traceTruncated: true, httpTargetUnavailable: httpUnavailable([applied, ...args]) } : applied;
      if (invoked || selectedCallable.opaqueClosure) this.callableActuals.set(expression, { env, value: invoked });
      if (invoked === undefined && !filesystemWrapper?.qualified && !archiveOpen && !archivePathCall && !archiveWriter) {
        // An opaque consumer may change headers; never reuse a stale non-HTML
        // exclusion after the response capability escapes to that consumer.
        for (const value of args) if (value.expressResponse) { value.expressResponse.mime = "unknown"; value.expressResponse.authority = 'unqualified_response'; }
        if (!this.session?.nosqlModel.bound(expression) && !this.session?.mongoModel.selector(expression, response?.mongoCollection)) {
          const seen = new Set<FlowValue>();
          const invalidate = (value: FlowValue, depth = 0): void => {
            if (seen.has(value) || depth > 8 || !this.session?.tick()) return;
            seen.add(value);
            if (value.sequenceContent) value.sequenceContent.valid = value.sequenceContent.closed = false;
            if (value.filesystemStream) value.filesystemStream.valid = false;
            if (value.archiveRole) { value.archiveRole.state.valid = false; this.session.archiveModel.unsupported(expression); }
            if (value.koaRequest) { value.koaRequest.state.valid = false; this.session.gap('module_export_unsupported', expression); }
            if (value.honoRequest) { invalidateHono(value.honoRequest); this.session.gap('module_export_unsupported', expression); }
            if (value.nosqlObject) {
              value.nosqlObject.value = combineValues([value.nosqlObject.value, ...args]);
              value.nosqlObject.modified = true;
            }
            if (value.constructed) value.constructed.valid = false;
            invalidateMongo(value.mongoDb, 'opaque');
            invalidateMongo(value.mongoCollection, 'opaque');
            for (const child of value.properties?.values() ?? []) invalidate(child, depth + 1);
          };
          for (const value of args) invalidate(value);
        }
        for (const value of args) {
          if (value.callable) this.session?.callback(value.callable, expression);
          else if (value.opaqueClosure) this.session?.gap('module_export_unsupported', expression);
        }
        if (responseState?.valid && ts.isPropertyAccessExpression(callee)
          && !["send", "json", "status", "type", "contentType", "set", "header", "setHeader", "append", "removeHeader"].includes(callee.name.text)) {
          responseState.mime = "unknown";
          responseState.authority = 'unqualified_response';
        }
      }
      const argumentFlows: NonNullable<InputFlowUse["argumentFlows"]> = [];
      for (let index = 0; index < expression.arguments.length; index += 1) {
        const value = consumedInput(args[index]);
        if (isInputRelated(value)) argumentFlows.push({ index, certainty: !this.declared && value.kind === "tainted" ? "tainted" : "unknown", staticFlow: evidence(value, expression), fixedDestination: this.certificateAvailable() && fixedQueryDestination(value.urlFragments) });
      }
      if (responseState?.valid && !this.certificateAvailable()) {
        responseState.mime = 'unknown'; responseState.authority = 'unqualified_response';
      }
      const responseMethod = ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
      const htmlResponse = responseState?.valid && expression.arguments.length === 1
        && (responseMethod === "send" || responseMethod === "json")
        && (responseState.mime === "html" || responseState.mime === "unknown"
          || responseMethod === "send" && responseState.mime === "default" && !args[0]?.expressObjectBody)
        ? "express" as const : undefined;
      const htmlResponseMime = htmlResponse && responseState?.mime !== "non_html" ? responseState?.mime : undefined;
      const htmlResponseAuthority = htmlResponse === 'express'
        ? this.declared || this.staticContext || response?.staticContext ? 'unqualified_response' as const : responseState?.authority
        : undefined;
      const httpRole = this.httpRole(expression, args[0]);
      const sqlRole = this.sqlRole(expression, args);
      const nosqlRole = this.nosqlRole(expression, args[0] ? consumedInput(args[0]) : undefined, response?.mongoCollection);
      const forkRole = this.session?.forkModel.role(expression);
      const processRole = processBinding ? this.processRole(expression, args, processBinding) : undefined;
      const filename = args[1] ? filenamePart(args[1]) : undefined;
      const filesystemProcess = filename && filesystemWrapper ? {
        outcome: filesystemWrapper.shell === 'enabled' ? 'argv_shell_input' as const
          : filesystemWrapper.shell === 'disabled' && filesystemWrapper.interpreter ? 'direct_argv_interpreter_unknown' as const
          : this.filesystemCertificateAvailable([filename, ...args]) && filesystemWrapper.shell === 'disabled' && args[1]?.sequenceContent?.closed && args[1].sequenceContent.valid ? 'argv_only_shell_disabled' as const : 'argv_shell_unknown' as const,
        staticFlow: evidence(filename, expression),
      } : undefined;
      const filesystemContext = filesystemProcess ? contexts(filename?.staticContext, conditionalContext('declared_process_wrapper', expression)) : undefined;
      const archive = args[0] ? archivePart(args[0]) : undefined;
      if (archive && archiveWriter && !archiveWriter.options) this.session!.archiveModel.unsupported(expression);
      const archiveWrite = archive && archiveWriter ? {
        outcome: !archiveWriter.options ? 'path_role_unknown' as const
          : this.certificateAvailable() && archiveWriter.closed && this.session?.archiveModel.contained(expression) ? 'lexically_contained' as const : 'path_input' as const,
        staticFlow: evidence(archive, expression),
      } : undefined;
      if (archiveWrite?.outcome === 'lexically_contained') this.session!.archiveModel.lexicalExclusions++;
      else if (archiveWrite) this.session!.archiveModel.writeCandidates++;
      if (filesystemProcess) this.session?.gap('module_export_unsupported', expression);
      if (argumentFlows.length > 0 || httpRole || sqlRole || nosqlRole || forkRole || processRole || filesystemProcess || archiveWrite) this.uses.push({ node: expression, kind: "call", argumentFlows, archiveWrite,
        staticContext: contexts(this.staticContext, filesystemContext, selectedCallable.staticContext, response?.staticContext, ...args.map(value => value.staticContext)),
        localCall: this.session?.modules.localCallable(expression), ...(htmlResponse ? { htmlResponse, htmlResponseMime, htmlResponseAuthority } : {}), ...(httpRole ? { httpRole } : {}), ...(sqlRole ? { sqlRole } : {}), ...(nosqlRole ? { nosqlRole } : {}), ...(forkRole ? { forkRole } : {}), ...(processRole ? { processRole } : {}), ...(filesystemProcess ? { filesystemProcess } : {}), localForkCall: this.session?.localForkCalls.get(expression), localProcessCall: this.session?.localForkCalls.get(expression) });
      return;
    }
    if (ts.isNewExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      const callee = expression.expression;
      if (evaluationShapedCallee(callee, true)) {
        // Syntax-shaped constructor operands only: no constructor dispatch or return proof.
        const argumentFlows: NonNullable<InputFlowUse['argumentFlows']> = [];
        const values: FlowValue[] = [];
        for (let index = 0; index < (expression.arguments?.length ?? 0); index += 1) {
          this.analyzeExpression(expression.arguments![index], env);
          const value = this.evalExpression(expression.arguments![index], env);
          values.push(value);
          if (isInputRelated(value)) argumentFlows.push({ index, certainty: !this.declared && value.kind === 'tainted' ? 'tainted' : 'unknown', staticFlow: evidence(value, expression) });
        }
        this.evaluationActuals.set(expression, { env, values });
        if (argumentFlows.length > 0) this.uses.push({ node: expression, kind: 'call', argumentFlows });
      } else {
        const htmlResponse = this.isHtmlResponse(expression);
        let responseBody: FlowValue | undefined;
        const values: FlowValue[] = [];
        for (const [index, argument] of (expression.arguments ?? []).entries()) {
          this.analyzeExpression(argument, env);
          values.push(this.evalExpression(argument, env));
          // Capture actual body before later options can reassign its binding.
          if (htmlResponse && index === 0) responseBody = this.evalExpression(argument, env);
        }
        const value = this.session?.construct(expression, values, env, this.staticContext);
        if (value) this.constructedActuals.set(expression, { env, value });
        else for (const actual of values) {
          invalidateMongo(actual.mongoDb, 'opaque');
          invalidateMongo(actual.mongoCollection, 'opaque');
        }
        if (responseBody && isInputRelated(responseBody)) this.uses.push({ node: expression, kind: "call", htmlResponse: "web",
          argumentFlows: [{ index: 0, certainty: !this.declared && responseBody.kind === "tainted" ? "tainted" : "unknown", staticFlow: evidence(responseBody, expression) }] });
      }
      return;
    }
    if (ts.isPrefixUnaryExpression(expression)) {
      this.analyzeExpression(expression.operand, env);
      if (expression.operator === ts.SyntaxKind.PlusPlusToken || expression.operator === ts.SyntaxKind.MinusMinusToken) {
        if (ts.isIdentifier(expression.operand)) env.assign(expression.operand.text, UNKNOWN);
        else if (env.resolve(staticMemberPath(expression.operand)[0] ?? '').koaRequest || env.resolve(staticMemberPath(expression.operand)[0] ?? '').honoRequest) this.assignMemberPath(expression.operand, UNKNOWN, env);
      }
      return;
    }
    if (ts.isPostfixUnaryExpression(expression)) {
      this.analyzeExpression(expression.operand, env);
      if (ts.isIdentifier(expression.operand)) env.assign(expression.operand.text, UNKNOWN);
      else if (env.resolve(staticMemberPath(expression.operand)[0] ?? '').koaRequest || env.resolve(staticMemberPath(expression.operand)[0] ?? '').honoRequest) this.assignMemberPath(expression.operand, UNKNOWN, env);
      return;
    }
    if (ts.isDeleteExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      // Only request capabilities need this negative effect. Preserve
      // historical handling for unrelated member expressions.
      if (env.resolve(staticMemberPath(expression.expression)[0] ?? '').koaRequest || env.resolve(staticMemberPath(expression.expression)[0] ?? '').honoRequest) this.assignMemberPath(expression.expression, UNKNOWN, env);
      return;
    }
    if (ts.isConditionalExpression(expression)) {
      this.analyzeExpression(expression.condition, env);
      const whenTrue = env.clone();
      this.analyzeExpression(expression.whenTrue, whenTrue);
      const trueValue = this.evalExpression(expression.whenTrue, whenTrue);
      const whenFalse = env.clone();
      this.analyzeExpression(expression.whenFalse, whenFalse);
      const falseValue = this.evalExpression(expression.whenFalse, whenFalse);
      this.conditionalActuals.set(expression, { env, value: joinValues(trueValue, falseValue) });
      env.merge([whenTrue, whenFalse]);
      return;
    }
    if (ts.isBinaryExpression(expression) && [
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken,
    ].includes(expression.operatorToken.kind)) {
      this.analyzeExpression(expression.left, env);
      const right = env.clone();
      this.analyzeExpression(expression.right, right);
      env.merge([right, env.clone()]);
      return;
    }
    if (ts.isJsxElement(expression)) {
      this.analyzeJsxAttributes(expression.openingElement.attributes, env);
      for (const child of expression.children) {
        if (ts.isJsxExpression(child) && child.expression) this.analyzeExpression(child.expression, env);
        else if (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child)) this.analyzeExpression(child, env);
      }
      return;
    }
    if (ts.isJsxSelfClosingElement(expression)) {
      this.analyzeJsxAttributes(expression.attributes, env);
      return;
    }
    if (ts.isObjectLiteralExpression(expression)) {
      const values = new Map<ts.Node, FlowValue>(), keys = new Map<ts.Node, FlowValue>();
      for (const property of expression.properties) {
        if (ts.isPropertyAssignment(property)) {
          if (ts.isComputedPropertyName(property.name)) {
            this.analyzeExpression(property.name.expression, env);
            keys.set(property, this.evalExpression(property.name.expression, env));
          }
          this.analyzeExpression(property.initializer, env);
          values.set(property, this.evalExpression(property.initializer, env));
        } else if (ts.isShorthandPropertyAssignment(property)) {
          if (property.objectAssignmentInitializer) this.analyzeExpression(property.objectAssignmentInitializer, env);
          values.set(property, env.resolve(property.name.text));
        } else if (ts.isSpreadAssignment(property)) {
          this.analyzeExpression(property.expression, env);
          values.set(property, this.evalExpression(property.expression, env));
        }
      }
      this.objectActuals.set(expression, { env, values, keys });
      return;
    }
    if (ts.isArrayLiteralExpression(expression)) {
      const values = new Map<ts.Node, FlowValue>();
      for (const element of expression.elements) {
        if (!ts.isOmittedExpression(element)) {
          this.analyzeExpression(element, env);
          values.set(element, this.evalExpression(element, env));
        }
      }
      this.arrayActuals.set(expression, { env, values });
      return;
    }
    if (ts.isPropertyAccessExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      return;
    }
    if (ts.isElementAccessExpression(expression)) {
      this.analyzeExpression(expression.expression, env);
      if (expression.argumentExpression) this.analyzeExpression(expression.argumentExpression, env);
      return;
    }
    if (ts.isTemplateExpression(expression)) {
      for (const span of expression.templateSpans) this.analyzeExpression(span.expression, env);
      return;
    }
    if (ts.isTaggedTemplateExpression(expression)) {
      this.analyzeExpression(expression.tag, env);
      this.analyzeExpression(expression.template, env);
      return;
    }
    if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression) || ts.isAwaitExpression(expression) || ts.isYieldExpression(expression)) {
      if (expression.expression) this.analyzeExpression(expression.expression, env);
      return;
    }
    expression.forEachChild((child) => {
      if (isFunctionLike(child)) return;
      if (ts.isExpression(child)) this.analyzeExpression(child, env);
    });
  }

  private analyzeAssignmentTarget(target: ts.Expression, env: FlowEnv): void {
    if (ts.isIdentifier(target)) return;
    if (isAssignmentPattern(target)) {
      target.forEachChild((child) => {
        if (ts.isExpression(child)) this.analyzeExpression(child, env);
      });
      return;
    }
    if (ts.isPropertyAccessExpression(target)) {
      this.analyzeExpression(target.expression, env);
      return;
    }
    if (ts.isElementAccessExpression(target)) {
      this.analyzeExpression(target.expression, env);
      if (target.argumentExpression) this.analyzeExpression(target.argumentExpression, env);
    }
  }

  private analyzeJsxAttributes(attributes: ts.JsxAttributes, env: FlowEnv): void {
    for (const attribute of attributes.properties) {
      if (ts.isJsxSpreadAttribute(attribute)) {
        this.analyzeExpression(attribute.expression, env);
        continue;
      }
      if (!ts.isJsxAttribute(attribute)) continue;
      const initializer = attribute.initializer;
      if (!initializer || ts.isStringLiteral(initializer)) continue;
      if (!ts.isJsxExpression(initializer) || !initializer.expression) continue;
      this.analyzeExpression(initializer.expression, env);
      if (ts.isIdentifier(attribute.name) && attribute.name.text.toLowerCase() === "dangerouslysetinnerhtml") {
        const value = this.evalExpression(initializer.expression, env);
        if (isInputRelated(value)) {
          this.uses.push({
            node: attribute,
            kind: "jsx",
            argumentFlows: [{ index: 0, certainty: !this.declared && value.kind === "tainted" ? "tainted" : "unknown", staticFlow: evidence(value, attribute) }],
          });
        }
      }
    }
  }

  private assignMemberPath(target: ts.Expression, value: FlowValue, env: FlowEnv): void {
    const path = staticMemberPath(target);
    if (path.length >= 2) env.assignProperty(path, withoutUrlProof(value));
  }

  private recordAssignment(node: ts.BinaryExpression, value: FlowValue): void {
    if (isInputRelated(value)) {
      const browserLocationRole: BrowserLocationRole | undefined = directBrowserLocationReceiver(node)
        ? this.declared || this.staticContext || value.staticContext ? 'unknown_receiver'
          : this.session?.browserLocationModel.role(node) ?? 'unknown_receiver' : undefined;
      this.uses.push({ node, kind: "assignment", ...(browserLocationRole ? { browserLocationRole } : {}),
        argumentFlows: [{ index: 0, certainty: !this.declared && value.kind === "tainted" ? "tainted" : "unknown", staticFlow: evidence(value, node) }] });
    }
  }

  private httpRole(call: ts.CallExpression, value?: FlowValue): HttpRoleUse | undefined {
    const model = this.session?.httpModel;
    const bound = model?.bound(call) === true;
    if (!bound && !legacyAxiosRequest(call)) return undefined;
    const inputRelated = value ? isInputRelated(value) : false;
    const config = value?.httpConfig;
    if (!this.certificateAvailable() && inputRelated) return {bound,inputRelated,outcome:'unknown_role',certainty:'unknown',...(value ? {staticFlow:evidence(value,call)} : {})};
    if (bound && model?.canQualify(call) && config?.closed && !config.target.httpTargetUnavailable) {
      if (config.encodedQueryInitialUrl && fixedQueryDestination(config.target.urlFragments)) return { bound, inputRelated, outcome: 'encoded_query_fixed_initial_url' };
      if (isInputRelated(config.target)) return { bound, inputRelated: true, outcome: 'target_input',
        certainty: config.target.kind === 'tainted' ? 'tainted' : 'unknown', staticFlow: evidence(config.target, call) };
      if (config.fixedInitialUrl) return { bound, inputRelated, outcome: 'payload_only_fixed_initial_url' };
    }
    const staticFlow = value && inputRelated ? evidence(value, call) : undefined;
    return { bound, inputRelated, outcome: 'unknown_role', certainty: 'unknown',
      ...(staticFlow ? { staticFlow: { ...staticFlow, truncated: true } } : {}) };
  }

  private processRole(call: ts.CallExpression, args: readonly FlowValue[], binding: ChildProcessBindingUse): ProcessRoleUse {
    const modeled = this.session!.processModel.layout(call, binding);
    const layout = { ...modeled, qualified: modeled.qualified && this.certificateAvailable() };
    const base = { api: binding.method, identity: binding.identity, shell: layout.shell };
    const selected = (value: FlowValue, outcome: ProcessRoleUse['outcome'], index: number, executable = false, known = false): ProcessRoleUse => {
      const certain = known && !this.declared && !this.staticContext && value.kind === 'tainted';
      const flow = evidence(value, call);
      return { ...base, inputRelated: true, outcome, operandIndex: index, executable, certainty: certain ? 'tainted' : 'unknown',
        ...(flow ? { staticFlow: certain ? flow : { ...flow, truncated: true } } : {}) };
    };
    const first = args[0] ? consumedInput(args[0]) : undefined;
    if (first && isInputRelated(first)) return selected(first,
      layout.shell === 'enabled' ? 'command_input' : layout.shell === 'disabled' ? 'executable_input' : 'unknown_role', 0,
      layout.shell === 'disabled', layout.qualified && layout.shell !== 'unresolved');
    const options = layout.optionsIndex === undefined ? undefined : args[layout.optionsIndex];
    const shell = layout.shellField ? options?.properties?.get('shell') : undefined;
    if (shell && isInputRelated(shell)) return selected(consumedInput(shell), 'shell_executable_input', layout.optionsIndex!, true, layout.qualified);
    const argv = layout.argvIndex === undefined ? undefined : args[layout.argvIndex] ? consumedInput(args[layout.argvIndex]) : undefined;
    if (argv && isInputRelated(argv)) {
      if (layout.qualified && layout.shell === 'enabled') return selected(argv, 'argv_shell_input', layout.argvIndex!, false, true);
      if (layout.qualified && layout.shell === 'disabled' && first?.kind === 'safe' && first.sqlFixedText && !first.sqlScalarUnavailable) {
        return { ...base, inputRelated: true, outcome: 'argv_only_fixed_executable' };
      }
      return selected(argv, 'unknown_role', layout.argvIndex!);
    }
    // Closed unrelated env/cwd/argv0 data is not shell/executable evidence.
    if (!layout.qualified && options && isInputRelated(options)) return selected(consumedInput(options), 'unknown_role', layout.optionsIndex!);
    return { ...base, inputRelated: false, outcome: 'no_input' };
  }

  private sqlRole(call: ts.CallExpression, args: readonly FlowValue[]): SqlRoleUse | undefined {
    const model=this.session?.sqlModel; if (!model?.bound(call)) return undefined;
    const config=args[0]?.sqlConfig;
    const inputRelated=args.some(isInputRelated);
    if (!this.certificateAvailable() && inputRelated) { const value=args.find(isInputRelated)!; return {bound:true,inputRelated,outcome:'unknown_role',certainty:'unknown',staticFlow:evidence(value,call)}; }
    const text=config?.text ?? args[0];
    const values=config?.values ?? args[1];
    const shape=config ? config.closed && call.arguments.length===1
      : call.arguments.length>=1 && call.arguments.length<=2 && text && !text.sqlScalarUnavailable && !args[0]?.properties
        && !(ts.isObjectLiteralExpression(call.arguments[0])) && !(args.length===2 && (args[1].sqlCallback || model.callbackArgument(call.arguments[1])));
    if (model.dispatch(call) && shape && text && !text.sqlScalarUnavailable) {
      if (isInputRelated(text)) return { bound:true,inputRelated:true,outcome:'statement_input',certainty:text.kind==='tainted'?'tainted':'unknown',staticFlow:evidence(text,call) };
      const fixed=fixedSqlCharacters(text)!==undefined;
      if (fixed && (!values || values.sqlArray?.closed===true && !values.sqlDataUnavailable)) return { bound:true,inputRelated,outcome:'values_only_fixed_text' };
    }
    const observed=args.find(isInputRelated); const flow=observed ? evidence(observed,call) : undefined;
    return { bound:true,inputRelated,outcome:'unknown_role',certainty:'unknown',...(flow ? {staticFlow:{...flow,truncated:true}} : {}) };
  }

  private nosqlRole(call: ts.CallExpression, selector?: FlowValue, mongo?: MongoCollectionRole): NoSqlRoleUse | undefined {
    const model = this.session?.nosqlModel;
    const mongoBound = this.session?.mongoModel.selector(call, mongo) === true;
    if ((!model?.bound(call) && !mongoBound) || !selector) return undefined;
    if ((this.staticContext || selector.staticContext) && mongoBound
      && (mongo!.db.conditionalOrigin === false || ['write', 'ambiguous'].includes(mongo!.invalidReason ?? '') || ['write', 'ambiguous'].includes(mongo!.db.invalidReason ?? ''))) {
      this.session?.gap('module_export_unsupported', call); return undefined;
    }
    let modified = false;
    const current = (value: FlowValue, depth = 0): FlowValue => {
      if (!this.session?.tick()) return value;
      if (depth > 8) { this.session.gap('alias_limit', call); return value; }
      const object = value.nosqlObject;
      if (object?.modified || value.nosqlUnknown) modified = true;
      const values = [value, ...(value.nosqlUnknown ? [value.nosqlUnknown] : []), ...(object?.modified ? [object.value] : []), ...[...value.properties?.values() ?? []].map(child => current(child, depth + 1))];
      return { ...value, ...combineValues(values), properties: value.properties, nosqlObject: object };
    };
    const observed = current(selector);
    const inputRelated = isInputRelated(observed);
    const api = mongoBound ? 'mongodb2' as const : 'marsdb' as const;
    if (mongoBound && (!mongo!.valid || !mongo!.db.valid)) this.session?.gap('module_export_unsupported', call);
    if (!inputRelated) return { inputRelated: false, outcome: 'string_selector', api };
    const candidate = (value: FlowValue, outcome: NoSqlRoleUse['outcome']): NoSqlRoleUse => ({ inputRelated: true, outcome, api,
      certainty: !this.declared && value.kind === 'tainted' && outcome !== 'unknown_role' ? 'tainted' : 'unknown',
      staticFlow: evidence(value, call) });
    if (!this.certificateAvailable() || selector.staticContext || !(mongoBound ? mongo!.valid && mongo!.db.valid : model!.qualified(call)) || modified) {
      if (mongoBound) this.session?.gap('module_export_unsupported', call);
      if (selector.nosqlWhere && isInputRelated(selector.nosqlWhere.value)) return { ...candidate(selector.nosqlWhere.value, 'unknown_role'), operatorNode: selector.nosqlWhere.node };
      return candidate(observed, 'unknown_role');
    }
    if (selector.nosqlWhere && isInputRelated(selector.nosqlWhere.value)) return { ...candidate(selector.nosqlWhere.value, 'where_input'), operatorNode: selector.nosqlWhere.node };
    const inspect = (value: FlowValue, expression: ts.Expression | undefined, depth: number): NoSqlRoleUse | undefined => {
      if (!this.session?.tick() || depth > 8) return candidate(value, 'unknown_role');
      if (!isInputRelated(value)) return undefined;
      const object = value.nosqlObject;
      if (!object || !object.closed || object.modified || !value.properties) {
        if (expression && model?.stringAt(expression, call)) return undefined;
        return candidate(value, object ? 'unknown_role' : 'selector_input');
      }
      let selected: NoSqlRoleUse | undefined;
      for (const property of object.node.properties) {
        if (!(ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property))) return candidate(value, 'unknown_role');
        const key = propertyName(property.name); if (!key) return candidate(value, 'unknown_role');
        const field = current(value.properties.get(key) ?? UNKNOWN);
        if (!isInputRelated(field)) continue;
        const result = key === '$where' ? candidate(field, 'where_input')
          : key.startsWith('$') ? candidate(field, 'unknown_role')
            : inspect(field, ts.isPropertyAssignment(property) ? property.initializer : property.name, depth + 1);
        if (result?.outcome === 'where_input') return result;
        if (result) selected ??= result;
      }
      return selected;
    };
    return inspect(selector, call.arguments[0], 0) ?? { inputRelated: true, outcome: 'string_selector', api };
  }

  /** Literal same-response MIME state only; no header values are retained in reports. */
  private updateResponseMime(method: string, args: readonly ts.Expression[], state: ExpressResponseState): void {
    const literal = (value: ts.Expression | undefined): string | undefined => value && ts.isStringLiteralLike(value) ? value.text.trim().toLowerCase() : undefined;
    const mime = (value: ts.Expression | undefined, extension = false): ExpressMime => {
      const text = literal(value)?.split(";", 1)[0].trim();
      if (text === "text/html" || extension && text === "html") return "html";
      if (["text/plain", "application/json"].includes(text ?? "") || extension && ["txt", "text", "json"].includes(text ?? "")) return "non_html";
      return "unknown";
    };
    if (method === "type" || method === "contentType") { state.mime = args.length === 1 ? mime(args[0], true) : "unknown"; return; }
    if (method === "removeHeader") {
      const header = literal(args[0]);
      if (args.length !== 1 || header === undefined) state.mime = "unknown";
      else if (header === "content-type") state.mime = "default";
      return;
    }
    if (!["set", "header", "setHeader", "append"].includes(method)) return;
    if (args.length === 2) {
      const header = literal(args[0]);
      if (header === undefined) state.mime = "unknown";
      else if (header === "content-type") state.mime = method === "append" ? "unknown" : mime(args[1]);
      return;
    }
    if ((method === "set" || method === "header") && args.length === 1 && ts.isObjectLiteralExpression(args[0])) {
      for (const property of args[0].properties) {
        if (this.session && !this.session.tick()) { state.mime = "unknown"; return; }
        if (!ts.isPropertyAssignment(property) || ts.isComputedPropertyName(property.name)) { state.mime = "unknown"; return; }
        if (propertyName(property.name)?.toLowerCase() === "content-type") state.mime = mime(property.initializer);
      }
      return;
    }
    state.mime = "unknown";
  }

  /** Closed literal HTML headers only. No inferred MIME type for a plain Response body. */
  private isHtmlResponse(node: ts.NewExpression): boolean {
    if (!ts.isIdentifier(node.expression) || node.arguments?.length !== 2) return false;
    const symbol = this.session?.modules.symbol(node.expression);
    const declaration = symbol?.declarations?.length === 1 ? symbol.declarations[0] : undefined;
    const nextImport = declaration && ts.isImportSpecifier(declaration)
      && !declaration.isTypeOnly && !declaration.parent.parent.isTypeOnly
      && (declaration.propertyName ?? declaration.name).text === "NextResponse"
      && ts.isImportDeclaration(declaration.parent.parent.parent)
      && ts.isStringLiteral(declaration.parent.parent.parent.moduleSpecifier)
      && declaration.parent.parent.parent.moduleSpecifier.text === "next/server";
    if (!(node.expression.text === "Response" && !symbol) && !nextImport) return false;
    const options = node.arguments[1];
    if (!ts.isObjectLiteralExpression(options)) return false;
    let headers: ts.ObjectLiteralExpression | undefined;
    const optionNames = new Set<string>();
    for (const property of options.properties) {
      if (this.session && !this.session.tick()) return false;
      if (!ts.isPropertyAssignment(property) || ts.isComputedPropertyName(property.name)) return false;
      const name = propertyName(property.name);
      if (!name || optionNames.has(name)) return false;
      optionNames.add(name);
      if (name === "headers") {
        if (!ts.isObjectLiteralExpression(property.initializer)) return false;
        headers = property.initializer;
      }
    }
    if (!headers) return false;
    let html = false;
    const names = new Set<string>();
    for (const property of headers.properties) {
      if (this.session && !this.session.tick()) return false;
      if (!ts.isPropertyAssignment(property) || ts.isComputedPropertyName(property.name)) return false;
      const name = propertyName(property.name)?.toLowerCase();
      if (!name || names.has(name) || !ts.isStringLiteralLike(property.initializer)) return false;
      names.add(name);
      if (name === "content-type") html = /^text\/html(?:\s*;|\s*$)/i.test(property.initializer.text.trim());
    }
    return html;
  }

  private honoRead(call: ts.CallExpression, receiver?: FlowValue): FlowValue | undefined {
    const role = receiver?.honoRequest;
    if (!role) return undefined;
    const callee = call.expression;
    const method = ts.isPropertyAccessExpression(callee) && !callee.questionDotToken ? callee.name.text : undefined;
    const plain = !call.questionDotToken && !call.arguments.some(ts.isSpreadElement);
    if (role.state.valid && plain && role.stage === 'context'
      && ['text', 'json', 'html', 'redirect', 'body', 'status', 'header', 'newResponse', 'set', 'get'].includes(method ?? '')) return UNKNOWN;
    if (role.state.valid && plain && role.stage === 'request') {
      if ((method === 'query' || method === 'param') && (call.arguments.length === 0
        || call.arguments.length === 1 && ts.isStringLiteralLike(call.arguments[0]))) return { ...traced(TAINTED, call, 'source'), honoSqlData: 'request_data' };
      // Body reading starts at this call. Later request replacement cannot
      // erase the captured promise's provenance; opaque promise effects can.
      if (method === 'json' && call.arguments.length === 0) {
        role.state.jsonReads = (role.state.jsonReads ?? 0) + 1;
        // Older Hono versions can share a cached parsed object between reads.
        role.state.jsonDataValid = role.state.jsonDataValid !== false && role.state.jsonReads === 1;
        return { ...UNKNOWN, honoSqlData: 'json_promise',
          honoRequest: { stage: 'promise', state: { valid: true }, origin: call, jsonSourceState: role.state } };
      }
    }
    invalidateHono(role);
    this.session?.gap('module_export_unsupported', call);
    return UNKNOWN;
  }

  private evalExpression(expression: ts.Expression, env: FlowEnv): FlowValue {
    if (this.session && !this.session.tick()) return UNKNOWN;
    if (ts.isIdentifier(expression)) {
      if (!env.has(expression.text) && this.session?.sqlModel.callbackArgument(expression)) return { ...UNKNOWN, sqlCallback:true };
      if (!env.has(expression.text) && this.session?.modules.symbol(expression)) return UNKNOWN;
      const current = consumedInput(currentQuery(env.resolve(expression.text)));
      const value = current.properties && this.session?.sqlModel.dataIdentifierUnavailable(expression) ? {...current,sqlDataUnavailable:true} : current;
      return value.kind === "root" && !value.trace?.some(item => item.role === "source") ? traced(value, expression, "source") : value;
    }
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) return literalValue(expression.text);
    if (ts.isNumericLiteral(expression) || ts.isBigIntLiteral(expression) || ts.isRegularExpressionLiteral(expression)) return SAFE;
    if (expression.kind === ts.SyntaxKind.TrueKeyword || expression.kind === ts.SyntaxKind.FalseKeyword || expression.kind === ts.SyntaxKind.NullKeyword || expression.kind === ts.SyntaxKind.UndefinedKeyword) return SAFE;
    if (ts.isAwaitExpression(expression)) {
      const value = this.evalExpression(expression.expression, env);
      if (value.honoRequest?.stage === 'promise') {
        if (!value.honoRequest.state.valid) { this.session?.gap('module_export_unsupported', expression); return UNKNOWN; }
        return value.honoRequest.origin ? traced(TAINTED, value.honoRequest.origin, 'source') : UNKNOWN;
      }
      return value.archiveRole?.stage === 'promise' && value.archiveRole.state.valid
        ? { ...value, archiveRole: { ...value.archiveRole, stage: 'directory' } } : value;
    }
    if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)) return this.evalExpression(expression.expression, env);
    if (ts.isYieldExpression(expression)) return expression.expression ? this.evalExpression(expression.expression, env) : UNKNOWN;
    if (expression.kind === ts.SyntaxKind.ThisKeyword) return this.constructedReceiver ?? UNKNOWN;
    if (ts.isPropertyAccessExpression(expression)) {
      const receiver = this.evalExpression(expression.expression, env);
      if (receiver.archiveRole?.state.valid && receiver.archiveRole.stage === 'entry' && expression.name.text === 'path') {
        this.session!.archiveModel.entryPaths++;
        return traced(withContext({ ...UNKNOWN_INPUT, traceSourceKind: 'archive_entry_path' },
          conditionalContext('declared_package_api', receiver.archiveRole.origin)), expression, 'source');
      }
      if (receiver.constructed) return receiver.constructed.valid ? receiver.constructed.slots.get(expression.name.text) ?? UNKNOWN : UNKNOWN;
      const projected = currentQuery(projectValue(receiver, expression.name.text));
      if (receiver.koaRequest && !receiver.koaRequest.state.valid) this.session?.gap('module_export_unsupported', expression);
      if (receiver.honoRequest && !receiver.honoRequest.state.valid) this.session?.gap('module_export_unsupported', expression);
      if (receiver.honoRequest?.stage === 'request' && !['query','param','json'].includes(expression.name.text)) receiver.honoRequest.state.jsonDataValid = false;
      return receiver.koaRequest && isInputRelated(projected) && !projected.trace?.some(step => step.role === 'source') ? traced(projected, expression, 'source') : projected;
    }
    if (ts.isElementAccessExpression(expression)) {
      const key = propertyName(expression.argumentExpression);
      const base = this.evalExpression(expression.expression, env);
      if (base.archiveRole?.state.valid && base.archiveRole.stage === 'entry' && key === 'path') {
        this.session!.archiveModel.entryPaths++;
        return traced(withContext({ ...UNKNOWN_INPUT, traceSourceKind: 'archive_entry_path' },
          conditionalContext('declared_package_api', base.archiveRole.origin)), expression, 'source');
      }
      if (key !== undefined) {
        const projected = currentQuery(projectValue(base, key));
        if (base.koaRequest && !base.koaRequest.state.valid) this.session?.gap('module_export_unsupported', expression);
        if (base.honoRequest && !base.honoRequest.state.valid) this.session?.gap('module_export_unsupported', expression);
        if (base.honoRequest?.stage === 'request' && !['query','param','json'].includes(key)) base.honoRequest.state.jsonDataValid = false;
        return base.koaRequest && isInputRelated(projected) && !projected.trace?.some(step => step.role === 'source') ? traced(projected, expression, 'source') : projected;
      }
      // Dynamic keys cannot be resolved in this bounded analysis, but a
      // tainted base still means the selected property is input-related.
      const keyValue = expression.argumentExpression
        ? this.evalExpression(expression.argumentExpression, env)
        : UNKNOWN;
      const value=isInputRelated(base) || isInputRelated(keyValue)
        ? inheritTrace(base.kind === "tainted" ? TAINTED : UNKNOWN_INPUT, [base, keyValue])
        : UNKNOWN;
      return {...value,sqlDataUnavailable:base.sqlDataUnavailable || keyValue.sqlDataUnavailable, httpTargetUnavailable:httpUnavailable([base,keyValue])};
    }
    if (ts.isArrayLiteralExpression(expression)) {
      const observed = this.arrayActuals.get(expression);
      const actuals = observed?.env === env ? observed : undefined;
      const properties = new Map<string, FlowValue>();
      const values: FlowValue[] = [];
      expression.elements.forEach((element, index) => {
        if (ts.isOmittedExpression(element)) return;
        const value = actuals?.values.get(element) ?? this.evalExpression(element, env);
        properties.set(String(index), withoutUrlProof(value));
        values.push(value);
      });
      for (const value of values) containResponse(value);
      const combined = combineValues(values);
      const filenameValues = values.map(filenamePart).filter((value): value is FlowValue => !!value);
      return { ...combined, expressObjectBody: true, properties,
        ...(filenameValues.length ? { filesystemContent: combineValues(filenameValues) } : {}),
        ...(this.session?.sqlModel ? { sqlArray:{ node:expression,closed:this.session.sqlModel.closedArray(expression,
          this.honoDataReads ? (call, awaited) => {
            const read = this.honoDataReads!.get(call);
            return read?.env === env && (awaited ? read.value.honoSqlData === 'json_promise'
              && read.value.honoRequest?.state.valid === true && read.value.honoRequest.jsonSourceState?.jsonDataValid === true
              : read.value.honoSqlData === 'request_data');
          } : undefined) && !combined.sqlDataUnavailable,count:expression.elements.length } } : {}) };
    }
    if (ts.isObjectLiteralExpression(expression)) {
      const observed = this.objectActuals.get(expression);
      const actuals = observed?.env === env ? observed : undefined;
      const properties = new Map<string, FlowValue>();
      const values: FlowValue[] = [];
      let target: FlowValue | undefined; let sqlText:FlowValue|undefined; let sqlValues:FlowValue|undefined;
      let nosqlWhere: FlowValue['nosqlWhere'];
      const dataUnavailable=expression.properties.some(p=>!(ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p))
        || ts.isComputedPropertyName(p.name) || ['toPostgres','toString','__proto__'].includes(propertyName(p.name) ?? ''));
      const sqlSnapshot=(value:FlowValue):FlowValue=>({kind:value.kind,root:value.root,inputRelated:value.inputRelated,trace:value.trace?.map(s=>({role:s.role,location:{...s.location}})),traceTruncated:value.traceTruncated,traceSourceKind:value.traceSourceKind,httpTargetUnavailable:currentQuery(value).httpTargetUnavailable,urlFragments:value.urlFragments?.map(p=>({...p})),sqlScalarUnavailable:value.sqlScalarUnavailable,sqlFixedText:value.sqlFixedText ? {...value.sqlFixedText} : undefined,sqlCallback:value.sqlCallback,sqlDataUnavailable:value.sqlDataUnavailable,sqlArray:value.sqlArray ? {...value.sqlArray} : undefined});
      const captureTarget = (value: FlowValue): void => {
        const current = currentQuery(value);
        // Immutable construction-time snapshot; no object/alias/query identity.
        target = { kind: current.kind, root: current.root, inputRelated: current.inputRelated,
          trace: current.trace?.map(s => ({ role: s.role, location: { ...s.location } })), traceTruncated: current.traceTruncated, traceSourceKind: current.traceSourceKind,
          urlFragments: current.urlFragments?.map(p => ({ ...p })), httpTargetUnavailable: current.httpTargetUnavailable };
      };
      for (const property of expression.properties) {
        if (ts.isPropertyAssignment(property)) {
          const key = propertyName(property.name);
          const value = actuals?.values.get(property) ?? this.evalExpression(property.initializer, env);
          if (ts.isComputedPropertyName(property.name)) values.push(actuals?.keys.get(property) ?? this.evalExpression(property.name.expression, env));
          if (key === 'url') captureTarget(value);
          if (key === 'text') sqlText=sqlSnapshot(value);
          if (key === 'values') sqlValues=sqlSnapshot(value);
          if (key === '$where') nosqlWhere = { node: property, value: traced(value, property, 'intermediate') };
          values.push(value);
          if (key !== undefined) properties.set(key, withoutUrlProof(value));
        } else if (ts.isShorthandPropertyAssignment(property)) {
          // Preserve the existing general shorthand/request-shaped fallback.
          // Only the new HTTP target snapshot needs an actual source position.
          const value = actuals?.values.get(property) ?? env.resolve(property.name.text);
          if (property.name.text === 'url') captureTarget(value.kind === 'root' && !value.trace?.length
            ? traced(value, property.name, 'source') : value);
          if (property.name.text==='text') sqlText=sqlSnapshot(value.kind==='root' && !value.trace?.length ? traced(value,property.name,'source') : value);
          if (property.name.text==='values') sqlValues=sqlSnapshot(value);
          values.push(value);
          properties.set(property.name.text, withoutUrlProof(value));
        } else if (ts.isSpreadAssignment(property)) {
          const value = actuals?.values.get(property) ?? this.evalExpression(property.expression, env);
          values.push(value);
          if (value.nosqlObject?.modified) values.push(value.nosqlObject.value);
          for (const [key, propertyValue] of value.properties ?? []) properties.set(key, withoutUrlProof(propertyValue));
          if (!value.properties || value.properties.has('$where')) nosqlWhere = value.nosqlWhere;
        }
      }
      for (const value of values) containResponse(value);
      const combined = combineValues(values);
      const closed = this.session?.httpModel.closedShape(expression) === true;
      return { ...combined, expressObjectBody: true, properties, nosqlWhere,
        nosqlObject: { node: expression, value: combined, modified: false, closed: expression.properties.every(property =>
          (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) && !ts.isComputedPropertyName(property.name)
          && !['__proto__'].includes(propertyName(property.name) ?? '')) },
        sqlDataUnavailable:combined.sqlDataUnavailable || dataUnavailable, ...(sqlText ? {sqlConfig:{node:expression,closed:this.session?.sqlModel.closedConfig(expression)===true,text:sqlText,values:sqlValues}} : {}), ...(target ? { httpConfig: { node: expression, closed,
        fixedInitialUrl: target.kind === 'safe' && !target.httpTargetUnavailable && fixedInitialHttpUrl(target.urlFragments),
        encodedQueryInitialUrl: !target.httpTargetUnavailable && fixedQueryDestination(target.urlFragments), target } } : {}) };
    }
    if (ts.isTemplateExpression(expression)) {
      return concatValues([literalValue(expression.head.text), ...expression.templateSpans.flatMap((span) => [this.evalExpression(span.expression, env), literalValue(span.literal.text)])]);
    }
    if (ts.isNoSubstitutionTemplateLiteral(expression)) return SAFE;
    if (ts.isConditionalExpression(expression)) {
      const observed = this.conditionalActuals.get(expression);
      return observed?.env === env ? observed.value : joinValues(this.evalExpression(expression.whenTrue, env), this.evalExpression(expression.whenFalse, env));
    }
    if (ts.isBinaryExpression(expression)) {
      if (isAssignmentOperator(expression.operatorToken.kind)) {
        if (isSimpleAssignment(expression.operatorToken.kind)) return this.evalExpression(expression.right, env);
        return combineValues([ts.isIdentifier(expression.left) ? env.resolve(expression.left.text) : UNKNOWN, this.evalExpression(expression.right, env)]);
      }
      if (expression.operatorToken.kind === ts.SyntaxKind.PlusToken) return concatValues([this.evalExpression(expression.left, env), this.evalExpression(expression.right, env)]);
      if ([
        ts.SyntaxKind.AmpersandAmpersandToken,
        ts.SyntaxKind.BarBarToken,
        ts.SyntaxKind.QuestionQuestionToken,
      ].includes(expression.operatorToken.kind)) return joinValues(this.evalExpression(expression.left, env), this.evalExpression(expression.right, env));
      return UNKNOWN;
    }
    if (ts.isCallExpression(expression)) {
      const applied = this.callableActuals.get(expression);
      if (applied?.env === env) return applied.value ?? UNKNOWN;
      const observed = this.evaluationActuals.get(expression);
      const args = observed?.env === env ? observed.values : expression.arguments.map((argument) => this.evalExpression(argument, env));
      const returned = this.session?.invoke(expression, args,this.receiver,this.declared,this.capabilityValue(expression.expression, env).callable,this.staticContext);
      if (returned) {
        // Unmodelled captures/opaque returns cannot erase a prior input candidate.
        if (returned.kind === "unknown" && !returned.inputRelated && !returned.constructed && !returned.callable && !returned.mongoCollection && !returned.mongoDb && args.some(isInputRelated)) {
          return { ...traced(combineValues(args), expression, "call"), kind: 'unknown', inputRelated: true, traceTruncated: true, httpTargetUnavailable:httpUnavailable([returned,...args]) };
        }
        return returned.sqlArray && this.session?.sqlModel.returnedArrayUse(expression)!==true
          ? {...returned,sqlArray:{...returned.sqlArray,closed:false}} : returned;
      }
      const receiver = ts.isPropertyAccessExpression(expression.expression) ? this.evalExpression(expression.expression.expression, env) : undefined;
      const method = ts.isPropertyAccessExpression(expression.expression) ? expression.expression.name.text : undefined;
      const honoRead = this.honoRead(expression, receiver);
      if (honoRead) return honoRead;
      if (ts.isIdentifier(expression.expression) && expression.expression.text === "URLSearchParams") {
        return withHttpUnavailable(args.some(isInputRelated) ? inheritTrace(rootValue("searchParams"), args) : args.every((value) => value.kind === "safe") ? SAFE : UNKNOWN, args);
      }
      if (method === 'toString' && receiver?.queryContent && args.length === 0) {
        // An immutable scalar snapshot: never retain the mutable content pointer.
        const content = receiver.queryContent.value;
        const serialized = content.kind === 'safe' ? SAFE : isInputRelated(content) ? UNKNOWN_INPUT : UNKNOWN;
        return { ...traced(inheritTrace(serialized, [currentQuery(receiver)]), expression, 'call'),
          urlFragments: receiver.nativeQuery ? [{ encodedQuery: true }] : undefined,
          traceTruncated: receiver.traceTruncated || !receiver.nativeQuery, httpTargetUnavailable:httpUnavailable([receiver]) };
      }
      // MIME setters are applied once during ordered statement analysis; reads
      // of fluent return values must not replay earlier header writes.
      if (receiver?.expressResponse?.valid && ["status", "type", "contentType", "set", "header", "append"].includes(method ?? "")) {
        return { ...UNKNOWN, expressResponse: receiver.expressResponse };
      }
      if (method === "json" && receiver?.kind === "root" && receiver.root === "request") return withHttpUnavailable(traced(inheritTrace(TAINTED, [receiver]), expression, "source"), [receiver,...args]);
      if (method === "get" && receiver?.kind === "root" && (receiver.root === "searchParams" || receiver.root === "formData")) return withHttpUnavailable(traced(inheritTrace(TAINTED, [receiver]), expression, "source"), [receiver,...args]);
      if (method === "get" && receiver?.kind === "tainted") return withHttpUnavailable(traced(inheritTrace(TAINTED, [receiver]), expression, "source"), [receiver,...args]);
      if (method === "get" && receiver && isInputRelated(receiver)) return withHttpUnavailable(traced(inheritTrace(UNKNOWN_INPUT, [receiver]), expression, "source"), [receiver,...args]);
      if (receiver && isInputRelated(receiver)) return { ...traced(combineValues([receiver]), expression, "call"), kind: 'unknown', inputRelated: true, traceTruncated: true, httpTargetUnavailable:httpUnavailable([receiver,...args]) };
      if (args.some(isInputRelated)) return { ...traced(combineValues(args), expression, "call"), kind: 'unknown', inputRelated: true, traceTruncated: true, httpTargetUnavailable:httpUnavailable(receiver ? [receiver,...args] : args) };
      return withHttpUnavailable(UNKNOWN, receiver ? [receiver,...args] : args);
    }
    if (ts.isNewExpression(expression)) {
      const constructed = this.constructedActuals.get(expression);
      if (constructed?.env === env) return constructed.value;
      const observed = this.evaluationActuals.get(expression);
      const values = observed?.env === env ? observed.values : (expression.arguments ?? []).map((argument) => this.evalExpression(argument, env));
      if (ts.isIdentifier(expression.expression) && expression.expression.text === 'URLSearchParams' && this.session && !this.session.modules.symbol(expression.expression)) {
        const content = queryContent(combineValues(values));
        return { ...inheritTrace(isInputRelated(content) ? rootValue('searchParams') : SAFE, values),
          httpTargetUnavailable:content.httpTargetUnavailable, queryContent: { value: content }, nativeQuery: this.session.queryModel.supports(expression) };
      }
      if (ts.isIdentifier(expression.expression) && expression.expression.text === "URLSearchParams") {
        return withHttpUnavailable(values.some(isInputRelated) ? inheritTrace(rootValue("searchParams"), values) : values.every((value) => value.kind === "safe") ? SAFE : UNKNOWN, values);
      }
      return withHttpUnavailable(values.some(isInputRelated) ? UNKNOWN_INPUT : UNKNOWN, values);
    }
    if (ts.isPrefixUnaryExpression(expression) || ts.isPostfixUnaryExpression(expression)) return UNKNOWN;
    if (ts.isSpreadElement(expression)) return this.evalExpression(expression.expression, env);
    if (ts.isArrowFunction(expression)) {
      if (!this.session?.modules.indexComplete) return { ...SAFE, sqlCallback: true };
      const callable = this.session?.closure(expression, env, this.constructedReceiver, this.staticContext);
      return { ...SAFE, staticContext: this.staticContext, sqlCallback: true, callable, ...(!callable && this.session ? { opaqueClosure: this.session.opaqueCaptures(expression, env) } : {}) };
    }
    if (ts.isFunctionExpression(expression)) return {...SAFE,sqlCallback:true};
    if (ts.isClassExpression(expression)) return SAFE;
    return UNKNOWN;
  }
}

/**
 * Find direct and same-function input flows. Unknown function calls deliberately
 * stay unknown; this avoids claiming that an unrecognised sanitizer is safe or
 * that an arbitrary wrapper preserves taint.
 */
export function findInputFlows(sourceFile: ts.SourceFile): InputFlowUse[] {
  return new DataflowAnalyzer(sourceFile).run();
}

export function findSnapshotInputFlows(files: readonly ts.SourceFile[], limits: FlowLimits = FLOW_LIMITS, parseErrorCount = 0, roleProofScopeComplete = true, parseFiles?: Iterable<ParseFileEvidence>, metadata: readonly CollectedFile[] = []): {
  uses: InputFlowUse[]; reasons: string[]; metrics: Record<string, number | string | boolean>; analysisGaps?: import('../contracts.js').AnalysisGaps;
} {
  const session = new FlowSession(files, limits, parseErrorCount, roleProofScopeComplete, parseFiles, metadata);
  session.run(files);
  const sourceContexts = new Map<ts.Node, StaticCandidateContext>();
  for (const use of session.uses) {
    if (!use.staticContext) continue;
    if (!session.tick()) break;
    const merged = contexts(sourceContexts.get(use.node), use.staticContext)!;
    sourceContexts.set(use.node, merged);
    if (merged.truncated) session.gap('module_export_unsupported', use.node);
  }
  return { uses: session.uses, reasons: [...session.reasons].sort(), analysisGaps: session.diagnostics.result(), metrics: {
    flowModel: "bounded-static-local-relative-v1", budgetModel: "shared-index-separate-flow-v1", entrySeedModel: "request_shaped_uncalled_exported_or_callback_escaped_function",
    expressEntryModel: 'lexical-express-registration-v1',
    koaEntryModel: 'lexical-koa-use-v1',
    honoEntryModel: 'lexical-hono-literal-route-v1',
    nodeVisits: session.nodeVisits, indexWork: session.indexWork, flowWork: session.flowWork,
    maxIndexWork: session.maxIndexWork, maxFlowWork: session.maxFlowWork,
    indexComplete: session.indexComplete, rootInventoryComplete: session.indexComplete,
    filesIndexInput: files.length, filesIndexed: session.indexComplete ? files.length : 0,
    filesIndexWalkCompleted: session.modules.indexWalkFiles.size, indexedAstNodes: session.modules.indexedAstNodes,
    symbolLookups: session.modules.symbolLookups, identifierReferences: session.modules.identifierReferences,
    cjsReferences: [...session.modules.cjsReferences.values()].reduce((sum, references) => sum + references.length, 0),
    nativeBoundaryNodes: session.modules.nativeBoundaryNodes.length, newExpressionsIndexed: session.modules.newExpressions.length,
    topLevelDeclared: files.length, topLevelStarted: session.topLevelStarted, topLevelCompleted: session.topLevelCompleted,
    topLevelPartial: session.topLevelPartial, topLevelSkipped: session.topLevelSkipped,
    entryRootsDeclared: session.entryRootsDeclared, entryRootsStarted: session.entryRootsStarted, entryRootsCompleted: session.entryRootsCompleted,
    entryRootsPartial: session.entryRootsPartial, entryRootsSkipped: session.entryRootsSkipped,
    functionContextsStarted: session.functionContextsStarted, functionContextsCompleted: session.functionContextsCompleted, functionContextsPartial: session.functionContextsPartial,
    tasksDeclared: files.length + session.entryRootsDeclared,
    functionsIndexed: session.modules.functions.length, externalEntryFunctions: session.modules.externalEntries.size,
    summaryWork: session.summaryWork, summariesCached: session.cache.size,
    resolvedCalls: session.resolvedCalls, unsupportedCalls: session.unsupportedCalls,
    moduleEdges: session.modules.moduleEdges.size,
    moduleGraphModel: 'snapshot-configured-esm-functions-v1',
    moduleConfigurationsObserved: session.modules.moduleConfigurations.observed,
    moduleConfigurationsSupported: session.modules.moduleConfigurations.supported,
    moduleConfigurationsUnsupported: session.modules.moduleConfigurations.unsupported,
    moduleConfigurationBytes: session.modules.moduleConfigurations.bytes,
    configuredModuleTargets: session.modules.configuredModuleTargets.size,
    configuredModuleCallSites: session.modules.configuredCallSites.size,
    configuredModuleCallContexts: session.configuredCallContexts,
    configuredBodyInspectionsQueued: session.configuredInspectionsQueued,
    configuredBodyInspectionsStarted: session.configuredInspectionsStarted,
    configuredBodyInspectionsDropped: session.configuredInspectionsDropped,
    configuredBodyInspectionFlowWork: session.configuredInspectionWork,
    barrelFunctionTargets: session.modules.barrelFunctionTargets.size,
    configuredNativeIdentityComplete: session.modules.configuredNativeIdentityComplete,
    configuredNativeIdentityVetoes: session.modules.configuredNativeLoads.size,
    maxNodeVisits: limits.nodeVisits, maxFunctions: limits.functions, maxSummaryWork: limits.summaryWork,
    maxCallDepth: limits.callDepth, maxModuleEdges: limits.moduleEdges, maxAliasSteps: limits.aliasSteps, maxTraceSteps: FLOW_LIMITS.traceSteps,
    analysisIncomplete: session.reasons.size > 0, incompleteReasons: [...session.reasons].sort().join(","),
    filesystemStreamModel: 'glob-stream-filename-v1', filesystemStreamsRecognized: session.filesystemModel.streamsRecognized,
    filesystemFilenameCallbacks: session.filesystemModel.filenameCallbacks, filesystemAccumulatorWrites: session.filesystemModel.accumulatorWrites,
    filesystemUnsupportedUses: session.filesystemModel.unsupportedUses,
    archiveDirectoriesRecognized: session.archiveModel.directoriesRecognized, archiveEntryPaths: session.archiveModel.entryPaths,
    archiveWriteCandidates: session.archiveModel.writeCandidates, archiveLexicalExclusions: session.archiveModel.lexicalExclusions,
    archiveUnsupportedUses: session.archiveModel.unsupportedUses,
  }};
}
