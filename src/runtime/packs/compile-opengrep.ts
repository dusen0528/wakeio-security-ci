import { createHash } from 'node:crypto';
import { JSON_MAX_INPUT_BYTES } from '../../json-snapshot.js';
import { parseFrameworkPackYaml } from './schema.js';
import type { FrameworkPack, PackLanguage, PackSanitizer, PackSource } from './schema.js';

export const PACK_COMPILER_REVISION = 'wakeio.framework-pack-opengrep/v1';
export type PackCompileDiagnostic = Readonly<{
  kind: 'surface'; index: number; provider: 'source-routes'; disposition: 'unsupported';
  reason: 'discovery-not-implemented'; annotations: readonly string[];
}> | Readonly<{
  kind: 'sanitizer'; index: number; vulnClass: 'sql'; disposition: 'not-applied';
  reason: 'binding-literal-overload-argument-unproven'; call: readonly string[];
  when: Readonly<PackSanitizer['when']>;
}>;
export interface CompiledFrameworkPack {
  packId: string; packVersion: number; generationRevision: typeof PACK_COMPILER_REVISION;
  rawPackSha256: string; semanticPackSha256: string; rulesSha256: string; rulesJson: string;
  engine: 'opengrep-core'; engineVersion: '1.30.0'; executionProtocol: 'core-rules-targets-intrafile';
  diagnostics: readonly PackCompileDiagnostic[]; diagnosticsSha256: string;
  verification: 'not_run';
}
type Formula = { pattern: string } | { 'pattern-inside': string } | { patterns: Formula[] }
  | { 'pattern-either': Formula[] } | { 'focus-metavariable': string }
  | { 'metavariable-type': { metavariable: string; type: string } }
  | { 'metavariable-regex': { metavariable: string; regex: string } };
interface TaintPattern { patterns: Formula[]; exact: true }
const sha = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');
function unsupported(feature: string): never { throw new TypeError('unsupported_framework_pack:' + feature); }

/** Canonical keys, original array order. The parser has already bounded and snapshotted this data. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key =>
    JSON.stringify(key) + ':' + canonical(Object.getOwnPropertyDescriptor(value, key)!.value)).join(',') + '}';
}

/** A call denotes a receiver type and method, never an executable or raw rule pattern. */
function callFormula(call: string, args: string): Formula[] {
  const dot = call.lastIndexOf('.'), owner = call.slice(0, dot), method = call.slice(dot + 1);
  const wildcard = method.endsWith('*');
  const patterns: Formula[] = [
    { pattern: `$RECEIVER.${wildcard ? '$METHOD' : method}(${args})` },
    { 'metavariable-type': { metavariable: '$RECEIVER', type: owner } },
  ];
  if (wildcard) patterns.push({ 'metavariable-regex': {
    metavariable: '$METHOD', regex: '^' + method.slice(0, -1) + '[A-Za-z0-9_]*$',
  } });
  return patterns;
}

function annotationSource(annotation: string, language: PackLanguage): TaintPattern {
  const alternatives: Formula[] = [];
  for (const suffix of ['', '(...)']) {
    const parameter = language === 'java' ? `$TYPE $SOURCE` : '$SOURCE: $TYPE';
    const head = language === 'java' ? '$METHOD' : 'fun $METHOD';
    const returns = language === 'java' ? [''] : ['', ': $RETURN'];
    for (const result of returns) alternatives.push({ 'pattern-inside':
      `${head}(..., @${annotation}${suffix} ${parameter}, ...)${result} { ... }` });
  }
  return { patterns: [{ 'pattern-either': alternatives }, { 'focus-metavariable': '$SOURCE' }], exact: true };
}

function sources(entries: PackSource[], language: PackLanguage): TaintPattern[] {
  return entries.flatMap(entry => 'annotation' in entry
    ? entry.annotation.map(name => annotationSource(name, language))
    : entry.call.map(call => ({ patterns: callFormula(call, '...'), exact: true })));
}

/** Closed metadata only, bounded by the validated Pack (surfaces16 + hints32; symbols16 per entry). */
function dispositions(pack: FrameworkPack): readonly PackCompileDiagnostic[] {
  const result: PackCompileDiagnostic[] = [];
  pack.surfaces.forEach((surface, index) => {
    if (surface.provider === 'source-routes') result.push(Object.freeze({
      kind: 'surface', index, provider: surface.provider, disposition: 'unsupported',
      reason: 'discovery-not-implemented', annotations: Object.freeze([...surface.annotations]),
    }));
  });
  pack.sanitizers.sql.forEach((hint, index) => result.push(Object.freeze({
    kind: 'sanitizer', index, vulnClass: 'sql', disposition: 'not-applied',
    reason: 'binding-literal-overload-argument-unproven', call: Object.freeze([...hint.call]),
    when: Object.freeze({ argCount: hint.when.argCount, placeholders: hint.when.placeholders }),
  })));
  return Object.freeze(result);
}

/** Compile data only. R3 must provide core -rules/-targets/-taint_intrafile, not preview's CLI flags. */
export function compileFrameworkPack(text: string): Readonly<CompiledFrameworkPack> {
  const pack = parseFrameworkPackYaml(text);
  // Preserve discovery configuration and unproven hints as diagnostics, never as applied sanitizers.
  const diagnostics = dispositions(pack);
  const semanticPackSha256 = sha(canonical(pack));
  const rules = pack.languages.map(language => ({
    id: `wakeio.pack.${pack.id}.v${pack.version}.${language}.sql.${semanticPackSha256}`,
    languages: [language], mode: 'taint', severity: 'ERROR',
    message: 'Pack-defined SQL flow candidate; runtime verification is not run.',
    'pattern-sources': sources(pack.sources, language),
    'pattern-sinks': pack.sinks.sql.flatMap(sink => sink.call.map(call => ({
      patterns: [...callFormula(call, [...Array(sink.arg).fill('$_'), '$SQL', '...'].join(', ')),
        { 'focus-metavariable': '$SQL' }], exact: true,
    }))),
  }));
  const rulesJson = canonical({ rules }) + '\n';
  const diagnosticJson = canonical(diagnostics);
  if (Buffer.byteLength(rulesJson + diagnosticJson, 'utf8') > JSON_MAX_INPUT_BYTES) unsupported('output-limit');
  return Object.freeze({ packId: pack.id, packVersion: pack.version, generationRevision: PACK_COMPILER_REVISION,
    rawPackSha256: sha(text), semanticPackSha256, rulesSha256: sha(rulesJson), rulesJson,
    engine: 'opengrep-core', engineVersion: '1.30.0', executionProtocol: 'core-rules-targets-intrafile',
    diagnostics, diagnosticsSha256: sha(diagnosticJson),
    verification: 'not_run' });
}
