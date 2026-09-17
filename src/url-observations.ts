import type { Finding } from "./contracts.js";
import { safeUrl, type FetchedResource, type NormalizedUrl } from "./url-network.js";

/**
 * The URL scanner deliberately exposes only typed observations.  This small
 * interface keeps the observation rules independent from the scanner's
 * mutable budget state and, in particular, prevents raw response values from
 * being copied into findings or notes.
 */
export interface UrlObservationSink {
  addFinding(input: Omit<Finding, "location"> & { location?: Finding["location"] }): void;
  addNote(note: string, incomplete?: boolean): void;
}

export interface TextObservationContext {
  baseOffset?: number;
  documentStarts?: number[];
  documentText?: string;
}

const MAX_OBSERVATION_MATCHES = 64;
const SOURCE_MAP_REFERENCE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/SourceMap";

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function locationForOffset(text: string, offset: number, starts = lineStarts(text)): { line: number; column: number } {
  const bounded = Math.max(0, Math.min(offset, text.length));
  let low = 0;
  let high = starts.length - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    if (starts[middle] <= bounded) low = middle + 1;
    else high = middle - 1;
  }
  const lineStart = starts[Math.max(0, high)] ?? 0;
  return { line: Math.max(1, high + 1), column: bounded - lineStart + 1 };
}

function safeLocation(url: NormalizedUrl | string, line?: number, column?: number): Finding["location"] {
  return {
    url: safeUrl(typeof url === "string" ? url : url.href),
    ...(line === undefined ? {} : { line }),
    ...(column === undefined ? {} : { column }),
  };
}

function locationForMatch(
  text: string,
  index: number,
  context: TextObservationContext,
): { line: number; column: number } {
  if (context.documentText !== undefined) {
    const starts = context.documentStarts ?? lineStarts(context.documentText);
    return locationForOffset(context.documentText, (context.baseOffset ?? 0) + index, starts);
  }
  return locationForOffset(text, index);
}

function headerValues(headers: Record<string, string | string[]>, name: string): string[] {
  return Object.entries(headers)
    .filter(([key]) => key.toLowerCase() === name.toLowerCase())
    .flatMap(([, value]) => Array.isArray(value) ? value.map(String) : [String(value)]);
}

function hasHeaderToken(values: string[], token: string): boolean {
  return values.some((value) => value.split(",").some((part) => part.trim().toLowerCase() === token.toLowerCase()));
}

function observedOriginPolicy(values: string[]): "wildcard" | "explicit" | "invalid" | "none" {
  if (values.length === 0) return "none";
  const trimmed = values.map((value) => value.trim()).filter(Boolean);
  if (trimmed.length === 1 && trimmed[0] === "*") return "wildcard";
  // ACAO has a single origin-or-wildcard value.  Keep unusual or repeated
  // values as an observation; this scanner does not try to emulate a browser's
  // parser for malformed header combinations.
  if (trimmed.length !== 1 || trimmed[0].includes(",") || /\s/.test(trimmed[0])) return "invalid";
  return "explicit";
}

/**
 * Record the original response CORS policy without sending an Origin header
 * or making a cross-origin request.  A wildcard is valid for public,
 * non-credentialed requests.  Wildcard plus ACAC=true is a browser-invalid
 * credentialed combination, but it is not evidence of a credentialed read or
 * a browser bypass.
 */
export function inspectCors(state: UrlObservationSink, response: FetchedResource): void {
  const allowOrigin = headerValues(response.headers, "access-control-allow-origin");
  const allowCredentials = headerValues(response.headers, "access-control-allow-credentials");
  const vary = headerValues(response.headers, "vary");
  if (allowOrigin.length === 0 && allowCredentials.length === 0 && vary.length === 0) return;

  const originPolicy = observedOriginPolicy(allowOrigin);
  // Fetch's credential permission token is the lowercase value `true`.
  // Preserve the original case so an invalid `TRUE` value is not reported as
  // a browser-enabled credential policy.
  const credentialsAllowed = allowCredentials.some((value) => value.trim() === "true");
  const variesByOrigin = hasHeaderToken(vary, "origin");
  state.addNote(
    `Observed CORS policy (${originPolicy} origin; credentials ${credentialsAllowed ? "enabled" : "not enabled"}; Vary: Origin ${variesByOrigin ? "present" : "absent"}). No Origin header or cross-origin request was sent.`,
    false,
  );

  if (originPolicy === "wildcard" && credentialsAllowed) {
    state.addFinding({
      ruleId: "url.cors-wildcard-credentials",
      title: "CORS wildcard is paired with credential permission",
      description: "The response advertises Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Browsers reject credentialed CORS reads with a wildcard; this static check sent no credentialed request and does not establish data exposure or a browser bypass.",
      severity: "medium",
      confidence: "low",
      kind: "candidate",
      location: safeLocation(response.finalUrl),
      remediation: "For public non-credentialed resources, keep the wildcard and omit credential permission. For credentialed access, return an approved explicit origin and verify the policy in a controlled test.",
      references: [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS",
        "https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch",
      ],
    });
  }
}

interface DisclosureRule {
  ruleId: string;
  title: string;
  description: string;
  regex: RegExp;
  severity: "low" | "medium";
  remediation: string;
  references?: string[];
}

const DISCLOSURE_RULES: DisclosureRule[] = [
  {
    ruleId: "url.disclosure-source-map-reference",
    title: "Public source-map reference candidate",
    description: "Fetched public content contains a source-map reference. The reference may make original sources easier to retrieve, but this scan did not resolve or fetch the map and cannot establish source disclosure.",
    regex: /\bsourceMappingURL\s*=\s*[^\s*"'<>]+/gi,
    severity: "low",
    remediation: "Review whether source maps should be publicly served; if they are not required, remove the public reference and map from the deployment.",
    references: [SOURCE_MAP_REFERENCE],
  },
  {
    ruleId: "url.disclosure-framework-runtime",
    title: "Public framework runtime marker inventory",
    description: "Fetched public content contains a common framework runtime marker. The marker alone is normal public metadata and does not produce a disclosure finding.",
    regex: /(?:__NEXT_DATA__|__next_data__|__next_f|webpackJsonp|window\.__[A-Z][A-Z0-9_]*__)/gi,
    severity: "low",
    remediation: "Review the serialized public runtime data and remove server-only fields before shipping browser content.",
  },
  {
    ruleId: "url.disclosure-debug-trace",
    title: "Public debug or stack-trace marker candidate",
    description: "Fetched public content contains a debug or stack-trace marker. This is a low-confidence disclosure candidate; no endpoint was probed and no runtime error was reproduced.",
    regex: /(?:stack\s*trace|traceback|uncaught\s+(?:exception|error)|internal\s+server\s+error|\bat\s+(?:\/|[A-Za-z]:\\)[^\r\n]*)/gi,
    severity: "medium",
    remediation: "Keep diagnostic traces and internal paths out of public responses while retaining detailed logs in an access-controlled system.",
  },
  {
    ruleId: "url.disclosure-sensitive-field",
    title: "Sensitive field disclosure candidate",
    description: "Fetched public content contains a sensitive field marker. The field may be a request or documentation example rather than an exposed secret, so its value and intended audience require verification.",
    regex: /(?:["']?(?:password|refresh[_-]?token|private[_-]?key|service[_-]?role|secret[_-]?key)["']?\s*[:=])/gi,
    severity: "medium",
    remediation: "Review the public response schema and omit server-only credentials, session material, and internal fields from browser-delivered data.",
  },
];

function likelyLiteralSecretAfterMarker(text: string, matchEnd: number): boolean {
  const remainder = text.slice(matchEnd, matchEnd + 256);
  return /^\s*(?:["'][^"'\r\n]{8,}["']|[A-Za-z0-9+/_=-]{16,})/.test(remainder);
}

/**
 * Inspect already collected text only.  In particular, source-map targets,
 * debug paths, and values mentioned by a marker are never fetched or copied
 * into a finding.
 */
export function scanDisclosure(
  state: UrlObservationSink,
  text: string,
  url: NormalizedUrl | string,
  context: TextObservationContext = {},
): void {
  let scanned = 0;
  for (const rule of DISCLOSURE_RULES) {
    rule.regex.lastIndex = 0;
    // Framework bootstrap markers are common public metadata. Record one
    // inventory note for the document and keep those repetitions out of the
    // candidate-output budget so a normal streamed page does not become
    // incomplete merely because it contains many framework chunks.
    if (rule.ruleId === "url.disclosure-framework-runtime") {
      if (rule.regex.test(text)) state.addNote("A public framework runtime marker was observed; its fields were not interpreted as a disclosure finding.", false);
      continue;
    }
    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(text)) !== null) {
      scanned += 1;
      if (scanned > MAX_OBSERVATION_MATCHES) {
        state.addNote("Public disclosure observation output was capped; content collection is incomplete.");
        return;
      }
      // Secret assignments already have a stronger, value-oriented detector.
      // Retain a field candidate for null/variable/object values, but avoid a
      // second finding for the same obvious literal secret marker.
      if (rule.ruleId === "url.disclosure-sensitive-field" && likelyLiteralSecretAfterMarker(text, match.index + match[0].length)) {
        if (match[0].length === 0) rule.regex.lastIndex += 1;
        continue;
      }
      const position = locationForMatch(text, match.index, context);
      state.addFinding({
        ruleId: rule.ruleId,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        confidence: "low",
        kind: "candidate",
        location: safeLocation(url, position.line, position.column),
        remediation: rule.remediation,
        ...(rule.references ? { references: rule.references } : {}),
      });
      if (match[0].length === 0) rule.regex.lastIndex += 1;
    }
  }
}

export function inspectSourceMapHeaders(state: UrlObservationSink, response: FetchedResource): void {
  const headerNames = ["sourcemap", "x-sourcemap"];
  if (!headerNames.some((name) => headerValues(response.headers, name).length > 0)) return;
  state.addFinding({
    ruleId: "url.disclosure-source-map-header",
    title: "Public source-map response header candidate",
    description: "The fetched response advertises a source-map location through a response header. The target was not resolved or fetched, so source disclosure is unverified.",
    severity: "low",
    confidence: "low",
    kind: "candidate",
    location: safeLocation(response.finalUrl),
    remediation: "Review whether source maps should be publicly served and remove an unnecessary SourceMap or X-SourceMap header from production responses.",
    references: [SOURCE_MAP_REFERENCE],
  });
}

interface ComponentDefinition {
  label: string;
  pattern: string;
}

const COMPONENTS: ComponentDefinition[] = [
  { label: "jQuery", pattern: "jquery(?:-migrate)?" },
  { label: "React", pattern: "react(?:-dom|[-.]client)?" },
  { label: "Vue", pattern: "vue(?:-router)?" },
  { label: "Angular", pattern: "angular(?:\.js|/(?:core|common|router))?" },
  { label: "Lodash", pattern: "lodash" },
  { label: "Next.js", pattern: "next(?:\.js)?" },
  { label: "Webpack", pattern: "webpack" },
  { label: "Axios", pattern: "axios" },
  { label: "Moment", pattern: "moment" },
  { label: "Bootstrap", pattern: "bootstrap" },
  { label: "Svelte", pattern: "svelte" },
  { label: "Preact", pattern: "preact" },
  { label: "Supabase JS", pattern: "supabase/supabase-js" },
];

const VERSION = "(\\d{1,6}\\.\\d{1,6}(?:\\.\\d{1,6})?(?:[-+][0-9A-Za-z.-]{1,32})?)";

function componentPattern(): string {
  return `(?:${COMPONENTS.map((component) => component.pattern).join("|")})`;
}

function componentLabel(raw: string): string | undefined {
  const normalized = raw.toLowerCase().replace(/^@/, "");
  return COMPONENTS.find((component) => new RegExp(`^${component.pattern}$`, "i").test(normalized))?.label;
}

function addComponentFinding(
  state: UrlObservationSink,
  url: NormalizedUrl | string,
  component: string,
  version: string,
  line: number,
  column: number,
): void {
  state.addFinding({
    ruleId: "url.component-version-clue",
    title: "Public component version clue",
    description: `Public HTML or JavaScript contains an explicit ${component} version marker (${version}). This is public evidence only; it is not lockfile SCA, a CVE/advisory result, or proof of the installed or server-side version.`,
    severity: "info",
    confidence: "low",
    kind: "candidate",
    location: safeLocation(url, line, column),
    remediation: "Confirm the effective deployed dependency version from a lockfile or SBOM and review its supported security advisories separately.",
  });
}

/**
 * Identify explicit public library/version evidence in collected HTML/JS.
 * Names without a version (for example, `react.min.js`) are intentionally
 * ignored because a filename alone does not identify a release.
 */
export function scanComponents(
  state: UrlObservationSink,
  text: string,
  url: NormalizedUrl | string,
  context: TextObservationContext = {},
): void {
  const seen = new Set<string>();
  let scanned = 0;
  let capped = false;
  const report = (match: RegExpExecArray, rawComponent: string, version: string): void => {
    if (capped) return;
    const component = componentLabel(rawComponent);
    if (!component) return;
    // One clue per component/version is sufficient for a collected asset. A
    // page commonly repeats the same CDN URL in several tags, and reporting
    // each textual occurrence would add noise without adding evidence.
    const key = `${component}|${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    scanned += 1;
    if (scanned > MAX_OBSERVATION_MATCHES) {
      capped = true;
      state.addNote("Public component observation output was capped; content collection is incomplete.");
      return;
    }
    const position = locationForMatch(text, match.index, context);
    addComponentFinding(state, url, component, version, position.line, position.column);
  };

  // Package CDN URLs carry the package name and release explicitly.  Restrict
  // this pass to well-known public CDN paths so arbitrary URLs do not become a
  // component finding.
  const cdn = new RegExp(
    `(?:https?:\\/\\/)?(?:unpkg\\.com|cdn\\.jsdelivr\\.net)\\/(?:npm\\/)?(@?[^\\s\\/"'<>]+(?:\\/[^\\s\\/"'<>@]+)?)@${VERSION}`,
    "gi",
  );
  let match: RegExpExecArray | null;
  while (!capped && (match = cdn.exec(text)) !== null) {
    report(match, match[1], match[2]);
    if (match[0].length === 0) cdn.lastIndex += 1;
  }

  const cdnjs = new RegExp(
    `(?:https?:\\/\\/)?cdnjs\\.cloudflare\\.com\\/ajax\\/libs\\/(${componentPattern()})\\/${VERSION}(?=[\\/\\s"'<>])`,
    "gi",
  );
  while (!capped && (match = cdnjs.exec(text)) !== null) {
    report(match, match[1], match[2]);
    if (match[0].length === 0) cdnjs.lastIndex += 1;
  }

  // The official jQuery CDN uses a versioned filename rather than an @range.
  const jqueryCdn = new RegExp(`(?:code\\.jquery\\.com\\/)?jquery[-.]${VERSION}(?=[-.\\/])`, "gi");
  while (!capped && (match = jqueryCdn.exec(text)) !== null) {
    report(match, "jquery", match[1]);
    if (match[0].length === 0) jqueryCdn.lastIndex += 1;
  }

  // Bundles frequently retain a license banner such as `React v18.2.0` or
  // `jQuery JavaScript Library v3.7.1`.  Requiring an explicit version marker
  // keeps ordinary identifiers and unversioned filenames out of the result.
  const banner = new RegExp(
    `\\b(${componentPattern()})\\s*(?:v(?:ersion)?\\s*[:=]?\\s*|[@/_-]\\s*)${VERSION}(?=\\b)`,
    "gi",
  );
  while (!capped && (match = banner.exec(text)) !== null) {
    report(match, match[1], match[2]);
    if (match[0].length === 0) banner.lastIndex += 1;
  }

  // Some UMD and framework bundles expose their release through a public
  // `Library.version` field rather than a license banner.
  const runtimeVersion = new RegExp(
    `\\b(${componentPattern()})\\.version\\s*[:=]\\s*["']?${VERSION}(?=\\b)`,
    "gi",
  );
  while (!capped && (match = runtimeVersion.exec(text)) !== null) {
    report(match, match[1], match[2]);
    if (match[0].length === 0) runtimeVersion.lastIndex += 1;
  }

  // Versioned local asset names are weaker than a package banner but still
  // public evidence when the component name and full version are both present.
  const asset = new RegExp(`\\b(${componentPattern()})[-_.]${VERSION}(?=[-_.\\/])`, "gi");
  while (!capped && (match = asset.exec(text)) !== null) {
    report(match, match[1], match[2]);
    if (match[0].length === 0) asset.lastIndex += 1;
  }
}
