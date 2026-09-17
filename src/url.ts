import { parse as parseHtml } from "parse5";
import type { CheckResult, Finding, Severity, UrlOptions } from "./contracts.js";
import {
  MAX_COMPRESSED_BODY_BYTES,
  MAX_REQUESTS,
  MAX_REDIRECTS,
  MAX_SINGLE_BODY_BYTES,
  UrlNetworkError,
  fetchResource,
  normalizeUrl,
  safeUrl,
  type FetchedResource,
  type NormalizedUrl,
  type UrlNetworkContext,
} from "./url-network.js";
import {
  inspectCors,
  inspectSourceMapHeaders,
  scanComponents,
  scanDisclosure,
} from "./url-observations.js";
import { analyzeCsp } from "./url-csp.js";
import { scanModuleReferences, type ModuleReferenceScan } from "./url-modules.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_PAGES = 1;
const DEFAULT_MAX_SCRIPTS = 20;
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
const MAX_TIMEOUT_MS = 120_000;
const MAX_PAGES = 8;
const MAX_SCRIPTS = 50;
const MAX_BYTES = 20 * 1024 * 1024;
const MAX_FINDINGS = 500;
const MAX_PATTERN_MATCHES_PER_SCAN = 256;

const SCOPE_NOTE = "Static URL inspection fetches the requested root page, optional same-origin pages, same-origin linked JavaScript, and static import/export modules with shared bounded GET requests; it does not execute a browser, submit forms, authenticate, fuzz, follow source-map or debug references, fetch remote or dynamic imports, or prove runtime behavior.";

interface SourceLocation {
  startLine?: number;
  startCol?: number;
  startOffset?: number;
}

interface HtmlAttr {
  name: string;
  value: string;
}

interface HtmlNode {
  nodeName?: string;
  tagName?: string;
  value?: string;
  attrs?: HtmlAttr[];
  childNodes?: HtmlNode[];
  sourceCodeLocation?: SourceLocation & { attrs?: Record<string, SourceLocation> };
}

interface ScanState {
  findings: Finding[];
  findingKeys: Set<string>;
  notes: string[];
  incomplete: boolean;
  pagesFetched: number;
  pagesSkipped: number;
  scriptsDiscovered: number;
  scriptsFetched: number;
  scriptsSkipped: number;
  moduleReferencesDiscovered: number;
  dynamicImportsObserved: number;
  computedImportsObserved: number;
  bytes: number;
  statusCode?: number;
  findingsCapped?: boolean;
  addFinding: (input: Omit<Finding, "location"> & { location?: Finding["location"] }) => void;
  addNote: (note: string, incomplete?: boolean) => void;
}

interface ScriptReference {
  raw: string;
  line?: number;
  column?: number;
}

interface HtmlInspection {
  scripts: ScriptReference[];
  moduleScans: ModuleReferenceScan[];
}

interface PendingScript {
  url: NormalizedUrl;
  kind: "html" | "module";
}

interface ResourceReference {
  raw: string;
  kind: string;
  line?: number;
  column?: number;
}

function makeState(): ScanState {
  const state: ScanState = {
    findings: [],
    findingKeys: new Set<string>(),
    notes: [SCOPE_NOTE],
    incomplete: false,
    pagesFetched: 0,
    pagesSkipped: 0,
    scriptsDiscovered: 0,
    scriptsFetched: 0,
    scriptsSkipped: 0,
    moduleReferencesDiscovered: 0,
    dynamicImportsObserved: 0,
    computedImportsObserved: 0,
    bytes: 0,
    addFinding: () => undefined,
    addNote: () => undefined,
  };
  state.addFinding = (input) => addFinding(state, input);
  state.addNote = (note, incomplete = true) => addNote(state, note, incomplete);
  return state;
}

function codeOf(error: unknown): string {
  if (error instanceof UrlNetworkError) return error.code;
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && /^[a-z0-9_:-]+$/i.test(code)) return code.slice(0, 80);
  }
  return "collection_error";
}

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

function addFinding(
  state: ScanState,
  input: Omit<Finding, "location"> & { location?: Finding["location"] },
): void {
  const location = input.location ?? {};
  const key = `${input.ruleId}|${location.url ?? location.path ?? ""}|${location.line ?? 0}|${location.column ?? 0}`;
  if (state.findingKeys.has(key)) {
    // The broad text pass can see a mixed-content URL before the HTML
    // attribute pass knows that it is an active script/frame/form. Preserve
    // the stronger severity when the later, more precise pass supplies it.
    const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const existingIndex = state.findings.findIndex((finding) => {
      const existingLocation = finding.location ?? {};
      return `${finding.ruleId}|${existingLocation.url ?? existingLocation.path ?? ""}|${existingLocation.line ?? 0}|${existingLocation.column ?? 0}` === key;
    });
    if (existingIndex >= 0 && rank[input.severity] > rank[state.findings[existingIndex].severity]) state.findings[existingIndex] = { ...input, location };
    return;
  }
  if (state.findings.length >= MAX_FINDINGS) {
    state.incomplete = true;
    state.findingsCapped = true;
    if (!state.notes.includes("Finding output was capped; content collection is incomplete.")) state.notes.push("Finding output was capped; content collection is incomplete.");
    return;
  }
  state.findingKeys.add(key);
  state.findings.push({ ...input, location });
}

function addNote(state: ScanState, note: string, incomplete = true): void {
  if (!state.notes.includes(note)) state.notes.push(note);
  if (incomplete) state.incomplete = true;
}

function urlLocation(url: NormalizedUrl | string, line?: number, column?: number): Finding["location"] {
  return { url: safeUrl(typeof url === "string" ? url : url.href), ...(line === undefined ? {} : { line }), ...(column === undefined ? {} : { column }) };
}

function headerValues(headers: Record<string, string | string[]>, name: string): string[] {
  return Object.entries(headers)
    .filter(([key]) => key.toLowerCase() === name.toLowerCase())
    .flatMap(([, value]) => Array.isArray(value) ? value.map(String) : [String(value)]);
}

function firstHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
  return headerValues(headers, name)[0];
}

function textFromNode(node: HtmlNode): string {
  if (node.value !== undefined) return node.value;
  return (node.childNodes ?? []).map(textFromNode).join("");
}

function attr(node: HtmlNode, name: string): HtmlAttr | undefined {
  return (node.attrs ?? []).find((entry) => entry.name.toLowerCase() === name.toLowerCase());
}

function sourceLocation(node: HtmlNode, attrName?: string): { line?: number; column?: number; offset?: number } {
  const source = node.sourceCodeLocation;
  if (attrName && source?.attrs) {
    const attrSource = source.attrs[attrName] ?? source.attrs[attrName.toLowerCase()];
    if (attrSource) return { line: attrSource.startLine, column: attrSource.startCol, offset: attrSource.startOffset };
  }
  return { line: source?.startLine, column: source?.startCol, offset: source?.startOffset };
}

function scriptTextLocation(node: HtmlNode): { text: string; offset?: number } {
  const text = textFromNode(node);
  const child = (node.childNodes ?? [])[0];
  return { text, offset: child?.sourceCodeLocation?.startOffset };
}

function severityForSecret(ruleId: string): Severity {
  if (ruleId === "url.secret-private-key" || ruleId === "url.secret-provider-token" || ruleId === "url.secret-supabase-service-key") return "high";
  return "medium";
}

type SupabaseKeyKind = "public-anon" | "public-publishable" | "service" | undefined;

function jwtRole(value: string): string | undefined {
  const payload = value.split(".")[1];
  // Keep JWT decoding bounded even when a page contains an unusually large
  // token-shaped value. The helper remains safe if it is reused by another
  // detector with a broader token matcher.
  if (!payload || payload.length > 4_096) return undefined;
  try {
    const decoded = Buffer.from(payload, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(decoded);
    if (parsed && typeof parsed === "object" && "role" in parsed) {
      const role = (parsed as { role?: unknown }).role;
      return typeof role === "string" ? role : undefined;
    }
  } catch {
    // A JWT-shaped value that is not decodable remains a generic candidate.
  }
  return undefined;
}

function supabaseKeyKind(text: string, value: string, index: number): SupabaseKeyKind {
  const before = text.slice(Math.max(0, index - 240), index);
  // Match both JavaScript assignments (`KEY = "..."`) and JSON/object
  // properties (`"KEY":"..."`) while keeping the key immediately adjacent
  // to this token. The backreference keeps a closing quote paired with its
  // opening quote instead of scanning through a neighboring property.
  const assignmentName = /(["'`]?)([A-Za-z_][A-Za-z0-9_.-]*)\1\s*(?:[:=])\s*["'`]?$/i.exec(before)?.[2] ?? "";
  // Keep classification tied to the token's own assignment. Looking through
  // a broad preceding window can apply a neighboring key's label to this
  // value, especially in compact inline configuration scripts.
  const supabaseAssignment = /supabase/i.test(assignmentName);
  const role = jwtRole(value);

  // New-format keys carry their privilege class in the prefix.  The
  // publishable prefix is intentionally exempt from secret findings even if a
  // caller stores it in a generic `apiKey` variable.
  if (/^sb_secret_[A-Za-z0-9_-]{8,}$/i.test(value) || (role === "service_role" && supabaseAssignment)) return "service";
  if (/^sb_publishable_[A-Za-z0-9_-]{4,}$/i.test(value)) return "public-publishable";
  // Legacy anon keys are JWTs with a low-privilege `anon` role. Require both a
  // decoded role and a Supabase assignment so an arbitrary JWT or a nearby
  // variable name cannot suppress a real provider-token finding.
  if (role === "anon" && supabaseAssignment) return "public-anon";
  return undefined;
}

interface SecretRule {
  ruleId: string;
  title: string;
  regex: RegExp;
}

const SECRET_RULES: SecretRule[] = [
  { ruleId: "url.secret-private-key", title: "Private key material candidate", regex: /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----/gi },
  { ruleId: "url.secret-provider-token", title: "Provider token candidate", regex: /\b(?:gh[pousr]_[A-Za-z0-9_\-]{20,}|github_pat_[A-Za-z0-9_\-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}|sb_secret_[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})\b/gi },
  { ruleId: "url.secret-jwt-candidate", title: "JWT-like token candidate", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  // Literal values only: environment/config references are not credentials
  // exposed in the fetched response and should not become noisy findings.
  { ruleId: "url.secret-assignment", title: "Secret-shaped assignment candidate", regex: /\b(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|secret(?:[_-]?key)?|service[_-]?role(?:[_-]?key)?|access[_-]?(?:key|token)|auth(?:orization)?|password|passwd|private[_-]?key|client[_-]?secret|session[_-]?token)\b\s*["']?\s*[:=]\s*(?:"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|[A-Za-z0-9+/_=-]{16,})/gi },
  { ruleId: "url.secret-bearer", title: "Bearer credential candidate", regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi },
];

function scanSecrets(state: ScanState, text: string, url: NormalizedUrl | string, baseOffset = 0, documentStarts?: number[], documentText?: string): void {
  const starts = documentStarts ?? lineStarts(text);
  let scanned = 0;
  for (const rule of SECRET_RULES) {
    rule.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(text)) !== null) {
      scanned += 1;
      if (scanned > MAX_PATTERN_MATCHES_PER_SCAN || state.findingsCapped) {
        state.incomplete = true;
        if (!state.notes.includes("Pattern match output was capped; content collection is incomplete.")) state.notes.push("Pattern match output was capped; content collection is incomplete.");
        return;
      }
      let candidateValue = match[0];
      let candidateValueIndex = match.index;
      if (rule.ruleId === "url.secret-assignment") {
        const valueMatch = /(?:[:=])\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([A-Za-z0-9+/_=-]{16,}))/i.exec(match[0]);
        const value = valueMatch?.[1] ?? valueMatch?.[2] ?? valueMatch?.[3];
        if (value && valueMatch) {
          candidateValue = value;
          candidateValueIndex = match.index + valueMatch.index + valueMatch[0].lastIndexOf(value);
        }
      }
      const supabaseKind = supabaseKeyKind(text, candidateValue, candidateValueIndex);
      // Supabase publishable/legacy anon keys are intentionally public.  They
      // still depend on RLS and grants, but their presence in browser content
      // is not itself a secret exposure.
      if (supabaseKind === "public-anon" || supabaseKind === "public-publishable") {
        if (match[0].length === 0) rule.regex.lastIndex += 1;
        continue;
      }
      const candidateRuleId = supabaseKind === "service" ? "url.secret-supabase-service-key" : rule.ruleId;
      const candidateTitle = supabaseKind === "service" ? "Supabase service or secret key candidate" : rule.title;
      const locationOffset = candidateRuleId === "url.secret-supabase-service-key" ? candidateValueIndex : match.index;
      const location = documentStarts && documentText
        ? locationForOffset(documentText, baseOffset + locationOffset, starts)
        : locationForOffset(text, locationOffset, starts);
      addFinding(state, {
        ruleId: candidateRuleId,
        title: candidateTitle,
        description: supabaseKind === "service"
          ? "A Supabase secret or legacy service-role key-shaped value was observed in browser-delivered content. The candidate value is intentionally omitted; key validity and actual access were not tested."
          : "A secret-shaped value was observed in fetched content. The candidate value is intentionally omitted and requires verification.",
        severity: severityForSecret(candidateRuleId),
        confidence: supabaseKind === "service" || rule.ruleId !== "url.secret-assignment" ? "high" : "medium",
        kind: "candidate",
        location: urlLocation(url, location.line, location.column),
        remediation: "Remove credentials from browser-delivered content and rotate any exposed credential through the owning provider.",
        references: ["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
      });
      if (match[0].length === 0) rule.regex.lastIndex += 1;
    }
  }
}

interface SinkRule {
  ruleId: string;
  title: string;
  regex: RegExp;
  severity: Severity;
}

const DOM_SINK_RULES: SinkRule[] = [
  { ruleId: "url.dom-sink-html", title: "DOM HTML sink candidate", regex: /\b(?:innerHTML|outerHTML)\s*(?:\+=|=)/gi, severity: "medium" },
  { ruleId: "url.dom-sink-insert-html", title: "DOM HTML insertion sink candidate", regex: /\binsertAdjacentHTML\s*\(/gi, severity: "medium" },
  { ruleId: "url.dom-sink-document-write", title: "document.write sink candidate", regex: /\bdocument\.write\s*\(/gi, severity: "medium" },
  { ruleId: "url.dom-sink-eval", title: "Dynamic code execution sink candidate", regex: /\beval\s*\(|\b(?:new\s+)?Function\s*\(/gi, severity: "medium" },
  { ruleId: "url.dom-sink-timer-string", title: "String timer sink candidate", regex: /\b(?:setTimeout|setInterval)\s*\(\s*["']/gi, severity: "low" },
  { ruleId: "url.dom-sink-srcdoc", title: "Inline document sink candidate", regex: /\bsrcdoc\s*=/gi, severity: "medium" },
  { ruleId: "url.dom-sink-dangerously-set-html", title: "Framework HTML sink candidate", regex: /\bdangerouslySetInnerHTML\b/gi, severity: "medium" },
];

function scanDomSinks(state: ScanState, text: string, url: NormalizedUrl | string, baseOffset = 0, documentStarts?: number[], documentText?: string): void {
  const starts = documentStarts ?? lineStarts(text);
  let scanned = 0;
  for (const rule of DOM_SINK_RULES) {
    rule.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(text)) !== null) {
      scanned += 1;
      if (scanned > MAX_PATTERN_MATCHES_PER_SCAN || state.findingsCapped) {
        state.incomplete = true;
        if (!state.notes.includes("Pattern match output was capped; content collection is incomplete.")) state.notes.push("Pattern match output was capped; content collection is incomplete.");
        return;
      }
      const location = documentStarts && documentText
        ? locationForOffset(documentText, baseOffset + match.index, starts)
        : locationForOffset(text, match.index, starts);
      addFinding(state, {
        ruleId: rule.ruleId,
        title: rule.title,
        description: "A static DOM or dynamic-code sink pattern was observed. Static text cannot establish attacker control or runtime reachability.",
        severity: rule.severity,
        confidence: "low",
        kind: "candidate",
        location: urlLocation(url, location.line, location.column),
        remediation: "Trace the value reaching this sink and use context-aware output encoding or a safe DOM API.",
        references: ["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
      });
      if (match[0].length === 0) rule.regex.lastIndex += 1;
    }
  }
}

function inspectCookies(state: ScanState, response: FetchedResource): void {
  const cookies = headerValues(response.headers, "set-cookie");
  for (const cookie of cookies) {
    // Only attribute names are retained. The cookie name and value are never
    // copied into a finding, note, metric, or error.
    const parts = cookie.split(";");
    const attributes = new Set(parts.slice(1).map((part) => part.trim().split("=", 1)[0].toLowerCase()));
    const sameSite = parts.slice(1).map((part) => part.trim().toLowerCase()).find((part) => part.startsWith("samesite="));
    if (response.finalUrl.protocol === "https:" && !attributes.has("secure")) {
      addFinding(state, {
        ruleId: "url.cookie-missing-secure",
        title: "HTTPS cookie without Secure attribute",
        description: "A Set-Cookie header observed over HTTPS lacks the Secure attribute. Cookie contents are omitted.",
        severity: "medium",
        confidence: "high",
        kind: "observation",
        location: urlLocation(response.finalUrl),
        remediation: "Set Secure on cookies that are sent only over HTTPS.",
      });
    }
    if (!attributes.has("httponly")) {
      addFinding(state, {
        ruleId: "url.cookie-missing-httponly",
        title: "Cookie without HttpOnly attribute",
        description: "A Set-Cookie header observed during the scan lacks HttpOnly. Cookie contents are omitted.",
        severity: "low",
        confidence: "high",
        kind: "observation",
        location: urlLocation(response.finalUrl),
        remediation: "Set HttpOnly for cookies that do not need browser JavaScript access.",
      });
    }
    if (!sameSite) {
      addFinding(state, {
        ruleId: "url.cookie-missing-samesite",
        title: "Cookie without SameSite attribute",
        description: "A Set-Cookie header observed during the scan lacks SameSite. Cookie contents are omitted.",
        severity: "low",
        confidence: "high",
        kind: "observation",
        location: urlLocation(response.finalUrl),
        remediation: "Choose an explicit SameSite policy appropriate for the session or cross-site flow.",
      });
    }
    if (sameSite?.split("=", 2)[1] === "none" && !attributes.has("secure")) {
      addFinding(state, {
        ruleId: "url.cookie-samesite-none-without-secure",
        title: "SameSite=None cookie without Secure attribute",
        description: "A SameSite=None cookie was observed without Secure. Cookie contents are omitted.",
        severity: "medium",
        confidence: "high",
        kind: "observation",
        location: urlLocation(response.finalUrl),
        remediation: "Pair SameSite=None with Secure and serve the cookie over HTTPS.",
      });
    }
  }
}

function inspectHeaders(state: ScanState, response: FetchedResource): void {
  const url = response.finalUrl;
  const location = urlLocation(url);
  const cspValues = headerValues(response.headers, "content-security-policy");
  const cspAnalysis = analyzeCsp(cspValues);
  const xFrame = firstHeader(response.headers, "x-frame-options")?.trim().toLowerCase() ?? "";
  const hasFrameAncestors = cspAnalysis.hasFrameAncestors;
  if (cspValues.length === 0) {
    addFinding(state, {
      ruleId: "url.header-missing-csp",
      title: "Content-Security-Policy header missing",
      description: "The inspected response did not include a Content-Security-Policy header.",
      severity: "medium",
      confidence: "high",
      kind: "observation",
      location,
      remediation: "Define a restrictive Content-Security-Policy and deploy it after testing required resources.",
    });
  } else {
    for (const note of cspAnalysis.notes) state.addNote(note, false);
    const inlineTypes = [
      cspAnalysis.unsafeInline.script ? "script elements" : "",
      cspAnalysis.unsafeInline.scriptAttr ? "script attributes" : "",
      cspAnalysis.unsafeInline.style ? "style elements" : "",
      cspAnalysis.unsafeInline.styleAttr ? "style attributes" : "",
    ].filter(Boolean);
    if (inlineTypes.length > 0) {
      addFinding(state, {
        ruleId: "url.csp-unsafe-inline",
        title: "CSP allows unsafe inline content",
        description: `The effective Content-Security-Policy allows unsafe-inline for ${inlineTypes.join(", ")}. Nonce/hash and directive fallback semantics were considered; this static check does not execute inline code.`,
        severity: "medium",
        confidence: "high",
        kind: "observation",
        location,
        remediation: "Replace inline script or style allowances with nonces, hashes, or external assets where possible.",
      });
    }
    if (cspAnalysis.unsafeEval) {
      addFinding(state, {
        ruleId: "url.csp-unsafe-eval",
        title: "CSP allows dynamic code evaluation",
        description: "The inspected Content-Security-Policy contains an unsafe-eval allowance.",
        severity: "medium",
        confidence: "high",
        kind: "observation",
        location,
        remediation: "Remove unsafe-eval and update dependencies that require dynamic code evaluation.",
      });
    }
  }
  if (url.protocol === "https:") {
    const hsts = firstHeader(response.headers, "strict-transport-security");
    if (!hsts) {
      addFinding(state, {
        ruleId: "url.header-missing-hsts",
        title: "Strict-Transport-Security header missing",
        description: "The inspected HTTPS response did not include Strict-Transport-Security.",
        severity: "medium",
        confidence: "high",
        kind: "observation",
        location,
        remediation: "Deploy HSTS with an appropriate max-age after confirming HTTPS coverage.",
      });
    } else {
      const maxAge = /(?:^|;)\s*max-age\s*=\s*(\d+)/i.exec(hsts)?.[1];
      if (maxAge === undefined || Number(maxAge) < 31_536_000) {
        addFinding(state, {
          ruleId: "url.header-weak-hsts",
          title: "Strict-Transport-Security policy may be weak",
          description: "The inspected HTTPS response declared a missing or short HSTS max-age.",
          severity: "low",
          confidence: "medium",
          kind: "candidate",
          location,
          remediation: "Use a deliberate HSTS max-age after confirming that all required hosts support HTTPS.",
        });
      }
    }
  }
  if (!xFrame && !hasFrameAncestors) {
    addFinding(state, {
      ruleId: "url.header-missing-framing-policy",
      title: "Framing protection header missing",
      description: "The inspected response did not provide X-Frame-Options or a CSP frame-ancestors directive.",
      severity: "medium",
      confidence: "high",
      kind: "observation",
      location,
      remediation: "Set an intentional framing policy with X-Frame-Options or CSP frame-ancestors.",
    });
  } else if (xFrame && !/^(deny|sameorigin)$/.test(xFrame)) {
    addFinding(state, {
      ruleId: "url.header-invalid-x-frame-options",
      title: "X-Frame-Options value may not enforce framing policy",
      description: "The inspected X-Frame-Options value is outside the supported DENY or SAMEORIGIN forms.",
      severity: "low",
      confidence: "medium",
      kind: "candidate",
      location,
      remediation: "Use DENY or SAMEORIGIN, or express the required policy with CSP frame-ancestors.",
    });
  }
  const nosniffValues = headerValues(response.headers, "x-content-type-options");
  if (nosniffValues.length === 0) {
    addFinding(state, {
      ruleId: "url.header-missing-nosniff",
      title: "X-Content-Type-Options header missing",
      description: "The inspected response did not include X-Content-Type-Options.",
      severity: "low",
      confidence: "high",
      kind: "observation",
      location,
      remediation: "Set X-Content-Type-Options: nosniff for browser-delivered resources.",
    });
  } else {
    const nosniffTokens = nosniffValues
      .flatMap((value) => value.split(",").map((token) => token.trim()).filter(Boolean));
    if (nosniffTokens.length === 0 || nosniffTokens.some((token) => token.toLowerCase() !== "nosniff")) {
      addFinding(state, {
        ruleId: "url.header-invalid-nosniff",
        title: "X-Content-Type-Options value is invalid",
        description: "The response included an X-Content-Type-Options header, but its value was not the supported nosniff token. The observed value is omitted.",
        severity: "low",
        confidence: "high",
        kind: "candidate",
        location,
        remediation: "Set the response header to exactly X-Content-Type-Options: nosniff.",
      });
    }
  }
  const referrerValues = headerValues(response.headers, "referrer-policy");
  if (referrerValues.length === 0) {
    addFinding(state, {
      ruleId: "url.header-missing-referrer-policy",
      title: "Referrer-Policy header missing",
      description: "The inspected response did not include Referrer-Policy.",
      severity: "low",
      confidence: "high",
      kind: "observation",
      location,
      remediation: "Set a Referrer-Policy appropriate for the application’s navigation and privacy needs.",
    });
  } else {
    const referrerTokens = referrerValues
      .flatMap((value) => value.split(",").map((token) => token.trim().toLowerCase()).filter(Boolean));
    const validReferrerPolicies = new Set([
      "no-referrer",
      "no-referrer-when-downgrade",
      "origin",
      "origin-when-cross-origin",
      "same-origin",
      "strict-origin",
      "strict-origin-when-cross-origin",
      "unsafe-url",
    ]);
    if (referrerTokens.length === 0 || referrerTokens.some((token) => !validReferrerPolicies.has(token))) {
      addFinding(state, {
        ruleId: "url.header-invalid-referrer-policy",
        title: "Referrer-Policy value is invalid",
        description: "The response included a Referrer-Policy header with an unrecognized value. The observed value is omitted; a valid comma-separated policy list may include a recognized fallback.",
        severity: "low",
        confidence: "high",
        kind: "candidate",
        location,
        remediation: "Use a recognized Referrer-Policy directive such as strict-origin-when-cross-origin or no-referrer.",
      });
    }
  }
  inspectCookies(state, response);
}

function isActiveMixedContentKind(kind: string): boolean {
  return new Set(["script", "stylesheet", "iframe", "frame", "img", "object", "embed", "video", "audio", "source", "form"]).has(kind);
}

function scanMixedContent(state: ScanState, text: string, pageUrl: NormalizedUrl, baseOffset = 0, documentStarts?: number[], documentText?: string): void {
  if (pageUrl.protocol !== "https:") return;
  const regex = /\bhttp:\/\/[^\s"'`<>]+/gi;
  const starts = documentStarts ?? lineStarts(text);
  let scanned = 0;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    scanned += 1;
    if (scanned > MAX_PATTERN_MATCHES_PER_SCAN || state.findingsCapped) {
      state.incomplete = true;
      if (!state.notes.includes("Pattern match output was capped; content collection is incomplete.")) state.notes.push("Pattern match output was capped; content collection is incomplete.");
      return;
    }
    const position = documentStarts && documentText
      ? locationForOffset(documentText, baseOffset + match.index, starts)
      : locationForOffset(text, match.index, starts);
    addFinding(state, {
      ruleId: "url.mixed-content-reference",
      title: "HTTP resource reference in HTTPS content",
      description: "HTTPS content contains an HTTP URL candidate. The referenced value is omitted from the finding.",
      severity: "medium",
      confidence: "medium",
      kind: "candidate",
      location: urlLocation(pageUrl, position.line, position.column),
      remediation: "Use HTTPS for active and passive resources embedded in an HTTPS page.",
    });
    if (match[0].length === 0) regex.lastIndex += 1;
  }
}

function inspectHtml(state: ScanState, html: string, pageUrl: NormalizedUrl): HtmlInspection {
  const scripts: ScriptReference[] = [];
  const inlineModuleScans: ModuleReferenceScan[] = [];
  const resources: ResourceReference[] = [];
  const documentStarts = lineStarts(html);
  let document: HtmlNode;
  try {
    document = parseHtml(html, { sourceCodeLocationInfo: true }) as unknown as HtmlNode;
  } catch {
    addNote(state, "HTML parsing failed; content collection is incomplete.");
    return { scripts, moduleScans: [] };
  }

  const walk = (node: HtmlNode): void => {
    const tag = (node.tagName ?? node.nodeName ?? "").toLowerCase();
    const nodeLocation = sourceLocation(node);
    if (tag === "script") {
      const src = attr(node, "src");
      if (src) {
        const type = attr(node, "type")?.value.trim().toLowerCase() ?? "";
        if (src.value.trim() && isJavaScriptType(type)) {
          const loc = sourceLocation(node, "src");
          scripts.push({ raw: src.value, line: loc.line ?? nodeLocation.line, column: loc.column ?? nodeLocation.column });
        }
      } else {
        const inline = scriptTextLocation(node);
        scanSecrets(state, inline.text, pageUrl, inline.offset ?? 0, documentStarts, html);
        scanDomSinks(state, inline.text, pageUrl, inline.offset ?? 0, documentStarts, html);
        scanMixedContent(state, inline.text, pageUrl, inline.offset ?? 0, documentStarts, html);
        const type = attr(node, "type")?.value.trim().toLowerCase() ?? "";
        if (type === "module") inlineModuleScans.push(scanModuleReferences(inline.text));
      }
    }

    for (const entry of node.attrs ?? []) {
      const name = entry.name.toLowerCase();
      if (name.startsWith("on") && name.length > 2) {
        const loc = sourceLocation(node, entry.name);
        addFinding(state, {
          ruleId: "url.dom-sink-inline-handler",
          title: "Inline event handler candidate",
          description: "An inline event handler was observed in fetched HTML. Static inspection cannot establish exploitability.",
          severity: "low",
          confidence: "high",
          kind: "candidate",
          location: urlLocation(pageUrl, loc.line ?? nodeLocation.line, loc.column ?? nodeLocation.column),
          remediation: "Move event handling into trusted code and apply appropriate output encoding to event data.",
        });
      }
      const resourceKind = resourceKindFor(tag, name);
      if (resourceKind) {
        const loc = sourceLocation(node, entry.name);
        resources.push({ raw: entry.value, kind: resourceKind, line: loc.line ?? nodeLocation.line, column: loc.column ?? nodeLocation.column });
      }
    }
    for (const child of node.childNodes ?? []) walk(child);
  };
  walk(document);

  for (const resource of resources) {
    if (pageUrl.protocol === "https:" && /^http:\/\//i.test(resource.raw) && isActiveMixedContentKind(resource.kind)) {
      addFinding(state, {
        ruleId: "url.mixed-content-reference",
        title: "HTTP resource reference in HTTPS content",
        description: "HTTPS HTML references an HTTP resource. The referenced value is omitted from the finding.",
        severity: resource.kind === "script" || resource.kind === "iframe" || resource.kind === "form" ? "high" : "medium",
        confidence: "high",
        kind: "candidate",
        location: urlLocation(pageUrl, resource.line, resource.column),
        remediation: "Serve embedded resources and form destinations over HTTPS.",
      });
    }
  }
  return {
    scripts,
    moduleScans: inlineModuleScans,
  };
}

function isJavaScriptType(type: string): boolean {
  return type === "" || type === "module" || type === "text/javascript" || type === "application/javascript" || type === "text/ecmascript" || type === "application/ecmascript";
}

function resourceKindFor(tag: string, attribute: string): string | undefined {
  if (tag === "script" && attribute === "src") return "script";
  if (tag === "link" && attribute === "href") return "stylesheet";
  if (tag === "iframe" && attribute === "src") return "iframe";
  if (tag === "frame" && attribute === "src") return "frame";
  if (tag === "img" && attribute === "src") return "img";
  if (tag === "object" && attribute === "data") return "object";
  if (tag === "embed" && attribute === "src") return "embed";
  if ((tag === "video" || tag === "audio") && attribute === "src") return tag;
  if (tag === "source" && attribute === "src") return "source";
  if (tag === "form" && attribute === "action") return "form";
  return undefined;
}

function scanJs(state: ScanState, text: string, url: NormalizedUrl): ReturnType<typeof scanModuleReferences> {
  scanSecrets(state, text, url);
  scanDomSinks(state, text, url);
  scanDisclosure(state, text, url);
  scanComponents(state, text, url);
  scanMixedContent(state, text, url);
  return scanModuleReferences(text);
}

function pageBudgetFor(options: UrlOptions): number {
  const explicitPages = Array.isArray(options.pages) ? options.pages.length : 0;
  return options.maxPages ?? (explicitPages > 0 ? Math.min(MAX_PAGES, explicitPages + 1) : DEFAULT_MAX_PAGES);
}

function optionsError(options: UrlOptions): string | undefined {
  if (!options || typeof options !== "object" || typeof options.url !== "string") return "invalid_url_option";
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pageInputs = options.pages;
  if (pageInputs !== undefined && !Array.isArray(pageInputs)) return "invalid_page_option";
  // The root URL is always one page. Keep the explicit list bounded even when
  // maxPages is set lower; normal URL inputs should never turn validation into
  // an unbounded parser loop.
  if (Array.isArray(pageInputs) && pageInputs.length > MAX_PAGES - 1) return "invalid_page_budget";
  const pages = pageBudgetFor(options);
  const scripts = options.maxScripts ?? DEFAULT_MAX_SCRIPTS;
  const bytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > MAX_TIMEOUT_MS) return "invalid_timeout_budget";
  if (!Number.isSafeInteger(pages) || pages < 1 || pages > MAX_PAGES) return "invalid_page_budget";
  if (!Number.isSafeInteger(scripts) || scripts < 0 || scripts > MAX_SCRIPTS) return "invalid_script_budget";
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > MAX_BYTES) return "invalid_byte_budget";
  return undefined;
}

function result(
  state: ScanState,
  status: CheckResult["status"],
  notes: string[] = state.notes,
  metrics: Record<string, number | string | boolean> = {},
): CheckResult {
  return {
    id: "url.scan",
    status,
    findings: state.findings,
    notes: [...new Set(notes)].slice(0, 64),
    metrics: {
      pagesFetched: state.pagesFetched,
      pagesSkipped: state.pagesSkipped,
      scriptsDiscovered: state.scriptsDiscovered,
      scriptsFetched: state.scriptsFetched,
      scriptsSkipped: state.scriptsSkipped,
      moduleReferencesDiscovered: state.moduleReferencesDiscovered,
      dynamicImportsObserved: state.dynamicImportsObserved,
      computedImportsObserved: state.computedImportsObserved,
      bytesInspected: state.bytes,
      ...metrics,
    },
  };
}

function errorResult(code: string, options: UrlOptions, state = makeState(), metrics: Record<string, number | string | boolean> = {}): CheckResult {
  addNote(state, `URL collection could not complete (${code}).`, true);
  return result(state, "error", state.notes, { requestCount: 0, errorCode: code, allowPrivate: options?.allowPrivate === true, ...metrics });
}

function markResponseStatus(state: ScanState, status: number, label: "root" | "page"): void {
  if (label === "root") state.statusCode = status;
  if (status < 200 || status >= 300 || status === 206) {
    addNote(state, label === "root"
      ? `The root response returned HTTP status ${status}; results are incomplete.`
      : `An explicitly requested page returned HTTP status ${status}; results are incomplete.`, true);
  }
}

function inspectPage(state: ScanState, response: FetchedResource, label: "root" | "page"): { scripts: ScriptReference[]; moduleScans: ModuleReferenceScan[] } {
  markResponseStatus(state, response.status, label);
  if (response.body.byteLength === 0) {
    addNote(state, label === "root" ? "The root response body was empty; content checks are incomplete." : "An explicitly requested page body was empty; content checks are incomplete.");
  }
  inspectHeaders(state, response);
  inspectSourceMapHeaders(state, response);
  inspectCors(state, response);
  const pageText = new TextDecoder("utf-8", { fatal: false }).decode(response.body);
  scanSecrets(state, pageText, response.finalUrl);
  scanDomSinks(state, pageText, response.finalUrl);
  if (response.finalUrl.protocol === "http:") {
    addFinding(state, {
      ruleId: "url.insecure-transport",
      title: "URL is served over HTTP",
      description: "The inspected page was fetched over unencrypted HTTP.",
      severity: "medium",
      confidence: "high",
      kind: "observation",
      location: urlLocation(response.finalUrl),
      remediation: "Serve the page and its authenticated flows over HTTPS and redirect HTTP requests after confirming coverage.",
    });
  }
  scanMixedContent(state, pageText, response.finalUrl);

  const contentType = firstHeader(response.headers, "content-type")?.toLowerCase() ?? "";
  const isHtml = !contentType || contentType.includes("text/html") || contentType.includes("application/xhtml+xml");
  if (isHtml) {
    scanDisclosure(state, pageText, response.finalUrl);
    scanComponents(state, pageText, response.finalUrl);
    const inspection = inspectHtml(state, pageText, response.finalUrl);
    return inspection;
  }

  addNote(state, label === "root"
    ? "The root response was not declared as HTML; only static text checks were applied."
    : "An explicitly requested page was not declared as HTML; only static text checks were applied.", false);
  return { scripts: [], moduleScans: [scanJs(state, pageText, response.finalUrl)] };
}

function recordModuleScan(state: ScanState, scan: ModuleReferenceScan): void {
  state.moduleReferencesDiscovered += scan.staticReferences.length;
  state.scriptsDiscovered += scan.staticReferences.length;
  state.dynamicImportsObserved += scan.dynamicImports;
  state.computedImportsObserved += scan.computedImports;
  if (scan.parseDiagnostics > 0) addNote(state, "A JavaScript module parse had syntax diagnostics; static module coverage may be incomplete.");
  if (scan.dynamicImports > 0) addNote(state, "Dynamic module imports were observed but were not fetched; browser/runtime resolution is outside the static URL scope.", false);
  if (scan.computedImports > 0) addNote(state, "Computed or deep dynamic module imports were observed but were not fetched.", false);
}

function isWebModuleSpecifier(specifier: string): boolean {
  return /^(?:\.\.?\/|\/|\/\/|https?:\/\/)/i.test(specifier);
}

function enqueueScript(
  state: ScanState,
  pending: PendingScript[],
  seenScripts: Set<string>,
  raw: string,
  baseUrl: NormalizedUrl,
  allowedOrigin: string,
  kind: PendingScript["kind"],
): void {
  const specifier = raw.trim();
  if (kind === "module" && !isWebModuleSpecifier(specifier)) {
    state.scriptsSkipped += 1;
    addNote(state, "A bare or non-HTTP module specifier was not followed by the static URL scanner.", false);
    return;
  }
  let scriptUrl: NormalizedUrl;
  try {
    scriptUrl = normalizeUrl(new URL(specifier, baseUrl.href).toString());
  } catch (error) {
    state.scriptsSkipped += 1;
    addNote(state, `A ${kind === "module" ? "static module" : "linked"} script was skipped (${codeOf(error)}).`);
    return;
  }
  if (scriptUrl.origin !== allowedOrigin) {
    state.scriptsSkipped += 1;
    addNote(state, kind === "module"
      ? "A cross-origin static module reference was outside the approved collection scope."
      : "Cross-origin linked JavaScript was outside the approved collection scope.", false);
    return;
  }
  if (seenScripts.has(scriptUrl.href)) return;
  seenScripts.add(scriptUrl.href);
  pending.push({ url: scriptUrl, kind });
}

function enqueueModuleScan(
  state: ScanState,
  pending: PendingScript[],
  seenScripts: Set<string>,
  scan: ModuleReferenceScan,
  baseUrl: NormalizedUrl,
  allowedOrigin: string,
): void {
  recordModuleScan(state, scan);
  for (const reference of scan.staticReferences) {
    enqueueScript(state, pending, seenScripts, reference.specifier, baseUrl, allowedOrigin, "module");
  }
}

function enqueuePageInspection(
  state: ScanState,
  pending: PendingScript[],
  seenScripts: Set<string>,
  inspection: { scripts: ScriptReference[]; moduleScans: ModuleReferenceScan[] },
  pageUrl: NormalizedUrl,
  allowedOrigin: string,
): void {
  state.scriptsDiscovered += inspection.scripts.length;
  for (const reference of inspection.scripts) {
    enqueueScript(state, pending, seenScripts, reference.raw, pageUrl, allowedOrigin, "html");
  }
  for (const scan of inspection.moduleScans) enqueueModuleScan(state, pending, seenScripts, scan, pageUrl, allowedOrigin);
}

async function processScripts(
  state: ScanState,
  pending: PendingScript[],
  seenScripts: Set<string>,
  context: UrlNetworkContext,
  maxScripts: number,
  maxBytes: number,
  allowedOrigin: string,
): Promise<void> {
  while (pending.length > 0) {
    const entry = pending.shift();
    if (!entry) break;
    if (state.scriptsFetched >= maxScripts) {
      state.scriptsSkipped += 1 + pending.length;
      pending.length = 0;
      addNote(state, "The shared same-origin JavaScript/module limit was reached.");
      return;
    }
    const remaining = maxBytes - state.bytes;
    if (remaining <= 0) {
      state.scriptsSkipped += 1 + pending.length;
      pending.length = 0;
      addNote(state, "The shared total decompressed body limit was reached.");
      return;
    }
    try {
      const script = await fetchResource(
        entry.url,
        context,
        allowedOrigin,
        Math.min(MAX_COMPRESSED_BODY_BYTES, remaining),
        Math.min(MAX_SINGLE_BODY_BYTES, remaining),
      );
      state.scriptsFetched += 1;
      state.bytes += script.body.byteLength;
      inspectSourceMapHeaders(state, script);
      const scriptType = firstHeader(script.headers, "content-type")?.toLowerCase() ?? "";
      if (scriptType && !scriptType.includes("javascript") && !scriptType.includes("ecmascript") && !scriptType.includes("text/plain")) {
        addNote(state, "A same-origin linked script or module returned an unexpected content type.");
      }
      const moduleScan = scanJs(state, new TextDecoder("utf-8", { fatal: false }).decode(script.body), script.finalUrl);
      enqueueModuleScan(state, pending, seenScripts, moduleScan, script.finalUrl, allowedOrigin);
      if (script.status < 200 || script.status >= 300 || script.status === 206) {
        addNote(state, entry.kind === "module" ? "A static module returned a non-success HTTP status." : "A linked script returned a non-success HTTP status.");
      }
    } catch (error) {
      state.scriptsSkipped += 1;
      addNote(state, `A ${entry.kind === "module" ? "static module" : "linked script"} could not be collected (${codeOf(error)}).`);
      const code = codeOf(error);
      if (code === "request_limit" || code === "timeout") {
        state.scriptsSkipped += pending.length;
        pending.length = 0;
        return;
      }
    }
  }
}

function pageTargetsFor(options: UrlOptions, target: NormalizedUrl): { targets: NormalizedUrl[]; error?: string } {
  const targets = [target];
  const seen = new Set([target.href]);
  for (const raw of options.pages ?? []) {
    let page: NormalizedUrl;
    try {
      page = normalizeUrl(new URL(raw, target.href).toString());
    } catch (error) {
      return { targets: [], error: codeOf(error) };
    }
    if (page.origin !== target.origin) return { targets: [], error: "cross_origin_page" };
    if (seen.has(page.href)) continue;
    seen.add(page.href);
    targets.push(page);
  }
  return { targets };
}

/** Run a bounded, static, same-origin URL inspection. */
export async function runUrl(options: UrlOptions): Promise<CheckResult[]> {
  const state = makeState();
  const invalidOption = optionsError(options);
  if (invalidOption) return [errorResult(invalidOption, options, state)];
  let target: NormalizedUrl;
  try {
    target = normalizeUrl(options.url);
  } catch (error) {
    return [errorResult(codeOf(error), options, state)];
  }
  const pageTargets = pageTargetsFor(options, target);
  if (pageTargets.error) return [errorResult(pageTargets.error, options, state)];

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxPages = pageBudgetFor(options);
  const maxScripts = options.maxScripts ?? DEFAULT_MAX_SCRIPTS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const budget: UrlNetworkContext["budget"] = {
    count: 0,
    // One shared request budget covers root/additional pages, linked scripts,
    // static modules, and every same-origin redirect hop.
    max: Math.min(MAX_REQUESTS, Math.max(4, 1 + (maxPages + maxScripts) * (MAX_REDIRECTS + 1))),
  };
  const context: UrlNetworkContext = { allowPrivate: options.allowPrivate === true, signal: controller.signal, budget, deadlineAt: Date.now() + timeoutMs };
  let root: FetchedResource;
  try {
    root = await fetchResource(
      target,
      context,
      target.origin,
      Math.min(MAX_COMPRESSED_BODY_BYTES, maxBytes),
      Math.min(MAX_SINGLE_BODY_BYTES, maxBytes),
    );
  } catch (error) {
    clearTimeout(timer);
    return [errorResult(codeOf(error), options, state, { requestCount: budget.count })];
  }

  state.pagesFetched = 1;
  state.bytes = root.body.byteLength;
  const pending: PendingScript[] = [];
  const seenScripts = new Set<string>();
  try {
    const rootInspection = inspectPage(state, root, "root");
    enqueuePageInspection(state, pending, seenScripts, rootInspection, root.finalUrl, root.finalUrl.origin);
    await processScripts(state, pending, seenScripts, context, maxScripts, maxBytes, root.finalUrl.origin);

    const targetLimit = Math.min(maxPages, pageTargets.targets.length);
    for (let index = 1; index < targetLimit; index += 1) {
      if (state.bytes >= maxBytes) {
        state.pagesSkipped += targetLimit - index;
        addNote(state, "The shared total decompressed body limit was reached before all requested pages were fetched.");
        break;
      }
      let page: FetchedResource;
      try {
        const remaining = maxBytes - state.bytes;
        page = await fetchResource(
          pageTargets.targets[index],
          context,
          root.finalUrl.origin,
          Math.min(MAX_COMPRESSED_BODY_BYTES, remaining),
          Math.min(MAX_SINGLE_BODY_BYTES, remaining),
        );
      } catch (error) {
        state.pagesSkipped += 1;
        addNote(state, `An explicitly requested same-origin page could not be collected (${codeOf(error)}).`);
        if (codeOf(error) === "request_limit" || codeOf(error) === "timeout") {
          state.pagesSkipped += targetLimit - index - 1;
          break;
        }
        continue;
      }
      state.pagesFetched += 1;
      state.bytes += page.body.byteLength;
      const inspection = inspectPage(state, page, "page");
      enqueuePageInspection(state, pending, seenScripts, inspection, page.finalUrl, root.finalUrl.origin);
      await processScripts(state, pending, seenScripts, context, maxScripts, maxBytes, root.finalUrl.origin);
    }
    if (pageTargets.targets.length > maxPages) {
      state.pagesSkipped += pageTargets.targets.length - maxPages;
      addNote(state, "The shared same-origin page limit was reached; additional requested pages were not fetched.");
    }
    if (controller.signal.aborted || Date.now() >= context.deadlineAt) addNote(state, "The collection deadline elapsed before all static checks completed.");
  } finally {
    clearTimeout(timer);
  }
  const status: CheckResult["status"] = state.incomplete ? "partial" : "completed";
  return [result(state, status, state.notes, {
    requestCount: budget.count,
    allowPrivate: context.allowPrivate,
    rootStatus: root.status,
    redirectHops: root.redirects.length,
    maxPages,
  })];
}
