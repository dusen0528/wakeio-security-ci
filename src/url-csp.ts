/**
 * Small, non-executing CSP parser used by the bounded URL observer.
 *
 * The scanner does not try to emulate every browser CSP feature.  It only
 * answers the questions needed by the existing header observations: which
 * source list applies to inline scripts/styles, whether unsafe-inline is
 * overridden by a nonce/hash/strict-dynamic expression, and whether
 * unsafe-eval is allowed by the effective script policy.  Each serialized
 * policy is kept separate because browsers enforce multiple policies
 * together.
 */

export type CspInlineType = "script" | "script-attr" | "style" | "style-attr";

interface ParsedPolicy {
  directives: Map<string, string[]>;
}

export interface CspAnalysis {
  policyCount: number;
  hasFrameAncestors: boolean;
  unsafeInline: {
    script: boolean;
    scriptAttr: boolean;
    style: boolean;
    styleAttr: boolean;
  };
  unsafeEval: boolean;
  notes: string[];
}

const INLINE_TYPES: readonly CspInlineType[] = ["script", "script-attr", "style", "style-attr"];
const VALID_HASH_ALGORITHMS = new Set(["sha256", "sha384", "sha512"]);

function splitHeaderPolicies(values: readonly string[]): string[] {
  const policies: string[] = [];
  for (const value of values) {
    // A CSP source expression cannot contain a comma.  Splitting a combined
    // header therefore preserves the serialized policies emitted by Node for
    // repeated Content-Security-Policy fields while keeping malformed comma
    // input bounded and observable.
    for (const policy of String(value).split(",")) {
      const trimmed = policy.trim();
      if (trimmed) policies.push(trimmed);
    }
  }
  return policies;
}

function parsePolicy(value: string): ParsedPolicy {
  const directives = new Map<string, string[]>();
  for (const serializedDirective of value.split(";")) {
    const tokens = serializedDirective.trim().split(/\s+/).filter(Boolean);
    const name = tokens.shift()?.toLowerCase();
    if (!name || !/^[a-z][a-z0-9-]*$/.test(name) || directives.has(name)) continue;
    // CSP ignores duplicate directives after the first occurrence.  Keep
    // empty source lists: a present directive with no sources is restrictive.
    directives.set(name, tokens);
  }
  return { directives };
}

function tokenIs(tokens: readonly string[], expected: string): boolean {
  return tokens.some((token) => token.toLowerCase() === expected);
}

function isNonceOrHashSource(token: string): boolean {
  const normalized = token.trim();
  if (!/^'[^']+'$/.test(normalized)) return false;
  const body = normalized.slice(1, -1);
  // CSP's base64-value grammar permits one or more alphabet characters and
  // at most two `=` padding characters at the end. Do not let malformed
  // nonce/hash tokens suppress an unsafe-inline observation.
  const base64Value = "[A-Za-z0-9+/_-]+={0,2}";
  const nonce = new RegExp(`^nonce-${base64Value}$`, "i").test(body);
  if (nonce) return true;
  const hash = new RegExp(`^([a-z0-9]+)-(${base64Value})$`, "i").exec(body);
  return Boolean(hash && VALID_HASH_ALGORITHMS.has(hash[1].toLowerCase()));
}

function sourceList(policy: ParsedPolicy, type: CspInlineType | "eval"): string[] | undefined {
  const { directives } = policy;
  const names: string[] = type === "eval"
    ? ["script-src", "default-src"]
    : type === "script"
      ? ["script-src-elem", "script-src", "default-src"]
      : type === "script-attr"
        ? ["script-src-attr", "script-src", "default-src"]
        : type === "style"
          ? ["style-src-elem", "style-src", "default-src"]
          : ["style-src-attr", "style-src", "default-src"];
  for (const name of names) {
    const values = directives.get(name);
    if (values !== undefined) return values;
  }
  return undefined;
}

function allowsAllInline(policy: ParsedPolicy, type: CspInlineType): { allowed: boolean; overridden: boolean; strictDynamic: boolean } {
  const tokens = sourceList(policy, type);
  if (tokens === undefined) return { allowed: false, overridden: false, strictDynamic: false };
  if (!tokenIs(tokens, "'unsafe-inline'")) return { allowed: false, overridden: false, strictDynamic: false };
  const nonceOrHash = tokens.some(isNonceOrHashSource);
  const strictDynamic = tokenIs(tokens, "'strict-dynamic'");
  // CSP ignores unsafe-inline for a source list containing a nonce/hash.  For
  // script and script attributes strict-dynamic also overrides it. The
  // browser's inline-source algorithm applies this override even when the
  // policy has no valid nonce/hash; that policy can consequently block every
  // parser-inserted script and does not make unsafe-inline effective.
  const strictDynamicOverride = strictDynamic && (type === "script" || type === "script-attr");
  const overridden = nonceOrHash || strictDynamicOverride;
  return { allowed: !overridden, overridden, strictDynamic };
}

function everyPolicyAllowsInline(policies: readonly ParsedPolicy[], type: CspInlineType): boolean {
  if (policies.length === 0) return false;
  let observedUnsafeInline = false;
  const allowed = policies.every((policy) => {
    const tokens = sourceList(policy, type);
    if (tokens === undefined) return true;
    if (!tokenIs(tokens, "'unsafe-inline'")) return false;
    observedUnsafeInline = true;
    return allowsAllInline(policy, type).allowed;
  });
  return observedUnsafeInline && allowed;
}

function everyPolicyAllowsEval(policies: readonly ParsedPolicy[]): boolean {
  if (policies.length === 0) return false;
  let observedUnsafeEval = false;
  const allowed = policies.every((policy) => {
    const tokens = sourceList(policy, "eval");
    // A policy without script-src/default-src places no eval restriction.
    if (tokens === undefined) return true;
    if (!tokenIs(tokens, "'unsafe-eval'")) return false;
    observedUnsafeEval = true;
    return true;
  });
  return observedUnsafeEval && allowed;
}

function hasOverriddenInline(policies: readonly ParsedPolicy[], type: CspInlineType): boolean {
  return policies.some((policy) => allowsAllInline(policy, type).overridden);
}

function hasStrictDynamic(policies: readonly ParsedPolicy[], type: CspInlineType): boolean {
  return policies.some((policy) => allowsAllInline(policy, type).strictDynamic);
}

/** Analyze one or more Content-Security-Policy response header values. */
export function analyzeCsp(values: readonly string[]): CspAnalysis {
  const policies = splitHeaderPolicies(values).map(parsePolicy);
  const notes: string[] = [];

  if (policies.length > 1) {
    notes.push("Multiple Content-Security-Policy policies were observed; inline and eval allowances were intersected across policies.");
  }

  const unsafeInline: CspAnalysis["unsafeInline"] = {
    script: everyPolicyAllowsInline(policies, "script"),
    scriptAttr: everyPolicyAllowsInline(policies, "script-attr"),
    style: everyPolicyAllowsInline(policies, "style"),
    styleAttr: everyPolicyAllowsInline(policies, "style-attr"),
  };
  for (const [type, label] of [
    ["script", "script elements"],
    ["script-attr", "script attributes"],
    ["style", "style elements"],
    ["style-attr", "style attributes"],
  ] as const) {
    if (hasOverriddenInline(policies, type)) {
      notes.push(`CSP unsafe-inline was overridden for ${label} by a nonce, hash${type.startsWith("script") && hasStrictDynamic(policies, type) ? ", or strict-dynamic" : ""}.`);
    } else if (hasStrictDynamic(policies, type)) {
      notes.push(`CSP strict-dynamic was observed for ${label}; this static check does not infer runtime script trust propagation.`);
    }
  }

  return {
    policyCount: policies.length,
    hasFrameAncestors: policies.some((policy) => policy.directives.has("frame-ancestors")),
    unsafeInline,
    unsafeEval: everyPolicyAllowsEval(policies),
    notes,
  };
}
