# Dynamic code signal

Ruleset `2026-10-05.16` separates literal operand observations from input-related
or unresolved code operand candidates. `ast:dynamic-code` uses API-shaped syntax;
it does not certify native callable identity or runtime execution.

- An eval/window.eval call with a directly literal first code operand, or a
  Function/window.Function call with every operand directly literal, produces
  an `info` / `observation`. String literals and templates without interpolation
  qualify only for direct eval/Function identifiers or an actual window identifier
  with a static eval/Function property (including string/no-substitution element
  names). A legacy computed-name fallback never qualifies. Direct `new Function` and `new window.Function` use the same policy.
- Related request-shaped input produces a `high` / `candidate` with the actual
  relevant operand trace. Function parameter strings and final body are all
  relevant. Tainted evidence has medium confidence; unknown evidence has low
  confidence. The lowest input index wins within the preferred tainted class.
  Descriptions identify the selected syntactic argument using a 1-based number
  and the API convention's code operand, parameter-source or body role. A spread
  records only a syntactic argument number; expanded ordinal/role is unverified.
- Nonliteral or unresolved operands remain high candidates with low confidence.
  Missing flow evidence does not make an operand a literal. Any spread anywhere
  in the argument list prevents the literal notice and leaves arity/roles
  unresolved. Only observed relevant input gets a trace; none is invented.

An observation is **not** a claim that code is safe, that external input is
absent, or that the callable is a pristine built-in. For example, a literal can
contain a nested input-dependent evaluation that this rule does not parse.
Literal contents are not allowlisted or interpreted. Shadowed/local calls keep
syntax-shaped labels, and existing analysis of their bodies remains active.
Replacement and runtime dispatch are unverified. These observations never act
as sanitizers or safe-return certificates.

The first eval argument alone is its code operand; trailing arguments do not
supply its code trace. Function checks all parameter/body operands. Zero-argument
calls, const propagation, concatenation, coercion, interpolated templates,
alias/call/apply/bind and new indirect constructor forms are not new literal
notice support. Existing direct call spellings remain, including their prior
static member-name recognition; dynamic computed fallbacks remain unresolved
high/low candidates with syntactic input evidence only. No API operand-role or
medium certainty is inferred for those fallbacks. Constructors are limited to Function and
window.Function with direct identifier/property syntax. Timer rules are unchanged.

Recognized eval/Function calls and direct Function constructors preserve operand
read order for their input evidence. A later argument assignment does not replace
an earlier argument's value. A following initializer/return evaluation uses the
same analyzer/environment's collected operands instead of replaying those reads
against the later write. This is not general heap or indirect-call analysis.

All four reports preserve observation/candidate, severity and retained evidence.
Info remains a finding row but is excluded from candidate counts. Completed
info-only checks return gate 0 under high, but may return 1 under `--fail-on info`.
Partial checks continue returning 2. Other blocking findings still block. Agent
verification stays false. Changed kind/title may change finding identity using
the unchanged identity algorithm; `.16` is a semantic ruleset revision, not proof
of a verified fix compared with earlier rulesets. No public schema, analysis
caps, source model or conditional singleton policy changed.
