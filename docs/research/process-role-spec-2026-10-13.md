# Process API role acceptance contract

Status: independent specification and synthetic test oracle, 2026-10-13. This
document makes no implementation, test-pass, exploitability, release or real
vulnerability claim. The root agent alone runs validation. Target source is
collected as data; never import it, install its dependencies or execute its
commands. CONTRIBUTING.md's candidate, redaction and incomplete-check contract
applies throughout.

## Pinned primary behavior

The reviewed references are the official Node.js **v22.20.0**
[child_process documentation](https://raw.githubusercontent.com/nodejs/node/v22.20.0/doc/api/child_process.md)
and [implementation](https://raw.githubusercontent.com/nodejs/node/v22.20.0/lib/child_process.js).
The same normalizers were independently checked in the official
[v22.22.0 implementation](https://raw.githubusercontent.com/nodejs/node/v22.22.0/lib/child_process.js)
at `normalizeExecArgs`, `normalizeExecFileArgs`, `normalizeSpawnArguments`,
`execFileSync` and `execSync`.
These define the API contract; the implementation is used only to resolve the
documented `exec` shell option ambiguity. No upstream detector rules are copied.

| APIs | argument 0 | argument 1 | options position | default interpretation |
| --- | --- | --- | --- | --- |
| `exec`, `execSync` | command string | options or callback (`exec`) | 1 | shell command |
| `execFile`, `execFileSync` | executable file | argv array or options; callback also allowed for `execFile` | 1 if argv absent, otherwise 2 | direct execution |
| `spawn`, `spawnSync` | executable command | argv array or options | 1 if argv absent, otherwise 2 | direct execution |

For the four direct APIs, `shell: true` or a nonempty shell-path string enables
shell interpretation of the executable and argv. `exec` and `execSync` use
`normalizeExecArgs`, which replaces non-string `shell` values with `true`;
therefore `shell: false` is **not** a shell-disabled control for these APIs.
An empty shell string remains a string but is falsey in the subsequent spawn
normalizer, so all six APIs take the direct-execution branch for `shell: ''`.
Non-string null/number values become true for `exec`/`execSync`. In direct APIs,
a numeric/object shell value throws a type error; null bypasses the non-null
validation and is falsey at runtime. Null is outside the documented shell
types; the pinned runtime nevertheless permits the same narrow direct argv
exclusion as false. This mismatch is recorded rather than changing the runtime
oracle or establishing general options safety.
Node v22.15 deprecated argv together with `shell: true` for `spawn`/`execFile`;
deprecation does not make the accepted call safe. Synchronous variants preserve
the relevant input roles. `fork` is a separate module-path lane and is not one
of these six methods.

## Required observable behavior

1. Recognize exact `node:child_process` and `child_process` lexical bindings:
   named ESM imports (including renamed methods), namespace/default imports,
   const CJS namespace/destructuring/method aliases and exact inline requires.
   A declared local/relative function or lexically shadowed loader must not gain
   native authority merely from a familiar name. Type-only imports do not bind
   executable methods. Follow completed local bodies to their nested sinks.
2. Tainted argument 0 is `ast:shell-input-sink`, critical, when it is a shell
   command; it is `ast:process-executable`, high, under default/false direct
   execution. Both are candidates with medium confidence for the closed
   declared API. Shell-disabled process selection is not a shell-metacharacter
   claim; wording must describe the executable/process role and preserve
   runtime uncertainty.
3. A fixed executable plus tainted argv under true/string shell options is a
   critical shell-input candidate. Proven direct execution under default or
   false options excludes this **shell** candidate. It does not establish safe
   flags, command-specific behavior, interpreter `-e`/`-c` safety, cwd/env/PATH
   safety, runtime identity or whole-call security.
4. Constant command/file/argv counterparts have no process-input candidate.
   Unused earlier input, opaque earlier results and an unrelated input-valued
   option cannot bootstrap argv or executable taint. Arrays must preserve the
   actual contributing element; a const alias must not lose that source.
   Command and argv evaluation must retain nested eval/SQL/HTTP/HTML findings
   even if the outer call is excluded as a shell-input candidate.
5. Keep known input visible when native identity, argv role or options are
   uncertain. Mutable method/namespace aliases, writes through another package
   binding, escapes, getters, computed fields, unresolved spreads, mutated or
   escaped options/arrays and overloaded opaque second arguments must not
   silently return completed clean. Accept a low-confidence candidate with
   explicit unresolved/unknown/possible wording and truncated flow, or a
   partial check and exit 2. Never label this as proven shell execution.
6. Plain literal field order is semantic: duplicate shell keys use the last
   field. Resolved data-only spread can be supported; unresolved spread is not
   proof of false, even when followed by an explicit false property, because
   accessor/iteration effects may affect binding or execution. A getter is
   never read/executed by the scanner or treated as a closed false value.
7. Input in a closed plain `options.shell` field is independently executable
   selection input, even with fixed command/file/argv: emit
   `ast:process-executable`, high, medium candidate with the actual shell-field
   source coordinate. The claim is conditional on an accepted nonempty string,
   not proof of runtime type/execution. Preserve field provenance through a
   supported const options record. An opaque options shape stays a low
   unresolved candidate or partial check; never steal an argument-0 source.
   Empty-shell direct argv exclusion is limited to this specific role: direct
   argument-0 input remains a process-executable candidate. Invalid options do
   not become proof of shell execution or completed clean safety; low unknown
   evidence or partial coverage is accepted where invalid/throw is unmodeled.

## Evidence, budgets and reporting

Known candidates end at the real call expression. Their source step names the
real argument contributor with exact one-based file, line and column. An argv
candidate must not borrow a source coordinate from argument 0 or an unrelated
earlier input. Separate-file const CJS provenance and source positions remain
reviewable under the same bounded model.

Existing public `runBuiltinAst` and `runSource` functions are the test entry
points. Tests import no prospective helper/module. The old runtime can load
the oracle and fail semantic assertions rather than missing imports. No
test-specific weakening or implementation-shaped expected counts is allowed.

Index/flow exhaustion, parse failures and collection limits remain partial;
`evaluateGate(..., 'none')` and the agent report both return exit 2. No closed
binding or safe exclusion may be inferred from incomplete indexing. Aggregate
work remains index plus flow, respects each budget, and retained analysis-gap
items remain bounded. Reported gaps are diagnostics, not measured security
coverage. An absent candidate on an incomplete scan is not a fixed result.

Public JSON, agent JSON, Markdown and SARIF must agree on candidate kind,
severity, source/sink evidence, review-required semantics and gate. None may
contain synthetic secret values, source snippets, target commands or escaped
copies of source. The scanner must leave every fixture byte unchanged.

## Freeze and review protocol

`tests/source-process-independent.test.ts` is the independently authored
synthetic acceptance suite. Freeze its baseline before validating engine work;
record failing semantic cases, then repeat the same suite against the changed
engine. Amend the oracle only for a documented API/spec mistake, with a reason
and primary evidence, never to fit detector behavior. A passing fixture suite
demonstrates only its declared cases. Separately owned OSS source-only replay
may provide external pattern evidence; it cannot turn these fixtures into a
new real vulnerability claim.
