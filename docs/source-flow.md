# Bounded source flow contract

Ruleset `2026-10-05.1` extends the existing built-in JavaScript/TypeScript AST
candidate detector with scan-local, argument-specific function summaries.
It is a bounded static model, not a general interprocedural SAST engine or
runtime vulnerability verification. No target import, dependency, hook, build,
script, server or test is executed to resolve calls.

## Declared support

- Direct identifier calls to immutable lexical function declarations and const
  arrow/function expressions; immutable identifier aliases are bounded.
- Actual argument values feed matching formal parameters. Return values and
  sink arguments are analyzed separately. Fixed SQL statements with tainted
  parameter values, unused tainted arguments and literal returns stay clean.
- Named relative ESM imports, including aliases and a unique `.js` to collected
  `.ts`/`.tsx` mapping. Static const destructuring of literal relative CommonJS
  `require` supports aliases and immutable `exports.name = fn` or one
  `module.exports = {name}` map. Resolution uses collected regular files only.
- Simple lexical shadowing, assignment order and early returns. Direct calls
  before const initialization are not resolved; calls in a deferred function
  body may use later module const declarations, assuming module initialization.
  Their actual runtime entry is not proven.
- `finally` always receives analysis, including after terminated try/catch
  branches. An unconditional finally return/throw overrides earlier return
  summaries. Branch joins remain conservative; this is not full exception or
  path-sensitive reachability analysis.

A helper invoked with concrete arguments is not freshly seeded from a formal
named `req`. Uncalled request-shaped functions, explicitly exported functions,
and local functions passed as arguments to unresolved/external calls retain
separate heuristic entry analysis. This preserves possible exported/callback
entries after an internal fixed call without treating every helper as a new
input source. Entry names and SQL/outbound sink names remain heuristic models;
this does not prove framework registration or database API identity.
Ruleset `.4` adds a narrow Axios `.request(config)` binding and input-role
model described in [source-role.md](source-role.md); `.7` composes its captured URL
field with the existing native encoded-query proof. Other input/SQL models
and outbound sink forms outside that model retain their existing heuristics.
Ruleset `.5` adds the narrow pg Pool/Client query binding and statement/bind-data
roles in [sql-role.md](sql-role.md). Generic SQL calls and input inference outside
that model retain their existing heuristics.

Summary cache identity includes the target file and AST position plus actual
abstract argument shapes and source origins. Safe and tainted calls, functions
with equal names, and separate scans do not share a context-free safe result.

## Limitations versus incomplete work

Package/dynamic imports, namespace/default imports, re-exports, mutable or
escaped exports, class dispatch, callback execution, free-variable captures,
full module initialization and framework/authentication/database semantics are
outside this declared model. Mutable/overwritten export maps and implicit
cross-file script globals cannot reuse a stale safe summary. Unknown calls are
not sanitizers. Opaque returns with input-related actual arguments retain a
low-confidence, truncated candidate fallback. A constant return can still be
safe in its narrow supported argument model.

Unsupported calls are counted in `unsupportedCalls` and described as model
limitations. They do not alone make every repository incomplete or safe.
Missing or ambiguous required relative targets, source parse failures, and
exhaustion of a declared analysis cap make the AST check `partial`. Input-related
supported recursive cycles are `summary_cycle`; cycles with no observed input
are counted as unsupported rather than creating a project-wide failure.
Incomplete checks produce scan gate exit 2 even with `--fail-on none`.

Caps are deterministic per scan:

| Resource | Limit | Incomplete reason |
| --- | ---: | --- |
| Indexed/analyzed AST work units | 200,000 | `node_limit` |
| Indexed function bodies | 2,000 | `function_limit` |
| New context-specific summary evaluations | 5,000 | `summary_limit` |
| Active summary call depth | 8 | `depth_limit` |
| Distinct analyzed relative import edges | 2,000 | `module_module_budget` |
| Function-alias resolution steps | 64 | `alias_limit` |
| Static trace positions | 24 | evidence `truncated`, not check partial |

Other resolution reasons are `module_missing`, `module_ambiguous`, and
`module_export_unsupported`. The last means a collected relative target file was
found but the requested callable/export identity could not be certified. It
keeps the check partial and gate exit 2; the diagnostic's actual call position
and `review_check_diagnostics` next read distinguish it from missing source.
Unrelated external/local/callback unsupported calls keep their existing policy.

Starting with ruleset `.12`, extensionless relative paths first use the existing
file candidates (`.js`, `.ts`, `.tsx`, `.jsx`, `.cjs`, `.mjs`). Only zero file
matches permits the same six `index` candidates. Multiple matches are ambiguous;
a file ambiguity is never rescued by an index file. A trailing slash requests
only directory/index candidates. Explicit `.js` retains the existing JS/TS/TSX
candidate policy; other supported explicit extensions match exactly, and
`.mts`/`.cts` remain explicit-only. Package main/exports, external filesystem,
installation and runtime loader execution are outside this static policy.

A top-level static `module.exports.name = function/arrow` or immutable local
function binding can connect actual arguments through the existing scalar
summary/return/trace machinery. New calls are const CJS named destructuring
(aliases allowed) or a const namespace's direct `.name(...)`. Starting with `.13`, receiver-independent ordinary sync and async scalar
targets share the same proof. Existing async body actual seeding is retained;
async/generator call-return SQL/HTTP safety qualifiers remain unavailable.
Generator and async-generator callable certification is unavailable. Duplicate/dynamic slots,
`this`/`super`, re-exports, UMD-local exports, callback/Promise capture and general
alias graphs remain unsupported. All observed importers resolving to the same
snapshot file (including `./dir` and `./dir/index.js`) share whole-export
mutation/escape/loader vetoes. A pristine selected slot does not override a
mutated exports object. Exported roots survive failed identity proof, and body
analysis still obeys the unchanged default/extended caps. Inner sinks are
preserved only in forms supported by the existing models; callable resolution
is not complete security coverage, runtime reachability or safety.
Metrics include actual counters, the corresponding `max*` limits,
`analysisIncomplete`, `incompleteReasons`, and
`flowModel: bounded-static-local-relative-v1`. Module indexing, export/binding
passes and summary analysis consume work units. TypeScript parser/program/binder
internals and abstract object serialization are not bounded by that counter.
Existing collection caps (default 1,000 files, 25 MiB total, 2 MiB per file) and
the caller/CI runtime timeout remain separate resource boundaries; this is not
hostile-code CPU isolation.

## Evidence and reports

Optional `staticFlow` steps contain only observed AST roles and relative
path/line/column positions: source, call, parameter, return and sink. No source
text, fabricated edge, command or runtime PoC is included. A trace requires an
observed source and sink endpoint to be exposed as complete static evidence.
Unknown transformations or the 24-step cap are marked truncated; absence of
trace is unknown, not proof of safety. Only one representative source path is
retained when flows join; the report does not enumerate every feasible path.

Sanitisation precedes JSON, SARIF `codeFlows`, Markdown and agent projection.
Unsafe paths and unknown proof fields are dropped. The agent uses
`static_provided`, `static_truncated` or `not_provided`; it keeps verification
`not_run`, vulnerability confirmation false and remediation `not_verified`.
Severity and confidence remain separate. Scan-gate/digest/delivery semantics
remain as documented in [agent-report.md](agent-report.md).

The unchanged 30 fixture sources retain 15 vulnerable and 15 fixed cases.
Corpus v2 promotes the two historical local/relative-module SQL misses to
supported expectations (13 to 15 supported findings), so future misses fail
strict gating. Baseline archives retain their historical v1 labels/counts.
Generic development safe pairs and independently added acceptance cases test
model boundaries; neither is a statistical blind holdout or production recall
estimate. Fixed-origin URLSearchParams encoded-query outbound precision is a
separate follow-up and is not solved by this change.


## URL destination qualifier (ruleset 2026-10-05.2)

The outbound arg0 model distinguishes a canonical literal absolute HTTP(S)
origin/path ending in `?` followed only by native encoded query fragments and
fixed query delimiter/text fragments. It preserves the original input taint and
position evidence for SQL, shell, HTML, and redirect checks. It is not a general
URLSearchParams sanitizer or a runtime SSRF safety assertion.

Native proof requires an unshadowed global constructor with one plain record
argument (or an empty constructor), stored in a direct `const` binding. A fresh
constructor immediately consumed by zero-argument `.toString()` is also supported;
its serialized scalar may be concatenated, templated, or returned by a supported
helper. A scan-local lexical reference index
permits same-function direct `toString()`, `append(key,value)`, and `set(key,value)`
only. Append/set on an initially empty object carries its actual input taint to
serialization and every other sink. Any object alias, containment, escape, other member use, or observed native
global/prototype access disables this proof before flow analysis. Scalar string
aliases and supported local parameter/return transfers retain the qualifier;
object/array storage strips it recursively because heap alias mutation is not
modelled. Native intrinsic behavior is assumed only within this declared static
boundary; effects of unobserved external runtime code are not proven.

Concatenation and templates carry at most 16 fragments and 2048 literal characters.
Exceeding these shape limits drops only the qualifier and preserves input evidence.
Both branch shapes must be identical to retain a joined qualifier. Summary cache
identity includes shape metadata. At a shared sink all observed contexts must be
qualified; one unqualified context retains the candidate and its evidence.
Existing flow-work limits and incomplete/exit2 semantics remain unchanged.

Outbound options support no options or plain literal properties: a fixed standard
HTTP `method`, and plain fixed string `headers` excluding `Host`/`:authority`.
Spread/getters/computed keys, opaque configuration, transport/adapter/base URL,
and all other fields retain candidates. The rule remains an API shape heuristic.
This describes the initial URL destination; redirects, DNS, proxy behavior, remote
query interpretation, authentication and actual exploitability require separate
verification. Mutable URL objects and URL/base resolution are unsupported.

AST metrics `outboundDestinationModel`, `outboundQueryQualifiedUses`, and
`outboundFixedDestinationSuppressed` expose the model and counts per merged sink
location, not per evaluation. Literal fragments stay internal and are not exported
in JSON/SARIF/Markdown/agent evidence. Candidate verification remains `not_run`;
no vulnerability confirmation or remediation verification is inferred.


Query input content is tracked separately from destination proof. A scan-local,
actual-context-local content cell is shared by direct identifier aliases of a
native params value. Append/set monotonically union observed input values and
position evidence even when alias/escape revokes destination qualification.
Branch environment copies conservatively share this content union; exact set
replacement, conditional object selection and general heap identity are not
modelled. Constant-only updates do not manufacture input evidence. A toString
result is an immutable scalar snapshot, so subsequent appends do not taint an
earlier serialization. Mutable query arguments or returned objects bypass
summary cache reuse; their normalized content excludes mutable pointers/cycles.
Scalar summary caching still includes bounded destination fragments. The content
cell is not exported as evidence or reused between scans or distinct actual
contexts. These are candidate flow semantics, not runtime exploit confirmation.

Opaque query content remains unknown through serialization: only definitely
`safe` content produces a safe scalar; observed input produces unknown input,
and unmodelled content remains unknown. This preserves the existing low-confidence
actual-argument fallback for unsupported captures/helpers rather than trusting
serialization as a sanitizer. Constant-content controls stay free of manufactured
input evidence. This corrects an unpublished implementation defect within ruleset
2026-10-05.2; revision source/bundle/support hashes distinguish the correction.


## Ruleset 2026-10-05.3: common index and separate work budgets

This unpublished revision changes budget semantics, not the supported source,
sink, module or URL grammar. The `.1`/`.2` 200,000 shared-work contract above is
historical. Current defaults are 300,000 index work units, 200,000 flow work
units, and 500,000 aggregate units. `FlowLimits.indexWork` and `flowWork` are
optional; omitted fields receive these defaults. Existing `nodeVisits` overrides
remain aggregate caps; `maxNodeVisits` reports the actual override, never a
misleading per-phase limit. Index/flow caps report `index_work_limit` and
`flow_work_limit`; the aggregate cap retains `node_limit`. Other limits remain
unchanged. Defaults were selected before new development measurements, without
per-function quotas or resumable scheduling.

One common indexing traversal records AST nodes, lexical owners, mutation
writes, symbol references, CommonJS boundary references and native-query
constructor/boundary nodes. Export/call/native validation reuses this metadata.
Validation and initial symbol lookup also consume index work; runtime resolution
and summary evaluation consume flow work after the phase switch. This is one
common *indexing* traversal, not one traversal across the entire scanner.
TypeScript parsing/binding, AST finding observation, inline secret checks,
serialization and report rendering are outside these charged counters.
Collection limits and CI timeouts remain separate; these work units do not
provide hostile-input CPU or memory isolation.

`nodeVisits = indexWork + flowWork`, with `maxIndexWork`, `maxFlowWork` and
`maxNodeVisits` reporting exact limits. `filesParsed` (and legacy alias
`filesAnalyzed`) counts parse attempts, including syntax failures;
`filesParseValid` and `filesIndexInput` count the parse-valid index inputs.
`filesIndexWalkCompleted` counts files whose common walk finished.
`filesIndexed` is the parse-valid file count only when all required index
validation finished, otherwise zero. A partially walked file is never called
fully indexed.

An index/aggregate cap, function-inventory cap or required index validation
failure makes `indexComplete` false. Immutable callee and native destination
proofs are then disabled. A partial called-set cannot hide possible entry roots:
all known collected functions receive potential root analysis while flow budget
remains. This can retain conservative candidates; exit 2 still takes precedence.
It does not recover unknown functions absent from the incomplete inventory.

Top-level tasks are parse-valid source files. Entry-root tasks are collected
body-bearing function declarations, function expressions, arrows, methods,
getters, setters and constructors, selected by uncalled-or-explicit-export-or-
callback-escape when indexing completes. There is no request-shaped formal
filter in structural task selection: arbitrary formal names yield UNKNOWN,
while existing request-shaped parameter heuristics supply source seeds.
`topLevelDeclared/Started/Completed/Partial/Skipped` and
`entryRootsDeclared/Started/Completed/Partial/Skipped` count these tasks;
`tasksDeclared` is their sum. Started = Completed + Partial and
Declared = Started + Skipped. Completed means that task encountered no new
incomplete event, not full runtime/path/framework coverage.
`functionContextsStarted/Completed/Partial` additionally counts invoked summary
contexts, excluding cache hits. A partial inventory reports only known tasks,
not a complete global root count. Flow-only exhaustion does not invalidate a
complete index inventory.

`indexComplete` describes only parse-valid index inputs.
`rootInventoryComplete` additionally requires zero source parse errors; a failed
parse can therefore leave indexComplete true and rootInventoryComplete false.
Partial summary contexts are never cached as complete summaries for a later
equal argument context. Their later evaluation retains incomplete events and
accurate per-root Partial counts. Neither counter asserts runtime coverage.

`.8`의 좁은 Node `child_process.fork` binding/modulePath 역할은 [fork-role.md](fork-role.md)를 참고하세요. argv/options와 socket/member dispatch의 보안 의미는 별도 미지원 한계입니다.

`.10`은 [상대 CommonJS 객체 메서드](interfile-object.md)의 wrapper slot → const child → own method 두-hop 연결을 추가한다. 기존 scalar helper/taint/sink 휴리스틱과 완료·후보 의미는 유지하며, 객체 몸체 전체 coverage나 런타임 identity를 인증하지 않는다.

## Explicit AST workload selection

Source scans accept SDK `analysisProfile: 'default' | 'extended'`, CLI `--analysis-profile default|extended`, and Action `analysis-profile`. Omission selects `default`; the Action omits the flag in URL/API-only mode, and `extended` requires source. Invalid selectors are rejected before collection or Action setup/install. No target configuration, numeric override, automatic expansion or retry is used.

The `ast-work-v1` record carries requested/effective profile and nine actual limits. Default keeps indexWork=300000, flowWork=200000, nodeVisits=500000, functions=2000, summaryWork=5000, moduleEdges=2000, callDepth=8, aliasSteps=64, traceSteps=24. Extended multiplies the first six workload limits by four; depth, alias and trace limits stay unchanged. Parser/binder/observation work, collector limits, API/native budgets and runtime supervision remain separate. Extended guarantees neither completion nor equivalent precision, elapsed time or RAM use.

JSON/agent check and source scope metadata, Markdown and SARIF run properties preserve the registered record. The agent first summary shows profile/revision. Source includes mixed source+URL/API modes. Scope fingerprints include the whole record; AST report comparison also requires matching scope/check records. Missing legacy identity is readable but unverified; present malformed records are rejected before comparison sanitization. A same-fingerprint budget mismatch cannot imply remediation. `not_observed` and finding verification=false retain their existing meaning. The ruleset is `.11`; source/sink models and ID algorithm are unchanged, without promising identical candidate sets or every actual ID.

Starting with ruleset `.13`, direct files and directory/index files normalize
`exports.fn`, `module.exports.fn`, and one `module.exports={fn}` (including
static alias keys and a top-level const plain wrapper) into the same canonical
producer descriptor. Flat scalar slots can coexist with existing const child
objects. Exact const named destructuring and const namespace direct calls reuse
actual/formal/return/trace/cache analysis; nested/default/rest/computed/array
bindings are not flattened into a scalar export.

Every observed canonical importer and producer participates in the existing
whole-group mutation/escape/loader/cycle checks. Multiple whole assignments,
whole/property mixtures, duplicate or opaque slots, producer global shadow,
pre-initialization aliases and callable escape cannot revive a fixed summary.
A file-found but unproved export retains `module_export_unsupported`, partial
and gate2, with known input fallback low/truncated. Shadowed local `require`
remains an ordinary local call rather than a native relative loader.

Known indexed export targets are retained as external-entry roots independently
of certification, including failed initialization/mutation/scope/receiver or
generator proofs. This is conservative source analysis, not runtime loader,
Promise completion, iterator execution or complete body security coverage.
Pure ESM remains separate; CJS/ESM interop and snapshot-outside importers are
not certified. The `.12` direct legacy export-map bypass is no longer used.
Finding ID schema/algorithm, source and sink models, default/extended caps and
bounded gap32 reporting remain unchanged; actual candidate sets may change.

Const wrapper scalar initialization is checked at object construction, not a
later export assignment. Primitive property siblings use the same non-callable
policy as whole literals. Lexical CJS declaration scopes distinguish an actual
shadow from an unrelated nested local name; local objects alone do not mark a
pure ESM producer as CJS. Genuine CJS mixed with default/empty exports or other
ESM module markers remains unproved independently of named callable-map size.

### Bounded reason distribution

Newly recorded `analysisGaps.reasonSummary` adds at most 13 fixed-reason rows in
registry order. Each row records weighted `eventsObserved` and `eventsDropped`:
these are diagnostic observations, including repeated contexts and weighted
parse events, not unique sites, functions, vulnerabilities or source coverage.
Dropped counts mean observations omitted from retained location items; they do
not count analysis work skipped. Whole-project unique gap sites are unavailable.

For exact metadata, reason observed/dropped sums equal the global counts and
per-reason retained observations plus dropped equals observed. Zero rows are
omitted. The report's 256-item cap moves removed observations to their reason's
dropped count once; the summary's three-item omission changes only
`omittedRetainedItems`. Neither cap changes analysis limits or check/gate status.
Legacy reports without this field remain unavailable; retained items cannot
reconstruct dropped reasons. Malformed reason metadata becomes unknown without
invalidating independently valid global accounting. Global unknown prevents
exact reason accounting. Sanitisation checks bookkeeping, not diagnostic truth.

JSON/agent/SARIF carry the same optional table and Markdown shows it in First
read and detailed Checks. Reason rows are independently copied. When the first
incomplete check has no retained item but has exact nonzero reason counts,
`nextRead` uses the first registry reason's existing review enum without a
location. Known reason and unavailable representative location remain distinct.
Existing first-item navigation, findings, scan gate, scope, source models,
analysis budgets, schemas and ruleset `.13` are unchanged. This is a reporting
improvement, not a detection-accuracy result or execution authority.

`.14`의 제한된 relative CommonJS class singleton은 canonical receiver를 유지해
actual→formal→method body와 직접 `this.other()` 흐름을 연결한다. Closed dispatch와
opaque native dynamic loading 아래의 declared body 후보는 구별하며, 후자는 기존
low certainty·export gap·partial로 남고 안전 반환이나 cache/root 제거를 인증하지 않는다.
정확한 문법·constructor·mutation·receiver·예산 및 미지원 경계는
[class singleton 계약](class-singleton.md)을 따른다.
