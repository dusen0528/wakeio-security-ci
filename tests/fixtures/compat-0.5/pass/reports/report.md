# Wakeio Security CI report

## First read

- Scan gate: pass; exit 0; fail-on high.
- Applicable declared checks completed; the selected threshold did not block this scan.
- Gate reason codes: none.
- Findings (rows): 0; candidates (rows): 0. Blocking findings (unique IDs): 0; blocking candidates (unique IDs): 0.
- Candidate rows and blocking IDs overlap and use different units; do not add these counts.
- Declared checks: 3 completed; 0 incomplete; 1 not applicable.
  - Code coverage: collected_code_inputs; accounting=exact; required=false; collection complete=true.
  - Collected=1, eligible=1, completed=1, uncovered=0. Eligible is selected input support, not execution; completed is bounded adapter completion, not vulnerability completeness.
  - typescript: collected=1, eligible=1, completed=1, uncovered=0; builtin_ast selected=true, status=completed, eligible=1, completed=1; bandit selected=false, status=not_selected, eligible=0, completed=0; opengrep_native selected=false, status=not_selected, eligible=0, completed=0.
- AST workload selection: default (ast-work-v1).
- Collection workload selection: collection-v1; max files=1000, total bytes=26214400, per-file bytes=2097152, directory entries=8000. Declared selection limits, not coverage proof.
- Collection budget identity against declared scope: consistent. This identity does not change the scan execution gate.
- Declared scope: source; tool selection=built_in_only; whole-project coverage=not_established.
- Declared ruleset: 2026\-10\-14\.5; fingerprint=0c5d40fdc6245304a18052e73da7407a7d998560cfc2178c5b4955d366bd8760.
- Next read: review_scope_limitations.
- This is a review enum, not authority to run commands, install dependencies or upload source.
- Scan gate is separate from delivery/final process exit. This summary does not confirm a vulnerability, verified fix or whole-project safety.

- Mode: source
- Started: 2026\-10\-22T06:37:25\.273Z
- Finished: 2026\-10\-22T06:37:25\.296Z

## Checks

- Scope fingerprint: 0c5d40fdc6245304a18052e73da7407a7d998560cfc2178c5b4955d366bd8760
- Ruleset: 2026\-10\-14\.5
- Project ID: compat\-0\.5\-pass
- AST analysis budget: default (ast-work-v1; requested=default), indexWork=300000, flowWork=200000, nodeVisits=500000, functions=2000, summaryWork=5000, moduleEdges=2000, callDepth=8, aliasSteps=64, traceSteps=24
- Collection budget: collection-v1; max files=1000, total bytes=26214400, per-file bytes=2097152, directory entries=8000. Declared selection limits, not coverage proof.
- Source content hash: recorded as provenance; it does not define comparison scope.

- **source\.inventory**: completed
  - Collection budget: collection-v1; max files=1000, total bytes=26214400, per-file bytes=2097152, directory entries=8000. Declared selection limits, not coverage proof.
  - Collection diagnostics: 0 recorded issues; none.
  - No typed collection issue was recorded.
  - Collected string snapshot source-snapshot-v1: f79e676d3a60e0268b4df7edb2ca1da383e02b6653ceb4ed647bdcb65424f04c; 1 files, 116 bytes; complete=true; output inside or at source root=false. Aggregate input identity, not runtime or file-byte verification.
  - Note: Collected 1 allowlisted file \(116 bytes\)\.
  - Note: External scanner scope was narrowed to built\-in checks \(\-\-tools none\)\.
- **source\.builtin\-ast**: completed
  - AST analysis budget: default (ast-work-v1; requested=default), indexWork=300000, flowWork=200000, nodeVisits=500000, functions=2000, summaryWork=5000, moduleEdges=2000, callDepth=8, aliasSteps=64, traceSteps=24
  - Note: Built\-in AST checks parsed 1 JavaScript or TypeScript file\.
  - Note: Declared flow model: request\-shaped entry parameters, same\-function assignments, statically bound local functions/immutable const arrows, named relative ESM imports and constant static CommonJS destructuring exports within the collected snapshot\. Unique ESM named/star function re\-exports retain lexical authority for relative\-only paths; any snapshot\-configured alias edge carries conditional body authority, not runtime module identity or negative safety proof\. Source/sink API shapes are candidates, not runtime framework or database identity proof\.
  - Note: Express entry positions are additionally recognized for a bounded same\-file lexical import/require, immutable app/Router and route\-registration subset\. Request/response parameter spelling is irrelevant inside that subset; dynamic dispatch, upstream middleware state and runtime package identity remain unverified\.
  - Note: Koa middleware's first context parameter is recognized only through a same\-file immutable default/default\-as ESM import, no\-argument Application construction and app\.use\(callback\) binding; approved context/request query, URL/path and incoming header reads supply request\-source traces regardless of parameter spelling\. This is a declared API candidate, not runtime package or middleware identity proof: next\(\)/middleware\-chain effects remain unknown, and CommonJS, routers, body parsers, response body/headers and application state are outside this request\-source subset\.
  - Note: Dynamic/package imports without a supported collected path mapping, namespace/default exports, mutable exports and arbitrary class dispatch remain model limitations beyond the separately declared narrow constructor/capture and legacy\-driver lanes\. A canonical relative CommonJS local class singleton supports receiver\-bound actual/body dispatch; opaque native dynamic loading retains only a declared possible body with low\-confidence input and partial coverage, without return safety or runtime identity proof\. Unknown external calls are not trusted sanitizers and do not alone make declared coverage incomplete\. Resolved callees are not freshly seeded unless explicitly exported or passed as a callback to an unresolved/external call; callback execution and runtime entry reachability are not proven\.
  - Note: Observed collected configuration overrides or unsupported nearest configuration for recognized native package loads conservatively veto snapshot\-wide negative native certificates, while retaining input seeds and conditional candidates\. This does not resolve or execute replacement packages\. Configured graph counts describe adopted paths configurations, file/specifier/target tuples, call sites and analysis contexts; they are not runtime coverage or detection rates\.
  - Note: Outbound destination qualifier covers only canonical literal HTTP\(S\) origin/path plus native encoded query, direct const params record/toString/append/set and scalar local transfer\. Object containers, alias/escape, modified or shadowed native intrinsics and opaque options retain candidates\. Options support absent or plain literal method/fixed non\-Host headers only\. This is initial destination control, not redirect, DNS, proxy, remote query processing or runtime SSRF safety proof\.
  - Note: Axios request config role model separates a closed fixed INITIAL url field from payload\-only input under the declared v1\.13\.2 API contract\. Lexical imports/static require bindings and indexed snapshot validation do not authenticate runtime packages or external side effects\. Defaults/interceptors/custom transport, alias/mutation, incomplete scope and opaque target roles retain low\-confidence candidates; unknown is not safe\. No body source is asserted to control URL authority\.
  - Note: Closed local/relative CommonJS function constructors support actual allocation, own arrow methods, immutable binding\-identity capture frames and bounded scalar return/callback transfer\. Unmaterialized owned roots, mutation/escape, unsupported captures, cycles and identity failures retain partial coverage\. These frames do not establish runtime entry reachability or general callable safety\.
  - Note: Legacy MongoDB roles use only bounded collected nearest package/lock metadata and anchored 2\.x contract evidence\. A statically bound MongoClient\.connect final callback supplies its second parameter as a declared Db; fixed\-name Db\.collection creates a collection capability\. Missing/contradictory/3\+ version evidence, opaque options and escaped/mutated capabilities remain unresolved/partial\. Metadata JSON parsing is capped at 1 MiB per file and 256 files, charged to shared indexing work; no installed package, DB connection or target program is executed\.
  - Note: Direct window\.location assignments exclude browser navigation only for a fresh function/module\-private const object with an own data location slot and complete bounded proof within the collected static subset\. Script\-global, opaque, escaped and mutated bindings remain low\-confidence candidates\. Exact evaluator names in identifiers/static literals and computed destructuring keys veto exclusion; ambient callable identity and runtime realm closure are not certified\. Unbound browser\-shaped names do not prove runtime browser identity\. Bracket spellings, nested href and standalone location retain their existing interpretation\.
  - Note: MarsDB NoSQL role model recognizes declared Collection selector arguments of find/findOne/update/remove/count/ids\. Update data and options are separate from the selector\. Primitive\-string exclusion covers only local const snapshots with a dominating terminating typeof guard and no alias/mutation/opaque intervening effects; repeated member reads remain candidates\. Input in $where remains executable\-selector input even when it is a string\. Package identity, dispatch at runtime and exploitability remain unverified\.
  - Note: pg SQL role model separates supported statement text from bound values under the declared pg JS API\. Default dispatch and closed statement shape are required before a text\-input claim\. A fixed text/values exclusion is not runtime package identity, SQL syntax validity, database\-side dynamic SQL safety or confirmed remediation\. Unsupported identity, mutation, prototype, native, callback and opaque value/array roles remain unknown; generic SQL/input seed behavior is retained\.
  - Note: Bare fork spelling is not classified as a shell API when every observed invocation resolves to an immutable local/relative function and its actual analysis completes\. This is not function safety: nested native/SQL/HTTP/HTML sinks remain findings\. Unresolved, mutable and incomplete analysis retain the legacy heuristic and partial gate\.
  - Note: Node fork role model recognizes declared lexical child\_process bindings and only the modulePath argument\. Fixed modulePath does not establish whole\-call safety: argv, execPath, execArgv, cwd and env are unmodeled\. Mutable/escaped/incomplete identity retains low candidates; socket dispatch and guards are not newly modeled\.
  - Note: Node process role model separates command, executable, argv and shell\-option input for six exact\-load child\_process APIs\. exec/execSync normalize non\-string shell options to enabled; an empty shell string disables shell interpretation\. The four direct APIs default to no shell\. Fixed executable plus input argv under proven direct execution excludes only shell interpretation: program\-option injection, explicit interpreter operands, argv0, cwd, env, PATH and whole\-process safety remain unmodeled\. Mutable/escaped bindings or options, opaque overloads, spreads/getters and incomplete proof retain unresolved input candidates\. Dynamic shell\-field input may select a shell executable if it is a string; runtime type/execution are unverified\. Completed local process\-shaped bodies suppress only the name heuristic, preserving nested findings\.
  - Note: Budget model: one charged common indexing walk with index 300000 and flow 200000 work, plus 500000 aggregate cap\. nodeVisits is total index\+flow; legacy overrides remain aggregate caps\. Parsed files are not fully analyzed files\. Partial indexing disables immutable callee/native destination proof; known root counts do not imply complete global inventory\. AST observation/render and TS parse/bind work are outside these counters\.
  - Note: Parser/binder and collector limits remain separate from deterministic flow\-work budgets; this is not hostile\-code CPU/memory isolation\.
- **source\.framework**: not\_applicable
  - Note: No recognized Supabase migration or Next/React source file was available for the bounded framework rules\.
- **source\.code\-coverage**: completed
  - Code coverage: collected_code_inputs; accounting=exact; required=false; collection complete=true.
  - Collected=1, eligible=1, completed=1, uncovered=0. Eligible is selected input support, not execution; completed is bounded adapter completion, not vulnerability completeness.
  - typescript: collected=1, eligible=1, completed=1, uncovered=0; builtin_ast selected=true, status=completed, eligible=1, completed=1; bandit selected=false, status=not_selected, eligible=0, completed=0; opengrep_native selected=false, status=not_selected, eligible=0, completed=0.
  - Note: Code coverage counts describe collected code inputs only, not vulnerability completeness or whole\-project safety\.
  - Note: Eligible means selected provider input support, not submitted or executed\. Completed requires a validated complete code\-analysis result; partial providers contribute zero completed files\.
  - Note: Secrets, advisory, configuration and framework checks do not establish code\-analysis completion\.

## Findings

No findings were reported.

_Generated locally by wakeio-security-ci._
