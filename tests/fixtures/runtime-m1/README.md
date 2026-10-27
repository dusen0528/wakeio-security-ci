# R8 independent M1 SQL inputs and expectations

These 18 IDs freeze CP1-r2 V1–V3/F1/F2/N1–N13. R5 had no SQL implementation when authored.
Existing primary cases, sources and ground truth are unchanged. R8 owns expectation changes.
All SQL/error/HTTP/canary strings are synthetic; no secret or target response is included.
No PostgreSQL, Docker, target build, parser package or WASM was executed.

`sql-cases.json` is canonical raw input plus fixed expected counts/reasons. Resolve raw-template refs
and replace `{marker}` with each request's distinct fixed marker. Hash the resulting UTF-8 payload,
marker, statement and compact raw-event bytes. Never hash a literal placeholder as runtime input.
Each case is a fresh run/nonce/session/lease; request ordinals are unique within that case.
The snapshot hash is a synthetic label identity, never a measured PostgreSQL snapshot digest.
Every normal control succeeds; V3 expects HTTP 500. Other baseline requests have complete collector/drain,
matching issued ledger/route/parameter/window, restored seed, exact coverage and confirmed cleanup.
Apply `faults` to that baseline. Each fault alternative is independent, never a combined success.
Missing control, broken observer, unsupported input and stale/misattributed events are unknown.
N12 exits 2. N13 retains the first confirmed while recording the other gap/cleanup error and exits 1.
N1/N2 retain strong=1 despite confirmed=0. Escaping alone does not erase PLAN's unbound-text grade.
N3's marker only occurs in a comment, which cannot execute SQL syntax; strong/confirmed stay zero.
N11 discards only its extra unmarked canary event; the valid bound control/probe remain observable.

N4 safe-search is a complete bound SQL negative. Its separate ping reflection check schedules no SQL
judgement and proves only SQL finding count zero, never that missing PG evidence proves safety.
If ping is assigned a SQL probe, its absent PG control must instead remain unknown/exit 2 as recorded.
The CLI planner's handling of that boundary requires R1/R5/R10 agreement; existing safeOnly=0 is unchanged.

`sql-projections.json` contains manually selected relevant AST/token roles and spans, not parser dumps.
It is a TEMPLATE for R1 Observation fields; resolve references/placeholders before calling an Oracle.
No SQL identifier/literal/comment/Bind value is copied into a projection. SQL-derived bytes stay raw-input-only.
`parserMetadata: null` explicitly means unmeasured; a verified external identity is required for real collection.
Do not invent lock/WASM hashes or present manual node kinds/quote diagnostics as actual library output.
Byte spans are computed directly on these ASCII fixtures. V3's opening quote is byte 39 / PG character 40.
The adapter must separately verify real parser/PG positions; ASCII equality does not prove Unicode conversion.
Profile `other-error` has mismatched context; `invalid` never becomes valid just because it has a hash.
An insertion may overlap a literal token's quotes; promotion needs literal-external tokens AND AST structure.
Observation.sequence/session-line/requestOrdinal each represent one request, never a group of requests.
N7/N8/N9/N10/N12 fault paths may prevent an Observation entirely; a template is not proof of collection.

Primary references: [PG lexical rules](https://www.postgresql.org/docs/18/sql-syntax-lexical.html),
[PG error positions](https://www.postgresql.org/docs/18/protocol-error-fields.html),
[scan byte spans](https://github.com/constructive-io/libpg-query-node/blob/main/versions/18/SCAN.md).
R9 must independently test fixture materialization, pure Oracle results, leak filters and actual owned runs.
