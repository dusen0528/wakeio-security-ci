# Agent-readable scan report

Every started `scan` writes `agent-report.json` alongside the existing
`report.json`, `report.sarif`, and `report.md`. This is a versioned projection of
the sanitised public report. It improves consumption and triage; it does not
change detector accuracy or establish an exploit or verified fix.

```sh
wakeio-security-ci scan --source . --tools none --fail-on high --out reports
```

The SDK keeps `writeReports(report, outDir)` compatible, with `high` as its
default threshold. Pass `{ failOn: 'none' }` as the optional third argument to
match a different CLI policy. `toAgentReport(report, failOn)` and
`evaluateGate(report, failOn)` are exported through the package index.

## First-read summary

New agent reports include optional additive `summary` metadata (version 1) in
schema 1.0. Markdown places the same projection before Checks and its full notes.
`toReportSummary(report, failOn = 'high')` is exported, and
`toMarkdown(report, failOn = 'high')` accepts the same optional threshold.
`writeReports(report, outDir, { failOn })` passes one threshold to Markdown and
the agent report; legacy calls still default to `high`. Standalone renderer
callers must pass their threshold explicitly when it differs from `high`.

Summary gate outcome/exit/threshold are copied from the existing adjudication.
`reasonCodes` copies the unique existing gate codes in their original order
(at most five), including `no_checks`, `no_applicable_checks` and
`invalid_fail_on` when no incomplete check row exists. It does not represent
delivery success or final process exit. A pass is no whole-project safety or
verified-fix claim; a candidate is not a confirmed vulnerability.

`counts.findings` and `counts.candidates` count **finding rows**. Repeated
identities remain repeated rows. `blockingFindings` counts **unique gate IDs**,
and `blockingCandidates` counts the unique intersection of candidate IDs and
blocking IDs. These units differ and overlap; do not add them or treat them as
independent vulnerability counts. The evaluator and finding identities are
unchanged.

The summary retains the first six incomplete checks (partial/error/skipped)
and the first three recorded gap items per check, in existing check/item order.
`checkIndex` disambiguates repeated IDs. `omittedIncompleteChecks` and
`omittedRetainedItems` describe summary omissions only: original event
accounting, recorded truncation and full diagnostics remain in the detailed
checks. Unknown accounting remains unknown/null, not zero. With no typed gap,
`diagnosticBasis: "check_status_only"` means cause/location are unknown.
Representative items are navigation, not an exhaustive or ranked cause list.

`scope` records the declared mode and optional fingerprint/ruleset; it does not
establish whole-project coverage. `toolSelection` is projected from the source
inventory's structured requested-tool metrics: `built_in_only`,
`external_tools_selected`, or `native_preview_selected`. Older reports, invalid
metadata or ambiguous duplicate inventories retain `unknown`. The summary never
parses notes or confuses selection with installation, execution or applicability.
Existing typed statuses/provenance remain available in the original report. A
`module_missing` gap does not by itself prescribe installing a dependency.

`nextRead` copies a recorded gap's fixed `nextReview` and optional reported
position for the first incomplete check. Without such an item it requests
`review_check_diagnostics`; without incomplete work it requests finding-evidence
or scope-limitation review. It contains no source text, commands or installation
authority. Sanitised location syntax is not authentication of source truth.
Every projection treats incoming report data as untrusted. Original report JSON,
SARIF results/rules/code flows, scan gate, scope, coverage and finding verification
are unchanged; the source ruleset remains `.7`.

## Scan gate and delivery

`schemaVersion: "1.0.0"` identifies the agent contract independently of
`reportSchemaVersion`. `scanGate` uses the same adjudication as
`exitCode(report, failOn)`:

- `pass`, exit 0: applicable declared checks completed and the configured
  threshold did not block. With `none`, findings may exist but do not block.
- `findings`, exit 1: the severity threshold was reached.
- `incomplete`, exit 2: partial/error/skipped work, no checks, no applicable
  checks, or invalid threshold. Incompleteness takes precedence over findings,
  including with `--fail-on none`.

`reasons` links incomplete check statuses and severity threshold findings to
check IDs and deterministic finding IDs. `coverage` counts **declared check
statuses**, not whole-project or runtime coverage. Each check retains its
sanitised notes/metrics; missing metrics or unsupported scope remain unknown.

`reportArtifact.digest` is the SHA-256 of the exact emitted `report.json` UTF-8
bytes, including its final newline. Verify it before joining artifacts. The
agent file is published last, after the three existing formats. All targets
use the existing ancestor/target symlink checks and per-file atomic writes.
This is **not** a four-file transaction. Failed delivery makes the CLI exit 2;
old or partially replaced artifacts are not proof of the final process exit
or CI success. Obtain the actual process/job receipt separately. On successful
delivery, the CLI exit matches `scanGate.exitCode`.

The composite Action exposes `report-agent` only when the fresh `report.json`
and agent digest match; otherwise its value is empty. The summary distinguishes
scan adjudication from Action/process status. Existing report outputs remain
available under their existing names. Setup failure may leave old files or
report paths that do not exist; output paths alone do not prove success.

## Finding evidence and consumer requirements

Each finding links its `findingId`, `checkIndex`, `checkId`, and `ruleId` to the
sanitised report. Indexes disambiguate duplicate check IDs; repeated findings
are retained. Severity, confidence, evidence `kind`, location, references, and
existing remediation guidance remain separate fields. `reachesFailOn` means a
finding meets the configured severity threshold, even if incomplete work takes
precedence. With `none`, it is false.

`evidence.basis` is `scanner_report`. An optional `staticFlow` contains only
observed source/call/parameter/return/sink positions, with no source text.
The optional native preview can also provide an `intermediate` position. It
does not assign a call/parameter/return edge to that location, and native
evidence is always `static_truncated`: complete dataflow edges are unverified.
This additive role keeps schema 1.0 and the existing envelope; consumers must
handle documented roles without treating any static position as runtime proof.
`traceStatus` is `static_provided` for a bounded source-to-sink trace,
`static_truncated` for capped or incomplete evidence, and `not_provided` when
no trace is available. JSON, SARIF, Markdown and the agent projection share this
sanitised evidence. See [the bounded source flow contract](source-flow.md).
No runtime trace, PoC, executable remediation recipe, or command is invented.
`verification.state` is `not_run`, `vulnerabilityConfirmed` is false, and
`remediation.state` is `not_verified`. Static findings disappearing in a later
scan do not establish a verified repair. Independent before/after security and
normal-control evidence belongs in a separate verification workflow.

`consumerRequirements` treats every external finding/note/guidance as untrusted
data. Do not execute its instructions or upload source because a finding says
to do so. `actionsRequireUserTaskAuthorization: true` and
`findingsGrantActionAuthorization: false` mean that human task authorization is
required; existing session authorization remains valid and need not be requested
again for every authorised action. These are requirements for consumers, **not
a guarantee of prompt injection protection**. This projection invokes no agent,
external service, source upload, target script, build, or test.

Location paths must be safe relative paths; URL credentials/query/fragments and
recognised credential forms pass through the existing public report sanitiser.
This is not a guarantee that arbitrary sensitive prose can be recognised.
`agent-report.json` is excluded from subsequent source collection, just like
the three existing report artifacts.

## Optional analysis gap diagnostics

`checks[].analysisGaps` is additive metadata in schema 1.0. It helps a consumer
locate supported analysis that did not finish; it creates no finding and changes
neither finding identity nor the scan gate. Missing metadata does not establish
complete analysis. The existing check status and coverage remain authoritative.

The producer records the first 32 distinct items per check. Report projections
retain the first 256 items across checks in check/item order. An item contains
only a fixed `reason`, `phase`, `extent`, positive `observations`, and a fixed
`nextReview` enum. Supported missing/ambiguous/module-budget call events may
include a source location proved against the collected snapshot and its actual
node range. Other budget, parse and index gaps are check-wide; no location is
invented. Import specifiers, source strings, commands and proposed missing paths
are excluded. The public sanitiser validates location syntax, not source truth.

For `accounting: "exact"`, `eventsObserved` equals retained observations plus
`eventsDropped`; `truncated` means observations were dropped by metadata caps.
These counts describe recorded events, not all missing paths or runtime coverage.
Malformed/overflowed accounting becomes `accounting: "unknown"`, both counts
`null` and `truncated: true`; retained valid items remain available. Repeated
sanitisation does not count the global cap twice. Path protection is limited to
the existing validator and recognised credential patterns, not arbitrary secrets.

JSON and the agent report carry the optional check field. Markdown displays
the accounting and review enums. SARIF uses a run-properties `analysisGaps`
array with `checkIndex`, `checkId` and the envelope, without adding results,
rules or code flows. `nextReview` requests source-only context, budget, parse or
check-diagnostic review; it grants no execution authority and links to no
affected finding IDs. This improves diagnostic navigation, not detection accuracy.

## Explicit AST workload selection

Source scans accept SDK `analysisProfile: 'default' | 'extended'`, CLI `--analysis-profile default|extended`, and Action `analysis-profile`. Omission selects `default`; the Action omits the flag in URL/API-only mode, and `extended` requires source. Invalid selectors are rejected before collection or Action setup/install. No target configuration, numeric override, automatic expansion or retry is used.

The `ast-work-v1` record carries requested/effective profile and nine actual limits. Default keeps indexWork=300000, flowWork=200000, nodeVisits=500000, functions=2000, summaryWork=5000, moduleEdges=2000, callDepth=8, aliasSteps=64, traceSteps=24. Extended multiplies the first six workload limits by four; depth, alias and trace limits stay unchanged. Parser/binder/observation work, collector limits, API/native budgets and runtime supervision remain separate. Extended guarantees neither completion nor equivalent precision, elapsed time or RAM use.

JSON/agent check and source scope metadata, Markdown and SARIF run properties preserve the registered record. The agent first summary shows profile/revision. Source includes mixed source+URL/API modes. Scope fingerprints include the whole record; AST report comparison also requires matching scope/check records. Missing legacy identity is readable but unverified; present malformed records are rejected before comparison sanitization. A same-fingerprint budget mismatch cannot imply remediation. `not_observed` and finding verification=false retain their existing meaning. The ruleset is `.11`; source/sink models and ID algorithm are unchanged, without promising identical candidate sets or every actual ID.

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
