# Changelog

## Unreleased

- Add an explicit policy-driven property-write API check for one disposable staging resource, with owner/verifier controls, strong ETag negative controls, a fresh normal-field barrier, and bounded conditional cleanup. All four reports preserve typed redacted HTTP readback evidence; ambiguity/cancellation stop writes and incomplete runs retain exit 2. This grants no automatic agent replay or independent storage/fix verification. See [operator contract](docs/api-property-write.md).

- Add bounded source-only Node HTML output-context candidates under ruleset
  `2026-10-14.5`: declared core HTTP/HTTPS request callbacks and a narrow send
  directory adapter preserve literal/input-hole provenance to quoted URL attributes.
  Unknown encoding, MIME and streaming remain partial low-confidence candidates;
  encoder names grant no safety proof. See [scope and gates](docs/html-output-context.md).

- Add the offline agent-DAST evaluation harness (internal, not exported or
  wired to the CLI) under `src/agent-dast/eval` and `benchmarks/agent-eval`:
  a label format with `tuning`/`final` splits, distinct-vulnerability TP/FP/FN
  scoring with cross-worker de-duplication, total-round request-budget
  summation against one shared cap, a pre-run coverage denominator, and pass
  criteria bound to the final label hash and attested as fixed before arm B.
  It sends no request and runs no engine or model; arm A (fixed plan) vs arm B
  (agent selection) is scored from synthetic or recorded results only. Adds a
  run-start record pinning the criteria, final label and shared check-list
  hashes, with `evaluate()` confirming the record and its digest are untampered
  and each scored finding links to its run.db row and evidence file. Stored
  run-plan bundles are linked read-only from DB observation to evidence to the
  engine finding in the task report; a plain evidence-dir hash check is reported
  as not-yet-provenance.

- Add an experimental `wakeio-security-ci/agent-dast` SDK with a bounded
  worker-result contract and RunStore v2. Completion requires the declared
  plan, retained task observations and trusted runner ledger to agree;
  deduplication preserves auth/location context, severity and evidence refs.
  Populated prototype v1 and WAL inputs are refused without inventing trusted
  evidence. Store runtime support is Node 22.13+ in 22.x, 23.4+ in 23.x, or 24+;
  other modes retain their Node floor. This adds no worker executor or CLI.
  See [store contract](docs/agent-dast-store.md).
- Add an explicit authenticated numeric POST JSON differential policy v4 with
  one bounded body field, distinct benign-value controls, twelve fixed logical
  steps and no automatic POST retry. Existing GET policies retain their scope;
  response candidates do not verify exploits or fixes. See [POST JSON contract](docs/native-dast-post-json.md).

- Close outstanding DAST target requests on cancellation, gate close or engine
  disconnect, and await HTTP/CONNECT connection cleanup while retaining tunnel caps.
- Forward Action SIGINT/SIGTERM through setup, native policy preflight and scan
  subprocesses with bounded process-group cleanup. Preserve fresh partial evidence
  and write non-success scan receipts instead of retaining stale successful status.
- Require cancellation and teardown regressions in the real-engine zero-skip gate.

## 0.5.0 — GitHub source preview

Source and the checked-in Action are versioned 0.5.0. The latest published npm
package remains 0.4.0; use a reviewed Git commit or build this checkout for the
features below. This entry does not claim an npm 0.5.0 publication.

- Always report collected-code language/provider coverage and add explicit
  `--require-code-analysis` gating for uncovered, incomplete or unknown code
  analysis. Default scan gates remain compatible; collection is not analysis
  completion or whole-project coverage. See [scope contract](docs/source-code-coverage.md).

- Add an explicitly consented owned PATCH state pilot through SDK, CLI and a
  dedicated composite Action. A fixed actor/resource matrix and independent
  persisted-state observer distinguish denial responses from actual mutation,
  preserving normal owner controls and original before/after gates. The bounded
  run permits only pinned author-owned loopback fixtures; existing API policy
  GET semantics remain unchanged. Reports, staged publication and caller ACK
  remain separate. See [owned write scope and validation](docs/api-write-state.md).

- Add bounded filesystem filename→stream callback→captured accumulator→process
  argv analysis under ruleset `2026-10-13.3` for the documented reviewed versions.
  Source-kind and conditional-context metadata preserve low-confidence candidate
  evidence and incomplete checks; advice policy 7 carries enums/counts only.
  The public glob advisory is a known source reference, not a new discovery or
  a whole-fixed-source safety result. See the
  [supported scope and validation record](docs/source-filesystem-flow.md).

- Add source-only, data-only `handoff create` and `handoff finish` commands.
  Bind one check/finding and the current source to a complete aggregate of
  scan-time collected UTF-8 strings, preserving a partial AST's original gate.
  Write new private report copies and receipts; finish combines strict report
  comparison with the full after gate, so unchanged high findings still fail.
  Handoff does not scan, create/run argv, invoke a model or apply a patch.
  `not_observed` is not a verified fix; independent controls remain not run.
  See [local source handoff](docs/source-handoff.md).

- Distinguish command, executable, argv and shell-selector roles for all six
  Node child_process execution APIs. Preserve unknown identity/options as
  review candidates or incomplete checks, use high `ast:process-executable`
  candidates for executable selection and critical shell-input candidates,
  and limit default/false argv exclusions to Node's shell interpretation.
  Source ruleset `2026-10-13.2` separates this candidate-meaning change from
  older scopes; report schema and package version are unchanged. Static input
  evidence does not verify runtime types, execution, program-option safety,
  exploitability, fixes or OSS detection efficacy. See `docs/process-role.md`.

- Add an explicit policy v3 `single-quoted` SQL differential profile, with optional paired Authorization/identity declarations and fixed eight/ten-step budgets. Numeric v1/v2 canonical hashes, requests and finding IDs remain unchanged; only validated single-quoted revisions namespace new IDs. CLI plans, same-profile replay, four report formats and advice projection policy 6 preserve scoped candidates and incomplete trailing identity evidence. No automatic SQL context discovery, arbitrary payload corpus, general database coverage or live policy-6 model call is claimed.

- Add opt-in native numeric SQL policy v2 with one selected environment Authorization credential, same-origin identity controls before and after the original eight SQL phases, and default ten shared HTTP attempts. HTTPS is required except explicitly permitted literal owned loopback tests. V1 policy hashes, profile and default eight attempts are unchanged. Failed identity controls remain partial; an already observed probe is retained as a low-confidence candidate without replay authority. CLI/Action offline preflight, fresh-credential replay and current advice projection policy 6 preserve these boundaries without storing credentials or identity values. Owned fixture validation does not establish production authentication or SQL coverage.

- Preserve incomplete API replay as `inconclusive` (exit 2), even when a
  candidate exposure was observed before a later control or request failed.
  A completed replay is required for `reproduced` or `not_reproduced`.
- Require API finding evidence to match the same run's ledger and coherent
  actor/case indexes within its control steps;
  inconsistent or unsupported control claims remain inconclusive. Freeze SDK
  inputs from own data properties before execution, rejecting accessors that
  could change permissions during a run.
- Refuse HTTPS Nuclei before target execution while opaque CONNECT tunnels
  prevent enforcement of the HTTP request budget. HTTP Nuclei remains available
  through the owned loopback egress gate with wire request counting. The CONNECT
  gate also caps tunnel openings, but a tunnel count is not an HTTP request count.
- Run the DAST Action trigger, consent and origin preflight before Python and
  Schemathesis engine preparation. Node.js setup still bootstraps the preflight.
  Retain SideFit regression fixtures already satisfied by this source branch;
  they do not establish a scan result for a live SideFit service.

- Attach in-run control evidence to API authorization exposure findings:
  `controlVerification` (`controls_passed` only when identity before/after,
  owner before/after and a completed probe all pass, otherwise `inconclusive`),
  `evidence` that references the check's own `apiExecution` ledger steps, and
  `replay` inputs (policy digest, case, actor). The report sanitiser drops
  evidence that does not match the ledger and demotes unsupported claims.
  Additive optional fields: report schema stays `1.0.0`, finding IDs, SARIF
  fingerprints, `kind` and the agent report's exploit/fix `verification` are
  unchanged. No added requests during scans.
- Add `replay` CLI and `replayApiFinding` SDK: re-execute only one finding's
  case, owner and probe actor when the policy digest matches. Outcomes are
  `reproduced` (1), `not_reproduced` (0), `inconclusive` or `refused` (2).
  The owned DAST corpus now also gates passed controls on every completed exposure.
- Cap HTTPS CONNECT tunnels through the active DAST egress gate at the request
  budget. A tunnel past the budget is refused with 503 and stops the run as
  `request_limit`, as plain-HTTP requests already did. A CONNECT tunnel can
  carry zero, one, or multiple HTTP requests; its count is not a substitute
  for the request budget. HTTPS Nuclei is therefore refused before execution.
- Provision the checksum-pinned Nuclei engine in `release-check` before the
  required-engine suite, matching `self-test`.
- Evaluate the DAST Action consent, trigger and origin policy in a preflight
  step before any engine setup. Python 3.12 and the Schemathesis virtualenv are
  now prepared only when that policy allows an OpenAPI run; previously a fork
  pull request or an unlisted origin with consent set still downloaded them.
  The main step still records every refusal.
- Add `--allowed-origin ORIGIN` (repeatable, up to 16) to the CLI, matching the
  DAST Action `allowed-origins` input. When set, `--url` and `--api-base` outside
  the list are usage errors before any DNS lookup or request, and an API policy
  whose `baseUrl` is outside it records an `api.authorization` error without
  sending a request. Without the option, behaviour is unchanged.

- Add opt-in two-round verification for the existing owned synthetic API fixtures.
  Preserve every phase report and earlier observations; inconsistent repeats,
  interrupted controls and missing phases remain inconclusive. One shared
  request/body budget and deadline cover all phases. Delivery retry reuses the
  retained redacted reports without replaying requests. This is bounded fixture
  evidence, not statistical reliability or production remediation verification.

- Extend the existing indexed API GET preflight plan with a versioned execution
  ledger: evaluated, inconclusive and never-attempted steps, shared HTTP retry
  accounting, fixed reasons and redacted plan identity. No added requests.
  Align CLI planning with the existing scan time budget; SDK defaults stay unchanged.
- Fail closed on malformed/incompatible ledger metadata while retaining findings
  and report delivery; comparisons require matching complete declared plans.
  Existing reports without a ledger stay readable. Hashes are not attestations.

- Keep authenticated HTTP 401 probes incomplete even when point-in-time identity
  controls pass or later requests recover; retain protected-canary findings.
  Add fixed numeric identity/session failure diagnostics without response values.
- Snapshot API/OpenAPI options from validated own data properties: inherited
  getters cannot enable private networking, and caller mutation cannot rewrite
  effective permissions or cancellation reporting during a run.
- Advance ruleset to `2026-10-06.3` so comparison scopes distinguish the corrected
  authentication adjudication; no request, transport or credential-refresh expansion.

- Add zero-network API/OpenAPI `plan` CLI and SDK preflight with redacted
  indexed diagnostics, ordered GET/control steps and separate logical/transport
  request budgets. Configuration readiness is never a scan or security verdict.
- Reuse bounded descriptor-safe JSON snapshots and runtime credential validation;
  reject invalid header values, accessor credentials and duplicate principal
  expectations before HTTP. Keep cancellation and incomplete outcomes intact.

- Resolve static script/module collection against the first HTML document base,
  decode explicit BOM/header/early-meta encodings, retain partial findings on
  bounded parser failure, and preserve scan reports after SIGINT/SIGTERM.
- Add opt-in exact known-canary matching across bounded JSON value positions,
  retaining actor/owner controls and incomplete outcomes on malformed/over-limit
  responses. Ship owned A/B/admin/two-tenant fixtures with verified cleanup.
- Compile explicit allowlisted OpenAPI GET selections and caller-supplied path
  values into the existing API v2 policy executor. No remote refs, new transport,
  arbitrary payload generation, real staging connection or mutation is added.
- Gate a repeated positive/safe/error loopback corpus and extracted npm consumer;
  report scoped configuration coverage, request counts and elapsed time.
- Ruleset `2026-10-06.2`; this source revision remains separate from the
  published npm 0.4.0 package.
- Replace the URL secret-assignment prefix search with consuming token matching,
  retaining literal detection/redaction while avoiding quadratic failed matches
  on long hyphenated input or whitespace. Add bounded subprocess regression
  guards; URL timeouts still do not preempt arbitrary synchronous parsing.
- Recognize renamed request/response parameters at narrowly bound Express app,
  Router, HTTP route and middleware registrations; preserve MIME safeguards and
  reject unsupported callback, alias, mutation and loader identities.
- Add bounded Express `res.send`/status-chain and explicit HTML Response/NextResponse
  candidates with actionable titles and redacted source-to-sink evidence.
- Resolve receiver-independent methods on audited immutable local class instances;
  keep general class dispatch and Koa input semantics outside this support boundary.
- Expand the inspectable source corpus from 30 to 50 cases. Benchmark schema 2
  makes all-corpus metrics primary, includes known misses in the denominator,
  and retains scoped failure signatures for incomplete or missed cases.
- Track bounded literal Express response MIME so plain text is not mislabeled HTML
  and JSON serialization with a pre-existing HTML type retains a candidate.
- Ship declarations and conditional type exports for strict TypeScript SDK users;
  align report/package versions and expose structured requested-tool selection.
- Accept OSV-Scanner 2.6's omitted empty vulnerabilities field while keeping null,
  invalid types, invalid inventory and contradictory process results fail-closed.
- Ruleset `2026-10-06.1`; no public finding-contract, external worker, network,
  repair or published package-version change.

## 0.4.0 — bounded source and fixture verification release

- Extend bounded JS/TS static flow analysis with interprocedural and selected local-module/object flows, SQL/HTTP/fork argument roles, immutable value qualifiers, parse diagnostics, and explicit analysis budgets/gaps. These are static candidates; runtime exploitability and remediation remain unverified.
- Add `agent-report.json` and first-read report summaries with shared scan gates, evidence positions, incomplete work, report digests, and separate delivery semantics. Findings never authorize executing instructions or uploading source.
- Add a version-pinned Schemathesis worker for owned broken/fixed OpenAPI fixtures, reproducible input replay, process supervision, redaction, and artifact fingerprints. Required-engine tests fail rather than skip when the reviewed Python environment is unavailable.
- Add an owned API resource/state pilot with independent before/after observations, normal controls, cancellation, lineage, and delivery-only retries. This executes only the bundled synthetic scenarios.
- Add an opt-in repair proposal CLI with declared Python/SQLite regression controls in a prepared local Docker image. External agents require explicit source-upload authorization; proposals do not modify the original source.
- Add an explicitly selected Darwin arm64 Opengrep preview using a reviewed binary and original rules. The binary is not bundled or downloaded automatically; native traces remain truncated static evidence.
- Ship compiled CLI/SDK code, fixture workers, examples, notices, and documentation in a filtered npm archive, with a separate source archive and SHA-256 manifest.

See [release scope and verification](docs/release-0.4.0.md). This release does not establish general SAST/DAST completeness, production security, real-world vulnerability accuracy, paid-tool parity, or verified remediation of a user application.

## 0.4.0-dev.1 — local development preview

- Correct PostgreSQL string/comment and quoted-identifier handling; add bounded migration-history RLS candidates and static client/env secret propagation.
- Extend JS/TS input flows and Python pinned requirements coverage; tighten Bandit output validation.
- Evaluate CSP nonce/hash/fallback/multiple-policy semantics; collect explicit additional pages and bounded same-origin static JavaScript modules.
- Add API policy v2 with actor identity controls before/after execution and separate resource/protected-data assertions. Legacy v1 remains partial.
- Add logical project identity, semantic comparison anchors, engine provenance and explicit ambiguous/unknown comparisons.
- Add doctor/init onboarding, a prebuilt Action bundle, verified native archive caching, Job Summary/status outputs and failure artifacts.

See `docs/preview-0.4.md` and `docs/verification-0.4.md` for the implemented boundaries and execution evidence. Packages remain local; no public upload is performed.

## 0.3.0-dev.1 — local development preview

- Add optional Bandit Python AST analysis with bounded staging, explicit tool selection, safe rule guidance, and incomplete-file accounting.
- Add bounded Next client secret and Supabase migration candidates, with public-key and normal-framework negative cases.
- Extend passive URL observations for CORS, source maps, debug candidates and explicit component versions; version clues are not CVE verdicts.
- Add user-authored GET-only API ownership policies with positive owner controls, denied actors, environment credentials, strict scope and response limits.
- Add stable JSON finding identifiers and report comparison. Missing results in incomplete or mismatched scans remain unverified.
- Extend CLI and vendored Action inputs and document the research, session requirements, runnable examples and remaining limits.

See `docs/preview-0.3.md` and `docs/verification-0.3.md`. No public upload or production-readiness claim is made.

## 0.2.0-dev.1 — local development preview

- Extend JS/TS input candidates to bounded same-function aliases, destructuring, assignments, and conservative branch handling. Cross-function and cross-file flow remain unsupported.
- Add an inspectable synthetic vulnerable/fixed corpus and a benchmark runner that preserves known misses and supports comparing trusted engine builds.
- Show scope, finding counts, incomplete checks, threshold outcome, and report locations in the CLI terminal output.
- Add filtered npm/source release packaging, versioned SHA-256 manifests, contributor guidance, and a release-check workflow. No public registry or GitHub release is created.
- Document the OSS roadmap for Next.js/React/Supabase, Node/Python, and API/authorization testing. Planned features are not included in the implemented coverage claim.

See `docs/oss-next-verification.md` for verification and limits. This version is not a production-readiness or detection-accuracy claim.

## 0.1.0 — local initial package

- Separate the source/URL CLI and local GitHub Action from the Wakeio service.
- Integrate bounded collection, JS/TS candidates, Gitleaks, OSV-Scanner, and Trivy configuration checks.
- Produce JSON, SARIF 2.1.0, and Markdown with explicit scope and incomplete execution states.

The original local artifacts and `docs/verification.md` retain the v0.1 verification record.
