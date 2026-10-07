# Changelog

## Unreleased

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
- Ruleset `2026-10-06.2`; the npm version remains 0.4.0 pending a separate release.
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
