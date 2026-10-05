# CI required-engine verification (2026-10-05)

## Current source-budget increment — scoped acceptance, 2026-10-05 06:20 KST

Ruleset `2026-10-05.3` shares bounded AST indexing metadata and separates index
work 300k / flow work 200k / aggregate nodeVisits 500k. The defaults were adopted before
new measurements. Legacy nodeVisits overrides remain aggregate caps. Partial
indexing disables immutable callee/native destination proof and preserves known
potential roots; partial summaries are not cached as complete evidence. Parsing,
index completion, root inventory and flow task counters are separate. Parser/
binder, finding observation and rendering are outside charged work; this is not
hard CPU/RSS isolation. See [current support contract](source-flow.md).

The required local suite passed **239/239, zero failed/skipped/cancelled/todo,
exit 0**, including both mandatory real Schemathesis tests. This is URL 232 plus
seven budget regressions; focused 72 is a subset. Source before/after and rebuilt
bundle matched. The unchanged strict 30-case synthetic corpus found 15/15 supported
expectations, FP 0/FN 0. Packed CLI passed: risky one candidate/exit 1, fixed zero/
exit 0. Existing local dependencies were reused, with no fresh installation or
publication claim.

Developmental generic measurement passed 33 valid trials (11 cohorts x 3 repeats).
Structured M forward/reverse each completed 200 files/957862bytes/124378 AST/
1220 functions with exact 10 candidates, index 175030 / flow 98751, 957-993ms. The first
subagent 33 trials had ps EPERM/unassessed RSS and remain operationally invalid;
they are not combined with the lead's valid replay 33. Repeats are performance
units, not unique accuracy cases. Index/function/alias/summary stress partials
retain exit 2 even under fail-on none. Independent budget QA passed 36 valid trials
with zero semantic/metrics/resource/operational failures; the former medium 12
partial/zero-candidate trials now complete, with risky 12 candidates and fixed/
normal zero. Reviewer 8 boundary trials passed separately.

SDK reduced-cap API probes passed 4 separate-child trials: indexWork=1 and
flowWork=1, each with high/none, validating individual limits and incomplete
gates. They reuse the original QA source and add zero unique accuracy cases.
The existing URL 71 replay passed; two explicit unknown
URL trials remain unknown, not safe negatives. The fixed real 211-file OSS rerun
completed indexing (index 170775, flow 120595, summary 145, resolved 356), but remains
partial/module_missing,exit 2,seven candidates (1741ms; roots 1080 started,
1052 completed, 28 partial). These are seven of the original 11 unreviewed
candidates, with no new candidates. The original two source-only FP candidates
were not observed, but suppression 0 does not demonstrate an FP fix. The lead accepted the scoped common index, phase budgets, partial-proof and
counter contract after independent review and receipt/hash comparison.
Prior SOURCE-003 partial and SOURCE-002 13 candidates
(source-only FP 2/unreviewed 11/confirmed 0) remain historical evidence. No real
field clean scan, false-positive elimination, runtime TP, paid parity or overall
goal completion is claimed.
The next step is W06 pinned maintained-engine comparison, licensing and quality
evaluation, not arbitrary AST expansion or scope/cap tuning against real results.
Wider SAST/DAST, E05-E07, fresh installation, hosted
CI, publication, validated remediation and disclosure/contribution remain pending.
No commit, push, target-repository remediation patch, disclosure or contribution was performed.

Frozen source SHA-256: `7e59521b720e4b1579a02e7073770435cb54feeee916ac2873bddcf7971c0f7a`.
Action bundle: `ef017140f07fee3c44d3898eb4ba417ef9659d3081a80d35a1d981957b8933e4`.
Build/src tree: `c34871dc734d331a04cbbba26d3f97846faa74f44ac1f66375c927d976a1b19d`.
Support: `4cf73b63ded78ff3b14ddd8097718210c74e908b73d2916b28c97c9de17837c5`.
Receipts are retained externally under the research workspace's
`evidence/source-budget-v1/`, including required-engine/required-engine-4zB8WU/
receipt.json. Lead acceptance is source-budget-v1/lead-acceptance.json
(SHA-256 836546a5a70f8c57fbdd4deeb6c6d73f05b9926d22d6199151a31754c04b6986).
Independent final documents are source-budget-review/FINAL-REVIEW.md,
source-budget-review/f01-source-004/RESULT.md and source-budget-qa/FINAL-RESULT.md.
Historical sections below preserve their dates/counts/hashes;
statements about then-current limitations apply only to those earlier revisions.

## Preserved URL revision 4 — 2026-10-05 05:50 KST

The required local suite passed **232/232, zero failed/skipped/cancelled/todo,
exit 0**, including both mandatory real Schemathesis tests. This is the prior
214 plus 18 URL test groups; the 69 focused tests are a subset. Preflight/build/
tests exited 0 with confirmed close/cleanup and unchanged source before/after.
Packed CLI consumption passed: risky one candidate/exit 1, fixed zero/exit 0,
with cleanup and unchanged source/build. The lead accepted this declared scope after reviewer field/package checks and
independent receipt/input-hash comparison; the overall goal remains active.
The indexing bug is not fixed.

Ruleset `2026-10-05.2` adds a bounded outbound initial-destination qualifier for
canonical literal HTTP(S) origin/path plus native encoded query. It retains the
input taint for other sinks, preserves direct query-alias content independently
of qualification, snapshots serialized scalars, and keeps opaque content unknown.
Native shadow/escape/prototype and opaque options remain conservative. See the
frozen [support contract](source-flow.md); this is not runtime SSRF safety proof.

The same QA matrix passed 71 known-case trials and reviewer failure replays six.
Two QA trials are explicit unsupported/unknown zero-candidate outcomes, not safe
true negatives. Previous v1 support failures/unknown timeout, v2 alias misses,
and v3 opaque-content miss remain preserved; replays add no unique accuracy cases.
The unchanged strict 30-case corpus remains 15/15 supported expectations, FP/FN0.

The same 211-file, 1,037,216-byte OSS snapshot remained **AST partial/node_limit,
exit 2, zero candidates** (1,021ms, 200k work, 1,150 indexed functions; summary,
resolved calls and destination suppression all zero). This does not demonstrate
real false-positive elimination, a clean scan or absence of vulnerabilities.
Shared-index/phase-budget design and maintained-engine evaluation are follow-up
work, not implemented by this URL increment. Fresh installation, hosted CI,
publication, wider SAST/DAST and worker E05–E07 remain unverified/incomplete.

Frozen source SHA-256:
`75a648d58b3e337865502826c78893b836b958a7df97146ae5bb1f80db267817`
(79 files, 976,982 bytes). Action bundle:
`c036d4ac0927ee8fbcd9db9c0a768ec940ac732d4241992da3e77768026731ae`.
Support contract:
`d9310131b9d7dd3c52a5fb2c4e10b4ba7a0b859083d50e7e9b135d7206314252`.
Detailed receipts are retained in the external research workspace under
`evidence/url-destination-v4/`. The lead acceptance receipt is `evidence/url-destination-v4/lead-acceptance.json`
(SHA-256 `30a6ca54c6b1cbd8a5f043a70b32d4a79f51e2b75c34ed577c74c6c7a0249826`).
Historical results below retain their original
counts/hashes and completion scope.


## Preserved SAST revision 2 — 2026-10-05 05:09 KST

Revision 2 passed the required local suite: **214 passed, zero failed/skipped/
cancelled/todo, exit 0**, including both mandatory real Schemathesis tests.
Preflight/build/tests each exited 0 with reason null and confirmed close/owned
process-group cleanup. Source SHA-256 before/after was
`da92c95cfcf2808d90dbd5108b7ec8cd3943b57d7da2817b528648e7eb88e745`
(77 files, 946,369 bytes). The 51 focused tests are a subset of the 214.

The R03 correction invalidates stale safe function summaries after actual
array/object/rest/default/for-in/of binding writes; property keys and default
expression reads remain safe controls. It preserves the existing declared
model, caps, `RULESET_VERSION=2026-10-05.1` and frozen [support contract](source-flow.md).
The current Action bundle SHA-256 is
`b6cc689b5fb0383fe56e15ddd5dd500351ab717e3bebea8ed97639d6cd3e5feb`.
Revision 1's later source-only destructuring counterexample produced zero
candidates / exit 0 and failed its oracle; the unchanged-safe control passed.
Revision 2 remeasurement preserves one low-confidence/truncated candidate /
exit 1 for the mutated binding, and zero / exit 0 for the safe control.
Previous 210-test and independent results below remain historical measurements.

The same independent current oracle accepted 22 case IDs / 36 valid trials;
module-binding accepted 9 trials, the added R03 pair 2 trials, and the same-process
SDK probe 6 rounds in one PID. These are reused acceptance units, not new
independent accuracy samples or a statistical blind holdout. Revision 1's
post-freeze SDK result exposure remains a limitation of future reuse.
The unchanged 30-case strict corpus still found 15/15 supported expectations,
FP 0 and FN 0. Static traces remain candidates with runtime verification not run.

Packed npm CLI remeasurement passed: risky source one candidate / exit 1,
fixed source zero / exit 0. Source archive scoped hash matched current source;
whole packed build and build before/after matched, temporary consumer removal
and command cleanup were confirmed, and no new dependencies were installed.
This is local package-consumption evidence, not fresh dependency installation,
hosted CI, publication or runtime vulnerability confirmation. Fixed-origin
encoded-query outbound precision, wider SAST/DAST and worker E05–E07 remain
follow-up work. The lead accepted this scoped increment; the overall goal remains
active. Detailed current receipts are retained externally under the research
workspace's `evidence/sast-summary-v2/`.

## Shared CI and preserved earlier verification

Both self-test and release-check now request Python **3.12.13** and invoke the same
explicit bootstrap and required-suite wrapper. The setup-python action is pinned
to a full commit confirmed in its official repository:
https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065

`bootstrap-schemathesis.mjs` is an explicit CI installer, not called by scan or the
test wrapper. It reuses all 53 exact versions in requirements.lock.txt and uses
binary distributions only, bounded pip retries and a 180-second install deadline.
The lock is **version-pinned, not distribution-hash-locked**. A lock SHA-256 is
input provenance; it does not authenticate installed wheel bytes. No new install
or hosted GitHub Actions run was performed during this local verification.

`npm run test:schemathesis` uses the existing environment. It checks every lock
entry against installed package metadata and Python 3.12, builds the package,
cleans only the declared generated build directory after rejecting a symlink,
and runs exactly the compiled mappings of current tests/*.test.ts sources.
Missing required original source fails even when stale compiled JS exists. Stage deadlines are preflight 10 seconds, build
120 seconds and tests 180 seconds, with bounded cleanup/settlement grace.
Missing/wrong engine or dependency versions fail with exit 2, never skip.
A normal test failure remains exit 1; timeout, cancellation, output limit,
malformed/absent receipt, source drift or unknown cleanup returns exit 2.

A custom Node reporter emits projected test pass/fail/global-summary events.
The verifier requires zero failed/skipped/cancelled/todo tests, consistent counts,
and exactly one passing event in the intended Schemathesis file for each required
real-engine test. Test stdout that prints a forged test name or counts is ignored.
This relies on reviewed test/runner code and test assertions; it is not an
attestation that untrusted PR code or an arbitrary worker is honest.

Each run writes a unique private directory below artifacts/ci (override with
WAKEIO_TEST_RECEIPT_DIR), containing stage logs, tests.ndjson and receipt.json.
Receipt fields include input source hash before/after, explicit snapshot scope,
compiled test-file hashes, lock hash, installed versions, command exit/signal,
completion/cleanup, actual counts and required passes. The same filesystem walk
works with or without .git and with deleted tracked files. Input roots and nested input symlinks are unsupported and fail closed. Root
generated build/artifacts are outside the scope; nested src/build or src/artifacts
remain source inputs. Only declared runtime/cache directory names are excluded; caps are 10,000 files,
32 MiB per regular file and 128 MiB total snapshot content. This is source input
integrity, not security correctness or anonymization.

`cleanupScope=command_process_group` means only the command's owned POSIX group.
Timeout/cancel/output overflow has an independent settlement deadline even if
signal delivery fails. Pipe destruction/unref permits bounded return; it never
means termination succeeded. Cleanup requires close confirmation and no live
owned group members; unreaped zombies are recorded distinctly. EPERM is not
interpreted as ESRCH: exact group membership is checked with ps. Escaped setsid
children, separately detached groups/containers created by tests, parent SIGKILL
and hostile-code isolation remain outside this helper's guarantee.

Dedicated contracts run with `node --test scripts/ci-verification.test.mjs` without
building shared outputs. They cover fake stdout/summary contradictions,
missing/wrong test identity, native reporter events, missing command/nonzero,
timeout/output cap, deliberate signal failure, owned child cleanup on timeout and
normal exit, Git-free/current-filesystem snapshots, deleted required source with stale JS,
generated-build symlink safety, and input root/TS/worker symlink rejection.

Release upload now declares and verifies only the current version's exact source
archive, npm archive and SHA256SUMS paths. It does not upload artifacts/ wholesale;
private replay, patch, field reports and CI logs remain outside that upload.
The source archive includes the CI scripts but excludes artifacts/runtime state.

Local baseline: HEAD dad74a0650df74864ddc7204cd6126a7f45aa04a with pre-existing dirty
changes; npm test and the previous required wrapper both passed 174 tests, zero
skips. Existing Node 22.22.1 / Python 3.12.13 / Schemathesis 4.2.0 were used, and
all 53 installed versions matched the version-pin lock. Baseline, failed focused
attempts and subsequent integration evidence are kept separately in the calling
research workspace, not embedded as release artifacts.

## Preserved pre-expansion baseline integration

The pre-expansion frozen-source local integration passed **189 tests, zero failed/skipped/
cancelled/todo**, including both mandatory real-engine tests. The increase from
174 consists of six worker protocol regressions and nine agent-report/Action
checks. Protocol checks reject contradictory status/reason/checks, duplicate
failures, incomplete completed replays and changed manifests/input fingerprints;
retry checks distinguish engine re-execution from retained-artifact delivery.
Agent checks exercise CLI vulnerable/fixed/normal and partial-none gates, missing
source, deterministic sanitized evidence IDs/digests, redaction, delivery errors,
collector exclusions, and actual bundled Action output, stale output and a fresh
JSON/wrong-agent-digest rejection. These are scoped local contract checks, not a
claim of broader vulnerability coverage. Dedicated CI helper tests passed 9/9.

The final required-suite receipt recorded source SHA-256
`0b9a193fc8c546ab6a67971f62fb07797bf8c3def8da923c64c899036fe71f7b`
before and after (75 scoped files); all stages confirmed owned-group cleanup.
Strict benchmark passed 30 synthetic JS/TS cases: 13 supported expected findings
found, zero false positives, and two known unsupported cross-function/cross-file
misses retained in the full denominator (13/15). This is a small scoped regression
result, not a production accuracy estimate. Local source/npm archives and exact
checksums were generated. Archive delivery verification uses existing local
Node/Python dependencies; fresh dependency installation and hosted CI remain
unverified. Final package checks and detailed receipts are retained externally in
`wakeio/docs/research/wakeio-dast-quality-2026-10-05/evidence/ci-integration/`.

## Preserved revision 1 — local integration (2026-10-05)

The 189-test/`0b9a193...`/13-of-15 results above are the preserved pre-expansion
baseline. The current scoped revision extends the existing AST model with
argument-specific local function and snapshot-only relative-module summaries;
see the frozen [support and cap contract](source-flow.md). It supports named
relative ESM and static const CommonJS destructuring within the declared model.
Observed source/call/parameter/return/sink positions pass through sanitized JSON,
SARIF, Markdown and agent reports. They remain static candidates, with runtime
verification `not_run` and remediation `not_verified`.

The final required-suite run completed **210 passed, zero failed/skipped/
cancelled/todo**, exit 0, including both required real Schemathesis tests.
Preflight/build/tests all exited 0 with reason null and close/owned-group cleanup
confirmed. Source SHA-256 before/after was
`266522ab5cc9ad8cd75ead8622a46ac18812031f5673fed0d6b3bb865bb5bf13`
(77 scoped files, 940,873 bytes). The increase from 189 is 21 new interprocedural
development tests; the 47 focused tests are a subset of these 210, not an extra
security sample. The dedicated helper 9/9 result above remains prior evidence;
it was not rerun for this revision.

Corpus `2026-10-05.synthetic-js-ts.v2` keeps the original 30 fixture sources,
case IDs and expected sink locations. It promotes the two historical local/
relative-module SQL misses from `known_miss` to `supported`, changing the
supported expected denominator from 13 to 15; future misses in either case fail
strict mode. Current strict regression measurement found 15/15 expected findings,
FP 0 and FN 0. Historical baseline labels/results are not rewritten. This small
synthetic measurement is not real-project recall, runtime TP or paid parity.
The initial empty-engine metric assertion failed as 15 versus historical 13;
the assertion was updated for the new denominator, and its failure excerpt is
preserved separately from the final 47/47 log.

Separate independent checks accepted 22 case IDs / 36 valid CLI trials and
8 module-binding development cases / 9 trials; a same-process SDK probe accepted
6 rounds in one PID. These are distinct model/contract acceptance units, not
independent vulnerabilities or a statistically blind holdout. Ordinary external
calls stay explicit model limitations; failure to complete declared relative
resolution or capped supported analysis makes the scan incomplete, including
under `--fail-on none`. Fixed-origin encoded-query outbound URL precision remains
a follow-up. Parser/binder internals are not hard CPU-bounded by AST work counters.

Packed CLI smoke passed using the locally generated npm archive: risky source
produced one candidate / exit 1, fixed source zero / exit 0; both measurements
were valid, temporary consumer cleanup was confirmed, and source/build hashes
were unchanged. Package checks confirmed scripts/devDependencies removed.
Existing local TypeScript dependency bytes were reused without a new install;
their full authenticity was not attested. The smoke adds no unique accuracy
cases and runs no target source. Fresh dependency installation, hosted
GitHub Actions, package publication and new-runtime OSS reproduction remain
unverified. This revision does not complete broader SAST/DAST work or worker
E05–E07. Final receipts are retained externally in the research workspace's
`evidence/sast-summary-v1/` and independent model-validation directories.
