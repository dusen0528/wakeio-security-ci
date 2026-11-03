# T3 self-review and fault evidence

## Scope and architecture

One executable QA-driver story. Only scripts/qa/, tests/roadmap-qa.test.ts and
owned .omo evidence changed. No delegates, sibling imports/copies, product
implementation, source/package/lock/docs edits or full-suite rerun.

Responsibilities: roadmap.mjs owns CLI dispatch and evidence qualification;
harness.mjs owns the real Node/HTTP fixture; process.mjs owns bounded child
supervision; artifacts.mjs owns safe artifact serialization; the test file owns
the QA boundary. All source files are below 200 pure LOC.

The boundary parses argv once, restricts case/mutation names, uses literal
imports, exclusively creates fresh output, rejects symlink ancestors, checks
regular artifact files and hashes their redacted bytes. No unsafe plugin path.
Closed captures are redacted by the repository's canonical implementation.
Capped captures are discarded because incomplete PEM delimiters are unsafe.
Artifacts include actual exit/signal, real HTTP capture, source SHA and digests.
The caller must use the repository's pinned Node 22.23.1 (native TS stripping).

Post-write gate: single responsibility yes; boundary parsing yes; no tagged
domain variants introduced (fixed status strings map directly to process exits);
no any/assertion/non-null/suppression escape hatches added; no unnecessary
defensive layer; nontrivial helpers have a named boundary or multiple consumers;
tests protect real behavior; no parameter bloat; teardown trusts successful rm
and independently probes owned PID/port receipts; positive names; no product
logger or new logging framework. CLI messages contain fixed safe event fields.

## Mutation proof

All mutations were applied to real owners with apply_patch, executed under real
Node, and restored before final-source checks. Receipts retain actual TAP output:

- mutant-child-success.json: removed actual child protocol/exit assertions.
  Exactly truncated-output and child-fail tests failed, 13 passed / 2 failed.
- mutant-input-ownership.json: weakened duplicate argv and symlink-ancestor
  refusal. Exactly malformed-argv and foreign-ownership tests failed,
  13 passed / 2 failed.
- mutant-capture-boundaries.json: removed pre-abort fast path and capture
  redaction. Exactly split-write redaction and zero-start pre-abort tests failed,
  13 passed / 2 failed.
- mutant-http-exits.json: changed actual HTTP body to value 43 and mapped
  unavailable to exit 0. Real HTTP-value test and every affected unavailable
  scenario test failed. No fabricated response or injected successful result.

Final tests additionally check exact owned-child/artifact counts and independent
negative PID absence. Missing policy/manifest tests check module availability,
so later integration of real modules does not pin permanent unavailability.

## Tool limitation investigation

The optional skill style auditor exited 2. Competing hypotheses:

1. Missing repository TypeScript dependency: rejected. npm ci installed the
   pinned dependency and npm run build ran its compiler successfully.
2. Wrong working directory/resolution: rejected. The error names this exact
   task worktree; command captures contain the expected invocation.
3. Incompatible auditor API: confirmed. Its loadTypescriptFromCaller requires
   typescript/unstable/async and typescript/unstable/ast (TypeScript 7);
   package.json pins TypeScript 5.9.3. Do not upgrade project dependencies for
   an optional external auditor.

No source diagnostics were suppressed. Repository compiler/build and Node syntax
checks provide applicable verification. LSP executables are not installed;
none was installed or added to package files. The separate junk-test auditor
passed with no findings.

The intermediate final/ build exposed TS18046 in a new negative test: closure
capture lost narrowing of the unknown cleanup.children property. Competing
causes were missing dependencies (rejected by earlier successful build), product
source drift (no product diff), and callback narrowing loss (confirmed by exact
diagnostic at tests/roadmap-qa.test.ts:103). The test now captures the narrowed
array in a const before the callback, without a cast or suppression.
The verification wrapper initially continued after this failed build, so its
final/ test results are explicitly stale and do not qualify that source.
The wrapper now stops on build failure. verified/ is the qualifying final run.

## Triggered risk classes

| Class | Actual proof |
| --- | --- |
| Malformed inputs | duplicate/odd/unknown/missing/path-valued argv refused before evidence; command-malformed.json exit 2 |
| Generated/stale outputs | rerun against successful output exits 2 without rewriting receipt; stale green fixture preserved; dist-action diff empty |
| Cancel/abort/handler exceptions | readiness-triggered child-abort and handler-error exit 2; external SIGTERM test exits 2 with cleaned child and socket |
| Dirty ownership | existing files and symlink ancestors refused; outside fixture remains empty; only fresh owned outputs written |
| Long-child bounded cancellation | real SIGTERM-ignoring child hits declared timeout, group SIGKILL, close and PID absence; command-long-child.json |
| Misleading success/incomplete evidence | nonzero child and truncated JSON exit 1; cap and incomplete cleanup exit 2; real owner mutations fail tests |
| Test nondeterminism/concurrency | event subscriptions before readiness/signals, no fixed sleeps/retries; three concurrent real cases use distinct ephemeral ports and output roots |
| Credential/capture boundary | unchanged report redaction tests, real split writes, capped private-key fragment discarded, artifacts sanitized before persistence |
| Dependency/build/cache/resource hygiene | no dependency changes; initial node_modules/build absent; owned cache roots exported per command; teardown.json records PID/port probes and removal |

N/A: Docker networks/volumes/images, browser contexts, databases, migrations,
external providers and published release identity. T3 creates none of these
resources and implements no scanner/Oracle. They remain downstream QA cases,
not inferred successes.
