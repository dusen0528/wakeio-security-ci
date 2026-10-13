# Independent collected-code coverage acceptance

2026-10-13. Root-supplied baseline main `25ade095…`. Root independently
reproduced Python-only gate2 and mixed Python/benign JavaScript gate0 in
`artifacts/code-coverage-2026-10-13/baseline-reproduction.json`. This author
read code and froze expectations before producer execution. Root alone runs
builds, tests, scanners, installed consumers and the Action. Target fixture
source is data, never imported or executed.

## Truth and scope

The denominator is every actually collected `category=code` input, classified
by the collector's fixed extensions. It is not repository files, executable
paths, attack surfaces, findings, or possible vulnerabilities. Ignored/generated
paths and files excluded by collection are outside this denominator; collection
completeness is separately required by the strict policy. A completed provider
means its declared bounded input scan completed, not semantic completeness,
runtime reachability, exploit confirmation or whole-project safety.

Fixed language order: javascript, typescript, python, c, cpp, csharp, go, java,
kotlin, php, ruby, rust, shell, swift, vue. Root finalized **nonzero collected
rows only**, in this order; empty snapshot has no rows. Each row contains all
three providers in order builtin_ast, bandit, opengrep_native. Only builtin
JS/TS AST, selected Python Bandit and explicitly selected JS/TS/Python native
can contribute. Gitleaks, OSV, Trivy and framework completion cannot substitute.

`CodeCoverage` v1: basis collected_code_inputs; requireCodeAnalysis boolean;
collectionComplete boolean; accounting exact|unknown; languages and totals
with collected/eligible/completed/uncovered counts. A provider row contains
provider, selected, status and eligible/completed. Eligible is the selected
input union, not a submission receipt. Completed requires the adapter's actual
validated accepted input set and complete result; notes or arbitrary metrics
cannot certify it. A partial adapter conservatively contributes zero completed
inputs. Totals and per-language union are not sums across overlapping providers.
Unknown accounting uses null rather than invented zero. Uncovered equals
collected minus completed for exact accounting.

The always-present `source.code-coverage` informational check is excluded from
security-check applicability together with inventory. `source.inventory`
codeFilesSelected records actual collected code count and must agree with the
denominator. Invalid present new evidence is incomplete under either policy.
Report-only defaults preserve existing advisory-only/selected-check intent.
Strict scope binds codeAnalysisPolicy {revision: code-coverage-v1,
requireCodeAnalysis: true}; missing check/evidence cannot erase that requirement.
Zero code, uncovered inputs, incomplete collection and unknown evidence are2,
including failOn none. Readable legacy report-only absence is not a strict pass.
An intact strict typed SDK check can adjudicate without ScanScope; scope is not
an invented SDK prerequisite. Entire-check deletion from a scope-less external
legacy report loses its original intent, which cannot be inferred. CLI always
binds policy in scope, so its missing proof remains incomplete. Schema and
cross-check validation cannot authenticate an external report whose author
coherently forges every check, metric, coverage and scope together; these records
are declared scanner evidence, not an authenticated execution receipt.

Public flags: SDK requireCodeAnalysis boolean; scan/doctor/init bare
--require-code-analysis; Action exact true|false input. Reject source-less flag,
duplicates and non-boolean SDK values. Doctor inventory remains metadata
estimate, not collector coverage. Preserve policy in nextCommand and generated
init workflow; never install/select an engine implicitly. Different policy
identity cannot certify a fix through report comparison.

## Independent owned inputs and six groups

1. Held-out Python P is `import subprocess` followed by a route calling
   subprocess.run(request.args['command'], shell=True). P alone has exactly one
   collected code input. Add unrelated `boot.js` containing only an exported
   boolean: exactly two inputs, JavaScript1/Python1. Python remains uncovered1
   in both. Historical tools-none gates remain Python-only2/mixed0; strict2
   for both. Adding unrelated code cannot discharge an unselected language.
2. A same-denominator JS/TS raw-SQL risky/fixed pair remains high finding1
   versus0 under strict policy; complete code-input admission does not erase
   findings, and a fixed candidate does not establish production safety. A
   strict CLI risk→handoff→fixed recheck preserves source policy and the original
   report bytes while accepting the new informational fourth check.
3. Mixed JS plus two Python files with a privately owned fake Bandit child
   exercise formatter/input admission: complete per-file metrics discharge
   both; one omitted metric, reported file error or missing executable yields
   incomplete2. Captured actual argv prove the supplied Python input set.
   These are protocol controls, not real Bandit efficacy. Native refusal is
   incomplete and cannot complete Python; actual native positive/coverage-set
   validation remains root-owned real-engine integration evidence.
4. Add Vue and Java: JavaScript1/Python1/Java1/Vue1, total4. Vue/Java unsupported,
   Python supported but unselected. Secret/advisory/framework completion cannot
   cover them. Valid OSV-only pinned Python default gate0 remains supported.
5. Public SDK/report trust boundaries: strict missing/duplicate/wrong-check,
   unknown enums, inconsistent or negative counts, forged note/metric completion,
   unknown or partial collection and zero code must not pass. Malformed present
   report-only proof is2. Reject accessors/proxies without invoking them; unknown
   source/body/path metadata must be redacted. Four public formats agree.
6. Doctor→scan and init→Action preserve explicit policy. Actual CLI and bundled
   Action discriminate strict mixed2 and strict JS0; default mixed remains0.
   Scope/compare, summary, advice and four-format evidence share the same counts;
   unknown legacy proof cannot establish strict success. Report enums never
   authorize model, source upload, package install or target execution.

No detector expansion, external corpus, arbitrary target, model call, upstream
reuse, file-semantic completeness percentage, onboarding redesign or automatic
provider installation belongs in this slice. This change makes missing input
analysis visible and enforceable; diverse real vulnerability efficacy and
authorized user-app integration remain separate completion requirements.

## First independent lock

The six groups in `tests/code-coverage-independent.test.ts` use only existing
public source/report/CLI/doctor/init/compare APIs and the existing advice
projection. No new producer helper is imported. Typed strict SDK evidence is
tested with and without scope; deleted proof is fail-closed only where retained
scope carries intent. Fake Bandit/OSV children are owned protocol controls with
the Bandit argv observed independently, not a real-engine efficacy claim. The
actual Action entry executes the bundled CLI rather than a relabeled CLI-only
check. Root owns all executions and immutable baseline/current logs.

Before any test execution, root authorized the additive advice policy bump:
the existing projectionVersion/policyVersion pins in agent-advice.test.ts were
changed7→8; all behavior assertions are unchanged. This is a contract revision,
not an outcome-driven weakening.

First test SHA256 submitted for lock:
`4a7d09ceaecfc20a80833be62d6cab22a3191074c4d09c4c580d80cb0941bdb8`.
No author build/test/scan/target/model execution or Git operation occurred.

Before first test execution, root's initial compile encountered producer
TS2571 in the coverage parser; this is a compile failure, not a measured test
outcome. Root authorized an additional group5 inherited-policy boundary:
prototype-provided requireCodeAnalysis true or false must return source.options
error/2 rather than silently erase policy. The existing first lock remains in
the audit record, and all previous six-group expectations are unchanged.
Second test SHA256 submitted for lock:
`eeb3bb67fd0ef43bafe774f3cece987f7424e1e8b1c0ca75914d698c90f11c17`.

Root preserved focused.log: the focused64 run yielded63 passing and one failure
in group6. Compiled line312 (source line255) compared the agent's safe
null-prototype JSON snapshot with the plain runtime coverage object. The exact
field/value data matched; the prototype identity was not part of the public
JSON contract. Root authorized normalizing this one assertion through JSON
serialization/parsing on both sides. No field is dropped and all remaining
gate, path, source counts and consumer checks stay unchanged. This is a test
comparison bug, not a measured product coverage failure.
Third test SHA256 submitted for lock:
`df54af7d912187e1288718ab55b9aabe9de784d69f2a950602f3213cac858cde`.

Before the next execution root authorized the same JSON-semantic normalization
for all three related summary/agent/advice coverage equality assertions, avoiding
sequential prototype-only failures. Every field/value still participates.

Separately, Standards/root reproduced a real SDK policy defect in
`callable-sdk-reproduction.json`: a function carrying own root/tools/strict true
properties returned gate0 with required=false. Group5 now requires this callable
options object to produce source.options error/gate2 and never invoke the
function. This regression is distinct from the prototype comparison test bug;
it does not weaken any prior expected outcome. The first three lock hashes and
root logs remain preserved. No author execution occurred.
Fourth test SHA256 submitted for lock:
`5ccad0f44f0fc2ca81194a25df2f21377b9d768efa95c4561d088f20509c192c`.

Root's full initial1030 run had1029 pass and one existing interprocedural test
prototype-equality failure. Producer normalized validated coverage parser
returns with structuredClone after all input/schema checks; no existing test
was weakened. Root's ensuing required snapshot completed1030/1030 with zero
skips, receipt required-engine-XllBHj. That successful snapshot precedes the
following newly discovered malformed-status boundary and does not prove it.

Final read-only Spec review found String(provider.status) on a selected provider
JSON object could throw after snapshotJsonData created a safe null-prototype
record. Root independently reproduced it in status-enum-reproduction.json.
After the snapshot completed, root authorized adding object, array, null and
numeric provider status mutations to group5. Each must render without throwing,
with partial JSON status, agent/evaluate gate2, Markdown incomplete2 and SARIF
executionSuccessful=false. All old outcomes remain. Producer's string-enum
fix and root rerun are pending at this lock; no author execution occurred.
Fifth test SHA256 submitted for lock:
`88eae3e6ae0704cef8d2335adf294315a647bc52bc5e18ed4c7a69b87a2035f8`.
