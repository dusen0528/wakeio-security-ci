# Independent owned API write acceptance contract

Date: 2026-10-13. Parent-supplied baseline: main `54ecc43`, branch
`feat/api-write-state`; parent froze the compiled baseline separately in
`artifacts/api-write-2026-10-13/baseline-build`. This contract is authored before
producer implementation/output. Only source/document reads and this acceptance
document/private oracle data are authorized now. No test code until the public
contract is agreed; no build, scan, target execution, install, model call, or Git
operation by this author. Root alone coordinates the public contract and runs
later verification.

## Missing behavior and existing contracts

The highest-value bounded next behavior is **an authenticated peer PATCH that
changes the owner's persisted title, distinguished from successful normal owner
write and from response-only claims**. Existing functionality is not absent:
API v2 has principal/organization identity, owner before/after and protected
canary read controls; native SQL has auth, numeric/quoted profiles and scoped
replay; the owned state pilot independently checks actual stored normal contents
and read exposure, repeats phases, and separates delivery retry from execution.

The write behavior is still missing. `src/api.ts:57` declares GET-only;
`src/url-network.ts:460` fixes transport method to GET. `src/api-state.ts:148`
rejects other methods, and lines 165–166 require state bytes to remain unchanged.
`src/api-state-observer.ts:14–26` requires original fixed titles/contents;
lines 74–83 compare read bytes and protected-data exposure. These checks cannot
adjudicate a legitimate title change or a rejected response that nevertheless
mutates state. `src/api-execution.ts` only accepts the GET identity/owner/deny
plan, and `ApiRequestPlanStep.method` is GET. Do not retrofit PATCH into that
ledger or silently turn read-policy permission into mutation permission.

Reuse the owned private-store and pinned-handler lifecycle, identity preparation,
bounded transport/capture ideas, report/gate and retained redacted-byte delivery.
Implement a **separate ApiWrite evidence v1** with its own ordered HTTP/local
observations. The current read observer must not validate changed titles by
merely relaxing its original-state comparisons.

`CONTRIBUTING.md` requires own synthetic material, a small V/F pair whose relevant
safety property changes, four-format/redaction checks, and an explicit partial
state for uncertainty. No upstream worker, payload corpus or real customer
source is needed. Existing filesystem/source work is outside this slice.

## Scope and honest completion claim

The first live execution boundary is exactly owned synthetic loopback: two
generated authenticated principals, two resources, and replacement of one string
`title`. Each resource gets owner/peer/explicit anonymous controls; other-row and
non-title fields are guards at every individual write. Fixed author-owned handlers are
manifest/hash pinned. No caller URL, arbitrary handler/observer callback, raw
patch, external credential, arbitrary method/body, DELETE/creation/upload,
redirect, anonymous fallback or endpoint discovery is accepted. Root approved
CLI `api-write-state --candidate fixed|ineffective|all-deny|normal-regression|status-only|wrong-object
--active-consent --out NEW_DIR [--timeout-ms N]`, SDK
`runOwnedApiWriteStatePilot({candidate,activeConsent:true,timeoutMs?,signal?})` /
`deliverOwnedApiWriteStatePilot(result,{outDir?,storage?})`, evidence
`apiWriteStateEvidence` v1 scope `owned-synthetic-resource-patch-write`, check
`api.owned-write-state-oracle`. Root subsequently approved all six candidate
meanings: fixed owner persists/peer+anonymous deny unchanged; ineffective peer403
after actual write; all-deny rejects owner; normal-regression owner wrong field
or expected title absent; status-only owner works/peer+anonymous200 no-op;
wrong-object owner PATCH mutates the other row. Evidence field/step types are now
documented in `src/contracts.ts`; SDK result/receipt and artifact names remain
pending. CLI consent is explicit
even though the only live target is owned. Scheduled anonymous probe is a named
control, never a fallback after failed authenticated identity.

Successful first-slice efficacy means independently discriminating real persisted
write/no-write effects across the controls below, with matching process gates
and redacted artifacts. It does not mean production exploitability, remediation
of a customer application, whole-service safety, or commercial value. Agent
`verification.state=not_run`, `vulnerabilityConfirmed=false`,
`remediationVerified=false`, and remediation `not_verified` remain unchanged.

This is not a permanent fixture-only definition of the product goal. The next
integration milestone must support an explicitly authorized user-owned staging
case with declared resource ownership, one reversible write, independent state
observation/reset/cleanup, normal behavior and same-case recheck. Before that
milestone, the report must state `owned synthetic` scope; do not expose an
arbitrary-target option as a shortcut. Planned user-app acceptance is an actual
authorized failing check -> reviewed patch -> normal/write controls -> recheck
with retained reports, not reuse of a candidate name or a fabricated customer
fixture. User setup success, false positives/negatives, useful reports and paid
value remain independently unproven.

## Independent oracle and control sequence

The handler contains the ownership decision. Its **generic store.write must not
enforce actor/owner**. The trusted store can enforce schema, target existence,
file identity and byte caps; it cannot decide whether a peer is authorized. The
V/F handlers differ only at the handler ownership predicate. Otherwise the
coordinator would block the vulnerable write and make the efficacy test circular.

An independently held readonly FD/snapshot observes actual persisted rows; a
handler boolean, HTTP status/echo, scanner finding, candidate enum, or observer
metadata submitted by a worker is never oracle truth. Distinct generated owner
control/probe values are private. Publish only bounded enums such as
`original`, `owner_control`, `peer_probe`, `unexpected`, plus aggregate lineage
digests. No token, standalone token hash, nonce, standalone nonce hash, raw body,
raw store value or source excerpt enters public output.

The initial QA proposal used one target, an in-phase reset,10 requests/phase,
shared32 attempts and a maximum120s deadline. **Root adopted a different bounded
matrix before implementation:** two resources,18 requests/phase,36 total maximum
attempts,12 total PATCH attempts, default/maximum30s, and no in-phase reset.
This is a disclosed scope/plan revision, not an expectation changed after seeing
output. Each phase starts a fresh private store whose initial state is verified.
Owner-control title is the before-probe reference rather than a reset original.
Local state reads/cleanup are separately ordered facts, not HTTP attempts:

| HTTP ordinal | Actor/action | Required independent local observation |
|---|---|---|
| 0–1 | owner and peer identity-before GET | Both authenticated identities distinct and expected |
| 2–8 | resource1: GETbefore, PATCHowner, GETnormal, PATCHpeer, GETcheck, PATCHanonymous, GETcheck | Snapshot both rows after every PATCH; owner-control mutation succeeds, unauthorized effects are classified independently, bodies agree with actual rows |
| 9–15 | resource2: same seven steps with its owner and peer roles exchanged | Each write leaves the other resource and non-title fields unchanged; previous resource evidence remains retained |
| 16–17 | owner and peer identity-after GET | Both still match identity-before |
| local | cleanup | Listener/socket/fds/store cleanup recorded, with bounded wait |

If either identity-before fails or is unknown, **all HTTP PATCH requests are
prohibited**, including owner control. They remain not_attempted with a fixed
prerequisite reason; do not switch to anonymous credentials. Store initialization
and trusted cleanup are local lifecycle operations, not target probes. Failed
owner normal control also prohibits that resource's unauthorized PATCHes. Initial
unknown state is not a baseline. Peer effect is observed and retained **before**
the subsequent anonymous attempt can overwrite title. A GET faithfully returning
a peer-mutated stored title is not by itself normal-function failure; the stored
unauthorized effect remains the finding. Stale/echoed body disagreement, lost
normal fields or failed owner write is normal-control failure. Independent
arrival/body/store observation must challenge fabricated counts/label verdicts.
Baseline observed unauthorized effect and valid normal controls are prerequisites
for running/accepting the candidate comparison; a failed baseline is not a fix.
The adopted baseline permits authenticated peer write, preserves successful
normal owner write, and denies the scheduled anonymous write. Do not redefine the
baseline to require anonymous mutation as positive evidence.

Observation and completeness are independent. A stored peer-probe effect is
retained even if later identity, normal, timeout or cleanup fails; the overall
result is then incomplete/2. If request receipt, state read or effect is unknown,
do not report successful denial. The matching target change is a scoped effect;
wrong-object/other-field changes are separately preserved unexpected effects.

## Six acceptance groups (expected before producer output)

All numeric gates below use the default `fail-on high`. `none` may suppress a
finding threshold but never incomplete/2. A pair/comparison gate is separate from
the original phase gates: a fixed candidate may yield comparison0 while the
original vulnerable phase1 remains recorded.

1. **Actual V/F discrimination and normal writer.** Vulnerable peer write reaches
   the persisted owner row, with owner control/identities/guard/cleanup
   complete: one stable high scoped write observation, completed phase1. Fixed
   owner predicate blocks the same peer write while owner control succeeds:
   effect not_observed, completed phase0 and scoped comparison0. Both resources
   and planned peer/anonymous probes are accounted for. Verify actual
   accepted PATCH/body/store facts independently, not only returned metrics or
   candidate labels. A new seed reproduces the relationship/operation, not the
   same original customer request or object. Preserve handler/policy/store/report
   lineage and the original vulnerable report.

2. **Misleading response and broken normal control.** Peer403 plus actual matching
   row write is1; peer200 with no row change is0 if all normal controls pass.
   Owner all-deny or owner200/no-op cannot pass the owner write control: partial2,
   and subsequent unauthorized PATCHes not_attempted. `normal-regression` also
   yields partial2, retaining concrete observed normal failure; the read pilot's
   existing regression gate is not changed. Owner echo-only/stale response is not a successful
   write. A scanner that treats HTTP403 as denial or HTTP200 as mutation fails this
   group. The generic store must permit the vulnerable handler's write rather
   than checking ownership itself.

3. **Identity and normal-state prerequisites.** Either identity-before failure,
   identity collision/drift, missing credential or malformed identity prohibits
   all PATCH traffic and gives2. Failure after a completed probe gives2, retaining
   any observed effect. Owner after-probe GET/body/store disagreement or lost
   normal fields gives2; it cannot certify fixed behavior. Verify no refresh,
   anonymous fallback, new probe or repair/model-triggered mutation occurs.

4. **Target, state and evidence integrity.** Wrong resource or unrelated-field
   mutation, unexpected guard change, malformed/oversized/truncated state, FD/path
   inode divergence or stale store read, altered handler/observer/policy pin,
   invalid method/order/ordinal/count/digest or forged evidence gives2. Preserve
   observed unexpected change and identify its bounded reason; do not reduce it
   to a matching-target finding or a clean denial. Legitimate title mutations
   remain schema-valid and are classified against private control/probe values.

5. **No retry, shared limits and uncertain termination.** Every PATCH has at most
   one send attempt. Response loss/timeout after write never retries it. Missing
   response or unknown receipt/effect is2 even if the observer can retain a stored
   change. Pre-abort causes zero traffic; active/between-step abort stops new
   probes, retains prior effects and attempts only bounded local cleanup. Request,
   body/store/deadline caps are shared across baseline/candidate in one invocation;
   a separately consented fresh recheck has its own finite run cap, not a resumed
   or delivery-retry budget. Exhaustion, identity
   aftermath or cleanup unknown is2, including `fail-on none`. A delivery retry
   only republishes retained redacted bytes and never reruns PATCH/handler.

6. **Publication, agent and consumer parity.** Public JSON/SARIF/Markdown/agent
   fields agree on scope, ordered evidence, effect, normal, counts, gates and
   lineage. Public sanitizers/parsers cannot erase malformed ApiWrite evidence
   into completed/pass. Secret/body/source markers never appear in any report,
   receipt, stdout/stderr or advice projection. Fresh installed CLI and extracted
   bundled Action must use the packaged entrypoint, return the same0/1/2 and retain
   the current-run reports. If the Action does not support the new explicit owned
   command in this slice, say so and leave Action parity unproven; an arbitrary
   shell SDK invocation is not evidence of bundled Action integration. Optional
   bounded advice is diagnostics only: no mutation argv, replay route, credential
   authority or automatic patch/execution. No live provider call is required.

## Budgets and atomic publication boundary

Root-adopted limits: phase18 logical HTTP requests, shared36 maximum HTTP attempts
across baseline/candidate (12 PATCH), default/maximum30s cooperative deadline.
Every attempt is charged before transmission. Request body4KiB, response64KiB,
shared aggregate response1MiB, store64KiB, cleanup2s and delivery5s are the adopted
finite caps. CLI timeout is1..30000ms; SDK exact result/receipt shapes remain pending.
Transport retries and automatic write retransmission are prohibited; no target
DNS traversal, redirect or forwarded credential is needed for the fixed listener.
Host I/O may outlive an SDK deadline; hard wall supervision is a separate
verification measurement, not inferred from timeoutMs.

The existing `writeReports` is **per-file atomic**, not a four-file transaction
(`src/report.ts:110–138`). This slice's owned artifact bundle should stage all
redacted report bytes plus digest metadata in an exclusive private sibling
directory on the same filesystem, then publish a fresh final directory once
complete. Existing final-attempt output, symlink/unsafe ancestor, partial write, late cancellation
or publication fault must not produce a success/ready receipt or replace another
run. Root clarified before first execution: SDK delivery accepts an existing OUT
root for fresh unique attempts and preserves previous bundles/sentinels; CLI
`--out NEW_DIR` refuses an existing root before traffic. SDK final collision must
never delete an earlier bundle in cleanup. A private builtin UUID interception
around delivery of an already completed result can exercise this without a
public fault option. Never copy private store/raw capture into the stage. Tests must fault late
publication as well as the first write, and verify original reports/source intact.

An atomic directory appearance proves a coherent publication, not final process
success or durable/crash-safe storage. A published manifest must say
publication_only/requiresCallerAcknowledgement; command/delivery ACK and final
exit remain separate. If uncancellable I/O publishes after timeout, caller status
remains unknown/2 and no receipt may claim execution/delivery success. Remote
storage transactions, crash recovery and malicious co-host isolation are outside
this bounded claim; limitations must remain visible. Delivery-only retries use
exact retained redacted bytes and fresh attempt paths, not a new scan.

## Public-contract agreement still required

Root approved the names, CLI consent, scope and revised bounded matrix above.
Public `ApiWriteStateEvidence` and `ApiWriteExecutionLedger` types were then
documented in `src/contracts.ts`: phase/execution/effect/normal/verification/
cleanup/reasons/counts/lineage/ledger/nextEvidence, counts plannedRequests/
httpAttempts/patchAttempts/capturedResponses/stateObservations, and a method-
bearing GET/PATCH ledger with fixed actions, actor/resource indices, attempted,
outcome and HTTP status. These are structural declarations, not measured effects.
Root then documented phase result `{report,scanGate,evidence}`, pilot result
`{version,scope,runId,before,after,verification,verificationGate,execution}`,
execution HTTP/PATCH/byte/state counts and cleanup, and delivery receipt with
run/attempt/path/status/reason/gates/digests and `apiReexecuted:false`. Exact paths
are `OUT/<outputRelativePath>/{before,after,verification}/` with the normal four
report names and `api-write-delivery.json` publication-only marker. CLI stdout
also carries delivery and commandStatus separately from gates. These public
contracts authorize independent test code now; no author execution follows from
that authorization. Actual narrow Action input/output contract and precise late
publication testing remain subject to its documented surface. Evidence
needs distinct HTTP attempt and local state/cleanup accounting; known
absence of a step differs from an unknown step. A plan digest authenticates
structure/lineage, not truth or permission. Default report names remain the normal
four formats. Do not force GET-ledger replay or native SQL evidence onto writes.

Independent private expected input/source-shape manifests may be frozen before
producer output. Later tests use only agreed existing public SDK/CLI/report APIs;
no producer-helper import and no target execution by the test author. Root owns
baseline/current executions, independent source/store observation, fresh package
CLI/Action receipts and the measured confusion table. Expected outcomes cannot be
changed to make current implementation output pass.

## First independent test lock

`tests/api-write-independent.test.ts` implements the six groups above through
public SDK namespace, existing main/report paths, and the actual narrow Action
wrapper. It imports no new detector/observer helper. Its own isolated child
`--import` preload observes actual loopback requests and private store bytes under
an owned temporary root. Identity, lost-response, abort and state-read faults are
private builtin interception, not shipped SDK callbacks. The readonly-FD fault
throws on scoped readSync/fstatSync after a chosen actual PATCH while leaving
FileHandle ownership intact for cleanup; it does not forcibly close a managed FD.
Fault-fired/read counters distinguish a test that exercised the boundary from
one that merely returned2 for an unrelated error.

Before first execution, root clarified existing SDK OUT roots versus occupied
final attempts. Tests now require two fresh successful deliveries with unchanged
artifact/report hashes and no HTTP, preserve earlier bundle/sentinel, force a
private UUID final collision and late directory-publication fault, and require2
without deleting the first bundle. CLI still refuses an occupied root. The exact
`api-write-manifest.json` schema is version/scope/runId/deliveryAttemptId/artifacts
with each known relative member's bytes and SHA256; marker.manifestSha256 binds
its exact bytes/newline. All twelve phase-format members are checked.

Real `actions/api-write-state/run.mjs` receives the agreed WAKEIO_WRITE_* inputs,
uses the bundled CLI, emits actual phase/final gate outputs and independently
acknowledges current hashes/process. The test invokes this wrapper for0/1/2 and
consent refusal; it does not rename a direct dist CLI invocation as Action proof.
Root's separate fresh npm/source archive harness establishes distribution parity.
No author build/test/scan/target/model execution has occurred. Root owns first
execution and subsequent immutable lock/log history; fixture bug corrections must
be recorded separately from product failures.

First test-file SHA256 submitted for lock:
`a191f259338dad3dae191bc4d33e04489d8434e760e08d50ad0d27b518cb700d`.

Root preserved `focused-initial.log`: first lock yielded4/6 groups passing. The
four passing groups exercised actual request/store discrimination, identity
prerequisites and post-effect failures, readonly state observation, lost response
without retry and abort. Group4's comparison assertion was a test-contract bug:
`parseScanReport` explicitly rejects write evidence attached to an unrelated
check ID with exactly `Invalid scan report`. Root authorized accepting either
that controlled refusal or comparable=false. All case-by-case four-format gate2
and redaction assertions still execute before comparison; no arbitrary exception
or comparable/pass is accepted. Group6's actual Action fixed2-versus-expected0
remains a product failure; its expectation is unchanged.

Second test lock submission SHA256:
`38cd10a0b1491d10d30f319ee5cc796da63018b74da0e48ea79a43d644a7aee5`.
The author only read the root log and parser guard; no execution was performed.

Root independently measured a product false green: completed observed write
evidence with its effect finding removed rendered a completed report and gate0.
Before the focused rerun, group4 now reuses the valid baseline check to require
partial/gate2 when the high observation is removed or downgraded, and when a
completed not_observed check carries a spurious observed-effect finding. Report,
agent, Markdown and SARIF must agree. An intact observed finding still permits
intentional failOn=none gate0; malformed evidence remains2 even with that policy.
These are additional consistency regressions, not relaxed semantic expectations.

Third test lock submission SHA256:
`1790612cef395bfb2c1d1d68a296deeddf5f431c2330aa73499927a62f72539c`.
All six group boundaries remain. No author execution or product edit occurred.

Root preserved `focused-final.log`: v3 yielded5/6 groups passing, including the
effect/finding consistency regression. Actual Action fixed now exits0 after the
product publication-permission correction; group6 next failed because its path
assertion compared macOS `/var` temporary paths with the wrapper's canonical
`/private/var` path. This is a test path-normalization bug. The assertion now
requires the returned path itself to equal its realpath and that realpath to lie
under realpath(workspace) plus a directory separator. Containment, all gates and
the remaining ineffective/all-deny Action expectations are unchanged.

Fourth test lock submission SHA256:
`806d22d77763d96fb335a3c25a805c35db11992765faea46d264555c36e135b1`.
No author execution or product edit occurred.
