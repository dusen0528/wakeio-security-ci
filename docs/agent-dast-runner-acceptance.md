# Independent bounded-runner acceptance

This matrix is proposed before producer implementation of the public runner.
It is an execution contract, not a passing result. The acceptance author reads
sources and writes this document only; root alone builds, imports, runs tests,
starts owned fixtures and exercises fresh package/Action consumers. No provider
or external target calls, Git mutations or unmerged PR29 instructions are part
of this review. Existing SDK/store integrity acceptance remains separate.

## Proposed public behavior

Expose one public structured-plan execution path in the package and CLI, with
an Action input forwarding that same plan. Exact names await producer agreement.
An agent can prepare a plan; no account/model call is needed to execute it.

The controller snapshots and validates the complete bounded JSON plan before
any selected check starts. A plan binds task identities to closed built-in
check identifiers and existing scanner policy schemas. It declares consent,
scope, a run-wide request cap, a run-wide deadline and bounded concurrency.
Unknown checks/keys, non-string enums, duplicate IDs, impossible assignments,
invalid budgets and mismatched policies are fixed-error rejection, not coerced
inputs. Planning data cannot choose shell commands, scripts, executable paths,
provider output, network proxies, SQLite paths or unrestricted worker code.
Credential values stay in locally supplied named environment variables.

The trusted controller executes existing native DAST and built-in source
checks, owns admissions, observations and any RunStore connection, and projects
the existing four report formats. Agent/worker stdout can never create trusted
coverage, findings, request counts or successful ledgers. Initially unsupported
engines/auth/checks are refused explicitly instead of silently dropped.

CLI and Action derive the same existing scan gate: 0 means selected applicable
checks completed without threshold findings; 1 means completed checks reached
the selected severity threshold; 2 means validation/setup/incomplete/cancelled/
cleanup/report-delivery failure. Error takes precedence over findings, and
`fail-on none` disables only severity failure. A finding retained in an
incomplete run remains reported. Completion means the declared checks ran; it
does not establish exploitability, remediation or whole-application safety.

## Frozen semantic acceptance matrix

| ID | Owned independent stimulus | Required observation |
| --- | --- | --- |
| R1 Public execution and useful findings | Use an independently owned SQL differential target with vulnerable, parameter-bound fixed and ordinary-value control modes. Feed the same supported plan through the public package/CLI. Separately scan owned vulnerable/fixed source pairs with built-in checks. | Target-side requests prove the declared DAST phases ran. Vulnerable mode yields the expected rule/context and high-threshold exit 1; fixed and ordinary-control modes finish without that finding, exit 0. Source rules likewise distinguish their actual supported vulnerable/fixed forms. A source/target marker is absent from public output. No target scripts/install/build/test hooks run. Labels or worker fixture stdout are insufficient evidence. |
| R2 Plan boundary before execution | Include one valid task followed by an unknown check, array enum such as `["anonymous"]`, duplicate task ID, cross-scope policy or invalid safe-integer budget. Mutate caller-owned nested data after submission. | Whole plan rejects with exit 2 before target traffic or source execution. Fixed diagnostic excludes unknown keys/value canaries. Accepted plan is a detached snapshot; mutations cannot alter the assigned scope/checks/limits. No inferred or widened scope. |
| R3 One shared request budget | Two tasks each need more requests than the run cap. Start them concurrently against a counting target; include retries/control/identity requests where supported. Pair with a sufficient-cap run. | Atomic admission never permits more than the run cap across all tasks. Sum of task-attributed attempts agrees with the run ledger; refused work does not count as evaluated coverage. Insufficient cap leaves explicit gaps/exit 2, even with `fail-on none`; sufficient cap completes. Existing per-check budgets cannot reset the run cap. |
| R4 One shared deadline | First task consumes most of the deadline; a second task and a held response remain. Pair with a generous deadline. | Queued and running tasks share the original absolute deadline, with no fresh per-task time allowance. Expiry stops admission, cancels active I/O, awaits cleanup and returns 2 with timeout gaps. Positive control completes. Target sees no new requests after stop. |
| R5 Cancellation and resource ownership | Abort before start, during a held target response and while another task is queued. Observe server-side close and active sockets; exercise CLI signal handling separately. | Pre-abort sends zero requests. Mid-run abort closes outgoing requests including pending connections, stops queued work, settles cleanup and returns 2. No late observation or completed transition after sealing. Findings already observed remain. Merely destroying the inbound proxy connection does not satisfy cleanup. |
| R6 Real HTTP accounting, including HTTPS | Make two requests on one keep-alive connection with run cap 1. If a proxy/CONNECT path exists, try two inner HTTPS requests and a disallowed inner method through one tunnel. | Second HTTP request cannot reach target. Trusted direct HTTPS counts admissions for each request. Opaque CONNECT is refused in this strict bounded lane; a tunnel count cannot become an HTTP request count or completed coverage denominator. Method/scope enforcement applies to every admitted request. |
| R7 Fabricated completion cannot attest execution | Supply coherent completed worker JSON with no trusted observations; then mismatched identity, planned/executed counts, finding IDs/severities, missing/contradictory/nonzero/truncated ledger. Pair with actual full native execution. | Claims cannot create executed coverage or findings, and cannot complete the run. Rejection/fallback preserves previously observed findings and produces incomplete exit 2. Worker receives no direct DB handle/path/write capability. Positive completion comes only from controller-owned execution and its sealed ledger. |
| R8 Concurrent isolation and attribution | Run multiple tasks with distinct surfaces; include the same rule/path under distinct auth or parameter-location contexts. Repeat a same-context observation and a later higher severity. Use two independent runs concurrently. | No task/run borrows another's requests, coverage, findings or terminal state. Same-context deduplication retains task-local observations and strongest severity; distinct auth/location remains distinct. Invalid/conflicting writes cannot erase evidence. The public report identifies the producing check/context without raw payloads. |
| R9 Scope and active-check refusal | Omit active consent; use a mismatched origin, blocked private target without explicit permission, redirect outside scope or a task-selected method outside the check contract. | Refusal occurs before forbidden traffic. No credential forwarding to another origin, automatic redirect widening or fallthrough to an unbounded transport. Explicit local permission works only for the owned positive target. Unsupported plan/check/auth stays visible as rejection or incomplete; it is never completed/no-findings. |
| R10 Failures and honest partial results | Target returns malformed/oversized JSON or unexpected 500; engine throws after recording a finding; a selected task is unavailable or cleanup fails. | Check-specific evaluated controls determine the result. Transport success/500 alone cannot attest a successful differential. All declared tasks remain accounted for; gaps are visible; retained findings stay in reports; overall exit 2. No fallback all-zero completed result. |
| R11 Four reports, redaction and delivery | Completed vulnerable/fixed runs and an incomplete run include independent request/response/header/source/credential canaries. Force report-path refusal or failure while old artifacts exist. | Fresh `report.json`, `report.sarif`, `report.md`, `agent-report.json` agree on findings and scope; agent projection binds fresh JSON digest and uses the same scan gate. Public stdout/stderr and reports exclude canaries/raw traffic/source. Delivery failure returns 2; per-file atomicity is not a four-file transaction, and a stale agent report is not a final-exit receipt. |
| R12 Public consumer and CI gate | Root later uses a fresh packed package and checked-in Action on owned plans for exits 0/1/2, including incomplete with `fail-on none` and output collision between concurrent runs. | Public import/CLI/Action actually execute the same runner, expose the four artifacts and propagate the final exit. Same output ownership cannot interleave reports or reuse another run's success. CI scan job fails on 1/2; a dependent build/deploy requires `needs: scan`. Report upload after failure is demonstrated separately. |

Independent tests will use target-side counts, close events, owned source
before/after bytes, fresh report contents/digest and real public return/exit
values as oracles. They will not define success by producer labels, substitute
fabricated SQL rows for real observations, or require arbitrary external worker
execution. Timing controls use explicit handshakes/held responses; generous
test wait allowances must not change product budgets.

## Source-read gaps to resolve before test authoring

- `src/agent-dast/index.ts` currently exposes result/store only. Its documentation
  explicitly excludes CLI/Action execution and four-report delivery.
- `runDast` builds a new request budget and deadline per invocation. Its public
  options currently cannot receive a controller-owned shared admission budget.
  Merely decrementing a cap after a task finishes cannot enforce concurrency.
- Existing `writeReports` and `evaluateGate` already provide redaction, the
  0/1/2 precedence and a digest-bound agent projection. Reuse those contracts;
  keep delivery failure/final exit distinct from in-report scan status.
- The earlier read-only review of WIP `a99c7ee` found CONNECT counted as a
  request, unowned outgoing cleanup and coerced enum values. That review is
  retained under `artifacts/agent-dast-integrity-2026-10-13/runner-branch-review.md`;
  this matrix treats them as must-reject controls, not verified live defects.
- Source checks need an explicit closed selection and applicability policy.
  Source collection/analysis gaps must remain incomplete rather than hidden by
  a passing DAST task or informational inventory check.

## Interface handoff required

Before independent test authoring, producer/root should agree on exported
parser/runner names, CLI/Action names, schema/check IDs, supported source/DAST
policy shapes, limits, returned report/exit shape and output ownership. Tests
may adopt those names before their first execution; the semantic expectations
above must not be weakened to match the implementation. Root records document
and test hashes before candidate build/execution and retains failures separately.

## Root-adopted first execution slice

After the initial matrix freeze, root selected `run-plan --plan FILE
--active-consent --allowed-origin ORIGIN --out NEWDIR`. Plan v1 contains bounded
same-origin native/Schemathesis/Nuclei tasks; global request/time/rate limits and
trusted runtime executable paths are owner CLI options. Plan-selected shell,
arbitrary code and worker DB permissions remain forbidden. Source execution
continues through the existing `scan` path and its independent source pairs;
source tasks inside plan v1 are not assumed.

Each task writes the existing four reports. Root artifacts are
`run-report.json`, `run-report.md` and `agent-run.json`, with task-ID-relative
links, digests and aggregate 2 > 1 > 0 gate. Output is a newly claimed directory;
existing paths or concurrent claim losers must not overwrite another run.
This clarifies R11/R12's artifact ownership; it does not require a root
`report.sarif`. Native/authenticated HTTPS remains supported with observable
direct per-request admission. An engine using opaque CONNECT without strict
request observation must produce incomplete exit 2 and cannot claim a bounded
completed run. A first slice can explicitly refuse that lane before traffic.

The transport interface agreed before tests is `RunAdmission` with one
`maxRequests`, `ratePerSecond`, absolute `deadlineAt` and optional abort signal;
`bindTask(taskId)` returns task admission. `reserve` atomically admits an actual
request immediately before transport creation after any rate wait, and owns an
idempotent response/transport-error permit. Refused/cancelled waits consume no
request count; failed wire attempts count. The native/egress/engine capability
is a second trusted runtime argument, absent from JSON plans. Run snapshots and
task ledgers contain fixed request metadata only, without URLs/query/headers/
bodies. Public parser/controller schema names remain pending.

## Independent test v1 freeze

Before producer implementation review or candidate execution, the interface
handoff fixed `plan.ts` exports `parseExecutionPlan`/`parseExecutionInputs` and
`runner.ts` exports `runExecutionPlan`. Plan v1 has closed engine tasks and
references input aliases; a separate inputs manifest binds each local input by
its file-byte SHA256. CLI requires `--inputs FILE`. Owner concurrency defaults
to 2 and is bounded to 1..4; request/time/rate/engine-runtime paths are owner
options. Controller rejection returns a fixed error result with no tasks,
zero requests and no output ownership; schema parsers throw fixed errors.

`tests/agent-dast-runner-independent.test.ts` v1 contains seven groups. It uses
real SQLite SELECT concatenation versus parameter binding and an ordinary
constant-query control behind an owned counting HTTP server. The concurrent
budget test holds both first responses until both task paths reach the target,
then requires exactly nine shared wire attempts and task-local attribution.
Cancel/deadline tests hold two real responses, then require server-side close
and no queued third-task requests. Delivery failure is an owned symlink fault
created while actual target requests run, rather than a fake report-writer
return value. No-clobber uses simultaneous claims for the same new directory.
CLI assertions use the built public entrypoint and real process exit values.

The seven groups cover the main R1–R5/R7/R10–R12 native/controller controls.
They do not claim real-engine Schemathesis/Nuclei, native authenticated HTTPS,
opaque CONNECT, every deduplication context or GitHub-hosted CI evidence. Those
remain separate root/transport regression and fresh-consumer acceptance work.
The existing independent source/report suites supply the SAST differential
controls; this new file does not duplicate them. No passing result or package
release is claimed. Root will record hashes before execution; author execution
count remains zero.

Root froze the original seven-group test SHA256
`56ad62cc29aeb09691aaa11a5fd016f68b1e2d07bd826cf012d352bbbb7aa4e1`
and then-current document SHA256
`c75691773710668b2e534c58be60e756daae19f45a0928cbfbbc0459415ed8fd`
in private copies before execution. That test file remains unchanged.

## Independent real-engine supplement

Root subsequently requested a separate
`tests/agent-dast-runner-engines.test.ts` with four groups: real Schemathesis
response-schema vulnerable/fixed and transport-failure gates 1/0/2; concurrent
native SQL plus real Nuclei using one unchanged signed `git-config` template;
native/Schemathesis competition for one shared cap; and exit-0/progress-100
fake Nuclei with zero traffic required to stay incomplete. The Nuclei subset
is copied at test execution from the existing reviewed library, with owned
subset provenance, avoiding a full-library scope run or new download.

The Nuclei/native positive fixture holds the first native response until the
signed template request reaches `/.git/config`, proving task overlap by target
observations. Real healthy engine counters must equal actual server requests;
failed attempted connections remain separately accountable and never become
completed response coverage. Secret canaries in schema-invalid response values
and extracted Git-config content must not escape task reports.

The authorized test-harness addition to `scripts/test-schemathesis.mjs` keeps
the existing pinned-runtime preflight and zero-skip checks. It sets
`WAKEIO_REQUIRE_SCHEMATHESIS=1` and `WAKEIO_REQUIRE_RUNNER_ENGINES=1`, and validates
all four exact test names from the supplemental built file into
`receipt.agentDastRunner`. In required mode missing runtimes fail assertions;
optional local runs may skip only unavailable real-engine groups. No author
runtime/import/build/install/Git/provider/target execution has occurred. Root
will freeze supplemental test/harness/document hashes before their execution.

Root additionally requested
`tests/agent-dast-runner-context.test.ts`: two concurrently executed real SQL
vulnerable endpoints, `/alpha?id=1` and `/beta?key=1`, must produce two canonical
store findings under the same native rule. The independently owned native
read-only SQLite connection queries `findings JOIN surface` and
`finding_observations` from the actual controller `run.db`; expected context is
the real method/path/parameter/location/auth, with two task-local observations
and unchanged DB bytes after the read. Root-only execution remains required.
Engine-group coverage rows are not an endpoint-coverage denominator; preserving
finding context is a separate integrity requirement. This supplemental file
does not alter the original seven-group freeze or the four engine-group names.

## Compile/interface corrections and template-path review

Root retained the original freezes and `build-v1.log`. The first build reported
only test-fixture literal widening: original plan/input version and kind, and
context task engine. The author added four `as const` annotations, with no input
or assertion changes. Root then reported a diagnostic run under canonical
`TMPDIR=/private/tmp` with 16/18 passing; the two failures identified the author's
incorrect expected rule ID. Both the pre-existing archived native source and
current native source use `dast.sql-boolean-differential`. Exactly three expected
strings were corrected to that established identity; finding counts, severity,
path, parameter, DB observations and runtime cases remain unchanged.

The resulting independent test SHA256 is
`b681211c46e48bef51e6e3c0c60030c1d0ba4a2b3bbfe923f34d2b493c3cb4ec`;
context test SHA256 is
`fcd163318bb72e307a854b0500e2042a92171f0967b0141885208424297cadd3`.
These changes correct typing and the existing rule-name contract, not the
semantic acceptance oracle. No author execution occurred.

Read-only controller review found that Schemathesis finding context compared
URL-normalized path braces with raw operation templates. A supported finding
on `/owned-items/{id}` could therefore become `store_error`/exit 2 instead of a
completed threshold finding. Producer's source fix now compares each declared
operation through the same URL pathname normalization and retains the original
template in the audit DB. The independent new
`tests/agent-dast-runner-template.test.ts` verifies actual generated
path-parameter vulnerable/fixed executions, expected completed1/0 gates, fresh
digest-bound task artifacts and read-only stored original template context.
Root froze its SHA256
`f71fd2a48ae60d2cea4db764b95c22322672ee9344cc0069e73ddbf978b7515f`
before execution. The required harness additionally validates this exact test
name/file into `receipt.agentDastRunnerTemplate`, so required runs cannot omit
or skip the template control. At source-review completion no other concrete
open P1/P2 controller DB-closure or artifact-gate defect was identified. Runtime
acceptance and final process/Action acknowledgement remain root's responsibility.

## Bounded authenticated runner integration

Root requested one remaining integration group in
`tests/agent-dast-runner-auth.test.ts`, reusing the already owned
`schemathesis-auth-target.mjs` fixture. The public `runExecutionPlan` executes
authenticated Schemathesis vulnerable/fixed plans plus a fixed plan whose
global cap is 5 while the selected engine cap remains 12. Expected gates are
1/0/2, including incomplete with `fail-on none`. The target's actual request
observer and protected handler identify identity, anonymous/normal and real
generated calls; task/run request counters and permit kinds must agree with
those observations. Complete runs require all five controls and generated id2
to reach the protected handler. The insufficient global cap must visibly stop
trailing controls. Credential/principal/normal-marker/body values and credential
hashes must be absent from every output artifact, including the audit DB.

This is one bounded integration group, not a second full auth suite. The
required harness validates its exact name/file into
`receipt.agentDastRunnerAuth` and required runtime absence cannot skip it. Tests,
fixture imports and target/provider execution remain root-only; author has
performed no runtime execution. Root freezes the new test/harness/document
before candidate execution.
