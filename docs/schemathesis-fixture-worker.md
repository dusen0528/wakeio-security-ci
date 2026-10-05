# Schemathesis fixture worker

Base commit: `dad74a0650df74864ddc7204cd6126a7f45aa04a`. This is an opt-in library
adapter with real OpenAPI-driven Hypothesis generation and Schemathesis response
checks, against a bundled synthetic WSGI fixture. No live-target option is added
to the CLI or Action. `completed` means the selected execution finished;
`records[].check` distinguishes a passing response from a contract violation.
A violation is not evidence of exploitation or broken authorization.

## Run

Node >=22, Python 3.12, macOS/Linux with POSIX process groups and a local
filesystem supporting hard links and directory fsync:

```bash
npm ci --ignore-scripts
python3.12 -m venv .venv-schemathesis
.venv-schemathesis/bin/pip install -r workers/schemathesis/requirements.lock.txt
npm run build
export WAKEIO_SCHEMATHESIS_PYTHON="$PWD/.venv-schemathesis/bin/python"
npm run test:schemathesis
node examples/schemathesis-fixture.mjs broken # exit 1: response contract failures
node examples/schemathesis-fixture.mjs fixed  # exit 0: selected checks passed
```

The required-engine test entrypoint fails with exit 2 when Python or Schemathesis
4.2.0 is unavailable. Ordinary `npm test` also runs the Python-dependent tests;
when `WAKEIO_SCHEMATHESIS_PYTHON` is unset they use
`.venv-schemathesis/bin/python` from the repository working directory. Missing
Python/dependencies are failures, not permitted skips. The worker reports an engine error rather than a clean scan
when dependencies are missing. The dependency lock is a tested version snapshot,
not a hash-locked supply-chain attestation. The implementation uses the pinned
[Python API](https://schemathesis.readthedocs.io/en/stable/reference/python/)
(`as_strategy`, `case.call`, `validate_response`) and explicitly selects
`not_a_server_error` and `response_schema_conformance`.

## Boundaries

| Boundary | Contract |
| --- | --- |
| API runner / adapter | Shared `createApiRunControl`, existing request/body/time constants, caller `AbortSignal`; cancelled API results stay partial |
| Job / worker | Version 1 JSON; `environment=staging`; fixture selector; exactly `readItems`; finite budgets/seed; optional bounded synthetic replay quantities |
| Python engine | Bundled schema only; GET `/items` WSGI calls; POST `/admin` excluded; no caller URL, schema, credentials, paths or code |
| Budgets | At most 64 calls, 120 seconds, 2 MiB single response, 10 MiB total response; caller may lower each cap; body cap stops the run |
| Process supervisor | Trusted executable/argv, no shell; minimal PATH environment; isolated POSIX group; cancellation/timeout/overflow kills group and awaits close; normal exit also terminates background group members |
| Worker output | 64 KiB stdout cap, stderr discarded; strict string enums, fixed selected-check/status consistency, expected implementation digests and recomputed safe-input fingerprints; metadata projection only; unknown/malformed/nonzero result becomes error |
| Shared storage | Projected JSON only; UUID key and SHA-256; same key+same bytes is idempotent; changed bytes conflict; failures reject delivery |

`CodeWorker.execute(job, signal)` and `SharedArtifactStorage.put(id, redactedJson)`
are separate replaceable interfaces. A remote Code Worker must terminate its
owned job on abort and await termination; an adapter that ignores the signal does
not satisfy this interface. Remote storage must implement conditional publication
and identical-byte retries. Credentials belong in trusted worker/storage
configuration, never in the job or artifact.

`runSchemathesisFixture` hashes the trusted bundled `worker.py`, `openapi.json`
and `requirements.lock.txt` before execution when `expectedManifest` is omitted.
For a custom deployment, coordinator configuration may provide
`expectedManifest: { workerSha256, schemaSha256, dependencyLockSha256 }` with
the expected lowercase SHA-256 values. Malformed manifests reject before worker
execution; well-formed manifests are copied and frozen before invoking the
worker. A result whose digests differ becomes a redacted `worker_error` artifact.
Protocol v1 still requires engine 4.2.0 and both fixed response checks; this option
does not enable arbitrary targets, checks or code. Digest equality checks protocol
consistency with the coordinator's selected implementation. A worker can echo
known hashes, so it is not proof of honest execution, coverage, installed
dependency bytes, or security correctness.

`localCodeWorker(executable, args)` is trusted deployment configuration, not an
API for job-selected code. `pythonFixtureWorker` selects the bundled script with
Python isolated mode (`-I`). Only processes remaining in the isolated process
group are covered; hostile code escaping the group requires cgroup/container
supervision. Windows is rejected rather than claiming equivalent termination.
The socket guard is defense in depth for this trusted fixture; it is not an OS
sandbox or complete egress policy.

The local store writes and fsyncs a private temporary file, then publishes it
using an atomic no-overwrite hard link and fsyncs the directory. Readers of
`<runId>.json` see complete bytes. Ordinary failures clean up temporary files.
An OS crash/SIGKILL can leave an unpublished `.tmp` file; storage owners may
remove such files when no writer is active. A failure after publication may leave
a complete final artifact: retry the same key and exact bytes to recover. This
is idempotent delivery, not exactly-once execution. Output directories and their
ancestors are trusted configuration. Scan timeout covers execution, not storage
I/O; remote storage implementations need their own bounded delivery policy.

## Redaction and reproduction

`src/api.ts` has no reusable generic regex masker. Its contract excludes tokens,
bodies and arbitrary scanner text from results. This adapter reuses that contract
through projection at both worker and Node boundaries. Raw HTTP request/response,
headers, cURL and exception messages are never persisted. Only the synthetic
integer `quantity` in 1..20 is retained; the token is `[REDACTED]` and injected
locally during replay.

Every inspected response records operation, method/path, ordinal, status, safe
input, check outcome and structural failure details. The broken fixture records
`response_schema_conformance`, `type_mismatch`, `/count`, expected `integer`,
actual type `string`, without the failing value. Artifacts also retain schema,
worker-source and dependency-lock SHA-256, Schemathesis/Python/Hypothesis/
JSONSchema/Werkzeug versions, Node version and the validated execution job.
The coordinator compares implementation hashes with its fixed expected values
and recomputes each fingerprint as SHA-256 of UTF-8 compact JSON
`{"quantity":<integer>}`. These comparisons do not verify installed dependency
bytes or worker honesty.

```bash
node examples/schemathesis-replay.mjs artifacts/schemathesis/<runId>.json
```

Replay reconstructs each recorded safe input with the bundled fixture, bypassing
generation, and compares implementation metadata and records. A seed alone does
not guarantee reproduction. Replay returns exit 2 if metadata/records differ or
the execution is incomplete. A completed explicit replay must observe every
planned quantity in order with ordinal 1..N, exactly once; repeated quantities
are valid when the plan repeats them. Generation may complete below its request
cap, which is an upper bound rather than an exact planned case count. Partial
replay records must match the planned prefix in both ordinal and input.
A partial artifact can contain fewer records than
attempted requests; killed workers may provide no trustworthy counts. Never
replace absent counts with zero. Exact replay supports inspected synthetic
requests only; it cannot reconstruct unrecorded or arbitrary real HTTP payloads.

By default each execution gets a new run ID. Calling `runSchemathesisFixture`
again with the same `runId` **executes the worker again**; identical resulting
artifacts converge on one file and changed bytes conflict. This is not a
delivery-only retry. `SharedArtifactStorage.put` can resend already retained
identical projected bytes without executing the worker, but this API does not
provide a durable execution spool or recovery workflow. No automatic execution
retries occur. Remote coordinators must separate actual execution from durable
delivery retry and retain projected bytes themselves.

These protocol changes do not close E05 (escaped descendants/supervisor death),
E06 (unbounded stalled storage delivery), or E07 (no durable execution spool).
Those remain separate execution/lifecycle work; process-group tests and
same-byte storage publication do not establish their completion.

## Completion criteria and evidence

- [x] Patch applies to the stated base and TypeScript builds.
- [x] Real engine distinguishes broken response contracts and passing responses.
- [x] Adapter and raw Python entrypoint reject production/mutation/unknown scope and invalid budgets before fixture calls.
- [x] Request, single/total response and execution time budgets are enforced.
- [x] Pre-cancel makes no calls; running cancellation and timeout terminate execution.
- [x] Supervisor tests terminate parent and descendant processes on cancel, timeout, overflow and normal parent exit.
- [x] Malformed/failed engine outputs become error artifacts; raw secret canaries do not cross storage.
- [x] Failure rule, endpoint, expected type and violation kind remain traceable without bodies.
- [x] Versions/digests and generated safe inputs are recorded; changing the replay seed preserves exact recorded cases.
- [x] Same-key concurrent/retry storage produces one complete file, conflicts reject, publication failures clean temporary files, storage errors reject delivery.
- [x] Required-engine full suite passes with zero skipped tests.
- [x] Installed npm tarball includes/resolves worker/schema/locks and executes broken/fixed cases.

The measured results and ZIP changes are recorded in
[verification-schemathesis.md](verification-schemathesis.md). To recheck package
resolution after building a release tarball locally:

```bash
npm run package:release
node scripts/verify-schemathesis-package.mjs artifacts/wakeio-security-ci-0.4.0-dev.1.tgz
```

## Scope still outside this patch

`environment=staging` is a synthetic job constraint, not verification of a server
environment. Live DAST needs separate target authorization, validated operation
and schema scope, external `$ref` rejection, network egress/redirect controls,
streamed body caps, credential injection outside artifacts, and remote job
cancellation. Authentication/session/authorization flows, ZAP, GraphQL, mutation,
stateful workflows and injection/exploit checks remain unimplemented here. Local
fixture evidence does not establish deployed service security or isolation of
untrusted Code Worker code.
