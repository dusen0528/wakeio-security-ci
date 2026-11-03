# T3 acceptance and QA design

Base: a49da4ceebc2c7dd24020ecbce420f46d0ca7625.
Branch: ulw/release-gates-w0-t3-qa.
This is one executable QA-driver story, not multiple product stories.
No scanner, Oracle, product, policy-case, or manifest-case implementation.

Acceptance fixed before verification:

- Real Node child stdout and exit plus loopback HTTP status, headers and body;
  pass only with complete captures, assertions and confirmed child/socket cleanup.
- Event-triggered child abort exits 2 with cleanup receipt.
- Unknown and absent future cases exit 2, never synthetic success.
- Malformed argv, existing output and symlink ownership violations refuse to run.
- Truncated JSON and nonzero child exit cannot pass; truncated byte capture and
  unconfirmed cleanup are unavailable.
- Signal and handler exceptions preserve owned cleanup.
- Output artifacts bind source HEAD, full source-scope digest and artifact hashes.

Reuse:

- Direct import of the canonical src/report-path.ts redactSecrets implementation,
  verified on the repository's pinned Node v22.23.1. No generated build dependency.
- scripts/ci-process.mjs sourceSnapshot reused unchanged.
- scripts/ci-process.mjs POSIX detached-process-group and close-confirmation pattern
  reused; its polling loop is not reused because this contract requires event-only
  readiness and settlement.
- src/report.ts ancestor symlink refusal pattern reused in the QA output boundary.
- Node stdlib spawn/http/net/events/fs/crypto only; no dependency changes.

Test authoring gate:

- Real CLI/HTTP integration owns qualification, artifact hash binding and cleanup;
  replacing assertions with success or removing either transport makes it red.
- Table-driven negative integration owns cancellation, time budget, capture limit,
  truncated child protocol and actual child failure. No existing QA-driver owner.
- Incomplete-cleanup control owns conservative qualification, not a fake clean run.
- Missing cases and malformed argv own safe dispatch and input refusal.
- Dirty-output/symlink controls own preservation and stale-evidence refusal.
- External signal test subscribes to the real readiness event before signalling.
- Split-write capture test owns whole-capture redaction using real child streams.
- Pre-abort/budget test owns zero child creation and valid execution budgets.
- No test-only exports, copied product implementations, fixed sleeps, prose pins,
  direct injected success, or mock response objects.

Case API:

`runCase({ out, mutate })` is async and returns
`{ status: 'pass' | 'fail' | 'unavailable', artifacts: string[], cleanup: { confirmed: boolean, ... } }`.
Artifact names are relative JSON filenames; the CLI checks regular files and
records byte lengths and SHA-256. Cases must clean resources in finally before
returning and write cleanup.json. A thrown case is unavailable with unknown cleanup.

QA-only helper API:

- scripts/qa/roadmap-cases/process.mjs:
  captureProcess(command, args, { signal?, timeoutMs?, maxOutputBytes?, onStdout? })
  returns redacted complete captures, actual exit/signal/reason, truncation and
  cleanup (PID, closeConfirmed, groupGone, confirmed). onStdout is ephemeral
  readiness handling; do not persist its unredacted input.
- scripts/qa/roadmap-cases/artifacts.mjs:
  redactArtifact(value), writeArtifact(out, name, value), sha256(bytes).
  writeArtifact redacts values recursively and exclusively creates mode-0600 JSON.

Owned resources:

RUN_TMP=.omo/tmp/t03-20261103-0528, scoped to this worktree.
TMPDIR, NODE_COMPILE_CACHE, BUN_RUNTIME_TRANSPILER_CACHE_PATH and npm cache are
within RUN_TMP. node_modules and build were absent before preparation and must
be removed after verification. Existing dist-action is not owned; generated
bytes must match its initial tracked version. No shared caches or Docker used.
