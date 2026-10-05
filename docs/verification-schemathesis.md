# Schemathesis fixture patch verification

2026-10-03 KST. Base: `dad74a0650df74864ddc7204cd6126a7f45aa04a`.
Local branch: `codex/schemathesis-fixture`.

The supplied ZIP was treated as source material. Its seven SHA256SUMS entries
matched, and its patch passed `git apply --check` against the local base before
integration. Its reported 153/153 is a previous-environment result, not reused
as current evidence. The inspected base currently contains 144 tests; the dated
99/99 in `verification-0.3.md` is historical evidence.

## Changes made after inspecting the supplied patch

1. Parent-only `child.kill` became isolated POSIX process-group termination,
   awaiting close and terminating background group members on normal exit too.
   Process tests cover running cancellation, timeout, stdout overflow and normal
   parent exit with a real child process. Linux zombies are treated as terminated
   while OS PID 1 retains responsibility for orphan reaping.
2. Direct final-path writes became temp-file write/fsync, atomic no-overwrite
   publication, directory fsync and identical-byte retry. Same-key concurrent
   publication creates one complete artifact; changed bytes conflict. Storage
   errors reject delivery; no automatic execution retries are introduced.
3. An opaque `response_contract` record now contains `GET /items`, the actual
   rule `response_schema_conformance`, `/count`, expected `integer`, actual type
   `string`, and violation kind `type_mismatch`. Values/messages remain excluded.
4. Artifacts record Python/Hypothesis/JSONSchema/Werkzeug and Node versions,
   along with engine version and worker/schema/lock digests. Safe generated
   quantity inputs permit exact synthetic case replay with a changed seed.
5. Tests cover invalid raw worker jobs, credentials excluded from subprocess
   environment, worker job mutation, scope and metadata injection, delivery
   retry/conflict/concurrency and publication-failure cleanup. Added venv/cache
   exclusions keep installed engine files out of source collection/inventory.
6. A required-engine test entrypoint fails when the Python engine is unavailable;
   ordinary optional-engine skips cannot be mistaken for completion.

## Measured results

Environment: macOS arm64, Node 23.6.0, Python 3.12.13, Schemathesis 4.2.0,
Hypothesis 6.168.3, JSONSchema 4.26.0, Werkzeug 3.1.3.

| Check | Result |
| --- | --- |
| `npm run test:schemathesis` | TypeScript + generated Action bundle build; **163/163 pass**, 0 failed, 0 skipped |
| Earlier focused API/worker checks | 37/37 pass, 0 skipped; subsequent API running-cancel test included in full 163 |
| Missing required-engine executable | Test entrypoint exit 2 before running/skipping tests |
| Real fixture generation | Broken: all selected responses violate schema; fixed: selected checks pass |
| Installed npm package | Offline install with lifecycle scripts disabled; broken 3 requests/3 contract failures; fixed 3 requests/0 failures |
| Artifact integrity | Persisted SHA-256 equals returned digest; worker/schema/lock hashes equal installed package files; no secret canary |
| Exact input replay | Stored safe quantities reproduce records after changing seed, and replay CLI checks implementation/record equivalence |
| Existing strict benchmark | Exit 0, no strict regressions; remains a source-analysis corpus, not live DAST accuracy |

`163` is the number of Node test cases, not vulnerabilities found or full service
coverage. Several cases group many boundary checks; five cases need the actual
Python environment. Full test evidence is `artifacts/schemathesis-full-tests.txt`;
installed-package evidence is `artifacts/schemathesis-installed-verification.json`.
These ignored local artifacts are included in the review ZIP with redacted
broken/fixed examples. Completion criteria and run/replay commands are in
[schemathesis-fixture-worker.md](schemathesis-fixture-worker.md).

## Evidence limits

The execution used synthetic fixtures only. The added Schemathesis fixture
worker does not prove authentication/session/authorization workflows, live
DAST, ZAP, GraphQL, production security or an arbitrary-code sandbox. POSIX group
supervision cannot contain hostile code that escapes its group. Crash-time
unpublished temporary files may remain; no partial final JSON is published.
Exactly-once remote execution and OS crash recovery were not tested. Hashes
record metadata, not dependency supply-chain attestations. GitHub-hosted CI was
not run; no push, PR, npm publication or deployment was performed.

Pre-existing community documents were preserved. An independently appearing
`self-test.yml` change was preserved and excluded from the generated patch;
its execution is not part of these verification claims.
