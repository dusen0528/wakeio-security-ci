# OpenAPI expansion memory fix (2026-10-21)

The v2 parser bounds the source JSON but expands shared references before applying its 8192-byte body and 16-field limits. A 7.7 KB reviewed policy expands to 33,554,432 leaves and aborts a 64 MiB V8 heap during offline preflight. The fix must reject it with the existing normal error/exit-2 path before any engine, target request or run output starts.

Use the existing bounded-JSON node limit and account encoded JSON bytes while generating each seed, before allocating each child. Include object keys, punctuation, arrays, escaped/UTF-8 strings, booleans and null, including DAGs with few mutable fields. Keep a fresh budget per seed/operation; preserve valid 8192-byte/16-field bodies and the 16-operation contract. Stop the scalar flattening walk before creating a seventeenth field. No new dependency, public flag, runner/store signature or model call is needed.

Increasing the heap would only delay exhaustion. A separate production worker could add process isolation for a broader parser service later, but is unnecessary to close this bounded expansion bug. Resource limits on subprocesses are used here to prove the regression safely, not as the parser's primary defense.

1. Add bounded-child regressions for shared-reference string/boolean/null/object and array shapes, plus real public plan/scan/run-plan refusal with zero owned-target requests. Verify they fail on the merged baseline.
2. Add incremental limits in the shared seed generator and immediate field rejection. Verify the regressions, exact byte boundaries, encoded bytes, normal nested reconstruction and per-operation independence.
3. Run actual ZAP/session integration and the required zero-skip engine suite, contract checks and installed-package regression. Update the v2 operator contract and changelog, then open a follow-up PR against dev. No merge, publication or deployment is included.

Success: amplified invalid input is a normal bounded rejection under a 64 MiB V8 heap; source analysis, authenticated actual ZAP and common artifact/request gates remain unchanged. Test inputs are public synthetic data; active requests use only the previously authorized owned loopback fixtures.

## CI follow-up and performance validation

The same memory-fix SHA passed the Linux release gate and PR package gate on rerun. The remaining push gate failed a separate owned-write oracle: its 700 ms end-to-end pilot budget expired before the injected peer-response loss. Reproduce with an 800 ms earlier read delay, then use the existing 3000 ms pilot budget and destroy the peer response only after the actual handler commits. Keep fault-observed, exactly-one peer PATCH, preserved side effect/high finding, exit 2 and no-request-after-abort assertions unchanged. Product request/deadline limits and ZAP version checks remain unchanged; no test is skipped.

After that fix, the PR package and release checks passed; the push package suite reached its 480-second aggregate watchdog with no failed assertions during the final actual ZAP controls. Give the aggregate suite 540 seconds and its workflow step 10 minutes (including install/build/contracts). Per-test, engine, request, cancellation and process cleanup bounds stay unchanged; successful runs finish immediately rather than waiting for the watchdog.

A later push run completed all 1603 tests but again returned `unsupported_engine_version` at 30 seconds during a supported ZAP startup. Reproduce with a 31-second version response and a 40-second total scan budget. Remove the separate 30-second cutoff and reuse the remaining shared scan deadline, as active execution already does. Distinguish exhausted/cancelled readiness (`engine_version_incomplete`) from a genuine wrong version. Verify the slow supported engine completes, and hanging/cancelled readiness sends zero target requests. A hung version check may now use the configured total timeout; no new total time/request authority is granted. Require both readiness regressions in the structured zero-skip receipt.

Measure the compiler before/after on identical valid query, nested JSON and boundary-size inputs, including 16 independent operations. Check exact output equality, alternate paired execution order over 30 rounds after warmup, retain p50/p95 and environment metadata. Report compiler-only overhead separately from full ZAP/network latency; these measurements cannot establish general end-to-end speed or a whole-process RSS ceiling. Merge only after every final-head GitHub check succeeds.
