# OpenAPI expansion memory fix (2026-10-21)

The v2 parser bounds the source JSON but expands shared references before applying its 8192-byte body and 16-field limits. A 7.7 KB reviewed policy expands to 33,554,432 leaves and aborts a 64 MiB V8 heap during offline preflight. The fix must reject it with the existing normal error/exit-2 path before any engine, target request or run output starts.

Use the existing bounded-JSON node limit and account encoded JSON bytes while generating each seed, before allocating each child. Include object keys, punctuation, arrays, escaped/UTF-8 strings, booleans and null, including DAGs with few mutable fields. Keep a fresh budget per seed/operation; preserve valid 8192-byte/16-field bodies and the 16-operation contract. Stop the scalar flattening walk before creating a seventeenth field. No new dependency, public flag, runner/store signature or model call is needed.

Increasing the heap would only delay exhaustion. A separate production worker could add process isolation for a broader parser service later, but is unnecessary to close this bounded expansion bug. Resource limits on subprocesses are used here to prove the regression safely, not as the parser's primary defense.

1. Add bounded-child regressions for shared-reference string/boolean/null/object and array shapes, plus real public plan/scan/run-plan refusal with zero owned-target requests. Verify they fail on the merged baseline.
2. Add incremental limits in the shared seed generator and immediate field rejection. Verify the regressions, exact byte boundaries, encoded bytes, normal nested reconstruction and per-operation independence.
3. Run actual ZAP/session integration and the required zero-skip engine suite, contract checks and installed-package regression. Update the v2 operator contract and changelog, then open a follow-up PR against dev. No merge, publication or deployment is included.

Success: amplified invalid input is a normal bounded rejection under a 64 MiB V8 heap; source analysis, authenticated actual ZAP and common artifact/request gates remain unchanged. Test inputs are public synthetic data; active requests use only the previously authorized owned loopback fixtures.
