# Express response classification evaluation — 2026-10-14

The source-only regression retained all 98 previously reviewed finding sites.
Express's 86 HTML-labelled candidates moved to machine-readable
`ast:response-input-sink`, with unresolved receiver, payload dispatch, MIME and
runtime request origin. No candidate was removed, no gate improved, and no
vulnerability was confirmed. The useful change is clearer agent triage:
verify the binding, caller, payload and headers before choosing a repair.
This is classification improvement, not measured false-positive reduction.

## Inputs and predeclared scope

The trusted baseline was `823c42b39f51e8c2b6585799cc95387bd113cae8`, built with
Node 22.22.1. The after engine was the uncommitted response-classification patch
copied at the owner's final build handoff, not a released package or invented
commit. Each frozen engine had 85 built-source JavaScript files and 456 files
including identical trusted runners/parser/dependencies. Sorted
path-to-JavaScript-hash manifest SHA-256 values were:

- Baseline: `a309e25b774aaf49c48ca75adbdfe143bf9891430074c0257232530b7373620d`.
- After: `6b01b3538515fe29b857122b5440ac7509a82d3e9071a94b45094f364300630a`.

The unchanged [production manifest](../../benchmarks/production-oss-corpus.json)
(`dff6e694374aaaf10f68f3f457a7e76fa33bf19470db6d60fc7d88e47781f6ec`)
reused these MIT source checkouts:

| Source | Commit | Tree |
| --- | --- | --- |
| [Express v5.1.0](https://github.com/expressjs/express/tree/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4) | `cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4` | `234b224fd3074adb169a0da0619b624a070a0517` |
| [Umami v2.19.0](https://github.com/umami-software/umami/tree/60eaaaff60a38efb3c779a250742187ec9201944) | `60eaaaff60a38efb3c779a250742187ec9201944` | `fbb639330def9805000da7bee1a5329468d8d504` |

Whole tracked trees and absence of extra files were verified before and after
scanning. Roots, exclusions, `tools: []`, extended profile, 10,000-file / 128 MiB
collection limits and five controls were unchanged; full budgets are in the
[original trial](production-source-trial-2026-10-14.md). No target dependency
installation, import, build, test, server, DAST or provider call ran.

The original 33 counterexample sites were frozen: boolean 8, derived array 15,
container 3, mapped array 6 and dynamic-index/prototype 1. That historical
manifest remains intact; it does not force suppression or universal type proof.
Before after outputs, a separate acceptance manifest froze all 98 locations,
source anchors, severity/gate expectations and the rule/triage migration.

## Full-row result and limitations

| Measure | Before | After |
| --- | ---: | ---: |
| Express candidates | 94 | 94 |
| Express HTML / unqualified response rules | 86 / 0 | 0 / 86 |
| Express redirect candidates | 8 | 8 |
| Umami SQL / server-request candidates | 3 / 1 | 3 / 1 |
| High-threshold blocking rows, Express / Umami | 86 / 4 | 86 / 4 |
| AST status, both projects | partial | partial |
| Scan exit, both projects | 2 | 2 |

All 98 path/line/column positions and complete static-flow objects matched;
new sites 0, missing sites 0. The other 12 finding objects were unchanged.
All 86 migrated candidates stayed high/candidate and became or remained low
confidence: 27 changed from medium, 59 were already low. All descriptions
explicitly preserve binding/dispatch/MIME/origin uncertainty; all remediation
texts ask for verification first and make HTML encoding conditional. The 33
historical counterexample sites retain their candidates without the definite
HTML classification. Type proof and suppression were not added.

Finding IDs and comparison keys changed for all 86 migrated rows. Every pair is
mapped by source anchor and exact location; this is not a repair or
`not_observed` receipt. The qualified `ast:html-input-sink` rule remains distinct,
without adding a public schema field. Two canonical report/agent-report pairs
and 98 projected rows were verified. After mapping IDs, both scan gates,
reasons and blocking memberships were unchanged.

Collections remained complete: Express 182 files / 733,183 bytes, Umami 862 /
5,726,461. Both indexes were complete with zero parse errors. Existing
`module_export_unsupported` gaps remained Express 226 events / 156 dropped and
Umami 144 / 86. Partial providers still contribute zero completed code inputs
out of 142 / 536; this does not mean those files were unread. Five controls
remain `unevaluable_scope` with zero overlapping candidates, not passing
negative scans. Benchmark exit remains 2.

This is a same-team, model-assisted regression review, not an independent
security audit or held-out efficacy study. The prior 421 source-reference hashes
were rechecked. Pinned [boolean getters](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/request.js#L451-L487)
and [response dispatch](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/response.js#L123-L157)
show why a definite HTML label can overstate the source evidence. The
[JSON method](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/response.js#L237-L251)
preserves an existing Content-Type, so blanket object/JSON suppression would
also be too strong. These are source observations, not runtime safety proof.

This checkout uses relative first-party Express loads, so all 86 are
unqualified under the bounded literal-Express entry model. The trial measures
no qualified positive; practical accuracy of that model remains unestablished.
Opaque middleware/callers, parser/prototype changes, payload and MIME remain
unknown. The next useful detection improvement needs bounded binding/payload/
header evidence; CI burden has not changed.

## Synthetic migration and reproduction

The frozen v4 baseline and [v5 corpus](../../benchmarks/corpus.json) both measured
56 completed / 0 incomplete cases, TP27 / FP0 / FN1 including the unchanged
known miss, supported FN0 and strict exit0. Only version and four expected
rule IDs changed; all fixture bytes, source locations, support and labels were
preserved. The [migration contract](../../benchmarks/README.md#corpus-v5-response-binding-classification-migration)
lists direct/template/receiver/status cases. V4 SHA-256 is
`bc815bea491d1e4164f44b778e25546decdfef60c100748b9ef2bb8a9ac256be`;
v5 is `4f793bd201233b1b97e06bede571700135f8bf9244d603861cbcba975c362f70`.
Raw results are not a same-corpus comparison. Applying only those four
case-specific rule mappings makes every complete expected/observed finding
list, coverage, check status and count identical. This is classification
continuity, not detection improvement or real-project precision/recall.

Use trusted builds of the baseline above and final patch, untouched OSS
checkouts pinned to the listed commits/trees, Node 22.22.1 and fresh outputs:

```sh
NODE22=/absolute/path/to/node-v22.22.1
BASELINE=/path/to/trusted-baseline-wakeio
CURRENT=/path/to/trusted-after-wakeio
EXPRESS=/path/to/pinned-express-source
UMAMI=/path/to/pinned-umami-source
OUTPUT=/path/to/fresh-output-parent

"$NODE22" "$BASELINE/scripts/benchmark-oss.mjs" \
  --manifest "$CURRENT/benchmarks/production-oss-corpus.json" --profile extended \
  --checkout "express=$EXPRESS" --checkout "umami=$UMAMI" --out "$OUTPUT/oss-before"
"$NODE22" "$CURRENT/scripts/benchmark-oss.mjs" \
  --manifest "$CURRENT/benchmarks/production-oss-corpus.json" --profile extended \
  --checkout "express=$EXPRESS" --checkout "umami=$UMAMI" --out "$OUTPUT/oss-after"
"$NODE22" "$BASELINE/scripts/benchmark.mjs" --strict \
  --engine-module "$BASELINE/build/src/index.js" \
  --corpus "$BASELINE/benchmarks/corpus.json" --out-dir "$OUTPUT/synthetic-v4"
"$NODE22" "$CURRENT/scripts/benchmark.mjs" --strict \
  --engine-module "$CURRENT/build/src/index.js" \
  --corpus "$CURRENT/benchmarks/corpus.json" --out-dir "$OUTPUT/synthetic-v5"
```

Preserve raw results. Map production rows through source anchors and exact
locations; normalize only the four declared synthetic rule migrations before
comparing complete site lists and coverage. Private ignored receipts under
`artifacts/express-response-semantics-2026-10-14` contain frozen engines,
predeclared locks, all four raw result sets, `after-row-review.json`, canonical
gate/projection verification and `synthetic-normalized-comparison.json`.
Unvalidated full findings are not published. Engine files were verified before
and after execution. OSS wall times were 4.091 seconds before and 8.876 after;
the latter overlapped the integrator's build/tests, so this is not a performance
comparison. Package publication, customer repairs and OSS runtime verification
are outside this record.

The first PR56 [release-check verify run](https://github.com/dusen0528/wakeio-security-ci/actions/runs/38492010103/job/115619159122) at feature SHA `f540951c0a4a831644d6b131822e194552730b36` failed explicitly with `tests:timeout`: buffered build completion was 00:46:53.913 UTC and the timeout was 00:49:53.941, matching the 180-second aggregate test-stage watchdog. The same SHA completed all 1309 tests with zero failures, cancellations or skips in [push self-test](https://github.com/dusen0528/wakeio-security-ci/actions/runs/38491967948/job/115619018310) (142.62 seconds) and [PR self-test](https://github.com/dusen0528/wakeio-security-ci/actions/runs/38492010062/job/115619160015) (168.70 seconds). The PR success left only 11.30 seconds below the old cap. Only the trusted full-suite stage allowance was raised to a fixed 270000 ms (4.5 minutes); the outer seven-minute step and individual test, engine, request, cancellation, cleanup and zero-skip contracts remain unchanged. This corrects aggregate CI capacity, not detector behavior or a proven individual-test defect. The failed run remains evidence; the adjusted revision requires a fresh complete verification.
