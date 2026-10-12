# Synthetic source benchmark

Running the benchmark requires the full source checkout or source archive. The npm runtime archive includes this guide, but does not include the corpus, fixtures, or test runner.

This directory contains an inspectable JavaScript/TypeScript regression corpus for the public `runSource` API. The fixtures are small source files with no real credentials, network targets, package installation, or customer data. `corpus.json` records each case's classification, synthetic handler shape, reason it is vulnerable or fixed, and expected rule ID and source location. These labels describe static code patterns; they do not establish exploitability or claim that a real framework runtime was exercised. A fixed case is a negative control for its declared pattern, not a whole-application safety claim.

Build the package first, then run the benchmark from the repository root:

```sh
npm run build
node scripts/benchmark.mjs
```

The command writes `benchmarks/results/benchmark.json`, `benchmark.md`, and `benchmark-failures.json`. Pass `--out-dir DIR` to keep results elsewhere. The reports include the corpus version, runtime label and version source, duration, rule IDs, TP/FP/FN counts, case completion states, and known unsupported scope. The failure artifact selects cases with an FP, an unobserved expectation (including a known miss), or incomplete coverage. It records fixture IDs/paths, expected/observed/missed/unexpected signatures and check statuses, without copying source, check notes or engine exception messages. Reproduce a case using its checked-in fixture and the same corpus and trusted engine; fixture code must remain unexecuted.

## Primary metrics and incomplete scans

Report schema `2.0.0` makes `truePositives`, `falseNegatives`, `precision`, and `recall` include **all** expected findings, including `known_miss`, consistently at summary, per-rule and case level. A detected known miss contributes to TP; an undetected one contributes to FN. Precision is TP / (TP + FP), and recall is TP / all expected findings. Empty denominators are `null`. Duplicate unmatched findings remain FPs. Fixed-case FP rate uses only the fixed-case denominator.

The explicitly named `supportedTruePositives`, `supportedFalseNegatives`, `supportedPrecision` and `supportedRecall` provide secondary supported-only accounting. Existing `allDetectedExpectedFindings`, `allFalseNegatives` and `allCorpusRecall` remain aliases for the primary totals. Consumers of schema 1 must account for the primary-field meaning change rather than assuming it still excludes known misses.

Both inventory and AST checks must be completed for a case to be complete. Partial, skipped, missing, failed or not-applicable checks retain their case evidence and make the report's `success` false. An engine exception marks that case incomplete and measurement continues with the remaining fixtures. `completedCases` and `incompleteCases` expose the coverage denominator. Unobserved expectations in incomplete cases still count as primary FNs; these counts describe the observed benchmark output, not a completed negative scan. In particular, an incomplete fixed case with no findings is never represented as completed clean. Findings already returned by a partial scan are preserved, but even perfect observed recall cannot make incomplete coverage successful.

Default execution exits 0 when every case was measured completely, even if findings were missed or false positives occurred. `--strict` exits 1 for `FP + supported FN > 0`; it does not require documented known misses to resolve. Incomplete runs exit 2 in either mode **after writing the incomplete report and failure artifact**. Malformed corpus/engine output, missing engine, fixture-copy errors or report-write failures also exit nonzero and are not converted into clean results. Existing reports in a reused output directory are not evidence that a failed invocation completed; use a fresh directory for an archived measurement.

## Same-corpus comparisons

The harness calls only `runSource({ root, tools: [] })` from the selected trusted engine module. It copies each fixture into a temporary directory and removes that directory after the case. It never imports, installs, builds, tests or executes fixture code. `--engine-module PATH` selects another trusted local package build, allowing before/after comparisons without changing expectations:

```sh
node scripts/benchmark.mjs \
  --engine-module /path/to/old-package/build/src/index.js \
  --engine-label frozen-baseline \
  --out-dir /tmp/wakeio-benchmark-old

node scripts/benchmark.mjs \
  --engine-module ./build/src/index.js \
  --engine-label current-build \
  --out-dir /tmp/wakeio-benchmark-current
```

The script exports `runBenchmark(runSource, options)` for programmatic comparisons. A caller supplies a trusted public `runSource` function and may provide `options.engine = { label, version, versionSource, modulePath }`; the returned report has the CLI's schema. `writeBenchmarkReports` writes the same three artifacts. The selected engine and the corpus are trusted local inputs; the runner is not a sandbox for an untrusted engine.

## Corpus v3 boundaries

Corpus `2026-10-05.synthetic-js-ts.v3` has **50 cases: 25 vulnerable and 25 fixed**, with **25 expected findings: 24 supported and 1 known miss**. It preserves the original 30 fixture sources, including the two historical local/relative-module SQL misses promoted to supported in v2. The 20 additions are ten independently authored, synthetic vulnerable/fixed pairs:

- Express string `res.send` versus JSON serialization
- Express template HTML versus fixed markup
- Express response `send` versus an unrelated local method also named `send`
- Express input through a receiver-independent method on a fixed local repository instance, with a parameterized SQL control
- Next `request.nextUrl.searchParams` SQL interpolation versus bound values
- Next query input in an explicitly HTML `Response` versus `Response.json`
- Koa `ctx.request.query` SQL interpolation versus bound values; input recognition is an explicit `known_miss`
- Relative imported SQL template helper versus fixed parameterized statement
- Aliased relative imported SQL concatenation helper versus fixed parameterized statement
- Express immediate `res.status(...).send(...)` versus `.json(...)`

These cases are acceptance/regression tests, not a statistically blind holdout. The Koa miss remains in the primary denominator and the failure artifact even if strict mode passes. The supported label is a regression commitment, not a reason to hide unsupported examples from the primary result. A newly failing supported case must be investigated rather than relabeled to make strict pass.

Compare engine revisions against the **same corpus version and fixture bytes**. Historical reports retain their original labels and denominators; do not compare the old 15-finding denominator directly with v3's 25 findings or rewrite old reports. More framework-shaped source makes this corpus more revealing, but 50 selected examples cannot measure real-project recall. Python semantics, real framework/database/browser execution, network behavior, authentication, package installation and build behavior remain outside the benchmark. Unrepresented patterns remain unknown even when all represented cases pass. See [the source flow contract](../docs/source-flow.md) for the bounded static model.
