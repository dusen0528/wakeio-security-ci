# Synthetic source benchmark

Running the benchmark requires the full source checkout or source archive. The npm runtime archive includes this guide, but does not include the corpus, fixtures, or test runner.

This directory contains an inspectable JavaScript/TypeScript regression corpus for the public `runSource` API. The fixtures are small source files with no real credentials, network targets, package installation, or customer data. `corpus.json` records each case's classification, synthetic handler shape, reason it is vulnerable or fixed, and the expected rule ID and source location. The fixture labels describe code patterns only; they do not claim that a real Next.js, React, Supabase, or other framework runtime was exercised.

Build the package first, then run the benchmark from the repository root:

```sh
npm run build
node scripts/benchmark.mjs
```

The command writes `benchmarks/results/benchmark.json` and `benchmarks/results/benchmark.md`. Pass `--out-dir DIR` to keep results elsewhere. The Markdown and JSON reports include the corpus version, explicit runtime label and version source, measured duration, covered rule IDs, TP/FP/FN counts, and the known unsupported scope. They show both supported-only recall and all-corpus expected recall, where the latter includes known misses.

The harness calls only `runSource({ root, tools: [] })` from the selected trusted engine module. It copies each fixture into a temporary directory and removes that directory after the case. It never imports, installs, builds, tests, or executes fixture code. `--engine-module PATH` selects another trusted local package build, which allows before/after comparisons:

```sh
node scripts/benchmark.mjs \
  --engine-module /path/to/old-package/build/src/source.js \
  --engine-label frozen-v0.1 \
  --out-dir /tmp/wakeio-benchmark-old

node scripts/benchmark.mjs \
  --engine-module ./build/src/index.js \
  --engine-label current-build \
  --out-dir /tmp/wakeio-benchmark-current
```

The script also exports `runBenchmark(runSource, options)` for a programmatic comparison. The caller supplies a trusted public `runSource` function and may provide `options.engine = { label, version, versionSource, modulePath }`; the returned report is the same schema written by the CLI.

Default execution exits 0 when every case was measured successfully, even when supported expectations have false positives or false negatives. `--strict` exits 1 when a supported expectation regresses (`FP + supported FN > 0`); known misses do not silently disappear, but they are excluded from the supported false-negative denominator and listed separately. A malformed corpus, missing engine, incomplete scan, or report write failure exits nonzero and is not converted into a clean benchmark report.

Metrics are synthetic and scoped to these fixtures and the selected runtime. Precision, recall, and false-positive counts are regression signals; they are not production accuracy, coverage, safety, or framework compatibility claims. Python semantics, real framework runtimes, network behavior, authentication, package installation, and build behavior are outside this JS/TS corpus and are listed in every report. Corpus `2026-10-05.synthetic-js-ts.v2` promotes the two historical cross-function/cross-file SQL misses to `supported` expectations under ruleset `2026-10-05.1`. Their IDs, fixture bytes and sink positions remain unchanged; the corpus still has 30 cases and 15 expected findings. The supported expectation denominator changes from 13 to 15, so future misses in either case fail `--strict`. Archived baseline reports and the earlier corpus remain historical evidence and are not rewritten. Resolving these fixtures does not establish real-project recall or prove a vulnerability. Generic development regressions separately exercise argument-specific local/relative-module summaries and safe pairs; see [the source flow contract](../docs/source-flow.md). Independent additional cases are acceptance tests, not a statistically blind holdout.
