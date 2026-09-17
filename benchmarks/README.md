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

Metrics are synthetic and scoped to these fixtures and the selected runtime. Precision, recall, and false-positive counts are regression signals; they are not production accuracy, coverage, safety, or framework compatibility claims. Python semantics, real framework runtimes, network behavior, authentication, package installation, and build behavior are outside this JS/TS corpus and are listed in every report. The two cross-function and cross-file SQL cases are deliberately marked `known_miss` so the report keeps those limits visible while preserving a clear supported denominator.
