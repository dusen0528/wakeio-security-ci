# P0 source performance baseline

This measures the built-in `runSource({ root, tools: [] })` API only. It is not end-to-end product latency or an accuracy estimate for production repositories. No detector, expectation, source engine, cache, worker or incremental analysis changed.

## Reproduce

Use Node 22 or newer. Install only WakeIO's locked dependencies and build WakeIO:

```sh
npm ci --ignore-scripts --no-audit --fund=false
npm run build
git clone --no-checkout https://github.com/OWASP/NodeGoat.git /tmp/wakeio-perf-nodegoat
git -C /tmp/wakeio-perf-nodegoat checkout --detach c5cb68a7084e4ae7dcc60e6a98768720a81841e8
PERF_CHECKOUT="$(cd /tmp/wakeio-perf-nodegoat && pwd -P)"
npm run benchmark:perf -- --checkout "$PERF_CHECKOUT" --runs 30 --profile
```

Use an absolute, real checkout path (on macOS `/tmp` resolves to `/private/tmp`). Do not install, build, serve or execute NodeGoat or the corpus fixtures. `verifyCheckout` checks the pinned commit/tree, every tracked blob and executable mode, expected SHA-256 values, and absence of extra files, symlinks and submodules. Missing/mismatched M input exits 2; it is never a successful skipped tier. Default output is `benchmarks/results/perf.json`; `--out-dir` changes it. Default `--runs` is 5; only integers 1–50 are accepted. CI may run the five-repeat smoke but must not use wall time as an absolute performance gate.

## Boundaries and interpretation

- S is one sequential suite of all 56 cases in manifest order, each with an independent prepared root. The case count is loaded from the corpus, never hardcoded by the harness.
- M is the whole pinned NodeGoat checkout, using default collection/analysis settings. Unlike `benchmark-oss.mjs`, this harness does not inherit `extended`, 10,000 files or 128 MiB.
- L generates 1,001 shallow TypeScript files with fixed seed 20528, one above the engine's default 1,000-file limit. The generator uses an unsigned 32-bit LCG and writes inert constant exports. Temporary inputs are removed in `finally`.
- Copying, generation, checkout verification, full-input hashing, collection-manifest preparation, output writing and cleanup are outside latency intervals. Preparation reads the inputs, so these are **not OS-cache-cold measurements**.
- **process-cold:** new Node child per sample; parent clock starts immediately before fork and ends on receipt of raw analysis results. Includes process startup, module loading, the analysis suite, serialization and IPC transfer. Excludes parent normalization/hashing and waiting for child exit.
- **warm:** a new process per tier imports the engine, runs one unaggregated preparation suite, then repeats the suite N times. Only the sequential `runSource` calls and their result accumulation are timed. Signature normalization between repetitions is excluded. No explicit GC or JIT control is imposed.
- RSS is Node `resourceUsage().maxRSS`, in KiB, reported by each child. Cold has one lifetime high-water mark through result send per child. Warm has a single whole-process lifetime high-water mark, including warmup and bookkeeping; it is not an independent peak per warm iteration. Parent RSS is not reported as child RSS.
- Percentiles use nearest rank: `sorted[ceil(p*n)-1]`, no interpolation. With n=30, p50 is the 15th and p95 the 29th ordered value.
- Finding signatures are sorted/deduplicated tuples of case ID, rule ID, relative path and line. Determinism also compares check status/metrics, collection completion/reasons, exact collected snapshot digest (file paths and content), applied budgets, gaps and code coverage. Warmup and profile results participate in the same comparison but not latency statistics. The prepared collector manifest is checked against actual `runSource` snapshot evidence.
- Error/empty/missing/skipped checks cannot pass simply by repeating identically. Unexpected collection/read/parse errors fail. Only the deliberate file-limit incompleteness is allowed for L. M's recorded model limitations remain partial analysis, even when measurement and determinism succeed. Meaningful drift is `nondeterministic`, exit 2. Child execution failure also exits 2.
- `--profile` starts separate S/M process-cold children with `--cpu-prof`, excluded from latency statistics. Leaf samples are weighted by `timeDeltas`, summarized as at most ten self-time functions. Fewer than 100 samples is flagged as insufficient. CPU sample percentages do not prove causes of total wall time.

## Accuracy and tests

Strict accuracy at BASE_SHA and after implementation: 56/56 completed cases, TP 27, FP 0, FN 1 (the existing known unsupported case), supported FN 0, strict exit 0. Entire summary objects match. The older accuracy benchmark's durations include fixture work and are not used as performance results.

- Original 1,521 tests in the prepared environment: 1,515 pass, 0 fail, 6 skip.
- `npm test` with the nine added performance tests: 1,524 pass, 0 fail, 6 skip (1,530 total).
- Six skips: two opt-in live provider tests and four unprovisioned real Nuclei tests. This is not a full release-check run.
- Two independent `--runs 5` smoke runs produced identical S/M/L input and result digests. Smoke timings overlapped other work and are not the official baseline.
- New tests cover nearest-rank edge cases; CLI range/exit 2; case-aware deduplication; finding/state/collection/budget drift; repeated empty/errors; seeded L reproducibility and unexpected errors; actual IPC and warmup; profile self-time; and mandatory M checkout preparation guidance.
- `git diff f18b75bb0731e71620f8638c1b3482d91139d9b2 -- src/` is empty.

Initial macOS test attempts were environment failures at the unmodified base: default Python 3.9.6 gave 26 failures; providing the existing Python 3.12.3/Schemathesis environment reduced this to eight repair failures. Repair intentionally sanitizes PATH, selecting system Python 3.9 without `tomllib`; putting an identical Node 22.23.1 executable and Python 3.12.3 beside each other in a local test-runtime directory made the base and changed suites pass. This ruled out the performance change as the cause and showed that changing caller PATH alone was insufficient. No product code was changed to fix the test environment.

For macOS test reproduction, prepare Schemathesis using `WAKEIO_BOOTSTRAP_PYTHON=<Python-3.12-executable> node scripts/bootstrap-schemathesis.mjs`. If system Python is older than 3.11, use a private directory containing a copy of the Node executable and a `python3` symlink to Python 3.12; prepend that directory to PATH when running `npm test`. Keep this test-only setup outside tracked files.

Raw local evidence lives under ignored `benchmarks/results/`: `p0-before/` (initial, prepared, isolated-base test logs and strict accuracy), `test-after.log`, `perf-tests.log`, `p0-after/accuracy/`, `p0-smoke-1/`, `p0-smoke-2/`, and `smoke-reproducibility.json`. Raw logs can contain local paths; they and original CPU profiles are not committed.

## Official measurement — 2026-10-15

Run window: 15:28:01–15:28:58 KST (includes the preceding WakeIO build); measurement metadata created at 2026-10-15T06:28:06.256Z. The release session recorded heavy validation complete at 15:25:59 KST, with no remaining local build/test/packaging. Process snapshots before/after found no overlapping release test/build/package workload. Normal desktop applications remained running; this is a quiet developer-machine baseline, not a dedicated isolated performance host. CPU idle snapshots were 80.62% before and 84.59% after; background activity within the interval was not continuously instrumented.

Environment: Apple M5 Pro, 15 logical cores, 48 GiB memory, macOS/Darwin 25.6.0 arm64, Node v22.23.1.

- BASE_SHA: `f18b75bb0731e71620f8638c1b3482d91139d9b2` (verified in remote `origin/dev` before branching).
- Measured HEAD: `aec620228585a0e4c8bbabd33d75fdbc4f027d65`; dirty: `false`. Subsequent baseline-document commit does not change the measured harness/engine.
- Scope: `runSource({ root: <each prepared case>, tools: [] })`; every other option omitted. Effective collection and AST budgets are retained in the reference state and compared for every execution.
- Exact recorded output: `benchmarks/results/p0-official/perf.json`; local original profiles: `benchmarks/results/p0-official/S.cpuprofile` and `M.cpuprofile`. Run log, exit code, release-completion evidence and system snapshots are in the same ignored directory.

| Tier | Mode | n | min ms | p50 ms | p95 ms | max ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| S | process-cold | 30 | 328.850 | 339.525 | 367.498 | 381.580 |
| S | warm | 30 | 31.662 | 37.742 | 52.062 | 58.613 |
| M | process-cold | 30 | 559.912 | 571.320 | 598.993 | 609.417 |
| M | warm | 30 | 202.415 | 218.746 | 260.205 | 263.278 |
| L | process-cold | 30 | 358.602 | 369.486 | 391.960 | 453.559 |
| L | warm | 30 | 82.565 | 85.383 | 105.547 | 109.147 |

The two modes have different timing boundaries. Their difference is not a measured cache/worker speedup. S is a suite duration, not per-file or per-case time. All 30 cold and 30 warm samples per tier, three unaggregated warmups and two profile runs were deterministic; exit 0. S collection and checks completed. M collection completed but AST analysis remained partial (`module_export_unsupported`, 44 JS files parsed without syntax errors). L collected 1,000/1,001 files with the expected `file_limit`; its collected AST analysis completed. These coverage limits are not suppressed by the successful measurement exit.

| Tier | All input files | All bytes | Collected files | Collected bytes | Cold child lifetime maxRSS range, KiB | Warm process lifetime maxRSS, KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| S | 61 | 8905 | 61 | 8905 | 166064–169280 | 332640 |
| M | 111 | 2976004 | 86 | 1147726 | 193664–204688 | 263600 |
| L | 1001 | 35664 | 1000 | 35628 | 166592–168432 | 265568 |

Whole input excludes `.git` metadata only. Collected size follows the actual default allowlist and limits; ignored NodeGoat files are included only in whole-input size. Warm RSS includes retained harness evidence and GC behavior, so it must not be used as the engine-only peak or extrapolated as per-scan memory.

### CPU sample self time

**S**: 267 samples, 361042 μs sampled; insufficient-sample flag: `false`. Single profile run, including startup and result transfer; the small sample set is exploratory, not a stable per-function benchmark.

| Function | Source | Self μs | Sampled share |
| --- | --- | ---: | ---: |
| `detectModuleFormat` | `node:internal/modules/esm/get_format:36` | 59583 | 16.50% |
| `parseSource` | `node:internal/deps/cjs-module-lexer/lexer:85` | 41166 | 11.40% |
| `compileSourceTextModule` | `node:internal/modules/esm/utils:344` | 18958 | 5.25% |
| `parseCJS` | `node:internal/deps/cjs-module-lexer/lexer:40` | 18958 | 5.25% |
| `(garbage collector)` | `:0` | 10208 | 2.83% |
| `(program)` | `:0` | 9708 | 2.69% |
| `evalExpression` | `file://<repo>/build/src/source/dataflow.js:3102` | 7457 | 2.07% |
| `runBuiltinAst` | `file://<repo>/build/src/source/ast.js:456` | 5876 | 1.63% |
| `(anonymous)` | `node:internal/modules/esm/translators:231` | 5751 | 1.59% |
| `(anonymous)` | `file://<repo>/build/src/source/collector.js:311` | 5292 | 1.47% |

**M**: 490 samples, 626833 μs sampled; insufficient-sample flag: `false`. Single profile run, including startup and result transfer; the small sample set is exploratory, not a stable per-function benchmark.

| Function | Source | Self μs | Sampled share |
| --- | --- | ---: | ---: |
| `detectModuleFormat` | `node:internal/modules/esm/get_format:36` | 59458 | 9.49% |
| `parseSource` | `node:internal/deps/cjs-module-lexer/lexer:85` | 49752 | 7.94% |
| `dataObject` | `file://<repo>/build/src/static-context.js:9` | 29708 | 4.74% |
| `(garbage collector)` | `:0` | 20999 | 3.35% |
| `redactSecrets` | `file://<repo>/build/src/report-path.js:4` | 20377 | 3.25% |
| `parseCJS` | `node:internal/deps/cjs-module-lexer/lexer:40` | 16915 | 2.70% |
| `compileSourceTextModule` | `node:internal/modules/esm/utils:344` | 16458 | 2.63% |
| `mergeStaticContexts` | `file://<repo>/build/src/static-context.js:56` | 15749 | 2.51% |
| `safeRelativePath` | `file://<repo>/build/src/report-path.js:29` | 12666 | 2.02% |
| `(anonymous)` | `file://<repo>/build/src/static-context.js:52` | 12166 | 1.94% |

### Follow-up candidates, not implemented

1. Measure module initialization separately and evaluate reducing repeated entry-module loading for batch scans. `detectModuleFormat` and `parseSource` account for 27.91% of S and 17.42% of M sampled self time. Cold/warm also differ in JIT, GC and IPC, so their latency difference cannot be assigned wholly to loading or promised as a speedup.
2. Add stage/call-count measurements around static-context validation/merging before considering reuse. In M, `dataObject` is 4.74% and `mergeStaticContexts` 2.51% of sampled self time. Any future change must preserve boundary validation and finding/coverage determinism. These samples alone do not establish a wall-time bottleneck.

### Fingerprints and digests

SHA-256 values use JSON-framed sorted paths/content for input manifests. The build fingerprint covers all 210 emitted files under `build/src` (2,240,118 bytes). The actual collected snapshot digest separately covers paths, categories, sensitivity, bytes, content and budget.

- build: `4af93e2f064fad6f37ec6b12ec4f5b1d5e0040f130ec1f11465498a5c0671a0b`
- packageLock: `033e0ef135f3e6c112d806af5a4bcc267ce3152119397e4fdd8d842b5ca4f96b`
- typescript: `3ae902c92cc44dace175c0e69e13a4b0899f6983c6121d76b9ab8dd5795e7675`
- harness: `541478486b0c1bf676cebc5d12c0e21d126c87aa5f64c43483efe0269cf048db`
- corpus: `4f793bd201233b1b97e06bede571700135f8bf9244d603861cbcba975c362f70`
- ossCorpus: `eadd5883b9f7a92b455d42af66947418bb2dfed4b5b7ea5d34bc823796a84e94`
- S input: `0ab4dda32f2e80e7c8beb41cd3294515d0e700d8a2b07707e555d7e57e86e67d`
- S semantic result: `a6cb39d70f542b58b6e1b88516017cc83b51dbb380254125a02dfc6802e5122e`
- M input: `01a259913349158e17ba9cd6012dddffb5ea8aad1d79c489ac19e28e2d23d168`
- M semantic result: `93f8f56d1d8e9234454c91c7b7875353f32a24ec123a673caf386667cd6ebe4e`
- L input: `4feb3ec35a1bf336fe002cbf5ee6060d09c1068e8d3486e191156abf2549c75f`
- L semantic result: `02c08cb9f35632847e6f82e4a0cca93c8c6a795d8a111e18276310e5b3db8967`

### Time samples in execution order

Display rounded to 0.001 ms; the local JSON retains the original numeric samples and per-child RSS values. These are the measured samples, excluding warmup/profile runs.

S process-cold:

```text
367.331, 343.533, 341.297, 343.553, 367.498, 381.580, 358.429, 339.525, 353.506, 332.746, 338.448, 341.054, 334.304, 332.029, 340.598, 328.850, 336.260, 340.219, 330.151, 342.480, 337.265, 332.265, 336.463, 338.185, 338.998, 337.094, 343.342, 355.379, 330.659, 359.578
```

S warm:

```text
58.613, 46.574, 45.907, 51.240, 45.278, 39.931, 37.107, 43.974, 42.034, 41.401, 52.062, 41.949, 39.858, 41.793, 36.444, 34.030, 37.993, 36.690, 37.742, 34.715, 35.435, 34.594, 33.836, 40.280, 33.623, 35.300, 32.531, 32.366, 31.662, 33.359
```

M process-cold:

```text
572.261, 571.790, 568.289, 571.320, 573.779, 573.353, 561.766, 571.199, 598.993, 571.033, 574.164, 570.318, 563.473, 579.249, 571.240, 571.953, 572.742, 594.953, 570.082, 580.956, 566.325, 566.014, 578.137, 570.672, 563.893, 574.998, 559.912, 573.387, 570.261, 609.417
```

M warm:

```text
254.957, 234.216, 217.817, 211.240, 210.588, 212.229, 229.704, 226.603, 212.674, 225.578, 219.471, 219.674, 214.971, 218.960, 226.708, 218.022, 218.285, 224.967, 218.746, 218.517, 215.468, 213.514, 211.963, 220.198, 215.238, 263.278, 229.277, 202.415, 260.205, 225.477
```

L process-cold:

```text
373.246, 453.559, 388.203, 369.642, 391.960, 370.226, 372.448, 367.399, 370.512, 376.852, 363.234, 370.996, 368.060, 360.916, 375.515, 374.336, 367.798, 362.374, 369.644, 364.897, 390.703, 364.869, 358.602, 361.349, 360.269, 374.131, 369.486, 358.955, 362.802, 360.959
```

L warm:

```text
105.547, 92.399, 92.203, 95.127, 89.142, 84.901, 84.911, 109.147, 82.565, 84.022, 83.252, 84.973, 92.997, 84.352, 83.970, 87.150, 84.498, 88.041, 85.383, 90.473, 92.468, 86.386, 84.022, 83.711, 82.578, 85.911, 89.182, 89.406, 84.275, 84.164
```

