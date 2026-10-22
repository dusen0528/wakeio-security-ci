# Offline KPI baseline (P0)

Measure the current trusted WakeIO source build without running a target application, HTTP scan or model. The runner reuses benchmark.mjs accuracy scoring and benchmark-oss.mjs's pinned NodeGoat checkout verifier. It does not change src/**, rules, CLI flags or gates.

## Preparation

Prepare WakeIO dependencies and build it. This is tool setup, not measurement or a target-project install.

    npm ci --ignore-scripts --no-audit --fund=false
    npm run build
    git clone --no-checkout https://github.com/OWASP/NodeGoat.git /tmp/wakeio-kpi-nodegoat
    git -C /tmp/wakeio-kpi-nodegoat checkout --detach c5cb68a7084e4ae7dcc60e6a98768720a81841e8

Use a real absolute checkout path. The runner verifies the declared commit/tree, all tracked bytes/modes and expected SHA256 values. No ignored/untracked files, symlinks or project dependency installation are allowed in that checkout. It never fetches a missing checkout.

## Measure and compare

    node scripts/kpi.mjs --checkout /ABS/REAL/NodeGoat --out /NEW/results/main
    node scripts/kpi.mjs --checkout /ABS/REAL/NodeGoat --engine-root /BUILT/WakeIO/candidate --out /NEW/results/candidate
    node scripts/kpi.mjs compare --before /NEW/results/main/kpi.json --after /NEW/results/candidate/kpi.json --out /NEW/results/diff

--engine-root selects only a trusted, prebuilt WakeIO checkout; it is not an agent-controlled executable. The same runner/corpus/runtime must measure both revisions. Output directories must not exist. No arbitrary scanner/target/URL/provider is accepted.

There are exactly three fresh npx processes. Each calls the checkout's own CLI bin with --offline --no-install, tools none and the default analysis profile. Timing starts immediately before npx spawn and stops at the first fully parseable report.json (2ms polling, with post-exit observation as an upper bound if needed). Tool installation, NodeGoat verification, fixture hashing, accuracy scoring, report validation and cleanup are excluded. “Warm” means dependencies/cache are prepared, not a warm analysis process or OS-cache-cold measurement.

Analysis time is measured separately as analysis_ms: one untimed runSource warmup, followed by three timed calls in the same process. The boundary includes source collection and built-in analysis and excludes npx/process startup, imports, report serialization and accuracy scoring. The median is compared with the base median; strictly greater than 1.5× produces a Job Summary warning only, never a failing exit code. Raw samples remain in the JSON.

The JSON records the raw timing samples, runtime environment, engine dependency-lock hash, harness/input/build digests, revision, every observed check status/reason and actual scan exit. The report's raw SHA must match agent-report.json and the current projection before evidence is accepted. Primary semantic hashing removes only top-level startedAt/finishedAt; arrays, gaps, scope and finding evidence remain.

Per-reason counts are weighted analysis gap events, not unique sites or vulnerabilities. The comparison reports before/after counts per incomplete check/reason, using the maximum across three runs. Exact counts becoming unknown fail the comparison; unknown counts are never inferred from retained/truncated examples.

NodeGoat may retain partial AST analysis (module_export_unsupported). A successful *measurement* does not make its source coverage complete: coverageComplete=false and scan exit2 remain visible. Synthetic accuracy is measured separately across the existing 56 cases, including the known Koa miss.

Loop termination, inventory recall, predeclared-cell completeness and actual HTTP budget KPIs are unavailable/null until their implementations/authorized measurements exist. Source requests=0 is not used as a wire-budget success.

Comparison rejects missing/malformed fields, inconsistent samples/counts, incomplete accuracy or differing fixture/corpus/harness/parameters or runtime os/arch/node/npm/image digest. It detects new FP/FN identities even if aggregate totals stay unchanged, new medium incomplete checks, increased event counts for the same check/reason, lost measurements and nondeterminism. Exit0=no measured regression, exit1=measured regression, exit2=failed/incomparable measurement. Dependency-only PRs remain comparable: engine.dependencyLock is metadata and an intra-run mutation guard, not a cross-revision match condition. Kernel release is recorded for diagnosis only. No millisecond gate or automatic baseline replacement is imposed.

Preparation/scan failure exits2 without a completed kpi.json; a reused output is refused, never treated as fresh evidence. Do not use leftover per-run artifacts as an overall successful measurement.

## Network-disabled reproduction

    docker build -f benchmarks/kpi.Dockerfile -t wakeio-kpi benchmarks

Run the prepared image with --network none and set WAKEIO_KPI_IMAGE_DIGEST to its actual docker image inspect --format '{{.Id}}' value, as CI does. A host-only run records imageDigest=null; it is incompatible with an image-backed run. On Linux use the host UID/GID as shown in CI; Docker Desktop can map bind ownership to root, so use the UID owning the mounted directories there instead of weakening Git safe-directory checks. Mount ordinary complete WakeIO clones (including readable .git metadata), the verified fixture and a fresh output parent. Keep the fixture read-only. The trusted WakeIO build must be writable because npm may chmod its CLI bin when resolving the local checkout, even with --no-install. The offline-kpi workflow shows the complete commands and measures base/candidate sequentially under the same image. A managed Git worktree's external .git pointer also needs its shared Git metadata mounted if used directly.

The Dockerfile installs only runtime diagnostic Git/procps during setup. Measurement containers have no network. Source-only compatibility tests include project lifecycle/config execution canaries. The job uses contents:read and SHA-pinned helper Actions, publishes artifacts/Job Summary only, and has no target server, provider, release command or PR write permission.

The committed kpi-baseline.json records a measured main revision/environment. Another environment must produce its own main baseline; it must not compare Linux and macOS timing as a performance regression. In CI, both sides are freshly measured in one job. Local CI reproduction does not establish a GitHub-hosted workflow run.

## Compatibility

tests/fixtures/compat-0.5 contains original main 0.5 report/agent-report/Markdown/SARIF artifacts plus their hashes and expected gates. Tests consume those frozen artifacts rather than regenerating the expected output from new code. Existing error/not_applicable and scan/compare gate differences are retained. The v1 plan validator is not widened for future loop metadata.

This P0 implements the measurement/compatibility prerequisites for approved D1–D6. It does not implement init-dast, execution-plan v2, state-snapshot, run-loop, agent providers or deployment.

## Recorded main reference

The committed Linux/Docker reference is main 536d968357c31a7c681164ef7afa6307b138d1a7, with NodeGoat commit c5cb68a7084e4ae7dcc60e6a98768720a81841e8 (111 tracked files), three runs and Node22.23.4. Median first report: 795.268ms; median analysis-only: 267.716ms (one excluded warmup, three samples); normalized primary hashes3/3 agree. The independent synthetic corpus remains TP27/FP0/FN1 across56 completed cases. NodeGoat AST remains partial with module_export_unsupported; loop/inventory/wire-budget metrics are unavailable. This is a reference measurement, not an adopted latency target.

## Proposed main trend storage (deferred)

Keep the existing per-run artifact upload. A future dedicated job should run only for successful push events on main and copy the measured kpi.json plus comparison.json into append-only object storage at main/<commit>/<workflow-run-id>/<attempt>/. Store the workflow URL, engine/lock hashes, harness/input digests and runtime image digest with each point. Group trend series by matching harness/input/runtime; never overwrite a prior point or automatically promote a failed/incomparable result into the baseline. The current PR only records this proposal: no storage credentials, write permissions, trend job or main-only persistence is added. GitHub artifact retention remains temporary until that separate work is approved.

## Remaining 0.6 release checks

- [ ] G5 (P4/P5): inject unique secret canaries through synthetic policy/env/spec/response; scan every report format, snapshot, run.db including any WAL/SHM, logs/stdout/stderr and evidence artifacts for raw canaries. Unpack archives before checking. Test both ordinary and cancellation/error paths; any match fails. Existing lifecycle/config canaries do not satisfy this release gate.
- [ ] G7 (P6): before publishing, verify package/lock version against the intended immutable tag and peeled source SHA using mocked registry/tag responses; include mismatch and pending-release tests. After separately authorized publishing, verify actual npm version/integrity/dist-tag and the GitHub tag/release assets agree. A local preflight is not evidence of successful publication. No publish or registry mutation is performed by P0.
