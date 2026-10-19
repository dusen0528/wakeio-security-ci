# Security toolchain: upstream analysis and applied changes

Baseline: `f326cfa5d1389c828c8571a475f718cb8eb6018a`, the first four-engine integration.
This follow-up keeps the existing CLI, Action, report and incomplete-scan contracts.
The user goal is broader useful detection with prepared local engines and one report,
without model credentials or another orchestration layer.

## Upstream versions and code inspected

| Tool | Pinned source | What the source established |
| --- | --- | --- |
| Semgrep CE 1.147.0 | [`e9a7c48`, taint data flow](https://github.com/semgrep/semgrep/blob/e9a7c48f06fe89556af234e3f9228b8951c9a5b9/src/tainting/Dataflow_tainting.ml) | Source/sink taint rules can follow assignments and expressions within a function; matches are potential bugs. Receiver identity, complete alias analysis and business authorization are not established. |
| govulncheck 1.9.0 | [`e672cbe`, build flags](https://github.com/golang/vuln/blob/e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5/internal/scan/flags.go), [package loading](https://github.com/golang/vuln/blob/e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5/internal/scan/source.go), [SBOM/package graph](https://github.com/golang/vuln/blob/e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5/internal/vulncheck/packages.go) | Build tags select a different static program. The protocol carries module versions and call-path stages; finding versions must match the emitted inventory. |
| Trivy 0.74.0 | [`e1fd17a`, pip analyzer](https://github.com/aquasecurity/trivy/blob/e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994/pkg/fanal/analyzer/language/python/pip/pip.go), [uv analyzer](https://github.com/aquasecurity/trivy/blob/e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994/pkg/fanal/analyzer/language/python/uv/uv.go), [file-pattern flag](https://github.com/aquasecurity/trivy/blob/e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994/pkg/flag/scan_flags.go) | The default pip filename is exactly `requirements.txt`. Additional names need the native file-pattern facility. `uv.lock` already has an upstream analyzer. Unsupported/unresolved packages can be omitted from inventories. |
| ZAP 2.17.0, automation 0.58.0, active rules 78 | [`8b171e1`, requestor](https://github.com/zaproxy/zap-extensions/blob/8b171e1c8704d2996b75d4bc119cbf9495d9aa12/addOns/automation/src/main/java/org/zaproxy/addon/automation/jobs/RequestorJob.java), [SQL injection rule](https://github.com/zaproxy/zap-extensions/blob/8b171e1c8704d2996b75d4bc119cbf9495d9aa12/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionScanRule.java) | A requestor can require an HTTP status and warn on a mismatch. The generic SQLi rule recognizes SQLite errors. Low strength runs bounded error/expression probes, rather than every blind/union technique. |

Only primary documentation/source was used for engine semantics. No upstream
registry rules or scanner implementation was copied into the application.

## Decisions and implementation

### Semgrep: six bounded Go rule families

The existing own Apache-2.0 rule pack gains command selection/shell injection,
outbound HTTP destination and filesystem-path rules. Existing SQL, trusted HTML
and TLS verification rules remain. Sources include query/form input, Go 1.22
`Request.PathValue`, header reads and the request URL path. Sink argument focus
keeps bound SQL values, data passed to a fixed HTTP destination and ordinary
arguments to a fixed executable out of these injection categories.

The fixed controls include bound SQL, ordinary template escaping, verified TLS,
separate process arguments, a fixed HTTP destination with untrusted body data,
and a rooted filesystem open. `filepath.Join`/`Clean` are not accepted as proof
of containment. The revision and rule hash are part of scan provenance.

This remains six Go rule families and an intraprocedural candidate analysis.
Arbitrary third-party frameworks, cross-function flows and application-specific
authorization are not claimed. The existing one-process, one-worker, memory and
per-rule time limits are retained.

### govulncheck: explicit build tags and inventory binding

`--go-build-tags feature,release` and the Action `go-build-tags` input select the
actual build variant. Tags are bounded names, normalized once and passed as an
argv value. The normalized tag set participates in scope identity and appears
in the report, together with the observed Go version. Module/toolchain downloads
and test execution remain disabled during a scan.

A finding for a module or version absent from the SBOM is rejected. The adapter
continues to distinguish module presence, imported package and static call path;
module-only observations do not become reachable vulnerability claims.

**Not adopted: `-test`.** With the pinned govulncheck 1.9.0 and Go 1.27.2, an owned
fixture imports `golang.org/x/text/language` only from an internal `_test.go` file.
`go list -test -deps` lists that dependency, while `govulncheck -json -test ./...`
emits duplicate root package paths, a generated `.test` root and an inventory
without that dependency. The inspected package graph deduplicates packages by
`PkgPath`; dropping a test variant is the source-level explanation to investigate
upstream. This is a pinned-fixture observation, not a claim about every release
or every external test package. No test-analysis option is exposed with an
unsupported completeness promise. Raw reproduction data stays in local ignored
`artifacts/security-toolchain-deepening/`.

### Trivy: native Python analyzers, shared requirements validation

The adapter now stages `uv.lock`, `requirements-dev.txt` and
`requirements-prod.txt` alongside the previously supported inputs. It selects
named requirements through Trivy's `--file-patterns` flag and uses the upstream
uv analyzer directly; there is no new requirements or TOML dependency resolver.

The existing OSV requirements inspection is shared with Trivy without changing
OSV behavior. A range, include, editable/URL dependency or unresolved requirement
keeps the scan partial even when another pinned package produced a valid
inventory. Known findings are retained. Input paths must still map to selected
files and vulnerability package/version pairs must exist in the inventory.

### ZAP: meaningful seed responses, real SQLi and distinct query findings

Every seed GET now declares native `responseCode: 200`. With `failOnWarning`
enabled, non-200 authentication/error responses cannot count as a completed clean scan.
This adds no separate preflight HTTP request. It does not establish an
authentication session or a permission comparison.

The owned target uses actual SQLite queries: interpolated SQL is compared with
the same query using a bound parameter. The real engine must detect rule 40018
only on the vulnerable SQL endpoint and rule 40012 only on the unescaped XSS
endpoint. Every observed server request must equal gate accounting.

Different vulnerable query parameters at the same redacted URL used to receive
the same public finding ID. A failing regression reproduces that collision.
ZAP now supplies a hashed query-surface anchor through the existing comparison
key; only ZAP finding IDs use that discriminator. Raw parameter names and values
are not retained. The identity survives report sanitation. Legacy findings and
other detectors keep their existing identity construction.

Simultaneous real scans exposed a second bug: the default local proxy port 8080
collided before any target request. The native network configuration now binds
the listener to loopback with an OS-assigned port. The pinned [network startup
code](https://github.com/zaproxy/zap-extensions/blob/8b171e1c8704d2996b75d4bc119cbf9495d9aa12/addOns/network/src/main/java/org/zaproxy/addon/network/ExtensionNetwork.java#L921-L960)
ignores a CLI `-port 0` override, so the adapter uses
`network.localServers.mainProxy.port=0` directly. A real two-scan regression failed
before the change; afterward both scans completed with 14 target requests and
14 gate requests each. Their outgoing authenticated gates remain independent.

HTTP GET/query scope, the two selected active rules, request/rate/time caps,
no-spider/no-OAST policy, proxy trust boundary and cleanup requirements remain.
HTTPS, arbitrary OpenAPI import, login and write operations need their own
bounded execution design; they are not enabled by copying an upstream default.

## Verification and reproduction

Use the prepared executable/cache variables from
[the initial validation record](security-toolchain-validation.md#reproduction).
Build with `npm run build`, then run `semgrep`, `govulncheck`, `trivy-vuln` and
`zap` test files under `build/tests/`. Required CI validates exact real-engine
test names with zero skips and bounds file concurrency to two. The aggregate CI watchdog is six minutes: the prior
four-engine suite took 263.60 seconds before adding denied-seed controls. This
changes no individual scanner/request budget or success condition.

Observed targeted checks:

- Semgrep risky/fixed pair: six risky rule families detected and zero on fixed controls.
- Go tag-gated vulnerable call: unreachable in the default build, reachable with the declared tag.
- Trivy four Python input layouts: Requests 2.31.0 retains CVE-2024-35195; the
  selected advisory is absent at 2.32.4. Other advisories are not suppressed or
  described as universally fixed. The upstream [Requests advisory](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
  identifies the affected and patched range.
- ZAP XSS and SQLite SQLi positive/fixed controls: 50 target requests = 50 gate
  requests; both vulnerable rule IDs observed, both fixed endpoints negative.
- ZAP 401/404 seed pair: partial, not completed; the exact two-request cap still stops at two.
- Query-parameter collision: regression failed before the change and passed after it.
- Concurrent ZAP scans: both complete with independent accounting after the native
  listener fix; the earlier fixed-port implementation fails the regression.

The existing strict-process environment test also encountered macOS `ps` state
`?Es` during natural child exit (one reproduction observed 3 failures in 30 runs).
Its environment-only fixture now waits for a declared supervisor timeout rather
than racing natural exit against sampling. All environment, RSS and cleanup
assertions remain; the production observer and its fail-closed unknown-state
behavior are unchanged. Thirty controlled repetitions passed.

The pinned Semgrep wheel is verified by the existing CI bootstrap, but its PyPI
transitive dependencies are not yet a complete hash-locked environment. This
research does not claim a fully reproducible third-party supply chain.

Final local verification on 2026-10-19 (macOS arm64, Node 22.23.1):

| Check | Observed result |
| --- | --- |
| Exact required-engine harness (`node scripts/test-schemathesis.mjs`) | 1,581 passed, 0 failed, 0 skipped; 214.58 seconds for tests; seven required real tests across the four new engines |
| CI/bootstrap contracts | 22 passed, 0 failed, 0 skipped |
| Final tarball installed in an isolated directory | Source/image CLI: 6 completed, 2 not applicable, 0 incomplete; all four reports; declared Go tag and both selected Python locations retained |
| Installed ZAP CLI, two query parameters and encoded control | Completed; 46 target requests = 46 gate requests; two distinct XSS finding IDs; no fixed-endpoint findings or extra passive requests; all four reports |

The tarball SHA256 was
`5db0c68103824681f8ab0db4bf5e0f196dfd290a2969e561ff5c281c843c99ed`.
Both installed CLI runs returned exit 1 for threshold findings, rather than an
execution error. The package excludes local validation artifacts. Local receipts
are in ignored `artifacts/security-toolchain-deepening/` and
`artifacts/ci/required-engine-ap6Oql/`; those directories are not distributed.

These fixture results are not production precision/recall, a performance
benchmark, a complete SAST/DAST assessment or autonomous-agent benefit. Existing
[performance baseline](perf-baseline.md) measurements are a separate artifact.
