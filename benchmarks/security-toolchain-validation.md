# Optional security toolchain validation

This change extends the unpublished 0.5.0 candidate. The integration base is
`f00fb8a0484a7124ab53d8ace99f0f994331b995` (`dev`), checked on 2026-10-19.
It is not a claim of complete application security, production precision/recall,
or autonomous-agent benefit.

## Implemented boundary

| Lane | Input and implementation | Explicit limit |
| --- | --- | --- |
| Semgrep CE | Bounded Go-only stage; own Apache-2.0 SQL-input, trusted-HTML and insecure-TLS rules | Three rules only; no registry rules, interprocedural guarantee or business-authorization proof |
| govulncheck | One complete root module; prepared Go and module cache; source/symbol protocol | No target dependency/toolchain download, local replacements or nested modules; static build-specific reachability |
| Trivy CVE | Dependency-only stage or explicit Docker/OCI archive; neutral config and package inventory binding | No image pull/build/run or cloud inspection; package presence is not exploitability |
| ZAP | Local 2.17.0; explicit HTTP GET query paths; rules 40012/40018; authenticated bounded proxy | No HTTPS, spider, login, OAST, scripts, writes or general auth/authz verification; trusted-engine proxy compliance, not an OS sandbox |

CLI/Action source paths share JSON, SARIF, Markdown and agent reports. ZAP is
CLI/SDK only; the existing `actions/dast` and `run-plan` engine enum is unchanged.
Default source tool selection is unchanged. Missing tools, malformed reports,
load failures and incomplete inventory remain exit 2. Go/Trivy advisories cannot
satisfy the source-code-analysis denominator.

## Actual engine checks

Environment: macOS arm64, Node 22.23.1; Semgrep CE 1.147.0;
govulncheck 1.9.0 with Go 1.27.2; Trivy 0.74.0; ZAP 2.17.0 with Java 21.
Engines were prepared outside scanned targets. Only owned loopback fixtures
received active requests. Public advisory databases and release downloads were
used separately.

| Actual check | Observed result |
| --- | --- |
| Semgrep owned Go risky/fixed pairs | 3 selected risky patterns detected; 0 on their fixed counterparts |
| Go `x/text` v0.3.6 → v0.3.7 | 4 → 3 advisories; reachable `GO-2021-0113` removed; unrelated remaining advisories retained |
| Go clean subpackage fixture | Completed with 0 findings; SBOM root maps to the declared module/subpackage |
| Trivy lodash 4.17.20 → 4.17.21 | 5 → 3 advisories against the observed DB; remaining advisories retained |
| Trivy clean npm inventory | Completed with 0 findings |
| Trivy Go manifest | Completed; 3 package records, 4 CVEs, no unreported input |
| Local Alpine 3.18.0 archive | 15 package records, 49 CVEs; image never executed |
| ZAP reflected-XSS/encoded-control pair | XSS detected only on risky endpoint; 24 server requests = 24 gate requests; completed |
| ZAP request cap 2 | Exactly 2 server/gate requests; partial/request_limit; no requests after return |
| Installed tarball source + image command | All four reports; 6 completed, 2 not applicable, 0 incomplete; exit 1 for threshold findings |
| Installed tarball ZAP command | All four reports; XSS finding, encoded control negative; 24 server/gate requests, no additional passive requests; exit 1 |

Counts above are engine observations, not distinct ground-truth vulnerabilities
or a cross-engine accuracy score. Vulnerability databases change. Older patched
versions are deliberately not described as universally clean.

Final full-suite run on this change: **1,574 passed, 0 failed, 2 skipped**
(1,576 tests, concurrency 2). All four real scanner integrations ran. The two
skips are optional live Codex/Claude schema smoke tests. An earlier unrestricted
concurrency run missed a short-lived process in an existing observer test; its
independent rerun and the final complete run passed without weakening the test.

Image manifest digest:
`sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11`.
Verified official archive SHA-256:

- Go: `76812b213b1b2302c978d28fa52fa92d541704b9e7d9d5db8002c50e4018c4c5`
- Trivy: `1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11`
- ZAP: `94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0`

## Reproduction

Build with `npm run build`. Provide prepared tool paths/caches through the test
variables below, then run the selected test files. Each source test creates
owned temporary inputs; the ZAP tests create their own loopback server.

```sh
WAKEIO_SEMGREP_TEST_PATH=/prepared/bin/semgrep \
  node --test build/tests/semgrep.test.js

WAKEIO_REQUIRE_GOVULNCHECK=1 \
WAKEIO_GOVULNCHECK_EXECUTABLE=/prepared/bin/govulncheck \
WAKEIO_GO_EXECUTABLE=/prepared/go/bin/go \
WAKEIO_GO_MODULE_CACHE=/prepared/go-mod \
  node --test build/tests/govulncheck.test.js

WAKEIO_REQUIRE_TRIVY_VULN=1 \
WAKEIO_TRIVY_EXECUTABLE=/prepared/bin/trivy \
WAKEIO_TRIVY_CACHE=/prepared/trivy-cache \
WAKEIO_TRIVY_IMAGE_ARCHIVE=/prepared/alpine-3.18.0.tar \
  node --test build/tests/trivy-vuln.test.js

WAKEIO_ZAP_PATH=/prepared/ZAP_2.17.0/zap.sh \
  node --test build/tests/zap.test.js
```

Prepare the Go cache with the two fixture dependencies before scanning. Trivy
real tests require its prepared vulnerability DB and the declared archive.
Missing mandatory real-tool inputs fail the require-enabled CVE tests;
Semgrep/ZAP live tests are skipped unless their executable variables are set.
The default offline protocol tests do not establish a real-engine pass.

The full suite also supports the existing prepared Schemathesis and Nuclei
runtimes. Use `node --test --test-concurrency=2 build/tests/*.test.js` when running
all real engines together. Local evidence is retained under ignored
`artifacts/security-toolchain/` and `artifacts/zap-runtime/`; raw ZAP attack/response
reports are not published. This document records the observed boundary rather
than claiming those local artifacts are distributed with the package.

## Failure-driven corrections

- ZAP's upstream proxy authentication needs explicit activation. Its automation
  context combines origin URLs with include rules; complementary exclusions are
  required to prevent root/random-path calibration from expanding the scope.
- Trivy omits `Version` for the root Go module. Only unversioned root inventory
  rows are accepted; an affected dependency still needs an exact version match.
- Govulncheck SBOM module and package roots must match the input `go.mod`; a
  well-formed report for a different module is rejected.
- Optional prepared caches must not enable unselected Action tools. ZAP defaults
  and declared budgets use shared constants; passive page options are rejected
  when ZAP owns the URL scope.
- Cleanup failure cannot produce a completed ZAP check. No failing outcome was
  replaced with a claim of clean findings.

Official contracts: [Semgrep engine/rules licensing](https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss/),
[govulncheck output and reachability](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck),
[ZAP automation policy](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/).
