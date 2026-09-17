# 0.4 verification record

Date: 2026-09-16. Version: `0.4.0-dev.1`. This record separates observed local execution from unrun hosted/publication paths. Fixtures use synthetic credentials and local servers; no customer source was uploaded.

## Parent independent acceptance

The parent reviewer used separate harnesses in a temporary directory, outside the implementation agents' test files.

| Area | Observed acceptance |
| --- | --- |
| Source | 14 scenarios passed: nested SQL comments, quoted identifier identity, ordinary backslash strings, public/private env distinctions, relative client secret imports, unprefixed next.config.env, grant/RLS history, destructured/Next/loop inputs, parameterized SQL negative case |
| API | 11 scenarios passed: normal denial, 200/403 protected-data leak, public-ID-only denial, allowed empty denial, expired credentials, mid-run expiry, same principal, rate limiting, invalid weak canary, legacy v1 partial |
| URL | 4 scenarios passed: nonce-based policy, unsafe-inline positive, invalid nosniff/referrer, explicit second page and static module graph |
| Next boundary | 3 scenarios passed: Server Action import excludes false client exposure, ordinary client import retains detection, React import alone is not treated as a client boundary |
| Comparison | 7 scenarios passed: line movement across checkouts, changed content as evidence, project mismatch, duplicate anchor ambiguity, unknown/malformed engine provenance, identical engine bytes at different paths versus engine-byte changes |
| npm consumer | 6 scenarios passed: clean relative tarball install, runtime package metadata, read-only doctor, init overwrite refusal, quoted-path YAML parsing, fresh npm ci plus generated scan without target lifecycle scripts |
| Native archive cache | 3 scenarios passed: verified cold download, offline verified hit with identical executable bytes, tampered archive rejected offline |

The bounded URL scenario requested `/`, `/a.js`, `/b.js`, `/c.js`, `/second`: two explicit pages, three scripts, five requests. An unapproved anchor link was not fetched. Reports did not contain the synthetic token/canary values used by the source and API fixtures.

## Native engines on macOS arm64

Runtime: Node.js 22.22.1. Engines installed from the installer’s pinned SHA-256 verified assets; Python Bandit installed in a separate temporary virtual environment.

| Engine | Actual fixture result |
| --- | --- |
| Gitleaks 8.30.1 | Completed; one synthetic GitHub token finding |
| OSV-Scanner 2.6.0 | Completed; `requests==2.19.1` pinned requirements input, one package and ten advisory records |
| Trivy 0.74.0 | Completed; Dockerfile fixture, two configuration findings |
| Bandit 1.9.4 / Python 3.14.5 | Completed; one Python file, B404 and B602 |

The same OSV executable and the actual Wakeio source adapter also accepted a synthetic `uv.lock` declaring requests 2.19.1 and returned one package/ten advisory records. Advisory counts describe the online dataset at execution time; they are not a pinned database promise. The initial Gitleaks fixture used a repetitive low-entropy token and returned no result; replacing it with a varied synthetic token exercised the intended detector. This was a fixture correction, not a claimed fix to Gitleaks.

## Local Linux and package acceptance

An isolated `node:22.22.1-bookworm-slim` container ran on Linux arm64. The source archive’s prebuilt Action ran without node_modules and produced JSON/SARIF/Markdown, Action status, outputs and Job Summary with the expected finding exit code. A clean npm tarball consumer also ran doctor and the scanner. Actual pinned Linux Gitleaks, OSV and Trivy completed and returned 1, 10 and 2 findings respectively on the synthetic fixture.

The first online OSV run failed closed because this minimal image lacked `/etc/ssl/certs/ca-certificates.crt`. Installing Debian’s standard `ca-certificates` package resolved it. TLS verification stayed enabled. Custom minimal runners need a working CA bundle; this was an environment preparation failure, not a clean scan.

The macOS clean consumer installed a reviewed relative `file:vendor/wakeio.tgz` dependency. After deleting its node_modules, the exact generated `npm ci --ignore-scripts` and scan commands worked. A synthetic target postinstall marker was not created. An output path containing an apostrophe and colon parsed as YAML and reached the intended report directory. Re-running init refused to overwrite the existing workflow.

## Final suite and benchmark

The final full `npm test` run passed **144/144 tests**, with zero failures or skips. The parent re-ran the source/API/URL/comparison/Next-boundary acceptance harnesses against the final build; all passed. The initial integration checkpoint had passed 135 tests before the final regressions were added. The strict 30-case benchmark passed with 13 of 15 expected vulnerable findings detected, zero false-positive cases among 15 fixed cases, and two known cross-boundary misses. The strict gate preserves these known misses; it does not mean all vulnerabilities were detected. These are synthetic regression results, not production accuracy.

The semantic-anchor load fixture contained 1,000 SQL findings in one 97,889-byte source file. `runSource` produced all 1,000 anchors in 190ms on this local macOS run. Whole-file parsing/masking is cached per file. This is a single synthetic performance observation, not a general latency guarantee.

The final release consists of the npm tarball, source archive and versioned SHA-256 manifest under `artifacts/`. The npm package omits unavailable contributor scripts/devDependencies; the source archive contains the prebuilt Action and its bundled third-party license file. See [distribution](distribution.md) for installation and checksum commands.

## Boundaries

macOS arm64 and local Linux arm64 were executed; x64 asset selection exists but x64 execution was not performed in this task. No npm registry upload, Marketplace listing, GitHub release or GitHub-hosted workflow execution has occurred in this task. A local Linux container run does not prove the hosted workflow’s permissions or SARIF UI behavior. No live customer API, payment flow, cloud account, production database or credential validation is included. Findings remain scoped observations/candidates/advisories, not a complete security assessment.
