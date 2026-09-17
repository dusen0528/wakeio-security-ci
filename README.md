# Wakeio Security CI

**Find security candidates before release and keep incomplete checks visible in CI.**

Wakeio checks the code, HTTP responses, and optional read-only API policy that you explicitly provide. It keeps findings, evidence, scope, incomplete checks, and limits visible together, so a clean result does not hide an untested area.

[한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md) · [implemented checklist](docs/checklist.md) · [0.4 guide](docs/preview-0.4.md) · [verification record](docs/verification-0.4.md)

**Preview:** `0.4.0-dev.1` · Apache-2.0 · Node.js 22+

This is a free local tool. It does not require a Wakeio account, subscription, hosted Wakeio service, LLM, or source upload, and it does not send usage telemetry. The npm registry is not a distribution path for this preview; use the Git checkout or the GitHub Action below.

## What it checks

| Scope | What Wakeio can observe | Boundary to keep in mind |
| --- | --- | --- |
| Source code | Bounded JS/TS AST candidates where request input reaches SQL, HTML, process, outbound-request, or redirect sinks; dynamic evaluation; selected credential shapes; selected Next/React and Supabase migration candidates | Same-function and bounded local-flow analysis. No general cross-function, cross-file, type-aware, runtime, build, or live database proof |
| Public URL | Explicit pages, same-origin static JavaScript modules, transport, security headers, CSP, cookies, CORS, mixed content, source-map/debug/version clues, DOM and secret-shaped candidates | Explicit bounded GET requests only. No browser execution, login, endpoint discovery, API fuzzing, payment flow, or automatic site crawl |
| Read-only API policy | Identity checks and owner/other-account/anonymous cases for a declared resource identity and distinct protected-data canary | GET requests defined by the policy. No writes, automatic login, endpoint discovery, or general fuzzing |
| Before/after reports | Logical project identity, semantic source anchors, changed findings, unchanged findings, and `not_observed`/`unverified` states | A missing later finding is never treated as proof that a fix is complete |

Source and URL scopes can be combined in one report. The API policy is opt-in and reads credentials from named environment variables; token and canary values are not written to reports. See the [API policy example](examples/api-authorization-policy.json) and [API guide](docs/preview-0.4-api.md).

The built-in source rules are intentionally narrow. They cover useful code scenes such as a request value flowing through a local variable into a raw SQL call, a JSX HTML sink, a process invocation, an outbound request, or a redirect. They also include bounded destructuring and loop bindings, selected Next route inputs, static client/server environment exposure, and Supabase migration history candidates. These are reviewable candidates, not exploit demonstrations or a claim that the whole application is safe.

## Quick start: built-in checks only

Clone the public repository and build it locally:

```sh
git clone --branch main https://github.com/dusen0528/wakeio-security-ci.git
cd wakeio-security-ci
npm ci --ignore-scripts
npm run build

node build/src/cli.js doctor --source /path/to/your-app --tools none
node build/src/cli.js scan \
  --source /path/to/your-app \
  --tools none \
  --out wakeio-security-reports
```

`doctor` is read-only: it inventories the target without running target code, package managers, scanners, or network requests. `--tools none` selects only the built-in checks and avoids optional engine setup. The scanner reads target files as data; it does not run the target project's install scripts, hooks, build, or tests.

For a URL-only check, name the root and any additional same-origin pages explicitly:

```sh
node build/src/cli.js scan \
  --url https://your-app.example \
  --page https://your-app.example/pricing \
  --tools none
```

For one report containing source and URL scopes:

```sh
node build/src/cli.js scan \
  --source /path/to/your-app \
  --url https://your-app.example \
  --tools none
```

Private or local URL/API targets require explicit `--allow-private`; metadata-address protections remain enabled. URL collection is limited to the declared pages, their same-origin static module graph, request/byte/time budgets, and a hard maximum of eight pages.

## GitHub Actions

The easiest CI path uses the public Action from the initial `main` branch. This example selects built-in checks explicitly, preserves reports when the scan finds a failure, and keeps the surrounding actions on their current pinned SHAs.

```yaml
name: wakeio-security-ci

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Check out application
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false

      - name: Run Wakeio Security CI
        uses: dusen0528/wakeio-security-ci@main
        with:
          source: .
          tools: none
          out: wakeio-security-reports
          fail-on: high

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: wakeio-security-ci-reports
          path: wakeio-security-reports
          if-no-files-found: error
```

Copy-ready version: [`examples/github-action.yml`](examples/github-action.yml). `@main` is convenient for trying the preview. For a production workflow, pin `dusen0528/wakeio-security-ci` to a reviewed commit and review updates deliberately; keep helper actions pinned to reviewed SHAs as well. The Action provisions Node.js 22, never runs scripts from the scanned project, writes a Job Summary, and leaves `report.md`, `report.json`, `report.sarif`, and `action-status.json` in the output directory.

## Optional engines

External engines are opt-in in the examples. The source CLI historically defaults to `gitleaks,osv,trivy`, so pass `--tools none` when you want built-in-only behavior or pass the exact set you reviewed. Bandit is never implicit.

| Engine | Version used in this preview | Adds | Important limit |
| --- | ---: | --- | --- |
| Gitleaks | 8.30.1 | Secret-pattern scanning over collected files | Current collected files only; no complete Git history and no key-validity check |
| OSV-Scanner | 2.6.0 | Advisories for supported lockfiles and self-contained pinned Python requirements | Advisory lookup, not source reachability or malware analysis; online mode may send package identifiers to the public OSV service |
| Trivy | 0.74.0 | Dockerfile, Kubernetes, and Terraform configuration checks | Configuration only; no image CVEs, live cloud inspection, or external-module proof |
| Bandit | 1.9.4 | Optional Python AST checks | Separately installed executable; selected Python files only and no target execution |

Examples:

```sh
# Explicitly enable the native engines you have reviewed.
node build/src/cli.js scan --source /path/to/app --tools gitleaks,osv,trivy

# Bandit is separately prepared and then selected explicitly.
node build/src/cli.js scan \
  --source /path/to/python-app \
  --tools bandit \
  --bandit /path/to/venv/bin/bandit
```

Prepare the pinned native binaries, or provide trusted executable paths, before enabling the optional-engine command. The [distribution guide](docs/preview-0.4-distribution.md) covers the installer, cache, and provenance details. The installer verifies native release assets with SHA-256. OSV can use a prepared database with `--osv-offline`; offline mode fails when that database is unavailable. Trivy may download scanner-managed policy or database data. These external network requests are separate from Wakeio: Wakeio itself does not upload source or call an LLM.

## Reports and exit codes

Every scan writes three primary files to `wakeio-security-reports/` (or `--out DIR`):

- `report.md` for a human-readable summary, evidence, limits, and remediation hints;
- `report.json` for the structured checks, scope, provenance, findings, and incomplete states;
- `report.sarif` as SARIF 2.1.0 for optional code-scanning workflows.

Findings are labeled as candidates, observations, or advisories. Missing tools, timeouts, changed or unknown provenance, unsupported input, duplicate semantic anchors, and collection gaps remain visible in the report and can make the run incomplete.

| Exit code | Meaning |
| ---: | --- |
| `0` | Applicable checks completed with no finding at or above the selected threshold |
| `1` | A finding reached the selected `--fail-on` threshold (high by default) |
| `2` | Configuration error, failed or incomplete check, or no applicable security check |

`--fail-on none` disables finding-based failure only; it does not turn an incomplete scan into a pass. Reports omit raw source and secret values, but can contain project paths, package identifiers, and URLs. Set CI artifact visibility accordingly.

## Read-only API policy and comparison

An API policy names the identity endpoint, expected principal, owner and other actors, resource identity, protected-data canary, and acceptable denial statuses. Credentials are referenced by environment-variable name. Identity controls and owner positive controls run around the deny probes. A protected canary received by the wrong actor is a finding even when the HTTP status is `403`; a repeated public ID by itself is not proof of a leak.

```sh
node build/src/cli.js scan \
  --api-policy /path/to/your-api-policy.json \
  --tools none
```

The checked-in policy targets the local synthetic server at `127.0.0.1:8877`; start `node examples/api-authorization-demo.mjs --vulnerable` in another terminal, export the two demo authorization variables, and add `--allow-private` to reproduce it. The [API guide](docs/preview-0.4-api.md) has the complete commands and fixed-variant run.

No write operation, payment action, automatic login, endpoint discovery, or general fuzzing is performed. Expired credentials, indistinguishable actors, rate limits, unexpected responses, and incomplete controls remain partial or unverified.

For a before/after review, keep the logical project identity and scan options stable:

```sh
node build/src/cli.js scan \
  --source /path/to/app \
  --project-id team/app \
  --tools none \
  --out /tmp/wakeio-before

# Make the change, then use the same declared scope and options.
node build/src/cli.js scan \
  --source /path/to/app \
  --project-id team/app \
  --tools none \
  --out /tmp/wakeio-after

node build/src/cli.js compare \
  --before /tmp/wakeio-before/report.json \
  --after /tmp/wakeio-after/report.json \
  --out /tmp/wakeio-comparison
```

Comparison refuses to present mismatched or incomplete scopes as a clean result. A finding that disappeared is `not_observed`, not an automatic fix certificate. See the [comparison guide](docs/preview-0.4-comparison.md).

## A small synthetic example

The following is a labeled regression fixture, not a real application result:

```text
candidate · high · ast:sql-input-sink
app/routes/users.ts:4
evidence: req.query.id -> statement -> db.query(...)
review: use the database driver's parameter binding and verify the generated query
```

Wakeio reports the code path it recognized and why it needs review. It does not execute the fixture, send an exploit, or claim that the surrounding application is secure.

## Verification and known limits

The current `0.4.0-dev.1` local verification record reports `npm test` passing **144/144** tests. Its strict synthetic JS/TS benchmark has 30 cases: 15 vulnerable and 15 fixed; 13 of 15 vulnerable expectations were detected, no fixed cases produced false positives, and two cross-function/cross-file cases remain documented known misses. This is a regression signal for the bounded detector, not production accuracy, coverage, or a security certification.

To reproduce the local checks:

```sh
npm test
npm run benchmark -- --strict
```

The implemented [checklist](docs/checklist.md), [0.4 guide](docs/preview-0.4.md), and [verification record](docs/verification-0.4.md) describe the exact scope. Complete penetration testing, exploit generation, browser/runtime proof, broad API fuzzing, live database or cloud inspection, image CVE scanning, and a whole-service safety verdict are outside this project’s contract.

## Contributing and license

Add rules with vulnerable/fixed synthetic fixtures, evidence and limits, and a compatible license. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Wakeio Security CI is Apache-2.0; external scanners and rules keep their own licenses in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
