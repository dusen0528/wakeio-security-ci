# Release 0.4.0

This release packages the accumulated bounded local security-analysis and owned
fixture-verification work. Node.js 22 or later is required. The default `scan`
path remains local and does not execute target hooks/builds/tests or upload source.

## Included behavior

- Bounded JS/TS source candidates cover selected interprocedural, local-module,
  object, SQL, HTTP-destination, and child-process argument roles. Parse failures,
  unsupported dependencies, ambiguous resolution, and exhausted budgets stay
  visible as incomplete work. See [source support](source-flow.md).
- JSON, SARIF, Markdown, and `agent-report.json` share the scan gate and sanitised
  evidence. Summaries expose current outcomes, retained analysis gaps, and next
  evidence to read; they do not certify finding accuracy or final process/delivery
  success. See [agent report](agent-report.md).
- The Schemathesis worker runs the bundled broken/fixed OpenAPI fixtures with
  explicit request/operation limits, safe-input replay, pinned engine metadata,
  source/lock fingerprints, redacted artifacts, and supervised processes. Its
  Python environment is prepared explicitly, not by `scan` or npm installation.
  See [fixture worker](schemathesis-fixture-worker.md).
- The API resource/state pilot runs four fixed, owned synthetic modules and checks
  authorization effects, stored state, and normal behavior independently. Its
  returned delivery acknowledgement is separate from artifact publication.
  See [state pilot](api-state-oracle.md).
- `repair` creates a proposal and private verification evidence using a trusted
  policy, a prepared image ID, and declared Python/SQLite regression and normal
  controls. Selecting an external provider also requires explicit source-upload
  authorization. See [repair preview](repair-preview.md).
- The optional native preview requires the separately reviewed Darwin arm64
  Opengrep core 1.30.0 binary. It uses original Apache-2.0 rules; the LGPL engine
  is not included in the package. See [native preview](native-preview.md) and
  [third-party notices](../THIRD_PARTY_NOTICES.md).

The package contains compiled CLI/SDK code and the required API-state and
Schemathesis worker files. It retains documentation, examples, and the explicit
optional-tool installer. Contributor test/build scripts and development
dependencies are removed from the packed package metadata; runtime dependencies
remain declared. The source archive retains contributor sources/tests/workflows
and excludes local environments, caches, reports, and secret environment files.

## Release verification

Local checks on 2026-10-06 KST used Node.js 22.22.1, Python 3.12.13, and
Schemathesis 4.2.0. CI verification contracts passed 9/9. The required-engine
suite passed 489/489 with zero failed/skipped/cancelled/todo cases. All stages
exited 0 with confirmed close/owned-group cleanup and matching before/after
source fingerprints. The strict 30-case synthetic corpus observed all 15
supported expected findings, with zero false positives/supported false negatives
and zero strict regressions. These counts describe tests and declared synthetic
expectations, not confirmed vulnerabilities or real-world accuracy.

The checks use the existing CI contract:

```sh
node --test scripts/ci-verification.test.mjs
npm run test:schemathesis
npm run benchmark -- --strict
npm run package:release
WAKEIO_SCHEMATHESIS_PYTHON=/absolute/reviewed/python \
  node scripts/verify-schemathesis-package.mjs artifacts/wakeio-security-ci-0.4.0.tgz
```

The required suite checks the installed pinned Python packages, rebuilds current
sources, requires passing real-engine fixture tests with zero skipped tests, and
records stage outcomes and source fingerprints. Strict benchmarking is the
repository's supported synthetic source corpus, not live DAST or population
accuracy. Installed-package checks use an isolated local consumer and disabled
lifecycle scripts; the release archive is reviewed before publication.

## Evidence limits

Static candidates remain `verification: not_run` and remediation remains
`not_verified`. A finding absent in a later compatible report is `not_observed`,
not a verified repair. Incomplete scans retain exit 2 even under `--fail-on none`.
The fixture worker and state pilot do not test arbitrary customer APIs,
authentication/session workflows, GraphQL, ZAP, production security, or paid-tool
parity. POSIX process groups and sampled resource limits are not a hostile-code
sandbox. Repair success is confined to its declared regression/normal controls.
Artifact hashes connect measured bytes and are not supply-chain attestations.

Dated verification documents retain their original counts and execution limits;
they are historical records rather than a claim that every earlier check was
repeated for this release. Registry publication and GitHub integration require
separate final receipts from the release owner.
