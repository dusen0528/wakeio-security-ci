# Security policy

Wakeio Security CI is a public local CLI and composite GitHub Action. It has
no hosted Wakeio endpoint, login flow, customer database, or service-side
credential store. The npm package and GitHub Marketplace listing are not yet
published; report issues against the public source repository or the reviewed
commit/archive you used.

## Reporting a vulnerability

Use the GitHub private vulnerability reporting form for this repository:

<https://github.com/dusen0528/wakeio-security-ci/security/advisories/new>

Do not put an exploitable detail, real secret, private source, personal data,
production URL, or unredacted report in a public issue or pull request. The
private report should include the affected commit or preview version, runner
platform and architecture, command or Action inputs, impact, and a redacted
reproduction. Synthetic fixtures are preferred when they demonstrate the same
behavior.

If the form is unavailable, do not disclose the sensitive details publicly;
contact the repository maintainers through an access-controlled channel and
include only a short pointer to the affected public commit.

## Data and report handling

The CLI is designed to keep source snippets and detected secret values out of
JSON, SARIF, and Markdown reports. That does not make input files, scanner
caches, runner logs, or uploaded artifacts automatically safe for public
disclosure. Review CI retention, logs, URLs, paths, package identifiers, and
tool messages before sharing an artifact.

The Action does not execute the scanned repository's package scripts, builds,
tests, or hooks. It does execute its own Node runtime and any scanner or
Bandit executable explicitly selected by the workflow. Keep credentials out of
ordinary fork pull request jobs and separate any controlled API-policy run from
untrusted changes.

Public issues are appropriate for ordinary documentation, reproducible
non-sensitive bugs, and feature requests. See [CONTRIBUTING.md](CONTRIBUTING.md)
for fixture and disclosure guidance.
