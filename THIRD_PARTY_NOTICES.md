# Third-party notices

Wakeio Security CI does not vendor these executables in the repository. The
installer downloads the exact upstream release asset for the three native
engines when explicitly run or invoked by the Action, checks the hard-coded SHA-256 from the upstream release metadata,
and places the executable in an isolated temporary directory.

## Gitleaks CLI 8.30.1

Gitleaks is provided by the gitleaks project under the MIT License. This
project invokes the CLI binary; it does not use the separate paid or
organization-oriented Gitleaks Action.

- Source and license: <https://github.com/gitleaks/gitleaks>
- Release: <https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1>
- Release checksum manifest: <https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt>

## OSV-Scanner 2.6.0

OSV-Scanner is provided by the Google OSV-Scanner project under the Apache
License 2.0.

- Source and license: <https://github.com/google/osv-scanner>
- Release: <https://github.com/google/osv-scanner/releases/tag/v2.6.0>
- Release checksum manifest: <https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_SHA256SUMS>

## Trivy 0.74.0

Trivy is provided by Aqua Security under the Apache License 2.0.

- Source and license: <https://github.com/aquasecurity/trivy>
- Release: <https://github.com/aquasecurity/trivy/releases/tag/v0.74.0>
- Release checksum manifest: <https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_checksums.txt>

The notices above describe the upstream scanner projects used as separate
runtime programs. They do not grant or claim rights to any private source,
prompt, customer material, or older Wakeio service repository.

## Generated Action bundle dependencies

`dist-action/wakeio-security-ci.mjs` is a prebuilt, dependency-free Node.js
Action entrypoint. It embeds the parser/runtime dependencies used by the CLI;
the generated `dist-action/THIRD_PARTY_LICENSES.txt` carries the resolved
license text for parse5, entities, TypeScript (including its third-party
notice text), and the pinned esbuild build tool. The source archive includes
both generated files so a vendored Action does not need `node_modules`.


## Optional Bandit 1.9.4

Bandit is provided by PyCQA under the Apache License 2.0. The optional Python
SAST adapter invokes a separately installed trusted executable. The native
engine installer above does not download Python or Bandit. Scan commands never
install packages or execute the Python target. Bandit inline `#nosec` comments
are ignored in this preview so a target cannot silently disable findings.

- Source and license: https://github.com/PyCQA/bandit
- Verified package version: https://pypi.org/project/bandit/1.9.4/
- CLI and suppression behavior: https://bandit.readthedocs.io/en/latest/man/bandit.html

The narrow framework/URL rules added in this repository are original project
code. No Semgrep-maintained rule bundle is included. Public version clues are
not an embedded CVE database.
