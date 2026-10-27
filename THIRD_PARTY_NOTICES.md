# Third-party notices

## Optional native preview and original rules

The optional native preview invokes a separately supplied Opengrep core 1.30.0
process; no engine binary is included in this package or downloaded at runtime.
The engine's pinned [LGPL-2.1 license](https://github.com/opengrep/opengrep/blob/acf67b45c97c4b63626536605c77064ef536806d/LICENSE)
and third-party distribution obligations remain separate from Wakeio's license.
Official artifact hash verification is not publisher signature, reproducible
build, or complete redistribution compliance verification.

The four experimental SQL/command rules in `src/source/opengrep-rules.ts` are
original Wakeio patterns, Copyright 2026 Wakeio Security CI contributors,
licensed under this package's Apache-2.0 [LICENSE](LICENSE). They do not contain
downloaded registry or restricted security rule content. Their embedded YAML
is byte-identical to the frozen original pack. See [the preview contract](docs/native-preview.md).

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

## Runtime target data validation dependencies

The development branch includes the following pinned npm dependencies for
strict target YAML parsing and validation against the repository's bundled
JSON Schema. Versions and license identifiers below match `package-lock.json`
and the installed packages' license files.

| Package | Version | License | Use |
| --- | --- | --- | --- |
| yaml | 2.9.1 | ISC | Restricted YAML 1.2 target data parsing |
| ajv | 8.20.0 | MIT | Validation against the trusted target JSON Schema |
| fast-deep-equal | 3.1.3 | MIT | Ajv dependency |
| fast-uri | 3.1.9 | BSD-3-Clause | Ajv dependency |
| json-schema-traverse | 1.0.0 | MIT | Ajv dependency |
| require-from-string | 2.0.2 | MIT | Ajv dependency |

The generated `dist-action/THIRD_PARTY_LICENSES.txt` includes the complete
license texts for these six packages in addition to the existing notices.
The runtime target parser is connected through the read-only `init-target` command;
`verify` execution and the common runtime report reader still await wiring.
The Action entrypoint now bundles this YAML/Ajv data-only path, while notices
retain all six approved package licenses, including `require-from-string`, whose
code is not retained in the current bundle.
The npm package ships `schemas/target.v1.json` and its emitted
`build/schemas/target.v1.json`; the parser imports the local schema statically.

## Separate PostgreSQL parser assets

`workers/pg-parser/pg-parser-worker.cjs` is a separate Node.js 22 CJS bundle,
distributed with `libpg-query.wasm` beside it for both npm and vendored Actions.
It embeds `libpg-query` 18.2.1 and `@pgsql/types` 18.0.0, both MIT licensed.
The CLI Action entrypoint remains separate; using these assets requires the
verified runtime execution capability and does not install npm packages.

Complete MIT texts are in [the worker notices](workers/pg-parser/THIRD_PARTY_LICENSES.txt).
Additional upstream notices are preserved byte for byte in
[LICENSE.libpg_query](workers/pg-parser/LICENSE.libpg_query) (BSD-3-Clause) and
[COPYRIGHT.PostgreSQL](workers/pg-parser/COPYRIGHT.PostgreSQL) (PostgreSQL License).
The generated `dist-action/THIRD_PARTY_LICENSES.txt` also contains these notices.
The BSD notice uses the corrected SHA256
`f9352c20940619a380a5e9f23cebe34d8f797cfbd747fc236a7a3e5fc8ef9b41`.
These candidate upstream notice sources were recorded at fixed upstream commits;
their exact source correspondence to the published WASM remains unverified.
Publisher signatures and a reproducible upstream build are also unverified.

`workers/pg-parser/manifest.json` records the exact npm versions/integrities,
selected upstream JS bytes/hashes, lock hash, local asset/notice hashes, build
tool version and explicit protocol revision. TS/JS source hashes are build
provenance; runtime identity uses revision constants and deployed asset pins.
Raw hashes do not authenticate the producer. Packaging checks do not execute
the WASM or establish the runtime sandbox, resource bounds or SQL verdicts.


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
