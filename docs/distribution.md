# Distribution

Wakeio Security CI is a free local CLI and composite GitHub Action. It needs
no Wakeio account, subscription, hosted service, or AI token. Runner time,
storage, network access, and optional scanner downloads are supplied by the
user's environment.

## Current release paths

The source repository is public at
<https://github.com/dusen0528/wakeio-security-ci>. A reviewed checkout can be
cloned and tested directly:

```sh
git clone https://github.com/dusen0528/wakeio-security-ci.git
cd wakeio-security-ci
npm ci --ignore-scripts
npm test
```

Version `0.4.0-dev.1` is a development preview. The public Action reference
`dusen0528/wakeio-security-ci@main` is usable for preview runs; `main` can move,
so resolve and review a commit, then use its full SHA for production. Do not
invent a version tag or treat `@main` as an immutable release.

The npm package is still unpublished and there is no GitHub Marketplace listing
or GitHub Release for this preview. The supported package paths are therefore
a public or reviewed checkout, the preview Action reference, a local npm
tarball, or a vendored source archive.

```sh
npm ci --ignore-scripts
npm test
npm run package:release
```

Packaging reads the version from `package.json` and produces:

```text
artifacts/wakeio-security-ci-0.4.0-dev.1.tgz
artifacts/wakeio-security-ci-source-0.4.0-dev.1.tar.gz
artifacts/wakeio-security-ci-0.4.0-dev.1-SHA256SUMS.txt
```

The checksum file covers both archives. Verify it with `sha256sum -c` or
`shasum -a 256 -c` from the artifact directory. This command does not publish
anything.

The npm tarball contains the built CLI, runtime metadata, docs, examples, and
the scanner installer. The source archive has extraction root
`wakeio-security-ci/` and includes the prebuilt Action bundle, source, tests,
lockfile, and build scripts. Environment files, node_modules, Git metadata,
local reports, and previous release artifacts are excluded. Symlinked artifact
destinations are rejected.

## npm CLI

Until npm publication, install a reviewed local tarball:

```sh
npm install --ignore-scripts --save-dev /path/to/wakeio-security-ci-0.4.0-dev.1.tgz
npx --no-install wakeio-security-ci doctor --source .
npx --no-install wakeio-security-ci scan --source . --tools none \
  --project-id my-team/my-app --out wakeio-security-reports
```

`npx --no-install` resolves the locally installed binary. `--tools none`
selects built-in checks. Optional Gitleaks, OSV-Scanner, Trivy, and Bandit
must be installed or configured for their respective checks. Use `doctor` and
[the setup details](preview-0.4-distribution.md) for engine and network
requirements. A registry command is intentionally omitted until npm is
published.

## GitHub Action

For a first hosted preview, copy
[the public example](../examples/github-action.yml) into the consumer
repository's `.github/workflows/`. It checks out the application with
`persist-credentials: false`, invokes
`dusen0528/wakeio-security-ci@main`, and sets `tools: none` explicitly so the
run uses only built-in checks. The example pins checkout and artifact helper
Actions. Review the resolved Wakeio commit before relying on the result, and
replace `@main` with that full SHA for production.

For a controlled or offline setup, use a reviewed source archive vendored at
`vendor/wakeio-security-ci` and copy
[the local Action example](../examples/github-local-action.yml). Its local
Action reference is `./vendor/wakeio-security-ci`; the source collector
excludes `vendor/`, and the example uploads reports with `if: always()`.

The Action runs its prebuilt bundle without running npm install or a build in
the consumer job. When optional native engines are selected, it prepares them
from pinned, SHA-256 verified archives and verifies archive bytes again on
cache hits. Binary archive caches and scanner-managed advisory or policy
databases have separate provenance. A warm cache does not prove a fixed
advisory snapshot.

The default report directory is `wakeio-security-reports/`. The Action adds
`action-status.json`, a Job Summary, and outputs for report paths,
setup/scan status, exit code, findings, and incomplete checks. Source or API
failures do not become a clean result. `project-id` defaults to
`github.repository`.

Target package scripts, builds, tests, and hooks are not executed. Test-account
API credentials belong only in a separately controlled workflow; the ordinary
fork pull request job needs no API secrets. SARIF upload is optional and
GitHub-entitlement dependent; ordinary JSON/Markdown artifacts and exit-code
gating are sufficient for core use.

## Other CI providers

[Generic shell](../examples/generic-ci.sh) and
[GitLab](../examples/gitlab-ci.yml) examples use the same CLI. URL-only runs
can omit source and external source engines. Node.js 22 is required. There is
no published Docker distribution image in this preview.

## Verification and publication

[The verification record](verification-0.4.md) identifies which local
macOS/Linux, native scanner, and clean-consumer paths actually ran. A workflow
file in this repository does not prove that a GitHub-hosted job succeeded.

The public GitHub source repository and the `@main` preview Action are
available now. npm publication, a GitHub Release, and a Marketplace listing
remain separate release steps and have not occurred. The release-check
workflow creates reviewable local artifacts only; it does not publish to npm
or mutate a registry. The package adds no usage telemetry.
