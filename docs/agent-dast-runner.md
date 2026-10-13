# Reviewed agent plans with a trusted built-in executor

`run-plan` connects an agent-authored JSON selection to the existing native DAST,
Schemathesis and Nuclei adapters. It executes 1..16 tasks concurrently, with one
owner-controlled admission budget and deadline across them. It does not call a
model, execute agent code, install tools, apply a patch, or give an agent SQLite
write access. This is experimental DAST execution; source analysis still uses
`scan --source`.

Use a reviewed source build or package containing `built-in-plan-run-v1`.
`run-plan` uses the existing store runtime boundary: Node 22.13+ within 22.x,
23.4+ within 23.x, or 24+. Its disk store requires POSIX file ownership and
private permissions. The ordinary scanner's runtime contract is unchanged.

## Plan and owner inputs

The agent proposes `plan.json`. The owner grants file aliases independently in
`inputs.json`, and reviews the target, tools and limits before providing consent.
The plan cannot select executable paths, arbitrary headers, code, providers,
credential values or a database path.

```json
{
  "version": 1,
  "kind": "wakeio.execution-plan",
  "origin": "https://owned.example",
  "tasks": [
    { "id": "t-injection", "engine": "native-dast", "policy": "sql_policy", "maxRequests": 12 },
    { "id": "t-contract", "engine": "schemathesis", "schema": "api_schema", "authPolicy": "api_auth", "operations": ["/items/{id}"], "seed": 1, "maxRequests": 16 }
  ]
}
```

Task IDs are unique `t-` names containing 1..40 lowercase letters, digits or
hyphens. Input aliases contain 1..40 lowercase letters, digits or underscores or
hyphens, beginning with a letter. Unknown fields and malformed values reject.
The third task form is `{ "id":"t-exposure", "engine":"nuclei",
"scopes":["exposures"], "maxRequests":100 }`; only the existing
`misconfiguration` and `exposures` scopes are available.

`inputs.json` has exactly `{ "version":1, "inputs":[{ "id":ALIAS,
"path":FILE, "sha256":DIGEST }] }`, up to 32 unique aliases. Relative paths
resolve against the manifest's directory. Each referenced file must be a regular
non-symlink JSON file no larger than 1 MiB. SHA256 is over **raw file bytes**,
not canonical JSON. The executor reads once through a bounded file descriptor,
checks stability and digest, and uses that parsed snapshot. Policies, generated
requests, assertion values and credentials are not copied into the run bundle.
An empty alias list is valid for a Nuclei-only plan.

The inputs use the existing [native policy](native-dast.md) and
[authenticated Schemathesis policy](schemathesis-auth-controls.md) contracts.
Schemathesis operations are explicit GET path templates. Its optional `authPolicy`
must cover exactly that selected set and provide principal and normal controls.
Credential environment values are selected with the existing own-data helpers;
the executor does not enumerate or copy unrelated environment secrets.

## Execute and use the reports

```sh
wakeio-security-ci run-plan --plan plan.json --inputs inputs.json \
  --allowed-origin https://owned.example --active-consent \
  --max-requests 64 --timeout-ms 120000 --rate-per-second 10 \
  --concurrency 2 --fail-on medium --out ../plan-results-001
```

The output directory must not exist, even if empty. Existing parent directories
must be real directories, except the exact macOS system aliases `/var` to
`/private/var` and `/tmp` to `/private/tmp`. Arbitrary symlink ancestors reject.
The output is atomically claimed with private permissions
before traffic; individual files are published afterward. This is not an atomic
filesystem tree transaction or an OS sandbox. Keep inputs and reports outside
untrusted worktrees where practical.

Global limits are owner CLI options: 1..20000 admitted HTTP attempts (default
64), 1..600000 milliseconds (default 120000), 1..150 admissions/second (default
10), concurrency 1..4 (default 2). Each task also retains its existing engine's
local request cap. A global cap smaller than the task sum can yield useful
partial evidence and exit 2; it never creates another budget per task. Controls
consume the same admission budget as probes. `requestCount` means admitted
attempts, including failed attempts and possible cancellation immediately
before transmission; `responseCompleted` means complete HTTP responses, not
successful oracle/schema adjudication. Body bytes exclude headers and TLS
overhead. Global attempt lists are empty; ordered metadata is task-local.

Plaintext credentialed native/Schemathesis traffic is restricted to explicit
private loopback fixtures with `--allow-private`. Native and authenticated
Schemathesis retain their existing pinned HTTPS/TLS transport. Nuclei and
unauthenticated Schemathesis HTTPS plans are refused because opaque CONNECT
cannot attest the shared HTTP request count. No TLS verification bypass is
provided. Engine paths are owner options `--schemathesis-python`, `--nuclei`
and `--nuclei-templates`; preparation is separate from scanning.

The fresh output contains:

- `run-start.json`: redacted declaration of expected task IDs/engines, input
  digests, scope and owner limits, written before target traffic.
- `tasks/<task-id>/report.json`, `report.sarif`, `report.md`, `agent-report.json`:
  unchanged task-local report contracts, avoiding ambiguous repeated check IDs.
- `run-report.json`, `run-report.md`, `agent-run.json`: task gates, report links
  and digests, admission counts and fixed stop reason. No aggregate synthetic
  vulnerability finding is created.
- `run.db` and `evidence/*.json`: private controller audit metadata and redacted
  finding references. Agents and engine workers are not given database authority.
- `run-manifest.json`: exact relative artifact paths, byte counts and SHA256.
- `run-receipt.json`: final `publication_only` marker binding the manifest and
  root report. It explicitly does not prove final process or Action success.

The database is an audit filled after each engine result. Its group assignments
and later finding-context registrations are not a live scheduler, crash-recovery
authority, preplanned endpoint denominator or clean endpoint coverage. Actual
native endpoint/parameter/location/auth identity is retained for deduplication;
Schemathesis/Nuclei findings retain their own observed locations. Failed storage
is incomplete, with best-effort error termination and already saved observations
preserved. The existing general store SDK lifecycle is unchanged.

Exit priority is **2 incomplete/cancelled/delivery failure**, then **1 findings at
the owner threshold**, then **0 all selected engine groups completed below that
threshold**. `--fail-on none` disables only severity blocking. It cannot suppress
incompleteness. Reports remain useful when another task fails. A publication
marker is not a whole-service safety or independent exploit/fix claim.

Use existing advice on an individual task report:

```sh
wakeio-security-ci advise --report ../plan-results-001/tasks/t-injection \
  --agent codex --auth cli-login --allow-report-upload --out ../advice-001
# API-key authentication is the existing alternative: --auth api-key, with CODEX_API_KEY.
```

Advice is optional, unverified and nonexecuting. Apply a reviewed change yourself,
rerun the same plan with a new output directory, then use the existing task-level
`compare` or native `replay` interface. A changed policy, schema, template scope
or owner limit changes declared scope; it must not be presented as verified
remediation under the earlier scope.

## CI Action

The separate composite is `dusen0528/wakeio-security-ci/actions/run-plan@<reviewed
full commit SHA>`. Use a commit containing this Action, pin the full SHA, and
prepare engines separately. It calls the checked-in bundle with argv arrays,
uses the same CLI authority boundary, validates manifest/task-report hashes,
and acknowledges the current child exit separately. It does not install or
build the target. Upload the fresh output with `if: always()`; deployment jobs
must explicitly depend on the scan job to be blocked by its outcome.

The owned workflow `.github/workflows/run-plan-self-test.yml` exercises the actual
composite risk, normal and incomplete gates. Its controls validate this bounded
execution contract, not commercial scanner accuracy or arbitrary target coverage.

For an owner-triggered CI run, replace both pins below with reviewed full commit
SHAs, select the actual authorized origin, and prepare the input files and any
external engines separately. The output suffix is generated by GitHub, not agent
data. This workflow installs no target dependencies.

```yaml
name: Reviewed DAST plan
on: workflow_dispatch
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@REPLACE_WITH_REVIEWED_FULL_CHECKOUT_SHA
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          node-version: '22'
      - uses: dusen0528/wakeio-security-ci/actions/run-plan@REPLACE_WITH_REVIEWED_FULL_WAKEIO_SHA
        with:
          plan: security/plan.json
          inputs: security/inputs.json
          active-consent: 'true'
          allowed-origin: https://owned.example
          max-requests: '64'
          timeout-ms: '120000'
          rate-per-second: '10'
          concurrency: '2'
          fail-on: medium
          out: wakeio-plan-${{ github.run_id }}-${{ github.run_attempt }}
      - uses: actions/upload-artifact@REPLACE_WITH_REVIEWED_FULL_UPLOAD_SHA
        if: always()
        with:
          name: wakeio-plan-${{ github.run_id }}-${{ github.run_attempt }}
          path: wakeio-plan-${{ github.run_id }}-${{ github.run_attempt }}
          if-no-files-found: warn
```

The Action accepts the same global controls plus owner-only `schemathesis-python`,
`nuclei-path` and `nuclei-templates` paths. It requires a supported preinstalled
Node runtime. Its outputs distinguish `exit-code`, `scan-status` and
`delivery-status`, with paths for the current root report, agent bundle,
manifest, publication marker and wrapper receipt. Review both the final Action
outcome and digest-verified delivery; the publication marker alone is insufficient.
