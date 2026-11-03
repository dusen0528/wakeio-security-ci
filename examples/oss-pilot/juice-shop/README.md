# Juice Shop: reviewable OSS pilot inputs

This is the input-only first step toward a v0.6 pilot. It adds no target
installer, launcher, scanner, orchestration change, release or version bump.
All files are independently owner-authored. They describe a reviewed subset,
not upstream's official OpenAPI specification or a discovered full API inventory.

**Execution is blocked.** The archive has not been downloaded or executed, its
downloaded bytes have not been verified, and the exact Node runtime version and
digest are unknown. The runtime pin is deliberately `null`, not a placeholder
digest. There is no approved runtime, local origin, target scan or rerun evidence.

## Offline review

From the repository root, with Node 22 or newer:

```sh
node examples/oss-pilot/juice-shop/validate-inputs.mjs
```

This reads the local fixture files, checks the pinned input contract and raw
schema SHA256s, and reports that execution remains blocked. It makes no network
requests, downloads nothing, starts no target, and grants no execution authority.
The compiled `tests/oss-pilot-inputs.test.ts` suite also checks compatibility with
the existing execution-plan/input parsers and explicit GET operation selector.

- `manifest.json`: source/release metadata, unverified runtime and bounded owner
  options. This is pilot metadata, not a new accepted `run-plan` schema
- `inventory.json`: two reviewed endpoints with provenance and distinct purposes
- `schema-normal.json`, `schema-error.json`: independent OpenAPI 3.0.3 JSON inputs
- `inputs.json`: existing owner alias contract; SHA256 binds each schema's raw bytes
- `run-plan.template.json`: existing task shape with an intentionally invalid
  `null` origin. Passing the committed template to `run-plan` must fail validation

The generic runner does not consume this pilot manifest or bind target/runtime
preparation to a run. Changing the origin alone is not an approved preparation
flow. There is intentionally no helper here that emits a runnable plan. A later
owner-reviewed preparation integration must establish the actual loopback origin,
verified pins, isolation and authorization before making a separate executable
copy. Tests substitute a synthetic loopback origin only to check parser shape;
they do not execute that plan or contact that origin.

## Pinned public evidence

Metadata was checked on 2026-10-14. The official annotated
[v20.3.0 tag](https://api.github.com/repos/juice-shop/juice-shop/git/tags/aa81d67fdeb83d497d29912f5f632da0c392dc44)
resolves to source commit `f189f521266f42c6bd05884468292000cee852ed`.
The [official release metadata](https://api.github.com/repos/juice-shop/juice-shop/releases/tags/v20.3.0)
declares `juice-shop-20.3.0_node22_linux_x64.tgz` with SHA256
`6148dcce8fe7d990a86bf8457a0e9a07821c127d498c76da1a3bc7dba12a77e5`.
This verifies the published metadata only, not the archive bytes, contents,
build provenance, installed dependencies or runtime behavior.

Juice Shop is [MIT licensed](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/LICENSE).
Attribution: OWASP Juice Shop, Bjoern Kimminich and the OWASP Juice Shop
contributors. No upstream implementation or test corpus is vendored here.
Preserve the upstream license if a later authorized preparation extracts its archive.

The pinned [route registration](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/server.ts),
[search implementation](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/routes/search.ts),
[response helper](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/lib/utils.ts)
and [upstream API tests](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/test/api/search.test.ts)
support the subset below. The upstream
[swagger.yml](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/swagger.yml)
describes only `POST /b2b/v2/orders`; it is not used as a GET search input.

## Finite inventory and limits

- `GET /rest/admin/application-version`: readiness only; never a scan task
- `GET /rest/products/search`: the only scan endpoint, anonymous, only query `q`
- Normal schema: required string `q` has the single value `nomatcheswhatsoever`;
  upstream tests expect HTTP 200 and an empty data array
- Error schema: required string `q` has the single short value `';`; upstream
  tests expect HTTP 500. There is no extraction query or broader payload search

The schemas accept the normal 200 JSON response shape (`status: success`, `data`
array). A 500 is intentionally not declared as a successful response. Current
Schemathesis live generation calls the pinned 4.2.0 direct `as_strategy()` API,
whose default is positive generation; required singleton enums constrain `q`.
See [the upstream API default](https://github.com/schemathesis/schemathesis/blob/v4.2.0/src/schemathesis/schemas.py#L652-L669).
Recheck this boundary before any future worker or engine-version change.

Each of the two tasks has seed 1 and an 8-attempt ceiling. Owner options are a
shared 16-attempt ceiling, 120000 ms, 2 admissions/second, concurrency 1,
`allowPrivate: true`, and `failOn: medium`. These are existing options, not added
plan fields. Finite generation can use fewer attempts than the ceiling; neither
8 per task nor 16 total is promised. Require actual attempts greater than zero
and completed status for both tasks. Count readiness separately, up to 12 GETs
over 60000 ms, and retain the combined preparation/scan totals.

An observed 500 yields `api.schemathesis.server_error`, a medium-severity,
high-confidence **observation**. HTML may produce a response-schema observation
as well, so do not require exactly one finding. Require a server-error observation
for the error case and no false finding for the normal case. This is a known
server-error contrast, not proof of SQL injection exploitability, data extraction,
a new vulnerability, or whole-service coverage. A default high-severity exit gate
would not necessarily block a medium observation; this pilot specifies medium.

## Approval and readiness checklist for a later execution

Every item below is pending. This input PR does not approve or implement it.

- Approve one local ephemeral runtime, its exact Node 22 version and full runtime
  binary/image SHA256, OS/architecture, and the download/start/scan/reset/cleanup scope
- Define and enforce numeric CPU, memory, process-count and wall-time limits;
  use non-root execution and disposable writable state
- Mount no host home, SSH/cloud credentials, host secrets or Docker socket;
  inherit no user tokens or unrelated environment secrets
- Allow preparation to fetch only the exact official archive; verify its bytes
  against the declared SHA256 before extraction. Reject traversal, absolute paths,
  unsafe links/special files and excessive expanded sizes/file counts; extract only
  into the newly created owned directory. Do not run install/postinstall/build hooks
- Deny target internet egress; allow scanner traffic only to the approved local app.
  A loopback URL and runner `allowPrivate` are not an OS sandbox. Never use a public demo
- Record readiness status/version 20.3.0 and the normal search's stable projection;
  count every readiness attempt and preserve failure/timeout rather than claiming clean
- Reset with a fresh instance and fresh writable state before each run; record
  configuration and stable selected data. Startup uses `sequelize.sync({force:true})`
  and seed creation, but time/random data means fresh state is not byte-identical state
- Clean up only this run's instance and owned temporary state; preserve a cleanup
  failure as a failure, not a successful final receipt

## Evidence and same-condition rerun acceptance

A later integration must bind source commit, verified archive bytes, exact runtime,
configuration, reset/readiness receipts, inventory, both raw schema digests, seed
and all owner limits to each run. The current generic run-start record binds owner
inputs but does not establish those target/runtime facts. This binding belongs in
the owner-maintained preparation/orchestration layer, outside this input-only PR.

Use two fresh output directories. Verify report/manifest hashes and the actual final
process status; a publication receipt alone proves neither process success nor
target readiness. Keep partial, skipped, failed, timeout, cancelled and zero-attempt
tasks distinct from completed clean checks. Expected normal/error findings must be
present on each run. Changed target/runtime/configuration/input/limits, missing
preparation evidence or state drift makes a same-condition claim unverified.

Existing task-level comparison can compare scanner evidence; it cannot fill missing
target/runtime binding. Save redacted statuses, counts, stop reasons, fingerprints
and artifact hashes, not raw request/response bodies, secrets or extracted records.
Source-analysis paths remain frozen. Changes to `src/agent-dast/**`, worker-result
schemas or migrations remain with their existing orchestration owner.
