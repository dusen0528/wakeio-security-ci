# P1a: offline OpenAPI GET inventory

P1a enumerates declared GET operations. It does not discover source routes, inspect frameworks, infer authorization policy, generate a plan, resolve DNS, send HTTP, invoke a model or execute a target script/configuration. P1b owns source-route discovery and further fixture variants.

## Command and compatibility

```sh
wakeio-security-ci init-dast --source /absolute/project \
  --openapi /absolute/openapi.json --out /existing-parent/new-inventory \
  --url https://owner-selected.invalid
```

`--source`, `--openapi` and `--out` are required. `--url` is optional and validates/normalizes only an HTTP(S) origin; no hostname is resolved. Userinfo, query, fragment and a non-root path are refused. OpenAPI `servers` is never used. The source directory must exist; its tree is not traversed and no source code/configuration is read or run. Only the explicitly selected OpenAPI JSON file is read, including when that file is inside source. Output must not exist, must be outside source, and its parent must already exist. Caller symlinks are refused; verified macOS `/tmp` and `/var` system aliases are accepted. The OpenAPI file is a stable, bounded regular UTF-8 JSON file read with the existing no-follow reader.

Only private `inventory.json` is written (directory0700/file0600). Existing files are never overwritten. Failure to publish is exit2; a leftover output from an unsuccessful publication must not be treated as successful evidence or reused.

The first successful stdout line is a scope summary, for example:

```text
Inventory status=partial partial=1 unverified=2 GET=1
```

`status` is the OpenAPI GET enumeration state. `partial` counts unresolved path-items; `unverified` counts emitted unverified entries, including the always-present source-routes entry. This is not a vulnerability or whole-project coverage summary.

Exit0 means an inventory was produced, including explicitly partial/unverified results. Exit2 means invalid arguments/input/path/origin or output failure. No finding gate1 is introduced. Existing `init`, its npm/Action modes, flags, workflow templates and exit meanings are unchanged. Frozen pre-P1a main templates are in `tests/fixtures/compat-0.5/init/`.

## Minimal emitted contract

[JSON Schema](surface-inventory.v1.schema.json) describes only emitted P1a fields:

- `schema`: `wakeio.surface-inventory/v1`.
- `origin`: normalized caller-supplied origin or null.
- `scope.openapi_get`: `observed`, `none_detected` or `partial`.
- `scope.source_routes`: always `unverified`.
- `surfaces`: sorted unique `{method:"GET",pathTemplate}` declarations.
- `unverified`: source-routes/deferred-to-P1b entry and unresolved path-item entries with fixed reason codes.
- `counts`: declared GET total (null when unknown), enumerated GET count, unresolved path-item count.

There are no framework, source-digest, evidence, authentication, check-plan, task-ID, timestamp or run-ID fields. The contract is not yet the 1.0 stability promise.

A fully inspected document with no GETs has `none_detected`, an empty surface list and declared count0. This includes a POST/HEAD-only document and empty `paths`. An unresolved path-item makes the state `partial` and declared total null, while already-known GETs remain listed. Neither case says source routes were checked: `source_routes` remains `unverified` in every result.

Operation identity is the exact method/path pair, not `operationId`. Path case, trailing slash and declared alias paths are preserved. A component path-item used at `/items` and `/archived-items` yields two declarations. Non-GET methods are ignored in P1a. Required bindings or auth input do not remove a GET declaration; inventory is not execution readiness.

Output contains endpoint templates, so treat it as private. Description/default/example/parameter values, response schemas, target source strings and credentials are not copied. It is not an attestation that every arbitrary endpoint name is public data.

## Pure enumeration and existing boundaries

`enumerateOpenApiGetOperations` in `src/openapi.ts` accepts JSON data only. It reuses `snapshotJsonData`, the existing limits and shared same-document pointer grammar. It resolves path-item references only; nested response/parameter data are not executed or fetched. A remote path-item, unresolved local pointer, cyclic path-item or unsupported ref siblings produces a fixed unresolved reason. Structural errors and hard limits fail.

The existing execution compiler/selector retains its whole-document reference validation, explicit operation selection, GET execution restrictions and failure behavior. P1a's support for empty paths/partial enumeration does not widen those execution parsers.

Limits:1MiB JSON,20,000 nodes,depth40,1,000 paths,256 path-item reference steps. Existing simple path-template validation is reused. No YAML, external file/URL reference loading or target script evaluation is added.

## Inventory KPI and independent ground truth

`benchmarks/inventory-corpus.json` fixes raw fixture SHA256 values and manually reviewed expected GET sets. Eight files are used:

| Fixture | Expected GET paths | Declared total |
| --- | --- | ---: |
| existing-live | `/items/{id}`, `/search` | 2 |
| existing-worker | `/items` | 1 |
| existing-preflight | `/documents/{id}`, `/whoami` | 2 |
| inline-unselected | `/documents/{id}`, `/unselected`, `/whoami` | 3 |
| local-path-item-alias | `/archived-items`, `/items` | 2 |
| no-get | none | 0 |
| empty-paths | none | 0 |
| unresolved-path-item | known subset `/local`; remote item unknown | null |

The first three are static copies of existing repository documents; preflight copies only its `document`, excluding actors/assertions. Inline-unselected materializes the previously-inline paths; `/unselected` must be included despite not being in the old execution allowlist. The alias fixture includes the existing `~1`/`~0` pointer escapes. Expected output is never generated from the detector.

`kpi.mjs` measures the selected trusted engine's exported enumerator. Each fixture is evaluated three times. It checks exact known GET sets, absence of duplicates/unexpected GETs, declared counts, state and unresolved counts. Evidence includes per-case expected/observed sets and deterministic bytes. SHA256 values and the corpus are bound into the KPI context.

Micro recall uses only known, nonzero denominators:10 expected GETs across five fixtures. The two zero-GET fixtures are `not_applicable/null`; the unresolved fixture is `unavailable/null`, with its known subset still compared exactly. They are not counted as100%. Any set/count/state/determinism mismatch fails the KPI gate, including equal-sized but different sets. A base engine without the new enumerator remains `inventory_recall: unavailable`; it is not assigned a fabricated baseline.

Run the same offline KPI workflow for base/candidate. P1a tests run under Docker `--network none`, including the URL string and remote-ref fixture, source lifecycle/config non-execution, three identical inventory files, and frozen legacy init output. The full existing suite separately uses repository-owned loopback HTTP fixtures; no external target or live model is required. Schema/input tests do not constitute vulnerability or whole-service coverage evidence.
