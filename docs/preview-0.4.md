# 0.4 development preview

This version improves source accuracy, authorization evidence, comparison identity, URL scope and CI distribution. It remains a free standalone local package. No Wakeio account, proprietary server or AI token is required. Nothing in `package:release` publishes to npm or GitHub.

## Source coverage

```sh
node build/src/cli.js scan --source /path/to/app --tools none --project-id team/app
```

The built-in source checks now cover bounded destructured request roots, loop bindings, supported Next route inputs, JSX HTML sinks and selected raw SQL calls. Framework checks add static `.env`/`next.config.env` and relative client import/re-export candidates. An explicit file-level `use server` boundary stops client import propagation, and a React import alone is not client-boundary evidence. Server Action return-value leakage and general interprocedural/type-aware analysis remain outside scope. The boundary follows the [Next.js Server Function import contract](https://nextjs.org/docs/app/api-reference/directives/use-server).

Supabase SQL handling distinguishes nested comments, ordinary/escape strings and quoted table identifiers. A bounded migration-history candidate reports a created table with SELECT/INSERT/UPDATE/DELETE/ALL granted to a public role and no observed RLS enable. Later migrations, effective schemas and live privileges are not proven by this check.

Python requirements must be fully pinned and self-contained to be sent to OSV. Unresolved ranges/includes/URLs remain partial. Bandit is optional and operates only on selected Python files. See [source details](preview-0.4-source.md).

## Explicit URL scope

```sh
node build/src/cli.js scan \
  --url https://your-app.example \
  --page https://your-app.example/pricing \
  --page https://your-app.example/docs \
  --max-pages 3 --tools none
```

The root is included in the page count. Additional pages must be explicit and share the origin; the hard page limit is eight. Linked same-origin JavaScript may lead to bounded static module imports/re-exports. Collection shares request, byte and script budgets across pages. Dynamic imports, browser execution, external modules and automatic anchor crawling are excluded.

CSP observations account for script fallback, nonce/hash sources, strict-dynamic and enforced policy intersection. These remain static policy observations, not browser exploit validation. Invalid nosniff/referrer values are distinguished from missing headers.

## API policy v2

Use [the example policy](../examples/api-authorization-policy.json) and [API guide](preview-0.4-api.md). Authenticated actors declare an identity endpoint and expected principal; cases declare both a resource identity and distinct protected string value. Credentials come from named environment variables.

```sh
node build/src/cli.js scan --api-policy /path/to/api-policy.json
```

Identity controls run before and after case execution. Owner positive controls run around deny probes. A confirmed protected-data leak is a finding even in a 403 response. A public ID echoed in an error is not sufficient evidence of a leak. Expired tokens, indistinguishable actors, rate limits and inconsistent controls leave coverage incomplete. Version 1 policies are accepted as partial evidence, not a clean authorization verdict.

No write operations, payment actions, endpoint discovery or general fuzzing are performed.

## Report comparison

Use the same logical project identity across developer and CI checkout paths:

```sh
node build/src/cli.js scan --source . --tools none --project-id team/app --out /tmp/before
# Make a change, then scan again with the same options into /tmp/after.
node build/src/cli.js compare --before /tmp/before/report.json \
  --after /tmp/after/report.json --out /tmp/comparison --fail-on high
```

Semantic source anchors are separate from display line/column. Duplicate anchors are ambiguous and remain unverified. Findings without semantic anchors retain location-based matching. Scope records the logical project and options separately from source-content evidence and selected engine hashes; executable installation paths do not define scope.

Unknown external advisory/rule data, mismatched rules or engines, and incomplete scans prevent a comparable verdict. `not_observed` is not proof of a fix. SARIF includes tool fingerprints and a stable analysis category; GitHub-hosted alert deduplication has not been verified in this local preview.

## First use and CI

```sh
node build/src/cli.js doctor --source /path/to/app
node build/src/cli.js init --help
```

`doctor` inspects inputs and available engines without network requests or target execution. `init` creates explicit starter files and refuses to overwrite existing files. See [distribution setup](preview-0.4-distribution.md) for the exact generated-file options.

The source archive includes the prebuilt Action bundle. Consumers do not need to install the tool's development dependencies or compile TypeScript at scan time. Native scanner archive caches are re-hashed against pinned upstream digests. Scanner-managed vulnerability databases remain separately identified as unknown provenance.

The Action exposes setup status, scan status, report paths, finding and incomplete counts, and exit code. Examples preserve failure artifacts in the visible `wakeio-security-reports/` directory. The default PR workflow requires no API credentials; run credentialed API checks in a separately controlled job. See [distribution](distribution.md).

## Evidence

[Verification](verification-0.4.md) records the actual tests, native-engine execution and package acceptance. It also distinguishes local Linux execution from an unexecuted GitHub-hosted workflow. [The prior analysis](research/next-iteration-analysis-2026-09-16.md) records the reasons for these changes; it is a historical analysis, not the final coverage contract.
