# Native numeric SQL differential preview

This preview is available from the source checkout and implements an original bounded HTTP(S) probe. It needs Node.js 22+, no external DAST binary, and an explicitly authorized target. It does not call a model. Build this checkout with `npm run build`; these commands are not available in the published npm 0.4.0 package, and npm 0.5.0 has not been published.

## Declare the checked behavior

Supply one URL, one existing unique query parameter with a nonnegative decimal value, and a known scalar JSON oracle. For an owned `/items?id=1` endpoint returning `{ "count": 1 }`, a policy can be:

```json
{
  "version": 1,
  "kind": "sql-boolean-differential",
  "baseUrl": "https://staging.example.test/",
  "url": "https://staging.example.test/items?id=1",
  "parameter": "id",
  "profile": "numeric",
  "oracle": {
    "jsonPointer": "/count",
    "expectedBaseline": 1,
    "expectedTrue": 1,
    "expectedFalse": 0
  }
}
```

Choose the oracle from the behavior of your authorized endpoint. `expectedTrue` must equal `expectedBaseline`; `expectedFalse` must differ. The parser rejects unknown keys, duplicate occurrences of the selected parameter, nonnumeric initial values, URL credentials/fragments, and an origin change. It preserves other supplied query parameters and never discovers additional paths or parameters.

```sh
# Offline validation only: no DNS, HTTP, model calls or scan reports.
node build/src/cli.js plan --dast-policy dast-policy.json

# Explicitly authorized active scan.
node build/src/cli.js scan --dast-policy dast-policy.json --active-consent \
  --allowed-origin https://staging.example.test --out dast-reports
```

Private/loopback targets need `--allow-private` in both commands; metadata/link-local addresses remain blocked. `plan` exit 0 means local configuration is ready, not that DNS, TLS, or the target has been checked. A plan below eight allowed attempts is blocked. Direct `scan` accepts lower budgets but must finish incomplete when the plan cannot complete.

## Authenticated numeric policy v2

For an authorized endpoint protected by an existing Authorization credential, use version 2 with the same numeric URL/parameter/oracle fields and these additional fields:

```json
{
  "version": 2,
  "kind": "sql-boolean-differential",
  "baseUrl": "https://staging.example.test/",
  "url": "https://staging.example.test/items?id=1",
  "parameter": "id",
  "profile": "numeric",
  "authorizationEnv": "STAGING_AUTHORIZATION",
  "identity": {
    "path": "/whoami",
    "status": 200,
    "jsonPointer": "/user/id",
    "equals": "owned-test-user"
  },
  "oracle": {
    "jsonPointer": "/count",
    "expectedBaseline": 1,
    "expectedTrue": 1,
    "expectedFalse": 0
  }
}
```

Supply `STAGING_AUTHORIZATION` through your local secret manager or CI environment. Its value is the **complete Authorization header**, not a token that Wakeio prefixes automatically. Keep the credential out of policy JSON, command arguments and committed workflows. Wakeio reads only the selected own environment property; missing/blank, control-character, non-Latin-1 or oversized values are refused. Each scan and replay captures a fresh selected credential and uses that value throughout its run. There is no login, credential refresh, cookie jar, discovery or unauthenticated fallback.

Authenticated requests require HTTPS. The only plaintext exception is explicit `--allow-private` with literal `127.0.0.1` or `[::1]` for owned tests; `localhost`, other private HTTP addresses and public HTTP are refused offline before DNS. The identity path stays on the same origin and cannot contain a query or fragment. `identity.status` is a 2xx status and `identity.equals` is a nonempty bounded string. Choose an identity response that distinguishes the intended principal; a public or misleading response cannot establish authentication.

Profile `sql-boolean-numeric-auth-v2` sends identity-before, the original eight SQL requests, then identity-after. All ten logical requests and DNS-address retries share one budget: default 10, maximum 64. Version 1 retains its original profile, policy hash behavior and default 8. Offline `plan` requires the selected credential and enough budget, printing enum phase records, origin, digests and effective limits. It omits identity path/pointer/principal, environment name and credential. Configuration readiness does not validate the live target or credential.

Both identity controls must match for a completed v2 result. A mismatch or failed trailing control keeps the check partial/exit 2. If all eight SQL phases already observed the differential, the report retains a **low-confidence candidate** with `probeOutcome: observed`; overall `outcome` stays inconclusive and cannot authorize finding replay. A before-control failure prevents SQL probes. Boundary identity checks cannot exclude a mid-run change or prove the SQL endpoint used the same principal.

The redacted v2 ledger has ten phase records plus `identityControls.before/after` (`matched`, `mismatched`, `inconclusive`, `not_attempted`) and `probeOutcome` (`observed`, `not_observed`, `inconclusive`). Scope binds revision, policy digest and effective budget, never the credential value. Reports and advice omit identity values and credentials. Advice projection policy 5 receives these enums only; failed controls expose diagnostics, not replay.

Supply the selected credential as an active Action step environment secret and omit `dast-max-requests` to use the policy-derived default:

```yaml
- uses: dusen0528/wakeio-security-ci/dast@REVIEWED_COMMIT_SHA
  env:
    STAGING_AUTHORIZATION: ${{ secrets.STAGING_AUTHORIZATION }}
  with:
    active-consent: 'true'
    allowed-origins: https://staging.example.test
    dast-policy: authenticated-dast-policy.json
    out: dast-reports
```

Consent, trigger/fork and origin refusals still run before engine setup. The passive Action is unchanged. SDK callers can pass `env` explicitly to `runDast` and `replayDastFinding`; selected credentials are snapshotted before awaits. `prepareDastPolicy` returns only validated policy/digest, and `snapshotDastEnvironment` returns a private one-key environment for v2 or undefined for v1. Do not serialize that private environment.

## Fixed execution and evidence

The only mutation is appending a fixed numeric true or false SQL predicate to the approved value. Each of two rounds performs baseline, true probe, false probe, baseline: eight logical GET requests. Both normal baselines must match the configured oracle in both rounds. A repeated true/baseline match and false/false-oracle match produces a **candidate**, not independent exploit verification. If both valid probes return the same known oracle value consistently and all baselines pass, the result is `not_observed` within this policy only. Unknown values, a changed baseline, disagreement between rounds, 429/5xx, malformed JSON, oversized bodies, network errors, cancellation and incomplete budgets remain `partial`/`inconclusive`.

The native runner uses Wakeio's Node transport directly: DNS answers are checked, sockets are pinned and peer-checked, TLS certificate/hostname verification remains enabled, and redirects are refused. Every HTTP attempt, including a retry against another approved DNS answer, consumes the shared request budget before sending. The default is 8 attempts for v1 and 10 for v2, maximum 64; timeout is capped at 120000 ms. Response collection is bounded per response and per run. Nuclei's separate HTTPS refusal is unchanged because its CONNECT proxy cannot count HTTP requests inside TLS.

`report.json` and `agent-report.json` carry a sanitized `checks[].dastExecution` ledger: policy digest, profile revision, effective attempt/time/private-network settings, eight v1 or ten v2 fixed phase records, HTTP statuses, counts and oracle-match categories. Reports retain no response body, original query value, oracle scalar, credential or model output. Markdown summarizes this scope; SARIF includes the ledger with a candidate finding. Missing, malformed, inconsistent or unsupported execution evidence cannot support a completed native check. Comparison requires unchanged policy and effective execution settings.

Exit 0 means the requested checks completed without a finding at the selected threshold; exit 1 means a threshold finding; exit 2 means incomplete/error. `--fail-on none` never converts incomplete work to success. No finding means the selected differential was not observed, not that the service is free of SQL injection.

## GitHub Action and SDK

Use the separate active DAST Action:

```yaml
- uses: dusen0528/wakeio-security-ci/dast@REVIEWED_COMMIT_SHA
  with:
    active-consent: 'true'
    allowed-origins: https://staging.example.test
    dast-policy: dast-policy.json
    dast-max-requests: '8'
    out: dast-reports
```

The Action validates the native policy through the same offline `plan` parser before preparing any selected engine. It also requires a listed origin and rejects untrusted fork triggers and `pull_request_target`. It invokes the committed CLI bundle without npm installation in the consumer checkout. The passive root Action remains passive.

The SDK exports `parseDastPolicy`, `runDast` and `sanitizeDastExecution`. Pass the parsed `policy` to `runDast({ policy, consent: true, allowPrivate, maxRequests, timeoutMs, signal })`; the runner validates and snapshots inputs again. Returned checks use the same standard report writers and gate as the CLI.

## Optional Codex advice

After reviewing the scan, explicitly request advice from your selected Codex CLI. See [the advice contract](agent-advice.md) for authentication and subprocess limitations:

```sh
# Use that CLI's existing login.
node build/src/cli.js advise --report dast-reports --agent codex \
  --auth cli-login --allow-report-upload --out dast-advice

# Or use CODEX_API_KEY supplied through the environment.
node build/src/cli.js advise --report dast-reports --agent codex \
  --auth api-key --allow-report-upload --out dast-advice-key
```

The command checks the report/agent-report digest pair and sends a capped, redacted metadata projection. It does not send source files, request values, raw responses or target credentials. Authentication is selected explicitly; failure does not switch auth modes. It writes a new private `agent-advice.json`, bound to the report digest. Advice is unverified, cannot modify scan evidence or gates, and is not applied to source. Only `advise` invokes the provider; `scan` stays model-free. A separate authorized `repair` flow retains its own source-upload consent and frozen verification contract.

## Validation scope and provenance

The native engine suite compares a real SQLite concatenated query with a parameter-bound query in an owned fixture. Transport/report/Action tests use additional labeled synthetic responses to exercise errors and integration. These checks establish their declared fixture behavior; they do not establish production coverage or validate a user's target.

For a reproducible CLI run against only those two owned loopback endpoints, build this checkout and choose a new absolute artifact directory:

```sh
npm run build
node examples/native-dast-demo.mjs --out /absolute/path/to/new-native-dast-demo
```

The example uses Node.js 22.13+ for `node:sqlite`. It starts an in-memory SQLite endpoint with a concatenated query and then one with a bound parameter, runs the same CLI with an eight-attempt limit and explicit loopback consent, and writes each case's `report.md`, `report.json`, `report.sarif`, and `agent-report.json` under `vulnerable/` or `bound/`. The candidate run exits 1 at the `high` threshold; the bound-parameter control exits 0. The script refuses to overwrite an existing artifact directory. The `vulnerable/agent-report.json` file can be supplied to the separate advice flow through its containing report directory after review. This demonstration makes no claim about a live service.

The implementation was informed by a review of real MIT-licensed OSS DAST sources, documented with pinned revisions in [the research record](research/mit-dast-engine-2026-10-13.md). No upstream engine source or template bundle is incorporated into this native probe. Other DAST engines retain their own dependency and license notices.


## Repeat a native finding with its original policy

Use the finding ID from `report.json` and the original local policy file. The command requires fresh active consent and a new output directory:

```sh
node build/src/cli.js replay --report dast-reports/report.json \
  --dast-policy dast-policy.json --finding <64-character-finding-id> \
  --active-consent --out dast-replay
```

For an originally private/loopback target, add `--allow-private` explicitly again. The receipt cannot grant that permission. The original report must fit the replay snapshot limit of 1 MiB of JSON data; larger reports are refused before traffic. Replay checks the policy digest, candidate identity and complete original versioned ledger (eight v1 or ten v2 phases) before making requests. Authenticated v2 additionally resolves a fresh selected credential and requires both original identity controls to match. Partial trailing-identity candidates are not replayable. It preserves the original maximum request count, timeout, profile and private-network setting; overrides are refused. Existing output directories are refused before traffic. API authorization replay continues to use `--api-policy`.

A complete repeated differential returns `reproduced` (exit 1). A complete baseline-preserving non-differential returns `not_reproduced` (exit 0). Incomplete or ambiguous execution returns `inconclusive`; invalid evidence, policy or permission returns `refused` (both exit 2). These are bounded scanner outcomes, not independent exploit or fix verification.

`replay.json` has `kind: "native-dast-finding-replay"`, the selected finding ID, policy/profile identity and source/fresh execution digests. `sourceReportSha256` identifies the bounded JSON-data snapshot serialization, not the original file bytes. An executed check also produces the usual four reports, and `reportArtifact` binds the receipt to the fresh `report.json` file bytes using SHA-256. Cancelled or failed output delivery exits 2 without retaining a successful replay receipt. A refusal writes only the replay receipt. Original reports are never changed. SDK callers can use `replayDastFinding` and `dastReplayExitCode` with the same policy and consent boundaries.


To exercise the full replay flow on one owned SQLite endpoint, use Node.js 22.13+ after building this checkout:

```sh
node examples/native-dast-replay-demo.mjs --out /absolute/path/to/new-replay-demo
```

The demo first records the vulnerable candidate (`original/`, exit 1, eight GETs), repeats it (`reproduced/`, exit 1, eight GETs), switches the same endpoint to parameter binding (`not-reproduced/`, exit 0, eight GETs), then to a server error (`inconclusive/`, exit 2, one GET). Each directory contains `report.json`, `agent-report.json`, `report.md` and `report.sarif`; the three replay directories also contain `replay.json`. `<out>/demo-receipt.json` records the outcomes, request counts and report digests, and checks that the original reports remain unchanged. The demo refuses an existing output directory. Its non-reproduction result demonstrates this fixture's behavior and does not verify a fix in a real service.
