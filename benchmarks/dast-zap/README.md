# Bounded ZAP policy, shared execution and owned pilot

## Problem and scope

Previously ZAP was a standalone HTTP query adapter. A fixed-plan or CI user could not combine its observations with the shared request ledger, and protected HTTPS/JSON API inputs were unsupported. This change uses the existing Node egress/admission and report/store code, without replacing the engine or adding model calls.

Success means the real pinned engine finds three declared owned SQLite/XSS flaws and rejects their three fixed controls, every received request equals the admitted count, and CLI/Action/run-plan preserve findings, incomplete gates and current artifact bindings. This is a deliberately small public pilot, not a production recall estimate or evidence that agents outperform a fixed plan.

## Operator contract

- Prepare ZAP **2.17.0**, Automation Framework **0.58.0**, active scan rules **78**, and Java (validated with 21). The scan never downloads/updates engines, installs target dependencies or starts the target.
- `policy.example.json` is a shape example. Replace the origin, reviewed seed paths, principal assertion and credential variable for an approved disposable target. The credential value never belongs in JSON.
- Policy: exact origin, 1..16 unique method/path pairs. GET requires explicit unique query names; POST has no query and exactly one top-level string/integer JSON field. Arrays, nested objects, extra fields, uploads and arbitrary verbs are refused. Seeds require HTTP 200.
- Optional Authorization requires HTTPS or explicitly allowed literal loopback HTTP. Principal before/after must match and anonymous identity must return 401/403. No login, cookies, token refresh, actor matrix or authorization diagnosis is inferred.
- All requests use one DNS-pinned Node peer. HTTPS enforces CA and hostname validation even if global Node TLS validation was disabled. For a private CA, start Node with `NODE_EXTRA_CA_CERTS=/approved/ca.pem`; do not disable TLS. Engine-facing HTTP is a virtual origin, not cleartext Internet forwarding. CONNECT is refused.
- Origin/path/method/query and bounded JSON validation precede upstream traffic. JSON is at most 4096 bytes, one declared field, mutated string at most 2048 characters. Duplicate keys/extra fields and chunked bodies are refused.
- Requests: default 200, maximum 2000 per ZAP task; rate 1..50/s. Auth controls, seeds and probes count equally. `run-plan` uses its existing global cap/rate/deadline across engines and concurrency, rather than refreshing the budget per task.
- `plan --zap-policy FILE --allow-private` validates offline. `scan --engine zap --url ORIGIN --zap-policy FILE --zap /prepared/zap.sh --active-consent` executes. Legacy `--zap-path` remains HTTP GET-only.
- `run-plan`: task `{"id":"t-zap","engine":"zap","policy":"owner-alias","maxRequests":200}` plus an existing SHA256 input alias. Set operator `--zap` / Action `zap-path`; engine paths or credentials are never agent task data. The separate `dast` Action accepts `engines: zap`, `url`, `zap-policy`, `zap-path` and ZAP budgets. Root source Action remains passive.
- Report gate: 0 completed with no threshold findings, 1 completed with threshold findings, 2 incomplete/error/refusal. `--fail-on none` never suppresses incompleteness. Check both wrapper exit and current delivery status.

Raw ZAP reports, payloads and responses stay in a private temporary directory and are removed. Four normalized reports retain rule, redacted location, hashed surface identity, remediation and counters. The shared runner additionally binds DB observation ID → evidence file → engine finding ID → task report; manifests hash the stored bundle. It preserves observed GET/query versus POST/body and authenticated state. These are stored-result consistency checks, not signatures proving request occurrence or creation time. Fixture-side counters independently observe requests in tests.

## Reproduce the owned pilot

```sh
npm ci
npm run build
WAKEIO_ZAP_PATH=/prepared/ZAP_2.17.0/zap.sh \
  node benchmarks/dast-zap/measure.mjs 5 /tmp/wakeio-zap-pilot.json
WAKEIO_ZAP_PATH=/prepared/ZAP_2.17.0/zap.sh \
  node --test build/tests/zap-policy.test.js build/tests/zap-integration.test.js
```

The measurement script creates only its own `127.0.0.1` port-0 fixture and sends active requests only there. No target URL can be supplied. SQLite interpolation and bound statements provide vulnerable/fixed GET and JSON routes; HTML reflection/encoding provides XSS counterparts. `labels.json` fixes six distinct rule/method/path/parameter units before measurement. Findings are deduplicated by that key; unexpected distinct findings count as FP. The benchmark uses the labels only after execution; it is public and has no hidden split.

Each of five preliminary repetitions uses a fresh fixture and ZAP process, cap 200 and rate 50/s. Elapsed time includes version checking, startup, seeds, three auth controls, active scan, shutdown and cleanup. It is not comparable to the source-only millisecond P0 baseline. See `pilot-results.json` for per-round values, label digest, runtime and limits.

## Observed pilot (2026-10-19)

On Node 22.23.1 / macOS arm64, five repetitions each returned TP **3**, FP **0**, FN **0**, TN **3**, with all three principal controls passing and **97/200** target requests. End-to-end elapsed p50 was **20,429.54 ms**, maximum **20,683.41 ms**. The scope contains three injected flaws and three fixed counterparts; these numbers do not estimate production accuracy or an improvement percentage. Per-round data and label digest are in `pilot-results.json`.

## Verification and remaining limits

Tests cover malformed owner input and request bodies with zero upstream traffic; worker credential/cookie stripping; private principal controls; initial anonymous-access failure and trailing principal expiry; global cap/rate across concurrent ZAP/native tasks; cancellation; trusted/untrusted/wrong-host TLS including unsafe global settings; actual ZAP detections; both actual bundled Actions; DB/evidence/report identity and four-report digests. The required-engine harness names these tests explicitly and refuses skips. Protocol stand-ins test transport failure semantics only; detection claims use the actual pinned engine.

The default two rules cover reflected XSS and SQL injection at selected inputs. No spider, browser/DOM XSS, OAST, arbitrary writes, OpenAPI-to-ZAP auto-import, stateful workflow, role/IDOR matrix, external-target benchmark, autonomous selection or production vulnerability coverage is claimed. Existing Schemathesis OpenAPI and explicit native/API actor controls remain separate lanes. The experimental agent-eval engine schema has not been changed.

The trusted installed ZAP process must honor its configured proxy. Node is an application-level gate, not an OS sandbox. Active requests can change state even with GET, so use an explicitly approved disposable target. Auth identity checks are start/end observations; transient identity changes returning HTTP 200 may be undetectable.

## Upstream evidence and choices

- [ZAP requestor contract](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/) and [pinned source](https://github.com/zaproxy/zap-extensions/blob/8b171e1c8704d2996b75d4bc119cbf9495d9aa12/addOns/automation/src/main/java/org/zaproxy/addon/automation/jobs/RequestorJob.java): request headers deserialize from strings, e.g. `Content-Type:application/json`; a list of objects failed real-engine initialization and was corrected before measurement.
- [Active-scan vectors](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascanconfig/): enable JSON only when POST seeds exist; disable multipart/XML/GWT/DWR, header/cookie/path/script vectors.
- [OpenAPI automation](https://www.zaproxy.org/docs/desktop/addons/openapi-support/automation/) has import-specific behavior. This change keeps reviewed seeds instead of allowing import/fetch/redirect behavior to widen the declared boundary.
- Core [2.17.0 source](https://github.com/zaproxy/zaproxy/tree/8a1bff313f4d183dba5aa154ecbe89ad751c9153); extensions [pinned implementation](https://github.com/zaproxy/zap-extensions/tree/8b171e1c8704d2996b75d4bc119cbf9495d9aa12).
