# OpenAPI and API sessions (v2)

`policy.openapi.example.json` is a shape example, not permission to scan a service. Set its exact origin, selected operations and principal assertion for an approved disposable target. The CLI and both Actions use the existing policy file/path inputs; `run-plan` binds the complete file through the existing SHA256 alias. Version 1 stays compatible.

## Prepare and run

1. Export an OpenAPI **JSON** document locally and review the operations you permit. Embed it as `openapi.document`; `openapi.operations` is an explicit allowlist. Document `servers`, security declarations, callbacks, unselected operations and external reference authority never become scanning authority. Same-document refs reuse WakeIO's resolver; remote/file/cyclic refs are refused before traffic. There is no schema URL fetch.
2. Supply concrete path/query values or bounded schema examples/defaults for the selected operations. POST seed bodies may contain nested objects/arrays. Login/refresh/identity paths must be separate from attack paths. No target launch or dependency installation happens during scanning.
3. Set the environment variables named by the authentication policy outside JSON. Use HTTPS, or explicitly approved literal-loopback HTTP with `--allow-private`. Start Node with `NODE_EXTRA_CA_CERTS=/approved/ca.pem` for a private CA.
4. Validate offline, then run:

```sh
node build/src/cli.js plan --zap-policy owner-policy.json --allow-private
node build/src/cli.js scan --url http://127.0.0.1:3000 --engine zap \
  --zap-policy owner-policy.json --zap /prepared/ZAP_2.17.0/zap.sh \
  --active-consent --allow-private --tools none --out reports
```

To reuse your local export rather than manually copying its document:

```js
import { readFile, writeFile } from 'node:fs/promises';
const policy = JSON.parse(await readFile('owner-policy.json', 'utf8'));
policy.openapi.document = JSON.parse(await readFile('openapi.json', 'utf8'));
await writeFile('owner-policy.json', JSON.stringify(policy, null, 2) + '\n');
```

An authenticated example declares `login.path`, `login.format` (`json` or `form`) and a field-to-environment-variable map. `session` chooses `{type: "bearer", tokenPointer: "/access", refreshPointer: "/refresh"}` or `{type: "cookie", name: "sid"}`. Optional Bearer `refresh` declares its same-origin path and JSON token field; otherwise HTTP 401 triggers re-login. `identity` asserts a stable response scalar and anonymous 401/403 denial. `maxAttempts` (1..8) bounds actual login + refresh attempts, including initial login. HTTP 403 is terminal; no permission escalation is attempted.

Login must directly return the declared JSON token or Set-Cookie; redirects, browser page interaction, anti-CSRF extraction, MFA, OAuth authorization-code flows, multiple dependent cookies and arbitrary authentication scripts are unsupported. This supports API login, not every application's authentication workflow.

## Native jobs and the request boundary

WakeIO generates a local sanitized OpenAPI projection for ZAP's native `openapi` job. It contains only approved concrete GET/POST paths and virtual parameters. The same native user is selected for import, requestor and activeScan. ZAP's native JSON/form authentication sends **synthetic** username/password aliases to a virtual endpoint and stores an opaque synthetic cookie. Node snapshots the actual selected login values, performs login/refresh and injects the real bearer/cookie on the pinned peer. It replaces actual auth responses with a fixed success/failure document. Auth response headers/bodies and credentials are not passed to ZAP or normalized reports.

Native user HttpSenders omit proxy Basic authentication. A 192-bit fresh random virtual-origin hostname therefore acts as an additional engine capability only in session mode. The controller retains a separate private credential; the engine capability cannot invoke principal or anonymous controls. Ordinary origins or a previous scan's virtual origin cannot use this exception. ZAP is still a **trusted installed process**, not an OS sandbox.

On HTTP 401 the synthetic session becomes invalid and native reauthentication invokes bounded refresh/re-login. The renewed principal must match before another probe can use the session. An identity failure, lost response, cap, deadline, cancellation, unresolved session failure or redirect yields incomplete exit **2**, including with `--fail-on none`. Authenticated start/end/renewal checks do not prove identity remained constant on every intervening HTTP 200 response.

Every actual target login, refresh, identity/anonymous control, import seed, requestor seed and attack consumes the existing shared cap/rate/deadline. A cached synthetic exchange and the local login-page placeholder are not target requests and consume no target request permit. Synthetic exchanges are separately capped at 32. ZAP's upstream import `maxMessages` is a soft limit; the Node gate remains authoritative.

For JSON, the engine gets deterministic scalar aliases. Node validates the exact alias key set and reconstructs only the prevalidated target object. Findings map back to distinct actual JSON pointers such as `/filter/name` and `/tags/0`; the shared runner persists POST/body and authenticated state through DB → evidence → engine finding → task report. Source OpenAPI and canonical projection SHA256 values are reported. Projection hashing uses a constant virtual origin so random session capabilities do not make equivalent scopes appear different.

## Bounded OpenAPI subset

- Embedded JSON <=1 MiB, <=1000 paths; select 1..16 unique GET/query or POST/JSON method/path pairs. Concrete path parameters are supported; path fuzzing is disabled.
- Objects <=32 declared properties, depth <=6, arrays <=8 entries, <=16 mutable string/number leaves, seed body <=8192 bytes. Booleans/null are preserved but not fuzzed. POST roots must be objects. Engine alias bodies <=4096 bytes; reconstructed target bodies <=16384 bytes. Strings may be mutated to attack text even when the seed is numeric.
- Source-file limits also apply before parsing. During each seed expansion, the parser separately charges generated nodes (at most 20,000) and encoded JSON bytes (at most 8192), including keys, punctuation, arrays, booleans and null. Shared-reference amplification is rejected before a large output tree is built; a seventeenth mutable field is refused immediately. Budgets reset for independent seeds/operations. These are parser allocation bounds, not a hard cap on the entire Node process RSS.
- Same-document refs, scalar types, examples/defaults/enums, required fields, basic number/string/array bounds are used for seed construction. This is **not a complete JSON Schema validator**; pattern/format and other semantic constraints are not a validity guarantee. Provide known successful seed values. Composition (`allOf`/`oneOf`/`anyOf`/`not`), mixed POST query/body inputs, uploads, XML, multipart, arbitrary verbs and missing fuzzable inputs are refused.
- Selected seeds must return HTTP 200. Public engine findings are observations with remediation, not proof of independent exploitation. Rules remain only reflected XSS (40012) and SQL injection (40018); no spider, DOM/browser, OAST or business-authorization coverage is inferred.

## Application evaluation

`application-labels.json` fixes distinct rule/method/path/input units **before** measurement. `measure-applications.mjs` compares fresh vulnerable/fixed instances with the same JSON/Bearer profile, caps and selected operations. The reference API includes SQLite search/filter, nested fields/arrays, JSON login and token expiry/refresh. Form/cookie re-login is a separate real-engine regression test, not a different authentication treatment in the timing comparison.

The external application pair is OWASP Juice Shop **19.0.0**, source commit `36870cbbdfe7864698e1adf644c7bf772f67ebb7` (MIT), image manifest `sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d`. Only `/rest/products/search?q` SQLi is selected. The paired fix changes just its Sequelize SQL interpolation to named replacements; original/fixed compiled route hashes are pinned in `juice-shop.mjs`. It does not repair the rest of Juice Shop. Login and the owned account's basket establish actual authenticated execution; other challenges are not tested or counted as TN.

Prepare the image explicitly before measurement (the harness does not pull it):

```sh
docker pull bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d
WAKEIO_OWNED_JUICE_SHOP=1 WAKEIO_ZAP_PATH=/prepared/ZAP_2.17.0/zap.sh \
  node benchmarks/dast-zap/measure-applications.mjs 5 /tmp/wakeio-applications.json
```

The harness creates only its own loopback listeners, accounts and captured Docker IDs. Containers use `--network none`, no published ports, no container logs and a persistent private Docker-stdin RPC bridge to actual internal loopback HTTP. An outer loopback observer independently counts completed target requests; it destroys responses on backend failure. This isolation adds transport overhead, so elapsed times across the two applications are not directly comparable. Provisioning is measured separately. Timed scans include engine/version startup, import, login/refresh/controls, probes, engine shutdown and its private-work-directory cleanup. Target provisioning and target teardown are outside scan elapsed time; provisioning is recorded separately. Runtime and label digests guard reproducibility; partial runs, misses and unexpected distinct findings remain in results.

These are public scoped preliminary measurements, with no hidden final split, model/agent comparison or production-recall claim. See `application-results.json` and the parent README for the observed results and verification summary.

Primary sources: [native OpenAPI job](https://www.zaproxy.org/docs/desktop/addons/openapi-support/automation/), [native authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/), [pinned extensions](https://github.com/zaproxy/zap-extensions/tree/8b171e1c8704d2996b75d4bc119cbf9495d9aa12), [Juice Shop search source](https://github.com/juice-shop/juice-shop/blob/36870cbbdfe7864698e1adf644c7bf772f67ebb7/routes/search.ts).
