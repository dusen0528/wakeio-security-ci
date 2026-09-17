# API authorization policy implementation

검토일: 2026-09-16 (KST) · 구현: [`src/api.ts`](../../src/api.ts)

API1:2023은 객체 ID를 받는 API가 현재 로그인 주체의 객체 권한을 검사해야 한다고 설명한다. 이 모듈은 그 원칙을 사용자가 제공한 합성 계정, 소유자 fixture, 보호 canary로 한정해 재현한다. 한 정책에 적은 경로와 actor만 확인하며 서비스 전체의 보안 인증서가 아니다. ([OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/))

## 정책 버전과 엄격한 스키마

현재 권장 버전은 `2`다. 루트, actor, identity, case, allow, resource, protected, deny 객체는 정해진 키 외의 키를 거부한다. ID, 환경변수 이름, 경로, JSON Pointer, 상태 코드, 배열 길이와 스칼라 값을 모두 bounded하게 검사한다. 정책에는 토큰 값이 들어가지 않고 환경변수 이름만 들어간다.

```json
{
  "version": 2,
  "baseUrl": "https://api.example.test",
  "actors": [
    {
      "id": "owner",
      "authorizationEnv": "WAKEIO_OWNER_AUTH",
      "identity": {
        "path": "/whoami",
        "status": 200,
        "jsonPointer": "/userId",
        "equals": "owner-user",
        "organization": { "jsonPointer": "/orgId", "equals": "shared-org" }
      }
    },
    {
      "id": "other",
      "authorizationEnv": "WAKEIO_OTHER_AUTH",
      "identity": {
        "path": "/whoami",
        "status": 200,
        "jsonPointer": "/userId",
        "equals": "other-user",
        "organization": { "jsonPointer": "/orgId", "equals": "shared-org" }
      }
    },
    { "id": "anonymous" }
  ],
  "cases": [
    {
      "id": "object-read",
      "path": "/documents/test-one",
      "allow": {
        "actor": "owner",
        "status": 200,
        "resource": { "jsonPointer": "/id", "equals": "test-one" },
        "protected": { "jsonPointer": "/canary", "equals": "synthetic-private-canary" }
      },
      "deny": [
        { "actor": "other", "statuses": [401, 403, 404] },
        { "actor": "anonymous", "statuses": [401, 403, 404] }
      ]
    }
  ]
}
```

`identity` is a bounded same-origin GET positive control. Its `jsonPointer`/`equals` pair is the principal marker and must be a non-empty, non-whitespace string. An authenticated actor must declare it; an actor with the `anonymous` ID has no token and no identity control. The optional `organization` marker may be shared, so two users in one organization are valid when their principal markers differ. Reusing the same principal marker, using only different token strings, an empty/null/boolean principal, or changing principal between the before and after controls leaves the check `partial`.

The identity path can be a `/whoami` endpoint or the actor's own fixture response. It must remain a GET path on `baseUrl` and use a scalar marker. The runner performs identity controls for every authenticated actor before the cases and again after them. This catches an expired token or principal change that happens during the case run; a listed `401` does not turn that actor into a completed denial.

Version `1` is still parsed for migration. It has no actor identity control and no protected-data assertion, so it is always reported as `partial` with a migration note. Its resource ID can be retained as weak evidence but cannot create a protected-data exposure finding. Add v2 identity controls and split `allow.resource` from `allow.protected` before treating a result as complete. Unknown v1 keys remain invalid; changing `version` to `2` is an intentional schema migration.

## What each case proves

The owner request is made before and after the deny requests. Both owner responses must have the configured 2xx status, valid JSON, the resource identity marker, and the separate protected canary. A protected canary must be a non-empty, non-whitespace string different from the resource marker; this avoids treating a common public ID or generic error field as secret data.

For each deny actor, the runner sends one bounded GET with only the explicitly resolved `Authorization` header. A 2xx response containing the protected canary is a scoped high-severity, high-confidence exposure finding; with verified actor identity it can complete the check with exit code 1. A 403 response containing that canary is also an exposure. A response that only repeats the public resource ID is recorded as weak authorization evidence and never as a high finding; in v2 it can be a completed expected denial when the actor identity and status are valid. The anonymous actor is evaluated separately and does not inherit an authenticated actor's identity evidence.

An expected non-429 4xx response with valid JSON and no protected canary is scoped denial evidence only. A policy may set `allowEmptyBody: true` for a listed status, but an empty body is accepted only after the authenticated actor's identity control passes (or for the explicit anonymous actor). A 401 from an expired or otherwise unverified actor remains incomplete. `429`, every 5xx, success/redirect-like responses without a canary, malformed JSON, non-JSON bodies, unexpected statuses, network failures, timeout, and budget exhaustion remain incomplete even if a status is listed. A canary finding can be retained alongside `partial` for a 429 or 5xx, but those responses do not count as denials.

Notes and findings contain case/actor IDs, statuses, safe URLs and bounded explanations. Raw Authorization values, response bodies, canary values, cookies, query credentials, and secrets are never copied into the report.

## Transport and budget boundary

The preview is read-only GET collection. It does not write data, follow redirects, execute browser code, fuzz IDs, discover an OpenAPI schema, infer JWT semantics, or test function/property-level authorization. The URL-network layer retains same-origin checks, DNS/private/metadata blocking, peer pinning, TLS verification, redirect rejection, decompression limits, and deadlines. Authenticated HTTP is permitted only for an explicit `--allow-private` loopback fixture; remote authenticated targets require HTTPS.

The policy allows at most 20 cases, 32 actors, 64 requests, 2 MiB per response, 10 MiB of retained response bytes, and a 120 second timeout ceiling. Planned requests include two identity requests per authenticated actor plus two owner controls and one request per deny actor for every case. Parsing and credential validation happen before the first DNS lookup. The report exposes request and byte counters and whether a body limit stopped collection.

The contract follows the distinction between an authentication identity and an object-level authorization decision described by OWASP. OpenAPI can describe security requirements, but the ownership relationship in this fixture is application-specific; a policy must therefore name its positive identity and resource markers. ([OpenAPI security requirements](https://swagger.io/specification/v3/?sbsearch=auth), [Schemathesis authentication](https://schemathesis.readthedocs.io/en/stable/guides/auth/))

