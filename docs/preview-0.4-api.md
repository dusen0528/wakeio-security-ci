# 0.4 API authorization preview

이 문서는 API 권한 preview와 2026-10-06에 추가한 zero-network preflight 사용법이다. `plan`은 로컬 설정만 확인한다. 별도의 API 실행은 사용자가 지정한 합성 fixture에 제한된 GET 요청만 보내며, 소스 업로드·LLM 호출·결제·외부 target 탐색을 하지 않는다.

## Zero-network staging preflight

현재 checkout을 빌드한 뒤 `plan`으로 실행 준비 상태를 확인한다. 아래 OpenAPI 예제는 문서·GET 허용 목록·path binding·actor·canary를 모두 담은 **합성 설정**이며 `https://staging.example.invalid`는 실제 대상이 아니다. 이 명령은 네트워크에 연결하지 않는다.

```sh
npm run build
WAKEIO_OWNER_AUTH='Bearer synthetic-owner' \
WAKEIO_OTHER_AUTH='Bearer synthetic-other' \
node build/src/cli.js plan --openapi-input examples/openapi-preflight-input.json

# 기존 loopback API 정책도 서버를 시작하지 않고 확인할 수 있다.
WAKEIO_OWNER_AUTH='Bearer synthetic-owner' \
WAKEIO_OTHER_AUTH='Bearer synthetic-other' \
node build/src/cli.js plan \
  --api-policy examples/api-authorization-policy.json \
  --allow-private --timeout-ms 5000
```

- `--api-policy FILE` 또는 `--openapi-input FILE` 중 하나만 사용한다. OpenAPI 입력은 원본 schema 파일만이 아니라 [전체 wrapper JSON](../examples/openapi-preflight-input.json)이다.
- 선택 옵션은 `--allow-private`, `--timeout-ms N`이다. timeout은 1..120000 ms, CLI 기본 120000 ms다. 계획에 표시할 실행 시간 예산이며 실제 실행에는 옵션을 별도로 전달한다. `--out`, `--tools`, `--url` 등 scan 옵션을 섞지 않는다.
- 입력은 1 MiB 이하의 읽을 수 있는 일반 JSON 파일이다. symlink나 FIFO 같은 비파일 입력은 지원하지 않는다. 원격 schema나 YAML을 읽지 않는다.
- 결과와 설정 오류는 stdout의 JSON이다. 종료 코드 `0`은 설정 `ready`, `2`는 `blocked`이며 `1`로 finding을 보고하지 않는다. DNS 조회·HTTP 요청·서버 시작·scan 보고서 작성은 없다. `plan --help`는 사용법 텍스트를 출력한다.

### 결과 읽기와 오류 수정

SDK와 CLI는 같은 `version: 1`, `kind: "api-preflight"` 결과를 사용한다. `status`는 `ready` 또는 `blocked`, `execution`은 항상 `not_run`, `networkRequests`와 `dnsLookups`는 항상 `0`이다. 고정된 `issues[].code`·`message`와 구조상의 `location`으로 설정 문제를 찾는다. 유효한 계획을 만들 수 없으면 `plan`은 `null`이며, 계획이 있어도 차단 사유가 있으면 실행 준비가 된 것이 아니다.

`plan.steps`는 0부터 시작하는 `ordinal`, `method: "GET"`, `phase`, `actorIndex`, 필요한 경우 `caseIndex`를 담는다. `actorIndex`와 `caseIndex`도 입력의 `actors`·`cases` 배열을 가리키는 0-based index이며 OpenAPI `operations` 배열 index가 아니다. identity-before → case별 owner-before·deny·owner-after → identity-after 순서다. 예제는 identity 4회, owner 2회, deny 2회로 `logicalRequests: 8`이다.

`maximumHttpAttempts: 64`는 실제 실행에서 주소 재시도까지 공유하는 상한이며 64회 요청을 보내겠다는 뜻이 아니다. `timeoutMs`, `maximumResponseBytes`, `maximumTotalResponseBytes`, `allowPrivate`와 actor/case 수도 함께 표시한다. 실패한 control이나 취소로 일부 단계가 생략될 수 있어 논리 계획은 실제 요청 수를 보장하지 않는다.

출력에는 대상 URL·요청 경로·actor/case ID·환경변수 이름·principal/resource/canary 값·credential 값이 없다. 원본 입력은 사용자가 로컬에서 대조한다. 예를 들어 `policy.actors[1].authorizationEnv`의 `invalid_credentials`는 두 번째 actor의 `authorizationEnv`를 원본에서 확인하고 해당 환경변수를 설정하라는 뜻이다. OpenAPI 입력에서도 `actors[1]`을 확인한다. 같은 credential 값은 서로 다른 환경변수 이름으로 설정해도 `duplicate_credentials`로 차단한다. `duplicate_principal`은 각 authenticated actor의 기대 principal이 같다는 뜻이며, 서로 다른 principal이 같은 organization marker를 공유하는 것은 허용한다. 이것은 선언값 검사일 뿐 실제 계정 구분을 입증하지 않는다.

### SDK

```js
import { readFile } from 'node:fs/promises';
import { preflightApiPolicy, preflightOpenApiPolicy } from './build/src/index.js';

const input = JSON.parse(await readFile('examples/openapi-preflight-input.json', 'utf8'));
const env = {
  WAKEIO_OWNER_AUTH: 'Bearer synthetic-owner',
  WAKEIO_OTHER_AUTH: 'Bearer synthetic-other',
};
const result = preflightOpenApiPolicy({ input, env, timeoutMs: 5000 });
console.log(JSON.stringify(result, null, 2));

// 기존 API 정책: preflightApiPolicy({ policy, env, allowPrivate, timeoutMs })
// env를 생략하면 process.env를 사용한다. 두 함수 모두 동기식이며 요청하지 않는다.
```

### 실행 전에 사용자가 확인할 것

1. 실제 staging origin과 identity/resource endpoint 각각의 실행 권한을 확인한다. OpenAPI 문서나 `ready`가 실행 승인을 대신하지 않는다.
2. 전용 합성 계정, 다른 principal, 소유 관계가 명확한 합성 객체, 공개 resource ID와 구별되는 합성 canary를 준비한다. 실제 개인정보나 운영 비밀을 canary로 사용하지 않는다.
3. allowlist의 모든 GET을 직접 검토한다. GET이어도 잘못 구현된 route는 상태를 바꾸거나 외부 동작을 일으킬 수 있으며 preflight는 부작용이 없음을 입증하지 않는다.
4. 환경변수가 존재하고 header 형식이 맞아도 token이 유효하거나 새롭다는 뜻은 아니다. DNS 해석·주소 pinning·TLS·실제 principal·owner/deny 응답은 승인된 실행에서 다시 확인해야 한다. `--allow-private`는 metadata/금지 주소 보호를 해제하지 않는다.

실제 staging 주소·계정·승인은 이 작업에 제공되지 않았고 외부 staging은 테스트하지 않았다. 위 합성 placeholder로 `ready`가 나와도 보안 통과가 아니다. 기존 API 실행 동작은 유지하며 `scan --api-policy` 또는 `runApiPolicy`/`runOpenApiPolicy`를 별도로 호출한다. `scan --openapi-input`은 지원하지 않는다.

## 합성 fixture 실행

빌드 후 첫 터미널에서 취약 fixture를 시작한다.

```sh
npm run build
node examples/api-authorization-demo.mjs --vulnerable
```

두 번째 터미널에서 합성 토큰을 환경변수로만 전달한다.

```sh
export WAKEIO_OWNER_AUTH='Bearer demo-owner'
export WAKEIO_OTHER_AUTH='Bearer demo-other'
node build/src/cli.js scan \
  --api-policy examples/api-authorization-policy.json \
  --allow-private --out results/api-before --fail-on high
```

v2 정책은 먼저 두 authenticated actor의 `/whoami` principal과 organization을 확인하고, 문서 owner의 positive control을 전후로 검사한다. 한 case의 계획 요청은 identity 4회, owner 2회, deny 2회로 모두 8회다. 취약 fixture는 `other`가 403 응답에서 보호 canary를 받으므로 high finding과 exit 1을 낸다. 보고서에는 canary 값과 토큰 값이 들어가지 않는다.

수정 fixture로 다시 실행한다.

```sh
# 첫 터미널에서 Ctrl-C 후
node examples/api-authorization-demo.mjs

node build/src/cli.js scan \
  --api-policy examples/api-authorization-policy.json \
  --allow-private --out results/api-after --fail-on high
```

owner는 같은 문서를 읽고, `other`와 anonymous는 보호 canary 없이 거부된다. principal이 서로 다르고 두 번의 identity control이 통과하면 high finding 없는 completed 결과와 exit 0을 기대할 수 있다. 403 본문에 공개 `id`만 남는 경우도 high로 올리지 않고 약한 근거로 기록한다.

## 만료 token 확인

`demo-expired`는 identity endpoint에서 401을 반환한다. 다른 actor의 deny 정책에 401이 포함되어 있어도 actor identity가 입증되지 않으므로 검사 전체는 partial, exit 2다.

```sh
export WAKEIO_OTHER_AUTH='Bearer demo-expired'
node build/src/cli.js scan \
  --api-policy examples/api-authorization-policy.json \
  --allow-private --out results/api-expired --fail-on none
```

`--fail-on none`은 발견 threshold만 낮출 뿐 incomplete 결과를 성공으로 바꾸지 않는다. expired, 429·5xx, timeout, malformed/non-JSON 응답은 계속 부분 검사다.

### 요청 중 인증 실패와 identity 변화

authenticated actor의 리소스 요청이 HTTP 401이면 앞뒤 identity control이 모두 200이어도 `partial`, exit 2다. 정책의 `statuses`에 401을 넣거나 `allowEmptyBody: true`로 빈 본문을 허용해도 같다. 이후 요청에서 인증이 회복되어도 앞선 불완전한 결과를 지우지 않는다. 401 본문에 보호 canary가 있으면 finding을 유지한다. anonymous actor의 정책에 맞는 401은 정상 대조군으로 유지한다.

`api.authorization.metrics`는 응답값 대신 다음 고정 숫자 진단을 제공한다.

- `authenticatedDeny401Count`: 인증된 actor의 deny 요청에서 받은 401 수
- `identityStatusMismatches`: identity endpoint의 기대 HTTP 상태 불일치 수
- `identityResponseFailures`: identity 응답의 non-JSON·malformed JSON 수
- `identityPrincipalMismatches`: 기대 principal 불일치 수
- `identityOrganizationMismatches`: principal 통과 뒤 확인한 organization 불일치 수
- `identityRequestFailures`: transport·body/time budget·취소 등으로 응답을 검사하지 못한 identity control 수. 실제 전송 횟수가 아니며 `requestCount`와 구분한다

이 계수는 처음 실패한 검사 단계만 분류한다. 모두 0이라고 세션 연속성이 입증되는 것은 아니다. 전후 identity 검사는 해당 시점의 표본이므로 중간에 사라졌다 회복된 세션·tenant 변화나 endpoint별 인증 동작을 보장하지 않는다. 특히 403만으로 권한 거부와 내부 인증 오류를 구별할 수 없다. 토큰 만료 시각을 추측하거나 자동 로그인·refresh·tenant header를 추가하지 않는다. endpoint와 credential 설정을 검토하고 새로 승인된 합성 자격증명으로 다시 실행해야 한다.

API/OpenAPI SDK 옵션은 own data property만 사용한다. 상속된 옵션·getter는 실행 권한을 제공하지 않으며, own accessor는 실행 전에 거부한다. `allowPrivate`, `signal`, 시간 예산, 정책과 credential은 실행 시작 시 고정한다. 전달한 env/옵션을 중간에 바꿔 token refresh나 권한 변경을 수행할 수 없다. 받은 signal 자체의 정상 abort는 계속 적용된다. `plan`은 로컬 설정만 확인하므로 401을 포함한 정책이 `ready`여도 실제 401 실행 결과는 `partial`일 수 있다.

## 계획 대비 실행 ledger

정상적으로 준비된 API/OpenAPI 실행은 `api.authorization.apiExecution`에 별도
`version: 1` ledger를 남긴다. 기존 GET runner를 관찰할 뿐 요청·인증 refresh·범위를
추가하지 않는다. `plan`의 순서와 `steps[].ordinal`은 0부터 시작하며 실행하지 못한
단계도 빠뜨리지 않는다. actor/case는 입력 배열 index로만 참조한다.

- `evaluated`: 기존 evaluator가 해당 control/probe를 판정했다. 보호 canary 노출
  finding도 이 상태가 될 수 있으므로 성공·안전·exploit 검증을 뜻하지 않는다
- `inconclusive`: HTTP 시도를 했지만 transport, response, identity 또는 assertion
  문제로 판정하지 못했다
- `not_attempted`: 해당 단계에서 HTTP 시도를 시작하지 않았다. 선행 owner control
  실패, cancellation, DNS/target 차단, 소진된 예산 등이 원인일 수 있다

`attemptStart`와 `httpAttempts`는 기존 runner의 HTTP attempt budget을 그대로 센다.
주소 retry는 한 logical step에서 여러 attempt를 사용할 수 있다. 이는 서버 수신 확인이
아니며 DNS lookup 수와도 다르다. `httpStatus`는 전체 bounded response를 받았을 때만
존재한다. redirect/body-limit 등의 예외에서는 헤더를 일부 받았어도 `null`이다.
응답 body/header, raw request, URL/path, actor 이름, 환경변수 이름, principal, canary,
credential 값은 ledger에 저장하지 않는다. 기존 finding/location/notes의 공개 계약은 별개다.

예를 들어 8단계 계획에서 owner-before인 step 2가 HTTP 503이면 step 3·4의 deny와
step 5의 owner-after는 `not_attempted / prerequisite_failed`로 남는다. 뒤의 identity
controls가 통과하더라도 이 세 probe를 통과한 것으로 세지 않는다. Markdown에서 미실행
index를 바로 찾고, 정책의 해당 case와 owner fixture를 확인한 뒤 승인된 동일 검사로
재실행할 수 있다. `--fail-on none`이어도 이 실행은 partial/exit 2다.

CLI `plan`의 기본 `--timeout-ms`는 `scan`과 같은 120000ms다. SDK의 API 기본값은
기존 30000ms를 유지한다. SDK와 CLI를 연결할 때는 같은 timeout 등 effective 옵션을
명시해야 같은 plan hash가 된다.

preflight와 runtime의 `planSha256`은 같은 canonical redacted plan, budget, policy
version에 대한 SHA-256이다. **같은 모양의 서로 다른 target·정책·assertion·credential은
동일한 hash를 가질 수 있다.** 이 hash는 exact-policy/credential commitment나 서명이
아니다. 기존 report scope/ruleset/tool provenance 비교와 함께 읽어야 한다.
`agent-report.json`의 기존 report digest가 ledger를 포함한 sanitized report bytes를
연결한다. 어떤 hash도 실행 사실·보고자 신뢰·독립 응답 증거를 증명하지 않는다.

SDK `sanitiseApiExecutionLedger(untrustedValue)`는 네트워크 없이 schema, 순서, 예산,
plan hash와 count/상태의 논리적 일관성만 확인한다. unknown version, accessor/proxy,
중복·누락·추가 ordinal, 불가능한 HTTP/control 상태나 변경된 hash는 raw input을 버리고
고정된 `status: invalid` envelope로 만든다. report 투영은 finding을 보존하면서 해당
check를 partial로 낮추므로 artifact 생성 전체를 중단하지 않는다. ledger가 없는 이전
report는 그대로 읽으며 사후에 실행 증거를 만들어 넣지 않는다.

`compare`는 한쪽에만 ledger가 있거나, incomplete/invalid ledger이거나, policy version과
redacted plan hash가 다르면 `unverified`다. 양쪽 ledger가 없으면 기존 비교 동작을
유지한다. 동일하고 complete인 ledger도 기존 scope/provenance 검사를 대체하지 않으며,
`not_observed`를 수정 완료로 승격하지 않는다.

## 정책 작성

[v2 JSON 예제](../examples/api-authorization-policy.json)를 복사해 `baseUrl`, actor별 환경변수, identity principal marker, resource marker, 보호 canary, deny 상태를 합성 값으로 바꾼다. principal marker는 actor마다 달라야 하며 organization marker는 공유할 수 있다. `identity.path`는 `/whoami`일 수도 있고 해당 actor가 소유한 fixture의 GET 경로일 수도 있다. `allow.resource`는 공개 리소스 식별이고 `allow.protected`는 owner에게만 돌아와야 하는 non-empty string canary다. 두 assertion에 같은 pointer나 값을 쓰지 않는다.

빈 denial body를 의도한 API라면 해당 deny 항목에 `allowEmptyBody: true`를 명시한다. authenticated actor의 identity control이 실패하면 이 선언도 denial을 완료시키지 않는다. v1 정책은 읽을 수 있지만 actor identity와 protected canary가 없으므로 migration note가 있는 partial 결과만 낸다. v1의 `jsonPointer`/`equals`를 그대로 두고 clean으로 해석하지 말고 v2로 올린다.

경로에는 query/fragment/임의 header/body를 넣을 수 없다. 기본은 HTTPS이며 `--allow-private`와 loopback을 함께 사용하는 합성 fixture만 HTTP를 허용한다. 리디렉션은 따르지 않고, 요청·응답·압축·전체 시간 예산은 기존 URL-network 제한을 공유한다.

## 2026-10-06: 다른 JSON 위치의 합성 canary와 독립 fixture 평가

`allow.protected.match: "json-values"`를 명시하면 deny 응답의 JSON 값 전체에서 **이미 정책에 선언된 canary와 정확히 같은 문자열**을 찾는다. 기본값은 기존 `jsonPointer` 위치 검사다. Owner positive control은 확장 모드에서도 지정 pointer의 resource와 canary를 정확히 확인한다. 응답 본문, canary, credential 값이나 공격자가 정한 JSON 키를 보고서에 복사하지 않는다.

탐색은 최대 10,000개 값과 깊이 64로 제한한다. 부재를 확인하기 전에 제한에 도달하거나 응답이 malformed/non-JSON이면 clean으로 판정하지 않고 partial로 남긴다. 문자열 일부, 키, 인코딩·변형된 값, 알 수 없는 실제 비밀은 이 판정 범위 밖이다. 알려진 합성 canary만 사용해야 한다.

`npm run test:dast`는 외부 주소를 받지 않고 매번 새 127.0.0.1 앱을 띄운다. 사용자 A/B, 다른 테넌트 사용자, 관리자와 객체 네 개를 메모리에 준비하고 종료 후 객체·credential·서버 정리를 검증한다. 직접/중첩/배열 노출, 정상 거부/공개 ID/다른 marker 대조군, malformed/잘못된 identity/owner 부재/5xx/깊이·노드 초과를 두 번씩 검사한다. 허용 경로와 GET만 요청했는지, 실제 서버 요청 수와 scanner 계수가 같은지, redaction과 incomplete 상태를 검사하며 request count와 시간을 출력한다.

이 비교는 **같은 빌드의 pointer 설정과 json-values 설정** 사이의 한정된 task coverage다. 독립 앱 fixture와 정해 둔 기대 결과를 사용하지만 실제 staging 검증이나 전체 보안 탐지율을 뜻하지 않는다. 사용자 소유 staging의 실제 계정, 합성 객체, endpoint와 실행 승인은 별도로 설정해야 하며 이 작업에서는 연결하지 않았다. Schemathesis/state-pilot의 fixture-only 범위도 그대로다.

## OpenAPI에서 명시적으로 허용한 GET 만들기

SDK의 `buildOpenApiPolicy(input)`은 네트워크 없이 v2 정책을 만들고, `runOpenApiPolicy({ input, env, signal, timeoutMs, allowPrivate })`는 기존 API 실행기에 그대로 위임한다. `input`은 parsed JSON `document`, 명시적 origin `baseUrl`, v2 `actors`, GET `operations` 허용 목록, operation ID를 참조하는 `cases`를 받는다. `/whoami` 같은 identity control 경로도 목록에 넣어야 한다. 각 operation에는 정확한 문서 path template과 사용자가 제공한 단순 scalar `pathParameters`만 사용한다.

OpenAPI 3.0/3.1의 제한된 부분집합이며 1 MiB/20,000-node/깊이 40/256-reference compile 예산이 있다. 같은 문서 JSON-pointer `$ref`만 해석하며 remote/file reference, 순환 reference, 모호한 경로, 필수 query/header/cookie, request body, callback, 지원하지 않는 parameter schema/serialization은 실행 전에 거부한다. `servers`, example/default, security 선언에서 주소·credential·payload를 자동으로 만들지 않는다. 응답 schema 검증이나 일반 fuzzing은 제공하지 않는다. CLI의 `plan --openapi-input FILE`은 네트워크 없는 준비 확인 전용이다. 실행은 기존 `scan --api-policy FILE` 또는 SDK를 사용하며 `scan --openapi-input`은 지원하지 않는다.

`node examples/openapi-owned-fixture.mjs`는 새 자체 fixture를 생성해 32개의 GET으로 정상 대조군을 검사한다. `--vulnerable`은 중첩 JSON 노출 대조군을 실행하며 high finding 때문에 exit 1이 정상 기대값이다. 둘 다 종료 시 합성 객체와 서버를 정리하며 외부 target 입력은 받지 않는다.
