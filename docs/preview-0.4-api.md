# 0.4 API authorization preview

이 문서는 2026-09-16 기준 API 권한 preview 사용법이다. 무료 OSS CLI는 사용자가 지정한 합성 fixture에 제한된 GET 요청만 보내며, 소스 업로드·LLM 호출·결제·외부 target 탐색을 하지 않는다.

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

OpenAPI 3.0/3.1의 제한된 부분집합이며 1 MiB/20,000-node/깊이 40/256-reference compile 예산이 있다. 같은 문서 JSON-pointer `$ref`만 해석하며 remote/file reference, 순환 reference, 모호한 경로, 필수 query/header/cookie, request body, callback, 지원하지 않는 parameter schema/serialization은 실행 전에 거부한다. `servers`, example/default, security 선언에서 주소·credential·payload를 자동으로 만들지 않는다. 응답 schema 검증이나 일반 fuzzing은 제공하지 않는다. CLI의 새 flag는 없으며 기존 `--api-policy` 입력 또는 SDK를 사용한다.

`node examples/openapi-owned-fixture.mjs`는 새 자체 fixture를 생성해 32개의 GET으로 정상 대조군을 검사한다. `--vulnerable`은 중첩 JSON 노출 대조군을 실행하며 high finding 때문에 exit 1이 정상 기대값이다. 둘 다 종료 시 합성 객체와 서버를 정리하며 외부 target 입력은 받지 않는다.
