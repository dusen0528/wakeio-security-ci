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

