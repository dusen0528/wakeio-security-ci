# Outbound request config의 입력 역할

Ruleset `2026-10-05.7`은 제한된 Axios request config에서 `url`과 `data`의
입력 역할을 구분한다. 기존 request-shaped 입력 추정과 SQL·shell·HTML의
taint는 유지한다. 이 모델은 초기 URL 필드만 판단하며 최종 목적지나 런타임
SSRF 안전성을 확인하지 않는다.

## 지원하는 형태

선언된 API 계약은 [Axios v1.13.2](https://github.com/axios/axios/blob/v1.13.2/README.md#axios-api)다.
실제 설치된 패키지의 버전이나 bytes를 인증하는 기능은 아니다.

- ESM default import, `default as` import, top-level `const`의 정적
  `require('axios')`에서 실제 lexical binding을 식별한다. CJS의 `require`가
  shadowed이면 지원하지 않으며, 다른 파일의 동명 script global을 인증하지 않는다.
- receiver의 직접 `.request(config)` 한 인자 호출을 지원한다. 임의 import
  별칭은 새 탐지 범위다. direct call, created instance, 다른 method overload,
  namespace/dynamic/deep import와 method extraction은 이 추가 모델 밖이다.
- config는 inline plain object 또는 같은 lexical scope에 직접 선언한 const
  plain object다. 최대 16개 고정·고유 key에 `url`(필수), `data`, 고정 method,
  고정 문자열 headers만 허용한다. Host/:authority header, computed key,
  spread, getter/setter 및 construction의 미지원 side effect는 제외 자격이 없다.
  `url`과 `data`의 shorthand도 실제 lexical 값을 생성 시점에 읽는다.
- `url`의 값과 증거는 객체 생성 시점에 보존한다. 이후 scalar 변수의 재할당으로
  과거 config의 target 값을 다시 계산하지 않는다. Scalar 인자·반환의 기존
  local/relative-module summary 지원 범위도 적용한다.
- payload-only 제외는 초기 URL이 최대 2048자의 canonical absolute HTTP(S)
  literal로 확인되는 경우다. userinfo, control/backslash, fragment, 상대 URL,
  불명확한 URL은 이 proof를 얻지 않는다.

아래는 의미를 설명하는 합성 예이며 스캐너가 대상 코드를 실행하지 않는다.

```ts
import client from 'axios';
function route(req) {
  client.request({url: 'https://fixed.example/path', data: req.body});
  client.request({url: req.query.target, data: 'fixed'});
}
```

첫 호출은 지원 조건이 모두 충족되면 outbound destination 후보만 제외한다.
두 번째는 실제 `url` 입력 증거를 가진 candidate다. 두 경우 모두 실제 요청
도달성, 권한 및 exploitability를 확인한 결과가 아니다.

## Proof를 폐기하는 조건

const 선언은 heap 불변성의 증거가 아니다. config alias/member write/container
storage/return/parameter 또는 알 수 없는 호출로의 escape가 있으면 제외 proof를
폐기한다. API binding의 재할당·escape, 다른 수집 파일의 같은 Axios package
binding에서 defaults/interceptors/customization, 지원 밖 import도 family proof를
폐기한다. 정확한 static package load의 inline/property require, import-equals,
dynamic import, re-export와 괄호/type assertion/non-null 표현도 관측해 미지원
형태를 검증된 binding처럼 취급하지 않는다. `baseURL`, `allowAbsoluteUrls`, params, proxy, adapter, transport,
socket 및 agent 설정은 이 config grammar 밖이다.

검토는 수집 snapshot의 indexed references를 재사용한다. Snapshot 미완료,
JS/TS parse 오류, 민감 JS/TS 경로 제외 및 incomplete index가 있으면
`roleProofScopeComplete` 또는 index proof를 충족하지 못하며 payload-only로
제외하지 않는다. 민감 코드를 새로 파싱하지 않는다. 검사 밖 dependency의
side effect나 런타임 override가 없다는 보장은 하지 않는다.

Alias proof를 폐기해도 이미 관측한 입력·trace는 유지한다. 기존 일반 heap
alias-only taint 누락을 해결했다고 주장하지 않는다. 직접 `.request` identity를
새로 식별한 alias도 불명확한 config의 입력을 low-confidence 후보로 남긴다.
기존 이름 기반 `axios.request`에서 얻은 후보도 unknown fallback을 유지한다.
기존 scalar fixed destination + encoded query 모델은 별도로 유지한다.

## 고정 초기 URL과 encoded query의 합성 (`.7`)

기존 native `URLSearchParams` provenance를 가진 scalar 문자열을 config의
URL 필드로 읽는 경우, canonical absolute HTTP(S) origin/path 뒤 `?`와
encoded query 조각만 이어지면 초기 destination 제어 후보를 제외한다.
URL query와 `data`가 모두 입력이어도 이 제외가 가능하다. 전체 argument가
query-only라는 뜻이 아니며, 입력 taint와 실제 source trace는 그대로다.

```ts
import client from 'axios';
function route(req) {
  const p = new URLSearchParams({q: req.query.term});
  const url = 'https://fixed.example/path?' + p.toString();
  client.request({url, data: req.body});
}
```

이는 고정 **초기** origin/path 필드의 분석이며 SSRF 안전성, remote query의
동작, redirect/DNS/proxy/transport 또는 실제 요청 실행을 인증하지 않는다.
Raw scheme/authority/path/suffix input은 실제 URL trace의 후보로 남는다.
Query 인코딩은 SQL·shell·HTML·redirect의 sanitizer가 아니다.

기존 native identity/shadow/global·prototype/alias·escape 검증과 config
binding/scope/closed shape가 모두 필요하다. URL parser의 성공만으로 native
serializer를 인증하지 않는다. Literal 2048자/조각 16개의 bound를 유지한다.
Config 밖에서 계산한 scalar 변수 및 ordinary sync local/relative actual-return은
기존 지원 경계를 사용한다. Config initializer에 직접 Call/New/Await/Yield를
넣는 문법과 config object 전달/반환은 추가하지 않는다.

생성 시 captured URL은 immutable snapshot이다. 값 branch join에서 URL 조각의
exact shape가 다르면 encoded proof를 버린다. 같은 config construction AST와
양쪽 proof, joined target의 조각 보존·재검증이 필요하며 URL 대안을 열거하지 않는다.
이 AST 동일성은 네트워크 URL origin의 동일성이 아니다.

Async/generator 호출 반환은 HTTP target proof가 불가용하다. `await`만으로
복구하지 않는다. 결격은 query content/append·set/문자열 snapshot/cache/join,
concat/container/static·dynamic projection 및 unknown-call fallback에서 유지된다.
URL target의 결격만 판정하며 body 결격을 authority 입력 근거로 옮기지 않는다.
Direct scalar outbound 모델은 새 결격을 veto로 소비하지 않고 기존 판정을 유지한다.
Runtime Promise·heap 모델이나 scope 밖 dependency의 부작용 부재는 증명하지 않는다.

## 보고서와 CI 의미

공개 Finding/StaticFlow/AgentReport schema를 추가하거나 변경하지 않는다.
기존 JSON, SARIF, Markdown, agent-report 정제 경계를 사용한다.

| 판단 | 보고서 의미 |
|---|---|
| `target_input` | `ast:server-request`, severity high. 실제 URL 필드 입력이 tainted이면 confidence medium, input-related unknown이면 low. URL에서 관측한 source trace를 선택한다. |
| `payload_only_fixed_initial_url` | 지원 proof 아래 해당 outbound 후보만 제외한다. Data taint를 SQL·shell·HTML에도 안전한 값으로 바꾸지 않는다. |
| `encoded_query_fixed_initial_url` | 지원 proof 아래 URL의 고정 초기 origin/path 뒤 native encoded query 형태에서 해당 outbound 후보만 제외한다. Body 입력도 함께 있을 수 있다. |
| `unknown_role` | 입력 관련 arg0가 있으면 severity high/confidence low의 config 후보다. URL authority 제어를 단정하지 않는다. 실제 config/body source 위치만 유지하며 trace가 있으면 truncated로 표시한다. |

여러 실제 인자 context가 한 sink에 합류하면 target > unknown > encoded > payload 순서로
판단한다. 어느 위험 context라도 있으면 제외하지 않으며, body trace를 URL
source로 바꾸지 않는다. Candidate는 `not_run`이고 취약점 및 수정 확인은 false다.
이 우선순위는 실제 입력 관련 context 사이에 적용한다. 무입력 context는 bound
call inventory만 합치며, 다른 context의 입력과 합쳐 새 unknown 후보를 만들지 않는다.
원문 URL이나 source excerpt를 public artifact에 추가하지 않는다.

`source.builtin-ast`의 고정 model label은 `axios-request-config-query-v2`이다.
`outboundRoleBoundUses`는 입력 없는 호출까지 포함해 실제 bound call 위치를
중복 제거한 수다. `outboundPayloadOnlyExcluded`, `outboundEncodedQueryExcluded`, `outboundTargetInputUses`,
`outboundRoleUnknownUses`는 입력 관련 candidate-bearing sink만 센다. 무입력
호출을 unknown 안전 결과나 제외 성공으로 세지 않는다. 함수 평가 횟수와도 다르다.
Encoded와 payload 정상 context가 섞이면 encoded metric 한 번으로 집계한다.
기존 payload metric은 literal-only 의미를 유지한다. Direct scalar suppression과
config 제외를 중복 성과로 합산하지 않는다. 새 outcome은 내부 분석값이고,
새 metric은 check metadata이며 공개 Finding schema에 outcome field를 추가하지 않는다.

Work cap은 index 300000, flow 200000, aggregate 500000 그대로다. 검토 중 cap에
도달하면 기존 partial와 CI 2가 유지된다. 지원 밖 문법 자체는 새로운 incomplete
사건이 아니다. Parser/binder 및 렌더링 비용까지 hard CPU bound라는 뜻은 아니다.

Ruleset `.3`, `.4`와 `.7`의 후보 감소는 모델 의미 변경이다. 자동으로 remediation
verified나 실제 취약점 해결로 해석하지 않는다. 기본 gate 판정은 유지되며
다른 candidate 및 incomplete가 있으면 그 판정이 우선한다. Field에서 검토한
기존 SQL/config 후보의 해결이나 maintained engine의 기본 채택을 의미하지 않는다.

API 역할과 customization 경계의 근거는 pinned
[Axios._request](https://github.com/axios/axios/blob/v1.13.2/lib/core/Axios.js#L60-L172),
[mergeConfig](https://github.com/axios/axios/blob/v1.13.2/lib/core/mergeConfig.js#L61-L90),
[buildFullPath](https://github.com/axios/axios/blob/v1.13.2/lib/core/buildFullPath.js)다.
2026-10-05에 공식 원문을 확인했다.

Native query serialization의 근거는
[WHATWG stringification](https://url.spec.whatwg.org/#urlsearchparams-stringification-behavior)과
[form serializer](https://url.spec.whatwg.org/#concept-urlencoded-serializer)다.
2026-10-05에 공식 문서와 위 pinned Axios 소스를 확인했다. 전체 flow 완료를
추가 보장하지 않으며 뒤늦은 무관 module_missing/flow cap은 기존 partial/CI2로 남는다.
