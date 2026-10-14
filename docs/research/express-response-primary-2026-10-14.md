# Express 응답 타입과 override의 정적 수용 기준

2026-10-14. [운영용 OSS source trial](production-source-trial-2026-10-14.md)의
Express false-claim 판정을 출발점으로 삼는다. 기본 boolean·container 응답을
요청 문자열의 HTML 출력으로 표현한 기존 경고를 검토했다. **타입 기반 경고
억제는 채택하지 않았다.** 대신 이름으로 추정한 response와 지원하는 Express
등록 근거를 분리하고, 전자는 검증 우선의 불확실한 후보로 정확히 표현한다.
이 연구와 대조는 source-only이며 Express 앱·dependency 설치, import, 테스트,
서버, provider, DAST 실행은 `not_run`이다. 앱 전체의 안전성이나 실제 XSS를
입증하는 기준이 아니다.

## 고정 primary source가 말하는 동작

Express **v5.1.0**, commit
`cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4`를 읽었다. 소스 줄 번호는 고정
checkout의 실제 파일을 기준으로 확인했다. 이번 scanner baseline은 `823c42b`이며
이전 OSS trial의 scanner baseline과 구분한다.

| 연산 | 확인한 기본 동작 | 정적 분석에서 필요한 경계 |
| --- | --- | --- |
| `req.fresh` | method·status·cache headers를 바탕으로 boolean을 반환 | 요청에 의존한다는 사실과 출력 bytes의 타입은 다르다 |
| `req.stale` | `fresh`의 논리 부정 | getter가 교체되면 기본 결과 타입을 인증할 수 없다 |
| `req.xhr` | header 값의 비교 결과인 boolean | header 문자열 자체를 반환한다고 표시하면 안 된다 |
| `res.send` | string은 기본 HTML; boolean·number·non-null object는 `this.json`으로 dispatch | receiver와 dispatch의 변경을 별도로 확인한다 |
| `res.json` | 직렬화 후 Content-Type이 없을 때만 JSON MIME을 설정하고 `this.send` 호출 | 기존 HTML MIME을 덮어쓰는 보장은 없다 |

Getter 정의와 configurable descriptor는
[request.js:453–515](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/request.js#L453-L515)에,
send의 타입 분기는
[response.js:123–155](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/response.js#L123-L155)에,
JSON MIME과 재dispatch는
[response.js:237–251](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/response.js#L237-L251)에 있다.
Null은 빈 body, array-buffer view는 별도 binary 분기이므로 모든 object를
하나의 직렬화 경로로 일반화하지 않는다.

Express는 app별 request/response prototype을 만들고 handler 진입 전에 이를
실제 객체에 연결한다. 따라서 app별·공유 prototype이나 instance member 변경은
기본 API 인증과 별개다.
[app 생성](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/express.js#L41-L53),
[handler dispatch](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/application.js#L164-L178).
공식 [API override 가이드](https://expressjs.com/en/guide/overriding-express-api/)
역시 request getter와 response method의 교체를 지원한다고 설명한다.
이 문서는 그 지원 사실을 사용하며 외부 middleware가 실행되었다고 가정하지 않는다.

직렬화도 순수 문자열 변환으로 가정할 수 없다. Express는 설정된 replacer와
spaces를 global `JSON.stringify`에 전달하고, `json escape`가 활성화된 경우에만
일부 HTML 관련 문자를 바꾼다.
[직렬화 구현](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/response.js#L1015-L1038).
ECMAScript의 [SerializeJSONProperty](https://tc39.es/ecma262/multipage/structured-data.html#sec-serializejsonproperty)는
property 읽기, callable `toJSON`, replacer 호출을 수행한다. 따라서 getter·hook의
헤더 변경이나 관찰된 stringifier 교체를 확인하지 않은 container는 새로운
기본 JSON 인증을 받을 수 없다. 기본 JSON stringify는 HTML encoding과 같지 않다.

## 채택한 보고 계약

Ruleset `2026-10-14.2`는 이름만으로 추정한 response-shaped use에
**`ast:response-input-sink`**를 사용한다. High severity·candidate kind를 유지하고
confidence는 low다. Receiver binding, payload dispatch, MIME, runtime caller origin은
확립되지 않았다고 명시한다. 먼저 실제 receiver·caller·dispatch·headers를 확인하고,
HTML 출력이 확인된 경우에 encoding을 적용하도록 안내한다. 별도 optional proof
필드를 추가하지 않고 기존 `ruleId`를 machine-readable 구분자로 사용한다.

지원하는 lexical Express 등록은 기존 `ast:html-input-sink` convention을 유지한다.
내부 authority는 `registered_express`와 `unqualified_response`를 구분한다. Alias는
이를 전달하며 mixed authority·opaque response effects는 보수적으로 unqualified가
우선한다. 같은 registered receiver의 HTML/plain 분기에서는 identity를 유지하고
MIME만 unknown으로 남겨 low-confidence HTML candidate를 유지할 수 있다.
등록 syntax는 dependency authenticity, 실제 callback 실행,
middleware 순서나 getter·serialization closure를 증명하지 않는다.
[공개 source-flow 계약](../source-flow.md#express-registration-positions-ruleset-2026-10-061).

기존 rule/title 변경은 finding ID와 semantic comparisonKey도 바꾼다. 이전 ruleset
`2026-10-14.1`과 새 report의 비교는 unverified·exit 2이며 이전 HTML 경고가
사라졌다는 사실을 fix로 해석하면 안 된다. 이번 효과는 경고의 근거와 조치 순서를
정확히 하는 것이며 false-positive 감소나 취약점 제거가 아니다.

## 미채택 타입 억제 대조의 보존

자체 작성한 inert source **32개**를 private
`artifacts/express-response-primary-2026-10-14/fixtures.json`에 먼저 고정했다.
SHA-256은 `e22726f97b85eb386b784a50616c6c711715322d3dff895d2bf6bb879561cf8d`다.
Target source를 fixture로 복사하거나 runtime import하지 않았다. 그러나 원본
33 site의 receiver/property/serialization/MIME closure를 타입만으로 인증할 수
없어 이 대조를 최종 product acceptance에 편입하지 않았다.

| 미채택 대조 | 연구 질문 |
| --- | --- |
| qualified boolean getter와 immutable scalar alias | 기본 결과 타입을 실제 receiver에 적용할 근거가 있는가 |
| object·array·native keys/values·mapped array | 값의 shape만으로 dispatch·MIME까지 인증할 수 있는가 |
| request 문자열·명시적 stringify·mixed branch | 타입 대조가 실제 문자열 후보를 지우지 않는가 |
| 같은 input의 HTML/plain MIME 쌍 | 좁은 MIME 선언과 전체 응답 동작을 구분하는가 |
| getter·response method·native method 교체 | 기본 API 이름만으로 override를 놓치지 않는가 |
| toJSON·getter·replacer·global stringifier 효과 | 직렬화 중 header 변경을 분석할 수 있는가 |
| opaque response/body·dynamic MIME | unknown을 음성으로 잘못 인증하지 않는가 |

원래 test source는 byte-identical private
`deferred-response-typing.test.ts`로 보존했고 public test에서 제거했다.
`deferred-scope.json`은 미채택 이유와 원본 SHA를 기록한다. 이 32개는 passing
negative·수정 효과·탐지 성능의 분모로 계산하지 않는다.

[새 독립 regression](../../tests/express-response-review.test.ts)은 채택한 계약에
맞춰 generic callback·alias와 registered callback을 구분한다. 같은 helper sink의
mixed actual contexts를 순서별로 확인하고, opaque 효과·MIME-only 분기와 production/test
경로 교차를 검증한다. Raw finding·JSON·agent-report·SARIF·advice의 rule ID, confidence,
gate와 SAST candidate의 `not_run`, vulnerabilityConfirmed false, remediation
`not_verified`가 일치해야 한다. Old/new ruleset comparison도 fix를 인증하지 않아야 한다.
Markdown은 기존대로 사람이 읽는 title·confidence·조치를 표시하며 rule ID 필드를
추가하지 않는다. Machine-readable 구분은 위의 JSON·agent·SARIF·advice에서 확인한다.

## 검증 기록의 경계

Node `22.22.1` 최종 build가 통과했고, 수정 엔진의 **19개 파일 focused suite는
277/277 통과**했다. Fail·cancelled·skipped·todo는 모두 0이다. 최종 TAP의
`ok 100`–`ok 106`은 위 독립 regression 7개이며 모두 실행·통과한 것을 확인했다.
Generic/registered 구분, mixed actual context의 순서, opaque/MIME-only 효과,
경로 비의존, report projection·검증 상태, ruleset 비교를 포함한다.

최종 로그는 private
`artifacts/express-response-semantics-2026-10-14/owner-focused-final.log`이며 SHA-256은
`f7d54d5831326b4fc1409248a60b23c5059789a201b5cd46dc4b080e705ebbaa`다.
`artifacts/express-response-primary-2026-10-14/focused-log-verification.json`은
독립 test source의 7개 이름과 최종 `ok` 행·전체 counts를 대조한 receipt다.
중간 `owner-focused.log`는 최종 결과의 근거로 사용하지 않는다. Trusted analyzer가
소유 source 문자열을 데이터로 읽는 계약 검증이며 대상 실행은 하지 않았다.
전체 required suite·고정 OSS/benchmark 재측정·package 소비·GitHub 통합은
각 별도 검증 기록에서 확인한다.

같은 팀이 알려진 false claim을 보고 설계한 회귀 대조이므로 blind holdout이나
제삼자 감사가 아니다. 경고 수 감소, 타입/dispatch 인증, 분석 미완료 보존을
분리하며 production precision·recall, 전체 Express 지원, 실제 취약점 수정 또는
유료 도구 대체를 주장하지 않는다. 이전 전체 OSS trial의 partial 및 source 범위는
그 고정 기록을 그대로 유지한다.
