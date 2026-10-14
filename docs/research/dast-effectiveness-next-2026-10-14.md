# 다음 DAST 효과 검증: 선언된 property write 권한

2026-10-14, main `fb6c5cd`의 읽기 전용 조사다. 이 문서의 새 workflow는
제안이며 구현·실행·staging 검증 결과가 아니다. 대상 실행, provider 호출,
외부 active scan, dependency 설치와 build/test는 하지 않았다.

## 현재 제품에서 확인한 범위

API v2는 actor identity, 같은 객체의 allow/deny GET, 보호된 scalar marker를
검사한다([계약](../../src/api.ts)). 따라서 새로운 GET identity/BOLA 검사만
추가하는 것은 이번 gap의 답이 아니다. Schemathesis worker는 이미 server-error와
response-schema 검사를 사용하지만 선택된 operation은 GET이다
([worker](../../workers/schemathesis/worker.py),
[auth controls](../schemathesis-auth-controls.md)). Schema conformance를 미구현
기능으로 세거나 generated 401/403만으로 성공을 선언하면 안 된다.

현재 [write-state pilot](../api-write-state.md)은 고정된 loopback 서버,
두 resource와 title property에 한정된다. 임의 staging URL·PATCH body·observer를
받는 제품 경로는 아니다([구현](../../src/api-write-state.ts)).
공통 [URL transport](../../src/url-network.ts)의 pinned request는 GET/POST를
선택한다. 외부 PATCH를 위해 pilot의 local HTTP 코드를 그대로 재사용하는 대신
기존 origin/DNS/TLS/deadline/request-budget 계약에 맞춘 transport가 필요하다.

기존 authorization-workflow 조사도 actor×resource×property matrix를 제안했다.
아래는 그 제안의 첫 배포 가능한 범위를 좁힌 것이며 새로운 탐지 성과가 아니다.
자동 보안 검토로 중단된 Schemathesis 개별 replay 작업은 재시도하지 않는다.

## 우선순위와 최소 제품 범위

1. **정상 owner의 금지 property PATCH와 별도 readback**: object 접근권한은
   있으나 특정 field 변경권한은 없는 경우를 검사한다. 먼저 정상 field 변경이
   실제 반영되는지 확인해야 deny-all을 정상 보안으로 오인하지 않는다.
2. **명시적 resource를 연결한 stateful GET 탐색**: 실존 ID가 필요한 operation의
   생성 coverage를 늘릴 수 있지만 권한 위반 자체의 정답을 제공하지는 않는다.

[OWASP API3:2023](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/)는
object property의 부적절한 읽기·변경 권한을 설명한다. Object 접근권한과 field
권한을 별도 정책으로 선언해야 한다. Field 이름이나 OpenAPI의 readOnly annotation만으로
사용자별 권한을 추측하지 않는다.
[Schemathesis stateful 설명](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/)의
response→request 연결은 resource 사용성을 돕지만 application의 권한 정책을 대신하지
않는다. 참고 engine의 [v4.2.0 license](https://raw.githubusercontent.com/schemathesis/schemathesis/v4.2.0/LICENSE)는
MIT다. Engine upgrade, 자동 signup/login, 자유 callback/hook은 이 제안에 포함하지 않는다.

첫 범위는 단일 origin, 사전 준비한 disposable object 하나, PATCH 하나,
정상 field와 보호 field 각각 하나다. Env credential을 읽는 owner와 privileged
verifier의 identity를 확인하고, exact object와 old state를 고정한다. 정상 owner
write/readback과 보호 field의 관측 가능성을 확인하는 privileged control을 먼저
실행한다. 이후 owner의 금지 field 변경과 새 readback을 비교한다. 사용자 staging에
취약 baseline 실행을 강제하지 않는다. API readback은 API 근거이며 독립 DB 관측으로
승격하지 않는다. 복원·동시 변경·모호한 PATCH는 explicit test-resource 계약이 필요하고,
모호한 변경 요청을 자동 재시도하지 않는다.

## 구현 전에 고정할 effectiveness oracle

| 독립 owned target 동작 | 기대 결과 |
| --- | --- |
| 정상 field는 변경되고 금지 field도 owner 요청으로 저장됨 | effect candidate, gate 1 |
| 정상 field는 변경되고 금지 field는 보존됨 | 해당 window에서 effect 미관측, gate 0 |
| 403을 반환하지만 금지 field는 저장됨 | effect candidate, gate 1 |
| 200을 반환하지만 금지 field는 보존됨 | status만으로 candidate를 만들지 않음 |
| 정상 write 거부, stale/숨겨진 readback, wrong object, identity drift | 검증 불가, gate 2 |
| timeout 후 변경 여부 불명, 충돌 또는 cleanup 불명 | 검증 불가, gate 2; 관측된 effect 보존 |

Engine 전후에 동일 target source·정책·원래 caps를 유지한다. 별도 owned 저장소
observer가 실제 변경을 정답으로 제공하고, CLI→HTTP→state→report→CI gate 전체를
검증한다. 탐지한 effect, 잘못된 경고, 검증 불가 control, 정상 write 보존,
시도 request 수와 변경 field 범위를 각각 기록한다. 후보 수를 precision으로 부르지
않으며 toy 결과를 사용자 staging 성과로 합치지 않는다. 배포 가능성을 주장하려면
추가로 operator가 제공한 disposable staging resource에서 같은 공개 계약의
사용 흐름을 확인해야 한다. 이번 읽기 전용 조사에서는 어느 oracle도 실행하지 않았다.

현재 개발 선택은 공개 serve-static advisory의 HTML output-context vertical slice다.
위 DAST 제안은 후속 후보로 남으며, 현재 HTML 작업의 결과나 상용 scanner 동등성을
주장하는 근거로 사용하지 않는다.
