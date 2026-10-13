# 사용자 목표 대비 API/DAST 공백 감사

기준: 2026-10-13, `main` `36c8341b69fecc663de8498295277289e7fbeb2b`. 코드·문서·테스트를 읽고 공식 자료를 조회한 **구현 전 감사**다. 이 감사에서는 test/build/server/DB/scan/model을 실행하지 않았다. 제품 파일·Git history를 변경하지 않고 이 문서만 추가한다. Active scan의 승인 범위는 소유 합성/loopback뿐이다. 외부 clone은 source data로만 취급하며 설치·실행·import·build·test·server·DB·DAST를 제안된 작업에 섞지 않는다.

## 결론

다음 탐지 기능의 우선순위는 **다른 사용자의 객체를 수정하는 write BOLA를, 응답 상태가 아닌 실제 저장 상태로 판정하는 좁은 검사**다. 기존 GET 데이터 노출·SQL 차등 검사에 공격 문자열을 더 보태는 것보다 새 위험 동작을 검증한다. 다만 owned fixture 하나를 추가한 상태를 사용자 앱 검증이나 유료 제품 수준의 가치 입증으로 표현하면 안 된다.

보다 작은 선행 개선이 필요하면 2순위인 Schemathesis 실패 요청의 정확한 replay를 택한다. 이는 기존 발견을 개발자가 고칠 수 있게 만드는 전달 공백을 메우지만 새 보안 취약점 종류를 입증하지는 않는다. 두 작업을 한 변경으로 묶지 않는다.

평가 기준은 fixture 개수가 아니라 (1) 실제 위험 동작 종류, (2) 독립적인 vulnerable/fixed 구별, (3) 사용자가 발견→CI 실패→수정→같은 조건 재검사까지 수행 가능한지, (4) 미완료가 clean으로 바뀌지 않는지다. 가격·경쟁 제품 대비 우위·수요는 이 조사에서 측정하지 않았다.

## 이미 구현된 범위

- API v2는 principal/선택 organization, owner 전후 대조, 보호 canary, pointer/json-values 노출, 실행 ledger, 같은 정책의 한 case replay를 갖췄다. `src/api.ts:57-151`, `src/replay.ts:61-109`, `docs/preview-0.4-api.md`.
- Native SQL은 numeric v1/v2와 명시적 single-quoted v3, 선택 Authorization 및 identity 전후 대조, 고정 8/10단계, policy/profile/revision을 묶은 replay를 갖췄다. `src/dast.ts:116-152,284-310,382-430`, `src/dast-replay.ts:96-126`, `docs/native-dast-auth.md`, `docs/native-dast-quoted.md`. 초기 numeric-only 연구 문서의 범위를 현재 구현 한계로 오해하지 않는다.
- 상태 pilot은 실제 저장 resource, 별도 observer, normal contents, 실제 handler bytes와 digest, 반복 및 delivery-only retry를 이미 지원한다. 단, read 노출을 검사하고 저장 상태 **불변**을 요구한다. `src/api-state.ts:135-169,193-208`, `src/api-state-observer.ts:51-85`, `docs/api-state-oracle.md:3-25`. 완료된 independent read observer를 다시 제안하지 않는다.
- Schemathesis live는 선택 GET에 대한 generation, 5xx/schema finding, gate와 예산, partial/error, engine/runtime provenance가 있다. `src/schemathesis-live.ts:23-49,115-139,234-246`, `tests/schemathesis-live.test.ts:33-114`. 과거 fixture-only 설명을 현행 live 구현 부재로 인용하지 않는다.
- Nuclei 선택형 어댑터도 이미 있으므로 MIT 엔진 wrapper를 새로 만드는 것은 추천하지 않는다. `docs/research/mit-dast-engine-2026-10-13.md`의 HTTPS request-count 제약 역시 보존한다.

이 목록은 읽은 구현 계약이다. 이번 감사에서 해당 테스트가 현재 통과하는지 재측정하지 않았다.

## 우선순위와 빠진 수용 흐름

| 순위 | 공백 | 사용자 이득과 정확한 근거 | 현재 빠진 수용 흐름 |
|---|---|---|---|
| 1 | 상태 변화가 있는 객체 수정 권한 검사 | GET은 안전하게 보여도 peer의 PATCH가 owner 객체를 바꿀 수 있다. `src/api.ts:57,127-151`은 method/body 모델이 없고 GET-only다. `src/url-network.ts:438-468`의 pinned transport도 GET 고정이다. `src/api-state.ts:148-149`는 non-GET을 거절하고 `165-166`은 state 변화 자체를 mismatch로 분류한다. | owner 정상 write를 독립 store에서 확인→reset→peer write→실제 owner row 변화/불변 확인→owner 정상 기능 보존→cleanup→CI gate→같은 정책/새 seed의 scoped replay. HTTP 403 뒤 mutation이나 200/no-op을 구별하는 흐름이 없다. |
| 2 | Schemathesis 실패 입력을 정확히 재전송할 수 있는 artifact | 현재 description은 실패 입력을 보존하지 않고 fingerprint만 남긴다고 명시한다 (`src/schemathesis-live.ts:129`). Worker는 request 구성의 hash만 보존하고 Hypothesis DB를 끈다 (`workers/schemathesis/worker.py:265-280`). CLI replay는 API/native만 제공한다 (`src/cli.ts:89-90`). | 발견의 정확한 request를 민감 데이터 없이 저장→같은 operation·schema·runtime·scope로 1회 replay→독립 server request 관측으로 동일 입력 확인→fixed의 정상 처리/관찰된 실패 부재. `seed` rerun은 같은 요청의 보증이 아니며 현행 문서도 version에 따라 generation이 달라질 수 있다고 말한다 (`src/schemathesis-live.ts:244`). |
| 3 | reflected XSS의 위험 실행 조건 검증 | 현재 DOM/source 후보는 브라우저 실행 증거가 없다 (`docs/checklist.md:36`); native/API도 browser 제외를 명시한다. 잘 인코딩된 reflection과 실행 가능한 sink의 차이를 검증하면 SQL 외 입력 위험을 넓힌다. Dalfox의 MIT 구현은 marker 생존만으로 executable sink를 인정하지 않고 hidden input 등 비실행 문맥을 구별한다. | owned HTML V/F 쌍→inert reflection 음성 대조→실행 sink 또는 엄밀한 구조 증거→별도 browser egress/credential/subresource 예산→재현. 현재 Node/gate 계약만으로 브라우저 전체 요청 상한을 주장할 수 없다. 따라서 1순위보다 구현/격리 불확실성이 크다. |

1순위는 OWASP API1의 객체별 **행위** 권한 요구에 대응한다. OWASP는 객체 권한 실패가 읽기 외 수정·삭제를 허용할 수 있다고 설명하며, ID를 받는 각 동작에서 권한을 검증하도록 권고한다. [공식 API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/). 이 표의 우선순위는 Wakeio의 현재 구현에 대한 설계 판단이며 OWASP가 Wakeio의 구현 순서를 정했다는 뜻이 아니다.

## 추천 구현 한 건: owned PATCH 객체 수정 검사

### 범위와 설계 경계

첫 증분은 **별도 owned mutation pilot**으로 제한한다. 기존 API v2 GET 정책/기본 URL 수집에 method 옵션을 넣어 쓰기를 자동 허용하지 않는다. 새 runner는 고정 author-owned handler와 private store, 두 합성 principal, 두 resource, `/whoami` GET과 정확한 `/resources/{id}` PATCH, 한 문자열 필드 `title`의 replace만 지원한다. 삭제·생성·결제·file upload·arbitrary body/header·사용자 callback·외부 target·third-party source 실행은 제외한다. 모델은 policy, oracle, fixture 소유권, consent, 실행 결과를 결정하지 않는다.

이 제한은 실용 API에 바로 적용하는 완성 기능이 아니라 다음 attack class의 독립 판정 가능성을 검증하는 최소 증분이다. 사용자 소유 staging용 범용 mutation policy는 별도 승인·resource/cleanup 계약과 실사용 근거가 필요한 후속 작업이다. 이번 task의 active 경계에서는 이를 실행하지 않는다.

### 독립 판정 순서

한 phase의 고정 순서: 두 actor identity-before → owner GET baseline → owner PATCH 정상 변경 → independent readonly fd로 저장 row 검증 → owner GET 정상 변경 확인 → trusted coordinator가 원 상태를 reset하고 fd 검증 → peer PATCH 같은 owner resource 수정 시도 → independent fd로 row 검증 → owner GET 정상 기능/row 대조 → 두 actor identity-after → cleanup. HTTP 요청은 10개이고 local observer/reset 단계도 별도 ledger ordinal을 갖는다. Peer PATCH 후 정상 write 추가로 효과를 덮지 않는다.

Trusted coordinator가 독립 fd로 실제 저장 bytes를 읽는다. Handler가 반환한 success, response echo, scanner finding, worker 제출 JSON을 observer 정답으로 삼지 않는다. Server는 단순 승인 여부에 따른 저장 동작만 수행하며 runner의 판정 함수를 호출하지 않는다. 새로운 title은 합성 nonce로 생성하고 보고서에서는 `original/owner_control/peer_probe/unexpected` 분류만 기록한다. Observation은 한 run·resource·행위의 효과이고 production vulnerabilityConfirmed/원인 증명으로 자동 승격하지 않는다.

### V/F 및 음성 대조의 기대 결과

| owned handler | 독립 저장 관측 | scoped CI 결과 |
|---|---|---|
| vulnerable: peer 허용, 실제 row write | owner control 성공, peer 값으로 owner row 변화 | completed + high observation → 기본 threshold에서 1 |
| fixed: owner check 추가, peer 거절 | owner control 성공, reset 검증, peer 후 원 row 그대로, owner GET 정상 | completed + 해당 finding 없음 → 0 |
| status-only fix: 403을 반환하면서 row 변경 | peer 후 저장 변화 유지 | 1, 403을 거절 증거로 쓰지 않음 |
| 200/no-op peer | owner control 성공, peer는 저장 변화 없음 | scoped unauthorized mutation not_observed; 200만으로 취약으로 올리지 않음 |
| all-deny/no-op owner | 정상 owner write가 저장에 반영되지 않음 | control 미충족/partial → 2, fixed 성공 아님 |
| unrelated field/다른 객체 변경 | 선언 target과 실제 변화 불일치 | 예상 밖 상태 변화 관측은 보존, 전체 partial → 2 |
| stale response/cache echo | body와 fd row 불일치 | partial → 2, 정상 기능 보존으로 인정하지 않음 |
| peer mutation 뒤 identity/cleanup 실패 | 효과는 관측했지만 control/정리 미완료 | high finding 보존 + partial → 2, replay authority 없음 |

이 쌍은 unsafe/fixed에서 relevant ownership predicate만 달라야 한다. 정상 writer와 observer가 같은 `if owner` predicate를 공유하면 독립 discriminating acceptance가 아니다. Separate reviewer가 store mutation과 scanner verdict 연결을 확인하고, 구현 팀이 만든 시나리오 외 status-only/response-echo adversarial pair를 독립적으로 제공한다. 기존 read pilot 테스트는 이 write 흐름을 대신하지 않는다 (`tests/api-state.test.ts:40-76`).

### 실패 불변조건

- **Scope:** own data property snapshot만 받고 accessor/proxy/unknown version 거절. method/path/body는 고정 allowlist로 dispatch 전 검사. 고정 loopback listener 외 주소·userinfo·redirect·다른 origin·query·credential forwarding은 허용하지 않는다. 새 write transport는 기존 GET collect의 자동 기능 확장으로 구현하지 않는다.
- **Budget:** phase 전후 V/F/replay까지 요청·body·시간 예산을 공유하고 각 실제 전송 전에 차감한다. write timeout/응답 유실에 자동 retry하지 않는다. 동일 title set이어도 수신 여부가 불명확하면 `write_effect_unknown`으로 중단한다. 10 logical 요청/phase와 실제 accepted/attempt는 따로 보고한다. 초기 제안 cap: 총 32 HTTP attempts, request body 4KiB, response 64KiB/개·1MiB 합계, store 64KiB, 단일 30초/최대120초. 수치는 구현 전 고정하고 예산 직전/직후를 독립 검증한다.
- **Cancellation:** abort 전이면 zero traffic. write 중 abort라면 이미 수신된 mutation을 지워 성공으로 보고하지 않는다. 새 probe를 중단하고 trusted cleanup만 별도 2초 상한으로 시도한다. cleanup timeout은 `unknown`; 잔존 socket/store를 없앴다고 주장하지 않는다. SDK cooperative timeout과 outer wall supervisor를 구별한다.
- **Credential:** runner가 generated synthetic actor credentials만 사용하고 principal 전후 검증. report/stdout/projection에 token, standalone token hash, nonce, raw body/store values를 넣지 않는다. identity-before 실패 후 peer write 금지. identity-after 실패는 저장 effect가 보여도 partial/2. Refresh/login/anonymous fallback 없음.
- **Report:** phase ledger·planned/attempted/accepted/evaluated count·store effect enum·normal control·cleanup·fixed reason·handler/observer/policy digest를 네 공개 형식에서 일치시킨다. 완결되지 않은 단계는 not_attempted/inconclusive. malformed/forged ledger 또는 delivery 실패는 exit2. 앞의 관측을 뒤의 실패가 지우지 않음. 독립 observer metadata는 글로벌 vulnerabilityConfirmed/remediationVerified flag를 변경하지 않음.
- **Replay:** complete controls + observed effect의 원본만 authorize. 동일 policy/profile/handler revision·예산·consent 요구, 원본 report 보존, 새 private store/resources/nonce로 동일 관계/행위를 다시 만든다. Raw artifact는 source 실행 권한이나 새 endpoint 선택권이 아니다. 입력·lineage 불일치 refused/2, missing store/incomplete controls/cleanup inconclusive/2. 새 nonce run의 재현은 관계/행위의 scoped 재현이며 같은 original customer object의 재전송이라고 주장하지 않음.
- **Delivery:** scan gate와 파일 저장/호출자 ACK를 분리. partial publication·failed ACK·late I/O는 성공 receipt가 아님. delivery-only retry는 보존 redacted bytes만 사용하며 write를 다시 수행하지 않음. 현재 read pilot의 delivery 계약을 좁게 재사용하되 durable/atomic storage는 별도 미완료로 남김.

### 완료에 필요한 실측

구현 완료를 보고하려면 independent V/F/status-only/no-op/all-deny/wrong-object/timeout-after-write/cancel-after-write/identity-after/cleanup failure가 각 기대 결과를 구별해야 한다. 한 fixture의 반복 성공 횟수 대신 **예상 실제 row effect와 판정 confusion table**, 잘못된 clean/잘못된 finding 수, 요청 count 차이, wall time과 조건, 정상 기능 보존, 잔존 resource를 기록한다. CLI 최종 exit·4 artifacts·Action exit/artifact retention·agent projection은 동일 실행의 digest로 연결하고 실제 process/CI receipt를 별도로 보존한다. Advice 모델 호출은 이 acceptance의 필수 단계가 아니다.

## 공식 구현·라이선스 확인과 재사용 판단

- Schemathesis **현재 공식 CLI 문서**는 실패 case를 저장하고 exact request replay 및 curl/JUnit 재현을 제공한다. [공식 CLI tutorial](https://schemathesis.readthedocs.io/en/stable/tutorials/cli/). 이는 Wakeio가 고정한 **4.2.0 SDK/worker가 최신 replay 기능을 지원한다는 증거가 아니다**. 2순위 구현 전에는 고정 버전의 request serialization/API 계약을 확인해야 하며 버전 갱신을 무심코 포함하지 않는다. [v4.2.0 공식 LICENSE](https://raw.githubusercontent.com/schemathesis/schemathesis/v4.2.0/LICENSE)는 MIT이며 저작권/허가문 유지가 필요하다. Public artifact에 raw input을 넣는 것은 현재 redaction 계약과 충돌하므로 credential-free bounded scalar subset과 별도 private reproduction contract부터 정의한다.
- Dalfox `e3573eb91ffdf268790f5e52eee08dd40bf447bf`의 [공식 DOM verifier](https://github.com/hahwul/dalfox/blob/e3573eb91ffdf268790f5e52eee08dd40bf447bf/src/scanning/check_dom_verification.rs)는 surviving executable sink, hidden input, attribute/context 조건을 확인한다. 이를 browser execution의 증명으로 바꾸어 부르지 않는다. [해당 commit LICENSE](https://raw.githubusercontent.com/hahwul/dalfox/e3573eb91ffdf268790f5e52eee08dd40bf447bf/LICENSE.txt)는 MIT. 이 감사는 코드/payload 복사나 엔진 설치를 하지 않았고 1순위 mutation에 Dalfox 코드 재사용은 필요 없다.
- [Nuclei v3.11.1 LICENSE](https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/LICENSE.md)는 MIT. 기존 어댑터를 대체/복제하지 않는다. Engine/license와 templates/assets/의존성 license는 별도로 확인한다. 현재 mutation 추천은 외부 코드를 복사하지 않는 자체 구현이다. OWASP는 methodology 참고만 하며 corpus/license를 재사용한다고 주장하지 않는다. 실질적 복사 시 `CONTRIBUTING.md`와 `THIRD_PARTY_NOTICES.md`의 attribution 요구를 적용한다.

## broader goal의 완료와 아직 입증되지 않은 것

`docs/oss-product-design.md:142-152`는 합성 결과와 실제 프로젝트, 미탐/오탐, fresh install, 시간 조건, 외부 프로젝트의 첫 검사→수정→재검사를 분리하도록 요구한다.

| 사용자 목표 | 현재 근거 및 다음 증분으로 할 수 있는 것 | 목표 완료에 여전히 필요한 것 |
|---|---|---|
| 실제 보안 문제를 찾음 | SQL 차등 candidate와 GET canary 노출; 다음 증분은 합성 store의 무권한 write 효과 | 독립 ground truth의 diverse owned corpus와 미탐/오탐; 이후 별도 승인된 사용자 소유 앱에서 root cause/실제 효과 검증. 공개 OSS source 후보만으로 live 취약점 확인 주장 금지 |
| CI에서 실패 | existing scan/replay 0/1/2; 다음은 mutation effect=1, incomplete=2 설계 | 새 설치 CLI/Action에서 실제 job failure와 artifact retention receipt. source 구현 존재를 hosted CI 통과나 npm 출시로 표현 금지 |
| actionable report와 재현 | 기존 native/API same-policy replay; mutation은 관계/행위 재현 계약 | 사용자에게 실제 source 위치/수정 조건/동일 조건 command가 충분한지 검증; Schemathesis exact input replay는 여전히 2순위 미완료 |
| agent가 수정하고 재검사 | bounded advice/repair의 별도 권한 및 unverified 상태는 보존 | 실제 수정 diff, normal behavior 보존, 동일 scope의 독립 재검증, 실패/부분 실행·credentials·cleanup integrity. 모델 문장/exit0을 oracle로 쓰지 않음 |
| 유료 도구에 가까운 가치 | 중요한 risk class 하나와 reproducible regression 검사를 늘릴 가능성 | target user 첫 결과 시간, setup 실패율, actionable/reused finding 비율, 실사용 false positive/negative, update/maintenance 운영, 비교 조건이 같은 경쟁 평가 및 지불 의사. fixture 수/OSS 엔진 수는 대체 근거가 아님 |

이번 문서의 recommendation 채택, 구현, 테스트 성공, 설치/출시, 사용자 실사용, 매출은 각각 별도 상태다.
