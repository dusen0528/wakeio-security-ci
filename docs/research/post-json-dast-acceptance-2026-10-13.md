# POST JSON numeric SQL 차등 검사의 독립 수용 기준

기준: 2026-10-13, main `397bb8e2d6de2edba0d5bf0b48ae9382e806d86f`. 이 문서는
구현 전 고정한 기대값과 공식 자료의 설계 근거다. 정책 v4는 **승인된 구현 범위**이며
아래 표는 검증 결과가 아니다. Root의 기존 frozen build에서는 v4 policy keys를
거부하고 invalid_policy·requestCount0을 기록했다. 로컬 전용 원본 경로는
`artifacts/post-json-dast-2026-10-13/baseline-reproduction.json`이다. 새 정책이 기존
GET 계약에 이미 지원됐던 것으로 표현하지 않는다.

## 고정할 입력과 실행 경계

인증된 단일 fixed URL의 POST JSON을 새 명시적 numeric profile로 추가한다. URL에
query를 넣지 않고 bounded top-level scalar body 중 선택한 numeric-string field
하나만 바꾼다. 다른 body field는 고정한다. Authorization은 선택한 환경 변수의
complete header를 snapshot하며 전후 동일 origin의 identity GET을 대조한다.
로그인·refresh·cookie jar·anonymous fallback·자동 field/context 발견은 없다.

고정 순서는 GET identity-before → 두 라운드의 POST baseline-before /
benign-alternate / true / false / baseline-after → GET identity-after다. 총
12 logical steps, GET2+POST10이다. Alternate benign value와 oracle는 baseline과
달라야 한다. Field가 응답을 실제로 바꾸는 정상 대조가 없으면 probe의 부재를
차단 성공으로 세지 않는다. Body의 exact schema·byte cap·revision field는 생산자의
최종 계약을 다음 절에 별도로 기록하며, 이 기대값을 결과에 맞춰 완화하지 않는다.

모든 요청은 기존 consent·origin allowlist·DNS peer·TLS·response byte·deadline·
request budget·취소·cleanup 계약을 공유한다. POST는 자동 retry하거나 redirect를
따라 다시 보내지 않는다. Transport가 전송 여부를 알 수 없어도 재전송하지 않는다.
POST method는 본질적으로 read-only가 아니므로 사용자는 반복 probe를 허가한
검색/조회 계약을 명시해야 한다. 이 기능은 저장 effect 확인이나 rollback을 제공하지
않는다. 기존 owned PATCH persisted-state pilot과 별도 기능이다.

## 구현 전 고정하는 독립 대조

| Group | 자체 정답과 실패 경계 |
| --- | --- |
| 1. Offline protocol | v4만 명시적으로 허용. Fixed origin/path, no URL query, top-level bounded scalar JSON, 선택 field 존재/초기 numeric string, 다른 field 불변, auth pair, distinct benign value/oracle를 검사. Array/nested object/unknown or prototype keys/URL credentials/선언 밖 authorization literal/잘못된 값은 HTTP0으로 거부. GET v1/v2/v3 의미·hash·counts 불변. |
| 2. 실제 SQLite pair | 인증된 자체 loopback fixture의 V는 선택 value를 numeric SQL text에 결합하고 F는 같은 query를 binding으로 처리. 두 라운드의 baseline·benign alternate가 정상값으로 맞아야 함. V는 반복 true/false differential candidate→기본 high gate1, F는 정상 대조를 유지한 not_observed→0. 단순 문자열 mock을 DB 실행 근거로 바꾸지 않음. |
| 3. 정상 기능과 near misses | Field ignored·상수 응답·all-denied·baseline/alternate drift·요청 field/body/method 오인·false/true round 불일치·missing/invalid oracle는 partial2. 정상 alternate를 받지 않은 run은 clean negative가 아님. |
| 4. Identity와 egress | Identity-before failure는 POST0. Trailing identity failure는 retained observed candidate를 낮은 confidence/partial2로 보존하며 replay 불허. Token은 한 번 snapshot, 전 요청 bound origin/peer, POST redirect/retry없음. Body sent at most once per planned POST; 네트워크 fault/429/5xx/body 한도는 미완료. |
| 5. Lifecycle와 immutable input | Deadline/budget/cancel은2, 이미 관찰한 결과를 지우지 않음. Caller policy/body/env mutation·accessor/proxy·body cap·malformed evidence는 fail closed. Child/server/worker 정리 확인과 method ledger를 독립 대조; 외부 OSS target code 설치/import/build/test는 실행하지 않음. Root는 자체 owned fixture와 trusted scanner를 실행해 실제 SQLite 대조를 검증. |
| 6. Public report and consumers | JSON/agent/Markdown/SARIF는 동일한 revision·method/phase·normal/identity/probe outcome와 budget을 보존. Body/token/original/alternate/probe/oracle values는 제외. CLI·bundle·실제 Action wrapper·fresh consumer·explicit replay가 같은 정책/consent/gate를 사용. Policy/context/body/normal-control drift는 unverified; --fail-on none도 partial2. |

Candidate는 응답 대조 근거이며 vulnerabilityConfirmed/remediationVerified를 true로
바꾸지 않는다. Completed no-observed는 이 policy의 bounded differential 미관찰이다.
Source candidate·저장 effect observation·동적 응답 differential을 서로 바꾸지 않는다.
기존 report/SDK/Action delivery receipt와 실제 최종 process exit는 별도로 확인한다.

## 채택된 producer protocol

최종 선언은 version4, kind `sql-boolean-differential`, profile `numeric`,
method `POST`, `baseUrl`, query 없는 `url`, `parameter`, scalar-map `body`,
`alternate: { value, expected }`, 기존 `oracle`, 필수 `authorizationEnv`와 `identity`다.
선택 field의 원본과 alternate는 서로 다른 canonical nonnegative numeric string
(`0` 또는 선행0 없는1–9자리)이다. Alternate expected scalar는 baseline과 달라야
하며 기존 true expected는 baseline과 같고 false expected는 달라야 한다.

Body는 own key 최대16개, key는 기존 PARAMETER grammar이며 `__proto__`,
`constructor`, `prototype`은 제외한다. Value는 JSON scalar만이며 문자열은1024자
이하다. Nested object/array는 없고 매 normal/probe body는 UTF8 4096bytes 이하다.
기존 CLI JSON.parse의 lexical duplicate-key 탐지를 이 slice에 새 요구사항으로
넣지 않는다. Unknown/prototype keys와 객체의 accessor/proxy는 별도 거부 경계다.

Revision은 `sql-boolean-json-auth-v4`, 기본 request budget12/최대64, timeout
기본30초/최대120초, response당128KiB/전체512KiB다. 각 POST는 승인된 DNS peer
하나에 한 번 전송하고 address retry/HTTP retry/redirect follow가 없다. 두 GET
identity는 기존 bounded retry 계약과 shared budget을 따른다. GET v1/v2/v3는 바꾸지
않는다. SDK runDast, CLI scan/plan, 별도 active DAST Action, explicit replay를 재사용한다.

Ledger는 method POST, authentication authorization, round별 normalControls
`matched|mismatched|inconclusive|not_attempted`, identityControls와 probeOutcome를
보존한다. Alternate oracleMatch와 `benign_control_mismatch` 원인이 추가된다.
Uniform fixed probes는 known baseline 또는 false scalar에 한해서만 not_observed로
완료할 수 있으며 임의 다른 scalar는2다. 선택 parameter name, raw body/value,
expected/oracle/auth/identity data는 producer 보고 문구에 복사하지 않는다.

Root의 **product 실행 전 SQL truth lock**은 로컬 전용
`artifacts/post-json-dast-2026-10-13/sqlite-truth-lock.json`에 있다. 한 라운드의
V oracle 순서는 `[2,1,2,0,2]`, bound F는 `[2,1,0,0,2]`이며 DB rows 불변으로
기록됐다. 이는 normal/probe 정답 동결이며 HTTP scanner 구현·게이트 성공 기록이
아니다. 원본 SHA256은
`9e5d3b833da04290bff10cebb8638ee15cd9c2950f1fd1ce7ec0de54899de068`다.

## 공식 자료의 적용과 라이선스

OWASP WSTG는 HTTP 입력을 조사할 때 POST form과 request body도 보도록 설명하고,
숫자 SQL context의 true/false 논리 대조와 재현 가능한 response 차이를 다룬다.
이것은 POST JSON 입력을 검사 범위에 포함할 근거이며 Wakeio의 정확한12단계나
기대 oracle를 OWASP 표준으로 주장하는 근거는 아니다.
[WSTG v4.2 SQL injection](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/).

전후 신원 대조는 선택 credential이 의도한 principal에 연결되는지 확인하는 제한된
control이다. 임의 endpoint의 권한 정책이나 중간 session continuity를 인증하지 않는다.
[WSTG authorization schema](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/).

Parameterized statement는 SQL code와 data를 분리하는 정상 counterpart의 근거다.
타입 검증·최소 권한 등은 별도이며 일반적으로 모든 SQL 문제를 해결했다고 주장하지
않는다. [OWASP SQL prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).

RFC9110 §9.2.2는 non-idempotent method를 의미를 모른 채 자동 retry하지 않도록
규정한다. 따라서 전송 여부가 모호한 POST를 재시도하지 않는 것은 이번 runner의
명시적 설계 결정이다. GET identity retry가 허용되더라도 동일 shared budget을
소비해야 한다. [RFC9110 §9.2.2](https://datatracker.ietf.org/doc/html/rfc9110#section-9.2.2).

[선행 MIT-engine 조사](mit-dast-engine-2026-10-13.md)는 공식 Nuclei engine과
별도 template license 및 narrow true/false matcher 원천을 구분했다.
[Nuclei3.11.1 engine MIT](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/LICENSE.md)와
[pinned template MIT](https://github.com/projectdiscovery/nuclei-templates/blob/3d818a6e398abd5867c50b35218ba25224d12b99/LICENSE.md)는 실제 코드/asset의 license다.
이번 POST protocol은 Wakeio가 독립 설계하며 외부 payload/template/code를 복사하지
않는다. OWASP 문서와 MIT engine code를 같은 라이선스의 복사 원천으로 취급하지
않는다. 구현은 CONTRIBUTING의 redaction·incomplete·four-format 계약을 따른다.

## 후속 구현·검증 기록

Acceptance 기대값은 위 표로 먼저 동결한다. Producer schema와 독립 tests의 초기
hash, root의 실제 실행·required suite·fresh distribution·hosted CI 결과는 뒤에
추가하며 과거 실패나 oracle를 덮어쓰지 않는다. 현재 실제 성공 수치는 없다. 외부
서비스 scan·모델 호출·npm publication·새 OSS 취약점 발견·상용 품질은 주장하지 않는다.

## 후속 archive source slice (미구현)

이번 구현에 포함하지 않은 별도 후보는 archive entry path→파일 write operand의
bounded source 역할 모델이다. 고정 Juice Shop의 [fileUpload.ts27–34](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/fileUpload.ts#L27-L34)는
entry.path를 write 경로에 연결하며, 기존 glob filename→shell 모델은 이 sink를
검사하지 않는다. 이는 알려진 교육용 경로이며 새 발견이 아니다. 다른 POST/owned
PATCH 기능에 archive source coverage가 생겼다고 해석하지 않는다. Multer/unzipper
선언 range는 설치 버전 증명이 아니며 exact source authority와 정상/경계 대조를
따로 동결한 후 제안한다. 아직 제품 변경이나 target 실행은 없다.


## 2026-10-13 후속 로컬 실행 기록

위 acceptance와 product 실행 전 SQL truth lock을 바꾸지 않고 이후 결과를 추가한다.
Root의 focused 검증55/55(새 POST JSON groups16개·기존 regressions39개), CI 지원
검사18개, required-engine 전체1067/1067이 통과했다. Failed/skipped/cancelled/todo는
모두0이다. 전체 suite는 기존 기능을 포함하며1067개를 새 POST 대조 수로 세지 않는다.

Required-engine receipt는 로컬 전용
`artifacts/ci/required-engine-xqqUFH/receipt.json`이며 status passed·exitCode0이다.
검사 전후 source SHA256은 모두
`66226ae1e5da6fe7800c0a98beb24fca715b7cc0d32e3f4a4be69b94a21afa41`다.
준비된 실행 환경은 Node22.22.1, Python3.12.13, Schemathesis4.2.0,
checksum-pinned Nuclei3.11.1이다. 외부 target 코드를 실행한 근거로 바꾸지 않는다.

자체 SQLite V/F와 정상·실패 controls, wire attempts, lifecycle, immutable inputs,
SDK/CLI·실제 기존 Action wrapper·네 보고서·explicit replay를 로컬에서 검증했다.
독립 Standards review와 별도 Spec review의 현재 actionable findings는 각각0이다.
Standards count는 문서 작성자 자신의 문서 검토를 독립 결과로 포함하지 않는다.

이 기록 시점의 fresh distribution consumer와 hosted CI는 위 로컬 suite와 별개의
검증 단계이며 여기서 통과를 주장하지 않는다. 이후 실제 receipt는 배포 검증과 PR
기록에서 별도로 확인한다. 모델 호출·npm 신규 publication·외부 서비스 효과·새 OSS
취약점 또는 상용 동등성을 입증하지 않는다. 이전 baseline refusal와 oracle는 보존한다.


## 2026-10-13 fresh consumer 후속 수정과 재검증

첫 fresh distribution consumer는 JSON·agent·SARIF와 달리 Markdown에서 v4
profile revision이 빠진 실제 출력 결함을 발견했다. 초기 Spec review의0건과
합쳐진 형식 문자열 assertion은 이 누락을 놓쳤다. 앞 절의 초기 검토·suite 기록을
형식별 계약이 처음부터 완벽했다는 근거로 해석하지 않는다. `src/report.ts`의 v4
Markdown line에 revision을 명시했고, producer와 독립 QA tests가 네 형식 각각에
revision이 존재하는지 assertion하도록 강화했다. 초기 consumer 실패 기록과 QA
manifest v2는 별도 private evidence로 보존하며 acceptance 기대값은 바꾸지 않았다.

수정 후 required-engine 전체1067/1067이 다시 통과했다. Failed/skipped/cancelled/
todo는 모두0이며 세 stage의 exitCode0·cleanupConfirmed true다. 최종 receipt는
로컬 전용 `artifacts/ci/required-engine-LqwlAZ/receipt.json`이다. 검사 전후 source
SHA256은 모두
`61989c3b36eeff8d547dee1213f6f7413d64f0bc9c4ccdbb3336f3b704745da8`다.
이 재검증도 전체 suite와 자체 대조 범위이며, 재포장 archive의 fresh consumer와
hosted CI 성공은 각각의 이후 실행 receipt에서 따로 확인한다.
