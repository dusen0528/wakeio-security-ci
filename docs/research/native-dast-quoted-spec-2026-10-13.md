# 명시적 single-quoted SQL 프로파일: 독립 수용 계약

2026-10-13. 기준 구현 main `0de8866`. 역할: 구현자와 분리된 efficacy/acceptance reviewer. 이 문서는 구현·실행 전 계약이며, 통과 결과가 아니다. 외부 대상이나 모델을 실행하지 않는다.

## 해결할 경계와 먼저 검증할 가설

현재 [`parseDastPolicy`](../../src/dast.ts)는 numeric만 받으며 기존 값에 ` AND 1=1` / ` AND 1=2`를 붙인다. SQLite의 문자열 결합 `WHERE name = '<input>'`에 숫자처럼 보이는 문자열 `1`을 넣으면, 기존 numeric 두 probe는 모두 정상적인 빈 결과가 된다. baseline/true/false/baseline 두 회가 `1,0,0,1`로 반복되어 현재 계약상 `not_observed`가 예상된다. 균형 quote 조건에서는 취약 counterpart가 `1,1,0,1`, 바인딩 counterpart가 `1,0,0,1`이어야 한다. 이는 일반 탐지율이나 운영 취약점의 주장이 아니다.

독립 baseline은 ignored `artifacts/dast-quoted-2026-10-13/baseline-quoted.mjs`이며 root가 보존한 `baseline-build/src` API를 불러온다. 자체 인메모리 SQLite와 literal loopback만 사용하고 새 출력 디렉터리에 기존 네 보고서의 SHA와 수동 대조 결과를 남긴다. 수동 결과는 scanner finding으로 합치지 않는다.

## 정책과 동작의 잠금

- 새 정책 version 3, 명시적 `profile: single-quoted`. v1/v2 numeric canonical bytes, policy SHA, revision, finding ID, 요청 수, replay 계약을 변경하지 않는다. 자동 문맥 추론·fallback은 없다.
- 원래 값은 decoded printable ASCII 1..128자이며 single quote, backslash, control, whitespace-only를 거절한다. 이름이 존재하는 query key 하나만 허용하고 중복·userinfo·fragment·origin 변경은 기존처럼 거절한다.
- mutation은 원래 값 뒤에 `' AND '1'='1` 또는 `' AND '1'='2`를 붙이는 두 고정 suffix뿐이다. comment, UNION, 함수, 지연, 데이터 추출, 임의 payload, 추가 파라미터 탐색은 없다. 이 문법의 문자열 비교 문맥 외에 SQL dialect 또는 escape 방식 지원을 주장하지 않는다.
- unauth는 B/T/F/B 두 회의 8 logical GET. auth는 authorizationEnv와 identity를 모두 지정한 경우만 허용하고 identity-before + 8 SQL + identity-after로 10 logical GET. 한 필드만 있으면 0-request refusal이다. 기존 HTTPS/명시적 literal-loopback 예외, env own-data snapshot, redirect 거절을 보존한다.
- profile/auth 여부를 policy SHA와 별도 revision에 결속한다. ledger는 버전 및 auth 모드로 8/10 고정 구조를 검증한다. 요청 시도·body·deadline·취소는 한 실행 예산이며 retry도 차감한다.

## 독립 수용 행렬

1. actual SQLite 문자열 결합과 prepared binding의 최소 쌍: 일반 문자열과 숫자형 문자열 모두 실행. 전자는 candidate/high/medium와 exit 1, 후자는 후보 없음·완료·exit 0. 입력 무시도 완료·후보 없음. 정확한 SQL 값을 검사하는 정규식 fixture로 대신하지 않는다.
2. 실제 wire 순서와 값은 fixture 내부에서만 검증한다. baseline drift, probe 비대칭·반복 불일치, unknown oracle, JSON 오류, 429/5xx, body 초과, redirect, budget 부족, timeout/cancel은 partial/exit 2다. `--fail-on none`도 미완료를 성공으로 바꾸지 않는다.
3. auth 실패 전 SQL 요청 0회. 뒤 identity 실패·예산9는 관찰된 SQL 후보를 low로 남기지만 partial/exit 2이고 replay 불가다. 토큰 회전은 동일 principal의 새 replay에서만 재해결한다.
4. report.json, agent-report.json, report.md, SARIF와 advice projection에 query seed/probe, SQL 원문, token 또는 token hash, env 이름, identity path/pointer/principal이 없어야 한다. 모델을 호출하지 않고 projection만 검사한다.
5. replay는 원래 완료 ledger·선택 finding·policy/revision·유효 예산·원점/private 재승인을 검사한다. profile/auth 변경과 forged ledger는 요청 전에 거절한다. 실제 binding 변경 후에는 `not_reproduced`; 오류는 `inconclusive`다. 원래 보고서는 불변이다.
6. CLI/SDK/Action/plan는 동일 정책을 사용한다. source-only init의 제약을 이 탐지 기능으로 해결했다고 주장하지 않는다. 누락된 oracle은 자동 추정하지 않는다.

기존 [MIT DAST 연구](mit-dast-engine-2026-10-13.md)는 반복 조건 비교의 참고 근거다. 새 suffix 및 SQLite 쌍은 독립 Wakeio 구현 계약이며 upstream 코드 복사나 광범위 detector 성능을 뜻하지 않는다. 현재 [native DAST 계약](../native-dast.md)과 [authenticated 계약](../native-dast-auth.md)의 동의·redaction·partial 경계를 유지한다.
