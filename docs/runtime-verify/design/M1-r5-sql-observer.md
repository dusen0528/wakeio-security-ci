# M1 R5: pg-log·마커·SQL Oracle CP1 설계

기준 `a49da4ceebc2c7dd24020ecbce420f46d0ca7625`, PLAN 4·6·7·11~13장. 설계 제안이며 구현·실측은 없다.
R5는 관측·판정만 소유한다. R8의 취약/수정/음성 예제와 기대값은 읽기 전용이고 판정에 맞춰 고치지 않는다.

## 1. 수집 경계와 PostgreSQL 로그

추천은 소유 PG의 `logging_collector=on`, `jsonlog`, `log_statement=all`, `log_min_error_statement=ERROR`다.
마지막 설정이 없으면 parse 단계의 오류 문장이 빠질 수 있다. CSV 대안은 RFC CSV 파서로 같은 사건을 만든다.
설정·PG 이미지/major·collector 버전·소유 DB/container ID를 R3 lease와 R1 artifact에 결속한다.
앱 DB role은 `NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS`이며 관리·collector 계정과 분리한다.
`pg_read_server_files`·`pg_write_server_files`·`pg_execute_server_program`의 직접/간접 멤버십과 관리 role로의 SET 경로는 0이다.
일반 verify 기본값도 R8처럼 DB CONNECT·대상 schema USAGE·허용 테이블 SELECT만 준다.
PUBLIC/상속을 포함한 유효 권한에서 앱 소유권·CREATE·TEMP를 배제한다.
seed/snapshot은 별도 관리 경로에서 수행하고 원문 복원 SQL·관리 credential·복원 capability를 앱에 전달하지 않는다.
`log_statement`·`log_min_error_statement`는 SUSET이므로 서버 레벨에 고정하고 앱에 parameter SET 권한을 주지 않는다.
Observer는 trusted pinned PG lease의 독립 관리 연결로 실제 `pg_settings`·role 속성/멤버십/parameter 권한을 초기 검증한다.
DB/role override·startup option을 포함한 앱 인증 세션의 유효값도 앱 응답을 통하지 않고 확인한다.
수집 시작/종료 barrier에서 같은 DB identity·유효 설정·role 경계와 collector cursor/연속성을 확인한다.
설정 드리프트·barrier 누락·앱 주장뿐인 값·비신뢰 DB 로그는 관련 구간 unknown/error이며 clean 근거로 쓰지 않는다.
target stdout나 HTTP 오류 본문을 PG 사건으로 받지 않고 관리 포트를 호스트에 공개하지 않는다.
JSON `message`의 statement/execute와 `statement`, `detail`의 Bind 값, `state_code`·`cursor_position`을 구분한다.
extended protocol의 `$1` 문장과 detail의 마커는 **binding**이다. 겹따옴표로 표시된 값은 SQL 문장으로 재파싱하지 않는다.
단일 JSON 객체·session/line으로 연결하고 연관을 입증할 수 없는 조각을 추측해 합치지 않는다.
SQLSTATE `42601`은 일반 문법 오류이므로 그 값이나 오류 문자열만으로 SQLi를 확정하지 않는다.
PG 오류 위치는 1-based 문자 인덱스다. scanner/AST의 위치 단위와 UTF-8 변환은 핀된 버전 테스트로 대조한다.
새 로그 시작 cursor를 seed 뒤에 고정하고 종료 drain까지 수집한다. 중복 session/line, rotation gap·잘린 줄은 미완료다.
로그 설정/DB identity 확인 실패, collector 중단·시간 초과·한도 도달·애매한 연결은 `unknown`으로 남긴다.

## 2. 마커와 공격·대조군 결속

`wk` + run prefix 4자 + 요청별 base32 8자. seed·target/Pack digest로 prefix를 만들고 발급 충돌을 거부한다.
동일 seed의 매핑은 재현하되 별도 고유 run nonce·소유 PG lease·새 cursor로 이전 실행 사건을 격리한다.
발급 ledger는 marker hash→run/route/method/parameter/location/payloadKind/request ordinal/pairId/control|probe를 묶는다.
평문 요청 값·credential은 ledger/보고서에 넣지 않는다. 발급된 합성 마커는 메모리에서만 대조한다.
recipe/seed/counter로 재현하고 report에는 marker hash만 노출한다. seed는 사용자 비밀값으로부터 파생하지 않는다.
미발급 마커·다중 요청에 재사용된 마커·다른 run/DB·닫힌 요청 구간의 늦은 사건은 판정 입력으로 거부한다.
route/parameter 단위로 무해 control과 probe를 직렬 실행하고 공통 admission에서 두 요청 모두 예산을 소비한다.
control 성공 응답·대응 PG 관측·동일 SQL 문맥을 확인해야 차등 판정이 유효하다. control이 없으면 `unknown`이다.
시계/로그 도착 시간만으로 request를 연결하지 않는다. 정확한 ledger 마커와 collector cursor·request 구간을 함께 쓴다.

## 3. 원문을 남기지 않는 단계 파일

원문 PG 줄은 bounded private 메모리에서만 해석한다. 마커 없는 사건은 저장·보고하지 않고 즉시 버린다.
R5의 Observer parser adapter가 원문 SQL을 PG parser/scanner로 분석해 아래 projection을 만든다.
식별자·literal·comment·Bind 값·localized error text·DB 사용자/호스트는 삭제하고 종류/길이/해시로 대체한다.
유지할 것은 SQL/원본 사건 hash, AST node 종류·관계, token 종류/범위, marker/payload 대응 위치·역할이다.
오류 projection에는 SQLSTATE·검증된 위치와 parser의 오류 분류만 남긴다. 원문 excerpt나 `formatSqlError` 출력은 금지한다.
payload 바깥 token hash와 control의 문맥을 비교한다. 단순한 fingerprint 차이나 문자열 포함은 승격 증거가 아니다.
원문 삭제 전에 projection의 범위·인코딩·literal/parameter 역할 보존을 확인하고 실패하면 `unknown`으로 낸다.
R1 artifact는 version/runNonce/target·Pack·parser digest/ledger hash/앞 단계 hash/body hash를 결속한다.
private 0700 경로·0600 exclusive write와 target 미공유 volume을 사용한다. 해시는 출처 인증을 대신하지 않는다.
R1 loader는 trusted collector lease와 artifact chain을 확인한다. target이 제공한 projection/판정 boolean은 허용하지 않는다.
제안 한도: SQL 32 KiB, PG record 64 KiB, 전체 normalized 8 MiB·4,096사건, AST 20,000노드·깊이40.
NUL·잘못된 UTF-8·초과·parser crash는 reason과 hash만 남기고 관측 범위를 미완료로 표시한다.

## 4. 순수 Oracle 입력·판정

`judge(attackLog, ledger, observations, coverage?)`에는 검증된 데이터만 주며 파일·네트워크·시계·Docker handle은 없다.
judge는 I/O 없는 함수다. parser 준비·실행·WASM 파일 로딩은 consent 뒤 Observer 단계로 격리한다.
판정 입력은 AST/token 역할 projection이며 judge가 승격 조건을 계산한다. 외부의 promoted boolean은 받지 않는다.
아래는 전체 event 수집과 유효한 control/pair·문맥 결속을 먼저 검증한 뒤 적용한다.

| 증거 | 결과 |
| --- | --- |
| marker가 Bind 값에만 있고 문장에는 `$n` | bound 관측, confirmed/strong 아님 |
| escaped literal/comment 안에만 남음 | literal/comment 관측, confirmed 아님 |
| 문장에 직접 조립됐으나 payload token의 구문 승격 입증 부족 | strong; 미지원 parser/역할 불명은 unknown |
| 발급 payload의 token이 literal 밖에 있고 대응 AST 구문이 생기며 control에는 없음 | confirmed, `syntax_promotion` |
| quote probe의 동일 문맥에서 PG42601 + parser의 마커 연관 따옴표 불균형/위치가 일치 | confirmed, `quote_imbalance` |
| probe와 무관한 syntax error, control 오류, 위치·token provenance 불명 | unknown, confirmed 아님 |
| SQL collector/관측 구간/ledger 결속 실패 | 해당 case unknown; 다른 유효 case의 confirmed는 유지 |
| SQL 증거는 유효하고 coverage만 누락/실패 | reach unknown; SQL confirmed를 취소하거나 안전으로 바꾸지 않음 |

승격은 발급 recipe의 정확한 삽입 구간과 parser token/AST를 함께 대조한다. 정규식 SQL parser는 만들지 않는다.
구문 오류 경로도 42601만으로 통과하지 않고 정상 control, quote payload 위치, 같은 parser의 불균형 진단을 요구한다.
syntax/control 판정과 reach는 별도다. JaCoCo handler·line 증거가 없으면 reach는 unknown이고 0줄로 대체하지 않는다.
R8 N13대로 유효 confirmed + 다른 case/coverage gap은 finding과 gap을 함께 남기고 verify exit1을 유지한다.
관측과 판정 결과는 안정적인 reason/marker hash/evidence hash·범위로 정렬해 같은 입력에 같은 결과를 낸다.

## 5. parser 선택지와 배포 (PLAN13 CP1 검토 대상)

추천 후보는 PostgreSQL18 + `libpg-query@18.2.1`의 parse/scan sync API다. 13~17 wrapper는 parse-only다.
공식 package 소스와 npm metadata에서 18.2.1/MIT를 확인했다. 설치·WASM 실행·무결성 실측은 아직 하지 않았다.
`loadModule`은 Observer의 전용 parser helper에서만 호출하고 Oracle에 package 자체를 import하지 않는다.
이 wrapper는 WASM trap 뒤 sync 호출에서도 비동기 재초기화를 시작한다. 준비된 sync API만으로 순수를 보장하지 않는다.
helper는 R3가 감독하는 전용 프로세스/컨테이너에서 실행하고 raw SQL을 stdout/stderr에 쓰지 않는다.
input/AST 한도 외에 초기 제안 1초·256MiB 제한을 적용하고 trap·재초기화·timeout은 unknown으로 종료한다.
버전만으로 동작을 신뢰하지 않고 정확한 npm integrity·transitive lock·WASM SHA·PG major/설정을 pin한다.
npm pack/설치·Action bundle 모두 로컬 WASM asset을 포함하고 런타임 CDN fetch·호스트 native build는 금지한다.
상류 libpg_query는 BSD-3-Clause/PostgreSQL 고지를, Node wrapper는 MIT 고지를 배포물에 포함한다.
대안은 같은 major C libpg_query의 격리 helper지만 native ABI·출력 검증 비용이 커 M1 추천은 아니다.
순수 TS 재구현은 PG 문법 동등성 근거가 없어 confirmed의 대체 판정기로 쓰지 않는다.
DB/parser major 불일치·미지원 문법·asset 누락은 unknown이다. 스키마에 없는 dialect 지원을 주장하지 않는다.

## 6. 파일·독립 검증·보고 연결

제품·helper·테스트 파일과 PLAN11/R8 case 매핑은 [R1 §7](M1-r1-contracts.md#7-cp1-이후-패킷파일검증-제안)이 유일한 canonical 명부다.
R1 공유 요청: 위 ledger·normalized observation·artifact provenance·control validity·unknown reason 필드.
R3 공유 요청: collector 로그 cursor/rotation·소유 PG lease·secret 분리·정리 확인; raw server volume은 종료 시 삭제한다.
R8은 parser와 무관하게 V/F/음성·binding·quote·comment·일반 오류·비마커·누락/중단 기대 매트릭스를 소유한다.
R9는 고정 관측 replay와 실제 V/F/safe 두 번 실행, 마커 충돌0·비마커/secret 누출0·cleanup을 독립 검증한다.
R10의 4종 보고에는 grade/reach·reason·artifact hash/위치만 전달하고 raw SQL·응답·PG detail을 넘기지 않는다.
발견+미완료는 verify exit1, 유효한 발견 없이 관측 실패는 exit2이며 기존 scan 종료 코드는 변경하지 않는다.

## 1차 자료

- [PG 로그·extended Bind·오류 문장](https://www.postgresql.org/docs/18/runtime-config-logging.html)
- [PG 오류 위치 단위](https://www.postgresql.org/docs/18/protocol-error-fields.html)
- [PG role 속성](https://www.postgresql.org/docs/18/sql-createrole.html) · [서버 파일·프로그램 role](https://www.postgresql.org/docs/18/predefined-roles.html)
- [wrapper API](https://github.com/constructive-io/libpg-query-node/tree/main/versions/18) · [scan 위치](https://github.com/constructive-io/libpg-query-node/blob/main/versions/18/SCAN.md)
- [wrapper 코드·초기화](https://github.com/constructive-io/libpg-query-node/blob/main/versions/18/src/index.ts) · [wrapper MIT](https://github.com/constructive-io/libpg-query-node/blob/main/LICENSE)
- [상류 parser·BSD](https://github.com/pganalyze/libpg_query) · [버전 후보](https://github.com/constructive-io/libpg-query-node/blob/main/versions/18/package.json)
