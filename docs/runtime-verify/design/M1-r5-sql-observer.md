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

`wk` + 20bit prefix의 base32 4자 + 요청 ordinal의 base32 8자이며 ledger 내부의 발급 충돌을 거부한다.
prefix는 SHA256(JSON 배열 `['wakeio.markers/v1', reproductionKey, seed]`)의 앞 20bit로 계산한다.
ledger의 reproductionKey·seed·ordinal만으로 원문 마커를 재구성할 수 있다. markerHash는 기밀성을 보장하지 않는다.
원문을 보고서에 직접 넣지는 않지만 재구성 가능성은 남는다. 이 마커는 합성 추적값이며 인증 비밀·실행 권한이 아니다.
동일 reproductionKey·seed의 매핑은 재현하되 별도 고유 run nonce·소유 PG lease·새 cursor로 이전 실행 사건을 격리한다.
발급 ledger는 marker hash→run/route/method/parameter/location/payloadKind/request ordinal/pairId/control|probe를 묶는다.
평문 요청 값·credential은 ledger/보고서에 넣지 않는다. 발급된 합성 마커는 메모리에서만 대조한다.
recipe/seed/counter로 재현하고 report에는 marker hash만 노출한다. seed는 사용자 비밀값으로부터 파생하지 않는다.
seed에는 비밀값을 넣지 않으며 재현성을 바꾸는 비밀 salt를 임의로 도입하지 않는다.
20bit prefix는 물리 실행 간 전역 유일성이나 이전 실행 사건의 구별을 보장하지 않는다.
미발급 마커·다중 요청에 재사용된 마커·다른 run/DB·닫힌 요청 구간의 늦은 사건은 판정 입력으로 거부한다.
route/parameter 단위로 무해 control과 probe를 직렬 실행하고 공통 admission에서 두 요청 모두 예산을 소비한다.
control 성공 응답·대응 PG 관측·동일 SQL 문맥을 확인해야 차등 판정이 유효하다. control이 없으면 `unknown`이다.
시계/로그 도착 시간만으로 request를 연결하지 않는다. 정확한 ledger 마커와 collector cursor·request 구간을 함께 쓴다.
후속 collector 완료 조건: 매 물리 실행마다 새 DB instance·container·소유 로그를 만들고 이전 실행 로그/volume을 재사용하지 않는다.
동일 이미지/seed snapshot을 복원해도 runNonce·DB/container identity·lease는 새로 결속하고 seed 뒤 새 cursor에서 시작한다.
control/probe는 직렬 window를 닫고 drain하며 늦은 사건·다른 run/lease/cursor의 로그 혼합을 거부한다.
이 격리는 collector/R9 후속 검증 대상이다. 재구성 가능한 마커의 일치나 hash만으로 수집 출처를 인증했다고 주장하지 않는다.

## 3. 원문을 남기지 않는 단계 파일

원문 PG 줄은 bounded private 메모리에서만 해석한다. 마커 없는 사건은 저장·보고하지 않고 즉시 버린다.
R5의 Observer parser adapter가 원문 SQL을 PG parser/scanner로 분석해 아래 projection을 만든다.
식별자·literal·comment·Bind 값·localized error text·DB 사용자/호스트는 삭제하고 허용된 종류/범위·집계 hash만 남긴다.
유지할 것은 SQL/원본 사건 hash, AST node 종류·관계, token 종류/범위, marker/payload 대응 위치·역할이다.
오류 projection에는 SQLSTATE·검증된 위치와 parser의 오류 분류만 남긴다. 원문 excerpt나 `formatSqlError` 출력은 금지한다.
payload 바깥 token hash와 control의 문맥을 비교한다. 단순한 fingerprint 차이나 문자열 포함은 승격 증거가 아니다.
개별 token hash는 비교용 transient 값이며 단계 파일에 보관하지 않는다. 아래 CPx8 N2 수명 정책을 적용한다.
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

## M1-58 순수층 구현 범위

`judgeSql`은 새 로컬 data-only binding으로 검증된 stage/collector identity·요청별 물리 창/원본 hash·parser pin을 받는다.
hash는 인증이 아니며 호출 전 pipeline의 provenance 검증이 필수다. Oracle 자체는 I/O·parser/WASM을 갖지 않는다.
관측은 개별 bounded snapshot, 메타데이터는 공통 snapshot으로 복사한다(각 1MiB/20,000 JSON node, 전체 8MiB/4,096건).
강한 판정은 control과 다른 literal 밖 OR/AND의 BoolExpr 자식 관계 또는 검증된 위치 대응의 quote 진단으로 한정한다.
R8 manual projection 테스트의 parser pin은 합성 라벨이며 실제 parser 출력·PG 실행·원문 폐기·cleanup·최종 exit 증거가 아니다.
R3/R5 collector는 요청별 원본 hash·statement byte 길이·물리 장벽·위치 대응을, R3 coverage는 요청별 reach projection을 제공해야 한다.
M1-62: SQL ledger의 모든 계획 pair를 평가하며 attempt/물리 binding 누락은 해당 case unknown으로 남긴다.
빈 SQL ledger와 미할당 attempt/request/observation은 별도 incomplete gap이며 다른 유효 finding은 보존한다.
binding이 SQL 계획을 정의하지 않는다. SQL 미배정 reflection은 이 Oracle의 SQL 전용 ledger에 넣지 않는다.
M1-63: coverage는 SQL 신뢰 입력과 별도로 최대 1MiB/4,096행 snapshot·검증한다.
손상·중복·결측·다른 요청/snapshot의 coverage는 reach unknown+gap이며 SQL confirmed를 취소하지 않는다.
요청 귀속을 안전하게 읽을 수 없는 Proxy/getter/초과 입력은 coverage 전체를 unknown으로 낮추고 호출하지 않는다.

## M1-68 마커 발급과 Oracle 지원 제약

`issueMarkers`는 이미 검증한 SurfaceRef와 control/probe 예약만 받는다. GET query/path, POST JSON scalar 위치를 명시한다.
공유 admission 잔여 예산과 최대 2,000행을 모두 지키며 발급은 예산 소비·실제 송신·SQL 판정이 아니다.
입력은 전체 1MiB 안에서 행별 own snapshot으로 복사한다. native-sql은 실제 송신 직전 공유 admission을 다시 검사한다.
reproductionKey와 비밀이 아닌 seed는 논리 실행 입력이다. 같은 입력/ordinal은 예약 순서와 무관하게 같은 마커를 만든다.
8자 suffix는 1~32,768 ordinal의 고정 base32 표현이며 ledger 안의 원문/hash 충돌을 거부한다.
4자 prefix는 인증·전역 고유 ID가 아니다. 다른 물리 실행의 runNonce/PG lease/cursor 격리는 별도 pipeline 책임이다.
보고/단계 파일에는 ledger만 전달하고 원문은 trusted executor의 transient lookup으로만 읽는다. seed의 비밀 여부는 호출자가 보장한다.
HTTP 직렬화·snapshot·수집은 후속 native-sql 책임이며 발급기는 DTO·요청 계획을 추측하지 않는다.
SurfaceRef에는 scalar/mediaType 필드가 없으므로 RuntimeSurface의 JSON scalar 검증은 호출 전 조건이다.
M1-73: root와 단일 trailing slash는 허용하되 exact surface ID/path를 그대로 사용하며 `/x`와 `/x/`를 합치지 않는다.
CPx6 N3: control AST에 기존 BoolExpr가 있으면 현재 promotion 판정은 보수적으로 unknown이다. Oracle는 변경하지 않았다.
R8 두 예제 쌍의 취약/수정 GET·POST 원본을 읽어 공격 전 질의에 AND/OR가 없음을 대조했다. 실제 parser/DB 실행 증거는 아니다.

## M1-98 별도 parser protocol·worker

helper의 `PG_PARSER_PROTOCOL_REVISION`과 worker의 `PG_PARSER_WORKER_PROTOCOL_REVISION`은 `wakeio.pg-parser/v1`이다.
helper는 package/WASM을 import하지 않는 순수 요청·reply 검증/정규화 모듈이다. worker만 stdin EOF 후 package를 지연 import한다.
stdin은 단일 JSON 객체이며 revision·requestId SHA·parser pin·worker/manifest SHA·SQL·payload hash/UTF-8 삽입 span을 요구한다.
SQL 32KiB/전체 stdin 64KiB, JSON 깊이40/노드20,000을 넘거나 UTF-8/NUL/surrogate/span이 잘못되면 거부한다.
stdout은 1MiB 이하 projection/reason만 담는다. collector 전체 8MiB/4,096건과는 별도 한도다.
reply는 statement SHA/byte 수·pin·배포 SHA·AST 종류/관계/span·token 종류/역할/span/hash와 삽입 참조만 보존한다.
token.text·identifier/literal/comment/Bind 값·오류 excerpt/stack은 출력하지 않는다. hash 자체가 기밀성/출처 인증은 아니다.
위치는 C scanner의 UTF-8 byte slice와 token.text 일치·문자 경계로 검증하고 AST location은 같은 scanner 시작점에 대응시킨다.
지원은 단일 SELECT·단순 target/from·단일 식별자/문자열/ParamRef·동등 비교·AND/OR BoolExpr에 한정한다.
다른 AST·불명 위치·parser 예외/trap/재초기화는 unknown이다. quote 진단/PG 문자 위치 변환은 아직 주장하지 않는다.
outside token hash는 삽입과 겹치는 token을 제외한 kind/role/hash 목록으로 계산하며 두 context 필드에 같은 skeleton을 결속한다.
protocol ok/worker exit0은 정규화 성공일 뿐 confirmed/관측 완료가 아니다. 실제 parser 출력과 R8 판정 대조는 R9 후속이다.
R10은 worker TS를 독립 CJS `workers/pg-parser/pg-parser-worker.cjs`로 묶고 WASM·manifest를 인접 배치한다.
wrapper는 즉시 instantiate하므로 CJS glue의 `__dirname` 기반 로컬 `libpg-query.wasm` 로딩을 보존하고 main에 합치지 않는다.
worker는 고정 인접 JS/WASM/manifest raw SHA와 명시적 revision·parser18.2.1/PG18/승인 lock pin을 대조한 뒤 import한다.
TS source SHA는 build provenance일 뿐이며 설치본에서 TS/lock 원문을 읽지 않는다. manifest 신뢰/불변 설치는 R3 선행 조건이다.
R3가 network none·1초·256MiB·UID/caps/readonly/CPU/PID와 native stderr/core dump 차단을 외부에서 강제해야 한다.
worker는 한 작업 뒤 종료하며 trap의 비동기 재초기화를 재사용하지 않는다. 이 코드가 실제 격리/자원 준수를 입증하지는 않는다.
새 DB/container/log·runNonce/lease·seed 뒤 cursor·닫힌 직렬 window의 실행 간 혼합 거부 조건은 collector 후속 완료 조건으로 유지한다.

## M1-108 CPx8 N2: 개별 token hash의 수명

`PgParserReply.projection.tokenHashes`는 worker→trusted collector의 private 비교용 transient RAM에서만 허용한다.
worker stdout은 디스크로 중계하지 않는 private pipe로만 받고 stderr·진단·추적 도구에도 reply를 복사하지 않는다.
Stage·Observation·ledger·report·log·evidence·agent 입력·transcript·cache에 개별 tokenHashes를 저장하거나 출판하지 않는다.
control/probe 비교와 context hash 계산이 끝나면 원문 SQL·token.text 및 개별 literal token hash를 포함한 모든 tokenHashes 참조를 폐기한다.
참조 폐기는 메모리의 즉시 물리 소거를 보장한다는 뜻이 아니다. 프로세스 종료·dump 차단은 별도 격리 조건이다.
salt 없는 hash는 기밀성 수단이 아니며 낮은 엔트로피 literal은 사전 대입으로 복원될 수 있다.
허용된 statement/event/context 집계 hash도 비밀성이나 수집 출처 인증을 보장한다고 주장하지 않는다.
현재 `Observation.sql` 타입의 token projection은 종류/역할/span이며 `tokenHashes` 필드는 없음을 읽기 대조했다.
후속 collector writer는 Observation에 허용된 projection 필드만 명시적으로 선택하고 전체 PgParserReply의 object spread·저장을 금지한다.
완료 조건은 개별 tokenHashes가 저장·보고 출력에 없음을 확인하는 negative contract test와 R9의 전체 출력 경로 audit다.
이 문서는 writer 구현·폐기 검증 완료를 뜻하지 않는다. HMAC 대안은 미선택이며 새 키·비밀 salt를 도입하지 않는다.
현재 parser/Oracle/protocol·pin·manifest·배포 asset bytes와 SHA는 이 수명 정책 반영으로 변경하지 않는다.

## M1-118 managed PG jsonlog 형식 정규화

`parsePgJsonLogRecord`는 own byte snapshot 한 줄을 parsed/ignored/unknown으로 해석하는 data-only 함수다.
parsed는 형식 해석 성공이며 실제 수집·출처 인증·Observation·SQL 보안 판정·gate 성공을 뜻하지 않는다.
[PG18 JSON 표](https://www.postgresql.org/docs/18/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-JSONLOG)와
고정 [REL_18_0 jsonlog.c](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/utils/error/jsonlog.c)를 대조했다.
필드는 `file_name`·`func_name`·`file_line_num`이며 sourcefile/funcname을 별칭으로 추측하지 않는다.
trusted collector가 `log_error_verbosity=verbose`·`lc_messages=C`·server encoding UTF8와 기존 all/ERROR 설정을 확인해야 한다.
[lc_messages](https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-LC-MESSAGES)는 서버 환경 상속값에 의존하지 않는다.
메시지 prefix만 믿지 않고 `postgres.c`의 exec_simple_query/exec_execute_message와 client backend origin을 요구한다.
[postgres.c](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/tcop/postgres.c)의 statement/execute 기본 LOG만 지원한다.
RAISE LOG의 pl_exec.c/exec_stmt_raise·누락된 source 정보·duration/parse/bind/fetch 메시지는 parsed로 승격하지 않는다.
extended Execute의 `Parameters: ` detail은 순차 `$n = NULL` 또는 PG 로그용 따옴표 값으로만 해석하며 SQL로 재파싱하지 않는다.
[params.c](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/nodes/params.c)와
[quote emitter](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/utils/mb/stringinfo_mb.c)의 doubled quote를 대조했다.
`log_parameter_max_length=-1`을 전제로 하며 생략부호로 끝난 값·잘린 따옴표·128개 초과·locale 변형은 unknown이다.
현재 모든 ERROR/42601·internal query·PG 문자 위치 변환은 미지원이다. 오류 excerpt/위치를 추측해 parser 증거로 만들지 않는다.
record 64KiB(LF 포함)·SQL 32KiB, UTF8/NUL/surrogate·잘림/여러 줄·JSON 깊이40/노드20,000·shape 손상은 unknown이다.
유효한 비마커 사건은 원문과 hash 모두 남기지 않고 ignored다. 알 수 없는 JSON 필드는 bounded snapshot 뒤 버린다.
발급 lookup의 14byte 마커/hash를 확인해 statement/Bind 채널·session/line·사건/문장 digest만 공개 metadata로 반환한다.
SQL은 빈 frozen opaque handle의 private WeakMap에만 두고 trusted synchronous parser sink에서 한 번 소비하거나 명시적으로 폐기한다.
JSON/object spread에는 SQL·Bind/literal/query 원문·개별 tokenHashes가 없다. callback 실패도 닫힌 소비 상태만 반환한다.
collector는 모든 종료 경로에서 handle을 소비/폐기해야 하며 이 API는 즉시 물리 메모리 소거를 보장하지 않는다.
R3의 새 DB/container/log·runNonce/lease/cursor·설정/연속성·닫힌 물리 창·private 수집 capability 연결은 후속 완료 조건이다.
inline envelope 계약 테스트는 R8 기존 SQL 템플릿을 읽지만 PG 캡처·실행 증거나 새로운 보안 기대 판정이 아니다.

## M1-125 내부 native-sql 실행자

`runNativeSql`은 issuer가 만든 immutable ledger/lookup의 메모리 identity와 원래 exact method/path에 결속한다.
계획은 ready Surface의 같은 parameter/schema locator를 요구한다. GET query/form·단일 path/simple string을 지원한다.
POST는 application/json의 단일 root string leaf만 보낸다. 다른 body leaf·required sibling·배열/미지원 타입은 unknown이다.
중첩 JSON pointer는 현재 DTO가 부모 object의 required/조합 제약을 보존하지 않으므로 값을 추측하지 않고 unknown이다.
optional query string은 생략하며 header/cookie/body·다른 path의 값을 지어내지 않는다. 임의 JSON 속성도 추가하지 않는다.
benign은 marker, quote는 marker 뒤 작은따옴표, boolean은 기존 OR recipe이며 GET/POST가 같은 정책을 사용한다.
query는 raw scalar tuple, path는 한 segment의 엄격 percent encoding, JSON은 선언 leaf만 든 object를 request port에 준다.
requestHash는 이 결정적 DTO의 hash다. relay가 확정하는 실제 HTTP wire bytes의 측정 digest라고 주장하지 않는다.
CPx11 N4: 현재 DTO requestHash는 내부 실행 상관값으로만 사용하고 보고서의 증거 hash·재현 wire 증거로 출판하지 않는다.
R1/R3 canonical relay encoding·실제 측정 wire digest 결속과 대조 테스트/증거를 M1 GATE 전에 완료해야 한다.
그 연결 전에는 이 값을 보고서 증거로 전달하는 producer나 보고서 필드를 추가하지 않는다.
직접 socket/fetch/FS/process/모델을 열지 않고 trusted stdio RuntimeRequestPort만 호출한다. host origin/redirect/proxy 입력은 없다.
각 요청마다 trusted restore→begin→request→complete(drain·coverage)의 순서를 지키고 hook 실패 뒤 후속 송신을 중단한다.
hook은 실제 장벽 완료·logical ordinal/phase/markerHash/snapshotHash를 확인해야 하며 입력을 그대로 echo한 값은 증거가 아니다.
마커 logical ordinal과 공유 admission ordinal은 별개다. begin의 실제 allocation과 response ordinal을 대조하고 재사용을 거부한다.
모든 health/discover/control/probe를 포함한 cap/rate/deadline/abort의 실제 강제 권한은 공유 port에만 있다.
executor는 deadline을 min으로 줄이며 자체 시계·재시도·별도 예산을 만들지 않는다. 예약/장벽만으로 sent를 confirmed라 쓰지 않는다.
응답 body는 own bounded bytes의 hash/허용 metadata만 확인하고 복사본을 폐기한다. payload/body/응답/marker 원문을 반환하지 않는다.
AttackAttempt와 별도 delivery에 실제 sent·취소/손실·공유 ordinal·잘림을 보존하며 hook/response 손상은 unknown과 닫힌 gap이다.
현재 실제 R3 request/restore/관측/coverage hook 연결은 없다. hook은 RunContext의 lease/runNonce/cursor·abort/deadline을 강제해야 한다.
후속 R1/R3 계약에는 실제 wire digest와 logical/shared ordinal 배정·barrier 결속을 확정해야 한다. 기존 공유 type은 바꾸지 않았다.
소유 계약 테스트의 fake port 응답은 실행 증거·Oracle 판정·R8 보안 기대값이 아니다.
