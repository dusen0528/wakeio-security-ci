# M1 R8: Spring SQLi 고정 예제·독립 기대값 계획

기준 커밋: `a49da4ceebc2c7dd24020ecbce420f46d0ca7625`. TASK M1-03의 CP1 설계이며 실행 증거가 아니다.
실제 예제·기대값 파일은 CP1 승인 후 R8이 작성하고, 판정 구현자는 이를 수정하지 않는다.
PLAN 5·6·7·11·12장의 Spring/SQL 최소 경로를 검증한다. 14장의 권한·계정·워크플로는 M2 이후다.

## 1. 예제 경계와 버전 후보

두 버전은 같은 경로·시드·응답 스키마를 사용하고 SQL 작성 방식만 다르게 한다.
취약본은 입력을 SQL 문자열에 조립한다. 수정본은 동일 질의를 JDBC 바인딩으로 실행한다.
행 수·응답 차이는 보조 관측이며 SQLi 확정의 근거가 아니다. 외부 서비스나 실제 사용자 데이터는 없다.

| 요소 | CP1 후보 pin | 선택 이유·확인할 것 |
| --- | --- | --- |
| Java | source/bytecode 17 | R3가 실제 JDK 패치·이미지 digest·플랫폼 manifest를 확정한다. 부동 tag로 실행하지 않는다. |
| Maven | 3.9.16 | [공식 릴리스](https://maven.apache.org/docs/3.9.16/release-notes.html). 플러그인·의존성도 고정하며 Maven 버전만으로 재현성을 주장하지 않는다. |
| Spring Boot | 3.5.16 회귀 기준 후보 | [3.5 최종 OSS 릴리스](https://spring.io/blog/2026/06/25/spring-boot-3-5-16-available-now/). PLAN의 3.5 actuator 형식을 고정하는 용도다. 지원 종료 상태이므로 제품 권장 버전으로 소개하지 않는다. |
| PostgreSQL | 17.11 | [17.11 릴리스](https://www.postgresql.org/docs/17/release-17-11.html). 같은 major의 파서 문법과 로그 형식을 고정한다. 이미지 digest는 아직 측정하지 않았다. |
| pgJDBC | 42.7.14 | [공식 다운로드](https://jdbc.postgresql.org/download/). PreparedStatement와 파라미터 로깅 구분을 검증한다. |
| JaCoCo agent·CLI | 0.8.16 둘 다 | [공식 변경 이력](https://www.jacoco.org/jacoco/trunk/doc/changes.html). 서로 다른 버전이나 SNAPSHOT을 섞지 않는다. |

위 값은 최종 채택이 아니다. CP1에서 지원 중인 Spring 4.1 계열을 기본 예제로 선택하는 대안과 비교한다.
3.5를 택하면 회귀 코퍼스 버전임을 명시하고, 4.1을 택하면 mappings/OpenAPI 원본을 다시 독립 검토한다.
springdoc, Maven plugin, JDK 이미지의 정확한 버전·digest는 R3/R4와 CP1에서 정한 뒤 manifest에 기록한다.
취약/수정본에 같은 의존성 pin을 적용해 프레임워크 버전 차이가 판정을 대신하지 않게 한다.

선언 라이선스의 출처는 [Spring Boot Apache-2.0](https://github.com/spring-projects/spring-boot/blob/v3.5.7/LICENSE.txt),
[Maven Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0.html),
[PostgreSQL License](https://www.postgresql.org/about/licence/),
[pgJDBC BSD-2-Clause](https://github.com/pgjdbc/pgjdbc),
[JaCoCo EPL-2.0](https://www.jacoco.org/jacoco/trunk/doc/license.html)이다.
실제 배포할 고정 artifact의 LICENSE/NOTICE와 SHA256을 R9가 대조한다. 라이선스 호환성의 법률 판단을 대신하지 않는다.

## 2. 애플리케이션·라우트 ground truth

주 예제는 `JdbcTemplate` 문자열 질의와 바인딩 오버로드의 쌍이다.
PLAN 11장의 Pack 검증에 맞춰 작은 두 번째 마이크로서비스도 계획한다.
두 번째는 직접 `Statement`와 `PreparedStatement`의 쌍이며 동일 SQLi를 재현한다.
두 서비스에 같은 Spring Pack을 사용하고, 서비스에 따라 Oracle나 엔진 코드를 바꾸지 않는다.

| 선언 메서드·경로 | 입력·동작 | 공격/커버리지 기대 |
| --- | --- | --- |
| GET `/api/items/search` | query `name`; SQL equality search | 무해·구문 승격·quote 오류 세 입력. 해당 handler의 실행 줄이 covered여야 한다. |
| POST `/api/items/search` | JSON `name`; GET과 별도 handler | GET과 같은 바인딩/구문 판정. POST handler와 입력 위치가 별도로 매핑된다. |
| GET `/api/items/safe-search` | query 문자열 `name`; 항상 바인딩 | 안전 대조 라우트. 무해 marker도 정상 수용하고 covered, 모든 공격에서 confirmed 0. |
| GET `/api/ping` | SQL을 호출하지 않는 고정 응답 | 안전 음성 사이트. marker 반사가 있더라도 SQL confirmed 0. |
| GET `/api/untouched` | 입력 없는 독립 handler | 발견 목록에는 남기되 공격 작업은 배정하지 않는다. handler 본문은 uncovered여야 한다. |

`/actuator/health`, `/actuator/mappings`, `/v3/api-docs`는 준비·발견용 경로로 별도 표시한다.
업무 라우트 recall 분모에 섞지 않는다. MVC의 암묵적 HEAD/OPTIONS와 명시 선언 메서드도 구분한다.
동일한 GET/POST 선언을 actuator와 springdoc 양쪽에서 얻으면 provenance 둘을 보존하고 중복 라우트로 세지 않는다.
source-file/class/method/시그니처를 ground truth에 적고, Java source SHA와 bytecode SHA를 함께 고정한다.
실제 line 범위는 CP1 후 예제 소스를 작성한 R8이 정한다. 지금 가상의 줄 번호를 만들지 않는다.

## 3. SQL·관측 프로토콜

단순 질의 모양은 `SELECT id,name FROM items WHERE name = '<입력>'`이다.
수정본은 `WHERE name = ?`와 바인딩 API를 사용한다. 안전 문자열 리터럴·comment 사례는 별도 단위 입력이다.
[pgJDBC 문서](https://jdbc.postgresql.org/documentation/query/)처럼 query 텍스트와 bound value를 구별한다.
서버 로그에서 placeholder가 `$1`로 보이는 것을 입력이 SQL 문법이 됐다는 증거로 취급하지 않는다.

PostgreSQL은 `log_statement=all`만으로 단순 구문 오류를 전부 기록하지 않는다.
따라서 소유 fixture DB에 `log_min_error_statement=ERROR`도 설정해야 한다.
실행된 statement와 Bind parameter는 서로 다른 역할로 읽는다.
이 구분은 [공식 logging 문서](https://www.postgresql.org/docs/17/runtime-config-logging.html)에 근거한다.
bind 로그 길이 설정·로그 포맷은 R5와 계약화하고, 잘린 값은 완전한 관측으로 쓰지 않는다.

모든 case는 발급된 marker, run/ledger hash, route, parameter 위치, payload 종류, request 번호에 결속한다.
각 공격 앞에 같은 라우트의 무해 marker 대조 요청을 둔다. control 실패나 미관측이면 판정은 unknown이다.
DB 역할은 소유 fixture schema의 SELECT만 허용한다. DROP·외부 파일·확장·sleep·stacked query는 사용하지 않는다.
Oracle 단위 fixture는 합성 statement/parameter/error 필드이며 앱 원문 응답·계정 비밀값은 포함하지 않는다.
실제 DB 로그는 임시 관측 입력일 뿐이다. 비마커 행은 버리고, 보존할 자료는 가린 excerpt와 hash로 제한한다.

## 4. 독립 기대 매트릭스

`m`은 case마다 발급된 marker를 뜻한다. 표의 입력은 형태 설명이며 실제 marker·원문은 CP1 후 R8이 고정한다.
confirmed 수와 이유를 먼저 동결한다. 런타임 계약의 필드명은 R1과 맞추되 기대 판정을 구현에 맞춰 바꾸지 않는다.

| ID | 입력/관측 | 기대 판정·반증 조건 |
| --- | --- | --- |
| V1 | 취약 GET, `m' OR 'm'='m`, 성공 control, 해당 SQL AST에 리터럴 밖 OR/비교 구문 | confirmed 1. marker 문자열 포함만으로는 통과하지 못한다. |
| V2 | 취약 POST JSON, V1과 같은 질의·control | confirmed 1; route/JSON field 매핑이 GET과 섞이면 실패. |
| V3 | 취약 GET, `m'`, 정상 control, 같은 statement의 quote 불균형 진단·SQLSTATE 42601 | confirmed 1. 해당 payload/statement/오류 결속이 없으면 unknown. |
| F1 | 수정 GET, V1/V3 payload가 Bind parameter에만 있음 | confirmed 0, strong 0. 바인딩 문자열을 SQL로 재파싱하면 실패. |
| F2 | 수정 POST, 같은 payload가 Bind parameter에만 있음 | confirmed 0, strong 0; 정상 완료한 관측은 unknown으로 숨기지 않는다. |
| N1 | 무해 `m`이 취약본 SQL의 하나의 문자열 리터럴에만 있음 | confirmed 0. PLAN의 strong 관측과 문법 승격은 구분한다. |
| N2 | quote를 올바르게 escape한 `m' OR ...` 전체가 하나의 리터럴 AST 노드 | confirmed 0. text에 OR/quote가 있다는 이유로 확정하면 실패. |
| N3 | marker와 OR 형태가 SQL comment 안에만 있음 | confirmed 0. comment를 실행 구문으로 취급하면 실패. |
| N4 | 안전 `/api/items/safe-search`의 바인딩과 `/api/ping`의 반사 응답 | confirmed 0. HTTP 200/500·반사만으로 확정 불가. |
| N5 | 공격 응답에만 가짜 SQL 오류 문자열이 있고 DB 관측은 없음 | unknown, confirmed 0. 응답 문자열을 DB 증거로 승격하지 않는다. |
| N6 | 42601이지만 control도 같은 오류이거나 다른 statement/marker의 오류 | unknown, confirmed 0. SQLSTATE 하나만으로 확정하면 실패. |
| N7 | Observer 미부착·로그 중단·marker event 누락·관측 timeout | unknown, confirmed 0; clean/안전으로 출력하면 실패. |
| N8 | 관측이 잘림·dialect/parser 불일치·파서 오류이며 V3의 결속된 quote 진단도 없음 | unknown, confirmed 0. 파싱 실패 전부를 SQLi로 확정하면 실패. |
| N9 | control 미발급·실패·누락, 공격 statement만 있음 | unknown, confirmed 0. 대조군 없는 확정 금지. |
| N10 | 예전 run의 marker·미발급 marker·다른 route의 event가 섞임 | 버림/불완전, confirmed 0; 현재 case에 전용하면 실패. |
| N11 | 비마커 statement에 합성 secret canary만 있음 | 저장 사건 0; 보고서/DB/증거에 원문 canary 0. |
| N12 | 관측 전 취소·DB 정지·health 실패 | unknown/미완료, exit 2; 기존 데이터로 clean을 만들면 실패. |
| N13 | 한 라우트 confirmed 후 다른 관측·커버리지 실패 | confirmed 유지, 나머지 unknown, exit 1; 누락을 숨기거나 발견을 덮지 않는다. |

N1/N2의 unbound statement marker는 PLAN의 strong 기준에 해당할 수 있다.
따라서 이 두 사례는 confirmed 음성 대조이며 모든 등급이 0이라는 요구로 바꾸지 않는다.
수정본 F1/F2는 실제 바인딩 경로이므로 strong도 0으로 고정한다.
V3는 실제 DB 구문 오류를 사용한다. 일반 parser 예외나 임의 quote 개수 비교로 기대값을 대체하지 않는다.

## 5. 커버리지·재현성·시드

- 시드는 고정된 세 item 행과 무해한 이름만 둔다. 매 공격 전에 동일 schema/data snapshot으로 복원한다.
- 요청 전에 JaCoCo dump/reset, 요청 후 dump/reset을 수행해 이전 요청의 누적 covered를 전용하지 않는다.
- 요청한 handler 본문의 instruction/line은 증가하고, `/api/untouched` 본문은 두 번 모두 uncovered여야 한다.
- DB 경계 증거와 코드 coverage를 각각 기록한다. coverage 누락이 SQL confirmed를 지우거나 안전을 증명하지 않는다.
- raw JaCoCo 파일의 session/time 정보와 판정 비교용 정규화된 라인 집합을 구별한다.
- 같은 소스·pin·seed·예산으로 두 fresh run을 돌려 정렬한 Verdict 집합과 marker→작업 매핑이 같아야 한다.
- 실행별 식별자·소요 시간·리소스 이름은 별도 기록하고, run 간 로그를 서로 재사용하지 않는다.
- marker 충돌 0, 발급 수=계획된 payload 수, 요청 예산·실제 wire request ledger 일치를 검사한다.
- 같은 variant의 소스를 두 번 빌드해 jar/image digest를 대조한다. 취약본과 수정본의 digest가 같은 것을 요구하지 않는다.
- digest가 다르면 timestamp/base/platform 등 차이를 기록한다. 이유 없는 차이를 재현 성공으로 세지 않는다.

## 6. CP1 후 R8 파일·R9 검증 계획

| R8 작성 예정 경로 | 내용 |
| --- | --- |
| `examples/runtime/spring-sqli/{vulnerable,fixed}/` | JdbcTemplate 쌍의 Maven·Java·설정·Dockerfile·제한 compose·target 초안 |
| `examples/runtime/spring-sqli-jdbc/{vulnerable,fixed}/` | 같은 Pack을 쓰는 작은 Statement/PreparedStatement 쌍 |
| `examples/runtime/spring-sqli/shared/` | 고정 schema/seed, ground-truth, pin manifest, payload/case manifest |
| `examples/runtime/spring-sqli/oracle-cases/` | 위 표의 합성 입력·독립 기대 Verdict/unknown/confirmed 수 |
| `benchmarks/runtime-corpus.json` | case ID·fixture tree/seed/expectation/Pack/image digest, 재현 인자 |

초기 구현 패킷은 주 쌍→순수 관측 매트릭스→두 번째 쌍으로 나눠 각 500줄 이내를 제안한다.
필드나 pin 변경이 필요하면 이유와 영향 case를 적어 오케스트레이터 승인을 받은 뒤 다음 리뷰에 남긴다.
R5/R6은 이 파일을 읽기만 한다. 검증 결과·관측 로그·KPI 파일은 R9만 작성한다.

R9는 승인된 `verify --target <owned-fixture> --execute-target-consent --out <fresh>` 경로로만 실행한다.
주 쌍과 두 번째 쌍에서 V1~V3 양성 및 모든 수정/안전 confirmed 0, SQL 바인딩 구분을 검증한다.
observer 중단·취소·제한 초과·consent 부재의 실패 경로도 실행하며 source snapshot 변조를 확인한다.
같은 검증을 동일 저장소 PR/push의 `contents: read` runtime CI에 붙이고 fork/`pull_request_target`을 거부한다.
매 run 뒤 소유 label로 생성한 컨테이너·네트워크·볼륨이 0인지 별도 조회한다. 정리 미확인은 error다.
secret canary는 모든 보고서·agent JSON·관측 파일·logs·archive 내부까지 검색해 원문 0을 확인한다.
KPI는 예제별 confirmed 정확도/음성 오판 수, 업무 라우트 recall/도달률, 전체 시간·요청 수를 분리한다.
없는 관측·분모를 0점/100%로 채우지 않고 unknown으로 남긴다. 기존 compat-0.5와 offline KPI도 그대로 통과해야 한다.

## 7. CP1에서 확정할 사항

Spring 3.5 회귀 기준과 지원 중인 4.1 기준 중 선택, springdoc/JDK/컨테이너 digest 최종 pin은 R3/R4와 정한다.
SQL parser·dialect 버전·구문 위치 필드 계약은 R1/R5가 제안하되 위 반증 매트릭스는 약화하지 않는다.
Snapshot 단위·coverage dump 경계·마커 재현성의 정확한 필드 계약은 R1과 맞춘다.
새 공개 스키마에 맞춰 기대값의 모양을 바꿀 때도 의미·case ID·판정 수와 변경 이유를 별도 보존한다.
