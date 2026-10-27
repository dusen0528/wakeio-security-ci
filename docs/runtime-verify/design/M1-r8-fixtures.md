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
| Java | source/bytecode 21 | [Boot 4.1.2 요구 범위](https://docs.spring.io/spring-boot/system-requirements.html)에 포함된다. 실제 JDK 패치·OCI 플랫폼 digest는 R3/R9 확인 전 미확정이다. |
| Maven | 3.10.0 | [공식 릴리스](https://maven.apache.org/docs/3.10.0/release-notes.html). R3 후보에 맞추고 플러그인·의존성도 고정한다. |
| Spring Boot | 4.1.2 기본 후보 | [공식 stable 문서](https://docs.spring.io/spring-boot/system-requirements.html). 지원 중인 계열로 새 예제를 만들고 실제 mappings 원본은 후속 검증한다. |
| springdoc | 3.2.0 | [공식 matrix](https://springdoc.org/#what-is-the-compatibility-matrix-of-springdoc-openapi-with-spring-boot)의 Boot 4.1.x/3.1.x~3.2.x 범위이며 R4 추천과 같다. |
| PostgreSQL | 18 major, 정확한 patch 미확정 | [PG18 문서](https://www.postgresql.org/docs/18/index.html). DB/parser major를 맞추되 이미지 존재·플랫폼 digest를 실측했다고 쓰지 않는다. |
| SQL parser/helper | `libpg-query@18.2.1` | [공식 package](https://github.com/constructive-io/libpg-query-node/blob/main/versions/18/package.json)와 [scan API](https://github.com/constructive-io/libpg-query-node/blob/main/versions/18/SCAN.md). R5의 PG18 parse/scan 추천이며 wrapper는 MIT 선언이다. |
| pgJDBC | 42.7.14 | [공식 다운로드](https://jdbc.postgresql.org/download/). PreparedStatement와 파라미터 로깅 구분을 검증한다. |
| JaCoCo agent·CLI | 0.8.16 둘 다 | [공식 변경 이력](https://www.jacoco.org/jacoco/trunk/doc/changes.html). 서로 다른 버전이나 SNAPSHOT을 섞지 않는다. |

M1 기본 추천은 Spring4.1.2/springdoc3.2.0, JDK21/Maven3.10.0/JaCoCo0.8.16, PG18/parser18.2.1 조합이다.
공식 버전·호환 범위 검토에 따른 CP1 제안이며 빌드·실행·digest 실측 완료를 뜻하지 않는다.
기존 Spring3.5.16/PG17.11 후보는 PLAN의 3.5 mappings 재현·기존 문법 회귀에 유리하지만 [3.5 OSS 지원은 종료됐다](https://spring.io/blog/2026/06/25/spring-boot-3-5-16-available-now/).
또 R5가 필요한 token scan까지 갖춘 PG18 wrapper와 major가 달라 기본 조합으로 추천하지 않는다.
정확한 PG18 patch·JDK 패치·OCI 플랫폼 digest·npm integrity/transitive lock·WASM SHA·라이선스 파일은 R3/R9 후속 실측 전 미확정이다.
Maven plugin pin과 실제 mappings/OpenAPI 원본도 R3/R4와 CP1에서 정한 뒤 manifest에 기록한다.
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
| N4 | 안전 `/api/items/safe-search`의 바인딩과 `/api/ping`의 반사 응답 | 두 경로 모두 SQL confirmed 0, strong 0. HTTP 200/500·반사만으로 SQL 증거 등급을 승격하지 않는다. |
| N5 | 공격 응답에만 가짜 SQL 오류 문자열이 있고 DB 관측은 없음 | unknown, confirmed 0. 응답 문자열을 DB 증거로 승격하지 않는다. |
| N6 | 42601이지만 control도 같은 오류이거나 다른 statement/marker의 오류 | unknown, confirmed 0. SQLSTATE 하나만으로 확정하면 실패. |
| N7 | Observer 미부착·로그 중단·marker event 누락·관측 timeout | unknown, confirmed 0; clean/안전으로 출력하면 실패. |
| N8 | 관측이 잘림·dialect/parser 불일치·파서 오류이며 V3의 결속된 quote 진단도 없음 | unknown, confirmed 0. 파싱 실패 전부를 SQLi로 확정하면 실패. |
| N9 | control 미발급·실패·누락, 공격 statement만 있음 | unknown, confirmed 0. 대조군 없는 확정 금지. |
| N10 | 예전 run의 marker·미발급 marker·다른 route의 event가 섞임 | 버림/불완전, confirmed 0; 현재 case에 전용하면 실패. |
| N11 | 비마커 statement에 합성 secret canary만 있음 | 저장 사건 0; 보고서/DB/증거에 원문 canary 0. |
| N12 | 관측 전 취소·DB 정지·health 실패 | unknown/미완료, exit 2; 기존 데이터로 clean을 만들면 실패. |
| N13 | 한 라우트 confirmed 후 다른 관측·커버리지 실패 | confirmed 유지, 나머지 unknown, exit 1; 누락을 숨기거나 발견을 덮지 않는다. |

전체 `verify`는 기본 `--fail-on-grade strong`에서 다음을 기대한다(필수 관측·정리·출판 완료 시).

| 독립 쌍 | 취약 variant 전체 | 수정 variant 전체 | 안전 대조만 계획한 실행 |
| --- | --- | --- | --- |
| 주 JdbcTemplate 쌍 | V1~V3 confirmed, exit 1 | F1/F2 confirmed 0·strong 0, exit 0 | N4 SQL confirmed 0·strong 0, exit 0 |
| 두 번째 Statement/PreparedStatement 쌍 | V1~V3 confirmed, exit 1 | F1/F2 confirmed 0·strong 0, exit 0 | N4 SQL confirmed 0·strong 0, exit 0 |

기준 이상 finding 없이 관측·커버리지·cleanup 등 실패만 있으면 exit 2, finding+실패면 exit 1로 N12/N13을 유지한다.

N1/N2의 unbound statement marker는 PLAN의 strong 기준에 해당할 수 있다.
따라서 이 두 사례는 confirmed 음성 대조이며 모든 등급이 0이라는 요구로 바꾸지 않는다.
수정본 F1/F2는 실제 바인딩 경로이므로 strong도 0으로 고정한다.
V3는 실제 DB 구문 오류를 사용한다. 일반 parser 예외나 임의 quote 개수 비교로 기대값을 대체하지 않는다.

## 5. 커버리지·재현성·시드

- 시드는 고정된 세 item 행과 무해한 이름만 둔다. R1 §1·4의 `snapshot: per-request`로 control/probe 각각 직전에 동일 schema/data snapshot을 복원한다.
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

신규 파일·테스트의 유일한 권위 목록은 `M1-r1-contracts.md` §7이다. 이 절은 별도의 파일 목록을 정의하지 않는다.
R8 쓰기 범위는 그 목록의 `examples/runtime/{spring-sqli,spring-sqli-jdbc}/**`, `benchmarks/runtime-corpus.json`, `tests/fixtures/runtime-m1/**`다.
두 취약/수정 쌍의 schema/seed·pin manifest·ground truth·payload/case와 위 독립 기대값의 작성·변경 소유권은 R8에 유지한다.

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

위 기본 조합을 CP1에 추천하고, 실행 전 정확한 PG18 patch·artifact/platform digest와 라이선스 파일을 확인한다.
R1/R5의 격리 parser helper는 AST/token projection으로 입력 shape를 바꿀 수 있으나 R8의 독립 기대값 소유권은 유지한다.
버전·projection 선택으로 V1~V3/F/N 판정 수·승격 강도·GET/POST ground truth를 약화하지 않는다.
`per-request` snapshot·coverage dump 경계·마커 재현성의 정확한 필드 계약은 R1과 맞춘다.
새 공개 스키마에 맞춰 기대값의 모양을 바꿀 때도 의미·case ID·판정 수와 변경 이유를 별도 보존한다.

## 8. M1-109: 정확한 JVM 이미지 후보 제안

2026-10-28 메타데이터 조회로 §1의 Maven3.10.0/JDK21 후보를 아래처럼 좁힌다.
[Maven 공식 다운로드](https://maven.apache.org/download.cgi)와
[3.10.0 릴리스](https://maven.apache.org/docs/3.10.0/release-notes.html)에 정식 배포가 있다.
공식 이미지도 존재하므로 Maven 버전을 낮추거나 별도 binary 설치 경로를 추가할 이유가 없다.

- 빌드 후보: `docker.io/library/maven:3.10.0-eclipse-temurin-21-noble`.
  [Docker 공식 Maven 명부](https://raw.githubusercontent.com/docker-library/official-images/master/library/maven)에
  정확히 이 tag와 amd64/arm64v8가 있다. source commit은 `4bcc1dea6507fba8ec40c602bf1bfdb963e21288`이다.
- 실행 JDK 후보: `docker.io/library/eclipse-temurin:21.0.12.1_1-jdk-noble`.
  [공식 Temurin 명부](https://raw.githubusercontent.com/docker-library/official-images/master/library/eclipse-temurin)에
  정확한 patch/build tag와 amd64/arm64v8가 있다. source commit은 `511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07`이다.
- Noble은 R9가 별도로 조사한 Ubuntu24.04 Docker 자산과 OS 계열을 맞추는 최소 변경 후보다.
  `latest`, `3`, `21-jdk-noble` 같은 tag를 최종 pin으로 삼지 않는다. 위 tag도 재게시될 수 있다.

공식 명부가 가리키는 Maven `eclipse-temurin-21-noble/Dockerfile`은 3.10.0 Maven stage와
`eclipse-temurin:21-jdk-noble` base를 사용한다. 그 source의 major tag만으로 JDK patch를 단정하지 않았다.
익명 Registry API로 읽은 OCI index→linux child manifest→config의 원시 SHA256을 대조했다.
네 config 모두 `JAVA_VERSION=jdk-21.0.12.1+1`, `JAVA_HOME=/opt/java/openjdk`이고 OS/architecture가 일치했다.
Maven config에는 `MAVEN_HOME=/usr/share/maven`이 있지만 `MAVEN_VERSION`은 없었다.
따라서 Maven3.10.0은 tag/공식 build 정의의 제안이며 실제 binary 버전 실행 확인은 아니다.

후속 R9 독립 대조용 index 후보:

- Maven: `sha256:2060a0028047a1974e7e0e343f93b7d2742db8cce69cb5662cf2a9a09b17dbca`
- Temurin: `sha256:57424b1d8eca9c4cf8a4fe226207027911f08d6758628891bf59fcfb53777029`

| 후보 | platform | metadata | 관측 SHA256 digest |
| --- | --- | --- | --- |
| Maven | linux/amd64 | manifest | `sha256:3e598b8b4680fa5ec51f9661fe278901cde75af841116f9f03956601c92a778f` |
| Maven | linux/amd64 | config | `sha256:6dae7ba6ab719b3627206c755e24c411d1c281a12b1acb3d53515051cd7dbf98` |
| Maven | linux/arm64 | manifest | `sha256:65cedfb84cfbb1dc9974c14662d6bf9b20aa6aea274c877fe08952bdfae7992f` |
| Maven | linux/arm64 | config | `sha256:fe1f0cef06dadb4b4e7b613be22c806414f48f3357c9728e659f7bc0baab7326` |
| Temurin | linux/amd64 | manifest | `sha256:8b3b108b98b06013f1fb7105745b4ab128f6bdce7759206d3fa8ef9fc58e4d90` |
| Temurin | linux/amd64 | config | `sha256:850a79a648b155cc2802ac214a109f2707418645a2f1eb16b227a3f22687b672` |
| Temurin | linux/arm64 | manifest | `sha256:47d408e3a08b4e0cf7e966e891491a8a886a49ca8c0d2f79f1d3a22995ba1ecf` |
| Temurin | linux/arm64 | config | `sha256:65c7de6113db9872bf81fd68e5328bfc73d71f61d610b1e277d4b89bb90f5aa4` |

index/child는 header·descriptor·원시 SHA가 일치했다. config는 descriptor·원시 SHA가 일치했지만
응답에 digest header는 없었다. layer digest는 선언만 읽었고 layer 다운로드·pull·실행은 0이다.
R8은 raw JSON·익명 bearer를 저장하지 않았다. bearer는 프로세스 메모리 밖으로 전달하지 않았다.
이 표는 R8의 조회 시점 제안이며 R9의 독립 byte 대조·최종 pin 승인·서명 검증을 대신하지 않는다.

[R9 JVM 자산 감사](../../../.handoff/evidence/M1/jvm-assets/README.md)의 PG18.6 OCI metadata와
JaCoCo0.8.16 runtime agent SHA256 `37ae2f374ad77e85c59c6e5b46565226c3ac3cb460ac19de0bcb844ac2f43e33`은
각각 별도 근거다. agent는 공개 SHA1과 대조됐지만 공개 SHA256 sidecar/서명·CLI JAR은 미확인이다.
[Docker 자산 감사](../../../.handoff/evidence/M1/docker-assets/README.md)도 정적 자산 검사이며 guest 설치 증명이 아니다.
guest JDK/Maven 실행, 실제 이미지 layer/rootfs, 소유 예제 빌드·JAR 재현·SQL/격리 게이트는 아직 미검증이다.

root 승인과 R9의 두 플랫폼 metadata·asset bytes 독립 확인 뒤에만 최종 platform digest를 선택한다.
그 뒤 별도 R8 Dockerfile/compose·pin 반영 패킷이 필요하다. 현재 예제·Java/Oracle·기대값·pin lock은 바꾸지 않는다.
