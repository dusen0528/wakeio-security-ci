# M1 R4: Spring 표면 발견과 Pack — CP1 제안

기준 `a49da4ceebc2c7dd24020ecbce420f46d0ca7625`. 설계만 작성하며 구현·실측 완료를 주장하지 않는다.
PLAN 4·5·10·11·12·13·14.4, HANDOFF, SUBAGENTS와 R1의 구체 계약 제안을 따른다.

## 1. 발견 계약과 v1 보존

- 신규 `src/runtime/surfaces/{openapi,spring-actuator,inventory,refs}.ts`에 순수 열거/병합을 둔다.
  fetch는 검증된 RunContext transport를 주입받는다. 소스별 provenance와 readiness는 별개다.
- `src/init-dast.ts`의 기존 진입점·GET-only `enumerateOpenApiGetOperations`·v1 출력/종료 코드는 그대로 둔다.
  필요하면 명시적 v2 함수만 추가한다. 기존 실행용 OpenAPI 선택기·참조 검증을 넓히지 않는다.
- `id = sha256(JSON.stringify(['wakeio.surface/v2', method, pathTemplate]))`를 제안한다.
  method는 대문자 HTTP token, 경로 대소문자·후행 slash·별칭은 보존한다. operationId는 정체성이 아니다.
- method/path가 같은 행의 provenance를 합쳐 정렬한다. 각 출처에는 provider, 원본 byte digest,
  마스킹 artifact ref, JSON pointer locator를 결속한다. 서로 다른 조건/파라미터는 조용히 덮어쓰지 않는다.
- 알려진 선언 수·병합된 고유 라우트 수·미해결 수를 구분한다. 미해결이 있으면 전체 분모는 null이다.
  빈 결과는 안전/완전 발견을 뜻하지 않는다. source-routes는 수행 전까지 unverified다.

## 2. OpenAPI v2 경로

- M1 제안 지원은 OpenAPI 3.0/3.1 JSON이다. get/put/post/delete/options/head/patch/trace를 모두 보존한다.
  지원 밖 버전/메서드는 명시적 gap이며 GET으로 치환하거나 배열에서 조용히 버리지 않는다.
- 문서의 servers·외부 문서·callback URL은 요청 목적지를 결정하지 않는다. 소유 origin만 RunContext에서 온다.
- path-item/parameter/requestBody/schema의 같은 문서 `#/...`만 해석한다. 경로와 operation의 parameters는
  `(in,name)`으로 병합하며 operation 정의가 우선이다. 각 배열의 중복 정의는 거부한다.
- query/path/header/cookie는 이름·필수 여부·단순 타입·직렬화 규칙을 기록한다. body는 mediaType,
  JSON pointer·필수 여부·스키마 locator를 보존한다. examples/default/실제 값·자격 증명은 출력하지 않는다.
- M1 준비 가능한 scalar query/path와 선언된 JSON body 입력은 공격 계획 작성에 넘기고, 배열/조합 스키마,
  multipart·인증·타입/직렬화 불명은 라우트를 남긴 채 readiness unresolved로 기록한다.
  발견된 POST 등과 실제 공격한 메서드를 구분한다. 공격 정책이 지원하지 않는 메서드는 미검사 사유를 낸다.
- 외부/다른 파일 ref는 fetch하지 않고 external_ref_blocked, 순환·미해결·모호한 siblings는 고정 gap이다.
  참조를 재귀 복제하지 않고 방문 집합·memo로 처리한다. 경로별 부분 결과를 남기되 hard limit은 error다.
- 기존 상한을 낮추지 않고 재사용한다: 입력 1MiB, 20,000노드, 깊이40, paths1,000, ref256, params32/route.
  추가 제안: body leaf32/route, 모든 provider 합계1,000 routes. 한도 초과를 잘라서 complete로 만들지 않는다.

## 3. actuator와 handler 근거

- Pack의 경로에서 구조화된 contexts/mappings/dispatcherServlets 또는 dispatcherHandlers만 읽는다.
  requestMappingConditions의 methods×patterns를 열거하고 predicate 문자열을 임의로 파싱하지 않는다.
- 빈 methods·와일드카드·정규식/동적 경로·구조가 없는 functional mapping은 unresolved gap이다.
  mapping 조건의 params/headers는 제약 정보이지 함수의 모든 입력 스키마나 성공 요청 증거가 아니다.
- handlerMethod의 className/name/descriptor는 핸들러 식별 근거다. 이를 Java 파일/줄 번호로 추측하지 않는다.
  R3의 실제 class/JaCoCo/source manifest 매핑이 확인된 경우만 R1의 handler.path/line을 채운다.
- OpenAPI에만 있는 라우트는 declared, actuator와 일치하는 라우트도 mapped로만 주장한다.
  두 출처의 body/type/조건 충돌·누락은 readiness unresolved이며 권한·도달·covered를 의미하지 않는다.

## 4. 요청·증거 경계

- 동의 뒤 R3가 만든 대상의 고정 origin 및 Pack에 선언된 내부 discovery 경로만 요청한다.
  사용자 외부 URL, DNS 재결정, origin 변경, redirect 추종은 금지한다. 외부 ref도 요청 0회다.
- discovery도 공통 요청 cap/deadline/cancellation에 산입한다. 제안: 5초/요청, 응답1MiB, JSON 구조 한도 동일.
  잘린 응답·비정상 압축·실패/401/404·종료 전 drain 실패는 provider partial/error와 gap으로 남긴다.
- raw 응답을 영속 저장하지 않는다. transient 원본 digest와 식별/타입/locator만 남긴 구조 artifact를 결속한다.
  원본 hash를 저장했다고 원문을 독립 재검증할 수 있다고 주장하지 않는다. 임의 endpoint 이름도 비공개 취급한다.

## 5. Spring Pack 데이터와 소유 경로

- `packs/spring-boot.v1.yml`은 version/id, languages, detect, runtime, surfaces, sources, sinks, sanitizers 데이터다.
  YAML은 중복 키·tag·alias·merge·보간을 거부하고 `schemas/framework-pack.v1.json`으로 검증한다.
  사용자 Pack도 동일 스키마·bounded 정규화·새 파일 출판 규칙을 따르며 모듈/명령/함수를 로딩하지 않는다.
- detect의 pom/build.gradle 문자열, JVM profile, 기본 port/health, actuator/OpenAPI 경로,
  Spring annotation/call과 sink 인자 위치는 Pack 데이터에만 둔다. 신규 framework별 TS if 분기는 만들지 않는다.
- raw Pack SHA·정규화 SHA·schema/compiler/engine 버전을 결과와 분석 artifact에 결속한다.
- R1에 generic `src/runtime/packs/{schema,compile-opengrep}.ts`와 신규 runtime Analyzer 등록을 공유 변경 요청한다.
  params에는 mediaType/JSON pointer/직렬화/schema locator, provenance에는 raw digest와 저장 artifact ref의 구분이 필요하다.
  Pack id는 검증된 데이터 식별자이며 특정 framework literal이나 모듈 경로 분기로 확장성을 제한하지 않는다.
  R4는 Spring Pack 데이터와 discovery만, R3는 신뢰 도구 실행/격리, R8은 독립 예제·기대값, R9는 검증을 맡는다.
  M1에서 R2나 기존 scan/Analyzer v1에 변경을 요구하지 않는다. 경로 소유 승인은 오케스트레이터가 별도 발행한다.
- compiler는 허용된 annotation/call/arg DSL을 `mode: taint`의 source/sink/sanitizer 규칙으로 변환한다.
  sanitize는 placeholder가 확인된 bound 인자만 보호하며, JdbcTemplate 인자가 2개라는 이유로
  동적으로 조립한 SQL arg0까지 안전 처리하지 않는다. 미지원 DSL은 거부하고 조용히 규칙을 누락하지 않는다.
  taint finding은 candidate이며 SQL Oracle confirmed나 runtime reach를 대신하지 않는다.

## 6. CP1 선택과 독립 검증

- Spring 3.5.16은 PLAN 링크의 재현 기준 후보, 공식 최신 stable 4.1.2+springdoc3.2.0은 신규 예제 추천 후보다.
  springdoc 공식 matrix는 Boot4.1.x에3.1.x~3.2.x를 제시한다. 선택·JDK/image digest는 R8/R3와 CP1에서 확정한다.
- R8 ground truth의 정확한 method/path/param/handler 집합과 비교해 recall·중복·unexpected·정렬 재현을 검증한다.
  actuator-only/OpenAPI-only/혼합·모든 메서드·로컬 alias·순환/원격/폭증·파라미터 충돌을 별도로 확인한다.
- R8의 두 마이크로 취약/수정 쌍에서 실제 Opengrep trace의 source→SQL sink를 확인한다.
  broad sanitizer 누락·bound 인자와 tainted SQL arg0 차이도 R8이 독립 기대값을 정하고 R9가 실행한다.
- 실제 요청 핸들러의 JaCoCo before/after covered와 미요청 handler uncovered를 대조한다.
  발견 recall·공격 비율·라인 coverage·confirmed 정확도를 별도 분모로 보고하고 실패를 100%로 바꾸지 않는다.
- M2 권한 Oracle과 M3/M4 workflow·sequences는 이번 설계에 구현하지 않는다. 신규 테스트/명령은 CP1 후 패킷에 적는다.

## 1차 출처

- [Spring mappings 구조](https://docs.spring.io/spring-boot/3.5/api/rest/actuator/mappings.html)
- [springdoc 경로·버전 matrix](https://springdoc.org/)
- [OpenAPI 3.1 path/operation/parameter/body](https://spec.openapis.org/oas/v3.1.0)
- [Opengrep taint 규칙](https://github.com/opengrep/opengrep/wiki/Guarded-taint-signatures)

## M1-40 구현 상태와 연결 요청

- 별도 순수 `enumerateOpenApiSurfaces`와 bounded local-ref reader를 구현했다. 모든 선언 메서드와 정확한 경로를
  보존하며 GET scalar query/path·POST JSON scalar leaf만 준비 가능하다. v1과 요청 실행 포트는 변경하지 않았다.
- 3.0/3.1 기본 scalar를 읽되 3.0 null/type-array와 3.1 union·동적 ref·모호한 ref siblings는 미지원 gap이다.
  ref alias는 허용하며 같은 parameters 배열의 중복 `(in,name)` 정의는 거부한다. 원문 JSON의 중복 key 탐지는
  파싱 전 호출자 책임이다. 이 API는 파싱된 own-data만 받으며 bytes/hash/artifact의 실제 결속도 호출자가 검증한다.
- 입력과 출력 artifact를 같은 JSON bytes/node 한도로 검증하고, 참조 해석 호출 수도 20,000으로 제한해
  leaf 없는 ref DAG와 alias 출력 폭증이 complete 결과로 남지 않게 했다.
- Pack 데이터는 현재 R1 schema를 통과한다. compiler가 source-routes·binding hint를 명시 거부하므로 실행 지원을
  주장하지 않는다. M1-45에서 R1 M1-44의 paths 계약에 맞춰 spring-actuator 항목에
  `paths: [/actuator/mappings]`를 실제 데이터로 명시했다. R1 소유 파일은 수정하지 않았다.
- paths가 없는 사용자 Pack은 후속 Provider에서 `unknown`/gap으로 보고해야 한다. optional schema 필드는
  코드에 기본 경로를 하드코딩하거나 임의 endpoint를 요청할 권한이 아니다. 실제 Actuator/Inventory/live cap 연결은
  여전히 후속 범위이며 source-routes·sanitizer hint를 삭제해 compiler 거부를 숨기지 않는다.
- R8 primary와 JDBC 두 ground truth를 읽고 합성 OpenAPI 계약 입력으로만 대조했다. 실제 Spring 응답·recall·
  Opengrep taint trace·coverage는 미검증이다. actuator/병합/live cap·deadline·origin 연결은 후속 패킷 범위다.

## M1-51: CPx4 N1/N3 한도 범위

- operation의 parameter 배열/병합 집합 또는 body scalar leaf가 32개를 넘으면 해당 surface를 지우지 않는다.
  `unresolved`와 `openapi_limit`를 기록하고 다른 정상 라우트를 보존한다. metadata는 일부 또는 전부 비어 있을 수
  있으며 완전한 입력 목록으로 쓰지 않는다. 결과는 `partial`, declared는 null이고 enumerated는 보존한 라우트 수다.
- 문서 bytes/nodes/depth/routes, ref 노드 256개, resolve 호출 20,000회 및 출력 artifact 한도는 전역 거부를 유지한다.
  ref 256은 unique target 수가 아니라 같은 ref가 반복돼도 각 `$ref` 노드 수다. 수백 ref를 생성하는 실제 Spring
  문서는 전체 error/unknown이 될 수 있어 recall을 낮춘다. 상한을 늘려 지원 완료로 주장하지 않는다.
- locator 결과는 immutable snapshot에서 memoize하고 parameter의 중복 resolve를 제거했다. cache hit도 resolve
  호출 예산에 산입해 leaf 없는 DAG의 전개를 제한한다. 이는 네트워크 호출 수나 고유 ref 수와 다른 계산이다.
- 실제 Spring live 응답과 recall은 이번 패킷에서도 측정하지 않았다.

## M1-69: 순수 Actuator 열거와 Inventory 병합

- [공식 Spring Boot 4.1 mappings 구조](https://docs.spring.io/spring-boot/4.1/api/rest/actuator/mappings.html)의
  contexts → mappings → dispatcherServlets/dispatcherHandlers → details.requestMappingConditions를 읽는다.
  입력 생산자는 Spring Actuator 구조이며 테스트 입력은 그 구조를 따른 inline JSON이다. 실제 응답 캡처가 아니다.
- methods×patterns의 모든 명시 메서드/별칭과 대소문자/후행 slash를 보존한다. 빈/전체 methods, 구조 없는
  functional/static predicate는 추측하지 않고 gap을 남긴다. handler className으로 Java 경로를 만들지 않는다.
  검증된 source 위치를 주는 입력은 이번 API에 없으므로 handler.path 자체를 출력하지 않는다.
- params/headers/produces 조건, 미지원/부정 consumes와 미지 조건은 blocking reason이다. 단일 positive
  application/json consumes만 보완 가능한 제약으로 기록한다. 조건 원문 값/handler/predicate는 보관하지 않고
  semantic signature SHA와 locator만 남긴다. 중복 handler/조건 모순은 unresolved다.
- Servlet root mapping `/`만 base-path 근거로 사용한다. 여러 context/parent 관계, 비루트 servlet mapping,
  WebFlux base-path 불명은 unresolved로 유지하고 prefix나 origin을 만들지 않는다. reactive 구조 열거와
  실제 origin/base-path 확인을 구분한다. 이 보수적 처리는 실제 앱 recall을 낮출 수 있다.
- JSON snapshot은 own-data/1MiB/20,000 nodes/depth40을 제한한다. context/dispatcher 그룹32, mapping/확장 route1000,
  methods16/aliases64/조건별32 및 출력 snapshot 한도를 둔다. 중복 alias도 임의로 GET이 되지 않는다.
- 순수 merge는 정확한 method+path와 runtimeSurfaceId만 사용한다. provider/provenance/gap/parameter를 결정적으로
  정렬·중복 제거하고 입력 순서를 선택 우선순위로 쓰지 않는다. 신뢰 OpenAPI의 같은 route schema는 오직
  actuator_input_schema_unknown을 보완한다. 조건/handler/미디어/입력 직렬화의 충돌은 계속 unresolved다.
- Actuator 단독은 입력 schema를 확정하지 않아 partial/null 분모다. 보완 후 route가 ready여도 provider의
  partial/error/null과 원래 gap은 Inventory에 전파된다. ready는 공격 입력 구성 정보이며 접근 성공·권한 증거가 아니다.
  source SHA/run artifact와 rawInput SHA/sanitized ref의 실제 결속은 신뢰 호출자가 검증하며 원문 저장을 주장하지 않는다.
- 두 R8 원본 업무 route 목록은 읽기만 해 합성 계약과 대조했다. 실제 Actuator 수집·recall·handler source/coverage,
  소유 origin·request cap/deadline 연결은 후속 검증이며 이 모듈에는 네트워크/실행 capability가 없다.

## M1-74: 전체 method의 알려진 path 보존

- methods가 비었거나 `*`를 포함해도 구조화 patterns가 있으면 각 alias를 `method: '*'`인 미해결 surface로
  남긴다. 여기서 `*`는 실제 HTTP method가 아니라 전체 method 범위를 확정하지 못했다는 정보 표시다.
  GET/POST를 추측하거나 실행 허용하지 않으며 unresolved·actuator_all_methods_unknown·null 분모를 유지한다.
  enumerated는 marker를 포함한 알려진 표시행 수이며 확정된 HTTP method 수가 아니다.
  merge도 wildcard를 ready로 승격하지 않는다.
- marker도 signature/constraints, raw SHA와 sanitized artifact/locator를 보존한다. method+path 정체성이므로 같은
  path의 실제 GET과 합쳐지지 않는다. 상위 scope 필터는 알려진 path를 판단할 수 있지만 필터/정책은 변경하지 않았다.
- 기존 계약 테스트의 "불명 mapping은 route 없음" 기대를 "두 alias marker와 명시 POST 보존"으로 바꿨다.
  이는 정보 손실을 줄이는 강화이며 실제 method 미추측·공격 미허용·unknown/null 기준과 R8 보안 verdict는 그대로다.
  patterns 자체가 불명이면 기존 gap만 남기고 path를 만들지 않는다. 실제 Actuator 측정은 여전히 후속 범위다.
