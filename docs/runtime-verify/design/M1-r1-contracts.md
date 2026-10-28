# M1 Spring verify 계약 제안 — CP1 검토용

기준: `a49da4ceebc2c7dd24020ecbce420f46d0ca7625`(M0 PR82 병합). 이 문서는 설계이며 구현·검증 완료 주장이 아니다. PLAN 3·4·6·7·10·11·12·13·14.4와 HANDOFF/SUBAGENTS를 따른다. CP1 승인 전 제품 코드를 쓰지 않는다.
계약 조정 입력: root의 M1-DESIGN/R3/R8 설계, R4 `cd3e2d0`·R5 `0e32823` 설계. R8의 V1~V3/F1~F2/N1~N13 기대값은 바꾸지 않는다.
M1-CP1(exit10) B1/B2·N3/N4/N5 수정: 공통 보고서 A, 명시적 check 계약·권위 파일/테스트 목록·per-request 복원·stdio relay로 정렬한다. 이 문서가 수정된 설계 제안이며 제품 구현은 아직 없다.
M1은 소유 Spring+Postgres compose 예제, JVM/JaCoCo, actuator/OpenAPI, pg-log, SQL Oracle의 세로 경로다.
기존 `scan/init/init-dast`, Inventory v1, 실행 계획 v1, `runExecutionPlan`·`RunStore` 공개 계약은 그대로 둔다.
M0의 제네릭 포트는 아래 구체 데이터 타입에 바인딩한다. 실행 어댑터와 순수 데이터/Oracle의 import 방향을 분리한다.

## 1. 명령과 입력 권한

- `verify`는 메모리 안의 argv/own-data 옵션에서 `--execute-target-consent`를 먼저 확인한다. 없으면 exit 2.
- 그 전에는 target/source lstat·read, 출력 생성, Docker/프로세스, DNS/HTTP, 모델을 모두 0회로 한다(고정 오류 stdio만 허용).
- 동의는 대상 URL 권한이 아니다. 대상 origin은 이번 실행이 만든 컨테이너의 검증된 내부 주소에서만 나온다.
- `init-target`는 명시한 소스만 읽어 감지 근거와 초안을 새 경로에 쓴다. 빌드/스크립트/Docker/네트워크는 실행하지 않는다.
- `doctor --runtime` 전체 구현은 M3다. M1 verify의 최소 사전 점검은 동의 뒤 실행하며 무검증 격리 fallback은 하지 않는다.
- YAML 저장 위치 선택은 PLAN 13의 미결정이다. 아래 TargetSpec은 두 저장 방식이 공유할 **정규화 데이터 계약**이다.
- 파서는 중복 키·알 수 없는 키·태그·앵커/alias·merge·환경 보간·함수·getter·Proxy를 거부한다. JSON snapshot 제한을 낮추지 않는다.

```ts
type Sha256 = string; // /^[a-f0-9]{64}$/; 이미지 digest는 별도 /^sha256:[a-f0-9]{64}$/
type PathRef = string; // root 내 상대 경로, '..'/절대 경로/링크/특수 파일 거부
type Gap = { area: string; code: string; surfaceId?: string }; // schema의 닫힌 reason enum
type ArtifactRef = { path: PathRef; bytes: number; sha256: Sha256 };
type TargetSpec = {
  version: 1; project: string; source: PathRef;
  build: { kind: 'compose'; file: PathRef; service: string };
  pack: { id: string; version: number }; // bounded data ID/version, 실행 모듈 경로가 아님
  entry: { port: number; health: string; startupTimeoutSec: number };
  dependencies: { service: string; observer: 'pg-log' }[];
  seed: { sql: PathRef[]; snapshot: 'per-request' }; // 각 control/probe 요청 전 같은 기준 상태 복원
  scope: { include: string[]; exclude: string[] };
  budget: { maxRequests: number; maxMinutes: number; ratePerSecond: number };
};
type SourceManifest = { files: { path: PathRef; mode: number; bytes: number; sha256: Sha256 }[]; complete: boolean };
type Stage<T> = {
  schema: 'wakeio.verify-stage/v1'; stage: string; runId: string; epoch: string; runNonce: string;
  inputs: ArtifactRef[]; output: T; status: 'completed' | 'partial' | 'error'; gaps: Gap[];
};
```

M1의 accounts/login/access와 auto/Dockerfile 빌드는 지원한다고 가장하지 않고 명시적 미지원으로 거부한다. Postgres 합성 접속값은 실행기가 생성해 메모리의 비밀 핸들로만 전달한다. 부모 env·CI 토큰·`.env`는 전달하지 않는다.
제안 상한: Target/Pack/단일 JSON 1MiB·20,000노드·깊이40, 라우트 1,000개, 공격 요청 2,000회, 전체 15분.
큰 기록은 줄별 검증 NDJSON(줄 64KiB·파일 64MiB·사건 20,000개)로 제한한다. 초과는 partial/error이며 잘라서 완료로 만들지 않는다.
이 상한과 세부 reason enum은 CP1 검토 대상이며 기존 v1 상한을 바꾸지 않는다.

## 2. 파일 전달과 단계별 해시 결속

각 Stage 파일의 정확한 UTF-8 바이트를 해시한다. 소비자는 크기·no-follow 안정 읽기·raw SHA·스키마·입력 체인을 모두 검증한다. `runner.ts`의 private readStable을 공개하거나 수정하지 않고 같은 보안 조건을 새 runtime artifact reader에 구현한다.
출력은 소스 밖 새 디렉터리(0700), 파일0600, 경로/조상 링크 거부, 임시 파일→rename, 기존 결과 덮어쓰기 금지다.
Stage 자체 digest는 다음 Stage/최종 manifest가 참조한다. 자기 digest를 자기 본문에 넣는 순환 결속은 만들지 않는다.

| 단계 | 파일과 최소 내용 | 필수 입력 결속 |
| --- | --- | --- |
| Prepare | `01-prepare.json`: 정규 TargetSpec·감지 근거·source manifest·Pack/정책/도구 버전 | target 원본 bytes, 복사한 모든 빌드 입력 bytes, seed/lock/config/Pack/schema SHA |
| Build | `02-build.json`: builder/version·imageDigest·cacheKey·IsolationReport | Prepare + 실제 effective compose/build 설정 + base/dependency image digest |
| Run | `03-run.json`: 대상/DB ID·검증된 내부 origin·health 상태·관측 세션·계측 digest | Build + seed/schema state hash + 계측 도구/설정 digest |
| Discover | `04-inventory.json`: Inventory v2·제공자 상태/출처 | Run + actuator/OpenAPI의 마스킹된 구조 artifact refs |
| Attack | `05-plan.json`, `05-markers.ndjson`, `05-attack.ndjson` | Inventory + seed + payload/engine 버전 + 예산 + 초기 DB snapshot hash |
| Observe | `06-observations.ndjson`, `06-coverage.json`, `06-collection.json` | Run/epoch + Attack/MarkerLedger SHA + Observer 버전·dump/source-map digest |
| Judge | `07-verdicts.json`: Verdict·case outcomes·gaps | 위 세 관측 파일 + plan/marker/attack + SQL parser/Oracle 버전·정책 SHA |
| Report | `08-cleanup.json`, `report.json`, `report.md`, `report.sarif`, `agent-report.json`, `run-manifest.json`, `run-receipt.json` | Judge + 전체 단계 refs + cleanup 결과; manifest가 4종 raw SHA를 결속, receipt가 manifest SHA를 결속 |

소스 식별은 기존 UTF-8 분석 문자열 해시와 구분한다. 정렬된 경로/모드/길이/raw SHA manifest가 실제 복사본을 식별한다. 불완전 수집·외부 symlink/hardlink·변경 중 파일이면 실행을 거부한다. 원본 소스는 실행/수정하지 않는다.
이미지 캐시 키는 source manifest+effective build 설정+lock/seed/Pack+builder/toolchain 버전을 포함하며 모르면 miss다.
M1은 빌드 의존성과 이미지 캐시만 다룬다. 판정/관측 캐시와 `reused`는 M5까지 사용하지 않는다.
중단 후 Stage 파일은 진단/검증 입력일 뿐 실행 권한이 아니다. 재개도 새 동의와 SHA 확인이 필요하다. 살아 있던 컨테이너/Observer를 파일만 보고 재사용하지 않는다. 새 epoch로 Run 이후를 다시 만들고 이전 epoch 사건은 거부한다.

## 3. Inventory v2: 발견과 실행 가능성의 분리

```ts
type HttpMethod = string; // 대문자 HTTP token, 길이<=32; GET 이외 메서드도 소실 없이 기록
type SurfaceRef = { id: string; method: HttpMethod; pathTemplate: string };
type Provenance = {
  provider: 'spring-actuator' | 'openapi'; rawInputSha256: Sha256; sanitizedArtifact: ArtifactRef; locator: string;
  handler?: { path: PathRef; className: string; methodName: string; line?: number };
};
type Surface = SurfaceRef & {
  params: { name: string; in: 'path' | 'query' | 'header' | 'cookie' | 'body'; required: boolean;
    mediaType: string | null; jsonPointer: string | null; schemaLocator: string; type: 'string' | 'integer' | 'number' | 'boolean' | 'null' | 'unknown'; serialization: { style: string | null; explode: boolean | null; allowReserved: boolean | null } }[];
  provenance: Provenance[]; readiness: 'ready' | 'unresolved' | 'excluded'; reasons: string[];
};
type InventoryV2 = {
  schema: 'wakeio.surface-inventory/v2'; sourceSha256: Sha256; run: ArtifactRef;
  surfaces: Surface[]; providers: { id: string; status: 'completed' | 'partial' | 'error' }[];
  counts: { declared: number | null; enumerated: number }; gaps: Gap[];
};
```

정체성은 method+정확한 pathTemplate이다. 대소문자·후행 slash·별칭을 보존하고 provenance를 합치되 순서를 결정적으로 정렬한다.
OpenAPI GET-only v1 enumerator는 바꾸지 않는다. v2의 별도 순수 열거기가 모든 선언 메서드를 보존하며 remote ref를 가져오지 않는다.
actuator의 메서드 무제한/조건식/동적 mapping은 임의 GET으로 바꾸지 않고 unresolved gap으로 남긴다.
M1 공격은 GET query/path와 POST의 선언된 JSON scalar leaf를 지원한다. GET/POST의 같은 SQL Oracle로 R8 V1/V2의 confirmed와 F1/F2의 confirmed/strong 0을 검증하며 V2를 GET으로 대체하지 않는다. 미지원 메서드/배열·조합/multipart/auth/직렬화·타입 불명 입력은 보존하고 unknown 사유를 낸다.
rawInputSha256은 메모리에서 본 원시 응답 bytes의 digest이며 저장 파일 ref가 아니다. sanitizedArtifact는 가린 구조 bytes의 별도 SHA/길이/경로다. 원문 삭제 후 원본을 독립 재검증할 수 있다고 주장하지 않는다. actuator만으로 schema를 추측하지 않는다.
출처는 발견의 근거이며 성공한 접근/권한 증거가 아니다. source-routes/crawler/agent와 sequence 추론은 이번 M1에 구현하지 않는다. `sequences`는 M3 schema 확장에서 추가하며 M1 파일에 가짜 빈 탐색 결과를 넣지 않는다.

## 4. 공격·마커·관측·커버리지·판정 데이터

```ts
type MarkerRow = {
  markerHash: Sha256; surfaceId: string; method: HttpMethod; param: { in: string; name: string; jsonPointer: string | null; schemaLocator: string };
  payload: 'benign' | 'sql-quote' | 'sql-boolean'; requestOrdinal: number; controlPairId: string;
};
type MarkerLedger = { reproductionKey: Sha256; seed: string; rows: readonly MarkerRow[] };
type AttackAttempt = {
  ordinal: number; surfaceId: string; markerHash: Sha256; payloadHash: Sha256; requestHash: Sha256;
  phase: 'control' | 'probe'; snapshotHash: Sha256;
  outcome: 'response' | 'transport_error' | 'not_started'; httpStatus: number | null;
};
type AttackLog = { plan: ArtifactRef; markers: ArtifactRef; attempts: readonly AttackAttempt[] };
type PgCursor = { dbLeaseId: string; logIdentity: string; rotation: number; byteOffset: number };
type Observation = {
  id: string; runId: string; epoch: string; runNonce: string; observerSession: string; sequence: number;
  requestOrdinal: number; markerHash: Sha256; sourceContainerId: string; pgSessionId: string; pgSessionLine: number;
  cursor: PgCursor; requestWindow: { begin: PgCursor; end: PgCursor; closed: boolean };
  sql: { channel: 'statement' | 'bind'; dialect: 'postgres'; rawStatementSha256: Sha256; rawEventSha256: Sha256;
    parser: { version: string; pgMajor: number; lockSha256: Sha256; wasmSha256: Sha256 };
    ast: { id: number; kind: string; parent: number | null; span: [number, number] }[];
    tokens: { kind: string; span: [number, number]; role: 'literal' | 'identifier' | 'operator' | 'syntax' | 'comment' | 'parameter' }[];
    insertions: { payloadHash: Sha256; span: [number, number]; tokenIndexes: number[]; nodeIds: number[] }[];
    error: { sqlState: string | null; pgCharPosition1Based: number | null; parserByteOffset0Based: number | null; kind: 'none' | 'quote_imbalance' | 'other_syntax' | 'unsupported' | 'invalid' }; controlContextHash: Sha256; outsidePayloadTokenHash: Sha256 }; evidence: ArtifactRef;
};
type CoverageMap = {
  basis: 'jacoco'; imageDigest: string; sourceSha256: Sha256; dump: ArtifactRef; agentVersion: string; agentSha256: Sha256;
  requests: { surfaceId: string; taskId: string; requestOrdinal: number; jacocoSessionId: string; classTree: ArtifactRef;
    before: { exec: ArtifactRef; xml: ArtifactRef; resetAck: ArtifactRef }; after: { exec: ArtifactRef; xml: ArtifactRef; resetAck: ArtifactRef };
    files: { path: PathRef; sha256: Sha256; coveredLines: number[]; executableLines: number[] }[];
    accounting: 'exact' | 'unknown'; reasons: string[] }[];
};
type RuntimeVerdict = {
  surface: SurfaceRef; vulnClass: 'sql'; grade: 'confirmed' | 'strong' | 'observed' | 'candidate';
  reach: 'triggered' | 'reached_not_triggered' | 'not_reached' | 'unknown';
  markers: Sha256[]; evidence: ArtifactRef[]; ruleRevision: string; controlPairId: string;
};
type CaseOutcome = { surfaceId: string; state: 'triggered' | 'not_triggered' | 'unknown'; reasons: string[] };
```

마커는 PLAN 형식 `wk`+접두4자+요청 base32 8자다. issuer가 route/param/payload/ordinal을 먼저 예약하고 충돌 시 거부한다.
고정 reproductionKey(입력 체인+seed+예산+버전)에서 논리 실행 접두와 요청 suffix를 결정적으로 만든다.
동일한 고정 이미지·seed·예산의 두 재현 실행은 MarkerRow/요청 계획·Verdict 집합이 같아야 한다. 실제 실행 runId/epoch/컨테이너 ID·시간은 별도 메타데이터다.
서로 다른 물리 실행은 새 epoch/Observer 세션/DB 로그 offset/격리 namespace를 쓴다. 같은 마커도 다른 실행 사건이면 버린다.
sourceContainerId/session/offset은 Run artifact와 일치해야 하고 markerHash/ordinal은 현재 요청 창·snapshot과 결속한다. 시간 근접성만으로 귀속하지 않는다.
이 논리 실행/물리 실행 구분은 CP1 검토 대상이다. 시간이나 랜덤 ID를 제외하는 의미 비교 규칙은 R8/R9가 독립 동결한다.
원문 토큰·payload·SQL 값·응답·자격 증명은 보고하지 않는다. collector는 비마커 사건을 저장 전 버리고 raw 로그 파일을 남기지 않는다.
Observer helper가 원문을 버리기 전에 AST/token/삽입 구간의 역할·원문 UTF-8 byte span과 PG의 1-based 문자 위치 변환을 검증한다. literal/identifier/comment/Bind 값·오류 원문은 저장하지 않으며 보존 실패는 unknown이다. 외부 promoted boolean은 금지하고 Oracle이 control 문맥·삽입 token/AST 관계로 승격을 계산한다.
PG lease/container/session/line과 seed 뒤 시작 cursor→요청 창→최종 drain cursor를 결속한다. rotation gap·중복·잘린 줄·닫힌 창의 늦은 사건·다른 runNonce/DB lease는 거부하고 해당 범위를 unknown으로 남긴다. SQLSTATE 42601만으로 확정하지 않는다.
R5 세부 제안 한도는 SQL32KiB·PG record64KiB·normalized8MiB/4,096사건·AST20,000노드/깊이40·helper1초/256MiB다. CP1에서 확정하며 어느 한도든 도달하면 unknown/미완료이지 잘라낸 성공이 아니다.
동일 라우트의 benign/probe를 동일 seed snapshot에서 직렬 실행한다. health/discovery/control/재시도도 전역 cap·deadline에 산입한다.
새 runtime admission이 기존 GET/HEAD/POST `RunAdmission`을 감싸며 v1의 허용 메서드·동작을 넓히지 않는다.
JaCoCo는 전체 run 합계만으로 라우트 귀속을 주장하지 않는다. 각 요청마다 before dump/reset ack→단일 requestOrdinal→after dump/reset ack의 장벽을 사용하며 한 CoverageMap.requests 행에 여러 요청을 묶지 않는다. 라우트 요약은 이 요청 행에서만 집계한다(CPx1 N1).
분모는 실행 가능한 줄과 발견된 라우트를 구분한다. 소스/클래스 매핑 실패·백그라운드 오염이면 accounting unknown, 0%/100%로 대체하지 않는다.
Observer 부착/연결/종료 drain 실패는 해당 case unknown이다. 음성 대조군의 무사건도 수집 완료 장벽 없이는 안전 증거가 아니다.
Oracle은 검증된 readonly `AttackLog+MarkerLedger`, Observation[], CoverageMap만 받는 data-only 함수다. 파일·네트워크·프로세스·시계·랜덤·env·동적 import·RunContext 권한이 없다. parser I/O/WASM 로딩·trap 후 재초기화는 R3가 감독하는 Observer 전용 helper에 격리하고 parser package를 Oracle에 import하지 않는다.
정상 control 응답·대응 PG 관측·같은 controlContextHash가 필수다. 문장 직접 조립은 strong 후보, 삽입 token의 literal 밖 AST 승격 또는 PG42601+일치 위치+parser quote 불균형 진단이 있어야 confirmed다. Bind/literal/comment 안의 값은 문법 승격이 아니다.
응답/SQLSTATE만으로 confirmed를 내지 않는다. parser/방언 미지원·손상·역할 불명은 unknown이며 F1/F2의 정상 바인딩 완료를 unknown으로 숨기지 않는다. unknown은 CaseOutcome+gap이고 빈 Verdict 배열은 안전/완료가 아니다. N1/N2의 confirmed 0을 모든 grade 0으로 바꾸지 않는다.

### M1-160 / native 오류 진단의 후속 계약 제안

이 절은 M1-149/155에서 확인한 실제 parser API 부족을 해결하기 위한 후속 CPx 제안이다. 현재 제품의 protocol/types/Oracle 또는 R8 기대값을 바꾸지 않는다. §7의 새 경로도 CPx 승인 뒤 root의 별도 구현 패킷으로만 쓴다. 설계 문서 자체는 설치·native build·WASM/PG/대상 실행 권한이 아니다.

**현재 한계와 근거.** pinned `libpg-query@18.2.1`의 parse 오류는 message/cursorPosition/fileName/functionName/lineNumber를 채우며 quote enum/SQLSTATE를 제공하지 않는다(type에 선언된 optional context도 이를 대신하지 못한다). wrapper가 원래 cursorpos>0이면 1을 빼고 나머지를0으로 만들므로 “위치 없음”과 “첫 문자”를 잃어버린다. wasm_scan 오류는 message만 반환하며 partial token 결과가 없다. libpg_query scan은 첫 전체 lexical pass가 성공한 뒤 두 번째 pass에서 token 결과를 만든다. lexical quote 실패의 정확한 outside-token context를 현재 API에서 복원할 수 없다.
- [고정 wrapper의 parse 오류/위치 변환](https://github.com/constructive-io/libpg-query-node/blob/55c0963bf79bfd437c2aa1eb5fba9329a6fcd76f/versions/18/src/index.ts#L395-L412) · [wasm_scan 오류 반환](https://github.com/constructive-io/libpg-query-node/blob/55c0963bf79bfd437c2aa1eb5fba9329a6fcd76f/versions/18/src/wasm_wrapper.c#L349-L377).
- [선언된 libpg_query source의 두 scan pass](https://github.com/constructive-io/libpg_query/blob/b0f5f331dc50d69597ec610de7b21afa47a66808/src/pg_query_scan.c#L63-L108) · [PG18 lexer EOF 분기](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/parser/scan.l#L742) · [byte 위치에서 PG 문자 위치로 변환](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/parser/scan.l#L1140-L1150).
위 source 읽기는 published npm WASM과 해당 source commit의 재현 빌드 대응을 입증하지 않는다. R8 `sql-projections.json`의 authorship도 manual ground truth/NOT measured PG로 명시돼 있다. V3의 UNTERMINATED_LITERAL·위치·context는 그 독립 예제이며 현재 native 출력이라고 주장하지 않는다. V3의 confirmed 기대값은 유지하고 실제 지원 부족을 unknown/미완료로 남긴다.

**wire 구분.** 아래 이름/형태는 새 revision의 후보이며 현 `wakeio.pg-parser/v1`이나 기존 error/hash 필드의 의미를 조용히 바꾸지 않는다. R1 타입/schema와 R5의 request/reply 검증을 함께 검토한 뒤 닫힌 union으로 구현한다.

| 제안 필드·domain | 의미와 거부 기준 |
| --- | --- |
| `dbError` | 실제 소유 PG 로그 사건의 SQLSTATE와 원래 statement 문자 위치를 담는다. native parser 오류나 HTTP 응답을 DB 오류로 복사하지 않는다. internal query 위치·다른 statement·없는 로그는 해당 statement의 증거로 쓰지 않는다. |
| `position` | `presence:present`이면 원래 PG 1-based 문자 위치와 검증한 UTF-8 0-based byte offset을 함께 둔다. `presence:absent`이면 두 값은 null이다. 원래 PG의0/없음을 첫 문자0-based 위치로 채우지 않으며 현재 wrapper의0에서 유효성을 역추정하지 않는다. |
| `nativeDiagnostic` | `none / lexer_eof / other_syntax / unsupported`를 구분한다. lexer_eof는 native lexer가 실패한 그 분기에서 기록한 닫힌 code·원본 UTF-8 span·위치 유효성을 요구한다. 원문 message/파일명/함수명 패턴으로 EOF 종류를 추정하지 않는다. |
| native EOF code | M1-165 고정 소스 조사에 따라 아래 M1-168의 닫힌 code와 최초 xq 지원만 선택한다. 다른 lexer 상태를 quote 성공 코드로 합치지 않는다. ABI 구현·실제 진단 검증은 후속 패킷이다. |
| `context.basis=complete_tokens` | 원본 statement의 전체 scan이 성공한 경우에만 token 역할/span 기반 context를 쓴다. 기존 token hash 계산/원문 폐기 규칙은 이 domain에서 유지한다. |
| `context.basis=control_template_bytes` | lexical 실패 때문에 token 결과가 없을 때 별도로 쓰는 원본 byte 문맥이다. 정상 control literal span·각 실제 삽입 span·recipe hash·삽입 전후 prefix/suffix의 길이 및 hash·domain을 구분한 template hash를 결속한다. token 결과나 outsidePayloadTokenHash인 것처럼 저장하지 않는다. |
| `context.basis=unavailable` | 정상 control·정확한 삽입 경계·byte 동일성·설정·native 진단 중 하나라도 검증할 수 없을 때 사용하며 해당 case는 unknown이다. 다른 basis의 hash끼리 같다는 이유로 비교하지 않는다. |

span은 원래 SQL의 검증된 UTF-8 byte 기준 반열린 구간이며 byte 범위·문자 경계·실제 입력 길이를 검사한다. PG 문자 위치는 JS UTF-16 index가 아니다. EOF의 끝은 원문 끝, 시작은 native lexer가 실제로 기록한 시작점이어야 한다. SQL을 고쳐 parser를 성공시키거나 추정 AST/token·UNTERMINATED_LITERAL을 만들어 실제 관측으로 내보내지 않는다. lexical 실패에는 AST/token 결과가 없다는 사실을 그대로 보존한다.
native SQLSTATE를 새로 제공하더라도 DB SQLSTATE와 출처를 분리한다. EOF enum은 해당 parser source의 구조적 진단이고, DB 발생/route 인과는 소유 PG 관측에서 따로 확인한다. producer가 준 promoted boolean·SQLSTATE 단독·HTTP 오류·오류 message regex로 grade를 올리지 않는다.

**control→probe 인과 조건.** 같은 route/param/controlPairId·발급 recipe·payload hash·requestOrdinal과 snapshot을 사용한 정상 control이 먼저 성공해야 한다. control의 실제 SQL에서 literal 범위와 marker 삽입 구간을 확인하고 probe의 원래 bytes에서 대응 삽입 전후 template가 같음을 확인한다. 이때 원문은 trusted helper/collector RAM에서만 비교하고 이전 개별 tokenHashes 수명 정책대로 폐기한다. hash가 기밀성이나 생산자 인증을 보장하지는 않는다.
native 오류의 시작점은 payload 내부라고 가정하지 않는다. V3처럼 삽입 앞의 control literal 여는 따옴표가 오류 위치일 수 있으므로 control literal·삽입 구간·원래 template의 위치 대응으로 검토한다. 삽입 경계가 여러 개/불명확하거나 실제 quoting/직렬화를 검증할 수 없으면 unknown이다. 이 조건을 만족한 lexer EOF 종류만 후속 Oracle의 quote 인과 검토 대상으로 삼는다.
DB 사건·control/probe 원문 hash·native 입력 hash는 같은 runId/epoch/runNonce·observer session·DB lease/container/PG session/line·요청 cursor 창·drain 완료에 묶는다. 늦은 사건·rotation gap·다른 run 재현 마커·누락/잘린 로그·일치하지 않는 statement는 거부하거나 unknown으로 남긴다. Bind 값은 SQL 본문 삽입이 아니므로 template/literal 실패 경로로 가장하지 않는다.
실제 PG 버전과 동일 DB의 server_encoding은 trusted 관리 연결로 확인하되, 앱 backend의 lexical 설정은 아래 M1-192의 실제 session·parse 시점 증거로 따로 결속한다. 관리 세션의 SHOW 결과를 같은 lease라는 이유로 앱의 실제 tuple로 사용하지 않는다. 방언·설정·유효성/byte 변환이 불명이거나 다르면 해당 설정 의존 판정은 unknown이다. 관측하지 않은 기본값으로 일치를 만들지 않으며 F1/F2의 정상 바인딩·다른 음성 조건도 그대로 검증한다.

**자산 정체성과 단계.** custom 진단에는 공식 npm18.2.1과 다른 artifact kind/id·revision 및 protocol revision을 부여한다. native source lock·patch SHA·compiler/linker/환경 image digest·옵션·생성 CJS/WASM bytes SHA·고지를 manifest의 build provenance로 구분한다. published upstream commit 선언·고지 원본·custom 재현 빌드의 입증 수준도 구분하며 npm WASM의 공식 version/integrity를 custom bytes에 붙이지 않는다. 원래 `libpg-query.wasm`은 원본 식별을 유지하고 custom 쌍은 §7의 다른 이름을 사용한다.
진행은 명부/계약 CPx 승인 → R5 C/wrapper 진단 보완 → R3 고정 source/toolchain의 격리 재현 build → R10 로컬 자산/manifest·고지/배포 연결 → R8 독립 projection 적합성 검토 → R9 실제 PG18 대조·인과/음성/실패 검증 순서다. R3는 R10 산출물의 최종 raw SHA가 확정된 뒤 별도 host 승인 pin을 갱신한다. source/worker directory의 manifest를 기대 pin으로 그대로 신뢰하지 않는다. 각 단계는 root 패킷과 기존 전체 lock pin 갱신 절차를 따른다.
native build는 별도 명시 script/승인된 tool 환경에서만 한다. 구체 상한·선택 조건은 아래 M1-168로 고정하며 parser job의1초/256MiB와 혼동하지 않는다. 일반 `npm run build`는 native source fetch·C/WASM compiler·Docker/VM을 요구하지 않고 고정된 로컬 native 자산의 검증/복사만 추가한다(기존 local tsc/esbuild 경로는 유지). 누락/손상/새 source 또는 toolchain 불일치에서 fail-closed하며 네트워크로 자동 복구하지 않는다.
R8은 고정 소스/보안 기대값의 독립 작성자이고 R5/R3/R10 출력으로 expected를 재생성하지 않는다. 새 native 진단과 V3 confirmed의 실제 결속은 R9의 실제 PG 로그·위치·설정·control/probe 대조가 있어야 입증된다. 고정 V3 등급을 낮추거나 manual projection 성공만으로 완료시키는 선택은 없다.

### M1-192 / lexical 설정의 실제 session·parse 결속

server_encoding은 **동일 DB**의 생성 시 고정 속성이다. DB 식별·lease 결속을 확인한 관리 연결의 조회를 그 속성의 근거로 쓸 수 있지만, DB가 다르거나 연결 귀속이 불명이면 공유하지 않는다. standard_conforming_strings/backslash_quote/client_encoding은 앱 session의 USERSET 값이며 DB 고정 속성과 다르다. [PG18 server_encoding](https://www.postgresql.org/docs/18/runtime-config-preset.html#GUC-SERVER-ENCODING), [고정 PG18 GUC 분류](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/utils/misc/guc_tables.c).
앱은 startup 설정·SET/SET LOCAL·set_config 등으로 session/transaction 값을 바꿀 수 있다. 관리 SHOW는 관리 session 값이며 connection 초기화나 role/database 기본값도 앱의 이후 parse 시점 값을 증명하지 못한다. 같은 backend에서 별도 조회했더라도 조회 뒤 상태 변경·함수의 일시 설정·연결 pool 교체를 배제하지 못하면 충분하지 않다. [session 설정](https://www.postgresql.org/docs/18/config-setting.html#CONFIG-SETTING-SQL), [SET·함수·transaction 수명](https://www.postgresql.org/docs/18/sql-set.html).
jsonlog의 session_id/pid/line_num·statement·SQLSTATE/오류 위치는 사건 귀속 자료이며 **lexical tuple 필드는 없다**. ParameterStatus는 client_encoding/standard_conforming_strings 등을 보고하지만 backslash_quote는 보고 대상이 아니므로 단독으로 tuple을 증명하지 못한다. 로그나 상태 메시지에 없는 값을 기본값으로 보충하지 않는다. [jsonlog 필드](https://www.postgresql.org/docs/18/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-JSONLOG), [ParameterStatus](https://www.postgresql.org/docs/18/protocol-flow.html#PROTOCOL-ASYNC).
simple Query는 전체 query 문자열의 최초 lexical/raw parse가 실행 전에 일어난다. extended protocol은 Parse와 Bind/Execute가 분리되므로 실행 시점이나 뒤의 조회 값을 원래 Parse에 소급하지 않는다. 재사용 prepared statement·여러 statement·내부 parse의 귀속도 구분해야 한다. [PG18 Query·Parse 단계](https://www.postgresql.org/docs/18/protocol-flow.html).
필요 증거는 실제 앱 backend의 **parse-entry와 lexical 오류 경로**에서 적용 설정을 확보하는 trusted capture, 또는 그 parse 동안 값을 실제로 강제했다는 증거다. 원본 statement hash·parse ID·session 식별·DB lease·요청 cursor/창에 설정의 출처·시점을 결속하고 native의 선언/적용 값과 대조한다. server/client encoding을 구별하며 SQL bytes의 변환·UTF-8 위치 대응도 검증한다. Executor 시점 자료만으로 parse 실패를 덮지 않는다.
현재 이 capture/enforcement 구현은 없다. 결속 불가·설정 관측 손실/변경 누락·불일치는 해당 설정 의존 판정을 unknown으로 남긴다. 특정 server extension·새 코드 경로·설정 불변성 대안은 이번에 선택하지 않는다. byte 패턴이나 SQL regex로 confirmed를 올리거나 실제 tuple 관측으로 표기하지 않는다.
후속 별도 계약 리뷰와 독립 R8 기대값·R9 실제 설정 교차 matrix가 필요하다. 이번 정정은 V3 confirmed 등급·R8 원본·현재 v1/선언된 native ABI를 바꾸거나 native 실행 완료를 주장하지 않는다.

### M1-208 / CPx19 검토: common scanner 진입의 tuple 정책 후보

M1-200/201/203의 source 조사에 따른 **후속 검토 후보**다. 최종 선택·구현·가동·tuple 동등성 완료를 뜻하지 않으며 PLAN14.4의 M1 범위를 넓히지 않는다. §7의 새 경로도 CPx19 검토·승인과 root의 역할별 패킷 전에는 생성하지 않는다.
공식 REL_18_6의 [scanner_init](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/parser/scan.l)은 lexical globals를 scanner extra로 복사하며, [SQL raw_parser](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/parser/parser.c)와 [PL/pgSQL 직접 scanner](https://github.com/postgres/postgres/blob/REL_18_6/src/pl/plpgsql/src/pl_scanner.c)가 함께 사용한다. source 읽기 결과이며 실제 custom 서버의 관측 증거는 아니다.

**최소 후보.** 고정 PG18.6 서버의 scanner_init에서 globals를 복사하기 전에 실제 `standard_conforming_strings=true`, `backslash_quote=safe_encoding`, `GetDatabaseEncoding()=UTF8`, `pg_get_client_encoding()=UTF8`를 검사한다. 관리 SHOW·기본값·env 선언을 검사값으로 대신하지 않는다.
불일치는 고정된 별도 non-42601 정책 오류(후보 SQLSTATE 0A000)와 닫힌 지원 거부 사유로 끝낸다. 해당 요청은 unknown/gap이며 취약점·정상 control·수집 완료로 세지 않는다. 원문 SQL이나 오류 문자열을 진단 증거에 넣지 않는다.
이 정책은 SET/rollback을 가로막거나 GUC hook를 바꾸는 방식이 아니다. 설정이 달라진 뒤 새 scanner를 열면 그 순간의 값으로 거부한다. 이미 파싱된 트리의 실행 당시에도 tuple이 같다고 주장하지 않는다.

| source에서 확인한 범위 | 후속 검증·제한 |
| --- | --- |
| simple Query·extended Parse | 새 raw parse의 scanner 진입을 검사한다. 여러 statement는 실행 전 전체 parse이고 Parse와 Execute 시점을 혼동하지 않는다. |
| PL/pgSQL body·SQL 검증·SPI·type-name mode | 공유 scanner 진입으로 raw_parser 단독 검사 사각을 줄인다. 내부 문장과 외부 로그 statement의 hash/위치 귀속은 여전히 별도다. |
| bootstrap·initdb·--single | bootstrap은 별도 BKI grammar다. initdb 후반 --single SQL은 검사 대상이며 standalone 전체 예외를 두지 않는다. UTF8 initdb·초기화 순서의 실제 성공은 미측정이다. |
| prepared tree·SQL function·parallel reuse | 새 scan이 없으면 재검사가 아니다. 최초 검증된 parse와 같은 서버/정책/lease의 트리라는 근거가 필요하며 worker의 새 nested scan도 matrix에 포함한다. |
| 직접·중첩·정규화 scanner 호출 | 같은 진입을 검사하므로 pg_stat_statements 재스캔 등도 거부될 수 있다. 독립 parser·임의 native extension까지 포괄하는 보장은 아니다. |

[scanner API](https://github.com/postgres/postgres/blob/REL_18_6/src/include/parser/scanner.h)는 호출자가 복사값을 바꿀 수 있게 한다. client encoding은 lexer action에서도 현재 값을 참조한다. 고정 호출자와 scanner 수명 중 변경·재진입을 검증하지 못하면 진입 검사만으로 M1-192 capture를 대체하지 않는다.
[initdb](https://github.com/postgres/postgres/blob/REL_18_6/src/bin/initdb/initdb.c)는 BKI encoding 대체 뒤 standalone SQL을 수행한다. 예외가 정말 필요하면 실제 bootstrap mode만 별도 검토하며 앱의 SQL 권한으로 켤 수 있는 우회 설정은 만들지 않는다. OS 실행/C 코드·서버 자산 쓰기 권한 배제도 확인한다.
server-side statement의 검증된 UTF8 bytes와 [client→server 변환](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/utils/mb/mbutils.c) provenance를 결속한다. clientUTF8 검사도 필요한 이유는 safe_encoding의 실제 lexer 분기가 client 값을 참조하기 때문이다. 정규화만으로 이 의존성을 없앴다고 하지 않는다.
서버의 네 값 검사와 native helper의 적용 tuple은 다른 증거다. 이 제안 시점의 worker는 공식 package parseSync/scanSync의 wakeio.pg-parser/v1 경로이며 custom 진단/정책 배선 완료가 아니다. 현재 v1·16B/44B native ABI의 encoding 의미를 바꾸지 않으며 libpg_query core18.4와 서버18.6의 진단·위치·설정 동등성은 독립 actual 대조 전 미입증이다. xq 코드만으로 V3를 승격하지 않는다.

**배포 최소 권장 후보.** 고정 로컬 PG source+patch를 trusted 관리 도구가 별도 제한 build하여 만드는 **custom image**를 우선 검토한다. source/patch·compiler/flags·libc/arch·base/runtime image·생성 postgres bytes와 최종 image digest를 결속하고 독립 host pin으로 승인한다. 공식 PG 이미지와 동일품으로 부르지 않는다.
image 생성/사용은 Target sourceExec와 분리한다. 앱 source·compose·env가 recipe/image/정책·server volume을 교체하거나 관리 DB role을 얻지 못해야 한다. sourceExec consent나 기존 VM 소유권만으로 새 tool build/daemon/대상 실행 권한이 생기지 않는다.
로컬 binary 배포안은 정확한 OS/arch/libc·동적 라이브러리·PG share 자산과 설치 경로를 함께 고정해야 한다. 플랫폼별 postgres를 npm에 직접 넣는 선택은 이번 최소안으로 삼지 않는다. 필요성이 실측되면 경로·크기·배포 목록을 별도 승인받는다.
일반 npm build는 선택된 로컬 metadata/자산의 검증·복사만 유지한다. 자동 source fetch·compiler·이미지 pull/build는 추가하지 않는다. custom 서버 build/run 상한은 후속 R3 패킷에서 구체적으로 CPx 검토하며 기존 WASM job1초/256MiB를 서버 전체의 한도로 전용하지 않는다.

**실행 전 입증.** R9는 고정 source/patch/build·postgres/image raw digest, 실제 실행 lease/container·DB/session·정책 revision을 대조한다. 문장 hash·parse ID·cursor/요청 창과 원본→UTF8 변환을 결속하며 자기 manifest나 producer의 enforced boolean만으로 승인하지 않는다.
실제 matrix는 새 연결·startup/role/DB 설정·SET/LOCAL/set_config·function proconfig·RESET/rollback/SIGHUP, direct/nested scanner·prepared/parallel reuse·UTF8 initdb/--single·실패 cleanup을 포함한다. 다른 tuple을 요구하는 앱은 지원 거부 범위로 드러낸다.
고정 R8 기대값/V3 confirmed 등급은 유지한다. R8이 독립 matrix를 작성하고 R9가 실제 서버와 native의 취약/수정·음성 대조를 확인한다. byte 패턴·SQL regex·manual projection이나 정책 오류만으로 confirmed를 만들지 않는다.
입증되면 검증 범위 안의 스캔에 한해 강제 정책 증거를 tuple 관측 대신 쓸 수 있다. 문장 인과·producer 신원·DB 사건 귀속까지 대신하지 않으며 누락·불일치·미검증 수명/경로는 unknown이다. 현재 구현·compile·전체 matrix 완료를 주장하지 않는다.

### M1-168 / 최소 native ABI·최초 지원·후속 실행 조건

M1-165의 고정 소스 조사와 CPx14 N2를 반영한 문서 계약이다. 아래 선택은 patch·새 wire/types/context 또는 자산 구현 완료를 뜻하지 않는다. 현재 공식 npm 자산·`wakeio.pg-parser/v1`은 그대로 두고, root가 이 문서를 병합한 뒤 R5 patch 패킷과 R1/R5의 새 protocol 계약 패킷을 별도로 발행한다.

**닫힌 EOF code.** 숫자0은 `none`, 1~10은 다음 순서로 고정한다. code는 native의 실제 EOF 분기에서만 채우며 다른 오류 message로 추정하지 않는다.

| code | scanner 상태 | 최초 quote 인과 승격 지원 |
| --- | --- | --- |
| 1 `comment` | xc | 미지원 |
| 2 `bit_string` | xb | 미지원 |
| 3 `hex_string` | xh | 미지원 |
| 4 `standard_string` | xq | 아래 설정 tuple·control/DB 인과 검증을 모두 만족할 때만 검토 |
| 5 `escape_string` | xe | 미지원 |
| 6 `unicode_string` | xus | 미지원 |
| 7 `dollar_string` | xdolq | 미지원 |
| 8 `identifier` | xd | 미지원 |
| 9 `unicode_identifier` | xui | 미지원 |
| 10 `unicode_surrogate` | xeu | 미지원 |

[PG18 scan.l의 EOF rule](https://github.com/postgres/postgres/blob/REL_18_0/src/backend/parser/scan.l#L482-L825)에서 xqs EOF는 닫힌 문자열의 정상 반환 경로다. xeu는 일반 문자·개행·EOF가 action을 공유하므로 **진짜 EOF에만** code10을 기록한다. xq/xe/xus의 공유 EOF action도 실제 상태를 보존해야 한다. 이 구분을 입증하지 못하면 unsupported다. 앞선 quote EOF 인용 #L694는 surrogate 오류 위치 갱신이므로 #L742로 정정했다.

**별도 C/WASM ABI.** `wakeio_pg18_diagnose_v1(sqlBytes, byteLength, settings)`와 `wakeio_pg18_diagnose_v1_free(result)`를 추가하는 최소안을 선택한다. 입력 byteLength는32KiB 이하이며 유효한 UTF-8·NUL 미포함을 검증한 뒤 호출 수명 안에서만 사용한다. 결과는 PG memory context 밖에 별도 할당한 고정 크기 numeric POD이며 기존 PgQueryError, scanner 함수 prototype, pg_query_* 공개 API를 바꾸지 않는다.

- POD 필드 순서는 모두 `uint32_t`인 `abiRevision=1`, `status`, 위 `code`, `presenceBits`, `constructStartByte`, `errorByte`, `endByte`, `pgCharPosition1Based`, `encoding`, `standardConformingStrings`, `backslashQuote`다. WASM32에서 결과44바이트·설정 입력16바이트를 검사하며 후속 JS/wire도 같은 revision/길이/enum을 요구한다.
- status는0=ok/1=eof/2=syntax/3=unsupported/4=invalid다. status=eof만 code1~10을 가지며 나머지는 code0이다. presenceBits는0~7만 받는다. code는 진단의 종류이고 승격 지원 여부와 다르다.
- 설정 입력은 `abiRevision=1`과 위 세 설정의 uint32_t POD다. 설정은0=미적용·미지원, encoding1=UTF8, standardConformingStrings1=true, backslashQuote1=safe_encoding으로 닫는다. 이 숫자는 PG 내부 enum과 별개이며 실제 적용에 성공한 값만 결과에 채운다.
- `presenceBits`는 bit0=constructStart, bit1=errorByte+원래 PG 문자 위치, bit2=end다. 없는 필드는0이며 bit가 없으면 첫 문자/빈 span으로 해석하지 않는다. EOF 성공 진단은 세 bit와 검증된 UTF-8 경계·`endByte=byteLength`를 요구한다. `constructStartByte`는 해당 construct 진입 때, `errorByte`는 실제 오류 위치에서 별도로 기록한다. 두 위치가 같거나 오류가 payload 안이라고 가정하지 않는다.
- scanner extra에는 instance별 진단 연결만 두고, job마다 초기화한 POD 저장소를 PG_TRY 전에 할당한다. PG_CATCH는 longjmp 뒤에도 살아 있는 그 저장소의 숫자만 보존한다. setjmp 뒤 수정된 자동 stack 변수·해제된 scanbuf/PG memory context에 의존하지 않는다. scanner/input/문자열 포인터는 결과로 복사하지 않고 원문 SQL·message·token 조각을 출력하지 않는다. 성공·실패·trap 뒤 다음 job에 상태가 남아서는 안 된다.
- 최초 지원 tuple은 **PostgreSQL18 / UTF8 / standard_conforming_strings=true / backslash_quote=safe_encoding**뿐이다. M1-192의 실제 앱 session·parse 시점 설정 증거와 native에 실제 적용한 값이 일치해야 한다. 설정 미관측·다른 tuple·다른 EOF code는 unknown이며 공식 기본값을 관측값으로 채우지 않는다. xq code만으로 confirmed가 되지 않고 앞 절의 정상 control·template bytes·DB 사건 결속이 계속 필요하다. 이번 문구는 native ABI의 encoding 필드를 client_encoding으로 재정의하지 않는다.

**확인한 source assembly 범위.** wrapper 고정 commit은 `55c0963bf79bfd437c2aa1eb5fba9329a6fcd76f`, libpg_query는 `b0f5f331dc50d69597ec610de7b21afa47a66808`이다. [wrapper Makefile](https://github.com/constructive-io/libpg-query-node/blob/55c0963bf79bfd437c2aa1eb5fba9329a6fcd76f/versions/18/Makefile#L18-L79)은 `versions/18/src/wasm_wrapper.c`와 `.cache/$(PLATFORM_ARCH)/libpg_query/$(LIBPG_QUERY_COMMIT)` 아래 archive/header를 연결한다. 원본 Makefile에는 git clone 경로가 있으므로 승인된 고정 로컬 source 조립 없이 그대로 실행하지 않는다.

- 해당 libpg_query 트리에는 `scan.l`이 없고 [생성 scanner C](https://github.com/constructive-io/libpg_query/blob/b0f5f331dc50d69597ec610de7b21afa47a66808/src/postgres/src_backend_parser_scan.c), `src/postgres/include/parser/scanner.h`, `src/pg_query_scan.c`, `pg_query.h`가 있다. patch는 이 source root와 wrapper root를 구분하여 실제 파일에 적용하고 base bytes/context 불일치 시 거부한다. upstream PG scan.l은 rule 대조 근거이며 이 트리에 존재하는 patch 대상으로 가장하지 않는다.
- [copy-templates의 full API 선택](https://github.com/constructive-io/libpg-query-node/blob/55c0963bf79bfd437c2aa1eb5fba9329a6fcd76f/scripts/copy-templates.js#L62-L87)에 따라 wrapper 원형은 `templates/full/wasm_wrapper.c`, 생성 위치는 `versions/18/src/wasm_wrapper.c`다. R5는 patch의 실제 적용 대상·생성물 일치 범위를 밝히며 기존 npm CJS/WASM을 수동 수정하지 않는다. M1-170의 source/OCI metadata 측정을 바탕으로 M1-171에서 source lock·Mac/Lima arm64 toolchain 후보·조립 root를 데이터로 선정한다. 실제 build/실행 준비를 뜻하지 않는다.

**M1-170 / R9가 측정한 입력 후보.** `.handoff/evidence/M1/native-parser-sources/{README.md,sources.json,oci.json}`은 manifest raw SHA256 `125ed713e2d06c8118709c76d76758fd6f8c5c27cdee8ec6e9d20cb506d4e878`에 결속된다. 두 archive의 고정 commit과 실제 byte SHA를 후속 source lock 입력으로 참조하며 이번 문서에서 제품 pin으로 승격하지 않는다.

| 고정 commit archive | 압축 bytes | SHA256 |
| --- | ---: | --- |
| wrapper `55c0963bf79bfd437c2aa1eb5fba9329a6fcd76f` | 497,766 | `92a879c16d194caf274eaac89f3b2259a125f820f7ab79990b517ff1e71b5395` |
| core `b0f5f331dc50d69597ec610de7b21afa47a66808` | 4,584,500 | `efb6664a0aab73bcc37a613ef9081f75439e3a520c0300fd6ac71eb5ffb8cfc3` |

R9의 archive 검사상 wrapper `versions/18/Makefile`은 template 생성물이고 package의 `wasm:make`는 정확히 `emscripten/emsdk:6.0.3`을 요구한다. core `Makefile`은 `PG_VERSION=18.4`를 선언하며 generated scanner C는 있지만 `scan.l`은 없다. 위 REL_18_0 링크는 설명·상태 대조 근거이며 실제 patch는 **고정 core의 생성 C/header·scan 연결부와 wrapper/template**에 적용한다. source 조립 경로는 확인한 Makefile 경로만 사용한다. PG18.4 core와 실제 PG18 대상 minor의 동작 동일성은 미입증이므로 설정 tuple만 맞았다고 실제 V3 지원 완료로 처리하지 않는다.
OCI `6.0.3` index 후보는 `sha256:bb0910e6a18bb9bd7cb31ae4ed40f9073148b78cb2cdb8ea8676454e0d85425c`다. child descriptor/raw manifest는 linux/amd64 `sha256:2a7a41cd7e2065b30ba389c8db0fbeaebd7ec06bb4e20f23cab8ba92180f25c7`, linux/arm64 `sha256:ddfb30ef76e97bb9a231af1fb262f0a4f2f6aa726778572a028e215922afac40`가 확인됐다. 이는 descriptor 수준이며 config/layer pull·guest compiler 실행·이미지 서명·재현 빌드는 검증되지 않았다. source lock의 arm64 후보 선정은 §7 M1-171에 기록하며 실제 toolchain 사용은 검증·별도 패킷 뒤다. 공식 npm WASM과의 동일성을 주장하지 않는다.

**후속 R3/R10 패킷의 필수 상한과 선택 조건(CPx14 N2).** native 진단 **job**은 기존 network-none·1초·256MiB를 유지한다. 별도 명시 native **build**의 후보 상한은 CPU2·메모리4GiB·PID256, 개별10분·재현2회 합계20분, 로그 각16KiB·산출물 합계32MiB다. 고정 로컬 source/toolchain만 사용하며 네트워크를 끈다. R3가 CPU/PID/메모리·전체 자식 종료·wall deadline·로그/산출물 상한을 실제 강제할 수 있는 수단을 확인하지 못하면 실행을 거부한다. 이 문서는 해당 격리 보장의 측정 결과가 아니다.
R10은 명시 custom artifactId·새 protocol revision·독립 source/build/pins가 **모두 일치할 때만** custom CJS/WASM을 선택한다. 누락·불일치·미지원 tuple은 거부/unknown·미완료이며 공식 v1 fallback으로 quote 진단 완료를 가장하지 않는다. 공식 v1의 기존 명시 실행 경로와 지원 범위는 유지한다. 일반 npm build는 고정 로컬 자산의 검증/복사만 하며 compiler·source fetch를 시작하지 않는다.
후속 순서는 **R9 source/OCI metadata 측정(M1-169 완료, toolchain 실행은 미검증) → R1 sources.lock 선정 패킷 → R5 고정 base patch 확인 → R3 별도 제한 build 패킷 → R10 배포/manifest → R3 독립 host pins → R8 독립 projection → R9 실제 PG 대조**다. 현재 source commit 읽기가 published WASM의 재현성을 증명하지 않으며 새 진단이나 R8 expected가 서로의 정답을 생성하지 않는다.

## 5. RunContext·격리·스냅샷·실패 수명

```ts
type IsolationReport = {
  requested: 'gvisor' | 'rootless-docker'; applied: 'gvisor' | 'rootless-docker' | 'unavailable';
  daemonRootless: boolean; backend: string; daemonVersion: string; runtimeVersion: string; targetUid: number | null; capDropAll: boolean; readOnlyRootfs: boolean; seccomp: string;
  cgroup: { version: number | null; driver: string; systemd: boolean; delegatedUnit: string | null; controllers: string[] };
  resources: { requested: { cpu: number; memoryBytes: number; pids: number }; measured: { cpuQuota: number | null; memoryMax: number | null; pidsMax: number | null }; probe: ArtifactRef; enforced: boolean };
  buildNetwork: 'registry-allowlist'; runNetwork: 'internal'; verified: boolean; gaps: Gap[];
};
type RunContext = {
  runId: string; epoch: string; runNonce: string; dbLease: { id: string; containerId: string; seedCursor: PgCursor }; target: Readonly<TargetSpec>; source: ArtifactRef; built: ArtifactRef;
  signal: AbortSignal; deadlineAt: number; // 실행기만 사용, Oracle/agent/파일로 넘기지 않음
  handles: { target: TargetHandle; observer: ObserverHandle; admission: AdmissionHandle;
    snapshots: SnapshotHandle; artifacts: ArtifactHandle }; // 내부 opaque capability, 직렬화 불가
  request: RuntimeRequestPort; // R3가 만든 stdio relay capability, R4/R5/R10에만 제공
};
type RuntimeRequestPort = {
  readonly transport: 'stdio-relay'; readonly leaseId: string; readonly origin: string;
  readonly deadlineAt: number; readonly maxRequests: number;
  request(input: { taskId: string; phase: 'health' | 'discover' | 'control' | 'probe';
    method: 'GET' | 'HEAD' | 'POST'; path: string; query: readonly [string, string][];
    body: null | { mediaType: 'application/json'; data: JsonData };
    deadlineAt: number; maxResponseBytes: number; signal: AbortSignal }): Promise<RuntimeResponse>;
};
type JsonScalar = null | boolean | number | string;
type JsonData = JsonScalar | { readonly [key: string]: JsonData }; // 선언된 scalar leaf의 중첩 object, 배열은 미지원
type RuntimeResponse = { ordinal: number; outcome: 'response' | 'transport_error' | 'cancelled' | 'limit';
  sent: 'confirmed' | 'not_sent' | 'unknown'; status: number | null; bodyBytes: Uint8Array; rawBodySha256: Sha256 | null; truncated: boolean };
```

transport는 stdio relay 하나로 정한다. host HTTP/loopback relay 대안은 제거한다. 고정 lease/container/port/origin 외의 authority·redirect·외부 URL·프록시·DNS 재결정은 입력에 허용하지 않는다.
path는 authority/query/fragment 없는 절대 요청 경로, query는 검증된 scalar 직렬화만 받는다. relay가 query/body bytes를 확정하며 body는 최대64KiB·원문은 메모리에서만 쓴다. JSON body의 대상 leaf는 plan의 JSON pointer/schema locator에 결속한다. sent는 실제 내부 송신 기록이며 admission 예약만으로 confirmed라 쓰지 않는다.
모든 요청은 공유 admission의 남은 cap와 min(전역 deadline, 입력 deadline)을 통과해야 한다. health/discover도 소비하며 상한을 호출자가 늘릴 수 없다. 응답 상한은 최대1MiB, 잘림/프로토콜 오류/취소는 unknown/미완료다.
R3는 signal을 후손 relay/내부 요청까지 전달하고 drain·프로세스 종료를 확인한다. bodyBytes는 private transient buffer이며 원문 저장 권한이 아니다. 허용 header/status만 따로 projection하며 새 host socket을 열지 않는다.
compose 원본 명령/볼륨/host network/privileged/devices/Docker socket/외부 endpoint를 그대로 실행하지 않는다.
검증된 effective compose를 소스 복사본에서 생성하고 승인된 app/DB·고정 이미지·tmpfs/소유 볼륨만 허용한다.
빌드 레지스트리 allowlist는 실제 egress에서 강제한다. 단순 env 설정을 차단 증거로 취급하지 않는다. 불가하면 사전 거부한다.
실행은 외부 차단 internal network, 대상 cap-drop ALL·non-root·가능한 readonly rootfs다. 쓰기 예외는 명시된 소유 tmpfs로 한정한다.
non-root UID와 rootless daemon은 따로 검증한다. gVisor 요구 미충족/실제 rootful-only 환경은 묵시적으로 통과시키지 않는다.
preflight는 cgroup v2+systemd+cpu/memory/pids controller 위임과 실제 제한 probe를 모두 요구한다. measured=null/enforced=false·미확인 backend면 target 생성 전 거부한다.
기존 `source/process.ts`의 argv-array/최소 env/abort/출력 cap 원칙을 재사용하되 Docker용 authority는 새 제한 어댑터에 둔다.
DB seed/schema hash의 초기 snapshot을 **각 control/probe 요청 전** 복원한다(`per-request`). PLAN 10 예시의 per-surface라는 이름과 다르지만 그보다 강한 요청별 대조 동일성의 명시이며 per-surface alias는 M1 schema에서 받지 않는다. 복원 실패 뒤에는 다음 요청을 보내지 않는다.
기존 api-write-state는 합성 상태 비교의 개념만 참고한다. 임의 Postgres snapshot/복원을 이미 제공한다고 가정하지 않는다.
abort/deadline/출력 상한/부분 health 실패에서도 finally로 관측 중단→최종 drain→target/DB 종료→network/volume 제거를 확인한다.
정리는 유한 별도 유예를 두고 `CleanupReport={status:'confirmed'|'error', lease:ArtifactRef, processGroupExitConfirmed:boolean, resources:{kind:string,id:string,absenceConfirmed:boolean}[], remainingOwnedIds:string[], reasons:string[]}`를 기록한다. 소유 label+실제 ID의 부재를 확인하며 daemon 전체 정리는 금지한다.
cleanup 불명·observer 손실·snapshot 오류는 반드시 error/unknown으로 보존한다. 기존 finding을 지우거나 clean 완료로 바꾸지 않는다.

## 6. 종료 코드와 보고서의 추가 계약

**A 공통 보고서 확장을 선택한다.** PLAN 10의 같은 4파일·runtime 섹션 추가를 따르며 독립 B envelope/별도 안정 계약은 목표에서 제외한다. B안에 대한 새 사람 승인을 기다리는 절차를 만들지 않는다. 실제 구현은 CP1 재검토 뒤 한다.
현재 legacy sanitiseReport는 runtime 필드를 폐기하고 Mode는 닫혀 있으며 evidence는 API-only다. 따라서 공통 Report/AgentReport의 discriminated additive union, reader/writer/sanitizer dispatch를 함께 확장한다. runtime-report.ts는 내부 projection이며 독립 주포맷이 아니다.

```ts
type Report = ScanReport | RuntimeReport; // 기존 ScanReport/Mode/FindingEvidence legacy branch는 불변
type RuntimeReport = Omit<ScanReport, 'mode' | 'checks' | 'scope'> & { mode: 'runtime'; scope?: never; checks: RuntimeCheck[];
  runtime: { revision: 'verify-m1-v1'; verifyGate: VerifyGate; scope: RuntimeScope;
    inputArtifacts: ArtifactRef[]; stages: ArtifactRef[]; cleanup: CleanupReport } };
type CheckStatus = 'completed' | 'partial' | 'error' | 'not_applicable' | 'skipped'; // 현재 CheckResult.status와 동일
type RuntimeCheck = { id: RuntimeCheckId; status: CheckStatus; findings: RuntimeFinding[];
  notes: string[]; runtime: RuntimeCheckData & { reasons: string[] } }; // 아래 id별 payload union, status 중복 없음
```

공통 schemaVersion은 기존 `1.0.0`이다. `mode=runtime`과 `runtime.revision=verify-m1-v1`를 **함께** 판별하고 runtime schema는 M1 draft로 둔다. legacy mode+runtime 혼합·revision 누락/오류는 축소/정규화하지 않고 거부한다.
RuntimeCheckId는 아래 5개다. consent/입력 거부로 아예 보고서를 만들지 않는 경로를 제외하면 각 check를 정확히 한 번 낸다. 상세의 유일한 JSON 위치는 `checks[].runtime`, run 전체의 scope/refs/cleanup/게이트는 최상위 `runtime`이다.

| checks[].id | checks[].runtime의 PLAN 10 필드·타입 | 완료/부분/오류·unknown 의미 |
| --- | --- | --- |
| `runtime.build` | `builder:string|null`, `imageDigest:string|null`, `cacheKey:string|null`, `isolation:IsolationReport|null`, `durationMs:number|null` | 이미지·입력 SHA·실제 격리 검증 완료만 completed; 일부 기록은 partial, 빌드/격리 실패는 error. 미측정 필드는 null+reason이며 성공 digest를 만들지 않음 |
| `runtime.start` | `lease:ArtifactRef|null`, `health:'passed'|'failed'|'unknown'`, `durationMs:number|null`, `instrumentation:ArtifactRef|null` | 소유 컨테이너·health·계측 확인 completed; 부분/손실 partial, health/start 실패 error, 미기동 skipped. unknown health를 passed로 대체하지 않음 |
| `runtime.surface` | `routes:{surface:SurfaceRef,provenance:Provenance[],attacked:boolean|null,reasons:string[]}[]`, `declared:number|null`, `enumerated:number` | 완전 열거 completed; 제공자/입력 해석 미해결 partial; 유효한 발견 파일 없음 error. attacked=true는 실제 송신 ledger 결속, false는 미배정/미송신 확인, 관측 불명 null |
| `runtime.coverage` | `method:'jacoco'`, `routes:{surface:SurfaceRef,files:CoverageMap['requests'][number]['files']|null,coveredFiles:number|null,coveredLines:number|null,executableLines:number|null,ratio:number|null,accounting:'exact'|'unknown',reasons:string[]}[]`, `dumpRefs:ArtifactRef[]` | 요청별 before/after/reset·class/source 매핑을 route로 집계한 경우만 completed; 일부 실패 partial, 전체 수집 실패 error. 미측정 files/count/ratio는 null, 분모0도 ratio=null+not_applicable 사유. HTTP method는 surface.method로 별도 보존 |
| `runtime.oracle.sql` | `method:'pg-ast-token-differential'`, `cases:CaseOutcome[]`, `verdictRefs:ArtifactRef[]`, `markerLedger:ArtifactRef|null`, `parserRevision:string|null` | control·관측 장벽과 모든 계획 case 평가 완료면 completed; unknown case 존재 partial, 판정 입력 손상/전체 관측 실패 error. findings의 evidence.grade/reach는 실제 Verdict만, unknown을 가짜 grade/0건 성공으로 만들지 않음 |

공유 상태 규칙: completed=요청한 범위의 신뢰 가능한 산출물 완료, partial=유효한 일부+명시된 미완료, error=해당 단계 수행/검증 실패, skipped=upstream 실패/취소로 미시작. `unknown`은 CheckStatus가 아니라 payload/CaseOutcome/reason이다.
ratio는 같은 route의 coveredLines/executableLines이며 분모>0·accounting=exact일 때만 계산한다. coveredFiles는 그 요청 창에서 도달한 고유 소스 파일 수다. 필수 reasons는 null/unknown/skip의 닫힌 사유 코드를 보존한다.
not_applicable은 명시적 비대상 범위에만 쓰며 위 5개 필수 M1 단계를 미구현/관측 실패 때문에 not_applicable로 숨기지 않는다. 수치 null은 0이 아니다. partial/error에서도 이미 검증된 finding과 provenance를 유지한다.
M1 미구현 `runtime.oracle.command/ssrf/path/xss/redirect/authz` check는 생략한다. `runtime.scope={requestedVulnClasses:['sql'],unsupportedVulnClasses:['command','ssrf','path','xss','redirect','authz'],gaps:Gap[]}`에 미지원 범위를 명시한다. 생략을 검사 완료로 세지 않는다.
`verifyGate`: 유효한 기준 이상 finding이 있으면 1 → 없고 계획된 검사/관측/정리/출판이 불완전하면 2 → 모두 완료면 0.
따라서 finding+미도달/관측 오류/cleanup 오류는 exit1이면서 status partial/error다. `--fail-on-grade` 제안 기본값은 strong, 선택지는 strong/confirmed다.
미검사 라우트 비율만으로 실패시키지 않고 별도 `--min-surface-coverage`를 명시할 때 평가한다. 빈 계획/전부 unknown은 완료가 아니다.
candidate에는 기존 severity 규칙만 적용하며 runtime confirmed로 승격하지 않는다. 게이트 정책/기준은 plan hash에 포함한다.
출판 실패 시에도 이미 검증된 finding이 있으면 CLI는 1, delivery=failed를 stderr/최종 receipt에 별도로 표시한다(새 verify만의 계약).
공통 writer는 branch를 한 번 검증해 같은 모델에서 `report.json/report.md/report.sarif/agent-report.json`을 만든다. agent-report.reportArtifact는 report.json의 정확한 raw SHA이고 agent-report는 마지막에 쓴다. manifest가 4종 raw SHA를 결속한다.
per-file atomicity를 4파일 트랜잭션/실제 최종 프로세스 종료 증명으로 부르지 않는다. receipt는 publication-only이며 최종 exit는 호출자가 확인한다. manifest/receipt 부재·불일치면 소비자는 미완료로 본다.
Finding.kind는 기존 observation/candidate/advisory다. runtime evidence는 `basis:'runtime-observation-ledger'`와 grade/reach/marker hashes/controlPairId/refs/Oracle revision을 갖는 additive 판별 분기이며 구 API evidence를 재해석하지 않는다. agent의 독립 exploit/fix verification.not_run/false도 덮어쓰지 않는다.
공통 reader/sanitizer/writer는 runtime branch를 별도 strict 분기로 처리한다. 기존 valid legacy 입력은 같은 reader·sanitizer·writer·evaluateGate/scanGate 경로로 흘러 byte/의미 해시가 그대로여야 한다. runtime을 legacy scan으로 축소 통과시키지 않는다.
agent 공통 projection에서도 legacy branch의 scanGate는 불변이다. runtime branch는 runtime.verifyGate가 유일한 권위이며 scanGate와 우선순위를 혼용하지 않는다. 구현 전 0.5 binary/구 consumer가 새 runtime까지 지원한다고 주장하지 않는다.
호환 검증은 기존 0.5 fixture/reader 불변과 **확장된 공통 reader**의 runtime 보존·검증·손상/혼합 거부를 함께 요구한다. 전자를 후자로 대체하거나 별도 B envelope 안정성으로 목표를 바꾸지 않는다. 새 타입/schema는 R1, 공통 dispatch·pipeline·4종 projection은 R10 소유다.
순서는 확정 취약점→verify 게이트→미도달→한계다. JSON/Markdown/SARIF/agent 모두 비밀 canary·원문 마커·DB 내용 누출 0을 검증한다.

### M1-150/153 / CPx12 N3 명시 공통 진입 방식의 선택·구현 단계

오케스트레이터는 M1-150의 **선택지 B(기존 공개 Scan 동작 보존 + 명시 runtime/common data 진입)**를 선택하고 R10에 M1-152를 발행했다. 같은 A 공통 Report 모델과 같은 `report.json/report.md/report.sarif/agent-report.json`을 유지한다. 여기서 B는 API 경계 선택의 이름이며 별도 B envelope/주포맷을 뜻하지 않는다. 사람 승인이나 구현 완료를 뜻하지도 않는다.
기존 공개 `sanitiseReport/toAgentReport/toReportSummary/toSarif/toMarkdown/writeReports`는 672 baseline의 **Scan 시그니처·동작**을 유지하고 선행 runtime 분류로 기존 입력을 새로 거부하지 않는다. benign whole-report forwarding Proxy를 포함해 기존 Scan sanitizer가 수용하던 JS 객체 동작을 보존한다. `sanitiseScanReport` 별칭만 남기고 원래 공개 이름을 좁히는 것으로 대신하지 않는다. 기존 scan 소비자는 이 변경 때문에 새 진입으로 옮길 필요가 없다.
새 `sanitiseCommonReport/toCommonAgentReport/toCommonReportSummary/toCommonSarif/toCommonMarkdown/writeCommonReports`는 Report union을 받는 명시 진입이다. explicit runtime/common 경계는 전체 raw Proxy를 trap0으로 거부하고 명확한 mode/top.runtime/check.runtime/runtime evidence 구조에 strict own-data 검증을 적용한다. 기존 Scan 경로에 전체 Proxy trap0 보장이나 runtime 지원을 새로 부여하지 않는다.
새 verify의 4종 writer/selector 배선은 명시 common 진입을 사용해야 한다. parseReport/readReport 및 explicit runtime parser의 data-only·상한·mixed 거부와 기존 parseScanReport/readScanReport의 경계는 유지한다. runtime.* ID 문자열만으로 namespace를 예약하지 않으며 실제 runtime 필드가 섞인 wire 입력을 Scan으로 축소 통과시키지 않는다.
serialized/plain JSON wire의 호환성과 in-process JS 객체 수용은 계속 구별한다. 8341092 단계의 전체 Proxy 거부가 기존 공개 이름까지 영향을 준 잔여 차이가 이 선택의 수정 대상이다. “valid legacy”의 뜻을 축소하지 않으며 CLI/plain JSON·확인된 class/nested Proxy/getter의 baseline 출력/추가 hook0 관측을 모든 JS 객체의 실행 안전성으로 일반화하지 않는다.
**단계:** M1-152는 R10 구현 중이고 이 문서 커밋은 API 배선·호환 복구 완료나 독립 검증을 입증하지 않는다. baseline whole Proxy/class/nested metadata의 기존 공개 Scan 출력·추가 hook 수, 명시 common의 whole Proxy trap0 거부·runtime/mixed 거부, 같은 4파일 raw SHA/legacy 회귀는 R10/R9 후속 검증으로 확인하고 CPx13에서 검토한다. 이 문서로 제품·타입·schema·기대값·보호 규칙을 바꾸거나 새 권한/안전 보장을 부여하지 않는다.

### M1-131 / runtime agent·summary의 additive projection 계약

`contracts.ts`는 기존 `AgentReport`/`ReportSummary`/Mode를 그대로 두고 `RuntimeAgentReport`, `RuntimeAgentFinding`, `CommonAgentReport=AgentReport|RuntimeAgentReport`, `CommonReportSummary=ReportSummary|RuntimeReportSummary`를 export한다. `RuntimeAgentCheck`/`RuntimeReportSummary`도 같은 contracts 경로에서 type-only 재export한다. 새 주포맷/B envelope가 아니라 같은 `agent-report.json`의 `mode=runtime`+`runtime.revision=verify-m1-v1` branch다.
agent 최상위 `runtime:RuntimeReportData`가 scope/cleanup/입력·stage refs와 유일한 권위 `runtime.verifyGate`를 보존한다. 최상위 legacy scope/scanGate는 금지한다. `checks`는 정확히5개의 `{checkIndex,checkId,status,findingIds,notes,runtime}`이며 기존 id별 runtime payload/null/reasons를 유지한다. `findings`는 findingId/checkIndex/checkId로 연결하고 `kind`는 최상위, evidence는 기존 RuntimeFindingEvidence의 basis/grade/reach/marker hashes/controlPairId/refs/oracleRevision 그대로다.
runtime agent의 `reachesFailOnGrade`는 기존 severity 기반 reachesFailOn과 다르다. remediation은 `{guidance,state:not_verified}`, 독립 verification은 항상 `{state:not_run,vulnerabilityConfirmed:false,remediationVerified:false}`다. confirmed grade도 이를 바꾸지 않는다. deliveryContract/consumerRequirements와 declared_check_statuses 기반 coverage의 의미는 legacy AgentReport와 같고 producer 인증·전체 프로젝트 분석·실제 CI 성공/최종 process exit를 증명하지 않는다.
`RuntimeReportSummary`는 version1/basis=sanitised_runtime_report/mode=runtime/revision=verify-m1-v1인 navigation이다. 표시 순서는 findings의 confirmedIds→strongIds/나머지 grade ID → 복사된 verifyGate → finding-row별 reach/unknownCases·coverage → limitations다. summary.verifyGate는 runtime.verifyGate의 동일 복사이며 재판정/별도 권위가 아니다. unknownCases는 state=unknown인 CaseOutcome과 사유를 보존하고 reach 집계는 finding 행만 세므로 전체 라우트/계이스 수로 해석하지 않는다.
summary.coverage의 declaredRoutes는 알려진 선언 분모 또는 null, enumeratedRoutes는 열거된 행 수, unknownRoutes는 attacked=null인 행 수다. unknownRoutes>0이면 attackedRoutes/unattackedRoutes는 null로 두며 부분 관측을 총계0으로 만들지 않는다. routeRatio는 선언 분모>0·완전 열거·unknown0·송신 집계 exact일 때 attackedRoutes/declaredRoutes이며 나머지는 null이다. lines는 route별 surface·coveredFiles/coveredLines/executableLines/ratio/accounting/reasons만 복사하고 겹치는 파일/줄을 합산해 가짜 project 분모를 만들지 않는다. 미측정/null·분모0·accounting unknown을 0/100%로 대체하지 않는다.
schema root는 계속 RuntimeReport만 검증한다. R10은 `wakeio.verify-artifact/v1#/$defs/RuntimeAgentReport`와 `#/$defs/RuntimeReportSummary` anchor를 별도로 검증하며 `$defs/RuntimeAgentCheck`/`RuntimeAgentFinding`도 제공한다. legacy agent/summary는 새 anchor로 통과시키지 않고 기존 소비자를 유지한다. 입력 own-data snapshot·sanitised public data·gate/summary 동일성·checkIndex/ID/집계/분모/참조 일치는 R10의 추가 의미 검증이다. schema 성공은 주장된 관측/cleanup의 진위를 인증하지 않는다.
reportArtifact는 `{name:report.json,algorithm:sha256,digest:<확정된 report.json의 정확 UTF-8 raw SHA>}`다. R10은 같은 검증·sanitize된 모델에서 report.json bytes를 먼저 확정하고 agent를 마지막에 출판한다. delivery receipt/4종 manifest·외부 신뢰/최종 exit 구분은 기존 계약을 유지한다. title/description/guidance/notes는 R10의 기존 runtime prose omission 정책을 거친 표시값일 뿐 증거가 아니며 원문 SQL/marker/tokenHashes/DTO requestHash/임의 public prose를 evidence에 넣지 않는다. 실제 writer/dispatch/selector는 R10 후속이며 이번 변경은 타입·구조 schema·소유 계약 테스트다.

## 7. CP1 이후 패킷·파일·검증 제안

이 절을 **유일한 권위 파일·테스트 목록**으로 한다. `{a,b}`는 각 파일의 정확한 열거이며 제품/테스트 경로의 임의 확장을 허용하지 않는다. 아래 신규/기존 변경은 CP1 승인 후 오케스트레이터가 경로별 패킷으로 승인한다.
역할 문서의 파일 목록은 이 절을 참조하거나 동일 경로만 재표기한다. 목록 밖 경로·이름 변경은 R1 소유 문서 수정 패킷과 CPx/승인부터 받고 구현한다. 기존 lifecycle 후보명은 쓰지 않고 아래 cleanup 테스트명으로 통일한다.

| 역할 | 정확한 제품/데이터/공유 경로(테스트는 아래 별도 목록) | 의존 | 완료/검증 |
| --- | --- | --- | --- |
| R1 | 기존 `src/contracts.ts`, `src/runtime/{types,registry}.ts`; 신규 `src/runtime/{target,artifacts,plan}.ts`, `src/runtime/packs/{schema,compile-opengrep}.ts`, `src/runtime/analyzers/framework-pack.ts`, `schemas/{target.v1,surface-inventory.v2,framework-pack.v1,verify-artifact.v1}.json` | CP1 | 구체 계약·generic Pack schema/compiler·runtime Analyzer 등록; verify-artifact schema의 additive 공통 report/check $defs, 기존 scan Analyzer/v1 불변 |
| R3 | 신규 `src/runtime/builders/{compose,compose-input,build-policy}.ts`, `src/runtime/runtimes/{jvm,jacoco,container-lifecycle,controller}.ts`, `src/runtime/{isolation,snapshots,process}.ts` | R1; 내부 실행 port를 R4/R5/R10에 제공 | trusted exec·stdio relay·Docker capability·rootless/cgroup/systemd 위임·실측 자원·PG lease/cursor·route dump·cleanup |
| R4 | 신규 `src/runtime/surfaces/{spring-actuator,openapi,inventory,refs}.ts`, `packs/spring-boot.v1.yml` | R1+R8; live R3 | Spring Pack 데이터·발견만 소유; 모든 메서드·입력 schema/serialization·raw/sanitized 출처·alias·unknown 분모 |
| R5 | 신규 `src/runtime/markers.ts`, `src/runtime/observers/{pg-log,sql-projection,pg-parser-helper}.ts`, `src/runtime/oracles/sql.ts`, `src/runtime/attacks/native-sql.ts` | R1+R8; helper 실행 R3 | GET/POST 같은 Oracle·삽입 token/AST·PG 오류 위치·control·runNonce/lease/cursor 결속; R8 기대값 불변 |
| R8 | `examples/runtime/{spring-sqli,spring-sqli-jdbc}/**`, `benchmarks/runtime-corpus.json`, `tests/fixtures/runtime-m1/**` 기대 데이터 | R1 CP1; R3/R5와 독립 | JdbcTemplate/Statement 취약·수정 쌍, V2 POST confirmed·F2 정상 바인딩·N1~N13·음성/미요청 라우트·재현 기대값; 구현 수정 금지 |
| R9 | `.handoff/evidence/M1/**`, `.github/workflows/runtime-m1.yml` | 전 패킷 병합 후 | 실제 compose 두 번·vulnerable confirmed/fixed·negative 0·route/line·시간·secret/egress·실패 cleanup; 기존 전체·compat·KPI compare, 로컬/CI 구분 |
| R10 | 기존 `src/{cli,report,compare}.ts`; 신규 `src/{init-target,runtime-report}.ts`, `src/runtime/{cli,verify}.ts`, `docs/runtime-verify/USAGE.md` | R1+R3 내부 port+R4/R5 | pipeline·공통 reader/sanitizer/writer dispatch·4종 projection·CLI/사용자 문서; runtime-report.ts는 A안의 내부 모듈 |

공유 배포 경로의 **후속 승인 제안**: R1은 `package.json`/`package-lock.json`의 strict YAML·JSON Schema 검증용 고정 dependency와 packs/schema 배포 파일 목록, R10은 `scripts/build-action-bundle.mjs`/`THIRD_PARTY_NOTICES.md`의 필요한 새 배포 자산·고지를 맡는다. legacy bundle/기존 출력 회귀를 검증한다.
기존 패키지로 충족되는지 먼저 확인하고, 안 되면 검증된 고정 dependency를 쓴다. 자체 불완전 YAML/JSON Schema 파서로 검증 목표를 축소하지 않는다. 구체 버전·SQL WASM helper 자산/파일 경로는 후속 실측 뒤 정확한 별도 경로 승인으로 남긴다.
이 명부 제안은 구현 권한을 스스로 부여하지 않는다. 위 공유 경로의 실제 수정에는 root 후속 패킷과 CPx 승인이 필수이며 M1-19에서는 package/lock/bundle builder/고지/dependency를 바꾸지 않는다.

### M1-224/227 / CPx20에 승인 요청할 root의 개발 CI 진단 경로

현재 `70ad9b6fb5a754f7661e7faca89e207729a7ea02`의 Linux required-engine CI 실패는 **미해결**이다.
R9의 `cpx19-timeout-diagnosis/README.md`와 `cpx19-timeout-comparison/{README.md,ERRATA.md}`를 함께 읽는다.
성공 기준은 약575.8초, 후보는600초 timeout이며, 출력 수집 시각·완료 duration 합은 실제 병렬 실행 경로가 아니다.
ERRATA에 따라 `zap-integration.test.ts`는7/7 완료이고 `zap.test.ts` 마지막 두 선언만 미보고다. 시작·정체 원인은 미확정이다.
이 절은 PLAN11·12의 회귀/증거를 위한 **후속 명부 제안**이며 제품·Oracle·테스트 기준 변경안이 아니다.

| 제안 소유 | 정확한 기존 경로 | 허용을 요청하는 개발 검증 범위 |
| --- | --- | --- |
| root 오케스트레이터 | `scripts/ci-test-reporter.mjs` | 안전한 임시 단조 시계 event-delivery metadata만 직접 추가한다. 기존 판정용 이벤트와 분리한다. |
| root 오케스트레이터 | `scripts/test-schemathesis.mjs` | timeout/실패에도 제한된 안전 metadata 요약을 직접 남긴다. 성공/실패·필수 시나리오 판정은 유지한다. |
| root 오케스트레이터 | `scripts/ci-process.mjs` | 전체 파일집합을 유지하는 결정적 순서의 진단과, 별도 승인된 후속 순서 실험만 직접 수행한다. |

위3개 script의 임시 안전 계측은 root가 직접 수행하는 CI orchestration 작업이며 R11·새 역할·R9 권한 확장이 아니다.
R9는 기존 `.handoff/evidence/**` 안의 evidence/prototype·검증과 `.github/workflows/runtime-*.yml` 범위만 유지하고 위 script를 수정하지 않는다.
root도 CPx20 검토와 정확한 후속 작업 범위 확정 전에는 위3개 script를 수정하지 않는다. SUBAGENTS 예외를 만들지 않는다.
보호 지침을 고치거나 명부 제안으로 구현 권한을 스스로 부여하지 않는다. R9의 `src/**`·기존 테스트/기대값 수정 권한은 없다.
`scripts/ci-verification.test.mjs`와 `.github/workflows/self-test.yml`은 읽기/기존 검증 대상으로만 두며 쓰기 명부에 추가하지 않는다.

**계측 의미와 노출 제한.** dequeue/start/end는 reporter가 해당 Node 이벤트를 **전달받은 시각**이다.
단조 시계의 상대 경과·sequence·닫힌 event type·파일 ID·이름 SHA256만으로 표현하며 실제 테스트 함수 실행 시작/끝으로 명명하지 않는다.
timeout의 active ID도 미종결 delivery 집합일 뿐 실제 실행 중이라는 증거가 아니다. 버퍼링·전달 지연·유실은 한계로 표시한다.
새 진단에서 이름은 hash만 쓰고, 경로는 소유 repo의 열거된 test allowlist 안의 상대 경로만 허용한다. 임의/외부 경로는 거부한다.
stderr/stdout 본문·Node diagnostic/error message·SQL·URI·secret·환경값을 metadata나 실패 요약으로 복사하지 않는다.
기존 판정용 이벤트의 정확한 이름/파일 매칭은 바꾸지 않는다. 새 metadata로 기존 pass/fail을 위조하거나 대체하지 않는다.
NDJSON/metadata와 요약은 기존8MiB/출력 상한 안에서 별도 행·필드·총 byte 한도를 강제하며 상한을 늘리지 않는다.
초과·불완전/손상 metadata는 제한 초과/관측 불명으로 남기고 통과 receipt를 합성하지 않는다. 새로운 자식/소켓 추적은 이 명부 밖이다.

**실험 순서.** root의 첫 임시 계측은 metadata-only이며 정렬·스케줄은 기존 그대로 둔다.
같은 Linux 원 required-engine 경로·고정 엔진/환경·전체190파일·2workers·global600초에서 실패 위치의 delivery를 먼저 관측한다.
원 source/test bytes·원 SHA 목록·전체 파일집합·테스트 선언/필수 시나리오를 빠짐없이 대조하고 입력·빌드 JS 해시를 남긴다.
허용된 harness 수정은 원/후보 SHA와 diff로 별도 식별하며 전체 source SHA가 baseline과 같다고 가장하지 않는다.
그 증거가 누적 스케줄 경로 가설을 지지할 때만 root의 **별도 패킷**으로 느린 파일을 앞에 놓는 결정적 순서를 실험한다.
순서 실험도 같은 전체190파일/동일 bytes·원 SHA·2workers/600초이며 파일 누락·중복·skip/개별 threshold 변경을 허용하지 않는다.
metadata와 순서 변경을 한 번에 실험하지 않는다. 파일 수/입력이 달라지면 동일 cohort 비교로 주장하지 않고 재검토한다.
`sourceSnapshot`의 범위·before/after 불변 검사, `validateTestEvents`의 pass/fail·zero-skip·필수 시나리오 의미는 그대로다.
공개 Scan·`runExecutionPlan`·`RunStore`·Oracle·기존 테스트 기대값과 workflow 한도도 유지한다.
이 문서 패킷은 테스트/엔진을 실행하지 않는다. 새 계측·순서 실험과 정확한 CI 재검증 전에는 원 timeout 해결이나 회귀 통과를 주장하지 않는다.

### M1-208 / CPx19에 승인 요청할 scanner 정책 경로 후보

아래는 §4 M1-208의 소유/경로 **검토 명부**다. 이번에는 이 문서만 수정한다. CPx19 승인과 root 후속 패킷 전에는 파일·자산 생성이나 기존 제품 변경을 하지 않는다. 명부가 실행 capability를 부여하지 않는다.
기존 pg-parser WASM과 별도 서버 정책 identity를 사용하며 제안 이름을 현재 배포/승인 pin처럼 해석하지 않는다.

| 역할 | 최소 신규 후보 또는 기존 재사용 경로 | 책임·후속 조건 |
| --- | --- | --- |
| R1 | 신규 `workers/pg-server-policy/native/sources.lock.json`; 기존 `src/runtime/types.ts`, `schemas/verify-artifact.v1.json` | 고정 PG18.6 source/build 입력·정책 revision·pending 핀 및 관측/강제 증거의 닫힌 계약. 미측정 SHA를 채우지 않는다. |
| R3 | 신규 `workers/pg-server-policy/native/scanner-tuple.patch`, `scripts/build-pg-server-policy.mjs` | 공통 scanner 진입의 최소 source patch와 로컬 고정 입력의 별도 제한 custom-image build recipe·감독. 필요 상한/실행 권한은 별도 검토한다. |
| R3 | 기존 `src/runtime/{process.ts,runtimes/controller.ts}` | 실제 custom image/binary·정책/DB lease의 독립 pin과 격리·negative probes·cleanup. Target recipe/자산 교체와 권한 승격을 거부한다. |
| R10 | 신규 후보 `workers/pg-server-policy/{manifest.json,THIRD_PARTY_LICENSES.txt}`; 기존 `scripts/build-action-bundle.mjs`, `THIRD_PARTY_NOTICES.md` | 생성 metadata/고지·관리 도구 배포. custom image는 소유 tool cache에서 식별하고 npm에 플랫폼 binary가 자동 포함된다고 가정하지 않는다. |
| R5 | 기존 `src/runtime/observers/{pg-log,sql-projection,pg-parser-helper,pg-parser-worker}.ts`, `src/runtime/oracles/sql.ts` | 실제 statement/parse/session/cursor와 정책 증거 결속·지원 거부 unknown. Oracle은 여전히 data-only이며 native18.4/서버18.6 동등성을 가정하지 않는다. |
| R8 | 기존 `tests/fixtures/runtime-m1/**`, `examples/runtime/{spring-sqli,spring-sqli-jdbc}/**` | 독립 설정/경로 matrix·원래 V3 및 음성/수정 기대 보존. 구현 출력에서 정답을 생성하지 않는다. |
| R9 | 기존 `.handoff/evidence/M1/**`(세부 파일은 root 패킷) | 입력/산출물 bytes·Target source 없는 고정 도구 build·앱 경로/설정·격리·실패·native/PG 대조를 독립 측정한다. |

image archive가 배포에 필요하거나 local binary안을 택하면 실제 asset 경로·크기·플랫폼/의존 자산을 실측한 뒤 canonical 명부에 정확히 추가 승인받는다. 이번에는 OCI tar/postgres binary 경로를 확정하거나 생성하지 않는다.
서버 PG18.6 source lock은 기존 `workers/pg-parser/native/sources.lock.json`의 core18.4/emsdk 입력과 섞지 않는다. 공유 package/files 변경도 필요성이 확인된 후 R1 별도 패킷으로만 한다.
후속 순서는 CPx19 명부/후보 검토 → root의 R9 입력 측정·R1 계약/핀 → R3 patch/제한 build → R10 metadata/배포 → R3 독립 host pin → R8 독립 matrix → R9 actual 대조·다음 CPx다. 각 실행은 별도 승인 범위 안에서만 한다.
새 테스트 파일은 제안하지 않는다. 기존 runtime-contracts(R1), runtime-cleanup(R3), runtime-pg-log/runtime-sql(R5), runtime-delivery(R10) 소유 테스트와 R8 matrix를 후속 패킷에서 재사용한다.

### M1-160 / CPx14 승인 native 진단 경로 명부

아래 경로/소유는 CPx14의 `e708f603a8f26a5e0fcc58ddc6d33e2e2b1fa5fc` APPROVE_WITH_NITS(exit0)로 승인됐다. 실제 파일 생성·수정은 root의 경로별 패킷으로만 하며 §7 밖 임의 확장은 금지한다. M1-168은 §4의 ABI·지원 tuple·후속 build 상한/자산 선택 조건을 정한다. M1-171은 R9 측정 source bytes와 toolchain child 후보를 lock 데이터로 선정하며 patch 봉인·R3 build는 별도 패킷이다. 현재 v1 protocol/types/context/핀을 교체하거나 이 문서로 실행 권한을 부여하지 않는다.

| 역할 | 새 경로 후보 또는 재사용할 정확한 기존 경로 | 책임·검증 |
| --- | --- | --- |
| R1 | **CPx14 승인 신규** `workers/pg-parser/native/sources.lock.json`; 기존 `src/runtime/types.ts`, `schemas/verify-artifact.v1.json` | 고정 PG/libpg_query/wrapper source commit/URL/bytes SHA·patch·toolchain/환경 digest·build 옵션의 데이터 명부, source/배포 provenance 및 새 diagnostic/context/position union을 소유한다. lock의 선언을 재현 build 증거로 부르지 않는다. |
| R5 | **CPx14 승인 신규** `workers/pg-parser/native/lexer-diagnostics.patch`; 기존 `src/runtime/observers/{pg-parser-helper,pg-parser-worker,pg-log,sql-projection}.ts`, `src/runtime/oracles/sql.ts` | 고정 upstream C/lexer·wrapper 보완 patch와 닫힌 protocol/정규화·실제 PG 오류/설정 수집·순수 Oracle 인과 검증을 소유한다. 새 TS SQL lexer·메시지 regex·수정 SQL AST로 대체하지 않는다. |
| R3 | **CPx14 승인 신규** `scripts/build-pg-parser-native.mjs`; 기존 `src/runtime/{process.ts,runtimes/controller.ts}` | 승인된 source lock/patch와 고정 compiler 환경의 별도 재현 build를 감독하고 결과 bytes를 측정한다. §4 M1-168 상한을 실제 강제할 수 없으면 실행을 거부한다. 실행 host의 독립 approval pins·trusted asset 경로를 유지하며 일반 npm build나 임의 source/target에게 compiler/VM 권한을 주지 않는다. |
| R10 | **CPx14 승인 신규** `workers/pg-parser/wakeio-pg18-diagnostics.cjs`, `workers/pg-parser/wakeio-pg18-diagnostics.wasm`; 기존 `scripts/build-action-bundle.mjs`, `workers/pg-parser/{pg-parser-worker.cjs,manifest.json}` | R3가 만든 custom 쌍의 고정 bytes를 로컬 검증/복사·배포한다. §4 M1-168의 artifactId/protocol/source/build/독립 pins가 모두 맞을 때만 선택하고 공식 v1 fallback으로 quote 완료를 가장하지 않는다. official 자산을 같은 이름으로 덮어쓰지 않는다. |
| R10 | 기존 `workers/pg-parser/{THIRD_PARTY_LICENSES.txt,LICENSE.libpg_query,COPYRIGHT.PostgreSQL}`, `THIRD_PARTY_NOTICES.md`, `dist-action/{wakeio-security-ci.mjs,THIRD_PARTY_LICENSES.txt}` | 실제 선정 source/patch/생성 loader의 고지·custom 출처와 미입증 사항을 반영하고 npm/Action의 로컬 파일·raw SHA 포함을 검증한다. 필요한 package/files/lock 변경은 기존 R1 `package.json`/`package-lock.json` 공유 절차로만 요청한다. |
| R8 | 기존 `tests/fixtures/runtime-m1/{sql-cases,sql-projections}.json`, `examples/runtime/{spring-sqli,spring-sqli-jdbc}/**` | 원래 V3 confirmed와 음성/정상 바인딩 기대를 유지하며 새 revision의 독립 ground truth/projection 적합성을 검토한다. 기존 manual projection을 actual native 출력으로 재표기하지 않는다. |
| R9 | 기존 `.handoff/evidence/M1/**`(root 패킷에서 세부 파일 지정) | native source/patch/compiler/환경과 산출물 raw SHA·재현성, 실제 PG18 설정/오류 위치·control/probe 인과·음성/Bind·유실/timeout/trap/cleanup·원문 비출판을 독립 검증한다. 구현이나 R8 expected는 수정하지 않는다. |

새 테스트 파일은 제안하지 않는다. 기존 `tests/runtime-contracts.test.ts`(R1: 새 union/핀/거부), `tests/runtime-{pg-log,sql}.test.ts`(R5: protocol·관측·순수 판정), `tests/runtime-cleanup.test.ts`(R3: 별도 build/실행 감독·실패), `tests/runtime-delivery.test.ts`(R10: source-free npm/Action 배포·손상/혼합 거부)를 각 소유 패킷에서 재사용한다. 보안 기대값은 R8 소유 파일만 참조하고 복제/완화하지 않는다. 실제 측정 증거는 R9에 남긴다.

### M1-171 / source lock 데이터 선정과 실행 전 장벽

`workers/pg-parser/native/sources.lock.json`의 닫힌 revision `wakeio.pg-parser-native-sources/v1`은 M1-170의 R9 manifest와 wrapper/core 고정 commit archive·선별 source/header/고지 bytes를 결속한다. 이 revision의 명시 키·enum만 의미가 있으며 후속 reader/builder는 unknown 키·값/경로·SHA/크기 불일치를 거부해야 한다. 현재 실행 reader나 build 구현을 추가하지 않는다.
조립 root는 각각 **`core/`, `wrapper/`**로 선정한다. 새 private 조립 디렉터리에서 각 archive의 정확한 `archiveRoot` prefix와 member 안전성을 검증한 뒤 **strip-one**하여 대응 root 아래 배치한다. 경로 탈출·링크·특수/중복 member·기존 파일 덮어쓰기는 거부한다. R5 patch 경로는 `a/core/...`/`b/core/...`, `a/wrapper/...`/`b/wrapper/...`이며 조립 root에서 patch prefix 하나만 제거한다. upstream clone/fetch나 template 자동 갱신은 사용하지 않는다. 실제 조립·patch 적용은 이번에 하지 않는다.
이 Mac/Lima profile의 toolchain 고정 후보는 upstream 선언 그대로 `emscripten/emsdk:6.0.3`의 **linux/arm64/v8 child digest**다. index·child manifest bytes와 config/layer descriptor를 보존하되 descriptor를 content 검증이나 guest compiler 실행 증거로 바꾸지 않는다. config/layer content·실행 환경·서명·재현성·published npm WASM 대응은 미검증이다. 다른 아키텍처로 자동 fallback하지 않는다.
M1-176은 승인된 `workers/pg-parser/native/lexer-diagnostics.patch`의 committed bytes(`e0e093e6fcfb14809bf0203ce10f94325b09c1c5`)만 **14,878B·SHA256 `5a3f8f36f68cc301c248d2859ab38797550d79bcfa5d34b1124571f155730831`·status:hash_sealed**로 봉인한다. 전체 상태는 pending_build_and_execution_checks이며 lock은 계속 **`ready:false/executable:false/authority:none`**이다. hash 봉인은 설치·pull·compile·실행 권한이나 준비 완료가 아니며 현재 배포 manifest/host pin/protocol/types는 바꾸지 않는다.
R5 보고의 최초 context 손상으로 인한 적용 실패2회와 수정본의 정/역방향 적용·정적 대조 성공을 구별한다. 이 봉인 시점까지 compile·실제 native 진단 실행은0이며 source/OCI 후보와 모든 기존 verification 미검증 값은 그대로다. 이후 새 구현 없이 R9 독립 검증·CPx15로 넘긴다.
M1-184는 CPx15 N1의 중복 상수 검사를 제거한 R5 commit `e489739ff4e729101ecb6f975b34187ffcd8ad24`의 Git blob을 **14,752B·SHA256 `e24e503523c6eb4111d29495c0c97f850a8c3fd26325cd5af55feccf194072de`**로 재봉인한다. lock의 나머지 필드·실행 미준비 상태는 그대로다. 이 계약 커밋 시점의 working patch는 이전 bytes이므로 root가 R3/R5를 병합하기 전 중간 상태를 일치/성공으로 검증하지 않는다.
CPx15 N3의 실제 copy-templates 실행·보존한 PG18 Makefile과의 byte 동일성 및 custom 출력/두 export 대조는 후속 승인된 제한 build 단계다. 이번 봉인은 그 실행·compile·실제 진단을 대신하지 않으며 통합 후 R9/CPx16 검증으로 이어간다.
후속 native build는 config/layer content와 실제 실행 환경, CPU2·4GiB·PID256·network-none·개별10분/2회 합계20분·로그 각16KiB·산출물 합계32MiB의 강제 수단을 검증하기 전에는 실행하지 않는다. runtime job의1초/256MiB/network-none와 별개다. 일반 npm build의 고정 로컬 자산 검증/복사 원칙도 유지한다.

### M1-83 / CPx7 승인 PostgreSQL parser 자산 명부

아래 명부는 **CPx7의 `5cf00c381a060844fd320dceec974c16037d4737` APPROVE_WITH_NITS(exit0)로 승인**됐다. 실제 변경은 root의 역할별 구현 패킷 경로/상한으로만 수행하며 §7 목록 밖 임의 확장 금지는 유지한다. M1-94는 package/lock/files와 이 설계만 반영하고 worker/자산/build/고지 구현은 후속 패킷이다.
근거는 R9 M1-81의 `.handoff/evidence/M1/pg-parser-assets/{README.md,packages.json,static.json,sources.json,manifest.json}`(측정 HEAD `6e7afc888f8600ab9b7cebdc6ac0b927df8bfd04`)이다. registry HTTPS metadata와 실제 tarball SHA512가 일치한 핀은 다음과 같다.

| 고정 입력 | R9 확인값 |
| --- | --- |
| `libpg-query@18.2.1` | `sha512-0zPlJei06//awjKmslKEwmGMSjF0n4p4OnPa3boRp8Xzl6ZnDIOddyLAsoJcJntrPCBLrWUbEwv5Laxg8BZYlA==` |
| `@pgsql/types@18.0.0` | `sha512-jtAY4JU7jdVYZ/Vv3zlZqVP+FRWZokyCLKPPCnAApiaJAElpyyiMC3HRiquBu29kSrVs+rkqZD50SUIb/zyEGw==` |
| `libpg-query`의 `wasm/libpg-query.wasm` | 1,717,872 bytes; SHA256 `355c489d8b0bf2bac28b48408f656e818852d7000e1e66a67503ad2bc7cc6062` |

최소안은 이미 고정된 esbuild로 **별도 Node CJS worker bundle + local WASM copy**를 만드는 것이다. Node CJS entry/생성 loader/`@pgsql/types`의 JS graph를 build 때 포함하고 Node builtin만 external로 남긴다. 런타임 npm 설치·bare package resolution·CDN fetch·native build는 없다. 현재 R9는 import graph만 읽었으며 bundling·local loader·실제 parse 호환은 아직 검증하지 않았다.
raw vendor 대안은 원래 CJS/ESM 상대 경로·package.json·`@pgsql/types` 해석 구조를 함께 배포해야 한다. 별도 `node_modules` vendor tree·공개 package 강제 설치·새 dependency 해석 계층을 피하려고 위 단일 worker JS 안을 추천한다. build에서도 광범위 package external 처리로 bare import를 남기지 않는다.

| 소유 | 정확한 승인 경로 | 단계·책임 |
| --- | --- | --- |
| R1 | 기존 `package.json`, `package-lock.json` | M1-94에서 `libpg-query:18.2.1`/`@pgsql/types:18.0.0`을 exact devDependencies로 고정한다. upstream 선언 `@pgsql/types:^18.0.0`은 보존하되 실제 lock 해석은 정확히18.0.0이다. npm `files`에 `workers/pg-parser`만 추가하며 기존 scripts/exports/scan API는 불변이다. |
| R5 | 기존 명부 `src/runtime/observers/pg-parser-helper.ts`; 신규 `src/runtime/observers/pg-parser-worker.ts` | helper는 닫힌 stdin/projection protocol·검증/오류 처리를 소유하고, 별도 worker entry만 package import/loadModule/parse/scan/local WASM 초기화를 소유한다. CPx7 N2대로 양쪽에 같은 명시적 protocol revision 상수를 두고 request/reply의 revision 불일치를 거부한다. Oracle은 둘의 실행 구현이나 package를 import하지 않는다. |
| R10 | 기존 `scripts/build-action-bundle.mjs` | tsc 뒤 기존 esbuild로 worker를 별도 `platform:node/format:cjs` entry로 bundle하고, 검증한 WASM·고지 copy 및 manifest 생성을 한다. Action main ESM bundle에 worker entry를 합치지 않는다. |
| R10 | 신규 `workers/pg-parser/pg-parser-worker.cjs`, `workers/pg-parser/libpg-query.wasm`, `workers/pg-parser/manifest.json` | npm/Action이 함께 사용하는 단일 로컬 자산 묶음이다. source archive의 기존 `workers` allowlist와 npm `files`를 이용하며 `dist-action` 아래 중복 사본은 만들지 않는다. JS/manifest는 승인된 build 결과, WASM은 핀된 원본 bytes이며 수동 생성물 편집은 금지한다. |
| R10 | 신규 `workers/pg-parser/THIRD_PARTY_LICENSES.txt`, `workers/pg-parser/LICENSE.libpg_query`, `workers/pg-parser/COPYRIGHT.PostgreSQL`; 기존 `THIRD_PARTY_NOTICES.md`, `dist-action/THIRD_PARTY_LICENSES.txt` | 첫 파일에 두 package의 MIT 전문을 package/version별로 싣고, BSD 및 PostgreSQL 전문은 별도 경로에 둔다. 기존 Action 고지 생성/중앙 고지와 연결한다. candidate upstream 고지를 published WASM의 입증된 source revision으로 표기하지 않는다. |
| R3 | 기존 명부 `src/runtime/{process.ts,runtimes/controller.ts}` 및 승인된 HostAdapter 경계 | trusted installation root의 위 고정 tool asset 위치만 사용한다. source/cwd/PATH/env/target가 worker 경로·manifest·WASM 위치를 선택하지 못하며 digest 검증 후 읽기 전용으로 제공한다. 실제 격리 실행 port는 root 후속 패킷 범위다. |
| R5 | 기존 명부 `tests/runtime-pg-log.test.ts` | protocol/핀 불일치·누락/손상 자산·trap/재초기화·projection 제한·원문 비노출 검증. 실제 SQL 기대값은 R8 소유 입력만 사용하고 생성/완화하지 않는다. |
| R10 | 기존 명부 `tests/runtime-delivery.test.ts` | npm packed install/Action 독립 복사에 같은 로컬 자산·고지·raw SHA 포함, `node_modules`/source TS 없는 worker graph·local WASM 경로·손상 거부·protocol revision/배포 pin 대조·main/worker 분리 검증. 기존 legacy 배포/0.5 회귀는 불변이다. |
| R3 | 기존 명부 `tests/runtime-cleanup.test.ts` | 감독 port의 1초 deadline·memory/network 강제·종료/후손·cleanup 실패 검증; mock 계약과 실제 강제 증거는 구분한다. |
| R9 | 기존 명부 `.handoff/evidence/M1/**`의 parser asset/실행 증거(root 패킷이 세부 파일 지정) | R1 lock/R10 산출물의 bytes·pin·pack/Action 포함을 독립 확인하고 실제 초기화/parse·trap/복구·자원/egress·cleanup을 검증한다. 구현/고정 기대값은 수정하지 않는다. |

`manifest.json`은 두 package의 정확한 version/integrity·선정된 원본 JS path/bytes/SHA256(`packages.json`과 대조), 전체 `package-lock.json` raw SHA256, 배포 worker JS/WASM/각 고지의 path/bytes/SHA256, esbuild 버전 및 명시적 `protocolRevision`을 결속한다. helper/worker TS의 raw SHA256은 **build provenance만** 기록하며 runtime protocol/interface identity로 사용하지 않는다. 주석/줄바꿈만 달라져도 source hash는 변할 수 있지만 protocol revision을 바꾸는 근거가 되지 않는다. manifest 자체의 raw SHA는 trusted controller의 승인 pin/Run artifact에 별도로 결속하고 자기 자신을 hash하지 않는다. 상대 경로는 위 고정 allowlist만 허용하며 hash는 생산자 인증을 대신하지 않는다.
worker는 CLI main과 다른 entry다. Action 전체 bundle의 `import.meta.url`을 보고 main 여부를 판단하는 방식으로 worker를 포함/실행하지 않는다. HostAdapter/helper는 명시적 protocol revision 상수와 배포 JS/WASM/manifest의 승인 pin을 비교한 뒤 고정 로컬 CJS를 별도 프로세스로 실행한다. 설치본에서 source TS 경로를 읽거나 source hash를 runtime 검증 전제로 요구하지 않는다. loader의 `locateFile`도 고정 로컬 WASM만 반환한다. Oracle은 파일/네트워크/시계/package import/WASM 초기화 능력이 없는 순수 data-only API로 유지한다.
R3의 외부 감독은 network none·1초·256MiB와 기존 UID/cap/read-only/CPU/PID 정책을 실제로 강제해야 한다. `runRuntimeProcess`의 timeout/PGID 정리만으로 sandbox·memory/network 제한을 입증하지 않는다. R9가 읽은 WASM memory declaration은 최소40MiB/최대1GiB이고 실제 RSS·256MiB 준수 측정이 아니다. cold load/trap·재초기화/상한/timeout·cleanup 불명은 unknown/error로 종료하며 원문 SQL/오류 excerpt를 stdout/stderr/증거에 남기지 않는다.
진행 순서는 CPx7 명부 승인 → R1 exact dependency/lock → R5 별도 worker/protocol → R10 bundle/local assets/manifest/고지 → R3 verified 실행 capability → R9 독립 실측이다. 각 구현은 별도 root 패킷으로 경로/상한을 다시 고정하며 parser 배포만으로 live SQL Oracle 완료를 주장하지 않는다.
R9 M1-86 `.handoff/evidence/M1/pg-parser-assets-errata/{ERRATA.md,ERRATA.json,manifest.json}`가 원본 cache와 고정 공식 URL 재조회 bytes(1,561B)를 대조했다. BSD notice의 correct SHA256은 `f9352c20940619a380a5e9f23cebe34d8f797cfbd747fc236a7a3e5fc8ef9b41`이고 원본 `sources.json`의 한 nibble 오류를 별도 errata로 정정했다. 기존 M1-81 증거/manifest는 불변이며 원본 manifest SHA256은 `7adfbf2b3c2f10d9baadd3aea6702ec175ae376a64d1c00f2de92bfa5f7b5c39`다. R10은 승인된 고지 경로에 이 correct pin을 적용한다. MIT 두 archive는 같은 LICENSE SHA이며 BSD/PostgreSQL 전문은 npm tarball에 들어 있지 않았다.
현재 미검증: published WASM에 대응하는 정확한 상류 source commit, publisher 서명, 재현 빌드, CJS bundle/local load·trap 복구·실제 자원 강제. package metadata의 상류 commit 선언만으로 published bytes의 source 대응을 입증하지 않으며 errata는 BSD 고지 hash만 정정한다.

#### M1-107 / CPx8 N1 전체 lock raw SHA 갱신 절차

현재 `PG_PARSER_PIN.lockSha256`/build의 `parserLock`/manifest의 `pin.lockSha256`·`build.lock.sha256`은 **package-lock.json 전체 bytes의 SHA256**을 계속 뜻한다. parser와 무관한 dependency·lock metadata/공백 변경에도 기존 build pin과 달라져 `invalid_pg_parser_build_input`으로 fail-closed하는 결합을 의도적으로 유지한다. 관련 package의 version+integrity만 정규화한 부분 hash로 바꾸는 안은 현재 미선택이며, 추후 계약 변경 검토 없이 같은 필드의 뜻을 축소하지 않는다.
이번 M1-107은 문서만 바꾼다. 현재 pin/hash·protocol revision·runtime request/reply header의 `pin.lockSha256` 비교 의미·build/lock/생성물은 그대로다. source TS hash는 기존대로 build provenance이며 설치본 runtime이 TS나 lock 원문을 읽어 검증하는 계약으로 바꾸지 않는다.
갱신이 필요하면 root가 아래 순서의 역할별 패킷을 발행해 **한 review bundle**로 통합하고, 전부 검증·CPx 승인 후 함께 승격한다. 중간 단계의 새 lock/옛 helper/옛 manifest/옛 host pin 조합을 정상 배포로 승인하지 않는다.

| 순서·소유 | 승인된 경로에서 수행할 갱신·검증 |
| --- | --- |
| 1 · root → R1 | dependency 변경 이유·정확한 version/integrity/선정 범위를 확인하고 `package.json`/`package-lock.json`을 갱신한다. parser가 그대로인 변경도 전체 lock raw SHA를 새로 계산해 요청서/후속 패킷의 결속값으로 전달한다. package별 핀 검증은 전체 lock pin의 대체가 아니다. |
| 2 · R5 | `src/runtime/observers/pg-parser-helper.ts`의 `PG_PARSER_PIN.lockSha256`을 선정된 새 전체 lock SHA에 맞춘다. worker가 포함하는 동일 helper pin과 request/reply의 exact 비교를 유지한다. dependency만 바뀌었으면 protocol revision을 임의로 올리거나 기존 pin 불일치 거부를 완화하지 않는다. |
| 3 · R10 | `scripts/build-action-bundle.mjs`의 `parserLock`을 같은 SHA에 맞추고 승인된 build로 worker CJS·local WASM·manifest/고지·Action 산출물을 재생성한다. manifest의 lock 필드/길이·배포 asset digests·build provenance를 대조한다. 생성물 수동 편집이나 현재 lock을 무조건 신뢰해 pin을 자동 채택하는 변경은 금지한다. |
| 4 · R3 | regenerated worker/manifest의 정확한 bytes SHA를 **별도 승인된 host 상수/신뢰 경로의 pin**에 반영한다. source/worker directory의 manifest를 읽어 그 안의 값을 기대 pin으로 그대로 넘기는 자기신뢰는 금지한다. 원본 경로/이름/고지 존재만으로 기대값을 만들지 않는다. |
| 5 · R9 | 선정 lock SHA·helper/build/manifest 일치, worker/WASM/manifest 실제 bytes·npm/Action 배포, old/new 혼합의 pin_mismatch/asset_mismatch 거부·legacy 회귀를 독립 검증한다. host 기대 pin은 worker 묶음과 다른 승인 근거에서 공급됐는지 확인한다. 실제 격리/WASM 동작 증거는 승인된 실행 범위 안에서 별도로 구분한다. |
| 6 · root → CPx | R1/R5/R10/R3 커밋·결속값과 R9 결과를 같은 요청서에 묶어 검토한다. 불일치/증거 누락이면 기존 승인 pin을 유지하고 승격하지 않는다. CPx 승인만으로 별도 배포/실행 권한이 생기지는 않으며 해당 root 패킷 범위를 따른다. |

N1 자체 확인은 기존 식 `reference('package-lock.json', undefined, parserLock)`과 `digest(raw) === sha256`/`requireBuild`를 읽고 메모리에서만 대조했다. parser 두 package 항목을 그대로 둔 채 `@types/node`의 lock version 한 항목만 바꾸면 raw SHA가 현재 pin과 달라져 위 조건이 실패한다. 제품 파일/lock/빌드 pin을 수정하거나 build를 재실행한 실험이 아니며, 새 의존성 버전의 존재/사용 가능성을 확인한 것도 아니다.

각 신규 테스트의 소유자·PLAN 11 항목·R8 참조를 아래처럼 고정한다. 계약/권한 검증은 Oracle 기대값과 구분하며 R8 case ID를 새로 만들지 않는다.

| 정확한 테스트 파일 | 소유자·PLAN 11 검증 / R8 case 또는 별도 계약 범위 |
| --- | --- |
| `tests/runtime-contracts.test.ts` | R1 · 고정 입력/보고서 계약: exact keys·raw SHA·schema/링크/변조·unknown/null·공통 union dispatch; 별도 계약 범위, Oracle 기대값 없음 |
| `tests/runtime-pack-compiler.test.ts` | R1 · FrameworkPack/AnalyzerProvider: 두 마이크로 source→sink·bound sanitizer 차이; R8 V1/V2/F1/F2의 독립 정적 위치 ground truth, 판정 자체를 대체하지 않음 |
| `tests/runtime-compose.test.ts` | R3 · Builder/격리: 정규화·rootless/cgroup·allowlist·image/JAR 재현·source/secret 불변; 별도 권한 검증과 R8 N11/N12 |
| `tests/runtime-jvm.test.ts` | R3 · RuntimeProfile: route dump/reset/class/source 매핑·미요청 handler uncovered; R8 V1/V2/N4 및 coverage 손실 N13 |
| `tests/runtime-cleanup.test.ts` | R3 · 격리/중단/정리: signal/deadline·후손/lease 자원 부재·relay cap/취소/손실; R8 N7/N12/N13와 별도 권한 검증 |
| `tests/runtime-surfaces.test.ts` | R4 · SurfaceProvider: 모든 메서드/parameter/provenance·ref/한도·선언 분모; R8 업무 라우트 ground truth와 별도 입력 계약 범위 |
| `tests/runtime-markers.test.ts` | R5 · AttackEngine: GET/POST route/JSON pointer·충돌0·seed/예산 재현·요청 결속; R8 V1/V2/V3/N9/N10 |
| `tests/runtime-pg-log.test.ts` | R5 · Observer: Bind·PG 위치/오류·cursor/drain·raw/secret 무보관·helper 실패; R8 F1/F2/N5~N12 |
| `tests/runtime-sql.test.ts` | R5 · Oracle: 순수 data-only·문법 승격/quote/control/unknown; R8 V1~V3/F1/F2/N1~N10, 기대값 독립 유지 |
| `tests/runtime-cli.test.ts` | R10 · 보안/종료 코드: consent zero-I/O·strict argv·help·finding+실패 우선순위; 별도 권한 계약과 R8 N12/N13 |
| `tests/runtime-init-target.test.ts` | R10 · Builder detect/FrameworkPack: 읽기 전용 감지·source 밖 신규 출력·경로/덮어쓰기 거부; 별도 계약 범위 |
| `tests/runtime-report.test.ts` | R10 · 보고서 계약: 5개 check payload/status/null·grade/reach·공통 reader/sanitizer dispatch·구 API evidence/scanGate/0.5 불변; R8 V/F/N projection |
| `tests/runtime-delivery.test.ts` | R10 · 보고서/종료 코드: 4종 raw SHA·손상/old-new 혼합·stale·출판 중단·취소/cleanup/출판 실패; 별도 delivery 계약과 R8 N13 |

기존 `tests/compat-0.5.test.ts`, `tests/runtime-{analyzers,m0-compat,registry}.test.ts` 및 기존 cli/report/agent-report/compare/KPI 검증은 읽기 전용 회귀군으로 유지한다. 새 테스트 목록으로 기존 기대값을 교체하지 않는다.
공유 contracts/report/compare/cli·보안 경계 구현은 필수 CPx에서 검토한다. R8 데이터 하위 파일은 독립 R8 패킷에 명세하되 이 절의 제품/테스트 목록을 확대하는 권한이 아니다. 생성 build/bundle은 소스 파일 수에서 분리한다.
R1 계약→R3/R4/R5→R10 순서로 통합한다. R8 독립 ground truth를 먼저 고정하고 R9가 증거를 만든다. 동시 실행은 최대4다.
고정 기대값을 제품 결과에서 재생성하거나 판정 구현자가 수정하지 않는다. R9의 증거와 구현 역할 자체 테스트를 구분한다.

## 8. CP1에서 남겨 둘 결정과 후속 범위

| PLAN 13 미결정 | 선택지와 추천(아직 확정하지 않음) |
| --- | --- |
| target 설정 위치 | 독립 `wakeio.target.yml` / compose `x-wakeio`; 검증·해시 경계를 단순하게 하는 독립 파일 추천 |
| ZAP 포함 | M0 v1 등록 유지 / verify marker 어댑터 추가; M1 SQL 세로 경로는 native만 추천, v1 ZAP은 건드리지 않음 |
| 자동 빌더 | Railpack / Buildpacks; M1 compose만, 기본 선택·라이선스 검토는 M3 |
| SQL parser/라이선스 | R5 추천 후보 PG18 + libpg-query18.2.1(MIT wrapper·상류 BSD/PostgreSQL 고지), 대안 같은 major C helper; CP1 전 미선정. npm integrity/lock/WASM SHA·PG major/설정·배포 asset을 고정하고 helper 밖 I/O는 금지 |
| 대시보드 | 1.0 동시 / CLI 뒤; M1 제외 추천 |
| 기존 scan 종료 코드 | 유지 / 별도 호환 변경; M1 유지 추천, verify 1 우선 규칙을 scan에 전파하지 않음 |

CP1 추가 확인: 결정적 마커의 논리/물리 실행 구분, A 공통 dispatch의 세부 계약, projection의 역할/위치 보존, parser/PG major·Spring pin, 실제 rootless CI 환경. 분야별 unknown을 좁은 성공으로 대체하지 않으며 이 공개 schema는 아직 M1 draft다.
M2 CP1은 14.1/14.2의 owner 요청 성공·identity 대조 실패→unknown, 접근 규칙 없는 라우트→unknown을 반드시 설계한다.
M3는 14.3 sequences/provenance·recall, M4는 빈 sequence만 agent 제안·판정 불변을 각 CP1에 넣는다. M1 범위를 넓히지 않는다.

## M1-19 첫 구현 범위

`types.ts`의 구체 데이터 포트와 `contracts.ts`의 type-only Report union을 추가한다. RuntimeReport 최상위 scope는 never이고 입력에 존재하기만 해도 거부한다. runtime.scope만 권위다(CP1-r2 N1/CPx1 N3).
`artifacts.ts`는 새 private flat vault다. 고정 이름의 상대 파일만 받고 0700 root·0600 파일·조상/leaf 링크·hardlink·특수 파일·안정 읽기·raw SHA/길이·Stage 입력 체인을 검증한다. target에 vault를 공유하지 않는다.
writeBytes/readBytes는 파일64MiB, `.json` Stage/JSON 체인 입력은 newline 포함1MiB, 체인은root 포함256개·깊이16·총64MiB로 제한한다. 큰 opaque/NDJSON 입력은 raw SHA로 결속하고 전체 JSON으로 파싱하지 않는다. put은 임시 파일 fsync 후 atomic link→임시 링크 삭제로 덮어쓰기 없이 출판하며 외부 hardlink는 읽기 거부한다.
readJsonInputBytes는 FD의 nlink/mode·이름/inode까지 확인하지 않아 vault에 그대로 쓰지 않는다. bounded JSON/own-data snapshot은 기존 snapshotJsonData를 재사용한다. 해시는 원본 생산자 인증이나 collector lease 검증의 대용이 아니다.
scope placement guard는 전체 RuntimeReport 파서가 아니다. 전체 report parser/sanitizer와 나머지 artifact schemas는 후속 패킷으로 남긴다. 이 구현으로 전체 verify 파이프라인 완료를 주장하지 않는다.

### M1-57 공통 runtime branch의 정적 schema

`schemas/verify-artifact.v1.json`의 root/$defs.RuntimeReport는 `mode=runtime`+`runtime.revision=verify-m1-v1`만 받는다. legacy 전체 파서가 아니며 기존 ScanReport 분기/Mode/0.5 출력·reader는 바꾸지 않는다. 최상위 scope/scanGate와 legacy mode 혼합·revision 누락·임의 필드는 거부한다.
canonical `$defs`는 RuntimeReport/RuntimeReportData/RuntimeCheck/RuntimeFinding/RuntimeFindingEvidence/RuntimeScope/VerifyGate/CleanupReport/IsolationReport/SurfaceProvenance/CoverageFiles/ArtifactRef/Stage다. 5개 check는 순서와 무관하게 각각 정확히 한 번이고 id별 payload만 받는다. 추가 Oracle check는 M1 지원이 아니다.
모든 concrete object는 닫힌 키·필수 키/상태 enum을 검증한다. null은 결측과 다르며 null/unknown 및 비completed에는 명시 reasons를 요구한다. accounting=unknown은 ratio=null이다. grade/reach는 기존 enum이며 Finding.kind와 API evidence를 재해석하지 않는다. 기존 Omit<Finding,'evidence'>의 optional static/control/replay 필드는 타입대로만 보존하며 runtime 판정/실행 권한을 주지 않는다.
ArtifactRef/Stage의 filename120·raw SHA256·64MiB·Stage inputs/gaps256 한도는 vault와 같다. Label의 schema maxLength=120은 Unicode code point 수이므로 Stage/Gap의 정확한 JS UTF-16 length≤120은 vault/R10이 추가 확인한다. Stage.output만 의도적으로 generic own JSON이다. Stage.inputs의 path별 중복, .json 체인 해석/깊이16·root 포함256·총64MiB·runId/epoch/runNonce/입력 순서·실제 bytes/inode/모드 검증은 기존 vault가 계속 맡는다.
호출자는 먼저 기존 snapshotJsonData(1MiB/20,000노드/깊이40)로 Proxy/getter/toJSON/상속/변이·비JSON을 거부한다. Ajv uniqueItems 전에는 검증된 snapshot만 ordinary JSON으로 복사한다. schema 자체에 accessor/Proxy 검사 권한은 없다. trusted 2020-12 schema만 strict/ownProperties/validateSchema로 컴파일하며 allErrors/$data/coerceTypes/useDefaults/removeAdditional/외부 ref/async loader/custom keyword·format은 사용하지 않는다.
R10 reader의 추가 의미 검증: (1) 날짜/버전·source 경로·image/cache digest의 생산자 형식·redaction, ref raw SHA/길이와 실제 vault 입력/lease·run 체인 결속, (2) route/provenance/공격 ordinal·snapshot·PG 관측·Verdict/marker/grade/reach의 근거 및 finding ID/참조 일치, (3) surface ID의 중복/동일 method+path·enumerated/declared의 집계, coverage 고유 파일·source SHA·covered⊆executable·각 count/분모/ratio의 일치, (4) null/unknown/미구현/빈 계획을 completed/not_applicable/0건 성공으로 처리하지 않기, isolation.verified/cleanup.confirmed의 실제 자원 부재 근거, (5) 실제 grade threshold의 blocking ID 집합과 finding 우선1→미완료2→완료0 재계산·출판 실패/4종 raw SHA 결속이다.
schema는 gate outcome↔exitCode·blocking ID의 공집합/비공집합, cleanup confirmed의 boolean/remaining ID 정합성만 추가 검사한다. 실제 실행·관측·프로세스 종료·지원 범위나 SQL 판정의 증명이 아니며 위 의미 검증을 생략해도 된다는 뜻이 아니다. 합성 계약 테스트는 R8 Oracle 기대값을 생성하지 않는다. root/emitted build schema의 JSON 동등성과 npm pack 배포 포함을 확인하며 Action bundle 연결은 R10 후속이다.

## M1-28 strict Target 입력과 CPx2 N2/N3

`target.ts`의 `parseRuntimeYaml(text):unknown`, `parseTargetSpec(input):TargetSpec`, `parseTargetYaml(text):TargetSpec`은 파일·build·network·환경 조회 권한 없는 동기 데이터 API다. 원본 YAML UTF-8 raw SHA와 안정 읽기·실제 파일/조상 링크 검증은 후속 I/O 호출자가 맡는다.
`schemas/target.v1.json`은 trusted 정적 2020-12 schema이며 Ajv가 이것만 컴파일한다. caller schema·외부 ref·async loader·$data·custom keyword/format을 받지 않는다. strict/ownProperties/validateSchema는 켜고 allErrors/coerceTypes/useDefaults/removeAdditional은 끈다. 입력 스키마 적합성과 실행 승인·대상 보안은 별개다.
YAML 1.2 core의 strict/uniqueKeys/stringKeys, merge:false/resolveKnownTags:false/customTags:[]를 사용한다. AST에서 tag·anchor·alias·merge key·보간·비정상 숫자를 거부하고 변환 전 깊이40/AST 노드20,000(키 포함)을 제한한다. 1MiB UTF-8 제한 뒤 own-data snapshot의 기존 한도를 그대로 적용한다. 복수 문서 오류를 잃지 않도록 parseDocument의 logLevel은 silent가 아닌 error다.
정규 root `source: .`만 별도 허용한다. compose/seed 파일은 비어 있지 않은 상대 segment로 제한하고 dot/dotdot·절대/drive/UNC·역슬래시·중복 slash·보간/인코딩 탈출을 거부한다. health/scope는 authority·query·fragment 없는 절대 요청 경로다. 이는 lexical 검사이며 존재/링크 검증을 대신하지 않는다.
M1 schema는 닫힌 키·compose·명시 pack id/version·per-request snapshot만 받는다. budget은 requests1~2,000/minutes1~15/rate(0,1000], startup1~900초다. rate 상한은 기존 TaskAdmission과 같다. seed32/dependencies16/scope 각1,000개·ID64자/경로512자이며 기본값 삽입·문자열 숫자 강제 변환은 없다.
[공식 yaml2.9.1 metadata](https://registry.npmjs.org/yaml/2.9.1)(ISC·직접 의존0)와 [Ajv8.20.0 metadata](https://registry.npmjs.org/ajv/8.20.0)(MIT)의 정확한 버전·sha512 integrity를 lock과 대조했다. 전이는 fast-uri3.1.9(BSD-3-Clause), fast-deep-equal3.1.3/json-schema-traverse1.0.0/require-from-string2.0.2(MIT)이며 모두 공식 registry integrity가 일치한다.
[yaml 옵션](https://eemeli.org/yaml/)과 [Ajv 보안 모델](https://ajv.js.org/security.html)을 기준으로 했고 primary npm registry audit의 현 생산 dependency 공지는0건이다. `--ignore-scripts`로만 신뢰 도구 dependency를 준비했다. 이후 공지 부재를 영구 보장하지 않는다.
배포 목록에는 원본 schemas 외에 TS가 복사한 `build/schemas`와 후속 Pack용 `packs`를 포함한다. dry-run 목록과 임시 소유 packed module import를 확인했다. source/emitted schema는 JSON 의미가 같고 TS 포맷 변경으로 raw SHA는 다르므로 후속 fingerprint는 실제 사용 자산에 결속한다. 아직 target parser의 CLI/Action 배선·Pack compiler·나머지 schema는 구현하지 않는다. R10이 후속 패킷으로 Action 자산·고지를 연결해야 하며 이번 tracked bundle은 그대로다.
CPx2 N2: `.json` 이름만 Stage 해석 후보이며 raw 이름의 Stage 모양 bytes는 검증된 opaque leaf다. N3: mkdir 뒤 실패하면 pinned dev/ino와 같은 디렉터리인지 확인하고 빈 디렉터리만 rmdir한다. 교체된 이름·링크·비어 있지 않은 경로는 삭제하지 않는다. 독립 child의 과도 umask·교체 경로 테스트로 전역 umask 오염 없이 확인한다.

## M1-38 FrameworkPack 입력과 순수 compiler

`packs/schema.ts`의 `parseFrameworkPack(input)`/`parseFrameworkPackYaml(text)`는 `framework-pack.v1.json`만 strict Ajv 2020-12로 컴파일한다. YAML·own-data snapshot 한도/거부는 기존 helper 그대로다. snapshot 뒤 ordinary JSON으로 복제하여 Ajv uniqueItems가 null-prototype 객체를 비교할 때 생기는 comparator 오류를 피한다. 원래 caller의 getter/toJSON/Proxy는 실행하지 않는다.
필수 최상위 키는 id/version/languages/detect/runtime/surfaces/sources/sinks/sanitizers이고 추가 키·raw pattern/모듈/명령은 받지 않는다. M1 언어는 java/kotlin, profile은 jvm, sink는 sql만이다. source는 annotation[] 또는 call[], sink는 call[]+정수 arg0~7이다. call은 receiver type와 member method를 점으로 구분한 데이터이고 method 끝의 단일 `*`만 지원한다. 생성자/static dispatch/임의 정규식은 현재 DSL에 없다.
배열은 schema의 min/max/uniqueItems로 닫고 source/sink/sanitizer group32개·그룹 내 symbol16개·symbol128자·ID64자·경로512자·version1~1,000,000을 제한한다. detect는 상대 file/문자열 needle 데이터, runtime env는 bounded literal strings일 뿐 실행 권한이 아니다. process loader·credential/proxy env는 거부하고 후속 R3가 주입 정책을 다시 확인한다.
surface의 source-routes와 sanitizer의 call/when.argCount/when.placeholders는 기존 계획 형태를 보존한 **예약 데이터**다. schema 통과는 지원/안전 판정이 아니다. CPx4 N4/M1-49에서 일괄 거부 대신 typed diagnostics로 미지원/미적용 사유와 원래 설정을 보존하며 SQL 규칙만 생성하도록 조정했다. query(sql,RowMapper)의 2인자를 바인딩으로 취급하지 않고 실제 overload·literal placeholder·bound 인자 증거가 없는 상태에서 전체 call/SQL arg0를 sanitize하지 않는다.
`packs/compile-opengrep.ts`의 `compileFrameworkPack(text)`는 원본 YAML UTF-8 raw SHA·키 정렬/배열 순서 보존 semantic Pack SHA·generation revision·정확한 newline 포함 rules JSON SHA를 돌려준다. ID는 Pack id/version/language/전체 semantic SHA로 결정한다. 생성물은 Opengrep이 받는 JSON rule 문서이며 YAML 입력을 실행하거나 caller pattern을 삽입하지 않는다. 출력도1MiB 상한이며 초과를 자르지 않는다.
공식 source annotation의 pattern-inside+formal parameter focus, source call의 exact:true, sink의 arg 위치 focus를 사용한다. Java/Kotlin annotation template만 언어 문법에 따라 다르며 framework명/fixture symbol 분기는 없다. receiver는 공식 metavariable-type으로 제한한다. 이는 compiler 계약 검증이며 type 해석·실제 syntax/trace 수용의 측정은 아니다.
`verification:'not_run'`, engine core1.30.0 및 executionProtocol만 기록한다. fs/process/network/clock/random/LLM port가 없고 기존 preview/Analyzer registry를 바꾸지 않는다. R3는 별도 core `-rules/-targets/-taint_intrafile` 프로토콜을 제공해야 하며 preview의 CLI형 flags를 재사용하면 안 된다. R8 handler→private helper·record accessor 추적/typed receiver와 두 마이크로는 후속 실제 core probe로 확인한다. 이번 배열/해시 일치 테스트를 M1 static gate PASS로 해석하지 않는다.
1차 문법 근거: [formal parameter/sink focus](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/advanced), [고정 Opengrep1.30 Java type constraint](https://github.com/opengrep/opengrep/blob/v1.30.0/tests/rules/metavar_type_not_java.yaml), [Kotlin type constraint](https://github.com/opengrep/opengrep/blob/v1.30.0/tests/rules/metavar_type_not_kotlin.yaml), [고정 core/CLI 옵션](https://github.com/opengrep/opengrep/blob/v1.30.0/src/osemgrep/cli_scan/Scan_CLI.ml#L631-L637). source/rules/정답은 수정하지 않는다.
별도 공유 수정 요청: 기존 target.ts의 null-prototype snapshot+Ajv uniqueItems도 서로 다른 dependency 객체 2개를 거부하는 현상을 읽기 전용으로 확인했다. 이 패킷에서 target.ts/기존 계약 테스트를 수정하지 않았으며 후속 R1 패킷으로 같은 comparator 경계와 회귀를 보완해야 한다.
## M1-41 Target uniqueItems bridge

Target 입력은 먼저 기존 snapshotJsonData로 Proxy/getter/toJSON/prototype/symbol/크기·깊이 한도를 검증한다. 그 뒤 ordinary JSON 복사본에서 정적 Ajv schema의 uniqueItems를 평가하여 null-prototype 객체의 comparator 오류를 피한다. 반환값은 원래의 private null-prototype snapshot을 유지한다.
서로 다른 pg-log dependency 서비스 2개는 generic TargetSpec schema에서 통과한다. 완전 동일 중복(키 순서가 달라도 동일)·app 서비스 중복·기존 schema 상한/unknown 키 거부는 그대로다. 이는 멀티 PG 실행 지원이 아니며 실제 M1 compose adapter의 1PG 지원 경계는 별도로 유지한다.

## M1-44 actuator 경로 데이터

PackSurface의 spring-actuator에도 optional paths:string[]을 추가한다. 기존 v1 draft의 미지정 형태는 보존하되 default를 삽입하지 않는다. 미지정은 실행 경로 권한이 아니며 후속 Provider가 unknown으로 처리해야 한다. builtin/사용자 Pack의 실제 경로는 R4가 별도 소유 패킷에서 명시한다. 제품 코드에 Spring endpoint를 기본값으로 넣지 않는다.
paths는 OpenAPI와 동일한 로컬 HTTP path 정의를 사용한다(1~16개·unique·각512자, URL/authority/query/fragment/dot segment/역슬래시/인코딩 탈출 거부). compiler는 바꾸지 않는다. 기존 Pack의 raw/semantic/rules 해시는 그대로이며 path metadata를 추가하면 전체 Pack 해시와 결속된 rule ID만 달라지고 taint formula는 같다. syntax/trace 측정이나 미지원 hint 처리 범위는 확대하지 않는다.

## M1-49 보수적 Pack disposition (CPx4 N4)

원본 builtin Spring Pack을 그대로 읽어 Java/Kotlin SQL source/sink rule을 생성한다. source-routes는 discovery-not-implemented/unsupported 진단으로 provider·원래 surface index·annotation 목록을 보존하고, SQL sanitizer는 binding-literal-overload-argument-unproven/not-applied로 원래 hint index·call/when을 보존한다. 알려지지 않은 DSL·값/환경/상한 거부는 그대로다.
진단은 closed discriminated union이며 validated Pack의 surface16+hint32, 각 symbol16/128자 상한에서 최대48개다. 배열·행·중첩 목록/when을 freeze하고 canonical diagnostics SHA도 반환한다. rules JSON+canonical diagnostics UTF-8 합계는1MiB를 넘기지 않으며 진단을 자르거나 raw 임의 필드를 복사하지 않는다. 원래 모든 설정은 raw/semantic Pack SHA와 결정적 ID에 계속 결속한다.
sanitizer hint는 pattern-sanitizers를 만들지 않는다. hint 유무와 관계없이 tainted SQL arg0의 source/sink formula를 보존한다. 최소 Pack의 기존 raw/semantic/rules SHA와 SQL generation revision은 유지한다. discovery 기능 지원·hint 적용과 SQL artifact 생성 성공을 분리하고 verification:not_run을 유지한다.
자체 검증은 원본 Pack compile·진단/해시·formula 보존 계약뿐이다. 실제 core로 원본 builtin+고정 두 쌍의 취약3위치/수정0을 재검증하는 것은 root가 발행할 R9 후속 범위다. 고정 Pack/소스/Oracle 기대값과 기존 wrapper는 수정하지 않는다.
