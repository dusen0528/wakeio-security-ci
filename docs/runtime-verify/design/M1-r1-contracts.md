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
surface의 source-routes와 sanitizer의 call/when.argCount/when.placeholders는 기존 계획 형태를 보존한 **예약 데이터**다. schema 통과는 지원/안전 판정이 아니다. compiler는 source-routes 또는 비어 있지 않은 sanitizer hint를 `unsupported_framework_pack`으로 거부한다. 힌트를 조용히 버리거나 query(sql,RowMapper)의 2인자를 바인딩으로 취급하지 않는다. 실제 overload·literal placeholder·bound 인자 증거가 없는 상태에서 전체 call/SQL arg0를 sanitize하지 않는다.
`packs/compile-opengrep.ts`의 `compileFrameworkPack(text)`는 원본 YAML UTF-8 raw SHA·키 정렬/배열 순서 보존 semantic Pack SHA·generation revision·정확한 newline 포함 rules JSON SHA를 돌려준다. ID는 Pack id/version/language/전체 semantic SHA로 결정한다. 생성물은 Opengrep이 받는 JSON rule 문서이며 YAML 입력을 실행하거나 caller pattern을 삽입하지 않는다. 출력도1MiB 상한이며 초과를 자르지 않는다.
공식 source annotation의 pattern-inside+formal parameter focus, source call의 exact:true, sink의 arg 위치 focus를 사용한다. Java/Kotlin annotation template만 언어 문법에 따라 다르며 framework명/fixture symbol 분기는 없다. receiver는 공식 metavariable-type으로 제한한다. 이는 compiler 계약 검증이며 type 해석·실제 syntax/trace 수용의 측정은 아니다.
`verification:'not_run'`, engine core1.30.0 및 executionProtocol만 기록한다. fs/process/network/clock/random/LLM port가 없고 기존 preview/Analyzer registry를 바꾸지 않는다. R3는 별도 core `-rules/-targets/-taint_intrafile` 프로토콜을 제공해야 하며 preview의 CLI형 flags를 재사용하면 안 된다. R8 handler→private helper·record accessor 추적/typed receiver와 두 마이크로는 후속 실제 core probe로 확인한다. 이번 배열/해시 일치 테스트를 M1 static gate PASS로 해석하지 않는다.
1차 문법 근거: [formal parameter/sink focus](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/advanced), [고정 Opengrep1.30 Java type constraint](https://github.com/opengrep/opengrep/blob/v1.30.0/tests/rules/metavar_type_not_java.yaml), [Kotlin type constraint](https://github.com/opengrep/opengrep/blob/v1.30.0/tests/rules/metavar_type_not_kotlin.yaml), [고정 core/CLI 옵션](https://github.com/opengrep/opengrep/blob/v1.30.0/src/osemgrep/cli_scan/Scan_CLI.ml#L631-L637). source/rules/정답은 수정하지 않는다.
별도 공유 수정 요청: 기존 target.ts의 null-prototype snapshot+Ajv uniqueItems도 서로 다른 dependency 객체 2개를 거부하는 현상을 읽기 전용으로 확인했다. 이 패킷에서 target.ts/기존 계약 테스트를 수정하지 않았으며 후속 R1 패킷으로 같은 comparator 경계와 회귀를 보완해야 한다.
## M1-41 Target uniqueItems bridge

Target 입력은 먼저 기존 snapshotJsonData로 Proxy/getter/toJSON/prototype/symbol/크기·깊이 한도를 검증한다. 그 뒤 ordinary JSON 복사본에서 정적 Ajv schema의 uniqueItems를 평가하여 null-prototype 객체의 comparator 오류를 피한다. 반환값은 원래의 private null-prototype snapshot을 유지한다.
서로 다른 pg-log dependency 서비스 2개는 generic TargetSpec schema에서 통과한다. 완전 동일 중복(키 순서가 달라도 동일)·app 서비스 중복·기존 schema 상한/unknown 키 거부는 그대로다. 이는 멀티 PG 실행 지원이 아니며 실제 M1 compose adapter의 1PG 지원 경계는 별도로 유지한다.
