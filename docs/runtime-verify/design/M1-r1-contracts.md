# M1 Spring verify 계약 제안 — CP1 검토용

기준: `a49da4ceebc2c7dd24020ecbce420f46d0ca7625`(M0 PR82 병합). 이 문서는 설계이며 구현·검증 완료 주장이 아니다. PLAN 3·4·6·7·10·11·12·13·14.4와 HANDOFF/SUBAGENTS를 따른다. CP1 승인 전 제품 코드를 쓰지 않는다.
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
  pack: { id: 'spring-boot'; version: 1 };
  entry: { port: number; health: string; startupTimeoutSec: number };
  dependencies: { service: string; observer: 'pg-log' }[];
  seed: { sql: PathRef[]; snapshot: 'per-surface' };
  scope: { include: string[]; exclude: string[] };
  budget: { maxRequests: number; maxMinutes: number; ratePerSecond: number };
};
type SourceManifest = { files: { path: PathRef; mode: number; bytes: number; sha256: Sha256 }[]; complete: boolean };
type Stage<T> = {
  schema: 'wakeio.verify-stage/v1'; stage: string; runId: string; epoch: string;
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
  provider: 'spring-actuator' | 'openapi'; input: ArtifactRef; locator: string;
  handler?: { path: PathRef; className: string; methodName: string; line?: number };
};
type Surface = SurfaceRef & {
  params: { name: string; in: 'path' | 'query' | 'header' | 'cookie' | 'body'; required: boolean }[];
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
M1 공격은 명시적으로 준비된 GET SQL 입력부터 시작한다. 다른 메서드/미해결 body/auth 입력도 Inventory에서 지우지 않고 미검사 사유를 남긴다.
출처는 발견의 근거이며 성공한 접근/권한 증거가 아니다. source-routes/crawler/agent와 sequence 추론은 이번 M1에 구현하지 않는다. `sequences`는 M3 schema 확장에서 추가하며 M1 파일에 가짜 빈 탐색 결과를 넣지 않는다.

## 4. 공격·마커·관측·커버리지·판정 데이터

```ts
type MarkerRow = {
  markerHash: Sha256; surfaceId: string; param: { in: string; name: string };
  payload: 'benign' | 'sql-quote' | 'sql-boolean'; requestOrdinal: number; controlPairId: string;
};
type MarkerLedger = { reproductionKey: Sha256; seed: string; rows: readonly MarkerRow[] };
type AttackAttempt = {
  ordinal: number; surfaceId: string; markerHash: Sha256; payloadHash: Sha256; requestHash: Sha256;
  phase: 'control' | 'probe'; snapshotHash: Sha256;
  outcome: 'response' | 'transport_error' | 'not_started'; httpStatus: number | null;
};
type AttackLog = { plan: ArtifactRef; markers: ArtifactRef; attempts: readonly AttackAttempt[] };
type Observation = {
  id: string; runId: string; epoch: string; observerSession: string; sequence: number;
  requestOrdinal: number; markerHash: Sha256; sourceContainerId: string;
  sql: { channel: 'statement' | 'bind'; shape: string; markerSpans: [number, number][];
    sqlState: string | null; dialect: 'postgres' }; evidence: ArtifactRef;
};
type CoverageMap = {
  basis: 'jacoco'; imageDigest: string; sourceSha256: Sha256; dump: ArtifactRef;
  surfaces: { surfaceId: string; before: ArtifactRef; after: ArtifactRef;
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
`shape`는 SQL 문법·마커 위치를 보존한 마스킹 구조다. 다른 literal/identifier 값은 제거하고 위치를 다시 계산한다. 가림 때문에 구문 판정이 보존되지 않으면 confirmed를 만들지 않는다. bind 값의 마커를 statement 문법 삽입으로 오인하지 않는다.
동일 라우트의 benign/probe를 동일 seed snapshot에서 직렬 실행한다. health/discovery/control/재시도도 전역 cap·deadline에 산입한다.
새 runtime admission이 기존 GET/HEAD/POST `RunAdmission`을 감싸며 v1의 허용 메서드·동작을 넓히지 않는다.
JaCoCo는 전체 run 합계만으로 라우트 귀속을 주장하지 않는다. 라우트별 reset/before/after 장벽과 단일 요청 창을 사용한다.
분모는 실행 가능한 줄과 발견된 라우트를 구분한다. 소스/클래스 매핑 실패·백그라운드 오염이면 accounting unknown, 0%/100%로 대체하지 않는다.
Observer 부착/연결/종료 drain 실패는 해당 case unknown이다. 음성 대조군의 무사건도 수집 완료 장벽 없이는 안전 증거가 아니다.
Oracle은 검증된 readonly `AttackLog+MarkerLedger`, Observation[], CoverageMap만 받는다. RunContext/파일 경로 권한/콜백은 받지 않는다. 파일·네트워크·프로세스·시계·랜덤·환경변수 접근과 동적 import를 금지한다. SQL parser는 고정 순수 함수 의존성으로만 연결한다.
statement 위치의 마커는 strong 후보이고, 대조군 차이와 파서의 literal 밖 문법 승격 또는 따옴표 불균형 오류를 확인해야 confirmed다.
상태 코드/본문 차이만으로 confirmed를 내지 않는다. parser/방언 미지원·손상 기록은 unknown/strong 한계를 명시한다. unknown은 grade를 꾸며낸 finding이 아니라 CaseOutcome+gap이다. 증거가 없는 빈 Verdict 배열을 완료/안전으로 해석하지 않는다.

## 5. RunContext·격리·스냅샷·실패 수명

```ts
type IsolationReport = {
  requested: 'gvisor' | 'rootless-docker'; applied: 'gvisor' | 'rootless-docker' | 'unavailable';
  daemonRootless: boolean; targetUid: number | null; capDropAll: boolean; readOnlyRootfs: boolean;
  buildNetwork: 'registry-allowlist'; runNetwork: 'internal'; verified: boolean; gaps: Gap[];
};
type RunContext = {
  runId: string; epoch: string; target: Readonly<TargetSpec>; source: ArtifactRef; built: ArtifactRef;
  signal: AbortSignal; deadlineAt: number; // 실행기만 사용, Oracle/agent/파일로 넘기지 않음
  handles: { target: TargetHandle; observer: ObserverHandle; admission: AdmissionHandle;
    snapshots: SnapshotHandle; artifacts: ArtifactHandle }; // 내부 opaque capability, 직렬화 불가
};
```

compose 원본 명령/볼륨/host network/privileged/devices/Docker socket/외부 endpoint를 그대로 실행하지 않는다.
검증된 effective compose를 소스 복사본에서 생성하고 승인된 app/DB·고정 이미지·tmpfs/소유 볼륨만 허용한다.
빌드 레지스트리 allowlist는 실제 egress에서 강제한다. 단순 env 설정을 차단 증거로 취급하지 않는다. 불가하면 사전 거부한다.
실행은 외부 차단 internal network, 대상 cap-drop ALL·non-root·가능한 readonly rootfs다. 쓰기 예외는 명시된 소유 tmpfs로 한정한다.
non-root UID와 rootless daemon은 따로 검증한다. gVisor 요구 미충족/실제 rootful-only 환경은 묵시적으로 통과시키지 않는다.
기존 `source/process.ts`의 argv-array/최소 env/abort/출력 cap 원칙을 재사용하되 Docker용 authority는 새 제한 어댑터에 둔다.
DB seed/schema hash에 묶인 초기 snapshot을 만들고 control/probe 전 복원 확인한다. 복원 실패 뒤에는 다음 요청을 보내지 않는다.
기존 api-write-state는 합성 상태 비교의 개념만 참고한다. 임의 Postgres snapshot/복원을 이미 제공한다고 가정하지 않는다.
abort/deadline/출력 상한/부분 health 실패에서도 finally로 관측 중단→최종 drain→target/DB 종료→network/volume 제거를 확인한다.
정리는 실행 예산과 별개인 유한 종료 유예를 둔다. `CleanupReport={status:'confirmed'|'error', remainingOwnedIds:string[], reasons:string[]}`를 기록한다. 소유 label+ID만 삭제하며 daemon 전체 정리는 금지한다.
cleanup 불명·observer 손실·snapshot 오류는 반드시 error/unknown으로 보존한다. 기존 finding을 지우거나 clean 완료로 바꾸지 않는다.

## 6. 종료 코드와 보고서의 추가 계약

`verifyGate`: 유효한 기준 이상 finding이 있으면 1 → 없고 계획된 검사/관측/정리/출판이 불완전하면 2 → 모두 완료면 0.
따라서 finding+미도달/관측 오류/cleanup 오류는 exit1이면서 status partial/error다. `--fail-on-grade` 제안 기본값은 strong, 선택지는 strong/confirmed다.
미검사 라우트 비율만으로 실패시키지 않고 별도 `--min-surface-coverage`를 명시할 때 평가한다. 빈 계획/전부 unknown은 완료가 아니다.
candidate에는 기존 severity 규칙만 적용하며 runtime confirmed로 승격하지 않는다. 게이트 정책/기준은 plan hash에 포함한다.
출판 실패 시에도 이미 검증된 finding이 있으면 CLI는 1, delivery=failed를 stderr/최종 receipt에 별도로 표시한다(새 verify만의 계약).
4종 파일은 같은 sanitised RuntimeReport에서 생성하며 agent-report는 정확한 report.json raw SHA를 가진다. agent-report를 마지막에 쓴다.
per-file atomicity를 4파일 트랜잭션/실제 최종 프로세스 종료 증명으로 부르지 않는다. receipt는 publication-only이며 최종 exit는 호출자가 확인한다. manifest/receipt 부재·불일치면 소비자는 미완료로 본다.
runtime 섹션에 입력/이미지/Pack/도구/Oracle hashes, 단계 상태, 격리, 관측 gaps, route/line coverage, cleanup, verifyGate를 둔다.
기존 Finding.kind는 유지한다. evidence.grade/reach/marker hashes/refs는 새 runtime evidence 분기에만 추가한다.
현재 FindingEvidence는 api-execution-ledger 전용이다. 그 분기를 재해석하지 않고 별도 RuntimeFindingEvidence와 구분 파서를 R1/R10이 제안한다.
runtime 보고서 타입/별도 writer 진입점으로 확장하고 기존 ScanReport/writeReports/evaluateGate·agent scanGate의 의미를 바꾸지 않는다.
verify의 권위 있는 게이트는 runtime.verifyGate로 4종 요약/CLI에 동일하게 표시한다. 기존 scanGate를 verify 성공으로 오독하지 않게 명시한다.
순서는 확정 취약점→verify 게이트→미도달→한계다. JSON/Markdown/SARIF/agent 모두 비밀 canary·원문 마커·DB 내용 누출 0을 검증한다.

## 7. CP1 이후 패킷·파일·검증 제안

아래 경로는 후속 작업 패킷에서 오케스트레이터의 쓰기 승인을 받아야 한다. 현재 패킷의 구현 권한이 아니다.

| 역할 | 쓰기 경로/신규 파일 | 의존 | 완료/검증 |
| --- | --- | --- | --- |
| R1 | `src/runtime/{types,registry,target,artifacts,plan}.ts`, `schemas/{target.v1,surface-inventory.v2,framework-pack.v1,verify-artifact.v1}.json`, `tests/runtime-contracts.test.ts` | CP1 | exact keys·크기·링크/TOCTOU·SHA tamper·버전 거부, pure import graph; 기존 v1 불변 |
| R3 | `src/runtime/builders/compose.ts`, `runtimes/jvm.ts`, 추가 승인 요청 `runtime/{verify,isolation,snapshots,process}.ts`, `tests/runtime-{compose,jvm,lifecycle}.test.ts` | R1→R4/R5 조립 | digest/격리·seed 복원·JaCoCo route 귀속·abort/deadline/cleanup 실패; 호스트 코드 실행 0 |
| R4 | `src/runtime/surfaces/{spring-actuator,openapi}.ts`, 추가 승인 요청 `runtime/packs.ts`, `packs/spring-boot.v1.yml`, `tests/runtime-{surfaces,pack}.test.ts` | R1+R8; live R3 | 모든 메서드·출처·alias·unknown 분모, Pack schema/Opengrep 변환 및 두 SQL source→sink 형태 |
| R5 | `src/runtime/markers.ts`, `observers/pg-log.ts`, `oracles/sql.ts`, 추가 승인 요청 `runtime/attacks/native-sql.ts`, `tests/runtime-{markers,pg-log,sql}.test.ts` | R1+R8; live R3/R4 | marker 결속·충돌·bind/문장 구분·대조/손실/혼입 거부; 순수 Oracle import/권한 검사 |
| R8 | `examples/runtime/spring-sqli/{vulnerable,fixed}/**`, `benchmarks/runtime-corpus.json`, `tests/fixtures/runtime-m1/**` 기대 데이터 | R1 CP1; R3/R5와 독립 | JdbcTemplate/Statement 취약·수정 쌍, 음성/미요청 라우트·모든 메서드 ground truth·두 번 재현 기대값; 구현 수정 금지 |
| R9 | `.handoff/evidence/M1/**`, `.github/workflows/runtime-m1.yml` | 전 패킷 병합 후 | 실제 compose 두 번·vulnerable confirmed/fixed·negative 0·route/line·시간·secret/egress·실패 cleanup; 기존 전체·compat·KPI compare, 로컬/CI 구분 |
| R10 | `src/cli.ts`, `src/report.ts`, 신규 `src/{init-target,runtime-report}.ts`, `tests/runtime-{cli,report}.test.ts`, 사용자 문서 | R1+R3~R5 | consent 없는 zero-I/O·v1 frozen hash·4종 raw SHA·verify 0/1/2/발견+오류·출판 실패, 구 scanGate 불변 |

공유 변경은 R1 `src/contracts.ts`의 runtime 확장 타입과 R10 `report.ts/cli.ts`에 한정 승인 요청하고, 변경 전후 CPx를 받는다.
신규 제품·schema·Pack·예제·테스트·CI 파일 목록은 위 표가 전부다. 기존 types/registry/contracts/report/cli 수정은 신규 파일 수와 구분한다.
R1 계약→R3/R4/R5→R10 순서로 통합한다. R8 독립 ground truth를 먼저 고정하고 R9가 증거를 만든다. 동시 실행은 최대4다.
고정 기대값을 제품 결과에서 재생성하거나 판정 구현자가 수정하지 않는다. R9의 증거와 구현 역할 자체 테스트를 구분한다.

## 8. CP1에서 남겨 둘 결정과 후속 범위

| PLAN 13 미결정 | 선택지와 추천(아직 확정하지 않음) |
| --- | --- |
| target 설정 위치 | 독립 `wakeio.target.yml` / compose `x-wakeio`; 검증·해시 경계를 단순하게 하는 독립 파일 추천 |
| ZAP 포함 | M0 v1 등록 유지 / verify marker 어댑터 추가; M1 SQL 세로 경로는 native만 추천, v1 ZAP은 건드리지 않음 |
| 자동 빌더 | Railpack / Buildpacks; M1 compose만, 기본 선택·라이선스 검토는 M3 |
| SQL parser/라이선스 | 순수 JS parser / libpg_query 계열 별도 수집-파싱 어댑터; 순수 Oracle에서 동작 가능한 고정 버전을 우선 평가, 의존성은 미선정 |
| 대시보드 | 1.0 동시 / CLI 뒤; M1 제외 추천 |
| 기존 scan 종료 코드 | 유지 / 별도 호환 변경; M1 유지 추천, verify 1 우선 규칙을 scan에 전파하지 않음 |

CP1 추가 확인: 결정적 마커의 논리/물리 실행 구분, runtime evidence 타입·writer, SQL 마스킹의 문법 보존 한계, 실제 rootless CI 환경.
M2 CP1은 14.1/14.2의 owner 요청 성공·identity 대조 실패→unknown, 접근 규칙 없는 라우트→unknown을 반드시 설계한다.
M3는 14.3 sequences/provenance·recall, M4는 빈 sequence만 agent 제안·판정 불변을 각 CP1에 넣는다. M1 범위를 넓히지 않는다.
