# Wakeio 다언어 실행 검증 제품 설계 계획

2026-10-27 · 최인호 · 원본: Claude Docs 설계 문서에서 내보냄. 이 파일이 Codex 작업의 기준(Source of Truth)이다.

## 1. 목표와 제품 정의

**한 줄 정의:** 어떤 언어·프레임워크로 만든 프로젝트든 격리된 컨테이너에서 빌드·실행합니다. 그다음 공격 요청이 DB·프로세스·네트워크 경계에 닿았는지 관측해 취약점을 증거로 확정하고, 검사하지 못한 범위까지 보고하는 CI 패키지입니다.

언어 지원의 핵심 결정은 **언어마다 분석 엔진을 만들지 않는다**는 것입니다. 언어별 차이는 빌드·런타임 계측·라우트 추출 어댑터에만 두고, 공격과 판정은 언어와 무관하게 하나로 유지합니다.

### 목표

1. **언어 추가 비용 최소화:** 새 언어나 프레임워크는 어댑터 1~2개와 Framework Pack(데이터 파일)으로 추가합니다. 엔진 코드는 바꾸지 않습니다.
2. **결정적 판정:** "확정" 판정은 관측 증거만으로 내립니다. LLM은 판정에 관여하지 않습니다.
3. **정직한 범위 보고:** 라우트별·코드 줄별로 도달 여부를 보고서에 남깁니다. 검사하지 못한 곳은 숨기지 않습니다.
4. **CI 시간 예산 준수:** PR 검사는 변경 범위만 짧게 보고, 전체 검사는 야간에 돌립니다.

### 비목표

- 언어별 자체 taint 엔진 구현 (JS/TS 기존 엔진은 유지만 함)
- 프로덕션이나 소유하지 않은 대상 스캔
- LLM이 취약점 여부를 판정하는 것
- 비즈니스 로직 전체의 자동 검증 (명시적으로 정의된 시나리오만 다룸)

### 차별점

| 항목 | Strix | Shannon | Wakeio (목표) |
| --- | --- | --- | --- |
| 라이선스 | Apache-2.0 | AGPL-3.0 | Apache-2.0 |
| 대상 앱 기동 | 문서상 방식 불명 | 이미 실행 중인 앱 필요 | compose·Dockerfile·자동 빌드로 직접 기동 |
| 판정 주체 | LLM 에이전트 + PoC | LLM 에이전트 + PoC | 경계 관측 Oracle (LLM 미관여) |
| LLM 필수 여부 | 필수 | 필수 | 선택 (준비 단계 보조용) |
| 커버리지 보고 | 문서상 없음 | 문서상 없음 | 라우트·줄 단위 도달 여부 |

경쟁 도구의 정보는 공개 문서 기준이며, 상세 출처는 문서 끝에 있습니다.

## 2. 현재 코드베이스 출발점

새로 만들 것보다 재사용할 것이 더 많습니다. 보고서 계약·실행 계획·예산·KPI 측정 체계는 그대로 쓰고, 문제는 언어·엔진이 코드 분기로 하드코딩된 지점들입니다.

### 재사용할 자산

| 자산 | 위치 | 새 구조에서의 역할 |
| --- | --- | --- |
| 결과 계약 | `src/contracts.ts` (`Finding`, `CheckResult`, `StaticFlow`) | 모든 어댑터의 공통 출력 형식 |
| 보고서 4종 | `src/report.ts`, `agent-report.json` | runtime 섹션만 추가 |
| Surface Inventory | `src/init-dast.ts`, `docs/surface-inventory.v1.schema.json` | 모든 라우트 발견 결과의 공통 형식 (v2로 확장) |
| 실행 계획 | `src/agent-dast/plan.ts` | "계획은 코드가 아니라 데이터" 원칙 유지, v2로 확장 |
| 요청 예산·승인 | `src/agent-dast/admission.ts`, `runner.ts`, `store.ts` | 공격 단계 예산과 실행 기록 |
| 외부 요청 통제 | `src/dast-egress.ts` | 실행 단계 네트워크 정책의 기반 |
| 프로세스 감독 | `src/source/process.ts` | 빌드·컨테이너 제어에 재사용 |
| 상태 검증 | `src/api-write-state.ts` | DB 스냅샷·복원 개념 |
| KPI·호환 테스트 | `scripts/kpi.mjs`, `tests/fixtures/compat-0.5` | 리팩터링이 동작을 바꾸지 않았는지 판별 |
| JS/TS 정적 엔진 | `src/source/dataflow.ts` 등 | Tier 1 언어의 정적 분석기로 그대로 유지 |

### 바꿔야 할 하드코딩 지점

- `src/source.ts`의 `runSource`·`runTool`이 `if (tool === "bandit")`, `if (tool === "trivy")` 분기로 도구를 고릅니다. → Analyzer 레지스트리로 교체
- `src/source/code-coverage.ts`의 `PROVIDERS`와 `supports()`가 도구↔언어 관계를 코드로 고정합니다. → 각 provider가 선언한 `languages`와 파일별 상태로 계산
- `src/agent-dast/plan.ts`의 `ExecutionEngine`이 `'native-dast' | 'schemathesis' | 'nuclei'`로 닫혀 있습니다. → AttackEngine 레지스트리
- Surface Inventory v1은 GET만 담고 `source_routes`가 항상 `unverified`입니다. → v2에서 메서드 전체와 발견 출처(provenance) 추가
- `Finding.kind`가 `observation | candidate | advisory`뿐입니다. → 관측으로 확정된 증거 등급 필드 필요 (10장)
- Express·Koa·Hono 지식이 TS 코드(`express-role.ts` 등)로 박혀 있습니다. → 신규 프레임워크는 Framework Pack 데이터로만 추가. 기존 JS 코드는 이관하지 않고 동결

## 3. 전체 아키텍처

`verify`는 8단계 파이프라인입니다. 언어에 따라 바뀌는 것은 앞의 네 단계뿐이고, 공격·관측·판정·보고는 모든 언어가 같은 코드를 씁니다.

```text
[언어별 어댑터]  1 Prepare → 2 Build → 3 Run → 4 Discover
                                                    ↓ Surface Inventory v2
[언어 독립]      8 Report ← 7 Judge ← 6 Observe ← 5 Attack
                              ↑ 정적 분석 후보 (AnalyzerProvider)
에이전트(선택)는 1~4단계에 설정·계획 데이터만 제안하며 7 Judge에는 접근하지 않는다.
```

위 줄(1~4)은 Framework Pack과 RuntimeProfile만 바꾸면 되고, 아래 줄(5~8)은 언어를 추가해도 바뀌지 않습니다. 정적 분석 후보는 판정 단계에서 런타임 커버리지와 합쳐져 도달 여부를 얻습니다.

### 단계별 산출물

| 단계 | 산출물 | 다음 단계가 쓰는 것 |
| --- | --- | --- |
| 1 Prepare | `wakeio.target.yml`, 감지 근거 | 빌드 방식, Pack ID |
| 2 Build | 이미지 digest, 격리 보고 | 실행할 이미지 |
| 3 Run | 기동·헬스 기록, 계측 설정 | 대상 origin, Observer 핸들 |
| 4 Discover | `inventory.json` (Surface Inventory v2) | 공격할 라우트 목록 |
| 5 Attack | 요청 기록 + 마커 발급표 | 마커 ↔ 라우트 대응 |
| 6 Observe | 마커가 포함된 관측 사건, 커버리지 덤프 | 판정 입력 |
| 7 Judge | Verdict 목록 (등급·도달 여부) | 보고서 내용과 게이트 |
| 8 Report | 보고서 4종, 종료 코드 | CI, 대시보드, 에이전트 |

단계 사이는 모두 파일(해시로 묶인 아티팩트)로 넘깁니다. 그래서 어느 단계에서든 멈추고 다시 시작할 수 있고, 8장의 캐시가 자연스럽게 붙습니다.

## 4. 추상화 계층

어댑터는 8종이고, 언어를 하나 추가할 때 건드리는 것은 보통 **RuntimeProfile 하나 + FrameworkPack 하나**입니다. Oracle은 순수 함수로 두고, Docker를 만지는 것은 Builder·RuntimeProfile·Observer 세 종류로 한정합니다.

| 어댑터 | 언어 의존 | 책임 | 추가 빈도 |
| --- | --- | --- | --- |
| Builder | 낮음 | 소스 → 이미지 (compose / Dockerfile / Railpack / Buildpacks) | 드묾 |
| RuntimeProfile | **높음** | 런타임 감지, 계측 env·마운트, 커버리지 수집 | 언어마다 1개 |
| SurfaceProvider | 중간 | 라우트 발견 (OpenAPI, actuator, 정적 추출, 크롤러) | 프레임워크마다 0~1개 |
| AttackEngine | 없음 | 기존 엔진 래핑, 요청에 마커 삽입 | 드묾 |
| Observer | 낮음 | DB 로그, execve/openat 추적, 카나리 서버, 내장 DB 훅 | 드묾 |
| Oracle | 없음 | 공격 기록 + 관측 → 판정 (순수 함수) | 취약점 유형마다 1개 |
| AnalyzerProvider | 중간 | 정적 분석 (기존 JS 엔진, Opengrep, Bandit, SARIF import) | 드묾 |
| FrameworkPack | **높음 (데이터)** | source·sink·라우트 규칙, 기본 포트·헬스 경로 | 프레임워크마다 1개 |

### TypeScript 시그니처 (초안)

```ts
// src/runtime/types.ts — 언어 독립 공통 타입
export type VulnClass = 'sql' | 'command' | 'ssrf' | 'path' | 'xss' | 'redirect';
export type EvidenceGrade = 'confirmed' | 'strong' | 'observed' | 'candidate';
export type Reach = 'triggered' | 'reached_not_triggered' | 'not_reached' | 'unknown';

export interface BuiltTarget {
  imageDigest: string;            // sha256:...
  builder: string;                // 'compose' | 'dockerfile' | 'railpack' ...
  cacheKey: string;               // 8장 참고
  isolation: IsolationReport;     // 실제로 적용된 격리 수준
}

export interface Builder {
  id: string;
  detect(snapshot: SourceSnapshot, spec: TargetSpec): Detection;  // 읽기만, 실행 없음
  build(spec: TargetSpec, ctx: BuildContext): Promise<BuiltTarget>;
}

export interface RuntimeProfile {
  id: 'jvm' | 'node' | 'python' | 'go' | 'php' | 'dotnet';
  detect(target: BuiltTarget, snapshot: SourceSnapshot): Detection;
  instrument(): { env: Record<string, string>; mounts: Mount[]; sidecars?: Sidecar[] };
  collectCoverage(ctx: RunContext): Promise<CoverageMap>;      // 파일·줄 단위
}

export interface SurfaceProvider {
  id: string;                     // 'openapi' | 'spring-actuator' | 'source-routes' | 'crawler'
  discover(ctx: RunContext): Promise<SurfaceResult>;           // Surface Inventory v2 항목
}

export interface AttackEngine {
  id: string;                     // 'native-dast' | 'schemathesis' | 'nuclei' | 'browser'
  plan(surfaces: Surface[], budget: Budget): AttackTask[];     // 데이터만 반환
  run(task: AttackTask, markers: MarkerIssuer, ctx: RunContext): Promise<AttackLog>;
}

export interface Observer {
  id: string;                     // 'pg-log' | 'mysql-log' | 'exec-trace' | 'file-trace' | 'egress-canary' | 'jdbc-hook' | 'py-audit'
  covers: VulnClass[];
  attach(ctx: RunContext): Promise<ObserverHandle>;
  drain(handle: ObserverHandle): Promise<Observation[]>;      // 마커가 포함된 사건만
}

export interface Oracle {
  vulnClass: VulnClass;
  judge(log: AttackLog, observations: Observation[], coverage?: CoverageMap): Verdict[];  // I/O 없는 순수 함수
}

export interface Verdict {
  surface: SurfaceRef; vulnClass: VulnClass;
  grade: EvidenceGrade; reach: Reach;
  markers: string[];              // 증거가 된 마커
  evidence: EvidenceRef[];        // 가린 로그 발췌 해시·위치
}
```

### 레지스트리 원칙

- `src/runtime/registry.ts` 한 파일에 배열로 등록합니다. 동적 플러그인 로딩은 하지 않습니다 (공급망 공격면 축소).
- 각 어댑터는 `detect()` 결과와 이유를 보고서에 남깁니다. "왜 이 런타임으로 봤는가"를 추적할 수 있게 합니다.
- Oracle은 네트워크·파일·시계에 접근하지 않습니다. 그래서 고정 관측 데이터만으로 단위 테스트와 재현이 가능합니다.
- 기존 정적 경로(`scan`)도 같은 AnalyzerProvider 레지스트리를 씁니다. 실행 모드와 정적 모드가 계약을 공유합니다.

## 5. 언어·프레임워크 지원 매트릭스

첫 대상은 **Spring Boot**입니다. 국내 백엔드 비중이 크고, actuator·springdoc·JaCoCo로 라우트와 커버리지를 표준 방식으로 얻을 수 있기 때문입니다. 그다음 Express(기존 자산)와 Flask로 판정의 언어 독립성을 검증합니다.

| 등급 | 프레임워크 | 빌드 | 커버리지 | 라우트 발견 | 정적 분석 | 도입 시점 |
| --- | --- | --- | --- | --- | --- | --- |
| A | Spring Boot (Java/Kotlin) | compose → Dockerfile → Buildpacks | JaCoCo 에이전트 | actuator mappings + springdoc + 정적 어노테이션 | Opengrep + Spring Pack | M1 |
| A | Express / Koa / Hono (Node) | compose → Dockerfile → Railpack | `NODE_V8_COVERAGE` | 기존 정적 라우트 추출 | 기존 JS/TS 엔진 | M2 |
| A | Flask / FastAPI (Python) | compose → Dockerfile → Railpack | coverage.py | `url_map` / OpenAPI(FastAPI) | Opengrep + Bandit | M2 |
| B | Django | 동일 | coverage.py | URLconf 정적 추출 | Opengrep + Bandit | M3 |
| B | Go (net/http, Gin) | 동일 | `go build -cover` + `GOCOVERDIR` | 정적 추출 + 크롤러 | Opengrep | M3 |
| C | PHP(Laravel), .NET, Ruby 등 | compose·Dockerfile만 | 없음 (미보고로 표시) | OpenAPI + 크롤러 | Opengrep 또는 SARIF import | 1.0 이후 |

- **A등급:** 빌드·커버리지·라우트·Oracle 모두 지원. 보고서에 줄 단위 도달 여부 표시.
- **B등급:** Oracle은 동일하지만 라우트 발견이 정적·크롤러에 의존. 보고서에 발견 한계 명시.
- **C등급:** 경계 Oracle만 동작. 커버리지는 `unknown`으로 남김.
- Oracle은 모든 등급에서 같습니다. 등급은 "얼마나 넓게 찾는가"를 나누고, "찾은 것을 얼마나 확실히 판정하는가"는 나누지 않습니다.

### Framework Pack 형식 예시 (Spring)

한 파일에 런타임 설정, 라우트 발견, 정적 규칙을 모읍니다. 정적 규칙은 빌드 시 Opengrep taint 규칙으로 변환합니다.

```yaml
# packs/spring-boot.v1.yml
id: spring-boot
version: 1
languages: [java, kotlin]
detect:
  anyFile: [pom.xml, build.gradle, build.gradle.kts]
  contains: ["org.springframework.boot"]
runtime:
  profile: jvm
  env:                                  # 우리가 띄우는 컨테이너에만 주입
    MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: "health,mappings"
    SPRINGDOC_API_DOCS_ENABLED: "true"
  defaultPort: 8080
  health: /actuator/health
surfaces:
  - provider: spring-actuator          # GET /actuator/mappings
  - provider: openapi
    paths: [/v3/api-docs]
  - provider: source-routes            # 없거나 막혔을 때 정적 보완
    annotations: [GetMapping, PostMapping, PutMapping, DeleteMapping, PatchMapping, RequestMapping]
sources:                                # 요청 입력
  - annotation: [RequestParam, PathVariable, RequestBody, RequestHeader, CookieValue]
  - call: ["HttpServletRequest.getParameter", "HttpServletRequest.getHeader"]
sinks:
  sql:
    - call: ["JdbcTemplate.query", "JdbcTemplate.update", "JdbcTemplate.execute"]
      arg: 0
    - call: ["EntityManager.createNativeQuery", "EntityManager.createQuery", "Statement.execute*"]
      arg: 0
  command:
    - call: ["Runtime.exec", "ProcessBuilder.<init>", "ProcessBuilder.command"]
  ssrf:
    - call: ["RestTemplate.*ForObject", "RestTemplate.exchange", "WebClient.*.uri", "URL.<init>"]
      arg: 0
  redirect:
    - return: { prefix: "redirect:" }
  path:
    - call: ["Files.read*", "new File", "FileInputStream.<init>"]
  xss:
    - template: { engine: thymeleaf, attr: "th:utext" }
sanitizers:
  sql:
    - call: ["JdbcTemplate.*"]
      when: { argCount: ">=2", placeholders: true }   # 바인딩 사용 시 제외
```

- Pack은 데이터이므로 JSON Schema로 검증하고, 변경은 버전·해시로 보고서에 남깁니다 (기존 ruleset fingerprint와 같은 방식).
- Pack을 추가해도 Oracle은 그대로입니다. Pack은 탐색 범위와 정적 후보만 늘립니다.

## 6. 경계 Oracle 설계

판정은 "마커가 어떤 역할로 경계에 도착했는가"로 내립니다. 마커가 단순히 보이는 것과, 마커에서 파생된 값이 **문법·실행 대상으로 승격**된 것을 구분하는 게 핵심입니다.

### 마커 설계

- 형식: `wk` + 실행별 접두 4자 + 요청별 base32 8자 (예: `wk7q2m` + `h4kd9x2a`). 소문자·숫자만 써서 대부분의 입력 검증을 통과합니다.
- 모든 마커는 발급 시 기록합니다: 마커 → (라우트, 파라미터, 페이로드 종류, 요청 번호). 기존 `store.ts`의 실행 기록에 합칩니다.
- 평문 값은 보고서에 남지 않고 해시만 남깁니다. 관측 로그도 마커가 없는 줄은 버립니다 (대상 데이터 최소 보관).

### 유형별 판정 조건

| 유형 | 페이로드 방식 | Observer | strong (강한 증거) | confirmed (확정) |
| --- | --- | --- | --- | --- |
| SQLi | `wk…'`, `wk…' OR 'wk…'='wk…` | `pg-log`(`log_statement=all`), `mysql-log`, 내장 DB는 `jdbc-hook`·`py-audit` | 마커가 바인딩 파라미터가 아닌 **문장 텍스트**에 있음 (문자열 조립) | SQL 파서로 분석했을 때 마커 뒤 토큰이 리터럴 밖 **구문**으로 해석됨, 또는 따옴표 불균형 구문 오류 |
| 명령 실행 | `;/tmp/wk…`, `$(/tmp/wk…)` (존재하지 않는 경로) | `exec-trace` (추적 사이드카가 PID 네임스페이스 공유, execve 기록) | 마커가 셀 인자 문자열에 포함 | `/tmp/wk…` 경로에 대한 **execve 시도** 기록 (ENOENT여도 확정, 실제 유해 실행 없음) |
| SSRF | `http://wk….canary.internal/` | `egress-canary` (내부 DNS + HTTP 카나리) | 마커 호스트 DNS 조회 | 카나리에 마커 호스트로 **HTTP 요청 도착** |
| 경로 조작 | `../../../tmp/wk…` | `file-trace` (openat) | 마커가 들어간 경로로 open 시도 | 정규화된 경로가 **앱 루트 밖**을 가리킴 |
| XSS | `<wk…>`, `"><script>__wk('wk…')</script>` | 응답 본문 + 헤드리스 브라우저 | 인코딩 없이 반영 | 브라우저에서 `__wk` 콜백이 **실제 호출**됨 |
| 오픈 리디렉트 | `https://wk….canary.internal/` | 응답 헤더 | `Location`에 마커 포함 | `Location`의 origin이 마커 호스트 |

### 증거 등급과 도달 여부

| 등급 | 의미 | 게이트 기본값 |
| --- | --- | --- |
| confirmed | 경계에서 문법·실행 승격까지 관측 | 실패 (exit 1) |
| strong | 마커가 위험 위치에 도달했지만 승격은 미확인 | 실패 (`--fail-on`으로 조절) |
| observed | 반영·로그 등 간접 증거만 | 경고 |
| candidate | 정적 분석 후보 (실행 증거 없음) | 기존 규칙 유지 |

도달 여부(`reach`)는 커버리지로 별도 기록합니다. 정적 후보의 sink 줄에 공격이 도달했는지에 따라 `triggered` / `reached_not_triggered` / `not_reached` / `unknown`으로 나눕니다.

### 오판 방지 원칙

- **대조군 필수:** 같은 라우트에 무해한 마커(예: `wk…` 단독)도 보내고, 두 관측의 차이로 판정합니다. 기존 차등 검사(differential) 계약과 같은 원칙입니다.
- **고정 예제로 검증:** 모든 Oracle은 취약 버전·수정 버전 쌍을 갖습니다. 수정 버전에서 `confirmed`가 나오면 회귀 실패입니다.
- **관측 실패는 미완료:** Observer가 붙지 못하면 해당 유형은 `unknown`입니다. 절대 "안전"으로 표시하지 않습니다.
- **권한(BOLA/IDOR·테넌트 격리) 판정:** 14.1의 권한 Oracle을 따른다 (M2).

## 7. 보안·격리 모델

실행 모드는 대상 코드를 실행하므로 **기존 `scan`과 완전히 분리된 서브커맨드**로 둡니다. `scan`의 "대상 코드를 실행하지 않음" 약속은 그대로 유지됩니다. Gradle 공식 블로그도 빌드는 설계상 코드를 실행하며 `gradle help`조차 위험할 수 있다고 경고합니다.

### 동의

- `verify`는 `--execute-target-consent`가 없으면 거부합니다 (기존 `--active-consent`와 같은 패턴).
- 대상은 사용자가 제공한 소스에서 띄운 컨테이너뿐입니다. 외부 URL을 공격 대상으로 받지 않습니다.

### 단계별 정책

| 단계 | 네트워크 | 비밀값 | 권한·자원 |
| --- | --- | --- | --- |
| 빌드 | 패키지 레지스트리 허용 목록만 (Maven Central, npm, PyPI, Go proxy). 사내 레지스트리는 설정으로 명시 추가 | 없음. CI 토큰·클라우드 자격 증명 전달 금지 | rootless, CPU·메모리·시간 제한, 소스는 복사본 마운트 |
| 실행 | `--internal` 네트워크. 외부 차단, 카나리·의존 서비스만 통신 | 테스트 계정·합성 자격 증명만. 값은 보고서에 남기지 않음 | `cap-drop ALL`, 읽기 전용 루트파일시스템 (가능한 경우) |
| 관측 | 추적 사이드카만 `SYS_PTRACE` 보유, 대상 컨테이너는 미보유 | 해당 없음 | 마커 없는 사건은 저장하지 않음 |
| 정리 | 컨테이너·네트워크·볼륨 삭제 확인 | 해당 없음 | 정리 미확인은 `error` (기존 repair의 cleanup 원칙) |

### 격리 수준 보고

- gVisor(`runsc`)가 있으면 사용하고, 없으면 rootless Docker로 내려갑니다. 실제 적용된 수준을 `isolation` 필드로 보고서에 남깁니다.
- `--require-isolation=gvisor`를 주면 낮은 수준에서는 실행을 거부합니다.

### CI 규칙

- 포크 PR에서는 실행하지 않습니다. `pull_request_target`에서도 금지합니다. 예제 워크플로는 같은 저장소 PR·main push·야간 스케줄만 제공합니다.
- 워크플로 권한은 `contents: read`만 줍니다. 보고서는 비공개 아티팩트로 올립니다.
- GitHub 호스트 러너에서는 Docker를 쓸 수 있지만 gVisor가 기본으로 없을 수 있습니다. 설치 스크립트를 제공하되 미설치는 보고서에 표시합니다 (M3에서 확인).

### 에이전트 관련 위협

- 대상 코드·주석·README는 프롬프트 인젝션 경로입니다. 에이전트 출력은 스키마 검증을 통과한 데이터만 받고, 판정·게이트·네트워크 정책에는 접근할 수 없습니다 (9장).

## 8. 캐시·증분 실행 설계

캐시는 프로세스 내부 메모이제이션(`@cache`)이 아니라 **해시를 키로 쓰는 영속 캐시**입니다. CI는 실행마다 새 프로세스·새 러너이기 때문입니다. 원칙은 하나입니다: **키에서 하나라도 빠지면 오래된 "안전" 결과가 통과하므로, 모르면 캐시를 쓰지 않는다.**

| 캐시 층 | 키 | 무효화 조건 | 위험도 | 도입 |
| --- | --- | --- | --- | --- |
| 빌드 의존성 | lockfile 해시 (BuildKit cache mount: `~/.m2`, `~/.gradle`, npm, pip) | lockfile 변경 | 낮음 | M1 |
| 이미지 | 소스 스냅샷 해시 + 빌드 설정 + builder 버전 | 어느 하나라도 변경 | 낮음 | M1 |
| 런타임 준비 | 시드 데이터 해시 + 스키마(마이그레이션) 해시 | 시드·마이그레이션 변경 | 낮음 | M2 |
| 정적 분석 | 파일 SHA + 파서·ruleset·Pack 버전 | 파일 또는 규칙 변경 | 중간 | M3 |
| **검사 결과** | 라우트 + 그 라우트가 거친 파일들의 해시 + 이미지 digest + 설정·env 해시 + 엔진·Oracle·Pack 버전 + 정책 파일 해시 | 아래 참고 | **높음** | M5 |

### 검사 결과 재사용 규칙

- 이전 실행의 런타임 커버리지로 "라우트 X가 거친 파일 목록"을 저장합니다. 이번 변경이 그 파일을 건드리지 않았을 때만 재사용합니다 (테스트 영향 분석 방식).
- 빌드 파일·설정 파일(`application.yml` 등)·lockfile·Pack 중 하나라도 바뀜면 **전체 무효화**합니다. 리플렉션·DI 설정·공용 라이브러리 변경은 커버리지가 놓칠 수 있기 때문입니다.
- 커버리지가 `unknown`인 라우트(C등급 언어)는 재사용하지 않습니다.
- OSV 같은 advisory 결과는 코드가 같아도 바뀌므로 캐시하지 않거나 advisory DB 버전을 키에 넣습니다.

### 보고서 표기

- 재사용한 판정은 `reused: { fromRunId, cacheKey, measuredAt }`을 달고, 새로 관측한 것처럼 보이지 않게 합니다.
- 요약에 "신규 관측 N건 / 재사용 M건"을 분리해 표시합니다.

### 실행 프로필

| 프로필 | 용도 | 캐시 | 범위 |
| --- | --- | --- | --- |
| `pr` | PR 검사 | 전체 층 사용 | 변경 영향 라우트 + 신규 라우트 |
| `full` | 야간·릴리스 전 | 빌드·이미지만 사용, 검사 결과는 미사용 | 전체 라우트 |

### 캐시 오염 방지

- 캐시는 신뢰 경계별로 나눕니다. main에서 만든 캐시는 PR이 읽을 수만 있고, PR이 쓴 캐시는 main이 읽지 않습니다.
- 검사 결과 캐시는 서명 대신 내용 해시를 다시 계산해 확인합니다 (기존 보고서 raw SHA 바인딩과 동일).

## 9. 에이전트 역할과 경계

LLM은 준비(띄우기)와 탐색(더 많이 보기)을 돕고, **판정과 게이트에는 접근하지 않습니다.** 에이전트 없이도 제품은 동작하고, 에이전트는 빌드 성공률과 라우트 도달률을 올리는 선택 기능입니다.

| 에이전트 | 입력 | 출력 (데이터만) | 측정 KPI |
| --- | --- | --- | --- |
| Build Doctor | 빌드 로그 (마스킹), 빌드 파일 | `wakeio.target.yml` 패치 (JDK 버전, 빌드 명령, 환경변수 이름) | 빌드 성공률 향상폭 |
| Env·Seed Doctor | 기동 로그, `application.yml`, compose | 의존 서비스 정의, 합성 설정값, 시드 SQL | 헬스체크 통과율 |
| Auth Flow Writer | 로그인 라우트, 보안 설정 | 테스트 계정 생성·로그인 절차 (계획 데이터) | 인증 필요 라우트 도달률 |
| Scenario Writer | Surface Inventory, 미도달 라우트 목록 | 추가 공격 작업 (실행 계획 v2 항목) | 커버리지 증가폭 |

### 코드워커 방식의 적용

1. 에이전트는 계획을 세우고, 결과를 **스키마가 있는 데이터 파일**로 냅니다 (설정 패치, 계획 v2 항목).
2. 결정적 실행기가 스키마·예산·정책을 검증한 뒤 실행합니다. 에이전트가 만든 쉘 명령을 호스트에서 직접 실행하지 않습니다.
3. 에이전트에는 요약된 결과만 돌려줍니다 (성공 여부, 오류 코드, 마스킹된 로그 발췌). 컨텍스트·비용을 줄이는 방식입니다.
4. 루프는 횟수·시간·비용 상한을 갖고, 상한에 도달하면 "미완료"로 보고합니다.

### 하지 않는 일

- 취약점 여부 판정, 증거 등급 변경, 게이트 결정
- 네트워크 정책·격리 수준·예산 변경
- 비밀값 읽기, 원본 저장소 수정·커밋

### 런타임

Codex SDK와 Claude SDK를 모두 provider로 둡니다. 기존 `src/agent-provider.ts`를 확장하고, provider 선택은 설정으로 합니다. 소스 업로드 동의는 repair와 같은 방식으로 별도로 받습니다.

## 10. CLI·설정·보고서 계약

새 기능은 기존 패키지의 서브커맨드 3개로 추가합니다. 기존 `scan`·`init`·`init-dast`의 플래그와 종료 코드 의미는 바꾸지 않습니다.

### 서브커맨드

| 명령 | 역할 | 대상 코드 실행 |
| --- | --- | --- |
| `init-target --source DIR` | 소스를 읽어 프레임워크·빌드 방식을 감지하고 `wakeio.target.yml` 초안 생성 | 없음 |
| `doctor --runtime` | Docker·gVisor·추적 권한·캐시 상태 점검 | 없음 |
| `verify --target FILE --execute-target-consent --out DIR [--profile pr\|full]` | 빌드 → 실행 → 발견 → 공격 → 관측 → 판정 → 보고 | **있음** (격리 컨테이너 안) |

추가 플래그 후보: `--cache DIR`, `--require-isolation gvisor`, `--fail-on-grade confirmed|strong`, `--agent codex|claude|none`, `--max-minutes N`.

### `wakeio.target.yml` 예시 (Spring + Postgres)

```yaml
version: 1
project: order-service
build:
  kind: compose                 # compose | dockerfile | auto
  file: docker-compose.yml
  service: app                  # 공격 대상 서비스
pack: spring-boot               # 생략 시 자동 감지
entry:
  port: 8080
  health: /actuator/health
  startupTimeoutSec: 180
dependencies:
  - service: db
    observer: pg-log            # log_statement=all 자동 주입
seed:
  sql: [seed/test-data.sql]
  snapshot: per-surface         # 라우트마다 DB 복원
accounts:                       # 값은 환경변수 이름만
  - name: owner
    usernameEnv: WAKEIO_OWNER_USER
    passwordEnv: WAKEIO_OWNER_PASS
  - name: other
    usernameEnv: WAKEIO_OTHER_USER
    passwordEnv: WAKEIO_OTHER_PASS
login:
  kind: form                    # form | bearer | none | agent
  path: /login
scope:
  include: ["/api/**"]
  exclude: ["/api/admin/shutdown"]
budget:
  maxRequests: 2000
  maxMinutes: 15
```

### 보고서 추가 필드

기존 4개 보고서(md·json·sarif·agent-report)를 그대로 쓰고, `runtime` 섹션과 새 check ID를 추가합니다.

- **check ID:** `runtime.build`, `runtime.start`, `runtime.surface`, `runtime.coverage`, `runtime.oracle.sql`, `runtime.oracle.command`, `runtime.oracle.ssrf`, `runtime.oracle.path`, `runtime.oracle.xss`
- **`runtime.build`:** builder, imageDigest, cacheKey, isolation, 소요 시간
- **`runtime.surface`:** 라우트별 발견 출처(actuator / openapi / source / crawler / agent)와 공격 여부
- **`runtime.coverage`:** 라우트별 도달 파일·줄 수, 전체 대비 비율, 수집 방식
- **Finding 확장:** 기존 `kind`는 유지하고 `evidence.grade`와 `evidence.reach`를 추가합니다. 기존 소비자가 깨지지 않게 하기 위함이며, compat-0.5 고정 데이터로 호환성을 확인합니다.
- **요약 순서:** 확정 취약점 → 게이트 → 미도달 라우트 → 한계. 평가 때 지적한 "한계 설명이 결과를 가리는 문제"를 새 섹션부터 피합니다.

### 종료 코드

| 코드 | `verify`에서의 의미 |
| --- | --- |
| 0 | 계획된 검사 완료, 기준 이상 판정 없음 |
| 1 | 기준 이상 판정 있음 (미도달 라우트가 있어도 1) |
| 2 | 빌드·기동·격리·관측 실패 등 도구가 검사를 수행하지 못함 |

발견과 미완료가 동시에 있으면 **1**을 냅니다. 기존 `scan`에서 발견이 있어도 불완전하면 2가 나오던 혼동을 새 명령에서는 반복하지 않습니다. 미도달 비율을 게이트로 쓰려면 `--min-surface-coverage`를 별도로 켭니다.

## 11. 요소별 핵심 검증 방법

각 어댑터와 기능은 "만들었다"가 아니라 **고정 예제로 증명된다**는 것이 원칙입니다. Oracle과 RuntimeProfile은 기존 KPI 하네스(버전 고정 코퍼스, compat 호환 테스트)에 붙여, 실행마다 해시로 재현성을 확인합니다.

### 검증 원칙 (모든 요소 공통)

1. **취약/수정 쌍:** 모든 Oracle·Pack은 취약 버전과 수정 버전을 쌍으로 갖습니다. 취약본에서 `confirmed`, 수정본에서 0건이어야 통과입니다.
2. **고정 입력:** 입력(이미지·시드·로그)은 바이트 해시로 고정합니다. 똑같은 입력은 똑같은 결과를 내야 합니다.
3. **음성(negative) 사이트:** 반드시 안전한 대조 라우트를 두고, 거기서 `confirmed`가 나오면 실패로 취급합니다 (오탐 게이트).
4. **재현성:** 같은 시드·예산에서 두 번 돌려 Verdict 집합과 마커 매핑이 동일해야 합니다.

### 어댑터별 검증

| 요소 | 핵심 검증 방법 | 통과 기준 | 시점 |
| --- | --- | --- | --- |
| Builder | 고정 예제를 빌드해 imageDigest 재현 확인; 빌드 중 네트워크를 허용 목록 밖으로 막고 실패 여부 확인; compose/Dockerfile/자동 세 경로를 같은 예제로 비교 | 같은 소스→같은 digest (또는 차이 설명), 금지 네트워크 요청은 차단 | M1(compose)/M3(자동) |
| RuntimeProfile | 요청으로 특정 핸들러를 건드리고 커버리지가 그 메서드를 가리키는지 대조(요청 전/후 줄 수 차이); JaCoCo 덤프를 소스 위치로 매핑 | 공격한 라우트의 핸들러가 covered로 잡힐, 미요청 라우트는 uncovered | M1(JVM)/M2(Node·Py) |
| SurfaceProvider | actuator·OpenAPI 출력을 수동 검토한 ground truth와 비교(recall); 기존 P1a 인벤토리 KPI와 동일 방식 | 고정 픽스처에서 recall 재현, 출처(provenance) 정확 | M1~ |
| AttackEngine | 마커가 요청↔라우트로 고유하게 매핑되는지; 시드 고정 시 예산 분배·요청 수가 재현되는지 (기존 schemathesis seed 재현 테스트) | 마커 충돌 0, seed 동일→요청 동일 | M1~ |
| Observer | 마커가 포함된 사건만 수집하는지(마커 없는 줄 버림 확인); 관측 실패 시 `unknown` 산출; 추적 중단·타임아웃이 partial로 남는지 | 마커 사건 재현, 비마커 누출 0, 중단 시 clean 아님 | M1(pg-log)/M2(exec·file·egress) |
| Oracle | 순수 함수라 I/O 없이 단위 테스트; 고정 관측 로그 입력→기대 Verdict; 취약/수정 쌍과 음성 사이트 | 수정본 confirmed 0, 음성 사이트 confirmed 0, 바인딩과 문장삽입 구분 | M1(SQL)/M2(나머지) |
| AnalyzerProvider | 기존 OSS 코퍼스(NodeGoat·Juice Shop) 그대로; SARIF import는 고정 SARIF 입력→정규화 필드 매핑 | 기존 벤치마크 결과 불변, import 필드 정확 | M0(리팩터링)/M5(SARIF) |
| FrameworkPack | Pack YAML을 JSON Schema로 검증; Pack을 Opengrep 규칙로 변환한 뒤 고정 예제에서 source→sink 추적 확인; 같은 취약점을 두 마이크로 재현 | Pack 해시 보고서 기록, 예제 추적 성공, 사용자 Pack도 스키마 거부 가능 | M1(Spring)~ |

### 가로지르는 기능 검증

| 요소 | 핵심 검증 방법 | 통과 기준 | 시점 |
| --- | --- | --- | --- |
| 격리 | 실행 단계에서 카나리 외 외부 접속을 시도해 차단 확인; 비밀값 env가 빌드 로그·보고서에 안 남는지 카나리 추출; `--require-isolation` 미충족 시 실행 거부 | 외부 접속 0, 비밀값 누출 0, 미충족→exit 2 | M3 |
| 캐시 | 키 요소 하나씩 바꿔 무효화되는지 (코드 고정 + lockfile·설정·Pack·정책 각각 변경); 재사용 판정의 내용 해시 재계산 일치; 포크↔main 캐시 격리 | 무관 변경은 hit, 유관 변경은 miss, advisory는 미캐시 | M3(빌드·이미지)/M5(검사 결과) |
| 에이전트 | 에이전트 출력이 스키마 검증을 통과한 데이터만인지; 에이전트 유무에 따라 판정 결과가 바뀌지 않는지 (같은 예제 A/B); 준비 성공률 향상폭 측정 | 스키마 밖 출력 거부, agent on/off에서 판정 동일, 준비 성공률 상승 | M4 |
| 보고서 계약 | compat-0.5 고정 데이터로 기존 소비자 호환 확인(새 필드 추가가 기존 파서를 깨뜨리지 않음); report.json↔agent-report↔SARIF raw 해시 바인딩; 요약 순서(확정→게이트→미도달→한계) 스냅샷 비교 | 기존 테스트·게이트 불변, 네 보고서 해시 일치, reused 표기 누락 0 | M1~(매 마일스톤) |
| 종료 코드 | 발견+미도달 동시, 도구 실패, 깨끗한 상태 세 경우를 고정 시나리오로 확인 | 발견+미도달→1, 도구 실패→2, 깨끗→0 (기존 scan 혼동 반복 안 함) | M1 |

### 전체 계층 검증 (KPI 하네스)

- **단위:** Oracle·plan·surface는 고정 입력→고정 출력 단위 테스트. I/O 없는 순수 함수라 빠르고 결정적입니다.
- **통합:** Spring·Express·Flask 고정 취약/수정 예제를 고정 코퍼스로 두고, 전체 `verify` 파이프라인을 돌려 Verdict 집합을 고정합니다. 기존 KPI compare 도구를 그대로 써서 마일스톤 간 회귀를 잡습니다.
- **호환:** compat-0.5 고정 데이터로 기존 `scan` 결과가 그대로 유지되는지 매 빌드 확인합니다.
- **정직성:** 뒤집어 생각하면, 가장 중요한 검증은 **수정본·음성 사이트에서 `confirmed`가 절대 나오지 않는 것**입니다. 이게 깨지면 "증거 기반" 주장 전체가 무너집니다.

## 12. 단계별 로드맵

순서의 핵심은 **자동 빌드보다 판정 구조를 먼저 검증**하는 것입니다. 기존 0.6~1.0 로드맵의 P1b(소스 라우트 발견), 실행 계획 v2, state-snapshot, run-loop, agent provider 항목은 아래 마일스톤에 흡수합니다.

| 마일스톤 | 버전 | 통과 게이트 (다음 단계로 넘어가는 조건) |
| --- | --- | --- |
| M0 추상화 리팩터링 | 0.6-a | compat-0.5 보고서 해시 동일, KPI 회귀 없음 |
| M1 verify 최소 경로 (Spring) | 0.6 | 취약 예제 SQLi `confirmed`, 수정본에서 `confirmed` 0건 |
| M2 경계 Oracle 확장 + 3개 언어 | 0.7 | 3개 언어 같은 판정 매트릭스 통과, 수정본 오판 0건 |
| M3 자동 빌드·격리·캐시 | 0.8 | OSS 코퍼스 빌드 성공률 기준선 측정·공개 |
| M4 에이전트 준비 루프 | 0.9 | 준비 성공률 향상폭 측정, 판정 결과는 에이전트와 무관 |
| M5 정적·동적 결합, 안정 계약 | 1.0 | 보고서 스키마 1.0 고정, npm 1.0 배포 |

각 게이트는 기존 KPI 하네스로 측정합니다. 게이트를 통과하지 못하면 다음 마일스톤으로 넘어가지 않습니다.

M2~M4에는 14.4의 추가 작업과 완료 조건이 더해집니다.

### 마일스톤 상세

기간은 Codex 서브에이전트 병행을 가정한 **제안값**이며, M0 완료 후 실측으로 다시 맞춥니다.

| 마일스톤 | 주요 작업 | 완료 조건 | 새로 측정할 KPI | 기간(제안) |
| --- | --- | --- | --- | --- |
| M0 추상화 리팩터링 | `runSource` 분기 → AnalyzerProvider 레지스트리, `code-coverage.ts` 일반화, `ExecutionEngine` → AttackEngine 레지스트리, `src/runtime/types.ts` 스켈레톤 | compat-0.5 보고서 의미 해시 동일, 기존 테스트 전부 통과, KPI compare exit 0 | 어댑터 추가 시 변경 파일 수 | 1~2주 |
| M1 verify 최소 경로 | `init-target`, `verify` 뼈대, compose Builder, JVM RuntimeProfile(JaCoCo), spring-actuator·openapi SurfaceProvider, `pg-log` Observer, SQL Oracle, Spring Pack v1, 취약/수정 Spring 예제 | 취약 예제에서 SQLi `confirmed`, 수정본에서 `confirmed` 0건, 라우트별 커버리지 보고, 정리 확인 | 확정 정확도(예제), 라우트 도달률, 전체 실행 시간 | 3~4주 |
| M2 경계 Oracle 확장 | `exec-trace`·`file-trace`·`egress-canary` Observer, 명령·경로·SSRF·XSS Oracle, Node·Python RuntimeProfile, Express·Flask 예제, 대조군 차등 판정 | 3개 언어 예제에서 같은 취약점 매트릭스 통과, 수정본 오판 0건 | 유형·언어별 확정률, 오판 수 | 3~4주 |
| M3 자동 빌드·격리·캐시 | Railpack/Buildpacks Builder, 격리 정책·`--require-isolation`, 빌드·이미지·시드 캐시, `doctor --runtime`, 빌드용 OSS 코퍼스 고정 | 코퍼스 빌드 성공률 기준선 공개, 캐시 적중 시 재빌드 시간 감소 측정 | 빌드·기동 성공률, 캐시 적중률 | 4~6주 |
| M4 에이전트 준비 루프 | Build·Env Doctor, Auth Flow Writer, 실행 계획 v2, Codex·Claude provider, 루프 상한·비용 기록 | 에이전트 사용 시 준비 성공률 향상폭 측정, 판정 결과는 에이전트 유무와 무관 | 향상폭, 실행당 LLM 비용 | 3~4주 |
| M5 결합·안정 계약 | 정적 후보 ↔ 커버리지 결합(`reach`), 검사 결과 재사용(`reused`), Django·Go B등급, 스키마 1.0, npm 배포 | 스키마 고정 문서·호환 테스트, npm·Action 태그 일치 검증 (기존 G7 게이트) | PR 프로필 실행 시간, 재사용률 | 3~4주 |

### M1 파일 배치 (초안)

```text
src/runtime/
  types.ts            # 4장 인터페이스
  registry.ts         # 어댑터 등록 (배열)
  verify.ts           # 파이프라인 실행기 (단계 간 파일 전달)
  markers.ts          # 마커 발급·기록
  builders/compose.ts
  runtimes/jvm.ts     # JaCoCo 주입·덤프
  surfaces/spring-actuator.ts
  observers/pg-log.ts
  oracles/sql.ts      # 순수 함수
packs/spring-boot.v1.yml
schemas/target.v1.json, surface-inventory.v2.json, framework-pack.v1.json
examples/runtime/spring-sqli/{vulnerable,fixed}/
tests/runtime-*.test.ts
```

## 13. 리스크와 미결정 사항

가장 큰 리스크는 기술이 아니라 **실제 프로젝트가 혼자 뜨지 않는다**는 점입니다. 그래서 M1을 compose 직접 제공으로 시작하고, 자동 빌드 성공률은 M3에서 기준선부터 측정합니다.

### 리스크

| 리스크 | 영향 | 대응 |
| --- | --- | --- |
| 자동 빌드·기동 실패율이 높음 (사내 레지스트리, 비밀값, 외부 API 의존) | 사용자가 첫 실행에서 포기 | compose 우선, `init-target`의 명확한 실패 안내, Env Doctor 에이전트 (M4) |
| CI 러너에서 ptrace·gVisor 제약 | 명령 실행·경로 Oracle 미동작 | `doctor --runtime`으로 사전 점검, 미동작 유형은 `unknown`으로 표시 |
| 실행 시간 초과 | PR에서 채택 거부 | `pr` 프로필 + 캐시, 예산 상한 (`--max-minutes`) |
| SQL 파서 의존 (Postgres/MySQL 문법 차이) | SQLi 확정 오판 | DB별 파서 고정 버전, 취약/수정 쌍 회귀 테스트 |
| 범위 확장으로 코드 양 급증 | 유지보수 불가 | 어댑터당 코드 상한을 리뷰 기준으로, 신규 프레임워크는 Pack 데이터만 허용 |
| Strix 등 경쟁 도구의 빠른 발전 | 차별성 약화 | "LLM 없이 재현 가능한 증거 + 커버리지"에 집중, 벤치마크 결과 공개 |
| LLM provider 보안 안전장치가 작업 중단 | 에이전트 단계 실패 | 에이전트는 준비 단계에만 쓰고, 없어도 핵심 기능 동작 |

### 미결정 사항

- [ ] 설정 파일을 자체 `wakeio.target.yml`로 둘지, compose의 `x-wakeio` 확장 필드로 둘지
- [ ] ZAP을 AttackEngine으로 포함할지 (`codex/dast-zap-unified` 브랜치 결과 확인 필요)
- [ ] Railpack·Buildpacks 중 기본 자동 빌더 선택 (라이선스·Maven 지원 확인 후 결정)
- [ ] 사용할 SQL 파서 (Postgres용 libpg_query 계열 등)와 라이선스
- [ ] 대시보드를 1.0에 포함할지, CLI 안정화 후로 미룰지
- [ ] 기존 `scan`의 종료 코드 혼동(발견+미완료=2)도 0.6에서 정리할지

### 다음 액션

- [ ] M0 작업 명세를 Codex에 전달 (Analyzer 레지스트리, 동작 변화 없음)
- [ ] Spring + Postgres 취약/수정 고정 예제 작성 (SQLi·명령 실행·SSRF 각 1건)
- [ ] Postgres `log_statement=all` 로그에서 마커 추출 프로토타입으로 Oracle 개념 검증
- [ ] Surface Inventory v2 스키마 초안 (메서드 전체, provenance)

### 출처

- [Strix (PyPI)](https://pypi.org/project/strix-agent/1.4.1/)
- [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon)
- [AppSecSanta — IAST tools](https://appsecsanta.com/iast-tools)
- [Railpack (Sevalla docs)](https://docs.sevalla.com/applications/build-options/railpack)
- [Gradle — Protecting Project Integrity](https://blog.gradle.org/project-integrity)
- [Spring Boot Actuator mappings](https://docs.spring.io/spring-boot/3.5/api/rest/actuator/mappings.html)
- [JaCoCo로 실행 중인 Java 앱 커버리지 측정](https://dev.to/arturmkr/how-to-measure-code-coverage-in-a-running-java-application-using-jacoco-5b13)

## 14. 추가 결정 (2026-10-27): 권한 Oracle · 계정 모델 · 워크플로 발견

다중 사용자 권한 검증과 업무 흐름 이해가 실사용 가치가 가장 큰 영역이라 범위에 추가한다. M0·M1 범위는 바꾸지 않고 M2~M4를 넓힌다.
저장소에 이미 있는 자산(읽기 전용 API 정책 v2의 소유자·다른 계정·익명 사례와 보호 카나리, 소유 PATCH 상태 검증)을 verify 구조로 옮기는 것이 핵심이다.

### 14.1 권한 Oracle (M2)

- **목적:** 소유하지 않은 계정·익명 사용자·다른 테넌트가 소유자의 데이터를 읽거나 바꿀 수 있는지 확인한다 (BOLA/IDOR, 테넌트 격리).
- **준비:** 시드 단계에서 소유자 리소스마다 고유 보호 카나리 값을 심는다. 기존 API 정책 v2의 protected canary와 같은 개념이다.
- **실행:** 같은 요청을 역할별 주체(소유자, 같은 테넌트의 다른 사용자, 익명, 다른 테넌트 사용자, 관리자)로 보낸다. 기대 접근은 `wakeio.target.yml`의 접근 규칙(14.2)에서 가져온다.
- **관측:** 응답 본문의 카나리 포함 여부, 쓰기 요청 뒤 소유자 리소스의 DB 상태 변화(스냅샷 비교).

| 등급 | 조건 |
| --- | --- |
| confirmed | 접근 규칙상 거부여야 할 주체의 응답에 소유자 보호 카나리가 나타남, 또는 그 주체의 쓰기 요청 뒤 소유자 리소스 상태가 바뀜 |
| strong | 거부여야 할 주체가 성공 응답(2xx)을 받았지만 카나리는 없음 |
| observed | 상태 코드·응답 크기 차이 등 간접 신호만 있음 |

- **대조군:** 같은 요청을 소유자 본인이 보냈을 때 정상 성공해야 판정이 유효하다. 소유자 요청이 실패하거나 인증 확인(identity)이 어긋나면 `unknown`이다. 기존 owner control 원칙과 같다.
- **쓰기 검사:** 소유 고정 예제에서만, 요청마다 DB 스냅샷 복원과 함께 한다.
- **재사용:** `src/api.ts` 정책 v2의 identity 확인·사례 구성·카나리 비교, `src/api-write-state.ts`의 상태 비교를 Oracle 인터페이스로 옮긴다. 기존 `scan` 쪽 API 정책 동작과 보고서는 바꾸지 않는다.
- **고정 예제:** Spring·Express·Flask 각각 취약(소유자 확인 누락)·수정(소유자 확인) 쌍과 테넌트 격리 쌍.

### 14.2 계정·역할·접근 모델 (M2)

`wakeio.target.yml`의 `accounts`에 역할·테넌트를 추가하고, 기대 접근을 선언하는 `access` 블록을 둔다.

```yaml
accounts:                       # 값은 환경변수 이름만
  - { name: alice, role: user,  tenant: t1, usernameEnv: WK_ALICE_USER, passwordEnv: WK_ALICE_PASS }
  - { name: bob,   role: user,  tenant: t1, usernameEnv: WK_BOB_USER,   passwordEnv: WK_BOB_PASS }
  - { name: carol, role: user,  tenant: t2, usernameEnv: WK_CAROL_USER, passwordEnv: WK_CAROL_PASS }
  - { name: admin, role: admin, tenant: t1, usernameEnv: WK_ADMIN_USER, passwordEnv: WK_ADMIN_PASS }
access:
  default: owner-only           # 리소스 기본 규칙
  rules:
    - match: "/api/admin/**"
      allow: [role:admin]
    - match: "/api/teams/{teamId}/**"
      allow: [same-tenant]
```

- 인증은 테스트 계정 로그인, 환경변수로 주입한 토큰·쿠키, 테스트 모드 IdP만 지원한다. 실제 SSO·MFA 절차를 자동화하는 것은 비목표다.
- 접근 규칙이 없는 라우트는 권한 판정을 `unknown`으로 남긴다 (추측하지 않음).

### 14.3 워크플로 발견 (M3 결정적 추론, M4 에이전트 보완)

- **결정적 추론 우선:** OpenAPI `links`와, 응답 필드와 다음 요청 파라미터의 이름·타입 대응으로 생산자-소비자 의존 관계를 추론한다 (RESTler·Schemathesis stateful 방식). 실제 응답으로 추론을 보정한다.
- **기록:** Surface Inventory v2에 `sequences`(생성 → 조회 → 수정 → 삭제 체인)와 각 연결의 출처(provenance: openapi-links / inferred / observed / agent)를 남긴다.
- **에이전트:** Scenario Writer는 결정적 추론이 비어 있는 곳만 시퀀스를 제안하고, 제안은 실행 계획 데이터로만 낸다. 판정에는 관여하지 않는다.
- **KPI:** 고정 예제의 기대 시퀀스 대비 recall, 시퀀스로 도달한 라우트 비율, 권한 Oracle이 평가할 수 있게 된 라우트 수.

### 14.4 로드맵 반영

| 마일스톤 | 추가 작업 | 추가 완료 조건 |
| --- | --- | --- |
| M2 | 권한 Oracle, 계정·역할·테넌트·접근 모델, 3개 언어 권한 취약/수정·테넌트 예제 | 권한 예제에서 기대한 confirmed만 나오고 수정본은 0건, 소유자 대조 실패 시 `unknown` |
| M3 | 결정적 워크플로 추론, Inventory v2 `sequences` | 고정 예제 시퀀스 recall 측정·공개 |
| M4 | Scenario Writer가 빈 시퀀스만 제안 | 에이전트 사용 유무에 따라 판정이 바뀌지 않음, 도달률 향상폭 측정 |

### 14.5 포지셔닝 문장

AI가 짠 코드를 실제로 띄워 **LLM 없이도 재현되는 증거**로 확정하고, **검사하지 못한 범위까지** 밝혀서, 코딩 에이전트가 바로 고칠 수 있는 형태(agent-report)로 돌려주는 오픈소스 CI 엔진.
