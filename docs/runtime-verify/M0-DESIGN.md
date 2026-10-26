# M0 설계: 기존 동작을 보존하는 정적 레지스트리

이 문서는 `PLAN.md` 4·11·12장의 M0 구현 전 체크포인트(CP1) 설계다. M0은 레지스트리와 타입의 내부 구조만 바꾼다. 대상 애플리케이션 빌드·실행, `verify` 명령, 새 판정, 새 보고서 필드는 M1 이후 작업이다.

## 현재 계약과 결정

- 기준은 `origin/dev`의 `scan`·`init`·`init-dast` 및 실행 계획 v1이다. `origin/main`의 KPI·compat-0.5·GET 인벤토리 기준을 브랜치에 병합했다. M0에서 공개 옵션·종료 코드·결과 순서·보고서 의미를 바꾸지 않는다.
- 분석기는 빌트인 AST, Framework Rules, Opengrep preview와 기존 선택형 도구 7개를 포함한다. 코드 커버리지의 provider ID와 순서는 `builtin_ast`, `bandit`, `opengrep_native`, `semgrep` 그대로다. `semgrep` 미선택 시 기존 3행 형식, 선택 시 4행 형식을 유지한다.
- 실행 엔진은 `native-dast`, `schemathesis`, `nuclei`, `zap` 네 개를 등록한다. `PLAN.md` 13장은 ZAP 포함 여부를 미결정으로 적지만, 현재 `origin/dev`에 ZAP이 이미 있으므로 M0에서는 호환성 보존을 위해 등록한다. M1의 마커 주입 지원 여부는 별도 결정으로 남긴다.
- `ExecutionPlan` v1의 정확한 키 집합, 엔진별 요청 상한, 파일 별칭·SHA256 결속, 승인·origin·예산 검사는 그대로 둔다. `runExecutionPlan`과 `RunStore`의 공개 시그니처도 바꾸지 않는다.
- 저장소 `AGENTS.md`의 G1/G2 소유 경계는 유지한다. M0은 실행 엔진 레지스트리가 목표에 명시된 별도 단계라 `runner.ts` 내부 디스패치만 최소 수정하고, `store.ts` 및 Claude 소유 평가·벤치마크 파일은 수정하지 않는다.
- 등록 목록은 코드에 고정된 배열이다. 사용자 입력에서 모듈 경로·실행 파일·함수를 로딩하거나 등록하지 않는다. 알 수 없는 ID는 기존처럼 거절하거나 무시하되, 각 기존 진입점의 현재 동작을 유지한다.

## 내부 타입과 스키마

`src/runtime/types.ts`는 4장의 공통 용어(`VulnClass`, `EvidenceGrade`, `Reach`)와 어댑터 포트의 **컴파일 전용 스켈레톤**을 둔다. M0에서 만든 포트는 외부 입력/출력 JSON 계약이 아니며, 미구현 단계를 호출하는 값이나 런타임 기본 동작을 만들지 않는다. M1 타입을 완성할 때도 판정과 실행 권한은 별도 경계로 둔다.

레지스트리의 내부 설계 형태는 다음과 같다. 실제 타입은 기존 `SourceSnapshot`, `SourceOptions`, `CheckResult`, `ExecutionTask`를 사용한다. 모든 함수는 정적 코드가 공급하며 요청서/계획 데이터가 공급하지 않는다.

```ts
interface AnalyzerProvider {
  id: string;
  checkId: string;
  selection: 'always' | 'native-preview' | 'tool';
  selected(options: SourceOptions): boolean;
  applicable(snapshot: SourceSnapshot): boolean;
  executable?(options: SourceOptions): string;
  stage?: 'shared' | 'python' | 'safe-config';
  notApplicable?(snapshot: SourceSnapshot): CheckResult;
  // 선택형 도구는 기존 사전 검사·스테이징·프로세스 감독을 재사용한다.
  run(context: AnalyzerRunContext): Promise<CheckResult> | CheckResult;
  codeCoverage?: {
    publicId: CodeProvider;
    languages: readonly CodeLanguage[];
    inputs(snapshot: SourceSnapshot): readonly CollectedFile[];
    complete(check: CheckResult, inputCount: number): boolean;
  };
}

interface RegisteredAttackEngine<T extends ExecutionTask = ExecutionTask> {
  id: T['engine'];
  parseTask(raw: Record<string, unknown>): T; // 기존 exact-key 규칙
  requiredInputs(task: T): readonly string[];
  prepare(task: T, context: PrepareContext): PreparedTask;
  execute(prepared: PreparedTask, context: ExecutionContext): Promise<CheckResult[]>;
  complete(prepared: PreparedTask, checks: readonly CheckResult[], observed: AdmissionSnapshot): boolean;
}
```

`src/runtime/registry.ts`에 두 정적 배열과 ID 조회를 둔다. 서로 다른 준비/실행 타입 때문에 순환 import가 생기면 기존 함수의 어댑터를 `src/source/analyzer-providers.ts`와 `src/agent-dast/engine-adapters.ts`로 옮기되, 등록 배열은 한 곳에서 유지한다. 기존 실행 단계의 순서·별도 스테이징·오류 문구·예산·정리 순서는 변경하지 않는다. `executable`, `stage`, `notApplicable`은 도구별 실행 파일 선택, Bandit/Trivy의 별도 입력 스테이징, 빈 입력의 기존 문구·메트릭을 등록 항목에서 지정한다. Bandit의 Python 입력 0개 판단도 실행 파일 탐색 전에 그 항목에서 처리한다. 디스패처에는 도구 ID 비교 분기를 남기지 않는다.

커버리지 생성·parser·consistency 검사는 코드 provider 네 개의 `languages`·check ID·입력 파일·완료 판정을 같은 레지스트리 메타데이터에서 읽는다. 다만 직렬화 계약을 보호하기 위해 v1의 허용 provider 행 집합과 순서는 별도 상수로 고정하고, 그 상수와 등록 메타데이터가 정확히 일치하는지 테스트에서 단언한다. 수집된 파일만 계수하며 기존 `CodeCoverage` parser의 검증 강도는 유지한다.

기존 분석 순서는 inventory → AST → Framework Rules → 선택한 native preview → 선택형 외부 도구 → coverage다. 외부 도구는 요청된 `tools` 순서의 `Promise.all` 동시 실행과 결과 순서를 그대로 유지한다. 레지스트리 순서는 이 공개 결과 순서를 덮어쓰지 않는다. 새 provider ID를 등록하더라도 v1 커버리지 parser의 허용 행과 순서를 자동 확장하지 않는다. 새 공개 provider를 노출하려면 별도 v2 계약이 필요하다.

M0의 `RegisteredAttackEngine`은 현행 실행 계획 v1을 감싸는 내부 포트다. `PLAN.md` 4장의 미래 `AttackEngine.plan/run(task, markers, ctx)`를 아직 구현하거나 마커 지원을 주장하지 않는다. 승인·origin·env·SHA 결속과 공통 예산은 runner의 공유 경계에 남긴다.

**새 공개 스키마는 없다.** `src/contracts.ts`, `src/report.ts`, `schemas/**`, `ExecutionPlan` v1 JSON, `CodeCoverage` v1 JSON, inventory v1 출력은 M0에서 바꾸지 않는다. 새 레지스트리 타입은 직렬화되지 않는다.

## 구현 파일 목록

| 파일 | 변경 계획 |
| --- | --- |
| `src/runtime/types.ts` | 4장 공통 타입과 컴파일 전용 포트 스켈레톤 |
| `src/runtime/registry.ts` | 분석기·공격 엔진의 정적 등록 순서, 고유 ID와 조회 |
| `src/source.ts` | 기존 `runSource` 순서와 사전 검사를 유지하며 등록된 분석기로 디스패치 |
| `src/source/code-coverage.ts` | provider별 언어·입력·완료 조건을 등록 메타데이터에서 읽음 |
| `src/agent-dast/plan.ts` | v1 discriminated union을 보존하고 엔진별 엄격한 파서를 등록 정보로 선택 |
| `src/agent-dast/runner.ts` | 공개 시그니처를 유지하고 준비·실행·완료 판정을 등록 엔진으로 선택 |
| `src/source/analyzer-providers.ts`, `src/agent-dast/engine-adapters.ts` | 순환 참조가 있을 때만 기존 내부 함수 이동 |
| `tests/runtime-registry.test.ts` | 목록·ID·조회·디스패치의 회귀 확인 |
| `tests/runtime-m0-compat.test.ts` | 고정 예제의 보고서 의미 해시 비교 |
| `tests/fixtures/runtime-m0-baseline.json` | `7a4ada1`에서 측정한 행별 해시·종료 코드·입력 해시를 CP2에서 동결해 CI 테스트가 읽음 |

구현 과정에서 격리·egress·비밀값 처리 또는 `src/contracts.ts`·`src/report.ts`를 수정해야 한다면 변경 전에 추가 체크포인트(CPx)를 연다.

## 테스트와 고정 예제

1. 레지스트리 테스트: ID 중복 없음, 기존 선택·실행 순서 동일, 요청 도구 순서와 동시 실행·취소 경계 유지, 미등록 ID 거절, 네 실행 엔진의 v1 필드 및 상한 거절 사례. 가짜 외부 플러그인은 사용하지 않는다.
2. 코드 커버리지: 기존 `code-coverage-independent`·`semgrep` 테스트의 언어별 eligible/completed, 3/4 provider 행 순서, 부분·미선택·미수집 상태를 유지한다. 등록 메타데이터와 실제 수집 파일의 불일치를 잡고, 등록된 네 provider의 ID·언어·순서가 고정 v1 행 집합과 일치하는지 단언하는 사례를 추가한다.
3. 보고서 의미 해시: 리팩터링 전 기준 커밋 `7a4ada1`을 별도 checkout에서 빌드해 23개 사례의 기준값을 먼저 기록했다. 기존 `compat-0.5`의 `pass`·`findings`·`partial` 소스(`--tools none`, 세 `--fail-on` 값)뿐 아니라 다음 디스패치 행렬을 고정 소스에서 실행한다: 선택형 도구 7개 각각 단독, `bandit,semgrep,gitleaks`와 역순 조합, native preview 선택/미선택, 빈 소스의 도구별 `not_applicable`, Semgrep 선택 여부의 coverage 3/4행. Python·Go·JS와 설정/의존성 입력을 포함한 고정 fixture로 Bandit의 Python 입력 0개/있음, Semgrep의 Go eligible, 실행 파일 미발견 partial을 구분한다. 이 기준 행렬은 `toolPaths`와 `--opengrep-core`에 의도적으로 없는 절대경로를 전달해 호스트 도구가 우연히 실행되지 않게 한다. 실제 엔진 완료 경로는 기존 스텁·진짜 엔진 테스트에서 별도로 확인한다. 변경 후 별도 checkout에서 동일한 입력·도구 순서·옵션을 실행해 `scripts/kpi.mjs`의 `semanticHash()`와 종료 코드를 각 행별로 비교한다. 기준 증거는 `.handoff/evidence/M0/compat-before.json`에 두고 CP2의 CI 테스트가 쓸 동일 내용을 `tests/fixtures/runtime-m0-baseline.json`으로 동결한다. 이 해시는 최상위 `startedAt`·`finishedAt`만 제외하고 배열 순서·check 상태·finding·gap·scope를 포함한다. 기존 0.5 artifact 네 묶음은 독립된 frozen parser/gate 테스트로 유지하고 기대값을 새 구현으로 재생성하지 않는다. `states`는 합성 check 상태 보고서이므로 실행 스캔 비교 대상에서 제외한다.
4. 실행 엔진: 기존 `agent-dast-runner*`, `zap-integration`, `compat-0.5`를 돌려 준비·요청 예산·승인·origin·실패/정리 동작을 확인한다. 실제 소유 대상 외부 스캔은 추가하지 않는다.
5. 통합: `npm run build`, 전체 기존 테스트, `tests/inventory.test.ts`·`tests/init-action-handoff.test.ts`, 그리고 동일 런타임/코퍼스의 `scripts/kpi.mjs compare`를 실행한다. 비교의 exit 0과 각 결과 SHA를 `.handoff/evidence/M0/`에 기록한다. 기준을 수정해 회귀를 숨기지 않는다.

‘어댑터 추가 시 변경 파일 수’의 리팩터링 전 참고 기준은 실제 ZAP 통합 커밋
`f2bcf2663217d3923f97fd3e1c09c1963f61fae1`의 `src/` 9개·`tests/` 4개, 합계 13개다.
재현 명령은 `git diff-tree --no-commit-id --name-only -r f2bcf266 -- src tests`다. 이 숫자는
정책·CLI·egress를 포함한 **전체 통합 비용**이다. M0 이후 등록 배선만 바꾸는 버리는 worktree의
파일 수와 같은 범위인 것처럼 비교하거나 개선율을 주장하지 않는다. GATE에는 역사적 전체 비용과
새 레지스트리의 배선 변경 파일 수를 별도 항목으로 기록하고, 동일 범위의 최초 실제 어댑터 추가
비용은 M1에서 측정한다. 공개 레지스트리에 테스트용 가짜 엔진을 남기지 않는다.
