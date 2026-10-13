# AGENTS.md

## 적용 범위와 역할

이 저장소는 DAST 멀티에이전트 구조로 개발한다. 이후 세션은 작업 전에 이 파일을 읽고 아래 경계를 따른다.

- **Codex**: 개별 DAST·API 검사의 정밀도와 검사 엔진 층을 담당한다.
- **Claude**: `src/agent-dast/` 아래 오케스트레이션 틀을 담당한다. 실행기, `run.db`, 에이전트 어댑터, 보고서 연결이 여기에 포함된다.
- 일반적인 파일 패턴보다 아래의 소유권, 동결, 공용 파일 예외와 수정 대기 규칙이 우선한다.

## 1. 소스 분석 동결

다음 파일과 경로에는 새 기능을 추가하지 않는다.

- `src/source/**`
- `src/source.ts`
- `src/source-handoff.ts`
- `src/repair*.ts`

이 영역은 기존 테스트가 깨지는 버그 수정만 허용한다. 해당 PR 제목에는 `[source-fix]`를 붙인다.

진행 중인 소스 분석 브랜치는 현재 상태에서 멈추고 새 PR을 열지 않는다. 이 경로에 포함되는 `src/source/process.ts`의 `runProcess`는 5절의 명시적인 공용 파일 예외를 따른다.

## 2. 계속할 검사 엔진 작업

Codex는 다음 영역에서 개별 검사의 정밀도를 개선한다.

- `src/dast*.ts`
- `src/api*.ts`
- `src/nuclei.ts`
- `src/schemathesis*.ts`
- `workers/**`

작업은 오탐 감소, 판정 근거의 정확한 기록, 중단 사유 보존 등 검사 엔진 개선에 집중한다. `src/dast-egress.ts`에는 이 목록보다 5절의 수정 대기 규칙을 우선 적용한다.

## 3. 진입점 계약

Claude가 기존 검사 함수를 워커 템플릿으로 감싸므로 공개 진입점의 호환성을 유지한다.

- `runDast`, `runOwnedApiWriteStatePilot`, `selectNucleiTemplates` 등 기존 export 함수의 시그니처를 깨지 않는다.
- 변경이 필요하면 새 함수를 추가하고 기존 함수와 시그니처를 유지한다.
- 검사 함수는 입력으로 origin, 대상 엔드포인트, 인증 토큰의 환경변수 이름, 요청·시간 예산, `AbortSignal`을 받고 구조화된 결과만 반환한다. 기존 진입점에 이 계약을 적용할 때도 앞의 호환성 규칙을 지킨다.
- 라이브러리 함수 안에서 원본 요청·응답을 stdout으로 출력하지 않는다.
- 라이브러리 함수 안에서 `process.exit`를 호출하지 않는다.

## 4. Claude 전용 영역

다음 영역은 Claude가 담당하며 Codex는 수정하지 않는다.

- `src/agent-dast/**`
- `schemas/worker-result*`
- `migrations/**`

검사 엔진 개선에 오케스트레이션 변경을 섞지 않는다.

## 5. 공용 파일과 작업 순서

### 수정 대기: `src/dast-egress.ts`

Claude가 `feat/agent-dast-runner`에서 실행 단위 공유 gate와 초당 요청 상한을 구현한다. 그 PR이 `dev`에 머지될 때까지 Codex는 `src/dast-egress.ts`를 수정하지 않는다. 수정에 착수하기 전에 머지 여부와 최신 `dev`의 내용을 확인한다.

### 최소 변경이 허용되는 공용 파일

- `src/source/process.ts`의 `runProcess`
- `src/contracts.ts`
- `src/report.ts`
- `src/cli.ts`
- `dast/action.yml`

검사 엔진 작업 때문에 꼭 필요한 경우에만 최소한으로 변경한다. `runProcess` 공용 예외를 소스 분석 기능 확장에 사용하지 않는다.

이 파일을 변경하는 PR은 설명 맨 위에 다음 형식으로 변경 파일을 모두 적는다.

```text
공용 파일 변경: <파일명>
```

## 6. 브랜치와 PR

- 항상 최신 `dev`에서 `feat/*` 또는 `fix/*` 브랜치를 만든다.
- PR의 대상 브랜치는 `dev`로 한다.
- PR 하나에는 주제 하나만 담는다.
- 이 경계를 처음 문서화하는 PR만 명시적으로 지정된 `docs/agents-boundary` 브랜치를 사용한다. 이후 작업에는 `feat/*` 또는 `fix/*` 규칙을 적용한다.
- 소스 분석 버그 수정의 `[source-fix]` 제목 규칙과 공용 파일 변경의 PR 설명 규칙을 함께 지킨다.

## 기존 기여·검증 지침

[CONTRIBUTING.md](CONTRIBUTING.md)와 [SECURITY.md](SECURITY.md)의 기존 지침을 계속 적용한다. 소스 분석의 새 탐지기 등 이전 문서에 일반적으로 허용된 작업도 위 동결 규칙을 넘어서 진행하지 않는다.

- 테스트와 예시에는 합성 데이터만 사용하고, 실제 비밀정보나 원본 요청·응답 등 민감한 자료를 저장소·로그·보고서에 남기지 않는다.
- `candidate`를 취약점 악용의 증명으로, 깨끗한 종료 코드를 전체 서비스의 안전 보장으로 표현하지 않는다.
- partial, skipped, timeout, failure 및 취소·중단 사유를 완료된 clean 결과와 구분해서 보존한다.
- 검사 동작을 바꾸면 관련 회귀 테스트와 공개 출력 계약을 검증하고, 실제 실행한 검증과 실행하지 못한 검증을 구분해 PR에 기록한다.
