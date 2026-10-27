# Codex ↔ Claude 핸드오프 프로토콜 (runtime-verify)

`docs/runtime-verify/PLAN.md`를 구현하는 동안 Codex(구현)가 Claude(리뷰·게이트 검사)를
**비대화식으로 직접 호출**하는 방식을 정한다. 사람은 게이트 승인과 예외 상황에만 개입한다.

## 역할

| 주체 | 역할 | 하지 않는 일 |
| --- | --- | --- |
| Codex | PLAN.md 마일스톤 구현, 체크포인트마다 요청서 작성 후 리뷰 래퍼 실행, 응답에 따라 진행 | 리뷰 없이 다음 단계 진행, 기준 완화, PLAN.md·보호 파일 수정 |
| Claude (로컬 Claude Code, `claude --print`) | 체크포인트 코드 리뷰, 마일스톤 게이트 독립 검사 | 소스 수정·커밋 (읽기 + 허용된 검증 명령만 가능) |
| 사람 | 게이트 결과 확인 후 dev PR 병합, 래퍼가 종료 코드 12·11·2를 낼 때 판단 | — |

## 보호 파일 (Codex 수정 금지)

```
scripts/handoff/claude-review.mjs        # 리뷰 래퍼
docs/runtime-verify/HANDOFF.md           # 이 문서
docs/runtime-verify/prompts/review.md    # 체크포인트 리뷰 프롬프트
docs/runtime-verify/prompts/gate.md      # 게이트 검사 프롬프트
docs/runtime-verify/prompts/response.schema.json
```

보호 파일은 사람(또는 사람이 Claude 앱에서 받은 수정본)만 바꾼다. 바꿀 때는 그 변경만 담은 커밋을 따로 만들고 제목에 `[handoff-update]`를 붙인다.
Claude 리뷰어는 매번 `git log`로 이 경로를 바꾼 커밋을 확인하고, 최초 도입 커밋 외에 `[handoff-update]`가 없거나 다른 파일과 섞인 커밋이 있으면 `BLOCKED`를 낸다.
응답 `.response.json`의 `meta.scriptSha256`으로 실제 실행된 래퍼를 확인할 수 있다.

## 브랜치

- 기준 브랜치: `origin/dev`. 마일스톤마다 `codex/rv-m<N>-<slug>` 브랜치를 만든다 (예: `codex/rv-m1-spring-sql`).
- 게이트 승인(종료 코드 0) 후 사람이 확인하고 `dev`로 PR을 병합한다.
- 리뷰 요청 시점에는 추적 중인 파일에 커밋 안 된 변경이 없어야 한다 (추적되지 않은 파일과 gitignore된 `.handoff/`는 무관).

## 체크포인트

| ID | 시점 | 리뷰 초점 |
| --- | --- | --- |
| `CP1` | 설계: 타입·스키마·파일 목록·테스트 목록·고정 예제 계획을 커밋한 직후, 본 구현 전 | PLAN 정합성, 인터페이스, 테스트 설계 |
| `CP2` | 핵심 구현 + 단위 테스트 완료 직후 | 정확성, 보안 경계, 코드 양·가독성 |
| `CPx<k>` | 추가 필수 정지: 직전 체크포인트 이후 diff가 800줄을 넘을 때, 또는 `src/contracts.ts`·`src/report.ts`·격리·외부 요청 통제·비밀값 처리 코드를 건드릴 때 | 해당 변경 |
| `GATE` | 마일스톤 완료 주장 시 | PLAN 12장 게이트의 독립 검증 |

## 호출 방법

1. 요청서 `.handoff/M<N>-<CP>.request.md`를 아래 형식으로 쓴다 (재요청은 `-r2`, `-r3`).
2. 실행한다:

   ```sh
   node scripts/handoff/claude-review.mjs --request .handoff/M1-CP2.request.md
   ```

   - 래퍼는 커밋 상태와 요청서의 head SHA를 확인한 뒤, 그 커밋의 임시 worktree에서 `claude --print`를 읽기 전용 권한(`--permission-mode dontAsk` + 허용 명령 목록)으로 실행한다.
   - 사용자 전역 훅·플러그인·CLAUDE.md·MCP는 `--safe-mode`로 끈다 (로그인 인증은 유지). 그래서 Intent Loop 같은 전역 훅이 리뷰 턴을 소모하지 않는다.
   - 결과는 `.handoff/M1-CP2.response.md`와 `.response.json`으로 저장된다. 실행 오류면 `.handoff/M1-CP2.error.json`에 원인이 남는다.
3. 종료 코드에 따라 행동한다.

| 종료 코드 | 의미 | Codex의 다음 행동 |
| ---: | --- | --- |
| 0 | 승인 (`APPROVE` / `APPROVE_WITH_NITS`) | nit 중 반영할 것을 반영하고 다음 단계로. GATE면 dev PR을 만들고 **정지** |
| 10 | 수정 요청 | 모든 blocking 항목을 고치고 `-r<k>` 요청서로 다시 호출 |
| 11 | BLOCKED | 정지하고 사람에게 보고 |
| 12 | 사람 판단 필요 (게이트 미검증 항목, 또는 같은 체크포인트 3회 초과) | 정지하고 사람에게 보고 |
| 2 | 실행 오류 | 아래 표에 따라 처리 |

### 종료 코드 2 처리 (`.error.json`의 `cause`)

| cause | Codex의 행동 |
| --- | --- |
| `not_clean`, `head_mismatch` | 직접 고친다(커밋하거나 요청서의 head SHA를 갱신). 다시 호출한다. 정지하지 않는다 |
| `max_turns`, `budget`, `timeout` | 해당 한도를 1.5배로 올려 **한 번만** 다시 호출한다 (`--max-turns`, `--budget-usd`, `--timeout-min` 인자 사용). 두 번째도 실패하면 정지 |
| `no_structured_output`, `schema_mismatch`, `claude_error`, `not_json` | 같은 인자로 **한 번만** 다시 호출한다. 두 번째도 실패하면 정지 |
| `claude_not_found`, `auth`, `permission` | 정지하고 `.error.json` 경로와 `cause`, `permissionDenials`를 보고한다 |

정지할 때는 `.error.json`을 그대로 첨부한다. 래퍼·프롬프트를 고쳐서 우회하지 않는다.

## 요청서 형식 (`*.request.md`)

```markdown
# M<N>-<CP> 리뷰 요청
- 브랜치: codex/rv-m<N>-...
- base SHA: <리뷰 범위 시작 커밋>
- head SHA: <현재 HEAD, 전체 40자>
- PLAN 참조: <섹션 번호>

## 이번 체크포인트 목표
## 변경 요약 (파일별 한 줄)
## PLAN과 다르게 결정한 것과 이유
## 실행한 검증 (명령, exit code, 통과/실패/건너뜀 수)
## 증거 파일 (경로 + sha256)  ※ GATE는 .handoff/evidence/M<N>/ 에 저장하고 재현 명령을 함께 적는다
## 특히 봐야 할 곳 (파일:라인)
## 이전 리뷰 반영 내역 (B<번호> → 수정 커밋 SHA)
## 미해결 질문 / PLAN 변경 제안
```

## Codex 규칙

1. 요청서 작성과 래퍼 호출 없이 체크포인트를 넘기지 않는다.
2. `.response.md`·`.response.json`을 수정하거나 지우지 않는다.
3. 게이트·테스트·KPI 기준을 통과시키려고 기준을 완화하지 않는다. 기준이 틀렸다고 판단되면 "PLAN 변경 제안"에 적고 리뷰를 받는다.
4. 기존 `scan` / `init` / `init-dast`의 동작과 종료 코드를 바꾸지 않는다. compat-0.5 테스트가 항상 통과해야 한다.
5. Docker가 필요한 검증은 직접 실행하고 결과를 `.handoff/evidence/M<N>/`에 남긴다. M1부터 같은 검증을 GitHub Actions 워크플로로도 돌린다.
6. 요청서·증거에 비밀값, 토큰, 대상 데이터 원문을 넣지 않는다.
7. 새 코드(`src/runtime/**`)는 한 줄 120자, 한 함수 60줄 이내를 기본으로 한다. 기존 파일의 밀집 스타일을 새 코드로 퍼뜨리지 않는다.
8. 보호 파일을 수정하지 않는다. 래퍼가 동작하지 않으면 위 종료 코드 2 표대로 처리한다. 사람이 보호 파일 수정본을 주면 그 파일들만 `[handoff-update]` 커밋으로 넣는다.
9. 래퍼 호출은 리뷰 비용이 든다. 기본 상한은 리뷰 3 USD, 120턴, 40분이며, 게이트는 `--budget-usd 8 --max-turns 200 --timeout-min 60`을 쓴다.

## 대화형 대체 경로

비대화식 호출이 안 되는 경우 `PROMPTS.md`의 3·4번 프롬프트를 사람이 Claude(앱)에 직접 보내고, Claude가 같은 형식의 `.response.md`를 쓴다.
