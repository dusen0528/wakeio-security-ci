# runtime-verify 프롬프트 모음

절차는 `HANDOFF.md`를 따른다. 기본 경로는 Codex가 `scripts/handoff/claude-review.mjs`로 Claude를 비대화식 호출하는 것이고,
3·4번은 그 호출이 안 될 때 사람이 Claude 앱에 직접 보내는 대체 경로다.

## 1. Codex — goal (최초 1회)

```text
목표: wakeio-security-ci에 다언어 실행 검증 모드(`verify`)를 docs/runtime-verify/PLAN.md에 따라 M0→M5 순서로 구현한다.

먼저 읽을 것:
- docs/runtime-verify/PLAN.md — 설계 기준(Source of Truth). 특히 4장(인터페이스), 6장(Oracle), 7장(보안·격리), 11장(요소별 검증 방법), 12장(로드맵·게이트), 14장(권한 Oracle·계정 모델·워크플로 발견).
- docs/runtime-verify/HANDOFF.md — 체크포인트마다 Claude 리뷰를 받는 절차. 반드시 지킨다.
- docs/runtime-verify/SUBAGENTS.md — 서브에이전트 운영 지침 (누적 역할 최대 10, 동시 최대 4). 반드시 지킨다.
- docs/surface-inventory-p1a.md, benchmarks/kpi.md — 기존 계약과 KPI 하네스.

작업 방식:
1. origin/dev 기준으로 codex/rv-m0-registry 브랜치를 만든다. 첫 커밋은 docs/runtime-verify/**, scripts/handoff/claude-review.mjs, .gitignore의 `.handoff/` 추가만 담는다. 이 파일들은 그 뒤로 수정하지 않는다 (HANDOFF 보호 파일).
2. 각 마일스톤은 HANDOFF.md의 체크포인트(CP1 설계 → CP2 구현 → 필요 시 CPx → GATE)를 따른다. 각 지점에서 코드를 커밋하고 .handoff/M<N>-<CP>.request.md를 쓴 뒤 `node scripts/handoff/claude-review.mjs --request <요청서>`를 실행한다. 게이트는 `--budget-usd 8 --max-turns 200 --timeout-min 60`을 붙인다.
3. 래퍼 종료 코드: 0이면 다음 단계(GATE면 dev로 PR을 만들고 정지), 10이면 .response.md의 blocking 항목을 모두 고쳐 -r<k> 요청서로 다시 호출, 11·12이면 정지하고 응답 파일 경로를 보고한다. 2이면 HANDOFF.md의 "종료 코드 2 처리" 표대로 .handoff/<요청 이름>.error.json의 cause를 보고 직접 고치거나 한 번 재시도하고, 표가 정지하라고 할 때만 정지한다.
4. 게이트 PR이 병합됐다는 지시를 받기 전에는 다음 마일스톤을 시작하지 않는다.

원칙:
- 최소 코드. 새 프레임워크는 Framework Pack(데이터)으로만, 새 어댑터는 레지스트리 등록으로만 추가한다.
- 판정(Oracle)은 I/O 없는 순수 함수다. LLM은 판정·게이트에 관여하지 않는다.
- 기존 scan / init / init-dast의 동작과 종료 코드는 바꾸지 않는다. compat-0.5 테스트와 KPI compare는 매 체크포인트에서 통과해야 한다.
- 모든 Oracle은 취약/수정 예제 쌍과 음성(안전) 사이트를 가진다. 수정본이나 음성 사이트에서 confirmed가 나오면 실패다.
- 대상 코드 실행은 verify에서만, --execute-target-consent가 있을 때만 한다.
- 테스트·게이트·KPI 기준을 완화해서 통과시키지 않는다. 막히면 요청서의 "미해결 질문"에 적고 리뷰를 받는다.
- PLAN 13장의 미결정 사항을 추측으로 확정하지 않는다. 해당 마일스톤 CP1 요청서에 선택지와 추천안을 적는다.
- Docker가 필요한 검증은 직접 실행해 결과를 .handoff/evidence/M<N>/에 남기고, M1부터 같은 검증을 GitHub Actions 워크플로로도 돌린다.
- 리뷰 응답 파일과 보호 파일은 수정하지 않는다.

지금 M0부터 시작한다.
```

## 2. Codex — 정지 후 재개

게이트 PR을 병합한 뒤:

```text
M<N> 게이트 PR을 병합했다. origin/dev를 다시 받아 M<N+1> 브랜치를 만들고 HANDOFF.md 절차대로 계속 진행해.
```

종료 코드 11·12, 또는 2의 정지 대상 cause로 멈춘 경우, 판단을 적어서:

```text
.handoff/<파일>.response.md 를 확인했다. 결정: <예: B3은 PLAN 변경 제안대로 진행 / UNVERIFIED 항목은 CI 결과로 확인 완료>.
이 결정을 다음 요청서의 "이전 리뷰 반영 내역"에 기록하고 HANDOFF.md 절차대로 계속 진행해.
```

## 3. Claude 앱 — 체크포인트 리뷰 (대체 경로)

```text
Wakeio runtime-verify 체크포인트 리뷰를 해줘.

- 저장소: /Users/inho/Desktop/wakeio-security-ci (연결된 폴더)
- 요청서: .handoff/<M1-CP2>.request.md
- 기준: docs/runtime-verify/PLAN.md, docs/runtime-verify/HANDOFF.md, 리뷰 기준은 docs/runtime-verify/prompts/review.md

review.md의 절차와 판정 규칙을 그대로 따르고, 결과는 .handoff/<같은 이름>.response.md에 HANDOFF 형식으로 써줘. 소스 코드는 수정하지 마.
나에게는 판정과 blocking 항목 요약만 짧게 알려줘.
```

## 4. Claude 앱 — 마일스톤 게이트 검사 (대체 경로, 또는 래퍼가 12를 낸 뒤 2차 확인)

```text
Wakeio runtime-verify M<N> 게이트 검사를 해줘.

- 저장소: /Users/inho/Desktop/wakeio-security-ci (연결된 폴더)
- 요청서: .handoff/M<N>-GATE.request.md, 증거: .handoff/evidence/M<N>/
- 기준: docs/runtime-verify/PLAN.md 11·12장, HANDOFF.md, 검사 절차는 docs/runtime-verify/prompts/gate.md

gate.md 절차를 따르되, 이 마일스톤 diff를 처음 보는 별도 에이전트에게 독립 검토를 한 번 더 맡기고 결과를 합쳐.
.handoff/M<N>-GATE.response.md에 기준별 PASS / FAIL / UNVERIFIED 표와 최종 판정을 써주고, 나에게는 판정과 FAIL·UNVERIFIED 기준만 짧게 알려줘.
```
