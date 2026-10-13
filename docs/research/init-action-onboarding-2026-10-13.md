# Pinned Action init onboarding — 2026-10-13

이 기록은 `575dbff63c6adc36e327487a2a9a2ead8337b4f0` 이후의 채택 계약과 근거를 구분한다. 구현 검증 결과는 아래에 별도 추가한다. npm 공개판은 0.4.0, 소스 preview는 0.5.0이다. 새로운 init 옵션은 baseline SHA에 들어 있지 않으며, 그 SHA는 기존 검토한 scanner Action 예제에만 사용한다.

## 확인한 사용자 경로의 공백

기존 README/예제는 target checkout `.` 아래에 보고서를 만들었다. 원 `sourceSnapshot.outputDirectoryExcluded=true` 때문에 다운로드를 밖으로 옮겨도 handoff create는 `source_binding_unknown`으로 거부된다(`src/source/snapshot-evidence.ts`, `src/source-handoff.ts`). Root가 보존한 baseline 재현은 scan `1` 이후 다운로드한 보고서의 handoff `2`이다. 실제 실행은 root가 담당했고 이 문서는 외부 대상 실행이나 scan을 하지 않았다. 기존 npm init은 대상의 npm 의존성·lockfile을 요구해 npm이 없는 저장소의 첫 CI에 추가 준비가 필요했다.

채택한 범위는 **새 `init --mode action --action-ref FULL40HEX`**이다. 기본 npm 모드는 유지한다. Doctor 변경, 새 analyzer, 자동 수정, 공통 delivery receipt 재설계, Job Summary 추가 UX는 이번 범위가 아니다.

## 공식 근거와 채택 규칙

| 채택 규칙 | 공식 근거 | Wakeio 계약에 적용 |
| --- | --- | --- |
| 사람이 검토한 full SHA를 입력받고 moving ref를 생성하지 않는다 | [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)는 dependency lockfiles를 가장 강한 보호로 안내하고, 미채택 시 full-length SHA 고정과 실제 Action 저장소 commit 확인을 권한다 | 정확한 40-hex 형식만 검증한다. 존재·출처·전체 공급망 신뢰를 자동 증명하지 않는다. helper Actions도 검토한 SHA 사용 |
| checkout과 결과 경로를 분리한다 | [고정 checkout README](https://github.com/actions/checkout/blob/11d5960a326750d5838078e36cf38b85af677262/README.md)의 `path`는 workspace 아래의 상대 경로다 | checkout/source `wakeio-source`; report base는 형제 디렉터리. 대상 npm/install/build/test 불필요, 내장 tools none 기본 |
| 실행과 attempt를 모두 사용한다 | [GitHub contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context)는 run ID와 증가하는 run attempt를 구분한다 | output와 artifact 이름에 `run_id-run_attempt` suffix를 붙인다. 기존 directory/file을 handoff 결과로 재사용하지 않는다 |
| 실패 보고서 보존과 검사 통과를 구분한다 | [always 표현식](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#always), [artifact 보관](https://docs.github.com/en/actions/tutorials/store-and-share-data), [다운로드 권한·기간](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts) | upload always + missing files error. 전달·보관은 scan gate를 바꾸지 않고 취소/runner 손실의 전달을 보장하지 않는다. 설정된 보관 기간 적용 |
| 정확한 run artifact와 실제 checkout 소스를 연결한다 | [gh run download](https://cli.github.com/manual/gh_run_download)은 run/name/dir 지정 지원. [PR 이벤트](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)는 기본 merge commit을 사용한다 | PR head나 run head SHA 대신 checkout 로그의 실제 SHA 확인. report pair와 collected snapshot·scope·ruleset을 CLI가 검증. source 불일치/불확실은 2 |

GitHub의 artifact digest/다운로드 무결성 안내는 transport 확인이다. 일부 자동 digest 불일치 처리는 경고이며 Wakeio의 canonical report pair/source binding 대신 사용하지 않는다. `sourceSnapshot`도 수집한 문자열 증거이며 Git commit 또는 프로젝트 전체 분석의 증명이 아니다. 사용자 경로는 [실용 안내](../init-action-onboarding.md)에 있다.

## 동결할 acceptance

1. 기존 npm 기본 렌더링을 유지하고 action-ref는 action 모드에만 허용한다. Action mode는 SHA 필수; tag/branch/잘못된 SHA를 거부한다.
2. 생성 파일은 기존 workflow를 덮어쓰지 않는다. report base는 bounded plain workspace-relative path이며 source 하위·절대·traversal·glob·표현식을 거부한다. run/attempt suffix가 렌더링에 고정된다.
3. 실제 Action 단계는 고정된 scanner bundle을 사용하고 대상 dependency 설치·lifecycle·build·test·모델 호출을 추가하지 않는다. source 한도/profile/strict code policy 전달을 확인한다.
4. owned 저장소의 기존 reviewed Action scan→보고서 쌍 다운로드/복사→호환 새 CLI handoff create→같은 범위 after scan→finish를 실제 검증한다. unchanged high는 1, 조건부 partial은 2, 불일치 source는 2를 유지한다. create 0을 원 scan 성공으로 해석하지 않는다.
5. 새 생성기 테스트, 기존 init 회귀, 전체 필수 suite, fresh distribution 및 hosted CI는 각각 자신의 receipt로 판정한다. 테스트 수·전달 성공·상용 탐지 효과를 서로 대체하지 않는다. 새로운 OSS 취약점 또는 수정 완료 주장은 없다.

## 검증 상태

2026-10-13 문서 초안 시점: root의 baseline 실패 재현과 source contract를 확인했다. 새 생성기·consumer·hosted 결과는 아직 이 기록에 성공으로 기재하지 않았다. 실행한 단계의 receipt가 도착하면 append-only로 추가한다.

### 첫 후보의 로컬 검증 — 2026-10-13

Root가 실행한 focused 검사 14/14가 통과했고, 그 안의 사전 동결한 독립 acceptance 4/4는 baseline에서 0/4였다. 합성 소스의 실제 Wakeio Action runner 입력, 0/1/2 gate, 보고서 쌍과 외부 다운로드 디렉터리에서의 create/finish를 검증한 범위다. 독립 Standards 코드 읽기 검토의 actionable 항목은 0이며 문서 자체를 독립 검토했다는 주장은 하지 않는다.

전체 required-engine receipt는 `status: passed`, 1101/1101, failed/skipped/cancelled/todo 모두 0이다. Node 22.22.1과 준비한 실제 engine을 사용한 기존 owned-loopback 회귀를 포함한다. 실행 전후 source fingerprint는 동일한 `80fcea9f10dd1a4b6d3e062d7af66e576bb7282852df6816c6da97513721e7f3`(256 files, 3362453 bytes)이다. private local-only receipt 경로: `artifacts/action-onboarding-2026-10-13/required-receipts/required-engine-bZYiON/receipt.json`. 원 실패 재현은 local-only `artifacts/action-onboarding-2026-10-13/baseline-receipt.json`이다. 외부 대상 소스·raw report는 이 문서에 포함하지 않는다.

이 로컬 검증은 GitHub 다운로드 서비스, 실제 PR merge ref 보존, 공개 SHA의 존재·신뢰, fresh package consumer 또는 hosted workflow 성공을 증명하지 않는다. 배포/호스티드 결과는 해당 실행의 별도 receipt와 PR/CI 기록에서 확인한다. npm 0.5.0 발행, live model 호출, 새 OSS 취약점 발견, 확인한 취약점/수정 또는 전체 프로젝트 안전을 주장하지 않는다.

후속 독립 Spec 검토에서 SDK `renderWorkflow`가 caller getter를 반복해서 읽어 검증했던 값과 출력 값이 달라질 수 있는 사례를 root가 재현했다. 이는 임의 JavaScript를 실행할 수 있는 신뢰된 SDK caller 경계의 public validation 약속에 관한 결함이며, CLI 입력 경로의 보안 취약점으로 해석하지 않는다. 첫 후보의 1101/1101 기록은 해당 단계의 결과로 보존한다. 안정적인 입력 정규화 수정과 회귀 검증 이후의 receipt가 최종 구현 근거이며 아직 이 문서에 성공으로 기재하지 않았다.

### 최종 로컬 검증 — 2026-10-13

Renderer는 알려진 입력 9개를 한 번 읽어 plain snapshot으로 보존하고 tools 배열을 복사한 뒤 검증·렌더링하도록 수정됐다. Root 최종 실행은 focused 15/15, CI support 18/18, required suite 1102/1102이며 failed/skipped/cancelled/todo는 모두 0이다. 독립 acceptance의 동결 파일 hash는 유지됐다. Root의 YAML 비교에서 README 영문·한글과 `examples/github-action.yml`의 workflow는 생성기 결과와 정확히 일치했다. 수정 후 독립 Standards delta의 actionable 항목은 0이다.

최종 required receipt는 private local-only `artifacts/action-onboarding-2026-10-13/required-final-receipts/required-engine-ociTfP/receipt.json`이다. 실행 전후 source fingerprint는 동일한 `c22453d19661436123c8529dd35b444dcd3e9126d0a5c1e8cb0348b525951b9f`(256 files, 3364118 bytes)이며 세 단계 모두 exit 0·cleanupConfirmed true다. 이 문서 동결은 로컬 source 구현 검증까지의 기록이다. 패키지 consumer·GitHub hosted 전달 결과는 각각의 별도 receipt와 최종 PR/CI 기록에서 확인하며 여기에서 아직 실행 성공으로 주장하지 않는다. 사용자 안내에는 첫 후보의 일시적 검사 수나 대기 상태를 넣지 않는다.
