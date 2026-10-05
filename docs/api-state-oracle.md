# 소유 합성 API의 resource/state 검증 pilot

기존 API v2의 GET 권한 검사를 재사용하면서 실제 저장 resource와 owner·보호 데이터·정상 title/contents를 별도 observer로 확인한다. Ghost/고객 API/임의 target의 재현이나 전체 DAST 완료가 아니다. 소스 검사 규칙 `.7`은 유지한다.

## SDK와 실행 예제

```js
import { runOwnedApiStatePilot, deliverOwnedApiStatePilot } from 'wakeio-security-ci';
const result = await runOwnedApiStatePilot({ candidate: 'fixed', timeoutMs: 30_000 });
const receipt = await deliverOwnedApiStatePilot(result, { outDir: 'results/api-state' });
// receipt.finalExitCode is the acknowledged delivery + comparison outcome.
```

빌드된 패키지의 `node examples/api-state-pilot.mjs fixed results/api-state`도 같은 SDK를 실행한다. candidate는 `fixed`, `ineffective`, `all-deny`, `normal-regression` 네 개의 고정 소유 module만 선택한다. URL·소스 root·worker·observer callback·임의 patch를 실행하는 옵션은 없다. 의존성/DB 설치와 provider/source upload는 없다.

예제 stdout의 `outputRelativePath`를 사용해 `OUT_DIR/RUN_ID/DELIVERY_ATTEMPT_ID/`를 찾는다. 각 `before/`, `after/`, `verification/`에 JSON/SARIF/Markdown/agent-report가 있고 마지막에 `api-state-delivery.json`을 쓴다. 원 API의 before/after gate와 별도 비교 gate는 덮어쓰지 않는다.

| candidate | 원 before API | 원 after API | 비교 |
|---|---:|---:|---:|
| fixed | 1 | 0 | 0 |
| ineffective: status만 변경, 보호 데이터 수신 유지 | 1 | 1 | 1 |
| all-deny: 정상 owner도 차단 | 1 | 2 | 2 |
| normal-regression: marker는 맞고 contents 삭제 | 1 | 0 | 1 |

before는 정상 actor 대조와 무권한 데이터 수신을 확인하기 위해 의도된 취약 source다. 이 위험 finding은 보존한다. 비교 0은 같은 seed/정책·실제 변경 source bytes에서 권한 효과가 차단되고 정상 기능·저장 상태·정리가 모두 유지된 한 합성 fixture의 결과다. 사용자 앱의 patch를 적용한 결과가 아니다.

## Observer와 증거 의미

별도 readonly fd로 저장 JSON resource를 읽고 trusted readResource ledger의 실제 row digest를 연결한다. 보호 효과는 `fetchResource`가 실제 읽은 content-decoded body의 internal passive capture를 독립 해석한다. Server가 제출한 bytes나 worker success boolean, API finding을 observer 정답으로 쓰지 않는다. Capture는 추가 HTTP replay가 아니며 raw wire 전체를 증명하지 않는다.

Owner 정상 판정은 resource ID·canary뿐 아니라 저장 title/contents까지 확인한다. Source/manifest/observer/정책 template·resolved 정책/state/phase report digest가 lineage에 남는다. Hash는 bytes 연결이고 실행자 정직성 서명이 아니다. 같은 host의 악성 코드에 대한 sandbox 보장을 하지 않는다.

`CheckResult.apiStateEvidence`는 optional version1 check metadata다. `phase`, `execution`, `effect`, `normal`, `verification`, `cleanup`, `reasons`, `counts`, `lineage`, `nextEvidence`를 네 형식에 동일하게 투영한다. Phase check의 metadata가 unknown이어도 기존 `api.authorization` 판정은 유지한다. 비교 `api.owned-state-oracle`의 malformed/incomplete metadata는 partial/2로 남는다. Sanitizer는 사실을 인증하지 않는다.

Agent finding의 기존 `verification.state=not_run`, `vulnerabilityConfirmed=false`, `remediationVerified=false`와 remediation `not_verified`는 그대로다. 새 scoped evidence로 이 필드를 true로 바꾸지 않는다. Unknown/cancel/5xx/빈 데이터/잘못된 resource·identity는 차단 성공이 아니며 전체 비교는2다. 유효한 정상 기능 회귀는1이다.

## 제한·취소·저장 재시도

Resource 2개, owner/other/anonymous, phase12 요청씩 총24회다. 기본30초/최대120초의 단일 cooperative deadline을 API 요청과 stage 사이에서 확인하며, 각 phase에 남은 시간만 전달한다. 초기 fixture/state 파일 I/O의 await는 AbortSignal로 중단되지 않으므로 파일시스템이 멈추면 SDK가 30초 안에 반환한다고 보장할 수 없다. 검증 실행의 전체 wall limit은 SDK deadline과 별개인 outer supervisor가 적용한다. API 기존64 request/2MiB 단일·10MiB 누적 body cap을 넘지 않는다. 별도 capture cap은64KiB/응답·1MiB 누적/32 record, store64KiB다. 실제 API 연결 시도와 서버 accepted 수는 실패 때 다를 수 있으며 차이를 숨기지 않는다.

Capture는 coordinator의 고유 phase signal에 등록하고 seal/dispose한다. 공유 caller AbortSignal, 동시/반복 실행에서 다른 API body와 섞이지 않도록 한다. Cleanup 전체(listener/socket/fd/임시 store)는 별도2초 대기 상한이며 timeout은 정리가 완료됐다는 뜻이 아니다. 이 숫자는 hard RAM/host process 격리가 아니다.

`deliverOwnedApiStatePilot(result, {storage?, outDir?})`는 실행에서 만든 retained redacted bytes만 사용한다. Same key/bytes storage 재시도로 API/handler를 재실행하지 않는다. Mutation 가능한 storage argument에는 복사본을 준다. 실패한 delivery를 새 run 호출로 복구하면 HTTP가 다시 실행되므로 delivery-only retry가 아니다.

각 배송 시도는 새 UUID 경로를 사용한다. 저장 receipt는 `publication_only`, `requiresCallerAcknowledgement=true`, `provesFinalProcessExit=false`이며 파일 존재만으로 명령 성공을 판정하지 않는다. SDK 반환 receipt의 해당 attempt ACK와 caller 최종 exit를 함께 확인한다. 예제는 배송 중 command 취소도 최종2로 표시한다. Storage5초 timeout은 ACK unknown이며 underlying I/O/late publication 중단을 보증하지 않는다. 12파일 transaction·durable spool·crash recovery는 미구현이다.

Public report/agent/stdout에는 token·canary·원 resource 데이터·raw body·내부 절대경로를 넣지 않는다. Private raw capture는 phase 후 버린다. 고정 합성 source module과 observer의 독립 리뷰 및 실제 실행 검증만 이 증분의 수용 근거다.
