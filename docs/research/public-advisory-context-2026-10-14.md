# 공개 advisory와 rest 인수 위치의 source-only 대조

2026-10-14. 첫 측정 engine은 main
`42a91af38c06e2e978728eccc62daf07bbf2f93b` 기준의 trusted build다.
JavaScript 86개와 선언 파일 86개, scanner source와 dependencies를 별도 사본으로
동결했다. 대상 dependency 설치·import·build·test·server·provider 호출은 하지 않았다.
아래 두 평가의 분모를 합치지 않는다. 알려진 공개 취약점과 로컬 재현 사례이며,
새 취약점 발견이나 runtime 악용 검증이 아니다.

## 공개 serve-static advisory: completed scan도 놓치는 실제 패턴

공식 [GHSA-cm22-4g7w-348p / CVE-2024-43800](https://github.com/expressjs/serve-static/security/advisories/GHSA-cm22-4g7w-348p)는
redirect template의 XSS를 설명한다. 공격자 입력 통제, redirect보다 먼저 template이
보이는 상황과 link 클릭 등의 전제가 있다. 이 실험은 그 전제를 실행해서 검증하지
않는다. 프로젝트의 [고정 license](https://github.com/expressjs/serve-static/blob/0c11fad159898cdc69fd9ab63269b72468ecaf6b/LICENSE)는 MIT다.

| 고정 source | Commit | Tree |
| --- | --- | --- |
| Vulnerable parent | `9b5a12a76f4d70530d2d2a8c7742e9158ed3c0a4` | `bfe296be58719e601f7a6d79cab304568c8faa83` |
| Direct fix | `0c11fad159898cdc69fd9ab63269b72468ecaf6b` | `8755d6ba5050eb6adf97ea4c11192b2a65540a35` |

공식 [fix diff](https://github.com/expressjs/serve-static/commit/0c11fad159898cdc69fd9ab63269b72468ecaf6b)는
`index.js`의 HTML anchor를 제거하고 escaped URL을 plain text로 표시한다.
양쪽에서 같은 escape helper와 Location header를 사용한다. 따라서 helper 이름만으로
안전성을 정하거나 redirect 자체가 사라졌다고 판정하면 수정 의미를 잘못 읽는다.
Parent의 실제 source 좌표는 `this.req` URL 읽기 190, URL 구성 197,
HTML anchor 구성 198–199, HTML Content-Type 203, `res.end(doc)` 208이다.
Fix의 해당 body 구성은 198, Content-Type 202, response 소비는 207이다.
Source 좌표는 수집한 원본 bytes를 기준으로 하며 web parser가 재배치한 줄 번호를 쓰지 않았다.

별도 shallow checkout 두 개의 tracked 파일 23개씩을 읽어 모든 Git blob과 file SHA256을
대조했다. 이 전체 파일 manifest는 baseline scan 후 기록했으므로 출력 전 동결된 oracle이라고
주장하지 않는다. Commit pin과 원본 bytes 일치는 확인했다. 두 checkout 모두 collector는
파일 16개·JavaScript 3개를 선택했고, AST는 170개 entry root를 전부 시작했다.
원래 root를 줄이거나 budget을 늘리지 않았다.

| Source-only baseline | 선택 bytes | Findings | Inventory / AST / code coverage | Gate |
| --- | ---: | ---: | --- | ---: |
| Vulnerable parent | 59,367 | 0 | completed / completed / completed | 0 |
| Direct fix | 59,271 | 0 | completed / completed / completed | 0 |

두 framework check는 not_applicable이다. **공개 취약 parent에서 completed·0건이므로
이 advisory 패턴은 알려진 false negative이며, parent/fix 구분 성과는 없다.** Partial을
이유로 분모에서 빼지 않는다. Fix의 0건도 대응 패턴을 구분한 true-negative 성공으로
계산하지 않는다. 모든 선택된 check가 완료됐다는 사실은 전체 보안 패턴 지원이나
프로젝트 안전성을 뜻하지 않는다. 원본 code에서 callback의 `this.req`, helper-return,
HTML URL context와 Node response 소비를 잇는 의미가 필요하며, 단순 rest 인수 수정이
이를 해결한다고 주장하지 않는다.

## Owned rest 3개: 다른 정답과 분모

ECMAScript 2024의 [IteratorBindingInitialization](https://tc39.es/ecma262/2024/#sec-runtime-semantics-iteratorbindinginitialization)와
[FunctionDeclarationInstantiation](https://tc39.es/ecma262/2024/#sec-functiondeclarationinstantiation)는
rest binding에 남은 인수들을 배열로 넣는다. 아래 owned source는 그 위치 관계를 검사한다.
이 사례들은 이미 관찰한 결함의 회귀이며 blind holdout이나 실제 앱 취약점이 아니다.
독립 source·기대값·hash manifest를 자체 baseline 실행 전에 기록했다.

```js
import { exec } from 'node:child_process';
function helper(...args) { exec(args[1]); }
export function route(req) { /* 아래 actual 인수로 helper 호출 */ }
```

| Actual 인수 | 기대 shell candidate | Baseline 관찰 / gate | 최종 v3 관찰 / gate |
| --- | ---: | --- | --- |
| `('safe', req.query.value)` | 1 | 0 — FN / 0 | 1 / 1 |
| `(req.query.value, 'safe')` | 0 | 1 — FP / 1 | 0 / 0 |
| `(req.query.value)` | 0 | 1 — FP / 1 | 0 / 0 |

세 scan은 inventory·AST completed다. 이는 source-level actual binding의 FN 1개와 FP
2개를 보여준다. Process를 실행한 결과나 원래 advisory의 탐지 수로 합산하지 않는다.
최종 v3는 동일 source·budget에서 **1 / 0 / 0**과 위험 tail의 input→sink trace를
기록했다. 이 한정된 위치 binding 회귀는 교정됐다. Spread/opaque iterable의 위치를
임의로 추측하거나 negative certificate를 새로 부여한 성과가 아니다.

## 최종 v3: 회귀 보존과 남은 miss

Engine 사본은 regenerated build의 JavaScript 86개·선언 파일 86개를 포함하며
owner의 파일별 hash와 대조했다. 최종 `dataflow.js` SHA256은
`8a14dded33c4d2b81973df40a0dc5b3843627ff9130b3333d4a64d12e54bc7e2`다.
앞선 candidate 1·2의 사본과 결과도 보존했다. 작은 rest 3개가 통과한 뒤에도
독립 검토에서 dynamic identifier index와 oversized-tail 비용 경계가 발견됐으므로,
첫 후보의 통과를 최종 판정으로 쓰지 않았다. 최종 계약은 static literal slot과
dot/literal length만 정밀하게 다루고, 다른 computed read는 unknown/input fallback으로
남긴다. Mutation/escape·불완전 index·spread·copy 한도는 정밀한 slot 증명을 제한한다.

같은 exact serve-static parent/fix를 최종 v3로 다시 검사해 **두 경우 모두
completed·finding 0·exit 0**을 얻었다. 위 공개 advisory FN과 구분 실패는 그대로다.
Rest 정확도 개선을 HTML context, callback request origin 또는 실제 CVE 탐지 개선으로
확대하지 않는다.

기존 [synthetic corpus v5](../../benchmarks/corpus.json) 56개를 같은 frozen fixture·harness로
baseline과 v3에 각각 실행했다. 양쪽 모두 56개 completed, TP 27·FP 0·FN 1,
strict exit 0이다. FN은 원래 Koa known miss이며 분모에서 빼지 않았다.
이 지표는 해당 synthetic source 패턴에 한정되며 생산 환경 precision이 아니다.

원래 [production manifest](../../benchmarks/production-oss-corpus.json)·checkout·수집 cap·
analysis budget을 유지한 전체 대조 결과는 다음과 같다. Baseline production engine은
이번 baseline 사본과 built JavaScript 86개가 파일별로 같음을 확인했다.

| Production source | Finding 배열 / ID | Started / skipped roots | Gate |
| --- | --- | --- | --- |
| Express | 94 → 94, 모든 행 내용 동일 | 3,027 / 0 → 3,027 / 0 | partial 2 → partial 2 |
| Umami | 4 → 4, 모든 행 내용 동일 | 1,815 / 0 → 1,815 / 0 | partial 2 → partial 2 |

원래 98행에 신규·누락은 없다. **이 cohort에서 탐지 효과가 증가한 증거는 없다.**
Umami는 같은 800,000 flow cap에서 completed root가 1,257→1,252,
partial root가 558→563이다. Deferred body queued는 3,117→3,110,
started는 1,701→1,687, dropped는 1,435→1,442다. 새 rest 지표는 recognized 0,
unsupported 152, materialized slots 0이다. 추가 uncertainty와 미검사를 숨기거나
cohort를 축소하지 않았고, 행 보존만으로 검사 완결성을 주장하지 않는다.

## 재현과 후속 비교 기준

Trusted baseline checkout의 build와 위 exact upstream checkout을 준비한 뒤 같은 CLI로
각 source를 검사한다. 다음은 재현 방법이며 이 연구에서 target build를 실행한 명령이 아니다.

```sh
NODE22=/path/to/node22
"$NODE22" /path/to/trusted-baseline/build/src/cli.js scan \
  --source /path/to/exact-source-checkout --tools none \
  --analysis-profile extended --source-max-files 10000 \
  --source-max-bytes 134217728 --project-id owned/public-serve-static-advisory \
  --out /path/to/new-report-directory
```

두 disclosed source, 세 owned case, 기존 synthetic 56개 및 원래 production 98행은
별도 분모로 유지한다. Before/after에는 선택 파일·bytes·parse/index 상태·declared/started/
skipped roots·flow work·gaps·candidate site와 trace·gate를 함께 기록한다.
기존 행이 줄면 각 행의 rest operand 근거와 정상 대조군으로 설명해야 한다.
Budget 소진이나 root 미실행으로 사라진 경고는 회귀다. 원래 cohort와 cap은 유지한다.

Source ruleset `.3`→`.4` 변경 후 역사 report 비교는 unverified다. 같은 고정 입력의
engine 정확도 실험과 사용자 patch의 remediation 비교를 구분한다.
이번 rest 수정 후에도 advisory miss는 남은 한계다.

Private acquisition·원본 file manifest·engine freeze·canonical report·로그는 검증 머신의
`artifacts/public-advisory-context-2026-10-14`에 보관한다. 공개 다운로드 링크나 제삼자
검증 완료를 뜻하지 않는다. 초기 receipt는 `baseline-oracle-results.json`,
`source-manifest.json`, `rest-oracle-manifest.json`, `rest-baseline-results.json`이다.
최종 기록은 `candidate-v3-freeze.json`, `candidate3-oracle-results.json`,
`synthetic56-baseline`/`synthetic56-candidate3`, `production-candidate3`와
`final-v3-measurement-review.json`이다. 마지막 receipt SHA256은
`965e3c3497a30fe37b978b3ec1605bcc5624bb55922c39e70e7b0d175ec97e1b`이다.
