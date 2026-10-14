# 수집 snapshot 안의 alias·ESM barrel과 diagnostic handoff

2026-10-14. Baseline은 main
`4089839320f21bcc526b024cfcb587db2e031c30`이다. 이번 변경은 수집한
JavaScript/TypeScript 함수 body를 더 명확히 연결하고, finding이 없는 미완료
check도 로컬 검토 packet으로 넘기는 범위다. Target dependency 설치·import·build·
test·server, provider 호출, source upload는 하지 않는다. 경로 해석과 함수 body
연결은 실제 HTTP caller origin, 실행 가능성, 취약점 또는 수정 검증이 아니다.

## TypeScript 원천과 이번 모델의 차이

공식 [paths 설명](https://www.typescriptlang.org/tsconfig/paths.html)은 mapping
기준을 `baseUrl`, 없으면 config 파일 위치로 설명한다. 또한 `paths`는 emitted
import를 바꾸지 않으므로 runtime/bundler가 같은 mapping을 사용한다는 증명이
되지 않는다. [Modules reference](https://www.typescriptlang.org/docs/handbook/modules/reference.html#paths)는
wildcard의 가장 긴 prefix와 여러 target의 fallback을 설명한다. 이번 모델은
**fallback array를 지원하지 않고 target 하나만 허용**한다.

설치된 trusted TypeScript `5.9.3`의 `lib/typescript.js`를 데이터로 읽어 다음을
대조했다. Target 프로젝트의 TypeScript나 plugin을 실행한 결과가 아니다.

| 설치된 5.9.3 구현 | 확인한 동작 | Wakeio 범위 |
| --- | --- | --- |
| `parseConfigFileTextToJson`, 42493 | JSON parser를 통해 config object와 diagnostic 생성 | 수집한 JSONC 문자열만 trusted parser에 전달 |
| `matchPatternOrExact`, 22753 | exact key 우선 | exact mapping 우선 |
| `findBestPatternMatch`, 3638 | 가장 긴 prefix, 같은 길이면 먼저 만난 pattern 유지 | 같은 우선순위를 적용 |
| `getPathsBasePath`, 20349 | baseUrl 또는 paths의 config 기준 경로 | baseUrl 또는 선택한 config directory만 사용 |
| `tryLoadModuleUsingPaths`, 46417 | mapping target들을 순회; 빈 capture는 target의 `*`를 치환하지 않음 | 단일 target; 빈 capture 뒤 `*`가 남으면 unsupported |

공개 primary 구현은 TypeScript v5.9.3의
[core](https://github.com/microsoft/TypeScript/blob/v5.9.3/src/compiler/core.ts),
[moduleNameResolver](https://github.com/microsoft/TypeScript/blob/v5.9.3/src/compiler/moduleNameResolver.ts),
[commandLineParser](https://github.com/microsoft/TypeScript/blob/v5.9.3/src/compiler/commandLineParser.ts)에서
확인한다. 초기 empty-capture 치환 가정은 이 대조 뒤 철회했다. Matcher가 빈
capture를 인정한다는 사실과 target lookup을 구분하며, 존재하지 않는 directory
index 연결을 만들지 않는다. Target에 wildcard가 없으면 빈 capture도 그 고정
target을 가리킬 수 있다.

## 채택한 snapshot 범위

[module-config](../../src/source/module-config.ts)는 filesystem을 다시 탐색하는
compiler resolver가 아니다. Collector가 이미 읽은 `tsconfig.json`/`jsconfig.json`
문자열만 사용한다. Importing file의 가장 가까운 ancestor config를 고르며,
같은 directory에서는 tsconfig가 jsconfig보다 우선한다. 이는 제한된 snapshot
convention이며 실제 build가 선택한 config를 인증하지 않는다.

- JSONC의 plain compilerOptions와 exact 또는 one-star `paths`를 다룬다.
  Target array는 정확히 하나여야 한다. Snapshot 밖, absolute/backslash/escape
  경로와 지원하지 않는 mapping은 선택하지 않는다. `baseUrl`은 paths target의
  기준이며 독립적인 bare-specifier fallback 전체를 구현하지 않는다.
- `extends`, project `references`, `rootDirs`, `moduleSuffixes`는 지원하지 않는다.
  Nearest config가 malformed/unsupported이면 부모 config로 조용히 fallback하지
  않는다. Plugin은 실행하지 않고, `include`/`exclude`로 scan 입력을 줄이지 않는다.
- Config 한 개 64 KiB, 전체 128개·1 MiB 제한과 기존 charged index work를 적용한다.
  Source graph는 수집된 파일들만 후보로 사용한다. 확장자 후보가 여러 개면
  TypeScript의 모든 mode별 우선순위를 흉내 내지 않고 ambiguity로 남긴다.

[modules](../../src/source/modules.ts)는 named ESM function body와 named re-export,
unique `export *` chain을 따라간다. 서로 다른 runtime export, 충돌, cycle, missing
module, unknown edge, depth/work budget은 편한 target 하나로 해결하지 않는다.
지원하는 sibling에 요청한 export가 없다는 사실은 conflict와 구분하지만,
missing/unknown sibling을 단순한 absent export로 취급하지 않는다.

**순수 relative-only lexical barrel**은 기존 resolved authority를 유지한다.
어느 edge라도 configured alias를 사용하면 body는 **conditional**이다.
`static-context-v1`의 새 `configured_module_resolution` kind가 이를 표시하고,
finding의 confidence·trace/context·partial gate가 그 한계를 보존한다.
Config로 발견한 body는 runtime module identity나 negative safety certificate가
아니다. Native/role identity용 `resolveSourceModule`은 relative-only로 유지한다.

Configured alias body는 **baseline-first FIFO deferred inspection**으로 검사한다.
기존 top-level과 declared entry root를 먼저 처리한 뒤 남은 기존 flow budget으로
queue를 소진한다. Caller는 검사한 body의 return, callable/receiver capability 또는
sanitizer 결과를 받지 않는다. Call 시점의 fallback은 unknown/input provenance를
보존할 뿐 body 분석으로 정당화한 반환값이 아니다.

Queue에는 공유 mutable heap 대신 plain input/root/trace/properties의 bounded snapshot을
넣는다. Native role과 negative certificate capability는 제거한다. Snapshot copy와
queue/drain 작업도 기존 shared budget에 과금하고, queue count·copied values·trace·
depth·cycle 한도를 유지한다. 한도 초과나 검사하지 못한 body는 partial과 dropped
진단으로 남기며 기존 root 수나 budget cap을 늘려 성공을 만들지 않는다. 이 scheduling
계약의 실제 OSS 보존 여부는 아래 동일 cohort 재측정으로 별도 확인했다.

Default-export object, namespace/object method graph 전체, CommonJS alias,
mutable/opaque dispatch, rest/spread/computed callback의 의미를 이 증분이 해결하지
않는다. Alias/barrel만 연결해도 HTTP field origin, database/schema 의미와 모든
route의 실행 경로가 따라오는 것은 아니다.

## Native package identity의 보수적 경계

Config가 native package 이름을 local module로 돌리거나, 그 mapping을 판단할 수
없으면 기존 negative certificate를 그대로 사용하면 안 된다. 수집 snapshot
전체의 관찰된 runtime load를 감사해 해당 증명을 취소한다. 알려진 input의
positive flow는 유지하며, 불확실한 candidate·conditional context와 partial을
남긴다. Erased type-only load는 runtime 변경 근거가 아니다.

감사 대상은 유한한 family set이다: `pg`, `pg-pool`, `pg-native`, `axios`,
`child_process`, `url`, `fs`, `path`, `glob`, `minipass`, `unzipper`,
`foreground-child`, `marsdb`, `mongodb`, `hono`, `koa`, `express`, `next`.
관찰하는 import·literal load 형태와 그 family의 subpath 범위만 다루며 모든
runtime loader, package authenticity, ambient realm을 인증하지 않는다.

[dataflow](../../src/source/dataflow.ts)의 SQL values-only, HTTP payload/encoded-query/
fixed-destination, process argv/fork, NoSQL string, filesystem/archive, Express
MIME 관련 negative certificate는 이 identity/context 경계를 따른다. `paths`에
mapping이 있다는 이유로 외부 API의 안전한 동작을 local shim에 부여하지 않는다.
기존 baseline에서 보인 certificate gap의 교정이며, 이것을 새 취약점 발견이나
whole-project 탐지율 증가로 계산하지 않는다.

## 지표의 단위와 검증 기준

`moduleGraphModel`은 `snapshot-configured-esm-functions-v1`이다. 다음 값은 서로
다른 단위이며 더하거나 coverage·route·vulnerability 수로 해석하지 않는다.

| Metric | 단위 |
| --- | --- |
| `moduleConfigurationsObserved/Supported/Unsupported` | 관찰한 config와 제한된 config subset 판정; 전체 TS/build 지원이 아님 |
| `moduleConfigurationBytes` | 검사한 config 문자열 bytes |
| `configuredModuleTargets` | unique importing-file/specifier/selected-file tuple; 함수 실행 수가 아님 |
| `configuredModuleCallSites` | configured body를 선택한 unique AST call node |
| `configuredModuleCallContexts` | 분석 중 configured call 처리 횟수; body 검사 시작 수나 runtime invocation이 아님 |
| `configuredBodyInspectionsQueued/Started/Dropped` | deferred body의 누적 queue 등록·검사 시작·거절/미검사 횟수; dropped에는 등록 전 거절도 포함 |
| `configuredBodyInspectionFlowWork` | baseline root 처리 뒤 deferred drain에 사용한 charged flow work; call 시점 snapshot copy까지 포함한 전체 추가 비용이 아님 |
| `barrelFunctionTargets` | export-name/target function resolution tuple |
| `configuredNativeIdentityComplete/Vetoes` | bounded native identity audit 상태와 관찰한 veto load site |

[독립 graph regressions](../../tests/source-configured-graph-independent.test.ts)는
JSONC·nearest config·precedence, exact/wildcard, named/star exports, absent export와
missing/conflicting/cyclic edge, metadata/index limits, CommonJS 거부, native mapping
및 unknown-config veto와 positive input 보존을 확인한다. 고정 module-resolution
기준과 source-data 대조이며 runtime TypeScript build나 target 앱 실행이 아니다.

[Diagnostic handoff tests](../../tests/source-handoff-diagnostic.test.ts)와
[독립 handoff controls](../../tests/source-handoff-diagnostic-independent.test.ts)는
zero-finding partial check 선택, complete snapshot binding, canonical report pair,
selected-check progress와 full after gate, unknown scope/refused revision/tampering을
검증한다. 자세한 CLI와 v1/v2 구분은 [source handoff](../source-handoff.md)에 있다.
기존 finding packet은 v1이고 diagnostic packet만 v2다. Strict finding comparison은
보존하며, 보고된 check completion을 `fixed`로 바꾸지 않는다.

Source ruleset은 `2026-10-14.2`에서 **`2026-10-14.3`**, advice projection policy는
**13**으로 바뀐다. 서로 다른 ruleset의 비교는 unverified·exit 2다. Advice projection은
source text나 위치를 보내지 않으며 기존 explicit advisory consent/auth 계약을 유지한다.
이번 policy의 실제 provider 실행 증거를 주장하지 않는다.

## 사전 회귀와 릴리스 채택 기준

첫 후보의 동일 source/flags public CLI 대조에서 Umami finding은 4개에서 1개로
줄었지만 개선으로 채택하지 않았다. `flowWork`가 기존 800,000 cap에 도달하며
declared root 1,815개 중 1,062개만 시작하고 753개를 건너뛰었고, 기존 SQL
candidate 3개가 누락됐다. Baseline은 같은 1,815개를 모두 시작했다. 두 보고서의
원래 gate는 모두 incomplete·exit 2였다. Express는 finding 94개를 유지했다.
이 결과는 경고 해소가 아니라 추가 탐색이 기존 root를 선점한 회귀다.
근거는 보존된 `baseline-cli-umami/report.json`과
기각된 `candidate-cli-umami/report.json`이다. 아래 비공개 검증 기록 표에 digest를 남긴다.

따라서 채택 기준에는 동일 고정 source·flags·caps에서 기존 root 실행과 candidate를
보존하는 대조를 포함한다. Deferred 계약은 이 회귀를 막기 위한 수정이며, 코드의
계약 설명과 실제 재측정 결과를 구분한다.

## 최종 source-only 대조와 실제 handoff

[고정 production corpus](../../benchmarks/production-oss-corpus.json)의
[Express commit](https://github.com/expressjs/express/tree/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4)과
[Umami commit](https://github.com/umami-software/umami/tree/60eaaaff60a38efb3c779a250742187ec9201944)을
같은 manifest·harness·configuration·inventory·analysis budget으로 다시 대조했다.
`fairness-independent-review.json`의
SHA256은 `c201a201e8ae3285134d2f4ba6ec8f5fde199c9f1c75d2f716a8f5908d5380d3`이며,
그 receipt에 묶인 `fairness-source-comparison.json`도
digest를 확인했다. 여기서 독립은 같은 팀의 별도 검토를 뜻한다.

| 고정 소스 | Baseline → 최종 finding | 추가 / 누락 | 최종 declared root 시작 / 건너뜀 | 원래 → 최종 gate |
| --- | --- | --- | --- | --- |
| Express | 94 → 94 | 0 / 0 | 3,027 / 0 | partial 2 → partial 2 |
| Umami | 4 → 4 | 0 / 0 | 1,815 / 0 | partial 2 → partial 2 |

98개 모두 site·ID·severity·kind를 유지했다. 97개 row는 전체 내용도 같고,
1개 request-shaped candidate는 conditional source/trace context가 추가됐다.
이 보존 대조는 기존 경고 누락 회귀가 사라졌다는 증거이며 precision 개선이나
새 취약점 발견 수가 아니다.

Umami의 configured target tuple은 650개, call site는 1,111개, call context는
3,136회, barrel function target tuple은 113개다. Deferred body는 3,117회
queued, 1,701회 started이고 dropped 1,435회는 **prequeue 거절 19회 + queued 후
미검사 1,416회**다. 따라서 dropped를 queued-started로만 계산하지 않는다.
Residual drain의 flow work는 356,226이며 전체 flow work는 기존 800,000 cap에
도달했다. 모든 기존 root를 시작했어도 추가 body 검사가 완료됐다는 뜻이 아니고,
보고서는 여전히 partial·exit 2다. Alias/barrel 선언 연결은 전체 HTTP field→SQL
경로나 database 의미를 증명하지 않는다.

최종 `final-cli-express`와 `final-cli-umami`의 canonical report pair로
각각 `handoff create --check-index 1`을 실행해 v2 packet·exit 0을 얻었다.
같은 report를 after로 넣은 `handoff finish`는 둘 다 exit 2,
`selectedCheckProgress.state=still_incomplete`였다. Complete collected snapshot을
재수집해 binding을 확인하고 원본 report pair의 bytes/digests를 유지했다.
Declared scope는 compatible이고 full after gate는 원래 exit 2를 보존했다.
별도 strict comparison은 unverified로 남았으며 Express의 duplicate identity
ambiguity도 숨기지 않았다. 이전 `.2` canonical report의 create는 두 경우 모두
`unsupported_scope`·exit 2였다.

Actual handoff의 `c-final-diagnostic-validation/receipt.json`은
SHA256 `f128fadfdfb50ceeec36323a5267deba6506e923474861ffc1f62b8de250d370`이다.
Packet directory 0700·files 0600, 원래 gate·full after gate·strict comparison,
vulnerability/remediation verification false와 controls `not_run`을 확인했다.
`cross-validation-engine-equality.json`은
이 실행 전후와 해당 측정 시점의 독립 engine·workspace의 built JavaScript 86개가 파일별로 같음을
확인한다. 서로 다른 aggregate fingerprint 방식의 문자열을 같다고 비교하지 않았다.

후속 filesystem 정상 제어 predicate 교정 후 최종 engine으로 같은 source cohort를
다시 측정했다. `release-independent-review.json`과 이에 묶인
`release-source-comparison.json`은 98개 site·ID·severity·kind 보존, 추가·누락 0개,
기존 root 3,027/1,815개 전부 시작·skipped 0, 두 gate partial·exit 2를 확인한다.
이전 수용 측정과 모든 check object·metrics·gaps도 같다. 별도 public CLI의
`release-cli-express`/`release-cli-umami` AST check JSON 전체도 이전 canonical
report와 같았다. 이 cohort에서 소스 분석 결과가 유지됐다는 한정된 증거다.
위 handoff receipt는 앞선 실행 시점의 기록이며, 테스트 harness 조정이 agent
runtime 동작을 변경했다거나 전체 required suite·릴리스가 완료됐다는 뜻은 아니다.

위 private report·receipt는 **검증 머신에 보관하며 공개 GitHub·패키지 배포에는
포함되지 않는다**. 아래 파일명과 SHA256은 해당 기록을 식별하며 공개 다운로드나
제삼자 검증 가능성을 뜻하지 않는다. 공개로 확인할 수 있는 근거는 이 문서의
tracked corpus·source·tests와 primary source 링크다.

| 비공개 기록 파일 | SHA256 |
| --- | --- |
| `baseline-cli-umami/report.json` | `ff78f60838939a01b89cd796af1fbd70bb68916a3110aa7460ed788929ac6754` |
| `candidate-cli-umami/report.json` | `cbd8e4df442c94a0cbdfc7717469d6e25ce15641d3370e6db2a8fa10da2dd25f` |
| `fairness-independent-review.json` | `c201a201e8ae3285134d2f4ba6ec8f5fde199c9f1c75d2f716a8f5908d5380d3` |
| `fairness-source-comparison.json` | `36d34fb3ee4318c8eea11df86c6c708824b2a81008da1157693513dfc6326a8c` |
| `final-cli-express/report.json` | `2949a6e7049261b6068e6e210360582fbe2c9f08c7df73066a8f7856ca7ba1e3` |
| `final-cli-express/agent-report.json` | `69e10b7db1f11d0ca3e446116253dd1c775d863e8819e7559e65afe35882bae1` |
| `final-cli-umami/report.json` | `e59aae65952f135c0a35373be15dfb1a88d6cdbd513da30c2ec829ee4b4d3327` |
| `final-cli-umami/agent-report.json` | `7ddf5e9ab1d5beb860f964c934ef1f7225c47dba19c489abb5fee2552df25720` |
| `c-final-diagnostic-validation/receipt.json` | `f128fadfdfb50ceeec36323a5267deba6506e923474861ffc1f62b8de250d370` |
| `cross-validation-engine-equality.json` | `d6448dc3d226c8020488ff65d27a4f15574443a659e2f9722047fa4d7885b6ba` |
| `release-freeze.json` | `d1f1af06b05031d4a749d9bbf925d5d6e19050fcf22b5d2a07873540d538bda9` |
| `release-independent-review.json` | `055f14c0b898b3c25ba197fdccc08a7280afaa26f14cf4feb460806613192c08` |
| `release-source-comparison.json` | `46ee4df8dbd7a3ae986cd06d715cee9f7e5c403d22bc77e6e0045aa485108c7e` |
| `release-measurement/oss-benchmark.json` | `656fcad62b2e5bbaf7c3f26f009c502d96bfcdafee04c931721c4d6625c54cff` |

취약점 의심 목록이나 특정 운영 route의 SQL 내용은 공개하지 않는다.
Same-team 회귀와 선정한 OSS 소스 평가는
blind holdout, 제삼자 audit, production precision/recall, 유료 도구 대체의 증거가
아니다. 전체 required suite·패키지 소비·GitHub 통합도 각각의 릴리스 기록에서
확인하며 이 문서의 계약 설명으로 대신하지 않는다.
