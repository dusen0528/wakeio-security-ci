# 실제 OSS 근거와 다음 확장 우선순위 (2026-10-13)

## 판단

다음 단계는 **공개 보안 권고의 실제 취약 부모/수정 커밋을 독립 기준으로 먼저 동결하고, 전체 입력 흐름을 설명하는 지원 범위를 추가하는 것**을 추천한다. 가장 구체적인 후보는 glob CLI의 파일명 입력 → stream callback → 배열 누적 → foreground-child → shell argv 경로다. 기존 HTTP 입력/native child_process 모델에서 벗어나는 실제 운영 도구 사례이며, 단일 sink 이름을 추가한 합성 시험으로 끝낼 작업이 아니다.

기존 교육용 앱의 partial을 억지로 completed로 만들거나 기존 7-flow 점수를 복구하는 것을 목표로 삼지 않는다. 새 실제 소스에서 baseline보다 추가로 설명한 경로, 잘못 제거하지 않은 위험 분기, 유지한 미완료 근거를 각각 보고해야 한다. 상용 수준의 유용성·정밀도·사용자 수정 성공은 현재 증거로 입증되지 않았다.

이 문서는 조사와 제안이다. 제품 코드, corpus, oracle, denominator를 수정하지 않았고 scanner도 실행하지 않았다. 대상 의존성 설치/import/build/test/server/DB/DAST, 모델 호출, 공개 disclosure, maintainer 연락, Git mutation은 하지 않았다. CONTRIBUTING의 candidate/observation/partial 및 source redaction 계약을 적용했다. 외부 소스는 데이터로만 읽었다.

## 동결 근거와 날짜

작업 시작 시 읽기 전용 `git rev-parse HEAD`는 `36c8341b69fecc663de8498295277289e7fbeb2b`였다. 이 HEAD의 새 OSS 측정 결과는 이 조사에서 만들지 않았다.

| 입력 | 관찰된 상태 / SHA-256 |
| --- | --- |
| [기존 corpus](../../benchmarks/oss-corpus.json) | 7개 흐름, 2개 고정 교육용 앱. SHA `eadd5883b9f7a92b455d42af66947418bb2dfed4b5b7ea5d34bc823796a84e94` |
| [이전 조건부 OSS 결과](../../artifacts/oss-efficacy-2026-10-13/oss-conditional-final/oss-benchmark.json) | `measuredAt=2026-10-12T23:09:09.172Z`; 당시 5/7, partial, exit 2. SHA `29c069438fc559adf00da6e76f09cd0ca0173c7e6fa390a04f077a30761df6c7` |
| [DVNA 최신 process replay receipt](../../artifacts/process-role-2026-10-13/dvna-replay-2/receipt.json) | `2026-10-13T02:01:55.606Z`–`02:02:00.892Z`. SHA `d33b8fea4a67ae702b17808791db984710dcbc22154bde3989e2e868d5b11445` |

5/7는 **이전 executable·시점의 결과**다. 현재 HEAD의 재측정값이나 일반적 recall이 아니다. 더 오래된 `nosql-root-final-corpus`에는 6/7가 저장되어 있지만 당시 실행 fingerprint가 다르다. [사전 기준표](oss-source-efficacy-2026-10-13.md)와 [조건부 context 계약](../source-conditional-context.md)을 함께 읽어야 한다. 이 조사에서는 corpus를 바꾸거나 unknown을 supported/clean으로 다시 이름 붙이지 않았다.

## partial의 원인은 서로 다르다

### Juice Shop: 전체 checkout 분석량과 실제로 불완전한 교육 조각

이전 `oss-conditional-final`의 Juice Shop은 수집 issue 0이어도 AST index가 incomplete다. `functionsIndexed=8000`, `maxFunctions=8000`, incomplete reason은 `function_limit`이며 parse 오류 39개가 별도로 남는다. Gap summary는 function_limit 318 events 전부 상세 목록에서 dropped, parse_error 39 events 중 7 dropped를 기록한다. Dropped는 발견 수나 취약점 수가 아니다.

Parse 위치들은 `data/static/codefixes`의 독립적으로 완성되지 않은 함수/표현식 조각이다. [예시](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/codefixes/localXssChallenge_1.ts)처럼 학습 화면에 넣는 조각을 독립 TS 파일로 parse하는 한 해당 오류가 실제로 존재한다. 단순 cap 증대는 parse 오류를 해결하지 않는다. 일부 registered route witness가 있어도 전체 source 완료를 선언할 수 없다.

지원 개선 여지는 root 작업 계획/예산, 명시적 source scope, 필요 파일을 모으는 bounded dependency closure다. 다만 교육 파일·tests를 삭제한 새 scope는 원래 whole checkout과 다른 입력이다. 원래 영수증을 보존하고 **별도 scope hash·포함/제외 목록·분모**를 가진 보조 측정으로만 사용해야 한다. 그런 측정의 completed는 그 범위만 뜻한다.

### NodeGoat: 구현한 조건부 흐름과 실제 dispatch 증명이 다르다

이전 조건부 결과에서는 index complete, parse 오류 0이다. 미완료는 `module_export_unsupported`: 317 gap events, 상세 102 dropped다. [server.js](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L132)의 routes 호출, [route 구성](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L11-L21), handler constructor, owned callback, DAO/collection이 이어지는 여러 경계가 원인이다.

N2의 threshold→DAO→`$where`→find 조건부 경로는 이미 구현되어 있다. [현재 계약](../source-conditional-context.md#nodegoat-n2와-독립-수용-기준)은 source `allocations.js:21:13`, call `:23:9`, parameter `allocations-dao.js:57:45`, operator `:78:21`, find `:86:9`와 여섯 context item을 명시한다. 새 작은 NoSQL sink 규칙을 제안할 단계가 아니다. 기존 oracle의 N2는 known_unsupported이고, 새 조건부 witness는 독립 검토 대상이다.

N3의 기존 요청→redirect witness도 사라진 것과 동일하지 않다. 조건부 dispatch/entry 가정이 더해져 low/truncated가 되어 기존 exact oracle을 충족하지 못했다. 점수 회복을 위해 context를 지우면 증거가 약해진 이유를 숨긴다.

Node의 [module wrapper](https://nodejs.org/download/release/v22.22.1/docs/api/modules.html#the-module-wrapper), [cache](https://nodejs.org/download/release/v22.22.1/docs/api/modules.html#requirecache), [resolve](https://nodejs.org/download/release/v22.22.1/docs/api/modules.html#requireresolverequest-options)는 module-local loader, 공유 cache 교체, 실행하지 않는 filename lookup을 구분한다. **일부 lookup 구문을 더 정확하게 분류하는 capability 개선**과, 동적 로더/외부 실행의 identity를 소스만으로 확인할 수 없는 **기존 runtime-unknown 경계**는 다르다. 단순 `require.resolve` 관찰을 실행으로 오인하는 보수성은 개선 후보지만, 동적 require를 안전한 loader로 인정할 근거가 되지 않는다.

### DVNA: 입력 역할이 더 분명해졌지만 추가 발견은 없다

최신 replay의 vulnerable pin `9ba473add536f66ac9007966acb2a775dd31277a`에서 baseline/current 모두 실제 `req.body.address` source `core/appHandler.js:39:22`→exec sink `:39:2`를 관찰했다. 둘 다 candidates 3, partial/exit 2, index complete, parse 오류 0, entry partial 18, `module_export_unsupported` events 40이다. Current의 `processRoleRecognizedUses=1`, `processCommandInputUses=1`은 역할 설명을 뒷받침한다. 같은 site의 추가 발견을 입증하지 않는다.

Historical fixed-pattern pin `4fe36fcfbd615fc9ea340e1238be33dd0d140ef8`에서는 둘 다 candidates 0, partial/exit 2, index complete, parse 오류 0, entry partial 22, 동일 reason events 65 중 14 dropped다. Current는 argv-only exclusion 1을 기록한다. [기존 독립 조사](process-role-references-2026-10-13.md#독립-http-소스-양성과-역사적-수정-패턴)처럼 이 fix의 부모는 이미 IPv4 guard를 갖고 있다. Master positive와 historical fix는 다른 source의 패턴 대조이며 직접 취약→수정 실효 쌍이 아니다. 후보 0을 앱의 안전성이나 전체 수정 확인으로 해석할 수 없다.

## 3개 공백의 우선순위

| 순위 | 구체적 공백 / 다음 산출물 | 근거와 수용 조건 |
| --- | --- | --- |
| 1 | **공개 advisory의 실제 parent/fix를 동결한 holdout + filesystem/CLI process 경로 지원** | glob의 실제 패치는 아래와 같다. baseline/current를 같은 바이트로 root가 읽고, 실제 배열·callback·wrapper 경로를 추가했는지 확인한다. Source 이름만 바꾼 합성 pair로 성공 처리하지 않는다. |
| 2 | **CJS/native/API 증명 실패 원인을 분해하고, 증명 가능한 loader observation만 개선** | 현재 `module_export_unsupported`는 export mutation, var/dynamic export, callback/constructor 지원, opaque loader 등을 뭉뚱그린다. 실제 위치와 실패 원인을 구분하면 사용자가 확인할 다음 근거가 생긴다. Closed/conditional/unknown authority는 그대로 유지한다. 진짜 동적 loader와 observed mutation은 계속 veto다. |
| 3 | **whole-source와 명시적 production scope를 병렬 보고하고 모든 잔여 후보를 독립 adjudication** | Juice Shop의 parse/function cap과 미등록 교육·test 코드를 구분한다. 기존 부분 결과 보존, 별도 scoped input fingerprint, 각 후보의 route/guard/source/control 근거가 필요하다. 기존 [triage](../../artifacts/oss-efficacy-2026-10-13/unreviewed-triage.md)는 더 오래된 18-site snapshot이므로 현재 전체 precision 증거가 아니다. |

1순위의 **증거 동결이 먼저**다. CLI가 현재 서비스 범위에 부적합하면 2·3순위를 먼저 진행할 수 있다. 이 경우 새 실효 탐지 향상을 약속하지 말고 개선이 검사 완료 가능성인지, 수동 검토 시간을 줄이는 것인지 측정해야 한다. 전체 corpus를 completed로 만드는 것은 세 작업의 자동 결과가 아니다.

## 1순위의 독립적인 실제 positive/fixed 근거

[Maintainer advisory GHSA-5j98-mcp5-4vw2 / CVE-2025-64756](https://github.com/isaacs/node-glob/security/advisories/GHSA-5j98-mcp5-4vw2)는 glob CLI에서 공격자가 영향을 줄 수 있는 파일명을 argv로 모아 shell에 전달하는 문제를 설명한다. Core library API 전체의 취약점으로 확대하지 않는다. 대상 source/license/pin은 제품 구현 전 독립 manifest로 동결해야 한다.

- **직접 부모 positive**: `1f0c1ca01a5f256cd17f543f83e9aaeedd133939`, [src/bin.mts](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/src/bin.mts#L225-L258). glob stream 결과가 callback line 257의 `matches.push`로 누적되고 다음 line 258의 foregroundChild argv에 들어간다. GitHub는 one-based, raw browser 표시의 zero-based 번호와 혼동하지 않는다. Shell 옵션은 literal true다. 요청-shaped heuristic을 이용해 filename을 req로 가장해서는 안 된다.
- **직접 수정**: `1e4e297342a09f2aa0ced87fcd4a70ddc325d75f`, [공식 patch](https://github.com/isaacs/node-glob/commit/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f). 실제 parent 관계도 확인했다. Default 분리 인자, known-shell positional 인자, opt-in unsafe 분기가 나뉜다. Maintainer [test source](https://github.com/isaacs/node-glob/blob/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f/test/bin.ts)는 safe positional `--cmd-arg`와 unsafe `--shell`을 별도 expectation으로 갖는다. 이 시험 파일을 읽었지만 실행하지 않았다.
- **Wrapper 원천**: [foreground-child v3.1.1 source](https://github.com/tapjs/foreground-child/blob/v3.1.1/src/index.ts)는 overload를 normalize한 뒤 Node spawn에 전달한다. Glob의 [parent package manifest](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/package.json)는 foreground-child range를 선언한다. Range만으로 실제 설치 버전/실행 identity가 입증되지는 않는다. 적용 버전 pin·source/lock·허용 overload를 별도로 정하고 unsupported 버전은 unknown으로 둔다.
- **라이선스**: glob의 [고정 LICENSE](https://github.com/isaacs/node-glob/blob/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f/LICENSE)는 ISC다. 외부 소스를 제품에 복사하지 않았고 redistribution을 할 경우 CONTRIBUTING의 attribution/notice 절차가 필요하다.

이 advisory와 exact parent/fix는 서로 다른 학습 snapshot을 패턴으로만 비교한 DVNA보다 강한 **소스 변화 원천**이다. 우리 detector의 검출 성공, 로컬 재현, 개선 크기는 아직 없다. Git tree/file SHA와 source archive SHA는 이번 web read만으로 만들어진 것으로 주장하지 않는다. Root가 안전한 DATA ONLY snapshot과 해시를 확보한 뒤 scanner 입력으로 쓴다.

## 구현 제안과 false-clean 방지 조건

필요한 재사용 능력은 네 가지다: (1) 선언된 filesystem stream의 data callback 입력 origin, (2) 특정 actual stream/callback/captured array의 bounded 누적과 end 소비, (3) identity/version/overload를 제한한 process wrapper 인자 역할, (4) CLI option/default와 branch별 shell 상태를 설명하는 값 모델이다. EventEmitter의 임의 `.on('data')`, 일반 `.push`, 이름이 같은 foregroundChild를 모두 신뢰하면 안 된다. 알려진 mutation/escape/다른 소비자와 동적 옵션은 proof를 취소하며 source trace를 잃으면 gap을 남긴다.

엄격한 full-flow 기능이 너무 넓으면 **version-gated wrapper 역할 + 실제 source의 unresolved-origin observation**까지만 먼저 만들 수 있다. 이때도 full glob path 검출 성공으로 보고하지 않는다. CLI parser 전부를 흉내내거나 임의 wrapper를 실행해서 identity를 얻는 방식은 이 과제 범위 밖이다.

| 독립 검증 대상 | 요구 결과 |
| --- | --- |
| Parent의 실제 stream filename→matches→shell argv | Root baseline/current read에서 exact source/callback/accumulation/argv/sink 또는 명시적 unresolved hop. 지원이 완성되면 실제 경로의 추가 관찰인지 baseline과 비교한다. |
| Fix의 default, separated argv / explicit shell false 경로 | 해당 shell interpretation 패턴이 제거되었다는 제한된 negative. Executable 선택, interpreter 의미, 옵션 주입 전체의 안전성은 주장하지 않는다. |
| Fix의 opt-in unsafe `--shell` 분기 | 위험 source path가 남아야 한다. 전체 fixed checkout을 zero-finding expectation으로 지정하지 않는다. |
| Dynamic shell value / opaque CLI parser default | unknown/candidate 또는 partial. CLI flag 선언의 default false가 모든 invocation에서 false를 의미하지 않는다. |
| Known Unix interpreter + quoted positional args 경로 | 별도 검토 대상. 단순 shell:false만으로 명시적 interpreter의 안전성을 인증하지 않는다. |
| Mutable/escaped wrapper, unrelated EventEmitter, altered callback array | Native/package source identity와 actual 연결이 부족하면 confidence/trace/gap을 보존한다. 공백을 “안전”으로 이름 붙이지 않는다. |

위 표는 계획이며 통과한 시험 결과가 아니다. 최소 acceptance는 실제 upstream parent와 fix의 **같은 선언된 위험 경로**를 독립적으로 설명하고, unsafe opt-in 분기를 놓치지 않으며, 이전 7-flow·DVNA 결과와 보고서 계약을 보존하는 것이다. 기존 corpus 숫자와 새 holdout 결과는 별도 분모다. Maintainer 시험은 패치 의도 근거이고 우리 엔진 시험·고객 결과는 아니다.

## 상용 효용을 확인하려면 남는 일

교육용 앱·공개 advisory는 선택된 known-vulnerable 예시다. 실제 제출된 프로젝트에서 발견되는 후보를 모두 독립적으로 검토하고, 확인된 actionability, 설명을 읽는 시간, 정확한 수정 요청 생성 여부, 재검사 시 같은 scope 유지 여부, 미해결 gap 처리까지 측정해야 한다. 새로운 기능의 local tests와 root-owned source replay가 통과해도 이 사용자 효용·가격 지불·상용 성능은 미확인이다. 현재의 honest partial/unknown 경계는 비용이 아니라 안전한 보고의 일부다.
