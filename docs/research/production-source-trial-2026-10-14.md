# 운영용 MIT OSS의 고정 source-only 평가

2026-10-14. Wakeio baseline **`c96b48a671660eabde19519f85037a33ba3cee52`**, tree `dabba3005acbf41079792485fb647aa2d2473004`의 이미 빌드된 scanner를 먼저 복사·동결했다. 이후 동시 진행한 Hono feature 코드·빌드는 이 측정에 포함되지 않는다. 아래 결과는 **운영용으로 개발된 OSS의 소스 평가**이며, 배포된 운영 환경을 검사한 결과가 아니다.

첫 고정 전체-root 스캔은 **Express 94행, Umami 4행, 총 candidate 98행**을 냈다. 두 저장소의 수집과 파싱·인덱싱은 끝났지만, AST의 `module_export_unsupported` gap 때문에 **두 scan gate와 benchmark 모두 exit 2**다. 대상 dependency 설치·import·build·test·server·DB·DAST·provider 호출은 `not_run`이다. 실행한 코드는 동결된 신뢰 scanner/collector/benchmark와 자체 검증 스크립트뿐이다.

가장 구체적인 제품 개선 근거는 Express의 **non-string 응답 타입을 HTML sink로 취급하는 경고**와 Umami의 **generic helper parameter를 실제 HTTP 요청 provenance처럼 표현하는 불확실성**이다. 단순히 test/ 디렉터리를 제외하거나 partial을 pass로 바꾸는 해결책을 뜻하지 않는다.

## 고정 표본과 원천

| 대상 | 고정 version / commit | Git tree | tracked 파일 / bytes |
| --- | --- | --- | ---: |
| Express | v5.1.0 / `cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4` | `234b224fd3074adb169a0da0619b624a070a0517` | 225 / 743122 |
| Umami | v2.19.0 / `60eaaaff60a38efb3c779a250742187ec9201944` | `fbb639330def9805000da7bee1a5329468d8d504` | 1302 / 5983022 |

Express는 CommonJS 웹 framework/library와 자체 테스트·예제를, Umami는 Next/Prisma 기반 analytics 앱과 shared client/server helper를 제공한다. 이 고정 버전을 최신 또는 취약점 없는 버전으로 선정한 것은 아니다. [Express release](https://github.com/expressjs/express/releases/tag/v5.1.0), [Express MIT LICENSE](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/LICENSE), [Umami release](https://github.com/umami-software/umami/releases/tag/v2.19.0), [Umami MIT LICENSE](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/LICENSE), [Umami project description](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/README.md).

2026-10-14 GitHub primary API 조회에서 repository star 수는 Express **69,643**, Umami **39,352**로 관찰했다. 이 값은 acquisition-date repository popularity snapshot이며 고정 release별 수치, 사용량·보안 품질·취약점 유무 지표가 아니다. 날짜·URL·HTTP metadata·response digest는 private `popularity-api.json`에 보존한다. [Express API](https://api.github.com/repos/expressjs/express), [Umami API](https://api.github.com/repos/umami-software/umami).

Target acquisition과 이 별도 metadata 조회만 primary GitHub에 요청했다.  Git config/system/global/template/hooks/fsmonitor/filter driver를 격리하고 submodule을 초기화하지 않았으며, 고정 release checkout의 HEAD를 위 full SHA와 대조했다. 모든 tracked 파일의 mode·Git blob·SHA-256을 첫 스캔 전에 기록했다. 기존 [안전 OSS runner](../../scripts/benchmark-oss.mjs)를 수정 없이 복사하여 전체 checkout 무결성을 스캔 전후 검증했다. 소스의 실행 지시·package script·README 명령은 실행하지 않았다.

## 동결한 범위와 기대값

`tools: []`, `analysisProfile: extended`, `maxFiles: 10000`, `maxBytes: 134217728`, 파일당 2097152 bytes, traversal 80000 entries/depth 64를 사용했다. AST의 indexWork 1200000, flowWork 800000, nodeVisits 2000000, functions 8000, summaryWork 20000, moduleEdges 8000, callDepth 8, aliasSteps 64, traceSteps 24를 기록했다. Safe runner의 추가 checkout 검증 cap은 20000파일·2GiB·depth64다. 자동 budget 확대·재실행·소스 축소는 하지 않았다. 기존 runner는 `requireCodeAnalysis: false`를 사용하며 code coverage 근거를 별도로 보존한다. 이미 제공되는 strict 정책을 새 기능이나 이번에 발견한 gate 결함으로 주장하지 않는다.

전체 root를 검사하되 기존 collector allowlist와 제외 규칙을 그대로 적용했다. 테스트·예제도 남겼다. 의미별 분류는 사후 source review에서 했으며, 경고를 줄이려고 파일을 제거하지 않았다. 각 exclusion의 실제 tracked 경로는 private `inventory.json`에 남겼다.

| 수집·AST 결과 | Express | Umami |
| --- | ---: | ---: |
| 수집 파일 / bytes | 182 / 733183 | 862 / 5726461 |
| 수집 code / parsed / parse-valid | 142 / 142 / 142 | 536 / 536 / 536 |
| parse errors / collection issues | 0 / 0 | 0 / 0 |
| excluded tracked files | 43 | 440 |
| AST / indexComplete | partial / true | partial / true |
| indexWork / flowWork | 227522 / 283749 | 272847 / 353508 |
| top-level partial / entry-root partial | 10 / 66 | 7 / 70 |
| module-export gap events / dropped | 226 / 156 | 144 / 86 |
| retained gap items | 32 | 32 |
| code coverage completed / uncovered | 0 / 142 | 0 / 536 |

`completed: 0`은 partial provider를 보수적으로 집계한 결과다. 678개 파일을 전혀 읽지 않았다는 뜻도, 모든 의미를 분석했다는 뜻도 아니다. Gap event는 가중 관찰 횟수이며 unique site 수가 아니다. 한도 소진이나 parse 오류가 이번 partial의 기록된 원인은 아니다. 기존 source.code-coverage check는 strict 미선택 상태라 completed이지만, AST partial 때문에 최종 gate는 2다.

Express 제외에는 `.ejs`20·`.hbs`3·`.tmpl`7이 포함된다. Umami에는 `.prisma`2·`.css`105·`.png`323 등이 제외됐다. 템플릿·schema·embedded code 전체 coverage는 주장할 수 없다. Collector `ignoredFiles`44/441에는 `.git` directory traversal accounting이 포함되어 excluded tracked43/440과 분모가 다르다. [기존 scope 계약](../source-code-coverage.md#scope와-비교의-경계), [collector 제외 규칙](../../src/source/collector.ts).

출력 전에 **전체 zero finding 기대값은 두지 않고**, 아래 다섯 좁은 대조만 고정했다. 줄 번호는 web raw renderer의 공백 생략 표시가 아니라 실제 고정 Git blob에서 확인한 값이다.

| 대조 | 좁은 source-data 기대 | 측정 결과 |
| --- | --- | --- |
| [Express test/res.json.js:117–119](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/test/res.json.js#L117-L119) | 고정 JSON markup을 요청 입력→HTML로 주장하지 않음 | overlap0, unevaluable_scope |
| [Umami response.ts:7–8](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/lib/response.ts#L7-L8) | Response.json을 HTML sink로 주장하지 않음 | overlap0, unevaluable_scope |
| [Umami login route:42–45](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/app/api/auth/login/route.ts#L42-L45) | local JSON wrapper 반환을 HTML로 주장하지 않음 | overlap0, unevaluable_scope |
| [Umami send route:137–143](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/app/api/send/route.ts#L137-L143) | URL parsing을 outbound HTTP 호출로 주장하지 않음 | overlap0, unevaluable_scope |
| [Umami send route:168–176](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/app/api/send/route.ts#L168-L176) | referrer URL parsing을 outbound HTTP 호출로 주장하지 않음 | overlap0, unevaluable_scope |

**다섯 대조 모두 passing negative로 세지 않는다.** Whole scan partial 때문에 runner가 unevaluable_scope를 유지했다. 별도 사전 context인 [Prisma294–306](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/lib/prisma.ts#L294-L306)은 data 값을 positional parameters로 분리한다는 좁은 사실만 확인하며, 임의 SQL 인자·모든 caller의 안전성에 대한 음성 정답이 아니다. Positive vulnerability oracle은0개이며 recall 분모를 만들지 않았다.

## 전체 98행의 판정과 gate 부담

첫 출력 뒤 같은 팀의 모델 보조 검토가 **98행 전부**를 소스와 대조했다. 사전 review cap은 저장소당100행이며 실제94/4행이라 모두 포함했다. Report SHA-256 + checkIndex/findingIndex로 식별하고 IDs로 중복을 합치지 않았다. 39개 source 파일의421개 range/hash reference와 각 행의 주장·판정·추가 필요 근거를 private `adjudication.json`에 보존했다. 검토 시간은 별도 계측하지 않아 reviewer latency/비용 지표는 unknown이다.

판정 축은 source provenance와 sink shape 각각 supported/contradicted/unresolved/not_claimed, path static_connected/statically_blocked/unresolved/not_applicable, actionability actionable_source_pattern/context_only/unresolved다. Test fixture·example app·application helper는 별도 sourceDomain이다. Static_connected는 선언된 소스 연결이며 runtime entry proof가 아니다. 외부 dependency의 선언된 역할·기본 API semantics를 사용한 정적 판정은 installed dependency 검증이나 realm/global-mutation 안전 증명이 아니다.

| 판정·보고 항목 | Express | Umami |
| --- | ---: | ---: |
| candidates / observations / advisories | 94 / 0 / 0 | 4 / 0 / 0 |
| high / medium | 86 / 8 | 4 / 0 |
| source supported / contradicted / unresolved | 64 / 17 / 13 | 0 / 0 / 4 |
| sink supported / contradicted | 61 / 33 | 4 / 0 |
| path connected / blocked / unresolved | 86 / 5 / 3 | 1 / 0 / 3 |
| actionable source pattern / context / unresolved | 5 / 89 / 0 | 0 / 1 / 3 |
| sourceDomain | test75 / example19 / library0 | application helper4 |

Express high86행 중 test75·example11이다. 이 중85행은 이번 소스 판정상 맥락 정보이며,1행만 example의 수정 검토 패턴이다. Medium8행 중4행은 example의 source pattern,4행은 맥락 정보다. Umami high4행은 shared HTTP helper context1·SQL 관련성 unresolved3이다. 이 분포는 **gate/review burden**이며85/86 등을 vulnerability false-positive rate로 계산하지 않는다. 원 exit2는 incomplete 이유와 threshold 이유를 모두 보존한다. `--fail-on none`으로도 partial은 통과하지 않는 기존 계약과 일치한다.

### 직접 확인 가능한 false-claim 예

[Express req.stale getter485–487](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/request.js#L485-L487)은 boolean을 반환한다. [test/req.stale.js:14](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/test/req.stale.js#L12-L15)의 send와 [req.xhr getter496–499](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/request.js#L496-L499) → [test/req.xhr.js:11](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/test/req.xhr.js#L9-L12)도 high HTML candidate다. 그러나 [response.js:123–155](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/response.js#L123-L155)의 boolean/non-null object 분기는 json으로 dispatch하고 [JSON 구현](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/lib/response.js#L232-L251)은 JSON MIME을 설정한다. 해당 fixture의 HTML-output 주장을 수정할 근거다. 같은 유형의 fresh/stale/xhr8행과 container 응답을 포함하여 sink 판정33행을 contradicted로 기록했다. 실제 운영 앱의 receiver/property override까지 해결한 범용 음성 proof는 아니다.

소스 provenance도 별도 문제다. [app.request.js](https://github.com/expressjs/express/blob/cd7d4397c398a3f3ecadeaf9ef6ac1377bd414c4/test/app.request.js#L25-L48)의 request-owned foobar 함수는 로컬 고정 문자열을 반환한다. Request 객체 소유 method라는 사실만으로 반환 bytes를 요청 원문으로 부르면 안 된다. 등록 전 parameter rewrite/error와 fixed mock records도 전체 행 판정에서 별도로 확인했다. 이들은 테스트를 실행해 입증한 결과가 아니다.

### Umami의 네 경고를 취약점으로 올리지 않은 이유

[ClickHouse221/241](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/lib/clickhouse.ts#L199-L245), [Prisma349/305–306](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/lib/prisma.ts#L281-L353)의 trace source는 generic queryParams helper 인자다. SQL text와 value 채널이 분리되어 있으며, query/identifier/orderBy 구조와 route callers의 검증은 별도로 확인해야 한다. Driver binding은 source에 선언된 연산 역할만 인정했다. HTTP origin과 공격자-controlled SQL structure는 이번 trace로 확립되지 않아 sourceClaim과 수정 관련성을 unresolved로 남겼다.

[fetch.ts:38→16](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/lib/fetch.ts#L10-L38)도 generic params에서 시작한다. [buildUrl](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/lib/url.ts#L1-L16)은 URLSearchParams로 query 값을 encode하며, [useApi React hook](https://github.com/umami-software/umami/blob/60eaaaff60a38efb3c779a250742187ec9201944/src/components/hooks/useApi.ts#L1-L45)이 이 helper를 호출한다. 선언된 fetch syntax는 있지만 server realm·public request-controlled destination은 입증하지 않았다. 이를 SSRF 신규 발견이나 이 앱 전체의 SSRF 음성 결과로 표시하지 않는다.

## 제품 결정과 수용 기준

1. **Express send payload semantics를 먼저 좁힌다.** 실제 receiver와 non-string 값/JSON dispatch를 확인할 때만 HTML 주장을 줄인다. 독립 source-data 대조에는 known boolean/container/fixed prototype-return, stringified request input positive, custom property/receiver override·opaque value·partial scope 유지가 필요하다. 파일 경로나 getter 이름만으로 broad suppression하지 않는다.
2. **Helper parameter와 request provenance를 분리한다.** queryParams/params 이름은 caller에서 HTTP 입력이 연결됐다는 근거가 아니다. 이를 실제 source evidence처럼 읽히지 않게 하고, parameter 값/SQL 구조 및 query-string/destination 채널을 구분해야 한다. 실제 request positive와 generic utility control을 함께 보존한다.
3. **Common module-export gap을 조사한다.** 두 보통 크기 checkout에서 parse/index/work limits가 아니라 module_export_unsupported만으로 whole scan이 partial이었다. Cypress/global helpers·CommonJS assembly 등 서로 다른 위치를 하나의 reason으로 뭉뚱그린 상태를 trace하여 좁은 지원 개선/명료한 gap 설명을 선택한다. Gap 수만으로 근본 원인이나 해결 완료를 단정하지 않는다. Strict code-analysis 정책은 이미 존재하므로 그것만으로 이 semantic completion 문제를 해결했다고 주장하지 않는다.

검증할 결과는 특정 false claim의 축소, 실제 string/request 위험 pattern 보존, 불확실성 유지, 같은 root·budgets·source bytes에서의 gap 변화다. 이 corpus를 보고 detector를 개선한 이후에는 **holdout이 아니라 회귀 corpus**로 표시한다. 새로운 별도 표본 없이 professional efficacy·population precision/recall·유료 도구 대체를 주장하지 않는다. [기존 synthetic 평가 경계](../../benchmarks/README.md#corpus-v3-boundaries), [교육용38행 판정의 경계](oss-candidate-adjudication-2026-10-14.md).

## 재현과 private receipt

공개 [production OSS corpus manifest](../../benchmarks/production-oss-corpus.json)는 사전 동결 manifest의 byte-identical copy다. Repository/commit/tree/license·reviewed file hashes·다섯 narrow negative controls만 포함하며, 경고 목록이나 로컬 경로는 포함하지 않는다. Manifest SHA-256은 아래 private 원본과 같다.

다른 사용자는 신뢰하는 Wakeio baseline checkout **`c96b48a671660eabde19519f85037a33ba3cee52`**의 기존 trusted build와 [기존 runner](../../scripts/benchmark-oss.mjs)를 사용한다. 대상 두 checkout은 위 exact commit의 수정 없는 소스여야 한다. 현재 Hono feature engine으로 실행한 결과를 이 baseline 측정으로 표시하지 않는다. Node 버전은 측정과 동일한 `v22.22.1`을 사용하고 output은 두 target 밖의 새 directory로 지정한다. 대상 install/build/test/server는 필요하지 않다.

```sh
NODE22=/absolute/path/to/node-v22.22.1
BASELINE=/absolute/path/to/trusted-wakeio-c96b48a-checkout
CORPUS=/absolute/path/to/reviewed-wakeio/benchmarks/production-oss-corpus.json
EXPRESS=/absolute/path/to/pinned-express
UMAMI=/absolute/path/to/pinned-umami
OUTPUT=/absolute/path/to/new-results
"$NODE22" "$BASELINE/scripts/benchmark-oss.mjs" \
  --manifest "$CORPUS" --profile extended \
  --checkout "express=$EXPRESS" \
  --checkout "umami=$UMAMI" \
  --out "$OUTPUT"
```

Trusted baseline engine의 준비/빌드는 target dependency 실행과 별개이며, 실행 전에 baseline commit·parser/lock·built JS fingerprint를 확인한다. 표의 narrow site-overlap 측정은 공개 manifest로 재현 가능하다. 사후98행 static adjudication은 위 문서의 same-team 검토이며 자동 ground-truth oracle로 배포하지 않는다. 전체 private 원본/검증 receipt는 `artifacts/production-source-trial-2026-10-14/`에 보존한다.

- Frozen built JS: `847b50b32ff218265f75b014f39a4053b3c5eaaa360f3842abbe0b376fd1d484` / 84 files. 이 hash는 built-src JS scope이며 root의 전체 source fingerprint와 직접 비교하지 않는다.
- Node `v22.22.1`, TypeScript `5.9.3`, Wakeio source toolVersion `0.5.0`; npm publication 상태를 뜻하지 않는다.
- Unchanged harness SHA-256: `d2b75eda501fd233f79d1fa1888c1cbfb632bda1a024f89d1d8c648ad4bd597d`.
- Manifest SHA-256: `dff6e694374aaaf10f68f3f457a7e76fa33bf19470db6d60fc7d88e47781f6ec`.
- Benchmark JSON SHA-256: `04bd6889c465c9c53389d5f4e29d237da95ee0f8148b9315badffaf4623c6925`.
- First two-repository runner wall time `3.98s`; target clone acquisition, manual review and follow-up integrity verification are excluded from this timer. Memory peak was not measured.

`freeze.json`, `acquisition.json`, `provenance.json`, `manifest.json`, `predeclared-controls.json`, `pre-scan-lock.json`은 첫 측정 전에 고정됐다. 원 benchmark의 unreviewedCandidates98 필드는 덮어쓰지 않고 사후 판정 sidecar가 reviewed98/unreviewed0을 기록한다. `inventory.json`은 실제 selected/excluded 파일 경로를, `adjudication.json`은 전체98행의 판정과 추가 검증 필요를 보존한다. `verification.json`은720 frozen 파일·421 source references·두 checkout과 canonical report pair·네 report artifact hashes를 재검증한 receipt다. 초기 inventory helper의 잘못된 미사용 export import는 실행 전에 실패했고 이를 제거한 뒤 inventory 검증을 완료했다. 첫 benchmark 출력·기대값·대상 소스에는 영향이 없다.

전체 warnings/source reports와 alleged vulnerability 목록은 공개 문서에 복사하지 않았다. 이 문서는 집계와 좁은 source-claim 예만 제공한다. 판정은 같은 팀의 정적 모델 보조 검토이며 **제삼자 독립 security audit, runtime exploit proof, 수정 효과, production safety 증명은 아니다**. Precision·falsePositives·recall은 null로 유지한다.
