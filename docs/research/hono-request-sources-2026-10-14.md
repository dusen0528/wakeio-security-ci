# Hono request source의 제한된 정적 연결

2026-10-14. 이 변경은 같은 파일에서 선언한 Hono route callback의 request
입력이 기존 outbound-request·SQL·process sink로 이어지는 경로를 추가한다.
Callback 인자의 이름을 `c`, `context`, `incoming` 등으로 바꿔도 선언한
등록 위치를 기준으로 인식한다. 대상 Hono·pg 패키지나 앱을 설치·import·실행한
결과가 아니며, finding은 candidate이고 runtime verification은 `not_run`이다.

같은 고정 56개 corpus에서 최종 엔진은 TP 27·FP 0·FN 1, supported 27/27을
기록했고 strict exit 0이었다. 기존 known miss 1개는 그대로다. 이 결과는
아래의 좁은 정적 수용 기준이며 production 탐지율이 아니다.

## 원천과 구현 범위

Hono의 [App API](https://hono.dev/docs/api/hono)는 import한 Hono instance에
HTTP-method handler를 등록한다. [Request API](https://hono.dev/docs/api/request)는
query·path parameter를 읽는 `query`/`param`과 awaited JSON body를 읽는 `json()`을
설명한다. 이번 모델은 그 API 중 다음 선언 형태만 다룬다.

- 정확한 `'hono'`의 named `Hono` ESM import와 immutable same-file
  constructor/app alias, 인자 없는 `new Hono()`를 인식한다.
- Literal path와 한 개의 inline 또는 immutable local handler를 받는 직접
  dot HTTP-method 등록과 같은 형태의 chain을 다룬다. Callback의 첫 인자가
  Context이며 두 번째 `next`는 request input이 아니다. Default app export와
  read-only `app.fetch` serving 참조는 허용한다.
- Context의 `.req`와 직접 dot `query`/`param`을 읽는다. 이 두 method는
  인자 없음 또는 literal key 하나만 다루며, JSON은 zero-argument `json()`의
  promise를 `await`한 결과만 data source로 사용한다. 이미 읽은 scalar나
  JSON promise의 provenance는 이후 request replacement 때문에 사라지지 않는다.

Request alias와 지원하는 local helper의 실제 인자 전달을 다루지만, generic
`ctx` 이름이나 관련 없는 `.req.query` 객체만으로 Hono source를 만들지 않는다.
Type-only Hono constructor·local fake·namespace import, app/constructor/handler mutation과
opaque escape, fluent-result escape, 관찰된 공유 request 변경은 등록 증명을
취소한다. Runtime `hono/*` subpath import/load도 보수적으로 제외하며 type-only
import는 runtime 효과로 보지 않는다. 따라서 정상 middleware/helper import도
이 좁은 범위 밖에 남을 수 있다.

Middleware 여러 인자·`.use`·composition·imported handler·동적 route·optional
call·spread·opaque computed access·detached method·추가 request API는 이 모델의
지원 선언이 아니다. Request mutation과 opaque effect는 미해결을 유지한다.
완료된 JS/TS 언어 분석은 이 선언 범위 밖의 Hono 경로나 전체 앱 coverage를
증명하지 않는다. [언어 coverage 계약](../source-code-coverage.md)을 함께 읽는다.

pg의 fixed SQL + separate values 제외는 별도 증명이다. 유효한 Hono read의
현재 분석 context에서 만든 내부 data witness를 사용하며, 일반 `await`,
`JSON.parse`, unknown call을 data라고 허용하지 않는다. Taint를 sanitize하지
않고 array/config·dispatch·reference closure를 유지한다. Getter·`toPostgres`·
mutation·opaque escape는 fixed-values 제외를 취소한다.

JSON values-only 제외는 더욱 좁다. 전체 snapshot에서 **handler proof 제거 전의
syntactic Hono 등록 하나와 potential JSON reader 하나**가 있어야 한다.
유효한 Context의 직접 `c.json(...)` response serialization은 reader 수에서
제외한다. Context의 모든 참조는 같은 handler의 직접 request read 또는 허용한
response call이어야 하며, request/Context alias·opaque escape·`bodyCache`·
사용된 `next`·반복 JSON read와 늦은 request effect는 제외 증명을 막는다.
JSON 결과의 ordinary const field alias는 전체 reference graph가 pristine일 때만
허용한다. 관찰된 `Request`/`JSON` mutation과 opaque intrinsic 접근도 JSON
data 제외를 막는다. 정상 `JSON.stringify`와 fresh `new Request`는 허용하지만
hostile runtime package authenticity나 realm 격리를 증명하지 않는다.
이 조건은 JSON의 SQL data 제외에만 적용하며 request source 인식과 taint를
없애지 않는다. 버전마다 같은 객체를 반환할 수 있는 [Hono v4.6 request cache](https://github.com/honojs/hono/blob/v4.6.0/src/request.ts)를 일반적인 새 JSON 객체라고 가정하지 않는다.
구현 근거: [Hono role](../../src/source/hono-role.ts),
[dataflow](../../src/source/dataflow.ts), [SQL role](../../src/source/sql-role.ts).

## Clone과 CI에서 쓰는 동선

Node.js 22+와 이 모델을 포함한 검토한 GitHub source build를 사용한다.
아래 명령은 cloned 앱을 데이터로 읽으며 앱의 install·build·test를 실행하지 않는다.
보고서는 source 밖의 새 디렉터리에 둔다.

```sh
node /path/to/wakeio-security-ci/build/src/cli.js doctor \
  --source /path/to/cloned-app --tools none --require-code-analysis --strict

node /path/to/wakeio-security-ci/build/src/cli.js scan \
  --source /path/to/cloned-app --project-id OWNER/APP --tools none \
  --require-code-analysis --fail-on high --out /path/outside/cloned-app/before
```

Scan exit 1은 threshold finding, 2는 미완료·오류이며 0도 선언 범위만 뜻한다.
`report.md`의 gate·근거·한계를 읽고 `ID`와 zero-based `Check index`를 선택한다.
[선택적 advice](../agent-advice.md#advice-for-one-selected-row)와
[source handoff](../source-handoff.md)는 그 선택을 별도 로컬 검토와 동일 옵션
재검사에 연결한다. 이 동선이 자동 patch나 verified fix를 만드는 것은 아니다.

CI에서는 이 모델을 포함한 reviewed full SHA를 Action ref로 선택해야 한다.
이전 pinned Action 예제나 published package가 새 모델을 자동으로 얻지 않는다.
Workflow 생성·artifact·실제 checkout source 연결은
[Action onboarding](../init-action-onboarding.md)에 따른다. 이번 변경은 npm
발행을 주장하지 않는다.

## 고정 corpus와 현재 증거

공개 corpus v4는 [query→fetch 양성/고정 destination 대조](../../benchmarks/fixtures/hono-query-fetch-vulnerable/app.ts),
[param→pg SQL text/bound data 대조](../../benchmarks/fixtures/hono-param-sql-vulnerable/app.ts),
[awaited JSON field→pg SQL text/bound data 대조](../../benchmarks/fixtures/hono-json-sql-vulnerable/app.ts)를
추가했다. 각각의 fixed fixture와 분모는 [benchmark README](../../benchmarks/README.md#corpus-v4-three-hono-source-pairs)에 연결했다.
신규 JSON 쌍의 ordinary immutable field alias도 입력에서 유지한다.

56 cases는 28 vulnerable·28 fixed, expected 28은 supported 27·기존 known miss 1이다.
이 라벨은 선언한 정적 패턴의 수용 기준이며 실제 취약점·안전 정답이 아니다.
기존 v3의 50 case 객체와 55 fixture 파일은 `c96b48a`에 대해 바이트 단위로
변경 없음을 확인했다. 같은 고정 corpus와 harness를 다음 두 엔진에 적용했다.

| 측정 | Complete | TP / FP / FN | Supported TP | Strict exit |
| --- | --- | --- | --- | --- |
| Frozen `c96b48a` baseline | 56/56 | 24 / 0 / 4 | 24/27 | 1 |
| 첫 Hono 구현의 중간 측정 | 56/56 | 27 / 1 / 1 | 27/27 | 1 |
| 최종 현재 엔진 재검사 | 56/56 | 27 / 0 / 1 | 27/27 | 0 |

Baseline은 신규 양성 3개를 모두 놓쳤고 신규 fixed 3개는 finding 없이 완료했다.
중간 측정은 신규 양성을 관찰했지만, JSON field alias의 fixed pg values 사례에
오탐 1개를 냈다. 이 실패 때문에 fixture·라벨을 바꾸지 않고 alias proof를
보강했다. 이후 중간 후보는 이 corpus를 통과했지만 별도 cross-handler
검토에서 isolation 문제가 확인돼 최종 판정으로 사용하지 않았다.
등록 제거 전의 count와 cached JSON·intrinsic 경계를 보강한 최종 빌드로
같은 입력을 재검사했다. 기존 known miss와 strict 정책은 그대로이며,
기존 50개 결과의 observed signature·counts·check status도 최종까지 유지됐다.

Private receipts는 로컬 전용 `artifacts/next-request-source-audit-2026-10-14/hono-v4/`
아래 `freeze-receipt.json`, `baseline/benchmark.json`, `current/benchmark.json`,
`comparison-interim.json`과 `candidate-2/benchmark.json`, 최종
`acceptance/benchmark.json`·`acceptance-receipt.json`이다. 최종 receipt는
동일 corpus/harness, 85개 built JS와 working build의 복사 전후·측정 후
일치, 기존 50개 결과 불변, strict exit 0을 확인한다.

| 최종 고정 입력·출력 | SHA-256 |
| --- | --- |
| Corpus manifest | `bc815bea491d1e4164f44b778e25546decdfef60c100748b9ef2bb8a9ac256be` |
| Corpus files fingerprint | `b403f25dcecfc91c0699da6af62165fb93d7d6725bd4296c8e15aa6a530ca065` |
| Frozen harness | `f6fa883f47aee1da324034a36dd7be352db660353c4a5b44f07e578940d648d6` |
| Final 85 built JS fingerprint | `b0b066a338c76b18787c63c644de490a8e81e9ca4519d17648aeee5027712d1d` |
| Final benchmark JSON | `64ed87ec976d307de52667d926f23a94c8ad912ab6575372c223abc9884939a8` |

Corpus/JS fingerprints는 sorted relative path·NUL·file SHA-256·LF 목록의
SHA-256이며 각 receipt에 목록과 기준을 보존한다.
[제품 회귀](../../tests/source-hono-role.test.ts)와
[독립 source 회귀](../../tests/source-hono-review.test.ts)는 trace·mutation·
shared subpath import·actual helper transfer·fixed operand·미완료·report 경계를
검증한다. [Benchmark 회귀](../../tests/benchmark.test.ts)는 v4의 56/28/27
분모, 기존 known miss 1개, FP rate, strict/미완료/예외·failure artifact를
검증하며 Node.js 22에서 14/14 통과했다(fail/cancelled/skipped/todo 0).
명령은 `node --test build/tests/benchmark.test.js`, log는 위 private 경로의
`benchmark-focused.log`다. 전체 required suite·패키지·GitHub 통합은 별도
릴리스 기록에서 확인한다.

이 corpus는 같은 팀이 작성한 acceptance/regression 집합이며 blind holdout이나
production precision/recall 측정이 아니다. 실제 production OSS의 source 판정과
runtime/control 확인은 별도 scope·보고서·근거가 필요하다. 이번 감사의 별도
Next 이름 대조에서도 `request`는 candidate/exit 1이지만 `incoming`은 0/0인
gap을 확인했다. 두 경우 strict 언어 coverage는 완료였다. 그 private receipt는
`artifacts/next-request-source-audit-2026-10-14/receipt.json`이며, Hono 개선이 이
Next gap을 해결했다고 주장하지 않는다.
