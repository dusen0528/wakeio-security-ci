# 상대 CommonJS 객체 메서드 연결 (.10)

기본 source-only AST 흐름 모델은 아래 두 단계 정적 property 호출을 같은 snapshot의 실제 함수 AST에 연결한다.

```js
// worker-api.js
const jobs = { run(value) { /* 기존 모델이 지원하는 sink 또는 scalar return */ } };
module.exports = { jobs }; // const api = { jobs }; module.exports = api; 도 지원
// route.js
const api = require('./worker-api');
function route(req) { api.jobs.run(req.query.value); }
```

producer의 top-level 단일 const plain child, 직접 literal 또는 top-level const plain wrapper, 유일한 정적 own method/function/arrow, importer의 shadow되지 않은 literal relative require와 const namespace를 지원한다. wrapper의 string-literal/identifier key·shorthand도 가능하다. primitive wrapper metadata는 가능하나 getter/spread/computed/duplicate/__proto__/opaque field는 인증하지 않는다. 임의 객체 alias graph, child를 다른 module에서 가져오는 경로, 세 번째 property hop, receiver-state/this/super는 지원 밖이다. 단순 local object 또는 한 hop으로 이 교차 파일 두-hop 지원을 대체하지 않는다.

공통 charged index의 file·symbol·AST와 모든 관측 importer refs로 identity를 검사한다. producer child/wrapper 또는 다른 importer의 direct/deep/computed write, delete/update, 별도 alias·storage·argument/return·member extraction·reflection escape는 공유 group의 연결 인증을 보류한다. 같은 target의 inline/destructured require, 안전 wrapper가 있는 require, ESM import/reexport/import-equals 및 literal dynamic import도 관측하며 신규 지원 밖 load이면 그 group을 보류한다. 관련 module cycle도 보류한다. require-as-value/cache escape·동적 loader를 관측해 importer 집합을 닫을 수 없으면 신규 group proof를 만들지 않는다. 표준 Node module loader를 ESM/CJS/import-equals/reexport/dynamic import로 가져오거나, 다른 파일의 shadow되지 않은 module.require·정적 module["require"]·cache/opaque module 사용을 관측해도 별도 loader 모델 없이 보류한다. local/shadowed module의 ordinary .require를 native loader로 인증하지 않는다. 이 제한은 collected snapshot 안의 lexical identity이며, snapshot 밖 importer·실제 require cache·런타임 loading/초기화 순서를 인증하지 않는다.

연결한 target에는 기존 actual→formal→sink/return, ordinary scalar local/relative helper, actual context summary/cache 및 position-only trace를 그대로 사용한다. exported methods는 외부 진입 root로 계속 남는다. 다른 context의 미완료를 완료로 덮지 않으며 partial index에서는 알려진 root를 보존한다. 새 호출 연결은 callee 몸체의 전체 보안 API coverage나 실행 가능성을 뜻하지 않는다. **기존 모델이 지원하는 형태의 sink**만 보고하며 임의 shell alias·Socket 입력·권한/allowlist/동적 member dispatch는 추가하지 않았다. 기존 spelling 기반 sink를 객체 method identity라는 이유로 포괄적으로 지우지 않는다.

collection/parse/sensitive exclusion과 최종 index가 가용해야 신규 member proof를 사용한다. 새 key/ref/load/ancestor/cycle 검증은 기존 phase work budget을 소비한다. 기존 caps, source seeds, 일반 taint/trace, Finding ID 알고리즘/schema와 gate0/1/2는 변경하지 않는다. 실제 budget/summary/depth/missing 오류는 기존 partial과 CI2, 지원 밖 shape는 기존 unknown/fallback이다. unsupported 호출의 후보0·CI0만으로 정상 또는 전체 coverage를 확정하지 않는다. unrelated late module_missing은 기존 전체 partial로 남으며 과거 proof를 whole-program 완료 주장으로 승격하지 않는다.

새로운 coverage 의미를 ruleset `2026-10-05.10`으로 구분한다. 정적 후보는 `verification=false`이며 취약점/실행 영향 확정이나 수정 검증이 아니다. 개발/노출된 회귀의 성공을 새 독립 정확도 분모로 세지 않는다.

## Flat scalar exports와 공유 인증 (.13)

`exports.fn`, `module.exports.fn`, `module.exports={fn}`의 flat callable도 기존 두-hop child와 같은 canonical producer·관측 importer 인증을 사용한다. static alias key와 단일 top-level const wrapper, flat scalar+const child 혼합을 지원하며 direct/index 호출을 같은 file로 검사한다. exact const named destructuring(aliases 가능)과 namespace direct 호출만 지원한다. nested/default/rest/computed/array binding은 flat export로 읽지 않는다.

Producer의 복수 whole 대입·whole/property 혼합·duplicate/opaque/getter/spread·module/exports shadow, callable의 mutation/escape, 모든 관측 importer의 write/alias/escape와 loader/cycle 결격은 group 전체 인증을 보류한다. 알려진 indexed target 발견과 인증은 분리하므로 pre-init·mutation·receiver·generator·scope 실패에도 exported root가 사라지지 않는다. 실제 찾지 못한 target을 추정하지 않는다.

Receiverless ordinary async scalar 함수는 기존 actual→formal→body 분석을 유지하나 async/generator 반환의 SQL/HTTP 안전 proof는 복원하지 않는다. generator/async-generator callable 인증은 보류한다. 이는 Promise/iterator 런타임 모델 추가가 아니다. Filefound 미인증 export는 actual-site `module_export_unsupported`·partial2와 기존 low/truncated known-input fallback을 유지한다. Shadowed local require는 native loader로 취급하지 않는다. `.13`은 기존 direct legacy map 우회를 제거하며 pure ESM과 일반 source/sink/budget/trace/gap 상한은 변경하지 않는다.

Const wrapper의 flat 값은 나중 export 시점이 아니라 literal 생성 시점에 초기화를 검증한다. Property assignment의 primitive sibling도 whole literal과 같이 callable이 아닌 닫힌 데이터다. Indexed declaration의 실제 lexical scope로 top-level shadow와 무관한 nested local module/exports를 구분하며, local 객체만으로 pure ESM을 CJS로 분류하지 않는다. Genuine CJS와 default/empty export 등 ESM marker가 혼합되면 named callable map 크기와 무관하게 인증을 보류한다.
