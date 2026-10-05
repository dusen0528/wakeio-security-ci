# 제한된 CommonJS class singleton body 흐름

Ruleset `2026-10-05.15`는 수집 snapshot의 top-level local base class를 단일
`module.exports = new LocalClass()`로 내보내고, const relative require importer가
직접 `instance.method(actual)`를 호출하는 형태를 지원한다. Ordinary sync/async
method의 실제 인자를 formal/body로 전달하고 같은 receiver의 직접
`this.other(actual)`를 연결한다. Source/sink는 기존 request-shaped candidate 모델이다.

Receiver identity는 canonical export file·new site·class site이며, invocation·summary
cache·cycle에도 유지된다. 다른 instance의 같은 이름, detached/destructured method,
borrowed/call/apply/bind, nested function/arrow의 this를 합치지 않는다. Method가 fixed
return을 하더라도 body 안의 지원된 SQL/HTTP/HTML/process sink evidence를 수집한다.
Receiver 반환에는 SQL/HTTP/URL 제외 proof를 자동 부여하지 않는다.

Constructor가 없거나 제한된 literal own data-field 할당이면 검사할 수 있다.
선택한 method를 shadow하지 않는 `this.field = new Helper()`는 무인자·same-snapshot
local 또는 relative CJS class의 닫힌 constructor/관측 ref를 별도로 검사하고 값은
opaque로 남긴다. 무관 helper declaration이나 다른 method의 opaque field call만으로
선택한 method identity를 폐기하지 않는다. 외부 constructor 실행/성공/안전성을
인증하지 않는다. Extends/decorator/private/static/accessor/computed/duplicate,
generator, constructor의 명시 return(primitive/undefined 포함), this/class capability
전달·capture·escape·replacement·reflection은 첫 지원 범위 밖이다.

모든 관측 canonical importer의 write/delete/deepwrite/alias/escape/unsupported load와
class/prototype/selected-slot 변경은 인증을 보류한다. Directory/direct spelling은 같은
file identity다. Index/scope/cycle/budget 실패를 닫힌 proof로 승격하지 않는다.

- **Closed**는 선언 구조와 관측 ref·loader closure까지 닫힌 정적 dispatch다. Runtime
  route 실행·외부 side effect·전체 instance/application 안전성을 뜻하지 않는다.
- **Declared**는 선택한 class/helper의 구조와 관측 capability를 검사했으나 native
  nonliteral require 또는 공유 helper의 다른 consumer에서 제한된 미모델 효과가
  남아 runtime callee를 닫지 못한 조건부 body 후보다. Primitive native typeof와 if/conditional에만
  소비되는 module truthiness는 capability escape와 구별한다. 다른 loader alias/cache/
  module escape나 observed mutation을 무시하지 않는다.
- **Rejected**는 구조·관측 ref·초기화·scope/index 등의 다른 실패다. Declared로도
  body를 인증하지 않으며 root/기존 후보는 보존한다.

Declared 호출은 실제 위치에 `module_export_unsupported`와 partial/gate2를 남긴다.
Actual input은 origin/trace가 있는 UNKNOWN_INPUT이고 low-confidence 후보다. 실제
생략된 trace steps만 `truncated`로 표시한다. Cache 조회·저장, called/root 제거,
safe-return certificate는 사용하지 않는다. Input actual이 있으면 fixed return도 caller를
sanitize하지 않아 low 후보를 유지할 수 있다. 실제 body의 fixed noninput URL에는
새 input/source를 만들지 않지만, 후보0/partial은 닫힌 정상/TN으로 세지 않는다.
독립 root에는 declared receiver를 seed하지 않는다.

기존 default/extended `ast-work-v1`의9개 caps·수집 범위·request source·sink·gap 회계는
유지한다. 전역 loader 실행/heap/prototype solver, Promise executor capture, callable Axios,
CommonJS arrow lexical this/custom Agent의 안전성은 이번 모델에 포함하지 않는다.
Class/root/resolved-call 수 증가만으로 전체 source-to-sink 탐지·SSRF·패치 수정 검증을
주장하지 않는다. Static finding의 vulnerabilityConfirmed/remediationVerified는 false다.

R2 review 정밀화: helper binding은 인증할 singleton export/new 실행 전에 초기화되어야 한다. 다른 new 결과를 variable/opaque consumer로 넘기는 class/helper는 지원하지 않는다. Helper를 다른 singleton own field에 두는 경우에도 그 consumer의 관측된 mutation/escape veto를 공유한다. Declared body에서 ordinary helper chain으로 이어지는 호출은 독립 request root를 제거하지 않는다. Input-bearing returned trace가 actual seed보다 우선이며 실제 생략 flag를 보존한다. 고정 noninput return에는 actual-origin fallback만 쓰고 없는 formal/body/return hop을 만들지 않는다.

.15는 기존 closed bool을 복구하지 않고 별도 조건부 자격을 계산한다. 다른 consumer의
정확한 own helper 저장과 모든 관측 importer/whole-this/field/prototype escape를 검사한 뒤,
무관 own field의 flat primitive array/object literal, 초기화된 same-snapshot 무인자 sibling
class 생성, readonly lexical-arrow own call/primitive read만 미모델 효과로 남긴다.
그 효과를 무부작용이나 공유 helper 무변경으로 인증하지 않는다. 임의 call/identifier/
spread/computed initializer·shared helper 전달·alias·깊은 write는 허용하지 않는다.
Sibling constructor/method 그래프·array heap·bind callback을 새로 분석하지 않는다.

Shared helper producer의 bare/return/pass-this, this.constructor/prototype/reflection,
own method 추출/변경은 closed와 declared 모두에서 거절한다. Relative helper와 같은 파일의
ephemeral helper에 같은 guard를 적용한다. 선택 receiver의 기존 hard veto, 초기화와
scope/index/cycle/caps 실패는 다른 consumer의 soft 효과 때문에 완화되지 않는다.

R2의 Broken-only 다른 instance escape 대조는 .15에서 low 조건부 후보가 될 수 있다.
이는 안전 정상/TN 전환이 아니다. Broken에 실제 shared helper를 넘기거나 whole consumer를
넘기는 관측 경로는 hard 거절한다. 조건부 ordinary helper chain의 독립 request roots를
보존하고 반복 조건부 호출을 summary cache에 저장하지 않는다. 무관한 독립 closed 함수의
정상 cache까지 제거하지 않는다. 원 Audiobookshelf SDK 1/3은 후속 동일 oracle 재관측 전까지
유지하며 이 구현 자체를 3/3·SSRF·수정 검증으로 주장하지 않는다.
