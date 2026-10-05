# Node fork modulePath 역할 (.8)

기본 AST 모델은 `child_process` 또는 `node:child_process`의 lexical ESM named alias/namespace, const CommonJS namespace/destructuring 및 shadow되지 않은 inline require의 직접 `fork` 호출을 인식한다. 기존 공통 인덱스와 bounded symbol references만 재사용한다. 동적 import, default import, 재export 및 일반 alias graph는 신규 지원 밖이다.

[Node 공식 API](https://nodejs.org/api/child_process.html#child_processforkmodulepath-args-options)의 첫 인자는 실행할 Node modulePath이며 argv/options와 역할이 다르다. 신규 `ast:fork-module-path`는 high severity 정적 후보다. native binding의 tainted 첫 인자는 medium confidence, UNKNOWN_INPUT 또는 바인딩 불변성·scope·index 인증 부족은 low confidence다. 이는 실제 실행, 경로 이탈, 런타임 native identity 또는 취약점 확정이 아니다.

정상 첫 인자가 고정되어 있어도 argv, `execPath`, `execArgv`, `cwd`, `env`의 안전은 판정하지 않는다. 해당 옵션의 입력을 modulePath trace로 복사하지 않는다. 실제 source 위치가 있는 첫 인자의 evidence만 기존 position-only static flow 계약으로 전달한다. mutation/escape 또는 관측한 지원 밖 package load는 native identity를 보류하고 알려진 첫 인자 입력을 unresolved fork-shaped 후보로 남긴다. local object/shadowed require에는 신규 native identity를 주장하지 않는다.

새 role로 인식한 bare fork는 기존 shell heuristic를 대체하여 중복을 막는다. 그 밖의 기존 spelling heuristic는 유지한다. source seed, 일반 taint/trace, local/relative scalar actual-return, scanGate와 finding ID 알고리즘은 그대로다. 후보 집합이나 모든 실제 ID의 동일성을 보장하는 의미는 아니다. cap은 기존 partial 상태와 exit2로 보고하며 모델 밖 외부 호출 자체가 새 incomplete를 만들지 않는다.

metric `forkRoleRecognizedUses`는 무입력을 포함한 관측 call 위치 수다. `forkModulePathInputUses`와 `forkUnresolvedInputUses`는 첫 인자 input-related call 위치 수이며 정확도·실행 횟수가 아니다. NodeBB의 socket/data/member dispatch 및 allowlist 의미는 이번 모델에서 추가하지 않았다. 공개 패치 전후 무후보 기준선은 이 한 sink가 전체 원인이라는 증거가 아니다.

const namespace 지원은 `const cp=require("child_process"); cp.fork(value)`다. `const f=require("child_process").fork` 추출과 일반 alias graph는 신규 지원 밖이다. mixed named import/destructuring의 fork 항목과 let 바인딩은 인식하되 identity를 unresolved로 남긴다. 동일 lexical owner에서 선언 전 직접 호출도 unresolved다. 다른 함수 body의 deferred 참조는 기존 구조적 바인딩 모델을 따르며 런타임 초기화 순서나 TDZ 도달성 증명이 아니다.

## .9 로컬 fork 이름의 제한적 구별

bare identifier `fork(...)`가 실제로 immutable local/지원 relative callable로 해석되고 모든 관측된 actual callee 분석이 완료되면, 그 이름만으로 기존 shell API 후보를 만들지 않는다. syntactic localCall이나 단순 함수 이름이 이 판정의 근거는 아니다. 완료 cache는 기존 actual key를 따르며 어느 context든 미해결·cycle·cap·partial이면 이전 완료 증명도 제외에 쓰지 않는다.

이는 로컬 함수 안전 인증이 아니다. 같은 이름의 함수 내부에서 기존 모델이 지원하는 형태의 native fork·SQL·HTTP·HTML sink 및 반환값을 받은 caller sink는 기존 taint/evidence로 보고한다. 실제 body 분석 완료는 전체 보안 coverage가 아니다. 임의 cp.exec 같은 미지원 alias/API는 이번 증분으로 추가하지 않는다. mutable binding, 지원 밖 alias/escape, direct 선언 전 호출, 불완전 index/analysis에는 기존 heuristic/partial gate를 유지한다. 다른 exec/spawn 이름 heuristic와 .8 native fork arg0 역할은 변경하지 않는다. runtime callable·권한·실행 순서를 증명하지 않는다.
