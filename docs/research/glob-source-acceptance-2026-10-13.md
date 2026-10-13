# glob filename → shell argv 독립 수용 계약 초안

2026-10-13. Wakeio 기준은 root가 지정한 `main` `50eea146f3e45014b248cb72e716d6eb064563fa`다. 작성자는 현재 CLI/dataflow/process 계약 및 공식 advisory·고정 upstream source를 읽었다. 제품 소스 수정, build/test/scan/install/target execution/Git mutation/model 호출을 하지 않았다. 연구 담당자의 정확한 source/dependency manifest freeze와 root 합의 전까지 아래는 **독립 계약 초안**이며 detector 성공 영수증이 아니다. 아직 대량 테스트를 작성하지 않는다.

## 위험 입력이 HTTP가 아닌 파일명인 근거

[공식 GHSA-5j98-mcp5-4vw2](https://github.com/advisories/GHSA-5j98-mcp5-4vw2)는 CLI의 `-c/--cmd` 실행에서 matched filenames가 shell에 전달되는 문제를 설명한다. CLI pattern/command를 입력하는 사용자와 파일명을 통제하는 공격자는 다른 신뢰 경계다. CVSS의 network 분류만 보고 소스 흐름을 HTTP request로 분류하면 안 된다. 일반 glob library API 자체를 이 advisory와 같은 취약 sink로 취급하지 않는다.

Research 담당이 제공한 [직접 부모 source](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/src/bin.mts)의 **로컬 exact bytes** `artifacts/glob-advisory-2026-10-13/source-glob-parent/src/bin.mts`를 읽어 아래 좌표를 확인했다. 기존 browser raw extraction은 내용을 생략해270/271을257/258로 표시했으므로 실제 oracle에 사용하지 않는다. 다음은 로컬 파일의 one-based physical 좌표다.

| 실제 소스 사실 | 증명하는 경계 | 증명하지 않는 것 |
|---|---|---|
| `src/bin.mts:2,4,7`의 foreground-child/jackspeak/local globStream import | 각 역할에 필요한 lexical load와 local export 연결의 출발점 | package 이름만으로 설치 버전·call identity·runtime truth 확정 |
| `:227`의 parser 결과 positionals/values | CLI command/pattern origin | emitted 파일명이 HTTP 요청에서 나왔다는 주장 |
| `:236-241`의 existsSync/filter/join 및 matches 초기화 | 이미 존재하는 positional pathname도 argv 목록에 들어갈 별도 경로 | 실제 filesystem을 스캐너가 실행·조회해 공격자 통제를 입증함 |
| `:242-263`의 globStream 생성 | pattern을 바탕으로 filename/path stream을 생성하는 역할 | `globStream`이라는 이름만 같은 임의 함수의 이벤트도 filename이라는 주장 |
| `:270`의 literal data callback parameter가 matches에 push됨 | filename source 위치와 같은 mutable array content에 대한 기여 | 앞선 무관한 CLI command나 아무 callback parameter를 대신 source로 삼음 |
| `:271`의 end callback에서 같은 matches가 foregroundChild arg1, shell true | 누적된 파일명이 shell argv 역할로 소비될 가능성 | 실제 subprocess 실행·악용 확인·원격 취약점 발견 |

원 source text나 공격 filename payload는 공개 finding 증거에 복사하지 않는다. Source 좌표/role/enum/version/budget만으로 흐름을 설명한다. HTTP 이름 `req`를 fixture에 도입해 기존 taint를 재활용하거나 CLI command arg0만 발견한 결과를 filename argv 검출 성공으로 세지 않는다.

## 현재 Wakeio와 새 기능의 정확한 차이

현재 `src/source/dataflow.ts:38-49,234-260`의 RootKind/sourceRootForName은 HTTP/browser/form 계열이다. `ProcessRoleModel`은 `PROCESS_METHODS`의 여섯 Node API를 exact child_process binding으로 판정하며, `ChildProcessBindings`는 source load identity/lexical shadowing/mutation/index 완결성을 검사한다 (`src/source/process-role.ts:6-21,44-48`, `src/source/fork-role.ts:7-32,146-170`). `.mts`가 collector/parser 대상인 사실은 filename source·stream callback·array accumulation·wrapper semantics를 지원한다는 증거가 아니다.

이번 기능은 source origin과 mutable array content 및 callback 연결, 별도 foreground-child wrapper role을 추가하는 것이다. Native binding 검증을 약하게 하거나 모든 `.on`/`.push`를 input source로 만드는 것은 요구가 아니다. 일반 shell false argv의 후보 제외, 실제 위험 operand trace, role unknown/partial, 다른 정상 context가 위험 context를 덮지 않는 기존 process 계약을 유지한다. [`docs/process-role.md`](../process-role.md)

## full-flow를 인정하기 위한 독립 근거

다음 항목을 모두 확인한 flow만 “filename source가 shell argv에 도달한다”로 집계한다.

1. **Source/dependency identity:** frozen origin source의 local import/export graph가 filename-producing glob stream 역할로 연결된다. Wrapper는 frozen foreground-child source/version 또는 별도로 검토한 bounded semantic contract와 맞는다. Dependency range만으로 특정 버전 실행을 증명하지 않는다. Shadowed/local/dynamic load는 별도 상태다.
2. **같은 stream:** 생성 receiver와 literal `'data'` 등록 receiver가 같은 객체 관계로 연결된다. Literal `'end'` 등록 역시 같은 stream이어야 한다. 다른 event 이름·다른 stream·opaque registration은 support를 추측하지 않는다.
3. **Callback source:** 실제 data callback parameter를 source로 기록한다. 이름은 `f`, `filename`, `item` 등 무엇이어도 lexical parameter identity로 해석하며 이름 자체를 taint 근거로 삼지 않는다.
4. **Array content:** 같은 matches/cmdArg 객체 content가 push/spread/지원한 변형으로 누적되고 sink arg1에서 소비된다. `push` 반환값은 array의 내용이 아니라 길이이므로 filename taint와 섞지 않는다. 서로 다른 array나 무관한 이전 입력을 trace로 빌리지 않는다.
5. **Wrapper role:** 실제 foregroundChild overload의 program/args/options 위치와 shell 전달을 독립 근거로 판정한다. 두 exact glob lock은 `foreground-child@3.2.1`의 같은 npm integrity를 선언한다. Research가 제공한 로컬 source `source-foreground-child-3.2.1/src/index.ts:72-99`는 overload normalize, `:135-142`는 options dispatch, `:14`는 POSIX Node/Windows cross-spawn 선택이다. 3.2.1 published archive bytes는 lock integrity와 일치한 data-only manifest로 연결한다. 먼저 읽었던 [v3.1.1 source](https://github.com/tapjs/foreground-child/blob/v3.1.1/src/index.ts)는 **역사 참고**이며 실제 대상 wrapper version의 oracle이 아니다. 하나의 v3 source를 임의 버전·Windows runtime 전체의 증명으로 확대하지 않는다.
6. **Shell boundary:** argv가 shell 문자열 재해석 경계에 들어가는지, separate positional argv인지 분류한다. 실행 명령 문자열과 파일명 argv의 역할을 분리한다. `sh -c`의 command operand 위험은 generic shell:false Node option 제외와 별도로 읽어야 하며 “shell:false = 프로그램 전체 안전”이라고 설명하지 않는다.

## parent/fix 정답의 mode 분리

Research의 exact pin/hash/lineage freeze 후 아래 mode expected를 manifest로 먼저 고정한다. Advisory의 두 release-line fix—`1e4e297…`와 `47473c0…`—및 각각의 direct parent를 혼동하지 않는다. 이번 primary-source 읽기에서는 [1e4e297 수정](https://github.com/isaacs/node-glob/commit/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f)과 [47473c0 수정](https://github.com/isaacs/node-glob/commit/47473c046b91c67269df7a66eab782a6c2716146)이 같은 filename 경계를 바꾸는 것을 확인했지만 최종 test pin은 research manifest로 결정한다.

| Mode/oracle | 독립 기대 판정 | 피해야 하는 거짓 성공 |
|---|---|---|
| 실제 parent 전체 source, 명시 cmd execution branch | filename stream source→동일 accumulated array→정확한 foreground sink에서 shell true 후보. 선언한 graph가 완결이면 medium static candidate; unresolved identity가 있으면 low/conditional·partial 표시 | HTTP source trace 또는 command arg0 발견만으로 filename flow 성공 집계 |
| 실제 fix 전체 source | source에 여러 runtime branch가 있음을 보고. 위험 fallback/opt-in branch는 남을 수 있으므로 파일/프로젝트 전체 무후보를 정답으로 요구하지 않음 | patched version 기반 blanket suppression 또는 no findings를 실제 default 실행/취약점 제거 증명으로 사용 |
| fixed default direct argv, 별도 owned mode fixture | 명시 shell false/default-disabled와 fixed executable의 filename arg는 filename-shell 후보 제외. 다른 실행 선택/프로그램 옵션 위험은 별도 | benign argv 항목까지 command taint로 합쳐 false positive |
| fixed known-shell positional path | filename은 인자 배열에서 command operand와 분리되고 인용 positional reference로 소비됨. 그 좁은 filesystem filename-shell 재해석만 제외할 수 있음 | raw filename이 command string에 직접 연결된 변형도 같은 safe path로 제외 |
| fixed explicit unsafe opt-in / unknown shell fallback | declared enabled mode는 후보 유지. parse flag/runtime 분기 identity가 미해결이면 conditional/unknown 유지 | 전체 fix를 clean하게 보이기 위해 retained unsafe branch 은폐 |
| callback/array/wrapper/source identity 미지원 변형 | 선언된 관계가 끊기는 위치와 missing support/analysis gap 표시; source-related evidence가 있으면 low candidate 유지. 근거 없는 새 taint source 생성 금지 | unsupported flow의 무후보를 검사가 완결된 음성 대조/clean으로 집계 |

Mode fixture는 실제 pinned source를 복제해 안전/위험 분기 차이만 좁히거나 독립적으로 작성한 synthetic case로 표기한다. Actual parent/fix whole-source oracle과 mode-specific synthetic oracle을 별도 분모로 보존한다. 지금은 source를 실행하지 않으므로 런타임 CLI option별 reachability나 exploit success를 주장하지 않는다.

## conditional/unknown/partial의 필수 경계

- 같은 이름의 local/shadowed `globStream`, `foregroundChild`, `jack`, `on`, `push`는 native/package proof가 아니다. Exact local identity가 안전 body로 닫히면 실제 body 분석으로 제외할 수 있지만 이름만 같다고 closed native도 clean도 부여하지 않는다.
- ESM/CJS import의 type-only, unknown package version/range, noncanonical require, namespace export/member reassignment, mutable alias/escape는 wrapper/source native certainty를 제한한다. Source-less unknown에서 완전한 source→sink trace를 꾸며 내지 않는다.
- Callback receiver alias 교체, event computed/nonliteral, callback opaque/captured replacement, end-before-data/미지원 scheduling은 event execution 순서 proof가 아니다. 지원한 lexical event contract의 가능 관계와 runtime 순서를 구별한다.
- Array의 push/unshift/spread, reassign, splice, computed index, getter/proxy, opaque mutator, escape 및 contents replacement는 bounded cell 모델의 한계를 유지한다. 정상 contribution이 위험 contribution을 지우지 않으며 exact clear proof가 없으면 clean 제외 금지다.
- CLI parser 기본값이 false라도 full source의 explicit flag branch를 지우지 않는다. Unknown flag/type/shell/string/overload는 known-disabled로 정규화하지 않는다. Conditional context와 low confidence는 현재 public report 규칙을 따른다.
- Collection/parse/index/flow/context/budget truncation, missing referenced local source, missing required dependency semantics는 completed whole-flow 지원으로 세지 않는다. 근거가 부족하면 `known_unsupported`/gap/partial을 명시하고 absent finding을 측정 accuracy의 true negative로 넣지 않는다.
- 모든 scanner finding은 candidate이며 four report formats의 좌표/trace/budget/gaps/verification 의미가 일치해야 한다. Public gate는 threshold와 incompleteness가 정하며 candidate 존재와 full-flow support count는 별도다.

## exact freeze 이후 합의할 acceptance 방향

먼저 독립 manifest에 advisory ID, direct parent/fix commit, reviewed upstream license, source-path raw SHA-256, source line/column source→accumulator→sink oracle, local graph/dependency source versions·hashes, expected modes, unsupported cases, collection/analysis budgets, roots/exclusions를 적는다. **현재 Wakeio 결과를 읽어 expected를 고치지 않는다.** Root가 scanner baseline code/hash와 manifest를 동결한 뒤 baseline/current를 같은 source bytes와 옵션으로 실행한다.

최소 meaningful groups는 (1) 실제 parent exact filename flow, (2) 실제 fix의 branch classification, (3) default/direct argv 음성, (4) known-shell positional 음성, (5) retained unsafe opt-in 양성/conditional, (6) shadowed/local impostor, (7) import/member mutation, (8) unrelated stream/array, (9) push return length와 benign item/argument false 제외, (10) opaque mutation/escape/unsupported callback, (11) missing graph/version/budget partial, (12) four-format redaction·artifact/source immutability다. 실제 .mts collection부터 trace endpoint까지 검사하되 source fixture execution이나 provider 호출은 추가하지 않는다.

Root가 테스트/build/scan/설치 검증을 실행하며 QA 작성자는 test 계약과 독립 정답을 담당한다. 실제 archive/source checksum과 baseline/source scope가 맞지 않으면 비교를 시작하지 않는다. Cold/fresh consumer 및 bundled Action은 root가 필요한 별도 boundary로 결정하며 synthetic test 개수는 real-world 탐지율로 바꾸지 않는다.

## 라이선스와 상태

최초 읽은 [foreground-child v3.1.1 LICENSE](https://github.com/tapjs/foreground-child/blob/v3.1.1/LICENSE)는 ISC인 역사 참고다. 실제 대상의 glob/foreground-child3.2.1 license/pin은 research 담당의 exact source/published evidence로 확인한다. 이번 문서는 외부 engine/code/payload를 제품에 복사하거나 dependency를 설치하지 않는다. 원 source를 fixture로 재배포하면 `CONTRIBUTING.md`의 notice/attribution 요구를 별도로 충족해야 한다.

현재 상태: independent methodology/primary-source 읽기 완료, exact research manifest와 root test-contract 합의 대기, 제품 구현·검사 성공·runtime exploit·fix verification·release·매출 미주장.

## 로컬 exact bytes 독립 확인

작성자는 source를 데이터로 읽고 SHA-256만 계산했다. 이 숫자는 detector 결과에서 가져온 정답이 아니다.

| exact artifact | commit / raw file SHA-256 | 독립 oracle 좌표 |
|---|---|---|
| glob parent `src/bin.mts` | `1f0c1ca01a5f256cd17f543f83e9aaeedd133939` / `6e57ea10a31296ad2d83eae03dcfd57e4eb70db982728b9ba5b99c41e5a4b3d7` | stream242, source/push270, sink271 |
| glob fix `src/bin.mts` | `1e4e297342a09f2aa0ced87fcd4a70ddc325d75f` / `ae6b53c6faf52ace6c9c823e889c2b0dd1a3af05b142bc39e5c756b1f23f22b3` | stream320, cmdArg seed347, data/push348, positional sink369, dynamic shell fallback379 |

Research의 local manifests가 fix의 direct parent를 위 parent commit으로 연결한다. 두 lock의 `node_modules/foreground-child`는3.2.1이며 integrity는 `sha512-PXUUyLqrR2XCWICfv6ukppP96sdFwWbNEnfEMt7jNsISjMsvaLNinAHNDYyvkyU+SZG2BTSbT5NjG+vZslfGTA==`다. Published manifest는 같은 integrity와 npm archive SHA-256 `e882cea1c6e3127e175a6c5cd9c1398b3cd007b0f5d1c4af76e5d2ff0d5660dc`를 연결한다. Lock은 설치/실행 완료 증거가 아니며 이번 자료는 설치 없이 읽었다.

Actual parent source의 local `index.ts:73-85`는 unset withFileTypes 옵션에서 string stream overload와 `new Glob(...).stream()` 경로를 보여 준다. 이 연결과 관련 class/walk identity가 frozen graph의 범위에 있어야 한다. Type annotation만으로 arbitrary stream의 filename origin을 증명하지 않는다. Exact graph와 negative/unknown mode expectations를 research manifest 및 root 승인으로 고정한 뒤 tests 작성으로 전환한다.

## Research oracle 동결 및 독립 test 작성 승인

Research 담당이 detector 출력 확인 전에 `artifacts/glob-advisory-2026-10-13/independent-oracle.json`을 동결했다. 전달 SHA-256은 `f584b06de913ad02b634003223ff67df143ee753a47e220b863dcaeae220be5a`다. 작성자는 파일을 읽어 exact archive/source/license/dependency 증거와 parent270:23→accumulation270:28→sink271:28, fix348:23→369:30/379:30 좌표를 확인했다. Actual holdout 정답은 이 private manifest가 우선하며 위 초안의 일반 fixture 예상을 actual truth로 대체하지 않는다.

동결된 네 mode는 모두 조건부 source oracle이다. Default 음성은 mode하의 Node shell=false 해석만이며 context-free whole-source clean 기대는 금지다. Explicit unsafe/dynamic generic branch의 unknown/candidate를 유지한다. Known Unix positional branch도 interpreter-role proof가 부족하면 unknown/review candidate가 허용되며 무조건 안전 인증을 요구하지 않는다. Whole-scan exit는 사전에 취약/수정 라벨만으로 정하지 않았다.

Root가 `feat/filesystem-stream-flow` 설계를 진행 승인하고 independent synthetic test 작성 범위를 부여했다. 공개 main API만 사용하며 신규 helper import를 하지 않는다. 실제 upstream source는 repo committed fixture로 복사하지 않고 root가 private immutable holdout에서 실행한다. Tests 기대값은 제품 출력 전에 동결하고 모든 실행은 root가 맡는다.

필수 보강은 일반 TypeScript ESM same-symbol overload dispatch다. Body 없는 overload signature 여러 개와 implementation body 정확히 하나면 실제 body로 연결해야 한다. Duplicate implementation body·type-only import·mutated callable·opaque re-export·index/dispatch budget 미완료에서 단일-body/native proof를 만들면 안 된다. 이 capability는 glob 파일명 흐름에만 special-case하지 않고 별도의 own ESM fixture로 검증한다.

**Observed conditional accumulator는 양성 unknown 증거다.** Same receiver에 parameter가 기여했다는 lexical 관측은 Array 타입, builtin push intrinsic, event scheduling, runtime identity나 실행을 입증하지 않는다. Opaque jackspeak `cmdArg`, dynamic shell flag, 미지원 mutable-array shape를 fixed-default clean 인증으로 사용하지 않는다. Public static-contract 이름/필드·identity 요구를 producer와 합의한 뒤12개 중심 그룹의 작은 test 파일을 작성한다.

## Public contract 합의와12개 independent groups

Producer가 `glob-source-design-2026-10-13.md` 마지막 절에 결과를 보기 전에 계약을 명시했다. 합의된 공개 표현은 `StaticFlow.sourceKind=filesystem_filename`, high/low-confidence `ast:filesystem-shell-input` candidate, `static-context-v1` conditional origin/schedule/accumulator/wrapper 문맥, `filesystemStreamModel=glob-stream-filename-v1` 및 고정 count metrics다. Qualified 양성도 low/truncated/partial이며 runtime proof가 아니다. Generic Node process 규칙과 별도이고 opaque list·flag는 enabled/unknown/interpreter 경계를 보존한다.

`tests/filesystem-stream-independent.test.ts`는 기존 공개 `main`과 report/compare helpers만 import한다. 원래 요청의 `analyzeSource`라는 함수명은 기존 export에 없으며 main으로 source-only CLI 경로를 검증한다. 새 producer helper와 upstream target code를 import/실행하지 않는다. Source·package/lock은 own synthetic data이며 source 실행이나 dependency 설치는 fixture contract에 없다. Root가 actual private upstream holdout을 별도로 검증한다.

| 그룹 | 독립 기대 |
|---|---|
| 1 | 실제 ESM package semantic filename source→same data/shared cell/end→operand1의 정확한 source/accumulation/sink와 high/low/partial2 |
| 2 | HTTP·고정값·benign push·branch·alias가 섞여도 sourceKind와 실제 filename callback source 좌표 일치. HTTP trace/cmd arg0에서 source를 빌리지 않음 |
| 3 | opaque parser list+dynamic shell의 positive unknown, conditional accumulator, actual Array/intrinsic/runtime 미주장 |
| 4 | 명시 false/default-disabled primitive argv와 고정 benign item의 좁은 filename-shell 제외. 전체 clean 강제 없음 |
| 5 | Node shell false여도 explicit interpreter의 filename argv는 unknown/review 후보 |
| 6 | arbitrary emitter·shadowed local name에서 filename origin 발급 금지. v2의 같은 root metadata/Glob 클래스명/local constructor 구조를 흉내 낸 fixed-emitter impostor 포함 |
| 7 | missing/mismatched package/version, import/member mutation은 proof 취소. v2의 declared range/lock 충돌, contradictory shrinkwrap/nested workspace, 무인자 wrapper 비충돌 포함 |
| 8 | unrelated array는 filename taint를 빌리지 않음; 다른 stream/end·computed event 관계가 미지원이면 explicit unknown/partial |
| 9 | push 숫자 반환값은 filename이 아님. Escape/replaced push는 기존 provenance를 safe proof로 바꾸지 않음 |
| 10 | withFileTypes true/dynamic의 string-origin 미지원과 collector truncation을 clean으로 숨기지 않음 |
| 11 | 일반 HTTP source→own ESM two signatures/one same-symbol body→native process의 known positive, named export alias 포함. Glob special-case와 독립 |
| 12 | duplicate body/type-only/mutated/opaque reexport/function-index budget의 incomplete dispatch proof; sourceKind four-format 보존·compare 소실 차단·unknown enum parser rejection/agent partial |

Generic origin metadata의 비교/투영 fixture는 구조 계약을 검증하는 synthetic report다. 실제 source scan이 medium-confidence filesystem evidence를 만들었다고 주장하지 않는다. Actual filesystem 양성은 별도의 high/low/conditional contract로 유지한다.

## Independent 파일 동결 이력

첫12그룹 파일 SHA-256 `b6e0396402e1ee438fe83b331ccc638c6f27ca190ebaa2ad2ee1661df124d8f4`를 root가 `independent-v1-lock.json` 및 source copy로 동결했다. Root는 baseline transpile 설정 NodeNext가 CJS를 출력해 loader failure가 났으며 이를 ESNext로 수정하고 동일 v1을 실행한다고 보고했다. 이는 제품 detector 실패나 expected 수정으로 집계하지 않는다. 작성자는 engine output이나 test 실행 결과를 보지 않았다.

그 후 root가 source-boundary subcase 추가를 명시 승인했다. v2는 그룹 수12와 기존 outcome/expected를 유지하고 group6/7 안에 추가했다: (1) 동일 glob10.4.5 root metadata 및 `globStream→new Glob→new FixedEmitter.stream` 구조만 가진 impostor의 sourceKind 발급 금지, (2) declaration2.x/lock3.2.1 충돌·contradictory shrinkwrap·nested package ambiguity에서 safe exclusion 금지, (3) foregroundChild 무인자 call이 scanner exception 없이 처리됨. 무인자 API misuse만으로 보안 finding을 요구하지는 않는다. 추가 subcase 이전의 v1 lock/log는 보존한다.

v2 제출 SHA-256: `38b0d094703745bef40a5c25466924ca088919c852b049a973b402309547c994`. 아직 작성자의 build/test/scan 실행은0이며 root가 새로 동결해 baseline/current를 검증한다. Unknown evidence를 제품 구현 편의에 맞춰 completed clean으로 바꾸는 기대 완화는 하지 않았다.

Local origin에 관해 **함수/클래스/method 명칭과 metadata만으로는 충분하지 않다**는 독립 기준을 유지한다. 실제 export symbol·unique body·원래 imported class·filesystem-result semantic graph 연결이 필요하며 original class/prototype/member mutation은 provider 변수 shadowing과 별도로 qualification을 취소해야 한다. Actual upstream class mutation은 private holdout의 별도 scoped 변형으로 root가 평가할 수 있고 frozen 원본은 수정하지 않는다.

## 별도 provider semantic boundary 3그룹

Root가 WIP `filesystem-role.ts`의 source-only semantic review와 별도 test 파일 작성을 승인했다. 먼저 작성한 own private negative inputs의 manifest SHA-256은 `e8fc82b754b27ff2704e4e9e3eca193ef66e266417707322695b5e1bdbddd298`다. (1) 호출되지 않는 PathScurry readdirCB/fullpath 메서드와 실제 constant-only 반환 stream의 공존, (2) 원래 연결된 filesystem stream class의 imported alias를 통한 prototype stream 교체가 대상이다. 두 입력 모두 metadata나 클래스 내부 구문 공존을 filename origin으로 인증해서는 안 된다. 미지원 local provider는 partial/2를 유지하고 전체 coverage clean으로 숨기지 않는다.

`tests/filesystem-provider-boundaries.test.ts`에 두 negative를 그대로 옮긴 뒤, 두 번째 입력의 prototype replacement만 제거한 **나중에 작성한 positive control**을 추가했다. Positive는 exact local export→constructor→stream 연결 및 PathScurry read callback entries→fullpath→same-symbol emit parameter→returned Minipass write가 연결된다. Producer는 이 generic connected graph가 의도한 local semantic 지원 범위에 해당한다고 source-only 계약으로 확인했다. 이 입력은 high/low conditional filename candidate, 실제 app callback/accumulation/sink 좌표, partial/2, JSON/agent/SARIF 표현 일치를 요구한다. 모든 local provider 거부로 negative만 통과하는 구현은 이 positive에서 실패한다.

새 파일은 기존 public `main`만 import한다. 신규 helper·upstream source import나 target 실행을 하지 않으며 frozen12 파일은 변경하지 않았다. 새 3그룹 제출 SHA-256은 `20036c1a57f69d6f1fc3bcbc7aaba5bdf6c4a361b3832d737e601a8d4b0b5518`이다. 작성자는 아직 build/test/scan이나 제품 detector 결과 확인을 수행하지 않았다. Root가 실행 전 별도로 동결한다.
