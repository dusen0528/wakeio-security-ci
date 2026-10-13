# Glob filename stream → process argv 지원 설계 (2026-10-13)

## 채택한 범위와 근거

부모는 baseline compiled build를 먼저 동결하고 실제 parent/fix 기반 filename flow 구현을 승인했다. 이 설계 작성 시 target 설치/import/build/test/server/DB, scan, 모델 호출, Git mutation은 수행하지 않았다. 개발 코드 작성은 이 계약을 독립 QA에 공유한 뒤 진행한다. [.mts](../../src/source/collector.ts#L91)는 이미 collector/AST/ScriptKind가 지원하므로 새 기여로 세지 않는다.

Actual upstream 입력은 `artifacts/glob-advisory-2026-10-13/`의 data-only snapshots와 로컬 전용 독립 oracle `artifacts/glob-advisory-2026-10-13/independent-oracle.json`이다. Parent `1f0c1ca01a5f256cd17f543f83e9aaeedd133939`, direct fix `1e4e297342a09f2aa0ced87fcd4a70ddc325d75f`의 `src/bin.mts`를 읽었다. Parent의 실제 source/accumulation은 line 270, sink는 271이다. Fix는 source 348, known-shell sink 369, generic/unsafe sink 379다. 이전 조사 문서의 257/258은 이 pin의 좌표가 아니다.

두 glob manifest version은 10.4.5지만 lock이 선언하는 **foreground-child는 3.2.1**이다. 3.1.1은 실제 resolved version으로 쓰지 않는다. 독립 담당이 확보한 로컬 전용 3.2.1 published data manifest `artifacts/glob-advisory-2026-10-13/foreground-child-3.2.1-published-manifest.json`는 두 lock의 SHA-512 integrity와 registry archive의 일치를 기록한다. 설치·실행 identity의 증거는 아니다. [고정 3.2.1 source](https://github.com/tapjs/foreground-child/blob/132a0178990aa4f53a6208bc3bdb90369b35e434/src/index.ts#L14-L142)는 POSIX `nodeSpawn` / Windows `crossSpawn` 분기를 line 14에 두고, `normalizeFgArgs` line 72와 downstream spawn line 142에 argv/options를 전달한다. Package name/version만으로 runtime native identity를 인증하지 않는다.

문서의 `artifacts/` 경로는 Git에서 제외된 로컬 검증용 자료 위치이며 공개 저장소·배포 패키지에는 포함되지 않는다. 공개 upstream 근거는 고정 commit의 GitHub 링크로 참조한다.

## 현재 엔진의 실제 공백

1. [sourceRootForName](../../src/source/dataflow.ts#L234)는 HTTP/web-shaped 이름 중심이다. `f`를 req로 바꾸거나 임의 `.on('data')` callback을 taint source로 삼지 않는다.
2. [collectExports](../../src/source/modules.ts#L388)는 반복 export 이름을 null로 만든다. Glob의 `globStream`은 [고정 parent index.ts 65–85](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/src/index.ts#L65-L85)의 bodyless overload 네 개와 implementation 한 개여서 실제 local export resolution을 먼저 개선해야 한다. 한 implementation과 같은 lexical symbol의 bodyless signatures만 묶고 duplicate actual body/opaque reexport/type-only/mutation은 veto한다.
3. [callback](../../src/source/dataflow.ts#L761)은 actual event parameter 없이 분석한다. Stream allocation·data/end registration·captures를 연결하는 source capability가 필요하다. 실제 local `./index.js` import를 export implementation으로 연결하며 root package name/version이나 path hash를 source로 삼지 않는다.
4. [FlowValue](../../src/source/dataflow.ts#L72)는 literal arrays의 properties/SQL shape를 담지만 일반 `.push` side effect와 callback 사이의 공유 accumulator를 보존하지 않는다. Parent matches는 conditional array/filter-map이고 fix cmdArg는 opaque jackspeak parse field다. Same-symbol accumulation witness는 가능하지만 실제 Array/내장 push/argv overload type의 proof라고 표현해서는 안 된다.
5. [ProcessRoleModel](../../src/source/process-role.ts#L35)은 exact Node child_process family다. Foreground-child를 native identity로 넣지 않고 versioned package-contract role을 따로 둔다. 실제 process API semantics, event scheduling, filesystem attacker control은 조건으로 남긴다.
6. [IfStatement 분석](../../src/source/dataflow.ts#L1199)은 두 분기를 분석/merge한다. jackspeak default false나 옵션 이름만 보고 `shell`을 false로 축소하지 않는다. Fix generic sink의 `{shell}`은 unknown domain/unsafe opt-in 가능성을 유지한다.

## 관찰과 semantic 가정의 분리

| 경계 | 소스로 확인할 것 | 조건으로 남길 것 |
| --- | --- | --- |
| local origin | imported symbol이 unique local export implementation에 연결되고 `new Glob(...).stream()` 및 실제 선언된 local constructor/stream chain을 따름 | glob의 filesystem-result API semantics, runtime monkeypatch/loader/type, 공격자 파일 쓰기 가능성 |
| callback | 같은 stream allocation의 literal data/end registrations, callback parameter, 실제 captured symbol | Minipass 전달·data-before-end scheduling, callback의 실제 도달/반복 |
| accumulator | 같은 captured symbol의 push/spread/unshift와 later operand1 소비 | opaque parser list type, Array intrinsic identity, escape/alias 동작 |
| wrapper | exact ESM foregroundChild symbol, source package dependency/lock version, reviewed overload contract | lock≠installed runtime, POSIX/Windows dispatch 및 crossSpawn/interpreter semantics |
| fix mode | known-shell branch의 observed `-c`/quoted positional construction과 separate generic `{shell}` site | CLI flags·SHELL 값·regex/default domain·actual shell expansion 안전성 |

Source adapter는 library semantic model이다. Advisory-specific path/tree/file hash blacklist, root package 이름만으로 origin 발급, arbitrary emitter/source 이름 규칙은 사용하지 않는다. 수집된 source/dependency metadata가 없거나 중복/버전/형상이 불확실하면 known input을 unknown/truncated candidate로 남기거나 typed analysis gap을 기록한다. 양성 증거가 없다는 이유로 안전하다고 결론내리지 않는다.

Mutable content는 scan/context-local cell로 추적하고 cache key/summary reuse에서 제외한다. Branch clone의 공유는 monotonic union이며 overwrite/path-sensitive exclusion을 주장하지 않는다. Known escape/write/push replacement는 qualification을 취소하되 이전 filename provenance를 지우지 않는다. Callback actuals와 closure captures는 같은 cell을 사용하고 모두 기존 flow/summary/depth/alias/trace 예산에 charge한다. 별도 무제한 AST walk나 target read/execute를 추가하지 않는다.

## 실제 parent/fix 수용 조건

- Parent 270 callback의 filesystem filename origin → matches push/captured cell → same stream end callback → 271 foregroundChild **operand1**까지 실제 observed positions로 추적한다. 사용자 `cmd` operand0를 filename finding의 대체 source로 쓰지 않는다. API/type/schedule assumptions 때문에 low conditional candidate와 truncated trace를 허용하지만 unresolved hop을 숨기지 않는다.
- Fix 348의 filename origin은 cmdArg cell에 남고, 369과 379는 각각 구분한다. 369의 absent shell option은 declared POSIX-wrapper convention 아래 filename의 Node shell 재해석만 제외할 수 있다. 실제 explicit interpreter `-c` operand와 사용자 command의 안전성은 별도 unknown이다. 이를 전체 fixed checkout의 clean 인증으로 쓰지 않는다.
- Fix 379의 dynamic `{shell}`은 default/plain argv와 unsafe `--shell` invocation을 source-only로 확정할 수 없다. Low candidate/partial을 보존한다. 독립 default/plain-argv negatives는 명시 shell false/별도 argv가 확인되는 **한정된 source semantics**이며 whole fixed no-findings expectation이 아니다.
- Version mismatch/missing dependency metadata, altered local implementation, shadow/type-only imports, unrelated emitters, replaced push, escaping/aliased streams/arrays, changed overloads, parse/collector/index/flow caps는 strict safety exclusion을 금지한다.
- 새 holdout은 독립 oracle과 baseline/current source bytes·build fingerprint를 같이 기록한다. 이전 7-flow/DVNA 점수와 별도 분모다. Root가 actual pin에서 추가로 설명한 stream/accumulator/wrapper 경로를 확인해야 완료이며 작은 fixture 통과만으로 재정의하지 않는다.

## 최종 구현 계약 — 독립 QA 공유 기준

**Ruleset:** `2026-10-13.3`. Report schema 1.0의 additive fields와 candidate/partial/0·1·2 adjudication은 유지한다. `scan` exit는 existing gate: partial/error/skipped가 있으면 2, 그 외 threshold finding이면 1, declared checks 완료·threshold 미도달이면 0이다. Adapter나 같은 이름의 함수가 보였다고 whole coverage/pass를 만들지 않는다.

**Public source-kind:** `StaticFlow.sourceKind?: 'filesystem_filename'`. 이 필드는 선택된 trace의 실제 filename origin을 가리키고 HTTP source를 뜻하지 않는다. 일반 SQL/HTML/redirect/dynamic-code 등으로 전달되어도 filename-origin flow에는 HTTP/request 문구를 붙이지 않는다. Legacy absence는 기존 unknown이다. JSON/agent/Markdown/SARIF에 같은 sanitized field를 보존한다.

**Conditional context kinds:** 기존 `static-context-v1`, authority `conditional`, bounded 8 items에 `declared_filesystem_stream_origin`, `declared_stream_callback_schedule`, `conditional_array_accumulator`, `declared_process_wrapper`를 추가한다. Items는 실제 collected-node position 및 optional observed target만 포함한다. Wrapper source가 scan snapshot 밖에 있으면 그 위치를 invented local trace에 넣지 않는다. Qualified source/stream/array/wrapper positive도 이 semantic assumptions를 가진 low candidate, `static_truncated`, vulnerability/fix verification `not_run/not_verified`로 남긴다. Context가 바뀌면 기존 compare는 unverified를 유지한다.

**Rule:** `ast:filesystem-shell-input`, severity `high`, kind `candidate`, confidence `low`. Typed internal filename process role의 outcome은 `argv_shell_input | argv_shell_unknown | direct_argv_interpreter_unknown | argv_only_shell_disabled`; public finding은 filename source가 실제 operand1까지 도달하고 enabled/unknown shell 또는 interpreter semantics가 unresolved이면 보존한다. Direct argv shell-disabled라는 단일 property를 전체 process/interpreter 안전으로 승격하지 않는다. Parent literal true와 fix dynamic shell의 description/metrics를 구분한다. Related command/executable input은 별도 existing rules이며 filename source로 바꾸지 않는다.

**Metrics:** source.builtin-ast에 `filesystemStreamModel:'glob-stream-filename-v1'`, `filesystemStreamsRecognized`, `filesystemFilenameCallbacks`, `filesystemAccumulatorWrites`, `filesystemWrapperArgvUses`, `filesystemShellEnabledUses`, `filesystemShellUnknownUses`, `filesystemInterpreterUnknownUses`, `filesystemShellDisabledExclusions`, `filesystemUnsupportedUses`. 이들은 syntax/analysis uses이며 unique vulnerabilities/whole coverage/verified fixes가 아니다. Native process 기존 metrics와 구분한다.

**Gaps:** 증명 실패는 기존 `module_export_unsupported`와 실제 위치를 우선 재사용한다. Budget failure는 기존 exact reason/tick accounting을 유지한다. Model-specific failure는 bounded fixed note/metrics와 conditional context로 설명하며 자유 source/Secret 값은 출력하지 않는다. 새로운 arbitrary reason을 넣어 accounting을 unknown으로 오염시키지 않는다.

**Advice boundary:** 새 context/source-kind가 bounded metadata projection에 포함되므로 policy version을 7로 올린다. Kind/count/structural enum만 전송하며 source path/positions/content/version-specific target 값/명령은 추가하지 않는다. Existing `review_static_flow_or_budget` route만 사용하고 실행/replay authority는 없다. Fake CLI regression은 독립 QA, live policy-7 provider call은 이 작업 범위 밖이다.

**독립 검증 소유권:** `tests/filesystem-stream-independent.test.ts`는 QA가 작성하고 실제 scan/build/benchmark/package/Action replay는 root가 수행한다. Implementation agent는 src와 ruleset/document 계약만 수정한다. Actual upstream source/code/lock 파일을 제품 fixture로 복사하거나 실행하지 않는다.

**첫 구현 동결 경계:** local model은 source의 단일 export body와 constructor/stream 선언을 연결하고, stream에서 도달하는 method graph 안의 directory-read callback, Path getter-derived actual → emitter formal, 같은 Minipass field의 allocation/write/return을 확인한다. Typed Path formal이나 reviewed readdirCB entries의 filename semantics는 semantic 가정이며 일반 heap/type/runtime 증명으로 표현하지 않는다. 수집된 exported data record에 constructor를 넣는 행위도 conditional package boundary로만 허용하고, 해당 public constructor slot의 local 접근·alias escape와 nested/prototype 변경은 qualification을 취소한다. Custom `fs`/`scurry` source option은 지원하지 않는다. Metadata는 파일당 1 MiB/256 entries 제한, malformed/중복/민감 nearest manifest sentinel 및 coherent narrow range/lock resolution을 적용한다.

첫 동결은 실행 결과가 아니다. Callback parameter 좌표, 독립 filename argv subset, opaque push return 및 no-argument wrapper boundary를 포함한 src가 root의 build/독립 시험/actual pair 검증을 기다리는 상태다. Actual parent/fix가 요구 경로를 보이지 않으면 fixture 통과와 관계없이 미완료로 남긴다.

**최종 provider 반증 경계:** 반환 stream field는 기존 charged module walk가 보존한 write들로 확인하며 단일 Minipass field initializer 또는 constructor allocation만 허용한다. 이후 direct/computed/member·array/object/default/rest target write, for-in/for-of initializer target write, delete/update 또는 알려진 constant emitter 교체는 source qualification을 취소한다. `readdirCB` receiver는 선언된 Path/PathScurry 또는 선언된 Path[] producer domain이어야 하며 같은 이름의 local fake object는 source가 아니다. Path type annotation은 incoming literal/object/const-alias/cast actual의 반증을 덮지 못한다. 선언된 domain과 callback schedule의 runtime 정합성은 여전히 conditional이고 unknown을 safe로 올리지 않는다. Present filename origin이 malformed flow 때문에 renderer에서 소실될 경우 check를 partial로 유지한다.
