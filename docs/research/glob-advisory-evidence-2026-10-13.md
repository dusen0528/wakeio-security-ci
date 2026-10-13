# glob 공개 advisory의 독립 소스 근거 (2026-10-13)

## 동결한 판단과 범위

이것은 [GHSA-5j98-mcp5-4vw2 / CVE-2025-64756](https://github.com/isaacs/node-glob/security/advisories/GHSA-5j98-mcp5-4vw2)의 **이미 공개된 취약점**에 대한 소스 기준이다. 새 취약점 발견·disclosure·Wakeio 탐지 성공·로컬 악용 확인을 주장하지 않는다. Maintainer advisory는 파일명을 argv로 모아 셸에 전달하는 CLI 문제와 core library API의 범위를 구분한다. 조건은 CLI command 기능 사용, 공격자가 영향을 줄 수 있는 매칭 파일명, 해당 실행 경로의 셸 해석이다.

기준 main은 `50eea146f3e45014b248cb72e716d6eb064563fa`다. **현재 detector 결과를 읽기 전에** 아래 원천과 기대값을 동결했다. Root만 별도 scanner replay를 수행한다. 이 조사는 대상 dependency install/import/build/test/hooks/server/DB/DAST, 모델 호출, maintainer 연락·공개 발표를 하지 않았다. 제품 소스와 이전 corpus/oracle/분모는 수정하지 않았다.

독립 manifest는 로컬 전용 `artifacts/glob-advisory-2026-10-13/independent-oracle.json`이며 SHA-256은 `f584b06de913ad02b634003223ff67df143ee753a47e220b863dcaeae220be5a`다. `detectorOutputsInspected=false`, source/archive/모든 파일 manifest 해시, dependency pin·integrity, 물리 좌표, 네 모드의 조건부 기대값을 담았다. 이는 hash로 식별한 독립 기준이며 작성자 서명이나 실행 증명은 아니다. 이후 scanner 결과에 맞춰 이 파일이나 원천을 변경하지 않는다.

문서의 `artifacts/` 경로는 Git에서 제외된 로컬 검증용 자료 위치다. 해당 manifest·snapshot·archive는 공개 저장소와 배포 패키지에 포함되지 않으며, 아래 공개 근거 링크는 고정 upstream commit을 참조한다.

## 이전 조사에 대한 정정

[이전 goal 감사](goal-oss-evidence-audit-2026-10-13.md)의 parent 좌표 257→258은 브라우저가 정규화한 표시를 물리 파일 위치로 잘못 해석한 값이다. 실제 Git archive 바이트에서는 parent data callback/배열 누적이 **270**, foregroundChild sink가 **271**이다. 이번 fix는 **348**의 callback/누적, **369**의 known-shell sink, **379**의 generic shell sink를 가진다. Advisory 본문의 위치 277도 이 pin의 sink 좌표로 쓰지 않는다.

이전 감사에서 읽은 foreground-child **3.1.1**은 의미 조사용 보조 원천이었다. 실제 parent와 fix의 lockfile은 모두 **3.2.1**을 resolve한다. [이전 process-role 조사](process-role-references-2026-10-13.md#공개-argv--shell-보안-기록)는 glob patch를 실제 HTTP/native detector의 지원 성공으로 세지 않았으며, 당시 글은 실제 lock·wrapper snapshot을 동결한 증거가 아니었다. 이번 자료가 정확한 dependency/좌표 기준이다. 3.1.1 snapshot은 `supplementalOnlyExcludedFromDependencyOracle`로 표시했다.

## 고정 원천과 파일 바이트

공식 [node-glob](https://github.com/isaacs/node-glob)과 [foreground-child](https://github.com/tapjs/foreground-child)만 `--no-checkout --filter=blob:none --no-tags`로 복제했다. Git hook은 `/dev/null`, submodule recursion은 false로 설정했다. 고정 commit의 Git archive를 만들고 absolute/traversal/link/special entry를 거부한 뒤 regular source 파일만 private 0700/0600으로 보존했다. 활성 기준 세 archive의 파일 목록이 원 Git tree 파일 목록과 모두 일치함도 확인했다.

| 원천 | Commit / tree | 로컬 전용 DATA ONLY snapshot |
| --- | --- | --- |
| glob parent | `1f0c1ca01a5f256cd17f543f83e9aaeedd133939` / `d64414a2ce295bc20ae54a3e9739b8f8588ede35` | `artifacts/glob-advisory-2026-10-13/source-glob-parent`, 77 files |
| glob fix | `1e4e297342a09f2aa0ced87fcd4a70ddc325d75f` / `1c3f5fcf56459673703863a7aec74a5efbda3db0` | `artifacts/glob-advisory-2026-10-13/source-glob-fix`, 77 files |
| foreground-child 3.2.1 | `132a0178990aa4f53a6208bc3bdb90369b35e434` / `64391dbf7909781e4a395c427891f83332c57c0e` | `artifacts/glob-advisory-2026-10-13/source-foreground-child-3.2.1`, 37 files |

Git object metadata confirmed that fix has **one parent, exactly the listed parent**. This is a direct before/fix source relationship, unlike the distinct-source DVNA comparison. Both glob package manifests still say `10.4.5`; the source patch commit is not the published `10.5.0` artifact. Package version alone must not classify the source change as fixed or vulnerable.

| 확인 파일 | 전체 파일 SHA-256 |
| --- | --- |
| parent `src/bin.mts` | `6e57ea10a31296ad2d83eae03dcfd57e4eb70db982728b9ba5b99c41e5a4b3d7` |
| fix `src/bin.mts` | `ae6b53c6faf52ace6c9c823e889c2b0dd1a3af05b142bc39e5c756b1f23f22b3` |
| parent/fix `package-lock.json` | `fea25b99a56f6949a2cfa8cd6f562d14e0b4f7dac39bb8799ed50d42f4ed239b` |
| parent/fix `LICENSE` | `cdbc258d13806538e727964c2436a8806e6e2496ccd616224aace6f7bf98dbc1` |

Archive SHA-256: parent `fe506f8bb9d6dc44ea3498a51ca95083e839cd885acd59fb623528009aaa9c8f`; fix `7349996e65e08ef572d5b72f1b002fdb922af5bf19f0048452fd1eeaf7809a79`; wrapper `b5090da77605ae26d6c09b934435ed9f5ccf9ac78f4c06e9a9cfcbe1153718f5`. Individual `*-source-manifest.json` files retain every file hash and byte count. The clones have no target working checkout; archives/snapshots contain no executed target code.

## Exact parent 흐름

[Parent src/bin.mts](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/src/bin.mts#L238-L271)는 line 242의 실제 glob stream과 line 270의 filename callback/배열 누적, line 271의 end callback 소비를 연결한다. 물리 좌표는 다음과 같다.

| 역할 | path:line:column |
| --- | --- |
| 실제 globStream creation | `src/bin.mts:242:18` |
| data callback filename parameter | `src/bin.mts:270:23` |
| 같은 captured matches 배열 누적 | `src/bin.mts:270:28` |
| foregroundChild program/argv/options sink | `src/bin.mts:271:28` |

이 경로에서 위험 입력은 **filesystem filename**이다. Operator의 cmd를 고정값으로 두어도 파일명 argv의 셸 해석 문제는 남는다. HTTP request, 단순 함수 이름, unrelated candidate, CLI command 선택 자체를 이 원천의 대체 witness로 쓰지 않는다. [같은 pin의 globStream source](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/src/index.ts#L61-L85)는 반환 stream과 data/end 계약을 설명한다. 임의 EventEmitter의 data를 모두 파일명 원천으로 인정할 근거는 아니다.

## Resolve된 wrapper 의미와 라이선스

두 [glob lockfile](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/package-lock.json)은 foreground-child `3.2.1`, jackspeak `3.4.2`, cross-spawn `7.0.3`을 기록한다. Package manifest의 foreground-child 선언은 `^3.1.0`이다. Version range와 exact lock selection을 합치지 않는다.

[foreground-child 고정 소스](https://github.com/tapjs/foreground-child/blob/132a0178990aa4f53a6208bc3bdb90369b35e434/src/index.ts#L72-L142)는 overload를 program/args/options로 정규화한다. Options의 shell 값은 제거되지 않으며 정상 args/options 형태는 POSIX Node spawn으로 전달된다. Line 14는 Windows에서는 cross-spawn을 선택한다. 따라서 이 oracle의 native 의미는 **POSIX 소스 계약**이며 Windows identity/escaping/실행까지 검증한 것으로 확대하지 않는다. [Node spawn 문서](https://nodejs.org/download/release/v22.22.1/docs/api/child_process.html#child_processspawncommand-args-options)의 shell 옵션과 별도 argv 의미를 근거로 사용했다.

Lock의 공식 registry tarball을 설치 없이 받아 SHA-512를 대조했다. Expected와 actual은 모두 `sha512-PXUUyLqrR2XCWICfv6ukppP96sdFwWbNEnfEMt7jNsISjMsvaLNinAHNDYyvkyU+SZG2BTSbT5NjG+vZslfGTA==`, tarball SHA-256은 `e882cea1c6e3127e175a6c5cd9c1398b3cd007b0f5d1c4af76e5d2ff0d5660dc`다. 로컬 전용 `artifacts/glob-advisory-2026-10-13/foreground-child-3.2.1-published-manifest.json`와 `artifacts/glob-advisory-2026-10-13/published-foreground-child-3.2.1/package`의 JS를 데이터로 읽어 같은 dispatch/normalizer 의미를 확인했다. Lock과 tarball의 일치는 artifact identity이며 실제 설치·module loader/runtime binding 확인은 아니다.

[glob 고정 LICENSE](https://github.com/isaacs/node-glob/blob/1f0c1ca01a5f256cd17f543f83e9aaeedd133939/LICENSE)와 [foreground-child 고정 LICENSE](https://github.com/tapjs/foreground-child/blob/132a0178990aa4f53a6208bc3bdb90369b35e434/LICENSE)는 모두 **ISC**다. Source snapshots retain the copyright and permission notices. 외부 소스를 제품 코드·tests에 복사하지 않았다. 이후 재배포하면 해당 notice와 CONTRIBUTING의 THIRD_PARTY_NOTICES 절차가 필요하다.

## Fixed 소스에서 나눠야 하는 네 모드

[Fixed src/bin.mts](https://github.com/isaacs/node-glob/blob/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f/src/bin.mts#L343-L379)는 default flag, known-shell positional path, explicit unsafe path를 구분한다. [Maintainer test source](https://github.com/isaacs/node-glob/blob/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f/test/bin.ts#L117-L244)도 별도 기대값을 갖는다. 이 tests를 실행하지 않았으므로 표는 **조건부 소스 기대값**이다.

| 독립 mode ID | 조건과 기대 truth | detector 결과를 읽을 때의 한계 |
| --- | --- | --- |
| `parent-command-file-stream-shell` | cmd 기능과 untrusted matching filename을 전제로 literal shell true가 argv를 해석하는 known-advisory positive | 정확한 filename/captured array/wrapper sink를 설명해야 한다. 임의 candidate 개수로 대체하지 않는다. |
| `fixed-default-separated-argv` | shell flag omitted/false인 generic branch의 filename argv는 Node shell interpretation에 들어가지 않는다. Default declaration은 line 40; test 근거는 198–244다. | 이 모드의 제한된 negative다. CLI option 값을 증명하지 못하면 unknown/candidate를 유지한다. |
| `fixed-explicit-unsafe-shell` | explicit shell true이며 known-shell guard가 실패하면 filename argv가 line 379에서 셸에 들어간다. Test 156–195가 이 의도를 명시한다. | Fixed **전체 소스의 무후보를 기대하면 안 된다**. Dynamic shell이 하나의 sink로 합쳐져도 위험/unknown 근거를 지우지 않는다. |
| `fixed-known-shell-positional` | guard 성공 시 line 369에서 explicit interpreter를 실행하며 filename은 뒤 positional args로 전달된다. Test 117–154는 fish 경로를 다룬다. | Filename을 command text에 넣는 기존 패턴의 대조다. shell:false/옵션 없음만으로 explicit interpreter 안전성을 인증하지 않는다. |

Fixed filename origin/누적은 `348:23`/`348:28`, generic sink는 `379:30`, known-shell sink는 `369:30`이다. Known-shell path에서는 별도 -c 문자열·positional arg 역할을 이해하지 못한 low/unknown 후보도 허용한다. Missing source/array/callback hop은 실제 미해결 공백으로 보고해야 한다. 검사 전체 completed/exit 기대값은 사전 강제하지 않았으며 범위/분석 한도와 다른 결과를 정직하게 남긴다.

네 모드는 네 개의 새로운 취약점이나 population recall 분모가 아니다. 하나의 공개 취약점과 patch의 조건부 경로를 검토하는 표다. 기존 7-flow·DVNA corpus는 그대로 두며, root-owned baseline/current의 동일 바이트 replay가 있어야 새 capability의 추가 설명 가능성을 보고할 수 있다. Source 검출·hash 일치·fixture 통과만으로 악용, 수정, production 안전성 또는 상용 효용은 입증되지 않는다.
