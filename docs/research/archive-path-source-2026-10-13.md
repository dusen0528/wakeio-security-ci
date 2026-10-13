# Archive entry path → filesystem writer 조사와 제안

2026-10-13, Wakeio 기준 `594d770`. **조사 결과와 구현 제안이며 아직 새 detector의
구현·실행 성공 기록이 아니다.** 외부 checkout/source는 데이터로만 읽었다. 설치,
import, hook, build, test, 서버·DB·DAST·scanner 실행과 Git 변경은 하지 않았다.
Root가 이후 실행을 담당한다. 아래 원천 코드를 제품 rule/payload로 복사하지 않는다.

## 실제 공백과 원천 권위

고정 Juice Shop `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`의
[fileUpload.ts27–34](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/fileUpload.ts#L27-L34)는
`await unzipper.Open.buffer` 결과의 `files`를 for-of로 순회하고 `entry.path`를
파일 경로에 연결해 Node `fs.createWriteStream`의 첫 operand로 보낸다. 중간의
`includes` 대조는 complaints 디렉터리 containment가 아니다. 경로가 cwd 문자열을
포함한다는 사실은 해당 하위 디렉터리에 속한다는 증명이 되지 않는다. 이것은 원문을
읽은 정적 판단이며 ZIP 업로드·파일 overwrite를 이번 조사에서 실행한 결과가 아니다.

[server337](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/server.ts#L336-L338)과
[memory storage722](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/server.ts#L722)는
업로드 buffer 경로의 source 문맥이다. `.zip` 이름, buffer 존재, challenge enable
조건도 [handler39–51](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/fileUpload.ts#L39-L51)에 있다.
실제 배포 설정·사용자 권한·쓰기 권한·런타임 도달성은 별도 unknown이다.
[maintainer challenge](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml#L70-L85)와
[자체 Cypress case137–143](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/test/cypress/e2e/complain.spec.ts#L137-L143)는
알려진 교육용 arbitrary-file-write 사례임을 명시한다. 새 취약점 발견이나 공개 대상이 아니다.

[package declaration](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/package.json#L154)는
`unzipper: ^0.12.3`이며 types 선언은 별도 `@types/unzipper: ^0.10.10`이다.
고정 checkout 루트에 package-lock/npm-shrinkwrap/yarn.lock/pnpm-lock은 없다.
`ftp/package-lock.json.bak`는 루트 설치 버전 증명이 아니다. **Installed/resolved
unzipper version은 unknown**이고 types 패키지도 런타임 구현의 증명이 아니다.

로컬 전용 checkout은 `artifacts/oss-efficacy-2026-10-13/juice-shop`이다. 현재 읽은
파일 SHA256은 fileUpload.ts `cbaa5d28d378d7ce5b521b634f5250bb8d1fa09c6ac6004bf3f4759bab892573`,
package.json `81771ac97016ceb8f24fb79ffd24751a90a189c1cbfa6625680142880aedf99c`다.
외부 source/report를 이 문서에 embed하지 않는다. 기존 seven-flow oracle/분모도 바꾸지 않는다.

## unzipper의 검토한 API 계약과 MIT

공식 GitHub ref API와 raw source를 직접 읽어 아래 두 pin을 확인했다. Master는
조회 시점의 snapshot이며 npm 최신 배포/설치 상태의 증명이 아니다.

| 원천 | Exact Git commit | source package version | LICENSE SHA256 |
| --- | --- | --- | --- |
| v0.12.3 tag | `d19c3fb9c1bbdce6e6bcb701ac65ddb071e1eb31` | 0.12.3 | `b9e9abeaf8b92573dc28915d4948dbce30d55b30c688d109898b35e6105c4215` |
| master, 2026-10-13 조회 | `431c45c5bcf0e95a8a3f56ca7da8f46daffb8ac2` | 0.12.5 | 동일 |

[tag ref](https://api.github.com/repos/ZJONSSON/node-unzipper/git/ref/tags/v0.12.3),
[master 조회](https://api.github.com/repos/ZJONSSON/node-unzipper/commits/master),
[tag package](https://github.com/ZJONSSON/node-unzipper/blob/d19c3fb9c1bbdce6e6bcb701ac65ddb071e1eb31/package.json),
[master package](https://github.com/ZJONSSON/node-unzipper/blob/431c45c5bcf0e95a8a3f56ca7da8f46daffb8ac2/package.json).

두 pin의 `Open.buffer`는 메모리 buffer를 directory reader에 전달한다. Directory의
`files` record `path`는 중앙 디렉터리 filename bytes의 UTF8 decode다. Record의
`stream`은 내용 stream이며 `path`가 승인된 로컬 경로라는 뜻은 없다.
[v0.12.3 Open](https://github.com/ZJONSSON/node-unzipper/blob/d19c3fb9c1bbdce6e6bcb701ac65ddb071e1eb31/lib/Open/index.js#L5-L18),
[v0.12.3 record](https://github.com/ZJONSSON/node-unzipper/blob/d19c3fb9c1bbdce6e6bcb701ac65ddb071e1eb31/lib/Open/directory.js#L210-L231),
[current record](https://github.com/ZJONSSON/node-unzipper/blob/431c45c5bcf0e95a8a3f56ca7da8f46daffb8ac2/lib/Open/directory.js#L217-L238).

직접 record를 writer에 전달하는 것은 library `Extract`/directory `extract`와
별개다. v0.12.3의 두 extract 구현은 normalized destination에 대한 문자열 prefix
대조를 쓴다. 조회한 master는 separators를 정리하고 `relative` 결과·부모 경로·
absolute 여부를 검사한다. 이 차이 때문에 `unzipper`나 모든 버전의 extract를
blanket-safe negative로 취급할 수 없다. 아래 source 비교는 신규 advisory 주장도 아니다.
[old directory extraction](https://github.com/ZJONSSON/node-unzipper/blob/d19c3fb9c1bbdce6e6bcb701ac65ddb071e1eb31/lib/Open/directory.js#L151-L179),
[old Extract](https://github.com/ZJONSSON/node-unzipper/blob/d19c3fb9c1bbdce6e6bcb701ac65ddb071e1eb31/lib/extract.js#L9-L36),
[current directory extraction](https://github.com/ZJONSSON/node-unzipper/blob/431c45c5bcf0e95a8a3f56ca7da8f46daffb8ac2/lib/Open/directory.js#L154-L177),
[current Extract](https://github.com/ZJONSSON/node-unzipper/blob/431c45c5bcf0e95a8a3f56ca7da8f46daffb8ac2/lib/extract.js#L20-L29).

검토한 두 [LICENSE](https://github.com/ZJONSSON/node-unzipper/blob/d19c3fb9c1bbdce6e6bcb701ac65ddb071e1eb31/LICENSE)는
Near Infinity Corporation 원작과 Ziggy Jonsson fork의 MIT다.
[current LICENSE](https://github.com/ZJONSSON/node-unzipper/blob/431c45c5bcf0e95a8a3f56ca7da8f46daffb8ac2/LICENSE)도 동일하다.
분석 참고만 하고 upstream code/template를 복사하지 않는다. 이후 복사를 택하면
CONTRIBUTING에 따라 attribution/THIRD_PARTY_NOTICES를 별도로 처리한다.

## 경로 검사에서 실제로 말할 수 있는 것

Node22의 `resolve`/`join`/`normalize`는 문자열 경로 계산이다. `resolve`는 절대
segment가 앞선 base를 대신할 수 있다. `relative(base,target)`의 결과를 검사하면
lexical containment를 판단할 수 있지만 `path` API 자체가 symlink·쓰기 권한·경쟁
상태를 확인하지 않는다. 기본 path flavor는 OS에 따라 달라지고 Windows에서는
두 separator와 drive/UNC 문맥을 고려해야 한다. 한 flavor로 검사한 뒤 다른 flavor로
writer를 해석하면 검사가 같은 경로를 증명하지 못한다.
[Node22 path](https://nodejs.org/download/release/v22.22.1/docs/api/path.html#pathrelativefrom-to).

`createWriteStream`의 첫 operand는 destination이고 기본 flags는 `w`다. 명시적 fd나
custom fs 구현을 주면 path가 실제 open 대상이라는 가정이 달라진다. `realpath`는
symlink를 포함한 실제 위치를 따로 해석하며 없는 destination은 오류다. 따라서
lexical guard를 인식해 후보를 제외하더라도 실제 파일 안전성을 인증하지 않는다.
[Node22 writer](https://nodejs.org/download/release/v22.22.1/docs/api/fs.html#fscreatewritestreampath-options),
[Node22 realpath](https://nodejs.org/download/release/v22.22.1/docs/api/fs.html#fsrealpathpath-options-callback).

CWE-22는 restricted directory 밖을 가리킬 수 있는 외부 경로 구성을 다룬다.
OWASP WSTG는 input vector를 먼저 열거하고 file operation·validation을 따라가도록
한다. 이 원칙에서 archive filename→destination 흐름이 도출되며, archive 관련
keyword만 찾는 방법이나 source candidate를 runtime exploit으로 부르는 방법은
도출되지 않는다. [CWE-22](https://cwe.mitre.org/data/definitions/22.html),
[WSTG v4.2](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include/).

## 현실적인 첫 구현 범위 — 제안

1. **Origin**: 실제 외부 `unzipper` import/require binding의 pristine `Open.buffer`
   call, awaited result, 그 result의 `files` for-of record, 해당 record의 `.path`를
   semantic identity로 연결한다. Local fake object, shadowed import, mutated Open,
   overwritten result/files/entry.path, unrelated `.path`는 origin이 아니다. Stream
   contents와 filename 역할을 섞지 않는다. Parse/events/other archive package는 초기 제외다.
2. **Authority**: bounded collected nearest package metadata를 사용한다. 실제 checkout에
   필요한 선언 `^0.12.3`를 설치 truth로 올리지 않고 reviewed Open API에 대한
   `declared_package_api` conditional authority로 표현한다. 첫 지원 literal/range와
   lock version의 exact allowlist는 root가 채택할 때 명시한다. Missing/invalid metadata,
   contradictory lock, local package shadowing, workspace/hoist ambiguity, shrinkwrap
   precedence 미지원은 unresolved다. 새 버전을 자동 safe로 취급하지 않는다.
3. **Sink/flow**: 검토된 Node fs binding의 `createWriteStream` 첫 path operand만 우선
   지원한다. 같은 record의 path가 const alias·문자열 연결·검토한 path 연산을 지나
   이 operand에 도달해야 한다. 선언 API authority이므로 candidate/low confidence,
   bounded conditional trace와 source kind가 필요하다. 원천 파일명/content는 보고서에
   복사하지 않는다. fd/custom fs/opaque writer options는 별도 unresolved다.
4. **정상 exclusion**: 같은 resolved destination에 대한 같은 flavor의 relative
   containment 대조 후 invalid 경로가 `throw`/`return`/해당 loop의 `continue`로
   writer 전에 종료하는 좁은 형태만 고려한다. Empty relative·parent escape·absolute
   relative를 거부하고 guard 이후 destination/기준값 mutation이 없어야 한다.
   `includes`, 경계 없는 prefix, 다른 variable/base 검사, 비종료 logging, guard 전
   writer, guard 안에서만 return하는 callback은 exclusion이 아니다. Fixed-name writer도
   좁은 정상 대조다. 어느 exclusion도 symlink/TOCTOU 또는 전체 extractor safety를 뜻하지 않는다.

현재 `FilesystemRoleModel`의 nearest metadata/version helper는 exact coherent lock을
필수로 하고, `MongoRoleModel`은 lock 없을 때 declared-range conditional 모델을 쓴다.
두 helper는 각각 private이며 동일 installed-resolution 서비스가 아니다. 재사용 시
정책 차이를 유지해야 한다. 기존 `StaticFlow.sourceKind`는 `filesystem_filename`만
허용하므로 archive origin을 그 enum으로 위장하지 않는다. 채택하면 typed contract,
sanitizer/compare/four formats/advice projection의 bounded enum 변경이 함께 필요하다.
기준 source: `src/source/filesystem-role.ts`, `src/source/mongo-role.ts`, `src/contracts.ts`.

## 구현 전 동결할 최소 대조와 유용성 경계

| 대조 | 기대 의미 |
| --- | --- |
| Risk | 실제 import+선언 metadata, Open.buffer→files for-of→entry.path→alias/concat→writer path. Candidate와 source/sink/conditional role 좌표를 확인. 원본 Juice Shop의 includes도 같은 좁은 positive holdout. |
| Normal | 같은 destination을 검사하는 terminating relative guard 및 fixed filename writer. 이 rule의 후보 부재만 기대하고 whole-project exit0은 요구하지 않음. |
| Near misses | Fake/local Open 또는 entry, shadow/mutation/escape, unrelated path, path를 write data로만 사용, fd/custom fs, prefix-only·비종료·다른값 guard, flavor mismatch. Unsupported origin은 unknown/partial이며 safe 점수가 아님. |
| Boundaries | Metadata/AST budget, source collection incomplete, guard/destination mutation, malformed new enum, four formats와 advice redaction·compare drift. Partial2와 not_observed≠verified_fix 유지. |

Root가 입력과 baseline build를 먼저 freeze하고 owned risk/normal/near-miss를 실행한
뒤 실제 고정 checkout을 source-only로 비교해야 한다. 기존 seven-flow metric은 유지하고
이 archive holdout은 새 별도 분모로 기록한다. 실제 flow의 후보·정상 exclusion·미지원
원인을 함께 세어 유용한 추가 coverage인지 판단한다. 이 단계는 ZIP 실행이나 실제
파일 overwrite를 검증할 필요가 없으며 detector tests를 추가한 사실만으로 상용 수준의
탐지/precision을 입증하지 않는다. 기대 이득은 현재 빠진 업로드 파일명→쓰기 경로를
리뷰 가능한 trace로 연결하는 것이고, 사용자가 실제 triage 시간을 줄이는지는 별도 측정이다.


## 2026-10-13 root가 채택한 초기 범위

위 feasibility 제안 중 초기 origin declaration은 literal0.12.3/`^0.12.3`, lock이
있으면 coherent reviewed0.12.3/0.12.5로 좁혔다. Native `fs.createWriteStream`
operand0만 지원하고 fd/custom fs/opaque identity는 partial이다. Public rule은
`ast:archive-path-write`, sourceKind는 `archive_entry_path`, conditional context는
`declared_package_api`, ruleset revision2026-10-13.4/advice policy10이다.

Guard 초기 문법은 immutable const base/destination/relative와 same-block preceding
if의 세 OR 조건(relative가 정확히 parent, parent+native separator로 시작, absolute
relative) 및 terminating return/throw다. 초기 제안의 추가 empty-relative 조건이나
일반적으로 동등한 guard 문법·continue·다른 flavor를 지원한다고 해석하지 않는다.
Exclusion 후에도 conditional origin gap은 남아 no-finding partial2가 가능하다.
이 단계는 contract adoption이며 구현·검증 성공 주장이 아니다.


초기 guard는 바로 다음의 동기 direct write expression 또는 단일 const writer
initializer로 제한한다. 사이의 await/opaque call, nested wrapper, String/Reflect 등의
불확실한 intrinsic은 exclusion을 승인하지 않는다. `path.isAbsolute`는 Boolean
predicate이므로 archive filename content를 반환하는 path transform으로 취급하지 않는다.

또한 matching package name과 exports가 있으면 Node self-reference가 외부 dependency
import에 우선한다. 이는 generic project-name suppression과 달리 수집 metadata의
명시적 loader-identity 모순이다. 해당 로컬 구현을 외부 unzipper API 근거로 올리지
않고 unresolved로 보존한다.
[Node22 package self-reference](https://nodejs.org/download/release/v22.22.1/docs/api/packages.html#self-referencing-a-package-using-its-name).


## 2026-10-13 fifth build 중간 실측 — 최종 완료 아님

Root의 private semantic 대조19개는 모두 선언한 의미와 일치했고 모두 partial2였다.
Fifth focused suite는35/35 통과했다. 고정 whole-checkout source-only 대조는 Juice
Shop 보고 항목32→33, NodeGoat5→5이며 기존 보고 항목37개를 모두 유지했다.
이37개는 rule/site 보고 항목 수이며 observation을 포함한다. 전부 취약점이나 candidate로 세지 않는다. 새 후보는
고정 `routes/fileUpload.ts` entry.path source30:22→native writer34:38의 단일 archive
conditional trace다. Source 선언 API 근거이며 앱/ZIP/파일 overwrite 실행이나 새
취약점 발견으로 바꾸지 않는다. Juice Shop flow work는766267/800000이었다.

기존 seven-flow oracle는5/7 observed, scanComplete=false, recall/precision=null을
유지한다. Archive holdout은 별도 분모이며 기존 기대값과 v2 source-only adjudication을
다시 분류하거나 unknown을 성공으로 올리지 않는다. 전체 findings count 증가1도
population accuracy, 고유 취약점 수 또는 상용 효과의 측정값이 아니다.

첫 required suite는1088 중1078 pass·10 fail이었고10개는 이전 version 기대값 불일치로
확인됐다. 이 결과는 passed가 아니다. 초기 literal/computed prototype counterexample은
기존 이름 기반 intrinsic veto의 누락을 드러냈으며 charged index의 추가 boundary로
수정됐다. 마지막 CJS destructured/direct-require shared mutation 경계는 별도 수정·
회귀와 전체 재실행을 기다린다. 앞선 Standards0은 당시 읽은 범위의 결과이며 후속
counterexample을 처음부터 발견했다는 주장이 아니다.

현재 final full suite, fresh distribution consumer와 hosted CI의 완료는 주장하지
않는다. Root가 각 단계의 최종 receipt를 확정하면 이 중간 기록을 덮어쓰지 않고 이후
결과를 추가한다. npm 신규 배포·모델 호출·외부 target 실행·실제 사용자의 triage 시간
절감 또는 상용 동등성은 이 실측의 범위 밖이다.


## 2026-10-13 `.cjs` collection 추가 동결과 baseline

Root가 실제 CLI 통합에서 mutation.cjs가 accepted code가 아니라 ignored였음을
확인했다(filesSelected2/code1/ignored1). Builtin AST의 확장자 지원은 실제 collection
증명이 아니었다. Collector CODE_EXTENSIONS와 code-coverage EXTENSIONS 두 table의
누락을 수정했으며 다른 AST/provider/anchor/staging 경로는 이미 지원했다.

새 독립 actual CLI collection 대조4개를 구현 결과 확인 전에 추가 동결했다. Test
source SHA256은
`dffc4d18d074290254258782df1365874c7f7628e7394b7794c92ee2d863e5e3`다. Root가 보존한
pre-collection build에서 실행한 baseline은0 pass·4 fail·0 skip이었다. 실행 주체는
root이며 문서 작성자는 scanner/target/test를 실행하지 않았다. 기존 v3 test hash와
oracle는 유지하고 새 collection-stage 대조를 별도 추가한 기록이다.

이전 private shared-mutation5개는 collection 누락 근거였으며, 무시된 `.cjs`가
실제로 분석돼 관련 mutation을 취소했다는 성공 근거가 아니다. Role-only supplied
snapshot 검증과 실제 CLI collector→code accounting→AST→four-format 경로를 구분한다.
현재 최종 build/focused40/private25/whole OSS 통합 receipt는 확인 중이다. 이 단계에서
최종 전체·배포 소비자·hosted CI 통과를 주장하지 않는다. Root의 이후 실제 실행
결과는 이 실패 기록과 동결 기대값을 바꾸지 않고 별도 append한다.


## 2026-10-13 최종 로컬 통합과 전체 suite

Root의 최종 integration receipt는 로컬 전용
`artifacts/archive-path-2026-10-13/integration-final-receipt.json`이며 status passed다.
Focused40/40·skip0, private25 semantic/gate matches(기존19+shared.cjs5+guide1)를
기록했다. 이번 shared5는 codeFiles_javascript1이 실제로 수집된 것을 assert했고,
direct fs/path guard는 lexicalExclusions0이다. 가이드의 exact TS example는 source-only
scan에서 no archive finding·lexicalExclusions≥1·partial2를 기록했다. TS example bytes는
문서 갱신에서도 유지했다. 이 결과는 runtime ZIP 추출/쓰기 안전성 증명이 아니다.

최종 whole OSS는 Juice Shop 보고 항목32→33, NodeGoat5→5, 기존 보고 항목37개
유지·총38개다. 추가1개는 같은 고정 fileUpload source30:22→writer34:38의 low-confidence
conditional archive candidate다. 기존 항목에는 observation도 있으므로 전부 취약점/
candidate로 세지 않는다. 최종 flow work는 Juice Shop766255/800000, NodeGoat101065다.
앞선 fifth766267는 당시 실측으로 보존한다. Seven-flow oracle5/7 observed,
scanComplete=false, recall/precision=null은 유지하며 archive holdout은 별도 분모다.

Full v2 required-engine은1093/1093 pass·failed/cancelled/skipped/todo0이다. Receipt는
로컬 전용
`artifacts/archive-path-2026-10-13/required-receipts/required-engine-aCDibe/receipt.json`이다.
Status passed·exitCode0이며 preflight/build/tests 세 stage가 exit0·cleanupConfirmed true다.
Integration과 required suite의 sourceBefore/sourceAfter SHA256은 모두
`845c057fc8984320e59ea4008981bc665ff4baea34c42b2b62b830842ee7bf9a`다.
문서 작성자는 receipt를 읽었고 실행은 root가 담당했다. 전체1093개는 기존 기능과
준비된 owned engine 대조를 포함하며 새 archive detector 사례 수가 아니다.

이 final 기록은 초기1088 suite의1078 pass/10 stale-version failures, QA coordinate
correction, literal prototype counterexample와 CJS collection4개 baseline0/4 실패를
덮어쓰지 않는다. 이전 private shared5가 `.cjs`를 실제 분석했다는 주장도 하지 않는다.
최종 관련 CLI/collection 회귀가 포함된 통합 evidence로 범위를 다시 확인했다.
독립 Standards 최종 targeted residual0이며 그 정적 검토를 실행 성공이나 처음부터
모든 결함을 발견한 근거로 올리지 않는다.

Fresh package/source consumer와 hosted CI는 배포/PR의 별도 특정 receipt로 확인한다.
이 로컬 source-only/owned suite 기록으로 그 실행 성공을 대신하거나 npm publication,
live model, 새로운 OSS 취약점, 실제 overwrite, 실사용 population precision/recall,
상용 동등성을 주장하지 않는다. 기존 oracle·test input hash와 초기 실패 기록은 유지한다.
