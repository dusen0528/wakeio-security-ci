# Source handoff 독립 acceptance 계약

2026-10-13. 작성 기준: 부모가 지정한 `main` `36c8341b69fecc663de8498295277289e7fbeb2b`의 공개 CLI 및 `goal-agent-ci-audit-2026-10-13.md` 마지막 계약. 작성자는 제품 소스를 편집하거나 test/build/scan/model/Git 명령을 실행하지 않았다. 아래는 실행 가능한 테스트의 **설계와 예상값**이며 통과 결과가 아니다. 실제 실행·baseline/implementation 판정·artifact hash 동결은 root가 별도로 수행한다.

테스트 파일: `tests/source-handoff.test.ts`. 새 handoff helper를 import하지 않으며 이전부터 존재한 `main`/`toAgentReport`와 Node 표준 라이브러리만 사용한다. 소유 temporary source fixture를 정적 데이터로 읽는 `scan --tools none`과 공개 `handoff create|finish`가 검증 대상이다. Source의 프로그램·lifecycle script·provider·network·서버·DB를 실행하지 않는다. Tests가 source 파일에 하는 수정은 owned V/F 데이터의 작성이며 원본 앱에 패치를 적용하는 작업이 아니다.

## 독립 판정 기준

- `create` 0은 local review packet 생성이다. 원 scanGate 1/2를 그대로 남기고 CI 통과나 수정 완료로 해석하지 않는다.
- `finish`는 after **전체 scan gate**와 comparison을 결합한다. unchanged high가 남으면1, 선택 candidate 제거와 같은 범위의 완결 clean scan이면0, partial/scope/source/receipt 불일치이면2다.
- 모든 성공/재검사 receipt의 `vulnerabilityConfirmed`, `remediationVerified`는 false이며 security/normal control은 `not_run`이다.
- `sourceSnapshot`/`sourceBinding`은 `source-snapshot-v1`, `basis=collected_utf8_strings`다. 원 byte 동일성, 동시에 고정된 filesystem tree, 서명된 실행 사실을 증명하지 않는다.
- 원 report exact bytes와 canonical agent projection을 동시에 검사한다. 테스트에서 canonical pair를 다시 만드는 integrity fixture도 서명된 실제 실행 증거라고 주장하지 않는다.

## 28개 검증 그룹

| 번호 | 검증 흐름 | 독립 예상 결과 |
|---|---|---|
| 1 | 실제 risk scan→create, private exact copies, source/report 불변 | create0, 원scanGate1, 0700/0600, 원 bytes 보존 |
| 2 | guidance에 untrusted command 문구 | data-only packet, recipe/argv/command 및 Markdown 원문 실행 지시 없음 |
| 3 | 효과 없는 변경/unchanged high→finish | comparison unchanged여도 after gate로1 |
| 4 | 실제 parameterized source counterpart→새 scan→finish | not_observed/0, controls not_run, 원본/after 불변 |
| 5 | 선택 candidate 제거 후 새 dynamic-code high 추가 | selected not_observed이나 전체 결과1 |
| 6 | 정상 collector와 실제 malformed AST 파일·보유 candidate | create0/원scanGate2 보존, finish2 |
| 7 | maxFiles로 collector truncation, fail-on none | retained candidate가 있어도 create2 |
| 8 | literal만 변경해 semantic anchor 유지 | comparisonKey 동일이나 stale snapshot create2 |
| 9 | source add/delete/rename | 과거 snapshot create2 |
| 10 | scanner collect 뒤 legacy tree hash 전에 실제 source 수정 | 수집한 risk 증거 유지, 현재 fixed source의 과거 handoff2 |
| 11 | after scan 뒤 source 재수정 | stale after finish2 |
| 12 | UTF8 BOM 유무만 변경 | decoded text bytes/digest 일치, create0; raw-byte 주장 없음 |
| 13 | 서로 다른 malformed UTF8 byte가 동일 replacement string으로 decode | create0, collected-string basis 유지 |
| 14 | included secret-category 문자열 변경 | aggregate mismatch2, 원 sentinel report/packet 비노출 |
| 15 | unsupported extension 문자열만 변경 | selected snapshot 밖이므로 create0; 전체 tree 검사 주장 없음 |
| 16 | 원 scan이 source 내부 output subtree 제외 | outputDirectoryExcluded=true, create2 |
| 17 | root/source symlink·source/report hardlink·report symlink | create2, link를 실행/쓰기 경로로 사용하지 않음 |
| 18 | 기존 output/source내 output/symlink ancestor/원 report 재사용 |2, 기존 data 유지 |
| 19 | report byte 변경 또는 agent gate/finding 변조 | digest/projection binding 실패2 |
| 20 | 없는 finding·다른 check membership·잘못된 check index |2 |
| 21 | missing/future snapshot, digest/count/complete 변경 | guessed source binding 없이2 |
| 22 | old tool/ruleset, mixed mode/check set, budget/profile incoherence |2 |
| 23 | receipt selected/sourceBinding/gate·before private copy·receipt link 변경 | finish2 |
| 24 | partial after, scope/budget/ruleset drift, duplicate semantic key | finish2 |
| 25 | after에서 원 fail-on high를 none으로 완화 | finish2 |
| 26 | 처음부터 명시한 fail-on none | unchanged finish0, 원 정책 유지, 검증 flag false |
| 27 | inert source/lifecycle canary와 recipe/model/patch/upload flag | canary 미실행, unknown argument2 |
| 28 | occupied finish output·중복 option·unknown operation |2, 기존 packet/output 보존 |

## 동결 후 수정 이력

Root가 첫 완성 알림의 v1을 복사해 동결하고 baseline 실행을 시작했다. 실행을 보지 않은 정적 자체검토에서 fixture 오류 두 개를 발견하여 v2를 제출했다. 최초 lock/log는 root가 보존한다.

1. `scan` helper가 기본 `--source-max-files 1000`과 truncation case의 `--source-max-files 1`을 중복 전달했다. Strict CLI grammar가 scan을 거부하면 report를 만들지 못하므로 acceptance 대상 이전의 fixture 오류다. v2는 명시 override가 있는 기본 option 쌍만 제외한다. 기대 결과는 완화하지 않았다.
2. Duplicate semantic-key 사례를 동일 함수 source redeclaration의 추론에 의존하지 않도록 변경했다. v2는 실제 after source scan의 canonical pair에 동일 comparisonKey를 가진 다른 위치의 finding을 명시적으로 추가하여 ambiguity trust boundary를 검사한다. Raw report/agent는 기존 공개 projection으로 다시 결합한다. 이 fixture는 실제 source가 그 두 finding을 만들었다는 주장에 사용하지 않는다.

그 밖의 계약·expected exit·필드명·검증 기준은 바꾸지 않았다. 작성자는 테스트 실행 결과를 아직 관찰하지 않았으며 제품 구현에 맞추기 위한 expectation 수정은 하지 않았다. 이후 수정이 필요하면 testbug/spec/implementation failure를 먼저 구분하고 root 동결·재실행 이력을 남긴다.

## 한계와 추가 검증

그룹10은 현재 baseline의 별도 `createReadStream` source provenance pass를 Node builtin mock과 `syncBuiltinESMExports`로 관측한다. 제품이 legacy tree hashing 자체를 제거하는 별도 승인 변경을 하면 hook 변경은 정당한 test adaptation일 수 있지만 기대 불변조건—수집 시점 strings만 증거가 됨—은 유지해야 한다.

이 suite는 same-size concurrent in-place edit, ancestor directory race, collector 뒤의 TOCTOU, 고장난 filesystem I/O의 hard wall bound, 한 host의 악성 실행자, 완전히 재작성한 일관된 forged pair의 작성자 진위까지 해결했다고 주장하지 않는다. 현재 collector의 normalized selected-input 증거와 local data-only handoff 범위를 검증한다.

AST staticContext의 conditional authority가 변화하는 별도 cross-module 사례, late delivery fault injection, hosted CI/install-package/Action fresh receipts는 root가 별도 범위로 평가한다. Fixture test 통과 수는 real-world detector accuracy나 유료 제품 가치의 근거가 아니다.

## Root 추가 리뷰의 경계 5그룹

Root 요청으로 동결된 기존 28그룹을 유지하고 `tests/source-handoff-boundaries.test.ts`를 별도로 작성했다. 이 추가 파일은 공개 `main`과 Node 표준 라이브러리만 import하며 root가 hash를 동결해 실행한다. 작성자는 실행하지 않았다.

1. 실제 source 파일명을 `[review](mailto:owned-review@example.invalid).ts` 또는 `<img onerror=owned_marker>.ts`로 만들고 정상 scan/create를 거친다. Markdown에 raw link/HTML이 남아 실행 가능한 markup으로 해석되지 않아야 하고 navigation 문구는 읽을 수 있어야 한다. JSON 따옴표는 Markdown escaping을 대신하지 않는다.
2. Comment raw marker와 synthetic token이 four report formats 및 private packet/copied pair에 남지 않는지 확인한다. Snapshot은 report/agent/SARIF/Markdown/receipt에 동일하고 copied pair exact bytes/digest는 유지돼야 한다.
3. Handoff collector가 source file을 실제 open한 직후 own builtin mock에서 `SIGINT`를 emit한다. Create2, 성공 marker 없음, source/report bytes 불변을 요구한다. 실제 process kill이 아니라 in-process signal listener의 cancellation 계약 검증이다.
4. Markdown 실제 write 뒤 `SIGTERM`을 emit하여 final receipt publication 전 cancellation을 검증한다. Create2, ready marker 없음, temporary marker 정리와 입력 불변을 요구한다.
5. Final receipt의 실제 no-clobber publication을 `fs.promises.link` mock으로 EIO 또는 갑자기 occupied target으로 만든다. Late failure2, incomplete 또는 marker 부재, ready marker 부재, temporary marker 정리와 입력 불변을 요구한다. 완전히 atomic four-file transaction이라고 주장하지 않는다.

추가 파일의 최초 제출 SHA-256: `42d145efcdd537f0a608f9c3b5a4fa9ebf7599c7724bc879fade1d7ec7810a3b`. 이미 root가 공유한 기존 v2 baseline은 9pass/19fail/0skip이며 이 문서 작성자가 직접 실행한 결과가 아니다. Current implementation 결과는 root의 별도 receipt로 기록한다.

첫 boundary 실행·동결 전에 Standards 독립 리뷰가 late failure/cancel 뒤 JSON은 incomplete여도 `handoff.md`에 ready/rechecked 성공 문구가 남는 문제를 발견했다. Root 요청으로 `noSuccessMarker` 한 곳에 Markdown 부재 또는 명시 incomplete, ready/rechecked 및 exit0/1 부재를 검사하는 조건을 추가했다. 기존 5그룹과 예상 exit는 유지한다. 이는 테스트 오류 수정이 아니라 두 형식의 실패 상태 일치를 검증하는 계약 강화이며 첫 lock은 강화된 파일에 적용한다.

강화된 boundary 첫 lock SHA-256: `36228d1a23c025728ab93e432383a043bb8cd00dad007840ea3d0b4f13e59ae5`. Root는 이 파일의 수정 전 제품 build에서 2pass/3fail—위험 파일명 Markdown, late SIGTERM, publication fault—을 관찰했다고 전달했다. 작성자는 테스트를 실행하지 않았다. 해당 실패를 test expectation 완화로 지우지 않고 제품 수정 후 동일 파일로 재검증한다.

## 독립 Spec 리뷰

`36c8341` 대비 working diff 및 새 source-handoff/snapshot 파일을 최종 1페이지 계약과 읽기 전용으로 비교했다. 신규 Spec finding은0이다. Scan-time strings aggregate, typed four-format 보존, complete collector/known budgets/check set, canonical pair/current recollection, 원 incomplete gate 보존, finish의 원 fail-on 및 full after gate 결합을 확인했다. Recipe/model/patch/target execution의 범위 확장을 확인하지 못했다.

이미 알려진 Markdown plain escaping, before/create와 after/finish digest 설명 구분, catch의 late Markdown 제거는 코드의 수정 상태만 확인하고 신규 finding으로 중복 집계하지 않았다. 실제 회귀 통과는 root의 required-suite 실행 receipt가 별도로 필요하다. TOCTOU·decoded/raw 차이·작성자 서명 부재는 현재 계약의 한계로 유지된다.

## Required-suite retry 이후 표시 문자열 testbug 수정

Root가 전달한 `artifacts/source-handoff-2026-10-13/required-engine-retry.log`를 읽어 998개 중996pass/2fail/0skip와 해당 stack을 확인했다. 두 실패는 제품의 navigation 값 삭제가 아니라 `app\\.ts` 및 `owned\\_marker`를 raw Markdown에서 `app.ts`/`owned_marker`로 찾던 test assertion의 오류다. 제품 `inline` escaping과 stack의 가독성 assertion 실패를 대조해 확인했으며 작성자가 테스트를 실행하지는 않았다.

Root 요청으로 가독성 assertion 정확히 두 곳에만 CommonMark의 backslash-escaped ASCII punctuation을 표시 문자로 decode하는 단계를 넣었다. Raw Markdown mail link·HTML·autolink 금지와 원문/source/secret 비노출, exit/gate/receipt/late-failure 검사는 변경하지 않았다. 기존28+추가5그룹도 그대로다. 제품 escaping이 없는 raw link를 decode로 숨겨 통과시키는 변경이 아니다. 변경된 각 파일은 root가 다시 hash lock하여 focused/full 검증한다.

첫 full 실행 timeout과 Mac sleep의 관계는 root가 별도 `pmset` 근거로 보고했다. 위 두 assertion 실패가 기록된 retry는 log의 `duration_ms 101206.4475`에서 테스트 완주를 확인했다. Timeout과 실제 완료된 retry의 test failure를 합치지 않는다.
