# Independent archive-entry destination acceptance

Baseline: `594d770`; branch: `feat/archive-path-flow`. Expectations are written before reviewing producer changes or running the candidate. Root is the sole execution owner. All test input below is independently authored synthetic source, read as data; no ZIP, target source, dependencies, or upstream application is executed.

## Frozen semantic matrix

The supported family is stable declared `unzipper.Open.buffer` → await directory → same directory `files` for-of element → that element's `path` → stable native `createWriteStream` operand 0. Content stream/buffer is a different role. Only this sink is admitted; writeFile, writeFileSync, general HTTP sinks and generic objects are outside this slice.

| Group | Input distinction | Independent expectation |
| --- | --- | --- |
| 1 | Direct entry path; scalar alias/concatenation/template/resolve reuse | High-severity low-confidence conditional candidate at the actual native destination; archive-path source witness; AST partial and gate 2, including fail-on none. Unsupported extra forms may remain explicit partial, never silently clean. |
| 2 | Same content, fixed destination; entry path only logged; unrelated files/path object | No archive destination finding or archive-origin tag. Archive contents must not borrow filename provenance. |
| 3 | Immutable root=path.resolve(fixed), dest=path.resolve(root,entry.path), rel=path.relative(root,dest); reject rel==='..' OR rel.startsWith('..'+path.sep) OR path.isAbsolute(rel), terminating throw/return; direct same dest write | No archive destination candidate. This excludes lexical escape only, not symlink/TOCTOU/permissions/runtime reachability. Root/dest/rel and native binding identity must be stable. |
| 4 | Weak prefix/cwd includes; wrong candidate/entry; guard after write; guard only in sibling branch; mutation after guard | No safe exclusion. Supported source/sink keeps candidate; otherwise explicit partial/unknown gate 2. |
| 5 | Unrelated/shadowed/mutated unzipper or fs; re-export/opaque role | No fabricated declared origin or native sink certificate. Known invalidated declared role must remain partial rather than a completed clean safety claim. |
| 6 | Declared unzipper 0.12.3 or ^0.12.3 without lock; coherent exact locks 0.12.3 and 0.12.5; contradictory manifest/lock or unreviewed version | Reviewed coherent declaration remains conditional, installed identity unknown. Contradictory/unreviewed identity is unsupported partial, not qualified-safe. No sourceKind minted from package spelling alone. |
| 7 | fd supplied, custom fs supplied, dynamic options | No ordinary pathname-write certificate where descriptor/custom implementation replaces it. A genuine connected path with unresolved options remains explicitly unsupported/partial; no full-runtime claim. |
| 8 | Explicit POSIX/Windows or mismatched separator/flavor guard; continue guard if unsupported | No generic safe exclusion. The standard guard uses one stable default node:path namespace and its own sep; cross-convention/runtime semantics stay unsupported/partial. |
| 9 | Bounded analysis exhausted or collection incomplete | Partial gate 2, even fail-on none; unavailable archive trace must not be upgraded to complete safety. |
| 10 | JSON/agent/SARIF/Markdown, compare/projection malformed sourceKind, raw source marker | All four preserve candidate origin/context and gate, false verification flags, and no raw source/secret. Unknown/contradictory source kind is rejected or partial/unverified, never a passing comparable report. |

Risk/fixed pairs change only the destination or guard property. Fixed-content paths are a separate normal control from guard exclusion. Property names and local variable names are varied to defeat spelling-only recognition. Positive fixtures contain opaque `buffer` parameters, not HTTP sources. The source trace must start at the selected entry path and end at the actual createWriteStream call, never at archive bytes, another entry, or a content method.

Path edge truth is lexical: sibling-prefix `/owned/out-evil`, `../escape`, absolute paths, nested traversal, legal `..cache`, and Windows drive/UNC/mixed separators distinguish boundary checks. This first slice does not execute path/ZIP targets; explicit flavors cannot certify unspecified filesystem semantics.

## Execution and efficacy threshold

Root first freezes this document and independent test hashes, transpiles the same public-API test file against its preserved baseline compiled tree, and records failures before candidate execution. Baseline should load existing public imports and fail supported positive acceptance because the archive role is absent. Baseline failures are evidence of a missing static capability, not an exploit demonstration. Use the existing isolated independent-test transpilation/loader workflow; do not import prospective producer helpers.

Advance to immutable Juice Shop DATA-only remeasurement only after every supported owned risk is observed, every normal/role negative has zero fabricated archive destination candidates, every ineffective guard has zero safe exclusions, uncertainty has zero false clean, and all four reports agree. Root verifies exact entry.path→destination coordinates in the unchanged upstream snapshot. Do not tune expectations after its scan. A successful source scan proves a conditional static candidate, not installed package authentication, extraction execution, exploitability, remediation, or whole-service coverage.

## Freeze history

- v1 semantic matrix: authored before producer implementation review and before any author/root candidate test execution. Public rule/enum naming may be appended after interface coordination without weakening this matrix.
- Public naming agreed: `ast:archive-path-write`, `archive_entry_path`, conditional context item `declared_package_api`; counters `archiveDirectoriesRecognized`, `archiveEntryPaths`, `archiveWriteCandidates`, `archiveLexicalExclusions`, `archiveUnsupportedUses`. Recognized declared archive origin itself retains a gap; even fixed destination/lexical exclusion may and currently should retain partial2. Repeated partial reports remain unverified comparison. This interface clarification precedes execution; no baseline/candidate outcomes are known by the author.
- v1 test SHA256 `b5e9f7c33d5d463955fafacd1c587c31b0c59a0d7b9d9275f6d71f3252b24f6b` preserved by root. Root reports baseline 2 pass/10 fail; no candidate execution yet. Before candidate execution, root clarified the original reviewed declaration set is only `0.12.3`/`^0.12.3`: resolved lock `0.12.5` is admitted via `^0.12.3`, not a newly reviewed exact `0.12.5` declaration. v2 moves the exact-0.12.5-declaration+lock case from positive to unsupported negative as an author contract-interpretation bug. The `^0.12.3`→locked `0.12.5` positive and every other expectation are unchanged.
- v2 test SHA256 `a041a9a73a8dbdac94836e7d7a388a1d8b9f43bbea2abe131863c67c56962d7a` and root `focused-third` result 31 pass/1 fail are preserved. Root independently saved `artifacts/archive-path-2026-10-13/reassigned-destination-proof.json`: the final weak-guard fixture overwrites `dest` with a second `entry.path` read, so the correct observed source is line 11 column 27, followed by its call and the line 12 sink. v2 incorrectly required the first source read. Root approved v3 to change only that variant's exact source needle to `entry.path);\nfs.createWriteStream(dest)`, which selects the actual overwrite RHS. Candidate presence, severity/confidence, origin kind, exact source/sink proof, partial gate and every other fixture assertion remain unchanged. This correction follows a candidate result and is recorded explicitly as an author oracle-coordinate bug; it is not a pre-execution expectation freeze.


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
