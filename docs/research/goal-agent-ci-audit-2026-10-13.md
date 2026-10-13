# CI에서 소스 수정과 재검사까지 이어지는 사용자 동선 감사

2026-10-13. 조사 기준은 부모 작업에서 지정한 `main` commit `36c8341b69fecc663de8498295277289e7fbeb2b`의 저장소 코드·문서·회귀 테스트다. 초기 감사는 읽기 전용으로 진행했고, 이후 부모가 source handoff Product 구현을 별도로 위임했다. 이 작성 에이전트는 build, 테스트, 대상 실행, 모델 호출, credential 사용, Git 변경을 수행하지 않았다. 아래 기존 테스트 인용은 **존재하는 검증의 범위**이지 이 에이전트가 다시 통과시킨 결과가 아니다. 원격 경쟁 제품 비교 없이 일차 자료인 현재 구현을 우선했다.

**채택한 결정:** aggregate collected-string snapshot과 data-only `handoff create/finish`를 구현한다. 개별 파일 hash/list, runnable recipe/argv, 모델/patch/scan 실행은 추가하지 않는다. 현재 필드와 종료 정책은 [최종 1페이지 계약](#최종-1페이지-계약-부모-리뷰-반영안)이 우선하며, 아래 per-file manifest 및 recipe 초안은 변경 이유를 남긴 조사 이력이다. 검증은 부모와 독립 QA가 수행한다.

## 결론

가장 큰 연결 부족은 **일반 소스 scan의 특정 candidate → 검토한 수정 대상 → 같은 선언 범위의 재검사 결과**다. 설치·CI 보고서·미완료 판정·선택적 조언·전후 비교는 이미 있다. 반면 선택된 소스 finding을 실제 수정/검증 기록에 연결하는 계약은 없다. 현재 `repair`는 독립 SQL fixture 검증기이고, `advise`는 원문과 위치를 전송하지 않는 제한된 조언이다. 이 둘을 일반 앱의 자동 수리 파이프라인으로 설명하면 검증 범위를 넘어선다.

다음 작은 제품 변경으로는 모델이나 범용 실행기를 추가하기보다, **로컬 source handoff와 결과 수령 계약**을 추천한다. 소스 파일은 사용자가 허가한 로컬 코딩 에이전트가 별도로 검토하고, Wakeio는 선택 finding·원본 artifact·소스 provenance·재검사 범위를 연결한다. 결과는 `still_observed`, `not_observed`, `unverified`에 머물며 독립 보안/정상 control은 별도로 남긴다.

## 현재 사용자 동선과 실제 증거

| 단계 | 현재 있는 동작 | 남은 부담 / 경계 | 일차 근거 |
| --- | --- | --- | --- |
| clone / 설치 | Node 22+, source build, 버전 고정 npm 0.4.0, 검토 SHA Action, bundled Action | 소스 버전은 0.5.0이고 npm 공개본은 0.4.0이라는 구분 필요 | [CONTRIBUTING](../../CONTRIBUTING.md), [한국어 README](../../README.ko.md), [package metadata](../../package.json) |
| 첫 입력 선택 | `doctor`의 메타데이터 inventory·tool availability·next command, non-overwriting `init`, 명시 collection/AST limits | doctor는 collector coverage 예측이 아니다. 생성된 npm workflow는 프로젝트 dependency/lockfile을 따로 준비해야 한다 | [doctorMain](../../src/doctor.ts#L84), [initMain](../../src/init.ts#L29), [renderWorkflow](../../src/init.ts#L138), [collection CLI tests](../../tests/collection-cli.test.ts#L44) |
| CI 실패 | 0/1/2, incomplete 우선, `--fail-on none`으로 incomplete 숨기지 않음. artifact always upload 예제 | Gate와 보고서 전달/최종 process status를 별도로 읽어야 한다 | [shared gate](../../src/report.ts#L166), [CLI delivery](../../src/cli.ts#L724), [Action freshness/digest](../../scripts/action-run.mjs#L457), [agent Action tests](../../tests/agent-report.test.ts#L210) |
| 에이전트가 읽음 | findingId/checkIndex/checkId/ruleId, static-flow positions, summary·typed gaps; raw 보고서 projection digest | 원문·모든 coverage·실행 가능성까지 입증하지 않는다. `verification=not_run`, `remediation=not_verified` | [agent finding projection](../../src/report.ts#L284), [first-read tests](../../tests/report-summary.test.ts#L59), [agent contract](../agent-report.md#finding-evidence-and-consumer-requirements) |
| 선택적 Codex 조언 | 명시 `cli-login` 또는 `api-key`, upload consent, report-pair digest/canonical validation, policy 6, exact recheck routes | 원문/위치가 없는 조언은 정적 수정안 생성의 입력으로 충분하지 않다. API-key 라이브 호출, policy-6 라이브 호출 미검증 | [reportPair](../../src/agent-advice.ts#L74), [findingRoute](../../src/agent-advice-context.ts#L96), [advice contract](../agent-advice.md), [policy6 fake CLI tests](../../tests/agent-advice.test.ts#L237) |
| 수정 검증 | `repair`가 explicit files·trusted verifier·image·before/after assertions·normal control을 고정하고 private patch만 전달 | scan report/finding을 받지 않는다. 성공은 선언된 SQL fixture 범위이며 CI candidate와의 일치 증거가 없다 | [repair options](../../src/repair.ts#L157), [repairMain](../../src/repair.ts#L182), [repair contract](../repair-preview.md), [repair tests](../../tests/repair.test.ts#L33) |
| 재검사 / 비교 | 같은 project/options/ruleset/완료 check/provenance/collection 아래 `new`, `changed`, `unchanged`, `not_observed`; 다르면 `unverified` | 일반 source는 사용자가 이전 argv, artifact, 선택 finding, patch를 수동으로 연결한다 | [compareReports](../../src/compare.ts#L140), [comparison gate](../../src/compare.ts#L364), [comparison tests](../../tests/compare.test.ts#L28) |

Native/API finding replay는 이미 별도의 정책/동의/새 credential/실행 control 경계를 가진다. 이를 새 기능으로 제안하지 않는다. Source 후보에 같은 replay 권한을 부여하는 것도 제안하지 않는다. [현재 routes](../../src/agent-advice-context.ts#L96)와 [README replay](../../README.ko.md#네이티브-dast와-선택형-codex-조언)를 참고한다.

## 순위가 있는 개선 기회

### 1. 소스 candidate를 수정 검토와 재검사에 연결 — 실제 기능 공백

**영향:** CI가 high candidate로 실패했을 때, 일반 개발자는 보고서의 파일·sink 근거를 찾아 코딩 에이전트에 맡기고 재검사할 수 있다. 그러나 Wakeio가 보관하는 연결은 scan끼리의 비교뿐이다. 독립 `repair.json`에는 scan artifact digest, findingId, checkIndex, 원 scan ruleset에 대한 결합이 없다. 효과 없는 SQL patch·위조 검증·잘못된 fingerprint·원본 변경·cleanup failure를 거부하는 회귀 테스트는 강하지만, **다른 candidate나 다른 앱의 결과를 잘못 연결하는 소비자 흐름**을 검증하지 않는다.

**근거:** [repair policy](../../src/repair.ts#L37), [options](../../src/repair.ts#L157), [receipt construction](../../src/repair.ts#L182), [verification outcomes](../../src/repair.ts#L228), [repair integrity tests](../../tests/repair.test.ts#L151). `advise`가 source 위치·원문을 제외하는 것은 의도된 보호 경계이지 bug가 아니다([context projection](../../src/agent-advice-context.ts#L147)).

**첫 범위:** built-in-only source scan의 로컬 handoff와 전후 artifact 수령. 일반 source runtime 검증, agent 호출, source upload, patch 적용, Docker 실행은 추가하지 않는다. 기존 SQL `repair`의 성공도 전역 `fixed`로 승격하지 않는다.

### 2. baseline / 새 문제만 막는 CI onboarding — 비교 엔진은 있고 workflow 공백이 있음

**영향:** 기존 candidate가 있는 앱에서 README 기본 scan을 붙이면 기존 high finding도 job을 실패시킨다. `compare`는 이미 `new`/`changed`만 threshold gate로 삼고, unchanged finding은 scan report에 남긴다. 따라서 새 baseline suppression 엔진을 만드는 것은 중복이다. 부족한 부분은 신뢰된 baseline artifact의 선택, PR 변경으로 baseline을 교체하지 못하는 workflow, incomplete 비교의 fail-closed 유지, scan exit 1 후에도 compare가 실행되는 예제다.

**근거:** [comparisonExitCode](../../src/compare.ts#L364), [unchanged gate regression](../../tests/compare.test.ts#L28), [scope/incomplete regression](../../tests/compare.test.ts#L41), [current init workflow](../../src/init.ts#L166), [README Action example](../../README.ko.md#github-actions). 현재 Action/CLI scan은 baseline 입력을 받지 않는다.

**첫 범위:** trusted base revision의 built-in source scan과 PR scan을 별도 새 디렉터리에 보관하는 opt-in 예제. Scan exit 1은 compare까지 진행시키되 exit 2 또는 unavailable fresh artifact는 job 실패를 유지한다. final scan gate와 comparison gate를 함께 보인다. baseline 생성/채택을 사용자의 CI 정책 선택으로 남기고 자동 suppression·ignore-file은 만들지 않는다. External advisory provenance가 unknown일 때 compare exit 2가 되는 현재 경계를 유지해야 한다([provenance regression](../../tests/compare.test.ts#L140)).

**문서 부채:** README가 연결하는 [0.4 distribution 문서](../preview-0.4-distribution.md)는 2026-09-16 preview 기록으로 npm 미발행·세 report를 설명한다. 현재 README/CONTRIBUTING은 npm 0.4.0 공개·네 report를 설명하므로, 역사 문서임을 표시하고 현재 설치 문서로 안내해야 한다. 이는 설치 실패를 새 기능으로 고칠 문제가 아니라 상태/링크 정리다. live registry를 이번 조사에서 확인하지 않았으며 현재 상태 주장은 README/CONTRIBUTING의 선언에 한정한다.

### 3. source collector 사전 입력 계획 — 메타데이터 doctor를 coverage로 오해하지 않게 하는 기능 후보

**영향:** 큰 clone에서 default collection/AST 한도로 partial이 난 후, 사용자는 어떤 범위를 다시 지정할지 알아야 한다. 현재 typed collection bounds/reasons, summary navigation, explicit cap/profile, Action parity가 이미 있다. 새 단순 요약이나 cap 옵션은 중복이다. 남은 부분은 source를 데이터로 읽는 별도 dry-run planner가 collector의 실제 선택/제외를 사전에 보여 주는 것이다.

**근거:** [doctor metadata contract](../../src/doctor.ts#L75), [source content hash](../../src/scan-scope.ts#L64), [collection CLI regressions](../../tests/collection-cli.test.ts#L62), [summary collection regressions](../../tests/report-summary.test.ts#L246). [preflight tests](../../tests/preflight.test.ts#L178)는 API/OpenAPI 입력의 무네트워크 planning을 이미 증명한다. 현재 `plan` 문법은 API/OpenAPI/native 정책용이다([CLI usage](../../src/cli.ts#L85)).

**첫 범위:** collector 선정 수/바이트·reason aggregates·user-selected cap를 보여 주는 source-only planning. target install/build/test, AST 완주 예측, scanner availability를 실제 검출 coverage로 바꾸지 않는다. 기존 `doctor`의 메타데이터-only 계약은 유지한다. 이 기능은 1번 연결 계약 이후 평가한다.

## 권장 구현안: local source handoff v1

이것은 **제안**이며 현재 구현되지 않았다. CLI 이름/필드는 구현 리뷰에서 확정한다. 작은 형태는 `handoff` create/finish 두 명령을 한 새 모듈에 넣고 기존 report parser, gate, scope builder, comparison을 재사용하는 것이다. Workflow·모델 공급자·규칙 변경을 같은 PR에 넣지 않는다.

### 입력과 출력

1. **Create:** digest-bound `report.json`/`agent-report.json` 쌍, selected `checkIndex`+`findingId`, 사용자가 지정한 source root와 명시 scan recipe, new private output을 받는다. 첫 버전은 `mode=source`, `tools=none`, known built-in ruleset/budgets만 허용한다. 혼합 URL/API/native/external-engine scope는 `unsupported`로 거부한다.
2. Report 내 fingerprint는 hash이므로 거꾸로 원 argv를 복원하지 않는다. 사용자가 제시한 trusted recipe를 기존 `buildScanScope`에 넣어 project/options/ruleset/budgets/fingerprint를 일치시킨다. Unknown/legacy recipe는 guessed default로 채우지 않는다. 필요 시 새 scan에 additive versioned source recipe를 기록하는 작은 선행 변경만 별도 검토한다.
3. `handoff.json`은 두 artifact digest, selected finding/check/rule, scan gate, scope identity, available source provenance, local evidence 위치, 고정된 검토 단계와 정상/보안 control 필요 상태(`not_run`)를 기록한다. Markdown에는 source text·Secret 값·실행 명령을 finding에서 복사하지 않는다. Source 위치는 로컬 navigation이며 실행 권한이나 target truth 인증이 아니다.
4. 현재 source provenance hash와 입력 source가 불일치하거나 unknown이면 `source_changed_or_unknown`으로 차단한다. **주의:** 현재 `sourceContentHash`는 bounded tree provenance로 collector와 동일한 immutable snapshot attestation이 아니다. 이 체크를 “스캐너가 이 바이트를 검사했음” 또는 TOCTOU 보호라고 설명하지 않는다. 더 강한 file binding이 필요하면 scan-time bounded collector manifest가 별도 선행 조건이다.
5. 원본 source/reports는 수정하지 않는다. 소스 수정은 인간이 허가한 코딩 에이전트나 인간이 별도로 수행한다. 패치 제안·적용·security control·normal control·scan rerun의 상태를 합치지 않는다. 현재 SQL `repair`를 사용하려면 독립 reviewed policy/verifier가 여전히 필요하다.
6. **Finish:** 원 handoff와 새 digest-bound after report 쌍을 읽고 기존 `compareReports`를 실행한다. selected finding의 `unchanged/changed/new/not_observed/unverified`와 전후 scan gate, comparison gate를 나란히 기록한다. scope/ruleset/collection/analysis drift, unknown provenance, partial scan이면 `unverified`, exit 2다. 조건부 context 변동과 ambiguous keys의 현재 보수적 계약을 보존한다.
7. Create exit 0은 handoff 생성, finish exit 0은 비교 가능한 declared recheck receipt 생성의 의미다. 둘 다 vulnerability/fix confirmation이 아니다. target execution과 독립 control을 수행하지 않았으므로 `vulnerabilityConfirmed=false`, `remediationVerified=false`, controls=`not_run`을 유지한다. Artifact delivery failure는 exit 2, fresh complete receipt가 아니면 결과로 받아들이지 않는다.

### 수용 기준: 소유 합성 fixture만 사용

| 사례 | 필요한 결과 |
| --- | --- |
| 원 CLI의 vulnerable SQL source candidate, known source/budget/recipe | selected checkIndex/findingId/ruleId가 정확히 결합된 private handoff 생성; 원 source·네 report bytes 불변 |
| 같은 위치의 unrelated finding, unknown/duplicated finding reference, tampered sibling report 또는 digest mismatch | 명시적 incomplete/invalid input; 모델·네트워크·target 실행 없음 |
| 다른 project ID/root, 생성 전 source 변화, missing provenance, unreadable/symlink path | handoff 차단 또는 unknown; stale source를 confirmed context로 기록하지 않음 |
| 코딩 에이전트 대신 owned fixture 파일을 수동으로 parameter binding 형태로 바꾼 뒤 source scan | finish는 해당 candidate `not_observed`; 독립 security/normal controls=`not_run`, remediationVerified=false |
| 효과 없는 변경, 동일 candidate 유지, 새 high candidate 추가 | selected state가 유지되고 새 finding도 전체 comparison에 남음; successful fix 문구 없음 |
| after partial, collection/analysis budget 변경, ruleset 변경, duplicate semantic key, static-context drift | existing compare 계약대로 unverified/exit 2; `--fail-on none`도 이를 통과시키지 못함 |
| historical agent/report pairing, old output directory, output inside source, delivery failure | fresh receipt로 인정하지 않음; private 출력은 새 디렉터리 0700·파일 0600 |
| lifecycle script·source instruction·fake credential canary가 있는 fixture | install/build/test·model·network가 실행되지 않음; source text/Secret 값은 handoff에 포함되지 않음 |

회귀 범위는 새 handoff 계약과 기존 `agent-report`, `compare`, `source collection` focused suite다. detector 효능·라이브 모델 품질·API 인증·실제 application fix를 이 수용 테스트의 성공으로 주장하지 않는다. API-key나 policy-6 live advice 검증은 별도 승인·실행 과제이며 이 구현의 선행 조건이 아니다.

## 운영상 판단

Ordinary user의 핵심 완료 조건은 “CI가 실패했고 무엇을 어디서 검토해 어떻게 재검사할지 알며, 그 재검사 결과를 과장 없이 읽는다”다. 현재는 첫 부분에 강한 출력 계약이 있고 뒤 연결은 수동이다. Baseline workflow는 도입 부담을 줄일 수 있지만 일반 source 수정 근거를 만들지는 않는다. 단순 모델 호출 확대는 이미 있는 조언의 범위를 넘어가며 정확한 source/target binding이나 정상 기능 검증을 대신하지 못한다.

## 추가 기술 검토: stale source를 실제 거부하는 최소 선행 조건

부모 리뷰 요청에 따라 source fingerprint/manifest 재사용 가능성을 더 확인했다. **기존 `sourceContentHash`만으로 source-bound handoff를 완료했다고 주장해서는 안 된다.** 다음 구분이 위 구현안의 4번을 구체화한다.

| 기존 식별자 | 실제 생성 위치/범위 | 재사용 판단 |
| --- | --- | --- |
| report-pair SHA-256 | exact `report.json` bytes와 canonical agent projection | 보고서 쌍 결합에 재사용 가능. 작성자를 인증하거나 source bytes를 증명하지 않는다 |
| scope fingerprint | 옵션·project·ruleset/예산 등 안정 선언 identity | 재검사 범위 동등성에 재사용 가능. 소스 수정 후 유지되는 것이 정상이다 |
| `sourceContentHash` | source 검사를 마친 뒤 [CLI declaredScope](../../src/cli.ts#L718)가 호출하는 별도 [tree walk](../../src/scan-scope.ts#L64) | 현재 tree provenance 비교에만 가능. collector allowlist/exclusion과 다르며 scanner가 읽은 snapshot을 증명하지 않는다 |
| `comparisonKey` | snapshot의 path/rule/check와 redacted normalized semantic anchor | 줄 이동을 흡수하는 전후 matching에 재사용 가능. literal/token 정규화가 있으므로 정확한 file hash나 stale-source 검증으로 사용하면 안 된다([sourceComparisonKey](../../src/source.ts#L325)) |
| `repair.inputFingerprint` | 신뢰된 SQL verifier가 출력하는 assertion 입력 | 독립 SQL 회귀의 전후 control 동일성에만 사용 가능([repair verification](../../src/repair.ts#L85)) |
| API-state manifest / lineage | owned synthetic API fixture와 frozen observer | 일반 source scan lineage로 사용 불가([API-state input](../../src/api-state.ts#L79)) |

현재 `CollectedFile`은 path/bytes/text/category/sensitive만 있고 digest가 없다. `runSource`가 collector snapshot을 받아 동일 snapshot으로 AST/framework/semantic anchors를 만든다([types](../../src/source/types.ts#L8), [runSource](../../src/source.ts#L801)). 따라서 최소 선행 구현은 다음과 같다.

1. Collector가 실제 읽은 bounded raw buffer에서 digest를 생성하고, 해당 scan의 **code 입력 manifest v1**을 만든다. SHA는 새 tree walk나 source text 재읽기가 아니라 [readRegularFile](../../src/source/collector.ts#L240)의 buffer에서 얻는다. TextDecoder가 malformed UTF-8을 치환하는 현재 동작 때문에 decoded text를 file-byte SHA로 부르면 안 된다. Raw byte hash와 parser-input hash를 구분하거나 raw byte hash만 명시한다.
2. 첫 handoff는 JS/TS code candidate만 허용한다. Secret-category 파일의 per-file hash·원문·파일명은 새 manifest에 확장하지 않는다. Manifest의 적합한 code path/hash/bytes와 effective collection budget, completeness를 typed 필드로 report/agent에 결합한다. Missing/malformed legacy manifest는 `source_binding_unknown`이고 guessed hash를 채우지 않는다. Public 데이터가 너무 커지는 것을 피하려면 selected finding/staticFlow가 참조하는 code files만 보관하되, 그 경우 `bindingScope=referenced_files_only`를 명시하고 전체 source-bound라고 부르지 않는다.
3. `handoff` create는 selected finding의 location/staticFlow에 등장하는 모든 code 파일을 현재 root에서 같은 regular-file/size/link 정책으로 읽어 manifest hash를 비교한다. 한 바이트 변화, 경로 삭제/교체/링크, 선택 finding의 missing bound path는 refusal로 남긴다. 이는 **선택 근거 파일의 byte match**이며 원격 실행 attestation·전체 repo 동결·악용 확인이 아니다. 사용자/에이전트가 수정 전에 받는 private handoff에는 bound path/hash와 명시 불확실성을 담는다.
4. Source recipe를 새 scan에 versioned enum/numeric fields로 남기거나 사용자에게 정확한 argv recipe를 요구한다. 첫 PR은 `source`, `tools=none`, explicit profile/caps/timeout/projectId만 받아 같은 scope fingerprint로 검증한다. 보고서 fingerprint를 역산하거나 자유문에서 command를 생성하지 않는다.
5. 구현량을 더 줄이면 **첫 PR은 manifest + create만** 구현하고, 기존 `scan`/`compare`를 재검사 동선에 그대로 사용한다. 별도 finish 명령은 다음 PR로 미룰 수 있다. 이 경우 complete 자동 result handoff가 아직 없다는 한계를 분명히 표시한다. Scoped user benefit은 “이 finding의 local 근거 파일이 아직 같은지 확인된 검토 패킷과 재검사 recipe”다.

추가 필수 acceptance는 **scan에서 파일 A를 읽은 뒤 scope tree hash 전에 파일을 변경한 소유 fixture**다. 새 manifest는 실제 읽은 A의 hash를 유지하고 현재 변경된 A의 handoff를 거부해야 한다. 기존 sourceContentHash가 변경 후 tree와 일치하더라도 수락하면 안 된다. 다른 owned fixture는 normalized anchor가 같도록 literal만 변경하여 comparisonKey가 유지되는 상황에도 file-byte match가 실패하는지 검사한다. 이 둘은 조작된 외부 앱 실행 없이 synthetic collector/handoff 계약으로 검증한다.

### 데이터 전용 handoff와 직접 repair 결합 비교

| 선택 | 사용자가 얻는 이익 | 거짓 검증 위험 / 제한 |
| --- | --- | --- |
| Source manifest + local handoff + 기존 scan/compare | 일반 JS/TS CI candidate를 허가된 로컬 coding agent가 정확한 위치/같은 파일 상태에서 검토. 수정 전후 scope·gate·candidate 변화를 보존 | 원문으로 문제를 판단하고 독립 control을 만드는 일은 여전히 별도. 후보 사라짐은 `not_observed`, control=`not_run`, verified=false로 유지하므로 runtime fix로 오해하기 어렵다 |
| 기존 repair에 report digest/finding 필드만 추가 | 이미 owned Python/SQLite fixture와 reviewed verifier를 준비한 좁은 사용자의 기록 연결 | 일반 JS/TS finding과 SQL fixture verifier가 동일 문제인지 증명하지 못한다. 관련 없는 fixture 성공을 CI candidate fix로 승격하는 위험. 적합한 rule/profile/runtime/source-file binding과 독립 fixture 작성 절차 없이는 product gap 해결 주장을 할 수 없다 |

권장은 첫 번째다. 두 번째는 나중에 **독립 검증기가 정확히 어떤 finding/source snapshot/보안 assertion/normal control을 대상으로 하는지** 명시하는 별도 integration일 때만 진행한다. 보고서 hash 한 필드는 semantic/runtime correspondence를 대신하지 못한다.

## 최종 1페이지 계약: 부모 리뷰 반영안

이 절이 앞선 구현 초안의 **per-file manifest·recipe/argv 생성과 finish exit 0=receipt 생성** 제안을 대체한다. Product 구현은 작성했고 부모 작업은 첫 build와 독립 focused 회귀가 통과했다고 보고했다. Markdown 수정 및 추가 boundary 사례를 포함한 required-engine 통합 검증은 아직 남아 있다. 이 작성 에이전트는 build/테스트/target/model/Git 실행을 수행하지 않았다.

**명령:** `wakeio-security-ci handoff create --report DIR --source DIR --finding ID --check-index N --out NEW_DIR`, `wakeio-security-ci handoff finish --handoff DIR --report AFTER_DIR --source DIR --out NEW_DIR`. Report/handoff/new output은 source 밖으로 한정한다. 모든 출력은 새 private directory(0700), receipt/Markdown/복사본(0600)이며 재사용·원본 쓰기·patch 적용 없음. 명시적 CLI task 외 별도 권한이나 모델 호출을 얻지 않는다. Create output에 original `report.json`/`agent-report.json` exact bytes를 private 복사하여 finish의 `--before` 옵션을 없앤다.

**v1 지원 범위:** mode=source, tools=none, 정확히 한 개씩 존재하는 `source.inventory`, `source.builtin-ast`, `source.framework`의 고정 built-in check set, known tool/ruleset/collection/analysis revisions, coherent typed budgets다. finding 선택은 `(checkIndex,findingId)`이며 해당 check membership/rule/location이 canonical agent projection과 일치해야 한다. Collector snapshot은 complete여야 하지만 **AST partial의 실제 보유 candidate도 review handoff로 생성 가능**하다. 이때 original scanGate=incomplete/2와 analysis gaps를 그대로 남긴다. Duplicate/ambiguous 선택, unknown source binding, collector partial/error, 취소, 혼합 URL/API/native/external scope는 exit 2다. `source.framework`의 documented not_applicable은 기존 gate 규칙을 따른다. Create 성공을 original CI 통과로 표시하지 않는다.

**scan-time collector binding:** `runSource`가 실제 받아 detectors/anchors에 사용하는 `SourceSnapshot.files`의 immutable collected strings에서 `source-snapshot-v1` aggregate SHA-256을 만든다. 고정 정렬·framing 규칙으로 relative path/category/sensitive/bytes/text와 effective collection budget를 묶되 외부에는 `sourceSnapshot:{revision:'source-snapshot-v1',basis:'collected_utf8_strings',algorithm:'sha256',digest,filesSelected,bytesSelected,complete,outputDirectoryExcluded}`만 남긴다. `outputDirectoryExcluded`는 source 내부 또는 root 자체로 output을 지정했음을 보수적으로 기록하며 v1 handoff는 true를 거부한다. 보고서를 source 밖으로 복사해 이 경계를 우회할 수 없다. 실제 root 디렉터리 제외의 증명으로 해석하지 않는다. Per-file list/hash·Secret 값·source text는 추가하지 않는다. 같은 decoded strings의 일치이며 raw file-byte attestations/파일시스템 전체 동결/검사자 인증은 아니다. 동일 내용의 다른 checkout도 content match이지 원 root 동등성 인증이 아니다. `sourceContentHash`, scope fingerprint, normalized semantic comparisonKey는 snapshot proof로 사용하지 않는다. Snapshot digest는 `source.inventory`의 typed 필드로 JSON/agent/Markdown/SARIF에 보존하고 malformed present metadata는 partial/외부 parser reject, legacy absent metadata는 일반 compare에서 기존처럼 읽되 handoff에서는 거부한다. Hash 생성은 추가 target read나 실행이 아니라 기존 collector snapshot에서 수행한다.

**재검사 동선:** runnable recipe·argv·새 recipe metadata를 만들지 않는다. Handoff는 DATA-ONLY review packet이다. 사용자가 원 CI scan 명령과 옵션을 별도로 재사용한 뒤 finish에 after report를 준다. 문서 예제는 source/projectId/tools/profile/caps/timeout/out을 완전히 명시한다. Fingerprint 역산, report에 없는 timeout 추론, 현재 기본값 가정, finding/model prose의 command 실행은 없다. Finish의 기존 compare가 선언 scope fingerprint/checkset/ruleset/known budgets의 일치를 판정한다.

**create:** bounded/symlink-safe input으로 exact report bytes digest와 canonical agent projection을 먼저 검증한다. 현재 supplied source를 기존 collector로 read-only 재수집하여 **known effective collection budget의 aggregate snapshot digest**와 비교한다. Scope/inventory/AST에 기록된 예산·profile의 coherence를 검증한다. complete가 아니거나 한 입력 문자열·선택 경로·category/budget가 달라지면 `source_drift_or_unknown`, exit 2다. source root·out ancestor/target link·hardlink 제한과 input/output exclusion은 기존 collector/새 private delivery 정책을 재사용한다. 이것이 현재 snapshot의 일치 근거이며 process/CI delivery는 별도 receipt 없으면 unknown이다.

**receipt v1:** `version:1`, `operation:create|finish`, `status:ready|rechecked|incomplete`, `reason` fixed enum, `exitCode`, `input:{reportSha256,agentReportSha256}`, `selected:{checkIndex,checkId,findingId,ruleId,comparisonKey?}`, original report `scope`, `sourceBinding:{revision:'source-snapshot-v1',basis:'collected_utf8_strings',algorithm:'sha256',digest,filesSelected,bytesSelected,complete,outputDirectoryExcluded}`, `originalScanGate`, `verification:{vulnerabilityConfirmed:false,remediationVerified:false,securityControl:'not_run',normalControl:'not_run'}`, `limitations` fixed text. `sourceBinding`은 create 당시 입력의 aggregate identity이며 추가적인 matched flag·per-file hash·raw-byte proof를 갖지 않는다. Finish는 `after:{reportSha256,agentReportSha256,sourceBinding,scanGate}`, full existing `comparison`, string `selectedState`를 추가하며 `after.sourceBinding`이 finish 현재 source와 일치한 입력이다. Incomplete refusal receipt는 version/operation/status/exitCode/reason/verification만 남길 수 있다. Create output은 `report.json`,`agent-report.json`,`handoff.md`,`handoff.json`; finish output은 `after-report.json`,`after-agent-report.json`,`handoff.md`,`handoff.json`이다. JSON의 ready/rechecked는 copies/Markdown 전달을 마친 뒤 마지막에 atomic link로 게시하는 commit marker이며 four-file atomic transaction은 아니다. Original evidence/guidance는 navigation용 untrusted data이며 실행 지시로 해석하지 않는다. Markdown에는 escape된 plain-text finding location·candidate 상태·독립 control 필요·원 CI 명령으로 별도 재검사하라는 안내만 보여 주고 rendered link/HTML·model prose/source snippets/새 argv는 넣지 않는다.

**finish / exits:** 기존 strict report parser·pair binding·`compareReports`를 재사용하며 private before copies/selected identity와 현재 after input을 다시 확인한다. Receipt의 report-derived fields는 canonical projection으로 재생성하여 비교한다. 이는 내부 불일치 거부이며 서명/작성자 진위 보장은 아니다. Supplied source를 현재 collector로 재수집하여 **after snapshot digest**도 일치해야 한다. `comparisonExitCode`와 **after full scan gate**를 함께 적용해 `2 > 1 > 0` 우선순위를 쓴다. create exit 0=ready review handoff 생성(원 CI exit 2도 그대로 보임), 2=refusal/delivery incomplete. finish exit 0=동등한 선언 범위의 after scan이 완료되고 원 threshold blocking finding이 없음, 1=after threshold finding 또는 comparison blocking change가 있음, 2=source/scope/provenance/budget/context/ambiguity drift·before/after incomplete·delivery 실패다. Unchanged high candidate도 after gate 때문에 exit 1이다. 선택 후보 미관찰은 `not_observed`이고 code 0도 verified fix를 뜻하지 않는다. `--fail-on none`이 원 정책이면 그대로 보존하고 incomplete를 통과시키지 않는다. Stale/부실 출력은 successful receipt로 받아들이지 않는다.

**필수 owned regressions:** 실제 CLI scan snapshot → create 성공과 original byte 불변/private exact copies; collector complete+AST partial+보유 candidate → create 0/originalGate2 보존/finish2; scan snapshot 뒤 tree hash 전에 mutation → create 거부; normalized anchor 유지하는 literal 변경 → aggregate mismatch; unknown legacy/malformed digest/budget·tampered report pair/receipt·다른 selected check·symlink/hardlink/new-output 실패 → exit 2; 효과 없는 patch → unchanged blocking/exit 1; 동일 원 scan 명령으로 candidate 제거 → not_observed/exit 0/controls not_run; 새 high issue → exit 1; stale AFTER source·partial·budget/ruleset/staticContext drift·duplicate key → unverified/exit 2. Lifecycle/model/network/target execution canary는 실행되지 않아야 한다. 과거 repair/API-state fixture 성공을 generic source fix evidence로 연결하는 테스트/문구는 추가하지 않는다.
