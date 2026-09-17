# v0.3.0-dev.1 다음 iteration: 공식 primary source 기반 기회

검토일: 2026-09-16 (KST) · 기준: `wakeio-security-ci` `0.3.0-dev.1`

이 문서는 기능을 구현하거나 출시를 승인하는 문서가 아니다. 현재 계약과 실제 재현 결과를 기준으로, 공식 제품 문서·표준·보안 가이드가 요구하는 다음 개선의 경계를 정리한다. 공식 문서는 기능·동작의 근거로 사용했고, OSV의 upstream issue는 보장된 로드맵이 아니라 방어적으로 수집할 실패 사례로 취급했다.

## 현재 계약과 판단

현재 CLI는 제한된 source snapshot, bounded URL GET, 명시적 API authorization policy를 실행하고 JSON·SARIF·Markdown을 쓴다. `candidate`·`observation`·`advisory`와 `completed`·`partial`·`error`·`not_applicable`·`skipped`를 나누며, 불완전한 check는 `--fail-on none`이어도 exit 2다. source에서는 JS/TS 제한 흐름, 선택적 Bandit, Gitleaks, 지원 lockfile의 OSV advisory, Dockerfile/Kubernetes/Terraform에 대한 Trivy config, 제한된 Next/Supabase 규칙을 제공한다. URL은 로그인·브라우저·API fuzzing을 하지 않는다. [CLI](../../src/cli.ts), [공유 계약](../../src/contracts.ts), [체크리스트](../checklist.md), [보고서](../../src/report.ts)

부모 에이전트의 loopback 재현은 다음 네 지점을 확인했다. 같은 파일·같은 scanner라도 임시 설치 경로가 달라지면 scope가 incomparable이 되고, 주석 한 줄 이동은 같은 sink를 `new`와 `not_observed`로 나눈다. 만료된 다른 계정 토큰이 401을 받아도 positive identity가 없으면 completed 0이 되며, 정상 오류 응답이 공개 resource ID를 반복하는 경우 보호된 본문 노출과 같은 high 후보가 된다. 빈 본문의 정상 403은 현재 JSON-only 계약 때문에 partial이다. [통합 재현 분석](next-iteration-analysis-2026-09-16.md), [재현 JSON](next-iteration-parent-reproductions-2026-09-16.json)

따라서 다음 버전의 중심은 scanner 수를 늘리는 것이 아니라 **동일한 검사를 같은 문제로 비교하고, 처음 실행한 사람이 검사 범위와 미검사를 이해하며, API 권한 결과를 실제 actor 증거로 판정하고, PR에서 수정 여부를 재검사하는 것**이다. 아래 8개는 이 흐름을 직접 개선하는 기회다.

| 우선 | 기회 | 사용자가 바로 얻는 변화 | 상대 비용 |
| --- | --- | --- | --- |
| P0 | 비교 identity + 외부 engine/data provenance | 임시 경로와 rule bundle 변화가 수정·회귀처럼 보이지 않음 | 중~높음 |
| P0 | `plan`/`doctor` first-use 안내 | 첫 실행 전에 적용 check, 누락 도구, 외부 통신을 알 수 있음 | 중 |
| P0 | API actor·evidence 판정 | 만료 token·ID echo·정상 403을 유출로 오판하지 않음 | 중 |
| P1 | 실제 Next/Supabase semantics | client boundary와 RLS/grant의 정적 한계를 분명히 검사 | 중~높음 |
| P1 | Node/Python dependency project model | requirements, marker, workspace, local link를 false clean 없이 다룸 | 중 |
| P1 | OSV resilience와 fidelity | advisory identity·미지원 데이터·upstream 장애를 숨기지 않음 | 중 |
| P2 | OSV reachability를 선택형 증거로 | 지원 언어에서만 called/uncalled 정보를 triage에 사용 | 높음 |
| P0/P1 | PR-native summary·annotation | 로그 대신 수정할 파일·상태·미검사를 PR에서 확인 | 낮음~중 |

## 1. 비교 identity와 외부 provenance를 분리한다 — P0

**현재.** `declaredScope`는 source의 절대 경로와 `toolPaths`를 fingerprint에 포함한다. finding identity도 check, rule, kind, title, path, URL, line, column에 의존한다. 그래서 경로가 바뀐 동일 CI 실행은 비교를 거부하고, 상단에 주석만 추가한 동일 sink는 line이 바뀌어 `new`와 `not_observed`가 된다. 현재 SARIF의 자체 `fingerprints`는 이 위치 기반 ID를 투영하지만, 외부 engine·rule bundle·advisory DB의 식별자는 보고하지 않는다. [scope 코드](../../src/cli.ts), [finding ID 코드](../../src/report.ts), [비교 코드](../../src/compare.ts)

**제안.** 보고서에서 다음을 별도 필드로 만든다.

- 사용자가 지정한 논리적 `project_id`, source-relative path, commit 또는 source content hash. 절대 checkout·실행 파일 경로는 identity에서 제외한다.
- 선택 scope(파일·URL·operation·actor·fixture), Wakeio adapter와 binary version/digest, rule/check bundle source·digest·시점, OSV DB 시점, online/offline mode.
- finding의 비교 ID와 표시 위치. rule+kind+상대 path+enclosing symbol 또는 정규화한 구문 anchor를 우선하고, API는 actor·fixture·resource identity를 포함한다. 여러 후보가 매치되면 `changed`/`unverified`로 남기고 임의로 fix 처리하지 않는다.
- GitHub 투영에는 자체 비교 ID와 SARIF의 `partialFingerprints`를 구분하고, 여러 분석을 함께 올릴 때 run `category`/자동화 ID를 안정적으로 지정한다. GitHub는 누락된 partial fingerprint를 upload action이 계산할 수도 있다고 문서화하므로, 현재 업로드가 항상 실패하거나 항상 중복된다고 주장하지 말고 실제 두 commit 업로드로 검증한다. [SARIF 업로드 공식 문서](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

Trivy는 실행 binary와 별도로 vulnerability DB·Java DB·checks bundle을 사용하고, checks bundle은 자동 갱신되거나 offline에서 binary 내장 fallback으로 대체될 수 있다. OSV-Scanner release에는 SLSA provenance가 붙지만 그것이 advisory DB의 동일 시점을 보장하지는 않는다. 따라서 Trivy에는 `bundle_source`(다운로드/내장/unknown), digest와 갱신 시점을, OSV에는 DB/network 상태를 기록하고 값이 없으면 unknown으로 남긴다. 같은 binary라는 이유로 결과를 comparable로 만들지 않는다. [Trivy DB와 bundle](https://trivy.dev/docs/dev/configuration/db/), [Trivy builtin checks](https://trivy.dev/docs/latest/scanner/misconfiguration/check/builtin/), [OSV 설치·release provenance](https://google.github.io/osv-scanner/installation/)

**도입 효과.** PR 재검사에서 같은 문제의 이동·경로 cache 차이·engine drift를 구분할 수 있다. 비교 결과를 “finding 수가 감소했으니 수정 완료”로 번역하지 않는 현재 원칙도 유지된다.

**비용과 위험.** symbol/구문 정규화, binary version/digest 수집, 외부 cache 식별과 schema migration이 필요하다. 정규화가 너무 강하면 서로 다른 두 sink를 합치고, 너무 약하면 현재와 같은 중복이 남는다. 프로젝트 ID만으로 다른 checkout의 동일성을 증명할 수 없으므로 scope/content와 provenance를 함께 보존하고, 모호한 매치는 성공으로 낮추지 않는다.

## 2. `plan`/`doctor`로 first use를 계약화한다 — P0

**현재.** 공개 진입점은 `scan`과 `compare`이고, 로컬 CLI는 PATH 또는 사용자가 준 도구 경로를 필요로 한다. composite Action은 매 실행 native 도구를 임시 directory에 설치한 뒤 `GITHUB_OUTPUT`에 report directory만 쓴다. 첫 실행 전에 어떤 check가 적용되는지, 도구 설치·cache가 실패했는지, OSV·Trivy가 무엇을 조회하는지 한 화면에 보여주는 preflight가 없다. [Action](../../action.yml), [Action runner](../../scripts/action-run.mjs), [현재 설치·CI 분석](next-iteration-analysis-2026-09-16.md)

**제안.** 네트워크·build·source write 없이 읽기 전용 `plan`/`doctor`를 추가한다. 출력에는 detected project signals(Next/Supabase/Node/Python/API/OpenAPI), 수집·제외 범위, 각 check의 applicable/not_applicable/partial 예상, missing executable, 실제 version·checksum, rule/data source, OSV online/offline, Trivy bundle fallback 가능성, API credential **환경변수 이름만**, 재실행 명령과 exit semantics를 넣는다. Action도 동일 요약을 scan 전에 내고, 예제 config를 만들 `init --write`는 별도의 명시적 동작으로 둔다.

OSV 문서는 lockfile·manifest 추출과 local DB/offline 경로를 별도로 설명하고, Trivy 문서는 DB를 자동 취득하는 구조와 offline fallback을 설명한다. GitHub Actions는 fork의 `pull_request` workflow에 secrets를 넘기지 않으며, privileged `pull_request_target`에서 untrusted checkout을 실행하지 말라고 경고한다. 따라서 doctor가 “credential이 없어 deny actor가 검증되지 않음”을 설치 실패나 clean으로 숨기지 않고 보여줘야 한다. [OSV 사용법](https://google.github.io/osv-scanner/usage/), [OSV 설치](https://google.github.io/osv-scanner/installation/), [GitHub fork/secrets 이벤트](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)

**도입 효과.** vibecoder가 scanner 네 개의 설치법과 결과 상태를 각각 추측하지 않고 첫 실행 전에 범위·미검사·외부 통신을 판단한다. 특히 fork PR에서 token이 없다는 사실이 권한 검사 성공으로 오해되는 것을 줄인다.

**비용과 위험.** OS별 executable discovery, version output parsing, cache provenance 유지가 필요하다. 파일명 heuristic만으로 Next/Supabase를 확정하면 false applicability가 생기므로 `detected`, `confirmed`, `not detected`를 구분한다. 도구가 없을 때 조용히 skip하지 않고 현재의 partial/error semantics로 연결한다.

## 3. API 결과를 actor·resource·protected data 증거로 판정한다 — P0

**현재.** 정책은 owner positive control 뒤에 anonymous/other actor의 GET을 실행할 수 있지만, 토큰의 존재·형식·서로 다름만 확인한다. 부모 재현처럼 만료된 다른 계정 token이 401을 반환해도 `completed` 0이 될 수 있다. 또한 `id`가 반복되는 정상 403과 protected field가 실제로 반환된 403을 하나의 marker로 판정하며, empty-body 403은 JSON-only 계약상 partial이다. [API 구현](../../src/api.ts), [API 정책 문서](api-policy-implementation.md), [통합 재현 분석](next-iteration-analysis-2026-09-16.md)

**제안.** 각 case를 다음 증거로 분리한다.

1. actor credential state: `valid`, `missing`, `expired`, `unknown`. 인증 actor는 identity endpoint 또는 자기 소유 fixture read가 기대 user/org marker와 함께 성공해야 한다.
2. resource identity: A가 읽은 fixture의 ID/marker가 B 요청과 같은 대상인지 확인한다.
3. protected-data assertion: secret/canary 필드의 존재·금지 필드·필수 JSON 조건을 별도로 지정한다. ID만 echo된 오류는 약한 evidence로 남기고 자동 high로 만들지 않는다.
4. deny policy: 유효 actor가 받은 401/403/404/empty-body 중 허용 결과를 case에 명시한다. malformed/non-JSON, 429, 5xx, timeout, positive control 실패는 `partial`/`error`/`unverified`다.

OWASP는 object ID를 받는 모든 endpoint에서 로그인 사용자의 object-level permission을 확인해야 한다고 하고, function-level authorization도 URL 모양이 아니라 role/function matrix로 테스트하라고 한다. OpenAPI `security`는 인증 요구사항의 대안·operation별 적용을 표현할 뿐 object ownership을 표현하지 않는다. Schemathesis도 auth·stateful workflow에 실제 fixture와 cleanup을 주입하는 모델이다. 따라서 OpenAPI operation inventory나 Schemathesis adapter는 정책 초안·요청 생성에만 쓰고, 소유권·조직 경계는 사용자가 제공한 actor/fixture로 판정한다. 기본은 현재처럼 GET-only이며 write/stateful 검사는 명시적 opt-in과 격리 cleanup을 요구한다. [OWASP BOLA](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/), [OWASP BFLA](https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/), [OpenAPI security](https://swagger.io/specification/v3/?sbsearch=auth), [Schemathesis auth](https://schemathesis.readthedocs.io/en/stable/guides/auth/), [Schemathesis stateful](https://schemathesis.readthedocs.io/en/stable/guides/stateful-testing/)

**도입 효과.** 만료 token·공개 ID·정상 privacy-preserving 404를 권한 검증 또는 data exposure로 과장하지 않으면서, 유효한 다른 actor에게 protected canary가 보이는 BOLA/BFLA 증거는 놓치지 않는다.

**비용과 위험.** 사용자 fixture와 identity endpoint를 요구하면 설정 부담이 생기고, API마다 404/empty/401의 정상 의미가 다르다. ID만 반복하는 오류를 high로 올리면 false positive이고, marker 없는 200을 안전으로 처리하면 false negative이므로 둘 다 `unverified`로 남긴다. 별도 actor의 인증이 확인되지 않으면 row를 성공으로 세지 않으며, bearer 원문·response body를 report에 보존하지 않는다.

## 4. Next/Supabase의 실제 boundary를 정적·로컬 evidence로 나눈다 — P1

**현재.** Next/React는 `use client`와 일부 `NEXT_PUBLIC_*`/Supabase secret 모양을 보는 후보 규칙만 있고, import graph·re-export·build artifact를 확인하지 않는다. Supabase migration 규칙도 RLS 해제와 permissive PUBLIC policy의 구문 후보일 뿐 live grant/RLS state나 전체 migration 순서를 증명하지 않는다. [체크리스트](../checklist.md), [framework rules](../../src/source/framework.ts)

**제안.** Next 규칙은 module graph에서 `use client` 경계, `server-only`, re-export/dynamic import를 따라가고 server secret 또는 전체 server object가 client bundle 경계로 넘어가는 후보를 표시한다. 사용자가 만든 `.next`/bundle을 별도 입력으로 주면 분석할 수 있지만, Wakeio가 project build나 untrusted code를 자동 실행하지 않는다. `NEXT_PUBLIC_*`가 client bundle로 inlining될 수 있고 `next.config.js`의 `env` 값은 이름과 무관하게 JS bundle에 포함될 수 있다는 공식 동작을 검사 기준으로 삼는다. [Next Server/Client Components](https://nextjs.org/docs/app/getting-started/server-and-client-components), [Next data security](https://nextjs.org/docs/app/guides/data-security), [Next environment variables](https://nextjs.org/docs/pages/guides/environment-variables), [Next `next.config.js env`](https://nextjs.org/docs/pages/api-reference/config/next-config-js/env)

Supabase는 publishable/legacy `anon` key를 public component에서 사용할 수 있다고 설명하는 반면, `sb_secret_`/legacy `service_role`은 backend 전용이고 RLS를 우회한다고 설명한다. exposed object는 grants와 RLS를 함께 봐야 하며, policy를 추가해도 기존 grant가 사라지지 않는다. 다음 정적 검사에는 exposed table/view/function의 RLS·grant·policy matrix와 `EXECUTE` grant 후보를 포함하되, public key 존재를 secret으로 판정하지 않는다. 사용자가 준비한 local database에서는 공식 `supabase test db`/pgTAP profile을 opt-in으로 실행해 select/insert/update/delete actor test를 evidence로 남길 수 있지만, cloud state를 기본 조회하지 않는다. [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys), [Supabase securing your API](https://supabase.com/docs/guides/api/securing-your-api), [Supabase RLS](https://supabase.com/docs/guides/database/postgres/row-level-security), [Supabase database testing](https://supabase.com/docs/guides/database/testing), [Supabase CLI test db](https://supabase.com/docs/reference/cli/supabase-test-db)

**도입 효과.** Next의 실제 client/server 경계와 Supabase의 grant+RLS 모델을 한 finding으로 뭉개지 않고, 개발자가 수정할 import/env/SQL 위치와 “live state 미확인”을 구별할 수 있다.

**비용과 위험.** TypeScript alias·monorepo·조건부 export·SQL dialect/순서 해석이 필요하다. heuristic만으로 client 경계를 확정하면 false positive가 생기고, 동적 import·unresolved alias를 놓치면 false negative가 된다. migration에서 RLS가 보였다는 사실은 운영 DB가 안전하다는 증명이 아니며, pgTAP test가 없다는 사실도 곧바로 취약성은 아니다. unresolved graph와 missing live state는 candidate/coverage/unknown으로 남긴다.

## 5. Node/Python을 lockfile 목록이 아니라 project model로 다룬다 — P1

**현재.** source collector는 `requirements.txt` 계열을 manifest로 인식하지만 OSV에 넘기는 lockfile 목록에는 넣지 않는다. OSV 결과 parser도 package name/ecosystem/version/advisory 중심으로 정규화하며 purl·direct/transitive/dev/optional·local link·적용 platform을 보존하지 않는다. Python SAST는 선택한 Bandit 실행 파일에 의존한다. [source collector](../../src/source.ts), [OSV parser](../../src/source/parsers.ts), [Bandit adapter](../../src/source/python.ts)

**제안.** OSV가 문서화한 arbitrary file syntax(예: `requirements.txt:/path`)를 사용해 requirements 계열을 명시적으로 스캔하고, PEP 508의 extras·URL requirement·version constraint·environment marker를 parse해 “이 runner에서 적용되는 dependency”를 report한다. npm은 workspace root/package, `file:`/`link:` local package, direct/transitive/dev/optional/peer 구분을 보존한다. package purl/source path와 unresolved/unsupported reason을 유지하며 package manager install·resolve·build를 실행하지 않는다. Bandit JSON의 test ID, severity, confidence, location과 파일 coverage를 같은 project inventory에 연결한다. [OSV source scan](https://google.github.io/osv-scanner/usage/), [OSV scan-source](https://github.com/google/osv-scanner/blob/main/docs/scan-source.md), [PEP 508 dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/), [npm workspaces](https://docs.npmjs.com/misc/workspaces/)

서명·provenance는 취약성 판정과 별도의 선택 metadata lane으로 둔다. `npm audit`는 dependency tree 설명을 default registry에 제출하고, `npm audit signatures`는 다운로드한 package의 registry signature와 provenance attestation을 검증한다. PyPI attestations는 release file digest와 build identity/source를 묶어 provenance를 보여주며, PyPI 문서도 유효한 attestation이 package의 trustworthiness를 보장하지 않는다고 한다. 따라서 기본 no-source-upload 계약에 audit metadata 전송을 섞지 않고, 사용자가 opt-in했을 때 “출처/무결성 확인”으로만 표시한다. [npm audit](https://docs.npmjs.com/cli/audit/), [npm audit signatures](https://docs.npmjs.com/cli/v11/commands/npm-audit), [PyPI attestations](https://docs.pypi.org/attestations/), [PyPI consuming attestations](https://docs.pypi.org/attestations/consuming-attestations/)

**도입 효과.** 흔한 Python requirements와 Node workspace가 “지원 lockfile 없음” 또는 registry package로 잘못 해석되어 clean/partial이 되는 일을 줄이고, 개발자가 직접 dependency인지 local link인지와 적용 환경을 볼 수 있다.

**비용과 위험.** npm workspace semantics, Python marker evaluation, package name normalization과 registry metadata 정책이 계속 변한다. OSV upstream에는 `link: true` local package를 registry advisory와 잘못 매칭했다는 issue가 있고, Python package name resolution 및 requirements package 누락 문제도 보고되어 있다. 이 issue들은 계약이 아니므로 구현 요구사항의 증명으로 쓰지 말고 fixture corpus로 사용한다. local/peer/platform 조건을 확정할 수 없으면 advisory 부재가 아니라 unknown/partial로 남긴다. [OSV local-link issue #2881](https://github.com/google/osv-scanner/issues/2881), [OSV Python name-resolution issue #2931](https://github.com/google/osv-scanner/issues/2931), [OSV requirements parsing issue #2940](https://github.com/google/osv-scanner/issues/2940)

## 6. OSV resilience와 advisory fidelity를 먼저 보강한다 — P1

**현재.** Wakeio는 `--no-call-analysis=all`로 OSV를 실행하고, parser는 package identity·advisory·fixed version·references만 남긴다. malformed JSON, 빈 결과, unsupported field는 check error로 처리할 수 있지만, purl·source identity·unknown ecosystem·call-analysis field와 upstream data availability를 보고서에서 설명하지 않는다. [OSV 실행](../../src/source.ts), [OSV parser](../../src/source/parsers.ts)

**제안.** OSV adapter를 forward-compatible envelope로 바꾼다.

- package purl 또는 raw identity, source path, aliases, affected/fixed range, advisory reference, tool/schema/DB/network state를 보존한다.
- unknown ecosystem, malformed fixed version, name normalization 실패, local link, upstream DB/metadata unavailable을 각각 `unsupported`/`partial`/`unknown`으로 분류한다. 한 package의 unknown 때문에 안전하게 계속할 수 있다면 다른 package 결과를 버리지 않되, 전체 report가 clean이 되지는 않게 한다.
- OSV의 JSON/SARIF output이 제공하는 source path, package, vulnerability/group과 experimental analysis 정보를 잃지 않고, parser fixture로 schema 변화와 빈/부분 응답을 고정한다.

upstream issue tracker에는 deps.dev gRPC outage 뒤 license scan이 실패하는 문제, unrecognized ecosystem advisory 처리 중 panic, local link 오매칭, platform-specific RubyGems normalization false positive, requirements package 누락, invalid fixed version panic이 각각 보고돼 있다. 이는 OSV가 반드시 고친다는 약속이 아니라 “외부 데이터가 흔들려도 Wakeio가 fail-open하지 않는가”를 시험할 입력이다. [OSV output](https://google.github.io/osv-scanner/output/), [OSV installation](https://google.github.io/osv-scanner/installation/), [issue #2942](https://github.com/google/osv-scanner/issues/2942), [issue #2867](https://github.com/google/osv-scanner/issues/2867), [issue #2881](https://github.com/google/osv-scanner/issues/2881), [issue #2898](https://github.com/google/osv-scanner/issues/2898), [issue #2940 requirements](https://github.com/google/osv-scanner/issues/2940), [issue #2936 fixed version](https://github.com/google/osv-scanner/issues/2936)

**도입 효과.** advisory가 없어서 clean인 것과 package identity/data source를 해석하지 못한 것을 구분한다. 데이터 장애가 있을 때도 다른 check 결과와 raw secret/source를 안전하게 보존하면서 exit 2로 재검사를 요구할 수 있다.

**비용과 위험.** OSV v1/v2와 experimental field의 버전 경계를 따라가는 adapter와 fixture 유지가 필요하다. unknown을 너무 넓게 잡으면 정상 CI가 자주 partial이 되고, normalization을 너무 공격적으로 하면 다른 package를 합친다. raw scanner output을 그대로 공개하지 말고 허용한 identity·상태만 보존한다.

## 7. OSV reachability는 명시적·제한적 evidence lane으로 둔다 — P2

**현재.** 현재 계약은 공개 advisory만 보고 reachability를 하지 않는다. OSV parser도 call-analysis 정보를 보존하지 않는다. [체크리스트](../checklist.md), [OSV 실행](../../src/source.ts), [OSV parser](../../src/source/parsers.ts)

**제안.** reachability는 기본값을 바꾸지 않는 별도 profile로 추가한다. 공식 문서가 설명하는 지원 범위에 맞춰 현재 Go 분석과 experimental Rust 분석만 우선 허용하고, Node/Python에 reachability가 있다고 추정하지 않는다. 결과는 `called`, `uncalled`, `unknown`으로 표시한다. `uncalled`는 triage priority를 낮출 수 있지만 advisory 자체를 삭제하거나 안전 판정으로 바꾸지 않는다. 분석 도구·compiler·toolchain이 없거나 advisory에 함수 정보가 없으면 unknown/partial이다. [OSV scan-source와 call analysis](https://github.com/google/osv-scanner/blob/main/docs/scan-source.md), [OSV output](https://google.github.io/osv-scanner/output/), [OSV experimental flags 주의](https://google.github.io/osv-scanner/installation/)

Rust call analysis는 build 과정에서 untrusted `build.rs`를 실행할 수 있다는 OSV 공식 문서 경고와 upstream security issue가 있다. 따라서 sandbox/격리 실행이 확보되기 전에는 Rust를 기본 활성화하지 않고, source upload·자동 build 없이 안전하게 실행할 조건을 먼저 정한다. [OSV Rust call-analysis issue #2753](https://github.com/google/osv-scanner/issues/2753)

**도입 효과.** Go/Rust 사용자가 알려진 advisory 중 실제 호출 여부를 우선순위에 반영할 수 있다. Node/Python 사용자에게 지원하지 않는 정밀도를 약속하지 않으므로 현재의 advisory 의미도 보존된다.

**비용과 위험.** compiler 실행 시간·sandbox·cross-build 환경이 필요하고, static call analysis는 reflection·dynamic import·generated code를 놓칠 수 있다. `uncalled`를 “취약하지 않음”으로 보여주면 false negative가 커지므로 원래 advisory와 분석 한계를 항상 함께 표시한다.

## 8. PR-native summary와 제한된 annotation을 제공한다 — P0/P1

**현재.** CLI는 JSON·SARIF·Markdown artifact를 쓰지만 Markdown은 check와 finding의 전체 목록 위주이며 compare는 별도 command다. composite Action은 report directory만 output으로 기록하고 `$GITHUB_STEP_SUMMARY`, file/line annotation, PR용 new/changed/not_observed/unverified 요약을 쓰지 않는다. SARIF에는 Wakeio 자체 fingerprint가 있으나 engine/data provenance와 GitHub용 partial fingerprint 연결은 없다. [report](../../src/report.ts), [compare](../../src/compare.ts), [Action runner](../../scripts/action-run.mjs)

**제안.** Action에만 GitHub projection을 추가한다.

- `$GITHUB_STEP_SUMMARY`에 scope, check 상태, findings by severity/kind, new/changed/not_observed/unverified, omitted count, incomplete reason, artifact path와 재검사 명령을 짧게 쓴다.
- 상위 파일/라인만 `::error`, `::warning`, `::notice`로 제한해 표시하고, GitHub가 문서화한 step annotation 제한(경고 10개·오류 10개)을 넘으면 생략 수를 summary에 적는다. full JSON/SARIF/Markdown은 artifact로 보존한다.
- SARIF에는 안정된 `partialFingerprints`와 analysis category/run identity를 추가하되, `partialFingerprints`가 없는 upload를 GitHub action이 보완할 수 있다는 동작을 고려해 실제 runner에서 유지·이동을 acceptance test한다. PR에 자동 comment를 쓰거나 write token을 요구하는 기능은 기본으로 넣지 않는다.

GitHub workflow command 문서는 summary, annotation, mask를 제공하고, Checks API는 Markdown summary/text와 annotation 위치를 지원한다. upload-sarif는 `security-events: write`와 source/SARIF의 일치를 요구하며, fork PR의 token·secret 제약도 있다. [workflow commands](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions), [upload SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file), [Checks API](https://docs.github.com/en/rest/checks/runs), [Actions secrets](https://docs.github.com/en/actions/concepts/security/secrets)

**도입 효과.** vibecoder가 로그와 세 artifact를 열어 보지 않고 PR에서 지금 고칠 finding, 이전부터 있던 finding, 검사하지 못한 범위를 구분한다. `partial`/`unverified`를 clean badge처럼 보이게 하지 않으면서도 상위 문제에 집중할 수 있다.

**비용과 위험.** GitHub-specific formatting, permissions, annotation 수 제한과 path/line 이동을 관리해야 한다. 요약에서 생략된 finding·미검사를 숨기면 거짓 안심이 되므로 count와 artifact 링크를 항상 표시한다. generic CLI는 계속 offline 산출물만 만들고, PR comment/write는 사용자 opt-in으로 남긴다.

## 채택 순서와 source의 긴장 지점

권장 순서는 (1) identity/provenance와 API actor evidence를 먼저 report 계약에 넣고, (2) `plan`/`doctor`로 그 계약과 외부 통신을 처음 실행부터 설명하며, (3) PR summary로 결과를 연결하는 것이다. 그 뒤 Next/Supabase graph·RLS evidence와 Node/Python inventory를 넓히고, OSV resilience를 reachability보다 먼저 안정화한다. reachability는 지원 언어·sandbox·unknown 상태를 입증한 뒤 마지막에 선택 profile로 둔다.

공식 자료를 함께 읽을 때 생기는 제한과 긴장은 다음과 같다.

- Next의 `NEXT_PUBLIC_`와 Supabase publishable/`anon` key는 public bundle에 들어갈 수 있지만, 그 존재만으로 secret leak이나 RLS 안전을 뜻하지 않는다. `sb_secret_`/`service_role`의 client 경계와 exposed object의 grant/RLS를 별도 판정해야 한다.
- Supabase migration의 RLS/policy 문서와 `supabase test db`는 live state와 test evidence를 요구한다. migration text만으로 운영 DB를 certifying할 수 없으므로 static candidate, local test evidence, live unknown을 나눈다.
- OSV output은 called/uncalled 정보를 보여줄 수 있지만, 설치 문서는 experimental flag가 바뀔 수 있음을 알리고 Rust analysis의 실행 위험이 있다. reachability를 Node/Python까지 확장하거나 advisory를 제거하는 근거가 아니다.
- npm audit의 signature/provenance와 PyPI attestation은 각각 registry/source 무결성 증거를 제공하지만, npm은 dependency metadata를 외부 registry에 보내고 PyPI도 attestation이 trustworthiness를 보장하지 않는다고 한다. “provenance verified = safe”로 표시하지 않는다.
- Trivy의 downloaded checks bundle과 embedded fallback은 결과에 시간·data identity를 만든다. binary version만 맞춘 비교는 부족하다.
- GitHub upload action의 fingerprint 보완 가능성 때문에 현재 SARIF를 전면 실패로 단정하지 않는다. 실제 runner의 두 commit·두 분석 category와 summary/annotation limits를 검증 대상으로 둔다.
- OSV issue tracker는 open, closed, duplicate, user request가 섞인 보고 채널이다. issue를 roadmap이나 탐지 보장으로 인용하지 않고, parser resilience와 false-positive regression fixture로만 사용한다.

이 문서의 제안은 모두 source·metadata·사용자 제공 fixture를 기본 입력으로 한다. source upload, LLM, paygate, telemetry, 무단 target scan을 다음 iteration의 전제에 넣지 않는다.
