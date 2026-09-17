# 0.3 이후 고도화 분석

분석일: 2026-09-16 KST · 기준: `wakeio-security-ci@0.3.0-dev.1`

이번 작업은 분석이다. 실행 코드·CLI 계약·버전·배포물을 변경하지 않았다. Luna max 에이전트가 공식 자료·소스·배포 경험을 나눠 조사했고 부모 에이전트가 API와 비교 기능을 재현·검토했다. 기존 테스트는 현재 작업 트리에서 다시 실행해 **99/99 통과**했다. 아래 추가 시나리오는 그 테스트가 검증하지 않던 사용 조건이며, 문서화된 제한과 결함을 구분한다.

## 판단

다음 공개 프리뷰의 중심은 **처음 실행하기 쉽게 만들고, 자주 하는 실수를 정확히 구분하고, PR에서 수정 여부를 계속 확인할 수 있게 하는 것**이다. 여러 scanner를 더 연결하기 전에 현재 기능이 실제 개발 흐름에서 끊기는 지점을 해결할 필요가 있다. 채택률·Star·다운로드 증가를 측정한 결과는 아니며, 아래 순위는 코드 재현과 사용자 작업 흐름에 근거한 제품·개발 판단이다.

무료 CLI와 CI, 소스·URL 분리, Next/React+Supabase·Node/Python·API 권한 세 사용자층을 유지한다. 사용 지표는 사용자가 선택한 npm 다운로드 통계면 충분하며 별도 telemetry·가입·AI 서버를 이 개선안의 조건으로 넣지 않는다.

## 부모 에이전트가 직접 재현한 문제와 한계

재현 요약은 [JSON 근거](next-iteration-parent-reproductions-2026-09-16.json)에 보관했다. 합성 소스와 loopback HTTP 서버만 사용했다. 도구 경로 비교에는 같은 내용의 신뢰된 가짜 scanner 두 개를 사용했으며, native Gitleaks 탐지 정확도를 시험한 결과는 아니다.

### 1. CI의 임시 도구 경로가 보고서 비교를 깨뜨림

같은 source root와 파일, 같은 내용의 scanner를 사용하고 `--gitleaks`의 설치 경로만 바꿨다. 두 scan은 완료됐지만 compare는 `comparable=false`, exit 2였다.

- 원인: `src/cli.ts:198`의 `declaredScope`가 source 절대 경로와 `toolPaths`의 절대 경로를 해시에 포함한다.
- 연결된 실제 흐름: `scripts/action-run.mjs:31`은 매 실행 `mkdtemp`로 engine 경로를 만들고 그 경로를 CLI에 넘긴다. 따라서 현재 Action 실행 결과 두 개를 비교할 때도 같은 성격의 불일치가 예상된다. 이번에 hosted Action 두 번을 실행한 것은 아니며 이 연결은 코드에서 도출한 판단이다.
- 분류: CI 통합 설계 문제. 보수적으로 비교를 거부하므로 수정 완료를 오판하지 않지만, 정상적인 반복 사용을 막는다.
- 제안: 명시한 project identity + 프로젝트 상대 경로 + 선택한 검사 범위 + 실제 engine/rule 식별자를 분리한다. 절대 설치 경로를 identity로 사용하지 않는다. engine hash/version을 기록하되 advisory DB 시점을 확보하지 못하면 unknown을 유지한다.
- source 내용 hash는 실행 증거로 별도 기록한다. 수정 전후 비교의 목적상 source 내용이 바뀌었다는 이유만으로 범위가 다르다고 판단해서는 안 된다. 사용자가 project identity를 재사용하거나 보고서를 수정할 수 있으므로 그 값 자체가 보고서의 진위를 증명하지는 않는다.
- 완료 조건: 다른 checkout/캐시 경로의 동일 프로젝트·동일 engine은 비교 가능, 다른 프로젝트·다른 실제 규칙/엔진은 정책에 따라 비교 제한. 단순히 scope 검증을 제거하지 않는다.

### 2. 주석 한 줄 때문에 기존 경고가 새 경고가 됨

`db.query(req.query.sql)`이 있는 동일 파일 위에 관련 없는 주석 한 줄만 추가했다. compare는 `new=1`, `not_observed=1`, exit 1이었다.

- 원인: `src/report.ts:418`의 finding ID에 line/column이 들어간다. `src/compare.ts:98`은 이 ID로 매칭한다.
- 분류: 이미 문서화된 위치 기반 식별자의 제한. 새 회귀 결함으로 과장하지 않는다. PR에서 새 문제만 확인하는 기능을 만들기 전에 해결해야 한다.
- 제안: rule + 상대 파일 + enclosing symbol + 정규화한 구문/맥락 fingerprint로 매칭하고 line/column은 표시 위치로 분리한다. 동일 구문이 반복될 때 오병합하지 않도록 다중 후보·모호함을 보존한다. 서로 다른 native 엔진에 같은 AST 알고리즘을 억지로 적용하지 않는다.
- 완료 조건: 주석/공백/상단 import 추가로 경고가 새로 생기지 않고, 같은 sink가 두 개 있거나 이동·수정된 경우에는 임의로 수정 완료 처리하지 않는다.

### 3. API의 다른 계정 토큰이 만료돼도 완료로 표시됨

소유자는 보호된 JSON을 정상적으로 읽고, 다른 계정은 만료된 토큰 때문에 `401 {"error":"expired token"}`을 받도록 했다. 정책의 deny 상태가 `[401,403,404]`일 때 `completed`, 발견 0, exit 0이었다.

- 원인: `src/api.ts:354`는 토큰 문자열의 존재·형식·서로 다름을 확인하고, `src/api.ts:639`와 `651`은 소유자만 전후 성공 대조한다. 다른 계정이 실제로 인증된 별도 사용자라는 확인은 없다.
- 분류: 정책이 허용한 401 처리 자체의 구현 오류는 아니다. 실제 사용자 간 권한을 검증했다고 해석하기에는 증거가 부족한 검사 설계 문제다.
- 제안: 인증 actor마다 신뢰할 수 있는 identity endpoint 또는 자기 소유 fixture의 읽기 성공을 요구한다. 기대 user/org 식별자와 상태를 확인하고 만료·다른 계정 재사용을 incomplete로 처리한다. 익명 actor는 별도로 둔다. 사용자 정의 endpoint 없이 모든 인증 체계를 자동 검증한다고 약속하지 않는다.
- 완료 조건: 소유자 성공 + 만료된 다른 계정 토큰은 exit 2; 유효한 별도 사용자로 잘못 공개된 리소스는 발견; 유효한 별도 사용자의 정상 거부는 완료.

### 4. 오류 응답의 공개 ID 반복을 데이터 노출로 판단할 수 있음

소유자는 `200 {"id":"A","private":"synthetic-only"}`, 다른 계정은 `403 {"id":"A","error":"no access"}`을 반환했다. `/id == "A"` 정책에서는 high 노출 후보, exit 1이었다. 보호된 본문을 실제 반환한 경우도 같은 판정이었다.

- 분류: 현재 명시적 marker 계약의 제한. 객체 ID만 반복한 정상 오류와 보호된 데이터 노출을 구분하지 못한다. 모든 403을 안전 처리하는 방식으로 고쳐서는 안 된다.
- 제안: 리소스 identity와 보호 내용에 대한 assertion을 나눈다. 합성 전용 protected canary, 필수/금지 필드, 최소한의 복수 JSON 조건을 지원하고, 빈 값·null·공개 ID만 선택한 정책에는 약한 판정 근거임을 알려준다.
- 완료 조건: ID만 반복한 403은 자동 high로 만들지 않고, 보호된 canary가 들어 있는 403은 계속 탐지한다. raw response와 token은 보고서에 남기지 않는다.

### 5. 빈 본문의 정상 거부가 partial로 남음

소유자는 정상 JSON을 반환하고 다른 계정은 빈 body의 403을 반환했다. 결과는 partial, exit 2였다.

- 분류: 현재 JSON-only 계약에 명시된 보수적 동작이다. 예상 가능한 실제 API 응답을 다루는 사용성 확대 항목이다.
- 제안: 정책에 명시한 empty-body denial을 지원하되 actor 인증 확인 후 적용한다. non-JSON 전체를 무조건 정상 거부로 확대하지 않는다. 429/5xx/네트워크 오류는 계속 incomplete다.

### 6. GitHub용 SARIF 식별자 연결이 부족함

`src/report.ts:200`은 자체 `fingerprints` 두 개를 출력한다. GitHub가 문서화한 `partialFingerprints` / `primaryLocationLineHash`는 없다. GitHub는 파일 경로의 일관성과 fingerprint를 사용하며, upload-sarif action이 누락 fingerprint를 소스에서 보완할 수도 있다고 설명한다. 따라서 현재 모든 GitHub 업로드가 실패하거나 반드시 중복된다고 단정하지 않는다. 직접 SARIF API 업로드까지 보장하려면 해당 계약을 확인해야 한다. [GitHub SARIF 공식 문서](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)

제안: 자체 비교 ID와 GitHub 호환 fingerprint를 분리해 지원하고 실제 GitHub runner에서 두 commit 업로드의 경고 유지/이동을 확인한다. SARIF 업로드가 없는 사용자에게도 Markdown·Job Summary·exit gating을 제공한다.

### 7. 정상 SQL을 RLS 해제로 오인하는 두 사례

부모가 다음 두 내용을 각각 `supabase/migrations/001.sql`에 넣고 `runSource({root, tools: []})`를 실행했다. 둘 다 `source.framework=completed`, high `supabase:disable-row-level-security` 후보가 나왔다.

```sql
/* outer
 /* nested */
 ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;
*/
SELECT 1;
```

```sql
ALTER TABLE "public"."users" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;
```

첫 번째는 PostgreSQL의 중첩 block comment 안에 있는 문장을 실행 구문으로 읽는 오경고다. 공식 문법은 중첩 주석을 지원한다. 두 번째는 현재 지원한다고 명시한 동일 migration의 disable→enable 대조가 인용된 식별자에서 동작하지 않는 사례다. [PostgreSQL lexical structure](https://www.postgresql.org/docs/14/sql-syntax-lexical.html)

`src/source/framework.ts`의 `maskSql`은 block depth를 유지하지 않고 첫 `*/`에서 주석을 끝내며, double-quoted identifier를 문자 그대로 공백 처리한다. SQL 정적 분석 전체가 불가능하다는 뜻은 아니며, 이미 구현한 규칙의 입력 처리 결함이다. 중첩 주석 깊이와 인용 식별자를 보존하는 tokenizer를 먼저 보완하고, 지원하지 않는 구문은 명시적으로 범위를 제한해야 한다. 실제 PostgreSQL에 SQL을 실행한 검증은 하지 않았다.

### 8. URL 헤더 검사가 문자열 존재와 실제 정책 효과를 구분하지 못함

loopback HTTP 서버에 `script-src 'nonce-dGVzdGZpeHR1cmU=' 'unsafe-inline'`을 포함한 CSP와 `X-Content-Type-Options: invalid-value`를 설정했다. URL 검사는 completed였고 `url.csp-unsafe-inline`을 출력했지만 잘못된 nosniff 값은 지적하지 않았다.

- CSP: `src/url.ts:453`은 전체 헤더에서 `unsafe-inline` 문자열을 찾는다. W3C CSP3의 source-list 알고리즘에서는 nonce/hash가 해당 목록에 있으면 모든 inline 동작을 허용하는 것으로 판단하지 않는다. 토큰 관찰 자체는 맞지만 이를 그대로 허용 동작으로 설명하는 것은 부정확하다. directive·fallback·nonce/hash·복수 정책을 고려해야 한다. 이는 표준과 정적 출력의 대조이며 실제 브라우저 실행 검증은 하지 않았다. 고정 nonce의 실운영 안전성을 주장하는 예제도 아니다. [CSP3 source-list 알고리즘](https://www.w3.org/TR/CSP/#allow-all-inline)
- nosniff: `src/url.ts:530`은 헤더 존재만 확인한다. Fetch 표준의 값 판정까지 적용하면 잘못된 값도 안내할 수 있다. 현재 missing-header 규칙의 구현 오류가 아니라 값 검증 범위를 늘리는 항목이다. [Fetch의 X-Content-Type-Options 판정](https://fetch.spec.whatwg.org/#x-content-type-options-header)
- URL만 있는 사용자에게는 이 정책 해석 보완과 **명시한 여러 페이지·같은 origin의 JS module 연결 수집**이 다음 후보다. 현재 수집은 root HTML과 직접 연결된 script이며 사이트 전체 crawl이 아니다. 페이지·바이트·시간 한도, 누락 목록, 같은 origin 제한을 유지한 선택형 확장이 적절하다. `maxPages` 타입의 존재를 실제 다중 페이지 검사 지원으로 설명해서는 안 된다.

작은 품질 개선도 있다. `src/source/python.ts:154`의 B603 도움말 URL은 404였다. [현재 Bandit 공식 B603 문서](https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html)로 연결하고 release 문서 링크 검사를 추가할 수 있다. 이번에는 실행 코드를 수정하지 않았다.

### 9. 흔한 Python dependency 입력이 OSV 검사에 연결되지 않음

연구 에이전트가 찾은 `requirements.txt` 차이를 부모가 재현했다. `requests==2.32.0` 한 줄이 있는 source와 실행 가능 여부만 충족하는 합성 scanner 경로를 준비했다. 현재 adapter는 scanner를 호출하기 전에 `lockfiles: 0`, `dependencyManifest: true`, `source.osv=partial`로 반환했다. native OSV의 advisory 정확도를 시험한 것은 아니다.

`src/source.ts`는 requirements를 manifest로 수집하지만 OSV 입력 allowlist에는 넣지 않는다. upstream OSV는 requirements 및 uv/PDM 등의 입력을 지원한다고 문서화한다. Wakeio가 미검사를 partial로 표시하는 것은 올바르지만, Python 사용자의 일반적인 시작 경로에 공백이 남는다. 우선 pinned requirements·지원 lockfile부터 실제 고정 버전의 OSV와 연결하고, version range·marker·include·local dependency는 설치 없이 판정 가능한 범위와 unknown을 나눠야 한다. 최신 upstream 지원 목록을 현재 고정 binary가 모두 지원한다고 간주하지 않는다. [OSV 지원 입력과 manifest 한계](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

## 개선 우선순위

| 순서 | 묶음 | 사용자가 얻는 변화 | 상대 비용 | 완료 기준 |
| --- | --- | --- | --- | --- |
| 공개 전 수정 | SQL 주석·식별자와 CSP 해석 | 정상 구문과 브라우저 정책을 잘못 설명하지 않음 | 중 | SQL 오경고 해결, CSP directive별 판정과 값 검증, 실제 위험 예제 탐지 유지 |
| 공개 전 수정 | CI 보고서 artifact 보존 | 검사 후 보고서를 실제로 내려받을 수 있음 | 낮음 | 숨김 디렉터리 업로드 계약 수정, hosted runner에서 exit 0/1/2 결과 파일 확인 |
| 1 | 비교 identity와 엔진 근거 | 같은 문제를 PR마다 새 문제로 보지 않음 | 중~높음 | 경로·줄 이동 재현 해결, 모호한 매칭 보존, 실제 GitHub SARIF 확인 |
| 2 | 설치·환경 확인·cache | scanner 네 개를 각각 공부하지 않고 첫 검사 실행 | 중 | clean runner에서 초기화→검사, 두 번째 실행 다운로드 재사용, 설치 실패와 발견 구분 |
| 3 | API actor와 판정 근거 | 만료 토큰·오류 ID 반복을 잘못 해석하지 않음 | 중 | 위 API 재현 3종과 정상/취약 대조 모두 구분 |
| 4 | 실제 Next/Supabase 작성 방식 | 일반적인 env·client import·migration 실수를 검사 | 중~높음 | 공개키 정상 예제와 위험 예제, SQL 구문 예외 및 제한을 함께 검증 |
| 5 | Node/Python dependency 입력 | Python requirements·Node workspace를 더 충실히 검사 | 중 | pinned requirements native 검사, local link·환경 조건·미지원 분리, parser 장애 시 incomplete 유지 |
| 6 | PR 요약·수정 안내 | 로그를 뒤져서 찾아야 하는 작업을 줄임 | 낮음~중 | Job Summary, 제한된 annotation, 실패 시에도 artifact 보존, 해결/미검사/기존 경고 구분 |
| 7 | 사례 corpus 확대 | 무엇을 잡고 놓치는지 사용자가 판단 가능 | 중 | 세 사용자층의 위험/정상 쌍, 미탐지 공개, parser·권한 대조와 실제 runtime 결과 분리 |
| 8 | 명시한 URL 여러 페이지·JS module 수집 | 첫 페이지 밖의 공개 화면도 선택해서 검사 | 중 | 같은 origin·전체 예산 제한, 누락/실패 표시, 실행 없는 수집 |
| 9 | OpenAPI에서 읽기 정책 초안 | API 정책을 처음부터 손으로 쓰는 부담 감소 | 중~높음 | 경로 초안만 생성, 사용자 계정/fixture 기대값 필수, 자동 쓰기·퍼징 없음 |
| 10 | 선택형 깊은 검사 | 필요할 때 이미지·Git 이력·스키마 검증 확장 | 높음 | 도구별 전송·실행·시간 한도와 재현 fixture를 먼저 확보 |

위 비용은 개발 기간 견적이나 벤치마크가 아니라 상대적 복잡도 판단이다. 세부 감사의 P0/P1도 작업 우선순위이며 취약점 심각도 등급이 아니다. 1·3은 현재 결과의 신뢰성, 2·6은 설치 후 사용 흐름, 4·5·7은 세 사용자층에 대한 탐지 품질을 개선한다. OSV reachability처럼 현재 주요 사용자층에 직접 적용되지 않는 확장은 후순위다.

## 세부 감사에서 채택한 추가 항목

### 처음 설치하고 CI 결과를 받는 흐름

배포 에이전트는 기존 npm tarball을 격리 consumer에 설치해 내장 검사 실행과 세 보고서 생성을 확인했다. 기본 external 검사에서는 도구가 없어서 exit 2였다. source archive Action도 두 번 실행해 매번 npm install/build를 반복하고 `report-dir`만 출력하는 것을 확인했다. 부모는 해당 runner 코드와 workflow를 읽어 이 동작을 대조했다.

특히 `examples/github-local-action.yml`과 `.github/workflows/self-test.yml`은 `.wakeio-security-ci` 숨김 경로를 `upload-artifact@v4`에 전달하면서 `include-hidden-files`를 지정하지 않는다. v4 공식 문서는 숨김 폴더 안의 파일도 기본 제외한다고 설명한다. **로컬 보고서 생성은 확인됐지만 실제 hosted 업로드는 미검증**이며, 공개 예제에서 먼저 바로잡을 계약 문제다. [upload-artifact v4 숨김 파일 규칙](https://github.com/actions/upload-artifact/blob/v4/README.md#uploading-hidden-files)

prebuilt Action, 명시한 engine cache, 환경 진단, Job Summary를 다음 배포 흐름으로 채택한다. packed `package.json`의 개발용 build/test 명령 정리는 부수 품질 개선이며, 이미 동작하는 CLI 자체의 설치 실패로 표현하지 않는다. Python이 없는 저장소에 Bandit을 선택했을 때 core는 not_applicable인데 Action은 path를 먼저 요구하는 불일치도 진단 흐름에서 정리한다. 실제 Linux/macOS runner 검증은 앞으로 할 일이다.

### 세 사용자층의 실제 작성 방식

| 사용자층 | 현재 확인된 경계 | 다음 확장 |
| --- | --- | --- |
| Next/React + Supabase | `.env`·`process.env` 연결과 client import graph 미해석; CREATE TABLE+GRANT에서 RLS 미활성 후보 없음 | 정적 env/relative import 연결, 공개키 정상 대조, CREATE/GRANT/ENABLE을 함께 보는 migration 후보 |
| Node/Python | 제한된 JS input/sink 이름·구문, JSX HTML sink 미연결; requirements가 OSV 입력에서 빠짐 | route parameter destructuring·loop binding·JSX sink·대표 raw-query API를 위험/정상 쌍으로 추가; pinned Python dependency부터 연결 |
| API/권한 | 인증된 다른 actor임을 입증하지 못함; 단일 scalar marker의 오판 가능성 | actor별 인증 대조, resource와 protected assertion 분리, 역할/조직별 읽기 matrix 초안 |

소스 에이전트는 각 누락을 합성 파일로 재현했다. `.env`/import graph·migration 간 상태·closure는 현재 문서화된 제한이므로 기존 기능 결함과 구분했다. 지원 구문을 늘릴 때에는 해당 프레임워크 버전에서 실제로 유효한 handler/props 예제를 별도로 확보해야 한다. 정적 후보가 실제 실행 가능한 취약점이라는 주장은 하지 않는다.

추가 parser 항목으로 standard-conforming SQL 문자열의 backslash를 항상 escape로 처리해 유효한 migration이 partial이 되는 문제, 합성 Bandit JSON의 실제 파일을 벗어난 줄 번호를 completed로 수용하는 경계가 있다. 부모는 코드 원인을 검토했고 독립 재실행은 하지 않았다. SQL lexer 보완과 외부 결과의 위치 유효성 검사 acceptance에 포함한다. 자세한 입력·출력은 아래 소스 감사에 남겼다.

## 공식 자료에서 확인한 기준과 구현 방향

- Next.js는 `.env`의 `NEXT_PUBLIC_` 값을 client bundle에 넣을 수 있다. 따라서 JS/TS 변수 선언 이름만 보는 검사는 일반적인 `process.env.NEXT_PUBLIC_*` 사용을 충분히 표현하지 못한다. env 텍스트의 키·값 형태와 정적인 참조·설정을 연결하되 target config를 실행하지 않는 방향이 필요하다. [Next 환경변수](https://nextjs.org/docs/app/guides/environment-variables)
- Supabase의 RLS·policy는 실제 DB 설정·역할과 연결된다. migration 정적 검사를 확대해도 live DB 접근 가능성을 확정하지 않으며, 테이블 생성/ALTER 순서를 알 수 없을 때 unknown을 남긴다. [Supabase RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)
- OWASP는 feature·role·data 차원의 권한 matrix를 테스트 입력으로 분리하는 접근을 제시한다. actor 유효성, 리소스, 보호된 내용, 기대 거부를 분리하자는 제안은 이를 현재 GET 전용 runner에 적용한 설계 판단이다. [OWASP 권한 테스트 자동화](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)

## 다음 버전의 작업 순서

1. 위 재현을 acceptance fixture로 옮기고 identity·actor 검사·오경고부터 보완한다.
2. `init`/`doctor`/도구 설치 안내를 설계한다. 이 명령은 **제안이며 현재 CLI에 없다**. 자동으로 대상 프로젝트의 install/build/config를 실행하지 않는다.
3. Node/Python/Next-Supabase 예제에 맞는 검사 계획과 CI 파일을 생성하고 다운로드 크기·네트워크 대상·미실행 검사를 보여준다. 캐시는 버전/OS/arch/hash로 분리하고 검증한다.
4. Job Summary·안전한 수정 예시와 재검사 명령을 붙인다. SQL 정책·권한·결제 로직의 자동 수정은 기본 기능으로 넣지 않는다. 사용자의 AI 도구에 전달할 설명도 원문/secret 없이 로컬 파일로 만들 수 있다.
5. 전체 archive를 clean Linux/macOS 환경에서 설치·실행하고 native engine을 포함한 검사 근거를 남긴 뒤 공개 배포 여부를 정한다.

## 이번 분석의 범위

기존 기능의 테스트 통과는 넓은 실서비스 탐지율이나 공개 배포 준비 완료를 뜻하지 않는다. hosted Linux CI, 실제 고객 API, 실데이터·클라우드 계정은 사용하지 않았다. 코드 업로드·telemetry·유료 기능·새 외부 계정은 추가하지 않았다. 실행 결과·코드에서 확인한 사실, 공식 도구 기능, 설계 제안을 구분해 위에 기록했다.

세부 조사:

- [소스 규칙 재현 분석](next-iteration-source-audit-2026-09-16.md)
- [설치·CI 분석](next-iteration-distribution-audit-2026-09-16.md)
- [공식 도구 비교](next-iteration-primary-sources-2026-09-16.md)
